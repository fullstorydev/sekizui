package main

import (
	"context"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/kyuushin"
)

// sourceWatcher publishes the job runner's three reports to anzen's reactive
// dispatcher as levels (D280): `source_nonconforming` (D243's tally),
// `source_stopped` (the melt guard) and `source_undeclared` (D277, D279).
//
// **UNTIL THIS, ALL THREE WERE READ BY NOTHING IN PRODUCTION.** Each was on the
// orphan allowlist as "its consumer is the same unwritten watcher" — a
// condition the runner computed on every tick and no operator or rule could
// see, which is the declared-and-inert shape this codebase keeps finding.
//
// **THE SAME SHAPE AS ITS FOUR SIBLINGS, for their reason**: a poll rather than
// publishing from the runner (the dispatcher's firer runs a rule's action
// through the enforcement path, so observing from inside a tick would re-enter
// it), registered after the listener so it stops first, and idle — said out
// loud — when there is no dispatcher or no runner.
//
// **WHAT A RULE MAY DO WITH THEM DIFFERS, AND BOOT ENFORCES IT.** The first two
// are the connector's fault and a rule may quarantine the target. The third is
// not — the source is behaving and nothing undeclared was published — so a
// rule watching it may only alert (config's anzenSignalActions).
type sourceWatcher struct {
	wiring *enforcementWiring
	every  time.Duration
	log    *slog.Logger

	jobs     sourceReports
	dispatch *anzen.Dispatcher

	// quarantined is the boot's D282 verdict, published as
	// `connector_quarantined` — a level that cannot fall within a process,
	// because a connector's schemas are compiled into it.
	quarantined map[string]string

	// toolNC is the MCP driver's run-time conformance tally (D289), or nil.
	toolNC func() map[string]string

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// sourceReports is what the watcher reads from the runner — an interface so a
// test can supply levels without driving a poll. *kyuushin.Runner satisfies it.
type sourceReports interface {
	Nonconforming() map[string]string
	Stopped() map[string]string
	Undeclared() map[string]string
}

var _ sourceReports = (*kyuushin.Runner)(nil)

// Name identifies this component in the init ledger and readiness output.
func (w *sourceWatcher) Name() string { return "anzen:source-watcher" }

// Start begins the poll loop.
func (w *sourceWatcher) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wiring == nil || w.wiring.jobs == nil || w.wiring.dispatch == nil {
		w.log.Info("anzen source-watcher idle: no job runner or no dispatcher was built",
			"signals", "source_nonconforming, source_stopped, source_undeclared")
		return nil
	}
	w.jobs, w.dispatch, w.quarantined = w.wiring.jobs, w.wiring.dispatch, w.wiring.quarantined
	w.toolNC = w.wiring.toolNonconforming

	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.loop(loopCtx)
	return nil
}

func (w *sourceWatcher) loop(ctx context.Context) {
	defer close(w.done)
	t := time.NewTicker(w.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.check(ctx)
		}
	}
}

// check reports each signal's CURRENT LEVEL; the dispatcher fires on the edge,
// per (signal, subject, rule) since D225, so one source's condition fires the
// rule naming that source and no other.
//
// **NONE OF THE THREE LEVELS FALLS**, each for the runner's stated reason: a
// later clean poll does not say the connector was fixed, a stopped source stays
// stopped until a restart, and what a schema did not declare stays undeclared
// until a new connector version declares it. So each rule fires once per source.
func (w *sourceWatcher) check(ctx context.Context) {
	for _, level := range []struct {
		signal   string
		subjects map[string]string
	}{
		{"source_nonconforming", w.jobs.Nonconforming()},
		{"source_stopped", w.jobs.Stopped()},
		{"source_undeclared", w.jobs.Undeclared()},
		{"connector_quarantined", w.quarantined},
		{"tool_nonconforming", w.toolLevel()},
		{"audit_unavailable", w.auditLevel()},
	} {
		// EACH SOURCE WITH ITS REASON, not a count: "1 source is nonconforming"
		// tells an operator that something is wrong and nothing about what —
		// the tool, the fields, the kind — which every tally already carries.
		// Found by the maintainer watching a live `tool_nonconforming` (D317).
		for _, subject := range sortedKeys(level.subjects) {
			w.log.Warn("a source is raising an anzen signal", "signal", level.signal,
				"source", subject, "why", level.subjects[subject])
		}
		w.dispatch.Observe(ctx, level.signal, level.subjects)
	}
}

// Stop halts the loop. Idempotent, because shutdown races call it twice.
func (w *sourceWatcher) Stop(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel == nil {
		return nil
	}
	w.cancel()
	<-w.done
	w.cancel = nil
	return nil
}

// auditLevel is the shipper's `audit_unavailable` level (D319): each audit
// destination currently refusing records, and why. Empty when none is
// configured or every one is caught up.
func (w *sourceWatcher) auditLevel() map[string]string {
	if w.wiring == nil || w.wiring.auditUnavailable == nil {
		return nil
	}
	return w.wiring.auditUnavailable()
}

// toolLevel is the MCP driver's `tool_nonconforming` level (D289), empty when
// no MCP driver reports one.
func (w *sourceWatcher) toolLevel() map[string]string {
	if w.toolNC == nil {
		return nil
	}
	return w.toolNC()
}

// sortedKeys orders a level's subjects, so the log reads the same every tick.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// shipComponent runs the audit shipper for the process's life (D319), with one
// last catch-up on shutdown so a clean stop leaves destinations current.
type shipComponent struct {
	shipper *auditwal.Shipper
	every   time.Duration
	cancel  context.CancelFunc
	done    chan struct{}
}

func (c *shipComponent) Name() string { return "audit:ship" }

func (c *shipComponent) Start(ctx context.Context) error {
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c.cancel, c.done = cancel, make(chan struct{})
	go func() { defer close(c.done); c.shipper.Run(loopCtx, c.every) }()
	return nil
}

func (c *shipComponent) Stop(context.Context) error {
	if c.cancel != nil {
		c.cancel()
		<-c.done
		c.cancel = nil
	}
	return nil
}
