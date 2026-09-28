package main

import (
	"context"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/churn"
	"github.com/fullstorydev/sekizui/internal/denial"
	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/internal/kyuushin"
	"github.com/fullstorydev/sekizui/internal/limiter"
	"github.com/fullstorydev/sekizui/internal/mistenant"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// staleWatcher publishes `credential_stale` to anzen's reactive dispatcher
// (D109, D157).
//
// **THE SIGNAL SOURCE, AND IT OWNS THE THRESHOLD.** D157 leaves thresholds with
// the source until P5 puts them in the rule, and this is why: D109 says the AGE
// distinguishes a rotation in progress — normal, resolving itself as you read it
// — from a drain that will never complete. Deciding which of those a number
// represents requires knowing what it measures, which the dispatcher does not.
//
// THE THRESHOLD IS `max_lifetime`, DERIVED RATHER THAN CONFIGURED. An entry still
// draining past the lifetime its own deployment set for it is stuck by
// definition: the bound exists precisely to say how long a client may live, and
// this one has outlived it while still holding a superseded credential. No new
// config field, and the knob an operator already has is the knob that governs it.
//
// A DEPLOYMENT WITH NO LIFETIME CONFIGURED GETS NO AUTOMATIC FIRING, which is
// stated at boot rather than left to be discovered. There is no threshold to
// cross, so the signal is never raised — the direction that does nothing rather
// than the one that guesses.
type staleWatcher struct {
	// wiring is filled by buildEnforcement, which runs during the listener's
	// VALIDATION — after this component is registered and before it starts.
	//
	// AN EXPLICIT HANDOFF RATHER THAN A CONSTRUCTOR ARGUMENT, because the
	// ordering leaves no alternative: spine registration is start order, so a
	// component must exist before the thing it depends on has been built. The
	// pointer is read at Start, by which time validation has completed — and if
	// it has not, Start says so rather than watching nothing.
	wiring *enforcementWiring
	every  time.Duration
	log    *slog.Logger

	pool     *pool.Pool
	dispatch *anzen.Dispatcher
	lifetime time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Name identifies this component in the init ledger and readiness output.
func (w *staleWatcher) Name() string { return "anzen:stale-watcher" }

// Start begins the poll loop.
//
// A TICKER RATHER THAN A HOOK ON THE POOL, and the difference matters. The pool
// knows when it SUPERSEDES an entry, which is a rotation and entirely normal;
// what this watches for is an entry that is still draining some time later, and
// that is only observable by looking again.
func (w *staleWatcher) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wiring == nil || w.wiring.pool == nil || w.wiring.dispatch == nil {
		// NOT AN ERROR, AND SAID OUT LOUD. A deployment can legitimately reach
		// here — `-mode=ingest` builds no enforcement stack — and refusing the
		// boot would turn a watcher into a requirement.
		w.log.Info("anzen stale-watcher idle: no enforcement stack was built",
			"signal", "credential_stale")
		return nil
	}
	w.pool, w.dispatch, w.lifetime = w.wiring.pool, w.wiring.dispatch, w.wiring.lifetime

	if w.lifetime <= 0 {
		w.log.Info("anzen stale-watcher idle: no pool max_lifetime configured, so there "+
			"is no threshold past which a draining entry is stuck",
			"signal", "credential_stale")
		return nil
	}

	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	w.cancel = cancel
	w.done = make(chan struct{})

	go w.loop(loopCtx)
	return nil
}

func (w *staleWatcher) loop(ctx context.Context) {
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

// check reports the signal's CURRENT LEVEL, and the dispatcher fires on the edge
// (D158).
//
// **THE LEVEL, NOT AN EVENT.** An earlier version called Observe once per stuck
// entry per tick, which is precisely the flood: a single stuck drain would have
// produced a revocation attempt every minute, on every replica, for as long as it
// was stuck. Reporting the level and letting the dispatcher latch on the
// transition turns one condition into one response.
func (w *staleWatcher) check(ctx context.Context) {
	// **PER TARGET, NOT A SINGLE LEVEL.** An earlier version reported one boolean
	// for the whole pool, and a rule acts on the target IT names (D134) — so one
	// target's stuck drain would fire a rule scoped to a different, healthy
	// target and revoke it. Reporting which SUBJECTS are affected is what keeps a
	// rule responding to its own target and nothing else.
	stuck := map[string]string{}
	for _, e := range w.pool.Stale() {
		if e.Age < w.lifetime {
			// A ROTATION IN PROGRESS. Entirely normal, resolving itself, and
			// firing on it would revoke a credential because the system was
			// doing exactly what it was asked to.
			continue
		}
		stuck[e.TargetRef] = e.TargetRef + " draining for " + e.Age.String() +
			" with " + strconv.Itoa(e.InFlight) + " call(s) in flight"
	}

	if len(stuck) > 0 {
		w.log.Warn("pooled clients are still holding superseded credentials past their "+
			"lifetime; credential_stale is RAISED",
			"targets", len(stuck), "lifetime", w.lifetime.String())
	}
	w.dispatch.Observe(ctx, "credential_stale", stuck)
}

// Stop halts the loop. Idempotent, because shutdown races call it twice.
func (w *staleWatcher) Stop(context.Context) error {
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

// enforcementWiring is what buildEnforcement hands to components registered
// before it ran.
type enforcementWiring struct {
	pool     *pool.Pool
	dispatch *anzen.Dispatcher
	lifetime time.Duration

	// quarantined names the connectors whose schemas are not sound, and why
	// (D282): refused by the gateway, summarised on /readyz, and published as
	// `connector_quarantined` by sourceWatcher.
	quarantined map[string]string

	// gateway is the enforcement path, for the handle sweeper (D291).
	gateway *gateway.Server

	// toolNonconforming reads, per target, the MCP results that ADDED fields to
	// their output contract (D289), published as `tool_nonconforming`.
	toolNonconforming func() map[string]string

	// auditUnavailable reads the shipper's failing destinations (D319),
	// published as `audit_unavailable`. Nil when no destination is configured.
	auditUnavailable func() map[string]string

	// churn is the re-establishment tally `churnWatcher` publishes from (D204).
	// Shared with the gateway, which writes it from the enforcement path.
	churn *churn.Counter

	// mistenant is the refused-egress tally `mistenantWatcher` publishes from
	// (D226). Shared with the gateway for churn's reason: the enforcement path
	// writes it and the watcher reads it, and two tallies would mean the
	// condition being published is not the condition being observed.
	mistenant *mistenant.Tally
	denials   *denial.Tally // D336

	// resolver, drivers and targets are what `driftWatcher` needs to ask each
	// spec-described target's driver for a comparison (D206). The resolver is
	// how a `connector.Target` is obtained at all — §6 mechanism 1 makes one
	// unconstructable anywhere else — so the watcher shares the enforcement
	// path's, rather than being handed a second way to build targets.
	resolver drift.Resolver
	drivers  map[string]connector.Driver
	targets  []config.TargetSpec

	// jobs is the governed job runner (D247). Shared with the gateway, which
	// dispatches `StartJob` to it, so `jobDrainer` stops the SAME runner the
	// enforcement path submits to — two would mean draining one while the
	// other still held work against a vendor.
	jobs *kyuushin.Runner

	// reflexes runs the reflex engine (D261). Built beside `jobs` for the same
	// cycle: the engine enforces through this server and subscribes through it.
	reflexes func(context.Context) (wait func(), err error)

	// rate is the limiter `budgetRefresher` re-reads allocations into (D209).
	// Shared with the gateway for the resolver's reason one field up: two
	// limiters would mean the budgets being refreshed are not the budgets being
	// enforced, and the divergence would be silent.
	rate *limiter.Local
}
