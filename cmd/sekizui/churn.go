package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/churn"
)

// churnWatcher publishes `credential_churn` to anzen's reactive dispatcher
// (D203, D204).
//
// **THE SIBLING OF `staleWatcher`, AND DELIBERATELY THE SAME SHAPE.** Both turn
// a condition the enforcement path observes into a LEVEL the dispatcher can
// latch on, both own their threshold because the dispatcher cannot know what a
// number means (D157), and both are registered after the listener so they stop
// first. Copying the shape is the point: a second signal source that invented
// its own lifecycle would be a second thing to get the stop order wrong.
//
// **WHAT IT IS FOR IS NOT MONITORING.** A target forcing re-mints is either
// holding a broken credential or making us churn against the secret manager, and
// nothing else can tell a human either way — a 401 is deliberate, so D141
// correctly counts it as the target being alive and the breaker never opens. The
// rule this feeds is load-bearing rather than advisory: the audit WAL and the
// secret manager's quota are shared by every target, so without a quarantine the
// accepted per-target outage becomes a fleet-wide one (CONTRACTS 78).
type churnWatcher struct {
	// wiring is filled by buildEnforcement during the listener's VALIDATION —
	// after this component is registered and before it starts. See staleWatcher
	// for why the handoff is explicit rather than a constructor argument.
	wiring *enforcementWiring
	every  time.Duration
	log    *slog.Logger

	counter  *churn.Counter
	dispatch *anzen.Dispatcher

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Name identifies this component in the init ledger and readiness output.
func (w *churnWatcher) Name() string { return "anzen:churn-watcher" }

// Start begins the poll loop.
func (w *churnWatcher) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wiring == nil || w.wiring.churn == nil || w.wiring.dispatch == nil {
		// NOT AN ERROR, AND SAID OUT LOUD, for staleWatcher's reason: a
		// deployment can legitimately reach here — `-mode=ingest` builds no
		// enforcement stack — and refusing the boot would turn a watcher into a
		// requirement.
		w.log.Info("anzen churn-watcher idle: no enforcement stack was built",
			"signal", "credential_churn")
		return nil
	}
	w.counter, w.dispatch = w.wiring.churn, w.wiring.dispatch

	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	w.cancel = cancel
	w.done = make(chan struct{})

	go w.loop(loopCtx)
	return nil
}

func (w *churnWatcher) loop(ctx context.Context) {
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
// **A LEVEL, WHICH IS THE WHOLE REASON `internal/churn` EXISTS.** The thing the
// enforcement path observes is an EVENT — one forced re-establishment, at an
// instant — and feeding an event to an edge latch either latches it forever
// (masking every later churn) or fires it on the first legitimate expiry. The
// counter turns the events into "this target is churning right now", which is a
// level, falls on its own when the window empties, and re-arms the rule.
func (w *churnWatcher) check(ctx context.Context) {
	churning := w.counter.Churning()
	if len(churning) > 0 {
		w.log.Warn("targets are forcing repeated credential re-establishments; "+
			"credential_churn is RAISED",
			"targets", len(churning), "threshold", churn.Threshold,
			"window", churn.DefaultWindow.String())
	}
	w.dispatch.Observe(ctx, "credential_churn", churning)
}

// Stop halts the loop. Idempotent, because shutdown races call it twice.
func (w *churnWatcher) Stop(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cancel == nil {
		return nil
	}
	w.cancel()
	w.cancel = nil
	<-w.done
	return nil
}
