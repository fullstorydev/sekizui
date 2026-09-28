package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/mistenant"
)

// mistenantWatcher publishes `tenant_mismatch` to anzen's reactive dispatcher
// (D226, §6 mechanism 3).
//
// **THE FOURTH SIGNAL SOURCE, AND DELIBERATELY THE SAME SHAPE AS THE OTHER
// THREE.** `staleWatcher`, `churnWatcher` and `driftWatcher` all turn a condition
// the enforcement path observes into a LEVEL the dispatcher can latch on, all own
// their own threshold because the dispatcher cannot know what a number means
// (D157), and all are registered after the listener so they stop FIRST. Copying
// the shape is the point: a signal source that invented its own lifecycle would
// be a fourth thing to get the stop order wrong.
//
// **WHY A POLL RATHER THAN PUBLISHING FROM THE PATH DIRECTLY, which looks like
// the obvious simplification and is a re-entrancy bug.** The dispatcher's firer
// runs a rule's action THROUGH the enforcement path (D18: no second code path),
// so observing synchronously from inside `Enforce` would re-enter `Enforce` from
// inside itself. Every other signal source polls for the same reason; this is
// not an accident of how churn happened to be built.
//
// **WHAT IT IS FOR IS NOT MONITORING.** A tenant mismatch is Sekizui about to put
// one customer's credential on another customer's request, caught by the last
// check before the wire. The assertion refuses that call — but a target that can
// produce one mis-bound request can produce more, and quarantining it is the
// response an operator would want made before they are awake to make it.
type mistenantWatcher struct {
	// wiring is filled by buildEnforcement during the listener's VALIDATION —
	// after this component is registered and before it starts.
	wiring *enforcementWiring
	every  time.Duration
	log    *slog.Logger

	tally    *mistenant.Tally
	dispatch *anzen.Dispatcher

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Name identifies this component in the init ledger and readiness output.
func (w *mistenantWatcher) Name() string { return "anzen:mistenant-watcher" }

// Start begins the poll loop.
func (w *mistenantWatcher) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wiring == nil || w.wiring.mistenant == nil || w.wiring.dispatch == nil {
		// NOT AN ERROR, AND SAID OUT LOUD, for churnWatcher's reason: `-mode=ingest`
		// builds no enforcement stack, and refusing the boot would turn a watcher
		// into a requirement.
		w.log.Info("anzen mistenant-watcher idle: no enforcement stack was built",
			"signal", "tenant_mismatch")
		return nil
	}
	w.tally, w.dispatch = w.wiring.mistenant, w.wiring.dispatch

	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	w.cancel = cancel
	w.done = make(chan struct{})

	go w.loop(loopCtx)
	return nil
}

func (w *mistenantWatcher) loop(ctx context.Context) {
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

// check reports the signal's CURRENT LEVEL; the dispatcher fires on the edge.
//
// **THE LEVEL DOES NOT FALL, AND THAT IS THE HONEST SHAPE HERE.** Churn's window
// empties and drift clears when the vendor's surface matches its spec again, so
// both re-arm. Nothing about a later successful call says the defect that
// mis-bound a target has been fixed, so inventing a decay would be inventing
// evidence. The rule fires once per mis-bound target and a different target still
// fires, because the latch is keyed per (signal, subject, rule) since D225.
func (w *mistenantWatcher) check(ctx context.Context) {
	mistenanted := w.tally.Mistenanted()
	if len(mistenanted) > 0 {
		w.log.Warn("targets have refused egress on a tenant mismatch; "+
			"tenant_mismatch is RAISED", "targets", len(mistenanted))
	}
	w.dispatch.Observe(ctx, "tenant_mismatch", mistenanted)
}

// Stop halts the loop. Idempotent, because shutdown races call it twice.
func (w *mistenantWatcher) Stop(context.Context) error {
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
