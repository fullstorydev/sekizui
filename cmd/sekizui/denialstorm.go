package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/denial"
)

// denialStormWatcher publishes `denial_storm` to anzen's reactive dispatcher
// (D143, D336) — the last of the anzen signals nothing raised (CONTRACTS 65).
//
// **THE SHAPE OF ITS SIBLINGS, ON PURPOSE** (mistenantWatcher's reasoning): it
// owns its threshold because the dispatcher cannot know what a number means
// (D157), it polls rather than being called from the refusal because the
// dispatcher fires through the enforcement path and observing from inside it
// would re-enter it, and it is registered after the listener so it stops first.
//
// **THE LEVEL NAMES THE MONOPOLISER, NOT THE VICTIMS**, and it FALLS when the
// window empties: contention clears, so the dispatcher re-arms and a later storm
// fires again — unlike a mis-bound target, whose level never decays.
type denialStormWatcher struct {
	wiring    *enforcementWiring
	every     time.Duration
	threshold int
	log       *slog.Logger

	tally    *denial.Tally
	dispatch *anzen.Dispatcher

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Name identifies this component in the init ledger and readiness output.
func (w *denialStormWatcher) Name() string { return "anzen:denial-storm-watcher" }

// Start begins the poll loop, idle and saying so without an enforcement stack.
func (w *denialStormWatcher) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.wiring == nil || w.wiring.denials == nil || w.wiring.dispatch == nil {
		w.log.Info("anzen denial-storm-watcher idle: no enforcement stack was built", "signal", "denial_storm")
		return nil
	}
	w.tally, w.dispatch = w.wiring.denials, w.wiring.dispatch
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	w.cancel = cancel
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		t := time.NewTicker(w.every)
		defer t.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-t.C:
				w.check(loopCtx)
			}
		}
	}()
	return nil
}

// check reports the signal's current level over one polling window.
func (w *denialStormWatcher) check(ctx context.Context) {
	storms := w.tally.Storms(w.every, w.threshold)
	if len(storms) > 0 {
		w.log.Warn("a principal over its share is causing refusals of others; denial_storm is RAISED",
			"monopolisers", len(storms))
	}
	w.dispatch.Observe(ctx, "denial_storm", storms)
}

// Stop halts the loop. Idempotent, because shutdown races call it twice.
func (w *denialStormWatcher) Stop(context.Context) error {
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
