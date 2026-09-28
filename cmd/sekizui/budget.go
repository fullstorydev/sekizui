package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/limiter"
)

// budgetRefresher re-reads every rate budget's allocation on a clock (D209).
//
// **A COMPONENT RATHER THAN A CALL ON THE COMMAND PATH, WHICH IS THE POINT.**
// §5.2.1 rejects a coordinator hop per command and D147 gives the coordination
// node a one-sentence budget: agreement primitives only, never consulted
// synchronously. So the allocator is asked here, on a ticker, and `Allow` stays
// local arithmetic — an allocator outage slows the RATE AT WHICH CAPACITY IS
// REVISED and never blocks a governed call.
//
// **REGISTERED AFTER THE LISTENER like the three signal watchers**, so it starts
// last and stops FIRST. The reason differs slightly from theirs — nothing here
// fires an anzen rule — but the ordering property is worth keeping uniform: a
// component that outlived the gateway would be adjusting budgets for a server
// that is draining.
//
// **AND IT RUNS AT ONE INSTANCE, which is the maintainer's constraint rather than
// anticipation** — *"the logic for P7 should already work at p2 as it's just 1/1
// instances."* With the local allocator every tick hands back the configured
// budget and nothing changes, and that is exactly why it must run: the code P7
// depends on is exercised from the first deployment rather than first executed
// in production.
type budgetRefresher struct {
	// wiring is filled by buildEnforcement during the listener's VALIDATION —
	// after this component is registered and before it starts, which is the
	// handoff `staleWatcher` established and the reason it is explicit rather
	// than a constructor argument.
	wiring *enforcementWiring

	// rate is captured from the wiring at Start. Nil when the deployment built
	// no enforcement stack, which `-mode=ingest` legitimately does.
	rate *limiter.Local

	every time.Duration
	log   *slog.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Name identifies this component in the init ledger and readiness output.
func (w *budgetRefresher) Name() string { return "limiter:budget-refresher" }

// Start begins the refresh loop.
func (w *budgetRefresher) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wiring != nil {
		w.rate = w.wiring.rate
	}
	if w.rate == nil {
		// NOT AN ERROR, AND SAID OUT LOUD, for churnWatcher's reason: a
		// deployment can legitimately reach here, and refusing the boot would
		// turn a refresher into a requirement.
		w.log.Info("budget refresher idle: no rate limiter was built")
		return nil
	}

	// `WithoutCancel` for the reason every other watcher uses it: the loop must
	// outlive the boot context that started it and end only when Stop says so.
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	w.cancel = cancel
	w.done = make(chan struct{})

	go func() {
		defer close(w.done)
		w.rate.StartRefresh(loopCtx, w.every, w.log)
	}()
	return nil
}

// Stop halts the loop. Idempotent, because shutdown races call it twice.
func (w *budgetRefresher) Stop(context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.cancel, w.done = nil, nil
	w.mu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()
	<-done
	return nil
}
