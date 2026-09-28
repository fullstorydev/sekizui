package main

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// handleSweeper closes stateful handles nobody closed (D291): on a timer, the
// ones idle past their target's limit; on Stop, all of them — the drain. Both
// go through the gateway's enforcement path as each handle's opener.
type handleSweeper struct {
	wiring *enforcementWiring
	every  time.Duration
	log    *slog.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Name identifies this component in the init ledger and readiness output.
func (w *handleSweeper) Name() string { return "gateway:handle-sweeper" }

// Start begins the sweep loop, or idles when no gateway was built.
func (w *handleSweeper) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.wiring == nil || w.wiring.gateway == nil {
		w.log.Info("handle sweeper idle: no gateway was built")
		return nil
	}
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	w.cancel, w.done = cancel, make(chan struct{})
	go func() {
		defer close(w.done)
		t := time.NewTicker(w.every)
		defer t.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-t.C:
				w.wiring.gateway.SweepHandles(loopCtx)
			}
		}
	}()
	return nil
}

// Stop ends the loop and CLOSES EVERY OPEN HANDLE (the drain). Idempotent.
func (w *handleSweeper) Stop(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel == nil {
		return nil
	}
	w.cancel()
	<-w.done
	w.cancel = nil
	if n := w.wiring.gateway.CloseAllHandles(ctx); n > 0 {
		w.log.Info("drain closed open handles as their openers", "handles", n)
	}
	return nil
}
