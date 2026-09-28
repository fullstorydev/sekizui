package main

import (
	"context"
	"log/slog"
	"sync"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/reflex"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/audit"
	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// buildReflexRun wires the reflex engine to the ONE scoped subscription path
// and the enforcement path, and returns the loop to run (D172, D261).
//
// **THE ADAPTER RETURNS `nil, err` EXPLICITLY, AND THAT IS NOT STYLE.**
// `SubscribeAs` returns a `*gateway.ScopedSubscription`; returning it straight
// through as a `reflex.Stream` on the error path would hand the engine a
// non-nil interface holding a nil pointer, and its first `Close()` would
// dereference nil. GO-PRIMER §15am.
func buildReflexRun(doc *config.Document, reg *schemareg.Registry, srv *gateway.Server, recorder audit.Recorder,
	dispatch *anzen.Dispatcher, b pkgbus.Bus, log *slog.Logger) func(context.Context) (func(), error) {

	// THE SIGNAL GOES WHERE EVERY OTHER SIGNAL GOES (D264): the anzen
	// dispatcher, which fires the reactive rules watching `budget_exceeded` —
	// the first producer CONTRACTS 65 has had for it. The rules it fired are
	// already recorded by the enforcement path they went through.
	signal := func(ctx context.Context, name string, subjects map[string]string) {
		_ = dispatch.Observe(ctx, name, subjects)
	}
	// THE SAME REGISTRY THE RUNNER AND THE SERVER USE (D276, D279, CONTRACTS
	// 128): an enrichment is held to the schema boot checked its
	// publishes_type against. Built once by the caller.
	validate := reg.Validate
	engine := reflex.NewEngine(doc.Reflexes, srv, recorder, signal, log, newEnvelopeID(), validate,
		reflex.WithSharedBudgets(doc.ReflexBudgets))
	subscribe := func(ctx context.Context, id *sekizuiv1.Identity, subjects []string) (reflex.Stream, error) {
		sub, err := srv.SubscribeAs(ctx, id, subjects)
		if err != nil {
			return nil, err
		}
		return sub, nil
	}
	return func(ctx context.Context) (func(), error) {
		// THE OFF SWITCH `disable_reflex` REACHES (D332): attached before the
		// rules subscribe, so a rule that trips on its first event can be
		// disabled by the response to it.
		if err := srv.AttachReflexes(engine); err != nil {
			return nil, err
		}
		return engine.Run(ctx, subscribe, b.Publish)
	}
}

// reflexRunner runs the engine for the life of the process (D261).
//
// A COMPONENT FOR `jobDrainer`'s REASON: the engine is built inside the
// listener's builder, and `enforcementWiring` is how this file reaches it.
// Registered AFTER the listener, so it starts last and stops FIRST — a rule
// dispatching into a gateway that is draining would issue commands the drain
// then refuses, which is noise in the audit log at the worst moment to read it.
type reflexRunner struct {
	wiring *enforcementWiring
	log    *slog.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Name identifies this component in the init ledger and readiness output.
func (r *reflexRunner) Name() string { return "reflex:engine" }

// Start subscribes every enabled rule and returns; the loop runs until Stop.
//
// A FAILED SUBSCRIPTION FAILS THE START, rather than being logged, because
// `Engine.Run` refuses all-or-nothing: a deployment reporting healthy with a
// rule that never listens is the inert-but-declared shape (D261).
func (r *reflexRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.wiring == nil || r.wiring.reflexes == nil {
		return nil // no enforcement stack, so nothing to consume for
	}
	// DETACHED FROM THE START CONTEXT, which ends when startup does; the loops
	// live until Stop cancels them.
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	wait, err := r.wiring.reflexes(runCtx)
	if err != nil {
		cancel()
		return err
	}
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		wait()
	}()
	return nil
}

// Stop cancels every rule's subscription and waits for in-flight dispatches.
func (r *reflexRunner) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cancel == nil {
		return nil
	}
	r.cancel()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
