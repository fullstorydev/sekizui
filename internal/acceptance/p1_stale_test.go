package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/internal/spine"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// step31CredentialStaleCountsSupersededButLiveEntries proves D109.
//
// **D99'S GAP MADE COUNTABLE.** Content-addressing creates a NEW pool entry when
// a credential rotates and does not remove the old one — which still holds the
// superseded credential and, for a session-oriented target (§4.7.4 class 3), a
// live authorised session. Explicit invalidation closes that, and rather than
// reasoning about whether the invalidation is correct, the pool counts what is
// left and publishes the number.
//
// A BOUND NOBODY CAN SEE IS A BOUND NOBODY TRUSTS.
func step31CredentialStaleCountsSupersededButLiveEntries(t *testing.T) {
	ctx := context.Background()

	clock := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)
	p := pool.New(func(context.Context, connector.Target) (any, error) {
		return "client", nil
	}, quietLogger(), pool.WithClock(func() time.Time { return clock }))

	v1 := lifetimeTarget(t, "kata:alpha", "v1")
	v2 := lifetimeTarget(t, "kata:alpha", "v2")

	// --- 31a: ZERO IS THE EXPECTED VALUE ---------------------------------
	if err := p.Do(ctx, v1, func(context.Context, any) error { return nil }); err != nil {
		t.Fatalf("borrow v1: %v", err)
	}
	if got := len(p.Stale()); got != 0 {
		t.Fatalf("credential_stale = %d before any rotation, want 0", got)
	}

	// --- 31b: A ROTATION WITH NOTHING IN FLIGHT LEAVES NOTHING STALE -----
	//
	// The common case, and the reason zero is the expected value rather than a
	// hopeful one: an idle superseded entry is torn down synchronously as the
	// rotation lands, so it never enters the count at all.
	if err := p.Do(ctx, v2, func(context.Context, any) error { return nil }); err != nil {
		t.Fatalf("borrow v2: %v", err)
	}
	if got := len(p.Stale()); got != 0 {
		t.Errorf("credential_stale = %d after a rotation with nothing in flight, want 0. "+
			"An idle superseded entry is finalised as the rotation lands", got)
	}

	// --- 31c: A ROTATION *DURING* A CALL IS COUNTED ----------------------
	//
	// THE WINDOW D109 EXISTS FOR, and the one nothing else in the pool could
	// observe: `supersedeOthers` removes the entry from the pool immediately so
	// nothing new can borrow it, and the entry then lives on only in the hands
	// of the caller still using it. Counting from the pool's own map reports
	// zero at exactly the moment the number is interesting.
	rotated := make(chan struct{})
	inCall := make(chan struct{})
	done := make(chan error, 1)

	v3 := lifetimeTarget(t, "kata:alpha", "v3")
	go func() {
		done <- p.Do(ctx, v2, func(context.Context, any) error {
			close(inCall)
			<-rotated
			return nil
		})
	}()
	<-inCall

	// Rotate while the call above is still running.
	clock = clock.Add(30 * time.Second)
	if err := p.Do(ctx, v3, func(context.Context, any) error { return nil }); err != nil {
		t.Fatalf("borrow v3: %v", err)
	}

	stale := p.Stale()
	if len(stale) != 1 {
		t.Fatalf("credential_stale = %d during a rotation with a call in flight, want 1. "+
			"This is the entry still holding the superseded credential", len(stale))
	}
	if stale[0].TargetRef != "kata:alpha" {
		t.Errorf("target = %q, want kata:alpha", stale[0].TargetRef)
	}
	if stale[0].InFlight != 1 {
		t.Errorf("in_flight = %d, want 1 — the reason it has not been torn down",
			stale[0].InFlight)
	}

	// **THE AGE, WHICH IS WHAT MAKES THE COUNT ACTIONABLE.** A non-zero count is
	// either a rotation happening right now — normal, resolving itself as you
	// read it — or a drain that will never complete. Those want opposite
	// responses and only the age tells them apart, so a report carrying the
	// count alone would be a number nobody could act on.
	if stale[0].Age <= 0 {
		t.Errorf("age = %v; without it an operator cannot tell a rotation in progress "+
			"from a drain that is stuck", stale[0].Age)
	}

	// --- 31d: IT CLEARS WHEN THE DRAIN COMPLETES -------------------------
	//
	// Non-vacuity, and the arm that matters most for trust in the signal: a
	// gauge that goes up and never comes down is one an operator learns to
	// ignore, which is D77's failure aimed at a metric.
	close(rotated)
	if err := <-done; err != nil {
		t.Fatalf("the in-flight call failed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(p.Stale()) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(p.Stale()); got != 0 {
		t.Errorf("credential_stale = %d after the drain completed, want 0. A gauge that "+
			"rises and never falls is one nobody acts on", got)
	}
}

// step33AStalePoolEntryDoesNotAffectReadiness proves D109's deliberate omission.
//
// **A SECURITY CONDITION IS NOT AN INABILITY TO SERVE**, and conflating them
// would make /readyz flap on something a load balancer cannot act on. Taking the
// instance out of rotation because a credential is draining removes capacity for
// a condition that resolves itself — and if the drain is genuinely stuck, going
// unready hides the evidence behind a pod nobody is looking at.
//
// The right response is a gauge somebody watches and, eventually, an anzen rule
// (D106 repairs what D109 detects). Not a readiness flap.
func step33AStalePoolEntryDoesNotAffectReadiness(t *testing.T) {
	ctx := context.Background()

	clock := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)
	p := pool.New(func(context.Context, connector.Target) (any, error) {
		return "client", nil
	}, quietLogger(), pool.WithClock(func() time.Time { return clock }))

	// Drive the pool into the stale state from step 31.
	rotated := make(chan struct{})
	inCall := make(chan struct{})
	done := make(chan error, 1)

	v1 := lifetimeTarget(t, "kata:alpha", "v1")
	v2 := lifetimeTarget(t, "kata:alpha", "v2")
	go func() {
		done <- p.Do(ctx, v1, func(context.Context, any) error {
			close(inCall)
			<-rotated
			return nil
		})
	}()
	<-inCall
	if err := p.Do(ctx, v2, func(context.Context, any) error { return nil }); err != nil {
		t.Fatalf("rotating: %v", err)
	}
	if len(p.Stale()) == 0 {
		t.Fatal("the fixture produced no stale entry, so this step would prove nothing")
	}
	defer func() { close(rotated); <-done }()

	// THE POOL DOES NOT REPORT HEALTH AT ALL, and that is the structural form of
	// the guarantee. A readiness reporter is a spine.HealthReporter; asserting
	// the pool is not one is stronger than asserting it currently answers
	// "ready", because it forecloses the change rather than observing its
	// absence today.
	var reporter any = p
	if _, isReporter := reporter.(spine.HealthReporter); isReporter {
		t.Error("the pool reports health. A stale entry is a security condition, not an " +
			"inability to serve: going unready removes capacity for something that " +
			"usually resolves itself, and if the drain IS stuck it hides the evidence " +
			"behind a pod nobody is looking at")
	}
}
