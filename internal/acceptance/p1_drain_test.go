package acceptance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// step40EvictionWaitsForInFlightCallsBeforeWiping proves the guarantee D110
// stated — under the mechanism D127 replaced it with.
//
// **D110 CHOSE DRAIN-THEN-WIPE AND D127 DISSOLVED THE PROBLEM RATHER THAN
// SOLVING IT.** D110's premise was that a driver holds the material for the whole
// outbound call, so a wipe must wait for the call to end. Lending inverted that:
// a driver receives the bytes inside a callback and for its duration alone, so
// the window shrank from a network round-trip to stamping a header.
//
// The GUARANTEE is unchanged and still worth proving — **a wipe must not zero
// bytes a caller is holding**, because zeroed material is not a refusal and the
// audit would read "the target returned 401" for a credential Sekizui destroyed
// underneath the call (D106's argument). What changed is what enforces it: an
// `RWMutex` on the credential rather than a drain on the pool. So this step
// asserts the property against the mechanism that actually holds it, and does so
// by observing ORDER rather than by timing, because a test that sleeps proves the
// scheduler works.
func step40EvictionWaitsForInFlightCallsBeforeWiping(t *testing.T) {
	// BUILT THROUGH THE VALIDATING CONSTRUCTOR with real material, because the
	// property under test is about the material and a target without any would
	// prove nothing.
	target, err := connector.NewTarget(connector.TargetParams{
		Ref: "kata:alpha", Kind: "kata", Tenant: "alpha",
		BaseURL: "https://alpha.invalid", CredentialVersion: "v1",
		Credential: connector.Secret("secret-material"),
	})
	if err != nil {
		t.Fatalf("target: %v", err)
	}

	inUse := make(chan struct{})
	release := make(chan struct{})
	used := make(chan error, 1)

	go func() {
		used <- target.UseRaw(func(material []byte) error {
			close(inUse)
			<-release

			// **THE BYTES ARE STILL THERE.** A wipe that proceeded while this
			// callback held the material would zero it underneath — and zeroed
			// bytes reaching an upstream produce a 401 that the audit log
			// attributes to the target rather than to us.
			if len(material) == 0 || material[0] == 0 {
				return errors.New("material was zeroed while a caller held it")
			}
			return nil
		})
	}()
	<-inUse

	// The wipe starts while the callback is still running.
	wiped := make(chan struct{})
	go func() {
		target.WipeCredential()
		close(wiped)
	}()

	// **A BOUNDED WAIT, AND THE ASYMMETRY IS WHAT MAKES IT SOUND.** With the read
	// lock held no wait is long enough for the wipe to complete; without it, any
	// wait is. So a pass here means the exclusion held and a failure means it did
	// not — the direction that cannot be satisfied by luck.
	//
	// THE FIRST VERSION OF THIS USED A NON-BLOCKING `select` and claimed to be
	// observing order rather than timing. It was observing neither: the wipe
	// goroutine had simply not been scheduled yet, so the check passed whether or
	// not the lock existed. Deleting the read lock and re-running is what found
	// it — the assertion had to be sabotaged before it could be trusted.
	select {
	case <-wiped:
		t.Fatal("the credential was wiped while a caller was inside Use. The window " +
			"D127 shrank is not zero, and a wipe that lands inside it destroys " +
			"material the caller is about to send")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	if err := <-used; err != nil {
		t.Fatalf("the borrow failed: %v", err)
	}

	// AND THEN IT COMPLETES. A lock that never released would pass everything
	// above while making a wipe impossible, which is the opposite failure and
	// just as bad: a credential believed destroyed and still in memory.
	select {
	case <-wiped:
	case <-time.After(2 * time.Second):
		t.Fatal("the wipe never completed after the borrow returned; a wipe that waits " +
			"forever is a credential nobody can destroy")
	}

	// NON-VACUITY: the wipe actually happened.
	if !target.CredentialWiped() {
		t.Error("WipeCredential returned and the credential does not report itself wiped")
	}
	if err := target.UseRaw(func([]byte) error { return nil }); err == nil {
		t.Error("a wiped credential was still usable; the wipe is bookkeeping rather " +
			"than an act")
	}
}

// step41ADrainThatDoesNotCompleteIsBoundedThenForced proves the other half.
//
// **A HUNG DRIVER MUST NOT POSTPONE A REVOCATION FOREVER.** Break-glass exists
// for the moment a credential is believed compromised, and a revocation that
// waits indefinitely on a driver ignoring its context is a revocation that never
// happens — with an operator watching a command that has not returned, unable to
// tell "draining" from "stuck".
//
// Same shape as `Listener.Stop` racing `GracefulStop`: wait for the graceful
// path, but not forever, and REPORT what did not finish rather than pretending
// it did.
func step41ADrainThatDoesNotCompleteIsBoundedThenForced(t *testing.T) {
	ctx := context.Background()

	p := pool.New(func(context.Context, connector.Target) (any, error) {
		return "client", nil
	}, quietLogger())

	target := lifetimeTarget(t, "kata:hung", "v1")

	// A CALL THAT IGNORES ITS CONTEXT — the driver this bound exists for. It
	// does not observe cancellation, so nothing but a deadline ends the wait.
	stuck := make(chan struct{})
	inCall := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- p.Do(ctx, target, func(context.Context, any) error {
			close(inCall)
			<-stuck
			return nil
		})
	}()
	<-inCall
	defer func() { close(stuck); <-done }()

	// The revocation races a deadline rather than the call.
	budget := 150 * time.Millisecond
	drainCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	started := time.Now()
	w, err := p.Revoke(drainCtx, target.Ref(), "operator:oncall")
	elapsed := time.Since(started)

	if err != nil {
		t.Fatalf("revoking against a hung call returned an error: %v. A revocation "+
			"must complete — bounded and honest about what it could not finish — "+
			"rather than failing because a driver misbehaved", err)
	}

	// **BOUNDED.** Generous, because the assertion is "it returned" and not "it
	// was fast": a revocation that waits on a hung driver forever is one an
	// operator cannot tell from a hung revocation.
	if elapsed > 5*time.Second {
		t.Errorf("the revocation took %v against a call that never ends; the drain "+
			"budget is not bounding anything", elapsed)
	}

	// **AND HONEST.** The straggler is REPORTED rather than absorbed: its
	// credential is not wiped yet, and an operator who believes a revocation
	// completely destroyed material when one copy is still live has been told
	// something false about a security action.
	if w.Stragglers == 0 {
		t.Error("the revocation reported no stragglers while a call was demonstrably " +
			"still running. Silence here means an operator believes the material is " +
			"gone when a driver is still holding it — the one thing a break-glass " +
			"report must never get wrong")
	}
	if w.Cancelled == 0 {
		t.Error("no in-flight call was cancelled; revocation cancels rather than waits " +
			"(§4.7.10's split between quarantine and revoke)")
	}
}
