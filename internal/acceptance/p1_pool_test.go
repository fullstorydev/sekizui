package acceptance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// P1 steps 4-9 and 11: rotation, supersession, drain-then-wipe, and the two
// break-glass severities.

// sessionClient stands in for a class 3 driver (§4.7.4) — one that holds
// server-side state and must be CLOSED rather than dropped.
type sessionClient struct {
	mu     sync.Mutex
	closed bool
}

func (c *sessionClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *sessionClient) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// targetWith builds a Target carrying a specific credential version and
// material, which is the only way to simulate rotation from outside.
func targetWith(t *testing.T, version, material string) connector.Target {
	t.Helper()
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "fullstory:prod", Kind: "fullstory", Tenant: "acme", Residency: "eu",
		CredentialVersion: version,
		Credential:        connector.Secret([]byte(material)),
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tgt
}

func newPool(t *testing.T) (*pool.Pool, *[]*sessionClient) {
	t.Helper()
	var (
		mu    sync.Mutex
		built []*sessionClient
	)
	p := pool.New(func(context.Context, connector.Target) (any, error) {
		c := &sessionClient{}
		mu.Lock()
		built = append(built, c)
		mu.Unlock()
		return c, nil
	}, quietLogger())
	return p, &built
}

// borrow runs one trivial call and reports which client the pool handed over.
//
// Client IDENTITY is what steps 4-6 assert, and Do no longer returns it — the
// client reaches only the callback, which is the point of D128. So the callback
// captures it.
func borrow(t *testing.T, p *pool.Pool, tgt connector.Target) any {
	t.Helper()

	var got any
	if err := p.Do(context.Background(), tgt, func(_ context.Context, c any) error {
		got = c
		return nil
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	return got
}

// heldCall is a borrow that has STARTED and not returned — the pool's definition
// of in flight, and the state every drain and cancellation assertion needs.
type heldCall struct {
	finish func()       // let the call complete normally
	wait   func() error // block for Do's error
}

// holdOpen starts a call that blocks inside the pool's callback until either
// finish is called or its context is cancelled, and returns once the call is
// genuinely in flight.
//
// THE CALLBACK HONOURS ITS CONTEXT, which is what a real driver does and what
// makes cancellation observable. A callback that ignored ctx would model a
// driver that ignores cancellation — worth testing too, and that is what step
// 9's straggler case does deliberately.
func holdOpen(t *testing.T, p *pool.Pool, tgt connector.Target) *heldCall {
	t.Helper()

	var (
		started = make(chan struct{})
		release = make(chan struct{})
		done    = make(chan error, 1)
	)

	go func() {
		done <- p.Do(context.Background(), tgt, func(ctx context.Context, _ any) error {
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				// What a driver reports: its transport aborted. Deliberately
				// NOT the revocation error — the whole question step 9 asks is
				// whether the pool restores the reason the driver cannot know.
				return ctx.Err()
			}
		})
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the call never entered the pool callback; nothing is in flight and " +
			"every assertion below would pass vacuously")
	}

	var once sync.Once
	return &heldCall{
		finish: func() { once.Do(func() { close(release) }) },

		// BOUNDED, AND THE BOUND IS THE POINT.
		//
		// The first version was `return <-done`, which is correct against a
		// working pool and catastrophic against a broken one. Sabotaging
		// Revoke to evict and report without actually cancelling — the single
		// most likely way this could regress, since every count would still be
		// right — turned the suite into a 400-second hang killed by an external
		// timeout, rather than a failure naming what broke.
		//
		// A hang is a worse signal than a failure: CI reports "timed out" with
		// no line number, and locally it reads as an infrastructure problem
		// rather than a defect. The deadline converts the most probable
		// regression back into a diagnosis.
		wait: func() error {
			select {
			case err := <-done:
				return err
			case <-time.After(10 * time.Second):
				t.Fatal("the held call never returned. Something claimed to cancel it " +
					"and did not — the eviction and the counts can all be correct while " +
					"the cancel functions are never fired, which is exactly the shape " +
					"this project keeps rediscovering")
				return nil
			}
		},
	}
}

// step4RotationPinned — a pinned reference moving 7 → 8 rebuilds the client.
func step4RotationPinned(t *testing.T) {
	p, built := newPool(t)

	c1 := borrow(t, p, targetWith(t, "gcp-sm://s/versions/7#1", "old"))
	c2 := borrow(t, p, targetWith(t, "gcp-sm://s/versions/8#2", "new"))

	if c1 == c2 {
		t.Error("a rotated credential reused the pooled client; the revoked one would " +
			"keep working until idle eviction (§4.3.2)")
	}
	if len(*built) != 2 {
		t.Errorf("%d clients built, want 2", len(*built))
	}
}

// step5RotationTracking — the reference string is IDENTICAL across a rotation.
//
// This is the case D99 exists for and the one a hash was originally proposed to
// solve. Only the generation distinguishes them (D123), so if versioning ever
// reverts to the bare reference this fails and step 4 does not.
func step5RotationTracking(t *testing.T) {
	p, built := newPool(t)

	const ref = "gcp-sm://s/versions/latest"

	c1 := borrow(t, p, targetWith(t, ref+"#1", "old"))
	c2 := borrow(t, p, targetWith(t, ref+"#2", "new"))

	if c1 == c2 {
		t.Error("a tracking reference reused the client across a rotation — the ref " +
			"string never changes, so only the generation can catch this (D123)")
	}
	if len(*built) != 2 {
		t.Errorf("%d clients built, want 2", len(*built))
	}
}

// step6SupersededIsEvicted — the old entry is REMOVED, not merely bypassed.
//
// A new key alone means the next caller gets a fresh client and says nothing
// about the old one, which keeps its credential and its session.
func step6SupersededIsEvicted(t *testing.T) {
	p, built := newPool(t)

	borrow(t, p, targetWith(t, "v#1", "old"))
	if p.Len() != 1 {
		t.Fatalf("%d entries after one call, want 1", p.Len())
	}

	borrow(t, p, targetWith(t, "v#2", "new"))

	if p.Len() != 1 {
		t.Errorf("%d entries after rotation, want 1 — the superseded entry is still "+
			"pooled, holding a credential nobody can reach but nothing removed", p.Len())
	}
	evicted, _, torndown, _ := p.Stats()
	if evicted != 1 {
		t.Errorf("evicted = %d, want 1", evicted)
	}
	// Class 3: the session must be CLOSED, not dropped.
	//
	// Waits on the COUNTER rather than the client's own flag. Finalisation runs
	// asynchronously — it must, because supersession happens under the pool lock
	// that finalise also takes — so the flag flips a few nanoseconds before the
	// stat does. A first version of this asserted the flag and then read the
	// stat, and failed on that window.
	waitFor(t, func() bool {
		_, _, n, _ := p.Stats()
		return n == 1
	}, "the superseded session was never closed — server-side state and possibly a "+
		"live authorised session are left behind (§4.7.4 class 3)")

	if !(*built)[0].isClosed() {
		t.Error("teardown was counted but the client was not actually closed")
	}
	_ = torndown
}

// step7WipeOnEviction — invariant 4 of §4.7.5, which had no caller at all until
// this pool existed.
func step7WipeOnEviction(t *testing.T) {
	p, _ := newPool(t)

	material := []byte("super-secret-token")
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "fullstory:prod", Kind: "fullstory", Tenant: "acme", Residency: "eu",
		CredentialVersion: "v#1", Credential: connector.Secret(material),
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	borrow(t, p, tgt)

	if bytes.Equal(material, make([]byte, len(material))) {
		t.Fatal("the material was already zero before eviction; this proves nothing")
	}

	borrow(t, p, targetWith(t, "v#2", "new"))

	waitFor(t, func() bool { return bytes.Equal(material, make([]byte, len(material))) },
		"the superseded credential was never zeroed — invariant 4 of §4.7.5")
}

// step8EvictionNeverRacesInFlight is D110's whole reason, and the assertion is
// ORDER rather than timing.
//
// A caller holds a client. The credential rotates. The old material must stay
// intact for exactly as long as that caller holds it, and be zeroed once it
// releases. Wiping on eviction instead would hand a live driver zeroed bytes —
// which is not a refusal, it is a request to the upstream with a broken
// credential (§4.7.10).
func step8EvictionNeverRacesInFlight(t *testing.T) {
	p, _ := newPool(t)

	material := []byte("in-flight-token")
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "fullstory:prod", Kind: "fullstory", Tenant: "acme", Residency: "eu",
		CredentialVersion: "v#1", Credential: connector.Secret(material),
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	// A call is genuinely running — inside the pool callback, not merely holding
	// an unreleased handle. The distinction became real with D128: "in flight"
	// now means the borrow window, and this asserts against the window.
	call := holdOpen(t, p, tgt)

	// Rotation supersedes it while that call is still running.
	borrow(t, p, targetWith(t, "v#2", "new"))

	if bytes.Equal(material, make([]byte, len(material))) {
		t.Fatal("the credential was zeroed while a call was still in flight. A driver " +
			"mid-call would send an all-zeros credential and the audit would record " +
			"whatever the upstream made of it, rather than an eviction (D110)")
	}

	// Now the call finishes. Only now may it be wiped.
	call.finish()
	if err := call.wait(); err != nil {
		t.Errorf("the in-flight call failed: %v. Supersession must not disturb a call "+
			"already running — that is the difference between eviction and revocation", err)
	}
	waitFor(t, func() bool { return bytes.Equal(material, make([]byte, len(material))) },
		"the credential was never wiped after the last caller released — drain "+
			"completed but the wipe did not follow")
}

// step9RevocationCancelsInFlight is D106's core claim, and the assertion is on
// the REASON rather than merely on the failure.
//
// A cancelled call fails no matter how the mechanism is built — including by the
// wiping design D106 rejects, where the driver sends zeroed bytes and the
// upstream returns 401. So "the call failed" proves nothing. What distinguishes
// cancellation from every alternative is that Sekizui can say WHY, and that the
// reason survives the driver, which reports only that its transport aborted.
func step9RevocationCancelsInFlight(t *testing.T) {
	p, _ := newPool(t)

	material := []byte("compromised-token")
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "fullstory:prod", Kind: "fullstory", Tenant: "acme", Residency: "eu",
		CredentialVersion: "v#1", Credential: connector.Secret(material),
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	call := holdOpen(t, p, tgt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, _ := p.Revoke(ctx, tgt.Ref(), "test")

	if w.Cancelled != 1 {
		t.Errorf("Withdrawal.Cancelled = %d, want 1. This is the number an incident "+
			"review asks for and nothing else can reconstruct (D106)", w.Cancelled)
	}
	if w.Stragglers != 0 {
		t.Errorf("%d straggler(s); the callback honours its context, so the drain "+
			"should have completed immediately", w.Stragglers)
	}

	err = call.wait()
	if err == nil {
		t.Fatal("the in-flight call completed successfully after its credential was " +
			"revoked — nothing was cancelled")
	}

	// THE POINT. The driver returned context.Canceled; the record must not.
	if fault.KindOf(err) != fault.KindDenied {
		t.Errorf("the cancelled call reported %v (kind %v), want kind %v. The driver "+
			"cannot know why its context died, so if the pool does not restore the "+
			"reason the audit row says the connection dropped — the same lie as the "+
			"all-zeros credential producing 'the target returned 401' (D106)",
			err, fault.KindOf(err), fault.KindDenied)
	}
	if errors.Is(err, context.Canceled) {
		t.Error("the raw context.Canceled reached the caller; an ordinary client " +
			"hang-up is indistinguishable from a break-glass revocation at that point")
	}
	if fault.KindOf(err).Retryable() {
		t.Error("a revoked call reported retryable; a driver's retry loop would " +
			"immediately re-resolve a credential somebody just revoked")
	}
	if !fault.KindOf(err).Deliberate() {
		t.Error("a revocation classified as a FAILURE rather than a deliberate " +
			"refusal, so it logs at WARN beside a target being down (D125)")
	}

	// New work is refused too, or revocation would only stop what it caught.
	if err := p.Do(context.Background(), tgt, func(context.Context, any) error {
		t.Error("a call ran against a revoked credential")
		return nil
	}); fault.KindOf(err) != fault.KindDenied {
		t.Errorf("a new call after revocation returned %v, want kind %v", err, fault.KindDenied)
	}

	waitFor(t, func() bool { return bytes.Equal(material, make([]byte, len(material))) },
		"the revoked credential was never zeroed")
}

// step11SeveritiesDiffer is the guard against the two verbs collapsing into one.
//
// They are adjacent in the vocabulary, they share a refusal kind, and the
// gentler one is a strict subset of the harder one's behaviour — which is
// exactly the shape somebody later "simplifies" by aliasing them. The
// difference that matters is a single row of §4.7.10's table, so that row is
// what gets asserted, on the same pool, with the same driver, in the same test.
func step11SeveritiesDiffer(t *testing.T) {
	run := func(t *testing.T, withdraw func(*pool.Pool, connector.Target) pool.Withdrawal) error {
		t.Helper()

		p, _ := newPool(t)
		tgt := targetWith(t, "v#1", "material")
		call := holdOpen(t, p, tgt)

		w := withdraw(p, tgt)

		// Either way, NEW work must be refused. That half is common to both
		// severities and asserting it here stops a "difference" being found in
		// the wrong place.
		if err := p.Do(context.Background(), tgt, func(context.Context, any) error {
			return nil
		}); fault.KindOf(err) != fault.KindDenied {
			t.Errorf("after %v a new call returned %v, want kind %v", w.Severity, err,
				fault.KindDenied)
		}

		call.finish()
		return call.wait()
	}

	quarantined := run(t, func(p *pool.Pool, tgt connector.Target) pool.Withdrawal {
		w, _ := p.Quarantine(context.Background(), tgt.Ref(), "test")
		if w.Cancelled != 0 {
			t.Errorf("quarantine reported %d cancelled; it must cancel nothing", w.Cancelled)
		}
		if w.LeftRunning != 1 {
			t.Errorf("quarantine reported %d left running, want 1 — an operator "+
				"quarantining during an incident needs to know work is still out there",
				w.LeftRunning)
		}
		return w
	})
	if quarantined != nil {
		t.Errorf("quarantine disturbed a call already in flight: %v. §4.7.10 lets those "+
			"finish; cancelling them makes quarantine an alias for revocation and "+
			"leaves no gentler option for a merely misbehaving target", quarantined)
	}

	revoked := run(t, func(p *pool.Pool, tgt connector.Target) pool.Withdrawal {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		w, _ := p.Revoke(ctx, tgt.Ref(), "test")
		if w.Cancelled != 1 {
			t.Errorf("revocation reported %d cancelled, want 1", w.Cancelled)
		}
		return w
	})
	if fault.KindOf(revoked) != fault.KindDenied {
		t.Errorf("revocation let an in-flight call finish (got %v); the two severities "+
			"are the same verb twice and a compromised credential has no hard stop",
			revoked)
	}
}

var _ = []func(*testing.T){
	step39DemoDrivesALiveInstance,
	step4RotationPinned, step5RotationTracking, step6SupersededIsEvicted,
	step7WipeOnEviction, step8EvictionNeverRacesInFlight,
	step9RevocationCancelsInFlight, step11SeveritiesDiffer,
}

// step39DemoDrivesALiveInstance guards the defect this step was written after
// (D115).
//
// `make demo` set SEKIZUI_ACCEPTANCE_TARGET and SEKIZUI_ACCEPTANCE_CERTS for two
// days while NOTHING read them, so it silently ran the ordinary in-process suite
// and reported success. A target that claims to drive a live instance and does
// not is worse than no target, because it gets quoted as evidence.
//
// The defect was a DISCONNECT between two files, so the guard compares them: every
// SEKIZUI_* variable the demo target sets must be read by the harness. Simpler
// and stricter than exercising the code path, and it catches the exact failure —
// a renamed variable, or a Makefile written against an intention.
func step39DemoDrivesALiveInstance(t *testing.T) {
	// THROUGH docref (D185). `moduleRoot` was this package's SECOND walk up to
	// go.mod, alongside `repoRoot` twenty lines away in another file — and a
	// Makefile target is exactly the case `Between` exists for, since a make
	// target has no heading level to derive an end from.
	makefile := mustDoc(t, "Makefile")
	target := mustText(t, makefile.Between("\ndemo:", "\n.PHONY"))

	set := regexp.MustCompile(`(SEKIZUI_[A-Z_]+)=`).FindAllStringSubmatch(target, -1)
	if len(set) == 0 {
		t.Fatal("the demo target sets no SEKIZUI_* variables, so it cannot be aiming " +
			"the harness anywhere")
	}

	harness := mustText(t, mustDoc(t, "internal/acceptance/acceptance_test.go"))

	assertDevCertsCoverEveryPrincipal(t, mustText(t, makefile))

	for _, m := range set {
		name := m[1]
		if name == "SEKIZUI_ACCEPT_TOK" {
			continue // consumed by the configuration, not the harness
		}
		if !strings.Contains(harness, name) {
			t.Errorf("`make demo` sets %s and the harness never reads it. That is exactly "+
				"how this target spent two days reporting success while running the "+
				"in-process suite.", name)
		}
	}
}

// assertDevCertsCoverEveryPrincipal is the second half of step 39, and it comes
// from the same defect wearing different clothes.
//
// `make demo` failed with: "dev/certs has no certificate for operator:oncall,
// agent:binding. Regenerate with: make dev-certs". The diagnosis was right and
// THE REMEDY DID NOT WORK — `dev-certs` had its own hardcoded principal list,
// so regenerating produced the same five identities and the same failure. Two
// files describing one set, drifting the moment a step added a principal.
//
// An error naming a remedy that does not fix anything is worse than an error
// naming none: it sends an operator round a loop that cannot terminate. So the
// two lists are compared here rather than trusted to stay aligned, which is the
// same treatment step 39 gives the demo target's environment variables.
func assertDevCertsCoverEveryPrincipal(t *testing.T, makefile string) {
	t.Helper()

	from := strings.Index(makefile, "\ndev-certs:")
	if from < 0 {
		t.Fatal("no `dev-certs` target in the Makefile, so nothing issues the " +
			"identities the demo needs")
	}
	target := makefile[from:]
	// +1 because end is an index into target[1:]. Without it the slice cuts one
	// character short — which here removed the closing quote of the principals
	// list and made the regex below match nothing, reporting "passes no
	// -principals list" about a target that plainly does.
	if end := strings.Index(target[1:], "\n\n"); end > 0 {
		target = target[:end+1]
	}

	m := regexp.MustCompile(`-principals\s+"([^"]+)"`).FindStringSubmatch(target)
	if m == nil {
		t.Fatal("the dev-certs target passes no -principals list")
	}

	issued := map[string]bool{}
	for _, p := range strings.Split(m[1], ",") {
		issued[strings.TrimSpace(p)] = true
	}

	var missing []string
	for _, p := range acceptancePrincipals {
		if !issued[p] {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		t.Errorf("`make dev-certs` issues no certificate for %s, but the acceptance run "+
			"acts as %s.\n\nAgainst a live instance the run fails and tells the operator "+
			"to run `make dev-certs` — which regenerates the same list and fails "+
			"identically. Add them to the -principals list in the Makefile.",
			strings.Join(missing, ", "), strings.Join(missing, ", "))
	}

	// Non-vacuity: an issued principal nobody uses is dead configuration, and a
	// certificate is not free — it is an identity the CA vouches for.
	used := map[string]bool{}
	for _, p := range acceptancePrincipals {
		used[p] = true
	}
	for p := range issued {
		if !used[p] {
			t.Errorf("`make dev-certs` issues a certificate for %q that the acceptance "+
				"run never presents. Either a step is missing or the identity is", p)
		}
	}
}
