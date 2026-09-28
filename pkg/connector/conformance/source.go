package conformance

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/connector"
)

// SourceCase describes the source under test.
type SourceCase struct {
	// Target the suite polls. It must have at least two events available from
	// the zero cursor, or the arms below pass vacuously and report coverage
	// they do not have.
	Target connector.Target

	// Limit the first poll asks for. Must be at least 1 and SMALLER than what
	// the target has available, so progress can be observed at all.
	Limit int

	// Tenant is the tenant the suite polls as. It must match Target's, because
	// a driver that asserts the tenant on reads (§6 mechanism 3, and D155 says
	// it must) will otherwise refuse every call and the arms fail for the
	// wrong reason.
	//
	// **THE SUITE BUILDS THE CONTEXT RATHER THAN TAKING ONE, and that is not a
	// convenience.** The first version of this took no tenant, so the
	// reference connector wrapped itself in an adapter to supply one — and the
	// adapter REPLACED the suite's context instead of deriving from it, which
	// silently discarded the cancellation `runSourceCancelled` exists to test.
	// The arm caught it, which is the suite working; but every author would
	// have written the same adapter, and a suite that makes the wrong thing
	// the easy thing is a suite that ships the defect.
	Tenant string

	// Pool is a spy the driver under test MUST have been constructed with, so
	// the suite can see whether the poll borrowed a client (D255).
	//
	// **REQUIRED, AND A CONCRETE TYPE RATHER THAN `connector.ClientPool`.** An
	// optional field would make the arm skip when it is absent, and "a skipped
	// arm in a mandatory suite is one nobody notices missing" — which is
	// exactly how this obligation went unchecked in the first place. The
	// concrete type is what stops an author satisfying the field with their
	// own pool and learning nothing.
	//
	// **WHAT IT PROVES IS NOT TIDINESS.** `revoke_credential` cancels the
	// contexts the POOL is holding. A source that dials privately is holding
	// none, so break-glass evicts an empty set and truthfully reports
	// cancelling nothing while the poll keeps running on a credential an
	// operator has just declared compromised — and a poll repeats on a timer.
	// The reference DRIVER had this defect while the reference CONNECTOR did
	// not, and this suite passed both.
	Pool *PoolSpy
}

// PoolSpy is a `connector.ClientPool` that records whether it was used.
//
// **THE SUITE CANNOT SUPPLY THIS ITSELF, and that is the awkward part of the
// contract rather than a flaw in it.** `RunSource` receives a driver that is
// already built, so the pool has to be wired in at CONSTRUCTION by the author:
//
//	spy := conformance.NewPoolSpy()
//	drv := mydriver.New(mydriver.WithPool(spy))
//	conformance.RunSource(t, drv, conformance.SourceCase{..., Pool: spy})
//
// An author who wires a different pool, or none, fails the arm. **FAILING
// CLOSED IS THE POINT**: the suite cannot tell "wired a pool I cannot see"
// from "dialled privately", and those must not be distinguishable, because the
// second is the defect and the first is indistinguishable from it at runtime
// too.
type PoolSpy struct {
	mu       sync.Mutex
	borrowed int
}

// NewPoolSpy returns a pool that runs the work and counts the borrow.
func NewPoolSpy() *PoolSpy { return &PoolSpy{} }

// Do runs fn with a nil client, exactly as a pool does for a driver that needs
// no client object, and records that the borrow happened.
//
// THE CONTEXT IS PASSED THROUGH UNCHANGED. A spy that substituted its own
// would hide the very mistake `ClientPool.Do`'s doc warns about — a driver
// passing its own context to the outbound call instead of the borrowed one.
func (p *PoolSpy) Do(ctx context.Context, _ connector.Target,
	fn func(ctx context.Context, client any) error) error {

	p.mu.Lock()
	p.borrowed++
	p.mu.Unlock()
	return fn(ctx, nil)
}

// Borrows reports how many times a client was taken.
func (p *PoolSpy) Borrows() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.borrowed
}

// pollCtx is the one place a tenant is attached, derived from the caller's
// context so cancellation and deadlines survive.
func pollCtx(ctx context.Context, c SourceCase) context.Context {
	if c.Tenant == "" {
		return ctx
	}
	return connector.WithTenant(ctx, c.Tenant)
}

// RunSource asserts the contract a `connector.Source` must satisfy.
//
// **EXPLICITLY SELECTED, NOT FOLDED INTO `Run`**, for the reason `RunHTTP` is
// separate and which D160 learned the hard way: most drivers are write-only
// (§4.6.5's sinks, every actuator), and a universal suite would either fail
// them for not being a source or quietly skip the half that matters. A suite
// that cannot fail for the shape it is aimed at is decoration.
//
// **THE RESPONSE CHECKS ARE NOT REIMPLEMENTED HERE.** They are
// `connector.ValidatePoll`, which the POLLER also calls on every tick — one
// definition of conforming, two callers, because CONTRACTS 93 is what two
// statements cost. What this file adds is everything a single response cannot
// show: progress across polls, whether a declared recovery policy is TRUE, and
// whether the driver honours a cancelled context.
//
// Usage, from a driver's own package:
//
//	func TestSourceConformance(t *testing.T) {
//	    conformance.RunSource(t, myDriver, conformance.SourceCase{
//	        Target: aTargetWithData, Limit: 2,
//	    })
//	}
func RunSource(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()

	if c.Limit < 1 {
		t.Fatal("SourceCase.Limit must be at least 1; a suite that asks for nothing " +
			"proves nothing about a source that returns nothing")
	}
	if c.Pool == nil {
		t.Fatal("SourceCase.Pool is required: construct the driver with a " +
			"conformance.NewPoolSpy() and pass the same spy here. Without it the " +
			"borrow arm cannot run, and an arm that skips is one nobody notices " +
			"missing")
	}

	runSourceBorrows(t, s, c)
	runSourceIsAdvertised(t, s, c)
	runSourceTypesDeclared(t, s, c)
	runSourceConformsToItsSchema(t, s, c)
	runSourceResponse(t, s, c)
	runSourceTenantAsserted(t, s, c)
	runSourceProgress(t, s, c)
	runSourceRecoveryIsTrue(t, s, c)
	runSourceCancelled(t, s, c)
}

// runSourceResponse is ValidatePoll, run against a real response.
func runSourceResponse(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()
	t.Run("the response conforms", func(t *testing.T) {
		events, next, err := s.Poll(pollCtx(context.Background(), c), c.Target, "", c.Limit)
		if err != nil {
			t.Fatalf("polling a healthy target from the zero cursor failed: %v", err)
		}
		// NON-VACUITY. Every arm below asks a question about events, and a
		// target with none answers all of them by accident.
		if len(events) < 2 {
			t.Fatalf("SourceCase.Target returned %d events from the zero cursor. This "+
				"suite needs at least two to observe anything, and a case that supplies "+
				"an empty source passes every arm without exercising one", len(events))
		}
		for _, v := range connector.ValidatePoll("", c.Limit, events, next) {
			t.Errorf("%s", v)
		}
	})
}

// runSourceBorrows requires the poll to take its client from the pool (D255).
//
// **A POLLER WITH A PRIVATE CLIENT IS INVISIBLE TO REVOCATION**, which is the
// whole of it. `revoke_credential` cancels the contexts the POOL is holding;
// a source that dialled privately is holding none, so break-glass evicts an
// empty set for that target, truthfully reports cancelling nothing, and the
// poll carries on against a credential an operator has just declared
// compromised. **A poll repeats on a timer, so the window is not one call.**
//
// **THIS ARM EXISTS BECAUSE THE REFERENCE DRIVER FAILED IT AND THIS SUITE
// PASSED IT ANYWAY.** `kata` did not borrow and `hako/solution` did, so the
// worked form in the blueprint was right while the driver everybody copies
// was wrong, for as long as the suite had nothing to say about it. That is
// CONTRACTS 93's shape — an obligation on a third party the published suite
// cannot check — and D35 makes the harmed population an out-of-tree author
// who passes here and is refused at deploy, or worse, is not.
//
// ASSERTED AFTER A REAL POLL rather than by inspecting the driver, because
// "has a pool field" and "uses it on this path" are different claims and only
// the second one matters: `Execute` borrowing proves nothing about `Poll`.
func runSourceBorrows(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()
	t.Run("the poll borrows its client from the pool", func(t *testing.T) {
		before := c.Pool.Borrows()
		if _, _, err := s.Poll(pollCtx(context.Background(), c), c.Target, "", c.Limit); err != nil {
			t.Fatalf("polling a healthy target failed: %v", err)
		}
		if c.Pool.Borrows() == before {
			t.Fatal("the poll did not borrow a client from the pool.\n\n" +
				"Wrap the outbound call in `pool.Do(ctx, target, work)` and give the " +
				"work the context the POOL hands it, not your own. A source that " +
				"dials privately cannot be stopped by `revoke_credential`: break-glass " +
				"cancels the contexts the pool is holding, finds none for this target, " +
				"and reports cancelling nothing while the poll keeps running on the " +
				"compromised credential — every tick, until somebody restarts the " +
				"process.\n\n" +
				"If this suite is reporting a driver you believe does borrow, check " +
				"that the spy in SourceCase.Pool is the SAME one the driver was " +
				"constructed with.")
		}
	})
}

// runSourceIsAdvertised requires the poll to appear in Actions().
//
// **IMPLEMENTED-BUT-UNADVERTISED IS THE INVERSE OF THE DEFECT THE DRIVER SUITE
// ALREADY CATCHES**, and it is just as fatal: `runActions` stops a driver
// advertising something it cannot do, and this stops one doing something
// nobody can be granted. A grant naming an action no driver implements cannot
// load (D196), so a Source absent from `Actions()` is a Source no deployment
// can authorise — it compiles, it conforms to every other arm, and it is
// unreachable.
//
// The catalog is the other reason: it is what tells an operator which targets
// are pollable and who may poll them, and it is generated from `Actions()`.
func runSourceIsAdvertised(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()
	t.Run("the poll is advertised in Actions", func(t *testing.T) {
		d, ok := s.(connector.Driver)
		if !ok {
			t.Fatal("this Source is not also a Driver. A target routes to a driver by " +
				"kind, so a Source that is not one can never be reached")
		}
		want := d.Kind() + ".poll"
		for _, spec := range d.Actions() {
			if spec.Name != want {
				continue
			}
			if spec.Mutating {
				t.Errorf("%q is declared mutating; a poll is a read, and declaring it "+
					"otherwise forces an idempotency key onto something that has no effect", want)
			}
			return
		}
		t.Errorf("this driver implements Source and does not advertise %q. A grant "+
			"naming an action no driver implements cannot load (D196), so nobody can "+
			"be authorised to poll it — the capability exists and is unreachable", want)
	})
}

// runSourceTypesDeclared requires the poll to DECLARE what it yields, and
// every event it returns to carry one of those types (D276).
//
// **THE DECLARATION IS WHAT MAKES A SOURCE GOVERNABLE, NOT A CATALOG NICETY.**
// A shin lens names an envelope type; an anzen detector and a reflex's
// `expects_type` name one; `payload_schemas` is keyed on one. A type nobody
// declared is a type none of them can name, so its events would reach the bus
// unlensed and unvalidated. The runner refuses them per event at runtime — this
// arm is where an author learns that before a deployment does, by losing them.
//
// DECLARED IS NECESSARY BUT THE EVENTS ARE THE PROOF: "the poll action has an
// OutputType" and "Poll emits that type" are two claims, and a driver that
// declares one type and stamps another passes the first alone.
func runSourceTypesDeclared(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()
	t.Run("every polled type is declared", func(t *testing.T) {
		d, ok := s.(connector.Driver)
		if !ok {
			t.Fatal("this Source is not also a Driver, so it has no Actions to declare its types in")
		}
		var declared []string
		for _, spec := range d.Actions() {
			if spec.Name == d.Kind()+".poll" {
				declared = spec.DeclaredOutputs()
			}
		}
		if len(declared) == 0 {
			t.Fatalf("%s.poll declares no output type (OutputType or OutputTypes). Every "+
				"event a poll yields is refused unless its type is declared (D276), because "+
				"a lens, a detector and a payload schema can only name a declared type", d.Kind())
		}
		events, _, err := s.Poll(pollCtx(context.Background(), c), c.Target, "", c.Limit)
		if err != nil {
			t.Fatalf("polling a healthy target failed: %v", err)
		}
		for _, ev := range events {
			if !slices.Contains(declared, ev.Type) {
				t.Errorf("event %q has type %q, which %s.poll does not declare (declared: %v). "+
					"The runner refuses it and it never reaches the bus", ev.ID, ev.Type, d.Kind(), declared)
			}
		}
	})
}

// runSourceTenantAsserted requires a poll carrying the WRONG tenant to be
// refused before it reaches the far side.
//
// **THE SOURCE HALF OF §6 MECHANISM 3, AND IT WAS MISSING UNTIL THE KATA'S
// EXERCISE WENT LOOKING FOR IT.** `runTenantAsserted` covers `Execute`;
// nothing covered `Poll`, so a source that skipped the assertion passed this
// suite cleanly. That is exactly the hole D155 describes — a read path
// acquiring an abbreviated copy of the checks one omission at a time, each
// invisible because the shorter path reads like a shorter version rather than
// a weaker one — arriving on the afferent plane, in the published contract, in
// the artefact written to teach it.
//
// D233's lesson again: the only honest test of a reusable artefact is its
// second, real user. Here the user was an exercise built to fail, and the gap
// it exposed was in the suite rather than in the learner's code.
func runSourceTenantAsserted(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()
	t.Run("a poll carrying the wrong tenant is refused", func(t *testing.T) {
		if c.Tenant == "" {
			t.Skip("SourceCase.Tenant is empty, so there is no right tenant to differ from")
		}
		// A TENANT THE TARGET IS NOT BOUND TO. Derived from the real one so it
		// cannot accidentally BE the real one.
		wrong := connector.WithTenant(context.Background(), c.Tenant+"-not")

		events, _, err := s.Poll(wrong, c.Target, "", c.Limit)
		if err == nil {
			t.Fatalf("polled as tenant %q against a target bound to %q and returned %d "+
				"events. A read is not exempt from the egress assertion — one enforcement "+
				"path, not two", c.Tenant+"-not", c.Tenant, len(events))
		}
		if len(events) > 0 {
			t.Errorf("refused the mismatched tenant AND returned %d events", len(events))
		}
	})
}

// runSourceProgress polls twice and requires the second window to be new.
//
// **WHAT ONE RESPONSE CANNOT SHOW.** `ValidatePoll` catches a cursor handed
// straight back, which is the stall in its blatant form. The quieter one is a
// cursor that CHANGES on every poll and addresses the same rows anyway — a
// source that returns the first page for ever while its cursor counts upwards.
// Same consequence, and only two polls can see it.
func runSourceProgress(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()
	t.Run("a second poll makes progress", func(t *testing.T) {
		ctx := context.Background()
		first, next, err := s.Poll(pollCtx(ctx, c), c.Target, "", c.Limit)
		if err != nil {
			t.Fatalf("first poll: %v", err)
		}
		if len(first) == 0 {
			t.Fatal("no events from the zero cursor; see the non-vacuity note above")
		}

		second, _, err := s.Poll(pollCtx(ctx, c), c.Target, next, c.Limit)
		if err != nil {
			t.Fatalf("polling from the cursor you returned failed: %v — a cursor a source "+
				"mints must be one it accepts", err)
		}

		seen := make(map[string]bool, len(first))
		for _, e := range first {
			seen[e.ID] = true
		}
		for _, e := range second {
			if seen[e.ID] {
				t.Errorf("id %q was returned again after the cursor advanced. The cursor "+
					"moved and the window did not, so a poller re-ingests the same rows "+
					"for ever while every log line reports a healthy poll", e.ID)
			}
		}
	})
}

// runSourceRecoveryIsTrue checks the DECLARATION against the behaviour.
//
// **A DECLARATION NOBODY CHECKS IS A CLAIM, and this one decides whether the
// spine writes a gap marker or re-polls** (D174, D241). Neither answer is
// skipped: `RecoveryRequery` owes the same window twice, and `RecoveryUnable`
// owes a `Why` that names the thing to change, because it lands in the gap
// marker an operator reads. **There is no branch here that asserts nothing**,
// which is the failure D160 found when a suite let a provider opt out.
func runSourceRecoveryIsTrue(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()
	t.Run("the declared recovery policy is true", func(t *testing.T) {
		p := s.Recovery(c.Target)

		if p.Mode == connector.RecoveryUnable {
			if strings.TrimSpace(p.Why) == "" {
				t.Error("declared RecoveryUnable with no Why. It lands in the gap marker, " +
					"which exists so somebody can act on the loss — \"recovery impossible\" " +
					"names a state, not the thing to change")
			}
			return
		}

		ctx := context.Background()
		first, next, err := s.Poll(pollCtx(ctx, c), c.Target, "", c.Limit)
		if err != nil {
			t.Fatalf("first poll: %v", err)
		}
		again, nextAgain, err := s.Poll(pollCtx(ctx, c), c.Target, "", c.Limit)
		if err != nil {
			t.Fatalf("re-polling the same cursor failed, having declared it re-queryable: %v", err)
		}
		if next != nextAgain || len(first) != len(again) {
			t.Fatalf("declared RecoveryRequery and the same cursor returned a different "+
				"window: %d events -> %q, then %d events -> %q. The spine will re-poll "+
				"after a crash on the strength of that declaration",
				len(first), next, len(again), nextAgain)
		}
		for i := range first {
			if first[i].ID != again[i].ID {
				t.Errorf("declared RecoveryRequery and row %d differs between polls: %q then %q",
					i, first[i].ID, again[i].ID)
			}
		}
	})
}

// runSourceCancelled requires a cancelled context to stop the poll.
//
// **D160 FOUND EXACTLY THIS AND IT IS WHY THE PROVIDER SUITE EARNED ITS KEEP ON
// THE FIRST RUN:** `file` and `ambient` both ignored a cancelled context while
// `EnvProvider` honoured it. Here it is worse than untidy — the spine's per-poll
// deadline IS a cancelled context, so a source that ignores one cannot be
// bounded by the thing that exists to bound it, and a shutdown waits for a
// vendor that is not coming back.
func runSourceCancelled(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()
	t.Run("a cancelled context stops the poll", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		events, _, err := s.Poll(pollCtx(ctx, c), c.Target, "", c.Limit)
		if err == nil {
			t.Fatalf("polled with an already-cancelled context and returned %d events and "+
				"no error. The spine's per-poll deadline is delivered as a cancelled "+
				"context, so a source that ignores one cannot be bounded", len(events))
		}
		if len(events) > 0 {
			t.Errorf("returned %d events alongside the cancellation error; a caller that "+
				"checks the error first will never see them, and one that does not will "+
				"ingest a partial window as though it were whole", len(events))
		}
	})
}
