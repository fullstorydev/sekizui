package acceptance

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// lifetimeTarget builds a Target for the pool, with a distinct credential
// version so a rotation can be simulated separately from an expiry.
func lifetimeTarget(t *testing.T, ref, credVer string) connector.Target {
	t.Helper()

	target, err := connector.NewTarget(connector.TargetParams{
		Ref: ref, Kind: "kata", Tenant: "lifetime",
		BaseURL: "https://lifetime.invalid", CredentialVersion: credVer,
	})
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	return target
}

// step29NoPoolEntryOutlivesMaxLifetime proves D108.
//
// **A DIFFERENT KIND OF GUARANTEE FROM THE REST OF §6**, and the step exists to
// assert that difference. Most of this design makes a failure impossible by
// CONSTRUCTION: a Target cannot be built without a tenant, a PoolKey cannot be
// printed, a Decision cannot be published. This one makes a failure BOUNDED IN
// TIME regardless of construction.
//
// Which matters because the thing it backstops is our own code. Content-
// addressing (D99) creates a new pool entry on rotation and does NOT remove the
// old one — the old entry still holds the superseded credential and, for a
// session-oriented target (§4.7.4 class 3), a live authorised session. Explicit
// invalidation closes that, and explicit invalidation is code we wrote and could
// get wrong. This bound holds either way, which is the whole point: **if
// eviction has a bug, nothing survives past the lifetime anyway.**
func step29NoPoolEntryOutlivesMaxLifetime(t *testing.T) {
	ctx := context.Background()

	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }

	var builds atomic.Int32
	p := pool.New(func(context.Context, connector.Target) (any, error) {
		builds.Add(1)
		return "client", nil
	}, quietLogger(),
		pool.WithClock(now),
		pool.WithMaxLifetime(10*time.Minute, nil))

	target := lifetimeTarget(t, "kata:alpha", "v1")
	borrow := func(t *testing.T) {
		t.Helper()
		if err := p.Do(ctx, target, func(context.Context, any) error { return nil }); err != nil {
			t.Fatalf("borrow: %v", err)
		}
	}

	// --- 29a: REUSED WHILE YOUNG -----------------------------------------
	//
	// First, because everything below is satisfied by a pool that rebuilds on
	// every borrow — and a pool that never reuses anything is not a pool.
	borrow(t)
	borrow(t)
	if got := builds.Load(); got != 1 {
		t.Fatalf("builds = %d after two borrows inside the lifetime, want 1; a pool "+
			"that rebuilds every time makes the assertion below meaningless", got)
	}

	// --- 29b: NOT REUSED PAST THE BOUND ----------------------------------
	//
	// A CLOCK SEAM, NOT A SLEEP — P1 exit criterion 12's house rule. A test that
	// waits ten minutes proves the scheduler works; a test that moves the clock
	// proves the policy does.
	clock = clock.Add(10 * time.Minute)
	borrow(t)
	if got := builds.Load(); got != 2 {
		t.Errorf("builds = %d after crossing max_lifetime, want 2. An entry past its "+
			"lifetime was reused, so the one guarantee that does not depend on our "+
			"invalidation path being correct is not in force", got)
	}

	// --- 29c: THE REPLACEMENT IS YOUNG AGAIN -----------------------------
	//
	// Non-vacuity in the other direction: without this, 29b passes against a
	// pool that rebuilds on every borrow AFTER the first expiry, which would be
	// a permanent regression disguised as the feature working.
	borrow(t)
	if got := builds.Load(); got != 2 {
		t.Errorf("builds = %d; the entry built after the expiry was itself discarded, "+
			"so the pool stopped pooling rather than bounding a lifetime", got)
	}

	// --- 29d: A ZERO CEILING MEANS UNBOUNDED ----------------------------
	//
	// The direction that changes nothing for a deployment which has not
	// configured a lifetime, which is every deployment before D108.
	t.Run("no configured lifetime means no expiry", func(t *testing.T) {
		var b atomic.Int32
		unbounded := pool.New(func(context.Context, connector.Target) (any, error) {
			b.Add(1)
			return "client", nil
		}, quietLogger(), pool.WithClock(func() time.Time { return clock }))

		tgt := lifetimeTarget(t, "kata:beta", "v1")
		for range 3 {
			if err := unbounded.Do(ctx, tgt, func(context.Context, any) error { return nil }); err != nil {
				t.Fatalf("borrow: %v", err)
			}
			clock = clock.Add(24 * time.Hour)
		}
		if got := b.Load(); got != 1 {
			t.Errorf("builds = %d with no lifetime configured, want 1 — a zero ceiling "+
				"must mean unbounded, or D108 changes behaviour for every deployment "+
				"that never asked for it", got)
		}
	})
}

// step30ATargetMayNarrowMaxLifetimeButNeverWidenIt proves D108's other half.
//
// THE FOURTH INSTANCE OF THE HOUSE FORM (D71, D59, D84, D108): a bound is set
// once by whoever is accountable for the blast radius, and narrowed per target by
// whoever needs it. Widening is refused at BOOT rather than clamped, because a
// target quietly given less than it asked for is a target whose operator believes
// something false — and the belief survives until an incident tests it.
func step30ATargetMayNarrowMaxLifetimeButNeverWidenIt(t *testing.T) {
	ctx := context.Background()
	bounds := config.OperationalBounds{MaxLifetime: 10 * time.Minute}

	// --- 30a: NARROWING IS HONOURED, AND OBSERVABLY -----------------------
	t.Run("a target's shorter lifetime is applied, not just accepted", func(t *testing.T) {
		clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

		var builds atomic.Int32
		p := pool.New(func(context.Context, connector.Target) (any, error) {
			builds.Add(1)
			return "client", nil
		}, quietLogger(),
			pool.WithClock(func() time.Time { return clock }),
			pool.WithMaxLifetime(10*time.Minute, map[string]time.Duration{
				"kata:brief": time.Minute,
			}))

		brief := lifetimeTarget(t, "kata:brief", "v1")
		patient := lifetimeTarget(t, "kata:patient", "v1")

		for _, tgt := range []connector.Target{brief, patient} {
			if err := p.Do(ctx, tgt, func(context.Context, any) error { return nil }); err != nil {
				t.Fatalf("borrow: %v", err)
			}
		}
		if got := builds.Load(); got != 2 {
			t.Fatalf("builds = %d, want one per target", got)
		}

		// PAST THE TARGET'S MINUTE AND WELL INSIDE THE DEPLOYMENT'S TEN. Only
		// the narrowed target should rebuild — which is what tells a narrowing
		// that is APPLIED from one that merely parsed.
		clock = clock.Add(2 * time.Minute)
		for _, tgt := range []connector.Target{brief, patient} {
			if err := p.Do(ctx, tgt, func(context.Context, any) error { return nil }); err != nil {
				t.Fatalf("borrow: %v", err)
			}
		}
		if got := builds.Load(); got != 3 {
			t.Errorf("builds = %d, want 3: kata:brief declares max_lifetime_s 60 and "+
				"should have been replaced, kata:patient should not. A narrowing that "+
				"parses and does nothing is the defect this codebase has found most "+
				"often", got)
		}
	})

	// --- 30b: WIDENING IS REFUSED AT BOOT, NOT CLAMPED -------------------
	t.Run("a target may not widen the deployment ceiling", func(t *testing.T) {
		limits := config.TargetLimits{MaxLifetimeS: 3600}
		doc := &config.Document{Targets: []config.TargetSpec{
			{Ref: "kata:greedy", Kind: "kata", Limits: &limits},
		}}

		bad := config.ExceedingTargets(doc, bounds)
		if len(bad) == 0 {
			t.Fatal("a target asking for an hour under a ten-minute ceiling was accepted")
		}
		if got := bad["kata:greedy"]; len(got) == 0 ||
			!containsSubstr(got, "max_lifetime_s") {
			t.Errorf("the refusal does not name max_lifetime_s: %v", got)
		}

		// NOT CLAMPED. A check that repaired the value would make the refusal
		// cosmetic and the next boot silently different from this one.
		if doc.Targets[0].Limits.MaxLifetimeS != 3600 {
			t.Error("the check MUTATED the target's limit; refusing and repairing are " +
				"different answers and doing both means the error describes a document " +
				"that no longer exists")
		}
	})

	// --- 30c: NARROWING IS ACCEPTED AT BOOT ------------------------------
	t.Run("a narrower lifetime boots", func(t *testing.T) {
		doc := &config.Document{Targets: []config.TargetSpec{{
			Ref: "kata:polite", Kind: "kata",
			Limits: &config.TargetLimits{MaxLifetimeS: 60},
		}}}
		if bad := config.ExceedingTargets(doc, bounds); len(bad) > 0 {
			t.Errorf("a target narrowing the ceiling was refused: %v. If narrowing is "+
				"refused there is no way to use the field at all", bad)
		}
	})

	_ = ctx
}

// containsSubstr reports whether any element contains want.
func containsSubstr(hay []string, want string) bool {
	for _, h := range hay {
		if len(h) >= len(want) && strings.Contains(h, want) {
			return true
		}
	}
	return false
}
