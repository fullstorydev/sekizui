package acceptance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/limiter"
	"github.com/fullstorydev/sekizui/internal/retry"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// step62TargetLimitsComeFromConfigBoundedByACeiling proves D142.
//
// Two halves, and the second is the one with teeth. A target may NARROW the
// deployment's operational limits — that is what makes changing a backoff an
// edit rather than a redeploy, which is §4.7.10's objection to break-glass
// applied to the knobs beside it. A target that tries to EXCEED them is refused
// at boot rather than silently clamped, because a target quietly given less than
// it asked for is a target whose operator believes something false, and the
// belief survives until an incident tests it (D108's ruling on max_lifetime).
//
// The third arm is the one reasoning gets wrong: "narrow" means LESS LOAD ON THE
// UPSTREAM, not a smaller number, and for the breaker cooldown that means
// LARGER. Three of the four bounds are ceilings and one is a floor.
func step62TargetLimitsComeFromConfigBoundedByACeiling(t *testing.T) {
	ctx := context.Background()

	deployment := config.OperationalBounds{
		RetryAttempts:   3,
		RetryCap:        5 * time.Second,
		BreakerTrip:     5,
		BreakerCooldown: 30 * time.Second,
	}

	// --- 62a: A TARGET NARROWS THE BREAKER, AND IT IS HONOURED --------------
	//
	// Non-vacuity is built in: the same breaker, same clock, same failure
	// sequence, and only the target ref differs. Without the second half this
	// would pass against a breaker that ignored the override and tripped early
	// for everyone.
	t.Run("a target narrows the breaker trip", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		b := limiter.NewBreaker(deployment.BreakerTrip, deployment.BreakerCooldown,
			limiter.WithBreakerClock(clock.Now),
			limiter.WithTargetBounds(map[string]limiter.Bounds{
				"kata:tetchy": {Trip: 2},
			}))

		b.Record("kata:tetchy", false)
		if !b.Allow("kata:tetchy") {
			t.Fatal("the narrowed breaker opened after ONE failure, before its trip of 2")
		}
		b.Record("kata:tetchy", false)
		if b.Allow("kata:tetchy") {
			t.Error("kata:tetchy declares breaker_trip: 2 and survived two consecutive " +
				"failures — the deployment's 5 is still in force, so the config field " +
				"parses and does nothing, which is the defect D142 refused to commit")
		}

		for i := range 4 {
			b.Record("kata:alpha", false)
			if !b.Allow("kata:alpha") {
				t.Fatalf("kata:alpha declares no limits and opened after %d failures; "+
					"it must follow the deployment's trip of 5", i+1)
			}
		}
		b.Record("kata:alpha", false)
		if b.Allow("kata:alpha") {
			t.Error("kata:alpha never opened at the deployment trip of 5, so 62a would " +
				"pass against a breaker that never trips at all")
		}
	})

	// --- 62b: A TARGET NARROWS RETRY, AND IT IS HONOURED --------------------
	t.Run("a target narrows retry attempts", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		policy := retry.Policy{
			MaxAttempts: deployment.RetryAttempts,
			Base:        200 * time.Millisecond,
			Cap:         deployment.RetryCap,
			Budget:      30 * time.Second,
		}
		r := retry.New(policy,
			retry.WithClock(clock.Now, clock.Sleep),
			retry.WithTargetPolicies(map[string]retry.Policy{
				// A target that wants NO retries says 1, not 0 — zero means
				// "use the deployment default", so a target unable to say 1
				// could not express the thing most likely to be wanted.
				"kata:fragile": {MaxAttempts: 1, Base: policy.Base, Cap: policy.Cap, Budget: policy.Budget},
			}))

		failing := func(context.Context) error {
			return &fault.Error{Kind: fault.KindRateLimited, Op: "upstream", Msg: "429"}
		}

		if n, _ := r.For("kata:fragile").Do(ctx, retry.Retryable, failing); n != 1 {
			t.Errorf("kata:fragile declares retry_attempts: 1 and made %d attempts. A "+
				"target that says it must not be retried and is retried anyway is the "+
				"D113 hazard reintroduced through configuration", n)
		}
		if n, _ := r.For("kata:alpha").Do(ctx, retry.Retryable, failing); n != 3 {
			t.Errorf("kata:alpha declares no limits and made %d attempts, want the "+
				"deployment's 3 — without this, 62b passes against a Runner that never "+
				"retries anything", n)
		}
	})

	// --- 62c: THE INVERTED BOUND, HONOURED IN THE RIGHT DIRECTION ----------
	//
	// A LONGER cooldown probes a dead target less often, so it is the GENTLER
	// setting. This arm exists because the natural reading of "a ceiling a
	// target may only narrow" makes every field smaller, and applying that here
	// would let a target probe a dead upstream harder than the deployment
	// permits while every check still read as "within the limit".
	t.Run("a target raises the breaker cooldown", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		b := limiter.NewBreaker(deployment.BreakerTrip, deployment.BreakerCooldown,
			limiter.WithBreakerClock(clock.Now),
			limiter.WithTargetBounds(map[string]limiter.Bounds{
				"kata:slowheal": {Cooldown: 5 * time.Minute},
			}))

		for range deployment.BreakerTrip {
			b.Record("kata:slowheal", false)
			b.Record("kata:alpha", false)
		}

		// Past the DEPLOYMENT's 30s cooldown and well short of the target's 5m.
		clock.now = clock.now.Add(time.Minute)

		if b.Allow("kata:slowheal") {
			t.Error("kata:slowheal declares breaker_cooldown_s: 300 and admitted a probe " +
				"after 60s. Treating cooldown as a ceiling like the other three would " +
				"make a target's own caution unexpressable and probe a dead upstream " +
				"harder than the deployment allows")
		}
		if !b.Allow("kata:alpha") {
			t.Error("kata:alpha declares no limits and admitted no probe after 60s, " +
				"past the deployment cooldown of 30s — so 62c would pass against a " +
				"breaker that never half-opens")
		}
	})

	// --- 62d: EXCEEDING IS REFUSED AT BOOT, NAMED, NOT CLAMPED -------------
	assertExceedingLimitsRefused(t, deployment)
}

// assertExceedingLimitsRefused covers all four bounds, in both directions.
//
// ALL FOUR IN ONE TABLE, because the failure this guards is a field somebody
// added to the struct and forgot to check — the same shape as the four fields
// D142 refused to ship early. A table that walks every bound makes the omission
// visible as a missing row rather than as nothing at all.
func assertExceedingLimitsRefused(t *testing.T, b config.OperationalBounds) {
	t.Helper()

	cases := []struct {
		name   string
		limits config.TargetLimits
		want   string
	}{
		{
			name:   "more attempts than the deployment permits",
			limits: config.TargetLimits{RetryAttempts: 10},
			want:   "retry_attempts",
		},
		{
			name:   "a longer single backoff than the deployment permits",
			limits: config.TargetLimits{RetryCapMs: 60_000},
			want:   "retry_cap_ms",
		},
		{
			name:   "tolerating more failures before withdrawing",
			limits: config.TargetLimits{BreakerTrip: 50},
			want:   "breaker_trip",
		},
		{
			// THE INVERTED ONE. Lower is more aggressive, so this is the value
			// BELOW the floor rather than above a ceiling.
			name:   "probing a dead target more often than the deployment permits",
			limits: config.TargetLimits{BreakerCooldownS: 1},
			want:   "breaker_cooldown_s",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := &config.Document{Targets: []config.TargetSpec{
				{Ref: "kata:greedy", Kind: "kata", Limits: &c.limits},
			}}

			bad := config.ExceedingTargets(doc, b)
			if len(bad) == 0 {
				t.Fatalf("kata:greedy declares %+v and boot accepted it. Silently "+
					"clamping is the failure D108 named: the operator believes a "+
					"number the deployment is not honouring", c.limits)
			}
			why := strings.Join(bad["kata:greedy"], "; ")
			if !strings.Contains(why, c.want) {
				t.Errorf("the refusal does not name %s: %q. An operator cannot fix a "+
					"limit the message does not identify", c.want, why)
			}

			// NOT CLAMPED. The document must be left exactly as written — a
			// check that repaired the value would make the refusal cosmetic and
			// the next boot silently different from this one.
			if got := *doc.Targets[0].Limits; got != c.limits {
				t.Errorf("the check MUTATED the target's limits: %+v became %+v. "+
					"Refusing and repairing are different answers, and doing both "+
					"means the error message describes a document that no longer exists",
					c.limits, got)
			}
		})
	}

	// --- NON-VACUITY -------------------------------------------------------
	//
	// Every row above is satisfied by a function that refuses everything.
	t.Run("a target narrowing every bound is accepted", func(t *testing.T) {
		doc := &config.Document{Targets: []config.TargetSpec{{
			Ref: "kata:polite", Kind: "kata",
			Limits: &config.TargetLimits{
				RetryAttempts:    1,
				RetryCapMs:       1_000,
				BreakerTrip:      2,
				BreakerCooldownS: 300,
			},
		}}}
		if bad := config.ExceedingTargets(doc, b); len(bad) > 0 {
			t.Errorf("a target narrowing every bound was refused: %v. If narrowing is "+
				"refused there is no way to use these fields at all", bad)
		}
	})

	// A target declaring NOTHING conforms trivially, which is what keeps every
	// pre-D142 configuration booting unchanged.
	t.Run("a target declaring no limits conforms", func(t *testing.T) {
		doc := &config.Document{Targets: []config.TargetSpec{{Ref: "kata:alpha", Kind: "kata"}}}
		if bad := config.ExceedingTargets(doc, b); len(bad) > 0 {
			t.Errorf("a target with no limits block was refused: %v", bad)
		}
	})
}
