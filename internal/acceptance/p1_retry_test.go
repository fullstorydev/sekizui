package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/limiter"
	"github.com/fullstorydev/sekizui/internal/retry"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// fakeClock is a clock and a matching sleep, advanced by sleeping rather than by
// waiting.
//
// THE TWO MUST AGREE OR THE TEST IS VACUOUS. A fake clock whose sleep does not
// advance it makes the retry budget check meaningless — every wait costs nothing
// and the budget never runs out — so retry.WithClock takes both together rather
// than offering them separately.
type fakeClock struct {
	now    time.Time
	slept  []time.Duration
	failOn int // return an error from Sleep on the Nth call; 0 disables
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.slept = append(c.slept, d)
	if c.failOn > 0 && len(c.slept) == c.failOn {
		return context.Canceled
	}
	c.now = c.now.Add(d)
	return nil
}

func (c *fakeClock) total() time.Duration {
	var sum time.Duration
	for _, d := range c.slept {
		sum += d
	}
	return sum
}

// step20RetryAfterIsHonouredAndBounded proves the 429 half of D14.
func step20RetryAfterIsHonouredAndBounded(t *testing.T) {
	ctx := context.Background()

	rateLimited := func(after time.Duration) error {
		return &fault.Error{Kind: fault.KindRateLimited, Op: "upstream", Msg: "429", RetryAfter: after}
	}

	t.Run("the upstream's own number is used where present", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		r := retry.New(
			retry.Policy{MaxAttempts: 3, Base: time.Second, Cap: time.Minute, Budget: time.Hour},
			retry.WithClock(clock.Now, clock.Sleep))

		attempts, err := r.Do(ctx, retry.Retryable, func(context.Context) error {
			return rateLimited(20 * time.Second)
		})

		if attempts != 3 {
			t.Fatalf("attempts = %d, want 3", attempts)
		}
		if err == nil {
			t.Fatal("a persistently rate-limited call reported success")
		}
		// THE UPSTREAM SAID 20s AND THE LOCAL MODEL WOULD HAVE SAID ~1s. Every
		// wait must come from the header, jittered into [10s, 20s] — a policy
		// that quietly preferred its own guess would produce waits near Base,
		// and this is the assertion that tells the two apart.
		for i, d := range clock.slept {
			if d < 10*time.Second || d > 20*time.Second {
				t.Errorf("wait %d = %v, want the upstream's 20s jittered into [10s,20s]; "+
					"a local model would have produced roughly %v", i, d, time.Second)
			}
		}
	})

	t.Run("a hostile Retry-After is capped", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		r := retry.New(
			retry.Policy{MaxAttempts: 2, Base: time.Second, Cap: 5 * time.Second, Budget: time.Hour},
			retry.WithClock(clock.Now, clock.Sleep))

		// AN HOUR, from a misconfigured proxy or a hostile upstream. Honouring
		// it exactly would let the far side set Sekizui's latency budget and
		// park a command until the caller's deadline killed it.
		if _, err := r.Do(ctx, retry.Retryable, func(context.Context) error {
			return rateLimited(time.Hour)
		}); err == nil {
			t.Fatal("expected the injected rate limit to survive")
		}
		if got := clock.total(); got > 5*time.Second {
			t.Errorf("slept %v against a Cap of 5s; the upstream's number is better "+
				"information, not an instruction", got)
		}
		if got := clock.total(); got == 0 {
			t.Error("slept nothing, so the cap was applied by not retrying at all")
		}
	})

	t.Run("the TOTAL budget bounds the sum, not just each wait", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		r := retry.New(
			retry.Policy{MaxAttempts: 10, Base: time.Second, Cap: 4 * time.Second, Budget: 5 * time.Second},
			retry.WithClock(clock.Now, clock.Sleep))

		attempts, _ := r.Do(ctx, retry.Retryable, func(context.Context) error {
			return fault.New(fault.KindTargetUnavailable, "upstream", "down")
		})

		// A CAP ON EACH WAIT IS NOT A CAP ON THE SUM. Ten attempts at up to four
		// seconds is forty seconds of retrying under a per-wait cap that looks
		// modest, which is how a bounded-looking policy produces an unbounded
		// outage.
		if attempts >= 10 {
			t.Errorf("attempts = %d; the budget never stopped it", attempts)
		}
		if got := clock.total(); got > 5*time.Second {
			t.Errorf("slept %v against a Budget of 5s", got)
		}
	})

	t.Run("a NON-retryable failure is not retried at all", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		r := retry.New(retry.DefaultPolicy(), retry.WithClock(clock.Now, clock.Sleep))

		// Residency is the sharpest case: it is the guarantee working, and
		// retrying it burns quota against a wall forever (fault.Retryable).
		attempts, _ := r.Do(ctx, retry.Retryable, func(context.Context) error {
			return fault.New(fault.KindResidency, "resolver", "wrong region")
		})
		if attempts != 1 {
			t.Errorf("attempts = %d for a non-retryable kind, want 1", attempts)
		}
	})

	t.Run("cancellation mid-backoff reports the CAUSE, not the last upstream error", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0), failOn: 1}
		r := retry.New(retry.DefaultPolicy(), retry.WithClock(clock.Now, clock.Sleep))

		_, err := r.Do(ctx, retry.Retryable, func(context.Context) error {
			return rateLimited(time.Second)
		})
		// A CANCELLED COMMAND DID NOT FAIL BECAUSE THE TARGET WAS BUSY, and the
		// audit record must not say it did.
		if got := fault.KindOf(err); got != fault.KindTimeout {
			t.Errorf("kind = %v, want timeout; the backoff was interrupted, and "+
				"reporting the upstream's 429 would attribute the failure to the "+
				"wrong party", got)
		}
	})
}

// step21RetryNeverDuplicatesAnUnkeyedWrite is D113, end to end.
func step21RetryNeverDuplicatesAnUnkeyedWrite(t *testing.T) {
	ctx := context.Background()
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(ctx)
	}
	if r.localOnly(t, "attempts are read from this process's audit log") {
		return
	}

	// A RETRYABLE FAILURE ON A MUTATING ACTION. Every ingredient for a retry is
	// present except the one D113 requires.
	args := map[string]any{
		"project":          "PROJ",
		kata.FailKey:       "rate_limited",
		kata.RetryAfterKey: "1ms",
	}

	attemptsFor := func(t *testing.T, key string) uint32 {
		t.Helper()
		cmd := execute("kata.create_issue", "kata:alpha", args)
		cmd.Command.IdempotencyKey = key

		resp, err := r.as(t, "agent:triage").Execute(ctx, cmd)
		if err == nil && resp.GetResult().GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Fatal("the injected rate limit did not surface")
		}
		for _, d := range readLog(t, r.path) {
			if d.GetIdempotencyKey() == key && d.GetEffect() != nil {
				return d.GetEffect().GetAttempts()
			}
		}
		t.Fatalf("no outcome record for idempotency key %q", key)
		return 0
	}

	// WITHOUT A KEY: exactly one attempt. The first call may have reached the
	// target and landed; a 429 does not say which side of the write it died on,
	// and a second issue is not recoverable by apologising.
	if got := attemptsFor(t, ""); got != 1 {
		t.Errorf("attempts = %d for a mutating action with NO idempotency key, want 1. "+
			"D113: the retry that creates the hazard arrives in P1, one phase before "+
			"P2's dedupe window was scheduled to answer it", got)
	}

	// WITH A KEY: retries resume. Non-vacuity — without this the assertion above
	// is satisfied by a system that never retries anything, and the refusal
	// would be indistinguishable from the feature being absent.
	if got := attemptsFor(t, "acc-21-keyed"); got < 2 {
		t.Errorf("attempts = %d with an idempotency key, want more than 1; the "+
			"refusal above proves nothing if retries never happen at all", got)
	}

	r.detail(t, "D113: an unkeyed mutating call is attempted once; the same call with "+
		"an idempotency key retries under the policy")
}

// step22BreakerOpensHalfOpensAndCloses is the third of §4.3.4's controls.
func step22BreakerOpensHalfOpensAndCloses(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	b := limiter.NewBreaker(3, time.Minute, limiter.WithBreakerClock(clock.Now))

	const dead, healthy = "kata:dead", "kata:alpha"

	// --- CLOSED, then OPEN ---------------------------------------------------
	for i := range 2 {
		b.Record(dead, false)
		if !b.Allow(dead) {
			t.Fatalf("breaker opened after %d failures, before the trip of 3", i+1)
		}
	}
	b.Record(dead, false)
	if b.Allow(dead) {
		t.Fatal("breaker did not open on the third consecutive failure")
	}
	if got := b.State(dead); got != "open" {
		t.Errorf("state = %q, want open", got)
	}

	// --- ISOLATION, which is what makes it per-target -----------------------
	//
	// Asserted here rather than at the end because it is the property most
	// likely to break silently: keyed wrongly, a breaker becomes a global kill
	// switch, and the symptom is a healthy target going dark for reasons its own
	// metrics cannot explain.
	if !b.Allow(healthy) {
		t.Error("a breaker open on kata:dead withheld calls to kata:alpha; health is a " +
			"property of the target, not of the process")
	}

	// --- HALF-OPEN admits exactly ONE probe ---------------------------------
	clock.now = clock.now.Add(2 * time.Minute)
	if got := b.State(dead); got != "half-open" {
		t.Errorf("state = %q after the cooldown, want half-open", got)
	}
	if !b.Allow(dead) {
		t.Error("no probe admitted after the cooldown; the breaker never recovers")
	}
	if b.Allow(dead) {
		t.Error("a SECOND caller was admitted while the probe was outstanding. A " +
			"hundred goroutines arriving as the cooldown expires would all hit a " +
			"target that is probably still down — the stampede the breaker exists " +
			"to prevent, rescheduled")
	}

	// --- A FAILED PROBE RE-OPENS from now -----------------------------------
	b.Record(dead, false)
	if got := b.State(dead); got != "open" {
		t.Errorf("state = %q after a failed probe, want open", got)
	}
	if b.Allow(dead) {
		t.Error("calls resumed after a failed probe")
	}

	// --- A SUCCESSFUL PROBE CLOSES IT OUTRIGHT ------------------------------
	clock.now = clock.now.Add(2 * time.Minute)
	if !b.Allow(dead) {
		t.Fatal("no second probe admitted")
	}
	b.Record(dead, true)
	if got := b.State(dead); got != "closed" {
		t.Errorf("state = %q after a successful probe, want closed. The trip counts "+
			"CONSECUTIVE failures, so one success is already evidence the streak "+
			"broke; requiring several would throttle a target that is demonstrably "+
			"serving", got)
	}
	if !b.Allow(dead) {
		t.Error("calls did not resume after the breaker closed")
	}
}
