package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/limiter"
	pkglimiter "github.com/fullstorydev/sekizui/pkg/limiter"
)

// step23FairnessUnderASharedTargetLimit proves BOTH of §4.3.4's failures are
// avoided, because avoiding either one alone is easy and wrong.
func step23FairnessUnderASharedTargetLimit(t *testing.T) {
	ctx := context.Background()

	const target = "kata:alpha"

	// A clock that never moves unless a test moves it, so the bucket drains
	// exactly as far as the calls drain it and refills only when asked.
	clock := &fakeClock{now: time.Unix(0, 0)}
	build := func() *limiter.Local {
		return limiter.NewLocal(
			map[string]limiter.Rate{target: {PerHour: 3600, Burst: 100}},
			limiter.WithLocalClock(clock.Now))
	}

	drain := func(t *testing.T, l *limiter.Local, principal string, n int) (allowed int) {
		t.Helper()
		for range n {
			ok, _, err := l.Allow(ctx, pkglimiter.Request{TargetRef: target, Principal: principal})
			if err != nil {
				t.Fatalf("Allow: %v", err)
			}
			if ok {
				allowed++
			}
		}
		return allowed
	}

	// --- FAILURE 1: OVER-THROTTLING ------------------------------------------
	//
	// One principal, alone, must be able to use the WHOLE budget. Fixed equal
	// shares fail here: three principals granted on the target would cap the
	// only one working at a third of a quota nobody else wants, and a control
	// that throttles an idle-fleet deployment to 33% is a control an operator
	// switches off — which is §4.3.4's first named failure, and the reason this
	// case is asserted before the fairness one.
	t.Run("a lone principal is not throttled to a share", func(t *testing.T) {
		clock.now = time.Unix(0, 0)
		l := build()
		if got := drain(t, l, "agent:solo", 100); got != 100 {
			t.Errorf("a lone principal got %d of 100 tokens; nobody was competing "+
				"for the rest, so this is over-throttling — the failure that gets "+
				"rate limiting disabled", got)
		}
	})

	// --- FAILURE 2: MONOPOLISATION -------------------------------------------
	//
	// Under contention, a principal past its share stops while a quiet one still
	// gets through. This is the case the reserve exists for: above it there is
	// headroom nobody wants, below it the budget is genuinely contested and
	// shares start being enforced.
	t.Run("a saturating principal does not starve a quiet one", func(t *testing.T) {
		clock.now = time.Unix(0, 0)
		l := build()

		// Both principals appear, so the target is contended and the share is
		// half the burst. `agent:quiet` spends one token and then waits.
		if got := drain(t, l, "agent:quiet", 1); got != 1 {
			t.Fatalf("the quiet principal was refused its first call (%d)", got)
		}
		hog := drain(t, l, "agent:hog", 99)

		// THE HOG IS CUT OFF BEFORE THE BUDGET IS GONE. If it drained all 99 the
		// reserve did nothing, and what remains for the quiet principal is
		// whatever the hog happened to leave — first-come-first-served, which is
		// monopolisation with extra steps.
		if hog >= 99 {
			t.Errorf("the hog took %d of 99 and was never cut off; the fairness "+
				"share is not being enforced under contention", hog)
		}

		// AND THE QUIET PRINCIPAL CAN STILL WORK, which is the whole point. A
		// test that only asserted the hog was throttled would pass on a limiter
		// that had simply run the target dry.
		if got := drain(t, l, "agent:quiet", 5); got == 0 {
			t.Error("the quiet principal was starved after the hog's burst — " +
				"§4.3.4's 'letting one agent monopolise', which is what the " +
				"per-principal key exists to prevent")
		}
	})

	// --- THE CAUSE IS NAMEABLE, NOT JUST THE SYMPTOM -------------------------
	//
	// `denial_storm` reports a principal being denied repeatedly, and a
	// monopolising principal is not denied at first — it causes OTHERS to be. So
	// that signal fires on the victims and sends an operator to the wrong
	// principal. Naming the cause is what makes a misconfigured caller visible
	// as itself.
	t.Run("the monopolising principal is nameable", func(t *testing.T) {
		clock.now = time.Unix(0, 0)
		l := build()

		drain(t, l, "agent:quiet", 1)
		drain(t, l, "agent:hog", 90)

		over := l.Monopolisers(target)
		if len(over) == 0 || over[0] != "agent:hog" {
			t.Errorf("Monopolisers = %v, want agent:hog first. An anzen rule "+
				"watching this is what turns 'somebody is being denied' into "+
				"'THIS caller is why'", over)
		}
		for _, p := range over {
			if p == "agent:quiet" {
				t.Error("the quiet principal was reported as a monopoliser; the " +
					"signal names the cause, and reporting a victim would send an " +
					"operator to throttle the wrong agent")
			}
		}
	})

	// --- ONE PRINCIPAL CANNOT MONOPOLISE AN UNCONTENDED BUDGET ---------------
	//
	// Non-vacuity for the signal: without this it could report anyone who used a
	// lot, which on a single-agent deployment is everyone, always.
	t.Run("a lone principal is never a monopoliser", func(t *testing.T) {
		clock.now = time.Unix(0, 0)
		l := build()
		drain(t, l, "agent:solo", 100)

		if over := l.Monopolisers(target); len(over) != 0 {
			t.Errorf("Monopolisers = %v with one principal competing; a budget "+
				"nobody else wants cannot be monopolised, and a signal that fires "+
				"on every single-agent deployment is a signal nobody reads", over)
		}
	})

	// --- THE UPSTREAM'S 429 DRAINS THE LOCAL BUCKET --------------------------
	//
	// Being told "no" means the local model was optimistic. Recording that and
	// carrying on admitting calls at the modelled rate keeps it wrong for the
	// rest of the window (D14, §5.2.1).
	t.Run("a 429 drains the local bucket", func(t *testing.T) {
		clock.now = time.Unix(0, 0)
		l := build()
		req := pkglimiter.Request{TargetRef: target, Principal: "agent:solo"}

		if ok, _, _ := l.Allow(ctx, req); !ok {
			t.Fatal("a fresh bucket refused the first call")
		}
		l.Observe(ctx, req, 429, 30*time.Second)

		ok, after, _ := l.Allow(ctx, req)
		if ok {
			t.Error("the bucket still admitted a call after the upstream said 429; " +
				"the upstream is the authority on its own quota, and ignoring it " +
				"keeps the local model wrong for the rest of the window")
		}
		if after <= 0 {
			t.Error("no retryAfter surfaced, so a caller cannot turn this into a " +
				"meaningful STATUS_RATE_LIMITED")
		}
	})
}
