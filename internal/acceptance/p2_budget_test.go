package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	intlimiter "github.com/fullstorydev/sekizui/internal/limiter"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/limiter"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// sharedBudget is the two-surface arrangement: one upstream, two targets, one
// budget, and a rate small enough that a handful of calls exhausts it.
//
// **DELIBERATELY TINY, ON THE MAINTAINER'S CONSTRAINT — *"I do not want to DDoS
// Fullstory"*.** The whole point is proven against local test servers with a
// budget of a few calls per hour, so exhaustion is reached in three requests
// rather than by generating real load at a vendor.
const (
	sharedBudgetName    = "fullstory-org-example"
	sharedBudgetPerHour = 4
)

func budgeted(t *testing.T, share uint32) func(*config.Document) {
	t.Helper()
	base := bothPaths(t)

	return func(d *config.Document) {
		base(d)
		// BOTH TARGETS NAME ONE BUDGET, and only one of them declares the rate.
		// That is the realistic shape: the vendor documents a limit for the org,
		// and the second surface simply draws on it.
		d.Targets[0].Limits = &config.TargetLimits{
			RatePerHr: sharedBudgetPerHour, Burst: sharedBudgetPerHour,
			Budget: sharedBudgetName, Share: share,
		}
		d.Targets[1].Limits = &config.TargetLimits{Budget: sharedBudgetName}

		// ONE BUDGET LINKS THE DOORS, so each vetted tool states what it mirrors
		// (D323) — or boot refuses. agent:dev holds the native action below, so
		// the union admits the MCP call and the budget stays what is measured.
		spec := d.MCPSpecs["fixture-mcp"]
		for i := range spec.Tools {
			spec.Tools[i].Native = []string{fullstory.ActionCreateEvent}
		}
		d.MCPSpecs["fixture-mcp"] = spec

		d.Grants = []config.GrantSpec{{Principal: "agent:dev", Allow: []config.CapabilitySpec{
			on("mcp.fullstory.*", "fixture-mcp"),
			on(fullstory.ActionCreateEvent, "fullstory-api"),
		}}}
	}
}

// step15TwoTargetsFrontingOneUpstreamShareOneBudget is criterion 2's second half
// (D52, D208, D209, D210).
//
// **CONTRACTS ITEM 11, AND A STATED P2 BLOCKER.** §4.3.4 keys the rate limit on
// TARGET precisely so two agents hitting one Jira instance share a budget — which
// is right until two TARGETS front one instance, and D52 makes that permanent.
// Keyed on target ref, Fullstory's MCP surface and its native API carry
// independent buckets while consuming one org quota, so Sekizui under-counts by
// a factor of two and discovers the real limit as 429s.
//
// **ASSERTED BY EXHAUSTING ONE PATH AND FINDING THE OTHER LIMITED**, not by
// reading configuration back — which would prove only that a field was set. The
// declared brief said exactly that and it is the right instrument.
//
// **AND THE ALLOCATION MACHINERY IS EXERCISED HERE RATHER THAN LEFT FOR P7
// (D209).** The maintainer's constraint was that the one-instance case must be the
// degenerate form of the many-instance one, so the arms below drive a real
// allocator through a real narrowing ceiling and a real decay. A skeleton
// switched off at one instance is one whose first real execution is in
// production.
func step15TwoTargetsFrontingOneUpstreamShareOneBudget(t *testing.T) {
	ctx := context.Background()

	// --- 15a: EXHAUST ONE PATH, THE OTHER IS ALREADY LIMITED ---------------
	//
	// **THE NATIVE CALL MUST BE REFUSED BY THE LIMITER, NOT BY THE DRIVER**, and
	// that distinction is the arm. The native target points at a server whose
	// certificate it does not trust, so a call that got as far as the transport
	// would fail anyway — and a test satisfied by "the second path also failed"
	// would pass on a system with two independent buckets. `rate_limited` is the
	// only outcome that says the budget was shared.
	t.Run("exhausting the budget through one path limits the other", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		stack := newMCPStack(ctx, t, budgeted(t, 0), func(m *mcpTuning) {
			m.gw.Rate = sharedLimiter(clock)
		})
		stack.up.offer(mcp.LiveTool{Name: "create_event", InputSchema: objectSchema("name")})

		// DRAIN THROUGH THE MCP SURFACE ONLY.
		spent := 0
		for i := 0; i < sharedBudgetPerHour; i++ {
			res, err := stack.call(ctx, t, "mcp.fullstory.create_event")
			if err == nil && res.GetStatus() == sekizuiv1.Status_STATUS_OK {
				spent++
			}
		}
		if spent == 0 {
			t.Fatal("15a: no call succeeded through the MCP surface, so the budget was " +
				"never spent and nothing below is being tested")
		}

		// NOW THE NATIVE SURFACE, WHICH HAS SPENT NOTHING OF ITS OWN.
		res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"),
			&sekizuiv1.Command{
				Action: fullstory.ActionCreateEvent, TargetRef: "fullstory-api",
				Args: mustArgs(t, map[string]any{"name": "x"}),
			})
		if err != nil {
			t.Fatalf("15a: %v", err)
		}
		if got := res.GetKind(); got != fault.KindRateLimited.String() {
			t.Fatalf("15a: the native surface answered %q after the MCP surface spent the "+
				"whole budget, want %q. Two targets fronting one upstream carry "+
				"independent buckets, so Sekizui is under-counting by a factor of two "+
				"against one org quota (CONTRACTS 11): %s",
				got, fault.KindRateLimited, res.GetReason())
		}
	})

	// --- 15b: A TARGET NAMING NO BUDGET IS UNCHANGED -----------------------
	//
	// **NOTHING MIGRATES, which is what makes the implicit budget worth having.**
	// Every deployment written before D208 keeps exactly the bucket it had, and
	// the mechanism is opt-in by naming.
	t.Run("a target naming no budget keeps its own bucket", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		l := intlimiter.NewLocal(map[string]intlimiter.Rate{
			"alpha": {PerHour: 2, Burst: 2},
			"beta":  {PerHour: 2, Burst: 2},
		}, intlimiter.WithLocalClock(clock.Now))

		drainBudget(ctx, t, l, "alpha", "agent:dev", 2)
		if ok, _, _ := l.Allow(ctx, limiter.Request{TargetRef: "alpha", Principal: "agent:dev"}); ok {
			t.Fatal("15b: alpha still had budget after being drained")
		}
		if ok, _, _ := l.Allow(ctx, limiter.Request{TargetRef: "beta", Principal: "agent:dev"}); !ok {
			t.Error("15b: draining alpha limited beta, which names no shared budget. " +
				"Unnamed targets must keep independent buckets or D208 is a behaviour " +
				"change for every deployment that predates it")
		}
	})

	// --- 15c: EQUAL PARTS UNDER CONTENTION, WORK-CONSERVING ABOVE IT -------
	//
	// **THE SPLIT IS AN ENTITLEMENT, NOT A CAP (D210), and this arm is what keeps
	// the two apart.** Read as a cap, a 50/50 would throttle the API while the
	// MCP surface is idle — which is D143's rejected control, the one an operator
	// switches off because it throttles against nothing. So an idle surface's
	// half stays available.
	t.Run("an idle surface leaves its half available", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		l := intlimiter.NewLocal(map[string]intlimiter.Rate{
			"api": {PerHour: 3600, Burst: 100, Budget: "org"},
			"mcp": {Budget: "org"},
		}, intlimiter.WithLocalClock(clock.Now))

		// ONE surface calling: it may spend past half, because nothing else is
		// contending for the other half.
		got := drainBudget(ctx, t, l, "api", "agent:dev", 80)
		if got <= 50 {
			t.Errorf("15c: one surface got %d of 100 with the other idle, want more than "+
				"half. A share enforced against an absent contender is the fixed-share "+
				"control D143 rejects", got)
		}

		// --- AND THE CONTRAST, WITHOUT WHICH THE ARM ABOVE IS VACUOUS -------
		//
		// **SABOTAGE FOUND THIS.** The first version had only the half above,
		// and with one contender the equal split returns the WHOLE capacity by
		// arithmetic — so it passed whatever the split did, and breaking the
		// contention check did not fail it. What makes "work-conserving" mean
		// anything is that the split BINDS when a second surface actually shows
		// up, so both halves have to be here.
		clock2 := &fakeClock{now: time.Unix(0, 0)}
		l2 := intlimiter.NewLocal(map[string]intlimiter.Rate{
			"api": {PerHour: 3600, Burst: 100, Budget: "org"},
			"mcp": {Budget: "org"},
		}, intlimiter.WithLocalClock(clock2.Now))

		// The other surface calls once, so it IS a contender.
		drainBudget(ctx, t, l2, "mcp", "agent:dev", 1)
		greedy := drainBudget(ctx, t, l2, "api", "agent:dev", 200)

		if greedy >= 99 {
			t.Errorf("15c: one surface took %d of a 100 budget while ANOTHER was "+
				"contending, want it held near its entitlement. The split does not bind, "+
				"so a shared budget is first-come-first-served — which is monopolisation "+
				"with extra steps (D143's own words, one level up)", greedy)
		}
		if greedy <= 50 {
			t.Errorf("15c: one surface got only %d of 100 with a single competing call "+
				"from the other. Above the reserve there is headroom nobody wants and "+
				"anyone may take it; enforcing the split there is the over-throttling "+
				"D143 rejects", greedy)
		}

		// --- THE TARGET LEVEL, ISOLATED — AND SABOTAGE IS WHY IT IS HERE ----
		//
		// **THE TWO LEVELS COINCIDE NUMERICALLY WHEN A TARGET HAS ONE PRINCIPAL,
		// so neither of the halves above can see the upper one.** A principal's
		// share is its target's entitlement divided by that target's contenders;
		// with one contender it IS the entitlement, so removing the target check
		// changed nothing and the sabotage passed. That is the shape D204 deleted
		// a safety gate over — a bound nothing can reach reads as a bound
		// somebody checked.
		//
		// **IT IS REACHABLE, AND THIS IS THE CASE THAT REACHES IT: PRINCIPALS
		// ARRIVING AT DIFFERENT TIMES.** One principal spends its share while
		// alone on a surface; a second then arrives, the share is recomputed
		// smaller, and the first principal's spend is not refunded. Only the
		// per-TARGET total notices that the surface has now exceeded its half.
		clock3 := &fakeClock{now: time.Unix(0, 0)}
		l3 := intlimiter.NewLocal(map[string]intlimiter.Rate{
			"api": {PerHour: 3600, Burst: 100, Budget: "org"},
			"mcp": {Budget: "org"},
		}, intlimiter.WithLocalClock(clock3.Now))

		drainBudget(ctx, t, l3, "mcp", "agent:mcp", 1) // the other surface contends
		first := drainBudget(ctx, t, l3, "api", "agent:one", 200)
		second := drainBudget(ctx, t, l3, "api", "agent:two", 200)

		// **THE THRESHOLD IS ABOUT THE RESERVE, AND THE FIRST VERSION GOT IT
		// WRONG.** It demanded the surface stay near 50 and failed at 74 — which
		// is CORRECT behaviour: above the reserve (a quarter of capacity) there
		// is headroom nobody is competing for and anyone may take it, which is
		// exactly the work-conservation D143 requires. What the target check
		// changes is what happens BELOW the reserve: with it, the second
		// principal is refused because the SURFACE is already over its half;
		// without it, that principal gets a fresh per-principal share and the
		// surface reaches ~99 of 100.
		if total := first + second; total > 85 {
			t.Errorf("15c: one surface took %d of a 100 budget (%d by its first "+
				"principal, %d by a second arriving later) while another surface was "+
				"contending, want it stopped once past its half rather than granted a "+
				"fresh share per principal. Per-principal shares alone cannot bound "+
				"this: the share shrinks when the second "+
				"shares alone cannot bound this: the share shrinks when the second "+
				"principal appears and the first one's spend is not refunded, so only "+
				"the per-TARGET total notices the surface has exceeded its half",
				total, first, second)
		}
	})

	// --- 15d: AN ALLOCATION MAY ONLY NARROW ---------------------------------
	//
	// **THE LOAD-BEARING GUARD, and it came from the maintainer asking whether lease expiry
	// could be used for nefarious means (D210).** At P7 an allocation is an INPUT
	// FROM OUTSIDE THE PROCESS, so without a ceiling, spoofing the coordinator
	// removes the rate limit fleet-wide in one step — the control switched off by
	// the mechanism built to distribute it.
	t.Run("an allocation narrows the budget and cannot widen it", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		alloc := &scriptedAllocator{}
		l := intlimiter.NewLocal(map[string]intlimiter.Rate{
			"api": {PerHour: 3600, Burst: 100, Budget: "org"},
		}, intlimiter.WithLocalClock(clock.Now), intlimiter.WithAllocator(alloc, "replica-1"))

		// NARROWING IS HONOURED.
		alloc.give(limiter.Allocation{PerHour: 360, Burst: 10})
		l.Refresh(ctx)
		if got := drainBudget(ctx, t, l, "api", "agent:dev", 100); got > 10 {
			t.Errorf("15d: %d calls admitted after an allocation of burst 10, want at "+
				"most 10. The lease was ignored, so a coordinator dividing a fleet's "+
				"budget could not actually divide it", got)
		}

		// WIDENING IS CLAMPED TO THE CONFIGURED CEILING.
		clock.advance(time.Hour)
		alloc.give(limiter.Allocation{PerHour: 3_600_000, Burst: 100_000})
		l.Refresh(ctx)
		if got := drainBudget(ctx, t, l, "api", "agent:dev", 500); got > 100 {
			t.Errorf("15d: %d calls admitted after an allocation claiming burst 100000 "+
				"against a configured 100. An allocation may only NARROW (D210): "+
				"config is the ceiling, and without that rule spoofing the allocator "+
				"removes the rate limit fleet-wide in one step", got)
		}
	})

	// --- 15e: KEEP-LAST, THEN DECAY -----------------------------------------
	//
	// **KEEP-LAST IS THE ONLY OPTION THAT FAILS IN NEITHER DIRECTION (D210).**
	// Reverting to the full budget is the twenty-instance case the budget exists
	// to prevent; dropping to a floor on the first miss is D143's over-throttling.
	// The decay is what bounds keep-last in TIME rather than trusting the outage
	// to end.
	t.Run("a failing allocator keeps the last lease and then decays", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(0, 0)}
		alloc := &scriptedAllocator{}
		l := intlimiter.NewLocal(map[string]intlimiter.Rate{
			"api": {PerHour: 3600, Burst: 100, Budget: "org"},
		}, intlimiter.WithLocalClock(clock.Now),
			intlimiter.WithAllocator(alloc, "replica-1"),
			intlimiter.WithFloorPercent(10))

		alloc.give(limiter.Allocation{PerHour: 3600, Burst: 100})
		l.Refresh(ctx)

		// ONE MISS: the last lease stands.
		alloc.fail()
		l.Refresh(ctx)
		clock.advance(time.Hour)
		if got := drainBudget(ctx, t, l, "api", "agent:dev", 100); got < 90 {
			t.Errorf("15e: only %d calls admitted after ONE missed refresh, want the "+
				"last lease to stand. Dropping on the first miss is the over-throttling "+
				"D143 rejects — a blip becomes a throttle", got)
		}

		// THREE MISSES: decayed to the floor.
		l.Refresh(ctx)
		l.Refresh(ctx)
		clock.advance(time.Hour)
		if got := drainBudget(ctx, t, l, "api", "agent:dev", 100); got > 10 {
			t.Errorf("15e: %d calls admitted after three missed refreshes, want at most "+
				"the 10%% floor. Keep-last with no decay leaves a partitioned fleet "+
				"spending its full budget per replica for as long as the outage lasts", got)
		}
	})
}

// --- fixtures ---------------------------------------------------------------

// advance moves the shared fake clock forward, so a bucket refills without a
// test waiting an hour (P1 exit criterion 12's house rule).
func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// sharedLimiter builds the limiter the stack enforces through.
func sharedLimiter(clock *fakeClock) *intlimiter.Local {
	return intlimiter.NewLocal(map[string]intlimiter.Rate{
		"fixture-mcp": {
			PerHour: sharedBudgetPerHour, Burst: sharedBudgetPerHour,
			Budget: sharedBudgetName,
		},
		"fullstory-api": {Budget: sharedBudgetName},
	}, intlimiter.WithLocalClock(clock.Now))
}

// drainBudget attempts n calls and reports how many were admitted.
func drainBudget(ctx context.Context, t *testing.T, l *intlimiter.Local,
	target, principal string, n int) int {

	t.Helper()
	admitted := 0
	for range n {
		ok, _, err := l.Allow(ctx, limiter.Request{TargetRef: target, Principal: principal})
		if err != nil {
			t.Fatalf("limiter: %v", err)
		}
		if ok {
			admitted++
		}
	}
	return admitted
}

// scriptedAllocator answers with whatever a test last handed it, or fails.
//
// **A STUB RATHER THAN THE LOCAL ALLOCATOR, and the reason is what the arms
// measure.** `LocalAllocator` returns the configured budget and never fails,
// which is correct for it and useless here: what must be driven is a lease that
// NARROWS, one that tries to widen, and an allocator that stops answering. Those
// are the P7 conditions, and P2's allocator cannot produce any of them.
type scriptedAllocator struct {
	alloc  limiter.Allocation
	broken bool
}

func (a *scriptedAllocator) give(al limiter.Allocation) { a.alloc, a.broken = al, false }
func (a *scriptedAllocator) fail()                      { a.broken = true }

func (a *scriptedAllocator) Allocate(_ context.Context, _, _ string) (limiter.Allocation, error) {
	if a.broken {
		return limiter.Allocation{}, fault.New(fault.KindUnavailable,
			"test.Allocate", "the allocator is unreachable")
	}
	return a.alloc, nil
}
