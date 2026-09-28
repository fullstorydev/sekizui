package limiter

import (
	"context"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/pkg/limiter"
)

// Local is the single-process rate limiter (D14, D143).
//
// TWO KEYS, AS pkg/limiter DESCRIBES. The shared budget is keyed on the TARGET,
// because an upstream meters per instance and two agents hitting one Jira must
// share it. Fairness is keyed on the PRINCIPAL within that budget, because one
// agent's burst must not starve another.
//
// WORK-CONSERVING, WHICH IS THE WHOLE DESIGN. §4.3.4 names two failures, not
// one: "over-throttling or letting one agent monopolise". Fixed equal shares
// solve the second and cause the first — three principals granted on a target
// means each is capped at a third of a quota the other two are not using, and an
// operator whose only working agent is throttled to 33% of a budget nobody else
// wants will turn the control off. So a share is enforced only when the budget
// is CONTENDED:
//
//	target bucket above the reserve  -> anyone may proceed, share or no share
//	target bucket below the reserve  -> only principals under their share proceed
//
// The reserve is what makes that a policy rather than a race. Without it the
// rule would be "first to arrive wins", which is precisely monopolisation with
// extra steps.
//
// A SHARE IS DERIVED, NOT CONFIGURED. It is the target's burst divided by the
// number of principals seen recently, so it tracks who is actually competing
// rather than who is granted — a principal with a grant it never uses should not
// shrink everyone else's share, and one that appears mid-incident should.
type Local struct {
	// reserveNum/reserveDen express the contention threshold as a fraction of
	// capacity, in integers, so the check needs no float and no rounding rule.
	reserveNum, reserveDen int64

	// window is how long a principal counts as a contender after its last call.
	window time.Duration

	now func() time.Time

	// of maps a target ref to the BUDGET it draws on (D208). A target absent
	// from it is its own budget, which is every deployment written before D208.
	of map[string]string

	// shares is targetRef -> explicit percent of its budget. Absent means an
	// equal part among the targets actually contending (D210).
	shares map[string]uint32

	// alloc, instance and the lease fields are the P7 seam running at P2 with
	// one instance (D209). See Refresh.
	alloc    limiter.Allocator
	instance string
	missed   int
	floorNum int64

	mu      sync.Mutex
	targets map[string]*targetBudget
}

// budgetOf is the budget a target draws on.
func (l *Local) budgetOf(targetRef string) string {
	if b, ok := l.of[targetRef]; ok && b != "" {
		return b
	}
	return targetRef
}

// targetBudget is one SHARED budget, which may be drawn on by several targets
// (D208). The name is unchanged because every deployment that has not named a
// budget still has exactly one target per bucket.
type targetBudget struct {
	capacity int64
	perSec   float64 // refill rate

	// configured is the capacity from config, and it is the CEILING an
	// allocation may narrow but never widen (D210). Kept beside `capacity`
	// rather than recomputed, because the whole point is that the two can
	// differ and only one of them is authoritative about the maximum.
	configuredCap  int64
	configuredRate float64

	tokens     float64
	lastRefill time.Time

	// seen is principal -> last attempt, and it is what makes the share track
	// actual competition. Pruned on read rather than by a goroutine: a limiter
	// that needs a background sweeper to be correct is a limiter that is wrong
	// while the sweeper is descheduled.
	seen map[string]time.Time

	// used is principal -> tokens consumed in this window, the numerator of
	// "is this principal over its share".
	used map[string]float64

	// --- the second level of the hierarchy (D210) --------------------------
	//
	// **THE DIVISION IS HIERARCHICAL AND THAT FOLLOWS FROM THE RULE RATHER THAN
	// BEING A SEPARATE CHOICE.** The maintainer: *"equal unless defined otherwise"*,
	// applied at each level. A budget divides among the TARGETS contending for
	// it; each target's entitlement divides among the PRINCIPALS contending for
	// that target — which is D143 already, since it derives a share from
	// principals seen in a window.
	//
	// Dividing equally among every (target, principal) pair instead would let a
	// surface with ten principals take ten elevenths of the budget from a
	// surface with one, and the 50/50 would hold nowhere.

	// seenTargets is targetRef -> last attempt, the contender set at the upper
	// level. Same pruning rule and same reason as `seen`.
	seenTargets map[string]time.Time

	// usedTargets is targetRef -> tokens consumed in this window.
	usedTargets map[string]float64

	// perTarget is targetRef -> principal -> tokens consumed, so a principal's
	// entitlement is measured inside its own target's slice rather than against
	// the whole budget.
	perTarget map[string]map[string]float64

	// seenPerTarget is targetRef -> principal -> last attempt.
	seenPerTarget map[string]map[string]time.Time
}

var (
	_ limiter.Limiter   = (*Local)(nil)
	_ limiter.Contended = (*Local)(nil)
)

// NewLocal builds a limiter over per-target rates.
//
// `rates` is targetRef -> (per-hour rate, burst). A target absent from the map
// is UNLIMITED, which is the correct reading of "no limit configured" — the
// alternative, defaulting to some number nobody chose, throttles a deployment
// that never asked to be throttled and is impossible to diagnose.
func NewLocal(rates map[string]Rate, opts ...LocalOption) *Local {
	l := &Local{
		reserveNum: 1, reserveDen: 4,
		window:   time.Minute,
		now:      time.Now,
		of:       map[string]string{},
		shares:   map[string]uint32{},
		floorNum: 10,
		targets:  map[string]*targetBudget{},
	}
	for _, o := range opts {
		o(l)
	}
	for ref, r := range rates {
		if r.Budget != "" {
			l.of[ref] = r.Budget
		}
		if r.Share > 0 {
			l.shares[ref] = r.Share
		}
		if r.PerHour == 0 {
			continue
		}
		burst := BurstOf(r)

		// **ONE BUCKET PER BUDGET, NOT PER TARGET (D208).** Two targets naming
		// one budget find the bucket already built and share it. Their declared
		// rates must AGREE, which boot refuses otherwise (`config.Validate`) —
		// silently picking one of two numbers is the defect class this
		// repository keeps finding, and here the consequence is a quota that is
		// double or half what somebody wrote down.
		name := l.budgetOf(ref)
		if _, exists := l.targets[name]; exists {
			continue
		}
		l.targets[name] = &targetBudget{
			capacity:       burst,
			perSec:         float64(r.PerHour) / 3600,
			configuredCap:  burst,
			configuredRate: float64(r.PerHour) / 3600,
			tokens:         float64(burst),
			lastRefill:     l.now(),
			seen:           map[string]time.Time{},
			used:           map[string]float64{},
			seenTargets:    map[string]time.Time{},
			usedTargets:    map[string]float64{},
			perTarget:      map[string]map[string]float64{},
			seenPerTarget:  map[string]map[string]time.Time{},
		}
	}
	return l
}

// BurstOf is the bucket capacity a Rate gets: its declared burst, or a tenth
// of the hourly rate. EXPORTED FOR ONE CALLER, `meter.Build`, which refuses at
// boot a poll whose price exceeds it (D284) — and must compute the SAME number
// the bucket will hold, not a copy of the arithmetic that could drift.
func BurstOf(r Rate) int64 {
	burst := int64(r.Burst)
	if burst <= 0 {
		// A BUCKET WITH NO BURST ADMITS ONE CALL PER REFILL INTERVAL, which
		// makes ordinary concurrency look like a rate-limit failure. A tenth
		// of the hourly rate is a minute or two of headroom at most rates.
		burst = int64(r.PerHour) / 10
		if burst < 1 {
			burst = 1
		}
	}
	return burst
}

// Rate is one target's configured quota.
type Rate struct {
	PerHour uint32
	Burst   uint32

	// Budget names the shared quota this target draws on (D208). Empty means
	// the target is its own budget, which is the pre-D208 behaviour and is why
	// nothing migrates.
	Budget string

	// Share is this target's explicit percent of that budget. Zero means an
	// equal part among the targets actually contending (D210).
	Share uint32
}

// LocalOption configures a Local.
type LocalOption func(*Local)

// WithLocalClock substitutes the clock, so a test can drain and refill a bucket
// without waiting an hour (P1 exit criterion 12's house rule).
func WithLocalClock(now func() time.Time) LocalOption {
	return func(l *Local) { l.now = now }
}

// Allow reserves capacity for one call.
//
// Returns retryAfter > 0 when denied so the caller can surface a meaningful
// STATUS_RATE_LIMITED rather than a bare failure — pkg/limiter's own words, and
// the reason the interface returns a duration rather than a bool.
func (l *Local) Allow(_ context.Context, r limiter.Request) (bool, time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.targets[l.budgetOf(r.TargetRef)]
	if b == nil {
		return true, 0, nil // unlimited: no rate configured for this budget
	}

	now := l.now()
	b.refill(now)
	b.prune(now, l.window)
	b.seen[r.Principal] = now
	b.seenTargets[r.TargetRef] = now

	cost := float64(r.Cost)
	if cost <= 0 {
		cost = 1
	}

	// THE SHARED CEILING FIRST. Fairness within an exhausted budget is not a
	// question worth asking: nobody may proceed, and telling a principal it is
	// over its share when the target is simply empty would send an operator to
	// rebalance grants over a quota problem.
	if b.tokens < cost {
		return false, b.waitFor(cost), nil
	}

	// THEN FAIRNESS, ONLY UNDER CONTENTION. Above the reserve there is headroom
	// nobody is competing for, so a principal over its share proceeds — that is
	// the work-conserving half, and without it this is fixed shares wearing a
	// different name.
	reserve := float64(b.capacity*l.reserveNum) / float64(l.reserveDen)
	if b.tokens > reserve {
		b.take(r.TargetRef, r.Principal, cost, now)
		return true, 0, nil
	}

	// **THE UPPER LEVEL: THIS TARGET'S ENTITLEMENT WITHIN THE BUDGET (D210).**
	// Skipped entirely when one target is drawing on the budget, which is both
	// the common case and the pre-D208 shape — a single contender is entitled to
	// everything, and computing "one equal part of one" would be arithmetic
	// dressed as a control.
	entitlement := float64(b.capacity)
	if len(b.seenTargets) > 1 {
		entitlement = l.entitlementOf(b, r.TargetRef)
		if b.usedTargets[r.TargetRef]+cost > entitlement {
			// THIS SURFACE is over its share of a contended shared budget. The
			// refusal is the same shape as a principal's, one level up.
			return false, b.waitFor(cost), nil
		}
	}

	// **THE LOWER LEVEL: THIS PRINCIPAL'S ENTITLEMENT WITHIN THE TARGET'S.**
	// D143 unchanged, except that what is being divided is the target's slice
	// rather than the whole budget — which is what stops a surface with ten
	// principals taking ten elevenths from a surface with one.
	contenders := max(1, len(b.seenPerTarget[r.TargetRef])+1)
	if _, already := b.seenPerTarget[r.TargetRef][r.Principal]; already {
		contenders = max(1, len(b.seenPerTarget[r.TargetRef]))
	}
	share := entitlement / float64(contenders)
	if b.perTarget[r.TargetRef][r.Principal]+cost > share {
		// OVER SHARE, UNDER CONTENTION. This principal is the cause rather than
		// a victim — see Monopolisers, which is what an anzen rule watches.
		return false, b.waitFor(cost), nil
	}

	b.take(r.TargetRef, r.Principal, cost, now)
	return true, 0, nil
}

// entitlementOf is a target's slice of a contended budget.
//
// **AN EXPLICIT SHARE OVERRIDES THE EQUAL SPLIT, and an equal split is what
// absence means (D210).** The maintainer: *"equal parts, so if MCP and API is enabled that
// is 50% of budget for each unless defined explicitly"*. The equal part is
// computed over the targets ACTUALLY CONTENDING rather than over every target
// configured against the budget, which is D143's work-conserving rule applied at
// this level: an idle MCP surface must leave its half available to the API, or
// this becomes the fixed-share control D143 rejects because "a control that
// throttles an idle fleet is a control an operator switches off".
func (l *Local) entitlementOf(b *targetBudget, targetRef string) float64 {
	if pct, ok := l.shares[targetRef]; ok && pct > 0 {
		return float64(b.capacity) * float64(pct) / 100
	}

	// EQUAL PARTS AMONG THE CONTENDERS, minus whatever explicit shares have
	// already been claimed — otherwise two targets, one holding an explicit 80%,
	// would each also be offered half and the budget would be over-subscribed.
	claimed, explicit := 0.0, 0
	for ref := range b.seenTargets {
		if pct, ok := l.shares[ref]; ok && pct > 0 {
			claimed += float64(pct) / 100
			explicit++
		}
	}
	rest := max(1, len(b.seenTargets)-explicit)
	remaining := 1 - claimed
	if remaining < 0 {
		remaining = 0
	}
	return float64(b.capacity) * remaining / float64(rest)
}

// Observe feeds back what the upstream actually said.
//
// A 429 DRAINS THE LOCAL BUCKET, rather than merely being recorded. The upstream
// is the authority on its own quota (D14): being told "no" means the local model
// was wrong and optimistic, and continuing to admit calls at the modelled rate
// would keep it wrong for the rest of the window. Draining converts the
// upstream's answer into local behaviour immediately, which is what makes a
// local limiter viable without a distributed coordinator (§5.2.1).
func (l *Local) Observe(_ context.Context, r limiter.Request, statusCode int, retryAfter time.Duration) {
	if statusCode != 429 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.targets[l.budgetOf(r.TargetRef)]
	if b == nil {
		return
	}
	b.refill(l.now())
	b.tokens = 0

	// The upstream's stated wait pushes the refill origin forward, so the bucket
	// does not simply start refilling from now and hand out a token a second
	// later against a target that asked for a minute.
	if retryAfter > 0 {
		b.lastRefill = l.now().Add(retryAfter)
	}
}

// Monopolisers names the principals currently over their fair share of a
// contended target, worst first.
//
// EXISTS FOR THE AUDIT LOG AND FOR ANZEN, not for the limiter's own decisions
// (D143). `denial_storm` already reports a principal being denied repeatedly —
// but a principal monopolising a shared quota is not itself denied at first: it
// causes OTHERS to be. That signal fires on the victims and names the symptom,
// so an operator reading it goes and looks at the wrong principal.
//
// This names the CAUSE, which is what makes a misconfigured caller — a retry
// loop with no backoff, a fan-out nobody sized — visible as itself rather than
// as everyone else's failures.
// Capacity is the configured burst of the budget targetRef draws on
// (limiter.Sized, D284).
func (l *Local) Capacity(targetRef string) (int64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.targets[l.budgetOf(targetRef)]
	if b == nil {
		return 0, false
	}
	return b.configuredCap, true
}

var _ limiter.Sized = (*Local)(nil)

func (l *Local) Monopolisers(targetRef string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.targets[l.budgetOf(targetRef)]
	if b == nil {
		return nil
	}
	now := l.now()
	b.prune(now, l.window)
	if len(b.seen) < 2 {
		// One principal cannot monopolise a budget nobody is competing for.
		return nil
	}

	share := float64(b.capacity) / float64(len(b.seen))
	var over []string
	for p, used := range b.used {
		if used > share {
			over = append(over, p)
		}
	}
	sortByUsage(over, b.used)
	return over
}

func (b *targetBudget) refill(now time.Time) {
	if !now.After(b.lastRefill) {
		return
	}
	b.tokens += now.Sub(b.lastRefill).Seconds() * b.perSec
	if b.tokens > float64(b.capacity) {
		b.tokens = float64(b.capacity)
	}
	b.lastRefill = now
}

func (b *targetBudget) take(targetRef, principal string, cost float64, now time.Time) {
	b.tokens -= cost
	b.used[principal] += cost
	b.seen[principal] = now

	b.usedTargets[targetRef] += cost
	b.seenTargets[targetRef] = now
	if b.perTarget[targetRef] == nil {
		b.perTarget[targetRef] = map[string]float64{}
		b.seenPerTarget[targetRef] = map[string]time.Time{}
	}
	b.perTarget[targetRef][principal] += cost
	b.seenPerTarget[targetRef][principal] = now
}

// waitFor is how long until the bucket holds `cost` again.
func (b *targetBudget) waitFor(cost float64) time.Duration {
	if b.perSec <= 0 {
		return time.Hour
	}
	need := cost - b.tokens
	if need < 0 {
		need = 0
	}
	return time.Duration(need/b.perSec) * time.Second
}

// prune forgets principals that have stopped competing, so a share tracks who is
// actually here. Without it a principal that ran once at boot would shrink
// everyone else's share for the life of the process.
func (b *targetBudget) prune(now time.Time, window time.Duration) {
	for p, last := range b.seen {
		if now.Sub(last) > window {
			delete(b.seen, p)
			delete(b.used, p)
		}
	}
	// THE SAME RULE AT THE TARGET LEVEL, so a surface that has stopped calling
	// stops shrinking the other's entitlement — the work-conserving half of
	// D210's equal split, without which an idle target holds its share forever.
	for ref, last := range b.seenTargets {
		if now.Sub(last) > window {
			delete(b.seenTargets, ref)
			delete(b.usedTargets, ref)
			delete(b.perTarget, ref)
			delete(b.seenPerTarget, ref)
		}
	}
	for ref, principals := range b.seenPerTarget {
		for p, last := range principals {
			if now.Sub(last) > window {
				delete(principals, p)
				delete(b.perTarget[ref], p)
			}
		}
	}
}
