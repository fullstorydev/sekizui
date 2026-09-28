// Package limiter defines the rate-limiting seam.
//
// PUBLIC API (D35), because a multi-replica operator needs a distributed
// implementation and we deliberately ship only the local one (D14).
//
// DESIGN.md references: §4.3.4, §5.2.1, D14.
package limiter

import (
	"context"
	"time"
)

// Limiter enforces outbound quota.
//
// NOTE THE DIRECTION. Lexicon rate-limited INBOUND traffic to protect its own
// endpoints (lexicon/rateLimiter.js). With no untrusted HTTP ingress the
// risk inverts entirely: the concern is now hammering Jira's, Fullstory's, and
// BigQuery's quotas. Same concept, opposite direction — and Lexicon had no
// outbound limiting, retry, or backoff at all, so this is net-new rather than a
// port.
//
// TWO KEYS, NOT ONE (§4.3.4):
//
//	Limit    keys on TARGET     — Jira Cloud quotas are per-instance, so two
//	                              agents hitting the same instance must SHARE it.
//	Fairness keys on PRINCIPAL  — within that shared budget, one agent's burst
//	                              must not starve another.
//
// Getting this wrong in either direction means over-throttling or letting one
// agent monopolise a shared quota.
type Limiter interface {
	// Allow reserves capacity for one call.
	//
	// Returns retryAfter > 0 when denied, so the caller can surface a meaningful
	// STATUS_RATE_LIMITED rather than a bare failure.
	Allow(ctx context.Context, r Request) (ok bool, retryAfter time.Duration, err error)

	// Observe feeds back what the upstream actually said.
	//
	// THE UPSTREAM IS THE AUTHORITY ON ITS OWN QUOTA. A 429 with Retry-After is
	// better information than any local model, so the limiter should adapt to it
	// rather than only predicting. This is what makes the local-limiter baseline
	// viable without a distributed coordinator (§5.2.1).
	Observe(ctx context.Context, r Request, statusCode int, retryAfter time.Duration)
}

// Request identifies what is being limited.
type Request struct {
	// Shared quota dimension: the external instance, e.g. "jira:acme".
	TargetRef string

	// Fairness dimension: who is asking, e.g. "agent:triage".
	Principal string

	// Action, for per-action limits where an API meters unevenly — a search may
	// cost far more quota than a comment.
	Action string

	// Cost in quota units. 1 for most calls; higher for expensive operations such
	// as a large BigQuery scan.
	Cost uint32
}

// Contended is the OPTIONAL interface a Limiter implements when it can say WHO
// is causing contention on a target (D143).
//
// WHY THE CAUSE NEEDS ITS OWN ANSWER. A rate-limit refusal names the principal
// that was refused — which, under contention, is usually a VICTIM rather than
// the cause. The principal monopolising a shared budget is not itself denied at
// first; it causes everyone else to be. anzen's `denial_storm` signal has the
// same shape and the same blind spot: it reports repeated denials, so an
// operator following it arrives at the throttled agent rather than the one
// doing the throttling.
//
// Naming the cause is what makes a misconfigured caller — a retry loop with no
// backoff, a fan-out nobody sized — visible as itself. Without it, the operator
// reads a page about `agent:reporting` being rate limited and has no way to
// learn that `agent:crawler` is why.
//
// DISCOVERED BY TYPE ASSERTION rather than declared on Limiter, per
// GO-PRIMER §2.2 and the precedent ChainedProvider sets (D131). A distributed
// limiter may have no cheap way to answer this — the whole point of it is that
// state lives elsewhere — and forcing the method onto every implementation
// would mean either a lie or a network round-trip on the refusal path.
type Contended interface {
	// Monopolisers names the principals currently over their fair share of a
	// target, worst first. Empty when the target is uncontended: one principal
	// cannot monopolise a budget nobody else wants.
	Monopolisers(targetRef string) []string
}

// Sized reports the most one request could ever be admitted at: the
// CONFIGURED capacity of the budget a target draws on (D284).
//
// **"NOT YET" AND "NEVER" ARE DIFFERENT ANSWERS, AND ALLOW ONLY GIVES THE
// FIRST.** A request costing more than its bucket can hold is refused by
// Allow with a RetryAfter that can never come true — a poll refused for ever
// under a message promising it will clear. With this, the meter refuses such a
// request as the REQUEST's fault, because waiting does not help.
//
// The configured capacity, not a leased one: a lease that has shrunk is "not
// yet", and must stay a rate limit. Optional for Contended's reason; false
// means the target has no budget.
type Sized interface {
	Capacity(targetRef string) (int64, bool)
}

// Breaker trips after repeated failures so a dead target stops consuming quota
// and latency budget.
//
// Separate from Limiter because the concerns differ: a limiter shapes healthy
// traffic, a breaker withdraws from unhealthy targets. Conflating them makes both
// harder to reason about.
type Breaker interface {
	// Allow reports whether calls to this target are currently permitted.
	Allow(targetRef string) bool

	// Record feeds an outcome. Trips on consecutive failures, half-opens after a
	// cooldown, closes on success.
	Record(targetRef string, success bool)

	// State returns "closed", "open", or "half-open" — surfaced in the panel's
	// target health view (§4.8).
	State(targetRef string) string
}

// Allocation is a LEASE of capacity, not a lookup (D209).
//
// **THE EXPIRY IS WHAT MAKES IT A LEASE, and CONTRACTS 43 is why it is here from
// the first version.** `withdrawal.Store.Load` was published, documented,
// correct about the problem it named — and could not express the fix, because it
// read once at boot and had no way to learn later. `NewLocal(rates)` fixes
// capacity at construction in exactly the same shape. A capacity that can only
// be read once is a capacity a coordinator can never revise, so the seam that
// P7 needs has to be the seam P2 ships.
type Allocation struct {
	// PerHour and Burst are this instance's share of the named budget.
	PerHour uint32
	Burst   uint32

	// For is how long the lease is good, FROM RECEIPT.
	//
	// **A DURATION, NEVER A DEADLINE, and that is a security property rather
	// than a convenience (D210).** A `time.Time` off the wire carries no
	// monotonic reading, so a received deadline is wall-clock arithmetic between
	// two machines: skewed by whatever their clocks disagree about, and
	// extendable by anyone who can move a host's clock. The instance computes
	// its own deadline from its own monotonic clock at the moment of receipt, so
	// the only thing that travels is a length of time.
	//
	// Zero means the allocator does not expire leases, which is the honest
	// answer for the local one — there is no coordinator to lose contact with.
	For time.Duration
}

// Allocator hands out a share of a named budget to ONE instance.
//
// **THE ONE-INSTANCE CASE IS THE DEGENERATE FORM, NOT A BYPASS (D209).** The maintainer's
// constraint: *"the last thing we want is 20 instances thinking they all have
// the same budget, so the mechanism for a shared budget in one instance should
// then also be extendable to the shared budget across instances"*, and *"the
// logic for P7 should already work at p2 as it's just 1/1 instances."* So the
// allocation path RUNS from P2 with a local allocator that returns the whole
// budget; at P7 the implementation changes and the enforcement path does not. A
// skeleton switched off at one instance is one whose real path first executes in
// production.
//
// **NEVER CONSULTED PER COMMAND.** This is §5.2.1's rejected hop and D147's
// one-sentence budget for a coordination node: the limiter refreshes on a clock
// and `Allow` stays local arithmetic. A synchronous call to a coordinator on the
// command path would put a network round trip inside every governed call and
// make an allocator outage a total outage.
type Allocator interface {
	// Allocate returns this instance's current share of a budget.
	//
	// **`instance` IS IN THE SIGNATURE FROM THE FIRST VERSION, and the local
	// implementation ignores it.** A lease belongs to a replica: a coordinator
	// dividing a budget must know how many claimants there are and which one is
	// asking, and retrofitting that argument later would change every
	// implementation including third-party ones (D35). Present and unused is a
	// seam that can express the fix; absent is CONTRACTS 43 again.
	Allocate(ctx context.Context, budget, instance string) (Allocation, error)
}
