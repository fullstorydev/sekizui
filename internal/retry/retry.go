// Package retry is the bounded-retry policy for outbound driver calls.
//
// PRIVATE (D35). A driver does not retry; the enforcement path does. That is
// deliberate: retry interacts with the audit record (`Effect.attempts`), with
// idempotency (D113), and with the breaker, and none of those is a driver's
// business. Three drivers each rolling their own backoff is how a fleet learns
// to hammer an upstream in three different ways.
//
// DESIGN.md references: §4.3.4, §5.2.1, D14, D113.
package retry

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Policy bounds how hard Sekizui may try.
type Policy struct {
	// MaxAttempts includes the first call. 1 disables retrying entirely.
	MaxAttempts int

	// Base is the first backoff; each subsequent wait doubles it.
	Base time.Duration

	// Cap bounds a SINGLE wait. §4.3.4 wants backoff bounded rather than
	// unbounded — an exponential with no ceiling turns a five-minute outage into
	// an hour-long one, because the last sleep started before recovery and
	// outlives it by design.
	Cap time.Duration

	// Budget bounds the TOTAL time spent retrying, across every attempt. A cap
	// on each wait is not a cap on the sum, and the caller's deadline is a
	// different budget from the operator's patience.
	Budget time.Duration

	// ReestablishAttempts includes the first call, so 1 disables re-establishing
	// entirely (D203). Read by the gateway, never by Do.
	//
	// **A FIELD ON THIS STRUCT THAT THIS PACKAGE DOES NOT ACT ON, DELIBERATELY.**
	// Re-establishing is retrying-after-re-minting, so it is the same kind of
	// per-target judgement as MaxAttempts and belongs beside it — the config
	// block already reads `retry_attempts` and `reestablish_attempts` as
	// neighbours, and splitting them here would need a second per-target map
	// keyed the same way, plumbed the same way, and free to drift.
	//
	// Do CANNOT run it, and that is D204: re-establishing means going back
	// through every ceiling, which happens above `gateway.Enforce` and not
	// inside a loop around one call.
	ReestablishAttempts int
}

// DefaultPolicy is deliberately modest. A local limiter has no cross-replica
// view (D14), so N replicas each retrying three times is 3N calls at an upstream
// that already said no.
func DefaultPolicy() Policy {
	return Policy{MaxAttempts: 3, Base: 200 * time.Millisecond, Cap: 5 * time.Second, Budget: 30 * time.Second}
}

// Runner executes a call under the policy.
//
// THE CLOCK AND THE SLEEP ARE SEAMS, because P1 exit criterion 12 already
// establishes the house rule: proven with a clock seam rather than a sleep. A
// test that asserts backoff by actually waiting is slow, flaky under load, and
// proves the scheduler works rather than that the policy does.
type Runner struct {
	policy Policy
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error

	// perTarget overrides the policy for named targets (D142). Built once at
	// wiring and never mutated, so it is safe to share across goroutines and
	// safe to carry into a derived Runner by reference.
	perTarget map[string]Policy
}

// Option configures a Runner.
type Option func(*Runner)

// WithClock substitutes the clock and the sleep together.
//
// ONE OPTION FOR BOTH, not two, because they must agree: a fake clock that does
// not advance when the fake sleep is called makes the budget check meaningless
// and every test using it vacuous.
func WithClock(now func() time.Time, sleep func(ctx context.Context, d time.Duration) error) Option {
	return func(r *Runner) { r.now, r.sleep = now, sleep }
}

// WithTargetPolicies narrows the policy for named targets (D142).
//
// THE POLICIES ARE ALREADY VALIDATED against the deployment ceiling when they
// arrive — boot refuses a target more aggressive than the deployment permits
// (config.ExceedingTargets), so this applies them rather than re-checking.
func WithTargetPolicies(m map[string]Policy) Option {
	return func(r *Runner) { r.perTarget = m }
}

// New builds a Runner.
func New(p Policy, opts ...Option) *Runner {
	r := &Runner{policy: p, now: time.Now, sleep: sleepCtx}
	for _, o := range opts {
		o(r)
	}
	if r.policy.MaxAttempts < 1 {
		r.policy.MaxAttempts = 1
	}
	return r
}

// For returns the Runner that applies to one target (D142).
//
// A DERIVED RUNNER RATHER THAN A targetRef PARAMETER ON Do. Do already takes a
// context, a predicate and a closure, and threading a fifth argument through it
// would put the target on every call site including the ones that have no target
// — a reflex retrying an in-process step, for instance. `For` keeps Do's
// signature honest about what it needs, and a call site that forgets it gets the
// deployment default rather than a compile error, which is the one weakness of
// this shape and is why the acceptance step asserts through the gateway rather
// than against the Runner directly.
//
// Returns the receiver unchanged when the target has no override, so the common
// path allocates nothing.
func (r *Runner) For(targetRef string) *Runner {
	p, ok := r.perTarget[targetRef]
	if !ok {
		return r
	}
	if p.MaxAttempts < 1 {
		p.MaxAttempts = 1
	}
	// The clock and sleep seams travel with it, or a test substituting them
	// would silently get the real ones back for any target with an override.
	return &Runner{policy: p, now: r.now, sleep: r.sleep, perTarget: r.perTarget}
}

// Policy reports the policy this Runner applies, so a caller that must act on a
// field Do does not read can get at it (D203's ReestablishAttempts).
//
// RETURNS A COPY — Policy is all value types, so a caller cannot reach in and
// change what a shared Runner will do next. The alternative, an accessor per
// field, grows one method every time the struct does.
func (r *Runner) Policy() Policy { return r.policy }

// Do runs fn until it succeeds, stops being retryable, or the policy is spent.
//
// Returns the number of attempts made, which the caller records as
// `Effect.attempts` — a field that read a hardcoded 1 for as long as nothing
// retried, and would have kept reading 1 while retries happened underneath it.
//
// `retryable` is asked SEPARATELY from the error's own kind, so the caller can
// refuse a retry it would otherwise be entitled to. D113 is the reason: a
// mutating action with no idempotency key must not be retried however retryable
// the failure looks, because the first call may have landed.
func (r *Runner) Do(ctx context.Context, retryable func(error) bool,
	fn func(ctx context.Context) error) (attempts int, err error) {

	const op = "retry.Do"

	started := r.now()

	for attempts = 1; ; attempts++ {
		err = fn(ctx)
		if err == nil {
			return attempts, nil
		}
		if attempts >= r.policy.MaxAttempts || !retryable(err) {
			return attempts, err
		}

		wait := r.backoff(attempts, err)

		// THE BUDGET IS CHECKED BEFORE SLEEPING, not after. Waking up to
		// discover the budget is spent has already spent it, and the caller
		// waited for nothing.
		if spent := r.now().Sub(started); spent+wait > r.policy.Budget {
			return attempts, err
		}
		if serr := r.sleep(ctx, wait); serr != nil {
			// The caller's context ended mid-backoff. Return the CAUSE rather
			// than the last upstream error: a cancelled command did not fail
			// because the target was busy, and the audit record should not say
			// it did.
			return attempts, fault.Wrap(fault.KindTimeout, op,
				"context ended while backing off", serr)
		}
	}
}

// backoff decides how long to wait before attempt n+1.
//
// THE UPSTREAM'S OWN NUMBER WINS WHERE IT SUPPLIED ONE. A 429 carrying
// Retry-After is better information than any local model — the server knows its
// own quota window and we are guessing at it. This is what makes the local
// limiter viable without a distributed coordinator (D14, §5.2.1): we do not have
// to predict what we can be told.
//
// It is still CAPPED. A `Retry-After: 3600` from a misconfigured proxy must not
// park a command for an hour, and the cap is the operator's statement about how
// long a single wait may be. Honouring it exactly would let an upstream set our
// latency budget.
//
// JITTERED, always, and for the reason §4.3.4 cares about rather than politeness:
// N replicas that all took a 429 at the same instant retry at the same instant
// without it, which is a self-inflicted thundering herd against a target that
// just said it was overloaded.
func (r *Runner) backoff(attempt int, err error) time.Duration {
	wait := fault.RetryAfterOf(err)
	if wait <= 0 {
		wait = r.policy.Base
		for i := 1; i < attempt; i++ {
			wait *= 2
			if wait >= r.policy.Cap {
				break
			}
		}
	}
	if wait > r.policy.Cap {
		wait = r.policy.Cap
	}

	// FULL JITTER over [wait/2, wait]. Halving the floor keeps the backoff
	// meaningfully long while spreading the herd; jitter over [0, wait] is the
	// other common choice and lets an unlucky replica retry almost immediately,
	// which is the case we are trying to avoid.
	half := wait / 2
	if half <= 0 {
		return wait
	}
	return half + time.Duration(rand.Int64N(int64(half)+1)) //nolint:gosec // jitter, not a secret
}

// Retryable is the default predicate: the taxonomy decides.
//
// Centralised in fault (§4.5.3) rather than restated here, because "may this be
// retried" is a property of the failure and three drivers answering it
// independently is how they come to disagree.
func Retryable(err error) bool { return fault.KindOf(err).Retryable() }

// UnsafeToRetry reports whether D113 forbids retrying this call whatever the
// error says.
//
// **A MUTATING ACTION WITH NO IDEMPOTENCY KEY MUST NOT BE RETRIED.** The first
// call may have reached the target and landed; a timeout or a dropped connection
// does not tell us which side of the write it died on. Retrying then risks a
// SECOND issue, a second payment, a second deletion — and the audit record would
// show one command and one outcome, which is the part that makes it dangerous
// rather than merely wrong.
//
// D113 puts this in P1 deliberately: the hazard arrives with the retries, one
// phase before P2's dedupe window was scheduled to answer it. P2's request-level
// idempotency is a different scope — the CALLER resending a whole command — and
// needs durable state this phase has no business acquiring.
//
// The refusal is the safe direction and the cheap one to fix: an operator adds
// an idempotency key and gets retries back.
//
// **REWRITTEN IN P2, AND THE OLD FORM WAS THE BUG** (CONTRACTS 63, D163). It read
// `mutating && idempotencyKey == ""`, so ANY non-empty key opened the gate —
// while the key reached the decision record and this predicate and nothing else,
// because Driver.Execute had no parameter carrying it. A key authorised a retry
// it did not make safe, and the only driver had no external side effect, so
// nothing could notice.
//
// The question is now HOW the action is idempotent rather than whether a string
// is non-empty. A `none`-class action is never retried however many keys the
// caller supplies; a `natural`-class one is retried with no key at all, because
// an upsert does not need one.
//
// **IT NOW RETURNS THE REASON, because refusing silently moved the hazard rather
// than removing it (D182).** The gate closed and the caller was handed the
// upstream's own error — a timeout, which the taxonomy calls RETRYABLE — so a
// well-behaved agent consulting that error retried and produced exactly the
// duplicate this predicate exists to prevent. A refusal a caller cannot see is a
// refusal only Sekizui is bound by.
//
// `(string, bool)` rather than a second predicate, per §15p: two functions
// answering "is it unsafe" and "why" are two sources of truth that will
// eventually disagree about a class, and the disagreement would be silent
// because only one of them gates anything. Both come from one return statement
// here.
//
// THE TWO REASONS ARE DISTINGUISHED because the remedies are opposites. A
// `none`-class action has no remedy at all — the upstream cannot help, and an
// operator hunting for a configuration knob is looking for something that does
// not exist. A class that merely wants a key has the cheapest remedy in the
// system: supply one and retries come back. Collapsing them into "retry not
// permitted" is what leaves an operator unable to tell a limitation from a
// mistake.
func UnsafeToRetry(mutating bool, class connector.IdempotencyClass,
	idempotencyKey string) (why string, unsafe bool) {

	if !mutating {
		return "", false
	}
	if !class.AllowsRetry() {
		// Explain() already states the consequence, so this does not restate it.
		// The first draft did, and the record read "…so a retry is refused, so a
		// repeat would not be deduplicated…" — two clauses saying one thing,
		// which is what a message assembled from two sources reads like unless
		// somebody looks at the output.
		return fmt.Sprintf("class %q, and %s. No idempotency key changes that — the "+
			"classification states what the FAR SIDE can do, not what we would "+
			"like (D163)", class, class.Explain()), true
	}
	// A class that needs a key and did not get one is exactly D113's original
	// case: the first call may have landed, and nothing distinguishes that from a
	// call that never arrived.
	if class.NeedsKey() && idempotencyKey == "" {
		return fmt.Sprintf("class %q, and %s — but the command carried no idempotency "+
			"key, so there was nothing to make the repeat safe. Supplying one restores "+
			"retries (D113)", class, class.Explain()), true
	}
	return "", false
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
