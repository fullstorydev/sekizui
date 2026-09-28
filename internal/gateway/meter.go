package gateway

import (
	"context"
	"fmt"
	"math"

	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/limiter"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// meterRefusal is the meter's answer, in a form EVERY verb can shape into its
// own response type — the same contract `ceilingRefusal` has, deliberately.
//
// It carries no `*sekizuiv1.Decision`, and that is the one difference from
// `ceilingRefusal` worth knowing. A ceiling refuses before a target is
// resolved, so it must build the row itself; the meter runs after resolve, by
// which point every caller already holds a `base` decision with the residency
// and posture stamped on it. Building a second one here would produce a row
// missing both.
type meterRefusal struct {
	kind fault.Kind
	err  error
}

// stage is the RefusedBy value every verb must record for a metered refusal.
//
// SHARED RATHER THAN CHOSEN PER VERB, because that is precisely what drifted:
// `Query` recorded an open breaker as `REFUSED_BY_ANZEN` while `enforceOnce`
// recorded no stage at all on the same condition.
func (m *meterRefusal) stage() sekizuiv1.RefusedBy {
	return sekizuiv1.RefusedBy_REFUSED_BY_METER
}

// meters applies §4.3.4's CONSUMING controls: the shared rate budget (D143)
// then the circuit breaker (D141).
//
// # WHY THIS IS A SECOND SEAM AND NOT PART OF `ceilings` (D253)
//
// It looks like it belongs there — both are "checks every verb owes" — and
// three things say otherwise, each of which would be a defect rather than an
// inelegance:
//
//  1. **ORDERING.** `ceilings` runs BEFORE policy, because D71 evaluates a
//     ceiling ahead of the grants it bounds. These two CONSUME: `Allow` takes
//     a token, and the breaker's half-open state admits exactly ONE probe.
//     Run before policy, a caller with NO GRANT AT ALL drains a target's
//     shared budget — a denial of service against legitimate callers, through
//     the policy layer — and a command policy is about to deny burns the
//     single probe, so a recovered target stays circuit-open.
//  2. **RECORD SHAPE.** A ceiling refusal is a call that never started and is
//     written as a Terminal row. A metered refusal on the command path is a
//     call ATTEMPTED AND STOPPED, written as an Outcome against an intent that
//     already exists — §5.2.2's two-phase shape, and the reason the breaker
//     check sits after `recorder.Intent` rather than before it.
//  3. **KIND.** The ceilings are predicates; these mutate. Folding them
//     together would make every ceiling evaluation a state change.
//
// So the enforcement path has TWO shared stages with a verb-specific middle,
// rather than one stage in the wrong place.
//
// # WHAT THIS EXTRACTION FOUND
//
// **`Query` NEVER CONSUMED THE RATE BUDGET.** `s.rate.Allow` appeared exactly
// once in the tree, inside `enforceOnce`. D155 is recorded as having closed
// all three of §4.3.4's controls for reads; the breaker and the retry landed
// and the limiter did not, so D155's most quoted sentence — *"a deployment
// configured for 100/hr sent 100 writes plus unlimited reads at an upstream
// that counts both"* — stayed literally true, **inside the comment that says
// it was fixed**. Three places claimed it: that comment, DESIGN §12's P2
// summary, and CONTRACTS 54.
//
// Nothing caught it because step 68's guard requires `ceilings` and
// `Withdrawn` — the two things D155 EXTRACTED INTO FUNCTIONS. The meters
// stayed inline, so they were never in the list, and **a guard naming the
// stages it knows about cannot ask about the one nobody extracted.** That is
// what `assertNoVerbTouchesAnEnforcementControlDirectly` now answers instead.
//
// # THE COST IS THE CONNECTOR'S PRICE, TAKEN BEFORE THE CALL (D284)
//
// It was `Cost: 1`, under a comment saying "`100/hr` means a hundred CALLS".
// True of Execute and Query, where one RPC is one upstream call — and false of
// a POLL, which the job gate meters once while a Fullstory events poll made a
// sessions call plus one context read per session. The caller now passes what
// the connector's Meter says the call or poll costs, in the connector's unit,
// at worst case; nothing is refunded afterwards on the driver's say-so.
//
// Returns nil when the call may proceed. An error is a genuine FAILURE of the
// limiter itself, which is not a refusal and must not be recorded as one.
// budgetRef is the limiter bucket the cost is charged to: the target itself for
// every consumer's call, and its SYSTEM budget for a drift comparison (D311).
// The breaker always watches targetRef — it asks whether the TARGET is alive,
// whoever is paying.
func (s *Server) meters(ctx context.Context, subject, action, targetRef, budgetRef string, cost uint64) (
	*meterRefusal, error) {

	const op = "gateway.meters"

	// THE RATE LIMIT FIRST, BECAUSE IT IS THE CHEAPER QUESTION. The limiter
	// asks "is there budget", the breaker asks "is the target alive".
	// Refusing on an exhausted budget without consulting a breaker costs
	// nothing; the reverse order would let a saturating principal keep probing
	// a target the breaker is trying to leave alone.
	if s.rate != nil {
		// **"NEVER" IS NOT "LATER" (D284).** A price above the most the
		// budget can ever hold would be refused by Allow with a RetryAfter
		// that cannot come true. That is the request's fault, and waiting
		// does not fix it — so it is refused as one, naming the fix.
		if sized, canSay := s.rate.(limiter.Sized); canSay {
			if capacity, metered := sized.Capacity(budgetRef); metered && int64(cost) > capacity {
				return &meterRefusal{
					kind: fault.KindInvalidArgument,
					err: fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
						"%s on %q costs %d and the budget it draws on holds at most %d at once, "+
							"so it can never be admitted — this is not a rate limit, and waiting "+
							"will not clear it. Raise the target's burst or rate_per_hr, or ask "+
							"for less (D284)", action, targetRef, cost, capacity)),
				}, nil
			}
		}
		ok, after, lerr := s.rate.Allow(ctx, limiter.Request{
			TargetRef: budgetRef,
			Principal: subject,
			Action:    action,
			// THE CONNECTOR'S PRICE, IN ITS UNIT (D284). A read costs what
			// the connector says, as a write does: §4.3.4 keys the budget on
			// the TARGET because the upstream counts both.
			Cost: saturate(cost),
		})
		if lerr != nil {
			return nil, lerr
		}
		if !ok {
			// RATE_LIMITED, NOT DENIED, and the two differ in the way that
			// matters most to a caller: this one clears itself. A denial is a
			// grant to review; this is a reason to come back later, and
			// `RetryAfter` is how the caller knows when.
			//
			// THE CAUSE, NOT ONLY THE VICTIM (D143). Under contention the
			// principal being refused is usually not the one responsible, so
			// the record names whoever is over their share — otherwise an
			// operator reading this row throttles the wrong agent.
			why := fmt.Sprintf("the shared budget for %q is exhausted, or %q is past "+
				"its fair share of it while others are competing (§4.3.4)",
				budgetRef, subject)
			var over []string
			if c, canSay := s.rate.(limiter.Contended); canSay {
				if over = c.Monopolisers(budgetRef); len(over) > 0 {
					why += fmt.Sprintf("; currently over share: %v", over)
				}
			}
			// AND TALLIED, so a window of these becomes `denial_storm`, naming
			// whoever the limiter named (D336). Every verb's rate refusal passes
			// here, which is why the tally is fed here and nowhere else.
			if s.denials != nil {
				s.denials.Record(budgetRef, subject, over)
			}
			return &meterRefusal{
				kind: fault.KindRateLimited,
				err: &fault.Error{
					Kind: fault.KindRateLimited, Op: op, Msg: why, RetryAfter: after,
				},
			}, nil
		}
	}

	if s.breaker != nil && !s.breaker.Allow(targetRef) {
		// THE SAME SENTENCE FOR EVERY VERB, which used to be maintained by
		// copying it: an operator reading two rows about one open breaker must
		// not have to work out that they describe the same condition.
		return &meterRefusal{
			kind: fault.KindTargetUnavailable,
			err: fault.New(fault.KindTargetUnavailable, op, fmt.Sprintf(
				"the circuit breaker for %q is open: consecutive failures took it out of "+
					"service, and calls are withheld until a probe succeeds. This is not a "+
					"denial — the grant is fine and the target is not", targetRef)),
		}, nil
	}
	return nil, nil
}

// meterOutcome feeds the call's result back to the two controls.
//
// **THE SECOND HALF OF THE SEAM, AND IT WAS DUPLICATED VERBATIM.** `Query` and
// `enforceOnce` each carried these two blocks, and a drift between them would
// have been invisible until a read and a write disagreed about whether a
// target was healthy — which is D155's own warning, applied to the feedback
// direction rather than the admission one.
//
// Takes the call's error and nothing else, because both controls ask a
// question about the UPSTREAM rather than about the command.
func (s *Server) meterOutcome(ctx context.Context, subject, action, targetRef string,
	callErr error) {

	// THE UPSTREAM'S ANSWER GOES BACK TO THE LIMITER. Being told 429 means the
	// local model was optimistic, and a limiter that only predicts stays wrong
	// for the rest of the window (D14, §5.2.1). A 429 DRAINS the bucket: the
	// upstream is the authority on its own quota.
	if s.rate != nil && callErr != nil && fault.KindOf(callErr) == fault.KindRateLimited {
		s.rate.Observe(ctx, limiter.Request{
			TargetRef: targetRef, Principal: subject, Action: action, Cost: 1,
		}, 429, fault.RetryAfterOf(callErr))
	}

	// **THE BREAKER RECORDS A FAILURE ONLY WHEN THE FAULT IMPLICATES THE TARGET
	// (D200).** It used to ask `Deliberate()`, which decides the WIRE SHAPE and
	// merely correlated: anything not deliberate counted against the target,
	// including a broken local configuration and an unreachable token endpoint.
	// One IdP blip therefore opened the breaker on every target whose credential
	// chained through it — a credential hiccup rendered as a fleet-wide outage,
	// with every log line naming the innocent party.
	//
	// The original rule survives inside `ImplicatesTarget`: a 429 or a policy
	// refusal from the upstream means it is alive and talking, so a DELIBERATE
	// refusal is never a failure however clearly it is the target's (D141).
	if s.breaker != nil {
		s.breaker.Record(targetRef,
			callErr == nil || !fault.KindOf(callErr).ImplicatesTarget())
	}
}

// saturate narrows a price to the limiter's width. SATURATING, never wrapping:
// a price that wrapped past 2^32 would come out small, and a small price is a
// way under the budget.
func saturate(cost uint64) uint32 {
	if cost > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(cost)
}
