// Re-establish-and-retry: the loop that traverses the enforcement path TWICE
// (D203, D204).
//
// **THIS FILE IS THE WHOLE CONTROL-FLOW CHANGE, AND IT IS SEPARATE FOR THAT
// REASON.** D203 was recorded and deliberately not built in the session that
// designed it, because it changes how the one enforcement path is entered and
// that argument should be reviewable on its own. It is: `enforceOnce` is
// untouched by it apart from one report line, and everything the second attempt
// is allowed to do is decided here, in sixty lines somebody can read at once.
//
// WHAT THE SECOND ATTEMPT IS. Not a retry of the CALL — step 8c already does
// that, with the same Target holding the same stale material, so retrying there
// cannot help. Re-establishing means invalidating the cached credential and
// going back through resolve, which is step 5, which is above step 8c. D203
// concluded from that that the second attempt belongs at step 5. D204 concluded
// it belongs above step 1, and the difference is every ceiling in between.
//
// DESIGN.md references: §4.7.16, D18, D141, D143, D146, D152, D163, D202, D203,
// D204, D213.
package gateway

import (
	"context"

	"google.golang.org/protobuf/proto"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// reestablishPrefix marks a command as the second attempt, in `produced_by`.
//
// A PREFIX ON A FIELD THAT IS ALREADY AUDITED rather than a new field. Causation
// exists on both Command and Decision, `produced_by` is documented as "what
// emitted this" with `command:<decision_id>` as one of its own examples, and a
// row that says `reestablish:<id>` is legible to a human and greppable by a
// warehouse without a proto change or a census entry (D164).
const reestablishPrefix = "reestablish:"

// reattempt is what one traversal reports back to the loop.
//
// See enforceOnce's doc for why this arrives as an out-parameter rather than as
// a return value. The zero value means "nothing to do", which is the answer on
// every path except one.
type reattempt struct {
	// what is the producer's marker, already gated by D163's class:
	// `ReestablishNone` means there is nothing to do, which is the answer on
	// every path except one.
	//
	// **IT CARRIES WHICH STATE RATHER THAN MERELY WHETHER (D213).** A bool was
	// enough while a credential was the only thing a far side could reject; an
	// expired MCP session is re-established by discarding a pooled client, and
	// running the credential remedy for it would force a mint nobody needed and
	// raise `credential_churn` about a target whose credential is fine.
	what fault.Reestablishment

	// decisionID is the row that recorded the failure — attempt 2's causation
	// parent, and the id an operator walks BACKWARDS from (D202).
	decisionID string
}

// Enforce is THE enforcement path, and there is exactly one of it.
//
// Takes an ALREADY-ESTABLISHED identity, so both callers share it:
//
//	Execute       — identity from the mTLS peer certificate
//	reflex.Engine — identity constructed for the rule's own principal
//
// **IT IS A LOOP OVER `enforceOnce` AND NOT THE PATH ITSELF (D204).** Every
// caller keeps calling this, so nobody gets re-establishment by wiring and
// nobody misses it by forgetting — which matters because there are three
// callers and a wrapper applied at one of them is exactly the drift D18 exists
// to prevent.
//
// **THE SECOND ATTEMPT RE-RUNS EVERY CEILING, WHICH IS THE POINT.** A principal
// suspended between the attempts (D146), a budget exhausted between them (D143),
// a breaker opened between them (D141) and a target withdrawn between them all
// refuse the attempt that would otherwise have gone out — and the call that
// lands on somebody's system at T+Δ is authorised at T+Δ rather than one call
// earlier. Break-glass placement is the sharpest of them: step 4b sits before
// resolve so that "the first act of revoking a credential" is not "go and fetch
// it", and a re-resolve that skipped it would be a FORCED fetch past the guard
// written to prevent the ordinary one.
//
// It also costs nothing in the audit. Two traversals write two intent rows and
// two outcome rows through the code that already writes them, and
// `credential_posture.version` is on every row (D130) — so the pair says which
// version drew the 401 and which replaced it, with no field invented for it.
func (s *Server) Enforce(ctx context.Context, id *sekizuiv1.Identity,
	cmd *sekizuiv1.Command) (*sekizuiv1.CommandResult, error) {

	var again reattempt
	result, err := s.enforceOnce(ctx, id, cmd, &again)
	if again.what == fault.ReestablishNone || !s.mayReestablish(cmd) {
		return result, err
	}

	s.reestablish(again.what, cmd.GetTargetRef())

	// DISCARDED DELIBERATELY, AND THIS IS NOT D202'S DEFECT. There is no third
	// traversal to report into — this function calls `enforceOnce` twice and
	// returns — so attempt 2's report has no reader by construction. Passing the
	// live struct and ignoring it would be the value-produced-and-dropped shape;
	// a scratch one says the answer is not wanted (GO-PRIMER §15ad).
	var discard reattempt
	return s.enforceOnce(ctx, id, s.reestablished(cmd, again.decisionID), &discard)
}

// reestablish performs the remedy the producer asked for, and NOTHING ELSE.
//
// **ONE SWITCH, ABOVE THE WHOLE PATH, AND THE EXHAUSTIVENESS IS THE POINT.** The
// two remedies are not interchangeable and neither is a superset of the other:
// a forced mint leaves a dead session in the pool, and discarding a pooled
// client leaves a rejected credential cached. Running both "to be safe" is worse
// than running the wrong one, because it spends a secret-manager mint and raises
// a churn signal on every session expiry — turning a routine event into an anzen
// condition.
func (s *Server) reestablish(what fault.Reestablishment, ref string) {
	switch what {
	case fault.ReestablishCredential:
		// THE FORCED MINT. One caller, above the whole path, for the reason
		// resolver.Invalidate states: this is an amplification primitive aimed at
		// the secret manager, and it must not be reachable from a driver.
		//
		// **D152 STILL REFUSES WHATEVER OLDER VERSION THIS TURNS UP**, because
		// Invalidate drops the cached entry and leaves the high-water mark alone.
		// That is the interaction worth noticing rather than assuming: the
		// attack's most valuable outcome — getting us to pick up a rolled-back
		// credential — is closed by a guard built for a different reason, and the
		// second attempt then refuses with `REFUSED_BY_CREDENTIAL` beside the
		// first row.
		s.resolver.Invalidate(ref)

		// **RAISED BESIDE THE INVALIDATION, WHICH IS THE SAME FACT.** A forced
		// mint and the churn it constitutes are one event, and recording them in
		// two places is how one of them comes to be forgotten.
		//
		// TWO READERS, BOTH DELIBERATE. The COUNTER is scraped, and it is what a
		// perimeter can see while an attack is happening — the audit log is local
		// and the warehouse is descoped from this phase (D169), so the WAL
		// explains the incident afterwards rather than holding the line during
		// it. The windowed COUNT is what `credential_churn` is published from, as
		// a level, so a rule can quarantine the target before the shared WAL and
		// the shared secret-manager quota turn a per-target attack into a
		// fleet-wide one.
		s.metrics.IncrFor("credential_churn_total", ref)
		if s.churn != nil {
			s.churn.Record(ref)
		}

	case fault.ReestablishSession:
		// **DISCARD THE POOLED CLIENT, AND TOUCH NEITHER THE CREDENTIAL NOR THE
		// CHURN SIGNAL (D213).** The next borrow finds no entry and builds one,
		// which for a stateful MCP target means a fresh `initialize` — so the
		// second traversal carries a live session without this function knowing
		// what a session is.
		//
		// **NO CHURN COUNTER, DELIBERATELY, and it is not an omission to tidy up
		// later.** `credential_churn` exists because a forced mint is an
		// amplification primitive aimed at a shared secret manager with a shared
		// quota; a re-handshake is one extra round trip to the same server we
		// were already talking to, bounded by the same `reestablish_attempts`.
		// Counting it would make an anzen rule quarantine targets for behaving
		// normally, which is D77's crying wolf with a quarantine attached.
		//
		// **NIL-TOLERANT for the reason `s.churn` is:** a Server built without a
		// pool refuses the break-glass verbs rather than pretending, and here it
		// simply has no client to discard — the second traversal still runs, and
		// a driver holding no pooled session was never going to have a stale one.
		if s.pool != nil {
			s.pool.DiscardClients(ref)
		}

	case fault.ReestablishNone:
		// UNREACHABLE: the caller returns before this. Named rather than left to
		// a default so the switch is total and a third member added later fails
		// the build here instead of silently doing nothing — which is the
		// unpopulated-field defect this codebase keeps finding, in control flow.
	}
}

// mayReestablish answers whether this command gets a second traversal.
//
// **ONE GATE, AND THE FIRST DRAFT HAD TWO.** It also refused a command whose
// causation already named a re-establishment — a depth backstop, on the argument
// that the fact travels ON the command and so survives a later restructuring of
// the loop. `make mutate` disagreed and was right: the mutation that removed it
// SURVIVED, because `Enforce` calls `enforceOnce` at most twice by construction,
// so there is no third traversal for a depth gate to stop. A guard nothing can
// reach is the defect this codebase keeps finding, and it is worse when it is a
// SAFETY guard, because it reads as a bound somebody has checked.
//
// **DEPTH IS BOUNDED STRUCTURALLY INSTEAD**: two calls, written out, not a loop.
// If that ever becomes a loop, this comment is the note saying the backstop has
// to come back — and the mutation to prove it belongs with it.
func (s *Server) mayReestablish(cmd *sekizuiv1.Command) bool {
	// PER TARGET, FROM THE POLICY THAT ALREADY TRAVELS PER TARGET (D142). One
	// means never, which is the block an operator asked for and is expressible
	// because the field copies `RetryAttempts`' escape from the
	// zero-means-unlimited trap. Zero means the deployment default.
	attempts := s.retry.For(cmd.GetTargetRef()).Policy().ReestablishAttempts
	if attempts == 0 {
		attempts = config.MaxReestablishAttempts
	}
	return attempts > 1
}

// reestablished builds attempt 2's command: the same command, carrying causation
// back to the row that explains attempt 1.
//
// **CLONED, NEVER MUTATED.** The caller owns the message it passed in — the
// reflex engine holds one per rule firing and `Execute` holds the one it decoded
// off the wire — and stamping causation onto it would change a value somebody
// else is still reading. The same reasoning `fault.WithDecisionID` records for
// the error it copies.
//
// THE ROOT IS PRESERVED WHEN THERE IS ONE. A command that arrived from a reflex
// already has a chain, and re-establishment is one more hop in it rather than
// the start of a new one — otherwise the row would claim a re-mint originated a
// causal chain that a rule firing originated twenty milliseconds earlier.
func (s *Server) reestablished(cmd *sekizuiv1.Command, decisionID string) *sekizuiv1.Command {
	next, _ := proto.Clone(cmd).(*sekizuiv1.Command)

	root := cmd.GetCausation().GetRootId()
	if root == "" {
		root = decisionID
	}
	next.Causation = &sekizuiv1.Causation{
		RootId:   root,
		ParentId: decisionID,
		Depth:    cmd.GetCausation().GetDepth() + 1,
		// NAMES THE ROW IT CAME FROM, not merely the mechanism. "A
		// re-establishment happened" is not a question anybody asks; "why was
		// this target called twice at 14:03" is, and the answer is one id away.
		ProducedBy: reestablishPrefix + decisionID,
	}
	return next
}
