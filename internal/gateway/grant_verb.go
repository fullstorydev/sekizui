package gateway

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/audit"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// grantVerb suspends or reinstates a principal's grants at runtime (D146).
//
// THE ALTERNATIVE WAS HOT RELOAD. §4.5 and D10 promise that a rule change does
// not need a redeploy, and building that meant a watcher plus an atomic document
// swap — machinery whose security problem is larger than the convenience, because
// three pieces of state gate the command path and rebuilding any of them makes a
// config edit the way to undo it. D133 had already refused exactly that for
// withdrawals. A governed verb has no document to swap and no derived state to
// rebuild, so there is nothing to launder.
//
// TERMINAL, NOT INTENT/OUTCOME, for the reason withdraw gives: the two-phase
// record exists because a side effect at an external system may or may not have
// landed when the process dies. This touches nothing outside the process.
func (s *Server) grantVerb(ctx context.Context, base *sekizuiv1.Decision,
	cmd *sekizuiv1.Command) (*sekizuiv1.CommandResult, error) {

	const op = "gateway.grantVerb"

	if s.revocations == nil {
		// REFUSES RATHER THAN REPORTING A CLEAN NO-OP, the same rule the pool
		// applies to a revocation with no pool. An operator told a suspension
		// succeeded, when nothing can suspend anything, stops looking.
		return nil, s.recordFailure(ctx, base, fault.New(fault.KindUnavailable, op,
			"this instance has no runtime revocation set, so "+cmd.GetAction()+
				" has nothing to act on and cannot honestly report success"))
	}

	principal, ok := strings.CutPrefix(cmd.GetTargetRef(), principalRefPrefix)
	if !ok || principal == "" {
		return s.refuse(ctx, base, sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
			fault.New(fault.KindInvalidArgument, op,
				cmd.GetAction()+" names a PRINCIPAL rather than a target; use "+
					principalRefPrefix+"<principal>"))
	}

	// THE TRIGGER, WHICH IS NOT THE IDENTITY (§4.11). Identity says who
	// authenticated; trigger says what fired this, and for an anzen rule there is
	// no human behind it at all.
	trigger := "operator:" + base.GetIdentity().GetSubject().GetPrincipal()
	if name := audit.ReflexNameFrom(ctx); name != "" {
		trigger = "anzen:" + name
	}

	if cmd.GetAction() == verb.ReinstateGrant {
		return s.reinstate(ctx, base, principal, trigger)
	}

	reason, _ := cmd.GetArgs().AsMap()["reason"].(string)
	if reason == "" {
		// A SUSPENSION WITH NO STATED REASON is a target that is mysteriously
		// refused and an incident review that cannot reconstruct why. Required
		// rather than defaulted, because a default would be a sentence nobody
		// wrote appearing in the audit log as though somebody had.
		return s.refuse(ctx, base, sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
			fault.New(fault.KindInvalidArgument, op,
				verb.RevokeGrant+" requires a `reason` argument. It is written into the "+
					"decision record and read by whoever asks why this principal stopped "+
					"working, possibly months later"))
	}

	// D158. AN ALREADY-SUSPENDED PRINCIPAL IS CONFIRMED, NOT REFUSED.
	//
	// **THIS SUPERSEDES D146'S CONCLUSION AND KEEPS ITS CONCERN.** D146 refused a
	// repeat so that nobody would "conclude the lever was pulled when it was
	// already pulled by someone else" — a real worry, and an error is the wrong
	// answer to it. Under stress a refusal reads as "it did not work", which
	// sends a second on-call engineer looking for a bigger hammer for a condition
	// already handled. Naming WHO pulled it and WHEN serves D146's concern
	// directly, where a refusal only signalled that something was odd.
	//
	// The rule, shared with withdrawal (D158): refuse when the caller's BELIEF is
	// wrong; confirm when their GOAL is already met. `reinstate_grant` on a
	// principal nobody suspended stays refused, because its precondition is
	// false.
	// **THE LIFETIME IS IN THE MESSAGE, AND THE REGISTRY IS WHERE IT IS
	// WRITTEN (D165).** A withdrawal is durable (D145); this is not (D146) —
	// "until config is redeployed". An operator reading a bare confirmation
	// could reasonably infer permanence this does not have, and then not edit
	// config. `verb.Spec.Lifetime` carries that sentence beside the verb, and
	// `Spec.Validate` refuses a confirming verb that declares none.
	vspec, _ := verb.Lookup(verb.RevokeGrant)
	if prior, already := s.revocations.Revoked(principal); already {
		resp, decided := verb.Repeated(vspec, strconv.Quote(principal), verb.Prior{
			Present: already, At: prior.At, By: prior.Trigger,
			Detail: "reason: " + prior.Reason,
		})
		if decided && resp.Confirm {
			base.MatchedRule = "revoked:" + principal
			return s.confirmRepeat(ctx, base, resp)
		}
	}

	if !s.revocations.Revoke(policy.Revocation{
		Principal: principal, At: s.now(), Trigger: trigger, Reason: reason,
	}) {
		// Unreachable given the check above, and kept: Revocations is its own
		// type with its own concurrency story, and a caller that assumed the
		// check above was sufficient would be assuming an atomicity across two
		// calls that nothing provides.
		return s.refuse(ctx, base, sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
			fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"%q was suspended between the check and the act", principal)))
	}

	// **AND IT REACHES WORK ALREADY IN FLIGHT (P3 criterion 17, D256).**
	//
	// Suspending a principal wrote to `policy.Revocations`, which `ceilings`
	// consults AT ADMISSION — and a job admits once, at the start of its run.
	// So a suspension landing a second later changed nothing about the job
	// already going: an operator saw a successful revocation while the work
	// carried on under the grant they had just pulled. **That is the widest
	// window in the system between authorisation and use.**
	//
	// SYMMETRIC WITH `revoke_credential`, which has always reached in-flight
	// work through the pool (D128, D129). Break-glass stopped live work on the
	// credential axis and not on the grant axis, for no reason anybody had
	// decided.
	//
	// **BEFORE THE RECORD IS WRITTEN, so the row can say how many.** An
	// operator pulling a lever at 03:00 needs the count in the same row as the
	// act, not inferred from job records they would have to go and find.
	var stopped []string
	if s.jobs != nil {
		stopped = s.jobs.CancelFor(principal)
	}
	// **THE REASON IS WRITTEN INTO THE RECORD (D340, CONTRACTS 158).** The check
	// above said so — "it is written into the decision record" — and it was
	// not: the reason reached the in-memory suspension and a log line, and
	// every suspension's record, an operator's included, carried none. Found
	// by the hotfix test for `revoke_grant` fired from a rule.
	base.Reason = reason
	if len(stopped) > 0 {
		base.Reason = fmt.Sprintf("%s; stopped %d job(s) already running: %s",
			base.Reason, len(stopped), strings.Join(stopped, ", "))
	}

	base.MatchedRule = "revoked:" + principal
	decisionID, err := s.recorder.Terminal(ctx, base)
	if err != nil {
		return nil, err
	}

	// SAYS OUT LOUD THAT IT IS NOT DURABLE. This is the asymmetry with D133 and
	// the one thing an operator must not misunderstand: config remains the
	// authority on grants, so a redeploy reasserts what config says and this
	// suspension goes with it. An operator who revokes during an incident and
	// does not also edit config gets the principal back at the next deploy.
	s.log.Warn("grants suspended at runtime; NOT DURABLE",
		"principal", principal, "trigger", trigger, "reason", reason,
		"decision_id", decisionID,
		"jobs_stopped", len(stopped),
		"lifted_by", "a redeploy, or "+verb.ReinstateGrant,
		"action_required", "edit the grant in configuration, or this returns on the next deploy")

	return &sekizuiv1.CommandResult{DecisionId: decisionID, Status: sekizuiv1.Status_STATUS_OK}, nil
}

// reinstate lifts a runtime suspension.
func (s *Server) reinstate(ctx context.Context, base *sekizuiv1.Decision,
	principal, trigger string) (*sekizuiv1.CommandResult, error) {

	const op = "gateway.reinstate"

	rev, was := s.revocations.Reinstate(principal)
	if !was {
		// Symmetric with restore_target's rule (D133): reinstating somebody
		// nobody suspended is refused, because a mistyped principal that answers
		// OK is how an operator concludes the fleet is healthy.
		vspec, _ := verb.Lookup(verb.ReinstateGrant)
		resp, _ := verb.Repeated(vspec, principal, verb.Prior{Present: false})
		return s.refuse(ctx, base, sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
			fault.New(fault.KindInvalidArgument, op, resp.Reason))
	}

	base.MatchedRule = "reinstated:" + principal
	decisionID, err := s.recorder.Terminal(ctx, base)
	if err != nil {
		return nil, err
	}

	s.log.Warn("runtime grant suspension lifted; this principal may act again",
		"principal", principal, "trigger", trigger,
		"suspended_at", rev.At, "suspended_by", rev.Trigger, "original_reason", rev.Reason,
		"decision_id", decisionID)

	return &sekizuiv1.CommandResult{DecisionId: decisionID, Status: sekizuiv1.Status_STATUS_OK}, nil
}
