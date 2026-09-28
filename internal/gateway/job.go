package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/internal/kyuushin"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/pkg/audit"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// JobRunner is the seam onto internal/kyuushin, declared here so the gateway
// depends on a method set rather than on a concrete runner (GO-PRIMER §2.1).
//
// **IT TAKES A `kyuushin.Job` RATHER THAN THE GATEWAY'S OWN STRUCT, WHICH IS A
// DELIBERATE EXCEPTION TO THE SEAM IDIOM.** The other seams here — Resolver,
// Tracer, ChurnRecorder — name only types the gateway already owns, so the
// package on the far side is invisible. This one cannot: the runner needs a
// resolved `connector.Target`, a `connector.Source` and the caller's identity,
// and a gateway-local mirror of that would need a hand-written adapter at the
// wiring site to convert between two structs with identical fields. That
// adapter is a place to drop a field silently, which is the one failure this
// binding cannot afford — it is how the caller's identity would stop reaching
// the poll's admission (D250).
type JobRunner interface {
	Submit(ctx context.Context, j kyuushin.Job) (string, error)
	Cancel(id string) bool

	// Status reports how a job is going, and WHO OWNS IT so this package can
	// authorise the question. False means no record here.
	Status(id string) (kyuushin.Status, bool)

	// Results is a caller's job's output, held for that caller (D267). False
	// means none are held — never run here, a schedule, or already dropped.
	Results(id string) (*kyuushin.Results, bool)

	// CancelFor stops every running job belonging to a principal, so
	// break-glass reaches work already in flight (P3 criterion 17).
	CancelFor(principal string) []string
}

// JobGate returns the enforcement seam the runner admits every poll through.
//
// **THE POINT IS THAT THERE IS NOTHING TO IMPLEMENT HERE.** `kyuushin.Gate`
// exists because the runner sits below this package in the import graph and
// calling up would be a cycle; what it must NOT become is a second, friendlier
// copy of the enforcement path, which is exactly what `Query` became one
// omission at a time (D155). So the adapter below is a forwarder onto
// `s.ceilings` and `s.policy` and holds no decision of its own.
func (s *Server) JobGate() kyuushin.Gate { return jobGate{s: s} }

// jobGate adapts the Server onto kyuushin.Gate.
//
// UNEXPORTED AND CONSTRUCTED ONLY BY JobGate, so there is no way to build one
// around anything other than the real enforcement path.
type jobGate struct{ s *Server }

// Admit runs the same ceilings and the same policy call an Execute takes.
//
// **NO ADMISSION CONTROL AND NO IDENTITY VERIFICATION, AND BOTH ABSENCES ARE
// DELIBERATE RATHER THAN OVERSIGHTS.** `s.admission` bounds concurrent RPCs on
// the wire and this is not one; `s.verifier` reads an mTLS peer and there is no
// peer behind a schedule. Everything from the ceilings onward is identical,
// which is the half D18 is about.
//
// **AND §4.3.4's METER, WHICH IS THE STAGE THIS VERB WAS ABOUT TO INHERIT A
// HOLE IN (D253).** CONTRACTS 118 opened as "the job path is not metered" and
// closed as something larger: `Query` was not metered either, and the guard
// could not see it because the meters had never been extracted. The fix is
// the shared `s.meters`, not a copy of `enforceOnce`'s steps 8a and 8b.
func (g jobGate) Admit(ctx context.Context, id *sekizuiv1.Identity,
	action, targetRef string) error {

	const op = "gateway.jobGate.Admit"
	s := g.s
	return s.admitUnasked(ctx, id, targetRef, unasked{
		op: op, action: action, authorise: true, budgetRef: targetRef,
		price: func() (uint64, error) { return s.pollPrice(op, targetRef) },
	})
}

// unasked is what distinguishes one call Sekizui makes UNASKED from another
// (D249, D311): a poll and a drift comparison share every stage, and differ
// only in these four facts.
type unasked struct {
	op, action string

	// authorise: the principal needs a GRANT. True for a poll (its source
	// principal is granted `<kind>.poll`); false for the built-in drift
	// principal, which is granted nothing because a grant is how a deployment
	// would switch a safety check off (D311).
	authorise bool

	// price is the call's worst-case cost in its connector's unit (D284).
	price func() (uint64, error)

	// budgetRef is the bucket that pays: the target's own for a poll, its
	// SYSTEM budget for a comparison, so consumers never pay for Sekizui's
	// safety traffic (D311).
	budgetRef string
}

// admitUnasked is THE admission sequence for every call Sekizui makes unasked —
// a scheduled poll and a drift comparison (D249, D311). ONE FUNCTION, because
// the drift gate's first version copied only the ceilings and quietly skipped
// the withdrawal check and the meter: a shorter path that read like a shorter
// version of the same one (D155's shape, found by P4 step 32d). Both gates now
// delegate here and do nothing else.
func (s *Server) admitUnasked(ctx context.Context, id *sekizuiv1.Identity, targetRef string,
	u unasked) error {

	op, action := u.op, u.action
	subject := id.GetSubject().GetPrincipal()

	// EVERY CEILING, THE SAME ONES Execute AND Query APPLY, IN THE SAME ORDER.
	//
	// No idempotency key and no causation: a poll is not a caller's retryable
	// command, and the job's causation lives on the envelopes it produces
	// rather than on its admission (D247).
	_, releaseCeilings, ceilingRef := s.ceilings(ctx, id, subject, action, targetRef, "", nil)
	defer releaseCeilings()
	if ceilingRef != nil {
		// RECORDED HERE RATHER THAN RETURNED FOR THE RUNNER TO RECORD, which is
		// what `Gate.Record`'s doc comment already promises: "every REFUSAL
		// (which the implementation writes from Admit, where the decision was
		// made)". The runner could not write this row honestly anyway — it does
		// not know which stage refused.
		if _, rerr := s.recorder.Terminal(ctx, ceilingRef.decision); rerr != nil {
			return rerr
		}
		return ceilingRef.err
	}

	// POLICY, FOR A PRINCIPAL THAT NEEDS A GRANT. The built-in drift principal
	// does not (D311): its admission is recorded as exactly that, so the audit
	// row never pretends a grant was consulted.
	dec := policy.Decision{Verdict: sekizuiv1.Verdict_VERDICT_ALLOW, Rule: "builtin:" + subject,
		Reason: "a built-in principal, admitted without a grant and under every ceiling (D311)"}
	if u.authorise {
		var err error
		if dec, err = s.policy.Authorise(ctx, policy.Request{
			Identity: id, Action: action, TargetRef: targetRef,
		}); err != nil {
			return err
		}
	}
	base := &sekizuiv1.Decision{
		Identity: id, Action: action, TargetRef: targetRef,
		Verdict: dec.Verdict, MatchedRule: dec.Rule, Reason: dec.Reason,
		ReflexName: audit.ReflexNameFrom(ctx),
	}
	if dec.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
		base.RefusedBy = sekizuiv1.RefusedBy_REFUSED_BY_POLICY
		if _, rerr := s.recorder.Terminal(ctx, base); rerr != nil {
			return rerr
		}
		return fault.New(fault.KindDenied, op, fmt.Sprintf("%s (%s)", dec.Reason, dec.Rule))
	}

	// A WITHDRAWN TARGET STOPS A POLL TOO (D133, D155).
	//
	// The afferent plane's copy of the hole the probe found on `Query`: a
	// credential revoked as compromised must not keep being used to FETCH,
	// which is the direction §4.1.1 calls "a data-exfiltration path". A poll
	// repeats on a timer, so leaving it out would mean a revoked credential in
	// use every thirty seconds until somebody restarted the process.
	if s.pool != nil {
		if sev, withdrawn := s.pool.Withdrawn(targetRef); withdrawn {
			werr := pool.WithdrawnErr(op, targetRef, sev)
			base.Verdict = sekizuiv1.Verdict_VERDICT_DENY
			base.RefusedBy = sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL
			base.Reason = werr.Error()
			if _, rerr := s.recorder.Terminal(ctx, base); rerr != nil {
				return rerr
			}
			return werr
		}
	}

	// §4.3.4'S METER, THE SAME STAGE Execute AND Query APPLY (D253).
	//
	// **PER POLL, WHICH IS THE ONLY CADENCE THAT MAKES SENSE, and it is why
	// this is not in `StartJob`.** For the synchronous verbs one RPC is one
	// outbound call, so metering at the verb and metering at the call are the
	// same moment. A job breaks that: one `StartJob` produces N calls over
	// time, and a recurrence produces them for ever. Metering at submission
	// would take one token for unbounded work — which is the shape CONTRACTS
	// 70 complains about, arriving in the limiter instead of in `MaxBytes`.
	//
	// **RECORDED AS A TERMINAL RATHER THAN AN OUTCOME, and the asymmetry is
	// `Gate.Record`'s doing rather than this stage's.** A poll has no intent
	// row to hang an outcome on, because the runner deliberately does not
	// record one per tick — ten sources on a thirty-second interval is D178's
	// disk amplification with Sekizui as the hostile party. So the refusal is
	// a complete row on its own.
	//
	// **PRICED AT THE POLL'S WORST CASE, NOT AT ONE (D284).** One poll is not
	// one call: a Fullstory events poll is a sessions call plus a context read
	// per session, and this stage used to take a single token for all of them.
	cost, perr := u.price()
	if perr != nil {
		base.Verdict = sekizuiv1.Verdict_VERDICT_DENY
		base.Reason = perr.Error()
		if _, rerr := s.recorder.Terminal(ctx, base); rerr != nil {
			return rerr
		}
		return perr
	}
	meterRef, merr := s.meters(ctx, subject, action, targetRef, u.budgetRef, cost)
	if merr != nil {
		return merr
	}
	if meterRef != nil {
		base.Verdict = sekizuiv1.Verdict_VERDICT_DENY
		base.RefusedBy = meterRef.stage()
		base.Reason = meterRef.err.Error()
		if _, rerr := s.recorder.Terminal(ctx, base); rerr != nil {
			return rerr
		}
		return meterRef.err
	}
	return nil
}

// pollPrice is what one poll of targetRef costs, in its connector's unit
// (D284), priced from the target's DECLARATION — nothing is resolved yet, and a
// price may not depend on a credential (connector.Configured).
func (s *Server) pollPrice(op, targetRef string) (uint64, error) {
	if s.doc == nil {
		return 1, nil
	}
	for _, t := range s.doc.Targets {
		if t.Ref != targetRef {
			continue
		}
		if why, q := s.quarantined[t.Kind]; q {
			return 0, fault.New(fault.KindConfig, op, fmt.Sprintf(
				"connector %q is quarantined — it is not sound: %s (D282)", t.Kind, why))
		}
		d, ok := s.drivers[t.Kind]
		if !ok {
			return 0, fault.New(fault.KindConfig, op, fmt.Sprintf("no driver registered for kind %q", t.Kind))
		}
		cost, err := d.Meter().Poll(connector.Configuration(t.Ref, t.Settings))
		if err != nil {
			return 0, fault.Wrap(fault.KindConfig, op, "the connector cannot price this poll", err)
		}
		return cost, nil
	}
	return 0, fault.New(fault.KindNotFound, op, fmt.Sprintf("no target %q is declared", targetRef))
}

// driftPrice is what one drift comparison of targetRef costs (D311), from the
// connector's own DriftCost — pollPrice's shape, for the other unasked call.
func (s *Server) driftPrice(op, targetRef string) (uint64, error) {
	if s.doc == nil {
		return 1, nil
	}
	for _, t := range s.doc.Targets {
		if t.Ref != targetRef {
			continue
		}
		if why, q := s.quarantined[t.Kind]; q {
			return 0, fault.New(fault.KindConfig, op, fmt.Sprintf(
				"connector %q is quarantined — it is not sound: %s (D282)", t.Kind, why))
		}
		d, ok := s.drivers[t.Kind]
		if !ok {
			return 0, fault.New(fault.KindConfig, op, fmt.Sprintf("no driver registered for kind %q", t.Kind))
		}
		cost, err := d.Meter().Drift(connector.Configuration(t.Ref, t.Settings))
		if err != nil {
			return 0, fault.Wrap(fault.KindConfig, op, "the connector cannot price this comparison", err)
		}
		return cost, nil
	}
	return 0, fault.New(fault.KindNotFound, op, fmt.Sprintf("no target %q is declared", targetRef))
}

// Record writes the decision for a completed poll (see kyuushin.Gate.Record for
// why this is not called once per tick).
//
// **IT MINTS NOTHING, AND THAT IS THE WHOLE CHANGE archcheck FORCED.** The
// first version built an identity here from a principal string — a chain of
// one, which for `agent:triage on behalf of human:alice` is a record naming one
// of the two. `TestOnlyNamedSitesMintAnIdentity` refused the site rather than
// the shape, which is the better error: the fix was not to justify the mint
// but to carry the identity that already existed (D250).
func (g jobGate) Record(ctx context.Context, id *sekizuiv1.Identity,
	action, targetRef string, events int) error {

	_, err := g.s.recorder.Terminal(ctx, &sekizuiv1.Decision{
		Identity: id,
		Action:   action, TargetRef: targetRef,
		Verdict:     sekizuiv1.Verdict_VERDICT_ALLOW,
		MatchedRule: "poll:completed",
		Reason:      fmt.Sprintf("%d events", events),
	})
	return err
}

// Begin writes a productive poll's intent before it publishes (D272).
func (g jobGate) Begin(ctx context.Context, id *sekizuiv1.Identity,
	action, targetRef string, atRisk int, note string) (string, error) {

	return g.s.recorder.Intent(ctx, &sekizuiv1.Decision{
		Identity: id,
		Action:   action, TargetRef: targetRef,
		Verdict:     sekizuiv1.Verdict_VERDICT_ALLOW,
		MatchedRule: "poll:publishing",
		Reason:      fmt.Sprintf("%d event(s) about to be published%s", atRisk, note),
	})
}

// Gap records a declared loss (D174, D275): WHICH events, from WHICH window,
// and the connector's own reason it cannot re-read them — in the record's
// detail, so an operator can go and check each one.
func (g jobGate) Gap(ctx context.Context, id *sekizuiv1.Identity, action, targetRef string,
	lost []string, a cursor.Attempt, why string) error {

	ids := make([]*structpb.Value, 0, len(lost))
	for _, l := range lost {
		ids = append(ids, structpb.NewStringValue(l))
	}
	_, err := g.s.recorder.Terminal(ctx, &sekizuiv1.Decision{
		Identity: id,
		Action:   action, TargetRef: targetRef,
		Verdict:     sekizuiv1.Verdict_VERDICT_GAP,
		MatchedRule: "poll:gap",
		Reason: fmt.Sprintf("%d event(s) may never have been delivered: a poll begun at %s was "+
			"interrupted, and this source declared it cannot re-read the window — %s",
			len(lost), a.At.Format(time.RFC3339), why),
		Effect: &sekizuiv1.Effect{Success: false, Detail: &structpb.Struct{Fields: map[string]*structpb.Value{
			"lost":        structpb.NewListValue(&structpb.ListValue{Values: ids}),
			"window_from": structpb.NewStringValue(a.From),
			"window_to":   structpb.NewStringValue(a.To),
		}}},
	})
	return err
}

// Complete closes a productive poll's intent with the count published (D272).
// The same outcome shape Finish writes, under its own name: a poll completing
// and a job ending are different events in the log.
func (g jobGate) Complete(ctx context.Context, decisionID string, published int) error {
	return g.Finish(ctx, decisionID, published, nil)
}

// Finish closes the intent `StartJob` wrote, saying how the job ended.
//
// **THREE STATES, AND THE LOG TELLS THEM APART BY SHAPE RATHER THAN BY A
// STATUS STRING (P3 criterion 15).**
//
//	finished      an intent with an outcome, success true, `events` in detail
//	failed        an intent with an outcome, success false, `error` set
//	still running an intent with NO outcome
//
// **`events` IS RECORDED EVEN WHEN IT IS ZERO, which is the arm that matters.**
// The pair that gets conflated is FAILED and FINISHED-WITH-NOTHING-TO-SAY:
// both produce no envelopes, and "no envelopes" is not a distinction. Success
// plus an explicit count is; and a count is recorded alongside a FAILURE too,
// because a job that published four envelopes and then failed published four
// (D177).
//
// **THE THIRD STATE IS AN ABSENCE, AND THE RESIDUAL IS NAMED RATHER THAN
// PAPERED OVER.** An intent with no outcome means "running, or the process
// died while it was" — §5.2.2 chose that shape deliberately, because a record
// saying an action was attempted with no outcome is the truth after a crash.
// Within one process the runner knows which; across a restart nothing does,
// and inventing a "running" heartbeat per job would be D178's amplification
// for a fact that is already legible.
func (g jobGate) Finish(ctx context.Context, decisionID string, events int, cause error) error {
	effect := &sekizuiv1.Effect{
		Success: cause == nil,
		// **THE COUNT GOES IN `detail`, NOT IN A NEW FIELD.** `Effect.detail`
		// is the free-form half already carrying what a driver returned, and
		// a job's result is the same kind of fact. A typed field would be a
		// schema change for one producer, which is the shape D138 warns
		// about when the existing carrier already fits.
		Detail: &structpb.Struct{Fields: map[string]*structpb.Value{
			"events": structpb.NewNumberValue(float64(events)),
		}},
	}
	if cause != nil {
		effect.Error = cause.Error()
	}
	return g.s.recorder.Outcome(ctx, decisionID, effect)
}

// StartJob is P3 criterion 14: a governed asynchronous job.
//
// **THE WHOLE VERB IS THIS FUNCTION REFUSING TO BE INTERESTING.** A job is "a
// governed action with a longer life and not a different kind of thing" — same
// action names, same grants, same ceilings — so every line before the submit is
// the line `Execute` runs, in the order `Execute` runs it, calling the same
// `s.ceilings`. D155 is the record of what the abbreviated copy costs, and the
// temptation here is stronger than it was on `Query`: a job is asynchronous, so
// anything omitted fails minutes later in a goroutine rather than in the
// caller's face.
//
// The AST guard in `p1_verb_symmetry_test.go` names this method, so a future
// edit that drops the shared sequence fails the build rather than the incident.
func (s *Server) StartJob(ctx context.Context, req *sekizuiv1.StartJobRequest) (
	*sekizuiv1.StartJobResponse, error) {

	const op = "gateway.StartJob"

	release, err := s.admission.Acquire(ctx, "StartJob")
	if err != nil {
		return nil, toStatus(err)
	}
	defer release()

	// NIL MEANS THE VERB IS UNAVAILABLE, NOT A SILENT NO-OP — the reading
	// `pool` and `revocations` already get. A deployment with no runner
	// wired would otherwise accept a job, return an id, and run nothing.
	if s.jobs == nil {
		// UNAVAILABLE RATHER THAN DENIED: nothing was decided about this
		// caller, and telling them they were refused would send them to read a
		// grant that is perfectly fine.
		return nil, toStatus(fault.New(fault.KindUnavailable, op,
			"this deployment has no job runner wired, so no job can be started; "+
				"a job id returned by a server that runs nothing is worse than a refusal"))
	}

	cmd := req.GetCommand()
	if cmd.GetAction() == "" || cmd.GetTargetRef() == "" {
		return nil, toStatus(fault.New(fault.KindInvalidArgument, op,
			"a job needs both an action and a target_ref"))
	}

	id, err := s.verifier.Verify(ctx)
	if err != nil {
		// No decision record, for Execute's reason: identity failed, so there
		// is no principal to attribute one to.
		return nil, toStatus(err)
	}
	subject := id.GetSubject().GetPrincipal()

	refuse := func(d *sekizuiv1.Decision, by sekizuiv1.RefusedBy, cause error) (
		*sekizuiv1.StartJobResponse, error) {

		d.RefusedBy = by
		// **AN ALLOW VERDICT IS OVERWRITTEN, NOT ONLY AN UNSPECIFIED ONE, and
		// D228's guard is what found the difference.**
		//
		// Every refusal after the policy stage reuses `base`, which by then
		// carries `VERDICT_ALLOW` — policy DID allow, and something later
		// refused. Guarding only on UNSPECIFIED left those rows saying a
		// command that never ran was PERMITTED, and naming the grant that
		// permitted it: "a refusal never records as permission" (D228), in a
		// verb written after the decision that says so.
		//
		// **IT AFFECTED EVERY POST-POLICY REFUSAL ON THIS VERB, not just the
		// budget one** — resolve failures, the withdrawal check and the
		// not-a-Source refusal all shared it, and none had an acceptance step
		// driving them, so the row was wrong from the day the verb was
		// written and nothing had looked. Step 35 is the first step to refuse
		// after an allow here, and the report refused to be written.
		//
		// ESCALATE AND BUDGET_EXCEEDED SURVIVE, because those ARE refusal
		// verdicts and flattening them to DENY would lose which one happened.
		switch d.Verdict {
		case sekizuiv1.Verdict_VERDICT_UNSPECIFIED, sekizuiv1.Verdict_VERDICT_ALLOW:
			d.Verdict = sekizuiv1.Verdict_VERDICT_DENY
		}
		if d.Reason == "" {
			d.Reason = cause.Error()
		}
		decisionID, rerr := s.recorder.Terminal(ctx, d)
		if rerr != nil {
			return nil, toStatus(rerr)
		}
		// A DELIBERATE REFUSAL IS A RESULT (D135), and it says WHICH STAGE
		// (D155). An empty `job_id` alone would be a negative assertion, which
		// is the shape that hid a missing status mapping for a whole phase
		// (D138).
		return &sekizuiv1.StartJobResponse{
			DecisionId: decisionID,
			Status:     fault.KindOf(cause).Status(),
			Reason:     cause.Error(),
			RefusedBy:  by,
		}, nil
	}

	// EVERY CEILING, SHARED WITH Execute AND Query (D18, D155).
	_, releaseCeilings, ceilingRef := s.ceilings(ctx, id, subject,
		cmd.GetAction(), cmd.GetTargetRef(), cmd.GetIdempotencyKey(), cmd.GetCausation())
	defer releaseCeilings()
	if ceilingRef != nil {
		return refuse(ceilingRef.decision, ceilingRef.by, ceilingRef.err)
	}

	dec, err := s.policy.Authorise(ctx, policy.Request{
		Identity: id, Action: cmd.GetAction(), TargetRef: cmd.GetTargetRef(),
		Args: cmd.GetArgs().AsMap(),
	})
	if err != nil {
		return nil, toStatus(err)
	}

	base := &sekizuiv1.Decision{
		Identity:  id,
		Trace:     traceFor(ctx, cmd),
		Action:    cmd.GetAction(),
		TargetRef: cmd.GetTargetRef(),
		// **NO REFLEX MAY START A JOB YET, AND THE FIELD IS STAMPED ANYWAY.**
		// D248 settles the eligibility question for the synchronous path at
		// step 36; until then this is the honest value rather than a blank
		// column that would have to be backfilled.
		ReflexName:     audit.ReflexNameFrom(ctx),
		Verdict:        dec.Verdict,
		MatchedRule:    dec.Rule,
		Reason:         dec.Reason,
		IdempotencyKey: cmd.GetIdempotencyKey(),
		Causation:      cmd.GetCausation(),
	}

	if dec.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
		return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
			fault.New(policyKind(dec.Verdict), op,
				fmt.Sprintf("%s (%s)", dec.Reason, dec.Rule)))
	}

	// **BOUNDED BEFORE IT RUNS, AND BEFORE THE CREDENTIAL IS EVEN FETCHED
	// (P3 criterion 18, CONTRACTS 70, D257).**
	//
	// "Review five sessions" and "review five million" are the same sentence
	// with a different number, and this is the path where the CALLER picks it.
	// **A bound checked after the work is paid for is an accountant rather
	// than a control**, so this sits at the earliest point where both numbers
	// are known — the caller's size and the budget of the capability that just
	// authorised them — which is before resolve, before the pool, and before
	// anything has been spent.
	// **RECORDED THE WAY `request_bounds` IS, AND NOT AS A BUDGET VERDICT.**
	// Policy ALLOWED — the grant covers this action on this target — and the
	// SIZE is what was refused, so claiming `VERDICT_BUDGET_EXCEEDED` would
	// say the engine returned something it did not. `enforceOnce` already has
	// this exact shape for a request it cannot serve: a DENY verdict, a
	// `MatchedRule` naming the bound, and `REFUSED_BY_REQUEST`.
	//
	// **AND THE KIND IS `KindInvalidArgument`, DELIBERATELY NOT
	// `KindBudgetExceeded`.** That kind maps to `STATUS_RATE_LIMITED`, which
	// tells a caller to come back later — true of a reflex firing budget,
	// whose window resets, and FALSE here: the same request will never fit,
	// and retrying it is the one thing the caller must not do. D201 is the
	// precedent for caring: a control that fires correctly and explains
	// itself wrongly is worse than either alone. The remedy is a corrected
	// request, which is `REFUSED_BY_REQUEST`'s own definition (D200's
	// attribution axis applied to a stage).
	limit, lerr := s.jobSize(cmd, dec.MaxBytes)
	if lerr != nil {
		base.MatchedRule = "capability_max_bytes"
		return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_REQUEST, lerr)
	}

	target, err := s.resolver.Resolve(ctx, cmd.GetTargetRef())
	if err != nil {
		kind := fault.KindOf(err)
		switch {
		case kind == fault.KindResidency:
			return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_RESIDENCY, err)
		case kind.Attribution() == fault.AttributionCredential:
			return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_CREDENTIAL, err)
		case kind == fault.KindConfig:
			return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_CONFIGURATION, err)
		}
		return nil, toStatus(s.recordFailure(ctx, base, err))
	}
	base.Residency = target.Residency()
	stampPosture(base, s.resolver, cmd.GetTargetRef())

	if s.pool != nil {
		if sev, withdrawn := s.pool.Withdrawn(cmd.GetTargetRef()); withdrawn {
			return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL,
				pool.WithdrawnErr(op, cmd.GetTargetRef(), sev))
		}
	}

	src, outputs, err := s.pollable(op, target)
	if err != nil {
		return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_CONFIGURATION, err)
	}

	// INTENT BEFORE THE SIDE EFFECT (§5.2.2), and a job is the case the rule was
	// written for: the work outlives the RPC, so a process that dies mid-job
	// leaves a row saying a job was authorised and started with no outcome —
	// which is the truth. **THE OUTCOME IS WRITTEN BY THE RUNNER** through
	// `jobGate.Finish`, long after this function returned, which is what makes
	// the intent/outcome pair mean something here rather than being ceremony.
	decisionID, err := s.recorder.Intent(ctx, base)
	if err != nil {
		return nil, toStatus(err)
	}

	jobID, err := s.jobs.Submit(ctx, kyuushin.Job{
		Target: target,
		Driver: src,
		// WHAT THE POLL MAY EMIT, as the driver declared it (D276).
		Outputs: outputs,
		// THE CALLER'S OWN IDENTITY, CARRIED WHOLE (D250). Not the principal
		// string: D59 intersects caller with subject, and a string is one of
		// the two.
		Identity: id,
		Limit:    limit,
		// THE ROW THIS JOB WAS ADMITTED UNDER, so its end closes its own
		// beginning rather than adding an unrelated second row (criterion 15).
		DecisionID: decisionID,
	})
	if err != nil {
		return nil, toStatus(s.recordFailure(ctx, base, err))
	}

	return &sekizuiv1.StartJobResponse{
		JobId:      jobID,
		DecisionId: decisionID,
		Status:     sekizuiv1.Status_STATUS_OK,
	}, nil
}

// defaultJobLimit bounds a job whose caller named no size.
//
// **A DEFAULT RATHER THAN AN UNBOUNDED RUN.** `kyuushin.Submit` refuses a
// non-positive limit, so something has to answer for a caller who named
// nothing, and "as many as the source feels like" is the one answer D243
// forbids the spine to give.
const defaultJobLimit = 100

// jobSize decides how many events this job may ask for, and refuses a caller
// whose number exceeds the budget of the capability that authorised them.
//
// Returns the limit and a refusal. **The declared cost is NOT returned**: its
// only reader is the refusal message, and a value handed back for nobody to
// read is the dead code `archcheck` keeps finding — so it is computed where it
// is used.
//
// # THE COST IS WHAT THE JOB COULD PRODUCE, NOT WHAT IT DID
//
// `safestruct.DefaultBudget` is the ceiling on ONE converted object, so
// `limit` events cannot exceed `limit × DefaultBudget` bytes however the
// source behaves. **Pessimistic on purpose**: the criterion's load-bearing
// half is BEFORE IT RUNS, and the actual size is only knowable after the work
// is paid for — at which point a bound is an accountant rather than a control.
//
// # AN EXPLICIT NUMBER IS REFUSED; AN ABSENT ONE IS CLAMPED
//
// **AND THE ASYMMETRY IS D142'S RULE, NOT A CONVENIENCE.** A target quietly
// given less than it asked for is one whose operator believes something
// false — so a caller who NAMED a size and cannot have it is told, never
// silently given a smaller one. A caller who named nothing asserted nothing,
// so fitting the default to the budget misstates no one's request and is the
// friendlier of two honest answers.
func (s *Server) jobSize(cmd *sekizuiv1.Command, maxBytes uint64) (int, error) {
	const op = "gateway.jobSize"
	const perEvent = uint64(safestruct.DefaultBudget)

	asked, explicit := 0, false
	if v, ok := cmd.GetArgs().AsMap()["limit"]; ok {
		// protobuf Struct carries every number as a float64 (GO-PRIMER §15j).
		if n, isNum := v.(float64); isNum && n > 0 {
			asked, explicit = int(n), true
		}
	}
	if !explicit {
		asked = defaultJobLimit
	}

	// UNCAPPED MEANS UNCAPPED. A grant with no `max_bytes` is the pre-existing
	// behaviour and must stay exactly that, or closing CONTRACTS 70 would
	// refuse deployments that never opted into a budget.
	if maxBytes == 0 {
		return asked, nil
	}

	affordable := int(maxBytes / perEvent)
	if !explicit {
		if affordable < asked {
			asked = affordable
		}
		if asked < 1 {
			// The budget cannot pay for a single event. Refused rather than
			// clamped to zero: `Submit` requires a positive limit, and a job
			// that runs and can return nothing is a worse answer than one
			// that says the grant is too small to be used.
			return 0, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"the capability authorising %q on %q allows %d bytes, and one event "+
					"may occupy up to %d — so this grant cannot pay for a single "+
					"event. Raise max_bytes on the capability",
				cmd.GetAction(), cmd.GetTargetRef(), maxBytes, perEvent))
		}
		return asked, nil
	}

	declared := uint64(asked) * perEvent
	if declared > maxBytes {
		// **NAMES BOTH NUMBERS, because a refusal that does not say by how
		// much is one nobody can act on.** The caller learns the size that
		// would fit; the operator learns which budget spoke.
		return 0, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"a job for %d events could produce up to %d bytes, and the capability "+
				"authorising %q on %q allows %d. Ask for %d or fewer, or raise "+
				"max_bytes on the capability",
			asked, declared, cmd.GetAction(), cmd.GetTargetRef(), maxBytes, affordable))
	}
	return asked, nil
}

// JobStatus answers "how is my job going" for the principal whose job it is
// (P3 criterion 15's caller half, D254).
//
// # WHY THIS IS AN RPC AND NOT AN ENVELOPE ON THE BUS
//
// The cheap design was a terminal envelope carrying the job's causation root,
// delivered on the subscription the caller already holds — no new surface, and
// the gap marker (D174) is precedent for Sekizui writing into the stream.
// **IT LEAKS, AND STRUCTURALLY.** The bus filters by SUBJECT, not by
// recipient, so any consumer whose subscribe grant matches would receive
// markers for other principals' jobs: their existence, their target, their
// timing and whether they failed. The two repairs are worse than the disease —
// encoding the job id in the subject needs a grant shaped `sekizui.job.>`,
// which matches everybody's, and filtering by recipient inside `Subscribe`
// puts a control-plane special case in the delivery path, which is a second
// path in the one place D18 is about. **Reusing an existing path is not the
// same as adding no surface**, and the maintainer's question is what got that checked.
//
// # NOT A GRANT — A JOB IS YOUR OWN
//
// Authorisation is identity equality with the principal recorded on the job,
// so this verb takes no capability and appears in no catalog. A grant would be
// the wrong instrument: "may read jobs" means "may read ANYBODY's jobs", and
// no deployment wants that sentence to be writable.
//
// # AN UNKNOWN JOB AND SOMEBODY ELSE'S ANSWER IDENTICALLY
//
// Both return `JOB_STATE_UNSPECIFIED` with no decision id. Separating them
// would answer "does this job id exist" for a caller with no business knowing,
// which is an enumeration oracle built out of helpfulness. **The audit log
// tells them apart for whoever is accountable** — a mismatch is recorded
// naming both principals, so somebody probing ids is visible to an operator
// while learning nothing themselves.
func (s *Server) JobStatus(ctx context.Context, req *sekizuiv1.JobStatusRequest) (
	*sekizuiv1.JobStatusResponse, error) {

	const op = "gateway.JobStatus"

	release, err := s.admission.Acquire(ctx, "JobStatus")
	if err != nil {
		return nil, toStatus(err)
	}
	defer release()

	if s.jobs == nil {
		return nil, toStatus(fault.New(fault.KindUnavailable, op,
			"this deployment has no job runner wired, so it knows of no jobs"))
	}
	if req.GetJobId() == "" {
		return nil, toStatus(fault.New(fault.KindInvalidArgument, op,
			"a status needs a job_id"))
	}

	id, err := s.verifier.Verify(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	asked := id.GetSubject().GetPrincipal()

	// **ONE RESPONSE FOR BOTH REFUSALS, BUILT ONCE**, so no future edit can
	// make the two branches diverge into an oracle by adding a helpful detail
	// to one of them.
	unknown := &sekizuiv1.JobStatusResponse{State: sekizuiv1.JobState_JOB_STATE_UNSPECIFIED}

	st, known := s.jobs.Status(req.GetJobId())
	if !known {
		return unknown, nil
	}
	if st.Principal != asked {
		// **RECORDED, AND THIS IS THE ASYMMETRY THAT MAKES THE SILENCE SAFE.**
		// The caller learns nothing; the log names both principals and the job,
		// so an operator can see somebody walking the id space. §5.4's rule
		// that a denial is the highest-value row, applied to a refusal the
		// refused party is not told about.
		//
		// A FAILURE TO RECORD IS NOT SWALLOWED: D150's direction says a
		// governance system that cannot record must not proceed as though it
		// had, and "someone probed another principal's job and it went
		// unlogged" is exactly the row whose absence matters.
		if _, rerr := s.recorder.Terminal(ctx, &sekizuiv1.Decision{
			Identity: id,
			Action:   "sekizui.job_status", TargetRef: "job:" + req.GetJobId(),
			Verdict:     sekizuiv1.Verdict_VERDICT_DENY,
			RefusedBy:   sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
			MatchedRule: "job:not_yours",
			Reason: fmt.Sprintf("%q asked for the status of a job belonging to %q; "+
				"the caller was told only that no such job is known", asked, st.Principal),
		}); rerr != nil {
			return nil, toStatus(rerr)
		}
		return unknown, nil
	}

	resp := &sekizuiv1.JobStatusResponse{
		DecisionId: st.DecisionID,
		//nolint:gosec // an event count is bounded by the job's own limit
		Events: int32(st.Events),
	}
	switch st.State {
	case kyuushin.StateRunning:
		resp.State = sekizuiv1.JobState_JOB_STATE_RUNNING
	case kyuushin.StateFinished:
		resp.State = sekizuiv1.JobState_JOB_STATE_FINISHED
	case kyuushin.StateFailed:
		resp.State = sekizuiv1.JobState_JOB_STATE_FAILED
		if st.Err != nil {
			resp.Reason = st.Err.Error()
		}
	case kyuushin.StateUnknown:
		// A RECORDED JOB IN THE ZERO STATE IS A BUG HERE, not a caller's
		// problem, and it must not be answered as "not yours" — that would
		// hide an internal defect behind a refusal.
		return nil, toStatus(fault.New(fault.KindInternal, op, fmt.Sprintf(
			"job %s is recorded with no state", req.GetJobId())))
	}

	// **NOT RECORDED WHEN IT SUCCEEDS.** A caller polling its own job's status
	// would otherwise write a row per poll for a question that changes nothing
	// — D178's amplification, and the same reasoning that keeps the poller
	// from recording every tick. The refusal above is recorded because it is
	// the row §5.4 calls the highest-value kind.
	return resp, nil
}

// CancelJob stops a running job.
//
// **NOT A GOVERNED VERB, AND THE ASYMMETRY WITH `revoke_grant` IS THE
// REASONING.** D129's break-glass verbs are governed because they act on
// somebody ELSE's capability; cancelling is a caller withdrawing their own
// request, and requiring a grant to stop work you started is how an operator
// ends up unable to stop something at 03:00. What it IS is authenticated and
// recorded: only the principal who started a job may cancel it.
func (s *Server) CancelJob(ctx context.Context, req *sekizuiv1.CancelJobRequest) (
	*sekizuiv1.CancelJobResponse, error) {

	const op = "gateway.CancelJob"

	release, err := s.admission.Acquire(ctx, "CancelJob")
	if err != nil {
		return nil, toStatus(err)
	}
	defer release()

	if s.jobs == nil {
		return nil, toStatus(fault.New(fault.KindUnavailable, op,
			"this deployment has no job runner wired, so there is nothing to cancel"))
	}
	if req.GetJobId() == "" {
		return nil, toStatus(fault.New(fault.KindInvalidArgument, op,
			"a cancellation needs a job_id"))
	}
	// REQUIRED, the same rule D146 applies to suspending a grant: a stop with
	// no reason is one the next person to read the log cannot account for.
	if req.GetReason() == "" {
		return nil, toStatus(fault.New(fault.KindInvalidArgument, op,
			"a cancellation needs a reason; an unexplained stop is paid for by "+
				"whoever reads the audit log next"))
	}

	id, err := s.verifier.Verify(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	// **RECURRENCE SCOPE IS REFUSED, WHICH IS WHAT THE WIRE CONTRACT ASKS FOR
	// RATHER THAN A STUB.** `CancelScope` says a recurrence scope is
	// "meaningless for a one-shot job, and refused there rather than silently
	// equivalent", and every job reachable through `StartJob` today is a
	// one-shot — `Submit` leaves `Every` zero. D249 is why silence would be
	// the wrong answer: an operator who meant to stop a schedule and stopped
	// only the run in flight has stopped nothing, and will believe otherwise
	// until the next tick.
	//
	// UNSPECIFIED FALLS THROUGH TO THIS_RUN, per the enum's own rule that the
	// safe reading of an ambiguous cancellation is the one that stops less.
	if req.GetScope() == sekizuiv1.CancelScope_CANCEL_SCOPE_RECURRENCE {
		return nil, toStatus(fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"job %s is a one-shot, so there is no recurrence to cancel; ask for "+
				"CANCEL_SCOPE_THIS_RUN. Accepting this and stopping only the run "+
				"would report success for something that did not happen",
			req.GetJobId())))
	}

	cancelled := s.jobs.Cancel(req.GetJobId())

	d := &sekizuiv1.Decision{
		Identity: id,
		Action:   "sekizui.cancel_job", TargetRef: "job:" + req.GetJobId(),
		Verdict:     sekizuiv1.Verdict_VERDICT_ALLOW,
		MatchedRule: "job:cancel",
		Reason:      req.GetReason(),
	}
	if _, rerr := s.recorder.Terminal(ctx, d); rerr != nil {
		return nil, toStatus(rerr)
	}

	// FALSE IS NOT AN ERROR: "it already stopped" is the outcome the caller
	// wanted, and reporting it as a failure invites a retry loop against
	// something that is already gone.
	detail := fmt.Sprintf("job %s cancelled", req.GetJobId())
	if !cancelled {
		detail = fmt.Sprintf("job %s was not running: it finished, or no such id was "+
			"ever minted", req.GetJobId())
	}
	return &sekizuiv1.CancelJobResponse{Cancelled: cancelled, Detail: detail}, nil
}

// pollable returns the SOURCE half of the driver serving a resolved target —
// the one lookup both triggers use (D249, D266).
//
// **A DRIVER THAT CANNOT BE POLLED IS A CONFIGURATION FAULT, NOT A MISSING
// GRANT.** `connector.Source` is an optional half of a driver (D244), so
// `<kind>.poll` can be granted against a kind whose driver only executes — and
// the caller would then be told their grant was fine and something unnamed went
// wrong. Naming the kind is what makes it actionable.
//
// **EXTRACTED FROM `StartJob` WHEN THE SCHEDULE NEEDED THE SAME ANSWER**, so the
// two triggers cannot disagree about which targets are pollable. One side
// effect, stated: a target whose kind has NO driver at all is now refused as
// configuration, where `StartJob` used to record it as a failure. Boot refuses
// a target with no driver, so neither was reachable through a booted document.
//
// **IT ALSO RETURNS THE POLL'S DECLARED OUTPUT SET (D276)**, read from the same
// driver in the same lookup — so a job carries exactly what the driver
// declared and boot checked, and the two triggers cannot disagree about it.
func (s *Server) pollable(op string, target connector.Target) (connector.Source, []string, error) {
	src, err := s.pollableSource(op, target)
	if err != nil {
		return nil, nil, err
	}
	action := target.Kind() + ".poll"
	for _, spec := range s.drivers[target.Kind()].Actions() {
		if spec.Name == action {
			return src, spec.DeclaredOutputs(), nil
		}
	}
	return src, nil, nil
}

func (s *Server) pollableSource(op string, target connector.Target) (connector.Source, error) {
	driver, err := s.driverFor(op, target)
	if err != nil {
		return nil, err
	}
	src, ok := driver.(connector.Source)
	if !ok {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"the driver for kind %q does not implement connector.Source, so target %q "+
				"cannot be polled; a job needs the source half of a connector",
			target.Kind(), target.Ref()))
	}
	return src, nil
}

// ScheduledJobs turns the document's `sources:` into recurring jobs (D266).
//
// **RESOLVED ONCE, AT BOOT, AND ADMITTED ON EVERY TICK** — the same split a
// caller's job has, where the target is resolved when `StartJob` admits it and
// every poll re-enters the gate. Holding the resolved target is safe because
// the credential is LENT per borrow (D127, D255), never captured here, so a
// rotation or a revocation reaches the next tick through the pool.
//
// A FAILURE REFUSES THE BOOT. A source that could not be resolved or cannot be
// polled would otherwise start as a loop that errors forever, which is a
// deployment reporting healthy while one of its sources never arrives.
func (s *Server) ScheduledJobs(ctx context.Context, specs []config.SourceSpec) ([]kyuushin.Job, error) {
	const op = "gateway.ScheduledJobs"
	jobs := make([]kyuushin.Job, 0, len(specs))
	for _, spec := range specs {
		target, err := s.resolver.Resolve(ctx, spec.TargetRef)
		if err != nil {
			return nil, fault.Wrap(fault.KindConfig, op,
				fmt.Sprintf("resolving scheduled source %q", spec.TargetRef), err)
		}
		// A QUARANTINED CONNECTOR'S SOURCE IS SKIPPED, LOUDLY, NOT A BOOT
		// FAILURE (D282): the rule above — a source that cannot be polled
		// refuses the boot — is for a MISCONFIGURED source, and this one is
		// configured correctly and waiting on a fixed connector. Every other
		// source starts.
		if why, q := s.quarantined[target.Kind()]; q {
			s.log.Error("scheduled source NOT started: its connector is quarantined (D282)",
				"source", spec.TargetRef, "connector", target.Kind(), "why", why)
			continue
		}
		src, outputs, err := s.pollable(op, target)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, kyuushin.Job{
			Target:  target,
			Driver:  src,
			Outputs: outputs,
			Every:   time.Duration(spec.EverySec) * time.Second,
			Limit:   int(spec.Limit),
			// NO IDENTITY: configuration is the caller, so the runner admits
			// every tick as `source:<target>` (D250).
		})
	}
	return jobs, nil
}

// JobResults streams a caller's job's results to that caller alone (D267).
//
// AUTHORISED AS JobStatus IS, AND BY THE SAME CODE PATH OF REASONING: identity
// equality with the job's owner, no grant, no catalog entry. An unknown job
// and somebody else's are answered with the SAME error, built once; the second
// is recorded, because a principal walking another's job ids is the row an
// operator needs and the caller must not get.
//
// **THE SAME DELIVERY STEP A SUBSCRIPTION TAKES** — `s.shape` — so a result is
// lensed exactly as a bus delivery is, and step 36's projection lands in one
// place for both.
func (s *Server) JobResults(req *sekizuiv1.JobResultsRequest,
	stream sekizuiv1.GatewayService_JobResultsServer) error {

	const op = "gateway.JobResults"
	ctx := stream.Context()

	release, err := s.admission.Acquire(ctx, "JobResults")
	if err != nil {
		return toStatus(err)
	}
	defer release()

	if s.jobs == nil {
		return toStatus(fault.New(fault.KindUnavailable, op,
			"this deployment has no job runner wired, so it holds no results"))
	}
	if req.GetJobId() == "" {
		return toStatus(fault.New(fault.KindInvalidArgument, op, "results need a job_id"))
	}
	id, err := s.verifier.Verify(ctx)
	if err != nil {
		return toStatus(err)
	}
	asked := id.GetSubject().GetPrincipal()

	// ONE ERROR FOR BOTH REFUSALS, BUILT ONCE, so no later edit can make the
	// two diverge into an oracle for which job ids exist.
	unknown := toStatus(fault.New(fault.KindNotFound, op,
		fmt.Sprintf("no results are held for job %q", req.GetJobId())))

	st, known := s.jobs.Status(req.GetJobId())
	if !known {
		return unknown
	}
	if st.Principal != asked {
		if _, rerr := s.recorder.Terminal(ctx, &sekizuiv1.Decision{
			Identity: id,
			Action:   "sekizui.job_results", TargetRef: "job:" + req.GetJobId(),
			Verdict:     sekizuiv1.Verdict_VERDICT_DENY,
			RefusedBy:   sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
			MatchedRule: "job:not_yours",
			Reason: fmt.Sprintf("%q asked for the results of a job belonging to %q; "+
				"the caller was told only that none are held", asked, st.Principal),
		}); rerr != nil {
			return toStatus(rerr)
		}
		return unknown
	}
	results, held := s.jobs.Results(req.GetJobId())
	if !held {
		return unknown
	}
	if err := results.Attach(); err != nil {
		return toStatus(err)
	}

	delivered := 0
	for {
		env, ok := results.Next(ctx)
		if !ok {
			// THE JOB ENDED AND EVERY RESULT WAS SENT — a real end, which is
			// the thing a bus subscription could never give a caller. A
			// cancelled stream ends here too; what it left unread is gone.
			s.log.Info("job results delivered", "job", req.GetJobId(),
				"caller", asked, "delivered", delivered)
			return nil
		}
		shaped, _, ok := s.shape("job_results", asked, env, req.GetLens(), req.GetIncludeProjection())
		if !ok {
			continue
		}
		if err := stream.Send(&sekizuiv1.JobResultsResponse{Envelope: shaped}); err != nil {
			return toStatus(fault.Wrap(fault.KindUnavailable, op, "sending to the caller", err))
		}
		delivered++
	}
}
