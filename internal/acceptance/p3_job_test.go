package acceptance

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/fullstorydev/sekizui/pkg/config"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step31 — a caller asks for a job and receives its results as lensed
// envelopes (P3 criteria 14 and 9, D247, D250).
//
// **THIS STEP REPLACES CRITERION 1's TEST SUBSCRIBER, AND THAT IS WHY IT LEADS
// THE PHASE.** D172 had already called that consumer thin — one existing only
// to prove delivery — and asking who consumes an envelope at all found that
// nothing did: reflexes are P5, the gold loop closes at P5 (D170), and the
// poller produces for nobody. A job has a caller with a grant and a reason to
// be there, so the whole plane is driven from ONE request and every stage is
// load-bearing rather than staged for the test.
//
// **IT IS ALSO THE HONEST WAY TO GET CRITERION 9.** An envelope from a real
// connector result rather than from a fixture that agrees with us by
// construction — which is the shape that cost the blueprint three defects
// (D222). `kata.Poll` is the driver's own Source half; nothing here hands the
// bus an envelope it built.
func p3Step31(t *testing.T) {
	r := newRun(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if r.localOnly(t, "the job runner is attached in-process; a live instance runs its "+
		"own and this step would be asserting about that one's bus") {
		return
	}

	caller := r.as(t, "agent:jobs")

	// **A BYSTANDER, SUBSCRIBED BEFORE THE JOB STARTS (D267).** agent:scoped is
	// granted raw kata rows from kata:alpha — exactly what this job produces.
	// Under D247 it would have received the caller's results; they are the
	// caller's alone now, and 31e proves it by ORDER, as step 37 does.
	subCtx, cancelSub := context.WithTimeout(ctx, 20*time.Second)
	defer cancelSub()
	bystander, err := r.as(t, "agent:scoped").Subscribe(subCtx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.raw.kata.>"},
	})
	if err != nil {
		t.Fatalf("step 31: the bystander could not subscribe: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 },
		"the bystander's subscription never registered")

	r.narrate(t, "a caller asks for a job and receives its results as lensed envelopes")

	// 31a — THE REQUEST. An ordinary Command: the same action name and the same
	// target ref an Execute would carry, which is D247's "not a different kind
	// of thing" stated in the only place it can be checked.
	started, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{
			Action:    "kata.poll",
			TargetRef: "kata:alpha",
		},
	})
	if err != nil {
		t.Fatalf("step 31a: StartJob: %v", err)
	}
	if started.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 31a: the job was refused: %s (%s)",
			started.GetReason(), started.GetRefusedBy())
	}
	if started.GetJobId() == "" {
		t.Fatal("step 31a: no job id, so nothing can be correlated with the results")
	}
	// THE DECISION THAT ADMITTED IT, on a refusal and an acceptance alike
	// (D201). A caller who cannot cite the row that authorised their job cannot
	// answer for it later.
	if started.GetDecisionId() == "" {
		t.Error("step 31a: the job started with no decision id, so the caller cannot " +
			"cite the row that says why they were allowed to")
	}
	r.detail(t, "job `%s` admitted by decision `%s`",
		started.GetJobId(), started.GetDecisionId())

	// 31b — THE RESULTS ARRIVE, AND THEY CARRY THE JOB AS THEIR CAUSATION ROOT.
	//
	// No `job_id` field was added to the envelope (D247): `Causation.root_id`
	// already means "the originating thing at the root of this chain", and for
	// a job that is the job. This arm is what makes that claim usable rather
	// than merely defensible — it is how a caller filters.
	// THE WHOLE WINDOW, NOT A SAMPLE. `kata:alpha` declares three rows, so
	// three is the number a caller is owed — reading "some" would pass while a
	// job silently delivered a prefix, which is the failure a caller cannot
	// detect for themselves.
	const wantRows = 3

	// **ATTACH AFTER THE JOB HAS FINISHED.** Under D247 this would have lost
	// everything — the bus drops what nobody is subscribed to (D24) — and the
	// caller had to subscribe before starting. The results are held for the
	// caller now, so waiting for the end first is the strongest form of the
	// claim rather than a race.
	waitFor(t, func() bool {
		st, serr := caller.JobStatus(ctx, &sekizuiv1.JobStatusRequest{JobId: started.GetJobId()})
		return serr == nil && st.GetState() == sekizuiv1.JobState_JOB_STATE_FINISHED
	}, "the job never finished")

	results, err := caller.JobResults(ctx, &sekizuiv1.JobResultsRequest{JobId: started.GetJobId()})
	if err != nil {
		t.Fatalf("step 31b: JobResults: %v", err)
	}
	var got []*sekizuiv1.Envelope
	for {
		received, rerr := results.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("step 31b: receiving result %d: %v", len(got)+1, rerr)
		}
		got = append(got, received.GetEnvelope())
	}
	// **THE STREAM ENDED, AND THAT IS AN ARM.** A job has an end (D247); a bus
	// subscription never did, so a caller reading one could only stop waiting.
	if len(got) != wantRows {
		t.Fatalf("step 31b: the job's results stream ended after %d result(s), want %d. A "+
			"job that delivers part of its window is worse than one that fails, because the "+
			"caller cannot tell", len(got), wantRows)
	}

	for i, env := range got {
		if root := env.GetCausation().GetRootId(); root != started.GetJobId() {
			t.Errorf("step 31b: result %d carries causation root %q, not the job id %q "+
				"— a caller subscribing on the root receives nothing", i, root,
				started.GetJobId())
		}
		if env.GetSource() != "kata:alpha" {
			t.Errorf("step 31b: result %d names source %q, not the target that was "+
				"polled", i, env.GetSource())
		}
		if env.GetType() != "kata.row.v1" {
			t.Errorf("step 31b: result %d has type %q; the lens and the schema "+
				"registry are both keyed on it", i, env.GetType())
		}
	}
	r.detail(t, "%d results delivered, all rooted at the job", len(got))

	// 31c — NARROWED BY SHIN, ASSERTED ON THE ROW'S ACTUAL BYTES.
	//
	// **AGAINST THE BYTES RATHER THAN NAMED FIELDS, which is the same reasoning
	// P1 step 19 used for credential material.** Checking `data["ref"] == nil`
	// asks whether ONE key somebody thought of is absent; a field added later
	// under a plausible name is the only way this could be lost, and only the
	// serialised form catches that. `job-results-lite` keeps `ordinal` and
	// drops `ref`, so both directions are proven by one row: a lens proven by a
	// field that was never there proves nothing.
	first := got[0].GetData().AsMap()
	if _, kept := first["ordinal"]; !kept {
		t.Error("step 31c: the lens removed `ordinal`, which it is configured to KEEP " +
			"— a lens that narrows everything is indistinguishable from a broken one")
	}
	rendered := renderStruct(t, got[0].GetData())
	if strings.Contains(rendered, "kata:alpha") && strings.Contains(rendered, `"ref"`) {
		t.Errorf("step 31c: `ref` survived the imposed lens and reached the caller. "+
			"Delivered bytes: %s", rendered)
	}
	r.detail(t, "shin narrowed the row to %v on the way out", sortedKeys(first))

	// 31d — THE SAME CEILINGS AN EXECUTE TAKES, AND THE ARM IS A REFUSAL.
	//
	// **A BEHAVIOURAL ARM ON THE ALLOWED PATH PROVES NOTHING ABOUT THE
	// CEILINGS**, because a job admitted with no checks at all looks exactly
	// like one admitted with all of them. So this drives a principal the grant
	// does not cover and asserts the refusal is SHAPED — a result with a mapped
	// status and a named stage (D135, D155), not a transport error and not an
	// empty `job_id` a caller has to interpret.
	//
	// An empty job id alone would be a NEGATIVE ASSERTION, satisfied by the
	// absence of an answer — which is exactly how a missing status mapping hid
	// for a whole phase (D138).
	refused, rerr := r.as(t, "agent:analytics").StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:alpha"},
	})
	if rerr != nil {
		t.Fatalf("step 31d: a policy refusal arrived as a transport error, which D135 "+
			"reserves for genuine failures: %v", rerr)
	}
	if refused.GetJobId() != "" {
		t.Error("step 31d: a principal with no kata.poll grant started a job")
	}
	if refused.GetStatus() != sekizuiv1.Status_STATUS_DENIED {
		t.Errorf("step 31d: the refusal carries status %s, want STATUS_DENIED",
			refused.GetStatus())
	}
	if refused.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_POLICY {
		t.Errorf("step 31d: the refusal names stage %s, want REFUSED_BY_POLICY — a "+
			"caller told only that no job started cannot tell a missing grant from a "+
			"suspended principal from a credential somebody revoked", refused.GetRefusedBy())
	}
	if refused.GetDecisionId() == "" {
		t.Error("step 31d: the refusal cites no decision, so the highest-value row in " +
			"the log cannot be found from the answer the caller received")
	}
	r.detail(t, "refused agent:analytics: %s (%s)",
		refused.GetStatus(), refused.GetRefusedBy())

	// 31e — NOBODY ELSE RECEIVED THEM (D267). The bystander has been subscribed,
	// with a grant matching every row the job produced, since before it started.
	// A sentinel published NOW must be the first thing it receives; if the
	// job's results had gone to the bus, they would have arrived first.
	sentinel := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": 99})
	sentinel.Id, sentinel.Source = "31e-sentinel", "kata:alpha"
	if err := r.srv.PublishForTest(sentinel); err != nil {
		t.Fatalf("step 31e: %v", err)
	}
	seen, err := bystander.Recv()
	if err != nil {
		t.Fatalf("step 31e: the bystander received nothing, not even the sentinel: %v", err)
	}
	if id := seen.GetEnvelope().GetId(); id != "31e-sentinel" {
		t.Fatalf("step 31e: agent:scoped received %q, one of agent:jobs's results, before the "+
			"sentinel. A job's results are its caller's alone (D267)", id)
	}

	// 31f — NOT YOURS AND NOT KNOWN ARE ONE ANSWER, AND THE PROBE IS RECORDED.
	notFound := func(who, jobID string) codes.Code {
		t.Helper()
		st, serr := r.as(t, who).JobResults(ctx, &sekizuiv1.JobResultsRequest{JobId: jobID})
		if serr == nil {
			_, serr = st.Recv()
		}
		return status.Code(serr)
	}
	theirs, madeUp := notFound("agent:analytics", started.GetJobId()), notFound("agent:analytics", "job_nope")
	if theirs != codes.NotFound || madeUp != codes.NotFound {
		t.Errorf("step 31f: another principal's job answered %s and an unknown one %s; both "+
			"must be NOT_FOUND, or this verb is an oracle for which job ids exist", theirs, madeUp)
	}
	probed := false
	for _, d := range readLog(t, r.path) {
		if d.GetAction() == "sekizui.job_results" && d.GetMatchedRule() == "job:not_yours" &&
			d.GetIdentity().GetSubject().GetPrincipal() == "agent:analytics" {
			probed = true
		}
	}
	if !probed {
		t.Error("step 31f: agent:analytics asking for agent:jobs's results left no record; the " +
			"caller is told nothing, so the log is the only place the probe can be seen")
	}
	// AND ONE READER PER JOB: the owner's second attach is refused.
	if again := notFoundOrErr(t, caller, ctx, started.GetJobId()); again == codes.OK {
		t.Error("step 31f: the owner attached to the same job's results twice; a second reader " +
			"would silently receive only what the first left")
	}
	// 31g — HOW LONG RESULTS WAIT IS CONFIGURED, AND BOUNDED (D268). A day is
	// the ceiling: longer is storage, and every held result is memory.
	step31ResultsTTLCeiling(t)

	r.detail(t, "a bystander granted the same rows received none of them; another principal was "+
		"told NOT_FOUND, as for a made-up id, and the probe was recorded")
}

// notFoundOrErr attaches to a job's results and returns the status code of the
// first thing that goes wrong, or OK.
func notFoundOrErr(t *testing.T, c sekizuiv1.GatewayServiceClient, ctx context.Context,
	jobID string) codes.Code {
	t.Helper()
	st, err := c.JobResults(ctx, &sekizuiv1.JobResultsRequest{JobId: jobID})
	if err == nil {
		_, err = st.Recv()
	}
	if errors.Is(err, io.EOF) {
		return codes.OK
	}
	return status.Code(err)
}

// renderStruct serialises a delivered payload so an assertion can be made
// against its BYTES.
//
// **THE POINT IS TO ASK A QUESTION A FIELD LOOKUP CANNOT.** `data["ref"] ==
// nil` is satisfied by the one key the author thought of; a value that
// reappears nested, or under a name added later, passes it while the guarantee
// is gone. P1 step 19 made the same move for credential material and it is the
// only form that survives a schema change nobody told the test about.
func renderStruct(t *testing.T, s *structpb.Struct) string {
	t.Helper()
	b, err := protojson.Marshal(s)
	if err != nil {
		t.Fatalf("rendering the delivered payload: %v", err)
	}
	return string(b)
}

// p3Step32 — finished, failed and still-running are distinguishable from the
// audit log (P3 criterion 15, D247).
//
// **THE PAIR THAT ACTUALLY GETS CONFLATED IS FAILED AND FINISHED-WITH-NOTHING,
// which is why a two-state test would pass and prove nothing.** Both publish
// zero envelopes, so "no envelopes" is not a distinction and neither is "the
// caller received nothing". The log has to say it.
//
// **ASSERTED ON THE REAL AUDIT LOG, not on the gate's own account of what it
// was told.** The unit test in `internal/kyuushin` already pins what the runner
// REPORTS; this pins what is DURABLE, which is the artefact an operator reads
// six months later and the only one §5.4 is about.
func p3Step32(t *testing.T) {
	r := newRun(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if r.localOnly(t, "the audit log belongs to the process that wrote it") {
		return
	}
	caller := r.as(t, "agent:jobs")

	r.narrate(t, "a job's end is a record, and says which end it was")

	// 32a — A JOB THAT FINISHES WITH RESULTS. `kata:alpha` has three rows.
	done, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:alpha"},
	})
	if err != nil {
		t.Fatalf("32a: StartJob: %v", err)
	}

	// **WAIT FOR THE OUTCOME ROW, NOT FOR A DURATION.** A sleep would make the
	// step's own timing the thing under test, and the failure it produces —
	// an intent with no outcome — is indistinguishable from the defect this
	// step exists to catch.
	finished := awaitOutcome(t, r, done.GetDecisionId())
	if !finished.GetSuccess() {
		t.Errorf("32a: a job that polled a healthy source recorded failure: %s",
			finished.GetError())
	}
	if got := finished.GetDetail().GetFields()["events"].GetNumberValue(); got != 3 {
		t.Errorf("32a: the outcome records %v events, want 3. Without a count, a job "+
			"that finished having found nothing reads exactly like one that fell "+
			"over", got)
	}
	r.detail(t, "finished: success, %v events",
		finished.GetDetail().GetFields()["events"].GetNumberValue())

	// 32b — A JOB THAT FINISHES HAVING FOUND NOTHING. **THE ARM THE OTHER TWO
	// EXIST TO BE TOLD APART FROM.** `kata:empty` declares no rows, so the
	// source is idle by design rather than broken.
	empty, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:empty"},
	})
	if err != nil {
		t.Fatalf("32b: StartJob: %v", err)
	}
	quiet := awaitOutcome(t, r, empty.GetDecisionId())
	if !quiet.GetSuccess() {
		t.Errorf("32b: a job that found nothing was recorded as FAILED (%s). Nothing "+
			"went wrong: the source is empty, and an operator told otherwise goes "+
			"looking for a fault that does not exist", quiet.GetError())
	}
	if got := quiet.GetDetail().GetFields()["events"].GetNumberValue(); got != 0 {
		t.Errorf("32b: the outcome records %v events for an empty source, want 0", got)
	}
	r.detail(t, "finished with nothing to say: success, 0 events — distinguishable "+
		"from a failure only because both halves are recorded")

	// 32c — A JOB THAT FAILS. `kata:panicky` panics inside Poll, which the
	// runner recovers per D243 so one bad source cannot take the process.
	broke, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:panicky"},
	})
	if err != nil {
		t.Fatalf("32c: StartJob: %v", err)
	}
	failed := awaitOutcome(t, r, broke.GetDecisionId())
	if failed.GetSuccess() {
		t.Fatal("32c: a job whose source panicked was recorded as a SUCCESS. This is " +
			"the conflation criterion 15 names — it published nothing, and so did " +
			"32b, and only the log can tell an operator which happened")
	}
	if failed.GetError() == "" {
		t.Error("32c: the failure carries no error, so the row says a job ended badly " +
			"and not why")
	}
	r.detail(t, "failed: %s", firstSentence(failed.GetError()))

	// 32d — STILL RUNNING IS AN INTENT WITH NO OUTCOME, and the residual is
	// NAMED rather than asserted away: after a crash the same shape means "was
	// running when the process died". §5.2.2 chose that deliberately, because
	// a record saying an action was attempted with no outcome is the truth.
	//
	// Driven with a source that blocks, so the intent is durable and the
	// outcome provably is not yet.
	running, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:slow"},
	})
	if err != nil {
		t.Fatalf("32d: StartJob: %v", err)
	}
	waitFor(t, func() bool { return intentFor(t, r, running.GetDecisionId()) != nil },
		"the job's intent row never became durable, so nothing records that it began")
	if got := outcomeFor(t, r, running.GetDecisionId()); got != nil {
		t.Errorf("32d: a job still in flight already has an outcome (%v), so the log "+
			"cannot distinguish running from finished", got)
	}
	r.detail(t, "still running: an intent with no outcome — the same shape a crash "+
		"leaves, which §5.2.2 chose on purpose")

	// **THE STEP CLEANS UP THE WORK IT DELIBERATELY LEFT RUNNING**, and this
	// is hygiene rather than an assertion — step 33 is where cancellation
	// reaching the far side is proven. Without it the blocked poll holds the
	// runner's Stop for the whole poll deadline, which turns a 6-second
	// acceptance run into a 36-second one: a step that makes the suite slow
	// enough to stop being run at session start has cost more than it proved.
	// 32e — THE CALLER CAN SEE ITS OWN JOB, WITHOUT READING THE AUDIT LOG.
	//
	// **THE HALF OF CRITERION 15 THE RECORD DOES NOT DISCHARGE (D254).** The
	// criterion asks for two things and only one is about the operator: "not
	// by the caller inferring it from silence". There are six RPCs and none
	// reads the audit log, so the `decision_id` a caller holds resolved to
	// nothing — the row existed and the party who paid for it could not see
	// it. Asserted on all three states, because a status verb that only ever
	// answers FINISHED would pass a one-state test.
	for _, tc := range []struct {
		what  string
		jobID string
		want  sekizuiv1.JobState
	}{
		{"finished", done.GetJobId(), sekizuiv1.JobState_JOB_STATE_FINISHED},
		{"failed", broke.GetJobId(), sekizuiv1.JobState_JOB_STATE_FAILED},
		{"running", running.GetJobId(), sekizuiv1.JobState_JOB_STATE_RUNNING},
	} {
		st, serr := caller.JobStatus(ctx, &sekizuiv1.JobStatusRequest{JobId: tc.jobID})
		if serr != nil {
			t.Fatalf("32e: JobStatus(%s): %v", tc.what, serr)
		}
		if st.GetState() != tc.want {
			t.Errorf("32e: a %s job reports %s, want %s — the caller is back to "+
				"inferring the answer from silence", tc.what, st.GetState(), tc.want)
		}
		if st.GetDecisionId() == "" {
			t.Errorf("32e: the %s job's status cites no decision, so the caller still "+
				"cannot name the row that accounts for its work", tc.what)
		}
	}
	r.detail(t, "the caller read all three states off its own jobs")

	// 32f — SOMEBODY ELSE'S JOB AND AN UNKNOWN JOB ANSWER IDENTICALLY.
	//
	// **NOT AN ORACLE, WHICH IS THE SECURITY HALF (D254).** Distinguishing
	// "no such job" from "not yours" would answer "does this id exist" for a
	// caller with no business knowing. The two answers are compared to each
	// other rather than to a constant, so a future edit that makes one of them
	// more helpful fails here.
	intruder := r.as(t, "agent:analytics")
	notYours, err := intruder.JobStatus(ctx,
		&sekizuiv1.JobStatusRequest{JobId: done.GetJobId()})
	if err != nil {
		t.Fatalf("32f: JobStatus on another principal's job errored: %v", err)
	}
	noSuch, err := intruder.JobStatus(ctx,
		&sekizuiv1.JobStatusRequest{JobId: "job-that-never-existed"})
	if err != nil {
		t.Fatalf("32f: JobStatus on an unknown job errored: %v", err)
	}
	if notYours.GetState() != sekizuiv1.JobState_JOB_STATE_UNSPECIFIED {
		t.Errorf("32f: another principal's job reports %s. A job is its owner's own "+
			"(D254), and this reads it", notYours.GetState())
	}
	if !proto.Equal(notYours, noSuch) {
		t.Errorf("32f: somebody else's job answers %v and an unknown one answers %v. "+
			"The difference is an enumeration oracle: a caller can walk the id space "+
			"and learn which jobs exist", notYours, noSuch)
	}

	// **AND THE OPERATOR CAN STILL TELL THEM APART**, which is what makes the
	// caller's silence safe rather than merely quiet. The refusal is recorded
	// naming both principals; the probe is visible to whoever is accountable.
	var probeRow *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetMatchedRule() == "job:not_yours" {
			probeRow = d
		}
	}
	if probeRow == nil {
		t.Error("32f: reading another principal's job left no audit row. The caller " +
			"learns nothing by design, so the log is the only place this is visible " +
			"— and without it somebody walking the id space is invisible to everyone")
	} else if !strings.Contains(probeRow.GetReason(), "agent:jobs") {
		t.Errorf("32f: the refusal row does not name the job's owner, so an operator "+
			"cannot tell whose job was probed: %q", probeRow.GetReason())
	}
	r.detail(t, "an intruder is told nothing and the log names both principals")

	if _, cerr := caller.CancelJob(ctx, &sekizuiv1.CancelJobRequest{
		JobId:  running.GetJobId(),
		Reason: "step 32d: releasing the source this step blocked on purpose",
	}); cerr != nil {
		t.Errorf("32d: could not cancel the job this step started: %v", cerr)
	}
}

// awaitOutcome blocks until the job's decision has an outcome row.
func awaitOutcome(t *testing.T, r *run, decisionID string) *sekizuiv1.Effect {
	t.Helper()
	var eff *sekizuiv1.Effect
	waitFor(t, func() bool {
		eff = outcomeFor(t, r, decisionID)
		return eff != nil
	}, "the job's end never reached the audit log: a job whose end is unobservable "+
		"is the melt in a different coat")
	return eff
}

// outcomeFor returns the effect recorded against a decision, or nil.
func outcomeFor(t *testing.T, r *run, decisionID string) *sekizuiv1.Effect {
	t.Helper()
	for _, d := range readLog(t, r.path) {
		if d.GetId() == decisionID && d.GetEffect() != nil {
			return d.GetEffect()
		}
	}
	return nil
}

// intentFor returns the decision row itself, outcome or not.
func intentFor(t *testing.T, r *run, decisionID string) *sekizuiv1.Decision {
	t.Helper()
	for _, d := range readLog(t, r.path) {
		if d.GetId() == decisionID {
			return d
		}
	}
	return nil
}

// p3Step33 — cancelling a job stops the work, not just the subscription
// (P3 criterion 16, D247, D128).
//
// **THE ARM THAT MATTERS IS THE FAR SIDE, and the easy observable is the
// wrong one.** A caller who unsubscribes from a job that keeps running has
// bought nothing: the credential it borrowed stays borrowed, and the vendor
// keeps being billed for output nobody will read. A test that asserted the
// STREAM closed would pass with the guarantee entirely absent — the same
// non-vacuity problem P1 step 52 has, where the observable that is easy to
// assert is not the one the guarantee is about.
//
// So this asserts `pool.InFlight`: the borrowed client is RELEASED, which is
// what `pool.Do`'s call-through exists to make unforgettable (D128) and which
// cannot happen unless the work itself was cancelled.
func p3Step33(t *testing.T) {
	r := newRun(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if r.localOnly(t, "the client pool is this instance's") {
		return
	}
	caller := r.as(t, "agent:jobs")

	r.narrate(t, "cancelling a job stops the work, not just the subscription")

	started, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:slow"},
	})
	if err != nil {
		t.Fatalf("33: StartJob: %v", err)
	}

	// 33a — THE FAR SIDE IS GENUINELY ENGAGED BEFORE ANYTHING IS CANCELLED.
	//
	// **WITHOUT THIS THE STEP PROVES NOTHING**, and it is the vacuity P1 step
	// 52 records: cancelling a job that never reached its driver releases a
	// client it never borrowed, and every assertion below passes. `kata:slow`
	// blocks INSIDE the borrow, so a non-zero InFlight is the driver holding a
	// pooled client at the moment of the cancellation.
	waitFor(t, func() bool { return r.pool.InFlight("kata:slow") > 0 },
		"the poll never borrowed a client, so there is no in-flight work to "+
			"cancel and the arms below would pass vacuously")
	r.detail(t, "the poll holds %d pooled client(s) for kata:slow",
		r.pool.InFlight("kata:slow"))

	// 33b — CANCEL, AND THE BORROWED CLIENT COMES BACK.
	//
	// **PROMPTLY IS THE LOAD-BEARING WORD.** The poll deadline is thirty
	// seconds; if cancellation reached only the caller's view of the job, the
	// borrow would persist until that deadline expired and the vendor would
	// be worked for all of it. Waiting on the observable rather than sleeping
	// means the step fails by TIMING OUT on exactly the condition it is about.
	cancelled, err := caller.CancelJob(ctx, &sekizuiv1.CancelJobRequest{
		JobId:  started.GetJobId(),
		Reason: "step 33: proving the work stops, not merely the subscription",
	})
	if err != nil {
		t.Fatalf("33b: CancelJob: %v", err)
	}
	if !cancelled.GetCancelled() {
		t.Fatalf("33b: the job reported nothing to cancel (%s), but it was holding a "+
			"pooled client a moment ago", cancelled.GetDetail())
	}

	waitFor(t, func() bool { return r.pool.InFlight("kata:slow") == 0 },
		"the borrowed client was never released. The subscription may have closed, "+
			"but the work did not stop: the credential stays borrowed and the vendor "+
			"keeps being billed for output nobody will read (D128, criterion 16)")
	r.detail(t, "the borrowed client was released: in-flight is now 0")

	// 33c — AND THE JOB ENDS, SAYING IT WAS CANCELLED.
	//
	// A cancelled job that never reaches a terminal state is the melt criterion
	// 15 names, reached by a different route — so the two criteria are checked
	// against each other here rather than separately.
	var final *sekizuiv1.JobStatusResponse
	waitFor(t, func() bool {
		st, serr := caller.JobStatus(ctx, &sekizuiv1.JobStatusRequest{
			JobId: started.GetJobId(),
		})
		if serr != nil {
			return false
		}
		final = st
		return st.GetState() != sekizuiv1.JobState_JOB_STATE_RUNNING
	}, "a cancelled job never left the RUNNING state, so the caller cannot tell "+
		"cancellation from work still in progress")

	if final.GetState() != sekizuiv1.JobState_JOB_STATE_FAILED {
		t.Errorf("33c: a cancelled job reports %s. Cancellation is not a successful "+
			"completion: a caller told FINISHED would believe the work ran",
			final.GetState())
	}
	if !strings.Contains(final.GetReason(), "context canceled") &&
		!strings.Contains(final.GetReason(), "cancel") {
		t.Errorf("33c: the ending reads %q, which does not name the cancellation. An "+
			"operator seeing a failed job needs to know it was stopped on purpose",
			firstSentence(final.GetReason()))
	}
	r.detail(t, "the job ended: %s — %s", final.GetState(),
		firstSentence(final.GetReason()))

	// 33d — CANCELLING AGAIN IS NOT AN ERROR. "It already stopped" is the
	// outcome the caller wanted, and reporting it as a failure invites a retry
	// loop against something that is already gone.
	again, err := caller.CancelJob(ctx, &sekizuiv1.CancelJobRequest{
		JobId:  started.GetJobId(),
		Reason: "step 33d: the second cancellation",
	})
	if err != nil {
		t.Fatalf("33d: cancelling a finished job errored: %v", err)
	}
	if again.GetCancelled() {
		t.Error("33d: cancelling an already-finished job reported that it cancelled " +
			"something")
	}
	if again.GetDetail() == "" {
		t.Error("33d: the no-op cancellation says nothing, so a caller cannot tell it " +
			"from a successful one")
	}
	r.detail(t, "cancelling again: %s", again.GetDetail())
}

// p3Step34 — a job cannot outlive its authorisation (P3 criterion 17, D129,
// D146, D247, D250, D255, D256).
//
// **THIS IS THE WIDEST WINDOW IN THE SYSTEM BETWEEN AUTHORISATION AND USE, and
// that is why it is a criterion rather than an implication.** A command is
// authorised and used in one breath. A recurrence re-admits every tick
// precisely because the window would otherwise be open. A job holds it open
// for as long as the work takes.
//
// **TWO ARMS, BECAUSE THE TWO REVOCATIONS DIFFER IN KIND AND IN DURABILITY** —
// a grant SUSPENDED (D146, in-memory, until config is redeployed) and a
// credential REVOKED (D129, durable per D145). Both must stop the job, and the
// record must say which: P1 step 68's first version passed for the wrong
// reason with the stage unnamed, which is the precedent for asserting on
// `refused_by` rather than on "it stopped".
//
// **NEITHER ARM WAS PROVABLE BEFORE THIS SESSION.** The grant arm needed D250
// (a job runs as its caller, so there is a caller's grant to suspend) and D256
// (suspension reaches work already in flight). The credential arm needed D255
// (the poll borrows, so pool eviction has something to cancel).
func p3Step34(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 34a — A GRANT SUSPENDED MID-JOB STOPS IT.
	t.Run("a grant suspended mid-job stops the work", func(t *testing.T) {
		//nolint:contextcheck // harness manages its own lifecycle via *testing.T
		r := newRun(t)
		if r.localOnly(t, "suspension state and the pool are this instance's") {
			return
		}
		r.narrate(t, "a job cannot outlive its authorisation")

		started, err := r.as(t, "agent:jobs").StartJob(ctx, &sekizuiv1.StartJobRequest{
			Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:slow"},
		})
		if err != nil {
			t.Fatalf("34a: StartJob: %v", err)
		}

		// NON-VACUITY FIRST. Suspending a principal whose job never reached
		// its driver stops nothing and passes everything.
		waitFor(t, func() bool { return r.pool.InFlight("kata:slow") > 0 },
			"the job never reached its driver, so there is no live work for the "+
				"suspension to stop and the arm below would pass vacuously")

		susp := &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
			Action: "sekizui.revoke_grant", TargetRef: "principal:agent:jobs",
			Args: mustArgs(t, map[string]any{
				"reason": "step 34a: proving a suspension reaches work already running",
			}),
			IdempotencyKey: "acc-34a-suspend",
		}}
		res, err := r.as(t, "operator:oncall").Execute(ctx, susp)
		if err != nil {
			t.Fatalf("34a: suspending: %v", err)
		}
		// **THE SUSPENSION MUST ACTUALLY HAVE HAPPENED, and checking the error
		// is not checking that** — D135 makes a deliberate refusal a result
		// with `err == nil`, which is how step 68's first version suspended
		// nothing and reported success.
		if res.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("34a: the suspension was itself refused (%s), so nothing below "+
				"tests what it claims", res.GetResult().GetReason())
		}

		waitFor(t, func() bool { return r.pool.InFlight("kata:slow") == 0 },
			"the suspended principal's job kept its borrowed client. `revoke_grant` "+
				"writes to the revocation set, which `ceilings` reads AT ADMISSION — "+
				"and a job admits once, at the start. Without reaching in flight, an "+
				"operator sees a successful revocation while the work carries on under "+
				"the grant they just pulled (criterion 17, D256)")
		r.detail(t, "the suspension stopped work already in flight")

		// AND THE RECORD SAYS SO, in the same row as the act: an operator at
		// 03:00 must not have to go and find the job records to learn what
		// their lever actually stopped.
		var suspRow *sekizuiv1.Decision
		for _, d := range readLog(t, r.path) {
			if d.GetMatchedRule() == "revoked:agent:jobs" {
				suspRow = d
			}
		}
		if suspRow == nil {
			t.Fatal("34a: the suspension left no audit row")
		}
		if !strings.Contains(suspRow.GetReason(), started.GetJobId()) {
			t.Errorf("34a: the suspension row does not name the job it stopped: %q. "+
				"The count and the act belong in one row", suspRow.GetReason())
		}
		r.detail(t, "the row names what it stopped: %s",
			firstSentence(suspRow.GetReason()))
	})

	// 34b — A CREDENTIAL REVOKED MID-JOB STOPS IT.
	//
	// **A DIFFERENT MECHANISM AND THE SAME GUARANTEE.** This one reaches the
	// work through the pool: `revoke_credential` cancels the contexts the pool
	// is holding (D128, D129). It could not have worked at all before D255,
	// because the reference driver's poll did not borrow — break-glass would
	// have evicted an empty set and truthfully reported cancelling nothing.
	t.Run("a credential revoked mid-job stops the work", func(t *testing.T) {
		//nolint:contextcheck // harness manages its own lifecycle via *testing.T
		r := newRun(t)
		if r.localOnly(t, "the pool is this instance's") {
			return
		}

		if _, err := r.as(t, "agent:jobs").StartJob(ctx, &sekizuiv1.StartJobRequest{
			Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:slow"},
		}); err != nil {
			t.Fatalf("34b: StartJob: %v", err)
		}
		waitFor(t, func() bool { return r.pool.InFlight("kata:slow") > 0 },
			"the job never borrowed a client, so a revocation would have nothing to "+
				"cancel and the arm would pass vacuously")

		rev := &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
			Action: "sekizui.revoke_credential", TargetRef: "kata:slow",
			Args: mustArgs(t, map[string]any{
				"reason": "step 34b: proving a revocation reaches work already running",
			}),
			IdempotencyKey: "acc-34b-revoke",
		}}
		res, err := r.as(t, "operator:oncall").Execute(ctx, rev)
		if err != nil {
			t.Fatalf("34b: revoking: %v", err)
		}
		if res.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("34b: the revocation was itself refused (%s)",
				res.GetResult().GetReason())
		}

		waitFor(t, func() bool { return r.pool.InFlight("kata:slow") == 0 },
			"the job kept polling on a credential an operator had just declared "+
				"COMPROMISED. `revoke_credential` cancels the contexts the pool holds, "+
				"so a poll that borrowed is stopped and a poll that dialled privately "+
				"is not (D128, D255)")
		r.detail(t, "the revocation stopped work already in flight")
	})
}

// p3Step35 — a job is bounded before it runs, and the caller chose the size
// (P3 criteria 18 and 7, CONTRACTS 70, D257).
//
// **THIS IS THE PATH THAT MAKES TOLERATING CONTRACTS 70 UNTENABLE.**
// `CapabilitySpec.MaxBytes` has been decoded from config, copied into the
// catalog and ADVERTISED TO AGENTS since P0, and referenced zero times by any
// enforcer — worse than inert, because the catalog tells an agent the limit
// exists. A job is where that stops: "review five sessions" and "review five
// million" are the same sentence with a different number.
//
// **BEFORE IT RUNS IS THE LOAD-BEARING HALF.** A bound checked after the work
// is paid for is an accountant rather than a control, so the arms below assert
// the refusal arrives with the driver never having been reached.
func p3Step35(t *testing.T) {
	r := newRun(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if r.localOnly(t, "the job runner and its pool are this instance's") {
		return
	}
	caller := r.as(t, "agent:jobs")

	r.narrate(t, "a job is bounded before it runs, and the caller chose the size")

	// 35a — A MODEST JOB IS ADMITTED AND REACHES ITS DRIVER.
	//
	// **NON-VACUITY FIRST**: a budget that refused everything would pass every
	// arm below while making the capability unusable, which is D142's named
	// failure — a control an operator switches off. The target BLOCKS inside
	// the borrow, so "it reached the driver" is observable rather than raced.
	ok, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{
			Action: "kata.poll", TargetRef: "kata:budgeted",
			Args: mustArgs(t, map[string]any{"limit": 4}),
		},
	})
	if err != nil {
		t.Fatalf("35a: StartJob: %v", err)
	}
	if ok.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("35a: a job within its budget was refused (%s). A bound that refuses "+
			"everything is a bound an operator switches off", ok.GetReason())
	}
	waitFor(t, func() bool { return r.pool.InFlight("kata:budgeted") == 1 },
		"the admitted job never reached its driver, so the arm below could not tell "+
			"a refused job from an admitted one")
	r.detail(t, "4 events fit the 2 MiB budget: admitted, and holding 1 pooled client")

	// 35b — A GREEDY JOB IS REFUSED, AND THE DRIVER IS NEVER REACHED.
	//
	// 64 events × 256 KiB worst case = 16 MiB against a 2 MiB budget.
	greedy, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{
			Action: "kata.poll", TargetRef: "kata:budgeted",
			Args: mustArgs(t, map[string]any{"limit": 64}),
		},
	})
	if err != nil {
		t.Fatalf("35b: the refusal arrived as a transport error, which D135 reserves "+
			"for genuine failures: %v", err)
	}
	if greedy.GetJobId() != "" {
		t.Fatal("35b: a job exceeding its capability's max_bytes was STARTED. " +
			"CONTRACTS 70: the catalog advertises the limit to agents and nothing " +
			"enforced it")
	}
	// **STATUS_INVALID_ARGUMENT, AND NOT STATUS_RATE_LIMITED.** The obvious
	// kind for a budget is `KindBudgetExceeded`, which maps to RATE_LIMITED —
	// "come back later". That is true of a reflex firing budget whose window
	// resets and false here: this request will never fit, and retrying it is
	// the one thing the caller must not do. D201's lesson, on the wire.
	if greedy.GetStatus() != sekizuiv1.Status_STATUS_INVALID_ARGUMENT {
		t.Errorf("35b: the refusal carries status %s, want STATUS_INVALID_ARGUMENT — "+
			"RATE_LIMITED would tell the caller to retry a request that can never "+
			"succeed, and DENIED would send them to read a grant that is fine",
			greedy.GetStatus())
	}
	if greedy.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_REQUEST {
		t.Errorf("35b: the refusal names stage %s, want REFUSED_BY_REQUEST: the grant "+
			"allows this action and the SIZE is what was refused",
			greedy.GetRefusedBy())
	}

	// **BOTH NUMBERS, because a refusal that does not say by how much is one
	// nobody can act on.** The caller needs the size that would fit; the
	// operator needs to know which budget spoke.
	for _, want := range []string{"2097152", "16777216", "kata.poll", "kata:budgeted"} {
		if !strings.Contains(greedy.GetReason(), want) {
			t.Errorf("35b: the refusal does not mention %q: %q", want, greedy.GetReason())
		}
	}
	if !strings.Contains(greedy.GetReason(), "8 or fewer") {
		t.Errorf("35b: the refusal does not tell the caller what WOULD fit, so their "+
			"only recourse is to guess: %q", greedy.GetReason())
	}
	r.detail(t, "refused: %s", firstSentence(greedy.GetReason()))

	// 35c — REFUSED BEFORE THE WORK, NOT AFTER IT.
	//
	// **THE FIRST VERSION OF THIS ARM COULD NOT TELL THE TWO APART, AND A
	// SABOTAGE IS WHAT SHOWED IT.** It asserted `InFlight == 0` on a target
	// that finished in microseconds, so a build that SUBMITTED the job and
	// refused the caller afterwards — "the accountant rather than the
	// control", the exact thing criterion 18 forbids — passed cleanly: the
	// work had already finished by the time the arm looked, and a refused
	// response carries no job id either way.
	//
	// The target blocks inside the borrow now, so the count is a STANDING
	// fact. 35a's job holds exactly one client; a refused job that had
	// reached the driver would make it two.
	if got := r.pool.InFlight("kata:budgeted"); got != 1 {
		t.Errorf("35c: %d clients are borrowed, want 1 (35a's). The refused job "+
			"reached the driver before being refused — a bound checked after the "+
			"work is paid for is an accountant rather than a control", got)
	}
	r.detail(t, "still 1 borrowed client: the refused job never reached the driver")

	// AND THE REFUSAL IS ON THE RECORD, naming the bound that spoke.
	var row *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetId() == greedy.GetDecisionId() {
			row = d
		}
	}
	if row == nil {
		t.Fatal("35c: the budget refusal cites a decision that is not in the log")
	}
	// THE ROW NAMES THE BOUND THAT SPOKE, which is what makes it filterable.
	// `request_bounds` is the precedent: the verdict is a plain DENY because
	// policy allowed, and `matched_rule` carries which bound refused.
	if row.GetMatchedRule() != "capability_max_bytes" {
		t.Errorf("35c: the row's matched_rule is %q, want \"capability_max_bytes\". "+
			"A budget refusal an operator cannot tell from a missing grant is one "+
			"they will go and debug in the wrong place", row.GetMatchedRule())
	}
	if row.GetEffect() != nil {
		t.Error("35c: the refusal carries an EFFECT, which says something happened at " +
			"the far side. Nothing did: it was refused before it ran")
	}
	r.detail(t, "recorded as %s / %s, with no effect — nothing was attempted",
		row.GetVerdict(), row.GetMatchedRule())

	// THE STEP RELEASES THE SOURCE IT BLOCKED ON PURPOSE (step 32d's reason:
	// a blocked poll otherwise holds the runner's Stop for the whole deadline).
	if _, cerr := caller.CancelJob(ctx, &sekizuiv1.CancelJobRequest{
		JobId:  ok.GetJobId(),
		Reason: "step 35: releasing the source this step blocked on purpose",
	}); cerr != nil {
		t.Errorf("35: could not cancel the job this step started: %v", cerr)
	}
}

// step31ResultsTTLCeiling is 31g.
func step31ResultsTTLCeiling(t *testing.T) {
	t.Helper()
	base, err := os.ReadFile("acceptance.yaml")
	if err != nil {
		t.Fatalf("step 31g: %v", err)
	}
	for _, tc := range []struct {
		ttl    string
		refuse bool
	}{{"86400", false}, {"86401", true}} {
		path := filepath.Join(t.TempDir(), "acceptance.yaml")
		src := string(base) + "\njobs: {results_ttl_s: " + tc.ttl + "}\n"
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatalf("step 31g: %v", err)
		}
		doc, err := config.NewFileSource(path).Load(context.Background())
		if err == nil {
			err = doc.Validate()
		}
		switch {
		case tc.refuse && (err == nil || !strings.Contains(err.Error(), "results_ttl_s")):
			t.Errorf("step 31g: results_ttl_s=%s booted (got %v); the ceiling is a day (D268)", tc.ttl, err)
		case !tc.refuse && err != nil:
			t.Errorf("step 31g: results_ttl_s=%s, exactly the ceiling, was refused: %v", tc.ttl, err)
		}
	}
}
