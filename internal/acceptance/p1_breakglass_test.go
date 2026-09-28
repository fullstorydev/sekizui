package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"

	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// P1 step 10: break-glass writes a decision record naming what it cancelled.

// step10RevocationIsRecorded drives a revocation the way an operator does —
// over mTLS, as a granted principal, through the one enforcement path — and
// then reads the audit log to see what it said.
//
// WHY THE RECORD IS THE STEP RATHER THAN THE REVOCATION. Step 9 already proves
// the cancellation works. What D106 additionally claims is that a revocation is
// AUDITABLE, and that claim is the entire reason cancellation was chosen over
// wiping the cached material: "a memory write cannot be audited". A revocation
// that stops the work and leaves no account of it satisfies half a decision and
// the wrong half — an incident review cannot ask a `clear()` what it destroyed,
// and it cannot ask an unrecorded cancellation either.
//
// THE COUNT IS THE ASSERTION THAT MATTERS. Severity and trigger can be
// reconstructed from the command; the number of in-flight calls killed cannot be
// reconstructed from anything, at any later time, by anybody. If it is not
// written down at the instant it happens it is gone, which is exactly why D106
// names it specifically.
func step10RevocationIsRecorded(t *testing.T) {
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	if r.localOnly(t, "it reads this process's audit log") {
		return
	}

	ctx := context.Background()

	// A REAL COMMAND, IN FLIGHT, OVER mTLS — not a call planted directly into
	// the pool.
	//
	// This is what changed when the driver started borrowing from the pool. The
	// earlier version reached into the shared pool by hand, which proved the
	// mechanism and left the integration untested: a production revocation
	// found an empty pool and truthfully reported cancelling nothing
	// (CONTRACTS §4 item 35). Now the in-flight call is an ordinary governed
	// command with a latency argument, and the revocation has to reach it the
	// way it would at 03:00.
	type outcome struct {
		status sekizuiv1.Status
		err    error
	}
	slow := make(chan outcome, 1)
	go func() {
		resp, err := r.as(t, "agent:binding").Execute(ctx,
			execute("kata.create_issue", "kata:alpha", map[string]any{
				"project":       "PROJ",
				kata.LatencyKey: "30s",
			}))
		slow <- outcome{resp.GetResult().GetStatus(), err}
	}()

	// Wait until it is genuinely in flight, rather than sleeping and hoping.
	waitFor(t, func() bool { return r.pool.InFlight("kata:alpha") > 0 },
		"no command reached the pool for kata:alpha, so the revocation below would "+
			"cancel nothing and the count it records would be vacuously zero")

	before := logLen(t, r)

	oncall := r.as(t, "operator:oncall")
	resp, err := oncall.Execute(ctx, execute(verb.RevokeCredential, "kata:alpha", nil))
	if err != nil {
		t.Fatalf("revoke_credential over the wire: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("revocation status = %v, want OK: %s", got, resp.GetResult().GetReason())
	}
	decisionID := resp.GetResult().GetDecisionId()
	if decisionID == "" {
		t.Fatal("the revocation returned no decision id, so nothing joins this action " +
			"to the record that explains it")
	}

	// The cancelled COMMAND must actually have unwound, and it must have failed.
	select {
	case got := <-slow:
		// A RESULT, NOT AN ERROR (D135). A cancelled in-flight command is a
		// deliberate refusal, so it reaches the caller the same way a policy
		// denial does — which is the whole point of the uniform shape, and the
		// first draft of this assertion checked `err == nil` and would have
		// reported the refusal as success.
		if got.err != nil {
			t.Errorf("the cancelled command arrived as a transport error (%v); a "+
				"revocation is deliberate and must reach the caller as a result", got.err)
		}
		if got.status != sekizuiv1.Status_STATUS_DENIED {
			t.Errorf("the in-flight command returned %v, want DENIED — it completed "+
				"normally through a revocation of the credential it was using", got.status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight command never returned after its credential was revoked. " +
			"Something reported a cancellation and cancelled nothing")
	}

	records := readLog(t, r.path)
	if len(records) <= before {
		t.Fatal("the revocation wrote no audit record at all. D106 chose cancellation " +
			"over wiping the cached material precisely because a memory write cannot " +
			"be audited — an unrecorded cancellation gives that reason away for nothing")
	}

	var rec *sekizuiv1.Decision
	for _, d := range records {
		if d.GetId() == decisionID {
			rec = d
			break
		}
	}
	if rec == nil {
		t.Fatalf("no record with id %q; the caller was handed a decision id that "+
			"resolves to nothing", decisionID)
	}

	rv := rec.GetRevocation()
	if rv == nil {
		t.Fatal("the record has no revocation detail, so it is indistinguishable from " +
			"any other allowed command — `Decision.revocation` is declared and inert, " +
			"which is the shape of CONTRACTS §4 item 23")
	}

	if got, want := rv.GetSeverity(), "revoke_credential"; got != want {
		t.Errorf("severity = %q, want %q — matching the anzen verb exactly, so a query "+
			"joins to the vocabulary", got, want)
	}
	if got, want := rv.GetTrigger(), "operator:operator:oncall"; got != want {
		t.Errorf("trigger = %q, want %q. Identity says who authenticated; trigger says "+
			"what fired it, and an anzen rule at 03:00 has no human behind it", got, want)
	}

	// THE NUMBER NOTHING ELSE CAN RECONSTRUCT.
	if got := rv.GetCancelledInFlight(); got != 1 {
		t.Errorf("cancelled_in_flight = %d, want 1. This is the count D106 names "+
			"specifically: it exists only at the instant of the revocation, and no "+
			"later query of any other record can recover it", got)
	}
	if got := rv.GetEvicted(); got != 1 {
		t.Errorf("evicted = %d, want 1", got)
	}
	if got := rv.GetLeftRunning(); got != 0 {
		t.Errorf("left_running = %d, want 0 — a revocation leaves nothing running; "+
			"that field belongs to quarantine", got)
	}
	if got := rv.GetStragglers(); got != 0 {
		t.Errorf("stragglers = %d, want 0; the call honoured its context, so the drain "+
			"completed and the material is wiped", got)
	}

	// The record must still be a proper decision record, not a special-cased row.
	if rec.GetIdentity().GetSubject().GetPrincipal() != "operator:oncall" {
		t.Errorf("identity.subject = %q, want operator:oncall — break-glass is governed "+
			"like everything else (D129), so the row names who did it",
			rec.GetIdentity().GetSubject().GetPrincipal())
	}
	if rec.GetResidency() != "us" {
		t.Errorf("residency = %q, want us. The audit sink refuses records it may not "+
			"receive (D29 item 4), and it can only do that if the row says where the "+
			"data came from", rec.GetResidency())
	}
	if rec.GetAction() != verb.RevokeCredential {
		t.Errorf("action = %q, want %q", rec.GetAction(), verb.RevokeCredential)
	}
}

// step10bUngrantedRevocationIsRefused is the non-vacuity half.
//
// Every assertion above would also pass if break-glass were an ungoverned side
// door that happened to write a record. What makes D129 true rather than
// decorative is that the verb is REFUSABLE by the same grant table as any other
// action — so a principal without the grant must be denied, and denied with a
// record.
func step10bUngrantedRevocationIsRefused(t *testing.T) {
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	if r.localOnly(t, "it asserts on this process's audit log") {
		return
	}

	triage := r.as(t, "agent:triage")
	resp, err := triage.Execute(context.Background(),
		execute(verb.RevokeCredential, "kata:alpha", nil))
	if err != nil {
		t.Fatalf("expected a recorded denial, got a transport error: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("agent:triage revoked a credential it has no grant for (status %v). "+
			"Break-glass would be an ungoverned side door and D18's single enforcement "+
			"path a fiction", got)
	}
	if resp.GetResult().GetDecisionId() == "" {
		t.Error("the refusal produced no decision record. §5.4: an attempted revocation " +
			"by an unauthorised principal is among the highest-value rows this system " +
			"can write")
	}
}

// step10cQuarantineRecordsWhatItLeftRunning proves the record distinguishes the
// two severities, not merely the mechanism.
//
// Step 11 shows the pool behaves differently. This shows an incident reviewer
// can TELL, months later, from the row alone — which is the difference between
// the severities existing and the severities being auditable.
func step10cQuarantineRecordsWhatItLeftRunning(t *testing.T) {
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	if r.localOnly(t, "it asserts on the shared client pool") {
		return
	}

	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "kata:alpha", Kind: "kata", Tenant: "alpha", Residency: "eu",
		CredentialVersion: "env://SEKIZUI_ACCEPT_TOK#1",
		Credential:        connector.Secret([]byte("alpha-token")),
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	call := holdOpen(t, r.pool, tgt)
	defer func() {
		call.finish()
		_ = call.wait()
	}()

	oncall := r.as(t, "operator:oncall")
	resp, err := oncall.Execute(context.Background(),
		execute(verb.QuarantineTarget, "kata:alpha", nil))
	if err != nil {
		t.Fatalf("quarantine_target over the wire: %v", err)
	}

	var rec *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetId() == resp.GetResult().GetDecisionId() {
			rec = d
			break
		}
	}
	if rec == nil {
		t.Fatal("no record for the quarantine")
	}

	rv := rec.GetRevocation()
	if rv == nil {
		t.Fatal("the quarantine wrote no revocation detail; the two severities are " +
			"indistinguishable in the audit log even though they differ in the pool")
	}
	if got, want := rv.GetSeverity(), "quarantine_target"; got != want {
		t.Errorf("severity = %q, want %q", got, want)
	}
	if got := rv.GetCancelledInFlight(); got != 0 {
		t.Errorf("cancelled_in_flight = %d, want 0 — quarantine cancels nothing", got)
	}
	if got := rv.GetLeftRunning(); got != 1 {
		t.Errorf("left_running = %d, want 1. An operator quarantining during an "+
			"incident needs to know work is still out there; 'nothing happened' and "+
			"'a call is still running' look identical without it", got)
	}
}

// step10BreakGlassIsRecorded is the registered step: three phases, each with its
// own instance.
//
// SEPARATE INSTANCES ON PURPOSE, not for tidiness. A withdrawal is sticky by
// design — it is lifted by a config reload and by nothing else (§4.11's
// `revoke_grant` shape) — so a revocation of kata:alpha in one phase would
// refuse the next phase's setup and the quarantine assertions would pass
// against a target that was already revoked. Sharing a run here would make the
// step cheaper and its third phase meaningless.
func step10BreakGlassIsRecorded(t *testing.T) {
	t.Run("revocation_names_what_it_cancelled", step10RevocationIsRecorded)
	t.Run("ungranted_revocation_is_refused", step10bUngrantedRevocationIsRefused)
	t.Run("quarantine_records_what_it_left", step10cQuarantineRecordsWhatItLeftRunning)
}
