package acceptance

import (
	"context"
	"testing"

	"github.com/fullstorydev/sekizui/internal/verb"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// P1 step 56: a withdrawal is lifted by an explicit governed verb (D133).
//
// RUNS AGAINST A LIVE INSTANCE, and that is the point rather than a bonus.
// Every other break-glass step reaches into this process's pool or audit log,
// so all of them skip under `make demo` — which meant the feature could not be
// SHOWN, only asserted. This one uses nothing but the wire: three commands and
// their statuses. It is also the step that makes demonstrating break-glass
// safe at all, since before `restore_target` existed a demo revocation left its
// target dead until the process restarted (CONTRACTS §4 items 34 and 36).
//
// Uses `kata:restore`, a target existing only for this, so a demo cannot
// sabotage another step by withdrawing something shared.
func step56RestoreLiftsAWithdrawal(t *testing.T) {
	const target = "kata:restore"

	ctx := context.Background()
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(ctx)
	}

	oncall := r.as(t, "operator:oncall")
	agent := r.as(t, "agent:binding")

	// commandRefused asserts the ONE shape a refusal takes (D135).
	//
	// This accepted TWO until the shapes were unified: a policy denial was a
	// DENIED result while a withdrawal refusal was a gRPC error, and the first
	// draft of this helper checked one and would have reported the other half of
	// refusals as SUCCESS. That happened twice in this suite, which is what made
	// the asymmetry worth fixing rather than working around. Asserting a single
	// shape here is the evidence that it was.
	commandRefused := func() (bool, string) {
		t.Helper()
		resp, err := agent.Execute(ctx,
			execute("kata.create_issue", target, map[string]any{"project": "PROJ"}))
		if err != nil {
			t.Fatalf("a refusal arrived as a transport error (%v); every deliberate "+
				"refusal reaches the caller as a result", err)
		}
		res := resp.GetResult()
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK && res.GetDecisionId() == "" {
			t.Error("a refusal carries no decision id, so the stdout line an operator " +
				"watches cannot be joined to the record explaining it (D124)")
		}
		return res.GetStatus() == sekizuiv1.Status_STATUS_DENIED, res.GetStatus().String()
	}

	commandOK := func() {
		t.Helper()
		resp, err := agent.Execute(ctx,
			execute("kata.create_issue", target, map[string]any{"project": "PROJ"}))
		if err != nil {
			t.Fatalf("commanding %s: %v", target, err)
		}
		if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("commanding %s: status %v: %s", target, got, resp.GetResult().GetReason())
		}
	}

	call := func(action string) *sekizuiv1.CommandResult {
		t.Helper()
		resp, err := oncall.Execute(ctx, execute(action, target, nil))
		if err != nil {
			t.Fatalf("%s on %s: %v", action, target, err)
		}
		return resp.GetResult()
	}

	// --- 0. restoring something nobody withdrew is REFUSED -------------------
	//
	// Asserted FIRST, while the target is definitely healthy. A no-op that
	// reports success is how a mistyped reference during an incident convinces
	// an operator the system is fine.
	noop, err := oncall.Execute(ctx, execute(verb.RestoreTarget, target, nil))
	if err != nil {
		t.Fatalf("the refusal arrived as a transport error (%v); it is deliberate", err)
	}
	// ASSERTED POSITIVELY, and the change matters more than it looks (D138).
	//
	// This read `!= STATUS_OK`, which was correct for what it was written to
	// catch and blind to what actually happened: the refusal arrived as
	// STATUS_UNSPECIFIED — the zero value, meaning "nobody set this" — because
	// KindInvalidArgument is Deliberate and had no entry in Kind.Status(). A
	// negative assertion is satisfied by the absence of an answer, so a client
	// switching on status fell through to its default while this test passed.
	if got := noop.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_INVALID_ARGUMENT {
		t.Errorf("restoring a target that was never withdrawn reported %v, want "+
			"STATUS_INVALID_ARGUMENT. During an incident a no-op that answers OK is "+
			"worse than failing — and so is one that answers nothing at all", got)
	}
	if got := noop.GetResult().GetKind(); got != "invalid_argument" {
		t.Errorf("kind = %q, want invalid_argument; the fine taxonomy is what an "+
			"in-process caller has instead of fault.KindOf (D138)", got)
	}

	// --- 1. healthy -----------------------------------------------------------
	//
	// Without this, nothing below distinguishes a working restore from a target
	// that never worked in the first place.
	commandOK()

	// --- 2. withdrawn ---------------------------------------------------------
	if got := call(verb.RevokeCredential).GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("revoke_credential status = %v, want OK", got)
	}
	if refused, how := commandRefused(); !refused {
		t.Fatalf("a command against a revoked target was not refused (%s). The "+
			"withdrawal is not stopping new work, so everything below is vacuous", how)
	}

	// --- 3. restored ----------------------------------------------------------
	restored := call(verb.RestoreTarget)
	if got := restored.GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("restore_target status = %v, want OK: %s", got, restored.GetReason())
	}
	if restored.GetDecisionId() == "" {
		t.Error("the restore produced no decision id. Lifting a revocation asserts that " +
			"a credential believed compromised is safe again — if that is not recorded, " +
			"the audit log says a target was revoked and never says anybody un-revoked it")
	}

	// A revocation that cannot be lifted is a one-way door needing a restart.
	commandOK()

	// --- 4. and it is symmetric for the gentler severity ----------------------
	if got := call(verb.QuarantineTarget).GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("quarantine_target status = %v, want OK", got)
	}
	if refused, how := commandRefused(); !refused {
		t.Fatalf("a command against a quarantined target was not refused (%s)", how)
	}
	if got := call(verb.RestoreTarget).GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("restore after quarantine status = %v, want OK", got)
	}
	commandOK()

	// --- 5. the record says which severity was lifted -------------------------
	//
	// Local only: it reads this process's audit log. The behaviour above is what
	// a live demo shows; this is what an incident review reads months later.
	if r.localOnly(t, "it reads this process's audit log") {
		return
	}
	var rec *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetId() == restored.GetDecisionId() {
			rec = d
			break
		}
	}
	if rec == nil {
		t.Fatalf("no record for restore decision %q", restored.GetDecisionId())
	}
	rst := rec.GetRestoration()
	if rst == nil {
		t.Fatal("the restore wrote no restoration detail, so the row is indistinguishable " +
			"from any other allowed command")
	}
	if got, want := rst.GetRestoredFrom(), "revoke_credential"; got != want {
		t.Errorf("restored_from = %q, want %q. Lifting a REVOCATION is a security "+
			"decision and lifting a quarantine is a health one; a reviewer must be able "+
			"to tell them apart", got, want)
	}
	if got, want := rst.GetTrigger(), "operator:operator:oncall"; got != want {
		t.Errorf("trigger = %q, want %q", got, want)
	}
}
