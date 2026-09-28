package acceptance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/verb"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step64GrantVerbsSuspendAPrincipalAtRuntime proves D146 — the alternative to
// hot reload.
//
// §4.5 and D10 promise that a rule change does not require a redeploy, and the
// machinery for that (a watcher plus an atomic document swap) turned out to cost
// more in security than it bought in convenience: three pieces of state gate the
// command path, and rebuilding any of them makes a config edit the way to undo
// it. A governed verb has no document to swap and no derived state to rebuild,
// so there is nothing to launder — and it leaves an audit record rather than a
// config diff.
func step64GrantVerbsSuspendAPrincipalAtRuntime(t *testing.T) {
	ctx := context.Background()
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(ctx)
	}

	oncall := r.as(t, "operator:oncall")
	suspended := "agent:global"

	// The suspended principal's own command, used to prove the lever works in
	// both directions. `agent:global` is granted on the us-resident kata:beta,
	// which this single-class run refuses on RESIDENCY — a different refusal
	// from the one under test, and that is exactly what makes it a good probe:
	// the two must stay distinguishable.
	probe := func(t *testing.T) *sekizuiv1.CommandResult {
		t.Helper()
		resp, err := r.as(t, suspended).Execute(ctx,
			execute("kata.create_issue", "kata:beta", map[string]any{"project": "PROJ"}))
		if err != nil {
			t.Fatalf("probe arrived as a transport error: %v", err)
		}
		return resp.GetResult()
	}

	before := probe(t)
	if before.GetKind() != "residency" {
		t.Fatalf("the probe refuses with kind %q before any suspension, want residency; "+
			"this step cannot tell a runtime suspension from the pre-existing refusal",
			before.GetKind())
	}

	// --- SUSPEND -------------------------------------------------------------
	revoke := execute(verb.RevokeGrant, "principal:"+suspended,
		map[string]any{"reason": "acceptance: proving the lever"})
	resp, err := oncall.Execute(ctx, revoke)
	if err != nil {
		t.Fatalf("%s: %v", verb.RevokeGrant, err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("%s = %v (%s)", verb.RevokeGrant, got, resp.GetResult().GetReason())
	}
	// THE REASON IS ON THE RECORD (D340, CONTRACTS 158). The verb REQUIRES one
	// because "it is written into the decision record" — and until the v1
	// hotfix it was not, for this or any suspension. Local: the log is this
	// process's.
	if !r.remote {
		var rec *sekizuiv1.Decision
		for _, d := range readLog(t, r.path) {
			if d.GetId() == resp.GetResult().GetDecisionId() {
				rec = d
			}
		}
		if rec == nil || !strings.Contains(rec.GetReason(), "acceptance: proving the lever") {
			t.Errorf("the suspension's record carries reason %q; the verb requires a reason precisely so "+
				"the record can say why this principal stopped working", rec.GetReason())
		}
	}

	// THE REFUSAL CHANGES ITS REASON, not merely its existence. Before the
	// suspension the probe was refused on RESIDENCY; after it, the suspension
	// outranks that — it is checked before the anzen guard and before policy,
	// because it answers a blunter question than either: not "may this principal
	// do this" but "may this principal do anything at all right now".
	during := probe(t)
	if during.GetKind() == "residency" {
		t.Error("the probe is still refused on RESIDENCY after its principal was " +
			"suspended, so the suspension is not being consulted — a lever that " +
			"changes nothing is worse than no lever, because an operator believes " +
			"they have acted")
	}
	if during.GetStatus() != sekizuiv1.Status_STATUS_DENIED {
		t.Errorf("status = %v during suspension, want DENIED", during.GetStatus())
	}

	// --- A SECOND SUSPENSION IS REFUSED, NOT A NO-OP -------------------------
	//
	// A REPEAT IS CONFIRMED, NOT REFUSED (D158, superseding D146's conclusion).
	//
	// D146 refused it so nobody would "conclude the lever was pulled when it was
	// already pulled by someone else" — a real concern, and an error is the wrong
	// answer to it. Under stress a refusal reads as "it did not work", which
	// sends a second on-call engineer after a bigger hammer for a condition
	// already handled, and on a fleet produces one false alarm per healthy
	// instance. **Naming WHO pulled it and WHEN serves D146's concern directly**,
	// where a refusal only signalled that something was odd.
	again, err := oncall.Execute(ctx, revoke)
	if err != nil {
		t.Fatalf("re-suspending: %v", err)
	}
	if again.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("a repeated suspension was refused: %s", again.GetResult().GetReason())
	}

	// THE ANSWER HAS TO CARRY THREE THINGS, or it is just a friendlier silence:
	// that it was already done, WHO did it, and — because this is the one that
	// is NOT durable (D146 vs D145) — that it lasts only until a redeploy. An
	// operator reading a bare confirmation could reasonably infer permanence
	// this does not have, and then not edit config.
	reason := again.GetResult().GetReason()
	for _, want := range []string{"already suspended", "operator:oncall", "redeployed"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the confirmation does not mention %q: %q", want, reason)
		}
	}

	// --- REINSTATE -----------------------------------------------------------
	//
	// NON-VACUITY, and the direction that matters most: a lever with no way back
	// would pass everything above while making the principal permanently dead
	// until a redeploy.
	back, err := oncall.Execute(ctx,
		execute(verb.ReinstateGrant, "principal:"+suspended, nil))
	if err != nil {
		t.Fatalf("%s: %v", verb.ReinstateGrant, err)
	}
	if got := back.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("%s = %v (%s)", verb.ReinstateGrant, got, back.GetResult().GetReason())
	}

	after := probe(t)
	if after.GetKind() != "residency" {
		t.Errorf("after reinstatement the probe refuses with kind %q, want residency — "+
			"the principal should be back to exactly the refusal it had before, and "+
			"anything else means the lift changed something it should not have",
			after.GetKind())
	}

	// --- A SUSPENSION WITH NO STATED REASON IS REFUSED -----------------------
	//
	// The reason is written into the decision record and read by whoever asks
	// why this principal stopped working, possibly months later. Required rather
	// than defaulted: a default would be a sentence nobody wrote appearing in
	// the audit log as though somebody had.
	noReason, err := oncall.Execute(ctx,
		execute(verb.RevokeGrant, "principal:"+suspended, nil))
	if err != nil {
		t.Fatalf("reason-less suspension: %v", err)
	}
	if noReason.GetResult().GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Error("a suspension with no `reason` was accepted; the audit record would " +
			"say a principal was suspended and not why")
	}
}
