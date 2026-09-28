package acceptance

import (
	"context"
	"testing"

	"github.com/fullstorydev/sekizui/internal/verb"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// P1 step 57: anzen supplies the DECISION, a human supplies only the TRIGGER
// (D134).

func step57AnzenDecidesAHumanFires(t *testing.T) {
	ctx := context.Background()
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(ctx)
	}

	oncall := r.as(t, "operator:oncall")

	fire := func(rule string) (*sekizuiv1.CommandResult, error) {
		t.Helper()
		resp, err := oncall.Execute(ctx,
			execute(verb.FireAnzen, "anzen:"+rule, nil))
		return resp.GetResult(), err
	}

	// refused asserts the ONE shape a refusal takes (D135). It accepted two
	// until the shapes were unified; asserting a single one now is what proves
	// they were.
	refused := func(res *sekizuiv1.CommandResult, err error) (bool, string) {
		t.Helper()
		if err != nil {
			t.Fatalf("a refusal arrived as a transport error (%v); every deliberate "+
				"refusal reaches the caller as a result", err)
		}
		return res.GetStatus() != sekizuiv1.Status_STATUS_OK, res.GetStatus().String()
	}

	// --- 1. a SHADOW rule cannot be fired ------------------------------------
	//
	// §4.11.4 item 3 wants a rule observed for a week before it enforces. An
	// observation a human can discharge on demand is not an observation, and
	// the alternative — letting it fire — is how an unmade decision comes to
	// look like a made one.
	if ok, how := refused(fire("quarantine-under-observation")); !ok {
		t.Errorf("a SHADOW anzen rule was fired on demand (%s). The observation period "+
			"is then whatever an operator decides it is, and a rule nobody has trusted "+
			"yet becomes live at the worst possible moment", how)
	}

	// --- 2. an unknown rule is refused, not silently ignored -----------------
	if ok, how := refused(fire("no-such-rule")); !ok {
		t.Errorf("firing an undeclared rule was not refused (%s). Silently doing nothing "+
			"during an incident is the worst available outcome", how)
	}

	// --- 3. firing a real rule performs ITS decision -------------------------
	//
	// The operator names only the rule. The subject (kata:restore) and the
	// severity (revoke_credential) come from configuration, which is the whole
	// point: nothing about the response is composed under pressure.
	res, err := fire("credential-compromise")
	if err != nil {
		t.Fatalf("firing credential-compromise: %v", err)
	}
	if got := res.GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("fire_anzen status = %v, want OK: %s", got, res.GetReason())
	}

	// It really withdrew the rule's subject, which the command never named.
	agent := r.as(t, "agent:binding")
	cmdResp, cmdErr := agent.Execute(ctx,
		execute("kata.create_issue", "kata:restore", map[string]any{"project": "PROJ"}))
	if cmdErr != nil {
		t.Fatalf("the refusal arrived as a transport error (%v); it is deliberate", cmdErr)
	}
	if got := cmdResp.GetResult().GetStatus(); got == sekizuiv1.Status_STATUS_OK {
		t.Error("kata:restore still serves commands after credential-compromise fired. " +
			"The rule named it as the subject and the operator never did, so if it is " +
			"still live the rule supplied nothing")
	}

	// Put it back, so this step cannot poison a live instance for the next run.
	if _, err := oncall.Execute(ctx,
		execute(verb.RestoreTarget, "kata:restore", nil)); err != nil {
		t.Fatalf("restoring kata:restore: %v", err)
	}

	// --- 4. the record names the rule that decided it ------------------------
	if r.localOnly(t, "it reads this process's audit log") {
		return
	}

	var fired, improvised *sekizuiv1.Revocation
	for _, d := range readLog(t, r.path) {
		if d.GetId() == res.GetDecisionId() {
			fired = d.GetRevocation()
			if got := d.GetIdentity().GetSubject().GetPrincipal(); got != "operator:oncall" {
				t.Errorf("identity.subject = %q, want operator:oncall. Anzen supplies the "+
					"DECISION; the human supplies the authority, and a record claiming an "+
					"anzen principal would misstate where that came from (D122)", got)
			}
			if got := d.GetTargetRef(); got != "kata:restore" {
				t.Errorf("target_ref = %q, want kata:restore — the record must name what "+
					"was actually withdrawn, not the rule that was addressed", got)
			}
		}
	}
	if fired == nil {
		t.Fatal("no record for the fired rule")
	}
	if got, want := fired.GetDecidedBy(), "credential-compromise"; got != want {
		t.Errorf("decided_by = %q, want %q", got, want)
	}
	if got, want := fired.GetSeverity(), "revoke_credential"; got != want {
		t.Errorf("severity = %q, want %q — taken from the rule, not from the command", got, want)
	}

	// --- 5. an IMPROVISED withdrawal is recorded as a GAP --------------------
	//
	// The raw verb stays available, because §4.7.10 rules out any path needing
	// a redeploy and the unanticipated incident is what break-glass is for. But
	// its absence from configuration must not read as health: `decided_by` is
	// empty, which makes the improvised withdrawals queryable as the list of
	// decisions nobody has made yet.
	raw, err := oncall.Execute(ctx,
		execute(verb.RevokeCredential, "kata:alpha", nil))
	if err != nil {
		t.Fatalf("improvised revocation: %v", err)
	}
	for _, d := range readLog(t, r.path) {
		if d.GetId() == raw.GetResult().GetDecisionId() {
			improvised = d.GetRevocation()
		}
	}
	if improvised == nil {
		t.Fatal("no record for the improvised revocation")
	}
	if got := improvised.GetDecidedBy(); got != "" {
		t.Errorf("decided_by = %q for a withdrawal nobody declared a rule for, want empty. "+
			"An empty value is what makes the gap QUERYABLE — if improvised withdrawals "+
			"cannot be told from planned ones, the absence of a rule looks like health", got)
	}
}
