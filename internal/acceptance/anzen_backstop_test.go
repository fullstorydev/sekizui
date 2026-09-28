package acceptance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// TestAnUnbuiltAnzenActionIsRefusedNotRevoked is the runtime backstop behind
// D331's boot refusal (CONTRACTS 157). Until D331 an enforcing rule doing
// `alert` — "changes no behaviour" — fired as a CREDENTIAL REVOCATION of its
// subject, because the withdrawal path read every action but quarantine as
// revoke. Boot refuses such a rule now, so this stands one up past validation
// and fires it exactly as the dispatcher does: refused, recorded, and the
// target still serves.
func TestAnUnbuiltAnzenActionIsRefusedNotRevoked(t *testing.T) {
	for _, do := range config.UnbuiltAnzenActions() {
		t.Run(do, func(t *testing.T) {
			rule := "backstop-" + strings.ReplaceAll(do, "_", "-")
			r := newRunWith(t, runOpts{postValidate: func(d *config.Document) {
				d.Anzen = append(d.Anzen, config.AnzenSpec{Name: rule, Enabled: true, Mode: "enforce",
					Watches: "budget_exceeded", Do: do, Subject: "kata:alpha"})
			}})
			if r.localOnly(t, "the patched deployment is this instance's") {
				return
			}
			ctx := context.Background()
			principal := "anzen:" + rule
			id := &sekizuiv1.Identity{
				Caller: &sekizuiv1.Caller{Principal: principal, Method: sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL,
					CredentialId: "anzen:reactive-dispatcher"},
				Subject: &sekizuiv1.Subject{Principal: principal, Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED},
				Chain:   []string{principal},
			}
			res, err := r.srv.Enforce(ctx, id, &sekizuiv1.Command{Action: verb.FireAnzen, TargetRef: "anzen:" + rule})
			if err != nil {
				t.Fatalf("firing %s: %v", rule, err)
			}
			if res.GetStatus() != sekizuiv1.Status_STATUS_DENIED || !strings.Contains(res.GetReason(), "does not implement") {
				t.Errorf("firing a rule that does %s came back %v (%s); want refused, naming the unbuilt action",
					do, res.GetStatus(), res.GetReason())
			}
			read, err := r.as(t, "agent:triage").Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
			if err != nil || read.GetStatus() != sekizuiv1.Status_STATUS_OK {
				t.Fatalf("after firing a rule that does %s, kata:alpha no longer serves: %v %v (%s) — the "+
					"action was carried out as a withdrawal", do, err, read.GetStatus(), read.GetReason())
			}
		})
	}
}
