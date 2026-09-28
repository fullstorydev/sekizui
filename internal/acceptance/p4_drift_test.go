package acceptance

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p4Step32 — every drift comparison leaves a decision record, and a finding
// survives a restart (D311).
func p4Step32(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "every drift comparison is admitted and recorded like a poll, and a finding "+
		"survives a restart")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stack := newMCPStack(ctx, t, func(d *config.Document) {
		d.Grants = append(d.Grants, config.GrantSpec{Principal: "operator:ops", Allow: []config.CapabilitySpec{
			{Action: verb.QuarantineTarget, TargetRef: "fixture-mcp"}}})
	})
	spec := stack.doc.MCPSpecs["fixture-mcp"]
	offer := func(skip string) {
		var live []mcp.LiveTool
		for _, tool := range spec.Tools {
			if tool.Name == skip {
				continue
			}
			lt := mcp.LiveTool{Name: tool.Name, InputSchema: tool.InputSchema}
			if tool.OutputSchemaOrigin == "vendor" {
				lt.OutputSchema = tool.OutputSchema
			}
			live = append(live, lt)
		}
		stack.up.offer(live...)
	}
	statePath := filepath.Join(t.TempDir(), "audit.jsonl.drift")
	open := func() *drift.Store {
		s, err := drift.OpenStore(statePath)
		if err != nil {
			t.Fatalf("step 32: the drift state does not load: %v", err)
		}
		return s
	}
	deps := drift.Deps{
		Resolver: resolveOnly{stack.mcpRig},
		Drivers:  map[string]connector.Driver{mcp.Kind: stack.driver},
		Targets:  stack.doc.Targets,
		Gate:     stack.gw.DriftGate(),
	}
	check := func(store *drift.Store) {
		drift.NewWatcher(store, time.Hour, discardLog(), func() drift.Deps { return deps }).Check(ctx, deps)
	}
	driftRecords := func() []*sekizuiv1.Decision {
		var out []*sekizuiv1.Decision
		for _, d := range readLog(t, stack.logPath) {
			if d.GetAction() == gateway.DriftAction {
				out = append(out, d)
			}
		}
		return out
	}
	last := func() *sekizuiv1.Decision {
		recs := driftRecords()
		if len(recs) == 0 {
			t.Fatal("step 32: no drift comparison is in the audit log at all")
		}
		return recs[len(recs)-1]
	}
	withheldAction := "mcp." + spec.Server + "." + spec.Tools[0].Name

	// 32a — A CLEAN COMPARISON LEAVES A TRACE, as the built-in principal.
	store := open()
	offer("")
	check(store)
	rec := last()
	switch {
	case rec.GetMatchedRule() != "drift:clean":
		t.Fatalf("step 32a: a clean comparison recorded %q", rec.GetMatchedRule())
	case rec.GetIdentity().GetSubject().GetPrincipal() != gateway.DriftPrincipal:
		t.Errorf("step 32a: the comparison is attributed to %q", rec.GetIdentity().GetSubject().GetPrincipal())
	case rec.GetEffect().GetDetail().AsMap()["state_persisted"] != true:
		t.Errorf("step 32a: the record does not say the state persisted: %v", rec.GetEffect().GetDetail().AsMap())
	}

	// 32b — A DIVERGENCE IS RECORDED WITH ITS FINDING, and the tool is withheld.
	offer(spec.Tools[0].Name)
	check(store)
	rec = last()
	findings, _ := rec.GetEffect().GetDetail().AsMap()["findings"].([]any)
	if rec.GetMatchedRule() != "drift:diverged" || len(findings) == 0 {
		t.Fatalf("step 32b: a withdrawn tool recorded %q with findings %v", rec.GetMatchedRule(), findings)
	}
	if !store.Withholds(stack.target.Ref(), withheldAction) {
		t.Fatalf("step 32b: the withdrawn tool %s is not withheld", withheldAction)
	}

	// 32c — A RESTART DOES NOT CLEAR IT; only a clean comparison does.
	restarted := open()
	if !restarted.Withholds(stack.target.Ref(), withheldAction) {
		t.Fatal("step 32c: a restart forgot the divergence — the withdrawn tool would be served " +
			"again; a restart must never be how a finding goes away")
	}
	offer("")
	check(restarted)
	if last().GetMatchedRule() != "drift:clean" || restarted.Withholds(stack.target.Ref(), withheldAction) {
		t.Error("step 32c: a clean comparison after the restart did not clear the finding")
	}

	// 32d — A REFUSED COMPARISON IS RECORDED AS REFUSED, and never reaches the vendor.
	res, err := stack.gw.Enforce(ctx, assertedIdentity("operator:ops"), &sekizuiv1.Command{
		Action: verb.QuarantineTarget, TargetRef: "fixture-mcp"})
	if err != nil || res.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 32d: the target could not be quarantined: %v %s", err, res.GetReason())
	}
	before := stack.up.listCalls()
	check(restarted)
	rec = last()
	if rec.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL {
		t.Errorf("step 32d: a comparison of a withdrawn target recorded %s / %q, not a withdrawal refusal",
			rec.GetRefusedBy(), rec.GetMatchedRule())
	}
	if stack.up.listCalls() != before {
		t.Error("step 32d: a comparison the ceilings refused still called tools/list")
	}
	r.detail(t, "clean, diverged and refused comparisons each left a record as %s; the finding "+
		"survived a restart and cleared only on a clean comparison", gateway.DriftPrincipal)
}
