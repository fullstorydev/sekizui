package acceptance

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p5Step5 — a budget trip halts the reflex and the alert reaches an anzen rule
// (D264, D331, D332). Halting on the budget was P3 step 40's; this proves the
// RESPONSE: `budget_exceeded` reaches the anzen dispatcher the binary wires, an
// `alert` rule records it, and a `disable_reflex` rule switches the reflex off.
func p5Step5(t *testing.T) {
	const budgeted = "budgeted-ticket" // acceptance.yaml: max_firings_per_hour 2
	r := newRunWith(t, runOpts{patch: func(d *config.Document) {
		d.Anzen = append(d.Anzen,
			config.AnzenSpec{Name: "alert-on-budget", Enabled: true, Mode: "enforce",
				Watches: "budget_exceeded", Do: "alert", Subject: budgeted},
			config.AnzenSpec{Name: "halt-on-budget", Enabled: true, Mode: "enforce",
				Watches: "budget_exceeded", Do: "disable_reflex", Subject: budgeted})
	}})
	if r.localOnly(t, "the reflex engine is this instance's; no governed verb publishes onto its bus (D246)") {
		return
	}
	r.narrate(t, "a budget trip halts the reflex and the alert reaches an anzen rule")
	ctx := context.Background()
	fired := map[string]*struct {
		result *sekizuiv1.CommandResult
		err    error
	}{}
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("p5-5-%d", i)
		e := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": 40, "ref": id})
		e.Id, e.Source = id, "fs:fixture"
		for _, o := range r.engine.Dispatch(ctx, e) {
			if o.Rule == budgeted {
				fired[id] = &struct {
					result *sekizuiv1.CommandResult
					err    error
				}{o.Result, o.Err}
			}
		}
	}

	// 5a — INSIDE THE BUDGET, THEN THE TRIP.
	for _, id := range []string{"p5-5-1", "p5-5-2"} {
		if f := fired[id]; f == nil || f.result.GetStatus() != sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED {
			t.Fatalf("step 5a: %s, inside the budget, did not fire in shadow: %+v", id, f)
		}
	}
	if f := fired["p5-5-3"]; f == nil || f.err == nil || !strings.Contains(f.err.Error(), "budget_exceeded") {
		t.Fatalf("step 5a: the third firing did not trip the budget of 2: %+v", f)
	}

	// 5b — THE RESPONSE: both rules fired through the enforcement path, each
	// recorded as its own principal, the alert changing nothing.
	var alerted, halted *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		switch d.GetIdentity().GetSubject().GetPrincipal() {
		case "anzen:alert-on-budget":
			alerted = d
		case "anzen:halt-on-budget":
			halted = d
		}
	}
	if alerted == nil || alerted.GetVerdict() != sekizuiv1.Verdict_VERDICT_ALLOW ||
		!strings.Contains(alerted.GetReason(), "anzen alert") || alerted.GetRevocation() != nil {
		t.Errorf("step 5b: the alert rule's record is %v; want ALLOW, an alert reason, and no withdrawal", alerted)
	}
	if halted == nil || !strings.Contains(halted.GetReason(), "disabled reflex "+budgeted) {
		t.Errorf("step 5b: the disable rule's record is %v; want it to say it disabled %s", halted, budgeted)
	}

	// 5c — HALTED: the fourth and fifth events match the rule and it does
	// nothing — no outcome and no record, where P3 step 40 recorded
	// BUDGET_EXCEEDED for each. The switch, not the budget, is answering.
	for _, id := range []string{"p5-5-4", "p5-5-5"} {
		if f := fired[id]; f != nil {
			t.Errorf("step 5c: %s reached the disabled rule: %+v", id, f)
		}
		for _, d := range readLog(t, r.path) {
			if d.GetCausation().GetParentId() == id && d.GetReflexName() == budgeted {
				t.Errorf("step 5c: the disabled rule left a %v record for %s", d.GetVerdict(), id)
			}
		}
	}
	if read, err := r.as(t, "agent:triage").Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"}); err != nil ||
		read.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("step 5c: kata:alpha, the budgeted rule's target, stopped serving (%v %v): the response "+
			"withdrew something, which neither action may", err, read.GetStatus())
	}

	// 5d — AN ACTION STILL UNBUILT IS REFUSED, NEVER CARRIED OUT AS A
	// REVOCATION (D331): stood up past validation, fired as the dispatcher fires.
	unbuilt := config.UnbuiltAnzenActions()[0]
	r2 := newRunWith(t, runOpts{postValidate: func(d *config.Document) {
		d.Anzen = append(d.Anzen, config.AnzenSpec{Name: "unbuilt-on-budget", Enabled: true, Mode: "enforce",
			Watches: "budget_exceeded", Do: unbuilt, Subject: "kata:alpha"})
	}})
	res, err := r2.srv.Enforce(ctx, gateway.AnzenIdentity("unbuilt-on-budget"),
		&sekizuiv1.Command{Action: verb.FireAnzen, TargetRef: "anzen:unbuilt-on-budget"})
	if err != nil || res.GetStatus() != sekizuiv1.Status_STATUS_DENIED {
		t.Errorf("step 5d: firing a rule that does %s came back %v %v; want refused", unbuilt, err, res.GetStatus())
	}
	if read, err := r2.as(t, "agent:triage").Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"}); err != nil ||
		read.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("step 5d: after firing a rule doing %s, kata:alpha no longer serves (%v %v %s) — carried out "+
			"as a withdrawal (CONTRACTS 157)", unbuilt, err, read.GetStatus(), read.GetReason())
	}
	r.detail(t, "budget 2: two shadow firings, the third tripped it; budget_exceeded reached the dispatcher: "+
		"alert-on-budget recorded an alert and changed nothing, halt-on-budget disabled %s, and events 4-5 "+
		"left no record; %s, still unbuilt, refused and kata:alpha kept serving", budgeted, unbuilt)
}
