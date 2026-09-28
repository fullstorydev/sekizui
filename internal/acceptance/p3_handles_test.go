package acceptance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step43 — a stateful handle is closed when it goes idle and when the
// process drains, as its opener; break-glass closes nothing (D291).
//
// Fullstory's session_open allocates a slot in the org's concurrent-session
// budget and returns `client_id`; its skill pairs every open with a close as
// the AGENT's discipline. Sekizui makes it a guarantee: the vetted spec
// declares the pairing, the gateway records each handle, and a handle nobody
// closed is closed for them — through the enforcement path, credited to the
// opener, marked system-initiated. On an injected clock, so idleness is exact.
func p3Step43(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "a stateful handle is closed when it goes idle and when the process drains, as its "+
		"opener; break-glass closes nothing")
	spec := loadReviewSpec(t)

	// 43a (load) — A PRINCIPAL THAT MAY OPEN AND NOT CLOSE IS REFUSED: every
	// automatic close would otherwise be a refusal.
	onlyOpen := &config.Document{
		Targets: []config.TargetSpec{{Ref: "fullstory-mcp", Kind: mcp.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://api.fullstory.com/mcp/fullstory", CredentialRef: "env://FS_MCP_TOK",
			Settings: map[string]string{"org_id": "EXAMPLE"}}},
		MCPSpecs: map[string]config.MCPSpec{"fullstory-mcp": spec},
		Grants: []config.GrantSpec{{Principal: "agent:reviewer", Allow: []config.CapabilitySpec{
			{Action: "mcp.fullstory.session_open", TargetRef: "fullstory-mcp"}}}},
	}
	if err := onlyOpen.Validate(); err == nil || !strings.Contains(err.Error(), "must cover both") {
		t.Errorf("step 43a: a principal granted session_open and not session_close loaded: %v", err)
	}

	clock := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	stack := newMCPStack(context.Background(), t, func(d *config.Document) {
		fixture := spec
		fixture.Host = "127.0.0.1"
		d.MCPSpecs = map[string]config.MCPSpec{"fixture-mcp": fixture}
		d.Targets[0].Settings = map[string]string{"org_id": "EXAMPLE"}
		var allow []config.CapabilitySpec
		for _, tool := range spec.Tools {
			allow = append(allow, config.CapabilitySpec{Action: "mcp.fullstory." + tool.Name, TargetRef: "fixture-mcp"})
		}
		d.Grants = append(d.Grants, config.GrantSpec{Principal: "agent:dev", Allow: allow})
	}, func(tn *mcpTuning) {
		tn.gw.HandleIdle = 10 * time.Minute
		tn.gw.Now = func() time.Time { return clock }
	})
	var live []mcp.LiveTool
	for _, tool := range spec.Tools {
		live = append(live, mcp.LiveTool{Name: tool.Name, InputSchema: tool.InputSchema})
	}
	stack.up.offer(live...)
	stack.up.answer("session_close", textResult(`{"success":true}`))
	stack.up.answer("session_get_a11y_tree", textResult(reviewTreeText))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	open := func(handle string) string {
		t.Helper()
		stack.up.answer("session_open", textResult(`{"client_id":"`+handle+`","events":[]}`))
		res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
			Action: "mcp.fullstory.session_open", TargetRef: "fixture-mcp",
			Args: mustArgs(t, map[string]any{"session_id": "1:2"})})
		if err != nil || res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("step 43: opening %s: %v %s", handle, err, res.GetReason())
		}
		return res.GetDecisionId()
	}
	closedHandles := func() []string {
		var out []string
		for _, a := range stack.up.argsFor("session_close") {
			out = append(out, a["client_id"].(string))
		}
		return out
	}

	// 43b — IDLE PAST ITS LIMIT: CLOSED, AS THE OPENER, MARKED SYSTEM-INITIATED.
	openDecision := open("HANDLE-IDLE")
	clock = clock.Add(11 * time.Minute)
	stack.gw.SweepHandles(ctx)
	if got := closedHandles(); len(got) != 1 || got[0] != "HANDLE-IDLE" {
		t.Fatalf("step 43b: the vendor saw closes %v; an idle handle must be closed", got)
	}
	if a := stack.up.argsFor("session_close")[0]; a["org_id"] != "EXAMPLE" {
		t.Errorf("step 43b: the automatic close carried org %v; it goes through the same pin as any call", a["org_id"])
	}
	var closeRec *sekizuiv1.Decision
	for _, d := range readLog(t, stack.logPath) {
		if d.GetAction() == "mcp.fullstory.session_close" && d.GetPhase() == sekizuiv1.Phase_PHASE_INTENT {
			closeRec = d
		}
	}
	switch {
	case closeRec == nil:
		t.Fatal("step 43b: the automatic close left no record — a close Sekizui makes is a governed command")
	case closeRec.GetIdentity().GetSubject().GetPrincipal() != "agent:dev":
		t.Errorf("step 43b: the close is credited to %q; it is made AS the opener",
			closeRec.GetIdentity().GetSubject().GetPrincipal())
	case closeRec.GetIdentity().GetCaller().GetMethod() != sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL ||
		closeRec.GetIdentity().GetCaller().GetCredentialId() != "sekizui:handle-expiry":
		t.Errorf("step 43b: the close claims caller %v; it must say it was system-initiated, never "+
			"that the opener's own credential made it", closeRec.GetIdentity().GetCaller())
	case closeRec.GetCausation().GetParentId() != openDecision:
		t.Errorf("step 43b: the close's causation parent is %q; it must join to the open's decision %q",
			closeRec.GetCausation().GetParentId(), openDecision)
	}
	r.detail(t, "an idle handle was closed as agent:dev, internally, its causation joined to the open")

	// 43c — A HANDLE IN USE IS NOT IDLE; ONE THE CALLER CLOSED IS FORGOTTEN.
	open("HANDLE-BUSY")
	open("HANDLE-DONE")
	clock = clock.Add(9 * time.Minute)
	if _, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "mcp.fullstory.session_get_a11y_tree", TargetRef: "fixture-mcp",
		Args: mustArgs(t, map[string]any{"client_id": "HANDLE-BUSY", "page_id": "p", "timestamp": 1})}); err != nil {
		t.Fatal(err)
	}
	if _, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "mcp.fullstory.session_close", TargetRef: "fixture-mcp",
		Args: mustArgs(t, map[string]any{"client_id": "HANDLE-DONE"})}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Minute) // BUSY last used 2m ago; DONE closed by its caller
	stack.gw.SweepHandles(ctx)
	if got := closedHandles(); len(got) != 2 || got[1] != "HANDLE-DONE" {
		t.Fatalf("step 43c: closes %v; a handle used 2 minutes ago is not idle, and one its caller "+
			"closed must not be closed again", got)
	}

	// 43d — THE DRAIN CLOSES WHAT IS LEFT.
	if n := stack.gw.CloseAllHandles(ctx); n != 1 {
		t.Errorf("step 43d: the drain closed %d handle(s); one was still open", n)
	}
	if got := closedHandles(); len(got) != 3 || got[2] != "HANDLE-BUSY" {
		t.Fatalf("step 43d: closes %v; the drain must close the handle still open", got)
	}
	r.detail(t, "a handle in use was left open, a closed one forgotten, and the drain closed the rest")

	// 43e — BREAK-GLASS CLOSES NOTHING: closing would use the revoked credential.
	// NOT ATTEMPTED, NOT MERELY REFUSED — and only the log tells them apart: an
	// attempt would be stopped by the withdrawal check before the vendor saw it,
	// so "the vendor saw no close" holds either way. The first draft of this arm
	// asserted only that, and passed for both.
	closeRecords := func() int {
		n := 0
		for _, d := range readLog(t, stack.logPath) {
			if d.GetAction() == "mcp.fullstory.session_close" {
				n++
			}
		}
		return n
	}
	open("HANDLE-REVOKED")
	if _, err := stack.pool.Revoke(ctx, "fixture-mcp", "step 43e"); err != nil {
		t.Fatal(err)
	}
	before := closeRecords()
	stack.gw.CloseAllHandles(ctx)
	switch {
	case len(closedHandles()) != 3:
		t.Errorf("step 43e: closes %v; a handle on a revoked target must not be closed through the "+
			"credential break-glass withdrew", closedHandles())
	case closeRecords() != before:
		t.Errorf("step 43e: the drain ATTEMPTED a close on the revoked target (%d new record(s)); "+
			"break-glass closes nothing, so nothing is attempted", closeRecords()-before)
	}
	r.detail(t, "after revoke_credential, the open handle was left to the vendor's own expiry")
}
