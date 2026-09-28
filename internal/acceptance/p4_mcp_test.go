package acceptance

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// fullstoryMCPVettedAgainst is the tools/list the shipped fragment was vetted
// against (2026-09-26, the maintainers' test org), minus `session_view` — a deprecated stub.
// A tool dropped from the fragment, or one added without vetting, fails 31a;
// whether the LIVE server still serves exactly this is the drift check's
// question (§4.9a.7), not this step's.
//
//nolint:gochecknoglobals // immutable
var fullstoryMCPVettedAgainst = []string{
	"build_funnel", "build_journey", "build_metric", "build_segment",
	"compute_funnel", "compute_journey", "compute_metric",
	"discover_groups", "discover_org_context",
	"get_funnel", "get_funnel_sessions", "get_journey", "get_managed_funnels", "get_metric",
	"get_opportunities", "get_opportunity", "get_opportunity_stats", "get_pages", "get_segment",
	"get_session_events", "get_sessions", "get_sessions_for_journey", "get_sessions_for_opportunity",
	"get_view_counts",
	"session_close", "session_diff", "session_get_a11y_tree", "session_open", "session_screenshot",
	"update_funnel", "update_journey", "update_metric", "update_segment",
}

// p4Step31 — the connector ships every tool; the deployment decides exposure
// (D307, D308).
func p4Step31(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the Fullstory MCP ships every tool it serves, vetted, and grants decide exposure")
	spec := loadReviewSpec(t)

	// 31a — EVERY TOOL, AND ONLY THOSE.
	var got []string
	byName := map[string]config.MCPToolSpec{}
	for _, tool := range spec.Tools {
		got = append(got, tool.Name)
		byName[tool.Name] = tool
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(fullstoryMCPVettedAgainst, ",") {
		t.Fatalf("step 31a: the shipped fragment's tools differ from the tools/list it was vetted against:\n got  %v\n want %v",
			got, fullstoryMCPVettedAgainst)
	}

	// 31b — VENDOR PROVENANCE WHEREVER THE VENDOR ADVERTISES A SCHEMA.
	for _, tool := range spec.Tools {
		if tool.Result == "text" {
			continue
		}
		if tool.OutputSchemaOrigin != "vendor" {
			t.Errorf("step 31b: %s's output schema is %q; Fullstory advertises one, so it is copied, origin vendor",
				tool.Name, tool.OutputSchemaOrigin)
		}
	}

	// 31c — THE WRITES ARE WRITES (D307), SO A GRANT CAN WITHHOLD THEM.
	writes := map[string]string{"session_open": "none", "session_close": "natural",
		"build_funnel": "none", "build_journey": "none", "build_metric": "none", "build_segment": "none",
		"update_funnel": "none", "update_journey": "none", "update_metric": "none", "update_segment": "none"}
	for _, tool := range spec.Tools {
		want, isWrite := writes[tool.Name]
		switch {
		case tool.Mutating != isWrite:
			t.Errorf("step 31c: %s is mutating=%v; ruled %v", tool.Name, tool.Mutating, isWrite)
		case isWrite && tool.Idempotency != want:
			t.Errorf("step 31c: %s has idempotency %q; ruled %q", tool.Name, tool.Idempotency, want)
		}
	}

	// 31d — IT VALIDATES BESIDE A REAL TARGET, and every action is advertised.
	doc := &config.Document{
		Targets: []config.TargetSpec{{Ref: "fullstory-mcp", Kind: mcp.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://api.fullstory.com/mcp/fullstory", CredentialRef: "env://FS_MCP_TOK",
			Settings: map[string]string{"org_id": "EXAMPLE"}}},
		MCPSpecs: map[string]config.MCPSpec{"fullstory-mcp": spec},
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("step 31d: the shipped fragment does not validate beside a real target: %v", err)
	}
	if n := len(mcp.New(doc.MCPSpecs).Actions()); n != len(fullstoryMCPVettedAgainst) {
		t.Errorf("step 31d: the driver advertises %d actions for %d vetted tools", n, len(fullstoryMCPVettedAgainst))
	}

	// 31e — THE NUMBERS SURVIVE THE CLOSED BOUNDARY (D306). compute_metric's
	// result is built from $refs; before D306 its data schema reduced them to
	// empty objects and the metric's value was stripped.
	cm := byName["compute_metric"]
	reg, err := schemareg.New(map[string]json.RawMessage{cm.OutputType: cm.DataSchema})
	if err != nil {
		t.Fatalf("step 31e: compute_metric's data schema does not load: %v", err)
	}
	shaped, _ := reg.Shape(cm.OutputType, map[string]any{"single": map[string]any{"value": 42.0,
		"comparison": map[string]any{"value": 40.0}}})
	single, _ := shaped["single"].(map[string]any)
	if single["value"] != 42.0 {
		t.Errorf("step 31e: compute_metric's single.value was stripped at the closed boundary: %v", shaped)
	}
	if cmp, _ := single["comparison"].(map[string]any); cmp["value"] != 40.0 {
		t.Errorf("step 31e: the comparison period's value was stripped: %v", shaped)
	}
	r.detail(t, "%d tools, the 30 JSON ones vendor-copied, 10 mutating, validated beside a real target; "+
		"compute_metric's value and its comparison survive shaping", len(spec.Tools))

	// 31f — THROUGH THE GOVERNED PATH, THE CONTRACT IS CHECKED BENEATH A $ref
	// (D306). compute_metric's result is references all the way down, and before
	// D306 the conformance walk checked nothing under one: a value that turned
	// into a string passed as conforming. A type break two references deep must
	// be REFUSED as a broken contract, and a conforming result must pass.
	stack := newMCPStack(context.Background(), t, func(d *config.Document) {
		fixture := spec
		fixture.Host = "127.0.0.1" // the fixture stands in for api.fullstory.com
		d.MCPSpecs = map[string]config.MCPSpec{"fixture-mcp": fixture}
		d.Targets[0].Settings = map[string]string{"org_id": "EXAMPLE"}
		d.Grants = append(d.Grants, config.GrantSpec{Principal: "agent:dev", Allow: []config.CapabilitySpec{
			{Action: "mcp.fullstory.compute_metric", TargetRef: "fixture-mcp"}}})
	})
	var live []mcp.LiveTool
	for _, tool := range spec.Tools {
		lt := mcp.LiveTool{Name: tool.Name, InputSchema: tool.InputSchema}
		if tool.OutputSchemaOrigin == "vendor" {
			lt.OutputSchema = tool.OutputSchema
		}
		live = append(live, lt)
	}
	stack.up.offer(live...)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	compute := func() (*sekizuiv1.CommandResult, string) {
		t.Helper()
		res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
			Action: "mcp.fullstory.compute_metric", TargetRef: "fixture-mcp",
			Args: mustArgs(t, map[string]any{"metric_id": "m-1"})})
		said := res.GetReason()
		if err != nil {
			said = err.Error()
		}
		return res, said
	}
	stack.up.answer("compute_metric", textResult(`{"metric_id":"m-1","single":{"value":42,"comparison":{"value":40}}}`))
	if res, said := compute(); res.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 31f: a conforming compute_metric result was not served: %s %s", res.GetStatus(), said)
	} else if single, _ := res.GetResult().AsMap()["single"].(map[string]any); single["value"] != 42.0 {
		t.Errorf("step 31f: compute_metric's value did not reach the caller: %v", res.GetResult().AsMap())
	}
	stack.up.answer("compute_metric", textResult(`{"metric_id":"m-1","single":{"value":42,"comparison":{"value":"forty"}}}`))
	if res, said := compute(); res.GetStatus() == sekizuiv1.Status_STATUS_OK || !strings.Contains(said, "broke its output contract") {
		t.Errorf("step 31f: a type break two $refs deep was not refused as a broken contract: %s %s",
			res.GetStatus(), said)
	}
	r.detail(t, "through the governed path, compute_metric's value is served, and a type break two "+
		"references deep is refused as a broken contract")
}
