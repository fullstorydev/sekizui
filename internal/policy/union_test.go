package policy

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// unionDoc is one upstream behind two doors, linked by a shared budget
// (D323), plus a second org's native target that is NOT linked — so a grant
// on the wrong org cannot satisfy the union.
const unionDoc = `
targets:
  - {ref: fs:eu1, kind: fullstory, tenant: eu1, residency: eu, base_url: https://api.eu1.fullstory.com, limits: {rate_per_hr: 60, budget: fs-eu1}}
  - {ref: fs:na1, kind: fullstory, tenant: na1, residency: eu, base_url: https://api.fullstory.com, limits: {rate_per_hr: 60, budget: fs-na1}}
  - {ref: fs-mcp, kind: mcp, tenant: eu1, residency: eu, base_url: https://mcp.invalid, limits: {budget: fs-eu1}}
mcp_specs:
  fs-mcp:
    server: fullstory
    host: mcp.invalid
    tools:
      - {name: get_session_events, native: [fullstory.session_events]}
      - {name: summarise, native: [fullstory.session_events, fullstory.session_summary]}
      - {name: ask_about_data, native: [opaque]}
      - {name: list_ai_notes, native: [none]}
grants:
  - principal: agent:mcp-only
    allow:
      - {action: "mcp.fullstory.*", target: fs-mcp}
  - principal: agent:wrong-org
    allow:
      - {action: "mcp.fullstory.*", target: fs-mcp}
      - {action: fullstory.session_events, target: fs:na1}
  - principal: agent:reader
    allow:
      - {action: "mcp.fullstory.*", target: fs-mcp}
      - {action: fullstory.session_events, target: fs:eu1}
  - principal: agent:constrained
    allow:
      - {action: "mcp.fullstory.*", target: fs-mcp}
      - {action: fullstory.session_events, target: fs:eu1, where: {session_id: ["s1"]}}
  - principal: agent:everything
    allow:
      - {action: "mcp.fullstory.*", target: fs-mcp}
      - {action: "fullstory.*", target: fs:eu1}
  - principal: agent:approval
    allow:
      - {action: "mcp.fullstory.*", target: fs-mcp}
    escalate:
      - {action: fullstory.session_events, target: fs:eu1}
`

func unionEngine(t *testing.T, opts ...Option) *GrantEngine {
	t.Helper()
	var doc config.Document
	if err := yaml.Unmarshal([]byte(unionDoc), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return NewGrantEngine(&doc, []string{"eu"}, opts...)
}

var fullstorySurface = WithSurfaces(func(kind string) []string { //nolint:gochecknoglobals // test fixture
	if kind == "fullstory" {
		return []string{"fullstory.session_events", "fullstory.session_summary", "fullstory.create_event"}
	}
	return nil
})

func TestTheDeclaredUnionIsEnforced(t *testing.T) {
	e := unionEngine(t, fullstorySurface)
	for _, c := range []struct {
		who, tool string
		want      sekizuiv1.Verdict
		rule      string
	}{
		// DENIED NATIVELY, SO DENIED THROUGH THE MIRROR — the D52 property.
		{"agent:mcp-only", "get_session_events", sekizuiv1.Verdict_VERDICT_DENY, "union:fullstory.session_events@fs:eu1"},
		// A GRANT ON ANOTHER ORG DOES NOT SATISFY IT: only linked targets count.
		{"agent:wrong-org", "get_session_events", sekizuiv1.Verdict_VERDICT_DENY, "union:fullstory.session_events@fs:eu1"},
		{"agent:reader", "get_session_events", sekizuiv1.Verdict_VERDICT_ALLOW, ""},
		// A COMPOSITE NEEDS EVERY ACTION IT MIRRORS.
		{"agent:reader", "summarise", sekizuiv1.Verdict_VERDICT_DENY, "union:fullstory.session_summary@fs:eu1"},
		// ARGUMENTS ARE NOT CARRIED ACROSS: a constrained native grant does not hold.
		{"agent:constrained", "get_session_events", sekizuiv1.Verdict_VERDICT_DENY, "union:fullstory.session_events@fs:eu1"},
		// OPAQUE IS THE WHOLE SURFACE.
		{"agent:reader", "ask_about_data", sekizuiv1.Verdict_VERDICT_DENY, "union:fullstory.session_summary@fs:eu1"},
		{"agent:everything", "ask_about_data", sekizuiv1.Verdict_VERDICT_ALLOW, ""},
		// NONE: its own grant alone.
		{"agent:mcp-only", "list_ai_notes", sekizuiv1.Verdict_VERDICT_ALLOW, ""},
		// ESCALATE NATIVELY, ESCALATE THROUGH THE MIRROR.
		{"agent:approval", "get_session_events", sekizuiv1.Verdict_VERDICT_ESCALATE, "union:fullstory.session_events@fs:eu1"},
	} {
		got := ask(t, e, c.who, c.who, "mcp.fullstory."+c.tool, "fs-mcp", nil)
		if got.Verdict != c.want || (c.rule != "" && got.Rule != c.rule) {
			t.Errorf("%s calling %s: %v %q (%s); want %v %q", c.who, c.tool, got.Verdict, got.Rule, got.Reason, c.want, c.rule)
		}
	}

	// IT ONLY NARROWS: an ungranted mirror is refused by the grant, not rescued.
	if got := ask(t, e, "agent:reader", "agent:reader", "mcp.fullstory.get_session_events", "fs:eu1", nil); got.Verdict != sekizuiv1.Verdict_VERDICT_DENY {
		t.Errorf("an MCP action on the native target was allowed: %+v", got)
	}
}

// TestAnOpaqueToolIsDeniedWhenTheSurfaceIsUnknown — the engine cannot show all
// of a surface it cannot enumerate, so it refuses rather than guessing.
func TestAnOpaqueToolIsDeniedWhenTheSurfaceIsUnknown(t *testing.T) {
	got := ask(t, unionEngine(t), "agent:everything", "agent:everything", "mcp.fullstory.ask_about_data", "fs-mcp", nil)
	if got.Verdict != sekizuiv1.Verdict_VERDICT_DENY || !strings.Contains(got.Reason, "cannot enumerate") {
		t.Errorf("an opaque tool with no known surface: %+v; want DENY naming why", got)
	}
}
