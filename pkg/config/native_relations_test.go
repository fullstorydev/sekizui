package config

import (
	"strings"
	"testing"
)

// TestNativeRelations — each refusal D323 names, one arm each, from the
// contract fixture, whose MCP target shares kata:alpha's budget.
func TestNativeRelations(t *testing.T) {
	// THE FIXTURE SETS EVERY FIELD RATHER THAN VALIDATING (other rules refuse
	// it), so each arm is judged on D323's own messages alone.
	d323 := func(d *Document) string {
		err := d.Validate()
		if err == nil {
			return ""
		}
		var out []string
		for _, line := range strings.Split(err.Error(), "\n") {
			if strings.Contains(line, "(D323") || strings.Contains(line, "(D324)") || strings.Contains(line, "listed twice") {
				out = append(out, line)
			}
		}
		return strings.Join(out, "\n")
	}
	if got := d323(documentFixture()); got != "" {
		t.Fatalf("the fixture's own relations are refused: %s", got)
	}
	target := func(d *Document, ref string) *TargetSpec {
		for i := range d.Targets {
			if d.Targets[i].Ref == ref {
				return &d.Targets[i]
			}
		}
		t.Fatalf("no target %s", ref)
		return nil
	}
	tools := func(d *Document) []MCPToolSpec { return d.MCPSpecs["fixture-mcp"].Tools }
	for _, c := range []struct {
		arm  string
		edit func(*Document)
		want string
	}{
		{"a linked tool with no relation", func(d *Document) { tools(d)[1].Native = nil }, "states its native"},
		{"an MCP server named after a native kind, unlinked and silent — the forgotten link", func(d *Document) {
			target(d, "fixture-mcp").Limits = nil
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Server = "kata"
			d.MCPSpecs["fixture-mcp"] = spec
			for i := range tools(d) {
				tools(d)[i].Native = nil
			}
		}, "touches a different surface"},
		{"none beside an action", func(d *Document) { tools(d)[1].Native = []string{NativeNone, "kata.comment"} }, "stands alone"},
		{"opaque beside an action", func(d *Document) { tools(d)[1].Native = []string{NativeOpaque, "kata.comment"} }, "stands alone"},
		{"an action of a kind nothing links, on a linked target", func(d *Document) { tools(d)[0].Native = []string{"fullstory.session_events"} }, "shares a budget with no fullstory target"},
		{"named after a native kind, unlinked, declaring an overlap — the forgotten link", func(d *Document) {
			target(d, "fixture-mcp").Limits = nil
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Server = "kata"
			d.MCPSpecs["fixture-mcp"] = spec
			tools(d)[0].Native = []string{NativeOpaque}
			tools(d)[1].Native = []string{NativeNone}
		}, "touches a different surface"},
		{"an MCP action", func(d *Document) { tools(d)[0].Native = []string{"mcp.fixture.search"} }, "is an MCP action"},
		{"an action listed twice", func(d *Document) { tools(d)[0].Native = []string{"kata.comment", "kata.comment"} }, "listed twice"},
		{"linked doors in two classes", func(d *Document) { target(d, "fixture-mcp").Residency = "us" }, "cannot sit in two classes"},
	} {
		d := documentFixture()
		c.edit(d)
		if got := d323(d); !strings.Contains(got, c.want) {
			t.Errorf("%s: want a refusal containing %q, got %q", c.arm, c.want, got)
		}
	}

	// THE PASSING DIRECTIONS: opaque alone, a composite, an MCP-only target
	// declaring nothing, and a hybrid left unlinked on purpose.
	for _, c := range []struct {
		arm  string
		edit func(*Document)
	}{
		{"opaque alone", func(d *Document) { tools(d)[1].Native = []string{NativeOpaque} }},
		{"a composite", func(d *Document) { tools(d)[0].Native = []string{"kata.create_issue", "kata.comment"} }},
		{"unlinked, relations shipped by a hybrid connector — inert where no native target runs", func(d *Document) {
			target(d, "fixture-mcp").Limits = nil
			tools(d)[0].Native = []string{NativeOpaque}
		}},
		{"unlinked and blank — the MCP-only connector writes nothing", func(d *Document) {
			target(d, "fixture-mcp").Limits = nil
			for i := range tools(d) {
				tools(d)[i].Native = nil
			}
		}},
		{"named after a native kind, unlinked ON PURPOSE — every tool [none], a different surface", func(d *Document) {
			target(d, "fixture-mcp").Limits = nil
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Server = "kata"
			d.MCPSpecs["fixture-mcp"] = spec
			for i := range tools(d) {
				tools(d)[i].Native = []string{NativeNone}
			}
		}},
	} {
		d := documentFixture()
		c.edit(d)
		if got := d323(d); got != "" {
			t.Errorf("%s: refused: %s", c.arm, got)
		}
	}
}
