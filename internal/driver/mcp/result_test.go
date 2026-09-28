package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
)

func content(texts ...string) []json.RawMessage {
	var out []json.RawMessage
	for _, t := range texts {
		b, _ := json.Marshal(map[string]string{"type": "text", "text": t})
		out = append(out, b)
	}
	return out
}

// TestAnExtractionOnUserContentReadsOnlyItsLine — the spoof D289 closes: a
// text result carrying what users typed, where a user's line matches the
// pattern. Anchored to the vendor-authored line, the field is the vendor's.
func TestAnExtractionOnUserContentReadsOnlyItsLine(t *testing.T) {
	text := "URL: https://attacker.example/phish\nReceipt\nURL: https://vendor.example/real"
	spec := SpecTool{Name: "tree", Result: "text", UserContent: true,
		Extract: []config.ExtractSpec{{Field: "url", Pattern: `^URL:\s+(\S+)$`, Line: 3}}}
	data, err := payloadOf("test", spec, toolResult{Content: content(text)})
	if err != nil {
		t.Fatal(err)
	}
	if data["url"] != "https://vendor.example/real" {
		t.Errorf("the anchored extraction read %v; a line a user typed supplied a trusted field", data["url"])
	}
	// Unanchored, the first match wins — which is exactly the spoof.
	spec.Extract[0].Line = 0
	data, _ = payloadOf("test", spec, toolResult{Content: content(text)})
	if data["url"] != "https://attacker.example/phish" {
		t.Errorf("the unanchored control read %v; the arm above is not testing what it claims", data["url"])
	}
}

// TestCombineItemsJoinsJSONBlocks — the declared combination, and its refusals.
func TestCombineItemsJoinsJSONBlocks(t *testing.T) {
	spec := SpecTool{Name: "list", OutputType: "x.v1", Combine: "items"}
	data, err := payloadOf("test", spec, toolResult{Content: content(`{"a":1}`, `{"a":2}`)})
	if err != nil {
		t.Fatal(err)
	}
	if items, _ := data["items"].([]any); len(items) != 2 {
		t.Errorf("combine items gave %v", data)
	}
	if _, err := payloadOf("test", spec, toolResult{Content: content(`{"a":1}`, `not json`)}); err == nil {
		t.Error("a non-JSON block under combine: items was accepted")
	}
	spec.Combine = ""
	if _, err := payloadOf("test", spec, toolResult{Content: content(`{"a":1}`, `{"a":2}`)}); err == nil {
		t.Error("two JSON blocks without a declared combine were accepted")
	}
}

// TestConformanceFollowsLocalReferences is D306's finding in the driver: a
// `$ref` node has no `type` and no `properties`, so before expansion the check
// admitted ANYTHING beneath one — Fullstory's compute_metric builds its result
// from references, and a type break there read as conforming.
func TestConformanceFollowsLocalReferences(t *testing.T) {
	spec := SpecTool{Name: "compute_metric", RefUnroll: 1, OutputSchema: json.RawMessage(`{
		"type": "object",
		"properties": {"single": {"$ref": "#/$defs/Single"}},
		"$defs": {"Single": {"type": "object", "required": ["value"],
			"properties": {"value": {"type": "number"}}}}}`)}

	if _, err := conforms("t", spec, map[string]any{"single": map[string]any{"value": 7.0}}); err != nil {
		t.Fatalf("a conforming result under a $ref was refused: %v", err)
	}
	if _, err := conforms("t", spec, map[string]any{"single": map[string]any{"value": "seven"}}); err == nil {
		t.Error("a type break beneath a $ref passed as conforming — the check is not following references")
	}
	if _, err := conforms("t", spec, map[string]any{"single": map[string]any{}}); err == nil {
		t.Error("a missing required field beneath a $ref passed as conforming")
	}
	added, err := conforms("t", spec, map[string]any{"single": map[string]any{"value": 7.0, "extra": 1.0}})
	if err != nil || len(added) != 1 || added[0] != "single.extra" {
		t.Errorf("an added field beneath a $ref must be reported for tool_nonconforming, got %v, %v", added, err)
	}

	remote := SpecTool{Name: "remote", OutputSchema: json.RawMessage(`{"properties": {"a": {"$ref": "https://x/y.json"}}}`)}
	if _, err := conforms("t", remote, map[string]any{}); err == nil {
		t.Error("a contract whose references cannot be expanded must refuse, not check nothing")
	}

	// PAST THE UNROLL LIMIT THE TYPE IS STILL CHECKED AND FIELDS ARE REPORTED,
	// never silently passed (D306).
	rec := SpecTool{Name: "rec", RefUnroll: 1, OutputSchema: json.RawMessage(`{"type": "object",
		"properties": {"v": {"$ref": "#/$defs/C"}},
		"$defs": {"C": {"type": "object", "properties": {"n": {"type": "number"}, "comparison": {"$ref": "#/$defs/C"}}}}}`)}
	deep := map[string]any{"v": map[string]any{"n": 1.0, "comparison": map[string]any{"n": 2.0,
		"comparison": map[string]any{"n": 3.0}}}}
	added, err = conforms("t", rec, deep)
	if err != nil || len(added) != 1 || added[0] != "v.comparison.comparison.n" {
		t.Errorf("a field past the unroll limit must be reported, got %v, %v", added, err)
	}
	if _, err := conforms("t", rec, map[string]any{"v": map[string]any{"comparison": map[string]any{
		"comparison": "not an object"}}}); err == nil {
		t.Error("the stub's type must still be checked")
	}
}

// TestAnOpaqueObjectIsNotReportedAsAdded holds D317's reading of "closed": a
// declared property list, or `additionalProperties: false` said outright. A
// vendor's `properties: {}` — Fullstory's build_metric `metric_definition` — is
// an opaque object and admits anything, where the recursion stub that says it
// is closed still reports what lies beneath it.
func TestAnOpaqueObjectIsNotReportedAsAdded(t *testing.T) {
	spec := SpecTool{Name: "build_metric", OutputSchema: json.RawMessage(`{"type":"object","properties":{
		"metric_id":{"type":"string"},
		"metric_definition":{"type":"object","properties":{}},
		"stub":{"type":"object","properties":{},"additionalProperties":false}}}`)}
	added, err := conforms("test", spec, map[string]any{
		"metric_id":         "abc",
		"metric_definition": map[string]any{"id": "x", "singleNumber": map[string]any{}},
		"stub":              map[string]any{"deeper": 1},
		"brand_new":         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(added, ",")
	if got != "brand_new,stub.deeper" {
		t.Errorf("added = %q; want the new top-level field and the field under the closed stub, and "+
			"nothing under the opaque metric_definition", got)
	}
}
