package jsonref

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func mustMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The shape Fullstory's compute_metric publishes: result fields that are
// references into $defs. Before D306 every one of them became an empty object.
func TestExpandInlinesLocalDefinitions(t *testing.T) {
	in := mustMap(t, `{
		"type": "object",
		"properties": {
			"trend": {"$ref": "#/$defs/Series", "description": "over time"},
			"old":   {"$ref": "#/definitions/Point"}
		},
		"$defs": {
			"Series": {"type": "array", "items": {"$ref": "#/definitions/Point"}}
		},
		"definitions": {
			"Point": {"type": "object", "properties": {"t": {"type": "string"}, "v": {"type": "number"}}}
		}
	}`)
	got, err := Expand(in)
	if err != nil {
		t.Fatal(err)
	}
	want := mustMap(t, `{
		"type": "object",
		"properties": {
			"trend": {"type": "array", "description": "over time",
				"items": {"type": "object", "properties": {"t": {"type": "string"}, "v": {"type": "number"}}}},
			"old": {"type": "object", "properties": {"t": {"type": "string"}, "v": {"type": "number"}}}
		}
	}`)
	if !reflect.DeepEqual(got, want) {
		g, _ := json.Marshal(got)
		t.Fatalf("expansion differs:\n got %s", g)
	}
	if _, still := in["$defs"]; !still {
		t.Error("Expand modified its input")
	}
}

func TestExpandRefuses(t *testing.T) {
	for name, c := range map[string]struct{ schema, want string }{
		"a remote reference": {`{"properties": {"a": {"$ref": "https://example.com/s.json#/x"}}}`, "not local"},
		"the root itself":    {`{"properties": {"a": {"$ref": "#"}}}`, "not local"},
		"a pointer inside a definition": {`{"properties": {"a": {"$ref": "#/$defs/A/properties/x"}},
			"$defs": {"A": {"type": "object"}}}`, "inside a definition"},
		"a missing definition": {`{"properties": {"a": {"$ref": "#/$defs/Nope"}}}`, "names no definition"},
		"a sibling constraint": {`{"properties": {"a": {"$ref": "#/$defs/A", "type": "string"}},
			"$defs": {"A": {"type": "object"}}}`, "sibling"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Expand(mustMap(t, c.schema))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, err)
			}
		})
	}
}

// THE BILLION-LAUGHS SHAPE: no cycle, and each definition references the next
// twice, so 2^n copies of the last. Must refuse, not exhaust memory.
func TestExpandBoundsExponentialGrowth(t *testing.T) {
	defs := map[string]any{"D0": map[string]any{"type": "string"}}
	for i := 1; i <= 16; i++ {
		prev := fmt.Sprintf("#/$defs/D%d", i-1)
		defs[fmt.Sprintf("D%d", i)] = map[string]any{"type": "object", "properties": map[string]any{
			"l": map[string]any{"$ref": prev}, "r": map[string]any{"$ref": prev}}}
	}
	schema := map[string]any{"properties": map[string]any{"x": map[string]any{"$ref": "#/$defs/D16"}}, "$defs": defs}
	_, err := Expand(schema)
	if err == nil || !strings.Contains(err.Error(), "nodes") {
		t.Fatalf("want the node bound to refuse, got %v", err)
	}
}

func TestExpandLeavesDataAlone(t *testing.T) {
	in := mustMap(t, `{"type": "object", "examples": [{"$ref": "not a reference"}]}`)
	got, err := Expand(in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("an example's $ref key was treated as a reference: %v", got)
	}
}

func TestExpandJSONIsIdentityWithoutReferences(t *testing.T) {
	body := []byte(`{"type":"object",  "properties":{"a":{"type":"string"}}}`)
	got, err := ExpandJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("a schema with no $ref must load byte for byte as before, got %s", got)
	}
}

// Fullstory's compute_metric, reduced: a result carries a comparison of its own
// type. Unrolled once, then a closed stub — the comparison's comparison is not
// admitted, and says why.
func TestExpandUnrollsRecursionOnce(t *testing.T) {
	in := mustMap(t, `{"type": "object", "properties": {"value": {"$ref": "#/$defs/Count"}},
		"$defs": {"Count": {"type": "object", "properties": {
			"n": {"type": "number"}, "comparison": {"$ref": "#/$defs/Count"}}}}}`)
	got, err := Expand(in)
	if err != nil {
		t.Fatal(err)
	}
	value := got["properties"].(map[string]any)["value"].(map[string]any)
	cmp := value["properties"].(map[string]any)["comparison"].(map[string]any)
	if _, ok := cmp["properties"].(map[string]any)["n"]; !ok {
		t.Fatalf("the first recursion must be expanded in full: %v", cmp)
	}
	stub := cmp["properties"].(map[string]any)["comparison"].(map[string]any)
	if props, _ := stub["properties"].(map[string]any); stub["type"] != "object" || props == nil ||
		len(props) != 0 || stub["$comment"] == nil {
		t.Fatalf("the second recursion must be a CLOSED STUB of the same type, marked: %v", stub)
	}

	// A mutual cycle unrolls the same way — each definition at most twice per path.
	mutual := mustMap(t, `{"properties": {"a": {"$ref": "#/$defs/A"}},
		"$defs": {"A": {"type": "object", "properties": {"b": {"$ref": "#/$defs/B"}}},
		          "B": {"type": "object", "properties": {"a": {"$ref": "#/$defs/A"}}}}}`)
	if _, err := Expand(mutual); err != nil {
		t.Fatalf("a mutual recursion must unroll, not refuse: %v", err)
	}
}

// D309: the depth is configurable — 0 stubs the first recursion, 2 expands two.
func TestUnrollIsConfigurable(t *testing.T) {
	schema := `{"type": "object", "properties": {"v": {"$ref": "#/$defs/C"}},
		"$defs": {"C": {"type": "object", "properties": {"n": {"type": "number"}, "c": {"$ref": "#/$defs/C"}}}}}`
	depth := func(n int) int {
		got, err := Expand(mustMap(t, schema), WithUnroll(n))
		if err != nil {
			t.Fatal(err)
		}
		d, node := 0, got["properties"].(map[string]any)["v"].(map[string]any)
		for {
			props := node["properties"].(map[string]any)
			next, ok := props["c"].(map[string]any)
			if !ok || len(next["properties"].(map[string]any)) == 0 {
				return d
			}
			d++
			node = next
		}
	}
	for n := 0; n <= 3; n++ {
		if got := depth(n); got != n {
			t.Errorf("WithUnroll(%d) expanded %d recursion(s)", n, got)
		}
	}
	if _, err := Expand(mustMap(t, schema), WithUnroll(MaxUnroll+1)); err == nil {
		t.Error("an unroll above MaxUnroll must refuse")
	}
}
