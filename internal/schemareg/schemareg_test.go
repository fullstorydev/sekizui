package schemareg

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

func reg(t *testing.T, schemas map[string]string) *Registry {
	t.Helper()
	raw := map[string]json.RawMessage{}
	for k, v := range schemas {
		raw[k] = json.RawMessage(v)
	}
	r, err := New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

const rageClick = `{
  "type": "object",
  "required": ["session_id", "url"],
  "additionalProperties": false,
  "properties": {
    "session_id": {"type": "string"},
    "url":        {"type": "string"},
    "clicks":     {"type": "integer"},
    "user":       {"type": "object", "properties": {"email": {"type": "string"}}}
  }
}`

func TestValidatesPayloads(t *testing.T) {
	r := reg(t, map[string]string{"fullstory.rage_click.v1": rageClick})

	if err := r.Validate("fullstory.rage_click.v1", map[string]any{
		"session_id": "abc", "url": "/checkout", "clicks": float64(7),
	}); err != nil {
		t.Errorf("a valid payload was rejected: %v", err)
	}

	for name, tc := range map[string]struct {
		payload map[string]any
		want    string
	}{
		"missing required field": {
			map[string]any{"url": "/checkout"}, "required field \"session_id\"",
		},
		"wrong type": {
			map[string]any{"session_id": 1, "url": "/x"}, "expected string",
		},
		"non-integer where integer declared": {
			map[string]any{"session_id": "a", "url": "/x", "clicks": 1.5}, "expected integer",
		},
		// CLOSED BY DEFAULT (D279): refused whether or not the schema says
		// additionalProperties: false.
		"undeclared field": {
			map[string]any{"session_id": "a", "url": "/x", "surprise": true}, `field "surprise" is not declared`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := r.Validate("fullstory.rage_click.v1", tc.payload)
			if err == nil {
				t.Fatal("accepted an invalid payload")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestUnregisteredTypeIsRefused. Publishing an event nobody declared is how a
// payload shape enters the system unreviewed — the same hole D46 closes for MCP.
func TestUnregisteredTypeIsRefused(t *testing.T) {
	r := reg(t, map[string]string{"fullstory.rage_click.v1": rageClick})

	err := r.Validate("fullstory.invented.v1", map[string]any{})
	if err == nil {
		t.Fatal("an unregistered type validated successfully")
	}
	if !errors.Is(err, fault.KindInvalidArgument) {
		t.Errorf("kind = %v", fault.KindOf(err))
	}
}

// TestUnsupportedKeywordsAreRefused settles the risk §12.1 flagged as highest:
// D42 "may be infeasible with oneOf / $ref cycles".
//
// `$ref` STAYS IN THE LIST FOR ITS NON-LOCAL FORM: since D306 a local reference
// (`#/$defs/<name>`) is expanded at load — TestLocalReferencesAreExpanded — and
// what still refuses is a reference that is not one, like "whatever" here.
//
// The resolution is to refuse rather than soften. A schema with more than one
// valid shape has no single answer to "does field X exist", and answering from
// whichever branch happens to contain it would let a rule pass boot validation
// and fail at runtime — which is exactly the silence D42 exists to prevent.
func TestUnsupportedKeywordsAreRefused(t *testing.T) {
	for _, keyword := range []string{"$ref", "oneOf", "anyOf", "allOf"} {
		t.Run(keyword, func(t *testing.T) {
			body := `{"type":"object","properties":{"x":{"` + keyword + `":"whatever"}}}`
			_, err := New(map[string]json.RawMessage{"a.b.v1": json.RawMessage(body)})
			if err == nil {
				t.Fatalf("a schema using %q was accepted; D42 cannot traverse it", keyword)
			}
			if !strings.Contains(err.Error(), keyword) {
				t.Errorf("the error does not name the keyword: %v", err)
			}
			// And it must say what to do instead.
			if !strings.Contains(err.Error(), "Flatten") {
				t.Errorf("the error offers no remedy: %v", err)
			}
		})
	}
}

// TestUnversionedTypeIsRefused — D41's dual-publish migration depends on v1 and
// v2 being distinct types.
func TestUnversionedTypeIsRefused(t *testing.T) {
	_, err := New(map[string]json.RawMessage{
		"fullstory.rage_click": json.RawMessage(`{"type":"object"}`),
	})
	if err == nil {
		t.Fatal("an unversioned type was registered")
	}
	if !strings.Contains(err.Error(), "version suffix") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestFieldPathExists is D42's boot-time check.
func TestFieldPathExists(t *testing.T) {
	r := reg(t, map[string]string{"fullstory.rage_click.v1": rageClick})

	for _, path := range []string{"session_id", "url", "clicks", "user", "user.email"} {
		if err := r.FieldPathExists("fullstory.rage_click.v1", path); err != nil {
			t.Errorf("%q should exist: %v", path, err)
		}
	}

	t.Run("missing field is named, with alternatives", func(t *testing.T) {
		err := r.FieldPathExists("fullstory.rage_click.v1", "sessionId")
		if err == nil {
			t.Fatal("a nonexistent path validated")
		}
		// An operator who typoed a field name needs the list, not just a no.
		if !strings.Contains(err.Error(), "session_id") {
			t.Errorf("the error does not list available fields: %v", err)
		}
	})

	t.Run("missing nested field", func(t *testing.T) {
		if err := r.FieldPathExists("fullstory.rage_click.v1", "user.name"); err == nil {
			t.Error("a nonexistent nested path validated")
		}
	})
}

// TestUnverifiableFieldPathSaysSo. An object with no declared properties accepts
// anything, so a path there cannot be refuted — but D42 promises CONFIRMATION,
// and "cannot confirm" is a different answer from "confirmed".
func TestUnverifiableFieldPathSaysSo(t *testing.T) {
	r := reg(t, map[string]string{
		// OPEN, deliberately: a closed object with no properties admits none
		// (D279), so the path would be absent — only an open one is unverifiable.
		"a.b.v1": `{"type":"object","properties":{"blob":{"type":"object","additionalProperties":true}}}`,
	})

	err := r.FieldPathExists("a.b.v1", "blob.anything")
	if err == nil {
		t.Fatal("a path into an undeclared object was confirmed")
	}
	if !strings.Contains(err.Error(), "cannot confirm") {
		t.Errorf("the error conflates 'unverifiable' with 'absent': %v", err)
	}
}

// TestLocalReferencesAreExpanded is D306's point: a result schema built from
// local references — Fullstory's compute_metric is one — used to be refused, and
// its drafted data_schema reduced every referenced field to an EMPTY object, so
// the metric's numbers were stripped at the closed boundary. Expanded, the
// fields it describes are admitted, and what it does not describe is still
// stripped (D279).
func TestLocalReferencesAreExpanded(t *testing.T) {
	body := `{"type":"object","properties":{"trend":{"$ref":"#/$defs/Series"}},
		"$defs":{"Series":{"type":"array","items":{"type":"object",
			"properties":{"t":{"type":"string"},"v":{"type":"number"}}}}}}`
	reg, err := New(map[string]json.RawMessage{"fs.metric.v1": json.RawMessage(body)})
	if err != nil {
		t.Fatalf("a schema using a local $ref was refused: %v", err)
	}
	got, _ := reg.Shape("fs.metric.v1", map[string]any{
		"trend": []any{map[string]any{"t": "2026-09-26", "v": 42.0, "leak": "x"}},
	})
	point := got["trend"].([]any)[0].(map[string]any)
	if point["v"] != 42.0 {
		t.Errorf("the referenced field was not admitted: %v", got)
	}
	if _, kept := point["leak"]; kept {
		t.Errorf("a field the definition does not name survived shaping — closed by default (D279): %v", got)
	}

	// RECURSION UNROLLS ONCE, THEN STRIPS (D306): a comparison of a comparison is
	// not admitted, because the closed stub at the limit names no properties.
	recursive := `{"type":"object","properties":{"value":{"$ref":"#/$defs/C"}},
		"$defs":{"C":{"type":"object","properties":{"n":{"type":"number"},"comparison":{"$ref":"#/$defs/C"}}}}}`
	rreg, err := New(map[string]json.RawMessage{"fs.recursive.v1": json.RawMessage(recursive)})
	if err != nil {
		t.Fatalf("a recursive schema must load, unrolled: %v", err)
	}
	deep, _ := rreg.Shape("fs.recursive.v1", map[string]any{"value": map[string]any{"n": 1.0,
		"comparison": map[string]any{"n": 2.0, "comparison": map[string]any{"n": 3.0}}}})
	cmp := deep["value"].(map[string]any)["comparison"].(map[string]any)
	if cmp["n"] != 2.0 {
		t.Errorf("the first recursion must be admitted: %v", deep)
	}
	if inner, _ := cmp["comparison"].(map[string]any); len(inner) != 0 {
		t.Errorf("past the unroll limit nothing may be admitted, got %v", inner)
	}
}
