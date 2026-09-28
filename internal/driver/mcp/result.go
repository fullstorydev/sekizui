package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/jsonref"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// payloadOf is D289's one payload rule — the shape sekizui-mcpspec drafts, so a
// vetted data_schema shapes what the driver delivers:
//
//   - `result: text` → `{text}` plus each extracted field, matched per line on
//     the FULL text (the 4 KB cap is the recorded copy's, not the payload's);
//   - a JSON result → structuredContent when it is an object, else JSON parsed
//     from the full text, else REFUSED as not the declared shape. A non-object
//     JSON value is refused rather than wrapped: no data_schema root describes
//     it, and inventing a wrapper key would be a field nobody declared.
func payloadOf(op string, spec SpecTool, result toolResult) (map[string]any, error) {
	full := fullTextOf(result.Content)
	if spec.Result == "text" {
		data := map[string]any{"text": full}
		lines := strings.Split(full, "\n")
		for _, e := range spec.Extract {
			re, err := regexp.Compile(e.Pattern)
			if err != nil {
				return nil, fault.Wrap(fault.KindConfig, op, "extract pattern for "+e.Field, err)
			}
			// ANCHORED TO ITS LINE when the spec gives one — required where the
			// text carries end-user content, so a line a user typed cannot supply
			// a trusted field (D289).
			scan := lines
			if e.Line > 0 {
				scan = nil
				if e.Line <= len(lines) {
					scan = lines[e.Line-1 : e.Line]
				}
			}
			for _, line := range scan {
				if m := re.FindStringSubmatch(line); len(m) == 2 {
					data[e.Field] = strings.TrimSpace(m[1])
					break
				}
			}
		}
		return data, nil
	}
	if len(result.StructuredContent) > 0 {
		var obj map[string]any
		if err := json.Unmarshal(result.StructuredContent, &obj); err == nil && obj != nil {
			return obj, nil
		}
	}
	// SEVERAL JSON BLOCKS ARE REFUSED UNLESS THE SPEC SAYS HOW TO COMBINE THEM
	// (D289) — the parity rule sekizui-mcpspec applies too. Joined, they do not
	// parse; treated as samples, they draft a union nobody declared.
	blocks := textBlocks(result.Content)
	if len(blocks) > 1 {
		if spec.Combine != "items" {
			return nil, fault.New(fault.KindTargetError, op, fmt.Sprintf(
				"tool %q returned %d text blocks and its vetted spec declares no `combine`; "+
					"several JSON blocks are one payload only by declaration (D289)",
				spec.Name, len(blocks)))
		}
		items := make([]any, 0, len(blocks))
		for i, b := range blocks {
			var v map[string]any
			if err := json.Unmarshal([]byte(b), &v); err != nil || v == nil {
				return nil, fault.New(fault.KindTargetError, op, fmt.Sprintf(
					"tool %q text block %d is not a JSON object; `combine: items` needs one per block",
					spec.Name, i))
			}
			items = append(items, v)
		}
		return map[string]any{"items": items}, nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(full), &obj); err == nil && obj != nil {
		return obj, nil
	}
	return nil, fault.New(fault.KindTargetError, op, fmt.Sprintf(
		"tool %q declares a JSON result (output type %q) and returned neither a structuredContent "+
			"object nor JSON-object text; its result cannot be shaped by its data schema, so it is "+
			"refused rather than passed through (D289)", spec.Name, spec.OutputType))
}

// fullTextOf is textOf without the truncation: the payload is built from what
// the tool returned, and the record's bound is applied to the record.
func fullTextOf(content []json.RawMessage) string {
	var parts []string
	for _, block := range content {
		var b struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(block, &b) == nil && b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// admitArgs holds a call's arguments to the vetted input_schema, CLOSED BY
// DEFAULT (D289), and applies the tool's pins. Returns a copy; the caller's map
// is not touched.
//
// **CLOSED BY DEFAULT, like every schema Sekizui enforces (D279).** An argument
// the vetted schema does not declare is refused unless it says
// `additionalProperties: true` — a vendor adding a parameter is then a vetting
// question, not a silent pass-through. Required arguments must be present; a
// declared JSON type must match. Constraint keywords this check does not
// enforce (`enum`, `format`, `pattern`…) are not claimed.
//
// **A PIN IS THE TARGET'S VALUE, NEVER THE CALLER'S** (the maintainer's ruling on
// Fullstory's `org_id`): injected when absent, refused when it names another.
func admitArgs(op string, t connector.Target, spec SpecTool, args map[string]any) (map[string]any, error) {
	var in struct {
		Properties           map[string]map[string]any `json:"properties"`
		Required             []string                  `json:"required"`
		AdditionalProperties any                       `json:"additionalProperties"`
	}
	if len(spec.InputSchema) > 0 {
		if err := json.Unmarshal(spec.InputSchema, &in); err != nil {
			return nil, fault.Wrap(fault.KindConfig, op, "the vetted input_schema of "+spec.Name, err)
		}
	}
	out := make(map[string]any, len(args)+len(spec.Pin))
	for k, v := range args {
		out[k] = v
	}
	for _, name := range spec.Pin {
		want := t.Setting(name)
		if got, supplied := out[name]; supplied && fmt.Sprint(got) != want {
			return nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"%q is pinned to target %q's own %s; this call names another. One target is one "+
					"org, and a call does not choose to reach a different one (D289)",
				name, t.Ref(), name))
		}
		out[name] = want
	}
	open := in.AdditionalProperties == true
	names := make([]string, 0, len(out))
	for k := range out {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		prop, declared := in.Properties[k]
		if !declared {
			if open {
				continue
			}
			return nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"tool %q takes no argument %q; its vetted input_schema declares %v and is closed "+
					"(D289). An argument the reviewer never saw does not reach the server",
				spec.Name, k, declaredNames(in.Properties)))
		}
		if want, ok := prop["type"].(string); ok && !jsonTypeIs(out[k], want) {
			return nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"tool %q argument %q must be %s (D289)", spec.Name, k, want))
		}
	}
	for _, r := range in.Required {
		if _, ok := out[r]; !ok {
			return nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"tool %q requires argument %q (D289)", spec.Name, r))
		}
	}
	return out, nil
}

func declaredNames(props map[string]map[string]any) []string {
	out := make([]string, 0, len(props))
	for k := range props {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// jsonTypeIs reports whether v, as decoded from JSON, is of JSON Schema type t.
func jsonTypeIs(v any, t string) bool {
	switch t {
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == float64(int64(f))
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "null":
		return v == nil
	}
	return true
}

// textBlocks are the non-empty text blocks of a content array, unjoined.
func textBlocks(content []json.RawMessage) []string {
	var out []string
	for _, block := range content {
		var b struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(block, &b) == nil && b.Type == "text" && b.Text != "" {
			out = append(out, b.Text)
		}
	}
	return out
}

// conforms checks a payload against its tool's output_schema, vendor or local
// (D289, closing CONTRACTS 137). A TYPE BREAK or a missing REQUIRED field is an
// error — the contract is broken, and shaping could admit something the admin
// never meant. ADDED fields are returned, for the caller to tally as the
// `tool_nonconforming` signal. Keywords beyond type/properties/required/items/
// additionalProperties are not claimed; no output_schema means nothing to check.
func conforms(op string, spec SpecTool, data map[string]any) (added []string, err error) {
	if len(spec.OutputSchema) == 0 {
		return nil, nil
	}
	// AN UNPARSEABLE CONTRACT REFUSES, IT DOES NOT SWITCH THE CHECK OFF. Load
	// requires valid JSON, so this is unreachable today — and a check that
	// quietly passes on bad input is the thing D289 exists to remove.
	var schema map[string]any
	if err := json.Unmarshal(spec.OutputSchema, &schema); err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, fmt.Sprintf(
			"tool %q's vetted output_schema does not parse, so its results cannot be checked", spec.Name), err)
	}
	// **EXPANDED FIRST, OR A `$ref` CHECKS NOTHING (D306).** A reference node
	// has no `type` and no `properties`, so the walk below admitted anything at
	// all beneath one — Fullstory's compute_metric builds its whole result from
	// references, and a type break there passed as conforming. A contract whose
	// references cannot be expanded refuses, as an unparseable one does.
	expanded, err := jsonref.Expand(schema, jsonref.WithUnroll(spec.RefUnroll))
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, fmt.Sprintf(
			"tool %q's vetted output_schema has references that cannot be expanded, so its "+
				"results cannot be checked", spec.Name), err)
	}
	schema = expanded
	var check func(path string, s map[string]any, v any) error
	check = func(path string, s map[string]any, v any) error {
		if !typeAdmits(s["type"], v) {
			return fault.New(fault.KindTargetError, op, fmt.Sprintf(
				"tool %q broke its output contract: %s is %T where the output_schema says %v. "+
					"Refused rather than shaped — a changed type is a changed meaning (D289)",
				spec.Name, orRoot(path), v, s["type"]))
		}
		switch val := v.(type) {
		case map[string]any:
			props, _ := s["properties"].(map[string]any)
			if req, ok := s["required"].([]any); ok {
				for _, r := range req {
					if name, _ := r.(string); name != "" {
						if _, present := val[name]; !present {
							return fault.New(fault.KindTargetError, op, fmt.Sprintf(
								"tool %q broke its output contract: required %s is missing (D289)",
								spec.Name, join(path, name)))
						}
					}
				}
			}
			// CLOSED MEANS A DECLARED LIST, OR `additionalProperties: false`
			// SAID OUTRIGHT (D317). A vendor that lists fields and later adds
			// one is what `tool_nonconforming` exists to report. A vendor that
			// declares an object with NO fields — Fullstory's `metric_definition`,
			// "the metric definition as structured JSON" — declared it opaque, and
			// JSON Schema admits anything under that; reading it as closed raised
			// a permanent false alarm on every build_metric, found live.
			open := s["additionalProperties"] == true ||
				(len(props) == 0 && s["additionalProperties"] != false)
			keys := make([]string, 0, len(val))
			for k := range val {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				sub, declared := props[k].(map[string]any)
				switch {
				case declared:
					if err := check(join(path, k), sub, val[k]); err != nil {
						return err
					}
				case !open:
					added = append(added, join(path, k))
				}
			}
		case []any:
			if items, ok := s["items"].(map[string]any); ok {
				for i, x := range val {
					if err := check(fmt.Sprintf("%s[%d]", path, i), items, x); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := check("", schema, data); err != nil {
		return nil, err
	}
	return added, nil
}

// typeAdmits reports whether a schema `type` (a name, a list, or absent) admits v.
func typeAdmits(t any, v any) bool {
	switch tt := t.(type) {
	case nil:
		return true
	case string:
		return jsonTypeIs(v, tt)
	case []any:
		for _, x := range tt {
			if name, _ := x.(string); jsonTypeIs(v, name) {
				return true
			}
		}
		return false
	}
	return true
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func orRoot(path string) string {
	if path == "" {
		return "the result root"
	}
	return path
}
