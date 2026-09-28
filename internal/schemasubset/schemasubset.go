// Package schemasubset reduces a vendor's JSON Schema to the closed subset
// Sekizui enforces (D279, D287, D314).
//
// PRIVATE (D35), AND A LEAF: the offline MCP drafter may not reach the network
// (P3 step 26), and the connectors that derive data schemas from vendor
// contracts need the same reduction — ONE converter, so a vendor schema means
// the same thing in a drafted MCP spec and in a derived API action. It was
// `mcpspec.closedSubset` until D314; the words of its warnings are unchanged.
package schemasubset

import (
	"fmt"
	"strings"
)

// dataKeywords is what a data_schema may carry: what schemareg enforces, and
// the annotations it accepts. A KEYWORD OUTSIDE IT IS DROPPED AND SAID — kept, it
// would refuse the schema at load (D278). This list is a copy of schemareg's
// vocabulary, because importing schemareg would reach the network through
// pkg/connector (P3 step 26); P3 step 28 loads every drafted data_schema into
// the real schemareg, so the copy cannot drift unnoticed.
var dataKeywords = map[string]bool{ //nolint:gochecknoglobals // immutable
	"type": true, "properties": true, "items": true, "callerOnly": true,
	"title": true, "description": true, "$comment": true,
}

// structural are the keywords that describe SHAPE a closed schema cannot
// follow — branches and references. Everything else outside dataKeywords is a
// constraint on a field that stays admitted.
var structural = map[string]bool{ //nolint:gochecknoglobals // immutable
	"$ref": true, "$defs": true, "definitions": true, "oneOf": true, "anyOf": true, "allOf": true,
	"not": true, "if": true, "then": true, "else": true, "patternProperties": true,
	"prefixItems": true, "dependentSchemas": true,
}

// Closed is the data schema drawn from a vendor schema (D287, D314): CLOSED,
// in the vocabulary schemareg enforces, and every loss named.
//
//   - A union type (`["string","integer"]`) cannot be one type: left untyped.
//   - A map keyed by DATA (`additionalProperties: {…}`) cannot name its keys in
//     a closed schema: admitted as an empty object — opening it is the admin's
//     decision, not a draft's.
//   - `additionalProperties: true` is dropped: absent means closed (D279).
//   - `required` is the contract's business, not the allowlist's.
//   - Any other keyword (`enum`, `format`, `oneOf`…) is dropped, and what it
//     described is not admitted. A `$ref` arrives here only if the expansion
//     before it refused (a cycle, a remote reference — D306).
func Closed(schema map[string]any, path string, warnings *[]string) map[string]any {
	out := map[string]any{}
	at := orRoot(path)
	for k, v := range schema {
		switch {
		case k == "type":
			if t, ok := v.(string); ok {
				out["type"] = t
			} else {
				*warnings = append(*warnings, fmt.Sprintf("data_schema: %s has more than one type "+
					"(%v); a data schema field has one, so it is left UNTYPED — a scalar passes as it "+
					"is and an object arrives EMPTY. Decide which type it is", at, v))
			}
		case k == "properties":
			props, _ := v.(map[string]any)
			sub := map[string]any{}
			for name, child := range props {
				if cs, ok := child.(map[string]any); ok {
					sub[name] = Closed(cs, join(path, name), warnings)
				}
			}
			out["properties"] = sub
		case k == "items":
			if cs, ok := v.(map[string]any); ok {
				out["items"] = Closed(cs, path+"[]", warnings)
			}
		case k == "additionalProperties":
			if _, isMap := v.(map[string]any); isMap {
				*warnings = append(*warnings, fmt.Sprintf("data_schema: %s is keyed by DATA; a "+
					"closed schema cannot name its keys, so it is admitted as an EMPTY object. "+
					"`additionalProperties: true` would admit everything under it — the admin's "+
					"call, never a draft's (D279)", at))
				out["type"] = "object"
			} else if v == true {
				*warnings = append(*warnings, fmt.Sprintf("data_schema: %s was open "+
					"(additionalProperties: true); drafted CLOSED — only its named properties are "+
					"admitted (D279)", at))
			}
		case k == "required":
		case dataKeywords[k]:
			out[k] = v
		case structural[k]:
			// WHAT IT DESCRIBES IS NOT ADMITTED: a branch or a reference is shape
			// the closed schema cannot follow, so nothing under it gets in.
			*warnings = append(*warnings, fmt.Sprintf("data_schema: %s uses %q, which Sekizui "+
				"cannot traverse; dropped. The field stays, but only as a scalar or an EMPTY "+
				"object — the fields it describes are NOT admitted; flatten them into properties "+
				"if they are needed (D278)", at, k))
		default:
			// A CONSTRAINT ON A FIELD THAT IS STILL ADMITTED. Saying "not
			// admitted" here — the first draft did — tells a reviewer the
			// opposite of what happens.
			*warnings = append(*warnings, fmt.Sprintf("data_schema: %s keeps its type but loses "+
				"%q, which Sekizui does not enforce: the field is ADMITTED WITHOUT that constraint "+
				"(D278)", at, k))
		}
	}
	return out
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func orRoot(path string) string {
	if path == "" {
		return "the response root"
	}
	return strings.TrimPrefix(path, ".")
}
