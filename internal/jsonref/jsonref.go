// Package jsonref expands LOCAL JSON Schema references into a reference-free
// tree (D306).
//
// PRIVATE (D35), AND A LEAF: it imports nothing of Sekizui's, so the offline
// drafter (`sekizui-mcpspec`, which may not reach the network — P3 step 26),
// the registry and the MCP driver can all use ONE resolver rather than three
// that disagree about what a reference means.
//
// **WHY EXPAND RATHER THAN TEACH EVERY WALKER TO FOLLOW `$ref`.** Four things
// walk a schema — `schemareg`'s shaping and validation, D42's field-path check,
// D292's lens paths, and the MCP driver's conformance check — and each would
// need its own cycle handling. Expanding once, at the edge, leaves every one of
// them reading the closed subset it already understands. The conformance check
// is the reason this is a finding and not a nicety: a `$ref` node has no `type`
// and no `properties`, so it checked NOTHING beneath one and passed whatever
// arrived (D306).
//
// **LOCAL ONLY, AND NARROW:** `#/$defs/<name>` and `#/definitions/<name>`, a
// WHOLE definition at the root. A remote reference would make loading a schema
// a network fetch; a pointer into the middle of a definition is a shape nobody
// has needed. Both refuse, loudly.
//
// **RECURSION IS UNROLLED, NOT REFUSED — AND THAT WAS LEARNED FROM A REAL
// SCHEMA.** The first version refused every cycle. Fullstory's compute_metric
// then turned out to be recursive by design: each result type carries
// `comparison: {"$ref": <itself>}` — the same result for the comparison period
// — while real data nests exactly once. So a definition may RECUR `unroll`
// times along one path — DEFAULT 1, CONFIGURABLE up to MaxUnroll (the maintainer, D309):
// per MCP spec as `ref_unroll`, and `-unroll` when drafting. Past that it
// becomes a CLOSED STUB of the same type, marked with `$comment`. In a data
// schema anything deeper is therefore STRIPPED (the safe direction, D279); in
// the conformance check the stub's type is still checked and anything under it
// is reported as an added field, never silently passed.
//
// **AND BOUNDED.** A schema with no cycle can still blow up exponentially — ten
// definitions each referencing the next twice expand to a thousand copies of
// the last — so the expansion is capped by DEPTH and by the NUMBER OF NODES it
// produces. The registry loads connector schemas at boot, and an unbounded
// expansion there is a denial of service against boot.
package jsonref

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Bounds on an expansion. Generous for any schema a vendor publishes (Fullstory's
// compute_metric expands to a few hundred nodes), and small enough that a hostile
// one fails fast.
const (
	maxDepth = 64
	maxNodes = 20000
)

// DefaultUnroll is how many times a definition may RECUR along one path when
// nobody says otherwise: once, which is what Fullstory's comparison periods
// need (D306, D309). MaxUnroll bounds a configured value — pkg/config refuses a
// `ref_unroll` above it, reading THIS constant so the two cannot disagree.
const (
	DefaultUnroll = 1
	MaxUnroll     = 8
)

// Option configures an expansion.
type Option func(*expander)

// WithUnroll sets how many times a definition may recur along one path. 0 means
// a recursion is never followed: the first one is already the stub.
func WithUnroll(n int) Option { return func(e *expander) { e.unroll = n } }

// definitionRoots are the two keywords a local reference may point into:
// `$defs` (2019-09 onward) and `definitions` (draft-07 and earlier).
var definitionRoots = []string{"$defs", "definitions"} //nolint:gochecknoglobals // immutable

// siblingAnnotations may sit beside a `$ref` and are carried onto the expansion.
// Anything else beside a `$ref` REFUSES: since 2019-09 a sibling constraint
// applies IN ADDITION to the reference (an implicit allOf), and folding it in
// or dropping it would each claim a shape the vendor did not publish.
var siblingAnnotations = map[string]bool{ //nolint:gochecknoglobals // immutable
	"description": true, "title": true, "$comment": true, "examples": true,
}

// verbatim are keywords whose values are DATA, not schemas: a `$ref` key inside
// an example is part of the example.
var verbatim = map[string]bool{ //nolint:gochecknoglobals // immutable
	"examples": true, "enum": true, "const": true, "default": true,
}

// Expand returns schema with every local reference replaced by a copy of what it
// names, and the definition roots removed. The input is not modified.
func Expand(schema map[string]any, opts ...Option) (map[string]any, error) {
	defs := map[string]map[string]any{}
	for _, root := range definitionRoots {
		block, ok := schema[root].(map[string]any)
		if !ok {
			continue
		}
		for name, def := range block {
			d, ok := def.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s/%s is not a schema object", root, name)
			}
			defs[root+"/"+name] = d
		}
	}

	e := &expander{defs: defs, unroll: DefaultUnroll}
	for _, o := range opts {
		o(e)
	}
	if e.unroll < 0 || e.unroll > MaxUnroll {
		return nil, fmt.Errorf("unroll %d is outside 0..%d (D309)", e.unroll, MaxUnroll)
	}
	out, err := e.node(schema, 0, nil, true)
	if err != nil {
		return nil, err
	}
	m, _ := out.(map[string]any)
	return m, nil
}

// ExpandJSON is Expand over bytes. A body that contains no reference is
// returned UNCHANGED, byte for byte, so a schema that never used `$ref` loads
// exactly as it did before this package existed.
func ExpandJSON(body []byte, opts ...Option) ([]byte, error) {
	if !strings.Contains(string(body), `"$ref"`) {
		return body, nil
	}
	var schema map[string]any
	if err := json.Unmarshal(body, &schema); err != nil {
		// Not an object at the root: nothing here can hold a definition, and
		// the caller's own decoding reports the real problem.
		return body, nil //nolint:nilerr // the caller's decoder owns this error
	}
	out, err := Expand(schema, opts...)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

type expander struct {
	defs   map[string]map[string]any
	nodes  int
	unroll int
}

func (e *expander) node(v any, depth int, chain []string, root bool) (any, error) {
	e.nodes++
	if e.nodes > maxNodes {
		return nil, fmt.Errorf("the expansion passes %d nodes — a schema that references the same "+
			"definition many times over can grow exponentially without a cycle, so this refuses "+
			"rather than exhaust memory at load (D306)", maxNodes)
	}
	if depth > maxDepth {
		return nil, fmt.Errorf("the expansion is deeper than %d levels (D306)", maxDepth)
	}

	switch t := v.(type) {
	case map[string]any:
		if ref, has := t["$ref"]; has {
			return e.reference(t, ref, depth, chain)
		}
		out := make(map[string]any, len(t))
		for k, child := range t {
			if root && isDefinitionRoot(k) {
				continue
			}
			if verbatim[k] {
				out[k] = child
				continue
			}
			c, err := e.node(child, depth+1, chain, false)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			c, err := e.node(child, depth+1, chain, false)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	default:
		return v, nil
	}
}

func (e *expander) reference(at map[string]any, ref any, depth int, chain []string) (any, error) {
	s, ok := ref.(string)
	if !ok {
		return nil, fmt.Errorf("a $ref is %T, not a string", ref)
	}
	key, err := localKey(s)
	if err != nil {
		return nil, err
	}
	def, ok := e.defs[key]
	if !ok {
		return nil, fmt.Errorf("$ref %q names no definition at the schema's root", s)
	}
	for k := range at {
		if k != "$ref" && !siblingAnnotations[k] {
			return nil, fmt.Errorf("$ref %q has a sibling %q; beside a reference only annotations "+
				"(description, title, $comment, examples) are accepted — a sibling constraint applies "+
				"IN ADDITION to the reference, and folding or dropping it would claim a shape the "+
				"schema does not publish (D306)", s, k)
		}
	}

	seen := 0
	for _, k := range chain {
		if k == key {
			seen++
		}
	}
	if seen > e.unroll {
		// THE CLOSED STUB: the definition's type and nothing it contains — so
		// shaping strips whatever is deeper and conformance reports it as added.
		stub := map[string]any{"$comment": fmt.Sprintf("recursion of %s unrolled %d time(s); "+
			"anything deeper is not admitted (D306, D309)", key, e.unroll)}
		if t, has := def["type"]; has {
			stub["type"] = t
		}
		// EMPTY `properties` AND `additionalProperties: false`, SAID OUTRIGHT:
		// the conformance walk reads an object with no declared properties as
		// OPEN — a vendor's `properties: {}` is an opaque object, which JSON
		// Schema admits anything under (D317) — so the stub states that it is
		// closed. Every field beneath it is then an ADDED field there, and
		// stripped in the registry.
		if def["type"] == "object" || def["properties"] != nil {
			stub["properties"] = map[string]any{}
			stub["additionalProperties"] = false
		}
		return stub, nil
	}
	expanded, err := e.node(def, depth+1, append(chain, key), false)
	if err != nil {
		return nil, err
	}
	out, _ := expanded.(map[string]any)
	merged := make(map[string]any, len(out)+len(at))
	for k, v := range out {
		merged[k] = v
	}
	// THE REFERENCING SITE'S ANNOTATIONS WIN: its description is about THIS
	// field, the definition's about the shape in general.
	for k, v := range at {
		if k != "$ref" {
			merged[k] = v
		}
	}
	return merged, nil
}

// localKey turns `#/$defs/Name` into the lookup key `$defs/Name`, refusing
// everything else — remote documents, the root itself, and pointers into the
// middle of a definition.
func localKey(ref string) (string, error) {
	for _, root := range definitionRoots {
		prefix := "#/" + root + "/"
		if !strings.HasPrefix(ref, prefix) {
			continue
		}
		name := ref[len(prefix):]
		if name == "" || strings.Contains(name, "/") {
			return "", fmt.Errorf("$ref %q points inside a definition; only a whole definition "+
				"at the schema's root is followed (D306)", ref)
		}
		// RFC 6901 escapes, in the order the RFC requires: ~1 before ~0.
		name = strings.ReplaceAll(strings.ReplaceAll(name, "~1", "/"), "~0", "~")
		return root + "/" + name, nil
	}
	return "", fmt.Errorf("$ref %q is not local; only #/$defs/<name> and #/definitions/<name> are "+
		"followed — a remote reference would make loading a schema a network fetch (D306)", ref)
}

func isDefinitionRoot(k string) bool {
	for _, root := range definitionRoots {
		if k == root {
			return true
		}
	}
	return false
}
