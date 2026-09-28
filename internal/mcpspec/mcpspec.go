// Package mcpspec drafts an MCP tool's `outputSchema` from responses somebody
// observed, for a human to vet into the configuration (D168).
//
// **WHY IT EXISTS.** Much of the MCP ecosystem publishes no `outputSchema`, and
// D51 makes absence NEVER read as drift — so without an authoring path a reflex
// cannot declare `ExpectsType` against such a tool at all, because D42 has no
// field paths to validate. The honest state before this was that those servers
// are governable but not reflexable.
//
// **THE HARD CONSTRAINT IS PROVENANCE, AND IT IS THE WHOLE SECURITY ARGUMENT.**
// Everything drafted here is `local` and this package is STRUCTURALLY INCAPABLE
// of minting `vendor`: no parameter for it, no code path that writes it, and P2
// step 28 asserts the word appears in neither this package nor the command.
// D51 exists to stop a hand-written guess masquerading as a vendor guarantee,
// and **a GENERATED guess is the same thing with more confidence behind it.** A
// `local` schema is never drift-checked, so a wrong one fails as "we guessed
// wrong" rather than as a security incident — the failure direction to keep.
//
// **IT DOES NOT DECIDE WHAT A HUMAN IS HERE TO DECIDE.** `mutating` and
// `idempotency` are never emitted, not even as defaults. MCP's `readOnlyHint`
// and `destructiveHint` are vendor-supplied, they drive the retry gate and
// audit-as-external-effect (D23, D163), and §4.9a.1 makes preserving the human's
// answer a requirement of this tool. A draft that filled them in from a hint
// would destroy the review it exists to feed. `native` IS emitted, as
// `[opaque]` (D323): unlike those two, it has an answer that is safe whatever
// the truth — the widest reading — so the draft starts there and the reviewer
// may only narrow it.
//
// **THE LOGIC IS HERE AND THE COMMAND IS WIRING**, which is not tidiness: step
// 28 asserts on what a draft CONTAINS, and a `package main` cannot be called
// from a test. The first version put it all in the command and the step could
// only have run a subprocess.
//
// DESIGN.md references: §4.9a, §4.9a.1, §4.9a.3a, D42, D46, D48, D50, D51, D168.
package mcpspec

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/fullstorydev/sekizui/internal/jsonref"
	"github.com/fullstorydev/sekizui/internal/schemasubset"
)

// Fragment is one drafted tool spec, ready for a human to vet.
type Fragment struct {
	// List is the draft as a human reads it: one `path: type` line per field,
	// flattened — `events[].event_type: string`. The FIRST rendering, and a
	// second rendering of the same inference as the schema in YAML (P3 step
	// 28), never a second inference. Types only, never values: a value is the
	// customer's data (D233), and this list is meant to be pasted into review.
	List string

	// YAML is the spec fragment to paste into the vetted configuration: the
	// tool's `data_schema` (D279), the connector-owned CLOSED allowlist of what
	// its results may bring in.
	YAML string

	// Warnings are what the draft had to GUESS about, and they are part of the
	// output rather than a debug aid: every one of them names a place where the
	// observations were too thin to support the schema that was written.
	Warnings []string

	// Obligations are what this package cannot answer and a person must.
	Obligations string
}

// Draft renders the spec fragment for one tool.
//
// `at` is a JSON pointer selecting the SUBTREE to describe, or empty for the
// whole response. See `Select`.
// Draft takes NO unroll option, deliberately: an INFERRED schema contains no
// `$ref`, so there is nothing to unroll — and P2 step 28 holds this signature
// to four parameters, because a fifth is how provenance becomes a caller's
// choice (D309).
func Draft(tool, outputType, at string, samples []any) (Fragment, error) {
	if tool == "" || outputType == "" {
		return Fragment{}, fmt.Errorf("both a tool name and an output type are required. " +
			"The output type is the registry key a reflex's ExpectsType matches, and it is " +
			"NOT the schema URI — the two were confused in three mutually-agreeing files " +
			"once already (D221)")
	}
	if len(samples) == 0 {
		return Fragment{}, fmt.Errorf("no observed responses given. A schema drafted from " +
			"nothing is a guess with no observation behind it, which is worse than the " +
			"absence D51 already handles honestly")
	}

	selected, err := Select(samples, at)
	if err != nil {
		return Fragment{}, err
	}
	samples = selected

	schema, warnings := infer(samples)
	return fragment(tool, outputType, originLocal, schema, len(samples), warnings,
		fmt.Sprintf("inferred from %d tool result(s) an AGENT supplied — UNVERIFIED: the result "+
			"reached this tool through an LLM, which can drop, truncate or invent fields", len(samples)))
}

// infer draws a JSON Schema over every sample, and returns what it had to guess
// about.
//
// **THE UNION OF THE SAMPLES, NOT THE FIRST ONE.** Two responses that disagree
// about a field's type describe a field that has both, and a schema drawn from
// whichever arrived first would reject the other.
func infer(samples []any) (map[string]any, []string) {
	d := &drafting{samples: len(samples), once: map[string]bool{}}
	schema := d.shapeOf(samples, "")
	if len(d.seenOnce) > 0 {
		d.warnOnce("single-sample-required", "observed only once, so they carry no `required` — "+
			"a single observation cannot tell a field that is always present from one that happened "+
			"to be: %s. Observe another response and re-run", strings.Join(d.seenOnce, ", "))
	}
	schema["$comment"] = "drafted from agent-supplied tool results; unverified until vetted (D287)"
	return schema, d.warnings
}

// drafting carries what the shape walk has learned and what it has already said.
type drafting struct {
	samples  int
	warnings []string
	once     map[string]bool

	// seenOnce are the objects observed only once, reported in ONE warning
	// that names them all (D289, keeping warnOnce's grouping).
	seenOnce []string
}

func (d *drafting) warn(format string, args ...any) {
	d.warnings = append(d.warnings, fmt.Sprintf(format, args...))
}

// warnOnce says a thing at most once, GROUPED BY REASON.
//
// **BECAUSE THE FIRST REAL RESPONSE PRODUCED THE SAME SENTENCE ELEVEN TIMES.**
// A single observation means no object anywhere gets a `required`, so the
// per-object warning fired for every nested object in the tree and buried the
// two warnings that named something specific. D97's finding in a different
// output: it grouped a boot refusal by REASON because the reason is the unit of
// action, and nobody acts on the eleventh copy.
func (d *drafting) warnOnce(key, format string, args ...any) {
	if d.once[key] {
		return
	}
	d.once[key] = true
	d.warn(format, args...)
}

//nolint:gocyclo // one shape function; splitting it scatters the type analysis
func (d *drafting) shapeOf(values []any, path string) map[string]any {
	types := map[string]bool{}
	var objects []map[string]any
	var arrayElems []any

	for _, v := range values {
		switch t := v.(type) {
		case map[string]any:
			types["object"] = true
			objects = append(objects, t)
		case []any:
			types["array"] = true
			arrayElems = append(arrayElems, t...)
		case string:
			types["string"] = true
		case bool:
			types["boolean"] = true
		case float64:
			// **ALWAYS `number`, NEVER `integer`.** JSON has one numeric type,
			// and every observed value being whole is not evidence that the next
			// one will be — a schema saying `integer` because the samples
			// happened to be round is a guess that fails on the first 1.5, and
			// it fails as a validation error against a response that is
			// perfectly legal.
			types["number"] = true
		case nil:
			types["null"] = true
		default:
			types["null"] = true
		}
	}

	// **A FIELD OBSERVED ONLY AS null GETS NO TYPE AT ALL.** Emitting
	// `"type": "null"` would assert the vendor never fills it, on the evidence
	// that it happened not to here. An empty schema accepts anything, which is
	// the honest statement of "we have not seen this populated" — and the
	// warning names it so a human can go and look.
	if len(types) == 1 && types["null"] {
		d.warn("%s was null in every observed response, so it is left UNTYPED rather than "+
			"typed as null — a schema asserting null would claim the vendor never fills it",
			orRoot(path))
		return map[string]any{}
	}
	delete(types, "null")

	out := map[string]any{}
	switch {
	case len(types) == 1:
		for t := range types {
			out["type"] = t
		}
	default:
		names := make([]string, 0, len(types))
		for t := range types {
			names = append(names, t)
		}
		sort.Strings(names)
		out["type"] = names
		d.warn("%s had more than one type across the observed responses (%v); the draft "+
			"accepts all of them, which is wider than any single response and probably "+
			"wider than the vendor's own contract", orRoot(path), names)
	}

	if len(objects) > 0 {
		d.describeObject(out, objects, path)
	}

	if types["array"] {
		if len(arrayElems) == 0 {
			d.warn("%s was an EMPTY array in every observed response, so its items are left "+
				"unconstrained", orRoot(path))
			out["items"] = map[string]any{}
		} else {
			out["items"] = d.shapeOf(arrayElems, path+"[]")
		}
	}

	return out
}

// describeObject decides whether an object is a RECORD or a MAP, which is the
// distinction the first real MCP response caught this tool getting wrong.
//
// **`discover_org_context` RETURNS `results` KEYED BY THE CALLER'S OWN SEARCH
// TERMS.** Drafted as a record, the schema's properties were the arguments that
// happened to be passed — a schema that can never match another response, with
// the caller's inputs baked in as though the vendor had promised them. **That is
// the exact failure D51 exists to prevent, arriving as a generated guess with
// more confidence behind it than a hand-written one.**
//
// **AN OBJECT USED AS A MAP IS INDISTINGUISHABLE FROM ONE USED AS A RECORD, FROM
// A SINGLE OBSERVATION.** So the tool does not choose silently:
//
//   - Two or more responses whose KEY SETS DIFFER are evidence of a map, and the
//     draft says `additionalProperties` over the union of the values.
//   - One response, or key sets that agree, draft as a record — and where the
//     object has several keys whose values all share one shape, the draft WARNS,
//     because that is what a map looks like from one sample.
func (d *drafting) describeObject(out map[string]any, objects []map[string]any, path string) {
	counts := map[string]int{}
	byKey := map[string][]any{}
	for _, obj := range objects {
		for k, v := range obj {
			counts[k]++
			byKey[k] = append(byKey[k], v)
		}
	}
	names := make([]string, 0, len(byKey))
	for k := range byKey {
		names = append(names, k)
	}
	sort.Strings(names)

	if d.looksLikeMap(objects, names, byKey, path) {
		all := make([]any, 0, len(byKey))
		for _, k := range names {
			all = append(all, byKey[k]...)
		}
		out["additionalProperties"] = d.shapeOf(all, path+"{}")
		return
	}

	props := map[string]any{}
	for _, k := range names {
		props[k] = d.shapeOf(byKey[k], path+"."+k)
	}
	out["properties"] = props

	// **`required` NEEDS MORE THAN ONE SAMPLE TO MEAN ANYTHING.** With a single
	// response every key present looks required, which is the difference between
	// "this field was there" and "this field is always there" — and the second
	// is a claim about somebody else's API that one observation cannot support.
	if len(objects) > 1 {
		var required []string
		for _, k := range names {
			if counts[k] == len(objects) {
				required = append(required, k)
			}
		}
		if len(required) > 0 {
			out["required"] = required
		}
		return
	}

	// PER OBJECT, SAID ONCE. The warning said "NO `required` is emitted
	// anywhere in this draft" — false whenever a nested object (an array's
	// elements) was seen more than once and so DID get one; found drafting the
	// Fullstory MCP's session_open. The first fix warned per object, which is
	// the eleven-copies regression warnOnce's own comment records. So the
	// objects are COLLECTED and named in one warning (infer emits it).
	d.seenOnce = append(d.seenOnce, orRoot(path))
}

// looksLikeMap reports whether this object's KEYS are data rather than schema.
func (d *drafting) looksLikeMap(objects []map[string]any, names []string,
	byKey map[string][]any, path string) bool {

	// EVIDENCE: two or more responses with NO KEY IN COMMON, whose values all
	// share one shape.
	//
	// **"THE KEY SETS DIFFER" WAS THE FIRST RULE AND IT WAS FAR TOO
	// AGGRESSIVE — an OPTIONAL FIELD makes key sets differ.** Step 28's own
	// fixture caught it within the minute: two responses of an obvious record,
	// one carrying an extra field, drafted as a map. Optional fields are
	// ubiquitous and map keys are not, so the discriminator has to be that
	// NOTHING recurs: a record's keys are fixed by the vendor, so at least one
	// of them appears in every response, while a map keyed by data — a query
	// term, an id — generally has nothing in common between independent calls.
	//
	// **THE RESIDUAL IS STATED: two calls that happen to use the same key read
	// as a record**, and the single-observation warning below then fires
	// instead. That is the safe direction — a record schema over map keys is
	// visibly odd to a reviewer, where `additionalProperties` over a genuine
	// record silently discards every field name the vendor does promise.
	if len(objects) > 1 {
		common := keySet(objects[0])
		for _, obj := range objects[1:] {
			next := keySet(obj)
			for k := range common {
				if _, ok := next[k]; !ok {
					delete(common, k)
				}
			}
		}
		// AN EMPTY OBJECT IN ANY SAMPLE TELLS US NOTHING about the key set, and
		// would make "no key in common" trivially true.
		empty := false
		for _, obj := range objects {
			if len(obj) == 0 {
				empty = true
			}
		}
		if !empty && len(common) == 0 && len(names) > 1 && sameShape(byKey, names) {
			d.warn("%s is drafted as a MAP (`additionalProperties`) rather than as a record: "+
				"the observed responses had NO key in common and every value shares one "+
				"shape, so the keys are DATA. A record schema would have baked one "+
				"response's keys in as though the vendor promised them", orRoot(path))
			return true
		}
		return false
	}

	// ONE OBSERVATION: no evidence either way, so draft the record and SAY what
	// the alternative reading would be. Several keys whose values all share one
	// shape is what a map looks like from a single sample.
	if len(names) > 1 && sameShape(byKey, names) {
		d.warn("%s has %d keys whose values all share one shape, which is what a MAP looks "+
			"like from a single observation — the keys may be data (a query term, an id) "+
			"rather than fields the vendor promises. Drafted as a record; observe a second "+
			"response with different keys to settle it", orRoot(path), len(names))
	}
	return false
}

func keySet(obj map[string]any) map[string]bool {
	out := make(map[string]bool, len(obj))
	for k := range obj {
		out[k] = true
	}
	return out
}

// sameShape reports whether every key's value looks like an instance of one
// thing, which is the map signature.
//
// **IT COMPARES KEY SETS AND KINDS, NOT FULL SHAPES, AND THE REAL RESPONSE IS
// WHY.** The first version rendered each value's whole inferred schema and
// required equality. Against `discover_org_context` that failed: one query's
// result group had EMPTY arrays where another's were populated, so the drafted
// items differed (`{}` against a full object) and two values of obviously the
// same type compared as different. The map went undetected at one sample and was
// detected at two only by accident of the other condition.
//
// So the question asked is the shallow one it should always have been: are these
// all objects with the same field names, or all the same scalar kind. A map's
// values are instances of one type; how deeply populated any instance happens to
// be says nothing about that.
func sameShape(byKey map[string][]any, names []string) bool {
	var want string
	for i, k := range names {
		got := shallowKind(byKey[k])
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			return false
		}
	}
	return true
}

// shallowKind renders a value's kind, and for objects its field names.
func shallowKind(values []any) string {
	kinds := map[string]bool{}
	fields := map[string]bool{}
	for _, v := range values {
		switch t := v.(type) {
		case map[string]any:
			kinds["object"] = true
			for k := range t {
				fields[k] = true
			}
		case []any:
			kinds["array"] = true
		case string:
			kinds["string"] = true
		case bool:
			kinds["boolean"] = true
		case float64:
			kinds["number"] = true
		default:
			kinds["null"] = true
		}
	}
	return strings.Join(sortedSet(kinds), ",") + "{" + strings.Join(sortedSet(fields), ",") + "}"
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orRoot(path string) string {
	if path == "" {
		return "the response root"
	}
	return strings.TrimPrefix(path, ".")
}

// Select narrows every sample to a JSON pointer, so a huge response yields the
// shape a reflex actually reads.
//
// **BECAUSE `ExpectsType` VALIDATES FIELD PATHS AGAINST A TYPE (D42), AND FOR A
// PAGE OF DATA THE TYPE IS THE ELEMENT.** A session-events response is an
// envelope — a session stub, a page token, and four hundred events — and the
// interesting registered type is the EVENT, not the page. Drafting the envelope
// registers a schema whose useful part is buried under `events[]`, and a reflex
// declaring `ExpectsType` against it is declaring against the wrapper.
//
// **`/events/0` SELECTS ONE ELEMENT AND `/events` SELECTS THE ARRAY**, which
// then collapses to `items` — both are useful and they answer different
// questions, so the pointer is the caller's to choose rather than something this
// package infers.
func Select(samples []any, pointer string) ([]any, error) {
	if pointer == "" {
		return samples, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("a JSON pointer must start with `/` (RFC 6901); got %q. "+
			"`/events/0` selects one element of `events`, `/events` selects the array",
			pointer)
	}

	out := make([]any, 0, len(samples))
	for i, sample := range samples {
		v := sample
		for _, token := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
			token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
			switch node := v.(type) {
			case map[string]any:
				next, ok := node[token]
				if !ok {
					return nil, fmt.Errorf("observed response %d has no %q at pointer %q. "+
						"A pointer that misses is REFUSED rather than skipped: a draft over "+
						"the samples that happened to match would describe a shape nobody "+
						"asked about", i+1, token, pointer)
				}
				v = next
			case []any:
				idx, err := strconv.Atoi(token)
				if err != nil || idx < 0 || idx >= len(node) {
					return nil, fmt.Errorf("observed response %d: %q is not an index into "+
						"the array at pointer %q (it holds %d element(s))",
						i+1, token, pointer, len(node))
				}
				v = node[idx]
			default:
				return nil, fmt.Errorf("observed response %d: pointer %q descends into a "+
					"value that is neither an object nor an array", i+1, pointer)
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// LargeSampleBytes is where a sample stops looking like one response.
//
// NOT A LIMIT, A WARNING. There is no size at which a response becomes
// undraftable — arrays collapse to `items`, so the SCHEMA stays small however
// many elements arrive. What grows is the OBSERVATION, and that is the hazard:
// a session-events response is tens of kilobytes of session ids, user emails,
// page URLs and click text. This is the point at which the tool says so.
const LargeSampleBytes = 16 << 10

// WarnOnSize returns the caution a large observation deserves, or "".
func WarnOnSize(raw [][]byte) string {
	var biggest int
	for _, b := range raw {
		if len(b) > biggest {
			biggest = len(b)
		}
	}
	if biggest < LargeSampleBytes {
		return ""
	}
	return fmt.Sprintf("an observed response is %d KB, which is a PAGE OF DATA rather than "+
		"one result. Two things follow: the useful type is probably a subtree (try `-at "+
		"/events/0`), and a response that big is customer data — PIPE it into this tool "+
		"rather than saving it, and if you must save it keep it under dev/ which is "+
		"gitignored. A schema needs shape, not somebody's session", biggest>>10)
}

// renderList is the schema as `path: type` lines — the rendering a human reads
// (D287). It WALKS THE SCHEMA rather than the samples, so the list and the
// schema cannot disagree: they are two renderings of one inference (P3 step
// 28). Arrays are `[]`, a map keyed by data is `{}`, an untyped field says so.
func renderList(tool, outputType, source string, schema map[string]any) string {
	var lines []string
	var walk func(path string, s map[string]any)
	walk = func(path string, s map[string]any) {
		label := typeLabel(s)
		if path != "" {
			lines = append(lines, path+": "+label)
		}
		if props, ok := s["properties"].(map[string]any); ok {
			names := make([]string, 0, len(props))
			for n := range props {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				child, _ := props[n].(map[string]any)
				walk(join(path, n), child)
			}
		}
		if items, ok := s["items"].(map[string]any); ok {
			walk(path+"[]", items)
		}
		if values, ok := s["additionalProperties"].(map[string]any); ok {
			walk(path+"{}", values)
		}
	}
	walk("", schema)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s → %s: %d field(s) the connector may provide, %s\n",
		tool, outputType, len(lines), source)
	b.WriteString("# types only; no value from the result is ever printed (D233)\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.String()
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// typeLabel is a schema node's type as one word: `string`, `string|integer`,
// or `untyped` where every observation was null (the draft warns about those).
func typeLabel(s map[string]any) string {
	switch t := s["type"].(type) {
	case string:
		return t
	case []string:
		return strings.Join(t, "|")
	case []any:
		parts := make([]string, 0, len(t))
		for _, v := range t {
			parts = append(parts, fmt.Sprint(v))
		}
		return strings.Join(parts, "|")
	}
	return "untyped"
}

// originLocal is the provenance of a schema this package INFERRED (D51). The
// only other value it can emit, `vendor`, appears in one place: DraftAdvertised,
// which copies and never infers (D287, P2 step 28).
const originLocal = "local"

// DraftAdvertised renders the spec fragment for a tool whose server ADVERTISES
// an `outputSchema` (D287) — piped by the agent as the tool's `tools/list`
// entry. The schema is COPIED, not inferred, so its provenance is the vendor's.
//
// **SAFE TO MARK `vendor` BECAUSE A VENDOR SCHEMA IS CHECKED LIVE.** It reached
// this tool through an LLM, which could mistranscribe it or be fed a fake one;
// but the MCP driver compares every vendor schema in a vetted spec against the
// server's own `tools/list` and gates readiness on it (§4.9a.7). A wrong copy
// fails loudly as drift. What D168 forbade — a GUESS posing as the vendor's word
// — still cannot happen: provenance follows the KIND OF INPUT, and no flag or
// parameter chooses it.
func DraftAdvertised(tool, outputType string, advertised json.RawMessage, opts ...jsonref.Option) (Fragment, error) {
	if tool == "" || outputType == "" {
		return Fragment{}, fmt.Errorf("both a tool name and an output type are required")
	}
	var schema map[string]any
	if err := json.Unmarshal(advertised, &schema); err != nil || schema == nil {
		return Fragment{}, fmt.Errorf("the advertised outputSchema is not a JSON object: %v", err)
	}
	return fragment(tool, outputType, "vendor", schema, 0, nil,
		"COPIED from the tools/list entry an agent supplied. Marked vendor because it is the "+
			"vendor's: the MCP driver checks it against the server's live tools/list, so a copy "+
			"that differs from what the server advertises fails as drift (§4.9a.7)", opts...)
}

// fragment renders both schemas and the list from ONE output schema: the
// data_schema is its closed subset, and the list walks the data_schema — so
// nothing is inferred twice (P3 step 28).
func fragment(tool, outputType, origin string, outputSchema map[string]any, results int,
	warnings []string, whence string, opts ...jsonref.Option) (Fragment, error) {

	// THE DATA SCHEMA IS DRAWN FROM THE EXPANSION, THE OUTPUT SCHEMA IS NOT
	// (D306). Local references are expanded so the fields they describe are
	// admitted — before D306 each became an EMPTY object and a compute tool's
	// numbers were stripped at the closed boundary. The output schema stays
	// exactly as copied, references and all, because the drift check compares
	// it with what the server advertises.
	source := outputSchema
	if expanded, err := jsonref.Expand(outputSchema, opts...); err != nil {
		warnings = append(warnings, fmt.Sprintf("data_schema: the output schema's references "+
			"could not be expanded (%v); every field under one is drafted as an EMPTY object", err))
	} else {
		source = expanded
	}
	var dataWarnings []string
	data := closedSubset(source, "", &dataWarnings)
	warnings = append(warnings, dataWarnings...)

	outBody, err := json.MarshalIndent(outputSchema, "", "  ")
	if err != nil {
		return Fragment{}, fmt.Errorf("rendering the output schema: %w", err)
	}
	dataBody, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return Fragment{}, fmt.Errorf("rendering the data schema: %w", err)
	}

	var b strings.Builder
	b.WriteString("# Drafted by sekizui-mcpspec — VET BEFORE USE.\n")
	fmt.Fprintf(&b, "# output_schema: the MCP's output contract, %s.\n", whence)
	b.WriteString("# data_schema: what this connector may PROVIDE to Sekizui (D279) — the closed\n")
	b.WriteString("# allowlist shin, anzen and every reflex work from. Narrow it to what you need.\n")
	fmt.Fprintf(&b, "- name: %s\n", tool)
	fmt.Fprintf(&b, "  output_type: %s\n", outputType)
	fmt.Fprintf(&b, "  output_schema_origin: %s\n", origin)
	// THE SAFE ANSWER, DRAFTED (D323): on a target sharing a budget with native
	// ones the relation is required, and a reviewer narrows it only where they
	// know what the tool reaches. On an unlinked target it changes nothing.
	b.WriteString("  native: [opaque]\n")
	b.WriteString("  output_schema: |\n")
	indent(&b, outBody)
	b.WriteString("  data_schema: |\n")
	indent(&b, dataBody)

	return Fragment{
		List:     renderList(tool, outputType, listSource(origin, results), data),
		YAML:     b.String(),
		Warnings: warnings,
		// ON THE TERMINAL RATHER THAN IN A COMMENT. A comment in the emitted
		// YAML is easy to paste past; a line whoever ran the command reads is
		// read by the person who still has to answer this.
		Obligations: "YOU MUST STILL SET `mutating`, and `idempotency` if it is mutating — this " +
			"tool cannot, because MCP's readOnlyHint and destructiveHint are the vendor's word and " +
			"those two fields drive the retry gate and audit-as-external-effect (§4.9a.1, D163). " +
			"`native` is drafted [opaque], the safe answer; narrow it to the native actions the tool " +
			"mirrors, or [none], only if you know (D323).",
	}, nil
}

func indent(b *strings.Builder, body []byte) {
	for _, line := range strings.Split(string(body), "\n") {
		fmt.Fprintf(b, "    %s\n", line)
	}
}

// closedSubset is the data_schema drawn from an output schema (D287) — since
// D314 the ONE converter in internal/schemasubset, shared with the connectors
// that derive data schemas from vendor contracts, so a vendor schema is reduced
// to what schemareg enforces one way everywhere.
func closedSubset(schema map[string]any, path string, warnings *[]string) map[string]any {
	return schemasubset.Closed(schema, path, warnings)
}

// Observation is what the agent piped, recognised (D287).
type Observation struct {
	// Advertised is the tool's outputSchema, when a tools/list entry that
	// carries one was piped. Draft it with DraftAdvertised.
	Advertised json.RawMessage

	// Samples are a tool RESULT's payloads, when a result was piped. Draft
	// them with Draft.
	Samples []any

	// Raw is the input, for WarnOnSize.
	Raw []byte

	// Warnings are what the reader set aside (a non-text content block).
	Warnings []string
}

// ReadObservation reads what the user's agent piped: a `tools/list` entry (or
// the whole `tools/list` result, narrowed to `tool`) or a `tools/call` result
// (D287).
//
// **THE AGENT CALLS THE MCP; THIS TOOL NEVER DOES.** The user's agent already
// holds the connection, the credential and a permission prompt per call, so
// the human's choice of tool happens there — and a CLI that authenticated to
// the server itself would be holding the very credential Sekizui exists to
// govern (P3 step 26 asserts it cannot dial).
//
// **RAW MCP JSON ONLY, AND PROSE IS REFUSED.** The result reaches this tool
// through an LLM that re-emits it, which can drop or invent fields; an agent
// PARAPHRASING a result is that at its worst, so anything that is not the
// protocol's own shape is refused rather than guessed at.
//
// **SEVERAL JSON BLOCKS ARE REFUSED UNLESS `combine` SAYS HOW TO JOIN THEM**
// (D289) — the rule the driver applies to the same result. This used to treat
// each block as a separate SAMPLE, drafting their union, while the driver joined
// them and failed to parse: a draft of a shape nothing would ever deliver.
// `combine == "items"` drafts `{items: [...]}`, exactly what the driver delivers.
func ReadObservation(r io.Reader, tool, combine string) (Observation, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Observation{}, fmt.Errorf("reading stdin: %w", err)
	}
	obs := Observation{Raw: raw}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil || v == nil {
		return Observation{}, fmt.Errorf("stdin is not a JSON object. Pipe the MCP's raw JSON — a " +
			"tools/list entry, or a tools/call result — not a description of it: an agent " +
			"paraphrasing a result drops and invents fields")
	}

	// A whole tools/list result: narrow to the named tool.
	if tools, ok := v["tools"].([]any); ok {
		for _, t := range tools {
			if entry, ok := t.(map[string]any); ok && entry["name"] == tool {
				v = entry
				break
			}
		}
		if v["name"] != tool {
			return Observation{}, fmt.Errorf("the tools/list result names no tool %q", tool)
		}
	}

	switch {
	case v["inputSchema"] != nil && v["name"] != nil:
		if v["name"] != tool {
			return Observation{}, fmt.Errorf("the piped tools/list entry is %q, not -tool %q", v["name"], tool)
		}
		out, has := v["outputSchema"]
		if !has {
			return Observation{}, fmt.Errorf("%q advertises no outputSchema, so there is nothing to "+
				"copy. Have your agent CALL the tool and pipe the result instead: its shape is then "+
				"inferred, and the draft is marked local", tool)
		}
		obs.Advertised, err = json.Marshal(out)
		return obs, err

	case v["isError"] == true:
		return Observation{}, fmt.Errorf("the piped result is an ERROR (isError: true); its shape " +
			"is the error's, not the tool's output")

	case v["structuredContent"] != nil:
		obs.Samples = []any{v["structuredContent"]}
		return obs, nil

	case v["content"] != nil:
		blocks, _ := v["content"].([]any)
		for i, b := range blocks {
			block, _ := b.(map[string]any)
			if block["type"] != "text" {
				obs.Warnings = append(obs.Warnings, fmt.Sprintf("content block %d is %v, not text; "+
					"set aside", i, block["type"]))
				continue
			}
			text, _ := block["text"].(string)
			var parsed any
			if json.Unmarshal([]byte(text), &parsed) == nil {
				if _, isObj := parsed.(map[string]any); isObj {
					obs.Samples = append(obs.Samples, parsed)
					continue
				}
				if _, isArr := parsed.([]any); isArr {
					obs.Samples = append(obs.Samples, parsed)
					continue
				}
			}
			obs.Warnings = append(obs.Warnings, fmt.Sprintf("content block %d is text that is not "+
				"JSON; it has no fields to draft, set aside", i))
		}
		if len(obs.Samples) == 0 {
			return Observation{}, fmt.Errorf("the result's content holds no JSON — only text a " +
				"schema cannot describe. A tool that returns prose has no fields for Sekizui to admit")
		}
		if len(obs.Samples) > 1 {
			if combine != "items" {
				return Observation{}, fmt.Errorf("the result holds %d JSON text blocks. They are one "+
					"payload only by declaration: re-run with -combine items to draft {items: [...]}, "+
					"which is what the driver delivers for a spec with `combine: items` (D289)",
					len(obs.Samples))
			}
			obs.Samples = []any{map[string]any{"items": obs.Samples}}
		}
		return obs, nil
	}
	return Observation{}, fmt.Errorf("stdin is neither a tools/list entry (name, inputSchema) nor " +
		"a tools/call result (content or structuredContent)")
}

// listSource says where the listed fields came from, in the list's own header.
func listSource(origin string, results int) string {
	if origin == originLocal {
		return fmt.Sprintf("inferred from %d tool result(s) an AGENT supplied — UNVERIFIED", results)
	}
	return "from the outputSchema the server ADVERTISES, copied — drift-checked live"
}
