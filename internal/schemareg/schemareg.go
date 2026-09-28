// Package schemareg is the payload schema registry (D40).
//
// PRIVATE (D35).
//
// SCHEMAS ARE DATA, NOT CODE — and since D279 they have OWNERS. A type a
// connector emits is declared by that connector, shipped in its package; a type
// the deployment itself produces (a reflex's enrichment) is declared in the
// document; one type, one owner, and the registry refuses a second. No protobuf
// change, no codegen, no redeploy of core — which is what keeps the migration
// treadmill from ever starting (§12 P0).
//
// CLOSED BY DEFAULT (D279). Unlike JSON Schema, an object admits only the
// properties its schema names; `Shape` strips the rest at ingest, recursively,
// and `Validate` refuses what `Shape` would have removed. An object that should
// admit anything says `additionalProperties: true`, deliberately.
//
// A DELIBERATE SUBSET OF JSON SCHEMA, and the subset is the interesting part.
// `type`, `properties`, `required`, and `additionalProperties` are supported.
// `oneOf`, `anyOf`, and `allOf` are REFUSED rather than ignored — see
// Validate's doc comment for why refusing beats best-effort here. A LOCAL
// `$ref` (`#/$defs/<name>`) is EXPANDED at load by internal/jsonref (D306), so
// every walker below still reads a reference-free tree; a remote reference or a
// cycle refuses.
//
// No JSON Schema library, for the same reason P0 has no Rego (D58): the subset
// that P0 needs is small enough to read in one sitting, and D44's compatibility
// checker will need to introspect schemas structurally anyway. A library is
// worth taking on when something needs what it does.
//
// DESIGN.md references: §4.6.1a, §4.6.1b, §4.6.1c, §12 P0, D40, D41, D42, D44.
package schemareg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/internal/jsonref"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// unsupported are the JSON Schema keywords this checker cannot traverse.
//
// REFUSED, NOT IGNORED. A schema using `oneOf` has more than one valid shape, so
// "does field X exist" has no single answer — and answering "yes" from whichever
// branch happens to contain it would make D42's boot validation report success
// for a rule that fails at runtime. Silence is the failure mode D42 exists to
// prevent, so the checker refuses the schema instead of guessing about it.
//
// This resolves the risk §12 flagged as highest ("may be infeasible with oneOf /
// $ref cycles"): D42 holds for schemas this can traverse, and says so loudly for
// schemas it cannot, rather than softening to a warning everywhere.
var unsupported = []string{"$ref", "oneOf", "anyOf", "allOf", "not", "if"} //nolint:gochecknoglobals // immutable keyword list

// Schema is the parsed subset.
type Schema struct {
	Type                 string             `json:"type"`
	Properties           map[string]*Schema `json:"properties"`
	Required             []string           `json:"required"`
	AdditionalProperties *bool              `json:"additionalProperties"`
	Items                *Schema            `json:"items"`

	// CallerOnly marks a field returned to the caller who asked and NEVER
	// recorded (D289) — Fullstory's seven-day signed screenshot URL, a bearer
	// link to customer imagery. ENFORCED by the gateway, not an annotation:
	// the recorded copy carries a trace (the field's name and a hash, never the
	// value), and the value is scrubbed from every other string in that record,
	// because a text result carries it too. Top-level properties only.
	CallerOnly bool `json:"callerOnly,omitempty"`

	// Format is `date-time` or absent (D300, D317). ENFORCED, not annotated
	// (D278): a value that does not parse as RFC 3339 fails validation, and
	// any other format is refused at load. It exists because a `refines:`
	// rule sorts rows by time and pairs them within seconds, so the input type
	// must say WHICH field is time and promise it parses — the engine treats
	// an unparseable time as an error, never as a false (D42).
	Format string `json:"format,omitempty"`

	// ANNOTATIONS, accepted and ignored: they describe, and claim no
	// enforcement. Every OTHER keyword is refused at load (D278) — see
	// decodeSchema.
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Comment     string `json:"$comment,omitempty"`
	Examples    []any  `json:"examples,omitempty"`
}

// decodeSchema parses a schema REFUSING every keyword this checker does not
// enforce (D278).
//
// **A KEYWORD THAT LOOKS ENFORCED AND IS NOT IS WORSE THAN NONE.** `enum`,
// `pattern`, `minimum`, `format`… were decoded into nothing and skipped, so a
// schema declaring `enum: [a, b]` passed `c` — and a reviewer reading it saw a
// constraint the system never applied. The same holds for a TYPO
// (`additonalProperties: false`), which silently left the schema open.
func decodeSchema(label string, body []byte, into *Schema) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("schema %q: %v — this checker enforces type, properties, required, "+
			"additionalProperties, items, callerOnly and format (date-time only), and accepts title, "+
			"description, $comment and examples as annotations; any other keyword would read as a "+
			"constraint nobody applies (D278)", label, err)
	}
	return checkFormats(label, into, "")
}

// FormatDateTime is the one `format` this checker enforces (D317).
const FormatDateTime = "date-time"

// checkFormats refuses a `format` the checker would not enforce, and one on a
// field that is not a string.
func checkFormats(label string, s *Schema, path string) error {
	if s == nil {
		return nil
	}
	if s.Format != "" && (s.Format != FormatDateTime || s.Type != "string") {
		return fmt.Errorf("schema %q: %s declares format %q on type %q — only `format: date-time` on "+
			"a string is enforced, and any other would read as a constraint nobody applies (D278)",
			label, at(path), s.Format, s.Type)
	}
	for name, sub := range s.Properties {
		if err := checkFormats(label, sub, join(path, name)); err != nil {
			return err
		}
	}
	return checkFormats(label, s.Items, path+"[]")
}

// Registry holds the schemas in force.
type Registry struct {
	byType map[string]*Schema

	// owner is who declared each type: a connector's kind, or "" for the
	// deployment document (D279).
	owner map[string]string

	// kinds holds the discriminated types (D276): which field is the kind,
	// which field it shapes, and one schema per declared kind.
	kinds map[string]kindFamily

	// quarantined: connector kind -> why (D282). quarantinedTypes: a type a
	// quarantined connector declares -> that connector.
	quarantined      map[string]string
	quarantinedTypes map[string]string

	// schemaFaults and meterFaults are the two halves of a quarantine (D284),
	// kept apart so each conformance arm reports its own half of ONE verdict
	// rather than re-deriving it. `quarantined` is their join.
	schemaFaults map[string]string
	meterFaults  map[string][]string
}

type kindFamily struct {
	discriminator, properties string
	schemas                   map[string]*Schema
	freeText                  []string
	keepFreeText              map[string][]string // kind -> the free-text fields it keeps

	// What a kind NOT in schemas becomes (D277, D279): refused (both nil),
	// reduced to a skeleton, or admitted under `open`.
	skeleton     *connector.Skeleton
	open         *Schema
	openFreeText []string
}

// ForDeployment builds the registry a deployment validates against (D279): the
// schemas every connector ships for the types it emits, and the document's own
// schemas for the types the deployment produces. One constructor for boot, the
// runner, the engine, the gateway and the tap.
//
// **A CONNECTOR'S FAULT QUARANTINES THAT CONNECTOR, NOT THE DEPLOYMENT (D282).**
// A declared type with no schema from its connector, schemas that do not parse
// or do not load, a schema for a type none of its actions declares, a type two
// connectors both claim: each is the CONNECTOR's packaging defect, and it
// quarantines that connector — none of its types is registered, so nothing it
// emits can enter, and `Quarantined` names it and why for the gateway to refuse
// its targets. Every other connector serves. One connector's packaging mistake
// no longer takes the whole deployment down with it.
//
// **AN UNSOUND METER QUARANTINES HERE TOO (D284), SO THERE IS ONE VERDICT.** It
// was merged into the boot's quarantine map afterwards, in `main` — which
// refused the connector's targets while leaving its TYPES registered, so the
// gateway and the registry answered "is this connector in service" differently.
// Decided here, a connector whose calls cannot be priced is dropped whole,
// exactly as one whose schemas are unsound.
//
// **A DOCUMENT'S FAULT STILL REFUSES THE BOOT**, as all configuration does: a
// document schema that does not load, or one declaring a type a connector owns
// — the deployment protects consumers with shin and anzen, it does not rewrite
// what a connector says exists.
func ForDeployment(doc *config.Document, drivers map[string]connector.Driver) (*Registry, error) {
	const op = "schemareg.ForDeployment"
	r, err := New(doc.PayloadSchemas)
	if err != nil {
		return nil, err
	}
	r.quarantined, r.quarantinedTypes = map[string]string{}, map[string]string{}
	r.schemaFaults, r.meterFaults = map[string]string{}, map[string][]string{}

	kinds := make([]string, 0, len(drivers))
	for k := range drivers {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)

	// PASS 1: each connector on its own, into a scratch registry, so a
	// connector that fails is dropped WHOLE rather than half-registered.
	scratch := map[string]*Registry{}
	var docProblems []string
	for _, kind := range kinds {
		d := drivers[kind]
		declared := map[string]string{} // type -> what declares it: "action X" or "refines rule R"
		for _, a := range d.Actions() {
			for _, t := range a.DeclaredOutputs() {
				declared[t] = fmt.Sprintf("action %q", a.Name)
			}
		}
		var problems []string
		// A CONNECTOR'S REFINES RULES EMIT ITS SEIREN TYPES (D299, D317): a type a
		// rule writes `into` is declared as surely as an action's output — the
		// connector ships it in the same schemas.yaml, one type one owner — and a
		// rule may only READ a type this connector's actions declare, because a
		// rule over another connector's type has no single owner and belongs to
		// the deployment (D299). Rules that do not parse are the connector's
		// packaging defect, and quarantine it like unsound schemas (D282).
		if rf, ok := d.(connector.Refiner); ok {
			rules, rerr := config.ParseReflexes(rf.Reflexes())
			if rerr != nil {
				problems = append(problems, fmt.Sprintf("its reflexes.yaml does not load: %v", rerr))
			}
			actionTypes := make(map[string]bool, len(declared))
			for t := range declared {
				actionTypes[t] = true
			}
			for _, rule := range rules {
				if !actionTypes[rule.Refines] {
					problems = append(problems, fmt.Sprintf("refines rule %q reads %q, which none of its "+
						"actions returns — a connector's rule refines the connector's own results (D299)",
						rule.Name, rule.Refines))
				}
				if !strings.HasPrefix(rule.Name, kind+".") {
					problems = append(problems, fmt.Sprintf("refines rule %q is not named under %q; a "+
						"deployment names rules across connectors, so each is prefixed with its kind",
						rule.Name, kind+"."))
				}
				declared[rule.Into] = fmt.Sprintf("refines rule %q", rule.Name)
			}
		}
		tmp := &Registry{byType: map[string]*Schema{}, owner: map[string]string{}, kinds: map[string]kindFamily{}}
		schemas, err := d.Schemas()
		if err != nil {
			problems = append(problems, fmt.Sprintf("its schemas do not parse: %v", err))
		}
		shipped := map[string]bool{}
		for _, sc := range schemas {
			shipped[sc.Type] = true
			switch {
			case r.Has(sc.Type):
				docProblems = append(docProblems, fmt.Sprintf("the document declares payload schema %q, "+
					"which connector %q owns; a deployment does not declare or narrow a connector's types — "+
					"lens what consumers see with shin (D279)", sc.Type, kind))
			case declared[sc.Type] == "":
				problems = append(problems, fmt.Sprintf("it ships a schema for %q, which none of its "+
					"actions declares and none of its refines rules writes — a declaration of something it "+
					"never emits", sc.Type))
			default:
				problems = append(problems, tmp.addConnectorSchema(kind, sc)...)
			}
		}
		for t, action := range declared {
			if !strings.Contains(t, ".v") {
				problems = append(problems, fmt.Sprintf("%s: output type %q has no version "+
					"suffix; types are versioned (D41)", action, t))
			}
			if !shipped[t] && err == nil {
				problems = append(problems, fmt.Sprintf("it declares output type %q (%s) and "+
					"ships NO SCHEMA for it. A connector ships the schema of everything it emits — "+
					"embed it beside the driver and return it from Schemas() (D279); for an MCP tool, "+
					"its vetted spec's data_schema", t, action))
			}
		}
		for t := range declared {
			r.quarantinedTypes[t] = kind // provisional; cleared below for a healthy connector
		}
		meter := connector.CheckMeter(d)
		if len(meter) > 0 {
			r.meterFaults[kind] = meter
		}
		if len(problems) > 0 || len(meter) > 0 {
			sort.Strings(problems)
			why := strings.Join(problems, "; ")
			if why != "" {
				r.schemaFaults[kind] = why
			}
			if len(meter) > 0 {
				if why != "" {
					why += "; "
				}
				why += "its meter is not sound: " + strings.Join(meter, "; ")
			}
			r.quarantined[kind] = why
			continue
		}
		scratch[kind] = tmp
	}
	if len(docProblems) > 0 {
		sort.Strings(docProblems)
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%d payload schema problem(s):\n  - %s", len(docProblems), strings.Join(docProblems, "\n  - ")))
	}

	// PASS 2: A TYPE TWO CONNECTORS CLAIM quarantines BOTH. Neither is more
	// right than the other, and letting the first in path order win would make
	// a filename decide what a type means.
	claimed := map[string][]string{}
	for _, kind := range kinds {
		if tmp, ok := scratch[kind]; ok {
			for t := range tmp.byType {
				claimed[t] = append(claimed[t], kind)
			}
		}
	}
	for t, owners := range claimed {
		if len(owners) > 1 {
			for _, kind := range owners {
				r.schemaFaults[kind] = fmt.Sprintf("type %q is claimed by connectors %v; one type, one "+
					"owner (D279)", t, owners)
				r.quarantined[kind] = r.schemaFaults[kind]
				delete(scratch, kind)
			}
		}
	}

	// PASS 3: register the healthy connectors.
	for kind, tmp := range scratch {
		for t, body := range tmp.byType {
			r.byType[t], r.owner[t] = body, kind
			delete(r.quarantinedTypes, t)
		}
		for t, fam := range tmp.kinds {
			r.kinds[t] = fam
		}
	}
	for t, kind := range r.quarantinedTypes {
		if _, q := r.quarantined[kind]; !q {
			delete(r.quarantinedTypes, t)
		}
	}
	return r, nil
}

// Quarantined names the connectors ForDeployment refused, and why (D282). The
// gateway refuses their targets; the boot, readiness and the
// `connector_quarantined` signal say so.
func (r *Registry) Quarantined() map[string]string {
	out := make(map[string]string, len(r.quarantined))
	for k, v := range r.quarantined {
		out[k] = v
	}
	return out
}

// CallerOnly names the top-level fields of typ marked callerOnly (D289), sorted —
// what the gateway withholds from the recorded copy of a result of that type.
func (r *Registry) CallerOnly(typ string) []string {
	s, ok := r.byType[typ]
	if !ok {
		return nil
	}
	var out []string
	for name, p := range s.Properties {
		if p != nil && p.CallerOnly {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// QuarantineOf splits one connector's verdict into its two halves — what is
// wrong with its schemas, and what is wrong with its meter — for the published
// conformance suite, whose arms each report one. Both empty: in service.
func (r *Registry) QuarantineOf(kind string) (schemaFaults string, meterFaults []string) {
	return r.schemaFaults[kind], r.meterFaults[kind]
}

// QuarantinedBy reports the quarantined connector that declares typ, if any —
// so a rule or lens naming it is reported as INERT while its connector is
// quarantined, rather than failing the boot the quarantine exists to keep up.
func (r *Registry) QuarantinedBy(typ string) (string, bool) {
	kind, ok := r.quarantinedTypes[typ]
	return kind, ok
}

// addConnectorSchema registers one connector-owned type and, if it is a
// family, its kinds — checked at load like every schema.
func (r *Registry) addConnectorSchema(owner string, sc connector.Schema) []string {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	if !strings.Contains(sc.Type, ".v") {
		add("connector %q: type %q has no version suffix (D41)", owner, sc.Type)
	}
	expanded, err := admit(sc.Type, sc.Body)
	if err != nil {
		return append(problems, err.Error())
	}
	var body Schema
	if err := decodeSchema(sc.Type, expanded, &body); err != nil {
		return append(problems, err.Error())
	}
	r.byType[sc.Type], r.owner[sc.Type] = &body, owner
	if sc.Family == nil {
		return problems
	}
	f, typ := sc.Family, sc.Type
	// EVERY FIELD A FAMILY NAMES IS TOP-LEVEL AND EXISTS: shaping removes and
	// rebuilds them, and a family keyed on a field the type does not have would
	// refuse every event.
	field := func(role, name string) {
		switch {
		case name == "":
			add("%s: family names no %s field", typ, role)
		case strings.Contains(name, "."):
			add("%s: family %s %q must be a top-level field", typ, role, name)
		case body.Properties[name] == nil:
			add("%s: family %s %q is not a field of the type", typ, role, name)
		}
	}
	field("discriminator", f.Discriminator)
	field("properties", f.Properties)
	for _, ft := range f.FreeText {
		field("free_text", ft)
		if ft == f.Discriminator || ft == f.Properties {
			add("%s: free_text %q is also the discriminator or the properties field", typ, ft)
		}
	}
	if len(f.Kinds) == 0 {
		add("%s: family declares no kinds", typ)
	}
	fam := kindFamily{discriminator: f.Discriminator, properties: f.Properties, freeText: f.FreeText,
		schemas: map[string]*Schema{}, keepFreeText: map[string][]string{}}
	kindSchema := func(label string, k connector.Kind) *Schema {
		if len(k.Schema) == 0 {
			add("kind %q: has no schema; write `schema: {type: object}` to admit no properties", label)
			return nil
		}
		for _, ft := range k.KeepFreeText {
			if !slices.Contains(f.FreeText, ft) {
				add("kind %q: keep_free_text names %q, which is not one of the family's free_text "+
					"fields %v — a typo here would read as a review that never happened", label, ft, f.FreeText)
			}
		}
		expanded, err := admit(label, k.Schema)
		if err != nil {
			add("%v", err)
			return nil
		}
		var ks Schema
		if err := decodeSchema(label, expanded, &ks); err != nil {
			add("%v", err)
			return nil
		}
		return &ks
	}
	for kind, k := range f.Kinds {
		if ks := kindSchema(typ+"#"+kind, k); ks != nil {
			fam.schemas[kind], fam.keepFreeText[kind] = ks, k.KeepFreeText
		}
	}
	if o := f.Other; o != nil {
		switch {
		case (o.Skeleton == nil) == (o.Open == nil):
			add("%s: family `other` sets exactly one of skeleton or open", typ)
		case o.Skeleton != nil:
			u := o.Skeleton
			// THE SKELETON IS AN ALLOWLIST, AND IT MAY NOT ADMIT CONTENT (D277).
			if !slices.Contains(u.Keep, f.Discriminator) {
				add("%s: the skeleton omits the discriminator %q, so a reduced event could not say "+
					"what kind it was", typ, f.Discriminator)
			}
			for _, k := range u.Keep {
				field("skeleton.keep", k)
				if k == f.Properties || slices.Contains(f.FreeText, k) {
					add("%s: the skeleton keeps %q, which carries content nobody reviewed", typ, k)
				}
			}
			field("skeleton.mark", u.Mark)
			if m := body.Properties[u.Mark]; u.Mark != "" && (m == nil || m.Type != "boolean") {
				add("%s: skeleton.mark %q must be a boolean field of the type", typ, u.Mark)
			}
			if slices.Contains(u.Keep, u.Mark) {
				add("%s: skeleton.mark %q is also kept", typ, u.Mark)
			}
			fam.skeleton = u
		default:
			fam.open, fam.openFreeText = kindSchema(typ+"#(other)", *o.Open), o.Open.KeepFreeText
		}
	}
	r.kinds[typ] = fam
	return problems
}

// Shaped says what Shape did to one payload (D277, D279).
type Shaped struct {
	// Kind is the discriminator's value; empty for a type with no kinds.
	Kind string
	// Undeclared: the family does not declare Kind. Then exactly one of:
	// Withheld (reduced to the skeleton), Open (admitted under `other.open`),
	// or neither — an event to refuse.
	Undeclared, Withheld, Open bool
	// Stripped are the dotted paths removed because no schema declares them;
	// FreeText is set when free-text fields were removed.
	Stripped []string
	FreeText bool
}

// Refused reports whether the event must not be published at all.
func (s Shaped) Refused() bool { return s.Undeclared && !s.Withheld && !s.Open }

// Shape reduces a payload to what its declaration admits (D277, D279), before
// it is validated or published — for EVERY type, not only families:
//
//   - every object keeps only the properties its schema names, recursively,
//     unless the schema says `additionalProperties: true`;
//   - a family's properties field is shaped by the KIND's schema, and its
//     free-text fields survive only for a kind that keeps them;
//   - a kind the family does not declare becomes its skeleton, is admitted
//     under `other.open`, or is returned as it came and reported, to be refused.
//
// **AN ALLOWLIST AT INGEST, NOT A LENS AT DELIVERY.** What is stripped here
// never reaches the bus, the recorder or a rule. A lens decides what a consumer
// sees; this decides what exists. An unregistered type is returned unchanged,
// for Validate to refuse. The input is not modified.
func (r *Registry) Shape(typ string, payload map[string]any) (map[string]any, Shaped) {
	s, ok := r.byType[typ]
	if !ok {
		return payload, Shaped{}
	}
	var shaped Shaped
	fam, isFamily := r.kinds[typ]
	if !isFamily {
		out, _ := shapeValue(s, payload, "", &shaped.Stripped).(map[string]any)
		sort.Strings(shaped.Stripped)
		return out, shaped
	}
	kind, _ := payload[fam.discriminator].(string)
	shaped.Kind = kind
	ks, keep := fam.schemas[kind], fam.keepFreeText[kind]
	if ks == nil {
		shaped.Undeclared = true
		switch {
		case fam.skeleton != nil:
			out := map[string]any{fam.skeleton.Mark: true}
			for _, f := range fam.skeleton.Keep {
				if v, ok := payload[f]; ok {
					out[f] = v
				}
			}
			shaped.Withheld = true
			return out, shaped
		case fam.open != nil:
			ks, keep, shaped.Open = fam.open, fam.openFreeText, true
		default:
			return payload, shaped
		}
	}
	rest := make(map[string]any, len(payload))
	for k, v := range payload {
		if k != fam.properties {
			rest[k] = v
		}
	}
	out, _ := shapeValue(s, rest, "", &shaped.Stripped).(map[string]any)
	if props, present := payload[fam.properties]; present {
		out[fam.properties] = shapeValue(ks, props, fam.properties, &shaped.Stripped)
	}
	for _, f := range fam.freeText {
		if _, present := out[f]; present && !slices.Contains(keep, f) {
			delete(out, f)
			shaped.FreeText = true
		}
	}
	sort.Strings(shaped.Stripped)
	return out, shaped
}

// shapeValue is the closed-by-default allowlist, recursively. An array with no
// `items` schema keeps its scalars and admits no property of an object inside
// it — closed means closed at every depth.
func shapeValue(s *Schema, v any, path string, stripped *[]string) any {
	switch val := v.(type) {
	case map[string]any:
		open := s.AdditionalProperties != nil && *s.AdditionalProperties
		out := make(map[string]any, len(val))
		for k, x := range val {
			sub, declared := s.Properties[k]
			switch {
			case declared:
				out[k] = shapeValue(sub, x, join(path, k), stripped)
			case open:
				out[k] = x
			default:
				*stripped = append(*stripped, join(path, k))
			}
		}
		return out
	case []any:
		items := s.Items
		if items == nil {
			items = &Schema{}
		}
		out := make([]any, len(val))
		for i, x := range val {
			out[i] = shapeValue(items, x, fmt.Sprintf("%s[%d]", path, i), stripped)
		}
		return out
	default:
		return v
	}
}

// AdmitsOtherKinds reports whether a family publishes kinds it does not
// declare — as a skeleton or open — so a rule naming one is not waiting for
// something that can never arrive.
func (r *Registry) AdmitsOtherKinds(typ string) bool {
	fam, ok := r.kinds[typ]
	return ok && (fam.skeleton != nil || fam.open != nil)
}

// Kinds reports a discriminated type's discriminator field and declared kinds.
func (r *Registry) Kinds(typ string) (discriminator string, kinds []string, ok bool) {
	fam, ok := r.kinds[typ]
	if !ok {
		return "", nil, false
	}
	for k := range fam.schemas {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return fam.discriminator, kinds, true
}

// New parses a document's payload schemas.
//
// Every schema is parsed and checked at LOAD time, not at first use. A malformed
// schema discovered on the first matching event is a schema that broke a
// production path; discovered at boot it is a config error with a name attached.
func New(raw map[string]json.RawMessage) (*Registry, error) {
	const op = "schemareg.New"

	r := &Registry{byType: make(map[string]*Schema, len(raw)), owner: map[string]string{},
		kinds: map[string]kindFamily{}}
	var problems []string

	for typ, body := range raw {
		expanded, err := admit(typ, body)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		var s Schema
		if err := decodeSchema(typ, expanded, &s); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		// D41: the type string carries its version — "fullstory.rage_click.v1".
		// A schema registered under an unversioned type cannot participate in
		// the dual-publish migration that makes most changes non-events.
		if !strings.Contains(typ, ".v") {
			problems = append(problems, fmt.Sprintf(
				"schema %q has no version suffix; types are versioned (D41), e.g. "+
					"%q — dual-publish migration depends on v1 and v2 being distinct types",
				typ, typ+".v1"))
		}
		r.byType[typ] = &s
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%d schema problem(s):\n  - %s", len(problems), strings.Join(problems, "\n  - ")))
	}
	return r, nil
}

// admit expands a schema's LOCAL references (D306) and then refuses what is
// left that this checker cannot traverse. It returns the body to decode: the
// expansion, or the original bytes unchanged when the schema has no `$ref`.
//
// EXPAND FIRST, THEN SCAN: the textual scan below would otherwise refuse every
// `$ref`, including the local ones the expansion removes; and scanning the
// expansion is what still catches a `oneOf` hiding inside a definition.
func admit(typ string, body []byte) ([]byte, error) {
	expanded, err := jsonref.ExpandJSON(body)
	if err != nil {
		return nil, fault.New(fault.KindConfig, "schemareg.New", fmt.Sprintf(
			"schema %q: %v. Point the reference at a whole definition under the schema's own "+
				"$defs, or Flatten the schema", typ, err))
	}
	if err := rejectUnsupported(typ, expanded); err != nil {
		return nil, err
	}
	return expanded, nil
}

// rejectUnsupported scans the raw JSON for keywords the checker cannot handle.
//
// Textual rather than structural, deliberately: the keyword may be nested
// arbitrarily deep, and a structural walk would need to parse the very
// constructs it is looking for.
func rejectUnsupported(typ string, body []byte) error {
	text := string(body)
	for _, keyword := range unsupported {
		if strings.Contains(text, `"`+keyword+`"`) {
			return fault.New(fault.KindConfig, "schemareg.New", fmt.Sprintf(
				"schema %q uses %q, which this checker cannot traverse. D42 validates that "+
					"every field path a reflex references exists in its schema, and a schema "+
					"with more than one valid shape has no single answer to that — reporting "+
					"success from whichever branch happened to match would make a rule pass "+
					"boot validation and fail at runtime, which is the silence D42 exists to "+
					"prevent. Flatten the schema, or split it into versioned types (D41)",
				typ, keyword))
		}
	}
	return nil
}

// Has reports whether a type is registered.
func (r *Registry) Has(typ string) bool {
	_, ok := r.byType[typ]
	return ok
}

// Types returns every registered type, sorted.
func (r *Registry) Types() []string {
	out := make([]string, 0, len(r.byType))
	for t := range r.byType {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Validate checks a payload against its registered schema — §4.6.1a's
// "publish-time validation against the registered schema means dynamic payloads
// are still CHECKED payloads".
//
// An UNREGISTERED type is an error, not a pass. Publishing an event nobody
// declared is how a payload shape enters the system without anyone reviewing
// it, which is the same hole D46 closes for MCP tools.
func (r *Registry) Validate(typ string, payload map[string]any) error {
	const op = "schemareg.Validate"

	s, ok := r.byType[typ]
	if !ok {
		return fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"payload type %q has no registered schema; known types are %v", typ, r.Types()))
	}

	var problems []string
	fam, isFamily := r.kinds[typ]
	if !isFamily {
		validate(s, payload, "", &problems)
	} else {
		// A DISCRIMINATED TYPE IS CHECKED TWICE (D276): the type's own fields
		// against the type, and the properties against the kind's schema — the
		// type's `{type: object}` for that field would otherwise read every
		// property as undeclared.
		rest := make(map[string]any, len(payload))
		for k, v := range payload {
			if k != fam.properties {
				rest[k] = v
			}
		}
		kind, _ := payload[fam.discriminator].(string)
		ks, keep := fam.schemas[kind], fam.keepFreeText[kind]
		switch {
		case ks == nil && fam.skeleton != nil && payload[fam.skeleton.Mark] == true:
			// A SKELETON (D277): valid only if it holds nothing but the kept
			// fields and the mark. Anything else means it was not shaped.
			for k := range payload {
				if k != fam.skeleton.Mark && !slices.Contains(fam.skeleton.Keep, k) {
					problems = append(problems, fmt.Sprintf("%s: a withheld %q event carries %q, "+
						"which its skeleton does not keep (D277)", k, kind, k))
				}
			}
			ks = nil
		case ks == nil && fam.open != nil:
			ks, keep = fam.open, fam.openFreeText
		case ks == nil:
			problems = append(problems, fmt.Sprintf("%s %q is not a declared kind of %q; declared: %v",
				fam.discriminator, kind, typ, sortedKinds(fam)))
		}
		if ks != nil {
			validate(s, rest, "", &problems)
			if props, present := payload[fam.properties]; present {
				validate(ks, props, fam.properties, &problems)
			}
			for _, f := range fam.freeText {
				if _, present := payload[f]; present && !slices.Contains(keep, f) {
					problems = append(problems, fmt.Sprintf("%s: free text is not kept for kind %q, "+
						"so it must be removed before publishing (D277)", f, kind))
				}
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"payload does not match schema %q:\n  - %s", typ, strings.Join(problems, "\n  - ")))
	}
	return nil
}

func sortedKinds(f kindFamily) []string {
	out := make([]string, 0, len(f.schemas))
	for k := range f.schemas {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func validate(s *Schema, value any, path string, problems *[]string) {
	if s.Type != "" && !typeMatches(s.Type, value) {
		*problems = append(*problems, fmt.Sprintf("%s: expected %s, got %T", at(path), s.Type, value))
		return
	}
	if s.Format == FormatDateTime {
		if str, _ := value.(string); !parsesDateTime(str) {
			*problems = append(*problems, fmt.Sprintf("%s: %q is not an RFC 3339 date-time", at(path), str))
		}
		return
	}

	if arr, isArr := value.([]any); isArr {
		items := s.Items
		if items == nil {
			items = &Schema{}
		}
		for i, x := range arr {
			validate(items, x, fmt.Sprintf("%s[%d]", path, i), problems)
		}
		return
	}
	obj, isObj := value.(map[string]any)
	if !isObj {
		return
	}

	for _, name := range s.Required {
		if _, present := obj[name]; !present {
			*problems = append(*problems, fmt.Sprintf("%s: required field %q is missing",
				at(path), name))
		}
	}

	for name, sub := range s.Properties {
		if v, present := obj[name]; present {
			validate(sub, v, join(path, name), problems)
		}
	}

	// CLOSED BY DEFAULT (D279): a field the schema does not name is refused
	// unless the schema says `additionalProperties: true`. SHAPED ⇔ VALID —
	// Shape strips exactly these, so a publisher that skipped it is refused
	// rather than leaking what it would have removed. Consumers ignoring
	// unknown fields (D41) is about READERS being tolerant; it never made a
	// publisher free to invent fields.
	if s.AdditionalProperties == nil || !*s.AdditionalProperties {
		for name := range obj {
			if _, declared := s.Properties[name]; !declared {
				*problems = append(*problems, fmt.Sprintf("%s: field %q is not declared, so it must "+
					"be stripped before publishing (D279)", at(path), name))
			}
		}
	}
}

// FieldPathExists is D42's boot-time check: "every field path the rule
// references exists in the payload schema".
//
// Paths are dotted — "session.id", "user.email". The failure it prevents is the
// nastiest in the design: a schema change makes a reflex silently stop matching,
// no error, nothing in the logs, and the first symptom is a business process
// that stopped happening weeks ago.
func (r *Registry) FieldPathExists(typ, path string) error {
	const op = "schemareg.FieldPathExists"

	s, ok := r.byType[typ]
	if !ok {
		return fault.New(fault.KindConfig, op,
			fmt.Sprintf("type %q has no registered schema", typ))
	}
	return pathIn(op, s, typ, path)
}

// pathIn walks path through one schema — FieldPathExists's walk, shared with
// LensPath's walk through a family's kinds so there is one reading of a path.
func pathIn(op string, s *Schema, typ, path string) error {
	cur := s
	var walked []string
	for _, segment := range strings.Split(path, ".") {
		if cur.Properties == nil && (cur.AdditionalProperties == nil || !*cur.AdditionalProperties) {
			return fault.New(fault.KindConfig, op, fmt.Sprintf(
				"field path %q does not exist in schema %q: %q declares no properties, and closed "+
					"by default it admits none (D279)", path, typ, at(strings.Join(walked, "."))))
		}
		if cur.Properties == nil {
			// An OPEN object accepts anything, so the path cannot be REFUTED —
			// but it also cannot be confirmed, and D42's promise is
			// confirmation. Say which.
			return fault.New(fault.KindConfig, op, fmt.Sprintf(
				"cannot confirm %q in schema %q: %q declares no properties, so any field "+
					"path is unverifiable there. Declare the shape, or accept that a schema "+
					"change can silently stop this rule matching (D42)",
				path, typ, at(strings.Join(walked, "."))))
		}
		next, ok := cur.Properties[segment]
		if !ok {
			return fault.New(fault.KindConfig, op, fmt.Sprintf(
				"field path %q does not exist in schema %q: %q has no field %q (available: %v)",
				path, typ, at(strings.Join(walked, ".")), segment, propertyNames(cur)))
		}
		walked = append(walked, segment)
		cur = next
	}
	return nil
}

// LensPath resolves a lens's field path for typ (D292): nil if the type or one
// of its family's kinds DECLARES it; plausible (with nil) if it sits under an
// OPEN kind, where the org's own data may carry it and nothing can confirm it;
// an error if no kind of typ could ever carry it.
//
// **THROUGH THE FAMILY, BECAUSE THAT IS WHERE THE FIELDS ARE.** A family type's
// `properties` field (Fullstory's `event_properties`) is declared per KIND, so
// the type-level walk found nothing under it — and no lens could name any event
// property at all, not even a click's documented `fs-element`.
func (r *Registry) LensPath(typ, path string) (plausible bool, err error) {
	const op = "schemareg.LensPath"
	err = r.FieldPathExists(typ, path)
	if err == nil {
		return false, nil
	}
	fam, isFamily := r.kinds[typ]
	rest, under := strings.CutPrefix(path, fam.properties+".")
	if !isFamily || fam.properties == "" || !under {
		return false, err
	}
	kinds := make([]string, 0, len(fam.schemas))
	for k := range fam.schemas {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		if pathIn(op, fam.schemas[k], typ+"#"+k, rest) == nil {
			return false, nil
		}
	}
	if fam.open != nil {
		return true, nil
	}
	return false, fault.New(fault.KindConfig, op, fmt.Sprintf(
		"field path %q: no declared kind of %q carries %q under %q, and the family admits no "+
			"open kind (kinds: %v)", path, typ, rest, fam.properties, kinds))
}

func typeMatches(want string, v any) bool {
	switch want {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number", "integer":
		// Everything numeric arrives as float64 through JSON — but a
		// connector's RAW event is not JSON-decoded, and a driver building
		// `map[string]any{"ordinal": i}` hands over a Go int (D279 shapes and
		// validates before translation). So every Go numeric type is a number;
		// integrality is checked on the value, not on Go's type.
		f, ok := asFloat(v)
		if !ok {
			return false
		}
		if want == "integer" {
			return f == float64(int64(f))
		}
		return true
	default:
		return true // unknown type keyword: not our business to reject
	}
}

func propertyNames(s *Schema) []string {
	out := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func at(path string) string {
	if path == "" {
		return "(root)"
	}
	return path
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

// asFloat reads any Go numeric value as a float64.
func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}

// ParseDateTime is THE reading of `format: date-time` — the validator's and
// the refinement engine's, so a time the schema admits is a time the engine
// can sort (D317).
func ParseDateTime(v string) (time.Time, error) { return time.Parse(time.RFC3339Nano, v) }

func parsesDateTime(v string) bool { _, err := ParseDateTime(v); return err == nil }
