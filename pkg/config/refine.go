package config

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// RefineRule is one `refines:` rule, as a connector ships it in its embedded
// `reflexes.yaml` (D299) — AVAILABLE by name, reaching nobody until a
// deployment imposes it with `refinements:` (D297 ruling 2).
//
// **THE VOCABULARY IS CLOSED, AND IT IS THIS STRUCT (D263, D300).** `where`
// selects rows with the shared operator set; ONE pairing level —
// `preceded_by` / `followed_by`, nearest match, optional `within_s` — exposes
// the paired row's fields under its `as:` name plus `duration_s`; and exactly
// one output shape, `list`, `count` or `first`. A pairing has no pairing inside
// it by construction. Adding to any of this is a code change and a review.
//
// **ONE RESULT IN, ONE KEY OUT.** A rule reads the rows of ONE result of type
// `refines` and writes ONE key, `key`, of the seiren type `into` — no state
// across results (D22), the input already bounded and priced by the action
// that returned it.
type RefineRule struct {
	Name string `json:"name"`

	// Params are a TEMPLATE's inputs (D299, D301): each is `required`, or a
	// default an imposition may override. A condition value or a `within_s`
	// written `{param: name}` takes the bound value.
	Params map[string]any `json:"params,omitempty"`

	Refines string `json:"refines"`
	Into    string `json:"into"`
	Key     string `json:"key"`

	Where      Predicate `json:"where,omitempty"`
	PrecededBy *Pairing  `json:"preceded_by,omitempty"`
	FollowedBy *Pairing  `json:"followed_by,omitempty"`

	List  *RefineList  `json:"list,omitempty"`
	Count *RefineCount `json:"count,omitempty"`
	First *RefineFirst `json:"first,omitempty"`

	// Mode is decoded ONLY TO BE REFUSED with the reason (D298). A `refines:`
	// rule never actuates, so its failure is a wrong refinement rather than a
	// wrong act; it is staged by AUDIENCE — imposed on one principal, then
	// widened — not by shadow. Left undecoded, strict parsing would refuse it
	// as merely "unknown", which tells an author nothing.
	Mode string `json:"mode,omitempty"`
}

// Pairing joins each selected row with the NEAREST row before (preceded_by) or
// after (followed_by) it that matches its own `where` (D300).
type Pairing struct {
	// As is the name the paired row's fields are carried under:
	// `landed.event_time`, and `landed.duration_s` for the seconds between.
	As string `json:"as"`

	// WithinS bounds the gap in seconds: a number, or `{param: name}`.
	// Absent means the nearest match at any distance within the result.
	WithinS any `json:"within_s,omitempty"`

	Where Predicate `json:"where,omitempty"`
}

// UnmarshalJSON refuses a pairing inside a pairing BY NAME (D300: one level).
// Strict decoding would refuse it anyway, as an unknown field — true, and no
// help to the author who needs to hear that the vocabulary stops here.
func (p *Pairing) UnmarshalJSON(raw []byte) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err == nil {
		for _, nested := range []string{"preceded_by", "followed_by"} {
			if _, ok := probe[nested]; ok {
				return fmt.Errorf("a pairing may not contain `%s`: the refinement vocabulary holds "+
					"ONE pairing level (D300) — a row may have one preceded_by and one followed_by, "+
					"never a pair of a pair", nested)
			}
		}
	}
	type plain Pairing // no methods, so no recursion (GO-PRIMER §15al)
	var v plain
	if err := strictJSON(raw, &v); err != nil {
		return err
	}
	*p = Pairing(v)
	return nil
}

// RefineList is one item per selected row, carrying the named fields (D63).
type RefineList struct {
	Carry []string `json:"carry"`
	Limit int      `json:"limit"`
}

// RefineCount counts the selected rows grouped by up to two carried paths.
type RefineCount struct {
	By    []string `json:"by"`
	Limit int      `json:"limit"`
}

// RefineFirst is the first selected row whose pairing held.
type RefineFirst struct {
	Carry []string `json:"carry"`
}

// RefinementSpec imposes a connector's rule on a target for an audience (D297
// ruling 2, D298) — the deployment's decision, never the connector's.
type RefinementSpec struct {
	// Rule is the connector's rule name, e.g. "fullstory.login".
	Rule string `json:"rule"`

	// Target is the target ref whose results the rule refines.
	Target string `json:"target"`

	// For is the audience: principals, trailing star permitted as in a lens's
	// `applies_to`. REQUIRED — staging by audience is the whole of the staging
	// mechanism for `refines:` (D298), so "everybody" must be written, never
	// implied by an omission.
	For []string `json:"for"`

	// Params binds a template's parameters (D299, D301).
	Params map[string]any `json:"params,omitempty"`
}

// ParamRequired marks a template parameter that has no default.
const ParamRequired = "required"

// ParamRef reports whether v is a `{param: name}` reference, and its name.
func ParamRef(v any) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return "", false
	}
	name, ok := m["param"].(string)
	return name, ok
}

// ParseReflexes reads a connector's `reflexes.yaml` STRICTLY — duplicate keys
// and unknown fields refused, as every configuration file is (D278) — and
// checks each rule's shape. A list, like `schemas.yaml`.
func ParseReflexes(raw []byte) ([]RefineRule, error) {
	j, err := yaml.YAMLToJSONStrict(raw)
	if err != nil {
		return nil, err
	}
	var rules []RefineRule
	if err := strictJSON(j, &rules); err != nil {
		return nil, err
	}
	p := &problems{}
	seen := map[string]bool{}
	for i, r := range rules {
		if seen[r.Name] {
			p.addf("rule[%d]: %q is declared twice", i, r.Name)
		}
		seen[r.Name] = true
		CheckRefineRule(p, r)
	}
	if err := p.err(); err != nil {
		return nil, err
	}
	return rules, nil
}

// CheckRefineRule is the SHAPE check — everything answerable from the rule
// alone. Types, paths and keys need the schema registry, and are checked there
// at boot (schemareg), as `where` paths are (D42).
func CheckRefineRule(p *problems, r RefineRule) {
	label := fmt.Sprintf("refines rule %q", r.Name)
	if r.Name == "" {
		p.addf("a refines rule has no name")
	}
	if r.Mode != "" {
		p.addf("%s: declares `mode: %s`. A refines rule never actuates — its failure is a wrong "+
			"refinement, not a wrong act — so it is staged by AUDIENCE (impose it `for:` one "+
			"principal, then widen), never by shadow (D298)", label, r.Mode)
	}
	for field, v := range map[string]string{"refines": r.Refines, "into": r.Into, "key": r.Key} {
		if strings.TrimSpace(v) == "" {
			p.addf("%s: names no `%s`", label, field)
		}
	}

	for name, v := range r.Params {
		switch v.(type) {
		case string, float64, bool:
		default:
			p.addf("%s: param %q is %v; a param is `required` or a string, number or boolean default",
				label, name, v)
		}
	}
	declared := func(where string, v any) {
		if name, ok := ParamRef(v); ok {
			if _, has := r.Params[name]; !has {
				p.addf("%s: %s uses {param: %s}, which the rule does not declare under `params`",
					label, where, name)
			}
		}
	}

	checkConditions(p, label+": where", r.Where, true)
	for i, c := range r.Where {
		declared(fmt.Sprintf("where[%d]", i), c.Value)
	}
	pairs := map[string]bool{}
	for kind, pr := range map[string]*Pairing{"preceded_by": r.PrecededBy, "followed_by": r.FollowedBy} {
		if pr == nil {
			continue
		}
		pl := label + ": " + kind
		switch {
		case pr.As == "":
			p.addf("%s: names no `as`, so nothing can carry the paired row's fields", pl)
		case strings.Contains(pr.As, "."):
			p.addf("%s: `as: %s` contains a dot; it is one name", pl, pr.As)
		case pairs[pr.As]:
			p.addf("%s: `as: %s` is used by both pairings", pl, pr.As)
		}
		pairs[pr.As] = true
		if len(pr.Where) == 0 {
			p.addf("%s: has no `where`, so it would pair with any row", pl)
		}
		checkConditions(p, pl+": where", pr.Where, true)
		for i, c := range pr.Where {
			declared(fmt.Sprintf("%s.where[%d]", kind, i), c.Value)
		}
		if pr.WithinS != nil {
			if _, isParam := ParamRef(pr.WithinS); isParam {
				declared(kind+".within_s", pr.WithinS)
			} else if n, ok := pr.WithinS.(float64); !ok || n <= 0 {
				p.addf("%s: `within_s` is %v; it is a positive number of seconds or {param: name}",
					pl, pr.WithinS)
			}
		}
	}

	outputs := 0
	var carried []string
	if r.List != nil {
		outputs++
		carried = append(carried, r.List.Carry...)
		if len(r.List.Carry) == 0 {
			p.addf("%s: `list` carries nothing", label)
		}
		if r.List.Limit <= 0 {
			p.addf("%s: `list` needs a positive `limit`", label)
		}
	}
	if r.Count != nil {
		outputs++
		carried = append(carried, r.Count.By...)
		if n := len(r.Count.By); n < 1 || n > 2 {
			p.addf("%s: `count` groups by %d paths; it takes one or two", label, n)
		}
		if r.Count.Limit <= 0 {
			p.addf("%s: `count` needs a positive `limit`", label)
		}
	}
	if r.First != nil {
		outputs++
		carried = append(carried, r.First.Carry...)
		if len(r.First.Carry) == 0 {
			p.addf("%s: `first` carries nothing", label)
		}
		if r.PrecededBy == nil && r.FollowedBy == nil {
			p.addf("%s: `first` is the first row whose pairing HELD, and the rule has no pairing", label)
		}
	}
	if outputs != 1 {
		p.addf("%s: declares %d output shapes; exactly one of `list`, `count` or `first` (D300)",
			label, outputs)
	}
	for _, c := range carried {
		head, rest, nested := strings.Cut(c, ".")
		if rest == "duration_s" && nested && !pairs[head] {
			p.addf("%s: carries %q, and %q is not a pairing", label, c, head)
		}
		if c == "duration_s" {
			p.addf("%s: carries `duration_s` bare; it belongs to a pairing — `<as>.duration_s`", label)
		}
	}
}

// Bind is the rule with an imposition's params applied: defaults filled,
// every `{param: name}` replaced. It refuses a required param left unbound
// (the login template imposed bare, D299) and a param the rule does not have.
func (r RefineRule) Bind(params map[string]any) (RefineRule, error) {
	var missing, unknown []string
	values := map[string]any{}
	for name, def := range r.Params {
		v, supplied := params[name]
		switch {
		case supplied:
			values[name] = v
		case def == ParamRequired:
			missing = append(missing, name)
		default:
			values[name] = def
		}
	}
	for name := range params {
		if _, has := r.Params[name]; !has {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(unknown)
	if len(missing) > 0 {
		return r, fmt.Errorf("rule %q needs %v — a template imposed without its required parameters "+
			"would match nothing, or the wrong thing, in every result (D299)", r.Name, missing)
	}
	if len(unknown) > 0 {
		return r, fmt.Errorf("rule %q has no parameter %v; it declares %v", r.Name, unknown, keys(r.Params))
	}

	var errs []string
	bindConds := func(label string, in Predicate) Predicate {
		out := make(Predicate, len(in))
		for i, c := range in {
			if name, ok := ParamRef(c.Value); ok {
				c.Value = values[name]
				if s, isStr := c.Value.(string); c.Op == OpPrefix && (!isStr || s == "") {
					errs = append(errs, fmt.Sprintf("%s[%d]: `prefix` needs a non-empty string, and "+
						"param %q is %v", label, i, name, c.Value))
				}
			}
			out[i] = c
		}
		return out
	}
	bindPair := func(label string, pr *Pairing) *Pairing {
		if pr == nil {
			return nil
		}
		b := *pr
		b.Where = bindConds(label+".where", pr.Where)
		if name, ok := ParamRef(pr.WithinS); ok {
			b.WithinS = values[name]
			if n, isNum := b.WithinS.(float64); !isNum || n <= 0 {
				errs = append(errs, fmt.Sprintf("%s.within_s: param %q is %v, not a positive number of "+
					"seconds", label, name, b.WithinS))
			}
		}
		return &b
	}
	out := r
	out.Params = nil
	out.Where = bindConds("where", r.Where)
	out.PrecededBy = bindPair("preceded_by", r.PrecededBy)
	out.FollowedBy = bindPair("followed_by", r.FollowedBy)
	if len(errs) > 0 {
		return r, fmt.Errorf("rule %q: %s", r.Name, strings.Join(errs, "; "))
	}
	return out, nil
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// err folds collected problems into one error, or nil.
func (p *problems) err() error {
	if len(*p) == 0 {
		return nil
	}
	return fmt.Errorf("%d problem(s):\n  - %s", len(*p), strings.Join(*p, "\n  - "))
}

// validateRefinements is the half of an imposition answerable from the
// document: the rule, target and audience are named. Whether the target's
// connector ships the rule, and whether its types, paths and keys hold, needs
// the drivers and the schema registry, and is checked there at boot.
func (d *Document) validateRefinements(p *problems, targets map[string]bool) {
	for i, r := range d.Refinements {
		label := fmt.Sprintf("refinements[%d] (%s)", i, r.Rule)
		if r.Rule == "" {
			p.addf("refinements[%d]: names no rule", i)
		}
		if !targets[r.Target] {
			p.addf("%s: target %q is not declared", label, r.Target)
		}
		if len(r.For) == 0 {
			p.addf("%s: names no audience. `for:` is required — staging by audience is how a "+
				"refines rule is rolled out (D298), so \"everybody\" must be written as a pattern, "+
				"never implied by leaving it out", label)
		}
		for _, who := range r.For {
			if strings.TrimSpace(who) == "" || (strings.Contains(who, "*") && !strings.HasSuffix(who, "*")) {
				p.addf("%s: audience %q — a principal, or a trailing-star pattern as in a lens's applies_to",
					label, who)
			}
		}
	}
}

// ReadPaths is every input path a rule reads, sorted: the time path, each
// condition's, and each carried field's — a paired row's under its own name,
// `<as>.duration_s` excepted (the engine computes it). THE ONE READING, for the
// engine deciding at run time whether a rule can run for a caller and for the
// boot refusing a rule no one in its audience could ever receive (D300).
func (r RefineRule) ReadPaths(timePath string) []string {
	set := map[string]bool{timePath: true}
	for _, c := range r.Where {
		set[c.Path] = true
	}
	pairs := map[string]bool{}
	for _, pr := range []*Pairing{r.PrecededBy, r.FollowedBy} {
		if pr != nil {
			pairs[pr.As] = true
			for _, c := range pr.Where {
				set[c.Path] = true
			}
		}
	}
	var carried []string
	switch {
	case r.List != nil:
		carried = r.List.Carry
	case r.Count != nil:
		carried = r.Count.By
	case r.First != nil:
		carried = r.First.Carry
	}
	for _, c := range carried {
		head, rest, nested := strings.Cut(c, ".")
		switch {
		case nested && pairs[head] && rest == "duration_s":
		case nested && pairs[head]:
			set[rest] = true
		default:
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// SubjectTokenAlgorithms is THE list of signed-subject algorithms this build
// implements (D318) — one list, read by boot validation and by the verifier's
// tests, so the two cannot disagree about what is accepted.
func SubjectTokenAlgorithms() []string { return []string{"RS256", "ES256", "EdDSA"} }

// validateIssuers is the half of an issuer answerable from the document (D318).
// Whether its key file resolves and parses needs the providers, and is checked
// where the verifier is built.
func (d *Document) validateIssuers(p *problems) {
	granted := map[string]bool{}
	for _, g := range d.Grants {
		granted[g.Principal] = true
	}
	seen := map[string]bool{}
	for i, is := range d.Issuers {
		label := fmt.Sprintf("issuers[%d] (%s)", i, is.Issuer)
		switch {
		case strings.TrimSpace(is.Issuer) == "":
			p.addf("issuers[%d]: names no issuer", i)
		case seen[is.Issuer]:
			p.addf("%s: declared twice; one issuer, one entry", label)
		}
		seen[is.Issuer] = true
		if strings.TrimSpace(is.Audience) == "" {
			p.addf("%s: names no audience — without one a token minted for any service is accepted here (D303)", label)
		}
		if !strings.HasPrefix(is.Keys, "file://") {
			p.addf("%s: keys %q — the broker's JWKS comes through file:// (D286, D318), so no key fetch sits "+
				"on the request path", label, is.Keys)
		}
		if len(is.Algorithms) == 0 {
			p.addf("%s: names no algorithms; the allowlist is required (D303)", label)
		}
		for _, a := range is.Algorithms {
			if !slices.Contains(SubjectTokenAlgorithms(), a) {
				p.addf("%s: algorithm %q is not implemented (%v are)", label, a, SubjectTokenAlgorithms())
			}
		}
		if len(is.Callers) == 0 {
			p.addf("%s: names no callers; the mTLS principals that may present its tokens are enumerated (D318)", label)
		}
		for _, c := range is.Callers {
			if strings.Contains(c, "*") {
				p.addf("%s: caller %q — callers are enumerated, never wildcarded (§4.4.1)", label, c)
			} else if !granted[c] {
				p.addf("%s: caller %q has no grant, so no request it carries could be authorised", label, c)
			}
		}
		if is.LeewaySec > MaxIssuerLeewaySec {
			p.addf("%s: leeway_s %d; at most %d — a longer skew is an expiry extended by configuration", label,
				is.LeewaySec, MaxIssuerLeewaySec)
		}
	}
}
