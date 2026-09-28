package schemareg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// Refinement is one imposed `refines:` rule, bound and checked (D297-D301,
// D317): what the engine runs, for whom, on which target's results.
type Refinement struct {
	Rule     config.RefineRule // params bound: no `{param}` remains
	Target   string
	For      []string
	TimePath string // the input type's one `format: date-time` field
}

// Refinements compiles the document's impositions against the connectors'
// shipped rules and the registry. ONE COMPILATION FOR BOOT AND THE GATEWAY: the
// boot check reports its problems and the gateway runs its result, so what
// was checked is what runs.
//
// An imposition on a QUARANTINED connector's target is inert, not a problem —
// the connector is out of service and its target refused (D282).
func Refinements(reg *Registry, doc *config.Document, drivers map[string]connector.Driver) (
	out []Refinement, problems, inert []string) {
	kindOf := map[string]string{}
	for _, t := range doc.Targets {
		kindOf[t.Ref] = t.Kind
	}
	shipped := map[string]map[string]config.RefineRule{} // kind -> name -> rule
	for i, imp := range doc.Refinements {
		label := fmt.Sprintf("refinements[%d] (%s on %s)", i, imp.Rule, imp.Target)
		kind := kindOf[imp.Target]
		if why, q := reg.Quarantined()[kind]; q {
			inert = append(inert, fmt.Sprintf("%s: connector %q is quarantined (%s)", label, kind, why))
			continue
		}
		rules, ok := shipped[kind]
		if !ok {
			rules = map[string]config.RefineRule{}
			if rf, isRefiner := drivers[kind].(connector.Refiner); isRefiner {
				parsed, err := config.ParseReflexes(rf.Reflexes())
				if err != nil {
					problems = append(problems, fmt.Sprintf("%s: connector %q's reflexes.yaml: %v", label, kind, err))
				}
				for _, r := range parsed {
					rules[r.Name] = r
				}
			}
			shipped[kind] = rules
		}
		rule, ok := rules[imp.Rule]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: connector %q ships no rule %q (it ships %v) — a "+
				"rule is imposed from what the target's own connector offers (D299)",
				label, kind, imp.Rule, ruleNames(rules)))
			continue
		}
		bound, err := rule.Bind(imp.Params)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", label, err))
			continue
		}
		timePath, ps := reg.checkRule(label, kind, bound, drivers[kind])
		problems = append(problems, ps...)
		if len(ps) == 0 {
			out = append(out, Refinement{Rule: bound, Target: imp.Target, For: imp.For, TimePath: timePath})
		}
	}
	problems = append(problems, collisions(out)...)
	problems = append(problems, neverBuilds(out, doc)...)
	return out, problems, inert
}

// neverBuilds refuses an imposition that an IMPOSED lens would always block
// (D300): a lens covering EVERY principal in the rule's audience, on the
// rule's input type and the target's residency, withholding a path the rule
// reads. Imposed lenses and imposed rules are both static configuration, so
// the answer is known now; only a lens a caller SELECTS waits for run time,
// where the rule is declared unavailable instead.
func neverBuilds(rs []Refinement, doc *config.Document) []string {
	residencyOf := map[string]string{}
	for _, t := range doc.Targets {
		residencyOf[t.Ref] = t.Residency
	}
	var out []string
	for _, r := range rs {
		for _, lens := range doc.Shin {
			if !lens.Enabled || (lens.Mode != "" && lens.Mode != string(shin.ModeImposed)) ||
				(lens.Type != "" && lens.Type != r.Rule.Refines) ||
				(lens.Residency != "" && lens.Residency != residencyOf[r.Target]) ||
				!coversAudience(lens.AppliesTo, r.For) {
				continue
			}
			for _, p := range r.Rule.ReadPaths(r.TimePath) {
				if shin.PathWithheld(lens.Fields, lens.Withholds, p) {
					out = append(out, fmt.Sprintf("refinement %q on %s for %v can never build: imposed lens %q "+
						"withholds %q from its whole audience, and the rule reads it (D300). Narrow the audience "+
						"or drop the imposition", r.Rule.Name, r.Target, r.For, lens.Name, p))
					break
				}
			}
		}
	}
	return out
}

// coversAudience reports whether a lens's applies_to reaches EVERY principal
// an audience could name. Empty applies_to is every principal (an imposed
// ceiling); a pattern covers a principal, or a narrower pattern.
func coversAudience(appliesTo, audience []string) bool {
	if len(appliesTo) == 0 {
		return true
	}
	for _, a := range audience {
		pa, aStar := strings.CutSuffix(a, "*")
		covered := false
		for _, p := range appliesTo {
			pp, pStar := strings.CutSuffix(p, "*")
			if (!aStar && (p == a || (pStar && strings.HasPrefix(a, pp)))) ||
				(aStar && pStar && strings.HasPrefix(pa, pp)) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// checkRule is D300's boot checks for one bound rule.
func (r *Registry) checkRule(label, kind string, rule config.RefineRule, d connector.Driver) (string, []string) {
	var ps []string
	add := func(format string, args ...any) { ps = append(ps, label+": "+fmt.Sprintf(format, args...)) }

	// TYPES: registered, and both the connector's own (D279, D299).
	for field, typ := range map[string]string{"refines": rule.Refines, "into": rule.Into} {
		if owner, ok := r.owner[typ]; !ok || owner != kind {
			add("%s type %q is not a type connector %q registers (owner %q)", field, typ, kind, owner)
		}
	}
	if len(ps) > 0 {
		return "", ps
	}

	// TIME: every rule sorts by time (D300 — replay rests on it), so the input
	// type must say which field is time and promise it parses (D317).
	timePath, err := r.TimePath(rule.Refines)
	if err != nil {
		add("%v", err)
	}

	// PATHS, narrowed by the kinds each `where` pins (D292, D300).
	ruleKinds, err := r.pinnedKinds(rule.Refines, rule.Where)
	if err != nil {
		add("where: %v", err)
	}
	pairKinds := map[string][]string{}
	for pk, pr := range map[string]*config.Pairing{"preceded_by": rule.PrecededBy, "followed_by": rule.FollowedBy} {
		if pr == nil {
			continue
		}
		k, err := r.pinnedKinds(rule.Refines, pr.Where)
		if err != nil {
			add("%s.where: %v", pk, err)
		}
		pairKinds[pr.As] = k
		for i, c := range pr.Where {
			if err := r.KindPath(rule.Refines, k, c.Path); err != nil {
				add("%s.where[%d]: %v", pk, i, err)
			}
		}
	}
	for i, c := range rule.Where {
		if err := r.KindPath(rule.Refines, ruleKinds, c.Path); err != nil {
			add("where[%d]: %v", i, err)
		}
	}

	// OUTPUT: carried paths resolve in the input, and land in the seiren schema
	// under the rule's one key (D63, D88).
	carried, shape := outputOf(rule)
	for _, c := range carried {
		head, rest, nested := strings.Cut(c, ".")
		kinds, isPair := pairKinds[head]
		switch {
		case nested && isPair && rest == "duration_s":
		case nested && isPair:
			if err := r.KindPath(rule.Refines, kinds, rest); err != nil {
				add("carries %q: %v", c, err)
			}
		default:
			if err := r.KindPath(rule.Refines, ruleKinds, c); err != nil {
				add("carries %q: %v", c, err)
			}
		}
	}
	if err := r.seirenSlot(rule.Into, rule.Key, shape, carried); err != nil {
		add("%v", err)
	}

	// LIMIT: at most what the input can hold (D300).
	if limit := outputLimit(rule); limit > 0 {
		if b := inputBound(d, rule.Refines); limit > b {
			add("limit %d exceeds %d, the most rows any action returning %q may deliver", limit, b, rule.Refines)
		}
	}
	return timePath, ps
}

// TimePath is typ's one top-level `format: date-time` property.
func (r *Registry) TimePath(typ string) (string, error) {
	s := r.byType[typ]
	var found []string
	if s != nil {
		for name, p := range s.Properties {
			if p.Format == FormatDateTime {
				found = append(found, name)
			}
		}
	}
	sort.Strings(found)
	if len(found) != 1 {
		return "", fmt.Errorf("type %q declares %d top-level `format: date-time` fields %v; a refines rule "+
			"sorts its rows by time and pairs them within seconds, so its input type declares exactly one "+
			"(D300, D317)", typ, len(found), found)
	}
	return found[0], nil
}

// pinnedKinds are the kinds a `where` pins on typ's discriminator (eq or in),
// each checked to be a declared kind. None, for a type with no family.
func (r *Registry) pinnedKinds(typ string, where config.Predicate) ([]string, error) {
	fam, isFamily := r.kinds[typ]
	if !isFamily {
		return nil, nil
	}
	var kinds []string
	for _, c := range where {
		if c.Path != fam.discriminator {
			continue
		}
		for _, v := range kindValues(c) {
			if _, declared := fam.schemas[v]; !declared {
				return nil, fmt.Errorf("%s %q is not a declared kind of %q, so no rule can confirm what its "+
					"rows carry (D292). Declared: %v", fam.discriminator, v, typ, sortedKinds(fam))
			}
			kinds = append(kinds, v)
		}
	}
	return kinds, nil
}

// KindPath resolves path on typ as D300 reads it: a field of the type itself,
// or one under the family's properties that EVERY kind the rule pins declares.
// Unpinned, a kind-specific field is refused — `event_properties.fs-form-name`
// resolves under `event_type: click` and nowhere else (D292, D300).
func (r *Registry) KindPath(typ string, kinds []string, path string) error {
	err := r.FieldPathExists(typ, path)
	if err == nil {
		return nil
	}
	fam, isFamily := r.kinds[typ]
	rest, under := strings.CutPrefix(path, fam.properties+".")
	if !isFamily || fam.properties == "" || !under {
		return err
	}
	if len(kinds) == 0 {
		return fmt.Errorf("%q is a field of a KIND of %q, and this `where` pins no %s — pin the kinds "+
			"(eq or in) so the path can be confirmed (D292, D300)", path, typ, fam.discriminator)
	}
	for _, k := range kinds {
		if perr := pathIn("schemareg.KindPath", fam.schemas[k], typ+"#"+k, rest); perr != nil {
			return perr
		}
	}
	return nil
}

// seirenSlot checks that `key` of the seiren type can hold what the rule writes:
// an array of objects for list and count, an object for first, with every
// carried path declared inside it — and `count` for a count.
func (r *Registry) seirenSlot(into, key, shape string, carried []string) error {
	seiren := r.byType[into]
	if seiren == nil || seiren.Properties == nil || seiren.Properties[key] == nil {
		return fmt.Errorf("key %q is not declared in seiren type %q, which is where the rule writes (D300)",
			key, into)
	}
	slot := seiren.Properties[key]
	item := slot
	if shape != "first" {
		if slot.Type != "array" || slot.Items == nil || slot.Items.Type != "object" {
			return fmt.Errorf("seiren type %q declares %q as %q; a %s writes an array of objects", into, key,
				slot.Type, shape)
		}
		item = slot.Items
	} else if slot.Type != "object" {
		return fmt.Errorf("seiren type %q declares %q as %q; `first` writes one object", into, key, slot.Type)
	}
	paths := append([]string(nil), carried...)
	if shape == "count" {
		paths = append(paths, "count")
	}
	for _, p := range paths {
		if err := pathIn("schemareg.seirenSlot", item, into+"#"+key, p); err != nil {
			return fmt.Errorf("the rule writes %q under %q, and seiren type %q cannot hold it: %v", p, key, into, err)
		}
	}
	return nil
}

func outputOf(rule config.RefineRule) (carried []string, shape string) {
	switch {
	case rule.List != nil:
		return rule.List.Carry, "list"
	case rule.Count != nil:
		return rule.Count.By, "count"
	case rule.First != nil:
		return rule.First.Carry, "first"
	}
	return nil, ""
}

func outputLimit(rule config.RefineRule) int {
	switch {
	case rule.List != nil:
		return rule.List.Limit
	case rule.Count != nil:
		return rule.Count.Limit
	}
	return 0
}

// inputBound is the most rows any of d's actions returning typ may deliver —
// its Bound, and one object where a read declares none (D283).
func inputBound(d connector.Driver, typ string) int {
	most := 0
	for _, a := range d.Actions() {
		for _, t := range a.DeclaredOutputs() {
			if t != typ {
				continue
			}
			n := 1
			if a.Bound != nil {
				n = a.Bound.MaxRows
			}
			most = max(most, n)
		}
	}
	return most
}

// collisions refuses two impositions that would write one key of one
// refinement: same target, same input type, overlapping audiences (D300). And
// one response carries ONE refinement of ONE type, so those two must also
// agree on `into`.
func collisions(rs []Refinement) []string {
	var out []string
	for i := range rs {
		for j := i + 1; j < len(rs); j++ {
			a, b := rs[i], rs[j]
			if a.Target != b.Target || a.Rule.Refines != b.Rule.Refines || !audiencesOverlap(a.For, b.For) {
				continue
			}
			switch {
			case a.Rule.Into != b.Rule.Into:
				out = append(out, fmt.Sprintf("refinements %q and %q refine %s on %s for overlapping audiences "+
					"into different types (%s, %s); one response carries one refinement of one type (D317)",
					a.Rule.Name, b.Rule.Name, a.Rule.Refines, a.Target, a.Rule.Into, b.Rule.Into))
			case a.Rule.Key == b.Rule.Key:
				out = append(out, fmt.Sprintf("refinements %q and %q both write %q on %s for overlapping "+
					"audiences %v and %v; which one wins is not a question a refinement answers silently (D300)",
					a.Rule.Name, b.Rule.Name, a.Rule.Key, a.Target, a.For, b.For))
			}
		}
	}
	return out
}

// audiencesOverlap reports whether any principal could match both lists —
// exact names, or trailing-star patterns as in a lens's applies_to.
func audiencesOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			px, sx := strings.CutSuffix(x, "*")
			py, sy := strings.CutSuffix(y, "*")
			switch {
			case sx && sy:
				if strings.HasPrefix(px, py) || strings.HasPrefix(py, px) {
					return true
				}
			case sx:
				if strings.HasPrefix(y, px) {
					return true
				}
			case sy:
				if strings.HasPrefix(x, py) {
					return true
				}
			case x == y:
				return true
			}
		}
	}
	return false
}

func ruleNames(rules map[string]config.RefineRule) []string {
	out := make([]string, 0, len(rules))
	for n := range rules {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
