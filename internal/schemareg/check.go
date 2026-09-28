package schemareg

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Checker is D42's boot-time validation, as a lifecycle component.
//
// WHY THIS EXISTS AS A COMPONENT RATHER THAN INSIDE config.Document.Validate:
// the check needs a parsed schema registry, and the registry lives in
// `internal/`. `pkg/config` cannot import it without inverting D35's layering.
//
// That layering constraint is the whole reason D42 went UNENFORCED. FieldPathExists
// was written, tested, documented as "boot-time", and called by nothing — the
// package had zero callers outside its own tests. A check nobody runs is worse
// than a missing one, because DESIGN records it as a guarantee and §12 lists it
// as delivered.
//
// So it lands where both halves are available: a spine.Validator registered
// after config, running in the same validate-everything-before-anything-starts
// phase. The document and the drivers meet here and nowhere else.
//
// DESIGN.md references: §4.6.1c, §4.11.4b, §4.12, D40, D41, D42, D88.
type Checker struct {
	doc     func() *config.Document
	drivers func(*config.Document) map[string]connector.Driver
	log     *slog.Logger
}

// NewChecker returns a Checker reading the document through a getter, because
// the document does not exist until config.Loader has validated it and spine
// runs validators in registration order.
//
// **THE DRIVERS ARE A FUNCTION OF THE DOCUMENT, AND THAT IS THE FIX.** They
// were a map, and the binary registered this check with `kata` ALONE — so
// since D279 made connectors own their schemas, the boot's D42 check knew only
// kata's types, and a rule naming any Fullstory, Jira or MCP type was refused
// in the binary while every in-process test, built with the full set, passed.
// Found by P3 step 21, the first rule to name a connector-owned non-kata type.
// The deployment's set needs the document (MCP drivers come from its specs),
// so the binary passes `builtin.ByKind`, and a test with a fixed set passes a
// closure returning it.
func NewChecker(doc func() *config.Document, drivers func(*config.Document) map[string]connector.Driver,
	log *slog.Logger) *Checker {
	return &Checker{doc: doc, drivers: drivers, log: log}
}

// Name identifies this component in the init ledger and readiness output.
func (c *Checker) Name() string { return "schema:check" }

// Start and Stop are no-ops: all the work is validation.
func (c *Checker) Start(ctx context.Context) error { return nil }
func (c *Checker) Stop(ctx context.Context) error  { return nil }

// Validate runs every schema-dependent check, collecting all failures.
//
// COLLECTS RATHER THAN RETURNING THE FIRST, matching config.Document.Validate:
// an operator fixing configuration wants the whole list, not one error per
// restart.
func (c *Checker) Validate(ctx context.Context) error {
	const op = "schemareg.Checker.Validate"

	doc := c.doc()
	if doc == nil {
		return fault.New(fault.KindInternal, op,
			"no validated configuration; config must be registered before this component")
	}

	// THE CONNECTORS' SCHEMAS AND THE DOCUMENT'S, with ownership checked
	// (D279): a declared type without a connector-shipped schema fails here,
	// naming the connector.
	drivers := c.drivers(doc)
	reg, err := ForDeployment(doc, drivers)
	if err != nil {
		return err
	}

	var problems, inert []string
	checkDrivers(drivers, &problems)
	checkReflexes(reg, doc, &problems, &inert)
	// REFINES RULES, IMPOSED (D297-D301, D317): the same compilation the
	// gateway runs, so what boot checked is what serves.
	_, refineProblems, refineInert := Refinements(reg, doc, drivers)
	problems = append(problems, refineProblems...)
	inert = append(inert, refineInert...)
	var notes []string
	checkLenses(reg, doc, &problems, &inert, &notes)
	for _, n := range notes {
		c.log.Info("a lens names a field it cannot confirm", "detail", n)
	}

	// A QUARANTINED CONNECTOR IS SAID OUT LOUD, AND DOES NOT FAIL THE BOOT
	// (D282): its targets are refused and everything else serves. What names
	// its types is INERT until a fixed connector ships — reported, not fatal,
	// or one connector's packaging mistake would take the deployment down
	// through the rules that mention it.
	for kind, why := range reg.Quarantined() {
		c.log.Error("connector QUARANTINED: its schemas or its meter are not sound, so its targets are refused "+
			"and nothing it emits can enter; every other connector serves (D282)",
			"connector", kind, "why", why)
	}
	for _, w := range inert {
		c.log.Warn("configuration names a quarantined connector's type and is inert until it is fixed",
			"detail", w)
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%d schema problem(s):\n  - %s", len(problems), strings.Join(problems, "\n  - ")))
	}

	c.log.Info("schema references validated",
		"types", len(reg.Types()), "reflexes", len(doc.Reflexes), "refinements", len(doc.Refinements),
		"lenses", len(doc.Shin))
	return nil
}

// checkDrivers runs the published action contract against every driver.
//
// WHETHER EVERY DECLARED TYPE HAS A SCHEMA is ForDeployment's, which built the
// registry this receives and refuses a connector that ships none (D279) — one
// place, so boot, the runner and the tap cannot disagree about it.
func checkDrivers(drivers map[string]connector.Driver, problems *[]string) {
	for kind, d := range drivers {
		// THE CONTRACT CHECK COMES FROM pkg/connector, NOT FROM HERE (D163, D167).
		// It is the same function the published conformance suite runs, so a
		// driver that passes the suite passes boot and vice versa.
		*problems = append(*problems, connector.ValidateActions(kind, d.Actions())...)
	}
}

// checkReflexes is D42 proper: "every field path the rule references exists in
// the payload schema".
func checkReflexes(reg *Registry, doc *config.Document, problems, inert *[]string) {
	for _, r := range doc.Reflexes {
		if !r.Enabled {
			// A disabled rule is not going to silently stop matching, because it
			// is not matching. Checking it would refuse boot over a rule somebody
			// deliberately parked.
			continue
		}
		label := fmt.Sprintf("reflex %q", r.Name)

		if r.ExpectsType == "" {
			continue
		}
		if kind, q := reg.QuarantinedBy(r.ExpectsType); q {
			*inert = append(*inert, fmt.Sprintf("%s expects %q, a type of quarantined connector %q",
				label, r.ExpectsType, kind))
			continue
		}
		if !reg.Has(r.ExpectsType) {
			*problems = append(*problems, fmt.Sprintf(
				"%s: expects_type %q has no registered schema, so no field path in this "+
					"rule can be confirmed (D42). Known: %v", label, r.ExpectsType, reg.Types()))
			continue
		}

		// --- against the INPUT schema ---------------------------------------
		for _, path := range r.Carry {
			if err := reg.FieldPathExists(r.ExpectsType, path); err != nil {
				*problems = append(*problems, fmt.Sprintf("%s: carries %q — %v", label, path, err))
			}
		}
		if r.DebounceKey != "" {
			if err := reg.FieldPathExists(r.ExpectsType, r.DebounceKey); err != nil {
				*problems = append(*problems, fmt.Sprintf(
					"%s: debounce_key %q — %v. A debounce key that does not exist collapses "+
						"every event into one bucket", label, r.DebounceKey, err))
			}
		}
		// EVERY PATH, EXACTLY (D263). This used to regexp `input.<path>` out of
		// a Rego string, best-effort, missing whatever the pattern missed; a
		// structured predicate names its paths, so none go unchecked.
		for i, c := range r.Where {
			if err := reg.FieldPathExists(r.ExpectsType, c.Path); err != nil {
				*problems = append(*problems, fmt.Sprintf(
					"%s: where[%d] references %q — %v", label, i, c.Path, err))
			}
			// A KIND THAT CANNOT ARRIVE (D276). On a discriminated type, a
			// condition on the discriminator may name only declared kinds:
			// every other kind is refused at publish, so a rule waiting for
			// one would be enabled, valid and permanently inert. UNLESS the
			// family admits other kinds (D279) — as a skeleton or open — in
			// which case such an event can arrive.
			if disc, kinds, isFamily := reg.Kinds(r.ExpectsType); isFamily && c.Path == disc &&
				!reg.AdmitsOtherKinds(r.ExpectsType) {
				for _, v := range kindValues(c) {
					if !contains(kinds, v) {
						*problems = append(*problems, fmt.Sprintf(
							"%s: where[%d] matches %s %q, which is not a declared kind of %q, so no "+
								"such event can ever reach it (D276). Declared: %v",
							label, i, disc, v, r.ExpectsType, kinds))
					}
				}
			}
		}

		// --- against the OUTPUT schema --------------------------------------
		//
		// The half that did not exist before D88. A rule can carry a field that
		// its input schema declares and its OUTPUT schema does not, and then
		// every downstream lens and rule silently fails to find it.
		if r.PublishTo == "" {
			continue
		}
		if r.PublishesType == "" {
			*problems = append(*problems, fmt.Sprintf(
				"%s: publishes to %q but declares no publishes_type. The type was previously "+
					"derived from the subject's last segment, which produced an unversioned, "+
					"unregistered type outside both D41 and D42 — a payload shape nobody "+
					"reviewed", label, r.PublishTo))
			continue
		}
		if !strings.Contains(r.PublishesType, ".v") {
			*problems = append(*problems, fmt.Sprintf(
				"%s: publishes_type %q has no version suffix; types are versioned (D41), "+
					"e.g. %q", label, r.PublishesType, r.PublishesType+".v1"))
			continue
		}
		if !reg.Has(r.PublishesType) {
			*problems = append(*problems, fmt.Sprintf(
				"%s: publishes_type %q has no registered schema. What a reflex emits is a "+
					"payload shape like any other, and one nobody declared cannot be "+
					"validated, lensed, or consumed by a rule downstream", label, r.PublishesType))
			continue
		}

		for _, path := range r.Carry {
			if err := reg.FieldPathExists(r.PublishesType, path); err != nil {
				*problems = append(*problems, fmt.Sprintf(
					"%s: carries %q into %q, which does not declare it — %v. Everything "+
						"downstream would look for a field that never arrives",
					label, path, r.PublishesType, err))
			}
		}
		for key := range r.With {
			if err := reg.FieldPathExists(r.PublishesType, key); err != nil {
				*problems = append(*problems, fmt.Sprintf(
					"%s: adds %q to the published payload, which %q does not declare — %v",
					label, key, r.PublishesType, err))
			}
		}
	}
}

// checkLenses validates shin field paths against the schemas they name (§4.12).
func checkLenses(reg *Registry, doc *config.Document, problems, inert, notes *[]string) {
	for _, l := range doc.Shin {
		if !l.Enabled || l.Type == "" {
			continue
		}
		label := fmt.Sprintf("shin %q", l.Name)

		if kind, q := reg.QuarantinedBy(l.Type); q {
			*inert = append(*inert, fmt.Sprintf("%s lenses %q, a type of quarantined connector %q",
				label, l.Type, kind))
			continue
		}
		if !reg.Has(l.Type) {
			// REPORTED HERE since D279. It used to be skipped because
			// config.Document.Validate reported it — which it can no longer do,
			// the type usually being a connector's. A skip that relied on
			// another component's check is exactly how this would have become a
			// lens that silently never matches.
			*problems = append(*problems, fmt.Sprintf("%s: type %q has no registered payload schema, "+
				"so this lens can never match. Types are versioned (D41) — check the .v1 suffix; a "+
				"connector's type is declared by its connector (D279)", label, l.Type))
			continue
		}
		// RESOLVED THROUGH THE FAMILY (D292): a path a declared kind carries is
		// declared; one under an OPEN kind is plausible and said so.
		for _, path := range l.Fields {
			plausible, err := reg.LensPath(l.Type, path)
			switch {
			case err != nil:
				*problems = append(*problems, fmt.Sprintf(
					"%s: keeps %q — %v. A lens naming a field the schema does not have "+
						"silently delivers less than someone believes it does", label, path, err))
			case plausible:
				*notes = append(*notes, fmt.Sprintf("%s: keeps %q, under an open kind — it cannot "+
					"be confirmed, only admitted when the org's data carries it (D292)", label, path))
			}
		}
		// **A TYPED LENS'S WITHHELD PATHS MUST BE RESOLVABLE (D292).** They were
		// never checked — for a TYPELESS jurisdiction rule ("never send
		// user.email", across every payload) that is right, and it stays. For a
		// lens scoped to one type it inverted the strictness: a typo in `fields`
		// refused the boot, and a typo in `withholds` withheld NOTHING, silently —
		// the safe direction strict and the leaking direction unchecked.
		for _, path := range l.Withholds {
			plausible, err := reg.LensPath(l.Type, path)
			switch {
			case err != nil:
				*problems = append(*problems, fmt.Sprintf(
					"%s: withholds %q, which no kind of %q could carry — %v. A typo here withholds "+
						"nothing and says nothing; name a field the type can carry (D292)",
					label, path, l.Type, err))
			case plausible:
				*notes = append(*notes, fmt.Sprintf("%s: withholds %q, under an open kind — "+
					"unverifiable, and withheld whenever the org's data carries it (D292)", label, path))
			}
		}
	}
}

// kindValues are the literal kinds a condition names: its eq value, or each of
// its in values.
func kindValues(c config.Condition) []string {
	switch c.Op {
	case config.OpEq:
		if v, ok := c.Value.(string); ok {
			return []string{v}
		}
	case config.OpIn:
		var out []string
		list, _ := c.Value.([]any)
		for _, v := range list {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
