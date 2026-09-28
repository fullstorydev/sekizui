package acceptance

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/predicate"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// refinerOver is a connector whose shipped rules are replaced — how a step
// plants a rule, or a driver release that adds one, without editing the file
// the product ships. Embedding delegates everything else (GO-PRIMER §15aw).
type refinerOver struct {
	connector.Driver
	yaml []byte
}

func (r refinerOver) Reflexes() []byte { return r.yaml }

// untimedFullstory is Fullstory with `event_time` stripped of its format — the
// input type then names no time, which a rule needs to sort and pair by.
type untimedFullstory struct{ refinerOver }

func (u untimedFullstory) Schemas() ([]connector.Schema, error) {
	schemas, err := u.Driver.Schemas()
	for i, s := range schemas {
		if s.Type != "fullstory.session_event.v1" {
			continue
		}
		var body map[string]any
		if jerr := json.Unmarshal(s.Body, &body); jerr != nil {
			return nil, jerr
		}
		props, _ := body["properties"].(map[string]any)
		timeField, _ := props["event_time"].(map[string]any)
		delete(timeField, "format")
		if schemas[i].Body, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	return schemas, err
}

const refineTarget = "fs:refine"

// compileRefinements runs the boot's compilation (the same function the
// schema check and the gateway read) over one Fullstory target.
func compileRefinements(t *testing.T, d connector.Driver, imps ...config.RefinementSpec) (
	[]schemareg.Refinement, string) {
	t.Helper()
	doc := &config.Document{
		Targets: []config.TargetSpec{{Ref: refineTarget, Kind: fullstory.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://api.fullstory.com", CredentialRef: "env://SEKIZUI_ACCEPT_TOK"}},
		Refinements: imps,
	}
	drivers := map[string]connector.Driver{fullstory.Kind: d}
	reg, err := schemareg.ForDeployment(doc, drivers)
	if err != nil {
		t.Fatalf("building the registry: %v", err)
	}
	if faults, _ := reg.QuarantineOf(fullstory.Kind); faults != "" {
		return nil, "QUARANTINED: " + faults
	}
	out, problems, _ := schemareg.Refinements(reg, doc, drivers)
	return out, strings.Join(problems, "\n")
}

func impose(rule string, who []string, params map[string]any) config.RefinementSpec {
	return config.RefinementSpec{Rule: rule, Target: refineTarget, For: who, Params: params}
}

func shippedYAML() []byte { return fullstory.New().Reflexes() }

// plantRule appends one rule to what Fullstory ships.
func plantRule(rule string) connector.Driver {
	return refinerOver{Driver: fullstory.New(), yaml: append(append([]byte{}, shippedYAML()...), []byte("\n"+rule)...)}
}

// --- step 14: available, not imposed -------------------------------------

func p4Step14(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "a connector's reflexes ship embedded and are available, not imposed")

	// 14a — SHIPPED: embedded, parsed in the closed vocabulary, the connector's own.
	fs := fullstory.New()
	rf, ok := any(fs).(connector.Refiner)
	if !ok {
		t.Fatal("step 14a: the Fullstory driver is not a connector.Refiner, so it offers no rules")
	}
	rules, err := config.ParseReflexes(rf.Reflexes())
	if err != nil {
		t.Fatalf("step 14a: Fullstory's reflexes.yaml does not load: %v", err)
	}
	var names []string
	for _, rule := range rules {
		names = append(names, rule.Name)
	}
	sort.Strings(names)
	if want := "fullstory.errors fullstory.frustration fullstory.login fullstory.path"; strings.Join(names, " ") != want {
		t.Errorf("step 14a: Fullstory ships %v; D298 ruled four built-ins: %s", names, want)
	}
	if _, problems := compileRefinements(t, fs); problems != "" {
		t.Errorf("step 14a: shipping the rules is itself refused: %s", problems)
	}

	// 14b — AVAILABLE, NOT IMPOSED: shipped rules reach nobody unimposed, and a
	// driver release that adds a rule changes nothing a deployment serves.
	if got, _ := compileRefinements(t, fs); len(got) != 0 {
		t.Errorf("step 14b: a deployment imposing nothing runs %d rules; shipped must mean available", len(got))
	}
	upgraded := plantRule(`- name: fullstory.extra
  refines: fullstory.session_event.v1
  into: fullstory.session_context.v1
  key: path
  where: [{path: event_type, op: eq, value: navigate}]
  list: {carry: [event_time], limit: 10}
`)
	got, problems := compileRefinements(t, upgraded, impose("fullstory.frustration", []string{"agent:a"}, nil))
	if problems != "" || len(got) != 1 || got[0].Rule.Name != "fullstory.frustration" {
		t.Errorf("step 14b: after a driver release added a rule, the deployment runs %v (problems: %s); it "+
			"imposed only fullstory.frustration, and upgrading a driver must never change an agent's input",
			got, problems)
	}

	// 14c — `mode:` REFUSES: a refines rule is staged by audience, not shadow.
	_, problems = compileRefinements(t, plantRule(`- name: fullstory.shadowed
  mode: shadow
  refines: fullstory.session_event.v1
  into: fullstory.session_context.v1
  key: path
  where: [{path: event_type, op: eq, value: navigate}]
  list: {carry: [event_time], limit: 10}
`))
	if !strings.Contains(problems, "QUARANTINED") || !strings.Contains(problems, "AUDIENCE") ||
		!strings.Contains(problems, "D298") {
		t.Errorf("step 14c: a refines rule declaring `mode: shadow` was not refused with D298's reason; got: %s",
			problems)
	}
	r.detail(t, "Fullstory offers %d rules by name; imposing none runs none, a release adding one changes "+
		"nothing served, and `mode:` quarantines the connector naming D298", len(rules))
}

// --- step 15: the login template ----------------------------------------

func p4Step15(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the login template refuses to be imposed bare, and defaults its window to 60 seconds")
	fs := fullstory.New()
	who := []string{"agent:a"}

	// 15a — BARE, OR HALF-BOUND, REFUSES, naming what is missing.
	_, problems := compileRefinements(t, fs, impose("fullstory.login", who, nil))
	if !strings.Contains(problems, "needs [signin_prefix success_prefix]") {
		t.Errorf("step 15a: the login template imposed bare was not refused naming both prefixes; got: %s", problems)
	}
	_, problems = compileRefinements(t, fs, impose("fullstory.login", who, map[string]any{"signin_prefix": "/login"}))
	if !strings.Contains(problems, "needs [success_prefix]") {
		t.Errorf("step 15a: imposed without success_prefix, the refusal did not name it; got: %s", problems)
	}
	_, problems = compileRefinements(t, fs, impose("fullstory.login", who,
		map[string]any{"signin_prefix": float64(42), "success_prefix": "/app"}))
	if !strings.Contains(problems, "`prefix` needs a non-empty string") {
		t.Errorf("step 15a: a numeric signin_prefix was not refused; got: %s", problems)
	}

	// 15b — BOTH BOUND: 60 seconds unless the imposition says otherwise (D317
	// revising D301: the window holds the person typing, not only redirects).
	withinOf := func(params map[string]any) any {
		got, problems := compileRefinements(t, fs, impose("fullstory.login", who, params))
		if problems != "" || len(got) != 1 {
			t.Fatalf("step 15b: the bound login template was refused: %s", problems)
		}
		return got[0].Rule.FollowedBy.WithinS
	}
	both := map[string]any{"signin_prefix": "/login", "success_prefix": "/app"}
	if w := withinOf(both); w != float64(60) {
		t.Errorf("step 15b: the login window defaults to %v; D317 ruled 60 seconds, for typing and an identity "+
			"provider's redirects", w)
	}
	both["within_s"] = float64(5)
	if w := withinOf(both); w != float64(5) {
		t.Errorf("step 15b: an imposition's within_s: 5 bound as %v", w)
	}
	r.detail(t, "bare and half-bound impositions refused naming the missing prefixes; bound, the "+
		"window is 60s by default and 5s where the imposition says so")
}

// --- step 16: the vocabulary is closed -----------------------------------

func p4Step16(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the refinement vocabulary is closed")
	base := "- name: fullstory.x\n  refines: fullstory.session_event.v1\n  into: fullstory.session_context.v1\n  key: path\n"
	for _, c := range []struct{ arm, yaml, want string }{
		{"an unknown operator", base + "  where: [{path: page_url, op: regex, value: '^/a'}]\n  list: {carry: [event_time], limit: 5}\n",
			`unknown operator "regex"`},
		{"an unknown output shape", base + "  where: [{path: event_type, op: eq, value: navigate}]\n  sum: {by: [page_url]}\n",
			`unknown field "sum"`},
		{"an unknown field", base + "  where: [{path: event_type, op: eq, value: navigate}]\n  list: {carry: [event_time], limit: 5}\n  lookup: fullstory.get_user\n",
			`unknown field "lookup"`},
		{"a pairing inside a pairing", base + "  where: [{path: event_type, op: eq, value: navigate}]\n  followed_by:\n    as: a\n    where: [{path: event_type, op: eq, value: click}]\n    followed_by: {as: b, where: [{path: event_type, op: eq, value: navigate}]}\n  first: {carry: [a.event_time]}\n",
			"ONE pairing level"},
		{"two output shapes", base + "  where: [{path: event_type, op: eq, value: navigate}]\n  list: {carry: [event_time], limit: 5}\n  first: {carry: [event_time]}\n",
			"exactly one of `list`, `count` or `first`"},
	} {
		if _, err := config.ParseReflexes([]byte(c.yaml)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("step 16: %s was not refused with %q; got: %v", c.arm, c.want, err)
		}
	}

	// `prefix` IS SHARED: in the operator set every rule kind reads, and
	// evaluated for a bus rule by the one predicate evaluator.
	if !strings.Contains(strings.Join(config.PredicateOps(), " "), config.OpPrefix) {
		t.Error("step 16: `prefix` is not in the shared operator set")
	}
	cond := config.Predicate{{Path: "page_url", Op: config.OpPrefix, Value: "/checkout"}}
	for url, want := range map[string]bool{"/checkout/pay": true, "/cart": false} {
		if got, err := predicate.Holds(cond, map[string]any{"page_url": url}); err != nil || got != want {
			t.Errorf("step 16: prefix /checkout over %q = %v (%v), want %v", url, got, err, want)
		}
	}
	if _, err := predicate.Holds(cond, map[string]any{"page_url": 7.0}); err == nil {
		t.Error("step 16: prefix over a number answered instead of refusing — a schema/data disagreement " +
			"must be an error, not a false (D42)")
	}

	// A TEMPLATE PARAMETER IS A CONNECTOR RULE'S, never a bus rule's.
	doc := &config.Document{Reflexes: []config.ReflexSpec{{Name: "bus", Principal: "reflex:x", Enabled: true,
		Consumes: "sekizui.raw.fullstory.>", ExpectsType: "fullstory.session_event.v1",
		Where: config.Predicate{{Path: "page_url", Op: config.OpPrefix, Value: map[string]any{"param": "p"}}}}}}
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "only a connector's `refines:` rule declares parameters") {
		t.Errorf("step 16: a bus rule using {param} was not refused; got: %v", err)
	}
	r.detail(t, "unknown operator, output shape and field refused; a pair of a pair refused naming ONE level; "+
		"prefix is shared and evaluated for bus rules; a bus rule cannot take a template parameter")
}

// --- step 17: paths, windows, limits and keys at boot --------------------

func p4Step17(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "a rule's paths, windows, limits and keys are checked at boot")
	who := []string{"agent:a"}
	rule := func(where, output string) string {
		return "- name: fullstory.planted\n  refines: fullstory.session_event.v1\n  into: fullstory.session_context.v1\n" +
			"  key: errors\n  where: " + where + "\n  " + output + "\n"
	}
	check := func(arm string, d connector.Driver, want string) {
		t.Helper()
		_, problems := compileRefinements(t, d, impose("fullstory.planted", who, nil))
		switch {
		case want == "" && problems != "":
			t.Errorf("step 17 %s: refused, and it is sound: %s", arm, problems)
		case want != "" && !strings.Contains(problems, want):
			t.Errorf("step 17 %s: not refused with %q; got: %q", arm, want, problems)
		}
	}
	carry := "list: {carry: [event_time, event_type], limit: 50}"

	// 17a — A KIND'S FIELD RESOLVES UNDER ITS KIND, AND NOWHERE ELSE (D292).
	check("17a pinned", plantRule(rule(`[{path: event_type, op: eq, value: click}, {path: event_properties.fs-form-name, op: exists}]`, carry)), "")
	check("17a unpinned", plantRule(rule(`[{path: event_properties.fs-form-name, op: exists}]`, carry)), "pins no event_type")
	check("17a undeclared kind", plantRule(rule(`[{path: event_type, op: eq, value: no-such-kind}]`, carry)),
		`"no-such-kind" is not a declared kind`)

	// 17b — A TIME PATH, DECLARED date-time, or nothing can be sorted or paired.
	window := "preceded_by: {as: cause, within_s: 5, where: [{path: event_type, op: eq, value: click}]}\n  " +
		"list: {carry: [event_time, event_type, cause.duration_s], limit: 50}"
	sound := rule(`[{path: event_type, op: eq, value: exception}]`, window)
	check("17b timed", plantRule(sound), "")
	untimed := untimedFullstory{refinerOver{Driver: fullstory.New(), yaml: append(append([]byte{}, shippedYAML()...), []byte("\n"+sound)...)}}
	check("17b untimed", untimed, "declares 0 top-level `format: date-time` fields")

	// 17c — THE LIMIT IS AT MOST THE INPUT BOUND.
	check("17c over the bound", plantRule(rule(`[{path: event_type, op: eq, value: exception}]`,
		"list: {carry: [event_time, event_type], limit: 500}")), "limit 500 exceeds 200")

	// 17d — CARRIED FIELDS LAND IN THE SEIREN SCHEMA (D63, D88).
	check("17d undeclared in seiren", plantRule(rule(`[{path: event_type, op: eq, value: navigate}]`,
		"list: {carry: [event_time, page_url], limit: 50}")), `cannot hold it`)

	// 17e — ONE KEY, ONE WRITER, per target and overlapping audience.
	fs := fullstory.New()
	_, problems := compileRefinements(t, fs, impose("fullstory.errors", []string{"agent:a"}, nil),
		impose("fullstory.errors", []string{"agent:*"}, nil))
	if !strings.Contains(problems, `both write "errors"`) {
		t.Errorf("step 17e: two impositions writing one key for overlapping audiences were not refused: %q", problems)
	}
	if got, problems := compileRefinements(t, fs, impose("fullstory.errors", []string{"agent:a"}, nil),
		impose("fullstory.errors", []string{"agent:b"}, nil)); problems != "" || len(got) != 2 {
		t.Errorf("step 17e: disjoint audiences writing one key were refused: %q", problems)
	}
	r.detail(t, "a kind's field resolves pinned and is refused unpinned; an untimed input, a limit over "+
		"200, a carry the seiren type cannot hold and two writers of one key are each refused, each beside "+
		"its sound counterpart")
}
