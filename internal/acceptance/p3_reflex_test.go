package acceptance

import (
	"context"
	"github.com/fullstorydev/sekizui/internal/builtin"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/reflex"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// runEngine starts the reflex engine over the named acceptance rules, wired
// exactly as `cmd/sekizui` wires it: subscribing through the server's scoped
// path, enforcing through its Enforce, publishing onto its bus.
//
// A SUBSET OF RULES, because the whole document is a loop: `correlate-friction`
// enriches a raw envelope and `friction-to-ticket` acts on the enrichment, and a
// step asserting one rule's behaviour must not be asserting a chain's.
func runEngine(t *testing.T, r *run, names ...string) {
	t.Helper()
	runEngineSignalling(t, r, noSignal, names...)
}

// runEngineSignalling is runEngine with the anzen signal observed, for the arm
// that asserts `budget_exceeded` is raised (D264).
func runEngineSignalling(t *testing.T, r *run, signal reflex.SignalFunc, names ...string) {
	t.Helper()
	doc := loadAcceptanceDoc(t)
	var rules []config.ReflexSpec
	for _, want := range names {
		found := false
		for _, rule := range doc.Reflexes {
			if rule.Name == want {
				rules, found = append(rules, rule), true
			}
		}
		if !found {
			t.Fatalf("acceptance.yaml declares no reflex %q", want)
		}
	}
	engine := reflex.NewEngine(rules, r.srv, r.recorder, signal, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() string { return "env_reflex_" + time.Now().Format("150405.000000000") }, mustSchemas(t, r.doc).Validate)

	ctx, cancel := context.WithCancel(context.Background())
	wait, err := engine.Run(ctx,
		func(ctx context.Context, id *sekizuiv1.Identity, subjects []string) (reflex.Stream, error) {
			sub, err := r.srv.SubscribeAs(ctx, id, subjects)
			if err != nil {
				return nil, err
			}
			return sub, nil
		},
		r.bus.Publish)
	if err != nil {
		cancel()
		t.Fatalf("the engine could not subscribe: %v", err)
	}
	t.Cleanup(func() { cancel(); wait() })

	want := len(rules)
	waitFor(t, func() bool { return r.bus.Subscribers() >= want },
		"the engine's rules never registered their subscriptions")
}

// publishRow puts a kata row on the bus as if a source had produced it.
func publishRow(t *testing.T, r *run, id, stage, source string) {
	t.Helper()
	publishRowWith(t, r, id, stage, source, map[string]any{"ordinal": 1})
}

// publishRowWith is publishRow with the payload chosen, for the predicate arms.
func publishRowWith(t *testing.T, r *run, id, stage, source string, data map[string]any) {
	t.Helper()
	e := envelope(t, stage, "kata.row.v1", data)
	e.Id, e.Source = id, source
	if err := r.srv.PublishForTest(e); err != nil {
		t.Fatalf("publishing %s: %v", id, err)
	}
}

// causedBy waits for the record a reflex wrote for one envelope.
func causedBy(t *testing.T, r *run, envID, what string) *sekizuiv1.Decision {
	t.Helper()
	var found *sekizuiv1.Decision
	waitFor(t, func() bool {
		for _, d := range readLog(t, r.path) {
			if d.GetCausation().GetParentId() == envID && d.GetReflexName() != "" {
				found = d
				return true
			}
		}
		return false
	}, what)
	return found
}

// p3Step22 — shadow is the default, and arming is a deliberate act in reviewed
// configuration (P3 criterion 8, D172).
//
// **ASSERTED ON THE LIVE ENGINE, NOT ON `BuildCommand`.** `DryRun: rule.Mode !=
// "enforce"` has been true since P0 and a unit test says so; what nobody had
// shown is that the engine consuming the bus reaches that line at all, rather
// than some other construction. Both arms go through the running loop.
func p3Step22(t *testing.T) {
	r := newRun(t)
	if r.localOnly(t, "the engine and the bus are this instance's") {
		return
	}
	r.narrate(t, "shadow is the default, and arming is a deliberate act in reviewed configuration")

	// 22c FIRST, because it needs no engine: A RULE MAY NOT READ AS BOUNDED
	// WHEN NOTHING BOUNDS IT (D262). Each field the engine does not enforce is
	// refused at boot, naming what it would have done.
	step22UnenforcedFieldsRefused(t)

	runEngine(t, r, "unarmed-ticket", "friction-to-ticket")

	// 22a — A RULE THAT SAYS NOTHING ABOUT MODE RECORDS AND DOES NOT FIRE.
	publishRow(t, r, "22a-row", "raw", "fs:fixture")
	d := causedBy(t, r, "22a-row", "the unarmed rule never reached the enforcement path")
	if d.GetVerdict() != sekizuiv1.Verdict_VERDICT_WOULD_HAVE_FIRED {
		t.Fatalf("step 22a: a rule with NO mode produced %s. Shadow is the default (D172, "+
			"§4.11.4 item 3); a rule nobody armed must record WOULD_HAVE_FIRED and touch nothing",
			d.GetVerdict())
	}

	// 22b — ARMED BY WHAT SOMEBODY WROTE. `friction-to-ticket` says
	// `mode: enforce` in reviewed configuration, and it is the only difference.
	publishRow(t, r, "22b-enriched", "enriched", "fs:fixture")
	d = causedBy(t, r, "22b-enriched", "the armed rule never reached the enforcement path")
	if d.GetVerdict() != sekizuiv1.Verdict_VERDICT_ALLOW {
		t.Fatalf("step 22b: the armed rule produced %s, want ALLOW — without this arm, 22a "+
			"would pass for an engine that never fires anything", d.GetVerdict())
	}
	r.detail(t, "unarmed-ticket recorded WOULD_HAVE_FIRED; friction-to-ticket, armed in "+
		"configuration, recorded ALLOW")
}

// p3Step38 — a reflex consumes as its principal, through the scope an agent's
// subscription takes (P3 criteria 20 and 8, D261).
//
// **THE RULE'S `consumes` IS NOT ITS AUTHORISATION.** Its principal's subscribe
// grant is: which subjects, from which targets. Before D261 the engine had no
// subscription at all, and the obvious one to give it — one engine-wide reader —
// would have read every tenant's events for every rule.
func p3Step38(t *testing.T) {
	r := newRun(t)

	r.narrate(t, "a reflex consumes as its principal, through the scope an agent's subscription takes")

	// 38c FIRST: THE BOOT REFUSES A RULE ITS PRINCIPAL MAY NOT FEED.
	step38BootRefusal(t)

	if r.localOnly(t, "the engine and the bus are this instance's") {
		return
	}
	runEngine(t, r, "unarmed-ticket")

	// 38a — ORDER IS THE INSTRUMENT, as in step 37. reflex:friction is granted
	// raw subjects from fs:fixture only, so the row from kata:beta — published
	// FIRST — must produce nothing, and would be processed first if it did.
	publishRow(t, r, "38a-beta-row", "raw", "kata:beta")
	publishRow(t, r, "38a-fixture-row", "raw", "fs:fixture")
	causedBy(t, r, "38a-fixture-row", "the rule never acted on the row from its granted target")
	for _, d := range readLog(t, r.path) {
		if d.GetCausation().GetParentId() == "38a-beta-row" {
			t.Fatalf("step 38a: reflex %q acted on a row from kata:beta, which its principal "+
				"has no subscribe entry for. A rule reads what its PRINCIPAL is granted, not "+
				"what its `consumes` pattern names (D261)", d.GetReflexName())
		}
	}

	// 38b — THE SUBSCRIPTION IS RECORDED AS THE RULE'S PRINCIPAL, internally
	// asserted, naming its targets — the same row an agent's subscription writes.
	var opened *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetAction() == "sekizui.subscribe" &&
			d.GetIdentity().GetSubject().GetPrincipal() == "reflex:friction" &&
			d.GetVerdict() == sekizuiv1.Verdict_VERDICT_ALLOW {
			opened = d
		}
	}
	switch {
	case opened == nil:
		t.Fatal("step 38b: the engine's subscription left no record; D93 records every " +
			"subscription once, and a reflex's is not exempt")
	case opened.GetIdentity().GetCaller().GetMethod() != sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL:
		t.Errorf("step 38b: the reflex's subscription records method %s, not INTERNAL (D57)",
			opened.GetIdentity().GetCaller().GetMethod())
	case !strings.Contains(opened.GetReason(), "fs:fixture"):
		t.Errorf("step 38b: the reflex's subscription record does not name its target: %q",
			opened.GetReason())
	}
	r.detail(t, "reflex:friction subscribed as itself, from fs:fixture only; a row from "+
		"kata:beta published first produced nothing")
}

// step38BootRefusal is 38c.
func step38BootRefusal(t *testing.T) {
	t.Helper()
	base, err := os.ReadFile("acceptance.yaml")
	if err != nil {
		t.Fatalf("step 38c: %v", err)
	}
	const entry = `      - {subject: "sekizui.raw.>", target: fs:fixture}`
	if !strings.Contains(string(base), entry) {
		t.Fatalf("step 38c: acceptance.yaml no longer carries %q, which this step removes", entry)
	}
	path := filepath.Join(t.TempDir(), "acceptance.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(base), entry+"\n", "", 1)), 0o600); err != nil {
		t.Fatalf("step 38c: %v", err)
	}
	doc, err := config.NewFileSource(path).Load(context.Background())
	if err == nil {
		err = doc.Validate()
	}
	if err == nil {
		t.Fatal("step 38c: a rule consuming raw subjects booted with no subscribe entry " +
			"covering them — it would be enabled, valid and never hear anything (D261)")
	}
	// correlate-friction consumes `sekizui.raw.>`, and the entry removed is the
	// only one covering it; unarmed-ticket's narrower pattern is still covered
	// by the kata:alpha entry step 7c added, which is the check being precise.
	for _, w := range []string{"may not consume", "D261", "correlate-friction"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("step 38c: the refusal does not say %q: %v", w, err)
		}
	}
}

// step22UnenforcedFieldsRefused is 22c: NO REFLEX FIELD IS DECODED AND DROPPED.
//
// **IT WAS A LIST OF REFUSALS AND IS NOW A STRUCTURAL GUARD, because the list
// emptied.** D262 refused `where`, the debounce pair and the firing budget
// while nothing read them, each refusal to be deleted by the change that made
// its field real — D263 and D264 made all of them real. What must outlive the
// list is the CLASS: a field that parses and that nothing reads. So every
// `config.ReflexSpec` field must be read by name in internal/reflex's
// production code, or be listed below as a declaration boot alone consumes.
// The next field somebody adds and forgets fails here.
//
// SYNTACTIC, AND SAYS SO: a selector `.Field` anywhere in the package counts
// as a reader, so a generic name like `Name` passes easily. The failure mode
// it catches — a field with NO reader at all — is exactly D262's.
func step22UnenforcedFieldsRefused(t *testing.T) {
	t.Helper()
	bootOnly := map[string]string{
		"AcknowledgesLLMInput": "a boot declaration (D64): validate refuses a rule consuming an " +
			"LLM stage without it, and there is nothing for the engine to do with it after",
	}
	dir := filepath.Join(mustRoot(t), "internal", "reflex")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("step 22c: %v", err)
	}
	read := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("step 22c: %v", err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				read[sel.Sel.Name] = true
			}
			return true
		})
	}
	// AN ALLOWLIST ENTRY WITH A READER IS STALE, and fails like one — the rule
	// TestPermittedOrphansAreStillOrphans applies to archcheck's list.
	for name := range bootOnly {
		if read[name] {
			t.Errorf("step 22c: %s is listed as boot-only and internal/reflex reads it; delete "+
				"the entry", name)
		}
	}
	rt := reflect.TypeOf(config.ReflexSpec{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if read[name] || bootOnly[name] != "" {
			continue
		}
		t.Errorf("step 22c: config.ReflexSpec.%s (%s) has no reader in internal/reflex. A field "+
			"that parses and that nothing reads makes a rule READ as doing something it does "+
			"not — D262's defect. Enforce it, refuse it at boot, or list it as boot-only with "+
			"the reason", name, rt.Field(i).Tag.Get("json"))
	}
}

// p3Step39 — a reflex's `where` is a declarative predicate, checked against the
// schema at boot (P3 criteria 21 and 8, D263).
func p3Step39(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "a reflex's `where` is a declarative predicate, checked against the schema at boot")

	// 39b-d FIRST: THE BOOT. Each form a predicate must not take is refused
	// naming the fix.
	step39BootRefusals(t)

	if r.localOnly(t, "the engine and the bus are this instance's") {
		return
	}
	runEngine(t, r, "high-ordinal-ticket")

	// 39a — THE PREDICATE DECIDES, IN THE LIVE LOOP. Both rows match the rule's
	// subject and type; only ordinal 7 satisfies `ordinal gt 5`. The failing row
	// is published FIRST, so if the predicate were ignored — D262's defect —
	// its record would be the first one written.
	publishRowWith(t, r, "39a-low", "raw", "fs:fixture", map[string]any{"ordinal": 1})
	publishRowWith(t, r, "39a-high", "raw", "fs:fixture", map[string]any{"ordinal": 7})
	causedBy(t, r, "39a-high", "the rule never acted on the row that satisfies its where")
	for _, d := range readLog(t, r.path) {
		if d.GetCausation().GetParentId() == "39a-low" {
			t.Fatalf("step 39a: rule %q fired on ordinal 1 despite `where: ordinal gt 5` — "+
				"the predicate is not evaluated (D262, D263)", d.GetReflexName())
		}
	}
	r.detail(t, "high-ordinal-ticket fired on ordinal 7 and not on ordinal 1, decided by "+
		"`{path: ordinal, op: gt, value: 5}` in the live loop")
}

// step39BootRefusals is 39b (a path the schema does not declare), 39c (an
// unknown operator) and 39d (the pre-D263 Rego string). 39b needs D42's schema
// check, which lives with the drivers, so it runs the same checker newRun does.
func step39BootRefusals(t *testing.T) {
	t.Helper()
	base, err := os.ReadFile("acceptance.yaml")
	if err != nil {
		t.Fatalf("step 39: %v", err)
	}
	const cond = "      - {path: ordinal, op: gt, value: 5}"
	if !strings.Contains(string(base), cond) {
		t.Fatalf("step 39: acceptance.yaml no longer carries %q", cond)
	}
	for _, tc := range []struct{ arm, replacement, want string }{
		{"39b: a path the schema does not declare", "      - {path: ordinl, op: gt, value: 5}",
			`where[0] references "ordinl"`},
		{"39c: an unknown operator", "      - {path: ordinal, op: matches, value: 5}",
			"unknown operator"},
		{"39d: the Rego string it replaced", `    where: "input.ordinal > 5"`, "D263"},
	} {
		src := string(base)
		if strings.HasPrefix(tc.arm, "39d") {
			src = strings.Replace(src, "    where:\n"+cond, tc.replacement, 1)
		} else {
			src = strings.Replace(src, cond, tc.replacement, 1)
		}
		path := filepath.Join(t.TempDir(), "acceptance.yaml")
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatalf("step 39: %v", err)
		}
		doc, err := config.NewFileSource(path).Load(context.Background())
		if err == nil {
			err = doc.Validate()
		}
		if err == nil {
			err = schemareg.NewChecker(func() *config.Document { return doc },
				func(*config.Document) map[string]connector.Driver {
					return map[string]connector.Driver{kata.Kind: kata.New()}
				},
				slog.New(slog.NewTextHandler(io.Discard, nil))).Validate(context.Background())
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("step %s booted without the refusal %q (got %v)", tc.arm, tc.want, err)
		}
	}
}

// p3Step40 — arming a rule requires a firing budget, and exhausting it refuses
// the firing (P3 criteria 21 and 8, D264).
//
// **PER REPLICA, AND THE STEP DOES NOT PRETEND OTHERWISE.** Two replicas each
// allow a rule its whole budget; what this proves is the bound one process
// keeps, and the fleet-wide one is P7's.
func p3Step40(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "arming a rule requires a firing budget, and exhausting it refuses the firing")

	// 40c FIRST: ARMING WITHOUT A BUDGET REFUSES THE BOOT.
	step40ArmingNeedsABudget(t)

	if r.localOnly(t, "the engine and the bus are this instance's") {
		return
	}
	var signalled []string
	var mu sync.Mutex
	runEngineSignalling(t, r, func(_ context.Context, name string, subjects map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		for subject := range subjects {
			signalled = append(signalled, name+":"+subject)
		}
	}, "budgeted-ticket", "debounced-ticket")

	// 40a — THE BUDGET. Two firings are allowed; the third is REFUSED AND
	// RECORDED as VERDICT_BUDGET_EXCEEDED, and `budget_exceeded` is raised for
	// the rule — once, on the transition, not per refusal.
	// FIVE ROWS, AND THE FIFTH IS THE INSTRUMENT. A refusal is RECORDED and
	// then SIGNALLED, so seeing the fourth row's record does not mean its
	// signal call has happened — and the first version of this arm read the
	// signals there and passed a build that signalled on EVERY refusal. The
	// rule's loop is sequential: once the fifth row's record exists, the
	// fourth's signal call has returned.
	for _, id := range []string{"40a-1", "40a-2", "40a-3", "40a-4", "40a-5"} {
		publishRowWith(t, r, id, "raw", "fs:fixture", map[string]any{"ordinal": 40, "ref": id})
	}
	for _, id := range []string{"40a-1", "40a-2"} {
		if d := causedBy(t, r, id, "a firing inside the budget left no record"); d.GetVerdict() !=
			sekizuiv1.Verdict_VERDICT_WOULD_HAVE_FIRED {
			t.Errorf("step 40a: firing %s inside the budget recorded %s", id, d.GetVerdict())
		}
	}
	for _, id := range []string{"40a-3", "40a-4", "40a-5"} {
		d := causedBy(t, r, id, "a firing past the budget left no record — refused SILENTLY")
		if d.GetVerdict() != sekizuiv1.Verdict_VERDICT_BUDGET_EXCEEDED {
			t.Fatalf("step 40a: the firing past a budget of 2 recorded %s, want BUDGET_EXCEEDED "+
				"— the budget is not enforced (D264)", d.GetVerdict())
		}
	}
	mu.Lock()
	got := append([]string(nil), signalled...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "budget_exceeded:budgeted-ticket" {
		t.Errorf("step 40a: signals raised = %v, want exactly [budget_exceeded:budgeted-ticket] — "+
			"once, on the transition into exhaustion, not once per refused firing", got)
	}

	// 40b — DEBOUNCE. Two rows with the same `ref`, then one with another: the
	// second is suppressed (no record — suppression is the rule working), and
	// the third fires. Published in order, so the third's record proves the
	// second was processed before it.
	publishRowWith(t, r, "40b-first", "raw", "fs:fixture", map[string]any{"ordinal": 41, "ref": "same"})
	publishRowWith(t, r, "40b-dup", "raw", "fs:fixture", map[string]any{"ordinal": 41, "ref": "same"})
	publishRowWith(t, r, "40b-other", "raw", "fs:fixture", map[string]any{"ordinal": 41, "ref": "other"})
	causedBy(t, r, "40b-first", "the first row of a debounce key never fired")
	causedBy(t, r, "40b-other", "a row with a different debounce key never fired")
	for _, d := range readLog(t, r.path) {
		if d.GetCausation().GetParentId() == "40b-dup" {
			t.Fatalf("step 40b: the second row with ref=same fired (%s) inside a one-hour "+
				"debounce window (D264)", d.GetVerdict())
		}
	}
	r.detail(t, "budget 2: two WOULD_HAVE_FIRED then BUDGET_EXCEEDED, one budget_exceeded "+
		"signal; debounce on ref: the duplicate suppressed, the other key fired")
}

// step40ArmingNeedsABudget is 40c.
func step40ArmingNeedsABudget(t *testing.T) {
	t.Helper()
	base, err := os.ReadFile("acceptance.yaml")
	if err != nil {
		t.Fatalf("step 40c: %v", err)
	}
	const budget = "    max_firings_per_hour: 100\n"
	if !strings.Contains(string(base), budget) {
		t.Fatalf("step 40c: acceptance.yaml no longer carries the armed rule's %q", budget)
	}
	path := filepath.Join(t.TempDir(), "acceptance.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(base), budget, "", 1)), 0o600); err != nil {
		t.Fatalf("step 40c: %v", err)
	}
	doc, err := config.NewFileSource(path).Load(context.Background())
	if err == nil {
		err = doc.Validate()
	}
	if err == nil || !strings.Contains(err.Error(), "mode: enforce needs max_firings_per_hour") {
		t.Errorf("step 40c: an armed rule with no budget booted (got %v). Arming is two "+
			"deliberate acts (D264, D157)", err)
	}
}

// p3Step8 — depth is bounded, and a self-caused loop is refused rather than
// counted (P3 criterion 2, §4.11.4 item 2).
//
// **A LOOP IS A CHAIN WHOSE DEPTH KEEPS RISING**: a reflex acts, a source emits
// what it did, the rule matches again, each hop one deeper (D19). Depth is the
// instrument and MaxDepth the bound. Until this step, reaching it made Match
// return an error the engine LOGGED — Sekizui stopped the runaway and left no
// row saying so. It is a governance outcome and now it is on the record.
func p3Step8(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "depth is bounded, and a self-caused loop is refused rather than counted")
	if r.localOnly(t, "the engine and the bus are this instance's") {
		return
	}
	runEngine(t, r, "unarmed-ticket")

	publishAtDepth := func(id string, depth uint32) {
		t.Helper()
		e := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": 1})
		e.Id, e.Source = id, "fs:fixture"
		e.Causation = &sekizuiv1.Causation{RootId: "8-root", ParentId: "8-parent", Depth: depth,
			ProducedBy: "reflex:unarmed-ticket"}
		if err := r.srv.PublishForTest(e); err != nil {
			t.Fatalf("step 8: %v", err)
		}
	}
	// AT THE CAP FIRST, then just below it; the loop is sequential, so the
	// second record proves the first envelope was processed.
	publishAtDepth("8-at-cap", uint32(reflex.MaxDepth))
	publishAtDepth("8-below-cap", uint32(reflex.MaxDepth-1))

	below := causedBy(t, r, "8-below-cap", "a chain below the cap never reached the rule")
	if below.GetVerdict() != sekizuiv1.Verdict_VERDICT_WOULD_HAVE_FIRED {
		t.Errorf("step 8: depth %d recorded %s; below the cap the rule must behave normally",
			reflex.MaxDepth-1, below.GetVerdict())
	}
	var atCap *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetCausation().GetParentId() == "8-at-cap" {
			atCap = d
		}
	}
	switch {
	case atCap == nil:
		t.Fatalf("step 8: a chain at depth %d was stopped with NO record — the runaway was "+
			"refused silently", reflex.MaxDepth)
	case atCap.GetVerdict() != sekizuiv1.Verdict_VERDICT_BUDGET_EXCEEDED:
		t.Errorf("step 8: the chain at the cap recorded %s, want BUDGET_EXCEEDED", atCap.GetVerdict())
	case atCap.GetMatchedRule() != "unarmed-ticket#max_depth" || atCap.GetId() == "":
		t.Errorf("step 8: the refusal names rule %q with id %q; it must name the bound and be "+
			"citable", atCap.GetMatchedRule(), atCap.GetId())
	}
	r.detail(t, "depth %d fired as normal; depth %d was refused and recorded as BUDGET_EXCEEDED "+
		"(unarmed-ticket#max_depth), decision %s", reflex.MaxDepth-1, reflex.MaxDepth, atCap.GetId())
}

// mustSchemas is the deployment's registry — the connectors' schemas and the
// document's — what boot, the runner and the engine all validate against
// (D276, D279, CONTRACTS 128).
func mustSchemas(t *testing.T, doc *config.Document) *schemareg.Registry {
	t.Helper()
	reg, err := schemareg.ForDeployment(doc, builtin.ByKind(doc, nil))
	if err != nil {
		t.Fatalf("the acceptance document's schemas: %v", err)
	}
	return reg
}
