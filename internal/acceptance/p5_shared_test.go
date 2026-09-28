package acceptance

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/reflex"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p5Step7 — two rules sharing one budget exhaust it together, and the refusal
// names the shared budget (D264, D334).
func p5Step7(t *testing.T) {
	rule := func(name string, ordinal int) config.ReflexSpec {
		return config.ReflexSpec{
			Name: name, Principal: "reflex:friction", Enabled: true, MaxFiringsPerHour: 10, Budget: "tickets",
			Consumes: "sekizui.raw.kata.>", ExpectsType: "kata.row.v1",
			Where:  config.Predicate{{Path: "ordinal", Op: "eq", Value: float64(ordinal)}},
			Action: "kata.create_issue", TargetRef: "kata:alpha", With: map[string]any{"project": "PROJ"},
		}
	}
	r := newRunWith(t, runOpts{patch: func(d *config.Document) {
		d.ReflexBudgets = append(d.ReflexBudgets, config.ReflexBudgetSpec{Name: "tickets", MaxFiringsPerHour: 3})
		d.Reflexes = append(d.Reflexes, rule("shared-a", 71), rule("shared-b", 72))
	}})
	if r.localOnly(t, "the reflex engine is this instance's; no governed verb publishes onto its bus (D246)") {
		return
	}
	r.narrate(t, "two rules sharing one budget exhaust it together")
	ctx := context.Background()
	send := func(id string, ordinal int, name string) (fired bool, err error) {
		e := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": ordinal, "ref": id})
		e.Id, e.Source = id, "fs:fixture"
		for _, o := range r.engine.Dispatch(ctx, e) {
			if o.Rule == name {
				return o.Err == nil, o.Err
			}
		}
		t.Fatalf("step 7: %s did not match %s", name, id)
		return false, nil
	}

	// 7a — THREE FIRINGS BETWEEN THEM, each rule far inside its own budget of 10.
	for i, s := range []struct {
		name    string
		ordinal int
	}{{"shared-a", 71}, {"shared-b", 72}, {"shared-a", 71}} {
		if fired, err := send(fmt.Sprintf("p5-7-%d", i), s.ordinal, s.name); !fired {
			t.Fatalf("step 7a: firing %d (%s) inside the shared budget was refused: %v", i+1, s.name, err)
		}
	}

	// 7b — THE FOURTH, OF EITHER RULE, IS REFUSED BY THE SHARED BUDGET, and the
	// record names it rather than the rule's own.
	for _, s := range []struct {
		name    string
		ordinal int
	}{{"shared-b", 72}, {"shared-a", 71}} {
		id := "p5-7-over-" + s.name
		fired, err := send(id, s.ordinal, s.name)
		if fired || err == nil || !strings.Contains(err.Error(), `budget "tickets"`) {
			t.Errorf("step 7b: %s past the shared budget: fired=%v err=%v; want refused naming budget tickets",
				s.name, fired, err)
		}
		// THIS RULE'S record: acceptance.yaml's unarmed-ticket also fires on every
		// kata row, so the envelope has more than one.
		var rec *sekizuiv1.Decision
		for _, d := range readLog(t, r.path) {
			if d.GetCausation().GetParentId() == id && d.GetReflexName() == s.name {
				rec = d
			}
		}
		if rec == nil {
			t.Fatalf("step 7b: %s's refusal left no record", s.name)
		}
		if rec.GetVerdict() != sekizuiv1.Verdict_VERDICT_BUDGET_EXCEEDED || rec.GetMatchedRule() != "reflex_budgets:tickets" {
			t.Errorf("step 7b: %s recorded %v, rule %q; want BUDGET_EXCEEDED by reflex_budgets:tickets",
				s.name, rec.GetVerdict(), rec.GetMatchedRule())
		}
	}
	r.detail(t, "shared-a and shared-b, own budgets 10, sharing tickets (3/hr): a, b, a fired; the fourth of "+
		"either refused as BUDGET_EXCEEDED by reflex_budgets:tickets, not by its own budget")
}

// runRules runs an engine of just these rules on the run's own gateway and bus,
// as `main` runs its engine, until the test ends.
func runRules(t *testing.T, r *run, rules []config.ReflexSpec) {
	t.Helper()
	seq := 0
	engine := reflex.NewEngine(rules, r.srv, r.recorder, noSignal, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() string { seq++; return fmt.Sprintf("01J0P5CONC%04d", seq) }, mustSchemas(t, r.doc).Validate)
	ctx, cancel := context.WithCancel(context.Background())
	before := r.bus.Subscribers()
	wait, err := engine.Run(ctx, func(ctx context.Context, id *sekizuiv1.Identity, subjects []string) (reflex.Stream, error) {
		sub, err := r.srv.SubscribeAs(ctx, id, subjects)
		if err != nil {
			return nil, err
		}
		return sub, nil
	}, r.bus.Publish)
	if err != nil {
		cancel()
		t.Fatalf("the engine could not subscribe: %v", err)
	}
	// CANCELLING RELEASES EVERY BLOCKED WRITE: kata:slow holds a write until its
	// context ends, and that context is this engine's.
	t.Cleanup(func() { cancel(); wait() })
	waitFor(t, func() bool { return r.bus.Subscribers() >= before+len(rules) },
		"the rules never registered their subscriptions")
}

// inFlight counts a rule family's firings IN FLIGHT by the audit log's own
// definition: an intent recorded, its outcome not yet (§5.2.2). kata's writes do
// not borrow through the pool, so the pool's count would read zero.
func inFlight(t *testing.T, r *run, rulePrefix string) int {
	t.Helper()
	open := map[string]bool{}
	for _, d := range readLog(t, r.path) {
		if !strings.HasPrefix(d.GetReflexName(), rulePrefix) {
			continue
		}
		switch d.GetPhase() {
		case sekizuiv1.Phase_PHASE_INTENT:
			open[d.GetId()] = true
		case sekizuiv1.Phase_PHASE_OUTCOME:
			delete(open, d.GetId())
		}
	}
	return len(open)
}

// slowRule fires kata.create_issue on kata:slow, which holds the write open.
func slowRule(name string, ordinal int) config.ReflexSpec {
	return config.ReflexSpec{
		Name: name, Principal: "reflex:friction", Enabled: true, Mode: "enforce", MaxFiringsPerHour: 10,
		Consumes: "sekizui.raw.kata.>", ExpectsType: "kata.row.v1",
		Where:  config.Predicate{{Path: "ordinal", Op: "eq", Value: float64(ordinal)}},
		Action: "kata.create_issue", TargetRef: "kata:slow", With: map[string]any{"project": "PROJ"},
	}
}

func grantSlow(d *config.Document) {
	for i := range d.Grants {
		if d.Grants[i].Principal == "reflex:friction" {
			d.Grants[i].Allow = append(d.Grants[i].Allow,
				config.CapabilitySpec{Action: "kata.create_issue", TargetRef: "kata:slow"})
		}
	}
}

// p5Step8 — a rule's firings are serialised, and a principal's concurrency is
// bounded by the anzen cap (D335: criterion 8 as the architecture guarantees it).
func p5Step8(t *testing.T) {
	// 8a — ONE RULE, THREE EVENTS: one firing in flight, the others waiting in
	// the rule's own stream. Engine.Run reads a rule's stream on one goroutine.
	r := newRunWith(t, runOpts{patch: func(d *config.Document) {
		grantSlow(d)
		d.Reflexes = append(d.Reflexes, slowRule("serial", 81))
	}})
	if r.localOnly(t, "the reflex engine is this instance's; no governed verb publishes onto its bus (D246)") {
		return
	}
	r.narrate(t, "a rule's firings are serialised, and a principal's concurrency is bounded by the anzen cap")
	runRules(t, r, []config.ReflexSpec{slowRule("serial", 81)})
	for i := range 3 {
		publishRowWith(t, r, fmt.Sprintf("p5-8a-%d", i), "raw", "fs:fixture", map[string]any{"ordinal": 81, "ref": i})
	}
	waitFor(t, func() bool { return inFlight(t, r, "serial") >= 1 }, "the first firing never reached kata:slow")
	time.Sleep(200 * time.Millisecond) // long enough for a parallel engine to have started the other two
	if got := inFlight(t, r, "serial"); got != 1 {
		t.Errorf("step 8a: one rule has %d firings in flight; its stream is read on one goroutine, so one", got)
	}

	// 8b — FIVE RULES OF ONE PRINCIPAL AT ONCE: anzen's reflex-burst-cap (3)
	// holds three in flight and refuses the rest, recorded as its refusals.
	r2 := newRunWith(t, runOpts{patch: func(d *config.Document) {
		grantSlow(d)
		for i := range 5 {
			d.Reflexes = append(d.Reflexes, slowRule(fmt.Sprintf("burst-%d", i), 90+i))
		}
	}})
	var rules []config.ReflexSpec
	for i := range 5 {
		rules = append(rules, slowRule(fmt.Sprintf("burst-%d", i), 90+i))
	}
	runRules(t, r2, rules)
	for i := range 5 {
		publishRowWith(t, r2, fmt.Sprintf("p5-8b-%d", i), "raw", "fs:fixture", map[string]any{"ordinal": 90 + i, "ref": i})
	}
	capped := func() int {
		n := 0
		for _, d := range readLog(t, r2.path) {
			if d.GetRefusedBy() == sekizuiv1.RefusedBy_REFUSED_BY_ANZEN && d.GetMatchedRule() == "anzen:reflex-burst-cap" &&
				strings.HasPrefix(d.GetReflexName(), "burst-") {
				n++
			}
		}
		return n
	}
	waitFor(t, func() bool { return inFlight(t, r2, "burst-") == 3 && capped() == 2 },
		"five concurrent firings did not settle at three in flight and two refused by reflex-burst-cap")
	time.Sleep(100 * time.Millisecond)
	if got := inFlight(t, r2, "burst-"); got != 3 {
		t.Errorf("step 8b: %d firings of reflex:friction in flight; the anzen cap is 3", got)
	}
	r.detail(t, "one rule, three events on a write that blocks: 1 in flight; five rules of reflex:friction at "+
		"once: 3 in flight, 2 refused by anzen:reflex-burst-cap")
}
