package acceptance

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
)

// P5 steps 3 and 4: the boot refusals, over Fullstory.

// fullstoryReflex is a bus→driver rule on real Fullstory session events that
// acts on Fullstory itself — the shape P5's rules take.
func fullstoryReflex(action string) config.ReflexSpec {
	return config.ReflexSpec{
		Name: "fs-act-on-event", Principal: "reflex:friction", Enabled: true,
		Consumes: "sekizui.raw.fullstory.>", ExpectsType: "fullstory.session_event.v1",
		Action: action, TargetRef: "fs:events", With: map[string]any{"id": "u-1"},
	}
}

// grantOn gives reflex:friction the capability on fs:events.
func grantOn(doc *config.Document, action string) {
	for i := range doc.Grants {
		if doc.Grants[i].Principal == "reflex:friction" {
			doc.Grants[i].Allow = append(doc.Grants[i].Allow,
				config.CapabilitySpec{Action: action, TargetRef: "fs:events"})
		}
	}
}

// p5Step4 — a Fullstory rule granted an action its principal lacks is refused
// at boot, and so is one whose action the connector's ceiling forbids (D330).
func p5Step4(t *testing.T) {
	// 4a — UNGRANTED: config's own check (§4.11.4b), named.
	doc, err := config.NewFileSource("acceptance.yaml").Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doc.Reflexes = append(doc.Reflexes, fullstoryReflex("fullstory.create_annotation"))
	err = doc.Validate()
	if err == nil {
		t.Fatal("step 4a: a Fullstory rule whose principal holds no grant for its action booted")
	}
	for _, want := range []string{"fs-act-on-event", "reflex:friction", "fullstory.create_annotation"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("step 4a: the refusal does not name %q: %v", want, err)
		}
	}

	// 4b — FORBIDDEN BY THE CEILING, under a wildcard grant: the gateway's boot
	// check, which the acceptance harness now runs as main does.
	rules := loadSuggestedAnzen(t)
	withCeiling := func(action string) func(*config.Document) {
		return func(d *config.Document) {
			kept := d.Anzen[:0]
			for _, r := range d.Anzen {
				if r.Name != "no-destructive-actions" { // prove the connector's rule, P4 step 33's reason
					kept = append(kept, r)
				}
			}
			d.Anzen = append(kept, rules...)
			grantOn(d, "fullstory.*")
			d.Reflexes = append(d.Reflexes, fullstoryReflex(action))
		}
	}
	var bootErr error
	if r := newRunWith(t, runOpts{patch: withCeiling(deleteUser), bootErr: &bootErr}); r != nil {
		if r.localOnly(t, "the patched deployment is this instance's") {
			return
		}
		t.Fatalf("step 4b: a rule whose every firing the ceiling refuses booted (%s)", deleteUser)
	}
	for _, want := range []string{"fs-act-on-event", deleteUser, "fullstory-irreversible", "can never act"} {
		if bootErr == nil || !strings.Contains(bootErr.Error(), want) {
			t.Errorf("step 4b: the boot refusal does not name %q: %v", want, bootErr)
		}
	}

	// 4c — NON-VACUITY: the same rule and grant, acting with a write the ceiling
	// does not name, boots — so 4b refused the CEILING's action, not the shape.
	r := newRunWith(t, runOpts{patch: withCeiling("fullstory.create_annotation")})
	r.narrate(t, "a Fullstory rule granted an action its principal lacks is refused at boot")
	r.detail(t, "ungranted: refused naming rule, principal and action; %s under a wildcard grant: refused, "+
		"fullstory-irreversible forbids every firing; create_annotation, which no guard names: boots", deleteUser)
}

// p5Step3 — criterion 3 is DISCHARGED BY CITATION (the maintainer, D330): P3 step 10
// already refuses a cyclic rule over Fullstory types at boot, naming the cycle,
// in every cumulative run. Re-asserting it here would prove nothing new; a
// citation that only checked the step EXISTS would be a claim. So this finds it
// in P3's own table, requires it built and about a cycle, and RUNS it — if P3
// step 10 ever regresses, P5's criterion falls with it.
func p5Step3(t *testing.T) {
	var cited *p3Step
	for _, s := range p3StepTable() {
		if s.n == 10 {
			s := s
			cited = &s
		}
	}
	switch {
	case cited == nil:
		t.Fatal("step 3: P3 has no step 10 to cite; the criterion is unproven")
	case cited.run == nil:
		t.Fatal("step 3: P3 step 10 is not built, so citing it proves nothing")
	case !strings.Contains(cited.what, "cyclic"):
		t.Fatalf("step 3: P3 step 10 is no longer a cyclic-rule refusal (%q); cite the step that is, "+
			"or prove criterion 3 here", cited.what)
	}
	// OVER FULLSTORY TYPES is a fact about its CODE — its text never says so —
	// so the code is read: crude, as connectorcheck's "the tests mention the
	// suite" is crude, and a crude check that fires beats a claim nobody reads.
	src, err := os.ReadFile("p3_pure_test.go")
	if err != nil {
		t.Fatalf("step 3: %v", err)
	}
	_, after, found := strings.Cut(string(src), "func p3Step10(")
	body, _, _ := strings.Cut(after, "\nfunc ")
	if !found || !strings.Contains(body, "fullstory.") {
		t.Fatal("step 3: P3 step 10's rule is no longer over a Fullstory type; criterion 3 is P5's " +
			"over Fullstory, so cite a step that is, or prove it here")
	}
	cited.run(t)
}
