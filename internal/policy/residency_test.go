package policy

import (
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// residencyDoc has one target per class and grants that differ only in whether
// they name the crossing.
const residencyDoc = `
targets:
  - {ref: kata:eu, kind: kata, tenant: a, residency: eu, base_url: https://eu.invalid}
  - {ref: kata:us, kind: kata, tenant: b, residency: us, base_url: https://us.invalid}
  - {ref: kata:anywhere, kind: kata, tenant: c, base_url: https://any.invalid}
grants:
  - principal: agent:silent
    allow:
      - {action: kata.read, target: kata:us}
      - {action: kata.read, target: kata:anywhere}
  - principal: agent:named
    allow:
      - {action: kata.read, target: kata:us, where: {target_residency: [us]}}
  - principal: agent:elsewhere
    allow:
      - {action: kata.read, target: kata:us, where: {target_residency: [eu, jp]}}
`

func residencyEngine(t *testing.T, permitted []string) *GrantEngine {
	t.Helper()
	var doc config.Document
	if err := yaml.Unmarshal([]byte(residencyDoc), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return NewGrantEngine(&doc, permitted)
}

// TestAnArgumentCannotSatisfyAResidencyConstraint is the security property the
// whole facet mechanism exists for (D136).
//
// `target_residency` rides the `where:` vocabulary, and every OTHER key in that
// vocabulary is matched against the caller's arguments. If this one were too, a
// command could carry `target_residency: "eu"` and satisfy its own compliance
// constraint — the exact inverse of the hole whereMatches already closes by
// refusing a MISSING argument. Absence is not consent in one direction; a
// forged presence must not be consent in the other.
func TestAnArgumentCannotSatisfyAResidencyConstraint(t *testing.T) {
	e := residencyEngine(t, []string{"eu", "us"})

	// agent:elsewhere may read kata:us only where the target is eu or jp
	// resident. It is neither, so this can never be allowed — including when the
	// caller helpfully supplies the answer it wants.
	forged := ask(t, e, "agent:elsewhere", "agent:elsewhere", "kata.read", "kata:us",
		map[string]any{"target_residency": "eu"})

	if forged.Verdict != sekizuiv1.Verdict_VERDICT_DENY {
		t.Fatalf("verdict = %v, want DENY. A command supplied its own residency and "+
			"was believed; the constraint is answered from configuration or it is "+
			"not a constraint at all", forged.Verdict)
	}

	// NON-VACUITY: the same principal is not simply denied everything. Naming
	// the true class in the GRANT works, which is what makes the denial above
	// about provenance rather than about the value.
	if d := ask(t, e, "agent:named", "agent:named", "kata.read", "kata:us", nil); //nolint:lll
	d.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
		t.Fatalf("verdict = %v, want ALLOW; a grant naming the target's real class "+
			"must work, or the test above proves only that everything is denied", d.Verdict)
	}
}

// TestTheGrantLayerTurnsOnWithTheSecondClass covers the rule being modal on the
// deployment, in both directions.
//
// A single-class deployment has no crossing to authorise, so a grant that says
// nothing is sufficient and every configuration written before D136 keeps its
// meaning. Declaring a second class makes every residency-bearing target a
// crossing, and silence stops being sufficient.
func TestTheGrantLayerTurnsOnWithTheSecondClass(t *testing.T) {
	cases := []struct {
		name      string
		permitted []string
		want      sekizuiv1.Verdict
	}{
		{"unconstrained", nil, sekizuiv1.Verdict_VERDICT_ALLOW},
		{"single class", []string{"us"}, sekizuiv1.Verdict_VERDICT_ALLOW},
		{"two classes", []string{"eu", "us"}, sekizuiv1.Verdict_VERDICT_DENY},

		// Arbitrary classes, not an eu/us binary. A deployment serving de, fr
		// and jp is the case CONTRACTS item 39 has to cover, and `len > 1` is
		// the rule precisely so it does.
		{"three classes", []string{"de", "fr", "jp"}, sekizuiv1.Verdict_VERDICT_DENY},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := residencyEngine(t, c.permitted)
			d := ask(t, e, "agent:silent", "agent:silent", "kata.read", "kata:us", nil)
			if d.Verdict != c.want {
				t.Errorf("verdict = %v, want %v (reason %q)", d.Verdict, c.want, d.Reason)
			}
		})
	}
}

// TestAnUnclassifiedTargetNeedsNoCrossing. There is no border to authorise, so
// a grant that says nothing is sufficient however many classes are served.
//
// This is the composition that makes UnclassifiedTargets a BOOT REFUSAL rather
// than a nuance: the ceiling permits an empty class too, so both layers pass and
// the target is an unpoliced route. The permissiveness is correct here and the
// hole is closed one level up, at wiring, where the deployment is known.
func TestAnUnclassifiedTargetNeedsNoCrossing(t *testing.T) {
	e := residencyEngine(t, []string{"eu", "us"})

	if d := ask(t, e, "agent:silent", "agent:silent", "kata.read", "kata:anywhere", nil); //nolint:lll
	d.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
		t.Errorf("verdict = %v, want ALLOW; an unclassified target has no crossing "+
			"to authorise", d.Verdict)
	}

	if orphans := e.UnclassifiedTargets(); len(orphans) != 1 || orphans[0] != "kata:anywhere" {
		t.Errorf("UnclassifiedTargets() = %v, want [kata:anywhere] — the hole the "+
			"allow above leaves must be reported somewhere", orphans)
	}
}

// TestUncoveredCrossingsNamesOnlyWhatIsUncovered. The boot report is what pays
// back the rule being modal, so it has to discriminate: a capability naming the
// crossing must not appear, or an operator learns to ignore the list.
func TestUncoveredCrossingsNamesOnlyWhatIsUncovered(t *testing.T) {
	got := residencyEngine(t, []string{"eu", "us"}).UncoveredCrossings()

	want := []Crossing{
		{Principal: "agent:silent", Action: "kata.read", TargetRef: "kata:us", Residency: "us"},
	}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("UncoveredCrossings() = %+v, want %+v", got, want)
	}

	// kata:anywhere is unclassified, so agent:silent's capability on it is not a
	// crossing and must not be reported — it is UnclassifiedTargets' business.
	// agent:named and agent:elsewhere both name a class, covered or not: a
	// constraint that cannot be satisfied is dead config, which boot validation
	// refuses, and not an uncovered crossing.
}
