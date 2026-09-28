// Package reference_test is hako's skeleton: the governance packaging that
// turns `internal/connectors/kata` from a driver into a CONNECTOR (D175, D244).
//
// **WHY IT LIVES AS A TEST RATHER THAN AS A DOCUMENT.** `BLUEPRINT.md` next
// door can say a grant should name its target; only this can fail when one
// does not. The document carries the reasoning a compiler cannot, and
// everything that CAN be checked is checked here — which is the division the
// markdown was on the wrong side of for two phases (CONTRACTS 96, D222).
//
// **AND WHY IT GOVERNS `kata` RATHER THAN A FICTIONAL VENDOR.** The exercise
// next door has a fictional notes service, because teaching the JUDGEMENT —
// what to withhold, what a real quota implies — needs a payload and a vendor.
// This governs the driver every author already reads, so the packaging is
// demonstrated against something whose action list, output type and
// idempotency classes are real and are cross-checked below. A grant naming an
// action `kata` does not implement fails HERE rather than at somebody's deploy.
package reference_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/grantcheck"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// load composes this directory as a deployment's loader does: kata.yaml and
// the connector's presets.yaml dropped in beside it (D327), presets expanded.
//
// THROUGH THE LOADER, NOT A RAW UNMARSHAL. The raw read could not expand a
// preset, so the skeleton could not have shown one. The loader's parse is
// STRICT too — an unknown key is an ERROR rather than silence: a lens spelled
// `witholds` parses cleanly under a lenient unmarshal, binds to nothing and
// withholds nothing, which is this repository's recurring defect in its
// quietest form.
func load(t *testing.T) config.Document {
	t.Helper()
	doc, err := config.NewFileSource(".").Load(context.Background())
	if err != nil {
		t.Fatalf("the reference connector does not load: %v", err)
	}
	return *doc
}

// TestTheBoxIsComplete — a connector missing any of the five is a driver with
// paperwork.
func TestTheBoxIsComplete(t *testing.T) {
	doc := load(t)

	// THE SCHEMAS ARE IN THE BOX, BUT NOT IN THIS FILE (D279): a connector
	// ships the schema of everything it emits beside its code, so the fifth
	// item is counted from the driver — and a schema written in the document
	// for one of its types would be refused at boot.
	schemas, err := kata.New().Schemas()
	if err != nil {
		t.Fatalf("the reference driver's schemas do not parse: %v", err)
	}
	for what, n := range map[string]int{
		"targets": len(doc.Targets), "grants": len(doc.Grants),
		"shin lenses": len(doc.Shin), "anzen guards": len(doc.Anzen),
		"payload schemas (shipped by the driver)": len(schemas),
	} {
		if n == 0 {
			t.Errorf("the box has no %s. D175's list is what makes this a CONNECTOR "+
				"rather than a driver somebody deployed", what)
		}
	}
}

// TestTheConfigurationSurvivesTheRealBootCheck runs what a deployment runs.
//
// **NOT A STRING THIS FILE TYPED ITSELF**, which is the mistake the exercise's
// answer key made and cemented for two phases: it asserted the schema URI where
// the payload TYPE belongs, the driver carried the same wrong value, and the
// two agreed with each other while a learner following them would have been
// refused at boot naming their own action.
func TestTheConfigurationSurvivesTheRealBootCheck(t *testing.T) {
	doc := load(t)

	checker := schemareg.NewChecker(
		func() *config.Document { return &doc },
		func(*config.Document) map[string]connector.Driver {
			return map[string]connector.Driver{kata.Kind: kata.New()}
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err := checker.Validate(context.Background()); err != nil {
		t.Errorf("the reference connector does not survive the boot-time schema check: %v", err)
	}
}

// TestTheGrantFitsTheDriver is what governing a REAL driver buys.
//
// The exercise's answer key governs a driver in the same directory, so its
// grant and its actions agree by construction — D222's "a fixture agrees with
// us" shape. Here the driver is the one the whole tree uses, so this is a
// genuine cross-check: every granted action exists, and every lensed type is
// one the driver actually declares.
func TestTheGrantFitsTheDriver(t *testing.T) {
	doc := load(t)

	implemented := map[string]connector.ActionSpec{}
	for _, spec := range kata.New().Actions() {
		implemented[spec.Name] = spec
	}

	for _, g := range doc.Grants {
		for _, c := range g.Allow {
			if _, ok := implemented[c.Action]; !ok {
				t.Errorf("the grant allows %q, which the driver does not implement. "+
					"A capability catalog that advertises it would lie to an agent, "+
					"which then burns turns discovering it (D196)", c.Action)
			}
			// EVERY CAPABILITY NAMES ITS TARGET. Omitting it is the defect the
			// exercise's step 6 is about, and the reference must not contain
			// the thing the exercise teaches you to remove.
			if c.TargetRef == "" {
				t.Errorf("capability %q names no target, so it covers every target of "+
					"this kind — including ones added later by somebody who never "+
					"read this grant", c.Action)
			}
		}
	}

	declaredTypes := map[string]bool{}
	for _, spec := range implemented {
		if spec.OutputType != "" {
			declaredTypes[spec.OutputType] = true
		}
	}
	for _, lens := range doc.Shin {
		if lens.Type != "" && !declaredTypes[lens.Type] {
			t.Errorf("the lens names type %q, which no action of this driver declares "+
				"as its OutputType. A lens keyed on a type nothing produces withholds "+
				"nothing, and reads as being in force", lens.Type)
		}
	}
}

// TestTheCeilingCoversWhatTheGrantDoesNot — the asymmetry, asserted.
//
// A grant is written by whoever needs a capability; a ceiling is written once
// by whoever carries the blast radius, and it holds even where a grant permits
// (D71). The reference is only a reference if it demonstrates that rather than
// happening to be safe because nobody asked for the dangerous thing.
func TestTheCeilingCoversWhatTheGrantDoesNot(t *testing.T) {
	doc := load(t)

	if len(doc.Anzen) == 0 || doc.Anzen[0].Mode != "enforce" {
		t.Fatal("the guard is absent or not enforcing — shadow is the default, so an " +
			"omitted mode is a ceiling that only warns")
	}
	if len(doc.Anzen[0].Forbids) == 0 {
		t.Fatal("the guard forbids nothing")
	}

	// NON-VACUITY: the forbidden action must actually EXIST on the driver, or
	// the ceiling is a rule about nothing and this test passes for the wrong
	// reason.
	var destructive bool
	for _, spec := range kata.New().Actions() {
		if spec.Name == "kata.delete_project" {
			destructive = true
		}
	}
	if !destructive {
		t.Error("the ceiling forbids `kata.delete_*` and the driver implements no such " +
			"action, so it bounds nothing. A guard aimed at an action nobody has is " +
			"the shape CONTRACTS 65 keeps finding")
	}
}

// TestThePresetIsTheConnectorsAndGrantsExactlyItsList — the deployment side of
// D327, on the driver every author reads.
//
// The grant names `kata.viewer`; the loader expanded it to the preset's list,
// no more; the copy this skeleton drops in is kata's current suggestion, so
// boot reports nothing; and every preset holds its `mirrors:` claim against
// kata's own grading — the rule boot applies.
func TestThePresetIsTheConnectorsAndGrantsExactlyItsList(t *testing.T) {
	doc := load(t)
	var viewer []config.CapabilitySpec
	for _, g := range doc.Grants {
		if g.Principal == "agent:reference-viewer" {
			viewer = g.Allow
		}
	}
	if len(viewer) != 1 || viewer[0].Action != "kata.read" || viewer[0].TargetRef != "kata:reference" {
		t.Fatalf("the preset grant expanded to %+v; want kata.viewer's one action, kata.read, on kata:reference", viewer)
	}
	if o := viewer[0].Origin; o == nil || o.Preset != "kata.viewer" {
		t.Errorf("the expanded capability does not remember its preset (%+v), so its record could not name it", o)
	}
	drivers := map[string]connector.Driver{kata.Kind: kata.New()}
	if f := grantcheck.PresetFindings(doc.Presets, drivers); len(f) != 0 {
		t.Errorf("the reference's copy differs from kata's suggestion: %v", f)
	}
	if m := grantcheck.PresetMisses(doc.Presets, drivers, nil); len(m) != 0 {
		t.Errorf("the reference's presets do not hold: %v", m)
	}
}
