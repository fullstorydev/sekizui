package jira_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/connectors/jira"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// TestTheGovernanceHalfIsRealConfiguration loads `jira.yaml` and validates it the
// way a deployment would.
//
// **WITHOUT THIS, BLUEPRINT STEPS 5 TO 9 ARE UNCHECKED PROSE.** The driver is
// guarded by the conformance suite; the lens, the ceiling, the narrow grant and
// the payload schema are YAML, and YAML nobody loads is exactly the
// plausible-looking snippet the blueprint exists to stop people pasting.
//
// **IT RUNS THE REAL BOOT CHECK RATHER THAN COMPARING STRINGS (D221).** The
// kata's answer key asserted its own `OutputType` as a literal and was wrong for
// two phases, because the driver carried the same wrong value and the two agreed
// with each other. Three copies that agree are not one checked copy. So this
// asks `schemareg` — the component that would refuse the boot — instead.
func TestTheGovernanceHalfIsRealConfiguration(t *testing.T) {
	raw, err := os.ReadFile("jira.yaml")
	if err != nil {
		t.Fatalf("reading the connector's configuration: %v", err)
	}

	var doc config.Document
	// **STRICT, so an unknown key is an ERROR rather than silence.** A lens
	// spelled `witholds` parses cleanly under a lenient unmarshal, binds to
	// nothing, and withholds nothing — a bar that reads as in force and enforces
	// nothing.
	if err := yaml.UnmarshalStrict(raw, &doc); err != nil {
		t.Fatalf("the connector's configuration does not load: %v", err)
	}

	if len(doc.Targets) != 1 || len(doc.Grants) != 1 || len(doc.Shin) != 1 ||
		len(doc.Anzen) != 1 {
		t.Fatalf("a governance block is missing: %d targets, %d grants, %d lenses, "+
			"%d guards — a connector shipping without one of these works perfectly "+
			"and governs nothing", len(doc.Targets), len(doc.Grants), len(doc.Shin),
			len(doc.Anzen))
	}

	checker := schemareg.NewChecker(
		func() *config.Document { return &doc },
		func(*config.Document) map[string]connector.Driver {
			return map[string]connector.Driver{jira.Kind: jira.New()}
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err := checker.Validate(context.Background()); err != nil {
		t.Errorf("the connector's configuration does not survive the boot-time schema "+
			"check: %v\n\nEvery type a driver declares must be registered in "+
			"`payload_schemas`, keyed by PAYLOAD TYPE and never by schema URI", err)
	}
}

// TestEveryCapabilityNamesItsTarget is blueprint step 6.
//
// A capability with no `target:` authorises the action against EVERY target of
// that kind, including ones added later by somebody who never read the grant.
// That is what makes it invisible in review rather than merely wide.
func TestEveryCapabilityNamesItsTarget(t *testing.T) {
	doc := loadDoc(t)

	for _, g := range doc.Grants {
		for _, c := range g.Allow {
			if c.TargetRef == "" {
				t.Errorf("%q names no target, so it authorises that action against "+
					"every jira target — including ones that do not exist yet", c.Action)
			}
		}
	}
}

// TestTheLensWithholdsWhatThisVendorActuallyCarries is blueprint step 7, and the
// one step nothing in the system would ever report missing.
//
// **THE ARM THAT MATTERS IS THE TYPE ONE.** A lens typed on something no action
// produces loads cleanly, reads in review as a control in force, and withholds
// nothing. `schemareg` catches an unregistered type; this catches a REGISTERED
// type that no action of this driver declares, which is a different mistake with
// the same symptom.
func TestTheLensWithholdsWhatThisVendorActuallyCarries(t *testing.T) {
	doc := loadDoc(t)

	declared := map[string]bool{}
	for _, spec := range jira.New().Actions() {
		if spec.OutputType != "" {
			declared[spec.OutputType] = true
		}
	}

	lens := doc.Shin[0]
	if !declared[lens.Type] {
		t.Errorf("lens %q is typed %q and no action of this driver declares that "+
			"OutputType. A lens on a type nothing produces is INERT", lens.Name, lens.Type)
	}
	if lens.Because == "" {
		t.Error("the lens records no `because`. A lens whose reason is unrecorded is " +
			"one nobody dares remove and nobody can justify, so it outlives the " +
			"concern that produced it")
	}

	// The reporter's address is the specific thing this vendor carries and an
	// agent has no use for. Named rather than counted: "withholds something" is
	// satisfied by withholding the wrong thing.
	var found bool
	for _, w := range lens.Withholds {
		if strings.Contains(w, "emailAddress") {
			found = true
		}
	}
	if !found {
		t.Errorf("the lens withholds %v, which does not include the reporter's email "+
			"address — the field this connector exists to be careful about",
			lens.Withholds)
	}
}

// TestTheGuardForbidsTheIrreversibleActions is blueprint step 8.
//
// A ceiling, not an opinion (D71): checked BEFORE policy, so a forbidden action
// is refused even where a grant permits it. `mode: enforce` matters — shadow is
// the default, so an omitted mode is a ceiling that only warns.
func TestTheGuardForbidsTheIrreversibleActions(t *testing.T) {
	guard := loadDoc(t).Anzen[0]

	if guard.Mode != "enforce" {
		t.Errorf("the guard is mode %q. Shadow is the default, so a ceiling that "+
			"omits this only warns while reading as enforcement", guard.Mode)
	}
	if len(guard.Forbids) == 0 {
		t.Fatal("the guard forbids nothing")
	}
	if len(guard.AppliesTo) != 0 {
		t.Errorf("the guard is scoped to %v. A destructive action nobody should "+
			"perform is not a per-principal question, and an empty applies_to means "+
			"every principal", guard.AppliesTo)
	}
}

func loadDoc(t *testing.T) config.Document {
	t.Helper()

	raw, err := os.ReadFile("jira.yaml")
	if err != nil {
		t.Fatalf("reading the connector's configuration: %v", err)
	}
	var doc config.Document
	if err := yaml.UnmarshalStrict(raw, &doc); err != nil {
		t.Fatalf("the connector's configuration does not load: %v", err)
	}
	return doc
}
