package acceptance

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/pkg/config"
)

// partial declares SOME properties and not others — a provider written before a
// posture field existed (D117).
//
// THE POINT IS THAT IT IMPLEMENTS Postured. Step 36 already covers a provider
// that declares nothing at all; this is the subtler and likelier case, because a
// provider that answers is a provider a reviewer will read as complete.
type partial struct{}

func (partial) Scheme() string { return "partial" }
func (partial) Resolve(context.Context, string) (config.Resolution, error) {
	return config.Resolution{Material: []byte("x")}, nil
}

func (partial) Posture(string) (config.Posture, error) {
	// Versioned, and silent about everything else — exactly what an
	// un-updated provider looks like the day a new property is added.
	return config.Posture{
		Versioning: config.VersionedByReference,
		Rotation:   config.RotationOnChange,
		AtRest:     "static-file",
		Why:        "a provider that predates the property being required",
	}, nil
}

// step43ThePostureCheckIsNotRoutedThroughShin proves D116's surviving half.
//
// D116 draws a category distinction that is easy to lose: posture CHECKING and
// posture DISCLOSURE look alike — declare, require, intersect — and are not the
// same kind of thing. Shin is a runtime projection over payloads whose
// load-bearing property is that it only ever REMOVES, which is why it can be
// trusted with automation (D85). A boot-time yes/no admission check reduces
// nothing, and routing it through machinery whose invariant is "strictly
// reducing" would empty that invariant of meaning.
//
// D116's DISCLOSURE half is superseded — D118 keeps decisions off the bus
// entirely, so there is no consumer for a lens to withhold posture from, and
// step 42 now proves that instead (D154). This half stands.
func step43ThePostureCheckIsNotRoutedThroughShin(t *testing.T) {
	// --- 43a: NON-VACUITY FOR THE CATEGORY DISTINCTION -------------------
	//
	// A deployment with NO lenses at all still refuses a provider missing a
	// required property. If the check were routed through shin, an unlensed
	// deployment would be an unchecked one — and "no lenses configured" is the
	// overwhelmingly common case.
	t.Run("a deployment with no lenses still refuses a missing property", func(t *testing.T) {
		doc := policyDoc("partial://thing", []string{"audited_reads"})
		if len(doc.Shin) != 0 {
			t.Fatal("the fixture declares lenses, so this arm would not prove what it claims")
		}

		assertRefused(t, credential.RefuseAtBoot(doc, managed(), false,
			[]config.Provider{partial{}}), "audited_reads")
	})

	// --- 43b: STRUCTURAL — the check cannot consult shin -----------------
	//
	// Asserted on the import graph rather than on behaviour, because behaviour
	// can only show that it did not happen this time. A category distinction is
	// worth enforcing where it is impossible to violate by accident: if
	// internal/credential cannot see internal/shin, nobody can route an
	// admission check through a projection without first making a change a
	// reviewer would notice.
	t.Run("the credential package cannot see shin", func(t *testing.T) {
		dir := filepath.Join(repoRoot(t), "internal", "credential")
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}

		fset := token.NewFileSet()
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parsing %s: %v", e.Name(), err)
			}
			for _, imp := range f.Imports {
				if strings.Contains(imp.Path.Value, "internal/shin") {
					t.Errorf("%s imports internal/shin. Posture CHECKING is admission and "+
						"posture DISCLOSURE is projection (D116); routing the check through "+
						"machinery whose invariant is 'strictly reducing' would empty that "+
						"invariant of the meaning D85 relies on", e.Name())
				}
			}
		}
	})
}

// step44AnUndeclaredPropertyIsNotOffered proves D117's house form.
//
// "Not declared is not available", across three unrelated mechanisms: an MCP
// tool is not callable unless a vetted spec names it (D46); a shin lens is not
// selectable unless declared, and naming an undeclared one is refused rather
// than ignored (D84); and a credential property is not offered unless a provider
// states it (D111).
//
// **THE TEMPTING DEFAULT IS THE OPPOSITE**, which is why D117 is worth stating
// as a rule rather than repeating three times. Reading absence as "no constraint
// stated, therefore permitted" is exactly how a vendor's new tool becomes
// callable before anyone reviews it, and how a provider that never declared its
// weakness passes the policy written to catch it.
func step44AnUndeclaredPropertyIsNotOffered(t *testing.T) {
	providers := []config.Provider{partial{}}

	// --- 44a: THE PROPERTY IT DOES DECLARE IS HONOURED ------------------
	//
	// First, so the arms below cannot pass against a provider whose posture is
	// simply ignored.
	t.Run("a declared property is honoured", func(t *testing.T) {
		if got := credential.RefuseAtBoot(
			policyDoc("partial://thing", []string{"versioned"}), managed(), false, providers); len(got) > 0 {
			t.Errorf("a provider declaring `versioned` was refused for lacking it: %v", got)
		}
	})

	// --- 44b: THE PROPERTY IT IS SILENT ABOUT IS REFUSED ----------------
	//
	// This is the day-after-a-new-field case. `audited_reads` is false on a
	// provider that never mentioned it, and a deployment requiring it does not
	// start. The alternative — treating silence as satisfaction — means the
	// providers least likely to have been reviewed are the ones that pass.
	t.Run("a property the provider is silent about is refused", func(t *testing.T) {
		refusals := credential.RefuseAtBoot(
			policyDoc("partial://thing", []string{"audited_reads"}), managed(), false, providers)

		assertRefused(t, refusals, "audited_reads")
		// The provider's own words appear, so an operator reading the refusal
		// learns what the source IS rather than only what it lacks.
		assertRefused(t, refusals, "predates the property")
	})

	// --- 44c: SILENCE IS REFUSED FOR EVERY PROPERTY, NOT A CHOSEN ONE ---
	//
	// Walking the whole vocabulary rather than picking one, because a check that
	// handled two of three properties and defaulted the third to "offered" would
	// pass a single-property test and fail exactly once in production.
	t.Run("every property the provider omits is refused", func(t *testing.T) {
		declared := map[config.CredentialProperty]bool{config.PropertyVersioned: true}

		for _, prop := range config.CredentialProperties {
			refusals := credential.RefuseAtBoot(
				policyDoc("partial://thing", []string{string(prop)}), managed(), false, providers)

			if declared[prop] {
				if len(refusals) > 0 {
					t.Errorf("%s is declared and was refused: %v", prop, refusals)
				}
				continue
			}
			if len(refusals) == 0 {
				t.Errorf("%s is NOT declared by this provider and was permitted. Silence "+
					"read as satisfaction means the providers least likely to have been "+
					"reviewed are the ones that pass the policy written to catch them", prop)
			}
		}
	})
}
