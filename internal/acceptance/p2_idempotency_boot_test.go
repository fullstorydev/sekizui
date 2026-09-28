package acceptance

import (
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// step5AMutatingActionWithNoIdempotencyClassFailsTheLoad proves D163.
//
// **THE FAILURE DIRECTION IS THE WHOLE ASSERTION.** There is no safe default for
// an unclassified mutating action: `none` would quietly forbid retries an
// upstream supports, and anything else permits a double-write nobody chose. So
// the load fails and a human writes the classification down — the same rule
// §4.9a.1 gives `Mutating` for MCP tools, and the same reason.
//
// FIRST P2 STEP BUILT, and chosen first deliberately: it needs no credential and
// no upstream, and it forces ActionSpec and the validator into their final shape
// before three drivers depend on them.
func step5AMutatingActionWithNoIdempotencyClassFailsTheLoad(t *testing.T) {
	// --- 5a: THE REFUSAL ---------------------------------------------------
	t.Run("a mutating action with no class is refused", func(t *testing.T) {
		problems := connector.ValidateActions("probe", []connector.ActionSpec{{NoResult: true,
			Name:        "probe.create_thing",
			Description: "Create a thing.",
			Mutating:    true,
			InputSchema: "sekizui://schema/probe/create_thing.v1",
		}})
		if len(problems) == 0 {
			t.Fatal("an unclassified MUTATING action loaded cleanly. There is no safe " +
				"default here: `none` forbids retries the upstream may support, and any " +
				"other default permits a double-write nobody chose (D163)")
		}
		joined := strings.Join(problems, "\n")
		if !strings.Contains(joined, "no idempotency class") {
			t.Errorf("the refusal does not say what is missing:\n%s", joined)
		}
		// THE MESSAGE MUST NAME THE CHOICES. An operator told "invalid" at boot
		// has to go reading source; told the vocabulary, they can fix it.
		for _, class := range connector.IdempotencyClasses() {
			if !strings.Contains(joined, string(class)) {
				t.Errorf("the refusal does not offer %q. It is derived from "+
					"IdempotencyClasses() precisely so a class added later appears "+
					"without anybody editing this message (§15q)", class)
			}
		}
	})

	// --- 5b: NON-VACUITY — a CLASSIFIED action loads ------------------------
	//
	// Without this the step passes against a validator that refuses everything,
	// and "the check works" would be indistinguishable from "the check is broken
	// in the other direction". P1 step 34 is the local precedent and CONTRACTS 59
	// is why it is a habit rather than a nicety.
	t.Run("a classified action loads", func(t *testing.T) {
		if problems := connector.ValidateActions("probe", []connector.ActionSpec{{NoResult: true,
			Name:        "probe.create_thing",
			Description: "Create a thing.",
			Mutating:    true,
			Idempotency: connector.IdempotencyNatural,
			InputSchema: "sekizui://schema/probe/create_thing.v1",
		}}); len(problems) > 0 {
			t.Errorf("a correctly classified action was refused: %v", problems)
		}
	})

	// --- 5c: A READ MUST NOT CARRY ONE -------------------------------------
	//
	// The paired invariant, in the shape OutputSchema and OutputSchemaOrigin
	// already use: a field that can never be consulted must be refused rather
	// than ignored, or a reviewer reads it as a guarantee in force.
	t.Run("a non-mutating action declaring a class is refused", func(t *testing.T) {
		if problems := connector.ValidateActions("probe", []connector.ActionSpec{{NoResult: true,
			Name:        "probe.read_thing",
			Description: "Read a thing.",
			Mutating:    false,
			Idempotency: connector.IdempotencyNatural,
		}}); len(problems) == 0 {
			t.Error("a READ declaring an idempotency class loaded cleanly. The " +
				"classification would never be consulted, so leaving it accepted lets " +
				"somebody read it as in force")
		}
	})

	// --- 5d: THE REAL DRIVER SATISFIES ITS OWN CONTRACT --------------------
	//
	// The arm that stops this being a test about a fixture. Every action the
	// reference driver advertises is validated, so a class dropped from a real
	// ActionSpec fails here rather than at the first retry.
	t.Run("the reference driver passes its own contract", func(t *testing.T) {
		d := kata.New()
		if problems := connector.ValidateActions(d.Kind(), d.Actions()); len(problems) > 0 {
			t.Errorf("the reference driver fails the contract every driver must meet:\n  - %s",
				strings.Join(problems, "\n  - "))
		}
	})

	// --- 5e: EVERY CLASS IS EITHER IMPLEMENTED OR REFUSED ------------------
	//
	// **RANGES OVER THE VOCABULARY, so a class added later is covered by
	// existing.** D163 builds the vocabulary whole even where a member is not
	// fleshed out, so the blueprint can show a connector author the full shape —
	// and the hazard that creates is a class sitting declared and inert. D53's
	// rule closes it: run or refuse, never silently succeed at nothing.
	t.Run("a declared but unimplemented class refuses rather than degrading", func(t *testing.T) {
		var unimplemented int
		for _, class := range connector.IdempotencyClasses() {
			spec := connector.ActionSpec{NoResult: true,
				Name: "probe.act", Description: "Act on a thing.",
				Mutating: true, Idempotency: class,
			}
			if class.NeedsPlacement() {
				spec.IdempotencyPlacement = "Idempotency-Key"
			}
			problems := connector.ValidateActions("probe", []connector.ActionSpec{spec})

			if class.Implemented() {
				if len(problems) > 0 {
					t.Errorf("implemented class %q was refused: %v", class, problems)
				}
				continue
			}
			unimplemented++
			if len(problems) == 0 {
				t.Errorf("class %q is declared and NOT implemented, and it loaded "+
					"cleanly. A class that cannot be honoured must fail the load, or a "+
					"connector author reads the vocabulary as a menu of things that work "+
					"and finds out at the first call", class)
			}
		}
		// NON-VACUITY: if every class becomes implemented this arm proves nothing,
		// and it should say so rather than pass quietly.
		if unimplemented == 0 {
			t.Skip("every class in the vocabulary is now implemented, so this arm has " +
				"nothing to prove. Skipping loudly rather than passing — if a class is " +
				"added unimplemented later, this starts asserting again")
		}
	})
}
