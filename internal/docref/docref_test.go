package docref

import (
	"strings"
	"testing"
)

// THIS PACKAGE IS NOW A SINGLE POINT OF FAILURE FOR EVERY DOCUMENT GUARD, which
// is the honest cost of centralising (D185). A bug in one extractor here weakens
// four guards at once and each of them still passes. So it gets its own tests,
// and the ones that matter are the NEGATIVE cases: what happens when a heading
// moves, a table prefix stops matching, or a marker is deleted.
//
// The positive cases are almost self-evidently right. The negative ones are the
// whole reason the package exists.

const sample = `# Title

Intro prose.

## 12. Phases

### 12.1 Spikes

| Spike | Why |
|---|---|
| **A** | because |

### 12.2 Phase overview

| Phase | Question | Release |
|---|---|---|
| **P0** Contracts | Does it work? | — |
| **P1** Tenancy | Can tenants leak? | — |

## 13. Glossary

Cites D45–D51 and D163, plus D9999-D1.

<!-- BEGIN:derived -->
derived text
<!-- END:derived -->
`

func doc(text string) *Doc { return &Doc{name: "sample", text: text} }

// --- the property the package exists for --------------------------------

func TestAnExtractorThatMatchesNothingErrors(t *testing.T) {
	// EACH OF THESE WOULD OTHERWISE RETURN AN EMPTY RESULT, and a guard
	// comparing two empty results finds them equal and reports success. That is
	// CONTRACTS 67's failure shape, and it is the one thing this package must
	// make impossible.
	for name, get := range map[string]func() error{
		"a heading that moved": func() error {
			_, err := doc(sample).Section("### 12.3 Nonexistent").Rows("| **P")
			return err
		},
		"a table prefix that stopped matching": func() error {
			_, err := doc(sample).Section("### 12.2 Phase overview").Rows("| **Q")
			return err
		},
		"a marker that was deleted": func() error {
			_, err := doc(sample).Marked("absent").Text()
			return err
		},
		"a bound that is not present": func() error {
			_, err := doc(sample).Between("## 13.", "## 99.").Text()
			return err
		},
		"a section citing no decisions": func() error {
			_, err := doc(sample).Section("### 12.1 Spikes").Decisions()
			return err
		},
		"a heading with no level": func() error {
			_, err := doc(sample).Section("12.2 Phase overview").Text()
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := get(); err == nil {
				t.Error("returned no error. An extractor that matches nothing must FAIL " +
					"rather than hand back an empty result, because a guard ranging over " +
					"nothing passes while checking nothing")
			}
		})
	}
}

// TestASlicingErrorSurvivesToTheTerminalCall is what makes the sticky error safe.
//
// The chain is the ergonomic win; it is only sound if a failure in the MIDDLE
// cannot be lost. Section fails, Rows is still called, and Rows must report the
// section's error rather than "no rows found" — which would send somebody to fix
// the table when the heading is what moved.
func TestASlicingErrorSurvivesToTheTerminalCall(t *testing.T) {
	_, err := doc(sample).Section("### 12.9 Gone").Rows("| **P")
	if err == nil {
		t.Fatal("a failed Section produced no error at the terminal call")
	}
	if !strings.Contains(err.Error(), "12.9") {
		t.Errorf("error = %q; it should name the SECTION that was not found. Reporting "+
			"the terminal operation's own complaint would send a reader to fix the "+
			"table when the heading is what moved", err)
	}
}

// --- Section's derived end ----------------------------------------------

// TestSectionEndsAtTheSameOrHigherLevel is the behaviour that replaces a
// caller-supplied terminator.
func TestSectionEndsAtTheSameOrHigherLevel(t *testing.T) {
	text, err := doc(sample).Section("### 12.2 Phase overview").Text()
	if err != nil {
		t.Fatalf("slicing: %v", err)
	}
	if !strings.Contains(text, "**P1** Tenancy") {
		t.Error("the section is missing its own last row")
	}
	// The next `## ` heading is a HIGHER level and must end it.
	if strings.Contains(text, "Glossary") {
		t.Error("the section ran past a higher-level heading, so a guard reading it " +
			"would see the next section's content as its own")
	}
	// And the PREVIOUS subsection must not be included.
	if strings.Contains(text, "**A** | because") {
		t.Error("the section included a sibling subsection's table")
	}
}

// TestSectionKeepsItsSubsections. A deeper heading belongs to the parent, so a
// guard reading `## 12.` sees 12.1 and 12.2 — and one reading `### 12.1` does
// not see 12.2.
func TestSectionKeepsItsSubsections(t *testing.T) {
	text, err := doc(sample).Section("## 12. Phases").Text()
	if err != nil {
		t.Fatalf("slicing: %v", err)
	}
	for _, want := range []string{"12.1 Spikes", "12.2 Phase overview"} {
		if !strings.Contains(text, want) {
			t.Errorf("the parent section dropped %q; a subsection belongs to its parent", want)
		}
	}
	if strings.Contains(text, "13. Glossary") {
		t.Error("the parent section ran into the next top-level heading")
	}
}

// --- the CONTRACTS 67 function ------------------------------------------

// TestDecisionsExpandsRanges is the regression test for the defect that
// motivated the package.
func TestDecisionsExpandsRanges(t *testing.T) {
	got, err := doc(sample).Section("## 13. Glossary").Decisions()
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}
	found := map[string]bool{}
	for _, d := range got {
		found[d] = true
	}

	// THE THREE CONTRACTS 67 NAMES. `(D45–D51)` yielded only its endpoints, so
	// the guard reported full coverage over a set missing exactly these.
	for _, want := range []string{"D45", "D46", "D49", "D50", "D51", "D163"} {
		if !found[want] {
			t.Errorf("%s is cited and was not extracted. A range citation hiding its "+
				"interior is CONTRACTS 67, and it made a coverage guard report success "+
				"over three unproven decisions", want)
		}
	}
}

// TestAnAbsurdRangeIsNotExpanded. `D9999-D1` in the fixture is a typo shape, and
// expanding it would silently claim every decision ever made — which would make
// the coverage guard pass for everything, the exact inversion of the defect
// above.
func TestAnAbsurdRangeIsNotExpanded(t *testing.T) {
	got, err := doc(sample).Section("## 13. Glossary").Decisions()
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}
	if len(got) > 50 {
		t.Errorf("extracted %d decisions from a fixture citing a handful; a malformed "+
			"range was expanded and now every decision reads as cited", len(got))
	}
	// Its endpoints are still picked up as singles, which is right: they were
	// written down, whatever the dash between them meant.
	found := map[string]bool{}
	for _, d := range got {
		found[d] = true
	}
	if !found["D1"] || !found["D9999"] {
		t.Error("a rejected range dropped its endpoints; they are cited either way")
	}
}

// --- the small things worth pinning -------------------------------------

func TestCellsIgnoresTheOuterPipes(t *testing.T) {
	got := Cells("| **D163** idempotency | proves a thing | — | breaks a thing |")
	want := []string{"**D163** idempotency", "proves a thing", "—", "breaks a thing"}

	if len(got) != len(want) {
		t.Fatalf("Cells returned %d cells %q, want %d. An off-by-one from the leading "+
			"pipe is how two readers come to disagree about which column is which",
			len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cell %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMarkedReturnsOnlyTheDerivedText(t *testing.T) {
	text, err := doc(sample).Marked("derived").Text()
	if err != nil {
		t.Fatalf("slicing: %v", err)
	}
	if strings.TrimSpace(text) != "derived text" {
		t.Errorf("Marked = %q, want just the derived text; including the markers would "+
			"make a byte comparison against generated content fail on the markers",
			strings.TrimSpace(text))
	}
}

// TestRootFindsTheModuleRoot. The one implementation, replacing six.
func TestRootFindsTheModuleRoot(t *testing.T) {
	root, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if _, err := Load("README.md").Text(); err != nil {
		t.Errorf("Root returned %q and README.md is not readable from it: %v", root, err)
	}
}

// TestLoadNamesTheDocumentInItsError. A reader that cannot say WHICH document
// failed sends somebody to grep, which is the difference between a two-second
// fix and a puzzle.
func TestLoadNamesTheDocumentInItsError(t *testing.T) {
	_, err := Load("NOT-A-DOCUMENT.md").Text()
	if err == nil {
		t.Fatal("loading a document that does not exist returned no error")
	}
	if !strings.Contains(err.Error(), "NOT-A-DOCUMENT.md") {
		t.Errorf("error = %q, which does not name the document", err)
	}
}
