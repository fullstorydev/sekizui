package archcheck

// In `package archcheck` rather than `archcheck_test`, because `repoRoot` and
// `walkGo` live here — the two test packages in this directory cannot share
// unexported helpers (§15w), and duplicating a tree walk to satisfy a file
// boundary would be this guard committing the offence it checks for.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// designDocs are the documents `internal/docref` owns the reading of.
//
// The Makefile and the mutation harness are in the list even though neither is
// Markdown: they are both read BY GUARDS as text, which is the property that
// matters — step 39 compares the demo target against the harness, and step 34
// compares the mutation list against the artefact table.
//
//nolint:gochecknoglobals // immutable list, read once
var designDocs = []string{
	"DESIGN.md", "DECISIONS.md", "CONTRACTS.md", "GO-PRIMER.md", "README.md",
	"VISION.md", "Makefile", "mutate.py",
}

// TestNoAdHocDocumentReads is D173's guard aimed at documents (D185).
//
// **THE PATTERN IT EXISTS FOR HAD SIX INSTANCES, not three.** `atomicfile`
// replaced three hand-rolled durable writes and `TestNoAdHocAtomicWrites` found
// the third on its first run — whose own comment said it was the third instance
// and copied it anyway. Document reading was worse when it was noticed: SIX
// functions walked up to `go.mod` (`acceptance.repoRoot`,
// `acceptance.moduleRoot`, `archcheck.repoRoot`, `archcheck.repoRootFor`, the
// walk inlined in `archcheck.readDesign`, and a hardcoded `../../` style that
// worked from exactly one package depth), with two of those pairs living in the
// SAME package under different names.
//
// **AND THE COST IS NOT DUPLICATION.** A document extractor that silently
// matches nothing turns its guard into a no-op that PASSES. CONTRACTS 67 is
// exactly that, already: the decision-derivation guard could not see the range
// citation `(D45–D51)`, so it reported full coverage over a set missing D46, D49
// and D50. Every reader that parses a citation without knowing about the en dash
// re-makes that mistake, and there is no way to notice — the guard goes on
// printing success.
//
// So `internal/docref` is the one place, and this is what keeps it the one place.
//
// **DELIBERATELY CRUDE**, for D167's reason: the check is "does a file outside
// docref name a design document next to a file-read, or walk up to go.mod", not
// a type-aware analysis of what it does with it. A crude check that fires beats
// a precise one nobody wrote (§15r). The false-positive direction is a comment
// mentioning a filename, which is why only literals paired with a read count.
func TestNoAdHocDocumentReads(t *testing.T) {
	root := repoRoot(t)
	docrefDir := filepath.Join(root, "internal", "docref")

	// A read call with a design-document name in the same expression. Matched on
	// one line deliberately: a multi-line call would slip through, and tightening
	// it means parsing, which is the precision this check trades away on purpose.
	read := regexp.MustCompile(`os\.(ReadFile|Open|Stat)\(`)

	// **OUR OWN TREES ONLY.** The first run walked from the module root and
	// reported 245 findings out of `.gocache`, the vendored module cache — every
	// one of them somebody else's code walking to its own go.mod, correctly. A
	// guard whose output is 98% noise gets muted, which is worse than not having
	// one.
	var findings []string
	inspect := func(path string) {
		if strings.HasPrefix(path, docrefDir) {
			return
		}
		// THIS FILE IS EXEMPT FROM ITSELF, and it found itself on its first run —
		// the line below contains the literal it searches for. Same treatment
		// `TestEveryRefusalUsesTheConstructor` gives `refusalResult`'s own body:
		// the checker is not an instance of what it checks, and the alternative
		// (assembling the needle from fragments so it does not appear literally)
		// trades a one-line exemption for a line nobody can read.
		if filepath.Base(path) == "docread_test.go" {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		rel, _ := filepath.Rel(root, path)

		for n, line := range strings.Split(string(data), "\n") {
			// A SECOND WALK TO THE MODULE ROOT. The most-duplicated thing in the
			// tree before docref, and the cheapest to detect.
			//
			// A line that READS go.mod THROUGH docref is not a walk: `docref.Load`
			// and the test helper over it resolve the root once, in docref. P6
			// step 12 reads go.mod's requirements that way (D344), and flagging it
			// would push the read out of docref — the opposite of this guard.
			if strings.Contains(line, `"go.mod"`) &&
				!strings.Contains(line, "docref.Load(") && !strings.Contains(line, "mustDoc(") {
				findings = append(findings, fmt.Sprintf(
					"%s:%d walks to the module root itself — use docref.Root", rel, n+1))
				continue
			}
			if !read.MatchString(line) {
				continue
			}
			for _, doc := range designDocs {
				if strings.Contains(line, `"`+doc) || strings.Contains(line, `/`+doc+`"`) {
					findings = append(findings, fmt.Sprintf(
						"%s:%d reads %s directly — use docref.Load", rel, n+1, doc))
					break
				}
			}
		}
	}
	for _, dir := range []string{"internal", "pkg", "cmd"} {
		walkGo(t, filepath.Join(root, dir), inspect)
	}

	sort.Strings(findings)
	if len(findings) > 0 {
		t.Errorf("%d ad-hoc document read(s) outside internal/docref:\n  %s\n\n"+
			"Every one is a second parser, and a document extractor that silently matches "+
			"nothing turns its guard into a no-op that PASSES — CONTRACTS 67 is that "+
			"failure, and it reported full coverage over three unproven decisions. "+
			"docref's extractors return an error rather than an empty result, which is the "+
			"whole reason it exists (D185).",
			len(findings), strings.Join(findings, "\n  "))
	}
}
