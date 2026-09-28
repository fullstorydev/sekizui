package acceptance

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
)

// step46TheConnectorContractIsStatedOnce proves criterion 24 (D218).
//
// **CONTRACTS 93 IS THE REASON THIS EXISTS, and the shape of the defect is worth
// carrying: the connector contract was stated in THREE places and no two
// agreed.** CONTRACTS §5's thirty checkboxes, D167's one sentence naming what
// the conformance suite asserts, and the suite's own code. D167 named seven
// assertions and the suite made four — and nothing could tell, because a
// sentence in a decision has nothing to be checked against. Two more instances
// (items 91 and 92) were found in the same hour by reading §5 against the tree.
//
// **THE FIX IS NOT A FOURTH STATEMENT.** It is D183's and D214's instrument
// aimed at the contract instead of at a README: `conformance.Arms()` is the
// source, the blueprint's table is generated from it, and this step is what
// makes "generated" true rather than aspirational.
//
// **THE FIRST ARM GUARDS THE SOURCE ITSELF**, or `Arms()` would simply BE the
// fourth statement — a hand-maintained list that drifts from the code beside it
// exactly as D167's sentence did. Three sets must be equal: DECLARED,
// CALLED and LISTED. Each catches a different rot, and the third is the one a
// registry usually lacks (D139): an arm that exists and is never invoked passes
// a declaration check and asserts nothing.
func step46TheConnectorContractIsStatedOnce(t *testing.T) {
	r := &run{path: auditPath(t)}

	declared, called := armsInSource(t)

	listed := map[string]string{} // name -> suite
	for _, a := range conformance.Arms() {
		listed[a.Name] = a.Suite
	}

	// --- 46a: DECLARED == CALLED == LISTED ---------------------------------
	t.Run("every arm is declared, called and listed", func(t *testing.T) {
		for name := range declared {
			if _, ok := called[name]; !ok {
				t.Errorf("%s is declared and never called from any entry-point suite. An arm "+
					"nothing invokes asserts nothing, and it reads in review exactly like "+
					"one that does — which is the rot D139's registry exists to catch",
					name)
			}
			if _, ok := listed[name]; !ok {
				t.Errorf("%s is an arm of this suite and conformance.Arms() does not list "+
					"it, so the blueprint's contract table UNDERSTATES what a driver must "+
					"satisfy. Add a line naming the obligation, not the check", name)
			}
		}
		for name, suite := range listed {
			if _, ok := declared[name]; !ok {
				t.Errorf("conformance.Arms() lists %q and no such function exists. The "+
					"blueprint would then promise a check nobody makes — the exact defect "+
					"CONTRACTS 93 recorded, reproduced in its own fix", name)
				continue
			}
			if got := called[name]; got != suite {
				t.Errorf("%s is listed under %q and is called from %q. A driver selects "+
					"RunHTTP explicitly, so a mislabelled arm tells an author they are "+
					"covered by a suite they never run", name, suite, got)
			}
		}
	})

	// --- 46b: THE BLUEPRINT'S TABLE IS THE RENDERING OF THAT SOURCE --------
	t.Run("the blueprint's enforced table is derived from the suite", func(t *testing.T) {
		want := renderArms()
		got := strings.TrimSpace(mustText(t, mustDoc(t, "hako/BLUEPRINT.md").
			Marked("derived-conformance-arms")))

		if got != want {
			t.Errorf("hako/BLUEPRINT.md's enforced table disagrees with "+
				"conformance.Arms(), which is the source.\n\nPaste this between the "+
				"derived-conformance-arms markers:\n\n%s\n", want)
		}
	})

	// --- 46c: THE KATA CANNOT DRIFT FROM THE BLUEPRINT --------------------
	//
	// **AN EXERCISE CANNOT BE GUARDED BY A RUNNER THAT REQUIRES GREEN**, because
	// it is meant to fail — so it needs a guard of a different kind. Every gap
	// in it is marked `HAKO STEP <n>` and must name a REAL blueprint step: add a
	// step to the blueprint and renumber, and a marker pointing at the old
	// number sends a learner to the wrong section, which is worse than no marker
	// because it looks authoritative.
	//
	// **NOT one-to-one, and D218 said one-to-one — this is the correction.** Not
	// every blueprint step has a machine-checkable failure, and a gap with no
	// check is a TODO comment: it teaches nothing, nobody notices when it stops
	// applying, and it makes the exercise look more thorough than it is. So the
	// requirement is markers ⊆ steps, plus the governance half covered, which is
	// the half the kata exists for.
	t.Run("every kata gap names a real blueprint step", func(t *testing.T) {
		steps := map[int]bool{}
		for _, h := range regexp.MustCompile(`(?m)^## (\d+)\. `).
			FindAllStringSubmatch(mustText(t, mustDoc(t, "hako/BLUEPRINT.md")), -1) {
			n, _ := strconv.Atoi(h[1])
			steps[n] = true
		}
		if len(steps) == 0 {
			t.Fatal("no numbered steps parsed out of hako/BLUEPRINT.md; the " +
				"extractor has drifted and this arm is vacuous")
		}

		marked := map[int]bool{}
		root := mustRoot(t)
		for _, rel := range []string{
			"hako/exercise/notes.go", "hako/exercise/notes.yaml",
			"hako/exercise/exercise_test.go",
		} {
			raw, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatalf("reading %s: %v", rel, err)
			}
			for _, m := range regexp.MustCompile(`HAKO STEP (\d+)`).
				FindAllStringSubmatch(string(raw), -1) {
				n, _ := strconv.Atoi(m[1])
				marked[n] = true
				if !steps[n] {
					t.Errorf("%s marks a gap as HAKO STEP %d and the blueprint has no "+
						"step %d. A marker pointing at a step that moved sends a learner "+
						"to the wrong section, and it looks authoritative doing it",
						rel, n, n)
				}
			}
		}

		// THE GOVERNANCE HALF IS THE KATA'S REASON TO EXIST. The compiler and
		// the conformance suite already teach steps 1-4; nothing else makes an
		// author confront the lens and the ceiling.
		for _, n := range []int{5, 6, 7, 8, 9} {
			if !marked[n] {
				t.Errorf("no kata gap covers blueprint step %d. Steps 5-9 are the "+
					"governance half — the part a connector ships without while working "+
					"perfectly, and the part CONTRACTS §5 never carried at all", n)
			}
		}

		// And the SOLUTION must carry none, or it is not a solution.
		raw, err := os.ReadFile(filepath.Join(root, "hako", "solution", "notes.go"))
		if err != nil {
			t.Fatalf("reading the solution: %v", err)
		}
		if regexp.MustCompile(`HAKO STEP \d`).Match(raw) {
			t.Error("the kata's SOLUTION carries a gap marker. It is the artefact CI " +
				"runs the full conformance suite against; a gap in it means the pair " +
				"has drifted and the learner's answer key is wrong")
		}
	})

	r.detail(t, "criterion 24: %d conformance arms, each declared, called and listed, "+
		"and the blueprint's contract table generated from that one source",
		len(conformance.Arms()))
}

// renderArms is the blueprint's table, from the suite's own declaration.
func renderArms() string {
	var b strings.Builder
	b.WriteString("| Arm | Selected by | What your driver must do |\n|---|---|---|\n")
	for _, a := range conformance.Arms() {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", a.Name, a.Suite, a.What)
	}
	return strings.TrimSpace(b.String())
}

// entryPoints are the suites a driver author selects, and the set this walk
// treats as roots.
//
// **DATA RATHER THAN A CONDITION, because the condition was wrong the moment a
// third suite arrived.** It read `fn.Name.Name != "Run" && fn.Name.Name !=
// "RunHTTP"`, so `RunSource`'s four arms were reported as "called from ”" —
// declared, listed, and invisible to the walk. The guard caught that itself,
// which is the right outcome; what it could not do is stop the next suite
// repeating it, and a named set can.
//
//nolint:gochecknoglobals // immutable table, read once
var entryPoints = map[string]bool{"Run": true, "RunHTTP": true, "RunSource": true, "RunDrift": true, "RunRefiner": true, "RunPresetter": true}

// armsInSource walks the conformance package for what it DECLARES and what the
// entry-point suites actually CALL.
//
// Parsed rather than grepped, for D185's reason: a substring match would go on
// passing through a reformat, and it cannot tell a call from a mention in a
// comment — this package's comments name its own arms constantly.
func armsInSource(t *testing.T) (declared map[string]bool, called map[string]string) {
	t.Helper()

	dir := filepath.Join(mustRoot(t), "pkg", "connector", "conformance")
	pkgs, err := parser.ParseDir(token.NewFileSet(), dir, nil, 0)
	if err != nil {
		t.Fatalf("parsing the conformance package: %v", err)
	}

	declared, called = map[string]bool{}, map[string]string{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil {
					continue
				}
				if strings.HasPrefix(fn.Name.Name, "run") {
					declared[fn.Name.Name] = true
				}
				if !entryPoints[fn.Name.Name] {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if id, ok := call.Fun.(*ast.Ident); ok &&
						strings.HasPrefix(id.Name, "run") {
						called[id.Name] = fn.Name.Name
					}
					return true
				})
			}
		}
	}

	if len(declared) == 0 || len(called) == 0 {
		t.Fatal("the conformance package parsed to no arms at all, so this step is " +
			"vacuous. The extractor has drifted from the package's shape")
	}

	names := make([]string, 0, len(declared))
	for n := range declared {
		names = append(names, n)
	}
	sort.Strings(names)
	t.Logf("conformance arms declared: %s", strings.Join(names, ", "))

	return declared, called
}
