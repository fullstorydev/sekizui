package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// step28ThePackageLevelStateLintIsEnabledAndNonVacuous proves §6 item 4.
//
// **THE CLAIM IS THAT "A LINT RULE MAKES REGRESSION STRUCTURALLY IMPOSSIBLE",
// and that claim has been false here before.** The rule existed while the
// enforcement did not, and `internal/auditwal` shipped a package-level counter
// that review missed. So asserting the config file contains a word is not
// enough — a linter can be listed, disabled by an exclusion, shadowed by a
// default, or simply not run by `make verify`.
//
// This plants a global and requires the linter to reject it. Sabotage as a step
// rather than sabotage as a habit, because the thing under test IS a guard, and a
// guard nobody has watched fail is a guard nobody should trust (CONTRACTS 59).
func step28ThePackageLevelStateLintIsEnabledAndNonVacuous(t *testing.T) {
	root := repoRoot(t)

	// --- 28a: IT IS CONFIGURED ------------------------------------------
	cfg, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatalf("reading .golangci.yml: %v", err)
	}
	if !strings.Contains(string(cfg), "gochecknoglobals") {
		t.Fatal("gochecknoglobals is not configured. §6 item 4 asks for a CI lint " +
			"rejecting package-level mutable state, and Lexicon violated that " +
			"everywhere with module singletons and a service registry")
	}

	// --- 28b: AND IT ACTUALLY REJECTS ONE --------------------------------
	//
	// The half that matters. A linter listed and not run, or listed and excluded,
	// reads identically to one doing its job.
	lint := filepath.Join(root, "bin", "golangci-lint")
	if _, err := os.Stat(lint); err != nil {
		t.Skipf("golangci-lint is not installed (%v); run `make tools`. Skipping rather "+
			"than passing: an unrun linter is exactly what this step exists to catch", err)
	}

	// PLANTED IN A REAL PACKAGE, not a throwaway one. An exclusion keyed on a
	// path would let a temp directory through while the tree stayed unguarded,
	// which is the failure mode of testing a linter somewhere it does not run.
	planted := filepath.Join(root, "internal", "acceptance", "zz_planted_global.go")
	// **THE PLANTED GLOBAL MUST BE USED, and finding that out was the point of
	// running it.** The first version planted a bare `var` and the linter refused
	// it as `unused` — a different rule answering first, which would have let this
	// step report gochecknoglobals working while gochecknoglobals never ran. An
	// exported reader satisfies `unused` (it cannot know who imports the package)
	// and leaves the global for the rule under test.
	source := "package acceptance\n\n" +
		"// Planted by acceptance step 28 and deleted immediately. If you are reading\n" +
		"// this in a committed tree, the step failed to clean up.\n" +
		"var plantedMutableGlobal = map[string]string{}\n\n" +
		"// PlantedReader keeps `unused` quiet so the rule under test is the one that\n" +
		"// answers.\n" +
		"func PlantedReader() int { return len(plantedMutableGlobal) }\n"
	if err := os.WriteFile(planted, []byte(source), 0o600); err != nil {
		t.Fatalf("planting: %v", err)
	}
	defer func() { _ = os.Remove(planted) }()

	cmd := exec.Command(lint, "run", "./internal/acceptance/")
	cmd.Dir = root
	// The Makefile puts the toolchain on PATH, which golangci-lint shells out to;
	// the child inherits it.
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("a planted package-level map passed the linter. §6 item 4's claim that "+
			"'a lint rule makes regression structurally impossible' is false, and it has "+
			"been false here before — the rule existed while the enforcement did not, and "+
			"internal/auditwal shipped a package-level counter that review missed.\\n%s", out)
	}
	if !strings.Contains(string(out), "gochecknoglobals") {
		t.Errorf("the linter failed for some OTHER reason, so this proves nothing about "+
			"gochecknoglobals:\\n%s", out)
	}
	if !strings.Contains(string(out), "plantedMutableGlobal") {
		t.Errorf("the failure does not name the planted global:\\n%s", out)
	}
}
