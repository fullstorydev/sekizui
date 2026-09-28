package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// step25EveryDriverPackageRunsTheConformanceSuite proves D167.
//
// **D160's GUARD AIMED AT `Provider` INSTEAD OF `Driver`, and mandatory for the
// same reason: a conformance suite nobody is required to run is documentation
// with a test harness attached.** The published suite is the only thing an
// out-of-tree driver author can check their work against (D35), and the in-tree
// drivers are the worked examples they will copy — so a driver quietly not
// conforming propagates.
//
// **THE THING UNDER TEST IS A GUARD, so the step is sabotage (D164's shape).**
// Asserting that the drivers currently conform proves the tree is tidy today; it
// says nothing about whether forgetting would be caught. So the second arm
// plants a driver package with tests that omit the suite and requires the guard
// to reject it.
func step25EveryDriverPackageRunsTheConformanceSuite(t *testing.T) {
	root := repoRoot(t)

	// --- 25a: EVERY DRIVER PACKAGE RUNS IT ---------------------------------
	//
	// **THE PACKAGES COME FROM `driverPackageDirs` SINCE D316**, which walks
	// every driver root AND fails if a registered driver is not among them. This
	// step walked `internal/driver/` until the connectors moved out of it, and it
	// failed loudly then only because its HTTP arm named `fullstory` by path.
	var checked []string
	for _, rel := range driverPackageDirs(t) {
		if !mentionsSuite(t, filepath.Join(root, rel)) {
			t.Errorf("25a: %s does not run the conformance suite", rel)
			continue
		}
		checked = append(checked, rel)
	}
	if len(checked) == 0 {
		t.Fatal("25a: no driver package was found to run the suite, so this step is " +
			"asserting nothing")
	}

	// **AND THE HTTP CONTRACT IS SELECTED BY THE DRIVERS THAT HAVE A TRANSPORT,
	// not by all of them.** `kata` is in-memory: demanding `RunHTTP` of it would
	// either fail a correct driver or teach an author to invoke a suite that
	// asserts nothing about their code — D160's vacuous-`Run` finding arriving
	// from the other side. So the asymmetry is asserted rather than assumed.
	for _, d := range []string{"internal/driver/mcp", "internal/connectors/fullstory"} {
		if !mentionsHTTPSuite(t, filepath.Join(root, d)) {
			t.Errorf("25a: %s speaks HTTP and does not select "+
				"conformance.RunHTTP, so ~200 lines of status-to-taxonomy mapping are "+
				"unchecked — the gap §14 named when it pulled this step forward", d)
		}
	}
	if mentionsHTTPSuite(t, filepath.Join(root, "internal", "connectors", "kata")) {
		t.Error("25a: internal/connectors/kata selects the HTTP contract, but it has no " +
			"transport — so either the driver grew one or the suite is being invoked " +
			"where it cannot fail, which is the shape D160 warns about")
	}

	// --- 25b: AND FORGETTING IS A FAILING BUILD ----------------------------
	//
	// **PROVEN BY THE GUARD ITSELF, NOT FROM HERE, AND THE REASON IS MEASURED.**
	// The first version of this arm planted a driver package in the real tree
	// and shelled out to `go test ./internal/archcheck/` to watch the guard
	// reject it. It worked, and it took `make ci` from about three minutes to
	// TWELVE: `make mutate` runs this suite once per mutation — forty-six times
	// — and each run rebuilt archcheck's test binary against a freshly mutated
	// tree. D161's own argument turned on it: a check that slows every run is
	// one people route around, and this was buying a guarantee the guard can
	// prove about itself for free.
	//
	// It also raced. Planting into `internal/driver/` while Go runs test
	// packages in PARALLEL made a directory appear and vanish under another
	// package's tree walk, which surfaced as `lstat: no such file or directory`
	// in an unrelated guard.
	//
	// So `archcheck.TestTheDriverConformanceGuardRejectsAPackageThatOmitsIt`
	// plants into a TEMP tree and requires the predicate to reject it, with a
	// compliant package beside it so the check is not merely rejecting
	// everything. The division is the honest one: the guard proves it REJECTS,
	// this step proves the tree COMPLIES and that the transport contract is
	// selected by the drivers that have a transport. That the guard EXISTS is
	// enforced by step 33, which fails if the README names a guard that does not.
	if !mentionsSuite(t, filepath.Join(root, "internal", "connectors", "kata")) {
		t.Error("25b: the reference driver stopped running the suite, which is the case " +
			"the guard exists for")
	}

	r := &run{}
	r.detail(t, "D167: %d driver package(s) run the published suite, and the HTTP contract "+
		"is selected by the two that have a transport and refused by the one that does "+
		"not. The guard's own sabotage — a planted package whose tests omit the suite — "+
		"lives in archcheck, because proving it from here cost `make ci` nine minutes "+
		"per run", len(checked))
}

func mentionsSuite(t *testing.T, dir string) bool {
	t.Helper()
	return testsMention(t, dir, "conformance.Run")
}

func mentionsHTTPSuite(t *testing.T, dir string) bool {
	t.Helper()
	return testsMention(t, dir, "conformance.RunHTTP")
}

func testsMention(t *testing.T, dir, want string) bool {
	t.Helper()

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Join(dir, f.Name()))
		if rerr != nil {
			t.Fatalf("reading %s: %v", f.Name(), rerr)
		}
		if strings.Contains(string(src), want) {
			return true
		}
	}
	return false
}
