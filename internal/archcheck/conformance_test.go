package archcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/builtin"
	"github.com/fullstorydev/sekizui/internal/connectorcheck"
	"github.com/fullstorydev/sekizui/pkg/config"
)

// TestEveryProviderRunsTheConformanceSuite keeps the published contract from
// becoming optional (D35, D156).
//
// **THE SUITE IS ONLY WORTH ANYTHING IF EVERY PROVIDER RUNS IT.** A conformance
// suite nobody is required to invoke is documentation with a test harness
// attached — and this codebase has the receipts: the suite found, on its FIRST
// run, that `file` and `ambient` both ignored a cancelled context, while
// `EnvProvider` honoured it and carried a comment predicting exactly this ("an
// implementation that quietly does not becomes the one people copy").
//
// So a new provider package must invoke it, and forgetting is a failing build
// rather than a gap nobody sees. The check is deliberately crude — a package
// under `pkg/provider/` must mention `conformance.Run` or `conformance.RunChained`
// somewhere in its tests — because the alternative is parsing test bodies to
// decide whether the call is real, and a crude check that fires is worth more
// than a precise one nobody wrote.
func TestEveryProviderRunsTheConformanceSuite(t *testing.T) {
	root := repoRoot(t)
	base := filepath.Join(root, "pkg", "provider")

	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("reading %s: %v", base, err)
	}

	for _, e := range entries {
		if !e.IsDir() || e.Name() == "conformance" {
			continue
		}

		dir := filepath.Join(base, e.Name())
		files, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}

		found := false
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), "_test.go") {
				continue
			}
			src, rerr := os.ReadFile(filepath.Join(dir, f.Name()))
			if rerr != nil {
				t.Fatalf("reading %s: %v", f.Name(), rerr)
			}
			if strings.Contains(string(src), "conformance.Run") {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("pkg/provider/%s does not run the conformance suite. `Provider` is "+
				"published (D35), so this package's real users are out of tree and will "+
				"never be seen by any test here — the suite is the only thing that "+
				"checks the contract they depend on. Add a TestConformance calling "+
				"conformance.Run, or conformance.RunChained for a chained provider",
				e.Name())
		}
	}
}

// TestEveryDriverRunsTheConformanceSuite is P2 step 25's guard (D167).
//
// **THE SIBLING OF THE PROVIDER CHECK ABOVE, AND MANDATORY FOR THE SAME REASON:
// a conformance suite nobody is required to run is documentation with a test
// harness attached.** D160 aimed that argument at `config.Provider`; D167 aims
// it at `connector.Driver`, which has more surface and a taxonomy to get right —
// so the cost of a driver quietly not conforming is higher, not lower.
//
// **CRUDE ON PURPOSE, same as its sibling.** A package under the driver tree
// must MENTION `conformance.Run` somewhere in its tests. Deciding whether the
// call is real would mean parsing test bodies, and a crude check that fires is
// worth more than a precise one nobody wrote.
//
// **`RunHTTP` IS NOT REQUIRED, and that asymmetry is the decision.** `kata` is
// in-memory and has no statuses to classify, so demanding the transport contract
// of every driver would either fail a correct one or teach authors to invoke a
// suite that asserts nothing about them — D160's vacuous-`Run` finding, arriving
// from the other direction. A driver that speaks HTTP selects it; that choice is
// visible in its tests and reviewable there.
func TestEveryDriverRunsTheConformanceSuite(t *testing.T) {
	root := repoRoot(t)

	// **TWO ROOTS SINCE D316**: a folder per connector, and the shared MCP
	// driver. Walked separately so an offender is named by its real path.
	walked := map[string]bool{}
	total := 0
	for _, rel := range []string{connectorcheck.Root, "internal/driver"} {
		offenders, packages, seen := driversMissingTheSuite(t, filepath.Join(root, rel))
		total += packages
		for _, name := range seen {
			walked[rel+"/"+name] = true
		}
		for _, name := range offenders {
			t.Errorf("%s/%s does not run the conformance suite. `Driver` is "+
				"published as an extension point (D35), so a third-party driver's author "+
				"has nothing but the suite to check the contract against — and the "+
				"in-tree drivers are the worked examples they will copy. Add a "+
				"TestConformance calling conformance.Run, and conformance.RunHTTP too if "+
				"the driver speaks HTTP", rel, name)
		}
	}

	// NON-VACUITY, AGAINST THE REGISTRY RATHER THAN A COUNT. "At least one
	// package found" is what D316's move defeated: with the connectors moved out
	// of `internal/driver/`, `mcp` alone satisfied it and this guard passed while
	// examining none of them. Every driver the binary registers must have been
	// walked.
	if total == 0 {
		t.Fatal("no driver packages found, so this guard is checking nothing")
	}
	for _, d := range builtin.Drivers(&config.Document{}, nil) {
		if dir := connectorcheck.PackageDir(d); !walked[dir] {
			t.Errorf("internal/builtin registers %T from %q, which this guard never walked — "+
				"the tree moved and the check did not", d, dir)
		}
	}
}

// TestTheDriverConformanceGuardRejectsAPackageThatOmitsIt is the guard's own
// sabotage, and it lives HERE rather than in an acceptance step for a measured
// reason.
//
// **P2 step 25 SHELLED OUT TO `go test` TO PROVE THIS AND IT TOOK CI FROM ~3
// MINUTES TO 12.** `make mutate` runs the acceptance suite once per mutation —
// forty-six times — and each run rebuilt this package's test binary against a
// freshly mutated tree. D161's own argument applies: a check that slows every
// run is one people route around, and the step was buying a guarantee the guard
// can prove about itself for nothing.
//
// **IT ALSO PLANTED INTO THE REAL TREE, which raced.** Go runs test packages in
// parallel, so a directory appearing and vanishing under `internal/driver/`
// while another package walked it produced `lstat: no such file or directory`
// in an unrelated guard. A temp tree cannot race anything.
//
// The split that remains is clean: the guard proves it REJECTS an omission, and
// step 25 proves the tree COMPLIES and that the HTTP contract is selected by the
// drivers that have a transport.
func TestTheDriverConformanceGuardRejectsAPackageThatOmitsIt(t *testing.T) {
	base := t.TempDir()

	// A package whose tests exist and never mention the suite. A package with NO
	// tests would be rejected by a weaker check too; the interesting case is one
	// that looks tested.
	planted := filepath.Join(base, "zzplanted")
	if err := os.MkdirAll(planted, 0o750); err != nil {
		t.Fatalf("planting: %v", err)
	}
	if err := os.WriteFile(filepath.Join(planted, "zzplanted_test.go"),
		[]byte("package zzplanted\n\nimport \"testing\"\n\nfunc TestNothing(t *testing.T) {}\n"), 0o600); err != nil {
		t.Fatalf("planting a test file: %v", err)
	}

	// And a compliant one beside it, so the check is not merely rejecting
	// everything.
	ok := filepath.Join(base, "zzcompliant")
	if err := os.MkdirAll(ok, 0o750); err != nil {
		t.Fatalf("planting: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ok, "zzcompliant_test.go"),
		[]byte("package zzcompliant\n\n// conformance.Run(t, d, c)\n"), 0o600); err != nil {
		t.Fatalf("planting a compliant file: %v", err)
	}

	offenders, packages, _ := driversMissingTheSuite(t, base)

	if packages != 2 {
		t.Fatalf("the fixture presented %d packages, want 2", packages)
	}
	if len(offenders) != 1 || offenders[0] != "zzplanted" {
		t.Errorf("offenders = %v, want exactly [zzplanted]. A guard that accepts a "+
			"package whose tests never invoke the suite makes the requirement advisory, "+
			"and a driver then conforms exactly as long as somebody remembers",
			offenders)
	}
}

// driversMissingTheSuite reports the packages under base whose tests never
// mention the suite, and how many packages it examined.
//
// SEPARATED FROM THE ASSERTION so the guard can be pointed at a planted tree
// (see above). Returning findings rather than calling t.Errorf is what makes a
// guard testable at all — the same shape D185 gave the document extractors.
//
// A folder with no Go at all is not a driver package — an MCP-only connector is
// a folder holding an `mcp.yaml` (D316) — so it is not counted; `seen` names
// the ones that were.
func driversMissingTheSuite(t *testing.T, base string) (offenders []string, packages int, seen []string) {
	t.Helper()

	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("reading %s: %v", base, err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(base, e.Name())
		files, rerr := os.ReadDir(dir)
		if rerr != nil {
			t.Fatalf("reading %s: %v", dir, rerr)
		}
		hasGo := false
		for _, f := range files {
			hasGo = hasGo || strings.HasSuffix(f.Name(), ".go")
		}
		if !hasGo {
			continue
		}
		packages++
		seen = append(seen, e.Name())

		found := false
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), "_test.go") {
				continue
			}
			src, ferr := os.ReadFile(filepath.Join(dir, f.Name()))
			if ferr != nil {
				t.Fatalf("reading %s: %v", f.Name(), ferr)
			}
			if strings.Contains(string(src), "conformance.Run") {
				found = true
				break
			}
		}
		if !found {
			offenders = append(offenders, e.Name())
		}
	}
	return offenders, packages, seen
}
