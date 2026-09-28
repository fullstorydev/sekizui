package acceptance

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/builtin"
	"github.com/fullstorydev/sekizui/internal/connectorcheck"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// driverRoots are where in-tree driver packages live: one folder per connector
// (D316), and the shared MCP driver.
//
//nolint:gochecknoglobals // immutable table, read once
var driverRoots = []string{connectorcheck.Root, "internal/driver"}

// driverPackageDirs is every repository-relative package directory under
// driverRoots that holds Go code — and it FAILS THE CALLER if a driver
// `internal/builtin` registers is not among them.
//
// **D316's MOVE FOUND THE REASON.** Four steps FOUND connector packages by
// walking `internal/driver/`, three of them guards of the connector's reach
// (P3 steps 13 and 42a: no connector can load the audit log's code). After the
// move two of the four failed loudly and the other two — both of those security
// guards — would have gone on passing, having quietly stopped examining
// fullstory, jira and kata: `internal/driver/mcp` was still there, so a
// "found at least one" non-vacuity check was satisfied. A walk's non-vacuity
// has to be checked against the REGISTRY, not against a count.
func driverPackageDirs(t *testing.T) []string {
	t.Helper()
	root := mustRoot(t)
	found := map[string]bool{}
	for _, base := range driverRoots {
		entries, err := os.ReadDir(filepath.Join(root, base))
		if err != nil {
			t.Fatalf("reading %s: %v", base, err)
		}
		for _, e := range entries {
			if e.IsDir() && hasGoCode(filepath.Join(root, base, e.Name())) {
				found[base+"/"+e.Name()] = true
			}
		}
	}
	for _, d := range builtin.Drivers(&config.Document{}, nil) {
		if dir := connectorcheck.PackageDir(d); !found[dir] {
			t.Fatalf("internal/builtin registers %T from %q, which is not under %v — a guard walking "+
				"those roots would pass without examining it. Move the driver into a connector folder "+
				"(D316), or add its root here", d, dir, driverRoots)
		}
	}
	dirs := make([]string, 0, len(found))
	for d := range found {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

func hasGoCode(dir string) bool {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			return true
		}
	}
	return false
}

// strayDriver is a registered driver declared outside any connector folder —
// here, in the acceptance package.
type strayDriver struct{ connector.Driver }

// p4Step34 — every in-tree connector is one complete folder (D316).
//
// **THE SAME `connectorcheck.Check` THE BUILD GUARD RUNS**, called here for the
// evidence report and so a mutation can show the guard notices. Unlike P2 step
// 25's sabotage, which moved to archcheck because shelling out to `go test`
// cost nine minutes a `make ci`, this one is an in-process call on a temp tree,
// so the step can prove the guard REJECTS as well as that the tree COMPLIES.
func p4Step34(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "every in-tree connector is one complete folder, and the build refuses one that is not")
	root := mustRoot(t)

	// 34a — THE TREE COMPLIES: every folder, both directions of registration.
	rep := connectorcheck.Check(root, builtin.Drivers(&config.Document{}, nil))
	for _, f := range rep.Findings {
		t.Errorf("step 34a: %s", f)
	}
	for _, name := range []string{"fullstory", "jira", "kata"} {
		if _, ok := rep.Folders[connectorcheck.Root+"/"+name]; !ok {
			t.Errorf("step 34a: no connector folder %s/%s — D316 moved it there", connectorcheck.Root, name)
		}
	}
	folders := make([]string, 0, len(rep.Folders))
	for f, ships := range rep.Folders {
		folders = append(folders, f+" ("+ships+")")
	}
	sort.Strings(folders)
	r.detail(t, "%d connector folders, each complete: %s", len(folders), strings.Join(folders, "; "))

	// 34b — NOTHING IS LEFT WHERE A CONNECTOR USED TO BE SPLIT: `internal/driver/`
	// holds only shared drivers, and `specs/` is gone.
	entries, err := os.ReadDir(filepath.Join(root, "internal", "driver"))
	if err != nil {
		t.Fatalf("step 34b: %v", err)
	}
	for _, e := range entries {
		if _, shared := connectorcheck.SharedDrivers["internal/driver/"+e.Name()]; e.IsDir() && !shared {
			t.Errorf("step 34b: internal/driver/%s is not a shared driver — a connector's driver lives in "+
				"its folder under %s (D316)", e.Name(), connectorcheck.Root)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "specs")); err == nil {
		t.Error("step 34b: specs/ exists again — a vetted MCP spec or a suggested ceiling lives in its " +
			"connector's folder as mcp.yaml or anzen.yaml (D316)")
	}

	// 34c — THE GUARD REJECTS: a driver folder missing what a driver owes, an
	// empty folder, a broken ceiling, and a driver registered outside any folder,
	// beside a complete MCP-only folder it must accept.
	c := filepath.Join(t.TempDir(), filepath.FromSlash(connectorcheck.Root))
	write := func(rel, body string) {
		p := filepath.Join(c, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mcpYAML, err := os.ReadFile(filepath.Join(root, "internal", "connectors", "fullstory", "mcp.yaml"))
	if err != nil {
		t.Fatalf("step 34c: %v", err)
	}
	write("zzmcp/README.md", "x")
	write("zzmcp/mcp.yaml", string(mcpYAML))
	write("zzcode/zzcode.go", "package zzcode\n")
	write("zzcode/zzcode_test.go", "package zzcode\n")
	write("zzempty/README.md", "x")
	write("zzanzen/README.md", "x")
	write("zzanzen/mcp.yaml", string(mcpYAML))
	write("zzanzen/anzen.yaml", "anzen: []\n")
	// A REGISTERED DRIFTER WHOSE TESTS SKIP RunDrift: the real kata driver, over
	// a planted kata folder that runs Run and RunSource only. Whether a suite is
	// owed is read from the DRIVER, so this is the arm that proves it is.
	write("kata/kata.go", "package kata\n")
	write("kata/README.md", "x")
	write("kata/schemas.yaml", "x")
	write("kata/kata_test.go", "package kata\n\n// conformance.Run( conformance.RunSource(\n")
	planted := connectorcheck.Check(filepath.Dir(filepath.Dir(c)), []connector.Driver{&strayDriver{}, kata.New()})
	var got []string
	for _, f := range planted.Findings {
		got = append(got, f.String())
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{
		"zzcode: has no README.md", "zzcode: has Go code and is not registered",
		"zzcode: has Go code and no schemas.yaml", "zzcode: does not run conformance.Run",
		"zzempty: has no Go code and no mcp.yaml", "zzanzen: anzen.yaml loads and carries no anzen rules",
		"strayDriver: is registered in internal/builtin but its package",
		"kata: does not run conformance.RunDrift",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("step 34c: the guard did not report %q; it reported:\n%s", want, all)
		}
	}
	if strings.Contains(all, "conformance.RunSource —") || strings.Contains(all, "kata: has") {
		t.Errorf("step 34c: the planted kata folder owes only RunDrift, and more was reported:\n%s", all)
	}
	if strings.Contains(all, connectorcheck.Root+"/zzmcp:") {
		t.Errorf("step 34c: the guard rejected a complete MCP-only folder:\n%s", all)
	}
	r.detail(t, "a planted tree drew %d findings — missing README, schemas, suite and registration; a "+
		"folder that is no connector; an empty ceiling; a driver registered outside any folder; a Drifter "+
		"whose tests skip RunDrift — and "+
		"the complete MCP-only folder beside them drew none", len(got))

	// 34d — THE GUARDS THAT FIND CONNECTORS BY WALKING cover every registered
	// driver (driverPackageDirs fails the step otherwise).
	dirs := driverPackageDirs(t)
	r.detail(t, "the walking guards (P2 25, P3 13 and 42a) examine %d driver packages, every one "+
		"internal/builtin registers: %s", len(dirs), strings.Join(dirs, ", "))
}
