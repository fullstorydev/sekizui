// Package connectorcheck answers "is every in-tree connector folder complete",
// so that adding a connector is a checklist the build enforces rather than a
// convention somebody remembers (D316).
//
// **ONE FUNCTION, TWO CALLERS, BECAUSE THE MAINTAINER RULED "BOTH".** The package test is
// the fast feedback — `make verify` fails the moment a folder is incomplete. P4
// step 34 calls the same `Check` for the evidence report and so a mutation can
// prove the guard notices (`make mutate` sees acceptance steps only, CONTRACTS
// 107). A check written twice would be two contracts that drift, which is the
// recurring class this repository keeps finding.
//
// **WHAT "COMPLETE" MEANS (the maintainer's ruling, D316).** Every folder under
// `internal/connectors/` has a README. A folder with Go code is a DRIVER: it
// ships `schemas.yaml` (D279), is registered in `internal/builtin`, and its
// tests run `conformance.Run` plus `RunSource` and `RunDrift` for whichever of
// those interfaces the registered driver implements. A folder with no code is an
// MCP-ONLY connector, served by the one generic driver in `internal/driver/mcp`,
// and it must ship an `mcp.yaml` that validates. `anzen.yaml`, `mcp.yaml`,
// `reflexes.yaml`, `presets.yaml` and `reference/<revision>/` are optional, and each must load
// when present.
//
// **WHETHER A DRIVER IS A SOURCE OR A DRIFTER IS READ FROM THE DRIVER, NOT THE
// SOURCE CODE.** The caller hands over the drivers `internal/builtin` registers,
// so a type assertion answers exactly the question the conformance suites ask —
// no go/types, no guessing from method names — and `reflect` names each one's
// package, which is what ties a registration to a folder in both directions.
//
// **CRUDE WHERE ITS SIBLINGS ARE CRUDE.** "The tests run the suite" means a
// `_test.go` file MENTIONS `conformance.Run(` — archcheck's D167 guard made the
// same trade, and for the same reason: a crude check that fires beats a precise
// one nobody wrote.
package connectorcheck

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/grantcheck"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// Root is where in-tree connector folders live, relative to the repository.
// Under `internal/` so no driver becomes a public import (D35); an out-of-tree
// connector is its own repository built against `pkg/connector`, copying hako.
const Root = "internal/connectors"

// SharedDrivers are registered drivers that serve connectors without being one:
// the MCP driver serves every MCP-only folder from that folder's `mcp.yaml`.
// A registered driver anywhere else is a connector outside its folder.
//
//nolint:gochecknoglobals // immutable table, read once
var SharedDrivers = map[string]string{
	"internal/driver/mcp": "the one MCP driver; an MCP-only connector is a folder with an mcp.yaml (D316)",
}

// Finding is one way a folder, or a registration, falls short.
type Finding struct {
	Where   string // a folder under Root, or a registered driver's package
	Problem string
}

func (f Finding) String() string { return f.Where + ": " + f.Problem }

// Report is what Check examined, so a caller can refuse a vacuous pass and
// narrate what each folder ships.
type Report struct {
	Findings []Finding
	// Folders maps each connector folder to what it ships, e.g. "driver, schemas,
	// conformance: Run+RunSource, anzen, mcp, reference".
	Folders map[string]string
}

// PackageDir is the repository-relative directory of a driver's package —
// `internal/connectors/kata` for kata's driver. Empty when the driver's type is
// not declared under `internal/`, which Check reports.
func PackageDir(d connector.Driver) string {
	t := reflect.TypeOf(d)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	p := t.PkgPath()
	i := strings.Index(p, "/internal/")
	if i < 0 {
		return ""
	}
	return p[i+1:]
}

// Check examines every folder under root/Root against the registered drivers.
func Check(root string, drivers []connector.Driver) Report {
	rep := Report{Folders: map[string]string{}}
	add := func(where, format string, args ...any) {
		rep.Findings = append(rep.Findings, Finding{where, fmt.Sprintf(format, args...)})
	}

	// REGISTRATION → FOLDER. A registered driver lives in a connector folder, or
	// is a shared driver named above.
	registered := map[string]connector.Driver{}
	for _, d := range drivers {
		dir := PackageDir(d)
		registered[dir] = d
		if _, shared := SharedDrivers[dir]; shared {
			continue
		}
		if !strings.HasPrefix(dir, Root+"/") || strings.Count(dir, "/") != 2 {
			add(fmt.Sprintf("%T", d), "is registered in internal/builtin but its package %q is not a "+
				"folder directly under %s/ — a connector split across the tree is the thing D316 ended", dir, Root)
		}
	}

	entries, err := os.ReadDir(filepath.Join(root, Root))
	if err != nil {
		add(Root, "cannot be read: %v", err)
		return rep
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rel := Root + "/" + e.Name()
		rep.Folders[rel] = checkFolder(root, rel, registered[rel], add)
	}

	sort.Slice(rep.Findings, func(i, j int) bool { return rep.Findings[i].String() < rep.Findings[j].String() })
	return rep
}

// checkFolder applies the ruling to one folder and says what it ships.
func checkFolder(root, rel string, d connector.Driver, add func(string, string, ...any)) string {
	dir := filepath.Join(root, rel)
	has := func(name string) bool { _, err := os.Stat(filepath.Join(dir, name)); return err == nil }
	var ships []string

	if !has("README.md") {
		add(rel, "has no README.md — say what the connector is and what it ships")
	}

	code, tests := goFiles(dir)
	switch {
	case code:
		ships = append(ships, "driver")
		if d == nil {
			add(rel, "has Go code and is not registered in internal/builtin — a driver the binary never "+
				"builds is a connector that exists only in the tree")
		}
		if has("schemas.yaml") {
			ships = append(ships, "schemas")
		} else {
			add(rel, "has Go code and no schemas.yaml — every type a connector emits is declared "+
				"closed, beside the code that emits it (D279)")
		}
		suites := []string{"Run"}
		if _, ok := d.(connector.Source); ok {
			suites = append(suites, "RunSource")
		}
		if _, ok := d.(connector.Drifter); ok {
			suites = append(suites, "RunDrift")
		}
		if _, ok := d.(connector.Refiner); ok {
			suites = append(suites, "RunRefiner")
		}
		if _, ok := d.(connector.Presetter); ok {
			suites = append(suites, "RunPresetter")
		}
		for _, s := range suites {
			if !mentions(tests, "conformance."+s+"(") {
				add(rel, "does not run conformance.%s — the published suite is the only check an "+
					"out-of-tree author has, and the in-tree connectors are what they copy (D167)", s)
			}
		}
		ships = append(ships, "conformance: "+strings.Join(suites, "+"))
	case !has("mcp.yaml"):
		add(rel, "has no Go code and no mcp.yaml — a folder that is neither a driver nor an "+
			"MCP-only connector is not a connector")
	}

	if has("mcp.yaml") {
		ships = append(ships, "mcp")
		if err := loadMCP(filepath.Join(dir, "mcp.yaml")); err != nil {
			add(rel, "mcp.yaml does not validate: %v", err)
		}
	}
	if has("anzen.yaml") {
		ships = append(ships, "anzen")
		if doc, err := load(filepath.Join(dir, "anzen.yaml")); err != nil {
			add(rel, "anzen.yaml does not load: %v", err)
		} else if len(doc.Anzen) == 0 {
			add(rel, "anzen.yaml loads and carries no anzen rules — a suggested ceiling that suggests "+
				"nothing reads as protection")
		}
	}
	if has("reflexes.yaml") {
		ships = append(ships, "reflexes")
		checkReflexes(dir, rel, d, add)
	}
	if has("presets.yaml") {
		ships = append(ships, "presets")
		checkPresets(dir, rel, d, add)
	}
	if has("reference") {
		ships = append(ships, "reference")
		checkReference(dir, rel, add)
	}
	return strings.Join(ships, ", ")
}

// checkPresets: a folder's presets.yaml is a fragment a deployment can drop in
// as it stands, every action is the driver's, and every `mirrors:` claim holds
// against the driver's own grading (D327) — grantcheck.PresetMisses, the rule
// boot applies to a deployment's copy. A driver that ships the file also embeds
// it, byte for byte, so boot can say when a deployment's copy has fallen behind
// what the connector now suggests.
//
// AN MCP-ONLY FOLDER'S PRESETS ARE PARSED AND NOT GRADED: there is no driver to
// ask what its tools need, so such a preset may not claim `mirrors:` — boot
// refuses that claim for the same reason.
func checkPresets(dir, rel string, d connector.Driver, add func(string, string, ...any)) {
	raw, err := os.ReadFile(filepath.Join(dir, "presets.yaml"))
	if err != nil {
		add(rel, "presets.yaml cannot be read: %v", err)
		return
	}
	presets, err := config.ParsePresets(raw)
	if err != nil {
		add(rel, "presets.yaml does not load: %v", err)
		return
	}
	if d == nil {
		return
	}
	p, ok := d.(connector.Presetter)
	switch {
	case !ok:
		add(rel, "ships presets.yaml and its driver is not a connector.Presetter, so boot cannot tell a "+
			"deployment its copy has fallen behind — embed the file and return it from SuggestedPresets() (D327)")
	case !bytes.Equal(p.SuggestedPresets(), raw):
		add(rel, "the driver's SuggestedPresets() is not this folder's presets.yaml; the file beside the "+
			"code is the suggestion boot compares against (D327)")
	}
	for _, miss := range grantcheck.PresetMisses(presets, map[string]connector.Driver{d.Kind(): d}, nil) {
		add(rel, "presets.yaml: %s", miss)
	}
}

// checkReflexes: a folder's reflexes.yaml loads in the closed vocabulary, and
// it IS what the driver serves — a Refiner whose Reflexes() is the file's bytes
// (D317). A file beside a driver that never embeds it is a rule set that exists
// only in the tree, the unregistered-folder failure one level down.
func checkReflexes(dir, rel string, d connector.Driver, add func(string, string, ...any)) {
	raw, err := os.ReadFile(filepath.Join(dir, "reflexes.yaml"))
	if err != nil {
		add(rel, "reflexes.yaml cannot be read: %v", err)
		return
	}
	if _, err := config.ParseReflexes(raw); err != nil {
		add(rel, "reflexes.yaml does not load: %v", err)
	}
	rf, ok := d.(connector.Refiner)
	switch {
	case !ok:
		add(rel, "ships reflexes.yaml and its driver is not a connector.Refiner, so no deployment can ever "+
			"impose these rules — embed the file and return it from Reflexes() (D317)")
	case !bytes.Equal(rf.Reflexes(), raw):
		add(rel, "the driver's Reflexes() is not this folder's reflexes.yaml; the file beside the code is the "+
			"file the binary serves (D299)")
	}
}

// goFiles reports whether dir has non-test Go files, and returns its test files'
// contents.
func goFiles(dir string) (code bool, tests []string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") {
			continue
		}
		if !strings.HasSuffix(n, "_test.go") {
			code = true
			continue
		}
		if src, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			tests = append(tests, string(src))
		}
	}
	return code, tests
}

func mentions(srcs []string, want string) bool {
	for _, s := range srcs {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// load is THE parse a deployment's config directory gets — duplicate keys and
// unknown fields refused — without composing or validating a whole deployment.
func load(path string) (*config.Document, error) {
	return config.NewFileSource(path).Load(context.Background())
}

// loadMCP loads a vetted MCP fragment and validates each spec beside a target
// synthesised for it, because MCP validation is relative to a target (a pinned
// argument names a target setting, D289). The target is the least that lets the
// SPEC's checks run; P3 step 25 and P4 step 31 test the Fullstory spec beside a
// realistic one.
func loadMCP(path string) error {
	doc, err := load(path)
	if err != nil {
		return err
	}
	if len(doc.MCPSpecs) == 0 {
		return fmt.Errorf("it declares no mcp_specs")
	}
	for ref, spec := range doc.MCPSpecs {
		if len(spec.Tools) == 0 {
			return fmt.Errorf("spec %q vets no tools", ref)
		}
		settings := map[string]string{}
		for _, tool := range spec.Tools {
			for _, p := range tool.Pin {
				settings[p] = "connectorcheck"
			}
		}
		host := "mcp.connectorcheck.invalid"
		if spec.Host != "" {
			host = spec.Host
		}
		doc.Targets = append(doc.Targets, config.TargetSpec{Ref: ref, Kind: mcp.Kind, Tenant: "connectorcheck",
			BaseURL: "https://" + host + "/mcp", CredentialRef: "env://CONNECTORCHECK", Settings: settings})
	}
	return doc.Validate()
}

// checkReference: each revision directory carries the manifest the P4 reference
// steps read. What the manifest SAYS is theirs to check (P4 steps 1-5).
func checkReference(dir, rel string, add func(string, string, ...any)) {
	revs, err := os.ReadDir(filepath.Join(dir, "reference"))
	if err != nil {
		add(rel, "reference/ cannot be read: %v", err)
		return
	}
	n := 0
	for _, r := range revs {
		if !r.IsDir() {
			continue
		}
		n++
		if _, err := os.Stat(filepath.Join(dir, "reference", r.Name(), "manifest.yaml")); err != nil {
			add(rel, "reference/%s has no manifest.yaml — a revision is the label, the snapshot is the "+
				"evidence (D299)", r.Name())
		}
	}
	if n == 0 {
		add(rel, "reference/ holds no revision directory")
	}
}
