package acceptance

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// P5 STEP 13 (D328): kata, the demo and hako are complete, so a v1 contributor
// has a worked form of every contract. THE SURFACE IS DERIVED FROM THE CODE —
// the interfaces pkg/connector exports, the fragments the connector-folder check
// knows, the Document's sections — and each member needs a worked form or a
// written exemption. A new interface, fragment kind or section fails here until
// somebody carries it or says why not; the exemptions are where a reviewer reads
// what v1 deliberately does not demonstrate.

// contractRole classifies every exported interface in pkg/connector.
//
//nolint:gochecknoglobals // immutable classification, read once
var contractRole = map[string]string{
	"Driver": "required",
	// INFRASTRUCTURE: types a driver USES or Sekizui implements; a driver never
	// implements them, so they owe no worked form in kata.
	"ClientPool": "infrastructure", "Resolver": "infrastructure", "Configured": "infrastructure",
	// OPTIONAL CONTRACTS a driver may implement.
	"HostBound": "optional", "Source": "optional", "Drifter": "optional", "Refiner": "optional",
	"Presetter": "optional", "Leveled": "optional", "ClientBuilder": "optional",
}

// kataImplements answers, by type assertion, whether the reference driver
// implements an optional contract — the question the suites ask.
func kataImplements(name string) bool {
	var d any = kata.New()
	switch name {
	case "HostBound":
		_, ok := d.(connector.HostBound)
		return ok
	case "Source":
		_, ok := d.(connector.Source)
		return ok
	case "Drifter":
		_, ok := d.(connector.Drifter)
		return ok
	case "Refiner":
		_, ok := d.(connector.Refiner)
		return ok
	case "Presetter":
		_, ok := d.(connector.Presetter)
		return ok
	case "Leveled":
		_, ok := d.(connector.Leveled)
		return ok
	case "ClientBuilder":
		_, ok := d.(connector.ClientBuilder)
		return ok
	}
	return false
}

// contractSuite is the published conformance suite that holds an optional
// contract; "" where the contract has no suite of its own.
//
//nolint:gochecknoglobals // immutable, read once
var contractSuite = map[string]string{
	"Source": "RunSource", "Drifter": "RunDrift", "Refiner": "RunRefiner",
	"Presetter": "RunPresetter", "Leveled": "RunPresetter", "ClientBuilder": "Run", "HostBound": "",
}

// kataExempt names the optional contracts kata deliberately does not implement.
//
//nolint:gochecknoglobals // immutable, read once
var kataExempt = map[string]string{
	"HostBound": "kata is in memory and dials nothing, so a host list would bound nothing; the worked " +
		"form is fullstory.AdmitBaseURL, taught in the blueprint",
}

// fragmentExempt names the connector-folder files kata does not ship.
//
//nolint:gochecknoglobals // immutable, read once
var fragmentExempt = map[string]string{
	"mcp.yaml": "kata is a native driver with no MCP server; the worked form is internal/connectors/fullstory/mcp.yaml",
	"reference": "kata is fictional and has no vendor docs to snapshot; the worked form is " +
		"internal/connectors/fullstory/reference/",
}

// sectionExempt names the Document sections hako/reference does not show, and
// where each is taught instead. Everything else must appear there.
//
//nolint:gochecknoglobals // immutable, read once
var sectionExempt = map[string]string{
	"stages":            "deployment topology, not connector packaging; acceptance.yaml's are the worked form",
	"llm_stages":        "deployment topology (D64); acceptance.yaml",
	"jobs":              "a deployment's job limits (D250); acceptance.yaml",
	"credential_policy": "a deployment's policy on credential posture (D111); acceptance.yaml",
	"demo":              "marks a demonstration deployment (D315); internal/acceptance/demo.d",
	"reflexes": "automation a deployment writes over any connector's events, not part of D175's box; " +
		"acceptance.yaml and P5 steps 1-9",
	"reflex_budgets": "bounds a deployment puts on its own reflexes (D334); P5 step 7",
	"issuers":        "the signed-subject trust root is the deployment's (D318); P4 steps 26-30",
	"payload_schemas": "a connector's types are its own and a document may not declare them (D279); the " +
		"worked form is kata's schemas.yaml",
	"policies":  "Rego modules; OPA survives only as an optional adapter nobody must run (D26, D263)",
	"mcp_specs": "kata is native; the worked form is internal/connectors/fullstory/mcp.yaml",
}

// demoEvidence maps each optional contract and each section hako shows to the
// step that exercises it on the RUNNING binary under `make demo` — or, prefixed
// "local-only:", why it cannot. DECLARED, and reviewable: which step drives the
// instance is a judgement; that every member is mapped is derived.
//
//nolint:gochecknoglobals // immutable, read once
var demoEvidence = map[string]string{
	// contracts
	"ClientBuilder": "P4 20", // the showcase reads and writes kata on the running binary
	"Drifter":       "P4 32",
	"Refiner":       "P4 20",
	"Presetter":     "P5 10",
	"Leveled": "local-only: graded at boot — the demo instance booting with the Fullstory presets' " +
		"mirrors claims is the check, and grantcheck refuses a false one",
	"Source": "local-only: the demo serves -mode gateway; polling runs under -mode ingest, and the job " +
		"runner is the instance's (D246)",
	"HostBound": "local-only: refused at boot, before anything serves — `make demo-refusals` shows the real " +
		"binary refusing a foreign host (TestBootRefusalsAreVisible, P3 step 24's case)",
	// sections hako/reference shows
	"targets":     "P4 20",
	"grants":      "P4 20",
	"shin":        "P0 15",
	"anzen":       "P4 33",
	"presets":     "P5 10",
	"refinements": "P4 20",
	"version": "local-only: provenance, logged at boot beside the content identity (D149); the " +
		"identity on every record is P1 step 65's, which narrates nothing into the registry",
	"sources": "local-only: polled only under -mode ingest; the demo serves -mode gateway",
}

// exportedInterfaces parses pkg/connector for the interfaces it exports.
func exportedInterfaces(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, filepath.Join(mustRoot(t), "pkg", "connector"),
		func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range pkgs {
		for _, f := range p.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				if ts, ok := n.(*ast.TypeSpec); ok && ts.Name.IsExported() {
					if _, isIface := ts.Type.(*ast.InterfaceType); isIface {
						out = append(out, ts.Name.Name)
					}
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out
}

// shippableFragments reads the connector-folder check's own list: every name it
// asks a folder whether it `has(...)`.
func shippableFragments(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(mustRoot(t), "internal", "connectorcheck", "connectorcheck.go"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`has\("([^"]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		seen[m[1]] = true
	}
	var out []string
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// documentSections are the Document's top-level keys, by their json tags.
func documentSections() []string {
	var out []string
	typ := reflect.TypeOf(config.Document{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func p5Step13(t *testing.T) {
	root := mustRoot(t)
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	// 13a — EVERY INTERFACE CLASSIFIED; EVERY OPTIONAL ONE CARRIED BY KATA,
	// RUN BY ITS SUITE, AND TAUGHT BY THE BLUEPRINT.
	ifaces := exportedInterfaces(t)
	kataTests := readAll(t, filepath.Join(root, "internal", "connectors", "kata"), "_test.go")
	blueprint := string(mustRead(t, filepath.Join(root, "hako", "BLUEPRINT.md")))
	for _, name := range ifaces {
		role, ok := contractRole[name]
		if !ok {
			add("pkg/connector exports interface %s, which step 13 does not classify — required, optional or "+
				"infrastructure. A new contract needs a worked form in kata, hako and the demo, or an exemption", name)
			continue
		}
		if role != "optional" {
			continue
		}
		if !strings.Contains(blueprint, "connector."+name) {
			add("the blueprint never names connector.%s; a contributor cannot learn a contract nothing teaches", name)
		}
		if why, exempt := kataExempt[name]; exempt {
			if kataImplements(name) {
				add("kata implements %s and is exempted from it (%q); delete the exemption", name, why)
			}
			continue
		}
		if !kataImplements(name) {
			add("kata does not implement connector.%s; the reference driver teaches every contract (D317) — "+
				"implement it or exempt it with the reason", name)
			continue
		}
		if s := contractSuite[name]; s != "" && !strings.Contains(kataTests, "conformance."+s+"(") {
			add("kata implements %s and its tests do not run conformance.%s", name, s)
		}
	}
	for name := range contractRole {
		if !contains(ifaces, name) {
			add("step 13 classifies %s, which pkg/connector no longer exports; delete it", name)
		}
	}

	// 13b — EVERY FRAGMENT A CONNECTOR FOLDER MAY SHIP IS SHIPPED BY KATA.
	for _, frag := range shippableFragments(t) {
		_, err := os.Stat(filepath.Join(root, "internal", "connectors", "kata", frag))
		_, exempt := fragmentExempt[frag]
		switch {
		case err != nil && !exempt:
			add("the connector-folder check knows %s and kata ships none; add it or exempt it", frag)
		case err == nil && exempt:
			add("kata ships %s and is exempted from it; delete the exemption", frag)
		}
	}

	// 13c — EVERY DOCUMENT SECTION HAS A WORKED FORM IN hako/reference.
	hako, err := config.NewFileSource(filepath.Join(root, "hako", "reference")).Load(context.Background())
	if err != nil {
		t.Fatalf("step 13c: hako/reference does not load: %v", err)
	}
	shown := map[string]bool{}
	hv := reflect.ValueOf(hako).Elem()
	for i := range hv.NumField() {
		f := hv.Type().Field(i)
		if f.IsExported() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			shown[name] = !hv.Field(i).IsZero()
		}
	}
	sections := documentSections()
	for _, s := range sections {
		_, exempt := sectionExempt[s]
		switch {
		case !shown[s] && !exempt:
			add("the config section %q has no worked form in hako/reference and no exemption", s)
		case shown[s] && exempt:
			add("hako/reference shows %q and it is exempted; delete the exemption", s)
		}
	}
	for s := range sectionExempt {
		if !contains(sections, s) {
			add("step 13 exempts section %q, which Document no longer has; delete it", s)
		}
	}

	// 13d — EVERY CONTRACT AND SHOWN SECTION HAS DEMO EVIDENCE, and the map
	// names nothing else.
	needDemo := map[string]bool{}
	for name, role := range contractRole {
		if role == "optional" {
			needDemo[name] = true
		}
	}
	for s, on := range shown {
		if on {
			needDemo[s] = true
		}
	}
	for k := range needDemo {
		if demoEvidence[k] == "" {
			add("%s has no demo evidence: map it to the step that exercises it on the running binary, or "+
				"say local-only and why", k)
		}
	}
	for k := range demoEvidence {
		if !needDemo[k] {
			add("demoEvidence maps %s, which is neither an optional contract nor a section hako shows", k)
		}
	}
	remote := r13remote(t)
	for k, ev := range demoEvidence {
		if strings.HasPrefix(ev, "local-only:") {
			continue
		}
		phase, n := parseStepRef(t, ev)
		if !builtStepsByPhaseIncludingP0()[phase][n] {
			add("demo evidence for %s is %s, which is not a built step", k, ev)
			continue
		}
		// UNDER `make demo` THE REMOTE HALF IS MEASURED: every phase runs in this
		// process, so the step's evidence is here — it must have run, passed, and
		// narrated something other than a skip notice. A heuristic, stated: a
		// step whose remote arm narrates nothing would read as not demo-visible.
		if remote {
			if why := demoVisible(phase, n); why != "" {
				add("demo evidence for %s is %s, and under make demo it %s", k, ev, why)
			}
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("step 13: kata, hako and the demo are not complete (%d):\n  - %s", len(problems),
			strings.Join(problems, "\n  - "))
	}
	r := newRun(t)
	r.narrate(t, "kata, the demo and hako are complete, so a v1 contributor has a worked form of every contract")
	r.detail(t, "%d interfaces classified; %d optional contracts carried by kata (1 exempt) and taught; %d fragments "+
		"shipped by kata (%d exempt); %d sections, %d shown by hako/reference; %d demo mappings%s", len(ifaces),
		countRole("optional"), len(shippableFragments(t)), len(fragmentExempt), len(sections), countShown(shown),
		len(demoEvidence), map[bool]string{true: ", measured on the running binary", false: " (measured under make demo)"}[remote])
}

// p0Steps is P0's step count. P0 predates the step tables (it narrates its steps
// inline) and is complete, so its range is fixed.
const p0Steps = 16

// readAll concatenates the files in dir with the suffix.
func readAll(t *testing.T, dir, suffix string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), suffix) {
			b.Write(mustRead(t, filepath.Join(dir, e.Name())))
		}
	}
	return b.String()
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// r13remote reports whether this run drives a live instance (`make demo`).
func r13remote(_ *testing.T) bool { return os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" }

// parseStepRef reads "P4 32".
func parseStepRef(t *testing.T, ref string) (string, int) {
	t.Helper()
	var phase string
	var n int
	if _, err := fmt.Sscanf(ref, "%s %d", &phase, &n); err != nil {
		t.Fatalf("step 13: demo evidence %q is not \"P<n> <step>\": %v", ref, err)
	}
	return phase, n
}

// builtStepsByPhaseIncludingP0 is the ledger guard's map with P0's fixed range.
func builtStepsByPhaseIncludingP0() map[string]map[int]bool {
	out := builtStepsByPhase()
	out["P0"] = map[int]bool{}
	for n := 1; n <= p0Steps; n++ {
		out["P0"][n] = true
	}
	return out
}

// demoVisible is "" when step (phase, n) ran in this process, passed, and
// narrated something other than a skip notice; otherwise what it did instead.
func demoVisible(phase string, n int) string {
	evidence.mu.Lock()
	defer evidence.mu.Unlock()
	var st *evidenceStep
	for _, s := range evidence.steps {
		if s.phase == phase && s.n == n {
			st = s
		}
	}
	switch {
	case st == nil:
		return "did not run in this process — the demo half needs the whole suite (`make demo`)"
	case st.failed:
		return "failed"
	case st.skipped:
		return "was skipped"
	}
	for _, d := range st.details {
		if !strings.Contains(d, "SKIPPED against a live instance") {
			return ""
		}
	}
	return "only skipped its remote arm — it narrated nothing from the running binary"
}

func countRole(role string) int {
	n := 0
	for _, r := range contractRole {
		if r == role {
			n++
		}
	}
	return n
}

func countShown(shown map[string]bool) int {
	n := 0
	for _, on := range shown {
		if on {
			n++
		}
	}
	return n
}
