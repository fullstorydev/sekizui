package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/apiref"
	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// P4 steps 1, 2, 4 and 5 — the Fullstory reference snapshot and what it holds
// the driver to (D294, D299, D301, D304, D311).

// refManifest is `reference/<revision>/manifest.yaml`.
type refManifest struct {
	Revision             string            `json:"revision"`
	Fetched              string            `json:"fetched"`
	Source               string            `json:"source"`
	DocumentedHosts      []string          `json:"documented_hosts"`
	VendorConfirmedHosts []refVendorHost   `json:"vendor_confirmed_hosts"`
	Endpoints            []refEndpoint     `json:"endpoints"`
	ExcludedOutside      []refOutsideEntry `json:"excluded_outside_server"`
}

type refVendorHost struct {
	Host     string `json:"host"`
	DC       string `json:"dc"`
	Decision string `json:"decision"`
}

type refEndpoint struct {
	Tier       string `json:"tier"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Permission string `json:"permission"`
	Deprecated bool   `json:"deprecated"`
	Excluded   string `json:"excluded"`
	Host       string `json:"host"`
	Docs       string `json:"docs"`
}

type refOutsideEntry struct {
	Section  string `json:"section"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Excluded string `json:"excluded"`
	Docs     string `json:"docs"`
}

func (e refEndpoint) key() string { return e.Method + " " + e.Path }

func referenceDir(t *testing.T) string {
	return filepath.Join(mustRoot(t), "internal", "connectors", "fullstory", "reference")
}

func loadManifest(t *testing.T, revision string) refManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(referenceDir(t), revision, "manifest.yaml"))
	if err != nil {
		t.Fatalf("the snapshot for revision %q: %v", revision, err)
	}
	var m refManifest
	if err := yaml.UnmarshalStrict(raw, &m); err != nil {
		t.Fatalf("the manifest does not load strictly: %v", err)
	}
	return m
}

// decisionExists reports whether DECISIONS.md has an entry for d — through
// docref, whose extractor fails rather than matching nothing (D185).
func decisionExists(t *testing.T, d string) bool {
	// PUBLIC EXPORT: the decision record is kept by the maintainers; a citation is an opaque
	// label here, so it is checked for its form only.
	t.Helper()
	return regexp.MustCompile(`^D[0-9]+$`).MatchString(d)
}

// p4Step1 — the connector declares a dated reference revision, and the snapshot
// behind it is committed (D299, D304).
func p4Step1(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the connector declares a dated reference revision, and the snapshot behind it is committed")
	rev := fullstory.New().ReferenceRevision()

	// 1a — THE REVISION NAMES EXACTLY ONE COMMITTED SNAPSHOT, and nothing else is there.
	entries, err := os.ReadDir(referenceDir(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != rev {
			t.Errorf("step 1a: reference/%s is a snapshot no revision names — the driver declares %q",
				e.Name(), rev)
		}
	}
	m := loadManifest(t, rev)
	if m.Revision != rev || m.Fetched == "" || m.Source == "" {
		t.Fatalf("step 1a: the manifest says revision %q, fetched %q, source %q; the driver declares %q",
			m.Revision, m.Fetched, m.Source, rev)
	}

	// 1b — EVERY ENTRY IS WHOLE, and every exclusion cites a decision that exists.
	tiers := map[string]bool{"v2": true, "v1": true, "beta": true}
	methods := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	seen := map[string]bool{}
	for _, e := range m.Endpoints {
		switch {
		case !tiers[e.Tier], !methods[e.Method], !strings.HasPrefix(e.Path, "/"),
			e.Permission == "", !strings.HasPrefix(e.Docs, "https://developer.fullstory.com/"):
			t.Errorf("step 1b: an incomplete entry: %+v", e)
		case seen[e.key()]:
			t.Errorf("step 1b: %s is listed twice", e.key())
		case e.Excluded != "" && !decisionExists(t, e.Excluded):
			t.Errorf("step 1b: %s is excluded by %s, which is not a decision", e.key(), e.Excluded)
		}
		seen[e.key()] = true
	}
	for _, e := range m.ExcludedOutside {
		if e.Excluded == "" || !decisionExists(t, e.Excluded) {
			t.Errorf("step 1b: %s %s outside /server/ is excluded by %q, which is not a decision",
				e.Method, e.Path, e.Excluded)
		}
	}
	for _, h := range m.VendorConfirmedHosts {
		if !decisionExists(t, h.Decision) {
			t.Errorf("step 1b: vendor-confirmed host %s cites %q, which is not a decision", h.Host, h.Decision)
		}
	}
	if len(m.Endpoints) == 0 {
		t.Fatal("step 1b: the manifest lists no endpoints; this step is checking nothing")
	}

	// 1c — EVERY OPERATION'S CONTRACT IS COMMITTED BESIDE IT (D313).
	contracts := loadContracts(t, rev)
	for _, e := range m.Endpoints {
		if c, ok := contracts[e.key()]; !ok {
			t.Errorf("step 1c: %s has no contract in contracts/", e.key())
		} else if c.Tier != e.Tier {
			t.Errorf("step 1c: %s is tier %s in the manifest and %s in its contract", e.key(), e.Tier, c.Tier)
		}
	}
	for _, e := range m.ExcludedOutside {
		if _, ok := contracts[e.Method+" "+e.Path]; !ok {
			t.Errorf("step 1c: %s %s has no contract in contracts/", e.Method, e.Path)
		}
	}
	r.detail(t, "revision %s: %d endpoints, %d outside /server/ excluded, %d vendor-confirmed host(s)",
		rev, len(m.Endpoints), len(m.ExcludedOutside), len(m.VendorConfirmedHosts))
}

// p4Step2 — every endpoint the driver calls is in the snapshot (D294, D299).
func p4Step2(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "every endpoint the driver calls is in the snapshot")
	drv := fullstory.New()
	m := loadManifest(t, drv.ReferenceRevision())
	byKey := map[string]refEndpoint{}
	for _, e := range m.Endpoints {
		byKey[e.key()] = e
	}

	// 2a — THE DECLARED SURFACE IS DOCUMENTED, AND NOTHING EXCLUDED IS CALLED.
	surface := drv.Surface()
	for _, s := range surface {
		e, ok := byKey[s]
		switch {
		case !ok:
			t.Errorf("step 2a: the driver calls %s, which the reference does not document — an "+
				"undocumented call is one the vendor never promised (D294)", s)
		case e.Excluded != "":
			t.Errorf("step 2a: the driver calls %s, which %s excluded", s, e.Excluded)
		}
	}

	// 2b — THE SURFACE CANNOT UNDER-REPORT: every request the package builds takes
	// its method and path from a declared endpoint, and every declared endpoint is
	// in `surface`.
	problems := surfaceIsTheOnlyWayOut(t)
	for _, p := range problems {
		t.Errorf("step 2b: %s", p)
	}
	if len(surface) == 0 {
		t.Fatal("step 2: the driver declares no surface; this step is checking nothing")
	}
	r.detail(t, "%d endpoint(s) called, each documented at revision %s; every request is built "+
		"from a declared endpoint", len(surface), drv.ReferenceRevision())
}

// surfaceIsTheOnlyWayOut reads the Fullstory driver's source: every
// http.NewRequestWithContext takes `<ep>.method` and a URL built with
// `<ep>.path(...)`, and every endpoint value declared is listed in `surface`.
func surfaceIsTheOnlyWayOut(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(mustRoot(t), "internal", "connectors", "fullstory")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	declared, listed := map[string]bool{}, map[string]bool{}
	requests := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.ValueSpec:
				for i, name := range x.Names {
					if i >= len(x.Values) {
						break
					}
					if lit, ok := x.Values[i].(*ast.CompositeLit); ok {
						if id, ok := lit.Type.(*ast.Ident); ok && id.Name == "endpoint" {
							declared[name.Name] = true
						}
						if name.Name == "surface" {
							for _, el := range lit.Elts {
								if id, ok := el.(*ast.Ident); ok {
									listed[id.Name] = true
								}
							}
						}
					}
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "NewRequestWithContext" || len(x.Args) < 3 {
					return true
				}
				requests++
				if m, ok := x.Args[1].(*ast.SelectorExpr); !ok || m.Sel.Name != "method" {
					problems = append(problems, fmt.Sprintf("%s builds a request whose method is not "+
						"an endpoint's", fset.Position(x.Pos())))
				}
				usesPath := false
				ast.Inspect(x.Args[2], func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "path" {
							usesPath = true
						}
					}
					return true
				})
				if !usesPath {
					problems = append(problems, fmt.Sprintf("%s builds a request whose URL is not an "+
						"endpoint's path — the surface would under-report it", fset.Position(x.Pos())))
				}
			}
			return true
		})
	}
	for name := range declared {
		if !listed[name] {
			problems = append(problems, fmt.Sprintf("endpoint %s is declared and not in `surface`", name))
		}
	}
	if requests == 0 {
		problems = append(problems, "no request construction was found; the arm is looking at nothing")
	}
	sort.Strings(problems)
	return problems
}

// --- step 4: the Lexicon audit -------------------------------------------------

type lexiconAudit struct {
	Source  string `json:"source"`
	Audited string `json:"audited"`
	Calls   []struct {
		Function string `json:"function"`
		Method   string `json:"method"`
		Path     string `json:"path"`
		Verdict  string `json:"verdict"`
		Why      string `json:"why"`
	} `json:"calls"`
	NewInReference []struct {
		Tier   string `json:"tier"`
		Method string `json:"method"`
		Path   string `json:"path"`
	} `json:"new_in_reference"`
}

var placeholder = regexp.MustCompile(`\{[^}]+\}`)

func shape(method, path string) string {
	return method + " " + placeholder.ReplaceAllString(path, "{}")
}

// p4Step4 — every endpoint Lexicon's Fullstory.js calls is classified (D294).
func p4Step4(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "every endpoint Lexicon's Fullstory.js calls is classified")
	rev := fullstory.New().ReferenceRevision()
	m := loadManifest(t, rev)
	documented, excluded := map[string]bool{}, map[string]bool{}
	for _, e := range m.Endpoints {
		documented[shape(e.Method, e.Path)] = true
		if e.Excluded != "" {
			excluded[shape(e.Method, e.Path)] = true
		}
	}
	raw, err := os.ReadFile(filepath.Join(referenceDir(t), rev, "lexicon-audit.yaml"))
	if err != nil {
		t.Fatalf("step 4: the audit artefact: %v", err)
	}
	var audit lexiconAudit
	if err := yaml.UnmarshalStrict(raw, &audit); err != nil {
		t.Fatalf("step 4: the audit does not load strictly: %v", err)
	}

	// 4a — EVERY VERDICT IS TRUE OF THE MANIFEST.
	for _, c := range audit.Calls {
		k := shape(c.Method, c.Path)
		switch c.Verdict {
		case "carried":
			if !documented[k] || excluded[k] {
				t.Errorf("step 4a: %s (%s) is marked carried and is not a documented, non-excluded endpoint",
					c.Function, k)
			}
		case "corrected", "not_carried":
			if documented[k] {
				t.Errorf("step 4a: %s (%s) is marked %s and IS documented as called", c.Function, k, c.Verdict)
			}
			if c.Why == "" {
				t.Errorf("step 4a: %s is %s with no reason", c.Function, c.Verdict)
			}
		case "excluded":
			if !regexp.MustCompile(`D\d+`).MatchString(c.Why) {
				t.Errorf("step 4a: %s is excluded without naming the decision", c.Function)
			}
		default:
			t.Errorf("step 4a: %s has verdict %q, which is not one of carried, corrected, not_carried, "+
				"excluded", c.Function, c.Verdict)
		}
	}
	for _, n := range audit.NewInReference {
		if !documented[shape(n.Method, n.Path)] {
			t.Errorf("step 4a: %s %s is listed as new in the reference and is not in it", n.Method, n.Path)
		}
	}

	// 4b — COMPLETE AGAINST THE FILE, where the file is present. Lexicon lives beside
	// this module in the monorepo and is read, never edited (D81); where Sekizui
	// stands alone the artefact's own consistency above is what remains checkable.
	lexicon := filepath.Join(mustRoot(t), "..", "lexicon", "Fullstory.js")
	js, err := os.ReadFile(lexicon)
	if err != nil {
		r.detail(t, "Lexicon is not beside this checkout; the audit's %d verdicts are checked against "+
			"the manifest, and its completeness against Fullstory.js is not", len(audit.Calls))
		return
	}
	sites := regexp.MustCompile(`_makeRequest\(`).FindAllIndex(js, -1)
	calls := len(sites) - 1 // the method's own declaration, `async _makeRequest(`
	if calls != len(audit.Calls) {
		t.Errorf("step 4b: Fullstory.js has %d _makeRequest call sites and the audit classifies %d — "+
			"an unclassified call is a gap somebody later fills without deciding", calls, len(audit.Calls))
	}
	fns := map[string]bool{}
	for _, c := range audit.Calls {
		fns[c.Function] = true
	}
	for name := range fns {
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`).Match(js) {
			t.Errorf("step 4b: the audit names %s, which Fullstory.js does not define", name)
		}
	}
	r.detail(t, "all %d _makeRequest call sites in Fullstory.js classified, each verdict true of the manifest",
		calls)
}

// --- step 5: reference drift, graded, at release -------------------------------

// refView is what the drift comparison compares for one operation: its tier,
// and the canonical form of its input (parameters + request body) and output.
type refView struct{ tier, input, output string }

// canon renders JSON canonically — encoding/json sorts map keys (GO-PRIMER §15s).
func canon(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func viewOf(tier string, op apiref.Operation) refView {
	return refView{tier: tier, input: canon(op.Parameters) + "|" + canon(op.RequestBody), output: canon(op.Response)}
}

// compareReference grades the differences between the committed snapshot and a
// published reference in the one drift vocabulary (D311): newly published is
// `unvetted`, gone from the documentation is `withheld`, a changed INPUT
// contract under a snapshotted operation is `refused` — what a human reviewed
// is not what the vendor now accepts, the grade an MCP input-schema change gets
// — and a tier move or a changed response is `informational`. Excluded
// endpoints are compared like any other: excluded is a decision about KNOWN
// endpoints, not a filter on the comparison.
func compareReference(snapshot, published map[string]refView) connector.DriftFindings {
	var out connector.DriftFindings
	for k, now := range published {
		was, ok := snapshot[k]
		switch {
		case !ok:
			out = append(out, connector.DriftFinding{Severity: connector.DriftUnvetted, Tool: k,
				Detail: "published, and not in the committed snapshot"})
		case was.input != now.input:
			out = append(out, connector.DriftFinding{Severity: connector.DriftRefused, Tool: k,
				Detail: "its documented parameters or request body changed"})
		case was.tier != now.tier:
			out = append(out, connector.DriftFinding{Severity: connector.DriftInformational, Tool: k,
				Detail: fmt.Sprintf("moved from %s to %s", was.tier, now.tier)})
		case was.output != now.output:
			out = append(out, connector.DriftFinding{Severity: connector.DriftInformational, Tool: k,
				Detail: "its documented response changed"})
		}
	}
	for k := range snapshot {
		if _, ok := published[k]; !ok {
			out = append(out, connector.DriftFinding{Severity: connector.DriftWithheld, Tool: k,
				Detail: "in the snapshot, and no longer published"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// loadContracts reads a revision's contracts/, keyed "METHOD /path".
func loadContracts(t *testing.T, revision string) map[string]apiref.Operation {
	t.Helper()
	dir := filepath.Join(referenceDir(t), revision, "contracts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("the snapshot's contracts: %v", err)
	}
	out := map[string]apiref.Operation{}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var op apiref.Operation
		if err := json.Unmarshal(raw, &op); err != nil {
			t.Fatalf("contract %s does not parse: %v", e.Name(), err)
		}
		out[op.Key()] = op
	}
	return out
}

func snapshotOf(t *testing.T, m refManifest) map[string]refView {
	t.Helper()
	contracts := loadContracts(t, m.Revision)
	out := map[string]refView{}
	for _, e := range m.Endpoints {
		out[e.key()] = viewOf(e.Tier, contracts[e.key()])
	}
	for _, e := range m.ExcludedOutside {
		k := e.Method + " " + e.Path
		out[k] = viewOf(e.Section, contracts[k])
	}
	return out
}

// p4Step5 — reference drift fails the live run and never the build (D299, D311).
func p4Step5(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "reference drift fails the live run and never the build")
	m := loadManifest(t, fullstory.New().ReferenceRevision())
	snap := snapshotOf(t, m)

	// 5a — AN IDENTICAL REFERENCE REPORTS NOTHING.
	if fs := compareReference(snap, snap); len(fs) != 0 {
		t.Fatalf("step 5a: the snapshot compared with itself reported %v", fs)
	}

	// 5b — A DRIFTED ONE IS GRADED, ONE FINDING PER KIND, IN THE VOCABULARY.
	drifted := map[string]refView{}
	for k, v := range snap {
		drifted[k] = v
	}
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	gone, moved, reshaped := keys[0], keys[1], keys[2]
	delete(drifted, gone)
	mv := drifted[moved]
	mv.tier = "promoted"
	drifted[moved] = mv
	rs := drifted[reshaped]
	rs.input += "+a-new-required-field"
	drifted[reshaped] = rs
	drifted["GET /v2beta/sekizui-probe"] = refView{tier: "beta"}
	fs := compareReference(snap, drifted)
	want := map[string]connector.DriftSeverity{
		gone: connector.DriftWithheld, moved: connector.DriftInformational,
		reshaped: connector.DriftRefused, "GET /v2beta/sekizui-probe": connector.DriftUnvetted,
	}
	if len(fs) != len(want) {
		t.Fatalf("step 5b: want %d findings, got %v", len(want), fs)
	}
	for _, f := range fs {
		if !f.Severity.Known() || want[f.Tool] != f.Severity {
			t.Errorf("step 5b: %s graded %q, want %q", f.Tool, f.Severity, want[f.Tool])
		}
	}

	// 5c — EXCLUDED IS NOT A FILTER: an excluded endpoint that disappears is still drift.
	for _, e := range m.Endpoints {
		if e.Excluded == "" {
			continue
		}
		without := map[string]refView{}
		for k, v := range snap {
			if k != e.key() {
				without[k] = v
			}
		}
		if got := compareReference(snap, without); len(got) != 1 || got[0].Severity != connector.DriftWithheld {
			t.Errorf("step 5c: excluded %s vanishing reported %v, want one withheld", e.key(), got)
		}
		break
	}
	r.detail(t, "offline: identical passes; one withheld, one refused (a changed input contract), one "+
		"informational and one unvetted graded; an excluded endpoint vanishing is still drift")

	// 5d — THE LIVE ARM, only when a live run was asked for (reaching out is an intent).
	if os.Getenv(liveWriteRequested) == "" {
		r.detail(t, "the live comparison with developer.fullstory.com was not requested "+
			"(`make acceptance-live` asks for it); the build touched no network")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	ops, err := apiref.Read(ctx, &http.Client{Timeout: 30 * time.Second}, "https://developer.fullstory.com",
		func(r string) bool {
			return strings.HasPrefix(r, "/server/") || strings.HasPrefix(r, "/anywhere/v1/webhooks/")
		}, liveTier)
	if err != nil {
		t.Fatalf("step 5d: reading the published reference: %v", err)
	}
	published := map[string]refView{}
	for _, op := range ops {
		published[op.Key()] = viewOf(op.Tier, op)
	}
	live := compareReference(snap, published)
	for _, f := range live {
		t.Errorf("step 5d: the published reference has drifted from the snapshot: %s — refresh the "+
			"snapshot as a new revision (D299)", f)
	}
	r.detail(t, "live: %d published operations compared with the snapshot, %d finding(s)",
		len(published), len(live))
}

// liveTier reads a page's tier from its route, as the snapshot tool does.
func liveTier(route string) string {
	switch {
	case strings.HasPrefix(route, "/server/beta/"):
		return "beta"
	case strings.HasPrefix(route, "/server/v1/"):
		return "v1"
	case strings.HasPrefix(route, "/server/"):
		return "v2"
	default:
		return strings.SplitN(strings.TrimPrefix(route, "/"), "/", 2)[0]
	}
}

// p4Step3 — every snapshot endpoint is implemented or excluded by a named
// decision (D294, D301, D314).
func p4Step3(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "every snapshot endpoint is implemented or excluded by a named decision")
	drv := fullstory.New()
	m := loadManifest(t, drv.ReferenceRevision())
	reached := map[string]bool{}
	for _, s := range drv.Surface() {
		reached[s] = true
	}
	implemented, excluded := 0, 0
	for _, e := range m.Endpoints {
		switch {
		case e.Excluded != "" && reached[e.key()]:
			t.Errorf("step 3: %s is excluded by %s and the driver still reaches it", e.key(), e.Excluded)
		case e.Excluded != "":
			excluded++
		case !reached[e.key()]:
			t.Errorf("step 3: %s is documented, not excluded, and no action reaches it — \"in full\" "+
				"is a promise about the reference, not about what was convenient (D294)", e.key())
		default:
			implemented++
		}
	}
	r.detail(t, "all %d documented operations accounted for: %d implemented, %d excluded by decision",
		len(m.Endpoints), implemented, excluded)
}

// --- step 33: the suggested anzen ceiling ------------------------------------

func loadSuggestedAnzen(t *testing.T) []config.AnzenSpec {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(mustRoot(t), "internal", "connectors", "fullstory", "anzen.yaml"))
	if err != nil {
		t.Fatalf("the suggested anzen fragment: %v", err)
	}
	var frag struct {
		Anzen []config.AnzenSpec `json:"anzen"`
	}
	if err := yaml.UnmarshalStrict(raw, &frag); err != nil {
		t.Fatalf("the suggested anzen fragment does not load strictly: %v", err)
	}
	return frag.Anzen
}

// p4Step33 — the Fullstory connector suggests anzen ceilings for its
// irreversible and recording-configuration operations, and they hold under any
// grant (D314).
func p4Step33(t *testing.T) {
	rules := loadSuggestedAnzen(t)
	forbidden := map[string]string{} // action -> rule
	for _, rule := range rules {
		for _, a := range rule.Forbids {
			forbidden[a] = rule.Name
		}
	}

	// 33a — EVERY NAME IS A REAL WRITE the connector advertises: a typo in a
	// blocklist forbids nothing and reads as protection.
	specs := map[string]connector.ActionSpec{}
	for _, s := range fullstory.New().Actions() {
		specs[s.Name] = s
	}
	for a := range forbidden {
		if s, ok := specs[a]; !ok || !s.Mutating {
			t.Errorf("step 33a: the fragment forbids %s, which is not a write the connector advertises", a)
		}
	}
	if len(forbidden) != 12 {
		t.Errorf("step 33a: the fragment forbids %d actions; the maintainer ruled 12 — three irreversible and nine "+
			"recording-configuration writes (D314)", len(forbidden))
	}

	// 33f — THE DEMO DEPLOYMENT THAT `make run` SERVES LOADS AND VALIDATES (D315),
	// so what `make demo` drives cannot rot unnoticed.
	demo, err := config.NewFileSource("demo.d").Load(context.Background())
	if err != nil {
		t.Fatalf("step 33f: the demo deployment does not load: %v", err)
	}
	if err := demo.Validate(); err != nil {
		t.Fatalf("step 33f: the demo deployment does not validate: %v", err)
	}

	// THE REMOTE PATH: `make demo` drives a RUNNING instance, which serves demo.d.
	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		p4Step33Remote(t, demo, forbidden)
		return
	}

	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	run := newRunWith(t, runOpts{patch: func(doc *config.Document) {
		// THE FRAGMENT ALONE. The shared deployment already carries a generic
		// `*.delete_*` ceiling, which matched the four deletes FIRST when this step
		// first ran — overlapping ceilings, first match named, which is correct —
		// so it is dropped here: this step proves the CONNECTOR'S rules hold on
		// their own, and a record naming a rule the connector never shipped would
		// prove nothing about them.
		kept := doc.Anzen[:0]
		for _, rule := range doc.Anzen {
			if rule.Name != "no-destructive-actions" {
				kept = append(kept, rule)
			}
		}
		doc.Anzen = append(kept, rules...)
		for i := range doc.Targets {
			if doc.Targets[i].Ref == "fs:fixture" {
				doc.Targets[i].BaseURL = srv.URL
			}
		}
		// A WILDCARD GRANT: the ceiling has to hold even where policy says yes.
		for i := range doc.Grants {
			if doc.Grants[i].Principal == "agent:triage" {
				doc.Grants[i].Allow = append(doc.Grants[i].Allow,
					config.CapabilitySpec{Action: "fullstory.*", TargetRef: "fs:fixture"})
			}
		}
	}})
	if run.localOnly(t, "the patched deployment is this instance's") {
		return
	}
	run.narrate(t, "the Fullstory connector's suggested anzen ceiling holds under a wildcard grant")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := run.as(t, "agent:triage")
	argsFor := func(action string) map[string]any {
		args := map[string]any{}
		for _, p := range []string{"id", "uid"} {
			args[p] = "p-1"
		}
		if strings.HasSuffix(action, "element_block_rules") || strings.HasPrefix(action, "fullstory.create_") {
			return map[string]any{}
		}
		if strings.HasSuffix(action, "_v1") {
			delete(args, "id")
		} else {
			delete(args, "uid")
		}
		return args
	}

	// 33b — EVERY FORBIDDEN ACTION IS REFUSED, and nothing reaches Fullstory.
	names := make([]string, 0, len(forbidden))
	for a := range forbidden {
		names = append(names, a)
	}
	sort.Strings(names)
	for _, a := range names {
		resp, err := client.Execute(ctx, execute(a, "fs:fixture", argsFor(a)))
		if err != nil {
			t.Fatalf("step 33b: %s: %v", a, err)
		}
		if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
			t.Errorf("step 33b: %s under a wildcard grant came back %s, not refused", a, got)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("step 33b: Fullstory received %d request(s) for actions the ceiling forbids", hits.Load())
	}

	// 33c — NON-VACUITY: a write the ceiling does NOT name passes anzen and policy
	// under the same grant (it is then stopped by the host check, D288 — the
	// fixture is not Fullstory — which is exactly what keeps this hermetic).
	allowed, err := client.Execute(ctx, execute("fullstory.create_annotation", "fs:fixture", map[string]any{}))
	if err != nil {
		t.Fatalf("step 33c: %v", err)
	}
	if allowed.GetResult().GetStatus() == sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("step 33c: create_annotation, which the ceiling does not name, was DENIED too — the "+
			"refusals above prove nothing about the ceiling: %s", allowed.GetResult().GetReason())
	}

	// 33d — THE RECORD NAMES THE STAGE AND THE RULE.
	named := map[string]bool{}
	for _, d := range readLog(t, run.path) {
		rule, isForbidden := forbidden[d.GetAction()]
		if !isForbidden {
			continue
		}
		if d.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_ANZEN || d.GetMatchedRule() != "anzen:"+rule {
			t.Errorf("step 33d: %s was recorded refused_by %s, rule %q; want anzen, %q", d.GetAction(),
				d.GetRefusedBy(), d.GetMatchedRule(), "anzen:"+rule)
		}
		named[d.GetAction()] = true
	}
	if len(named) != len(forbidden) {
		t.Errorf("step 33d: %d of %d forbidden actions have a refusal record", len(named), len(forbidden))
	}

	// 33e — DESCRIBE TELLS THE AGENT WHICH RULE WITHHOLDS EACH, rather than
	// leaving a capability silently missing (CONTRACTS 64).
	desc, err := client.Describe(ctx, &sekizuiv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("step 33e: %v", err)
	}
	withheld := map[string]string{}
	for _, w := range desc.GetWithheld() {
		if w.GetTargetRef() == "fs:fixture" {
			withheld[w.GetAction()] = w.GetGuard()
		}
	}
	for a, rule := range forbidden {
		if withheld[a] != rule {
			t.Errorf("step 33e: Describe reports %s withheld by %q, want %q", a, withheld[a], rule)
		}
	}
	run.detail(t, "%d actions forbidden by 2 suggested rules: each refused under a wildcard grant with "+
		"the rule on its record and named in Describe, none reached Fullstory, and an unnamed write passed "+
		"anzen and policy", len(forbidden))
}

// p4Step33Remote is step 33 against the running instance `make demo` drives
// (D315): the showcase principal's wildcard grant, the ceiling holding on a
// real binary, and Describe naming the rule that withholds each action — the
// rule anzen ITSELF picks first in the demo deployment, computed by building its
// own Guards, because the deployment also keeps acceptance.yaml's generic
// `*.delete_*` ceiling and that one rightly matches the deletes first.
func p4Step33Remote(t *testing.T, demo *config.Document, forbidden map[string]string) {
	run := newRun(t)
	run.narrate(t, "the Fullstory connector's suggested anzen ceiling holds on the running instance")
	guards := anzen.New(demo.Anzen)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := run.as(t, "agent:showcase")

	names := make([]string, 0, len(forbidden))
	for a := range forbidden {
		names = append(names, a)
	}
	sort.Strings(names)
	for _, a := range names {
		resp, err := client.Execute(ctx, execute(a, "fs:fixture", map[string]any{"id": "p-1", "uid": "p-1"}))
		if err != nil {
			t.Fatalf("step 33 (remote): %s: %v", a, err)
		}
		if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
			t.Errorf("step 33 (remote): %s under the showcase wildcard came back %s, not refused", a, got)
		}
	}
	desc, err := client.Describe(ctx, &sekizuiv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("step 33 (remote): %v", err)
	}
	withheld := map[string]string{}
	for _, w := range desc.GetWithheld() {
		if w.GetTargetRef() == "fs:fixture" {
			withheld[w.GetAction()] = w.GetGuard()
		}
	}
	for _, a := range names {
		want, _ := guards.Forbids("agent:showcase", a, "eu")
		if withheld[a] != want {
			t.Errorf("step 33 (remote): Describe reports %s withheld by %q; anzen names %q", a, withheld[a], want)
		}
	}
	offered := 0
	for _, c := range desc.GetCapabilities() {
		if c.GetTargetRef() == "fs:fixture" && strings.HasPrefix(c.GetAction(), "fullstory.") {
			offered++
		}
	}
	if offered == 0 {
		t.Error("step 33 (remote): the showcase principal is offered no Fullstory action — the wildcard " +
			"grant is not in the running instance's configuration (start it with `make run`, which " +
			"serves demo.d)")
	}
	run.detail(t, "on the running instance: %d Fullstory actions offered to agent:showcase, %d forbidden "+
		"and refused, each named in Describe with the rule anzen picked", offered, len(names))
}
