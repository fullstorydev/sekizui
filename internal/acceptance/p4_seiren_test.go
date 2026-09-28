package acceptance

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/refine"
	"github.com/fullstorydev/sekizui/internal/schemareg"
)

const sessionEventType = "fullstory.session_event.v1"

// builtIns is Fullstory's four rules imposed for agent:a, compiled as boot
// compiles them.
func builtIns(t *testing.T) []schemareg.Refinement {
	t.Helper()
	who := []string{"agent:a"}
	got, problems := compileRefinements(t, fullstory.New(),
		impose("fullstory.frustration", who, nil), impose("fullstory.path", who, nil),
		impose("fullstory.errors", who, nil),
		impose("fullstory.login", who, map[string]any{"signin_prefix": "/login", "success_prefix": "/app"}))
	if problems != "" {
		t.Fatalf("the built-ins do not compile: %s", problems)
	}
	return got
}

var seirenT0 = time.Date(2026, 9, 24, 19, 28, 49, 934_000_000, time.UTC)

func sessionRow(offsetMS int, kind, page string) map[string]any {
	r := map[string]any{"event_time": seirenT0.Add(time.Duration(offsetMS) * time.Millisecond).Format(time.RFC3339Nano),
		"event_type": kind}
	if page != "" {
		r["page_url"] = page
	}
	return r
}

// syntheticSession has distinct times throughout: a login through a redirect,
// a dead-click and the network and console errors it caused, a later page.
func syntheticSession() []map[string]any {
	return []map[string]any{
		sessionRow(0, "navigate", "/login"), sessionRow(2000, "click", ""),
		sessionRow(3000, "navigate", "/sso/redirect"), sessionRow(6000, "navigate", "/app/home"),
		sessionRow(10000, "dead-click", ""), sessionRow(10157, "network-error", ""),
		sessionRow(10159, "console-error", ""), sessionRow(30000, "navigate", "/app/settings"),
		sessionRow(31000, "rage-click", ""),
	}
}

func seirenJSON(t *testing.T, rs []schemareg.Refinement, rows []map[string]any) string {
	t.Helper()
	s, err := refine.Refine(refine.For(rs, refineTarget, "agent:a", sessionEventType), rows, false, nil)
	if err != nil {
		t.Fatalf("refining: %v", err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// p4Step23 — the seiren is deterministic (D298, D300).
func p4Step23(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the seiren is deterministic")
	rs := builtIns(t)

	// 23a — THE VENDOR'S ORDER IS NOT TRUSTED: shuffled, byte-identical.
	want := seirenJSON(t, rs, syntheticSession())
	rng := rand.New(rand.NewSource(20260926)) //nolint:gosec // a fixed seed IS the point: the permutations replay
	for i := 0; i < 50; i++ {
		rows := syntheticSession()
		rng.Shuffle(len(rows), func(a, b int) { rows[a], rows[b] = rows[b], rows[a] })
		if got := seirenJSON(t, rs, rows); got != want {
			t.Fatalf("step 23a: permutation %d produced a different seiren:\n got %s\nwant %s", i, got, want)
		}
	}
	if !strings.Contains(want, `"login"`) || !strings.Contains(want, `"duration_s":0.157`) {
		t.Fatalf("step 23a: the seiren being compared is not the expected one: %s", want)
	}

	// 23b — TIES BREAK BY RESPONSE POSITION, so replaying the recorded order is
	// exact. Two navigates in one millisecond: the path lists them in the order
	// the response gave, and the same response gives the same seiren every time.
	tied := []map[string]any{sessionRow(0, "navigate", "/a"), sessionRow(0, "navigate", "/b"),
		sessionRow(1000, "navigate", "/c")}
	first := seirenJSON(t, rs, tied)
	if !strings.Contains(first, `"page_url":"/a"},{"event_time":"2026-09-24T19:28:49.934Z","next":{"duration_s":1},"page_url":"/b"}`) {
		t.Errorf("step 23b: tied rows were not ordered by response position: %s", first)
	}
	for i := 0; i < 10; i++ {
		if got := seirenJSON(t, rs, tied); got != first {
			t.Fatalf("step 23b: replaying one recorded response gave a different seiren")
		}
	}

	// 23c — AN UNPARSEABLE TIME IS AN ERROR, NEVER A FALSE (D42).
	bad := append(syntheticSession(), map[string]any{"event_time": "24/09/2026 19:28", "event_type": "navigate",
		"page_url": "/x"})
	if _, err := refine.Refine(refine.For(rs, refineTarget, "agent:a", sessionEventType), bad, false, nil); err == nil ||
		!strings.Contains(err.Error(), "not an RFC 3339 date-time") {
		t.Errorf("step 23c: an unparseable event_time was not refused: %v", err)
	}

	// 23d — PURE: the engine reaches nothing that can dispatch, publish, record
	// or hold a credential, so its output is a function of its input (D317).
	cmd := exec.Command(goTool(t), "list", "-deps", "-f", "{{.ImportPath}}", "./internal/refine")
	cmd.Dir = mustRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("step 23d: go list: %v\n%s", err, out)
	}
	const mod = "github.com/fullstorydev/sekizui/internal/"
	for _, dep := range strings.Fields(string(out)) {
		for _, forbidden := range []string{"gateway", "bus", "auditwal", "pool", "credential", "reflex", "kyuushin"} {
			if dep == mod+forbidden || strings.HasPrefix(dep, mod+forbidden+"/") {
				t.Errorf("step 23d: internal/refine reaches %s — the engine must be unable to act (D317)", dep)
			}
		}
	}
	r.detail(t, "50 shuffles of one session gave one byte-identical seiren; tied rows follow response "+
		"position and replay exactly; an unparseable time refuses; the engine's import graph reaches "+
		"nothing that can act")
}

// --- the wire: steps 19, 20, 21, 24 -------------------------------------

const seirenSession = "6606828898126528473:5450116830618425003"

// seirenFixtureServer serves Generate Context for one session: the synthetic
// session above, grouped by page as the vendor groups it. The driver stamps
// each row with its page's URL, and shaping keeps it on navigate rows only.
func seirenFixtureServer(t *testing.T, pages []map[string]any) *httptest.Server {
	t.Helper()
	const contextPath = "/v2/sessions/6606828898126528473%3A5450116830618425003/context"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic fixture-token" {
			http.Error(w, "not the target's credential", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.EscapedPath() != contextPath {
			http.Error(w, "not an endpoint this read uses", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"context_data": map[string]any{"pages": pages}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fixtureEvent(offsetMS int, kind string) map[string]any {
	return map[string]any{"type": kind, "timestamp": seirenT0.Add(time.Duration(offsetMS) * time.Millisecond).
		Format(time.RFC3339Nano), "properties": map[string]any{}}
}

// fixturePages is syntheticSession as Generate Context returns it.
func fixturePages() []map[string]any {
	page := func(url string, events ...map[string]any) map[string]any {
		return map[string]any{"url": url, "events": events}
	}
	return []map[string]any{
		page("/login", fixtureEvent(0, "navigate"), fixtureEvent(2000, "click")),
		page("/sso/redirect", fixtureEvent(3000, "navigate")),
		page("/app/home", fixtureEvent(6000, "navigate"), fixtureEvent(10000, "dead-click"),
			fixtureEvent(10157, "network-error"), fixtureEvent(10159, "console-error")),
		page("/app/settings", fixtureEvent(30000, "navigate"), fixtureEvent(31000, "rage-click")),
	}
}

// seirenRun is an in-process run whose fs:events target reads the fixture,
// with `imps` imposed on it and agent:analytics granted the same read as
// agent:jobs — the principal OUTSIDE the audience.
func seirenRun(t *testing.T, pages []map[string]any, imps []config.RefinementSpec, lenses ...config.ShinSpec) *run {
	t.Helper()
	fx := seirenFixtureServer(t, pages)
	t.Setenv("SEKIZUI_FS_LIVE", "fixture-token")
	return newRunWith(t, runOpts{
		patch: func(d *config.Document) {
			for i := range d.Targets {
				if d.Targets[i].Ref == "fs:events" {
					d.Targets[i].BaseURL = fx.URL
				}
			}
			for i := range d.Grants {
				if d.Grants[i].Principal == "agent:analytics" {
					d.Grants[i].Allow = append(d.Grants[i].Allow,
						config.CapabilitySpec{Action: "fullstory.session_events", TargetRef: "fs:events"})
				}
			}
			for i := range imps {
				imps[i].Target = "fs:events"
			}
			d.Refinements = append(d.Refinements, imps...)
			d.Shin = append(d.Shin, lenses...)
		},
		fullstoryClient: trustingSystemAnd(t, fx),
	})
}

func readEvents(t *testing.T, r *run, principal string, args map[string]any) *sekizuiv1.QueryResponse {
	t.Helper()
	return readEventsLensed(t, r, principal, args, "")
}

// readEventsLensed selects a requestable lens by name, as a caller may (D84).
func readEventsLensed(t *testing.T, r *run, principal string, args map[string]any, lens string) *sekizuiv1.QueryResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if args == nil {
		args = map[string]any{}
	}
	args["session_id"] = seirenSession
	resp, err := r.as(t, principal).Query(ctx, &sekizuiv1.QueryRequest{Action: "fullstory.session_events",
		TargetRef: "fs:events", Args: mustArgs(t, args), Lens: lens})
	if err != nil {
		t.Fatalf("%s's read was refused: %v", principal, err)
	}
	return resp
}

// jobsBuiltIns imposes the four built-ins for agent:jobs alone.
func jobsBuiltIns() []config.RefinementSpec {
	who := []string{"agent:jobs"}
	return []config.RefinementSpec{
		{Rule: "fullstory.frustration", For: who}, {Rule: "fullstory.path", For: who},
		{Rule: "fullstory.errors", For: who},
		{Rule: "fullstory.login", For: who, Params: map[string]any{"signin_prefix": "/login", "success_prefix": "/app"}},
	}
}

func valueJSON(t *testing.T, s *sekizuiv1.Seiren, key string) string {
	t.Helper()
	b, err := json.Marshal(s.GetValue().AsMap()[key])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// p4Step19 — the seiren reaches the audience it is imposed on and nobody else
// (D298): staging by audience IS the staging mechanism.
func p4Step19(t *testing.T) {
	r := seirenRun(t, fixturePages(), jobsBuiltIns())
	r.narrate(t, "the seiren reaches the audience it is imposed on and nobody else")
	if r.localOnly(t, "the imposition is this instance's configuration") {
		return
	}
	in, out := readEvents(t, r, "agent:jobs", nil), readEvents(t, r, "agent:analytics", nil)
	if in.GetSeiren() == nil || len(in.GetSeiren().GetRules()) != 4 {
		t.Fatalf("step 19: agent:jobs, the audience, received seiren %v; want the four imposed rules", in.GetSeiren())
	}
	if out.GetSeiren() != nil {
		t.Errorf("step 19: agent:analytics is outside the audience and received a seiren: %v", out.GetSeiren())
	}
	if len(in.GetRows()) != len(out.GetRows()) || len(in.GetRows()) != 9 {
		t.Errorf("step 19: rows %d and %d; both principals read the same nine events", len(in.GetRows()), len(out.GetRows()))
	}
	r.detail(t, "same call, same target: agent:jobs (imposed) received a seiren from %v; agent:analytics "+
		"(not imposed) received the same %d rows and no seiren", in.GetSeiren().GetRules(), len(out.GetRows()))
}

// p4Step20 — silver and seiren arrive in one response (D297, D300, D317).
func p4Step20(t *testing.T) {
	// 20d — BESIDE A ROW AND BESIDE A WRITE'S RESULT, ON THE DEMO DEPLOYMENT
	// (CONTRACTS 145, 147): kata's rules imposed on agent:showcase by demo.d.
	// Against a running instance that is ALL this step can show — the
	// Fullstory arms need a fixture only this process can serve.
	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		r := newRun(t)
		r.narrate(t, "silver and seiren arrive in one response, on the running instance")
		p4Step20Kata(t, r)
		return
	}
	p4Step20Kata(t, demoSeirenRun(t))

	r := seirenRun(t, fixturePages(), jobsBuiltIns())
	r.narrate(t, "silver and seiren arrive in one response")
	plain := seirenRun(t, fixturePages(), nil)
	with, without := readEvents(t, r, "agent:jobs", nil), readEvents(t, plain, "agent:jobs", nil)

	// 20a — THE ROWS ARE SILVER, UNCHANGED BY THE IMPOSITION.
	rowsJSON := func(q *sekizuiv1.QueryResponse) string {
		var rows []any
		for _, row := range q.GetRows() {
			rows = append(rows, row.AsMap())
		}
		b, _ := json.Marshal(rows)
		return string(b)
	}
	if rowsJSON(with) != rowsJSON(without) {
		t.Errorf("step 20a: imposing refinements changed the rows; the seiren travels BESIDE silver, never instead")
	}
	// 20b — ONE TYPED SEIREN beside them, of the connector's seiren type, with
	// what each rule made of the result.
	s := with.GetSeiren()
	if s.GetType() != "fullstory.session_context.v1" {
		t.Fatalf("step 20b: seiren type %q", s.GetType())
	}
	for key, want := range map[string]string{
		"login":       `"landed":{"duration_s":6`,
		"errors":      `"cause":{"duration_s":0.157,"event_time":"2026-09-24T19:28:59.934Z","event_type":"dead-click"}`,
		"path":        `"page_url":"/sso/redirect"`,
		"frustration": `{"count":1,"event_type":"rage-click","page":{"page_url":"/app/settings"}}`,
	} {
		if got := valueJSON(t, s, key); !strings.Contains(got, want) {
			t.Errorf("step 20b: %s = %s; want it to contain %s", key, got, want)
		}
	}
	// 20c — IMPOSED: the request carried nothing asking for it.
	if without.GetSeiren() != nil {
		t.Error("step 20c: a deployment imposing nothing produced a seiren")
	}
	r.detail(t, "nine silver rows, byte-identical with and without the imposition, and beside them one "+
		"%s seiren: login landed 6s after the sign-in page through a redirect; the network error's cause "+
		"is the dead-click 157ms before it", s.GetType())
}

// p4Step21 — the seiren is computed over the whole result before paging, and
// states its window (D300).
func p4Step21(t *testing.T) {
	r := seirenRun(t, fixturePages(), jobsBuiltIns())
	r.narrate(t, "the seiren is computed over the whole result before paging, and states its window")
	if r.localOnly(t, "the imposition is this instance's configuration") {
		return
	}
	// 21a — THE WINDOW: first and last event time, and not truncated — nine
	// events against the default limit is the whole session.
	s := readEvents(t, r, "agent:jobs", nil).GetSeiren()
	w := s.GetWindow()
	if w.GetFirstEventTime() != "2026-09-24T19:28:49.934Z" || w.GetLastEventTime() != "2026-09-24T19:29:20.934Z" ||
		w.GetTruncated() {
		t.Errorf("step 21a: window %v", w)
	}
	// 21b — A FULL LAST SLICE IS TRUNCATED: asked for 9, given 9, earlier
	// events may exist — and the window says so, and so does the response.
	full := readEvents(t, r, "agent:jobs", map[string]any{"event_limit": float64(9)})
	if !full.GetSeiren().GetWindow().GetTruncated() || !full.GetTruncated() {
		t.Errorf("step 21b: a read that filled its limit reported truncated=%v (window %v); Generate Context "+
			"returned the session's LAST events, which may not be the session",
			full.GetTruncated(), full.GetSeiren().GetWindow())
	}
	// 21c — BEFORE THE RESPONSE BUDGET: the login pairs a navigate on the
	// first page with one on the third — rows the response could have cut
	// apart — because the seiren is computed before any row is dropped.
	if got := valueJSON(t, s, "login"); !strings.Contains(got, `"event_time":"2026-09-24T19:28:49.934Z"`) ||
		!strings.Contains(got, `"landed":{"duration_s":6,"event_time":"2026-09-24T19:28:55.934Z"}`) {
		t.Errorf("step 21c: login = %s", got)
	}
	r.detail(t, "window %s → %s, truncated only when the slice filled its limit; the login paired "+
		"across three pages of the vendor's grouping", w.GetFirstEventTime(), w.GetLastEventTime())
}

// p4Step24 — the seiren is built only from lensed rows, and a withheld value
// appears nowhere (D269's disclosure path, aimed at the seiren).
func p4Step24(t *testing.T) {
	// A lens agent:jobs SELECTS, withholding page_url: its value must be absent
	// from the response's BYTES — rows, seiren, and every unavailable reason.
	// Selected rather than imposed, because an imposed lens blocking a rule
	// for its whole audience is refused at boot (step 22b).
	r := seirenRun(t, fixturePages(), jobsBuiltIns(), noURLsLens())
	r.narrate(t, "the seiren is built only from lensed rows, and a withheld value appears nowhere")
	if r.localOnly(t, "the lens and the imposition are this instance's configuration") {
		return
	}
	resp := readEventsLensed(t, r, "agent:jobs", nil, "no-urls")
	raw, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"/login", "/sso/redirect", "/app/home", "/app/settings"} {
		if strings.Contains(string(raw), v) {
			t.Errorf("step 24: the withheld page_url %q appears in the response's bytes", v)
		}
	}
	// And the rules that read it did not run; errors, which never reads it, did.
	s := resp.GetSeiren()
	unavailable := gapKeys(s, sekizuiv1.SeirenGapKind_SEIREN_GAP_KIND_UNAVAILABLE)
	if strings.Join(unavailable, ",") != "frustration,login,path" || valueJSON(t, s, "errors") == "null" {
		t.Errorf("step 24: unavailable %v, errors %s; want the three page_url rules unavailable and errors run",
			unavailable, valueJSON(t, s, "errors"))
	}
	r.detail(t, "with page_url withheld, no page value is anywhere in %d response bytes; %v declared "+
		"unavailable, errors still built", len(raw), unavailable)
}

// noURLsLens is a lens agent:jobs may SELECT that withholds page_url.
func noURLsLens() config.ShinSpec {
	return config.ShinSpec{Name: "no-urls", Enabled: true, Mode: "requestable", AppliesTo: []string{"agent:jobs"},
		Type: sessionEventType, Withholds: []string{"page_url"},
		Because: "P4 steps 22 and 24: a caller that may not see which pages a user visited"}
}

// p4Step22 — a rule runs when its own inputs survived the lens, and the seiren
// says what did not (D300).
func p4Step22(t *testing.T) {
	r := seirenRun(t, fixturePages(), jobsBuiltIns(), noURLsLens())
	r.narrate(t, "a rule runs when its own inputs survived the lens, and the seiren says what did not")
	if r.localOnly(t, "the lens and the imposition are this instance's configuration") {
		return
	}

	// 22a — AT RUN TIME, FOR A LENS THE CALLER CHOSE: the unit is the RULE.
	s := readEventsLensed(t, r, "agent:jobs", nil, "no-urls").GetSeiren()
	reasons := map[string]string{}
	for _, g := range s.GetGaps() {
		if g.GetKind() == sekizuiv1.SeirenGapKind_SEIREN_GAP_KIND_UNAVAILABLE {
			reasons[g.GetKey()] = g.GetReason()
		}
	}
	for _, key := range []string{"path", "frustration", "login"} {
		if !strings.Contains(reasons[key], "page_url") || !strings.Contains(reasons[key], "no-urls") {
			t.Errorf("step 22a: %s unavailable as %q; want the path and the lens named", key, reasons[key])
		}
	}
	if _, listed := reasons["errors"]; listed || !strings.Contains(valueJSON(t, s, "errors"), "dead-click") {
		t.Errorf("step 22a: errors never reads page_url and must run; unavailable %v", reasons)
	}
	// Without the lens, the same caller gets every rule.
	if all := readEvents(t, r, "agent:jobs", nil).GetSeiren(); len(all.GetGaps()) != 0 || len(all.GetRules()) != 4 {
		t.Errorf("step 22a: without the selected lens, gaps %v", all.GetGaps())
	}

	// 22b — AT BOOT, FOR AN IMPOSED LENS: a rule its whole audience could never
	// receive refuses the deployment; one some of its audience can receive boots.
	imposedOn := func(appliesTo []string, audience []string) string {
		doc := &config.Document{
			Targets: []config.TargetSpec{{Ref: refineTarget, Kind: fullstory.Kind, Tenant: "acme", Residency: "eu",
				BaseURL: "https://api.fullstory.com", CredentialRef: "env://SEKIZUI_ACCEPT_TOK"}},
			Refinements: []config.RefinementSpec{impose("fullstory.path", audience, nil)},
			Shin: []config.ShinSpec{{Name: "imposed-no-urls", Enabled: true, AppliesTo: appliesTo,
				Type: sessionEventType, Withholds: []string{"page_url"}, Because: "step 22b"}},
		}
		drivers := map[string]connector.Driver{fullstory.Kind: fullstory.New()}
		reg, err := schemareg.ForDeployment(doc, drivers)
		if err != nil {
			t.Fatal(err)
		}
		_, problems, _ := schemareg.Refinements(reg, doc, drivers)
		return strings.Join(problems, "\n")
	}
	if p := imposedOn([]string{"agent:*"}, []string{"agent:a"}); !strings.Contains(p, "can never build") {
		t.Errorf("step 22b: an imposed lens withholding page_url from the whole audience of fullstory.path "+
			"did not refuse the boot: %q", p)
	}
	if p := imposedOn([]string{"agent:a"}, []string{"agent:*"}); p != "" {
		t.Errorf("step 22b: the lens covers only part of the audience, so the rule can build for the rest; "+
			"refused: %q", p)
	}
	// 22c — A KEY WRITTEN IN PART SAYS SO (CONTRACTS 146): sixty errors against
	// fullstory.errors' limit of fifty keep the key, cut to fifty, and a
	// TRUNCATED gap says how many there were — a partial answer never reads as
	// the whole one.
	var many []map[string]any
	for i := 0; i < 60; i++ {
		many = append(many, sessionRow(i*1000, "exception", ""))
	}
	cut, err := refine.Refine(refine.For(builtIns(t), refineTarget, "agent:a", sessionEventType), many, false, nil)
	if err != nil {
		t.Fatalf("step 22c: %v", err)
	}
	var truncated []string
	for _, g := range cut.Gaps {
		if g.Kind == refine.GapTruncated {
			truncated = append(truncated, g.Key+": "+g.Reason)
		}
	}
	if strings.Join(truncated, ";") != "errors: kept the first 50 of 60 items (limit 50)" ||
		len(cut.Value["errors"].([]any)) != 50 {
		t.Errorf("step 22c: truncated gaps %v; want errors kept 50 of 60, the key present", truncated)
	}

	r.detail(t, "with page_url withheld by a selected lens, path, frustration and login are declared "+
		"unavailable naming the lens and errors still builds; an imposed lens blocking a rule's whole "+
		"audience refuses the boot, one blocking part of it does not; 60 errors under a limit of 50 keep "+
		"the key and declare it TRUNCATED")
}

// gapKeys are the keys a seiren declares gaps for, of one kind, in order.
func gapKeys(s *sekizuiv1.Seiren, kind sekizuiv1.SeirenGapKind) []string {
	var out []string
	for _, g := range s.GetGaps() {
		if g.GetKind() == kind {
			out = append(out, g.GetKey())
		}
	}
	return out
}

// demoSeirenRun is an in-process run carrying demo.d's showcase grants and
// refinements — READ FROM demo.d, so the in-process arm and `make demo` prove
// the same configuration and there is no copy of it here to drift.
func demoSeirenRun(t *testing.T) *run {
	t.Helper()
	demo, err := config.NewFileSource("demo.d").Load(context.Background())
	if err != nil {
		t.Fatalf("step 20d: the demo deployment does not load: %v", err)
	}
	return newRunWith(t, runOpts{patch: func(d *config.Document) {
		for _, g := range demo.Grants {
			if g.Principal == "agent:showcase" {
				d.Grants = append(d.Grants, g)
			}
		}
		d.Refinements = append(d.Refinements, demo.Refinements...)
	}})
}

// p4Step20Kata reads a kata row and makes a kata write as agent:showcase, and
// requires a kata.receipt.v1 seiren beside each — a CommandResult's included.
func p4Step20Kata(t *testing.T, r *run) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := r.as(t, "agent:showcase")

	read, err := c.Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
	if err != nil {
		t.Fatalf("step 20d: the showcase read was refused: %v", err)
	}
	wrote, err := c.Execute(ctx, &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
		Action: "kata.create_issue", TargetRef: "kata:alpha",
		Args:           mustArgs(t, map[string]any{"project": "PROJ", "title": "seiren"}),
		IdempotencyKey: "p4-20d-" + strconv.FormatInt(time.Now().UnixNano(), 36),
	}})
	if err != nil {
		t.Fatalf("step 20d: the showcase write failed: %v", err)
	}
	result := wrote.GetResult()
	if result.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 20d: the showcase write came back %s: %s", result.GetStatus(), result.GetReason())
	}
	for _, c := range []struct {
		arm    string
		seiren *sekizuiv1.Seiren
		key    string
		field  string
		want   string
	}{
		{"beside the read's rows", read.GetSeiren(), "read", "id", read.GetRows()[0].AsMap()["id"].(string)},
		{"beside the write's result", result.GetSeiren(), "write", "action", "kata.create_issue"},
	} {
		items, _ := c.seiren.GetValue().AsMap()[c.key].([]any)
		if c.seiren.GetType() != "kata.receipt.v1" || len(items) != 1 {
			t.Fatalf("step 20d: no kata.receipt.v1 seiren %s: %v", c.arm, c.seiren)
		}
		item, _ := items[0].(map[string]any)
		if item[c.field] != c.want || item["at"] == nil {
			t.Errorf("step 20d: the seiren %s holds %v; want %s=%s and the time kata recorded", c.arm, item, c.field, c.want)
		}
	}
	if result.GetResult() == nil || len(read.GetRows()) != 1 {
		t.Error("step 20d: the seiren replaced silver; it travels beside it")
	}
	r.detail(t, "agent:showcase, from demo.d's impositions: a kata.receipt.v1 seiren beside the read's row "+
		"and beside the write's CommandResult, silver intact under both")
}

// p4Step18 — the four built-ins over one REAL web session (D297, D298, D301,
// D317). The fixture is shaped rows captured through the real binary
// (`make capture-seiren`); the assertions are what the rules made of it, read
// before they were written down — so they describe the test org's session, not the
// rules' author's expectations.
func p4Step18(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the four built-ins turn a real Generate Context result into seiren")
	raw, err := os.ReadFile(captureFile(t))
	if err != nil {
		t.Fatalf("step 18: the captured fixture: %v — `make run-capture` then `make capture-seiren`", err)
	}
	var fx sessionCapture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("step 18: the captured fixture does not parse: %v", err)
	}
	signIn, landed := stripQuery(fx.SignIn), stripQuery(fx.Landed)
	refineWith := func(within any) *refine.Seiren {
		t.Helper()
		params := map[string]any{"signin_prefix": signIn, "success_prefix": landed}
		if within != nil {
			params["within_s"] = within
		}
		who := []string{"agent:a"}
		rs, problems := compileRefinements(t, fullstory.New(),
			impose("fullstory.frustration", who, nil), impose("fullstory.path", who, nil),
			impose("fullstory.errors", who, nil), impose("fullstory.login", who, params))
		if problems != "" {
			t.Fatalf("step 18: the built-ins do not compile: %s", problems)
		}
		s, err := refine.Refine(refine.For(rs, refineTarget, "agent:a", sessionEventType), fx.Rows, fx.Truncated, nil)
		if err != nil {
			t.Fatalf("step 18: refining the real session: %v", err)
		}
		return s
	}
	value := func(s *refine.Seiren, key string) string {
		b, _ := json.Marshal(s.Value[key])
		return string(b)
	}
	s := refineWith(nil)

	// 18a — LOGIN, on the real checkout: the sign-in step, then billing, 24.386s
	// later — and under D301's old 15-second window, no login at all.
	if signIn != "https://www.cargorentalsfs.com/checkout#login" || landed != "https://www.cargorentalsfs.com/checkout#billing" {
		t.Errorf("step 18a: the fixture's login pages are %q -> %q", signIn, landed)
	}
	if got := value(s, "login"); !strings.Contains(got, `"landed":{"duration_s":24.386,`) {
		t.Errorf("step 18a: login = %s; want the landing 24.386s after the sign-in page", got)
	}
	if _, wrote := refineWith(float64(15)).Value["login"]; wrote {
		t.Error("step 18a: under a 15s window the 24.386s login still paired — the arm proves nothing")
	}

	// 18b — ERRORS: the error-click is an error AND the cause of the two after it.
	errs := value(s, "errors")
	for _, want := range []string{
		`{"event_time":"2026-09-26T14:58:27.679Z","event_type":"error-click"}`,
		`{"cause":{"duration_s":0.153,"event_time":"2026-09-26T14:58:27.679Z","event_type":"error-click"},"event_time":"2026-09-26T14:58:27.832Z","event_type":"console-error"}`,
		`{"cause":{"duration_s":0.198,"event_time":"2026-09-26T14:58:27.679Z","event_type":"error-click"},"event_time":"2026-09-26T14:58:27.877Z","event_type":"network-error"}`,
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("step 18b: errors lacks %s\n  errors = %s", want, errs)
		}
	}

	// 18c — FRUSTRATION: the rage-click storm first, on the page it happened on.
	frus := value(s, "frustration")
	if !strings.HasPrefix(frus, `[{"count":19,"event_type":"rage-click","page":{"page_url":"https://www.cargorentalsfs.com/search?`) {
		t.Errorf("step 18c: frustration = %s; want 19 rage-clicks on the search page, most frequent first", frus)
	}

	// 18d — PATH: every page with its dwell, the last with none.
	var path []map[string]any
	_ = json.Unmarshal([]byte(value(s, "path")), &path)
	if len(path) != 9 {
		t.Fatalf("step 18d: path lists %d pages; the session navigated 9 times", len(path))
	}
	if next, _ := path[0]["next"].(map[string]any); next["duration_s"] != 68.067 {
		t.Errorf("step 18d: the home page's dwell is %v, want 68.067", path[0]["next"])
	}
	if _, has := path[len(path)-1]["next"]; has {
		t.Error("step 18d: the last page carries a dwell; nothing followed it")
	}

	// 18e — THE WHOLE SESSION, nothing missing.
	if s.Window.Truncated || len(s.Gaps) != 0 || len(s.Rules) != 4 {
		t.Errorf("step 18e: window %+v, gaps %v, rules %v; want the whole session and all four rules", s.Window, s.Gaps, s.Rules)
	}
	r.detail(t, "session %s (%d shaped rows, captured through the real binary): login landed 24.386s after "+
		"/checkout#login and would not under 15s; the error-click caused a console error (+153ms) and a network "+
		"error (+198ms); 19 rage-clicks on one search page; 9 pages with dwell", fx.Session, len(fx.Rows))
}

// p4Step25 — Describe reports every refinement imposed on the principal asking
// (D298, D302), and what it reports is what ARRIVES: the advertised rules equal
// the rules a real query's seiren carries, for the principal inside the
// audience and the one outside it.
func p4Step25(t *testing.T) {
	r := seirenRun(t, fixturePages(), jobsBuiltIns())
	r.narrate(t, "Describe reports every refinement imposed on the principal asking")
	if r.localOnly(t, "the imposition is this instance's configuration") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	advertised := func(principal string) (rules []string, entries []*sekizuiv1.ImposedRefinement) {
		t.Helper()
		d, err := r.as(t, principal).Describe(ctx, &sekizuiv1.DescribeRequest{})
		if err != nil {
			t.Fatalf("step 25: %s's Describe was refused: %v", principal, err)
		}
		for _, ir := range d.GetImposedRefinements() {
			rules = append(rules, ir.GetRule())
		}
		sort.Strings(rules)
		return rules, d.GetImposedRefinements()
	}

	// 25a — INSIDE THE AUDIENCE: every imposed rule, fully described, and
	// exactly the rules its seiren carries.
	rules, entries := advertised("agent:jobs")
	arrived := readEvents(t, r, "agent:jobs", nil).GetSeiren().GetRules()
	if strings.Join(rules, ",") != strings.Join(arrived, ",") || len(rules) != 4 {
		t.Errorf("step 25a: Describe advertises %v and the seiren carries %v; they must be the same four", rules, arrived)
	}
	for _, ir := range entries {
		if ir.GetTargetRef() != "fs:events" || ir.GetSeirenType() != "fullstory.session_context.v1" ||
			ir.GetSchemaUri() != "sekizui://schema/fullstory.session_context.v1" || ir.GetKey() == "" || ir.GetLookups() {
			t.Errorf("step 25a: %s is described as %v; want its target, seiren type, schema URI, key, and no lookups", ir.GetRule(), ir)
		}
	}

	// 25b — OUTSIDE IT: nothing advertised, and nothing arrives.
	if none, _ := advertised("agent:analytics"); len(none) != 0 {
		t.Errorf("step 25b: agent:analytics is outside every audience and Describe advertises %v", none)
	}
	if s := readEvents(t, r, "agent:analytics", nil).GetSeiren(); s != nil {
		t.Errorf("step 25b: agent:analytics received a seiren Describe never mentioned: %v", s.GetRules())
	}
	r.detail(t, "agent:jobs: Describe advertises %v, and its seiren carries exactly those; agent:analytics: "+
		"nothing advertised, nothing arrives", rules)
}
