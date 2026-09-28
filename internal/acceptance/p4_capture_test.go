package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// THE STEP-18 CAPTURE (D317): one real web session from the maintainers' test org, fetched
// THROUGH THE REAL BINARY — governed, recorded, shaped to the connector's
// closed schema — and committed as P4 step 18's replay fixture.
//
// **ONE WEB SESSION, AND THE RULES ARE AN EXAMPLE (the maintainer, D317).** Fullstory's
// four rules are the worked example of the Refiner contract, not a product, and
// mobile is skipped: the fixture is a Desktop session holding an error-click
// AND a login — a sign-in page, then a landing within the login template's
// window. the test org's checkout has both (`/checkout#login` → `#billing`).
//
// **SHAPED ROWS, NOT THE VENDOR'S RESPONSE.** What the engine refines is the
// shaped, lensed row, so that is what the fixture holds; shaping strips free
// text (click text, descriptions, emails) at the schema (D279).
//
// **REQUESTED, NEVER AMBIENT.** `make capture-seiren` sets SEKIZUI_CAPTURE_STEP18;
// no other run rewrites the committed fixture. The capture deployment's grant is
// two reads and `build_metric` (capture.local.d).

// step18Queries are the metrics discovery BUILDS through the MCP. The MCP's
// session finders take only ids its own `build_*` tools mint: it refused the
// Server API's segment id and a UI-saved metric's id. `build_metric` allocates
// an UNNAMED metric — mutating in the vetted spec (D307), and, the maintainer: not a
// saved metric until somebody saves it in the UI. The same words build
// different metrics run to run, so there are two.
var step18Queries = []string{ //nolint:gochecknoglobals // immutable, read once
	"unique users who clicked on text login",
	"unique users who error clicked anything on a desktop browser",
}

const captureWanted = "SEKIZUI_CAPTURE_STEP18"

// captureSessionEnv names the session explicitly, skipping discovery: a
// session URL or `device:session` id.
const captureSessionEnv = "SEKIZUI_STEP18_SESSION"

// sessionCapture is the committed fixture.
type sessionCapture struct {
	Session   string `json:"session"`
	Query     string `json:"query,omitempty"` // the metric discovery built, when it did
	Captured  string `json:"captured"`
	Truncated bool   `json:"truncated"`
	// SignIn and Landed are the pages the login was found on — what step 18
	// sets the login template's two prefixes to.
	SignIn string           `json:"sign_in"`
	Landed string           `json:"landed"`
	Rows   []map[string]any `json:"rows"`
}

func captureFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(mustRoot(t), "internal", "connectors", "fullstory", "testdata", "seiren", "web.json")
}

// sessionIDOf pulls `device:session` out of a Fullstory session URL, or
// accepts one bare. FROM THE URL, NOT `device_id`: the MCP's schema types the
// device id as an INTEGER, and the test org's exceed 2^53 (CONTRACTS 150).
var sessionIDIn = regexp.MustCompile(`(\d+)(?::|%3A)(\d+)`)

func sessionIDOf(s string) (string, bool) {
	m := sessionIDIn.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1] + ":" + m[2], true
}

// candidate is one session get_sessions offered, with its rows once read.
type candidate struct {
	Session string
	Device  string
	OS      string
	Rows    []map[string]any
}

func isDesktop(device string) bool { return strings.EqualFold(device, "Desktop") }

// fits reports whether c is the fixture step 18 needs: a Desktop session with
// an error-click AND a login, and the login's two pages. PURE, so the choice
// is testable offline; the live half only feeds it.
func fits(c candidate) (signIn, landed string, ok bool) {
	if !isDesktop(c.Device) {
		return "", "", false
	}
	errorClick := false
	for _, r := range c.Rows {
		errorClick = errorClick || r["event_type"] == "error-click"
	}
	if !errorClick {
		return "", "", false
	}
	return loginSucceeded(c.Rows)
}

// isSignInPage recognises a sign-in page in the spellings sites use: login,
// log-in, signin, sign-in, sign_in — in the path or, on the test org's checkout, the
// fragment (`/checkout#login`).
func isSignInPage(page string) bool {
	p := strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(page))
	return strings.Contains(p, "login") || strings.Contains(p, "signin")
}

// loginWindow mirrors the login template's default (60s, D317 revising D301):
// the window runs from ARRIVING on the sign-in page, so it holds the person
// typing as well as the redirects.
const loginWindow = 60 * time.Second

// loginSucceeded finds a navigate to a sign-in page followed, within
// loginWindow, by a navigate to a page that is not one.
func loginSucceeded(rows []map[string]any) (signIn, landed string, ok bool) {
	type nav struct {
		at   time.Time
		page string
	}
	var navs []nav
	for _, r := range rows {
		if r["event_type"] != "navigate" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, fmt.Sprint(r["event_time"]))
		if err != nil {
			continue
		}
		navs = append(navs, nav{at, fmt.Sprint(r["page_url"])})
	}
	sort.Slice(navs, func(i, j int) bool { return navs[i].at.Before(navs[j].at) })
	for i, n := range navs {
		if !isSignInPage(n.page) {
			continue
		}
		for _, m := range navs[i+1:] {
			if m.at.Sub(n.at) > loginWindow {
				break
			}
			if !isSignInPage(m.page) {
				return n.page, m.page, true
			}
		}
	}
	return "", "", false
}

// summary names what a candidate held by COUNT, never by value.
func summary(c candidate) string {
	kinds := map[string]int{}
	for _, r := range c.Rows {
		k, _ := r["event_type"].(string)
		kinds[k]++
	}
	_, _, login := loginSucceeded(c.Rows)
	return fmt.Sprintf("%s/%s: %d rows, error-click %d, navigate %d, login %v",
		c.Device, c.OS, len(c.Rows), kinds["error-click"], kinds["navigate"], login)
}

// TestCaptureSelectionIsOneDesktopSessionWithBoth holds the selection offline.
func TestCaptureSelectionIsOneDesktopSessionWithBoth(t *testing.T) {
	row := func(offsetMS int, kind string) map[string]any { return sessionRow(offsetMS, kind, "") }
	nav := func(offsetMS int, page string) map[string]any { return sessionRow(offsetMS, "navigate", page) }
	login := []map[string]any{nav(0, "https://x.test/checkout#login?car-id=1"),
		nav(2000, "https://sso.test/sign-in/callback"), nav(26500, "https://x.test/checkout#billing?car-id=1")}
	withError := append(append([]map[string]any{}, login...), row(40000, "error-click"))
	for _, c := range []struct {
		name string
		cand candidate
		want bool
	}{
		{"desktop, error-click and login", candidate{Device: "Desktop", Rows: withError}, true},
		{"mobile is skipped", candidate{Device: "Mobile", OS: "iOS", Rows: withError}, false},
		{"no error-click", candidate{Device: "Desktop", Rows: login}, false},
		{"login too slow", candidate{Device: "Desktop", Rows: []map[string]any{nav(0, "https://x.test/login"),
			nav(70000, "https://x.test/account"), row(1000, "error-click")}}, false},
	} {
		signIn, landed, ok := fits(c.cand)
		if ok != c.want {
			t.Errorf("%s: fits = %v, want %v", c.name, ok, c.want)
		}
		if ok && (signIn != "https://x.test/checkout#login?car-id=1" || landed != "https://x.test/checkout#billing?car-id=1") {
			t.Errorf("%s: pages %q -> %q; the SSO redirect is a sign-in page, not the landing", c.name, signIn, landed)
		}
	}
	if id, ok := sessionIDOf("https://app.fullstory.com/ui/EXAMPLE/session/6606828898126528473%3A5450116830618425003"); !ok ||
		id != "6606828898126528473:5450116830618425003" {
		t.Errorf("session id from URL = %q", id)
	}
}

// TestCaptureStep18Fixture is the capture, against the REAL BINARY: the
// in-process harness resolves `env://` only (CONTRACTS 148), so `make
// run-capture` serves capture.local.d and this drives it over mTLS as
// `agent:triage` — the production path, end to end.
func TestCaptureStep18Fixture(t *testing.T) {
	if os.Getenv(captureWanted) == "" {
		t.Skipf("the step-18 capture was not requested; `make capture-seiren` asks for it (sets %s)", captureWanted)
	}
	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") == "" {
		t.Fatal("the capture drives a RUNNING binary: `make run-capture` in one terminal, then " +
			"`make capture-seiren` in another")
	}
	r := newRun(t) // remote: the running instance serving capture.local.d
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	triage := r.as(t, "agent:triage")

	read := func(session string) ([]map[string]any, bool) {
		t.Helper()
		for {
			resp, err := triage.Query(ctx, &sekizuiv1.QueryRequest{Action: "fullstory.session_events",
				TargetRef: "fs:capture", Args: mustArgs(t, map[string]any{"session_id": session,
					// THE MAXIMUM, so the window is cut as rarely as Generate
					// Context allows; the default is 50.
					"event_limit": float64(200)})})
			// SEKIZUI'S OWN LIMITER SAID WAIT, so the capture waits (P3 step
			// 29's shape): the refused read was never sent, and is recorded.
			if err == nil && resp.GetStatus() == sekizuiv1.Status_STATUS_RATE_LIMITED {
				t.Logf("  waiting for fs:capture's budget — refused before sending, recorded as %s", resp.GetDecisionId())
				select {
				case <-ctx.Done():
					t.Fatalf("reading %s: the deadline passed while waiting for fs:capture's budget", session)
				case <-time.After(6 * time.Second):
				}
				continue
			}
			if err != nil || resp.GetStatus() != sekizuiv1.Status_STATUS_OK {
				t.Fatalf("reading %s through Sekizui: %v %s", session, err, resp.GetReason())
			}
			rows := make([]map[string]any, 0, len(resp.GetRows()))
			for _, row := range resp.GetRows() {
				rows = append(rows, row.AsMap())
			}
			return rows, resp.GetTruncated()
		}
	}

	var chosen *candidate
	var query, signIn, landed string
	var notes []string
	try := func(found []candidate, q string) {
		for _, c := range found {
			if chosen != nil {
				return
			}
			if !isDesktop(c.Device) { // mobile is skipped (the maintainer, D317)
				continue
			}
			c.Rows, _ = read(c.Session)
			notes = append(notes, summary(c))
			t.Logf("read %s — %s", c.Session, summary(c))
			if s, l, ok := fits(c); ok {
				chosen, query, signIn, landed = &c, q, s, l
			}
		}
	}
	if named := os.Getenv(captureSessionEnv); named != "" {
		id, ok := sessionIDOf(named)
		if !ok {
			t.Fatalf("%s=%q names no session", captureSessionEnv, named)
		}
		try([]candidate{{Session: id, Device: "Desktop"}}, "")
	} else {
		seen := map[string]bool{}
		for _, q := range step18Queries {
			if chosen != nil {
				break
			}
			var fresh []candidate
			for _, c := range discoverByMetric(t, ctx, triage, q) {
				if !seen[c.Session] {
					seen[c.Session] = true
					fresh = append(fresh, c)
				}
			}
			t.Logf("discovery: %q offered %d new session(s)", q, len(fresh))
			try(fresh, q)
		}
	}
	if chosen == nil {
		t.Fatalf("no Desktop session with both an error-click and a login among %d read:\n  %s\nset %s to name one",
			len(notes), strings.Join(notes, "\n  "), captureSessionEnv)
	}

	rows, truncated := read(chosen.Session) // re-read so rows and truncation come from one response
	out := sessionCapture{Session: chosen.Session, Query: query, Captured: time.Now().UTC().Format(time.RFC3339),
		Truncated: truncated, SignIn: signIn, Landed: landed, Rows: rows}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(captureFile(t)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(captureFile(t), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("captured %s: %d shaped rows, truncated=%v, login %s -> %s", chosen.Session, len(rows), truncated,
		stripQuery(signIn), stripQuery(landed))
}

// discoverByMetric builds a metric from query through the governed MCP target,
// then lists its sessions — without `include_matching_sessions` if Fullstory
// refuses it ("retry with include_matching_sessions=false"). A failed build is
// logged, not fatal: Sekizui will not repeat a class-none write (D163).
func discoverByMetric(t *testing.T, ctx context.Context, c sekizuiv1.GatewayServiceClient, query string) []candidate {
	t.Helper()
	built, err := c.Execute(ctx, &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
		Action: "mcp.fullstory.build_metric", TargetRef: "fullstory-mcp",
		Args: mustArgs(t, map[string]any{"query": query, "output_type": "single_number"})}})
	if err != nil || built.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Logf("discovery: building the metric %q failed, moving on: %v %s", query, err, built.GetResult().GetReason())
		return nil
	}
	metricID, _ := built.GetResult().GetResult().AsMap()["metric_id"].(string)
	if metricID == "" {
		t.Logf("discovery: build_metric for %q returned no metric_id, moving on", query)
		return nil
	}
	for _, args := range []map[string]any{
		{"metric_id": metricID, "limit": float64(50), "include_matching_sessions": true},
		{"metric_id": metricID, "limit": float64(50)},
	} {
		got, err := c.Execute(ctx, &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
			Action: "mcp.fullstory.get_sessions", TargetRef: "fullstory-mcp", Args: mustArgs(t, args)}})
		if err != nil || got.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
			continue
		}
		var out []candidate
		sessions, _ := got.GetResult().GetResult().AsMap()["sessions"].([]any)
		for _, s := range sessions {
			m, _ := s.(map[string]any)
			if id, ok := sessionIDOf(fmt.Sprint(m["session_url"])); ok {
				out = append(out, candidate{Session: id, Device: fmt.Sprint(m["device"]), OS: fmt.Sprint(m["os"])})
			}
		}
		return out
	}
	t.Logf("discovery: listing the sessions of the metric built from %q was refused, moving on", query)
	return nil
}

// stripQuery drops everything from the first `?` — a URL's query, and on
// the test org's checkout the parameters that live INSIDE the fragment
// (`#login?car-id=…`), where url.Parse sees no query at all. What remains is
// the prefix an operator would write for the login template.
func stripQuery(page string) string {
	before, _, _ := strings.Cut(page, "?")
	return before
}
