package refine_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/refine"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// fullstoryRules compiles Fullstory's four shipped rules for agent:a through
// the boot's own compilation — the engine is tested on what boot would run.
func fullstoryRules(t *testing.T) []schemareg.Refinement {
	t.Helper()
	imp := func(rule string, params map[string]any) config.RefinementSpec {
		return config.RefinementSpec{Rule: rule, Target: "fs:t", For: []string{"agent:a"}, Params: params}
	}
	doc := &config.Document{
		Targets: []config.TargetSpec{{Ref: "fs:t", Kind: fullstory.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://api.fullstory.com", CredentialRef: "env://X"}},
		Refinements: []config.RefinementSpec{
			imp("fullstory.frustration", nil), imp("fullstory.path", nil), imp("fullstory.errors", nil),
			imp("fullstory.login", map[string]any{"signin_prefix": "/login", "success_prefix": "/app"}),
		},
	}
	drivers := map[string]connector.Driver{fullstory.Kind: fullstory.New()}
	reg, err := schemareg.ForDeployment(doc, drivers)
	if err != nil {
		t.Fatal(err)
	}
	rs, problems, _ := schemareg.Refinements(reg, doc, drivers)
	if len(problems) > 0 {
		t.Fatalf("the shipped rules do not compile: %v", problems)
	}
	return rs
}

var t0 = time.Date(2026, 9, 24, 19, 28, 49, 934_000_000, time.UTC)

func ev(offset time.Duration, kind string, page string) map[string]any {
	r := map[string]any{"event_time": t0.Add(offset).Format(time.RFC3339Nano), "event_type": kind}
	if page != "" {
		r["page_url"] = page
	}
	return r
}

// session: a login through an SSO redirect, the mobile-style failed request
// of D300's live read, and a rage-click on a later page.
func session() []map[string]any {
	ms := time.Millisecond
	return []map[string]any{
		ev(0, "navigate", "/login"),
		ev(2*time.Second, "click", ""),
		ev(3*time.Second, "navigate", "/sso/redirect"),
		ev(6*time.Second, "navigate", "/app/home"),
		ev(10*time.Second, "dead-click", ""),
		ev(10*time.Second+157*ms, "network-error", ""),
		ev(10*time.Second+159*ms, "console-error", ""),
		ev(30*time.Second, "navigate", "/app/settings"),
		ev(31*time.Second, "rage-click", ""),
	}
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTheFourBuiltInsOverASession(t *testing.T) {
	s, err := refine.Refine(refine.For(fullstoryRules(t), "fs:t", "agent:a", "fullstory.session_event.v1"),
		session(), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"login": `{"event_time":"2026-09-24T19:28:49.934Z","landed":{"duration_s":6,"event_time":"2026-09-24T19:28:55.934Z"}}`,
		"path": `[{"event_time":"2026-09-24T19:28:49.934Z","next":{"duration_s":3},"page_url":"/login"},` +
			`{"event_time":"2026-09-24T19:28:52.934Z","next":{"duration_s":3},"page_url":"/sso/redirect"},` +
			`{"event_time":"2026-09-24T19:28:55.934Z","next":{"duration_s":24},"page_url":"/app/home"},` +
			`{"event_time":"2026-09-24T19:29:19.934Z","page_url":"/app/settings"}]`,
		"errors": `[{"cause":{"duration_s":0.157,"event_time":"2026-09-24T19:28:59.934Z","event_type":"dead-click"},"event_time":"2026-09-24T19:29:00.091Z","event_type":"network-error"},` +
			`{"cause":{"duration_s":0.159,"event_time":"2026-09-24T19:28:59.934Z","event_type":"dead-click"},"event_time":"2026-09-24T19:29:00.093Z","event_type":"console-error"}]`,
		"frustration": `[{"count":1,"event_type":"console-error","page":{"page_url":"/app/home"}},` +
			`{"count":1,"event_type":"dead-click","page":{"page_url":"/app/home"}},` +
			`{"count":1,"event_type":"network-error","page":{"page_url":"/app/home"}},` +
			`{"count":1,"event_type":"rage-click","page":{"page_url":"/app/settings"}}]`,
	}
	for key, w := range want {
		if got := asJSON(t, s.Value[key]); got != w {
			t.Errorf("%s:\n got %s\nwant %s", key, got, w)
		}
	}
	if s.Type != "fullstory.session_context.v1" || len(s.Rules) != 4 || len(s.Gaps) != 0 {
		t.Errorf("type %q, rules %v, unavailable %v", s.Type, s.Rules, s.Gaps)
	}
	if s.Window != (refine.Window{FirstEventTime: "2026-09-24T19:28:49.934Z",
		LastEventTime: "2026-09-24T19:29:20.934Z", Truncated: true}) {
		t.Errorf("window %+v", s.Window)
	}
}

func TestAFirstThatFindsNothingWritesNoKey(t *testing.T) {
	rows := session()[4:] // no sign-in page
	s, err := refine.Refine(refine.For(fullstoryRules(t), "fs:t", "agent:a", "fullstory.session_event.v1"), rows, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, wrote := s.Value["login"]; wrote {
		t.Errorf("login written with no sign-in page: %v", s.Value["login"])
	}
}

func TestAWithheldPathMakesItsRuleUnavailableAndNoOther(t *testing.T) {
	withheld := func(p string) (string, bool) { return "no-urls", p == "page_url" }
	s, err := refine.Refine(refine.For(fullstoryRules(t), "fs:t", "agent:a", "fullstory.session_event.v1"),
		session(), false, withheld)
	if err != nil {
		t.Fatal(err)
	}
	if got := asJSON(t, s.Gaps); strings.Contains(got, `"Kind":2`) || !strings.Contains(got, `"Key":"frustration"`) ||
		!strings.Contains(got, `"Key":"login"`) || !strings.Contains(got, `"Key":"path"`) ||
		strings.Contains(got, `"Key":"errors"`) {
		t.Errorf("unavailable = %s; the three rules reading page_url, not errors", got)
	}
	if _, ok := s.Value["errors"]; !ok {
		t.Error("errors never reads page_url and must still run (D300: the unit is the rule)")
	}
}

func TestNobodyOutsideTheAudienceGetsARule(t *testing.T) {
	if rs := refine.For(fullstoryRules(t), "fs:t", "agent:b", "fullstory.session_event.v1"); len(rs) != 0 {
		t.Errorf("agent:b is outside the audience and got %d rules", len(rs))
	}
}

// TestTheEngineCannotAct holds the leaf property on the import graph: nothing
// the engine reaches can dispatch, publish, record or hold a credential.
func TestTheEngineCannotAct(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".").CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable here: %v", err)
	}
	const mod = "github.com/fullstorydev/sekizui/internal/"
	for _, forbidden := range []string{"gateway", "bus", "auditwal", "pool", "credential", "reflex",
		"connectors", "driver", "kyuushin"} {
		for _, dep := range strings.Fields(string(out)) {
			if dep == mod+forbidden || strings.HasPrefix(dep, mod+forbidden+"/") {
				t.Errorf("internal/refine reaches %s; the engine must be unable to act (D317)", dep)
			}
		}
	}
}

// TestALimitThatCutsSaysSo — CONTRACTS 146: a `list` or `count` holding fewer
// items than it matched keeps its key AND declares a TRUNCATED gap, so a
// partial answer never reads as the whole one.
func TestALimitThatCutsSaysSo(t *testing.T) {
	rule := func(name, key string, list *config.RefineList, count *config.RefineCount) schemareg.Refinement {
		return schemareg.Refinement{Target: "t", For: []string{"a"}, TimePath: "event_time", Rule: config.RefineRule{
			Name: name, Refines: "x.v1", Into: "y.v1", Key: key,
			Where: config.Predicate{{Path: "event_type", Op: config.OpExists}}, List: list, Count: count}}
	}
	rs := []schemareg.Refinement{
		rule("x.list", "list", &config.RefineList{Carry: []string{"event_type"}, Limit: 2}, nil),
		rule("x.count", "count", nil, &config.RefineCount{By: []string{"event_type"}, Limit: 1}),
		rule("x.room", "room", &config.RefineList{Carry: []string{"event_type"}, Limit: 50}, nil),
	}
	s, err := refine.Refine(rs, session(), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := asJSON(t, s.Gaps)
	for _, want := range []string{
		`{"Key":"count","Kind":2,"Reason":"kept the 1 most frequent of 6 groups (limit 1)"}`,
		`{"Key":"list","Kind":2,"Reason":"kept the first 2 of 9 items (limit 2)"}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("gaps %s; want %s", got, want)
		}
	}
	if strings.Contains(got, `"room"`) {
		t.Errorf("a list with room for every item declared a gap: %s", got)
	}
	if n := len(s.Value["list"].([]any)); n != 2 {
		t.Errorf("the truncated list holds %d items; the key stays, cut to its limit", n)
	}
}
