package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step18 — Fullstory session events are polled by timestamp window, and they
// are a differently-shaped producer (P3 criteria 3 and 6, D274, D276, D277,
// D279).
//
// **THE CONNECTOR OWNS WHAT MAY ENTER (D279), AND THE FIXTURE HOLDS WHAT A REAL
// SESSION HOLDS** — shapes read from the synthetic EXAMPLE session on 2026-09-23:
//
//   - `User Login`, a custom event this target does NOT list: never requested
//     (Generate Context's `include_types`), so its email never leaves the vendor.
//   - `sekizui_acceptance_step1`, a custom event the target lists: admitted
//     OPEN, properties and description as they came — the deployment's shin
//     protects consumers from there.
//   - a `click` carrying `email`: a declared standard kind, so only the
//     properties its schema names survive, and its description (which quotes
//     on-screen text) and page URL (which carries an account id) are dropped.
//   - a `navigate`: keeps its page URL, and only that.
//   - a `click` whose `fs-element` is a number: a declared kind that does not
//     conform — REFUSED, and counted in the poll's decision.
//
// And the request itself is checked: the fixture refuses one that does not
// exclude the user context, and records the types it was asked for.
func p3Step18(t *testing.T) {
	fx, seen := eventsFixtureServer(t)
	t.Setenv("SEKIZUI_FS_LIVE", "fixture-token")
	r := newRunWith(t, runOpts{
		patch: func(d *config.Document) {
			for i := range d.Targets {
				if d.Targets[i].Ref == "fs:events" {
					d.Targets[i].BaseURL = fx.URL
				}
			}
		},
		fullstoryClient: trustingSystemAnd(t, fx),
	})
	r.narrate(t, "Fullstory session events are polled by timestamp window, and they are a "+
		"differently-shaped producer")
	if r.localOnly(t, "the job runner is this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caller := r.as(t, "agent:jobs")

	first, decision := pollEventsJob(t, ctx, caller)

	// 18a — THE SHAPE: the one declared type, from the polled target, about its
	// session, ids exact.
	byKind := map[string]map[string]any{}
	for _, env := range first {
		data := env.GetData().AsMap()
		kind, _ := data["event_type"].(string)
		byKind[kind] = data
		switch {
		case env.GetType() != "fullstory.session_event.v1":
			t.Errorf("step 18a: type %q, want fullstory.session_event.v1", env.GetType())
		case env.GetSource() != "fs:events":
			t.Errorf("step 18a: source %q, want the polled target", env.GetSource())
		case env.GetSubject() != "6606828898126528473:5450116830618425003":
			t.Errorf("step 18a: subject %q, want the session in device:session form", env.GetSubject())
		case data["device_id"] != "6606828898126528473" || data["session_id"] != "5450116830618425003":
			t.Errorf("step 18a: ids %v / %v; above 2^53 they must stay exact strings",
				data["device_id"], data["session_id"])
		}
		if enc, _ := json.Marshal(data); strings.Contains(string(enc), "BenjaminClark") ||
			strings.Contains(string(enc), "a@example.test") || strings.Contains(string(enc), "1509793") &&
			kind != "navigate" {
			t.Errorf("step 18d: an envelope carries what its connector does not admit: %s", enc)
		}
	}
	if len(first) != 4 {
		t.Fatalf("step 18a: %d envelopes; the fixture serves 5 requested events of which 1 is "+
			"nonconforming and refused", len(first))
	}

	// 18d — WHAT THE CONNECTOR ADMITS (D279).
	if _, fetched := byKind["User Login"]; fetched {
		t.Error("step 18d: User Login was published; the target does not list it, so it is never requested")
	}
	if click := byKind["click"]; click != nil {
		props, _ := click["event_properties"].(map[string]any)
		if props["email"] != nil || props["fs-element"] != "input" {
			t.Errorf("step 18d: click properties %v; want fs-element kept and email stripped", props)
		}
		if click["description"] != nil || click["page_url"] != nil {
			t.Errorf("step 18d: click kept free text: %v", click)
		}
	} else {
		t.Error("step 18d: the conforming click was not published")
	}
	if nav := byKind["navigate"]; nav == nil || nav["page_url"] != "https://example.test/account/1509793" ||
		nav["description"] != nil {
		t.Errorf("step 18d: navigate %v; it keeps its page URL and nothing else free", nav)
	}
	if step1 := byKind["sekizui_acceptance_step1"]; step1 != nil {
		props, _ := step1["event_properties"].(map[string]any)
		if props["run"] != "20260923T092144Z" || props["extra"] != "kept" || step1["description"] == nil {
			t.Errorf("step 18d: the listed custom event was not admitted open: %v", step1)
		}
	} else {
		t.Error("step 18d: the listed custom event step1 was not published")
	}
	req := seen.asked()
	if !slices.Contains(req, "sekizui_acceptance_step1") || !slices.Contains(req, "click") ||
		slices.Contains(req, "User Login") {
		t.Errorf("step 18d: include_types %v; want the declared kinds and the listed custom events, "+
			"and not User Login", req)
	}

	// 18b — THE REFUSAL IS IN THE LOG. The intent put every fetched event at
	// risk; the outcome says how many were published.
	atRisk, published := pollCounts(t, r, decision)
	if atRisk != 5 || published != 4 {
		t.Errorf("step 18b: the poll's decision says %d at risk and %d published; want 5 and 4", atRisk, published)
	}

	// 18e — THE GAP IS THE CONNECTOR OWNER'S, NOT A CONTRACT BREACH (D277,
	// D279): the stripped email is on the undeclared condition, named not
	// valued; the connector-fault tally holds only the nonconforming payload.
	gap := r.runner.Undeclared()["fs:events"]
	if !strings.Contains(gap, "click:event_properties.email stripped") || strings.Contains(gap, "a@example.test") {
		t.Errorf("step 18e: the undeclared condition is %q", gap)
	}
	if bad := r.runner.Nonconforming()["fs:events"]; !strings.Contains(bad, "nonconforming_payload") {
		t.Errorf("step 18e: the connector-fault tally is %q; want the nonconforming payload", bad)
	}

	// 18f — A READ IS INGEST TOO (D279). The same events through Query come
	// back shaped by the same connector schema before any lens: the click's
	// email and free text gone, the unlisted custom event never requested.
	qr, err := caller.Query(ctx, &sekizuiv1.QueryRequest{Action: "fullstory.session_events",
		TargetRef: "fs:events", Args: mustArgs(t, map[string]any{
			"session_id": "6606828898126528473:5450116830618425003"})})
	if err != nil {
		t.Fatalf("step 18f: the read was refused: %v", err)
	}
	var sawClick bool
	for _, row := range qr.GetRows() {
		m := row.AsMap()
		if enc, _ := json.Marshal(m); strings.Contains(string(enc), "a@example.test") ||
			strings.Contains(string(enc), "BenjaminClark") {
			t.Errorf("step 18f: a query row carries what the connector does not admit: %s", enc)
		}
		if m["event_type"] == "click" {
			if props, _ := m["event_properties"].(map[string]any); props["fs-element"] == "input" {
				sawClick = true
			}
		}
	}
	if !sawClick {
		t.Error("step 18f: the read returned no shaped click; the rows were not the fixture's")
	}

	// 18c — A RE-READ YIELDS THE SAME EVENTS: `requery` (D275) is sound only
	// if the same window yields the same events in the same order.
	second, _ := pollEventsJob(t, ctx, caller)
	if len(second) != len(first) {
		t.Fatalf("step 18c: the re-read yielded %d events, the first read %d", len(second), len(first))
	}
	for i := range first {
		a, b := first[i].GetData().AsMap(), second[i].GetData().AsMap()
		if a["event_time"] != b["event_time"] || a["event_type"] != b["event_type"] {
			t.Errorf("step 18c: event %d differs between reads: %v@%v / %v@%v", i,
				a["event_type"], a["event_time"], b["event_type"], b["event_time"])
		}
	}
	r.detail(t, "%d events from session 6606828898126528473:5450116830618425003; include_types "+
		"asked for the declared kinds and the two listed custom events and not User Login, with the "+
		"user context excluded; a click's email stripped with its free text, navigate kept its URL, "+
		"the listed custom event entered open, a nonconforming click refused and counted (%d at "+
		"risk, %d published); a second job re-read the same events", len(first), atRisk, published)
}

// pollEventsJob runs one `fullstory.poll` job on fs:events and returns what it
// delivered and the poll's decision id.
func pollEventsJob(t *testing.T, ctx context.Context, caller sekizuiv1.GatewayServiceClient) (
	[]*sekizuiv1.Envelope, string) {
	t.Helper()
	started, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "fullstory.poll", TargetRef: "fs:events"},
	})
	if err != nil || started.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 18: the poll job was refused: %v %s (%s)", err, started.GetReason(),
			started.GetRefusedBy())
	}
	stream, err := caller.JobResults(ctx, &sekizuiv1.JobResultsRequest{JobId: started.GetJobId()})
	if err != nil {
		t.Fatalf("step 18: JobResults: %v", err)
	}
	var got []*sekizuiv1.Envelope
	for {
		msg, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("step 18: receiving: %v", rerr)
		}
		got = append(got, msg.GetEnvelope())
	}
	st, err := caller.JobStatus(ctx, &sekizuiv1.JobStatusRequest{JobId: started.GetJobId()})
	if err != nil || st.GetState() != sekizuiv1.JobState_JOB_STATE_FINISHED {
		t.Fatalf("step 18: the job ended %s (%s), err %v", st.GetState(), st.GetReason(), err)
	}
	if len(got) == 0 {
		t.Fatal("step 18: the poll produced no events")
	}
	return got, got[0].GetCausation().GetDecisionId()
}

var atRiskReason = regexp.MustCompile(`^(\d+) event\(s\) about to be published`)

// pollCounts reads a poll decision's intent (how many were put at risk) and
// outcome (how many were published) from the log.
func pollCounts(t *testing.T, r *run, decision string) (atRisk, published int) {
	t.Helper()
	atRisk, published = -1, -1
	waitFor(t, func() bool {
		for _, d := range readLog(t, r.path) {
			if d.GetId() != decision {
				continue
			}
			switch d.GetPhase() {
			case sekizuiv1.Phase_PHASE_INTENT:
				if m := atRiskReason.FindStringSubmatch(d.GetReason()); m != nil {
					atRisk, _ = strconv.Atoi(m[1])
				}
			case sekizuiv1.Phase_PHASE_OUTCOME:
				if v, ok := d.GetEffect().GetDetail().GetFields()["events"]; ok {
					published = int(v.GetNumberValue())
				}
			}
		}
		return atRisk >= 0 && published >= 0
	}, "the poll's decision had no intent and outcome in the log")
	return atRisk, published
}

// eventsFixture is what the fixture's one session holds — including an event
// the target does not ask for. Mixed precisions and an offset, because the
// vendor's timestamps vary and the poll compares times.
var eventsFixture = []map[string]any{
	{"type": "navigate", "timestamp": "2026-09-23T09:00:00Z", "description": "HomePage", "properties": map[string]any{}},
	{"type": "click", "timestamp": "2026-09-23T09:00:04.5Z",
		"description": `element (Login: Email Field) with text "a@example.test"`,
		"properties":  map[string]any{"fs-element": "input", "email": "a@example.test"}},
	{"type": "User Login", "timestamp": "2026-09-23T09:00:04.6Z",
		"description": "email=benjamin.clark@example.com,displayName=Benjamin Clark,is_host=false,",
		"properties": map[string]any{"email": "benjamin.clark@example.com", "displayName": "Benjamin Clark",
			"is_host": false}},
	{"type": "sekizui_acceptance_step1", "timestamp": "2026-09-23T11:21:44.123456+02:00",
		"description": "run=20260923T092144Z,extra=kept,",
		"properties":  map[string]any{"run": "20260923T092144Z", "extra": "kept"}},
	{"type": "click", "timestamp": "2026-09-23T09:30:00Z", "properties": map[string]any{"fs-element": 42}},
	{"type": "rage-click", "timestamp": "2026-09-23T09:31:00Z", "properties": map[string]any{}},
}

// eventsFixtureServer serves the captured sessions response and Generate
// Context for its one session, AS THE VENDOR FILTERS (D279): only the
// requested `include_types` come back. It refuses a request that does not
// exclude the user context, and reports the types it was last asked for.
//
// IT IGNORES `event_limit` ON PURPOSE (P3 step 19c): a connector returning more
// than it was asked for is what the gateway's truncation to the declared,
// priced size must catch.
//
// SIX EVENTS, FIVE REQUESTED: User Login is not in the target's include_types.
// Of the five served, the click whose fs-element is a number is refused — so
// four are published.
// eventsSeen is what the fixture observed of the requests it served.
type eventsSeen struct {
	mu           sync.Mutex
	lastAsked    []string
	lastLimit    int
	contextCalls int
}

func (e *eventsSeen) asked() []string { e.mu.Lock(); defer e.mu.Unlock(); return e.lastAsked }
func (e *eventsSeen) limit() int      { e.mu.Lock(); defer e.mu.Unlock(); return e.lastLimit }
func (e *eventsSeen) calls() int      { e.mu.Lock(); defer e.mu.Unlock(); return e.contextCalls }

func eventsFixtureServer(t *testing.T) (*httptest.Server, *eventsSeen) {
	t.Helper()
	sessions, err := os.ReadFile(filepath.Join(mustRoot(t), "internal", "connectors", "fullstory",
		"testdata", "sessions_v2.json"))
	if err != nil {
		t.Fatalf("step 18: the captured response: %v", err)
	}
	seen := &eventsSeen{}
	const contextPath = "/v2/sessions/6606828898126528473%3A5450116830618425003/context"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic fixture-token" {
			http.Error(w, "not the target's credential", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sessions/v2":
			_, _ = w.Write(sessions)
		case r.Method == http.MethodPost && r.URL.EscapedPath() == contextPath:
			var body struct {
				Slice struct {
					Mode       string `json:"mode"`
					EventLimit int    `json:"event_limit"`
				} `json:"slice"`
				Events struct {
					IncludeTypes []string `json:"include_types"`
				} `json:"events"`
				Context struct {
					Exclude []string `json:"exclude"`
				} `json:"context"`
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			if body.Slice.Mode != "FIRST" && body.Slice.Mode != "TIMESTAMP" && body.Slice.Mode != "LAST" {
				http.Error(w, "a poll reads FIRST or by TIMESTAMP and a read LAST, got "+body.Slice.Mode,
					http.StatusBadRequest)
				return
			}
			if !slices.Contains(body.Context.Exclude, "user") {
				http.Error(w, "the user context must be excluded (D279)", http.StatusBadRequest)
				return
			}
			seen.mu.Lock()
			seen.lastAsked, seen.lastLimit = body.Events.IncludeTypes, body.Slice.EventLimit
			seen.contextCalls++
			seen.mu.Unlock()
			var served []map[string]any
			for _, e := range eventsFixture {
				if slices.Contains(body.Events.IncludeTypes, e["type"].(string)) {
					served = append(served, e)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"context_data": map[string]any{
				"pages": []any{map[string]any{"url": "https://example.test/account/1509793", "events": served}}}})
		default:
			http.Error(w, "not an endpoint this poll uses: "+r.Method+" "+r.URL.EscapedPath(), http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}
