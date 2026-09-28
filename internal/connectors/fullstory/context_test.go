package fullstory

import (
	"encoding/json"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// contextFixture serves a response in the SHAPE confirmed live on 2026-09-23
// (not the live body, which carries a user's name and email): org, user and
// device context the driver must NOT pass on, and one custom event carrying
// the run stamp. It refuses a request that is not the one the vendor requires:
// POST, the session's colon as %3A, and a LAST slice.
func contextFixture(t *testing.T, stamp string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		switch {
		case r.Method != http.MethodPost:
			http.Error(w, "context is a POST", http.StatusMethodNotAllowed)
		case r.URL.RawPath != "/v2/sessions/1%3A2/context" && r.URL.EscapedPath() != "/v2/sessions/1%3A2/context":
			http.Error(w, "the session id's colon must be %3A: got "+r.URL.EscapedPath(), http.StatusBadRequest)
		case body.Slice.Mode != "LAST":
			http.Error(w, "want the LAST slice", http.StatusBadRequest)
		// D279: ask only for the listed types, and never for the user context.
		case !slices.Contains(body.Events.IncludeTypes, "sekizui_acceptance_step29") ||
			!slices.Contains(body.Events.IncludeTypes, "navigate"):
			http.Error(w, "include_types must name the declared kinds and the listed custom events", http.StatusBadRequest)
		case !slices.Contains(body.Context.Exclude, "user"):
			http.Error(w, "the user context must be excluded", http.StatusBadRequest)
		default:
			_, _ = w.Write([]byte(`{"context_data":{"context":{"session_id":"1:2",` +
				`"user_context":{"user_uid":"1509793","display_name":"Private Person","email":"private@example.com"},` +
				`"org_context":{"org_id":"o"}},"pages":[{"url":"https://x","events":[` +
				`{"type":"navigate","timestamp":"2026-09-23T09:00:00Z","properties":{}},` +
				`{"type":"sekizui_acceptance_step29","timestamp":"2026-09-23T09:21:44Z","properties":{"run":"` + stamp + `"}}]}]}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestSessionEventsReadsBackTheStamp is D270 at the driver: the request is the
// one the vendor requires, every event comes back as a row with its properties,
// and the user's name and email reach no row.
func TestSessionEventsReadsBackTheStamp(t *testing.T) {
	fx := contextFixture(t, "20260923T092144Z")
	rows, err := New(WithHTTPClient(fx.Client()), withServer(fx)).Query(tenantCtx("alpha"),
		readBackTarget(t, fx.URL), ActionSessionEvents, map[string]any{"session_id": "1:2"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows.Rows) != 2 {
		t.Fatalf("%d rows, want one per event (2)", len(rows.Rows))
	}
	if rows.Rows[0]["device_id"] != "1" || rows.Rows[0]["session_id"] != "2" {
		t.Errorf("the device:session id was not split into device_id and session_id: %v", rows.Rows[0])
	}
	found := false
	for _, r := range rows.Rows {
		if props, _ := r["event_properties"].(map[string]any); props["run"] == "20260923T092144Z" {
			found = true
		}
		enc, _ := json.Marshal(r)
		if s := string(enc); strings.Contains(s, "Private Person") || strings.Contains(s, "private@example.com") {
			t.Errorf("a row carries the session's user context: %s", s)
		}
	}
	if !found {
		t.Error("the run stamp was not found in any row's properties; the read-back cannot see the write")
	}
	for _, bad := range []float64{0, 201} {
		if _, err := New(WithHTTPClient(fx.Client()), withServer(fx)).Query(tenantCtx("alpha"), sessionsTarget(t, fx.URL),
			ActionSessionEvents, map[string]any{"session_id": "1:2", "event_limit": bad}); err == nil {
			t.Errorf("event_limit %v was accepted; the bound is 1..%d", bad, maxSessionEvents)
		}
	}
}

// readBackTarget lists the read-back's custom event, which a context read
// fetches only when the target names it (D279).
func readBackTarget(t *testing.T, base string) connector.Target {
	t.Helper()
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "fs:live", Kind: Kind, Tenant: "alpha", Residency: "eu", BaseURL: base,
		CredentialVersion: "v1", Credential: connector.Secret("fixture-token"),
		Settings: map[string]string{SettingCustomEvents: "sekizui_acceptance_step29"},
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tgt
}
