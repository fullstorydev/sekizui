package fullstory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
)

// sessionsFixture serves the LIVE response captured on 2026-09-23
// (testdata/sessions_v2.json) at /sessions/v2, and refuses a request that is
// not the one the driver must send: GET, the uid in the query, Basic auth.
func sessionsFixture(t *testing.T) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile("testdata/sessions_v2.json")
	if err != nil {
		t.Fatalf("reading the captured response: %v", err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method != http.MethodGet || r.URL.Path != "/sessions/v2":
			http.Error(w, "not the sessions endpoint", http.StatusNotFound)
		case r.URL.Query().Get("uid") != "1509793":
			http.Error(w, "wrong uid", http.StatusBadRequest)
		case !strings.HasPrefix(r.Header.Get("Authorization"), "Basic "):
			http.Error(w, "no Basic credential", http.StatusUnauthorized)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sessionsTarget(t *testing.T, base string) connector.Target {
	t.Helper()
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "fs:sessions", Kind: Kind, Tenant: "alpha", Residency: "eu", BaseURL: base,
		CredentialVersion: "v1", Credential: connector.Secret("fixture-token"),
		Settings: map[string]string{SettingSessionsUID: "1509793"},
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tgt
}

// TestPollCarriesTheLiveShapeFaithfully is D265's four facts, against the
// captured response.
func TestPollCarriesTheLiveShapeFaithfully(t *testing.T) {
	fx := sessionsFixture(t)
	events, next, err := New(WithHTTPClient(fx.Client()), withServer(fx)).Poll(tenantCtx("alpha"),
		sessionsTarget(t, fx.URL), "", 5)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("%d events, want the 1 session the live response carries", len(events))
	}
	e := events[0]
	// THE IDS ARE STRINGS, EXACT: above 2^53, a float would round them.
	if e.Data["session_id"] != "5450116830618425003" || e.Data["user_id"] != "6606828898126528473" {
		t.Errorf("ids = %v / %v; they must be carried as the exact strings the vendor sent",
			e.Data["session_id"], e.Data["user_id"])
	}
	// createdTime WAS A STRING OF EPOCH SECONDS, and it became the event time.
	if e.At.Unix() != 1789032077 {
		t.Errorf("event time %v, want epoch 1789032077", e.At)
	}
	// THE uid WE ASKED FOR, which the response does not echo.
	if e.Data["uid"] != "1509793" {
		t.Errorf("uid = %v; the source must record whose sessions these are", e.Data["uid"])
	}
	if e.Subject != "6606828898126528473:5450116830618425003" {
		t.Errorf("subject %q, want the user:session entity", e.Subject)
	}

	// THE CURSOR MOVED PAST IT: the same response again yields nothing new.
	again, _, err := New(WithHTTPClient(fx.Client()), withServer(fx)).Poll(tenantCtx("alpha"),
		sessionsTarget(t, fx.URL), next, 5)
	if err != nil || len(again) != 0 {
		t.Errorf("re-polling from cursor %q returned %d event(s), err %v; want none", next, len(again), err)
	}
}

// TestAMalformedCreatedTimeFailsThePoll: a value that is not epoch seconds is
// the vendor breaking its contract, never time zero.
func TestAMalformedCreatedTimeFailsThePoll(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sessions":[{"userId":"1","sessionId":"2","createdTime":"yesterday","fsUrl":"x"}]}`))
	}))
	defer srv.Close()
	if _, _, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Poll(context.Background(),
		sessionsTarget(t, srv.URL), "", 5); err == nil {
		t.Error("a createdTime of \"yesterday\" was accepted; it would sort before every cursor " +
			"and never be delivered")
	}
}

// TestSourceConformance runs the published source suite (D167, D255) against
// the captured response. The captured org has ONE session for this uid, and
// the suite needs at least two from the zero cursor, so the fixture here
// serves the live row twice over with distinct ids and times.
func TestSourceConformance(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sessions":[` +
			`{"userId":"6606828898126528473","sessionId":"5450116830618425003","createdTime":"1789032077","fsUrl":"u1"},` +
			`{"userId":"6606828898126528473","sessionId":"5450116830618425004","createdTime":"1789032078","fsUrl":"u2"},` +
			`{"userId":"6606828898126528473","sessionId":"5450116830618425005","createdTime":"1789032079","fsUrl":"u3"}]}`))
	}))
	defer srv.Close()
	spy := conformance.NewPoolSpy()
	conformance.RunSource(t, New(WithHTTPClient(srv.Client()), withServer(srv), WithPool(spy)),
		conformance.SourceCase{Target: sessionsTarget(t, srv.URL), Limit: 2, Tenant: "alpha", Pool: spy})
}
