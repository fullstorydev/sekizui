package acceptance

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step4 — Fullstory sessions are polled, translated, published, and consumed
// (P3 criteria 1 and 11, D24, D265).
//
// **TWO RUNS OF ONE STEP.** Under `make acceptance-live` the target is the real
// org and the step must find the session P2 step 1 wrote its event into — the
// join criterion 12 wants. Otherwise a TLS fixture serves the response captured
// live on 2026-09-23 and REFUSES a request that is not the one the driver must
// send, so the ordinary run proves the request as well as the parsing.
func p3Step4(t *testing.T) {
	live := os.Getenv(liveWriteRequested) != ""
	var r *run
	// The fixture's user and session offline; the configured ones live.
	wantUID, wantDevice, wantSession := "1509793", "6606828898126528473", "5450116830618425003"
	if live {
		lc := liveFullstory(t) // sets SEKIZUI_FS_LIVE from the configured key
		wantUID, wantDevice, wantSession = lc.UID, lc.device, lc.uiSession
		r = newRunWith(t, runOpts{patch: lc.targetsFor})
	} else {
		fx := sessionsFixtureServer(t)
		t.Setenv("SEKIZUI_FS_LIVE", "fixture-token")
		r = newRunWith(t, runOpts{
			patch: func(d *config.Document) {
				for i := range d.Targets {
					if d.Targets[i].Ref == "fs:sessions" {
						d.Targets[i].BaseURL = fx.URL
					}
				}
			},
			fullstoryClient: trustingSystemAnd(t, fx),
		})
	}
	r.narrate(t, "Fullstory sessions are polled, translated, published, and consumed")
	if r.localOnly(t, "the job runner is this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caller := r.as(t, "agent:jobs")

	started, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "fullstory.poll", TargetRef: "fs:sessions"},
	})
	if err != nil || started.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 4: the poll job was refused: %v %s (%s)", err, started.GetReason(),
			started.GetRefusedBy())
	}
	stream, err := caller.JobResults(ctx, &sekizuiv1.JobResultsRequest{JobId: started.GetJobId()})
	if err != nil {
		t.Fatalf("step 4: JobResults: %v", err)
	}
	var got []*sekizuiv1.Envelope
	for {
		msg, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("step 4: receiving: %v", rerr)
		}
		got = append(got, msg.GetEnvelope())
	}
	st, err := caller.JobStatus(ctx, &sekizuiv1.JobStatusRequest{JobId: started.GetJobId()})
	if err != nil || st.GetState() != sekizuiv1.JobState_JOB_STATE_FINISHED {
		t.Fatalf("step 4: the job ended %s (%s), err %v", st.GetState(), st.GetReason(), err)
	}
	if len(got) == 0 {
		t.Fatal("step 4: the poll produced no sessions; the captured response has one, and the " +
			"live org has at least the one P2 step 1 writes into")
	}

	// 4a — TRANSLATED FAITHFULLY. The type, the source, the causation root, and
	// the ids as the EXACT strings the vendor sent (above 2^53, a float rounds).
	var joined bool
	for _, env := range got {
		data := env.GetData().AsMap()
		switch {
		case env.GetType() != "fullstory.session.v1":
			t.Errorf("step 4a: type %q, want fullstory.session.v1", env.GetType())
		case env.GetSource() != "fs:sessions":
			t.Errorf("step 4a: source %q, want the polled target", env.GetSource())
		case env.GetCausation().GetRootId() != started.GetJobId():
			t.Errorf("step 4a: causation root %q, not the job", env.GetCausation().GetRootId())
		case data["uid"] != wantUID:
			t.Errorf("step 4a: uid %v; the response does not echo it, so the source must", data["uid"])
		}
		if _, isString := data["session_id"].(string); !isString {
			t.Errorf("step 4a: session_id arrived as %T; it must stay a string", data["session_id"])
		}
		if data["user_id"] == wantDevice && data["session_id"] == wantSession {
			joined = true
		}
	}
	// 4b — THE JOIN: the session P2 step 1 writes its event into, identified
	// exactly as the live report's link names it. In the fixture run this is the
	// captured row; live, it is the org saying so again.
	if !joined {
		t.Errorf("step 4b: session %s:%s — where P2 step 1's "+
			"event lands — was not among the polled sessions, or its ids were altered", wantDevice, wantSession)
	}
	how := "a fixture serving the response captured live on 2026-09-23"
	if live {
		how = "the configured org, live"
	}
	r.detail(t, "%d session(s) for uid %s from %s, delivered to agent:jobs as "+
		"fullstory.session.v1, ids intact, including the session P2 step 1 writes into", len(got), wantUID, how)
}

// sessionsFixtureServer serves the captured response, refusing any request the
// driver must not send: not GET /sessions/v2, not this uid, or not
// `Authorization: Basic <the target's credential>`.
func sessionsFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(mustRoot(t), "internal", "connectors", "fullstory",
		"testdata", "sessions_v2.json"))
	if err != nil {
		t.Fatalf("step 4: the captured response: %v", err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method != http.MethodGet || r.URL.Path != "/sessions/v2":
			http.Error(w, "not the sessions endpoint", http.StatusNotFound)
		case r.URL.Query().Get("uid") != "1509793":
			http.Error(w, "wrong uid", http.StatusBadRequest)
		case r.Header.Get("Authorization") != "Basic fixture-token":
			http.Error(w, "not the target's credential", http.StatusUnauthorized)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// trustingSystemAnd returns a client trusting the system roots AND the
// fixture's certificate — so substituting it changes WHERE the driver can
// reach, never whether it verifies TLS.
func trustingSystemAnd(t *testing.T, fx *httptest.Server) *http.Client {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pool.AddCert(fx.Certificate())
	c := fx.Client()
	tr := c.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.RootCAs = pool
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}
