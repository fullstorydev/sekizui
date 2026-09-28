package acceptance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step24 — the Fullstory slice is bounded, and the boundary is checkable
// (D239): the driver dials only Fullstory's own API hosts.
//
// **WHAT "REFUSES RATHER THAN HALF-SERVES" CAME TO MEAN.** The driver is one org
// in one data centre per target by construction — one credential, one host —
// so no configuration can "ask for" multi-org. What it could do was name any
// HOST, and the target's credential went there on every call (CONTRACTS 117,
// the road D286's credential theft rode). The maintainer ruled: only Fullstory's hosts.
func p3Step24(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the Fullstory slice is bounded by P3's own criteria, and the boundary is checkable")

	// 24a — THE RULE, AGAINST THE SHAPES AN ATTACKER WOULD TRY.
	d := fullstory.New()
	for _, c := range []struct {
		url   string
		admit bool
	}{
		{"https://api.fullstory.com", true},
		{"https://api.eu1.fullstory.com/", true},
		{"https://collector.example.test", false},
		{"https://api.fullstory.com.example.test", false}, // a look-alike
		{"https://api.fullstory.com@example.test", false}, // userinfo: the host is example.test
		// USERINFO ON A REAL HOST — material in configuration, which §4.7
		// forbids. The exact-host rule alone admits it; this case is why the
		// userinfo check exists (its mutation survived without it).
		{"https://someone:secret@api.fullstory.com", false},
		{"https://api.fullstory.com:8443", false}, // a non-default port
		{"http://api.fullstory.com", false},       // plaintext
	} {
		if err := d.AdmitBaseURL("fs:x", c.url); (err == nil) != c.admit {
			t.Errorf("step 24a: %s admitted=%v, want %v (%v)", c.url, err == nil, c.admit, err)
		}
	}
	r.detail(t, "two Fullstory hosts admitted; a foreign host, a look-alike, a userinfo trick, a port "+
		"and plaintext refused")

	// 24b — AND ON EVERY CALL, BEFORE ANYTHING IS SENT. A target patched onto
	// a TLS server the driver was NOT told to trust as a fixture: the governed
	// call is refused and the server never sees a request, credential or not.
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SEKIZUI_FS_LIVE", "a-real-looking-key")
	run := newRunWith(t, runOpts{patch: func(doc *config.Document) {
		for i := range doc.Targets {
			if doc.Targets[i].Ref == "fs:live" {
				doc.Targets[i].BaseURL = srv.URL
			}
		}
	}})
	if run.localOnly(t, "the patched target is this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := run.as(t, "agent:triage").Query(ctx, &sekizuiv1.QueryRequest{
		Action: "fullstory.session_events", TargetRef: "fs:live",
		Args: mustArgs(t, map[string]any{"session_id": "1:2"}),
	})
	// NON-VACUITY: the refusal must be THIS rule's. A policy denial would
	// also leave the server untouched and prove nothing about the host check.
	said := resp.GetReason()
	if err != nil {
		said = err.Error()
	}
	switch {
	case err == nil && resp.GetStatus() == sekizuiv1.Status_STATUS_OK:
		t.Fatalf("step 24b: a read against a non-Fullstory host SUCCEEDED; the credential was sent there")
	case !strings.Contains(said, "Fullstory's API hosts"):
		t.Fatalf("step 24b: the read was refused, but not by the host check — so the server staying "+
			"untouched proves nothing about it: %s", said)
	case hits.Load() != 0:
		t.Fatalf("step 24b: the foreign host received %d request(s) — the credential left the "+
			"process before the refusal", hits.Load())
	}
	r.detail(t, "a read patched onto a foreign host was refused and the host received nothing")
}
