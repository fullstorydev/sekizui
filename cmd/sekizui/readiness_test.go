package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/internal/metrics"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/internal/spine"
)

// **THESE GO THROUGH `probeMux`, NOT THROUGH `readinessRefusal`.** Asserting the
// wording function directly would prove the strings differ and say nothing about
// whether an operator ever reads them — which is exactly the gap CONTRACTS 83
// was filed about, one layer down. The handler is the contract: a status code
// and a body, over HTTP.
//
// It is also the only place the ORDERING is observable from outside: readiness
// has to be withdrawn while the process is still answering probes, and a test
// that stopped the spine first would have nothing left to ask.

func probeFor(t *testing.T, sp *spine.Spine) http.Handler {
	t.Helper()

	return probeMux(sp, runtime.Profile{}, runtime.ModeGateway,
		metrics.New(), memoryStore(t), nil)
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func quietSpine() *spine.Spine {
	return spine.New(runtime.Profile{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestReadyzSaysWhichWayTheProcessIsGoing is CONTRACTS 83, at the surface an
// operator actually reads.
func TestReadyzSaysWhichWayTheProcessIsGoing(t *testing.T) {
	ctx := context.Background()

	sp := quietSpine()
	h := probeFor(t, sp)

	// --- before Start: initializing ----------------------------------------
	code, body := get(t, h, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Errorf("before Start, /readyz = %d, want 503", code)
	}
	if !strings.Contains(body, "initializing") {
		t.Errorf("before Start, /readyz body = %q, want it to say initializing", body)
	}

	if err := sp.Start(ctx); err != nil {
		t.Fatalf("starting: %v", err)
	}

	// --- serving: 200 ------------------------------------------------------
	code, body = get(t, h, "/readyz")
	if code != http.StatusOK {
		t.Errorf("while serving, /readyz = %d (%q), want 200", code, body)
	}

	// --- STOPPING, WITH COMPONENTS STILL RUNNING ---------------------------
	//
	// The state the whole item is about, and the one the process spends its
	// drain window in. `BeginStopping` withdraws readiness without stopping
	// anything, which is why this is askable at all.
	sp.BeginStopping()

	code, body = get(t, h, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Errorf("while stopping, /readyz = %d, want 503", code)
	}
	if strings.Contains(body, "initializing") {
		t.Errorf("while STOPPING, /readyz says %q. That is the defect CONTRACTS 83 was "+
			"filed for: a 503 during a rollout and a 503 during a cold start call for "+
			"opposite reactions, and this told an operator the wrong one", body)
	}
	if !strings.Contains(body, "stopping") {
		t.Errorf("while stopping, /readyz body = %q, want it to say so", body)
	}
	// **AND IT SAYS THE WITHDRAWAL WAS DELIBERATE**, because a bare "stopping"
	// during a rollout still reads like a fault to whoever is watching a
	// dashboard go red.
	if !strings.Contains(body, "draining") {
		t.Errorf("the stopping body does not mention draining: %q. An operator seeing a "+
			"503 mid-rollout needs to know it is the designed behaviour rather than an "+
			"incident", body)
	}

	// --- liveness is UNAFFECTED throughout ---------------------------------
	//
	// The half that must not change: a liveness probe failing during shutdown
	// gets the container killed rather than drained, so /healthz stays 200
	// while /readyz refuses.
	if code, _ := get(t, h, "/healthz"); code != http.StatusOK {
		t.Errorf("while stopping, /healthz = %d, want 200. A failing liveness probe "+
			"during a drain gets the container killed instead of drained", code)
	}

	if err := sp.Stop(ctx); err != nil {
		t.Fatalf("stopping: %v", err)
	}
	if _, body := get(t, h, "/readyz"); !strings.Contains(body, "stopped") {
		t.Errorf("after Stop, /readyz body = %q, want it to say stopped", body)
	}
}

// TestDebugzTargetsIsHonestWithNoDriftReporters keeps the other new surface from
// being a blank page.
//
// A deployment with no spec-described target is the COMMON case today — the MCP
// driver is not wired until P2 step 36 — so the endpoint's normal answer is the
// one most likely to be read, and an empty body would leave an operator unable
// to tell "nothing to report" from "this endpoint is broken".
func TestDebugzTargetsIsHonestWithNoDriftReporters(t *testing.T) {
	sp := quietSpine()
	code, body := get(t, probeFor(t, sp), "/debugz/targets")

	if code != http.StatusOK {
		t.Errorf("/debugz/targets = %d, want 200", code)
	}
	if strings.TrimSpace(body) == "" {
		t.Fatal("/debugz/targets returned an empty body, so an operator cannot tell " +
			"'nothing to report' from 'this endpoint does not work'")
	}
	if !strings.Contains(body, "no target reports spec drift") {
		t.Errorf("/debugz/targets body = %q, want it to say plainly that nothing "+
			"reports drift", body)
	}
}

// TestReadyzNamesAQuarantinedConnectorAndStaysReady is D282 on the surface an
// operator reads first: a quarantined connector is named on one line, the
// status stays 200 — one connector's packaging defect must not take the
// instance out of rotation (D197's reasoning) — and a deployment with none
// says nothing new.
func TestReadyzNamesAQuarantinedConnectorAndStaysReady(t *testing.T) {
	sp := quietSpine()
	if err := sp.Start(context.Background()); err != nil {
		t.Fatalf("starting: %v", err)
	}
	quarantined := map[string]string{"jira": "ships no schema", "fullstory": "schemas do not parse"}
	h := probeMux(sp, runtime.Profile{}, runtime.ModeGateway, metrics.New(), memoryStore(t),
		func() map[string]string { return quarantined })
	code, body := get(t, h, "/readyz")
	if code != http.StatusOK || !strings.Contains(body, "connectors quarantined: fullstory, jira") {
		t.Errorf("/readyz = %d %q; want 200 naming both connectors", code, body)
	}
	quarantined = nil
	if _, body := get(t, h, "/readyz"); strings.Contains(body, "quarantined") {
		t.Errorf("with nothing quarantined /readyz still mentions it: %q", body)
	}
}

// memoryStore is a drift store held in memory only (D311: OpenStore("")).
func memoryStore(t testing.TB) *drift.Store {
	t.Helper()
	s, err := drift.OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestProbesAreUnsniffablePlainText — D344. /healthz and /readyz set no type, so
// Go sniffed one from a body that carries subsystem errors and connector names.
// Every probe path now answers text/plain with nosniff, before AND after Start
// (the refusal body is a different writer from the ready one); /metrics keeps
// its exposition format.
func TestProbesAreUnsniffablePlainText(t *testing.T) {
	sp := quietSpine()
	h := probeFor(t, sp)
	check := func(path, wantType string) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, wantType) {
			t.Errorf("%s: Content-Type = %q, want %s", path, got, wantType)
		}
	}
	check("/readyz", "text/plain; charset=utf-8") // not started: the refusal body
	if err := sp.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = sp.Stop(context.Background()) })
	for _, path := range []string{"/healthz", "/readyz", "/debugz/targets", "/debugz/glossary", "/debugz/profile"} {
		check(path, "text/plain; charset=utf-8")
	}
	check("/metrics", "text/plain; version=0.0.4")
}
