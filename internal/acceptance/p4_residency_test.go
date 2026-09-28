package acceptance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// RESIDENCY ACROSS FULLSTORY DATA CENTRES (D29, D304, D320), P4 steps 6-8.
//
// **THE TWO DCs ARE FIXTURES BEHIND THEIR REAL HOSTNAMES.** The targets name
// `https://api.fullstory.com` and `https://api.eu1.fullstory.com`, exactly as a
// deployment would; only the test client's dialer sends each name to its own
// TLS fixture, whose certificate is issued for both. Each fixture records the
// host and the key it was sent, so "the eu1 target dials the eu1 host with the
// eu1 org's key, and never the other" is asserted at the far side. Any other
// address is refused by the dialer, so no arm can reach the real vendor.

const (
	na1Host = "api.fullstory.com"
	eu1Host = "api.eu1.fullstory.com"
	na1Key  = "na1-org-key"
	eu1Key  = "eu1-org-key"
)

// dcHit is one request a DC fixture received.
type dcHit struct{ host, auth, path string }

// dcFixture stands in for one Fullstory data centre.
type dcFixture struct {
	srv *httptest.Server

	mu       sync.Mutex
	hits     []dcHit
	throttle bool // answer 429 with Retry-After, the upstream's own quota speaking (step 13)
}

func (f *dcFixture) setThrottle(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.throttle = on
}

// writes counts the events a DC accepted or refused: POSTs to /v2/events.
func (f *dcFixture) writes() int {
	n := 0
	for _, h := range f.seen() {
		if h.path == "/v2/events" {
			n++
		}
	}
	return n
}

func (f *dcFixture) seen() []dcHit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dcHit(nil), f.hits...)
}

// dcFixtures are the two DCs and the client that reaches them by name.
type dcFixtures struct {
	na1, eu1 *dcFixture
	client   *http.Client
}

// newDCFixtures serves the two reads steps 6-7 make — a session's context and
// one user's sessions — from each DC, each refusing any key but its own org's.
func newDCFixtures(t *testing.T) *dcFixtures {
	t.Helper()
	cert, leaf := dcCertificate(t)
	sessions, err := os.ReadFile(filepath.Join(mustRoot(t), "internal", "connectors", "fullstory",
		"testdata", "sessions_v2.json"))
	if err != nil {
		t.Fatalf("the captured sessions response: %v", err)
	}
	const contextPath = "/v2/sessions/6606828898126528473%3A5450116830618425003/context"
	serve := func(key string) *dcFixture {
		f := &dcFixture{}
		f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.hits = append(f.hits, dcHit{host: r.Host, auth: r.Header.Get("Authorization"), path: r.URL.EscapedPath()})
			throttled := f.throttle
			f.mu.Unlock()
			switch {
			case r.Header.Get("Authorization") != "Basic "+key:
				http.Error(w, "not this org's key", http.StatusUnauthorized)
			case throttled:
				w.Header().Set("Retry-After", "3600")
				http.Error(w, "org quota exceeded", http.StatusTooManyRequests)
			case r.Method == http.MethodPost && r.URL.Path == "/v2/events":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			case r.Method == http.MethodPost && r.URL.EscapedPath() == contextPath:
				_ = json.NewEncoder(w).Encode(map[string]any{"context_data": map[string]any{"pages": fixturePages()}})
			case r.Method == http.MethodGet && r.URL.Path == "/sessions/v2":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(sessions)
			default:
				http.Error(w, "not an endpoint these steps use", http.StatusNotFound)
			}
		}))
		f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		f.srv.StartTLS()
		t.Cleanup(f.srv.Close)
		return f
	}
	fx := &dcFixtures{na1: serve(na1Key), eu1: serve(eu1Key)}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	roots.AddCert(leaf)
	route := map[string]string{
		na1Host + ":443": fx.na1.srv.Listener.Addr().String(),
		eu1Host + ":443": fx.eu1.srv.Listener.Addr().String(),
	}
	var d net.Dialer
	fx.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			to, ok := route[addr]
			if !ok {
				return nil, fmt.Errorf("the DC fixtures dial only %s and %s, not %s", na1Host, eu1Host, addr)
			}
			return d.DialContext(ctx, network, to)
		},
	}}
	return fx
}

// dcCertificate is a self-signed certificate for both DC hostnames — trusted
// by the fixture client alone, so verification stays on.
func dcCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fullstory DC fixture"},
		DNSNames:  []string{na1Host, eu1Host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// inClass is a capability that names the residency class it reaches (D136).
func inClass(action, target, class string) config.CapabilitySpec {
	return config.CapabilitySpec{Action: action, TargetRef: target,
		Where: map[string]any{config.TargetResidencyFacet: []any{class}}}
}

// dcRun is a run with an na1 org (us) and an eu1 org (eu) as targets, and
// agent:jobs granted a read of each and a poll of the eu1 one — every
// capability naming its class, so it holds under any ceiling.
func dcRun(t *testing.T, fx *dcFixtures, ceiling []string) *run {
	t.Helper()
	t.Setenv("SEKIZUI_FS_NA1", na1Key)
	t.Setenv("SEKIZUI_FS_EU1", eu1Key)
	return newRunWith(t, runOpts{
		residency: ceiling,
		patch: func(d *config.Document) {
			settings := map[string]string{"sessions_uid": "1509793"}
			d.Targets = append(d.Targets,
				config.TargetSpec{Ref: "fs:na1", Kind: fullstory.Kind, Tenant: "na1", Residency: "us",
					BaseURL: "https://" + na1Host, CredentialRef: "env://SEKIZUI_FS_NA1", Settings: settings},
				config.TargetSpec{Ref: "fs:eu1", Kind: fullstory.Kind, Tenant: "eu1", Residency: "eu",
					BaseURL: "https://" + eu1Host, CredentialRef: "env://SEKIZUI_FS_EU1", Settings: settings})
			for i := range d.Grants {
				if d.Grants[i].Principal == "agent:jobs" {
					d.Grants[i].Allow = append(d.Grants[i].Allow,
						inClass("fullstory.session_events", "fs:na1", "us"),
						inClass("fullstory.session_events", "fs:eu1", "eu"),
						inClass("fullstory.poll", "fs:eu1", "eu"))
				}
			}
		},
		fullstoryClient: fx.client,
	})
}

// readDC reads the fixture session's events from one DC target.
func readDC(t *testing.T, r *run, target string) *sekizuiv1.QueryResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := r.as(t, "agent:jobs").Query(ctx, &sekizuiv1.QueryRequest{Action: "fullstory.session_events",
		TargetRef: target, Args: mustArgs(t, map[string]any{"session_id": seirenSession})})
	if err != nil {
		t.Fatalf("the read of %s was a transport error: %v", target, err)
	}
	return resp
}

// recordOf is the WAL record of a decision.
func recordOf(t *testing.T, path, id string) *sekizuiv1.Decision {
	t.Helper()
	for _, d := range readLog(t, path) {
		if d.GetId() == id {
			return d
		}
	}
	t.Fatalf("no record for decision %q", id)
	return nil
}

// onlyFrom asserts every request a DC received named its host and carried its
// org's key — and that it received at least one.
func onlyFrom(t *testing.T, step string, f *dcFixture, host, key string) {
	t.Helper()
	hits := f.seen()
	if len(hits) == 0 {
		t.Errorf("%s: %s received no request", step, host)
	}
	for _, h := range hits {
		if h.host != host || h.auth != "Basic "+key {
			t.Errorf("%s: %s received host=%q auth=%q on %s; want its own host and its own org's key only",
				step, host, h.host, h.auth, h.path)
		}
	}
}

// p4Step6 — one agent reads two Fullstory orgs in different DCs (D29, D304).
func p4Step6(t *testing.T) {
	fx := newDCFixtures(t)
	r := dcRun(t, fx, []string{"eu", "us"})
	r.narrate(t, "one agent reads two Fullstory orgs in different DCs")
	if r.localOnly(t, "the two DCs are fixtures this process serves, under a ceiling this step sets") {
		return
	}

	// 6a — EACH READ SUCCEEDS THROUGH ITS OWN HOST, WITH ITS OWN ORG'S KEY.
	na1, eu1 := readDC(t, r, "fs:na1"), readDC(t, r, "fs:eu1")
	for name, resp := range map[string]*sekizuiv1.QueryResponse{"fs:na1": na1, "fs:eu1": eu1} {
		if resp.GetStatus() != sekizuiv1.Status_STATUS_OK || len(resp.GetRows()) != 9 {
			t.Fatalf("step 6a: the read of %s: %v %q, %d rows; want OK and the fixture's nine events",
				name, resp.GetStatus(), resp.GetReason(), len(resp.GetRows()))
		}
	}
	onlyFrom(t, "step 6a", fx.na1, na1Host, na1Key)
	onlyFrom(t, "step 6a", fx.eu1, eu1Host, eu1Key)

	// 6b — RESIDENCY IS ON THE TARGET, and so on each read's record.
	if got := recordOf(t, r.path, na1.GetDecisionId()).GetResidency(); got != "us" {
		t.Errorf("step 6b: the na1 read's record carries residency %q; want us", got)
	}
	if got := recordOf(t, r.path, eu1.GetDecisionId()).GetResidency(); got != "eu" {
		t.Errorf("step 6b: the eu1 read's record carries residency %q; want eu", got)
	}

	// 6c — EVERY ENVELOPE THE eu1 ORG PRODUCES CARRIES eu: a poll, as a job.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caller := r.as(t, "agent:jobs")
	started, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "fullstory.poll", TargetRef: "fs:eu1"}})
	if err != nil || started.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 6c: the eu1 poll was refused: %v %s", err, started.GetReason())
	}
	stream, err := caller.JobResults(ctx, &sekizuiv1.JobResultsRequest{JobId: started.GetJobId()})
	if err != nil {
		t.Fatalf("step 6c: JobResults: %v", err)
	}
	envelopes := 0
	for {
		msg, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("step 6c: receiving: %v", rerr)
		}
		if env := msg.GetEnvelope(); env != nil {
			envelopes++
			if env.GetResidency() != "eu" {
				t.Errorf("step 6c: envelope %s from the eu1 org carries residency %q; want eu", env.GetId(), env.GetResidency())
			}
		}
	}
	if envelopes == 0 {
		t.Errorf("step 6c: the eu1 poll produced no envelope; the residency arm is vacuous without one")
	}
	onlyFrom(t, "step 6c", fx.eu1, eu1Host, eu1Key)
	r.detail(t, "agent:jobs read fs:na1 through %s and fs:eu1 through %s, each with its own org's key and "+
		"neither host seeing the other's; the records carry us and eu, and every one of the eu1 poll's %d envelope(s) "+
		"carry eu. No live eu1 arm: no eu1 key can be had, and the endpoints are confirmed (D324)", na1Host, eu1Host, envelopes)
}

// residencyRefusal is the shape a cross-region refusal must have: the status
// the caller is answered with, and the record's verdict, stage, rule and class
// — the tuple steps 7 and 8 compare.
//
// **THE RULE IS WHAT PINS THE GATEWAY'S CEILING.** Resolve refuses a crossing
// too, as defence in depth, with the same status, stage and class — so with the
// ceiling switched off every other field still matched, and step 8's
// comparison survived a defect both doors share. Only the ceiling records
// `residency:ceiling`; a Resolve refusal carries the grant policy admitted. The answer's own stage is checked beside it,
// because the verbs name it differently: a Query answers `refused_by`, a
// command answers `kind` (D135).
type residencyRefusal struct {
	status    sekizuiv1.Status
	verdict   sekizuiv1.Verdict
	recordBy  sekizuiv1.RefusedBy
	rule      string
	residency string
}

var wantResidencyRefusal = residencyRefusal{ //nolint:gochecknoglobals // immutable expectation
	status: sekizuiv1.Status_STATUS_DENIED, verdict: sekizuiv1.Verdict_VERDICT_DENY,
	recordBy: sekizuiv1.RefusedBy_REFUSED_BY_RESIDENCY, rule: "residency:ceiling", residency: "us",
}

// p4Step7 — a cross-region resolve is refused, and the refusal is audited (D29).
func p4Step7(t *testing.T) {
	// 7r — ON THE RUNNING DEMO INSTANCE (D315, D324): agent:showcase is GRANTED
	// a read of kata:beta, a us target, and the eu instance refuses it on
	// residency — the ceiling, not policy, answered before any resolve.
	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		r := newRun(t)
		r.narrate(t, "a cross-region resolve is refused, on the running instance")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := r.as(t, "agent:showcase").Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:beta"})
		if err != nil {
			t.Fatalf("step 7r: a transport error, where a deliberate refusal is a result (D135): %v", err)
		}
		if resp.GetStatus() != sekizuiv1.Status_STATUS_DENIED || resp.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_RESIDENCY {
			t.Fatalf("step 7r: agent:showcase's granted read of kata:beta (us) on the eu instance: %v refused_by %v "+
				"(%s); want DENIED by residency", resp.GetStatus(), resp.GetRefusedBy(), resp.GetReason())
		}
		r.detail(t, "agent:showcase is granted kata.read on kata:beta, and the instance refused it: %v, refused_by "+
			"%v — %s", resp.GetStatus(), resp.GetRefusedBy(), resp.GetReason())
		return
	}
	fx := newDCFixtures(t)
	r := dcRun(t, fx, []string{"eu"}) // an eu1 instance: the na1 read is the crossing
	r.narrate(t, "a cross-region resolve is refused, and the refusal is audited")
	if r.localOnly(t, "the DC fixtures are this process's") {
		return
	}

	// 7a — REFUSED ON RESIDENCY, POSITIVELY: the stage and the status, in the
	// answer and in the record, never `!= STATUS_OK` (D138).
	resp := readDC(t, r, "fs:na1")
	rec := recordOf(t, r.path, resp.GetDecisionId())
	got := residencyRefusal{resp.GetStatus(), rec.GetVerdict(), rec.GetRefusedBy(), rec.GetMatchedRule(), rec.GetResidency()}
	if got != wantResidencyRefusal || resp.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_RESIDENCY {
		t.Errorf("step 7a: the us read under an eu ceiling: %+v, answered refused_by %v (reason %q); want %+v "+
			"answered by residency", got, resp.GetRefusedBy(), resp.GetReason(), wantResidencyRefusal)
	}

	// 7b — BEFORE RESOLVE: the na1 DC was never dialled, its key never sent.
	if hits := fx.na1.seen(); len(hits) != 0 {
		t.Errorf("step 7b: %s received %d request(s) for a refused crossing; the ceiling must refuse before resolve", na1Host, len(hits))
	}

	// 7c — NON-VACUITY: the same agent, the same fixtures, the served class.
	if ok := readDC(t, r, "fs:eu1"); ok.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("step 7c: the eu read in the same run: %v %q; without it 7a proves only that reads fail",
			ok.GetStatus(), ok.GetReason())
	}
	r.detail(t, "fs:na1 (us) under an eu ceiling: %v, refused_by %v, recorded %v with class %q — and %s "+
		"never dialled; fs:eu1 read OK in the same run", got.status, got.recordBy, got.verdict, got.residency, na1Host)
}

// p4Step8 — the MCP target refuses a cross-region resolve exactly as the native
// driver does (D29, D52): one stack fronting one system through both doors,
// both in a class the ceiling does not serve.
func p4Step8(t *testing.T) {
	ctx := context.Background()
	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		t.Skip("needs a deployment whose ceiling and MCP fixture this step controls")
	}
	base := bothPaths(t)
	stack := newMCPStack(ctx, t, func(d *config.Document) {
		base(d)
		for i := range d.Targets {
			d.Targets[i].Residency = "us"
		}
		d.Grants = []config.GrantSpec{{Principal: "agent:dev", Allow: []config.CapabilitySpec{
			inClass("fullstory.create_event", "fullstory-api", "us"),
			inClass("mcp.fullstory.create_event", "fixture-mcp", "us"),
		}}}
	}, func(m *mcpTuning) { m.residency = []string{"eu"} })
	stack.up.offer(mcp.LiveTool{Name: "create_event", InputSchema: objectSchema("name")})

	refusal := func(who, action, target string) residencyRefusal {
		res, err := stack.gw.Enforce(ctx, assertedIdentity(who), &sekizuiv1.Command{
			Action: action, TargetRef: target, Args: mustArgs(t, map[string]any{"name": "x"}),
			IdempotencyKey: "p4-8-" + who + "-" + target})
		if err != nil {
			t.Fatalf("step 8: %s was refused as a transport error: %v", target, err)
		}
		if res.GetKind() != "residency" {
			t.Errorf("step 8: %s refused with kind %q; want residency", target, res.GetKind())
		}
		rec := recordOf(t, stack.logPath, res.GetDecisionId())
		return residencyRefusal{res.GetStatus(), rec.GetVerdict(), rec.GetRefusedBy(), rec.GetMatchedRule(), rec.GetResidency()}
	}
	native := refusal("agent:dev", "fullstory.create_event", "fullstory-api")
	viaMCP := refusal("agent:dev", "mcp.fullstory.create_event", "fixture-mcp")

	// 8a — THE SAME REFUSAL THROUGH BOTH DOORS, and it is the CEILING's: the
	// rule in the tuple is what tells it from Resolve's defence in depth.
	if native != wantResidencyRefusal || viaMCP != native {
		t.Errorf("step 8a: native %+v, MCP %+v; want both %+v", native, viaMCP, wantResidencyRefusal)
	}

	// 8c — THE CEILING SPEAKS FIRST EVEN WHERE NO GRANT EXISTS (step 59's
	// ordering, through both doors). A caller with no capability at all would
	// be refused by policy if the ceiling did not run ahead of it, and told to
	// review a grant about a target this deployment may never touch.
	strangerNative := refusal("agent:stranger", "fullstory.create_event", "fullstory-api")
	strangerMCP := refusal("agent:stranger", "mcp.fullstory.create_event", "fixture-mcp")
	if strangerNative != wantResidencyRefusal || strangerMCP != strangerNative {
		t.Errorf("step 8c: with no grant, native %+v, MCP %+v; want both the ceiling's %+v",
			strangerNative, strangerMCP, wantResidencyRefusal)
	}
	// 8b — THE MCP SERVER NEVER SAW THE CALL.
	stack.up.mu.Lock()
	calls := append([]string(nil), stack.up.calls...)
	stack.up.mu.Unlock()
	if len(calls) != 0 {
		t.Errorf("step 8b: the MCP server received tools/call %v for a refused crossing", calls)
	}
	t.Logf("step 8: fullstory-api and fixture-mcp, both us under an eu ceiling, refused alike: %+v; "+
		"the MCP server received no call", viaMCP)
}
