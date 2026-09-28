package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/catalog"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/identity"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// THIS FILE IS P0 EXIT CRITERIA 1 AND 2.
//
//	1. "An mTLS caller asserting a subject it may speak for gets a command
//	   executed against the kata driver, with a durable decision record naming
//	   the matched rule."
//	2. "A DENIED command also produces a decision record (the easily-dropped
//	   half of §5.4)."
//
// Assembled from the real components — identity, policy, resolver, the kata
// driver, and the audit recorder — rather than mocks, because the criterion is
// about them working TOGETHER. A mocked policy engine would prove the gateway
// calls something, not that the enforcement path holds.

const testConfig = `
stages: [raw, enriched, triaged, judged]
targets:
  - {ref: kata:alpha, kind: kata, tenant: alpha, residency: eu, credential: env://SEKIZUI_TEST_TOK}
  - {ref: kata:beta,  kind: kata, tenant: beta,  residency: us, credential: env://SEKIZUI_TEST_TOK}
grants:
  - principal: agent:triage
    allow:
      - {action: kata.create_issue, target: kata:alpha, where: {project: [PROJ]}}
      - {action: kata.read, target: kata:alpha}
    escalate:
      - {action: kata.delete_project, target: kata:alpha}
  - principal: mesh:primary
    allow:
      - {action: kata.create_issue, target: kata:alpha}
      - {action: kata.read, target: kata:alpha}
    may_speak_for: [agent:triage]
  # GRANTED on the us-resident target, deliberately. Residency must refuse a
  # target the principal IS permitted to use — otherwise the test proves only
  # that policy works, which is a different test.
  - principal: agent:global
    allow:
      - {action: kata.create_issue, target: kata:beta}
`

type harness struct {
	srv   *Server
	sink  *captureSink
	clock time.Time
}

type captureSink struct {
	mu      sync.Mutex
	records []*sekizuiv1.Decision
}

func (c *captureSink) Name() string                { return "capture" }
func (c *captureSink) Residencies() []string       { return nil }
func (c *captureSink) Close(context.Context) error { return nil }
func (c *captureSink) Write(_ context.Context, batch []*sekizuiv1.Decision) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, batch...)
	return nil
}
func (c *captureSink) all() []*sekizuiv1.Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*sekizuiv1.Decision(nil), c.records...)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, kata.New())
}

// newHarnessWith is newHarness serving the kata targets with `drv` — so a
// test can put a misbehaving driver behind the real enforcement path.
func newHarnessWith(t *testing.T, drv connector.Driver) *harness {
	t.Helper()
	t.Setenv("SEKIZUI_TEST_TOK", "fake-token")

	var doc config.Document
	if err := yaml.Unmarshal([]byte(testConfig), &doc); err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("the test config is invalid: %v", err)
	}

	sink := &captureSink{}
	clock := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	// Region eu, permitting eu only — so kata:beta (us) must be refused.
	profile := runtime.Detect(func(k string) string {
		if k == "SEKIZUI_REGION" {
			return "europe-west1"
		}
		return ""
	}, runtime.Override{})

	return &harness{
		sink:  sink,
		clock: clock,
		srv: New(Config{
			Verifier: identity.NewVerifier(&doc),
			Policy:   policy.NewGrantEngine(&doc, nil),
			Resolver: resolver.New(&doc, profile, []string{"eu"}, config.EnvProvider{}),
			Drivers:  map[string]connector.Driver{kata.Kind: drv},
			// D279: query results are shaped to the connector's schema.
			Payloads: mustPayloads(t, &doc),
			Guards:   anzen.New(doc.Anzen),
			Catalog: catalog.New(catalog.Config{Doc: &doc,
				Drivers: map[string]connector.Driver{kata.Kind: kata.New()},
				Policy:  policy.NewGrantEngine(&doc, nil),
				Guards:  anzen.New(doc.Anzen), Lenses: shin.New(doc.Shin)}),
			Lenses:    shin.New(doc.Shin),
			Recorder:  auditwal.NewRecorder(sink, "test-config", auditwal.WithClock(func() time.Time { return clock })),
			Admission: NewAdmission(8),
			Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
			Now:       func() time.Time { return clock },
		}),
	}
}

// --- mTLS plumbing ----------------------------------------------------------

func callerCtx(t *testing.T, principal string) context.Context {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: principal},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)

	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}},
	})
}

func actingFor(ctx context.Context, subject string) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.Pairs(identity.SubjectHeader, subject))
}

func cmd(action, target string, args map[string]any) *sekizuiv1.ExecuteRequest {
	a, _ := structpb.NewStruct(args)
	return &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
		Action: action, TargetRef: target, Args: a, IdempotencyKey: "ik-1",
	}}
}

// --- P0 exit criterion 1 ----------------------------------------------------

func TestExitCriterion1_CommandTraversesTheFullPath(t *testing.T) {
	h := newHarness(t)

	// The mesh, acting for an agent it may speak for.
	ctx := actingFor(callerCtx(t, "mesh:primary"), "agent:triage")

	resp, err := h.srv.Execute(ctx, cmd("kata.create_issue", "kata:alpha",
		map[string]any{"project": "PROJ", "title": "checkout friction"}))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	res := resp.GetResult()
	if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("status = %v, reason %q", res.GetStatus(), res.GetReason())
	}
	if res.GetDecisionId() == "" {
		t.Error("no decision id returned")
	}

	// TWO records: intent before the side effect, outcome after (§5.2.2).
	records := h.sink.all()
	if len(records) != 2 {
		t.Fatalf("%d decision records, want 2 (intent + outcome)", len(records))
	}
	intent, outcome := records[0], records[1]

	if intent.GetPhase() != sekizuiv1.Phase_PHASE_INTENT {
		t.Errorf("first record phase = %v, want INTENT", intent.GetPhase())
	}
	if intent.GetEffect() != nil {
		t.Error("the intent record carries an effect; nothing had happened yet")
	}
	if outcome.GetPhase() != sekizuiv1.Phase_PHASE_OUTCOME {
		t.Errorf("second record phase = %v, want OUTCOME", outcome.GetPhase())
	}

	// "...naming the matched rule" — the criterion's own words.
	if outcome.GetMatchedRule() == "" {
		t.Error("no matched rule; an unexplainable allow is a log line, not an audit record")
	}
	if !strings.Contains(outcome.GetMatchedRule(), "mesh:primary") ||
		!strings.Contains(outcome.GetMatchedRule(), "agent:triage") {
		t.Errorf("matched_rule = %q; both principals' grants had to agree, so both should appear",
			outcome.GetMatchedRule())
	}

	// The full delegation chain, not just the subject (§5.4).
	chain := outcome.GetIdentity().GetChain()
	if len(chain) != 2 || chain[0] != "mesh:primary" || chain[1] != "agent:triage" {
		t.Errorf("chain = %v, want [mesh:primary agent:triage]", chain)
	}
	if outcome.GetIdentity().GetCaller().GetMethod() != sekizuiv1.AuthMethod_AUTH_METHOD_MTLS {
		t.Error("auth method not recorded as mTLS")
	}

	// The effect joins to the target system's own records.
	if outcome.GetEffect().GetExternalRef() == "" {
		t.Error("no external_ref; the audit trail joins to nothing")
	}
	if !outcome.GetEffect().GetSuccess() {
		t.Errorf("effect reports failure: %q", outcome.GetEffect().GetError())
	}
}

// --- P0 exit criterion 2 ----------------------------------------------------

func TestExitCriterion2_DenialProducesARecord(t *testing.T) {
	h := newHarness(t)
	ctx := callerCtx(t, "agent:triage")

	// Not granted: the agent may create issues, not delete projects... and
	// delete_project is ESCALATE, so use a truly ungranted action instead.
	resp, err := h.srv.Execute(ctx, cmd("kata.comment", "kata:alpha", nil))
	if err != nil {
		t.Fatalf("a denial should return a result, not an error: %v", err)
	}

	res := resp.GetResult()
	if res.GetStatus() != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("status = %v, want DENIED", res.GetStatus())
	}
	if res.GetReason() == "" {
		t.Error("a denial with no reason is unactionable")
	}

	records := h.sink.all()
	if len(records) != 1 {
		t.Fatalf("%d records for a denial, want exactly 1", len(records))
	}
	rec := records[0]

	if rec.GetVerdict() != sekizuiv1.Verdict_VERDICT_DENY {
		t.Errorf("verdict = %v", rec.GetVerdict())
	}
	// OUTCOME, not INTENT — nothing further is coming, and a record left at
	// INTENT would look forever like an action whose result was lost.
	if rec.GetPhase() != sekizuiv1.Phase_PHASE_OUTCOME {
		t.Errorf("phase = %v, want OUTCOME", rec.GetPhase())
	}
	if rec.GetAction() != "kata.comment" || rec.GetTargetRef() != "kata:alpha" {
		t.Error("the record does not say what was attempted")
	}
	if rec.GetIdentity().GetSubject().GetPrincipal() != "agent:triage" {
		t.Error("the record does not say who attempted it")
	}
}

func TestEscalationProducesARecordAndNoSideEffect(t *testing.T) {
	h := newHarness(t)
	ctx := callerCtx(t, "agent:triage")

	resp, err := h.srv.Execute(ctx, cmd("kata.delete_project", "kata:alpha", nil))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_ESCALATED {
		t.Fatalf("status = %v, want ESCALATED", got)
	}

	records := h.sink.all()
	if len(records) != 1 {
		t.Fatalf("%d records, want 1", len(records))
	}
	if records[0].GetVerdict() != sekizuiv1.Verdict_VERDICT_ESCALATE {
		t.Errorf("verdict = %v", records[0].GetVerdict())
	}
	// No intent record means no side effect was attempted.
	if records[0].GetEffect() != nil {
		t.Error("an escalated command produced an effect")
	}
}

// TestConstraintsAreEnforced — `where: {project: [PROJ]}` from the grant.
func TestConstraintsAreEnforced(t *testing.T) {
	h := newHarness(t)
	ctx := callerCtx(t, "agent:triage")

	resp, err := h.srv.Execute(ctx, cmd("kata.create_issue", "kata:alpha",
		map[string]any{"project": "SECRET"}))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Errorf("status = %v, want DENIED — the grant permits only project PROJ", got)
	}
}

// TestUnauthenticatedCallerGetsNoRecord.
//
// Deliberate asymmetry with criterion 2: a DENIAL is recorded because there is a
// principal to attribute it to. A failed IDENTITY has none, so a record would
// say "unknown was refused" — unactionable, and an unauthenticated flood would
// fill the audit log with them.
func TestUnauthenticatedCallerGetsNoRecord(t *testing.T) {
	h := newHarness(t)

	_, err := h.srv.Execute(context.Background(), cmd("kata.create_issue", "kata:alpha", nil))
	if err == nil {
		t.Fatal("a caller with no certificate was served")
	}
	if n := len(h.sink.all()); n != 0 {
		t.Errorf("%d audit records for an unauthenticated request, want 0", n)
	}
}

// TestConfusedDeputyIsRefusedAtTheGateway — §4.4.1, end to end.
func TestConfusedDeputyIsRefusedAtTheGateway(t *testing.T) {
	h := newHarness(t)
	// agent:triage has no may_speak_for at all.
	ctx := actingFor(callerCtx(t, "agent:triage"), "mesh:primary")

	if _, err := h.srv.Execute(ctx, cmd("kata.create_issue", "kata:alpha", nil)); err == nil {
		t.Fatal("an agent impersonated the mesh")
	}
}

// TestResidencyRefusesCrossRegion — §7.1 residency item 2, "refuse to resolve a
// target whose residency conflicts with the instance region, rather than
// discovering it in an audit". Reachable only now that RuntimeProfile carries a
// region.
//
// THE PRINCIPAL IS GRANTED ON THE TARGET, deliberately. A principal without the
// grant is refused by POLICY before the resolver is reached — which proves
// policy works and says nothing about residency. The interesting case is a
// permitted action refused on compliance grounds.
func TestResidencyRefusesCrossRegion(t *testing.T) {
	h := newHarness(t)
	ctx := callerCtx(t, "agent:global")

	// A RESULT, NOT AN ERROR (D135). Residency is §7.1 item 2's guarantee
	// working, so it refuses the way every deliberate refusal does.
	resp, err := h.srv.Execute(ctx, cmd("kata.create_issue", "kata:beta", nil))
	if err != nil {
		t.Fatalf("residency arrived as a transport error (%v); a deliberate refusal "+
			"reaches the caller as a result", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("status = %v — a us-resident target resolved in an eu-only deployment", got)
	}
	if resp.GetResult().GetDecisionId() == "" {
		t.Error("the residency refusal carries no decision id (D124)")
	}

	// THE DISTINCTION IS NOW ONLY IN THE METRIC AND THE RECORD, not in what the
	// caller receives — `Status` collapses denied, unauthenticated and residency
	// into one value on purpose. §7.1 item 2 and D89 both rest on residency
	// being separable from a policy denial ("a grant to review" versus "a
	// deployment topology problem"), so this asserts the place that separation
	// still lives. CONTRACTS §4 item 38 is whether the caller should get it too.
	var scrape bytes.Buffer
	if _, werr := h.srv.Metrics().WriteTo(&scrape); werr != nil {
		t.Fatalf("scraping metrics: %v", werr)
	}
	if got := scrape.String(); !strings.Contains(got, `outcome="residency"`) {
		t.Errorf("no residency series in the metrics; the distinction between a grant "+
			"to review and a deployment topology problem has been lost entirely:\n%s", got)
	}
}

// TestResidencyAllowsMatchingRegion — the check must not refuse everything.
func TestResidencyAllowsMatchingRegion(t *testing.T) {
	h := newHarness(t)
	ctx := callerCtx(t, "agent:triage")

	resp, err := h.srv.Execute(ctx, cmd("kata.create_issue", "kata:alpha",
		map[string]any{"project": "PROJ"}))
	if err != nil {
		t.Fatalf("an eu-resident target was refused in an eu deployment: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Errorf("status = %v", got)
	}
}

// TestDryRunAudits is §4.11.4 item 3's shadow mode: a real record, no effect.
func TestDryRunAudits(t *testing.T) {
	h := newHarness(t)
	ctx := callerCtx(t, "agent:triage")

	req := cmd("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"})
	req.Command.DryRun = true

	resp, err := h.srv.Execute(ctx, req)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED {
		t.Errorf("status = %v, want WOULD_HAVE_FIRED", got)
	}

	records := h.sink.all()
	if len(records) != 1 {
		t.Fatalf("%d records for a dry run, want 1", len(records))
	}
	if records[0].GetVerdict() != sekizuiv1.Verdict_VERDICT_WOULD_HAVE_FIRED {
		t.Errorf("verdict = %v", records[0].GetVerdict())
	}
	if records[0].GetEffect() != nil {
		t.Error("a dry run produced an effect")
	}
}

// TestQueryIsGovernedIdentically — §4.1.1: "an agent running an unbounded scan
// across BigQuery is a data-exfiltration path", so reads carry the same checks.
func TestQueryIsGovernedIdentically(t *testing.T) {
	h := newHarness(t)
	ctx := callerCtx(t, "agent:triage")

	resp, err := h.srv.Query(ctx, &sekizuiv1.QueryRequest{
		Action: "kata.read", TargetRef: "kata:alpha",
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("status = %v", resp.GetStatus())
	}
	if len(h.sink.all()) != 2 {
		t.Errorf("%d records for a read, want 2 — reads are audited like writes", len(h.sink.all()))
	}

	// And a denied read produces a record too.
	h2 := newHarness(t)
	denied, err := h2.srv.Query(callerCtx(t, "agent:triage"), &sekizuiv1.QueryRequest{
		Action: "kata.read", TargetRef: "kata:beta",
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if denied.GetStatus() != sekizuiv1.Status_STATUS_DENIED {
		t.Errorf("status = %v, want DENIED", denied.GetStatus())
	}
	if len(h2.sink.all()) != 1 {
		t.Errorf("%d records for a denied read, want 1", len(h2.sink.all()))
	}
}

// TestErrorsCarryBothTheGRPCCodeAndTheKind.
//
// status.Error() returns a fresh error and would erase the fault.Kind, which is
// invisible over the wire — a client sees only the code — and matters a great
// deal in-process, because the reflex engine calls the enforcement path directly
// from P5 and must distinguish a residency refusal from a rate limit.
func TestErrorsCarryBothTheGRPCCodeAndTheKind(t *testing.T) {
	h := newHarness(t)

	// USES A FAILURE, NOT A REFUSAL. This test is about errors carrying both a
	// gRPC code and a kind, and since D135 a residency refusal is no longer an
	// error at all — deliberate refusals are results. A target that cannot be
	// reached still is an error, and is the right subject for the contract this
	// asserts.
	_, err := h.srv.Execute(callerCtx(t, "agent:triage"),
		cmd("kata.create_issue", "kata:alpha",
			map[string]any{"project": "PROJ", "_fail": "target_unavailable"}))
	if err == nil {
		t.Fatal("expected a failure")
	}

	// The wire contract.
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("error does not carry a gRPC status; a client would see Unknown")
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", st.Code())
	}

	// The in-process contract. The reflex engine calls this path directly (D18,
	// D69) and must be able to tell a target being down from a target refusing,
	// because one is retryable and the other is not.
	if !errors.Is(err, fault.KindTargetUnavailable) {
		t.Errorf("classification lost at the boundary: kind = %v", fault.KindOf(err))
	}
	if !fault.KindOf(err).Retryable() {
		t.Error("an unreachable target reported non-retryable; the caller would give up " +
			"on a condition that clears itself")
	}
}

// TestToStatusCarriesTheDecisionID is D202's remote half.
//
// A gRPC client receives a code and a message and nothing else, so an id
// attached to the error exists for that caller only if it reaches the message.
// Asserted here rather than in the acceptance run because proving it there would
// need a test-only export on this package, and an exported symbol whose only
// caller is a test is what `archcheck` objects to.
func TestToStatusCarriesTheDecisionID(t *testing.T) {
	const id = "01JBQ7XKZ9MOCKDECISIONID"

	err := fault.WithDecisionID(
		fault.New(fault.KindTargetError, "driver.Execute", "the far side returned 500"), id)

	// **TWO SURFACES, AND THE FIRST DRAFT ASSERTED THE WRONG ONE.** `Error()` is
	// the IN-PROCESS view and deliberately returns the original cause verbatim;
	// `GRPCStatus().Message()` is what crosses the wire. An in-process caller
	// reads the id with `fault.DecisionIDOf`, so decorating its message would
	// add noise to the only caller that does not need it.
	wire, ok := toStatus(err).(interface{ GRPCStatus() *status.Status })
	if !ok {
		t.Fatal("toStatus returned something with no gRPC status")
	}
	msg := wire.GRPCStatus().Message()

	if !strings.Contains(msg, id) {
		t.Errorf("the gRPC message does not carry the decision id, so a remote caller "+
			"cannot name the row explaining its own failure: %s", msg)
	}
	// THE CAUSE STILL READS FIRST. An id prepended, or substituted for the
	// message, would make every failure look like a reference number.
	if !strings.HasPrefix(msg, "driver.Execute: target_error: the far side returned 500") {
		t.Errorf("the cause no longer reads first: %s", msg)
	}
	// AND THE IN-PROCESS VIEW IS UNTOUCHED.
	if got := toStatus(err).Error(); strings.Contains(got, id) {
		t.Errorf("the in-process message was decorated too: %s", got)
	}
	// NOTHING IS APPENDED WHEN THERE IS NO ID. A bare `[decision ]` is worse
	// than its absence.
	bare, _ := toStatus(fault.New(fault.KindTargetError, "driver.Execute", "boom")).(interface{ GRPCStatus() *status.Status })
	if strings.Contains(bare.GRPCStatus().Message(), "decision") {
		t.Errorf("an error with no id gained a decision clause: %s",
			bare.GRPCStatus().Message())
	}
}

// mustPayloads is the harness's registry: kata's own schemas and the document's.
func mustPayloads(t *testing.T, doc *config.Document) *schemareg.Registry {
	t.Helper()
	reg, err := schemareg.ForDeployment(doc, map[string]connector.Driver{kata.Kind: kata.New()})
	if err != nil {
		t.Fatalf("the harness's schemas: %v", err)
	}
	return reg
}

// TestAQuarantinedConnectorsTargetsAreRefused is D282 at the gateway: every
// governed verb against a quarantined connector's target is refused, the
// refusal names the connector and why, and it is RECORDED like any other —
// while the rest of the process serves.
func TestAQuarantinedConnectorsTargetsAreRefused(t *testing.T) {
	h := newHarness(t)
	h.srv.quarantined = map[string]string{"kata": `it declares output type "kata.row.v1" and ships NO SCHEMA`}
	ctx := callerCtx(t, "agent:triage")

	_, err := h.srv.Execute(ctx, cmd("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"}))
	if err == nil || !strings.Contains(err.Error(), `connector "kata" is quarantined`) ||
		!strings.Contains(err.Error(), "ships NO SCHEMA") {
		t.Errorf("a command against a quarantined connector: err = %v", err)
	}
	_, err = h.srv.Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
	if err == nil || !strings.Contains(err.Error(), `connector "kata" is quarantined`) {
		t.Errorf("a read against a quarantined connector: err = %v", err)
	}
	var recorded int
	for _, r := range h.sink.all() {
		if strings.Contains(r.GetReason(), "quarantined") {
			recorded++
		}
	}
	if recorded != 2 {
		t.Errorf("%d refusal records name the quarantine; want one per verb (2)", recorded)
	}
	// A SCHEDULED SOURCE of a quarantined connector is skipped, not a boot
	// failure: it is configured correctly and waiting on a fixed connector.
	jobs, err := h.srv.ScheduledJobs(context.Background(),
		[]config.SourceSpec{{TargetRef: "kata:alpha", EverySec: 60, Limit: 10}})
	if err != nil || len(jobs) != 0 {
		t.Errorf("a quarantined connector's scheduled source: %d jobs, err %v; want 0 and no error", len(jobs), err)
	}
}

// leakyKata is kata whose writes return a field its schema does not declare —
// and, when noResult is set, declares its writes as returning nothing at all.
type leakyKata struct {
	*kata.Driver
	noResult bool
	// unregistered declares the writes' result as a type no schema registers.
	unregistered bool
}

func (l leakyKata) Actions() []connector.ActionSpec {
	specs := l.Driver.Actions()
	for i := range specs {
		switch {
		case !specs[i].Mutating:
		case l.noResult:
			specs[i].OutputType, specs[i].NoResult = "", true
		case l.unregistered:
			specs[i].OutputType = "kata.nobody_registered.v1"
		}
	}
	return specs
}

func (l leakyKata) Execute(ctx context.Context, t connector.Target, action string, args map[string]any,
	idem connector.Idempotency) (connector.Result, error) {
	res, err := l.Driver.Execute(ctx, t, action, args, idem)
	if res.Data != nil {
		res.Data["leaked_email"] = "someone@example.invalid"
	}
	return res, err
}

// TestAWriteResultIsShapedBeforeItIsRecordedOrReturned is D283 end to end: a
// write's result used to reach the fsynced audit record and the caller exactly
// as the driver returned it. Now an undeclared field is stripped from both, and
// a NoResult action's data is withheld from both.
func TestAWriteResultIsShapedBeforeItIsRecordedOrReturned(t *testing.T) {
	for name, c := range map[string]struct {
		drv       leakyKata
		wantEmpty bool
	}{
		"declared type, undeclared field": {leakyKata{Driver: kata.New()}, false},
		"NoResult":                        {leakyKata{Driver: kata.New(), noResult: true}, true},
		// Shape passes an unregistered type through for a validator to refuse,
		// and a result has no validator after it — so it must be withheld.
		"an unregistered type": {leakyKata{Driver: kata.New(), unregistered: true}, true},
	} {
		h := newHarnessWith(t, c.drv)
		resp, err := h.srv.Execute(callerCtx(t, "agent:triage"),
			cmd("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"}))
		if err != nil || resp.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("%s: %v %v", name, err, resp.GetResult().GetStatus())
		}
		for _, r := range h.sink.all() {
			detail := r.GetEffect().GetDetail().AsMap()
			if _, leaked := detail["leaked_email"]; leaked {
				t.Errorf("%s: the audit record carries a field no schema declares: %v", name, detail)
			}
			if r.GetPhase() == sekizuiv1.Phase_PHASE_OUTCOME {
				if c.wantEmpty && len(detail) != 0 {
					t.Errorf("%s: data that must be withheld reached the record: %v", name, detail)
				}
				if !c.wantEmpty && detail["action"] != "kata.create_issue" {
					t.Errorf("%s: the declared fields were lost: %v", name, detail)
				}
			}
		}
	}
}

// TestPriceResultCoversEveryShape is D283's pricing, one row per branch: a
// declared maximum is enforced, a grant too small for one result is refused, a
// default is lowered through the action's argument, an explicit request that
// does not fit is refused naming what would, and a read with no argument to ask
// for fewer is refused rather than silently cut.
func TestPriceResultCoversEveryShape(t *testing.T) {
	per := uint64(safestruct.DefaultBudget)
	bounded := connector.ActionSpec{Bound: &connector.ResultBound{MaxRows: 200, Arg: "n", Default: 50}}
	fixed := connector.ActionSpec{Bound: &connector.ResultBound{MaxRows: 10}}
	for name, c := range map[string]struct {
		spec      connector.ActionSpec
		args      map[string]any
		maxBytes  uint64
		wantRows  int
		wantClamp bool
		wantErr   string
	}{
		"uncapped default":       {bounded, nil, 0, 50, false, ""},
		"over the declared max":  {bounded, map[string]any{"n": 500.0}, 0, 0, false, "returns at most 200"},
		"one object, no budget":  {connector.ActionSpec{}, nil, per - 1, 0, false, "cannot pay for a single result"},
		"one object fits":        {connector.ActionSpec{}, nil, per, 1, false, ""},
		"default lowered to fit": {bounded, nil, 3 * per, 3, true, ""},
		"explicit over budget":   {bounded, map[string]any{"n": 50.0}, 3 * per, 0, false, "which fits 3"},
		"explicit fits":          {bounded, map[string]any{"n": 2.0}, 3 * per, 2, false, ""},
		"no argument to lower":   {fixed, nil, 3 * per, 0, false, "offers no argument to ask for fewer"},
	} {
		rows, clamped, err := priceResult("op", "a", "t", c.spec, c.args, c.maxBytes)
		switch {
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: err = %v; want %q", name, err, c.wantErr)
		case c.wantErr == "" && (err != nil || rows != c.wantRows || clamped != c.wantClamp):
			t.Errorf("%s: rows %d clamped %v err %v; want %d %v", name, rows, clamped, err, c.wantRows, c.wantClamp)
		}
	}
}
