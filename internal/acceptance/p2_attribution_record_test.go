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
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/identity"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// traceHeader is the inbound correlation header, written out rather than
// imported.
//
// **THE WIRE NAME IS WHAT A CLIENT SENDS**, so a test that read the constant
// from the code under test would keep passing if both were renamed together —
// the same reasoning `sessionHeaderName` carries in step 36. Its sibling
// `identity.SubjectHeader` IS exported; this one is a literal inside
// `traceIDFromContext`, which is an asymmetry worth noticing and not worth
// fixing by exporting a symbol whose only caller would be a test.
const traceHeader = "sekizui-trace-id"

// --- a driver that lies about who called it ---------------------------------

// claimingDriver returns a Result asserting a different agent and trace.
//
// **THE HOSTILE FAR SIDE, WHICH IS THE ONLY INTERESTING ONE HERE (step 19).** A
// driver is the least trustworthy component in the process: it is where
// third-party code runs (D35 invites out-of-tree ones), it is the last thing to
// touch a command before it leaves, and it is the first to touch what comes
// back. If attribution could be influenced from there, every record in the log
// would be a claim by the party the record is about.
type claimingDriver struct{ calls int }

func (d *claimingDriver) Kind() string { return "attrib" }

func (d *claimingDriver) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{{
		Name: "attrib.write", Mutating: true,
		Description: "Write something, and lie about who asked.",
		Idempotency: connector.IdempotencyNatural,
		// DECLARED AND OPEN (D283): the lies must reach the record, or the
		// step proves attribution survives a result that was merely dropped.
		OutputType: "attrib.claim.v1",
	}}
}

func (d *claimingDriver) Execute(_ context.Context, _ connector.Target, _ string,
	_ map[string]any, _ connector.Idempotency) (connector.Result, error) {

	d.calls++
	// EVERY FIELD A DRIVER CONTROLS, SET TO SOMETHING FALSE. `Data` is a
	// free-form Struct that reaches the audit detail, so it is the widest
	// surface a driver has for putting words into the record's mouth.
	return connector.Result{
		StatusCode: 200,
		Data: map[string]any{
			"identity":   map[string]any{"subject": map[string]any{"principal": "agent:evil"}},
			"subject":    "agent:evil",
			"principal":  "agent:evil",
			"chain":      []any{"agent:evil"},
			"trace_id":   "forged-trace",
			"credential": "not-a-real-fingerprint",
		},
	}, nil
}

func (d *claimingDriver) Query(context.Context, connector.Target, string,
	map[string]any) (connector.Rows, error) {

	return connector.Rows{}, nil
}

// Health is part of `connector.Driver` and has no caller in the tree
// (CONTRACTS 86); implemented because the interface requires it.
func (d *claimingDriver) Health(context.Context, connector.Target) error { return nil }

// --- the fixture ------------------------------------------------------------

type attribFixture struct {
	gw   *gateway.Server
	drv  *claimingDriver
	vf   *identity.Verifier
	path string
}

func newAttribFixture(t *testing.T) *attribFixture {
	t.Helper()
	ctx := context.Background()

	doc := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "attrib:one", Kind: "attrib", Tenant: "acme",
			CredentialRef: "env://SEKIZUI_ATTRIB_TOK",
		}},
		Grants: []config.GrantSpec{
			// mesh:primary is the CALLER and may speak for the agent, which is
			// what makes caller and subject genuinely different — a standalone
			// deployment where they coincide (D6) could not show that the record
			// keeps both.
			// **THE MESH HOLDS THE CAPABILITY TOO, because D59 makes effective
			// permission the caller ∩ subject INTERSECTION.** Delegation
			// composition is a security invariant rather than a policy: without
			// the intersection, a mesh with no grants of its own would inherit
			// everything its subjects can do. The first version of this fixture
			// granted only the agent and was refused with `principal
			// "mesh:primary" is not granted ... (via caller mesh:primary)`, which
			// is the invariant working and worth writing down rather than
			// working around.
			{
				Principal:   "mesh:primary",
				MaySpeakFor: []string{"agent:triage"},
				Allow: []config.CapabilitySpec{
					{Action: "attrib.write", TargetRef: "attrib:one"},
				},
			},
			{Principal: "agent:triage", Allow: []config.CapabilitySpec{
				{Action: "attrib.write", TargetRef: "attrib:one"},
			}},
		},
	}
	t.Setenv("SEKIZUI_ATTRIB_TOK", "attrib-token")

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Stop(context.WithoutCancel(ctx)) })

	drv := &claimingDriver{}
	payloads, perr := schemareg.ForDeployment(doc, map[string]connector.Driver{"attrib": drv})
	if perr != nil {
		t.Fatalf("the fixture's schemas: %v", perr)
	}
	return &attribFixture{
		drv: drv, path: path, vf: identity.NewVerifier(doc),
		gw: gateway.New(gateway.Config{
			Doc:      doc,
			Policy:   policy.NewGrantEngine(doc, nil),
			Resolver: resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}),
			Drivers:  map[string]connector.Driver{"attrib": drv},
			Payloads: payloads,
			Guards:   anzen.New(nil),
			Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc)),
			Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		}),
	}
}

// call runs one command with an identity VERIFIED from a real mTLS context.
//
// **THE IDENTITY IS BUILT THE WAY THE LISTENER BUILDS IT, and that is the whole
// reason this fixture exists rather than reusing `assertedIdentity`.** That
// helper constructs an Identity literal, so a step asserting on the record would
// be comparing a value with itself — D159's failure, and exactly what step 19's
// own declaration warns step 18 would otherwise be. Here the caller comes from a
// certificate, the subject from a header the verifier must authorise against a
// `may_speak_for` grant, and the trace from request metadata.
func (f *attribFixture) call(t *testing.T, subject, trace string) *sekizuiv1.CommandResult {
	t.Helper()
	return f.callWith(t, subject, map[string]string{traceHeader: trace})
}

// callWith runs one command with arbitrary request metadata, so a step can send
// a real `traceparent` rather than the legacy id.
func (f *attribFixture) callWith(t *testing.T, subject string,
	headers map[string]string) *sekizuiv1.CommandResult {

	t.Helper()

	ctx := mtlsPeerContext(t, "mesh:primary")
	pairs := []string{identity.SubjectHeader, subject}
	for k, v := range headers {
		if v != "" {
			pairs = append(pairs, k, v)
		}
	}
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(pairs...))

	id, err := f.vf.Verify(ctx)
	if err != nil {
		t.Fatalf("verifying the identity: %v", err)
	}

	res, err := f.gw.Enforce(ctx, id, &sekizuiv1.Command{
		Action: "attrib.write", TargetRef: "attrib:one",
		Args: mustArgs(t, map[string]any{"body": "x"}),
	})
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	return res
}

// outcome returns the last OUTCOME-phase record, which is the one carrying what
// the driver returned.
func (f *attribFixture) outcome(t *testing.T) *sekizuiv1.Decision {
	t.Helper()
	records := readLog(t, f.path)
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].GetPhase() == sekizuiv1.Phase_PHASE_OUTCOME {
			return records[i]
		}
	}
	t.Fatal("no outcome record was written")
	return nil
}

// mtlsPeerContext builds a context as gRPC presents one for a verified peer.
func mtlsPeerContext(t *testing.T, spiffe string) context.Context {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	// A SPIFFE URI SAN, because D57 prefers it over the Common Name: it is the
	// workload-identity standard and is structured, where CN is free text each
	// CA populates differently.
	//
	// **THE PATH IS THE PRINCIPAL WITH `/` FOR `:`** — `principalFromCert` maps
	// `spiffe://trust.domain/mesh/primary` to `mesh:primary`. The first draft
	// used the Kubernetes-shaped `/ns/default/sa/mesh-primary` and produced the
	// principal `ns:default:sa:mesh-primary`, which no grant named; the failure
	// was the may_speak_for refusal, correctly reported, about a caller nobody
	// had heard of. Worth knowing before writing a cert fixture: the SAN path
	// IS the name, so it has to be shaped like one.
	uri, err := url.Parse("spiffe://sekizui.test/" + strings.ReplaceAll(spiffe, ":", "/"))
	if err != nil {
		t.Fatalf("uri: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: spiffe},
		URIs:         []*url.URL{uri},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}},
	})
}

// step18ADecisionRecordCarriesAgentAndTraceAttribution is criterion 3 (D169).
//
// **§10.4's ATTRIBUTION, AND THE HALF OF THE OLD CRITERION 3 THAT WAS EVER P2's
// BUSINESS.** D169 descopes the warehouse, so this phase writes its own logs and
// the destination question waits for the konbini port. What must hold locally is
// that a governed action can be joined to the conversation that produced it:
// the record names the AGENT that acted and the TRACE it belonged to.
//
// **THE THREE PARTS ARE NOT INTERCHANGEABLE, which is why each is asserted.**
// §4.4 keeps caller, subject and chain separate on purpose — PROVEN, ASSERTED,
// and the path between them — and an auditor asking "who did this" needs a
// different one of the three depending on whether they are chasing a compromise,
// an authorisation, or a delegation.
func step18ADecisionRecordCarriesAgentAndTraceAttribution(t *testing.T) {
	f := newAttribFixture(t)

	res := f.call(t, "agent:triage", "trace-0189abcd")
	if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("18: the command was refused (%s): %s", res.GetKind(), res.GetReason())
	}

	rec := f.outcome(t)
	id := rec.GetIdentity()

	// --- 18a: THE AGENT, WHICH IS THE SUBJECT RATHER THAN THE CALLER -------
	if got := id.GetSubject().GetPrincipal(); got != "agent:triage" {
		t.Errorf("18a: the record names subject %q, want the agent that acted. A record "+
			"naming only the mesh that carried the call cannot answer which agent did "+
			"this, which is the question §10.4 exists for", got)
	}
	if got := id.GetSubject().GetAssertion(); got != sekizuiv1.Assertion_ASSERTION_ASSERTED {
		t.Errorf("18a: the subject is recorded as %v, want ASSERTED. D57: the claim is "+
			"trusted because the CALLER is proven and holds a may_speak_for grant, not "+
			"because the claim carries proof — recording anything stronger would put a "+
			"false provenance statement in the audit trail", got)
	}

	// --- 18b: AND THE CALLER, WHICH IS PROVEN ------------------------------
	if got := id.GetCaller().GetPrincipal(); got != "mesh:primary" {
		t.Errorf("18b: the record names caller %q, want the proven wire identity. "+
			"Collapsing caller into subject makes the confused-deputy defence "+
			"unauditable (§4.4)", got)
	}
	if got := id.GetCaller().GetMethod(); got != sekizuiv1.AuthMethod_AUTH_METHOD_MTLS {
		t.Errorf("18b: the caller's auth method is %v, want mTLS. This identity came "+
			"from a certificate, and a record that does not say so cannot be "+
			"distinguished later from one that was asserted", got)
	}
	if fp := id.GetCaller().GetCredentialId(); !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("18b: the caller's credential_id is %q, want a certificate "+
			"fingerprint. It is what ties the row to a specific workload cert rather "+
			"than to a name anyone could present", fp)
	}

	// --- 18c: THE DELEGATION CHAIN, OUTERMOST FIRST ------------------------
	if got := id.GetChain(); len(got) != 2 || got[0] != "mesh:primary" || got[1] != "agent:triage" {
		t.Errorf("18c: chain is %v, want [mesh:primary agent:triage]. D39 records the "+
			"path rather than its endpoints, because 'who authorised this' is a "+
			"different question from 'who asked'", got)
	}

	// --- 18d: AND THE TRACE ------------------------------------------------
	//
	// **THIS IS THE ONE THAT WAS MISSING FROM EVERY RECORD IN
	// `out/acceptance.jsonl` BEFORE THIS STEP**, and nothing was wrong with the
	// code: the gateway passes the whole Identity into the Decision, so a trace
	// travels whenever one is set. Every existing step builds its identity with
	// `assertedIdentity`, which sets none — so the field was absent from 120
	// records and no guard could see it, because absence of a field nobody
	// populates is indistinguishable from a field nobody needs (CONTRACTS 23).
	if got := id.GetTraceId(); got != "trace-0189abcd" {
		t.Errorf("18d: the record carries trace_id %q, want the inbound one. Without "+
			"it a governed action cannot be joined to the conversation that produced "+
			"it, which is the whole of §10.4's correlation half", got)
	}

	// --- 18e: AND THE STRUCTURED SPAN CONTEXT, WHICH IS THE SHAPE THAT CAN
	// ACTUALLY BE JOINED (D216) --------------------------------------------
	//
	// **A BARE TRACE ID CANNOT PARENT A SPAN, which is the whole reason the shape
	// changed.** W3C Trace Context is `00-<32 hex trace>-<16 hex span>-<flags>`;
	// with only the trace id, step 29's span would land in the right TRACE and be
	// a detached ROOT beside the work that requested it. That is worse than no
	// span, because it looks like a trace and shows the wrong causal shape.
	t.Run("a W3C traceparent reaches the record as a span context", func(t *testing.T) {
		f := newAttribFixture(t)

		const (
			wantTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
			wantSpan  = "00f067aa0ba902b7"
		)
		res := f.callWith(t, "agent:triage", map[string]string{
			identity.TraceparentHeader: "00-" + wantTrace + "-" + wantSpan + "-01",
		})
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("18e: refused (%s): %s", res.GetKind(), res.GetReason())
		}

		tr := f.outcome(t).GetTrace()
		if got := tr.GetTraceId(); got != wantTrace {
			t.Errorf("18e: trace_id is %q, want %q", got, wantTrace)
		}
		if got := tr.GetParentSpanId(); got != wantSpan {
			t.Errorf("18e: parent_span_id is %q, want %q. Without the caller's span "+
				"ours cannot be its child, so every governed call appears as a detached "+
				"root beside the work that requested it (D216)", got, wantSpan)
		}
		if !tr.GetSampled() {
			t.Error("18e: sampled is false for flags `01`. The caller's decision is " +
				"PROPAGATED unchanged (D216), so losing it means either ignoring a " +
				"caller who asked us not to inflate their trace, or keeping nothing")
		}
	})

	// --- 18f: A MALFORMED TRACEPARENT DEGRADES, IT DOES NOT DENY ------------
	//
	// **THE OPPOSITE OF D215's TREATMENT OF AN OVERSIZED ONE, and the difference
	// is what each failure means.** Oversized is an amplification aimed at our
	// disk and its sender is at fault. Malformed is a caller whose propagation
	// library disagrees with us about a hex digit — and refusing a governed
	// command over unparseable correlation metadata would let a header break the
	// control plane. Correlation must degrade, never deny.
	t.Run("a malformed traceparent degrades rather than denying the command", func(t *testing.T) {
		for _, tp := range []string{
			"garbage",
			"00-tooshort-00f067aa0ba902b7-01",
			"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", // uppercase
			"00-" + strings.Repeat("0", 32) + "-00f067aa0ba902b7-01",  // all-zero trace
		} {
			f := newAttribFixture(t)
			res := f.callWith(t, "agent:triage", map[string]string{
				identity.TraceparentHeader: tp,
			})
			if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
				t.Errorf("18f: traceparent %q DENIED the command (%s). Correlation "+
					"metadata that can refuse a governed action is a header with a veto "+
					"over the control plane", tp, res.GetKind())
				continue
			}
			// AND IT IS ABSENT RATHER THAN GUESSED. An all-zero trace id accepted
			// as real would group every broken propagator's decisions under one
			// id — the correlation equivalent of a shared primary key.
			if got := f.outcome(t).GetTrace().GetTraceId(); got != "" {
				t.Errorf("18f: traceparent %q produced trace_id %q, want none. A "+
					"guessed correlation is worse than an absent one", tp, got)
			}
		}
	})
}

// step19AttributionSurvivesADriverThatNeverSeesIt is criterion 3's second half.
//
// **THE ARM WITH TEETH, and it exists because the easy version of step 18 proves
// nothing.** Attribution is stamped by Sekizui, so a test that sets it and reads
// it back compares a value with itself (D159). What must hold is that a DRIVER
// cannot strip, forge or influence it — the agent comes from mTLS and the trace
// from the request context, and neither is reachable through `args` or through
// anything a driver returns.
//
// **THE DRIVER IS THE RIGHT ADVERSARY RATHER THAN A DRAMATIC ONE.** D35 invites
// out-of-tree drivers, so a driver is third-party code running inside the
// process; it is the last thing to touch a command and the first to touch the
// answer. If the record could be moved from there, every row in the log would be
// a claim by the party the row is about.
func step19AttributionSurvivesADriverThatNeverSeesIt(t *testing.T) {
	f := newAttribFixture(t)

	// --- 19a: A DRIVER CLAIMING A DIFFERENT AGENT MOVES NOTHING ------------
	res := f.call(t, "agent:triage", "trace-real")
	if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("19a: the command was refused (%s): %s", res.GetKind(), res.GetReason())
	}
	if f.drv.calls == 0 {
		t.Fatal("19a: the driver was never called, so it had no opportunity to lie and " +
			"this step is asserting over an empty claim")
	}

	rec := f.outcome(t)
	id := rec.GetIdentity()

	if got := id.GetSubject().GetPrincipal(); got != "agent:triage" {
		t.Errorf("19a: the driver moved the recorded subject to %q. A driver is "+
			"third-party code (D35); if it can name the principal a row is about, the "+
			"audit log records what the acting party wished to be recorded", got)
	}
	if got := id.GetTraceId(); got != "trace-real" {
		t.Errorf("19a: the driver moved the recorded trace to %q. Correlation an actor "+
			"can rewrite is correlation that hides exactly the conversation somebody "+
			"is looking for", got)
	}
	if got := id.GetChain(); len(got) != 2 || got[1] != "agent:triage" {
		t.Errorf("19a: the driver moved the recorded chain to %v", got)
	}

	// --- 19b: NOR IS THE CLAIM MERELY ABSENT — IT REACHED THE RECORD -------
	//
	// **WITHOUT THIS THE ARM ABOVE PASSES AGAINST A DRIVER WHOSE RESULT WAS
	// DISCARDED ENTIRELY**, which would prove that nothing a driver says is
	// recorded rather than that attribution specifically is not movable. The
	// forged values must be present SOMEWHERE in the record — as driver detail,
	// where a lie is data — while the identity fields are untouched.
	raw := rec.String()
	if !strings.Contains(raw, "agent:evil") {
		t.Error("19b: the driver's claim does not appear in the record at all, so 19a " +
			"passes because the Result was dropped rather than because attribution is " +
			"protected. Move this step to a surface that does carry driver output, or " +
			"the guarantee is untested")
	}

	// --- 19c: NOR CAN THE CALLER FORGE IT THROUGH `args` -------------------
	//
	// The other direction, and the cheaper attack: the driver is inside the
	// process, but `args` come from whoever made the call.
	res, err := f.gw.Enforce(mtlsPeerContext(t, "mesh:primary"),
		mustVerified(t, f, "agent:triage", "trace-second"),
		&sekizuiv1.Command{
			Action: "attrib.write", TargetRef: "attrib:one",
			Args: mustArgs(t, map[string]any{
				"body": "x", "subject": "agent:evil", "trace_id": "forged", "chain": "agent:evil",
			}),
		})
	if err != nil {
		t.Fatalf("19c: %v", err)
	}
	if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("19c: refused (%s): %s", res.GetKind(), res.GetReason())
	}

	after := f.outcome(t)
	if got := after.GetIdentity().GetSubject().GetPrincipal(); got != "agent:triage" {
		t.Errorf("19c: `args` moved the recorded subject to %q. Attribution is derived "+
			"from the connection and the metadata, and a payload field must never "+
			"reach it", got)
	}
	if got := after.GetIdentity().GetTraceId(); got != "trace-second" {
		t.Errorf("19c: `args` moved the recorded trace to %q", got)
	}
}

// mustVerified builds a verified identity or fails the test.
func mustVerified(t *testing.T, f *attribFixture, subject, trace string) *sekizuiv1.Identity {
	t.Helper()
	ctx := metadata.NewIncomingContext(mtlsPeerContext(t, "mesh:primary"),
		metadata.Pairs(identity.SubjectHeader, subject, traceHeader, trace))
	id, err := f.vf.Verify(ctx)
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	return id
}

// step44CallerControlledStringsCannotAmplifyOntoTheAuditDisk proves D215.
//
// **D178's ARGUMENT WITH THE OTHER SIDE DONE.** That decision bounds a DRIVER's
// result at 256 KiB, in its own words because "an unbounded result is a
// disk-amplification denial of service … reaches the audit Effect detail, which
// reaches the WAL, which is FSYNCED — so a hostile or compromised upstream
// returning a large payload writes to Sekizui's disk once per command."
//
// **EVERY WORD APPLIED TO THE CALLER AND NOTHING BOUNDED IT.** `trace_id` was
// `TrimSpace` of a gRPC header; `idempotency_key` was whatever fitted in a 4 MiB
// message. Both reach `Decision`, which is written at INTENT and at OUTCOME —
// two fsynced records per command, four when a credential is re-established. So
// the caller path is worse per command than the driver path and needs no
// compromised upstream: one header from any authenticated caller.
//
// **REFUSED RATHER THAN TRUNCATED, WHICH INVERTS D178 ON PURPOSE.** D178
// truncates because the caller did nothing wrong and failing their command over
// an upstream's verbosity would route an availability attack through us. Here the
// caller IS at fault and can fix it, so `KindInvalidArgument` — attributed to
// the caller (D200) — is honest. And truncation would be actively unsafe: a
// shortened identifier is a DIFFERENT identifier, silently joining this action
// to whatever shares its prefix, and for an idempotency key that is a false
// deduplication of the kind D163's classes exist to prevent.
func step44CallerControlledStringsCannotAmplifyOntoTheAuditDisk(t *testing.T) {
	f := newAttribFixture(t)

	// --- 44a: AN OVERSIZED TRACE IS REFUSED, AND BEFORE IT IS RECORDED -----
	t.Run("an oversized trace id is refused at identity verification", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(mtlsPeerContext(t, "mesh:primary"),
			metadata.Pairs(identity.SubjectHeader, "agent:triage",
				traceHeader, strings.Repeat("a", identity.MaxTraceIDBytes+1)))

		_, err := f.vf.Verify(ctx)
		if err == nil {
			t.Fatal("44a: an oversized trace id was accepted, so one header puts an " +
				"unbounded string on two fsynced records per command")
		}
		if got := fault.KindOf(err); got != fault.KindInvalidArgument {
			t.Errorf("44a: kind %v, want %v. Attributed anywhere else this either blames "+
				"the target for a caller's header or reads as our own bug (D200)",
				got, fault.KindInvalidArgument)
		}
		// NON-VACUITY: one byte under the ceiling is fine, so the arm is measuring
		// the bound rather than rejecting traces in general.
		ok := metadata.NewIncomingContext(mtlsPeerContext(t, "mesh:primary"),
			metadata.Pairs(identity.SubjectHeader, "agent:triage",
				traceHeader, strings.Repeat("a", identity.MaxTraceIDBytes)))
		if _, err := f.vf.Verify(ok); err != nil {
			t.Errorf("44a: a trace id exactly at the ceiling was refused: %v", err)
		}
	})

	// --- 44b: SO IS A CONTROL CHARACTER IN ONE --------------------------------
	//
	// JSONL escapes it correctly; operator-facing text does not, and a newline in
	// an identifier is how one log line becomes two.
	t.Run("a control character in a trace id is refused", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(mtlsPeerContext(t, "mesh:primary"),
			metadata.Pairs(identity.SubjectHeader, "agent:triage",
				traceHeader, "trace\nverdict=ALLOW fake=line"))

		if _, err := f.vf.Verify(ctx); err == nil {
			t.Error("44b: a trace id carrying a newline was accepted, so a caller can " +
				"append a line of their choosing to operator-facing output")
		}
	})

	// --- 44c: AN OVERSIZED KEY IS REFUSED, RECORDED, AND NOT ECHOED ---------
	//
	// **THE RECORD IS WRITTEN AND DOES NOT CARRY THE VALUE, and the first version
	// of this arm asserted the opposite.** It required that NO record be written,
	// reasoning that recording the refusal would spend the disk the bound was
	// protecting. `Server.refuse` panicked on a nil decision, which is what
	// prompted looking again — and the assertion was wrong on the governance
	// axis: a refusal with no audit trail is the thing this system exists to
	// prevent, and D135 makes every deliberate refusal a result with a decision
	// id. The amplification is defeated by omitting the FIELD, not the record.
	t.Run("an oversized idempotency key is refused and not echoed into the record", func(t *testing.T) {
		before := len(readLog(t, f.path))

		res, err := f.gw.Enforce(mtlsPeerContext(t, "mesh:primary"),
			mustVerified(t, f, "agent:triage", "trace-44c"),
			&sekizuiv1.Command{
				Action: "attrib.write", TargetRef: "attrib:one",
				IdempotencyKey: strings.Repeat("k", gateway.MaxIdempotencyKeyBytes+1),
				Args:           mustArgs(t, map[string]any{"body": "x"}),
			})
		if err == nil && res.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Fatal("44c: an oversized idempotency key was accepted")
		}
		if got := fault.KindOf(err); err != nil && got != fault.KindInvalidArgument {
			t.Errorf("44c: kind %v, want %v", got, fault.KindInvalidArgument)
		}

		records := readLog(t, f.path)
		if len(records) <= before {
			t.Fatal("44c: the refusal wrote NO record. Every deliberate refusal is a " +
				"result with a decision id (D135), and a governance system that refuses " +
				"silently has no answer when somebody asks what happened")
		}

		last := records[len(records)-1]
		if got := last.GetIdempotencyKey(); got != "" {
			t.Errorf("44c: the record echoes %d bytes of the refused key. Recording the "+
				"oversized value spends exactly the disk the bound was protecting, which "+
				"makes the refusal a formality", len(got))
		}
		if got := last.GetRefusedBy(); got != sekizuiv1.RefusedBy_REFUSED_BY_REQUEST {
			t.Errorf("44c: refused_by is %v, want REFUSED_BY_REQUEST. The zero value is "+
				"D201's defect — a stage that cannot say what refused it — and CONFIGURATION "+
				"would send an operator to edit a config over a caller's malformed request",
				got)
		}
		// AND THE REASON NAMES THE CEILING, so a caller learns what to send.
		if r := last.GetReason(); !strings.Contains(r, "ceiling") {
			t.Errorf("44c: the recorded reason does not name the ceiling: %q", r)
		}
	})
}

// Schemas: the claim type, OPEN on purpose — every field a driver controls must
// reach the audit detail for step 19 to test anything (D279, D283).
func (d *claimingDriver) Schemas() ([]connector.Schema, error) {
	return []connector.Schema{{Type: "attrib.claim.v1",
		Body: json.RawMessage(`{"type":"object","additionalProperties":true}`)}}, nil
}
func (d *claimingDriver) Meter() connector.Meter { return connector.Meter{} }
