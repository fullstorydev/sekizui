// Package identity establishes who is asking, on whose behalf, and what the
// two of them may do together.
//
// PRIVATE (D35). The three questions §4.4 separates, deliberately not collapsed:
//
//	CALLER   — proven, from the verified mTLS peer certificate. Never a payload
//	           field, because a payload field can be lied about (CONTRACTS §2.2).
//	SUBJECT  — CLAIMED, in metadata, and therefore checked against the caller's
//	           may_speak_for grant. This check is the confused-deputy defence.
//	CHAIN    — the delegation path, recorded on every Decision (D39).
//
// D6 says there is ONE model: standalone is a chain of length 1, not a second
// code path. §9.7 rejected two modes precisely because branching in the enforcer
// on "which world are we in" is where authorisation bugs live.
//
// DESIGN.md references: §4.4, §4.4.1, §4.4.2, §4.4.3, D6, D7, D18, D37.
package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/fullstorydev/sekizui/internal/signedsubject"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// SubjectHeader is the metadata key carrying the claimed subject.
//
// Lowercase because gRPC normalises metadata keys to lowercase; using
// "Sekizui-Subject" here would silently never match.
const SubjectHeader = "sekizui-subject"

// Verifier turns a request context into a verified Identity.
type Verifier struct {
	// grants is the may_speak_for relation, principal -> set of principals it
	// may act for. Rebuilt whenever configuration is (re)loaded.
	grants map[string]map[string]bool

	// signedState is tier two (D303, D318): pinned issuers, roles, lenses.
	signedState
}

// NewVerifier builds a Verifier from a validated configuration document.
//
// Takes the Document rather than a config.Loader so it is trivially testable and
// so the dependency runs one way: identity reads configuration, configuration
// knows nothing about identity.
func NewVerifier(doc *config.Document, opts ...Option) *Verifier {
	v := &Verifier{grants: make(map[string]map[string]bool, len(doc.Grants))}
	for _, o := range opts {
		o(v)
	}
	v.initSigned(doc)

	for _, g := range doc.Grants {
		if len(g.MaySpeakFor) == 0 {
			continue
		}
		set := make(map[string]bool, len(g.MaySpeakFor))
		for _, p := range g.MaySpeakFor {
			set[p] = true
		}
		v.grants[g.Principal] = set
	}
	return v
}

// Verify establishes the Identity for an incoming request.
//
// Returns the protobuf Identity directly rather than an internal struct: it is
// embedded whole into every Decision (D39), and a parallel internal type would
// be one more thing to keep in sync for no gain.
func (v *Verifier) Verify(ctx context.Context) (*sekizuiv1.Identity, error) {
	const op = "identity.Verify"

	caller, err := CallerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// TIER TWO WHEN A TOKEN IS PRESENTED (D303, D318): the token names the
	// subject, the connection still proves the caller, and binding ties the
	// two together. Otherwise tier one: asserted, checked against may_speak_for.
	var subject *sekizuiv1.Subject
	if token := firstMetadataValue(ctx, SubjectTokenHeader); token != "" {
		thumb, terr := peerThumbprint(ctx)
		if terr != nil {
			return nil, terr
		}
		subject, err = v.signedSubject(ctx, caller, token, firstMetadataValue(ctx, SubjectHeader), thumb)
	} else {
		subject, err = v.subjectFromContext(ctx, caller.Principal)
	}
	if err != nil {
		return nil, err
	}

	// **THE TRACE IS CHECKED BEFORE IT IS RECORDED, not after (D215).** This is
	// the one place every verified identity passes through, which is why the
	// check lives here rather than in `Execute`: `Enforce` has three callers and
	// a check at one of them is the drift D18 exists to prevent.
	trace := traceIDFromContext(ctx)
	if err := refuseUnusableTrace(op, trace); err != nil {
		return nil, err
	}

	// Chain is outermost first. Standalone — caller acting as itself — is a
	// chain of ONE, not an empty chain and not a special case (D6).
	chain := []string{caller.Principal}
	if subject.Principal != caller.Principal {
		chain = append(chain, subject.Principal)
	}

	return &sekizuiv1.Identity{
		Caller:  caller,
		Subject: subject,
		Chain:   chain,
		TraceId: trace,
	}, nil
}

// CallerFromContext extracts the proven caller from the verified TLS peer.
//
// THIS IS THE ONLY SOURCE OF CALLER IDENTITY. There is deliberately no path that
// reads it from a header or a request field, because anything a client can write
// is something a compromised client can forge — and the entire delegation model
// rests on the caller being proven rather than claimed.
func CallerFromContext(ctx context.Context) (*sekizuiv1.Caller, error) {
	const op = "identity.CallerFromContext"

	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fault.New(fault.KindUnauthenticated, op, "no peer information on the request")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fault.New(fault.KindUnauthenticated, op,
			"connection is not mTLS; caller identity cannot be established")
	}

	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil, fault.New(fault.KindUnauthenticated, op,
			"no client certificate presented")
	}
	cert := certs[0]

	principal, err := principalFromCert(cert)
	if err != nil {
		return nil, err
	}

	return &sekizuiv1.Caller{
		Principal: principal,
		Method:    sekizuiv1.AuthMethod_AUTH_METHOD_MTLS,
		// Fingerprint, not the certificate: enough to correlate an audit row
		// with a specific credential, and worthless to anyone who steals the
		// log. Never a secret, per the field's contract.
		CredentialId: fingerprint(cert),
	}, nil
}

// principalFromCert derives the principal name from a client certificate.
//
// PREFERS A SPIFFE URI SAN over the Common Name. SPIFFE IDs are the workload
// identity standard §4.4 assumes, they are structured, and unlike CN they are
// not a free-text field that different CAs populate differently. CN is accepted
// as a fallback because plenty of internal PKI still issues that way.
func principalFromCert(cert *x509.Certificate) (string, error) {
	const op = "identity.principalFromCert"

	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			// spiffe://trust.domain/agent/triage -> agent:triage
			path := strings.Trim(u.Path, "/")
			if path == "" {
				return "", fault.New(fault.KindUnauthenticated, op,
					fmt.Sprintf("SPIFFE ID %q has no path component to derive a principal from", u))
			}
			return strings.ReplaceAll(path, "/", ":"), nil
		}
	}

	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		return cn, nil
	}

	return "", fault.New(fault.KindUnauthenticated, op,
		"client certificate has neither a SPIFFE URI SAN nor a Common Name")
}

// peerThumbprint is the connection certificate's RFC 8705 `x5t#S256` — the same
// SHA-256 of the DER `fingerprint` records, base64url-encoded (D303).
func peerThumbprint(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fault.New(fault.KindUnauthenticated, "identity.peerThumbprint", "no peer information on the request")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", fault.New(fault.KindUnauthenticated, "identity.peerThumbprint", "no client certificate presented")
	}
	return signedsubject.Thumbprint(tlsInfo.State.PeerCertificates[0].Raw), nil
}

// fingerprint is the SHA-256 of the DER encoding, hex-encoded.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// subjectFromContext reads the claimed subject and checks the caller may speak
// for it.
//
// §4.4.1, THE CONFUSED DEPUTY TRAP. Without this check, anything able to reach
// Sekizui as the mesh could claim to be any agent, and every per-agent grant
// collapses into "whatever the mesh can do". The check is therefore not an
// optimisation or a nicety — it is the reason per-agent grants mean anything.
func (v *Verifier) subjectFromContext(ctx context.Context, caller string) (*sekizuiv1.Subject, error) {
	const op = "identity.subjectFromContext"

	claimed := firstMetadataValue(ctx, SubjectHeader)

	// No subject asserted: the caller acts as itself. Standalone, chain of one.
	if claimed == "" || claimed == caller {
		return &sekizuiv1.Subject{
			Principal: caller,
			Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED,
		}, nil
	}

	if !v.grants[caller][claimed] {
		return nil, fault.New(fault.KindUnauthenticated, op, fmt.Sprintf(
			"caller %q may not speak for %q; add %q to that caller's may_speak_for, "+
				"which must be enumerated rather than wildcarded (§4.4.1)",
			caller, claimed, claimed))
	}

	return &sekizuiv1.Subject{
		Principal: claimed,
		// ASSERTED, not SIGNED: the claim is trusted because the CALLER is
		// proven and holds a grant to make it, not because the claim itself
		// carries proof. Signed subject tokens are the §4.4.2 upgrade path;
		// misreporting this as SIGNED would put a false statement in the audit
		// record about how the identity was established.
		Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED,
	}, nil
}

// MaySpeakFor reports whether caller may act for subject. Exported for the
// catalog and for boot-time grant validation.
func (v *Verifier) MaySpeakFor(caller, subject string) bool {
	return caller == subject || v.grants[caller][subject]
}

func firstMetadataValue(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return strings.TrimSpace(vals[0])
}

// MaxTraceIDBytes bounds an inbound trace id (D215).
//
// **UNBOUNDED, THIS WAS D178's DISK AMPLIFICATION WITH THE EASIER ENTRY POINT.**
// That decision bounds a DRIVER's result at 256 KiB because "an unbounded result
// is a disk-amplification denial of service… reaches the audit Effect detail,
// which reaches the WAL, which is FSYNCED". Every word applies here and one side
// was done: a trace id reaches `Decision.identity`, which is on the INTENT
// record and the OUTCOME record — two fsynced writes per command, four when a
// credential is re-established — and it arrives in a gRPC header rather than
// from a compromised upstream. One header, from any authenticated caller.
//
// **256 BYTES, WHICH IS FAR PAST ANYTHING REAL.** A W3C `traceparent` is 55
// characters and an OpenTelemetry trace id is 32 hex digits; step 29 replaces
// this reader with the span context, and neither shape comes close. The bound is
// deliberately not tight to either, because the field is documented as "an
// inbound trace ID" and a deployment correlating by its own convention is
// entitled to a slightly longer one.
const MaxTraceIDBytes = 256

// traceIDFromContext reads an inbound trace ID, or returns empty.
//
// P0 accepts what the caller supplies. When OTel lands at P2 this reads the span
// context instead, and correlation stops depending on callers being well-behaved.
func traceIDFromContext(ctx context.Context) string {
	return firstMetadataValue(ctx, "sekizui-trace-id")
}

// refuseUnusableTrace rejects a trace id that cannot safely be recorded (D215).
//
// **REFUSED RATHER THAN TRUNCATED, WHICH IS THE OPPOSITE OF D178 AND FOR THE
// REASON D200 GAVE US THE VOCABULARY FOR.** D178 truncates a driver's result and
// marks it, because the CALLER did nothing wrong and failing their command over
// somebody else's verbosity would be an availability attack routed through us.
// Here the caller IS the party at fault and is the party who can fix it, so
// `KindInvalidArgument` — attributed to the caller (D200), deliberate, and
// mapped to `STATUS_INVALID_ARGUMENT` — is both honest and actionable.
//
// **AND TRUNCATING WOULD BE WORSE THAN IT LOOKS.** A shortened trace id is not a
// degraded trace id; it is a DIFFERENT one, silently joining this action to
// whatever else happens to share the prefix. `Identity` has no truncation
// marker and should not grow one to paper over this: the whole value of the
// field is that it identifies exactly one conversation.
//
// The charset check is the second half. A trace reaches JSONL, where
// `encoding/json` escapes it correctly — but it also reaches operator-facing
// text, and a newline in an identifier is how one log line becomes two.
func refuseUnusableTrace(op, trace string) error {
	if len(trace) > MaxTraceIDBytes {
		return fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"the inbound %s header is %d bytes, and the ceiling is %d. It is recorded "+
				"on every decision this command produces, each of which is fsynced to "+
				"the audit log, so an oversized one is a write amplifier aimed at our "+
				"disk (D178's reasoning, D215). Send an identifier: a W3C traceparent "+
				"is 55 characters",
			traceHeaderName, len(trace), MaxTraceIDBytes))
	}
	for i := 0; i < len(trace); i++ {
		if c := trace[i]; c < 0x20 || c == 0x7F {
			return fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"the inbound %s header contains a control character at byte %d. A trace "+
					"id is an identifier and reaches operator-facing text, where a newline "+
					"in one turns a single log line into two (D215)",
				traceHeaderName, i))
		}
	}
	return nil
}

// traceHeaderName is the wire name, so a refusal can say which header to fix.
const traceHeaderName = "sekizui-trace-id"

// TraceparentHeader is the W3C Trace Context header (D216).
//
// **THE STANDARD ONE, so a caller already propagating trace context needs to do
// nothing special for Sekizui.** The legacy `sekizui-trace-id` stays as a
// fallback because a deployment may correlate by its own convention and D216
// keeps `Identity.trace_id` alive for records already written.
const TraceparentHeader = "traceparent"

// TraceFromContext derives the span context from request metadata (D216).
//
// **THREE FIELDS WITH REAL WRITERS, AND THE FOURTH DELIBERATELY ABSENT.**
// `trace_id`, `parent_span_id` and `sampled` are all in the inbound header, so
// they are populated from the first commit. `span_id` is OURS and needs a tracer
// to mint — step 29 — so the field does not exist yet, because a field nothing
// populates is the defect the proto's own `REFUSED_BY_DRIVER` note forbids.
//
// **A MALFORMED `traceparent` IS IGNORED, NOT REFUSED, and that is the opposite
// of D215's treatment of an oversized one.** The difference is what each failure
// means: an oversized value is an amplification aimed at our disk, and a
// malformed one is a caller whose propagation library disagrees with us about a
// hex digit. Refusing a governed command because correlation metadata was
// unparseable would let a header break the control plane — correlation must
// degrade, never deny. The bound still applies, so ignoring is safe.
func TraceFromContext(ctx context.Context) *sekizuiv1.Trace {
	if tp := firstMetadataValue(ctx, TraceparentHeader); tp != "" {
		if t := parseTraceparent(tp); t != nil {
			return t
		}
	}
	// THE LEGACY PATH. A bare id yields a trace with no parent and no sampling
	// decision, which is honest: that is exactly what the caller supplied.
	if id := traceIDFromContext(ctx); id != "" {
		return &sekizuiv1.Trace{TraceId: id}
	}
	return nil
}

// parseTraceparent reads `00-<32 hex>-<16 hex>-<2 hex>`, or returns nil.
//
// **VERSION `00` ONLY, AND A HIGHER ONE IS NOT AN ERROR.** The specification
// says an unknown version must be parsed as far as it is understood rather than
// rejected, because the first three fields are fixed. So a future version with
// the same prefix shape still yields a usable trace, and anything that does not
// match the shape yields nothing rather than a guess.
func parseTraceparent(v string) *sekizuiv1.Trace {
	parts := strings.Split(v, "-")
	if len(parts) < 4 {
		return nil
	}
	traceID, spanID, flags := parts[1], parts[2], parts[3]

	// **ALL-ZERO IS INVALID BY SPECIFICATION, and checking it matters because it
	// is what a broken propagator emits.** Treating it as a real trace would
	// group every such caller's decisions under one id — the correlation
	// equivalent of a shared primary key.
	if !isHex(traceID, 32) || traceID == strings.Repeat("0", 32) {
		return nil
	}
	if !isHex(spanID, 16) || spanID == strings.Repeat("0", 16) {
		spanID = ""
	}

	sampled := false
	if len(flags) >= 2 && isHex(flags[:2], 2) {
		b, err := strconv.ParseUint(flags[:2], 16, 8)
		sampled = err == nil && b&0x01 == 1
	}
	return &sekizuiv1.Trace{TraceId: traceID, ParentSpanId: spanID, Sampled: sampled}
}

// isHex reports whether s is exactly n lowercase hex digits.
//
// LOWERCASE ONLY, which the specification requires — and rejecting uppercase
// rather than folding it keeps the recorded value byte-identical to what a
// conforming caller sent, so a join against their trace store cannot miss.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
