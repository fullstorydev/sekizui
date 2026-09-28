package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Real certificates, not mocks. The claim under test is that caller identity is
// PROVEN rather than claimed, and a fake peer object would test the plumbing
// while assuming away the thing that matters.

func certWithSPIFFE(t *testing.T, id string) *x509.Certificate {
	t.Helper()
	u, err := url.Parse(id)
	if err != nil {
		t.Fatalf("bad SPIFFE id %q: %v", id, err)
	}
	return makeCert(t, pkix.Name{}, []*url.URL{u})
}

func certWithCN(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return makeCert(t, pkix.Name{CommonName: cn}, nil)
}

func makeCert(t *testing.T, subj pkix.Name, uris []*url.URL) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subj,
		URIs:         uris,
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
	return cert
}

// mtlsContext builds a context as gRPC would present it for a verified mTLS peer.
func mtlsContext(certs ...*x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: certs},
		},
	})
}

func withSubject(ctx context.Context, subject string) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.Pairs(SubjectHeader, subject))
}

// meshVerifier: mesh:primary may speak for two agents, and nobody else may
// speak for anyone.
func meshVerifier() *Verifier {
	return NewVerifier(&config.Document{
		Grants: []config.GrantSpec{
			{Principal: "mesh:primary", MaySpeakFor: []string{"agent:triage", "agent:architect"}},
			{Principal: "agent:triage"},
		},
	})
}

func TestCallerFromSPIFFECertificate(t *testing.T) {
	ctx := mtlsContext(certWithSPIFFE(t, "spiffe://sekizui.test/agent/triage"))

	caller, err := CallerFromContext(ctx)
	if err != nil {
		t.Fatalf("CallerFromContext: %v", err)
	}
	if caller.Principal != "agent:triage" {
		t.Errorf("principal = %q, want agent:triage", caller.Principal)
	}
	if caller.Method.String() != "AUTH_METHOD_MTLS" {
		t.Errorf("method = %v, want mTLS", caller.Method)
	}
	// The fingerprint identifies WHICH credential without being one.
	if !strings.HasPrefix(caller.CredentialId, "sha256:") {
		t.Errorf("credential_id = %q, want a sha256 fingerprint", caller.CredentialId)
	}
	if strings.Contains(caller.CredentialId, "BEGIN CERTIFICATE") {
		t.Error("credential_id embedded the certificate rather than a fingerprint")
	}
}

func TestCallerFallsBackToCommonName(t *testing.T) {
	caller, err := CallerFromContext(mtlsContext(certWithCN(t, "mesh:primary")))
	if err != nil {
		t.Fatalf("CallerFromContext: %v", err)
	}
	if caller.Principal != "mesh:primary" {
		t.Errorf("principal = %q, want mesh:primary", caller.Principal)
	}
}

// TestCallerIdentityCannotBeForged is the core security property.
//
// There is deliberately no path from a header or a request field to caller
// identity. If one is ever added, this test does not catch it directly — but the
// cases below pin that WITHOUT a certificate there is no identity at all, which
// is the property an attacker would need to break first.
func TestCallerIdentityCannotBeForged(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"no peer at all": context.Background(),

		"peer with no TLS": peer.NewContext(context.Background(), &peer.Peer{}),

		"mTLS with no client certificate": mtlsContext(),

		// The most important case: a caller supplying the header a naive
		// implementation might trust.
		"header claiming to be someone": metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("sekizui-caller", "mesh:primary", SubjectHeader, "agent:architect"),
		),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CallerFromContext(ctx)
			if err == nil {
				t.Fatal("established a caller identity with no verified certificate")
			}
			if !errors.Is(err, fault.KindUnauthenticated) {
				t.Errorf("kind = %v, want KindUnauthenticated — this is 'we do not know "+
					"who you are', not 'we know and the answer is no'", fault.KindOf(err))
			}
		})
	}
}

func TestCertificateWithNoUsableNameIsRejected(t *testing.T) {
	_, err := CallerFromContext(mtlsContext(makeCert(t, pkix.Name{}, nil)))
	if err == nil {
		t.Fatal("accepted a certificate with neither SPIFFE SAN nor CN")
	}
	if !errors.Is(err, fault.KindUnauthenticated) {
		t.Errorf("kind = %v, want KindUnauthenticated", fault.KindOf(err))
	}
}

// TestStandaloneIsAChainOfOne — D6: one model, no second code path. Standalone
// must not be an empty chain or a special case.
func TestStandaloneIsAChainOfOne(t *testing.T) {
	ctx := mtlsContext(certWithSPIFFE(t, "spiffe://sekizui.test/agent/triage"))

	id, err := meshVerifier().Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(id.Chain) != 1 || id.Chain[0] != "agent:triage" {
		t.Errorf("chain = %v, want [agent:triage]", id.Chain)
	}
	if id.Subject.Principal != id.Caller.Principal {
		t.Errorf("subject %q != caller %q with no subject asserted",
			id.Subject.Principal, id.Caller.Principal)
	}
}

// TestDelegationProducesAChainOfTwo — the mesh acting for an agent it may speak
// for. Chain is outermost first (D39).
func TestDelegationProducesAChainOfTwo(t *testing.T) {
	ctx := withSubject(mtlsContext(certWithCN(t, "mesh:primary")), "agent:triage")

	id, err := meshVerifier().Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := id.Chain; len(got) != 2 || got[0] != "mesh:primary" || got[1] != "agent:triage" {
		t.Errorf("chain = %v, want [mesh:primary agent:triage] outermost first", got)
	}
	if id.Caller.Principal != "mesh:primary" {
		t.Errorf("caller = %q", id.Caller.Principal)
	}
	if id.Subject.Principal != "agent:triage" {
		t.Errorf("subject = %q", id.Subject.Principal)
	}
	// ASSERTED, not SIGNED: trusted because the caller is proven and holds the
	// grant, not because the claim carries proof. Recording SIGNED would put a
	// false statement about provenance into the audit record.
	if id.Subject.Assertion.String() != "ASSERTION_ASSERTED" {
		t.Errorf("assertion = %v, want ASSERTED", id.Subject.Assertion)
	}
}

// TestConfusedDeputyDefence is §4.4.1, and the reason per-agent grants mean
// anything at all.
//
// Without it, anything reaching Sekizui as the mesh could claim to be any agent,
// and every per-agent grant would collapse into "whatever the mesh can do".
func TestConfusedDeputyDefence(t *testing.T) {
	v := meshVerifier()

	t.Run("subject the caller may not speak for", func(t *testing.T) {
		ctx := withSubject(mtlsContext(certWithCN(t, "mesh:primary")), "agent:unlisted")

		_, err := v.Verify(ctx)
		if err == nil {
			t.Fatal("mesh:primary impersonated an agent it has no grant for")
		}
		if !errors.Is(err, fault.KindUnauthenticated) {
			t.Errorf("kind = %v, want KindUnauthenticated", fault.KindOf(err))
		}
		// The error must tell an operator how to fix it, and must not suggest
		// a wildcard as the remedy.
		if !strings.Contains(err.Error(), "may_speak_for") {
			t.Errorf("error does not name the grant to change: %v", err)
		}
	})

	t.Run("caller with no delegation grant at all", func(t *testing.T) {
		ctx := withSubject(mtlsContext(certWithSPIFFE(t, "spiffe://sekizui.test/agent/triage")),
			"agent:architect")

		if _, err := v.Verify(ctx); err == nil {
			t.Fatal("an agent with no may_speak_for spoke for another agent")
		}
	})

	t.Run("unknown caller cannot delegate", func(t *testing.T) {
		ctx := withSubject(mtlsContext(certWithCN(t, "stranger")), "agent:triage")

		if _, err := v.Verify(ctx); err == nil {
			t.Fatal("a principal absent from config delegated successfully")
		}
	})
}

// TestSubjectEqualToCallerIsNotDelegation. Asserting yourself is not a
// delegation and must not require a grant — otherwise every standalone caller
// would need a may_speak_for entry naming itself.
func TestSubjectEqualToCallerIsNotDelegation(t *testing.T) {
	ctx := withSubject(mtlsContext(certWithSPIFFE(t, "spiffe://sekizui.test/agent/triage")),
		"agent:triage")

	id, err := meshVerifier().Verify(ctx)
	if err != nil {
		t.Fatalf("asserting one's own identity required a grant: %v", err)
	}
	if len(id.Chain) != 1 {
		t.Errorf("chain = %v, want length 1", id.Chain)
	}
}

func TestMaySpeakFor(t *testing.T) {
	v := meshVerifier()

	for _, tc := range []struct {
		caller, subject string
		want            bool
	}{
		{"mesh:primary", "agent:triage", true},
		{"mesh:primary", "agent:architect", true},
		{"mesh:primary", "agent:unlisted", false},
		{"agent:triage", "agent:architect", false},
		{"agent:triage", "agent:triage", true}, // self is always allowed
		{"stranger", "agent:triage", false},
	} {
		if got := v.MaySpeakFor(tc.caller, tc.subject); got != tc.want {
			t.Errorf("MaySpeakFor(%q, %q) = %v, want %v", tc.caller, tc.subject, got, tc.want)
		}
	}
}

// TestVerifierIgnoresWildcards. Document.Validate rejects wildcarded
// may_speak_for at boot, but the Verifier must not treat "*" as special even if
// one reaches it — defence in depth, since a second config path could appear.
func TestVerifierIgnoresWildcards(t *testing.T) {
	v := NewVerifier(&config.Document{
		Grants: []config.GrantSpec{{Principal: "mesh:primary", MaySpeakFor: []string{"*", "agent:*"}}},
	})

	if v.MaySpeakFor("mesh:primary", "agent:triage") {
		t.Error(`"*" was honoured as a wildcard; it must match only a principal literally named "*"`)
	}
}

func TestTraceIDIsCarriedThrough(t *testing.T) {
	ctx := metadata.NewIncomingContext(
		mtlsContext(certWithCN(t, "agent:triage")),
		metadata.Pairs("sekizui-trace-id", "abc123"),
	)

	id, err := meshVerifier().Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.TraceId != "abc123" {
		t.Errorf("trace_id = %q, want abc123", id.TraceId)
	}
}
