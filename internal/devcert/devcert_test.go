package devcert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generate(t *testing.T, principals ...string) *Bundle {
	t.Helper()
	b, err := Generate(t.TempDir(), principals)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return b
}

func parse(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return cert
}

// TestSpiffeIDRoundTripsThroughIdentity is the property that matters most here,
// and the one that would break silently.
//
// devcert ENCODES "agent:triage" into a SPIFFE URI SAN; identity DECODES it
// back. The two live in different packages and neither imports the other, so
// nothing but this test makes them agree. A drift would not fail to compile —
// it would issue certificates that authenticate as the wrong principal, or as
// none, which is the worst class of identity bug.
//
// The decoding is duplicated here deliberately rather than imported, so this
// test pins the FORMAT rather than agreeing with whatever identity currently
// does. If both change together the test still fails, which is correct: a
// format change is a decision, not an implementation detail.
func TestSpiffeIDRoundTripsThroughIdentity(t *testing.T) {
	for _, principal := range []string{
		"agent:triage", "mesh:primary", "reflex:friction", "agent:global",
	} {
		t.Run(principal, func(t *testing.T) {
			b := generate(t, principal)
			cert := parse(t, b.ClientCerts[principal])

			if len(cert.URIs) != 1 {
				t.Fatalf("got %d URI SANs, want exactly 1", len(cert.URIs))
			}
			u := cert.URIs[0]
			if u.Scheme != "spiffe" {
				t.Errorf("scheme = %q, want spiffe; identity would fall back to the CN "+
					"and the SPIFFE path would go untested everywhere", u.Scheme)
			}
			if u.Host != TrustDomain {
				t.Errorf("trust domain = %q, want %q", u.Host, TrustDomain)
			}

			// The exact inverse of identity.principalFromCert.
			got := ""
			if path := u.Path; len(path) > 1 {
				got = replaceAll(path[1:], "/", ":")
			}
			if got != principal {
				t.Errorf("SPIFFE ID %q decodes to principal %q, want %q", u, got, principal)
			}
		})
	}
}

// TestClientCertificatesVerifyAgainstTheCA — the whole point of the bundle is
// that the server's pool accepts these and nothing else.
func TestClientCertificatesVerifyAgainstTheCA(t *testing.T) {
	b := generate(t, "agent:triage")

	pool := x509.NewCertPool()
	raw, err := os.ReadFile(b.CACertFile)
	if err != nil {
		t.Fatalf("reading CA: %v", err)
	}
	if !pool.AppendCertsFromPEM(raw) {
		t.Fatal("the generated CA is not loadable as PEM")
	}

	if _, err := parse(t, b.ClientCerts["agent:triage"]).Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("a client certificate does not verify against its own CA: %v", err)
	}
}

// TestTwoBundlesDoNotTrustEachOther — each run must produce an independent CA.
// A shared or deterministic CA would mean any developer's laptop could mint
// identities another instance accepts.
func TestTwoBundlesDoNotTrustEachOther(t *testing.T) {
	a := generate(t, "agent:triage")
	b := generate(t, "agent:triage")

	pool := x509.NewCertPool()
	raw, _ := os.ReadFile(a.CACertFile)
	pool.AppendCertsFromPEM(raw)

	if _, err := parse(t, b.ClientCerts["agent:triage"]).Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Error("a certificate from one bundle verified against another bundle's CA; " +
			"every run must produce an independent trust root")
	}
}

// TestPrivateKeysAreNotWorldReadable — a 0644 private key in a repo checkout is
// how a development credential becomes a real incident.
func TestPrivateKeysAreNotWorldReadable(t *testing.T) {
	b := generate(t, "agent:triage", "mesh:primary")

	keys := []string{b.ServerKey}
	for _, k := range b.ClientKeys {
		keys = append(keys, k)
	}

	for _, k := range keys {
		info, err := os.Stat(k)
		if err != nil {
			t.Fatalf("stat %s: %v", k, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s has mode %o, want 600", filepath.Base(k), perm)
		}
	}
}

// TestCertificatesAreShortLived — a development certificate that lives a year
// ends up in a staging environment, then in a runbook.
func TestCertificatesAreShortLived(t *testing.T) {
	b := generate(t, "agent:triage")
	cert := parse(t, b.ClientCerts["agent:triage"])

	if life := cert.NotAfter.Sub(cert.NotBefore); life > 32*24*time.Hour {
		t.Errorf("certificate lifetime is %v; development material must expire before "+
			"it can become infrastructure", life)
	}
}

// TestTheCACannotSignAnotherCA — MaxPathLenZero. Without it, a leaked
// development key could issue an intermediate and mint anything.
func TestTheCACannotSignAnotherCA(t *testing.T) {
	b := generate(t, "agent:triage")
	ca := parse(t, b.CACertFile)

	if !ca.IsCA {
		t.Fatal("the CA is not marked as a CA")
	}
	if !ca.MaxPathLenZero {
		t.Error("the CA does not set MaxPathLen=0, so it could sign an intermediate")
	}
}

// TestLeafCertificatesAreNotCAs — a client certificate that is itself a CA
// could issue certificates for any other principal.
func TestLeafCertificatesAreNotCAs(t *testing.T) {
	b := generate(t, "agent:triage")

	for name, path := range map[string]string{
		"server": b.ServerCert,
		"client": b.ClientCerts["agent:triage"],
	} {
		if parse(t, path).IsCA {
			t.Errorf("the %s certificate is marked as a CA and could mint identities", name)
		}
	}
}

// TestSerialsDiffer — sequential serials would collide across two runs, and a
// client holding the older certificate would then be rejected confusingly.
func TestSerialsDiffer(t *testing.T) {
	a := generate(t, "agent:triage")
	b := generate(t, "agent:triage")

	if parse(t, a.ClientCerts["agent:triage"]).SerialNumber.Cmp(
		parse(t, b.ClientCerts["agent:triage"]).SerialNumber) == 0 {
		t.Error("two independently generated certificates share a serial number")
	}
}

// TestAMalformedPrincipalIsRefused — a principal without a kind produces a
// SPIFFE path that decodes back to something else.
func TestAMalformedPrincipalIsRefused(t *testing.T) {
	for _, bad := range []string{"", ":triage", "agent:"} {
		if _, err := Generate(t.TempDir(), []string{bad}); err == nil {
			t.Errorf("Generate accepted the malformed principal %q", bad)
		}
	}
}

// replaceAll avoids importing strings for one call in a test that is about
// pinning a format.
func replaceAll(s, old, new string) string {
	out := ""
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			out += new
			i += len(old)
			continue
		}
		out += string(s[i])
		i++
	}
	return out
}
