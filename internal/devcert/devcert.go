// Package devcert generates a local CA and leaf certificates for development.
//
// PRIVATE (D35), and deliberately not wired into any serving path — it is used
// by `make dev-certs` and by tests. A binary that can mint its own trusted
// identities is a binary whose identity model means nothing, so this stays a
// generator that writes files, never a fallback the server reaches for when
// certificates are missing (§4.4).
//
// SPIFFE URI SANs, not Common Names. identity.principalFromCert prefers a SPIFFE
// ID and falls back to CN, so generating CN-only certificates locally would
// exercise the fallback in development and the real path only in production —
// the wrong way round for the code you most want tested.
//
// DESIGN.md references: §4.4, §4.4.1, D57.
package devcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/internal/atomicfile"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// TrustDomain is the SPIFFE trust domain for locally generated identities.
//
// "dev.sekizui.local" rather than anything resembling a real domain, so a
// development certificate that escapes into a real trust store is obvious in
// an audit log rather than plausible.
const TrustDomain = "dev.sekizui.local"

// Bundle is a generated CA and the leaf certificates issued under it.
type Bundle struct {
	Dir         string
	CACertFile  string
	ServerCert  string
	ServerKey   string
	ClientCerts map[string]string // principal -> cert file
	ClientKeys  map[string]string // principal -> key file
	NotAfter    time.Time
	TrustDomain string
	Principals  []string
}

// Generate writes a CA, a server certificate, and one client certificate per
// principal into dir.
//
// LIFETIME IS DELIBERATELY SHORT. A development certificate that lives for a
// year ends up in a staging environment, then in a runbook. Thirty days makes
// it expire before it can become infrastructure.
func Generate(dir string, principals []string) (*Bundle, error) {
	const op = "devcert.Generate"

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "creating "+dir, err)
	}

	notBefore := time.Now().Add(-time.Hour) // clock skew on a laptop is real
	notAfter := time.Now().Add(30 * 24 * time.Hour)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fault.Wrap(fault.KindInternal, op, "generating the CA key", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "sekizui development CA", Organization: []string{"sekizui-dev"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // this CA signs leaves only, never another CA
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fault.Wrap(fault.KindInternal, op, "self-signing the CA", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fault.Wrap(fault.KindInternal, op, "parsing the CA back", err)
	}

	b := &Bundle{
		Dir:         dir,
		CACertFile:  filepath.Join(dir, "ca.crt"),
		ServerCert:  filepath.Join(dir, "server.crt"),
		ServerKey:   filepath.Join(dir, "server.key"),
		ClientCerts: map[string]string{},
		ClientKeys:  map[string]string{},
		NotAfter:    notAfter,
		TrustDomain: TrustDomain,
		Principals:  principals,
	}

	if err := writePEM(b.CACertFile, "CERTIFICATE", caDER, 0o644); err != nil {
		return nil, err
	}

	// --- server leaf ---------------------------------------------------------
	serverTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "sekizui"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "sekizui"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if err := issue(b.ServerCert, b.ServerKey, serverTmpl, caCert, caKey); err != nil {
		return nil, err
	}

	// --- client leaves -------------------------------------------------------
	for _, p := range principals {
		uri, err := spiffeID(p)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial(),
			// CN is set too, but the SPIFFE SAN is what identity prefers. Both
			// present means a mismatch between them would be caught by a test
			// rather than hidden by only ever setting one.
			Subject:     pkix.Name{CommonName: p},
			NotBefore:   notBefore,
			NotAfter:    notAfter,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			URIs:        []*url.URL{uri},
		}
		safe := strings.ReplaceAll(p, ":", "_")
		certFile := filepath.Join(dir, safe+".crt")
		keyFile := filepath.Join(dir, safe+".key")
		if err := issue(certFile, keyFile, tmpl, caCert, caKey); err != nil {
			return nil, err
		}
		b.ClientCerts[p] = certFile
		b.ClientKeys[p] = keyFile
	}

	return b, nil
}

// spiffeID converts "agent:triage" to spiffe://dev.sekizui.local/agent/triage,
// the exact inverse of identity.principalFromCert.
func spiffeID(principal string) (*url.URL, error) {
	const op = "devcert.spiffeID"

	if principal == "" || strings.HasPrefix(principal, ":") || strings.HasSuffix(principal, ":") {
		return nil, fault.New(fault.KindConfig, op,
			"principal "+principal+" does not have the form kind:name")
	}
	return &url.URL{
		Scheme: "spiffe",
		Host:   TrustDomain,
		Path:   "/" + strings.ReplaceAll(principal, ":", "/"),
	}, nil
}

func issue(certFile, keyFile string, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) error {
	const op = "devcert.issue"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "generating a key", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "signing "+certFile, err)
	}
	if err := writePEM(certFile, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "marshalling the key", err)
	}
	// 0600 on private keys, always. A world-readable key in a repo checkout is
	// how a development credential becomes a real incident.
	return writePEM(keyFile, "EC PRIVATE KEY", keyDER, 0o600)
}

// writePEM writes one PEM block through atomicfile (D344).
//
// It opened `path` O_CREATE|O_TRUNC and then chmod-ed it BY NAME — both follow a
// symlink, so a link planted at `ca.key` redirected a private key, or truncated
// whatever it pointed at. atomicfile writes a fresh temp file created
// exclusively, sets the mode on the handle (exact, not masked by umask — which
// is what the explicit chmod here was for), fsyncs, and renames: a rename
// REPLACES a link rather than following it.
func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	const op = "devcert.writePEM"
	if err := atomicfile.Write(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), mode); err != nil {
		return fault.Wrap(fault.KindConfig, op, "writing "+path, err)
	}
	return nil
}

func serial() *big.Int {
	// 128 random bits, the CA/Browser Forum minimum. Sequential serials from a
	// counter would collide across two runs of `make dev-certs`, and a client
	// holding the older certificate would then be rejected confusingly.
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}
