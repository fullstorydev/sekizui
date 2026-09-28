// Package signedsubject verifies a subject token signed by a pinned issuer —
// §4.4.2's tier two, as D303's skeleton, in the shape D318 fixed.
//
// **NARROW ON PURPOSE, AND ON THE STANDARD LIBRARY (D318).** Compact JWS only:
// no JWE, no nested tokens, and no key a token carries or points at (`jwk`,
// `jku`, `x5u`, `x5c` are never followed). Three algorithms — RS256, ES256,
// EdDSA — and **the algorithm is the CONFIGURED KEY's, never the header's**: the
// header's `alg` must equal it or the token refuses. So `alg: none` and
// HMAC/RSA confusion are impossible by construction, not by a library's
// defaults, which is where JWT libraries have shipped CVEs.
//
// **PURE.** Verify takes the token, the issuer's keys and policy, the
// connection's certificate thumbprint and the time, and returns the claims or a
// refusal that names its reason. No I/O: keys arrive through `file://` (D286)
// at the caller, and nothing here reaches a network.
//
// **THE ADVERSARY REPLAYS (D303).** A prompt-injected agent inside the
// perimeter holds a real token and presents it elsewhere, later, or to a
// Sekizui it was never meant for — so audience, expiry and the binding to the
// mTLS certificate (RFC 8705) are the checks this package exists for.
//
// DESIGN.md references: §4.4.2, §4.4.4, D57, D303, D318.
package signedsubject

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// The algorithms this verifier implements (D318).
const (
	RS256 = "RS256"
	ES256 = "ES256"
	EdDSA = "EdDSA"
)

// MaxTokenBytes bounds what is parsed at all: a subject token is a few hundred
// bytes, and anything past this is refused before a byte is decoded.
const MaxTokenBytes = 8 << 10

// Key is one public key from an issuer's JWKS, with the algorithm its type
// implies — the only algorithm a token may claim under it.
type Key struct {
	KID string
	Alg string
	pub crypto.PublicKey
}

// jwk is the subset of RFC 7517 this verifier reads.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseJWKS reads an issuer's key file. Every key must be a public signing key
// of a type this verifier implements; a key whose declared `alg` disagrees with
// its type refuses the file, because that disagreement is how a confusion
// attack would be staged.
func ParseJWKS(raw []byte) ([]Key, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("the key file is not a JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("the key file holds no keys")
	}
	var out []Key
	seen := map[string]bool{}
	for i, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			return nil, fmt.Errorf("key %d (%q) is for %q, not signatures", i, k.Kid, k.Use)
		}
		key, err := parseKey(k)
		if err != nil {
			return nil, fmt.Errorf("key %d (%q): %w", i, k.Kid, err)
		}
		if k.Alg != "" && k.Alg != key.Alg {
			return nil, fmt.Errorf("key %d (%q) declares alg %q but is a %s key", i, k.Kid, k.Alg, key.Alg)
		}
		if seen[key.KID] {
			return nil, fmt.Errorf("kid %q appears twice", key.KID)
		}
		seen[key.KID] = true
		out = append(out, key)
	}
	return out, nil
}

func parseKey(k jwk) (Key, error) {
	b := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
	switch k.Kty {
	case "RSA":
		n, err1 := b(k.N)
		e, err2 := b(k.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 {
			return Key{}, fmt.Errorf("an RSA key needs base64url n and e")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 {
			return Key{}, fmt.Errorf("an RSA key of %d bits is refused; 2048 is the least", pub.N.BitLen())
		}
		return Key{KID: k.Kid, Alg: RS256, pub: pub}, nil
	case "EC":
		if k.Crv != "P-256" {
			return Key{}, fmt.Errorf("EC curve %q is not implemented; P-256 (ES256) is", k.Crv)
		}
		x, err1 := b(k.X)
		y, err2 := b(k.Y)
		if err1 != nil || err2 != nil {
			return Key{}, fmt.Errorf("an EC key needs base64url x and y")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.IsOnCurve(pub.X, pub.Y) {
			return Key{}, fmt.Errorf("the EC point is not on P-256")
		}
		return Key{KID: k.Kid, Alg: ES256, pub: pub}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return Key{}, fmt.Errorf("OKP curve %q is not implemented; Ed25519 (EdDSA) is", k.Crv)
		}
		x, err := b(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return Key{}, fmt.Errorf("an Ed25519 key needs a 32-byte base64url x")
		}
		return Key{KID: k.Kid, Alg: EdDSA, pub: ed25519.PublicKey(x)}, nil
	}
	return Key{}, fmt.Errorf("key type %q is not implemented (RSA, EC P-256 and OKP Ed25519 are)", k.Kty)
}

// Policy is what one issuer entry requires of its tokens.
type Policy struct {
	Issuer       string
	Audience     string
	Algorithms   []string // a subset of Algorithms()
	Leeway       time.Duration
	RequireBound bool
	RoleClaim    string // default "role"
}

// Claims is what a verified token says.
type Claims struct {
	Subject string
	Role    string
	// Grants and Lenses are the token's optional narrowing (D303): grants may
	// only intersect with the role's, lenses may only add.
	Grants []string
	Lenses []string
	// Bound is true when the token carried `cnf.x5t#S256` and it matched.
	Bound bool
	// Proof is the SHA-256 of the token, for the record — never the token.
	Proof []byte
}

// PeekIssuer reads a token's `iss` WITHOUT verifying anything, so the caller
// can choose which issuer's keys and policy to verify it with. Nothing it
// returns is trusted; Verify checks the issuer again after the signature.
func PeekIssuer(token string) (string, error) {
	parts, err := split(token)
	if err != nil {
		return "", err
	}
	var p struct {
		Iss string `json:"iss"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(raw, &p) != nil || p.Iss == "" {
		return "", refuse("the token's payload names no issuer")
	}
	return p.Iss, nil
}

// Verify checks token against one issuer's keys and policy, the connection's
// certificate thumbprint (base64url SHA-256 of its DER, RFC 8705's
// `x5t#S256`), and now. Each refusal names its reason (P4 step 27).
func Verify(token string, keys []Key, p Policy, certThumbprint string, now time.Time) (Claims, error) {
	parts, err := split(token)
	if err != nil {
		return Claims{}, err
	}
	var header struct {
		Alg  string   `json:"alg"`
		Kid  string   `json:"kid"`
		Crit []string `json:"crit"`
	}
	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hraw, &header) != nil {
		return Claims{}, refuse("the token's header is not base64url JSON")
	}
	if len(header.Crit) > 0 {
		return Claims{}, refuse(fmt.Sprintf("the token marks %v critical, and no extension is implemented", header.Crit))
	}
	if header.Alg == "" || strings.EqualFold(header.Alg, "none") {
		return Claims{}, refuse("the token is unsigned (`alg: none`); an unsigned subject is an ASSERTED one, " +
			"and assertion has its own path (§4.4.2 tier one)")
	}

	// THE KEY FIRST, THEN ITS ALGORITHM — never the header's choice.
	key, err := selectKey(keys, header.Kid)
	if err != nil {
		return Claims{}, err
	}
	if !slices.Contains(p.Algorithms, key.Alg) {
		return Claims{}, refuse(fmt.Sprintf("key %q is %s, which this issuer's algorithm allowlist %v excludes",
			key.KID, key.Alg, p.Algorithms))
	}
	if header.Alg != key.Alg {
		return Claims{}, refuse(fmt.Sprintf("the token claims %s under key %q, which is a %s key — refused rather "+
			"than verified the token's way, which is how algorithm confusion works", header.Alg, key.KID, key.Alg))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, refuse("the token's signature is not base64url")
	}
	if !verifySignature(key, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, refuse(fmt.Sprintf("the signature does not verify under key %q", key.KID))
	}

	// THE CLAIMS, only now that the signature says whose they are.
	praw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, refuse("the token's payload is not base64url")
	}
	var c map[string]any
	if err := json.Unmarshal(praw, &c); err != nil {
		return Claims{}, refuse("the token's payload is not JSON")
	}
	if iss, _ := c["iss"].(string); iss != p.Issuer {
		return Claims{}, refuse(fmt.Sprintf("the token's issuer %q is not %q", iss, p.Issuer))
	}
	if !audienceHas(c["aud"], p.Audience) {
		return Claims{}, refuse(fmt.Sprintf("the token's audience %v does not name this Sekizui (%q) — a token "+
			"minted for another service, replayed here", c["aud"], p.Audience))
	}
	exp, ok := numericDate(c["exp"])
	if !ok {
		return Claims{}, refuse("the token has no `exp`; a subject token that never expires is a credential forever")
	}
	if now.After(exp.Add(p.Leeway)) {
		return Claims{}, refuse(fmt.Sprintf("the token expired at %s", exp.UTC().Format(time.RFC3339)))
	}
	if nbf, ok := numericDate(c["nbf"]); ok && now.Before(nbf.Add(-p.Leeway)) {
		return Claims{}, refuse(fmt.Sprintf("the token is not valid before %s", nbf.UTC().Format(time.RFC3339)))
	}
	sub, _ := c["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return Claims{}, refuse("the token names no subject (`sub`)")
	}
	roleClaim := p.RoleClaim
	if roleClaim == "" {
		roleClaim = "role"
	}
	role, _ := c[roleClaim].(string)
	if strings.TrimSpace(role) == "" {
		return Claims{}, refuse(fmt.Sprintf("the token names no role (`%s`); a role selects the subject's grants "+
			"from Sekizui's own configuration (D303)", roleClaim))
	}

	// RFC 8705: bound to the connection presenting it, or refused by default.
	bound := false
	if cnf, has := c["cnf"].(map[string]any); has {
		want, _ := cnf["x5t#S256"].(string)
		if want == "" || want != certThumbprint {
			return Claims{}, refuse("the token is bound to another certificate (`cnf.x5t#S256` does not match this " +
				"connection) — a mismatch ALWAYS refuses (D303)")
		}
		bound = true
	} else if p.RequireBound {
		return Claims{}, refuse("the token is not bound to a certificate (no `cnf.x5t#S256`), and this issuer requires " +
			"binding; an operator whose broker cannot bind sets `require_bound: false` (D303)")
	}

	sum := sha256.Sum256([]byte(token))
	return Claims{Subject: sub, Role: role, Grants: stringList(c["grants"]), Lenses: stringList(c["lenses"]),
		Bound: bound, Proof: sum[:]}, nil
}

// Thumbprint is RFC 8705's `x5t#S256` for a certificate's DER.
func Thumbprint(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func split(token string) ([]string, error) {
	if len(token) > MaxTokenBytes {
		return nil, refuse(fmt.Sprintf("the token is %d bytes; more than %d is refused unread", len(token), MaxTokenBytes))
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, refuse(fmt.Sprintf("the token has %d parts; a compact JWS has three (JWE and nested tokens are "+
			"not implemented)", len(parts)))
	}
	return parts, nil
}

func selectKey(keys []Key, kid string) (Key, error) {
	if kid == "" {
		if len(keys) == 1 {
			return keys[0], nil
		}
		return Key{}, refuse("the token names no `kid` and the issuer has several keys")
	}
	for _, k := range keys {
		if k.KID == kid {
			return k, nil
		}
	}
	return Key{}, refuse(fmt.Sprintf("no key %q in the issuer's key file — a retired key, or not this issuer's", kid))
}

func verifySignature(k Key, signed, sig []byte) bool {
	digest := sha256.Sum256(signed)
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
	case *ecdsa.PublicKey:
		if len(sig) != 64 { // JWS: r||s, 32 bytes each — not DER
			return false
		}
		return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case ed25519.PublicKey:
		return ed25519.Verify(pub, signed, sig)
	}
	return false
}

func audienceHas(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == want {
				return true
			}
		}
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)), true
}

func stringList(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func refuse(why string) error {
	return fault.New(fault.KindUnauthenticated, "signedsubject.Verify", why)
}
