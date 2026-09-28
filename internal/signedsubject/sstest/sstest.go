// Package sstest mints subject tokens for tests — good ones and every kind of
// bad one D303 names — against keys it generates. TEST SUPPORT ONLY: it is
// registered test-only, so a production caller fails the build (archcheck).
package sstest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// Signer is a generated key pair with a kid.
type Signer struct {
	KID  string
	Alg  string
	priv crypto.Signer
}

// NewRSA, NewEC and NewEd generate a key of each implemented type.
func NewRSA(kid string) *Signer {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &Signer{KID: kid, Alg: "RS256", priv: k}
}

func NewEC(kid string) *Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Signer{KID: kid, Alg: "ES256", priv: k}
}

func NewEd(kid string) *Signer {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Signer{KID: kid, Alg: "EdDSA", priv: k}
}

// JWKS renders the public halves as the issuer's key file.
func JWKS(signers ...*Signer) []byte {
	b := func(x []byte) string { return base64.RawURLEncoding.EncodeToString(x) }
	var keys []map[string]any
	for _, s := range signers {
		switch p := s.priv.Public().(type) {
		case *rsa.PublicKey:
			keys = append(keys, map[string]any{"kty": "RSA", "kid": s.KID, "alg": "RS256", "use": "sig",
				"n": b(p.N.Bytes()), "e": b(big.NewInt(int64(p.E)).Bytes())})
		case *ecdsa.PublicKey:
			keys = append(keys, map[string]any{"kty": "EC", "kid": s.KID, "crv": "P-256",
				"x": b(p.X.FillBytes(make([]byte, 32))), "y": b(p.Y.FillBytes(make([]byte, 32)))})
		case ed25519.PublicKey:
			keys = append(keys, map[string]any{"kty": "OKP", "kid": s.KID, "crv": "Ed25519", "x": b(p)})
		}
	}
	out, _ := json.Marshal(map[string]any{"keys": keys})
	return out
}

// Mint signs claims under s with the header s implies, overridden by header —
// the lever for `alg: none` and HMAC confusion tokens.
func (s *Signer) Mint(claims map[string]any, header map[string]any) string {
	h := map[string]any{"alg": s.Alg, "kid": s.KID, "typ": "JWT"}
	for k, v := range header {
		if v == nil {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	enc := func(v any) string { j, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(j) }
	signing := enc(h) + "." + enc(claims)
	alg, _ := h["alg"].(string)
	return signing + "." + base64.RawURLEncoding.EncodeToString(s.sign(alg, []byte(signing)))
}

func (s *Signer) sign(alg string, data []byte) []byte {
	digest := sha256.Sum256(data)
	switch alg {
	case "none":
		return nil
	case "HS256": // HMAC keyed with the PUBLIC key — the confusion attack
		pub, _ := json.Marshal(JWKSKey(s))
		m := hmac.New(sha256.New, pub)
		m.Write(data)
		return m.Sum(nil)
	}
	switch k := s.priv.(type) {
	case *rsa.PrivateKey:
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		return sig
	case *ecdsa.PrivateKey:
		r, ss, _ := ecdsa.Sign(rand.Reader, k, digest[:])
		return append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...)
	case ed25519.PrivateKey:
		return ed25519.Sign(k, data)
	}
	return nil
}

// JWKSKey is one signer's public JWK, as a map.
func JWKSKey(s *Signer) map[string]any {
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal(JWKS(s), &set)
	return set.Keys[0]
}
