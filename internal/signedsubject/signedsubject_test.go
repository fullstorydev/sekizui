package signedsubject_test

import (
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/signedsubject"
	"github.com/fullstorydev/sekizui/internal/signedsubject/sstest"
	"github.com/fullstorydev/sekizui/pkg/config"
)

var now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

const thumb = "certificate-thumbprint"

func policy() signedsubject.Policy {
	return signedsubject.Policy{Issuer: "https://broker.test", Audience: "sekizui:acceptance",
		Algorithms: config.SubjectTokenAlgorithms(), Leeway: 60 * time.Second, RequireBound: true}
}

func claims(over map[string]any) map[string]any {
	c := map[string]any{"iss": "https://broker.test", "aud": "sekizui:acceptance", "sub": "user:alice",
		"role": "architect", "exp": float64(now.Add(time.Hour).Unix()), "cnf": map[string]any{"x5t#S256": thumb}}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func TestEachAlgorithmVerifies(t *testing.T) {
	for _, s := range []*sstest.Signer{sstest.NewRSA("r1"), sstest.NewEC("e1"), sstest.NewEd("d1")} {
		keys, err := signedsubject.ParseJWKS(sstest.JWKS(s))
		if err != nil {
			t.Fatalf("%s: %v", s.Alg, err)
		}
		got, err := signedsubject.Verify(s.Mint(claims(nil), nil), keys, policy(), thumb, now)
		if err != nil {
			t.Errorf("%s: a valid token refused: %v", s.Alg, err)
			continue
		}
		if got.Subject != "user:alice" || got.Role != "architect" || !got.Bound || len(got.Proof) != 32 {
			t.Errorf("%s: claims %+v", s.Alg, got)
		}
	}
}

// TestEachRefusalNamesItsReason is D303's list, one arm each — the replay arms
// (audience, time, binding) are the ones the skeleton exists for.
func TestEachRefusalNamesItsReason(t *testing.T) {
	rsaKey, other := sstest.NewRSA("r1"), sstest.NewRSA("r2")
	keys, err := signedsubject.ParseJWKS(sstest.JWKS(rsaKey))
	if err != nil {
		t.Fatal(err)
	}
	unbound := policy()
	unbound.RequireBound = false
	for _, c := range []struct {
		arm   string
		token string
		pol   signedsubject.Policy
		want  string
	}{
		{"unsigned", rsaKey.Mint(claims(nil), map[string]any{"alg": "none"}), policy(), "unsigned"},
		{"HMAC against an RSA key", rsaKey.Mint(claims(nil), map[string]any{"alg": "HS256"}), policy(), "algorithm confusion"},
		{"a key the issuer does not hold", other.Mint(claims(nil), nil), policy(), `no key "r2"`},
		{"a bad signature", rsaKey.Mint(claims(nil), nil)[:len(rsaKey.Mint(claims(nil), nil))-4] + "AAAA", policy(), "does not verify"},
		{"another issuer", rsaKey.Mint(claims(map[string]any{"iss": "https://evil.test"}), nil), policy(), "is not"},
		{"another audience (replayed)", rsaKey.Mint(claims(map[string]any{"aud": "other-service"}), nil), policy(), "replayed here"},
		{"expired", rsaKey.Mint(claims(map[string]any{"exp": float64(now.Add(-2 * time.Minute).Unix())}), nil), policy(), "expired"},
		{"not yet valid", rsaKey.Mint(claims(map[string]any{"nbf": float64(now.Add(2 * time.Minute).Unix())}), nil), policy(), "not valid before"},
		{"no expiry", rsaKey.Mint(claims(map[string]any{"exp": nil}), nil), policy(), "no `exp`"},
		{"no role", rsaKey.Mint(claims(map[string]any{"role": nil}), nil), policy(), "names no role"},
		{"bound to another certificate", rsaKey.Mint(claims(map[string]any{"cnf": map[string]any{"x5t#S256": "someone-else"}}), nil), policy(), "another certificate"},
		{"unbound, binding required", rsaKey.Mint(claims(map[string]any{"cnf": nil}), nil), policy(), "not bound"},
		{"bound to another certificate even when binding is optional", rsaKey.Mint(claims(map[string]any{"cnf": map[string]any{"x5t#S256": "x"}}), nil), unbound, "another certificate"},
		{"critical extension", rsaKey.Mint(claims(nil), map[string]any{"crit": []string{"b64"}}), policy(), "critical"},
		{"an algorithm off the allowlist", rsaKey.Mint(claims(nil), nil), signedsubject.Policy{Issuer: "https://broker.test",
			Audience: "sekizui:acceptance", Algorithms: []string{signedsubject.EdDSA}, RequireBound: true}, "allowlist"},
		{"five parts (JWE)", "a.b.c.d.e", policy(), "three"},
	} {
		_, err := signedsubject.Verify(c.token, keys, c.pol, thumb, now)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want a refusal containing %q, got %v", c.arm, c.want, err)
		}
	}

	// UNBOUND IS ACCEPTED ONLY WHERE THE ISSUER SAID SO, AND SAYS SO.
	got, err := signedsubject.Verify(rsaKey.Mint(claims(map[string]any{"cnf": nil}), nil), keys, unbound, thumb, now)
	if err != nil || got.Bound {
		t.Errorf("an unbound token under require_bound false: %+v %v; want accepted and marked unbound", got, err)
	}
}

func TestAKeyFileThatStagesConfusionIsRefused(t *testing.T) {
	raw := strings.Replace(string(sstest.JWKS(sstest.NewRSA("r1"))), `"alg":"RS256"`, `"alg":"HS256"`, 1)
	if _, err := signedsubject.ParseJWKS([]byte(raw)); err == nil || !strings.Contains(err.Error(), "declares alg") {
		t.Errorf("an RSA key declaring HS256 was accepted: %v", err)
	}
}

// FuzzVerifyNeverPanics — the parser sees attacker-chosen bytes before any
// signature says whose they are.
func FuzzVerifyNeverPanics(f *testing.F) {
	s := sstest.NewEd("d1")
	keys, _ := signedsubject.ParseJWKS(sstest.JWKS(s))
	f.Add(s.Mint(claims(nil), nil))
	f.Add("a.b.c")
	f.Add("..")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = signedsubject.Verify(token, keys, policy(), thumb, now)
		_, _ = signedsubject.PeekIssuer(token)
	})
}
