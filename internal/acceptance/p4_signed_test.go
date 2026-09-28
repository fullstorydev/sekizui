package acceptance

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/fullstorydev/sekizui/internal/identity"
	"github.com/fullstorydev/sekizui/internal/signedsubject"
	"github.com/fullstorydev/sekizui/internal/signedsubject/sstest"
	"github.com/fullstorydev/sekizui/pkg/config"
	filecred "github.com/fullstorydev/sekizui/pkg/provider/file"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// THE SIGNED-SUBJECT SKELETON (D303, D318), P4 steps 26-30: a broker signs the
// subject, the connection still proves the caller, a role selects Sekizui's own
// grants, and a token may only narrow them.

const (
	testIssuer   = "https://broker.acceptance.test"
	testAudience = "sekizui:acceptance"
)

// signedEnv is one run with an issuer pinned, its key file on disk under a
// file:// root, and two roles.
type signedEnv struct {
	r      *run
	keys   string // the JWKS path, which a step may rewrite to rotate
	signer *sstest.Signer
}

func newSignedEnv(t *testing.T, patch func(*config.IssuerSpec), signers ...*sstest.Signer) *signedEnv {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "broker.jwks")
	if len(signers) == 0 {
		signers = []*sstest.Signer{sstest.NewEC("k1")}
	}
	if err := os.WriteFile(keys, sstest.JWKS(signers...), 0o600); err != nil {
		t.Fatal(err)
	}
	// THE file:// PROVIDER, ROOTED AT THE KEYS' DIRECTORY (D286, D318) — the
	// binary's own reader, confined as it confines a secret.
	provider := filecred.New(filecred.Roots(dir))
	r := newRunWith(t, runOpts{
		issuerKeys: func(ctx context.Context, ref string) ([]byte, error) {
			res, err := provider.Resolve(ctx, ref)
			return res.Material, err
		},
		patch: func(d *config.Document) {
			is := config.IssuerSpec{Issuer: testIssuer, Audience: testAudience, Keys: "file://" + keys,
				Algorithms: config.SubjectTokenAlgorithms(), Callers: []string{"agent:triage", "mesh:primary"}}
			if patch != nil {
				patch(&is)
			}
			d.Issuers = append(d.Issuers, is)
			d.Grants = append(d.Grants,
				config.GrantSpec{Principal: "role:architect", Allow: []config.CapabilitySpec{
					{Action: "kata.read", TargetRef: "kata:alpha"},
					{Action: "kata.create_issue", TargetRef: "kata:alpha"}}},
				config.GrantSpec{Principal: "role:viewer", Allow: []config.CapabilitySpec{
					{Action: "kata.read", TargetRef: "kata:alpha"}}})
		},
	})
	return &signedEnv{r: r, keys: keys, signer: signers[0]}
}

// thumbOf is RFC 8705's x5t#S256 of a principal's client certificate.
func (e *signedEnv) thumbOf(t *testing.T, principal string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(e.r.bundle.ClientCerts[principal], e.r.bundle.ClientKeys[principal])
	if err != nil {
		t.Fatal(err)
	}
	return signedsubject.Thumbprint(pair.Certificate[0])
}

// token mints a subject token for user:alice bound to boundTo's certificate,
// with over applied (a nil value deletes a claim).
func (e *signedEnv) token(t *testing.T, boundTo string, over map[string]any) string {
	t.Helper()
	c := map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "user:alice", "role": "architect",
		"exp": float64(time.Now().Add(time.Hour).Unix()), "cnf": map[string]any{"x5t#S256": e.thumbOf(t, boundTo)}}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return e.signer.Mint(c, nil)
}

func withToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, identity.SubjectTokenHeader, token)
}

// read asks for kata:alpha's read as principal, carrying token.
func (e *signedEnv) read(t *testing.T, principal, token string) (*sekizuiv1.QueryResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.r.as(t, principal).Query(withToken(ctx, token), &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
}

// write asks for a kata issue as principal, carrying token.
func (e *signedEnv) write(t *testing.T, principal, token string) (*sekizuiv1.ExecuteResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.r.as(t, principal).Execute(withToken(ctx, token), &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
		Action: "kata.create_issue", TargetRef: "kata:alpha",
		Args:           mustArgs(t, map[string]any{"project": "PROJ", "title": "signed"}),
		IdempotencyKey: "p4-signed-" + time.Now().Format("150405.000000000"),
	}})
}

// recordOf is the audit record the decision id names.
func (e *signedEnv) recordOf(t *testing.T, id string) *sekizuiv1.Decision {
	t.Helper()
	for _, d := range readLog(t, e.r.path) {
		if d.GetId() == id && d.GetIdentity() != nil {
			return d
		}
	}
	t.Fatalf("no record %s in the audit log", id)
	return nil
}

// p4Step26 — a token from the pinned issuer names the subject, and the record
// says SIGNED.
func p4Step26(t *testing.T) {
	e := newSignedEnv(t, nil)
	e.r.narrate(t, "a token from the pinned issuer names the subject, and the record says SIGNED")
	if e.r.localOnly(t, "the issuer and its keys are this instance's configuration") {
		return
	}
	tok := e.token(t, "agent:triage", nil)
	resp, err := e.read(t, "agent:triage", tok)
	if err != nil || resp.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 26: a valid bound token from the pinned issuer was refused: %v %s", err, resp.GetReason())
	}
	d := e.recordOf(t, resp.GetDecisionId())
	id := d.GetIdentity()
	sub := id.GetSubject()
	switch {
	case id.GetCaller().GetPrincipal() != "agent:triage":
		t.Errorf("step 26: the caller is %q; the connection still proves it", id.GetCaller().GetPrincipal())
	case sub.GetPrincipal() != "user:alice" || sub.GetAssertion() != sekizuiv1.Assertion_ASSERTION_SIGNED:
		t.Errorf("step 26: the subject is %q %v; want user:alice SIGNED", sub.GetPrincipal(), sub.GetAssertion())
	case sub.GetIssuer() != testIssuer || sub.GetRole() != "role:architect" || sub.GetUnbound():
		t.Errorf("step 26: issuer %q role %q unbound %v", sub.GetIssuer(), sub.GetRole(), sub.GetUnbound())
	case len(sub.GetProof()) != 32:
		t.Errorf("step 26: the proof is %d bytes; want the token's SHA-256", len(sub.GetProof()))
	case strings.Join(id.GetChain(), ",") != "agent:triage,user:alice":
		t.Errorf("step 26: the chain is %v; unchanged in shape, caller then subject (§4.4.2)", id.GetChain())
	}
	// THE TOKEN ITSELF IS NEVER RECORDED — it is a bearer credential (D318).
	raw, err := os.ReadFile(e.r.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), strings.Split(tok, ".")[2]) {
		t.Error("step 26: the audit log contains the token's signature — a replayable credential was recorded")
	}
	e.r.detail(t, "agent:triage presented a bound token: the record names user:alice SIGNED by %s as %s, chain "+
		"[agent:triage user:alice], the token's hash as proof and the token nowhere", testIssuer, sub.GetRole())
}

// p4Step27 — a token that is not a valid one from a configured issuer refuses
// before policy, one arm per check.
func p4Step27(t *testing.T) {
	e := newSignedEnv(t, nil)
	e.r.narrate(t, "a token that is not a valid one from a configured issuer refuses before policy")
	if e.r.localOnly(t, "the issuer and its keys are this instance's configuration") {
		return
	}
	stranger := sstest.NewEC("k1") // same kid, not the issuer's key
	good := func(over map[string]any) string { return e.token(t, "agent:triage", over) }
	before := len(readLog(t, e.r.path))
	for _, c := range []struct {
		arm, token, want string
	}{
		{"an unknown issuer", good(map[string]any{"iss": "https://elsewhere.test"}), "not one this deployment pins"},
		{"alg none", e.signer.Mint(map[string]any{"iss": testIssuer}, map[string]any{"alg": "none"}), "unsigned"},
		{"HMAC against an EC key", e.signer.Mint(map[string]any{"iss": testIssuer}, map[string]any{"alg": "HS256"}), "algorithm confusion"},
		{"aud naming another service (replayed)", good(map[string]any{"aud": "another-service"}), "replayed here"},
		{"expired (replayed later)", good(map[string]any{"exp": float64(time.Now().Add(-5 * time.Minute).Unix())}), "expired"},
		{"not yet valid", good(map[string]any{"nbf": float64(time.Now().Add(5 * time.Minute).Unix())}), "not valid before"},
		{"a bad signature", stranger.Mint(map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "user:alice",
			"role": "architect", "exp": float64(time.Now().Add(time.Hour).Unix())}, nil), "does not verify"},
		{"an unknown role", good(map[string]any{"role": "wizard"}), `"role:wizard", which has no grant`},
	} {
		resp, err := e.read(t, "agent:triage", c.token)
		if err == nil {
			t.Errorf("step 27 %s: served (%s); want a refusal", c.arm, resp.GetStatus())
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("step 27 %s: refused as %v; want the reason %q", c.arm, err, c.want)
		}
	}
	// AN UNLISTED CALLER: a valid token bound to agent:jobs's own certificate,
	// from agent:jobs — everything checks out but the issuer's enumeration.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := e.r.as(t, "agent:jobs").Query(withToken(ctx, e.token(t, "agent:jobs", nil)),
		&sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
	if err == nil || !strings.Contains(err.Error(), "may not present tokens") {
		t.Errorf("step 27 an unlisted caller: %v; want a refusal naming the issuer's enumerated callers (D318)", err)
	}
	// NONE REACHED POLICY: identity refused each, so no decision was recorded.
	if after := len(readLog(t, e.r.path)); after != before {
		t.Errorf("step 27: %d decision(s) were recorded for tokens identity refused; they must never reach policy",
			after-before)
	}
	e.r.detail(t, "eight bad tokens — unknown issuer, alg none, HMAC confusion, wrong audience, expired, not yet "+
		"valid, bad signature, unknown role — and a valid one from a caller the issuer does not list: each refused "+
		"with its reason, none reaching policy")
}

// p4Step28 — a token bound to another certificate refuses, and an unbound one
// refuses by default.
func p4Step28(t *testing.T) {
	e := newSignedEnv(t, nil)
	e.r.narrate(t, "a token bound to another certificate refuses, and an unbound one refuses by default")
	if e.r.localOnly(t, "the issuer and its keys are this instance's configuration") {
		return
	}
	// 28a — BOUND ELSEWHERE: always refused.
	if _, err := e.read(t, "agent:triage", e.token(t, "agent:jobs", nil)); err == nil ||
		!strings.Contains(err.Error(), "another certificate") {
		t.Errorf("step 28a: a token bound to agent:jobs's certificate, presented by agent:triage: %v", err)
	}
	// 28b — UNBOUND: refused by default.
	if _, err := e.read(t, "agent:triage", e.token(t, "agent:triage", map[string]any{"cnf": nil})); err == nil ||
		!strings.Contains(err.Error(), "not bound") {
		t.Errorf("step 28b: an unbound token was not refused by default: %v", err)
	}
	// 28c — THROUGH A MESH: bound to the mesh's certificate, accepted from the
	// mesh and refused from the agent it names.
	meshTok := e.token(t, "mesh:primary", nil)
	wrote, err := e.write(t, "mesh:primary", meshTok)
	if err != nil || wrote.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("step 28c: the mesh-bound token was refused from the mesh: %v %s", err, wrote.GetResult().GetReason())
	}
	if _, err := e.read(t, "agent:triage", meshTok); err == nil || !strings.Contains(err.Error(), "another certificate") {
		t.Errorf("step 28c: the mesh-bound token was accepted from agent:triage: %v", err)
	}

	// 28d — AN ISSUER THAT SAYS require_bound: false admits unbound tokens,
	// and every record says so.
	relaxed := newSignedEnv(t, func(is *config.IssuerSpec) { f := false; is.RequireBound = &f })
	resp, err := relaxed.read(t, "agent:triage", relaxed.token(t, "agent:triage", map[string]any{"cnf": nil}))
	if err != nil || resp.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 28d: an unbound token under require_bound false was refused: %v", err)
	}
	if !relaxed.recordOf(t, resp.GetDecisionId()).GetIdentity().GetSubject().GetUnbound() {
		t.Error("step 28d: the record admitting an unbound token does not say `unbound`")
	}
	if _, err := relaxed.read(t, "agent:triage", relaxed.token(t, "agent:jobs", nil)); err == nil {
		t.Error("step 28d: a token bound to another certificate was accepted where binding is optional — a mismatch ALWAYS refuses")
	}
	e.r.detail(t, "bound elsewhere: refused; unbound: refused by default, admitted and marked unbound where the "+
		"issuer says require_bound false; a mesh-bound token served the mesh and was refused from the agent")
}

// p4Step29 — issuer keys come through file://, rotate, and cost no network on
// the request path.
func p4Step29(t *testing.T) {
	old, next := sstest.NewEC("k1"), sstest.NewEC("k2")
	e := newSignedEnv(t, nil, old)
	e.r.narrate(t, "issuer keys come through file://, rotate, and cost no network on the request path")
	if e.r.localOnly(t, "the issuer's key file is this instance's") {
		return
	}
	oldTok := e.token(t, "agent:triage", nil)
	if _, err := e.read(t, "agent:triage", oldTok); err != nil {
		t.Fatalf("step 29: the first key's token was refused: %v", err)
	}
	// ROTATE: add the new key, then retire the old — with no restart.
	if err := os.WriteFile(e.keys, sstest.JWKS(old, next), 0o600); err != nil {
		t.Fatal(err)
	}
	e.signer = next
	if _, err := e.read(t, "agent:triage", e.token(t, "agent:triage", nil)); err != nil {
		t.Errorf("step 29: after adding k2, its token was refused: %v", err)
	}
	if err := os.WriteFile(e.keys, sstest.JWKS(next), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.read(t, "agent:triage", oldTok); err == nil || !strings.Contains(err.Error(), `no key "k1"`) {
		t.Errorf("step 29: a token signed by the retired key was not refused: %v", err)
	}
	// NO NETWORK ON THE REQUEST PATH: keys are file:// or the boot refuses.
	doc := &config.Document{Grants: []config.GrantSpec{{Principal: "agent:triage"}}, Issuers: []config.IssuerSpec{{
		Issuer: testIssuer, Audience: testAudience, Keys: "https://broker.acceptance.test/jwks",
		Algorithms: []string{"ES256"}, Callers: []string{"agent:triage"}}}}
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "comes through file://") {
		t.Errorf("step 29: an issuer whose keys are a URL was not refused: %v", err)
	}
	e.r.detail(t, "keys read through the file:// provider under its root: k1 served, k2 added and served, k1 "+
		"retired and its token refused, all without a restart; a URL for keys refuses the boot")
}

// p4Step30 — a role selects Sekizui's grant set, and a token may only narrow it.
func p4Step30(t *testing.T) {
	e := newSignedEnv(t, nil)
	e.r.narrate(t, "a role selects Sekizui's grant set, and a token may only narrow it")
	if e.r.localOnly(t, "the issuer and its roles are this instance's configuration") {
		return
	}
	// 30a — THE ROLE DECIDES: viewer may read and may not write, though the
	// caller could do both.
	viewer := e.token(t, "agent:triage", map[string]any{"role": "viewer"})
	if resp, err := e.read(t, "agent:triage", viewer); err != nil || resp.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("step 30a: the viewer role's read was refused: %v", err)
	}
	if w, err := e.write(t, "agent:triage", viewer); err != nil || w.GetResult().GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Errorf("step 30a: the viewer role wrote: %v %v", err, w.GetResult().GetStatus())
	}
	// 30b — THE TOKEN NARROWS: architect limited to kata.read may not write.
	narrow := e.token(t, "agent:triage", map[string]any{"grants": []any{"kata.read"}})
	w, err := e.write(t, "agent:triage", narrow)
	if err != nil || w.GetResult().GetStatus() == sekizuiv1.Status_STATUS_OK ||
		!strings.Contains(w.GetResult().GetReason(), "the token narrows") {
		t.Errorf("step 30b: an architect token narrowed to kata.read wrote, or not for that reason: %v %s", err,
			w.GetResult().GetReason())
	}
	// 30c — A FORGED CLAIM GETS THE ROLE AND NOTHING BEYOND, AND IS NOTED.
	forged := e.token(t, "agent:triage", map[string]any{"grants": []any{"kata.read", "kata.delete_project"}})
	resp, err := e.read(t, "agent:triage", forged)
	if err != nil || resp.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 30c: the read under a token claiming extra grants was refused: %v", err)
	}
	if excess := e.recordOf(t, resp.GetDecisionId()).GetIdentity().GetSubject().GetExcessGrants(); strings.Join(excess, ",") != "kata.delete_project" {
		t.Errorf("step 30c: the record notes excess %v; want kata.delete_project, the claim the role lacks", excess)
	}
	// 30d — LENSES ADD: a token naming a lens restricts what arrives.
	lensed := e.token(t, "agent:triage", map[string]any{"lenses": []any{"no-pii-to-analytics"}})
	plain, err1 := e.read(t, "agent:triage", e.token(t, "agent:triage", nil))
	restricted, err2 := e.read(t, "agent:triage", lensed)
	if err1 != nil || err2 != nil {
		t.Fatalf("step 30d: %v %v", err1, err2)
	}
	email := func(q *sekizuiv1.QueryResponse) any {
		u, _ := q.GetRows()[0].AsMap()["user"].(map[string]any)
		return u["email"]
	}
	if email(plain) == nil || email(restricted) != nil {
		t.Errorf("step 30d: email without the lens %v, with it %v; the token's lens must withhold it", email(plain), email(restricted))
	}
	e.r.detail(t, "viewer read and could not write; architect narrowed to kata.read could not write; a claim to "+
		"kata.delete_project granted nothing and was noted on the record; a token-added lens withheld user.email")
}
