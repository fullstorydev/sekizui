package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// The resolver is §6 mechanism 1's sole constructor: nothing else may build a
// Target, so every guarantee about tenancy and residency passes through here.
// It shipped with NO tests, which a coverage audit caught — the most
// security-critical package in the tree at 0%.

const doc = `
targets:
  - {ref: kata:eu, kind: kata, tenant: alpha, residency: eu, credential: env://SEKIZUI_RES_TOK}
  - {ref: kata:us, kind: kata, tenant: beta,  residency: us, credential: env://SEKIZUI_RES_TOK}
  - {ref: kata:none, kind: kata, tenant: gamma}
  - {ref: kata:notenant, kind: kata, residency: eu}
  - {ref: kata:badscheme, kind: kata, tenant: delta, credential: vault://secret/x}
`

func build(t *testing.T, permitted ...string) *Resolver {
	t.Helper()
	t.Setenv("SEKIZUI_RES_TOK", "resolver-token")

	var d config.Document
	if err := yaml.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	profile := runtime.Detect(func(k string) string {
		if k == "SEKIZUI_REGION" {
			return "europe-west1"
		}
		return ""
	}, runtime.Override{})

	return New(&d, profile, permitted, config.EnvProvider{})
}

func TestResolvesAConfiguredTarget(t *testing.T) {
	tgt, err := build(t, "eu").Resolve(context.Background(), "kata:eu")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !tgt.Resolved() {
		t.Error("the resolver produced an unresolved Target")
	}
	if tgt.Tenant() != "alpha" || tgt.Kind() != "kata" || tgt.Residency() != "eu" {
		t.Errorf("fields lost: %+v", tgt)
	}
	// The credential version is what makes rotation invalidate a pooled client
	// (§4.3.2) — but it must NOT be readable from the key, which is now a
	// self-redacting type (D112). This assertion used to require the opposite:
	// that the credential reference appeared in the key's string form.
	if got := tgt.PoolKey().String(); strings.Contains(got, "SEKIZUI_RES_TOK") {
		t.Errorf("PoolKey prints the credential reference: %q. A secret-manager path "+
			"names a project and a secret, which is infrastructure layout nobody needs "+
			"in a log line", got)
	}
	if got := fmt.Sprintf("%v", tgt); strings.Contains(got, "resolver-token") {
		t.Errorf("the credential leaked through %%v on the Target: %q", got)
	}
}

// TestUnknownTargetIsAConfigFault — D211.
//
// **IT USED TO ASSERT `not_found`, AND THE RENAME IS THE POINT.** A caller
// cannot arrive here with a ref of its own invention: boot refuses a grant whose
// `target_ref` names no declared target, and policy runs before the resolver, so
// an unauthorised ref is denied earlier. Reaching this line means the grant table
// and the target list disagree — ours to fix, and `not_found` now means a caller
// named something that does not exist.
func TestUnknownTargetIsAConfigFault(t *testing.T) {
	_, err := build(t).Resolve(context.Background(), "kata:invented")
	if !errors.Is(err, fault.KindConfig) {
		t.Errorf("kind = %v, want KindConfig: a target missing from configuration while "+
			"policy authorised it is an inconsistency in this deployment, not a caller "+
			"naming something that does not exist (D211)", fault.KindOf(err))
	}
}

// TestResidencyRefusalIsClassifiedSeparately — §7.1 item 2.
//
// KindResidency rather than KindDenied, because the remedies differ completely:
// a denial is a grant to review, a residency conflict is a deployment topology
// problem, and an operator should not have to infer which from the message.
func TestResidencyRefusalIsClassifiedSeparately(t *testing.T) {
	_, err := build(t, "eu").Resolve(context.Background(), "kata:us")
	if err == nil {
		t.Fatal("a us-resident target resolved in an eu-only deployment")
	}
	if !errors.Is(err, fault.KindResidency) {
		t.Errorf("kind = %v, want KindResidency", fault.KindOf(err))
	}
	// The message must name the region, or the operator cannot tell which side
	// is misconfigured.
	if !strings.Contains(err.Error(), "europe-west1") {
		t.Errorf("the error does not name the instance region: %v", err)
	}
}

// TestResidencyRefusesBeforeReadingTheSecret. Ordering matters: a cross-region
// target must never cause a secret-manager read, or a compliance boundary
// becomes an access pattern in someone's audit of the secret manager.
func TestResidencyRefusesBeforeReadingTheSecret(t *testing.T) {
	// No token in the environment at all. If the resolver read the credential
	// first, the error would be about a missing variable rather than residency.
	var d config.Document
	yaml.Unmarshal([]byte(doc), &d)
	profile := runtime.Detect(func(string) string { return "" }, runtime.Override{})
	r := New(&d, profile, []string{"eu"}, config.EnvProvider{})

	_, err := r.Resolve(context.Background(), "kata:us")
	if !errors.Is(err, fault.KindResidency) {
		t.Errorf("kind = %v, want KindResidency — residency must be checked before "+
			"the credential is read", fault.KindOf(err))
	}
}

// TestEmptyPermittedSetIsUnconstrained. Correct for a single-region deployment
// that has not thought about residency yet; refusing everything would make the
// feature impossible to adopt gradually.
func TestEmptyPermittedSetIsUnconstrained(t *testing.T) {
	if _, err := build(t).Resolve(context.Background(), "kata:us"); err != nil {
		t.Errorf("an unconstrained deployment refused a target: %v", err)
	}
}

// TestTenantAbsenceIsRefusedByTheConstructor — §6 mechanism 1, reached through
// the resolver rather than by calling NewTarget directly.
func TestTenantAbsenceIsRefusedByTheConstructor(t *testing.T) {
	_, err := build(t).Resolve(context.Background(), "kata:notenant")
	if err == nil {
		t.Fatal("a target with no tenant resolved; §6 mechanism 1 does not hold")
	}
	if !errors.Is(err, fault.KindConfig) {
		t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
	}
}

func TestTargetWithNoCredentialIsLegitimate(t *testing.T) {
	tgt, err := build(t).Resolve(context.Background(), "kata:none")
	if err != nil {
		t.Fatalf("a credential-free target was refused: %v", err)
	}
	// A credential-free target must REFUSE a borrow rather than lend nothing:
	// an empty slice reaching a driver becomes an unauthenticated request the
	// upstream rejects, which reads in the audit as the target's refusal.
	if err := tgt.Use(func(connector.Material) error { return nil }); err == nil {
		t.Error("a credential-free target lent material; it must refuse")
	}
}

func TestUnregisteredSchemeIsRefused(t *testing.T) {
	_, err := build(t).Resolve(context.Background(), "kata:badscheme")
	if err == nil {
		t.Fatal("a vault:// ref resolved with no vault provider registered")
	}
	if !strings.Contains(err.Error(), "vault") {
		t.Errorf("the error does not name the missing scheme: %v", err)
	}
}

// TestResolveHonoursCancellation — the credential read is I/O, and every path
// through it must respect a deadline.
func TestResolveHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := build(t, "eu").Resolve(ctx, "kata:eu"); err == nil {
		t.Error("resolution proceeded on a cancelled context")
	}
}

func TestKindsListsEveryTarget(t *testing.T) {
	kinds := build(t).Kinds()
	if len(kinds) != 5 {
		t.Errorf("Kinds returned %d entries, want 5", len(kinds))
	}
	if kinds["kata:eu"] != "kata" {
		t.Errorf("Kinds[kata:eu] = %q", kinds["kata:eu"])
	}
}
