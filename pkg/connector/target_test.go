package connector

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// These tests ARE the §12.1 pull-forward spike: "Target unconstructability
// spike — 30 lines proving the resolver-only pattern isn't fighting Go",
// scheduled before Phase 1 because "the entire cross-pollination guarantee rests
// on it".
//
// VERDICT: the pattern works, with one honest limit recorded in
// TestSealingIsValidatedNotAbsolute. §6 mechanism 1 stands.

func params() TargetParams {
	return TargetParams{
		Ref: "jira:acme", Kind: "jira", Tenant: "acme", Residency: "eu",
		BaseURL: "https://acme.atlassian.net", CredentialVersion: "7",
		Credential: Secret("token"),
	}
}

// TestTenantAbsenceIsRefused is §6 mechanism 1's actual content: "make tenant
// absence a compile error".
//
// Go cannot literally make it a compile error — `var t Target` compiles — but it
// can make an unresolved Target impossible to obtain from the constructor and
// detectable everywhere else. This is the first half.
func TestTenantAbsenceIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*TargetParams){
		"no tenant":         func(p *TargetParams) { p.Tenant = "" },
		"whitespace tenant": func(p *TargetParams) { p.Tenant = "   " },
		"no ref":            func(p *TargetParams) { p.Ref = "" },
		"no kind":           func(p *TargetParams) { p.Kind = "" },
	} {
		t.Run(name, func(t *testing.T) {
			p := params()
			mutate(&p)

			got, err := NewTarget(p)
			if err == nil {
				t.Fatal("constructed a target that should be impossible")
			}
			if !errors.Is(err, fault.KindConfig) {
				t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
			}
			if got.Resolved() {
				t.Error("a failed construction returned a Target reporting itself resolved")
			}
		})
	}
}

func TestValidTargetIsConstructed(t *testing.T) {
	tgt, err := NewTarget(params())
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	if !tgt.Resolved() {
		t.Error("a constructed target reports itself unresolved")
	}
	if tgt.Tenant() != "acme" || tgt.Ref() != "jira:acme" || tgt.Residency() != "eu" {
		t.Errorf("fields did not survive construction: %+v", tgt)
	}
}

// TestZeroTargetIsDetectable is the second half of mechanism 1.
//
// `var t Target` is legal Go and no amount of unexported fields prevents it. The
// property that CAN be had is that the zero value is useless and says so — which
// is what Assert relies on to stop one reaching an outbound call.
func TestZeroTargetIsDetectable(t *testing.T) {
	var zero Target

	if zero.Resolved() {
		t.Error("the zero Target reports itself resolved")
	}
	if err := zero.Assert("acme"); err == nil {
		t.Error("an unresolved target passed the egress assertion")
	}
}

// TestSealingIsValidatedNotAbsolute records the spike's honest limit.
//
// CONTRACTS §4 item 2 predicted this: perfect cross-package sealing is not
// achievable in Go, because an unexported interface method confines
// IMPLEMENTATION to a package, not CONSTRUCTION. NewTarget is exported, so any
// package can call it — the resolver is the only intended caller by convention,
// not by compiler.
//
// The trade is deliberate and item 2 states it: weakening to exported struct
// fields would be worse, because then every call site becomes a place to forget
// a tenant. Here there is exactly one place, and it validates.
//
// So the residual risk is "someone bypasses the resolver" — narrow, greppable,
// and reviewable — rather than "someone forgot a tenant", which is neither.
func TestSealingIsValidatedNotAbsolute(t *testing.T) {
	// Any package can do this. That is the limit, stated rather than hidden.
	tgt, err := NewTarget(params())
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	// What cannot be done is produce a VALID target without a tenant, which is
	// the property §6 actually needs.
	bad := params()
	bad.Tenant = ""
	if _, err := NewTarget(bad); err == nil {
		t.Fatal("the one property the mechanism must guarantee does not hold")
	}
	if !tgt.Resolved() {
		t.Error("precondition")
	}
}

// TestPoolKeyIsDerivedFromTheType is §6 mechanism 2: "derive pool keys from the
// type, never at call sites. Every leak is a cache key missing a dimension."
func TestPoolKeyIsDerivedFromTheType(t *testing.T) {
	base, _ := NewTarget(params())

	otherTenant := params()
	otherTenant.Tenant = "contoso"
	otherTenant.Ref = "jira:contoso"
	other, _ := NewTarget(otherTenant)

	if base.PoolKey() == other.PoolKey() {
		t.Error("two tenants share a pool key; a pooled client would be handed to the wrong one")
	}

	// Rotation MUST change the key, or a revoked credential keeps working from
	// the pool until TTL expiry (§4.3.2).
	rotated := params()
	rotated.CredentialVersion = "8"
	after, _ := NewTarget(rotated)

	if base.PoolKey() == after.PoolKey() {
		t.Error("rotating the credential did not change the pool key; the pooled client " +
			"would keep using the revoked credential")
	}
}

// TestEgressAssertion is §6 mechanism 3: "assert before every egress… nanoseconds;
// catches every pooling bug".
func TestEgressAssertion(t *testing.T) {
	tgt, _ := NewTarget(params())

	if err := tgt.Assert("acme"); err != nil {
		t.Errorf("matching tenant was refused: %v", err)
	}

	t.Run("mismatch is refused", func(t *testing.T) {
		err := tgt.Assert("contoso")
		if err == nil {
			t.Fatal("a target bound to one tenant passed an assertion for another")
		}
		// KindInternal, not KindDenied: this is not policy refusing a request,
		// it is Sekizui about to leak one tenant's credential into another
		// tenant's call. Our bug, and it must read as one.
		if !errors.Is(err, fault.KindInternal) {
			t.Errorf("kind = %v, want KindInternal — a tenant mismatch is our bug, "+
				"not a policy decision", fault.KindOf(err))
		}
		if !strings.Contains(err.Error(), "TENANT MISMATCH") {
			t.Errorf("the loudest possible failure was not loud: %v", err)
		}
	})

	t.Run("empty request tenant is refused rather than assumed", func(t *testing.T) {
		if err := tgt.Assert(""); err == nil {
			t.Error("an empty tenant was treated as a match; assuming is how a leak starts")
		}
	})
}

// TestCredentialStaysRedactedThroughConstruction — construction must not be a
// hole in the redaction that pkg/connector otherwise guarantees.
func TestCredentialStaysRedactedThroughConstruction(t *testing.T) {
	p := params()
	p.Credential = Secret("super-secret-value")

	tgt, err := NewTarget(p)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	// Lending, not a getter (D127): the material is reachable only inside a
	// callback, and the callback is the only place the real bytes exist.
	var lent string
	if err := tgt.Use(func(m Material) error {
		b, err := m.AppendTo(nil)
		lent = string(b)
		return err
	}); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if lent != "super-secret-value" {
		t.Errorf("Use lent %q, want the resolved material", lent)
	}
	if got := fmt.Sprintf("%v", tgt); strings.Contains(got, "super-secret-value") {
		t.Errorf("the credential leaked through %%v on the Target: %q", got)
	}

	// And a construction FAILURE must not spill it into the error message,
	// which is the likelier accident: error strings get logged everywhere.
	bad := p
	bad.Tenant = ""
	_, err = NewTarget(bad)
	if err == nil {
		t.Fatal("precondition")
	}
	if strings.Contains(err.Error(), "super-secret-value") {
		t.Errorf("construction error leaked the credential: %v", err)
	}
}

// TestPoolKeyCannotBePrinted is D112, and it is the second use of the
// self-redacting pattern Secret established (§4.3.3).
//
// Every formatting verb a developer might reach for must yield only the safe
// half. A reviewer can remember; a %v in an error path written at 3am cannot.
func TestPoolKeyCannotBePrinted(t *testing.T) {
	p := params()
	p.CredentialVersion = "gcp-sm://projects/acme-prod/secrets/jira-token/versions/7#3"
	tgt, err := NewTarget(p)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	key := tgt.PoolKey()

	for _, rendered := range []string{
		key.String(),
		key.GoString(),
		fmt.Sprintf("%v", key),
		//nolint:gosimple,staticcheck // exercising the verb IS the test: %s must
		// route through String(), and simplifying it away would stop checking that
		fmt.Sprintf("%s", key),
		fmt.Sprintf("%+v", key),
		fmt.Sprintf("%#v", key),
		fmt.Sprint(key),
	} {
		if strings.Contains(rendered, "acme-prod") || strings.Contains(rendered, "versions/7") {
			t.Errorf("a rendering leaks the credential reference: %q", rendered)
		}
	}

	// Non-vacuous: the safe half must actually be there, or a key that printed
	// nothing at all would pass.
	if got := key.String(); !strings.Contains(got, "jira:acme") {
		t.Errorf("String() = %q, want the kind and ref so a log is still useful", got)
	}

	// And slog must take the LogValue path rather than reflecting the struct.
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("pooled", "key", key)
	if strings.Contains(buf.String(), "acme-prod") {
		t.Errorf("slog leaked the reference: %s", buf.String())
	}
}
