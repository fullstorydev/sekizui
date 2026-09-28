package connector

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// TargetParams is what a resolver supplies to build a Target.
//
// A separate type rather than a long parameter list so that adding a dimension
// is a compile error at the resolver and nowhere else — and, more importantly,
// so PoolKey can be derived from the Target rather than assembled by a caller
// (§6 mechanism 2: "every leak is a cache key missing a dimension").
type TargetParams struct {
	Ref       string
	Kind      string
	Tenant    string
	Residency string
	BaseURL   string

	// CredentialVersion comes from the credential REFERENCE, not the material.
	// It is part of PoolKey, which is what makes rotation invalidate pooled
	// clients rather than leaving a revoked credential working until TTL
	// expiry (§4.3.2).
	CredentialVersion string

	Credential Secret
	Settings   map[string]string
}

// NewTarget is the validating constructor — §6 mechanism 1.
//
// THE GUARANTEE AND ITS HONEST LIMIT. §6 wants "tenant absence to be a compile
// error": driver methods require a Target, Target's fields are unexported, so a
// driver method cannot be called without a resolved Target and therefore cannot
// be called without a tenant. That much holds, and it is the property that
// actually matters.
//
// What does NOT hold is perfect sealing. This constructor is exported, so any
// package can call it — Go cannot express "only internal/resolver may construct
// this" without contortions (an unexported interface method confines
// IMPLEMENTATION to the defining package, not construction). CONTRACTS §4 item 2
// anticipated exactly this and concluded that validated-single-constructor is
// what is achievable, and that weakening to exported struct fields would be
// worse because then every call site becomes a place to get it wrong.
//
// So the residual risk is "someone bypasses the resolver", not "someone forgets
// a tenant" — a much narrower and more reviewable failure. The zero Target
// remains useless: an unresolved Target has an empty tenant, and Assert catches
// it before any outbound call.
//
// This doubles as the §12.1 pull-forward spike, which asked for ~30 lines
// proving the resolver-only pattern is not fighting Go. Verdict: it is not,
// with the caveat above.
func NewTarget(p TargetParams) (Target, error) {
	const op = "connector.NewTarget"

	var missing []string
	if strings.TrimSpace(p.Ref) == "" {
		missing = append(missing, "ref")
	}
	if strings.TrimSpace(p.Kind) == "" {
		missing = append(missing, "kind")
	}
	// THE FIELD THIS WHOLE MECHANISM EXISTS FOR. A Target with no tenant is the
	// cross-pollination bug §6 is written to prevent, so it cannot be
	// constructed rather than being caught later by a review or an assertion.
	if strings.TrimSpace(p.Tenant) == "" {
		missing = append(missing, "tenant")
	}
	if len(missing) > 0 {
		return Target{}, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q cannot be constructed without %v", p.Ref, missing))
	}

	return Target{
		ref:       p.Ref,
		kind:      p.Kind,
		tenant:    p.Tenant,
		residency: p.Residency,
		baseURL:   p.BaseURL,
		credVer:   p.CredentialVersion,
		cred:      NewCredential(p.Credential),
		settings:  p.Settings,
	}, nil
}

// Resolved reports whether this Target came from NewTarget rather than being a
// zero value.
//
// The zero Target is legal to construct in Go — `var t Target` compiles — so
// unexported fields alone cannot make an unresolved Target impossible. What they
// can do is make it *detectable*, which is what Assert uses.
func (t Target) Resolved() bool { return t.ref != "" && t.tenant != "" }

// Assert is §6 mechanism 3: the egress-time check, called immediately before
// every outbound call.
//
// "Nanoseconds; catches every pooling bug." A pooled client keyed on a stale or
// incomplete PoolKey will eventually hand back a client belonging to another
// tenant, and no amount of care at construction prevents that — the bug is in
// the cache, not the constructor. This is the check that catches it, and it is
// the reason §6 lists both mechanisms rather than trusting either alone.
//
// wantTenant comes from the request context. Passing it explicitly rather than
// reading a context here keeps this package free of a context-key convention
// that drivers would have to know about.
// ErrTenantMismatch marks the one failure §6 mechanism 3 exists to produce.
//
// **GROUNDWORK FOR THE `tenant_mismatch` ESCALATION (P2 step 45), WHICH IS NOT
// BUILT YET.** The sentinel is useful on its own — it makes the one failure §6
// mechanism 3 produces identifiable — and it has no consumer until the step that
// raises the signal lands. Recorded as unfinished rather than presented as
// complete.
//
// **A SENTINEL RATHER THAN A KIND, and the distinction is the point.** The
// taxonomy answers "who is at fault and can a retry help"; this answers "which
// of our bugs was it", which is a different question and does not belong in a
// wire-visible enum that eighteen call sites switch on. `errors.Is` reaches it
// through `fault.Error.Unwrap`, so the kind stays `internal` — as it must,
// because a tenant mismatch IS an internal fault — while the escalation that
// raises `tenant_mismatch` can still recognise it exactly.
//
// **NOT COMPARED BY MESSAGE.** The text says "TENANT MISMATCH" and a matcher
// keyed on that survives exactly until somebody rewords it, which is the failure
// mode this repository already records for transport errors.
var ErrTenantMismatch = errors.New("tenant mismatch on egress")

func (t Target) Assert(wantTenant string) error {
	const op = "connector.Target.Assert"

	if !t.Resolved() {
		return fault.New(fault.KindInternal, op,
			"unresolved target reached an outbound call; it did not come from a resolver")
	}
	if wantTenant == "" {
		return fault.New(fault.KindInternal, op, fmt.Sprintf(
			"no tenant on the request for target %q; refusing rather than assuming", t.ref))
	}
	if t.tenant != wantTenant {
		// Deliberately KindInternal, not KindDenied: this is not a policy
		// refusal, it is Sekizui about to leak one tenant's credential into
		// another tenant's request. That is our bug and it must read as one.
		//
		// **WRAPPED AROUND A SENTINEL SO IT IS IDENTIFIABLE WITHOUT READING THE
		// MESSAGE.** The escalation to the `tenant_mismatch` signal has
		// to tell THIS internal error from every other one, and the kind cannot:
		// `internal` is deliberately shared with an unresolved target, an absent
		// request tenant, and anything else that is our bug rather than the
		// caller's or the vendor's. Matching on "TENANT MISMATCH" in the text
		// would break the first time somebody improves the sentence — which is
		// the argument `transportFault` already makes for `errors.Is` over a
		// string match, applied one layer up.
		return fault.Wrap(fault.KindInternal, op, fmt.Sprintf(
			"TENANT MISMATCH: target %q is bound to tenant %q but the request is for %q; "+
				"refusing egress (§6 mechanism 3)", t.ref, t.tenant, wantTenant),
			ErrTenantMismatch)
	}
	return nil
}
