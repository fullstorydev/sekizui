// Package resolver turns a target reference into a resolved Target.
//
// PRIVATE (D35). THE SOLE CONSTRUCTOR in practice — §6 mechanism 1's "make
// tenant absence a compile error" rests on nothing else calling
// connector.NewTarget. Go cannot enforce that (CONTRACTS §4 item 2), so the
// property is: one place constructs Targets, and it validates. The residual risk
// is "someone bypassed the resolver", which is greppable, rather than "someone
// forgot a tenant", which is not.
//
// P0 SCOPE, deliberately thin: resolve, validate residency, cache nothing. The
// credential cache with versioned keys and jittered expiry (§4.3.2), the keyed
// client pool with singleflight, and warm-start (§7.1) are all P1 — this is the
// seam they land behind.
//
// DESIGN.md references: §4.3, §4.7, §6, §7.1, D29.
package resolver

import (
	"context"
	"fmt"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// THE PUBLISHED INTERFACE IS SATISFIED, AND SAID SO. `connector.Resolver`
// documents what a resolver must do — refuse a residency conflict, cache the
// credential with the version in the key — and nothing in the tree connected it
// to the one implementation. The method sets matched by coincidence, which is
// how a published contract drifts from the thing that honours it: change one
// signature and the interface quietly describes nobody.
//
// A compile-time assertion rather than a comment, so the two cannot separate
// without the build saying so. Found by extending archcheck to exported TYPES
// (CONTRACTS §4 item 33) — the interface had no reference anywhere.
var _ connector.Resolver = (*Resolver)(nil)

// Resolver constructs Targets from configuration.
type Resolver struct {
	targets map[string]config.TargetSpec
	creds   *credential.Cache
	profile runtime.Profile

	// permitted are the residency classifications this deployment may serve.
	// Empty means unconstrained (§7.1 residency item 2).
	permitted []string
}

// New builds a Resolver over a validated document, with a credential cache of
// its own.
//
// DELEGATES TO NewWithCache RATHER THAN ASSEMBLING A SECOND ONE. The two bodies
// were identical but for the cache — same map sizing, same target loop — and
// two constructors for one struct is how the two come to differ: a field added
// to the struct is initialised in whichever one the author was looking at, and
// the other silently produces a zero value. Found by the type-resolved orphan
// guard, which reported this function as having no non-test caller at all
// (`New` is declared 17 times in `internal/`, so the bare-name matcher had
// counted somebody else's every time).
func New(doc *config.Document, profile runtime.Profile, permitted []string,
	providers ...config.Provider) *Resolver {

	return NewWithCache(doc, profile, permitted, credential.New(providers))
}

// NewWithCache is New with a caller-supplied credential cache.
//
// THE PRODUCTION PATH, and not merely a test seam: `cmd/sekizui` builds ONE
// cache and hands it to both the resolver and the boot-time credential checks,
// so a target's credential is resolved once and D152's version marks are
// consulted against the same entries the command path will use. A test
// substituting the clock or the jitter source (§4.7.6) is the other user.
func NewWithCache(doc *config.Document, profile runtime.Profile, permitted []string,
	creds *credential.Cache) *Resolver {

	r := &Resolver{
		targets:   make(map[string]config.TargetSpec, len(doc.Targets)),
		creds:     creds,
		profile:   profile,
		permitted: permitted,
	}
	for _, t := range doc.Targets {
		r.targets[t.Ref] = t
	}
	return r
}

// Resolve produces a Target for ref, or refuses.
//
// THE ORDER OF CHECKS IS DELIBERATE: existence, then residency, then credential.
// Residency before credential means a cross-region target never causes a secret
// manager read — refusing early keeps a compliance boundary from becoming an
// access pattern that shows up in someone's audit of the secret manager.
func (r *Resolver) Resolve(ctx context.Context, ref string) (connector.Target, error) {
	const op = "resolver.Resolve"

	// Honour cancellation before doing anything. A resolve involves a
	// SecretProvider, and while EnvProvider is instant, GCP Secret Manager or
	// Vault is network I/O — the contract has to hold for every implementation,
	// not the cheapest one. Checked here rather than only inside the provider so
	// a provider that forgets does not silently become the exception.
	if err := ctx.Err(); err != nil {
		return connector.Target{}, fault.Wrap(fault.KindTimeout, op,
			"context done before resolving "+ref, err)
	}

	spec, ok := r.targets[ref]
	if !ok {
		// **KindConfig, NOT KindNotFound (D211), and reachability is the
		// argument.** Boot refuses a grant whose `target_ref` names no declared
		// target (`grantcheck`), and policy runs before the resolver — so a
		// caller cannot arrive here with a ref of its own invention: it would
		// have been denied for lacking a grant. Reaching this line means the
		// configuration or the plumbing is inconsistent with itself, which is
		// ours to fix and is what KindConfig says. `not_found` now means a
		// caller named something that does not exist, and this is not that.
		return connector.Target{}, fault.New(fault.KindConfig, op,
			fmt.Sprintf("no target %q in configuration, yet policy authorised it — the "+
				"grant table and the target list disagree, which boot refuses and so "+
				"should be unreachable here", ref))
	}

	// §7.1 residency item 2: "refuse to resolve a target whose residency
	// conflicts with the instance region, rather than discovering it in an
	// audit." KindResidency, not KindDenied — a denial is a grant to review, a
	// residency conflict is a deployment topology problem, and an operator
	// should not have to infer which (see fault.KindResidency).
	if !r.profile.ResidencyPermitted(r.permitted, spec.Residency) {
		return connector.Target{}, fault.New(fault.KindResidency, op, fmt.Sprintf(
			"target %q is %s-resident; this deployment serves %v (region %q) and will not "+
				"resolve it — move the workload or widen the permitted set deliberately",
			ref, spec.Residency, r.permitted, r.profile.Region))
	}

	cred, version, err := r.credential(ctx, spec)
	if err != nil {
		return connector.Target{}, err
	}

	// connector.NewTarget is the validating constructor. A missing tenant is
	// refused here rather than becoming a Target that leaks later (§6).
	return connector.NewTarget(connector.TargetParams{
		Ref:               spec.Ref,
		Kind:              spec.Kind,
		Tenant:            spec.Tenant,
		Residency:         spec.Residency,
		BaseURL:           spec.BaseURL,
		CredentialVersion: version,
		Credential:        cred,
		Settings:          spec.Settings,
	})
}

// credential resolves the reference, through the cache (§4.7.6).
//
// WAS A PROVIDER CALL PER COMMAND. That is merely wasteful for `env://` and
// unusable for a secret manager, where it is an API call per Execute and per
// Query — the blocker that made the cache a prerequisite for `gcp-sm://` rather
// than a companion to it.
//
// Returns the version separately because it belongs in PoolKey — that is what
// makes rotation invalidate pooled clients rather than leaving a revoked
// credential working until TTL expiry (§4.3.2).
func (r *Resolver) credential(ctx context.Context, spec config.TargetSpec) (connector.Secret, string, error) {
	if spec.CredentialRef == "" {
		// NO LONGER REACHABLE FROM A BOOTED DEPLOYMENT. D98 landed with step 14:
		// `credential.RefuseAtBoot` refuses an empty reference, because an
		// absence could not be told apart from a forgotten one, and `ambient://`
		// is how a target says it uses workload identity.
		//
		// KEPT AS DEFENCE RATHER THAN DELETED, and the distinction matters
		// because this codebase deletes unreachable code on principle: a
		// Resolver can be built from a hand-made Document that never passed
		// through boot, which every test in the tree does. Returning no material
		// is the safe answer there; the alternative is a nil dereference in the
		// one situation nobody has checked.
		return nil, "", nil
	}
	return r.creds.Resolve(ctx, spec.CredentialRef)
}

// Invalidate drops the cached credential behind one TARGET, so the next Resolve
// mints fresh material (D203, D204).
//
// **TAKES A TARGET REF AND NOT A CREDENTIAL REF, WHICH IS THE POINT.** The
// gateway is the caller and has no business knowing that `fullstory:prod` is
// backed by `file:///run/secrets/fs`. Threading the credential reference up to
// the enforcement path so it could be handed back down would put a secret
// LOCATION on the one code path that already refuses to log one (D112), for no
// gain over asking the component that owns the mapping.
//
// **SILENT ON AN UNKNOWN REF, AND ON A TARGET WITH NO CREDENTIAL.** Both are
// reachable without anything being wrong: `Resolve` owns the not-found refusal
// and a second answer here would be one to drift from it, and an `ambient://`
// or credential-free target has nothing to invalidate. A caller re-establishing
// after a 401 cannot act on either distinction — it goes on to the second
// attempt, where the ceilings and the far side get to answer properly.
//
// ONE CALLER, and it is `gateway.Enforce`'s re-establishment loop. A forced mint
// is an amplification primitive aimed at the secret manager, so it is reachable
// from exactly one place above the whole enforcement path and from no driver.
func (r *Resolver) Invalidate(ref string) {
	spec, ok := r.targets[ref]
	if !ok || spec.CredentialRef == "" {
		return
	}
	r.creds.Invalidate(spec.CredentialRef)
}

// Kinds returns every configured target's driver kind, keyed by ref.
//
// **DECLARED BY `gateway.Resolver` AND, UNTIL D190, CALLED BY NOTHING.** It
// carried an archcheck allowlist entry predicting the caller — "a driver registry
// that builds itself from config, which arrives with the second driver at P2" —
// and the prediction was wrong in an instructive way: a driver is CODE, so the
// registry is populated from code. What config was actually needed for is the
// other direction, and it is `gateway.Server.Validate`: a target naming a kind
// no driver implements must be refused at BOOT rather than at the first command
// that names it (D50, D190). It was nearly deleted as speculative before that
// caller was found.
func (r *Resolver) Kinds() map[string]string {
	out := make(map[string]string, len(r.targets))
	for ref, spec := range r.targets {
		out[ref] = spec.Kind
	}
	return out
}

// ResidencyRefused reports whether this deployment's ceiling forbids a target's
// declared class, WITHOUT resolving anything.
//
// EXISTS SO THE CEILING CAN BE CHECKED BEFORE POLICY (D136). D71's argument is
// that a ceiling has to be evaluated before the grants it bounds, or a broad
// grant wins and the ceiling becomes an opinion. Residency is the most absolute
// ceiling Sekizui has — the deployment cannot lawfully serve the class at all —
// and it was being checked at RESOLVE, several stages after policy. That mostly
// worked, because both outcomes are a refusal; what it got wrong is WHICH
// refusal is reported when both apply, and §7.1 item 2 turns on the operator not
// having to infer that.
//
// A LOOKUP, NOT A RESOLVE, and the distinction is the point of the method
// existing at all. Resolve fetches the credential through the cache, so calling
// it to learn a residency would make the first act of refusing a cross-border
// target be to go and read its secret — the same trap §4.7.10 avoids for
// revocation, and the reason Resolve orders residency before credential in the
// first place.
//
// ONE BOOL, PHRASED AS THE REFUSAL. The first version returned
// `(class, permitted, known bool)`, and two adjacent bools in a signature is a
// transposition waiting to happen — at the only call site the correct guard was
// `known && !permitted`, which reads as a puzzle and inverts silently if the
// pair is ever swapped. Phrasing the method as the question the caller actually
// asks collapses both into one unambiguous answer.
//
// AN UNKNOWN REF IS NOT REFUSED HERE. Resolve owns the not-found refusal, and a
// second one would be a second answer to drift from the first.
func (r *Resolver) ResidencyRefused(ref string) (class string, refused bool) {
	spec, ok := r.targets[ref]
	if !ok {
		return "", false
	}
	return spec.Residency, !r.profile.ResidencyPermitted(r.permitted, spec.Residency)
}

// PostureOf reports the security posture behind a target's credential (D100,
// D119), for the decision record.
//
// NOT ON connector.Target, AND THAT WAS THE FIRST ATTEMPT. Carrying it there
// meant `pkg/connector` — the DRIVER-facing API — importing `pkg/config`, and
// the smell was visible in the doc comment it needed: "a driver has no business
// reading this". A field on a driver-facing type that drivers must not read is
// in the wrong place, and Go said so as an import cycle in `pkg/config`'s own
// tests before the design argument had to be made.
//
// So the enforcement path asks the RESOLVER, which is the component that owns
// the cache and already knows the reference. The gateway discovers this by type
// assertion (GO-PRIMER §2.2), so a Resolver that cannot answer stamps nothing
// rather than failing to compile.
//
// A LOOKUP, NOT A RESOLVE — the same distinction ResidencyRefused draws. Calling
// this does not fetch a credential: the posture comes from the provider's own
// description plus the version this cache last saw, so it is safe to call on a
// path that has already resolved and must not resolve again.
func (r *Resolver) PostureOf(ref string) (config.Posture, bool) {
	spec, known := r.targets[ref]
	if !known || spec.CredentialRef == "" {
		return config.Posture{}, false
	}
	return r.creds.ProviderPosture(spec.CredentialRef)
}
