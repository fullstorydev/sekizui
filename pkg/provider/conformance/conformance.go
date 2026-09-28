// Package conformance is the contract every `config.Provider` must satisfy
// (D35, D156).
//
// **WHY A PUBLISHED SUITE AT ALL.** D35 makes `Provider` the extension point: a
// self-hoster on a platform Sekizui has not met writes their own, and nothing in
// this repository will ever see it. A published interface with no conformance
// suite is a contract you cannot check you have met — the implementer reads a doc
// comment, guesses at the edges, and discovers the guesses in production.
//
// **IT ALSO EXISTS BECAUSE THE ACCEPTANCE STEPS ALREADY CONTAINED IT.** Steps 26,
// 27, 36, 44 and 67 assert properties that are not about Sekizui at all — they are
// about what any provider must do. Leaving them there meant every future provider
// would have been checked against whichever assertions somebody remembered to
// copy.
//
// **WHAT IT DELIBERATELY DOES NOT TEST: the environment.** A suite that demanded
// a reachable secret manager would be untestable offline and would fail for
// reasons that are not the provider's. The caller supplies references that work
// where they are running; this checks the CONTRACT around them.
//
// Usage, from a provider's own package:
//
//	func TestConformance(t *testing.T) {
//	    conformance.Run(t, myProvider, []conformance.Case{
//	        {Name: "a working reference", Ref: "mine://something"},
//	    })
//	}
//
// DESIGN.md references: §4.7.2, §12.1, D35, D111, D130, D152, D156.
package conformance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
)

// Case is one reference the provider can resolve where the test is running.
type Case struct {
	Name string
	Ref  string

	// NoMaterial marks a reference that legitimately yields no bytes.
	//
	// `ambient://` is the reason this exists: the platform authenticates the
	// workload and the SDK picks the identity up, so there is nothing for a
	// broker to hold. Without this field the suite would have to choose between
	// failing a correct provider and never checking that material arrives at
	// all — and the second is how a suite becomes decoration.
	NoMaterial bool
}

// Run asserts the Provider contract.
func Run(t *testing.T, p config.Provider, cases []Case) {
	t.Helper()

	runScheme(t, p)
	runRefusals(t, p)
	for _, c := range cases {
		runCase(t, p, c)
	}
	runPosture(t, p, cases)
}

// runScheme checks the scheme is usable as a routing key.
func runScheme(t *testing.T, p config.Provider) {
	t.Helper()

	t.Run("scheme is a stable routing key", func(t *testing.T) {
		s := p.Scheme()
		if s == "" {
			t.Fatal("Scheme() is empty; the cache routes on it, so an empty scheme " +
				"means every reference either misroutes or resolves to nothing")
		}
		if strings.Contains(s, "://") {
			t.Errorf("Scheme() = %q and contains the separator. It is the part BEFORE "+
				"`://`, and including it makes every reference double-prefixed", s)
		}
		if s != p.Scheme() {
			t.Error("Scheme() is not stable across calls; the provider set is built once " +
				"at boot, so a scheme that changes afterwards routes nothing")
		}
	})
}

// runRefusals checks the provider refuses what it cannot resolve, rather than
// guessing or panicking.
func runRefusals(t *testing.T, p config.Provider) {
	t.Helper()

	for _, c := range []struct{ name, ref string }{
		{"a reference for another scheme", "not-this-scheme://whatever"},
		{"an empty reference", ""},
		{"the scheme with no path", p.Scheme() + "://"},
	} {
		t.Run(c.name+" is refused", func(t *testing.T) {
			// A PANIC IS A FAILED TEST, NOT A CRASHED SUITE. A third-party
			// provider that panics on a malformed reference would take the
			// gateway down at boot, and the suite must report that rather than
			// dying with it.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Resolve panicked on %q: %v. A malformed reference reaches "+
						"a provider from configuration, and a panic there is a boot "+
						"crash rather than a refused credential", c.ref, r)
				}
			}()

			res, err := p.Resolve(context.Background(), c.ref)
			if err == nil {
				t.Errorf("Resolve(%q) succeeded, returning %d bytes. A provider that "+
					"accepts a reference it cannot honestly resolve hands the caller "+
					"material from somewhere nobody asked about", c.ref, len(res.Material))
			}
		})
	}
}

// runCase checks one working reference.
func runCase(t *testing.T, p config.Provider, c Case) {
	t.Helper()

	t.Run(c.Name, func(t *testing.T) {
		ctx := context.Background()

		res, err := p.Resolve(ctx, c.Ref)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", c.Ref, err)
		}

		switch {
		case c.NoMaterial && len(res.Material) > 0:
			t.Errorf("the case declares no material and %d bytes arrived", len(res.Material))
		case !c.NoMaterial && len(res.Material) == 0:
			t.Error("no material and none declared. If this provider legitimately " +
				"supplies none — workload identity, where the platform authenticates — " +
				"say so with NoMaterial, because silence here is indistinguishable from " +
				"a provider that failed quietly")
		}

		// **THE VERSION IS AN IDENTITY, NOT A DIGEST (D130).** Two resolutions of
		// one reference must report the same version, or every one of them looks
		// like a rotation: D99's content-addressed PoolKey would tear down pooled
		// clients on a timer, and for a session-oriented target re-initialise a
		// live session, for nothing.
		second, err := p.Resolve(ctx, c.Ref)
		if err != nil {
			t.Fatalf("second Resolve(%q): %v", c.Ref, err)
		}
		if res.Version != second.Version {
			t.Errorf("Version changed between two resolutions of one reference: %q then "+
				"%q. A version is the credential's IDENTITY and must not move because "+
				"the bytes were fetched again — that reports a rotation nobody performed",
				res.Version, second.Version)
		}

		// A CANCELLED CONTEXT IS REFUSED. The Provider contract says every
		// implementation honours cancellation, and one that quietly does not
		// becomes the one people copy.
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := p.Resolve(cancelled, c.Ref); err == nil {
			t.Error("Resolve succeeded with an already-cancelled context. A boot that " +
				"is being torn down, or a request whose caller has gone, must not still " +
				"be fetching credentials")
		}
	})
}

// runPosture checks a Postured provider describes itself consistently (D111).
func runPosture(t *testing.T, p config.Provider, cases []Case) {
	t.Helper()

	asked, can := p.(config.Postured)
	if !can {
		// OPTIONAL, AND SAYING SO IS THE POINT. A provider that cannot describe
		// itself offers no properties and fails every `credential_policy`
		// requirement (D111's fail-safe direction) — which is a legitimate
		// choice, and one the implementer should make knowingly.
		t.Log("this provider does not implement config.Postured, so it offers NO " +
			"properties and any deployment stating credential_policy will refuse it " +
			"(D111). That is the fail-safe direction, not a bug — but it is a choice.")
		return
	}

	for _, c := range cases {
		t.Run("posture for "+c.Name, func(t *testing.T) {
			got, err := asked.Posture(c.Ref)
			if err != nil {
				t.Fatalf("Posture(%q): %v", c.Ref, err)
			}

			if got.AtRest == "" {
				t.Error("AtRest is empty. It names WHERE THE BYTES LIVE — " +
					"secret-manager, k8s-secret, static-file, platform — and it is the " +
					"column that tells an operator their SOPS-encrypted values are " +
					"sitting in a Kubernetes Secret at runtime (D103). Never the bytes " +
					"themselves (D119)")
			}
			switch got.Versioning {
			case config.Unversioned, config.VersionedByReference, config.VersioningNotApplicable:
			default:
				t.Errorf("Versioning = %d, which is not one of the three states", got.Versioning)
			}
			switch got.Rotation {
			case config.RotationLive, config.RotationOnChange, config.RotationNone:
			default:
				t.Errorf("Rotation = %q, want live, on-change or NONE (D104)", got.Rotation)
			}

			// DERIVED, NOT DECLARED (D153). Two fields answering one question
			// eventually disagree, and this asserts the derivation still holds
			// for an implementation that might have shadowed it.
			if got.RotatableLive() != (got.Rotation == config.RotationLive) {
				t.Error("RotatableLive() disagrees with Rotation")
			}

			// **THE PROPERTY THAT DECIDES WHETHER A DEPLOYMENT BOOTS.** A
			// provider claiming `versioned` while reporting no version at all is
			// claiming a guarantee it cannot keep, and `credential_policy` would
			// admit it (D111, D153).
			if got.Offers(config.PropertyVersioned) && got.Versioning == config.Unversioned {
				t.Error("Offers(versioned) is true while Versioning is Unversioned")
			}
		})
	}
}

// ChainedCase is one reference for a provider whose references embed others.
type ChainedCase struct {
	Name string
	Ref  string

	// Inner is what the reference is expected to name, keyed by the parameter
	// the provider will look them up under.
	Inner map[string]config.Resolution
}

// RunChained asserts the contract for a `config.ChainedProvider` (D131).
//
// **A DIFFERENT CONTRACT, NOT A SPECIAL CASE OF Run.** `oauth-cc://` embeds
// another reference for its client secret, and D131 resolves it INNER-FIRST BY
// THE CACHE precisely so a provider never receives a resolver it could point at
// any secret. So `Resolve` on a chained provider must REFUSE — a chained
// reference resolved through the plain path would be one whose inner reference
// nobody fetched — and the real work happens in `ResolveChained`.
//
// Running `Run` against such a provider would pass vacuously: every refusal
// assertion holds because it refuses everything, and no case could ever succeed.
// A suite that cannot fail for the shape it is pointed at is worse than no suite,
// because it reports coverage.
func RunChained(t *testing.T, p config.ChainedProvider, cases []ChainedCase) {
	t.Helper()

	plain, isPlain := p.(config.Provider)
	if !isPlain {
		t.Fatal("a ChainedProvider must also be a Provider: the cache routes on Scheme() " +
			"before it discovers the chaining, so a chained provider with no scheme is " +
			"unreachable")
	}
	runScheme(t, plain)

	t.Run("the plain Resolve path refuses", func(t *testing.T) {
		if _, err := plain.Resolve(context.Background(), cases[0].Ref); err == nil {
			t.Error("Resolve succeeded on a chained reference. Its inner reference was " +
				"never fetched, so whatever came back was assembled from an unresolved " +
				"placeholder — and D131's whole point is that the CACHE resolves inner " +
				"references so a provider never holds a resolver it could aim anywhere")
		}
	})

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			// INNER REFERENCES ARE NAMED, and named consistently. The cache looks
			// them up by these keys, so a provider that names one thing and reads
			// another resolves nothing and reports it as a missing secret.
			names, err := p.Inner(c.Ref)
			if err != nil {
				t.Fatalf("Inner(%q): %v", c.Ref, err)
			}
			for _, n := range names {
				if _, ok := c.Inner[n]; !ok {
					t.Errorf("Inner names %q and the case supplies no resolution for it; "+
						"either the provider names something it will not read, or this "+
						"case is incomplete", n)
				}
			}

			// **A MISSING INNER RESOLUTION MUST REFUSE.** Proceeding without one
			// would exchange an empty client secret and surface as an upstream
			// 401 — attributed to the target rather than to the missing
			// reference, which is D106's argument about zeroed material in
			// another guise.
			if len(names) > 0 {
				if _, err := p.ResolveChained(context.Background(), c.Ref, nil); err == nil {
					t.Error("ResolveChained succeeded with no inner resolutions supplied")
				}
			}
		})
	}
}
