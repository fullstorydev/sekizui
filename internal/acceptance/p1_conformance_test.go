package acceptance

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// disablingProvider is a secret manager whose versions can be DISABLED, under
// the test's control (D156).
//
// A SIMULATION RATHER THAN A CLOUD ACCOUNT, and that is the decision rather than
// a compromise. D152 established that a characterisation test reports what one
// project, in one region, against one API version, did on one day — which
// disqualifies it as the evidence break-glass rests on, and simultaneously says
// what to prove instead: enumerate the behaviours and be safe under each.
type disablingProvider struct {
	scheme string

	// live is the version `latest` currently resolves to.
	live atomic.Value // string

	// fallback decides which of the two possible platform behaviours this
	// instance exhibits when the newest version is disabled. THERE IS NO THIRD
	// OPTION: either the alias fails, or it resolves to the newest version that
	// is still enabled.
	fallback atomic.Bool

	// disabled is the version that has been taken out of service.
	disabled atomic.Value // string
}

func (p *disablingProvider) Scheme() string { return p.scheme }

func (p *disablingProvider) Resolve(_ context.Context, ref string) (config.Resolution, error) {
	const op = "disabling.Resolve"

	want := strings.TrimPrefix(ref, p.scheme+"://")
	off, _ := p.disabled.Load().(string)

	// A PINNED reference names one version. If that version is disabled the
	// resolution fails; there is nothing else it could honestly return.
	if !strings.HasSuffix(want, "latest") {
		if off != "" && strings.HasSuffix(want, off) {
			return config.Resolution{}, fault.New(fault.KindNotFound, op,
				"version "+off+" is disabled")
		}
		return config.Resolution{
			Material: []byte("material-" + want), Version: want,
		}, nil
	}

	// A TRACKING reference. Both platform behaviours, selected by the test.
	live, _ := p.live.Load().(string)
	if off != "" && live == off {
		if !p.fallback.Load() {
			return config.Resolution{}, fault.New(fault.KindNotFound, op,
				"the newest version is disabled and `latest` does not fall back")
		}
		// THE DANGEROUS BEHAVIOUR: silently one version older, and every log
		// line reports a successful resolution.
		older := previousVersion(live)
		return config.Resolution{
			Material: []byte("material-" + older), Version: older,
		}, nil
	}
	return config.Resolution{
		Material: []byte("material-" + live), Version: live,
	}, nil
}

// previousVersion steps a `.../versions/N` reference back by one, which is what
// a falling-back alias would hand you.
func previousVersion(v string) string {
	i := strings.LastIndex(v, "/")
	if i < 0 {
		return v
	}
	n, err := strconv.Atoi(v[i+1:])
	if err != nil || n <= 1 {
		return v
	}
	return v[:i+1] + strconv.Itoa(n-1)
}

// step26BreakGlassIsCorrectUnderEitherPlatformBehaviour proves D152 and D156.
//
// **REPLACES A CHARACTERISATION TEST AGAINST A REAL GCP PROJECT**, which was the
// only thing in P1 needing a cloud account. The question was: does
// `gcp-sm://…/versions/latest` fall back to an older ENABLED version when the
// newest is disabled? Google's documentation does not say — checked, not assumed.
//
// So the step enumerates instead of measuring. There are exactly two behaviours
// and both are simulated. That is strictly MORE than a characterisation test
// would have given: it covers the platform nobody has characterised, and the one
// whose behaviour changes next year.
func step26BreakGlassIsCorrectUnderEitherPlatformBehaviour(t *testing.T) {
	ctx := context.Background()
	const ref = "sm://projects/p/secrets/s/versions/latest"

	for _, tc := range []struct {
		name     string
		fallback bool
	}{
		{"the alias fails when the newest version is disabled", false},
		{"the alias falls back to an older enabled version", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &disablingProvider{scheme: "sm"}
			p.live.Store("projects/p/secrets/s/versions/7")
			p.fallback.Store(tc.fallback)

			store := credential.NewMarkFileStore(filepath.Join(t.TempDir(), "audit.jsonl.credver"))
			c := credential.New([]config.Provider{p},
				credential.WithTTL(0),
				credential.WithVersionMarks(store),
				credential.WithLogger(quietLogger()))
			if _, err := c.RehydrateMarks(ctx); err != nil {
				t.Fatalf("marks: %v", err)
			}

			// Version 7 is in service and resolves.
			if _, _, err := c.Resolve(ctx, ref); err != nil {
				t.Fatalf("v7 while enabled: %v", err)
			}

			// BREAK-GLASS: an operator disables v7 because it is compromised.
			p.disabled.Store("projects/p/secrets/s/versions/7")

			_, _, err := c.Resolve(ctx, ref)
			if err == nil {
				t.Fatalf("the credential still resolved after the version an operator "+
					"disabled as compromised. Under the %q behaviour that means the "+
					"compromised credential is still in service, or a DIFFERENT one is "+
					"and nobody chose it", tc.name)
			}

			// THE SAME OUTCOME UNDER BOTH BEHAVIOURS, which is the whole point.
			// Where the platform fails, the failure is the refusal. Where it
			// falls back, D152's monotonic guard refuses the downgrade — and
			// then break-glass works on a platform whose behaviour would
			// otherwise have quietly defeated it.
			t.Logf("refused, as required: %v", err)
			if tc.fallback && !strings.Contains(err.Error(), "OLDER") {
				t.Errorf("under the fallback behaviour the refusal should name the "+
					"DOWNGRADE, because that is what an operator has to understand: "+
					"got %v", err)
			}
		})
	}
}

// step27ADisabledPinnedVersionFailsClosed proves D99's break-glass claim about a
// pinned reference — and it turned out not to be a claim about the platform at
// all (D156).
//
// "A disabled pinned version fails closed" is a statement about SEKIZUI: when a
// reference naming one specific version stops resolving, the cache must not go on
// serving the material it already holds, must not substitute another version, and
// must not swallow the failure into a success. None of that needs a cloud.
func step27ADisabledPinnedVersionFailsClosed(t *testing.T) {
	ctx := context.Background()
	const pinned = "sm://projects/p/secrets/s/versions/7"

	p := &disablingProvider{scheme: "sm"}
	p.live.Store("projects/p/secrets/s/versions/7")

	c := credential.New([]config.Provider{p},
		credential.WithTTL(0),
		credential.WithLogger(quietLogger()))

	// --- 27a: IT RESOLVES WHILE ENABLED ----------------------------------
	sec, _, err := c.Resolve(ctx, pinned)
	if err != nil {
		t.Fatalf("a pinned enabled version did not resolve: %v", err)
	}
	if sec == nil {
		t.Fatal("resolved with no material")
	}

	// --- 27b: DISABLED MEANS REFUSED, NOT SUBSTITUTED -------------------
	p.disabled.Store("projects/p/secrets/s/versions/7")

	_, gotVersion, err := c.Resolve(ctx, pinned)
	if err == nil {
		t.Fatalf("a pinned version that an operator disabled still resolved, to %q. "+
			"D99's whole argument for supporting pinning is that disabling the version "+
			"IS break-glass for it", gotVersion)
	}

	// NOT A SUBSTITUTION. A provider offering a different version for a pinned
	// reference would be answering a question nobody asked, and the cache must
	// not paper over it either.
	if strings.Contains(err.Error(), "versions/6") {
		t.Errorf("the failure mentions another version (%v) — a pinned reference names "+
			"one version and must never resolve to a different one", err)
	}

	// A REAL FAULT KIND, so a caller can tell this from a network blip. Swallowed
	// into a generic failure it would look transient, and something would retry
	// a credential an operator deliberately took out of service.
	if kind := fault.KindOf(err); kind == fault.KindUnknown {
		t.Errorf("kind = %v; a disabled version is a definite answer and must not "+
			"arrive as an unclassified failure", kind)
	}

	// --- 27c: THE CACHE DOES NOT KEEP SERVING IT ------------------------
	//
	// The arm with teeth. Everything above is about one resolution; this is about
	// the entry the cache is already holding. A cache that answered from it after
	// the version was disabled would give a compromised credential a second life
	// bounded only by the TTL — and it is exactly the kind of thing that looks
	// fine because the first resolution was legitimate.
	for i := range 3 {
		if _, _, err := c.Resolve(ctx, pinned); err == nil {
			t.Fatalf("resolution %d after disabling succeeded from cache. A disabled "+
				"version must not be served from an entry that predates the disabling",
				i+1)
		}
	}
}
