// Package credential caches resolved credential material (§4.3.2, §4.7.6).
//
// PRIVATE (D35).
//
// WHY THIS IS THE FIRST THING P1 BUILDS. Before it, `resolver.Resolve` called
// the provider on EVERY Execute and every Query. With `env://` that is an
// `os.Getenv` and merely wasteful. With `gcp-sm://` it is a Secret Manager API
// call per command: quota burn, network latency on the enforcement path, cost,
// and an access log too noisy to audit. So the cache is a PREREQUISITE for
// secret-manager support rather than a companion to it, and everything else in
// P1's credential work waits behind it.
//
// THREE PROPERTIES, each of which is an acceptance step:
//
//	one provider call per TTL, not per command          (step 1)
//	N concurrent cold resolves produce ONE call         (step 2)
//	jitter is per-INSTANCE, never derived from the key  (step 3)
//
// The third is the subtle one. Jitter exists so N replicas do not refresh the
// same credential at the same instant and stampede the issuer (§4.3.2). Jitter
// computed from the reference — hashing it, say — is identical on every replica
// and therefore defeats its own purpose while looking correct.
//
// NOT YET HERE: eviction, `Secret.Wipe`, and the drain that must precede it
// (D110), and revocation (D106). Those are steps 6-9 and they need the
// per-target in-flight registry. Deliberately absent rather than stubbed: a
// wipe that races an in-flight call is worse than no wipe, and there is nothing
// to drain against yet.
//
// DESIGN.md references: §4.3.2, §4.7.6, §4.7.11, D110.
package credential

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/credver"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// DefaultTTL is how long resolved material is reused.
//
// Short on purpose. It bounds how long a rotated credential can go unnoticed by
// a deployment that tracks `latest` (D99), and it is the ceiling on staleness
// that D108's pool lifetime then backs up. Long enough that a busy target makes
// one call per five minutes rather than thousands.
const DefaultTTL = 5 * time.Minute

// DefaultJitter is the fraction by which an individual TTL varies.
const DefaultJitter = 0.20

// Cache resolves credential references through providers, and remembers.
type Cache struct {
	providers map[string]config.Provider
	ttl       time.Duration
	now       func() time.Time

	// jitter returns a fraction in [-1, 1], scaled by DefaultJitter.
	//
	// A FIELD RATHER THAN A CALL to math/rand, so a test can make expiry
	// deterministic without making it identical — step 3 needs two caches whose
	// jitter differs, which a hardcoded source cannot express.
	jitter func() float64

	// markStore and marks are D152's monotonic high-water guard. A SEPARATE
	// MUTEX from the entry cache on purpose: the entry lock is held across a
	// provider call in the singleflight path, and putting the downgrade check
	// behind it would serialise every resolution behind whichever one is
	// currently talking to a secret manager.
	// log carries the one thing this cache must say out loud: that a version
	// mark could not be persisted. DEFAULTS TO slog.Default() rather than to a
	// no-op, because a default of silence is how a warning nobody configured
	// becomes a warning nobody receives.
	log *slog.Logger

	markStore credver.Store
	markMu    sync.Mutex
	marks     map[string]credver.Mark

	mu      sync.Mutex
	entries map[string]*entry

	// generations counts how many DISTINCT credentials this reference has
	// yielded, and digests is how that is detected across an eviction — of the
	// provider's reported VERSION where there is one, of the material where
	// there is not (D130).
	//
	// WHY A COUNTER RATHER THAN A CONTENT HASH IN THE KEY. D99 called for
	// content-addressing so a tracking reference (`versions/latest`) invalidates
	// the pool when the ref string never changes. A hash of the material in
	// PoolKey achieves that and creates a confirmation oracle: anyone holding a
	// candidate secret can check it against a value that travels through map
	// keys, error strings, and metric labels. D112 proposed mitigating that with
	// a per-process salt and a self-redacting type.
	//
	// A generation counter gives the identical property with nothing to
	// mitigate: the key changes exactly when the material changes, and no value
	// derived from the secret ever reaches it. It also removes the need for a
	// package-level salt, which §6 item 4 bans outright.
	//
	// The digest stays INTERNAL and exists only so a refetch after eviction can
	// tell "rotated" from "same credential again" — without it, every TTL expiry
	// would bump the generation and churn every pooled client for no reason.
	generations map[string]uint64
	digests     map[string][32]byte

	// resolvedVersions is the last version each provider reported for a ref
	// (D130), which is what a decision record needs and the pool-key version is
	// not — the pool key is `ref#generation`, an internal counter, and putting
	// that on an audit row would answer a question nobody asked.
	resolvedVersions map[string]string

	// Counters, guarded by mu, and mirrored to the metrics registry when one is
	// supplied. Reported rather than merely counted, because "resolutions per
	// TTL" is the number that says whether §4.7.6's blocker is actually fixed in
	// a running deployment — and a counter nobody scrapes proves nothing there.
	calls, hits uint64
	metrics     counter
}

// counter is the slice of the metrics registry this package needs, declared
// here so `internal/credential` depends on a method set rather than a package
// (GO-PRIMER §2.1).
type counter interface{ Incr(name string) }

// WithMetrics mirrors provider calls and cache hits into a registry.
func WithMetrics(c counter) Option { return func(k *Cache) { k.metrics = c } }

// WithVersionMarks installs the monotonic high-water store (D152), which makes a
// tracking reference unable to resolve BACKWARDS.
//
// OPTIONAL, and nil means the guard does not run. That is the direction D150
// requires: a defence that refuses to start when it has not been configured
// turns an unset option into an outage, and the marks protect against a future
// downgrade rather than against anything happening right now.
func WithVersionMarks(s credver.Store) Option {
	return func(c *Cache) { c.markStore = s }
}

// WithLogger substitutes the logger.
func WithLogger(l *slog.Logger) Option { return func(c *Cache) { c.log = l } }

// entry is one cached credential, possibly still in flight.
type entry struct {
	// ready is closed when the fetch completes. Everything below is written
	// before the close and read only after it, so the close is the
	// happens-before edge and no other synchronisation is needed.
	ready chan struct{}

	material connector.Secret
	version  string
	expires  time.Time
	err      error
}

// Option configures a Cache.
type Option func(*Cache)

// WithTTL overrides how long material is reused.
func WithTTL(d time.Duration) Option { return func(c *Cache) { c.ttl = d } }

// WithClock substitutes the clock, so expiry is testable without sleeping.
func WithClock(now func() time.Time) Option { return func(c *Cache) { c.now = now } }

// WithJitterSource substitutes the jitter source.
//
// For tests that need two caches to differ predictably. Production uses a
// per-instance PRNG seeded from crypto/rand.
func WithJitterSource(f func() float64) Option { return func(c *Cache) { c.jitter = f } }

// New builds a cache over the given providers.
func New(providers []config.Provider, opts ...Option) *Cache {
	c := &Cache{
		providers:        make(map[string]config.Provider, len(providers)),
		ttl:              DefaultTTL,
		now:              time.Now,
		entries:          map[string]*entry{},
		generations:      map[string]uint64{},
		digests:          map[string][32]byte{},
		resolvedVersions: map[string]string{},
		jitter:           newJitterSource(),
		log:              slog.Default(),
		marks:            map[string]credver.Mark{},
	}
	for _, p := range providers {
		c.providers[p.Scheme()] = p
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// newJitterSource returns a PRNG seeded PER INSTANCE from crypto/rand.
//
// Per-instance is the whole point (step 3). A source seeded from the credential
// reference, or from anything else every replica shares, produces identical
// expiry times across the fleet — which is precisely the stampede jitter exists
// to prevent, wearing the appearance of a fix.
func newJitterSource() func() float64 {
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		// crypto/rand failing is not recoverable and not worth a code path;
		// fall back to the clock so jitter is still per-instance.
		binary.LittleEndian.PutUint64(seed[0:8], uint64(time.Now().UnixNano()))
		binary.LittleEndian.PutUint64(seed[8:16], uint64(time.Now().UnixNano()>>7))
	}
	src := mrand.New(mrand.NewPCG(
		binary.LittleEndian.Uint64(seed[0:8]),
		binary.LittleEndian.Uint64(seed[8:16]),
	))

	var mu sync.Mutex
	return func() float64 {
		mu.Lock()
		defer mu.Unlock()
		return src.Float64()*2 - 1 // [-1, 1)
	}
}

// Resolve returns credential material for a reference, from cache where fresh.
//
// SINGLEFLIGHTED. N goroutines meeting a cold entry produce one provider call;
// the rest wait on the entry's ready channel. Without this, a cold start under
// load issues N calls to the secret manager simultaneously — the stampede
// §4.3.2 warns about, at boot rather than at expiry.
func (c *Cache) Resolve(ctx context.Context, ref string) (connector.Secret, string, error) {
	const op = "credential.Resolve"

	for {
		c.mu.Lock()
		if e, exists := c.entries[ref]; exists {
			c.mu.Unlock()

			// Wait for whoever owns this fetch, honouring cancellation. A
			// caller giving up must not be trapped behind a slow provider.
			select {
			case <-e.ready:
			case <-ctx.Done():
				return nil, "", fault.Wrap(fault.KindTimeout, op,
					"context done while waiting for "+ref, ctx.Err())
			}

			if e.err != nil {
				// The failure is SHARED rather than retried by each waiter, so a
				// provider outage costs one call rather than one per goroutine.
				// The entry is already gone, so the next Resolve tries again.
				return nil, "", e.err
			}

			c.mu.Lock()
			if c.now().Before(e.expires) {
				c.hits++
				c.mu.Unlock()
				c.count("credential_cache_hits_total")
				return e.material, e.version, nil
			}
			// Expired. Evict and loop; the next pass owns the fetch. Compared
			// by identity so a concurrent refresh is not thrown away.
			if c.entries[ref] == e {
				delete(c.entries, ref)
			}
			c.mu.Unlock()
			continue
		}

		// This goroutine owns the fetch.
		e := &entry{ready: make(chan struct{})}
		c.entries[ref] = e
		c.calls++
		c.mu.Unlock()
		c.count("credential_provider_calls_total")

		res, ver, err := c.fetch(ctx, ref)
		e.material, e.version, e.err = res.Material, ver, err
		// Honours what the provider said (D130). Previously this applied the
		// configured TTL unconditionally and discarded the provider's expiry.
		e.expires = c.expiryFor(res)
		close(e.ready)

		if e.err != nil {
			c.mu.Lock()
			if c.entries[ref] == e {
				delete(c.entries, ref)
			}
			c.mu.Unlock()
		}
		return e.material, e.version, e.err
	}
}

// RehydrateMarks loads the high-water marks, and MUST be called before serving.
//
// FAILING TO LOAD FAILS THE BOOT, which is withdrawal.Store's rule for
// withdrawal.Store's reason: starting with no marks silently permits every
// downgrade the marks existed to refuse, and an empty set is not a degraded
// start. Note the asymmetry with Put, which must NOT fail a resolution — see
// credver.Store.
func (c *Cache) RehydrateMarks(ctx context.Context) (int, error) {
	const op = "credential.RehydrateMarks"

	if c.markStore == nil {
		return 0, nil
	}
	marks, err := c.markStore.Load(ctx)
	if err != nil {
		return 0, fault.Wrap(fault.KindConfig, op,
			"loading credential version marks; refusing to start rather than permitting "+
				"every downgrade they exist to refuse", err)
	}

	c.markMu.Lock()
	defer c.markMu.Unlock()
	c.marks = make(map[string]credver.Mark, len(marks))
	for _, m := range marks {
		c.marks[m.Ref] = m
	}
	return len(c.marks), nil
}

// checkMonotonic refuses a resolution that went BACKWARDS, and records it when it
// went forward (D152).
//
// KEYED ON THE CONFIGURED REFERENCE, not on the resolved version: the reference
// is the thing whose meaning can change underneath the deployment, which is the
// whole hazard. A pinned reference names one version forever and simply never
// trips this.
//
// **REACHED ONLY ON A CACHE MISS, and that is correct rather than a gap** —
// worth stating because it decides WHEN a downgrade is caught. While the newer
// version is still cached, Sekizui is serving the newer version, so there is
// nothing yet to refuse; the fallback becomes observable at the next real
// resolution and is refused then. What that leaves is the ordinary cache-TTL
// window, in which a credential declared compromised is still in use — and the
// answer to that window is not this guard but `sekizui.revoke_credential`
// (D129), which evicts rather than waiting for expiry. Two mechanisms for two
// different moments.
func (c *Cache) checkMonotonic(ctx context.Context, ref string, res config.Resolution) error {
	const op = "credential.checkMonotonic"

	if c.markStore == nil {
		return nil
	}
	ordinal, ordered := credver.Ordinal(res.Version)
	if !ordered {
		// NO ORDER, NO GUARD. A content digest has no older or newer, and
		// inventing one would refuse legitimate edits — see credver.Ordinal.
		return nil
	}

	c.markMu.Lock()
	prev, seen := c.marks[ref]
	if seen && ordinal < prev.Ordinal {
		c.markMu.Unlock()
		// **`KindUnauthenticated`, NOT `KindDenied` (D201).** Both are deliberate
		// refusals and both map to STATUS_DENIED, so the caller sees the same
		// coarse answer — but the STAGE the audit row names is derived from the
		// attribution (D200), and `KindDenied` is attributed to the caller, which
		// put this refusal in the audit log as a POLICY or RESIDENCY decision.
		// It is neither: the credential offered is not acceptable for use, which
		// is what `unauthenticated` means and what an operator needs the row to
		// say when they come looking for why a rollback was stopped.
		//
		// **AND IT MUST NEVER BECOME `fault.CredentialRejected` (D203).** That
		// constructor sets the re-establishment marker, and re-establishing here
		// means invalidating the cache and resolving again — which re-runs this
		// guard and gets the same answer, having spent a mint. Worse than
		// useless: a forced re-resolve is precisely what an attacker rolling a
		// credential back is trying to make us do, so marking this refusal turns
		// the guard into a retry loop pointed at the attack.
		// `archcheck.TestOnlyADriverReportsAFarSideRejection` enforces it.
		return fault.New(fault.KindUnauthenticated, op, fmt.Sprintf(
			"credential %s resolved to version %q, which is OLDER than %q seen before. "+
				"Refusing: a tracking reference may only move forward (D152).\n\n"+
				"This is what a disabled newest version looks like when the platform falls "+
				"back to an older enabled one — so a credential somebody revoked as "+
				"compromised would be silently back in service, and every log line would "+
				"report a successful resolution.\n\n"+
				"If the rollback is deliberate, PIN the version in configuration rather "+
				"than letting a tracking reference go backwards; that way it is a reviewed "+
				"change with a name against it.",
			ref, res.Version, prev.Version))
	}
	if seen && ordinal == prev.Ordinal {
		c.markMu.Unlock()
		return nil
	}
	m := credver.Mark{Ref: ref, Version: res.Version, Ordinal: ordinal, At: c.now()}
	c.marks[ref] = m
	c.markMu.Unlock()

	if err := c.markStore.Put(ctx, m); err != nil {
		// DELIBERATELY NOT FATAL. The credential resolved correctly and is in
		// force; refusing it because a guard could not write its bookkeeping
		// would make a defence into an outage, which is exactly the failure D150
		// names — fail-closed is right against integrity and IS the attack
		// against availability. The mark is already in memory, so the guard
		// still holds for this process lifetime.
		c.log.Warn("could not persist the credential version mark; the downgrade guard holds for this process and not across a restart", "ref", ref, "err", err)
	}
	return nil
}

// ProviderPosture reports the security posture behind a reference (D100, D119).
//
// TYPE-ASSERTED, because config.Postured is optional — D35 makes Provider a
// published interface, and a required method would break every out-of-tree
// implementation. A provider that cannot answer reports `ok == false` and the
// record carries nothing, which is honest; the alternative is a row asserting a
// rotation posture nobody established.
//
// SCHEME AND VERSION ARE FILLED HERE, not by the provider: the cache is what
// dispatched on the scheme, and the version is the one THIS cache last saw the
// provider resolve to.
func (c *Cache) ProviderPosture(ref string) (config.Posture, bool) {
	scheme, _, ok := strings.Cut(ref, "://")
	if !ok {
		return config.Posture{}, false
	}
	p, known := c.providers[scheme]
	if !known {
		return config.Posture{}, false
	}

	out := config.Posture{Scheme: scheme}

	c.mu.Lock()
	out.Version = c.resolvedVersions[ref]
	c.mu.Unlock()

	asked, can := p.(config.Postured)
	if !can {
		// The scheme and version are still worth carrying: D100 asked for the
		// scheme alone and D119 widened it, so the narrower record is the older
		// contract rather than an empty one.
		return out, true
	}
	got, err := asked.Posture(ref)
	if err != nil {
		return out, true
	}
	got.Scheme, got.Version = out.Scheme, out.Version
	return got, true
}

// fetch dispatches to the provider matching the reference's scheme.
func (c *Cache) fetch(ctx context.Context, ref string) (config.Resolution, string, error) {
	const op = "credential.fetch"

	scheme, _, ok := strings.Cut(ref, "://")
	if !ok {
		return config.Resolution{}, "", fault.New(fault.KindConfig, op,
			"credential "+ref+" is not a reference (§4.7)")
	}
	p, ok := c.providers[scheme]
	if !ok {
		return config.Resolution{}, "", fault.New(fault.KindConfig, op,
			"no provider registered for scheme "+scheme)
	}

	res, err := c.resolveThrough(ctx, p, ref)
	if err != nil {
		return config.Resolution{}, "", err
	}

	// D152, BEFORE THE MATERIAL IS HANDED BACK. A downgrade must never reach a
	// pool, a driver or an upstream — by the time a caller holds the bytes,
	// refusing is a report rather than a defence.
	if err := c.checkMonotonic(ctx, ref, res); err != nil {
		return config.Resolution{}, "", err
	}

	// THE VERSION IS THE REFERENCE PLUS A GENERATION.
	//
	// The reference alone is not enough: `versions/latest` never changes while
	// the material behind it does, so a pooled client would keep a superseded
	// credential (D99). The generation closes that without putting anything
	// derived from the secret into a value that gets logged.
	return res, ref + "#" + strconv.FormatUint(c.generationFor(ref, res), 10), nil
}

// innerRefs is a chained reference's nested references, keyed by the parameter
// the provider declared (D131) — ONE reading, shared by resolution and by the
// boot's confinement walk (D286), so the references boot admits are exactly the
// ones the cache will resolve.
func innerRefs(op string, chained config.ChainedProvider, ref string) (map[string]string, error) {
	params, err := chained.Inner(ref)
	if err != nil || len(params) == 0 {
		return nil, err
	}
	u, err := url.Parse(ref)
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "chained credential reference is not a URL", err)
	}
	q := u.Query()
	out := make(map[string]string, len(params))
	for _, name := range params {
		nested := q.Get(name)
		if nested == "" {
			return nil, fault.New(fault.KindConfig, op,
				"the provider declared "+name+" as a nested reference and it is absent")
		}
		if nested == ref {
			// A reference naming itself would recurse until the stack gave out.
			return nil, fault.New(fault.KindConfig, op,
				"the nested reference in "+name+" is the reference itself")
		}
		out[name] = nested
	}
	return out, nil
}

// resolveThrough dispatches to a provider, resolving nested references FIRST
// when the provider declares any (D131).
//
// INNER-FIRST, AND IN THE CACHE RATHER THAN IN THE PROVIDER. The alternative —
// handing every provider a resolver so it can fetch its own inner references —
// is what makes Sekizui a library rather than a broker. A provider able to
// resolve references can resolve ANY reference, and providers are
// third-party-implementable (D35), so that interface would grant every
// self-hoster's connector the ability to read every secret this process can
// reach. The read would also happen below this seam, where nothing audits it and
// where caching, jitter, singleflight and rotation detection would each have to
// be reimplemented — meaning D123's invalidation could silently not work for
// somebody else's provider.
//
// Resolving here keeps all of that in one place and reduces a provider to
// something that receives material it was handed and cannot reach for more.
//
// THE INNER RESOLUTION GOES THROUGH Resolve, NOT THROUGH THE PROVIDER DIRECTLY,
// so a chained secret gets exactly the same caching, jitter, singleflight and
// generation tracking as a directly-referenced one. That is what makes
// "rotating the client secret invalidates the pool" true for a chained
// reference and not just for a plain one.
func (c *Cache) resolveThrough(ctx context.Context, p config.Provider, ref string) (config.Resolution, error) {
	const op = "credential.resolveThrough"

	chained, ok := p.(config.ChainedProvider)
	if !ok {
		return p.Resolve(ctx, ref)
	}

	nestedRefs, err := innerRefs(op, chained, ref)
	if err != nil {
		return config.Resolution{}, err
	}
	if len(nestedRefs) == 0 {
		return p.Resolve(ctx, ref)
	}

	inner := make(map[string]config.Resolution, len(nestedRefs))
	for name, nested := range nestedRefs {
		material, version, rerr := c.Resolve(ctx, nested)
		if rerr != nil {
			return config.Resolution{}, rerr
		}
		inner[name] = config.Resolution{Material: material, Version: version}
	}

	return chained.ResolveChained(ctx, ref, inner)
}

// expiryFor decides when a cached entry goes stale, given what the provider
// said (D130).
//
// TWO CASES, AND THE JITTER DIFFERS BETWEEN THEM. Where the provider reports no
// expiry — a static key from env:// or file:// — the configured TTL applies and
// jitter swings BOTH ways, because the only thing being spread is our own
// refresh schedule across replicas.
//
// Where the provider reports a real expiry, jitter may only move it EARLIER.
// The value is a hard deadline at the issuer, so a positive swing hands out
// material that is already dead and turns jitter into the very failure it
// exists to avoid — every replica discovering expiry at the moment of use,
// against the upstream, instead of refreshing quietly beforehand. Refreshing a
// little early costs one extra mint; refreshing a little late costs a request.
//
// The configured TTL remains a CEILING in both cases: a provider handing back a
// thirty-day expiry should not pin material in memory for thirty days when
// §4.7.5 bounds how long it may live there.
func (c *Cache) expiryFor(res config.Resolution) time.Time {
	now := c.now()
	ceiling := now.Add(c.jitteredTTL())

	if res.Expiry.IsZero() {
		return ceiling
	}

	// Early-only: scale the remaining lifetime down by up to DefaultJitter.
	lifetime := res.Expiry.Sub(now)
	if lifetime <= 0 {
		// Already expired on arrival. Cache it as expired rather than treating
		// it as fresh; the next Resolve refetches. Silently extending it would
		// be the discarded-expiry bug wearing a different face.
		return now
	}
	early := res.Expiry.Add(-time.Duration(float64(lifetime) * DefaultJitter * absJitter(c.jitter())))

	if early.After(ceiling) {
		return ceiling
	}
	return early
}

// absJitter folds the [-1,1) source into [0,1), because early-only jitter needs
// a magnitude rather than a direction.
func absJitter(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// generationFor returns how many distinct credentials this reference has
// yielded, incrementing when the credential's IDENTITY differs from last time.
//
// IDENTITY, NOT BYTES, and the difference is D130 correcting D123. The original
// digested the material, which is right for a static secret and wrong for a
// refreshable one: an OAuth reference yields a new access token on every
// refresh, so digesting it would bump the generation, change `PoolKey`, and
// evict the pooled client on a timer — re-initialising an MCP session and
// destroying server-side state for a credential that never rotated. §4.7.1's
// table says plainly that refresh must be invisible to pooling.
//
// So a provider that knows its version reports it, and that is the identity.
// The digest survives as the FALLBACK for providers that cannot — env:// has no
// version at all — which keeps D123's property intact without letting it
// misfire on the case it was never designed for.
//
// The generation, not the identity, is what reaches `credVer`. That is
// deliberate: it keeps the exposed value uniform whether the provider reported
// a version or we digested bytes, and it keeps a secret-derived value out of
// something that travels through map keys and metric labels regardless of which
// provider is in play.
func (c *Cache) generationFor(ref string, res config.Resolution) uint64 {
	var sum [32]byte
	if res.Version != "" {
		// Prefixed so a version can never collide with a material digest, in
		// the transition case where a provider begins reporting one.
		sum = sha256.Sum256([]byte("version:" + res.Version))
	} else {
		sum = sha256.Sum256(res.Material)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.resolvedVersions[ref] = res.Version

	prev, seen := c.digests[ref]
	if !seen {
		c.digests[ref] = sum
		c.generations[ref] = 1
		return 1
	}
	// subtle.ConstantTimeCompare rather than ==, not because timing is a threat
	// here (both operands are ours) but because a digest comparison written the
	// obvious way is the one that gets copied somewhere it does matter.
	if subtle.ConstantTimeCompare(prev[:], sum[:]) == 1 {
		return c.generations[ref]
	}
	c.digests[ref] = sum
	c.generations[ref]++
	return c.generations[ref]
}

// jitteredTTL spreads expiry so replicas do not refresh in lockstep.
func (c *Cache) jitteredTTL() time.Duration {
	spread := float64(c.ttl) * DefaultJitter * c.jitter()
	return time.Duration(float64(c.ttl) + spread)
}

// count mirrors to the registry when one was supplied.
func (c *Cache) count(name string) {
	if c.metrics != nil {
		c.metrics.Incr(name)
	}
}

// Invalidate drops one reference's cached material so the next Resolve refetches
// it (D203, D204).
//
// **IT DROPS THE ENTRY AND NOTHING ELSE, AND THAT IS THE WHOLE SAFETY ARGUMENT.**
// Three other maps are keyed by the same ref and every one of them must survive:
//
//	marks             D152's monotonic high-water. Clearing it would let the very
//	                  next resolve accept an OLDER version — and this function is
//	                  called on the path an attacker triggers by returning 401,
//	                  so clearing it would hand the downgrade guard amnesia at
//	                  exactly the moment it is under attack
//	generations       the pool key is `ref#generation` (D130). Resetting it would
//	                  make a rotated credential collide with the pool entry of
//	                  the one it replaced
//	digests           what tells a refetch "rotated" from "same credential again".
//	                  Losing it bumps the generation on every invalidation and
//	                  churns every pooled client for no reason
//
// So this is deliberately NOT `expireAllForTest` widened, and it is deliberately
// not a `reset`. Instance ~eighteen of the recurring class was available here:
// a guard whose state is discarded by a new code path that had no reason to know
// the guard existed.
//
// **CALLED FROM ONE PLACE**, `gateway.Enforce`'s re-establishment loop. A forced
// refetch is an amplification primitive aimed at the secret manager, so one call
// site above the whole enforcement path is provable and reachable-from-a-driver
// is not — `archcheck.TestInvalidateHasOneCaller` is what keeps that true.
//
// Idempotent, and silent about whether anything was there: a caller
// re-establishing after a 401 wants the next resolve to be fresh, and whether
// the entry had already expired on its own is not a distinction it can act on.
func (c *Cache) Invalidate(ref string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, ref)
}

// expireAllForTest drops every entry without touching generations, so a test can
// force a refetch. Named for what it is; there is no production reason to expire
// everything at once, and eviction proper arrives with D110's drain.
func (c *Cache) expireAllForTest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]*entry{}
}

// Stats reports provider calls and cache hits.
func (c *Cache) Stats() (calls, hits uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.hits
}

// ExpiryFor reports when a cached reference goes stale, for tests asserting
// that jitter actually differs between instances. Zero when not cached.
func (c *Cache) ExpiryFor(ref string) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[ref]; ok {
		return e.expires
	}
	return time.Time{}
}
