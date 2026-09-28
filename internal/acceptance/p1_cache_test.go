package acceptance

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// P1 steps 1-3: the credential cache (§4.7.6).
//
// The cache is P1's first deliverable because everything else in the phase
// waits behind it — resolution happened once per command, which is unusable for
// a secret manager.

// countingProvider records how many times the backend was actually asked, which
// is the only thing steps 1 and 2 are really about.
type countingProvider struct {
	scheme string

	mu       sync.Mutex
	calls    int
	material string

	// block, when non-nil, holds every Resolve until closed — so a test can put
	// N goroutines inside one flight simultaneously rather than hoping.
	block chan struct{}
}

func (p *countingProvider) Scheme() string { return p.scheme }

func (p *countingProvider) Resolve(ctx context.Context, ref string) (config.Resolution, error) {
	p.mu.Lock()
	p.calls++
	block := p.block
	material := p.material
	p.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return config.Resolution{}, ctx.Err()
		}
	}
	return config.Resolution{Material: []byte(material)}, nil
}

func (p *countingProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// step1CachedResolution — N commands, ONE provider call.
func step1CachedResolution(t *testing.T) {
	prov := &countingProvider{scheme: "test", material: "s3cret"}
	clock := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	cache := credential.New([]config.Provider{prov},
		credential.WithTTL(5*time.Minute),
		credential.WithClock(func() time.Time { return clock }))

	const commands = 50
	for range commands {
		mat, ver, err := cache.Resolve(context.Background(), "test://key")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if string(mat) != "s3cret" || ver == "" {
			t.Fatalf("material=%q version=%q", mat, ver)
		}
	}

	if got := prov.count(); got != 1 {
		t.Errorf("%d provider calls for %d commands, want 1. With gcp-sm:// each of "+
			"those is a Secret Manager API call on the enforcement path (§4.7.6)",
			got, commands)
	}

	calls, hits := cache.Stats()
	if calls != 1 || hits != commands-1 {
		t.Errorf("stats: calls=%d hits=%d, want 1 and %d", calls, hits, commands-1)
	}

	// NON-VACUOUS: past expiry it must fetch again, or "one call" would just
	// mean the cache never refreshes.
	clock = clock.Add(10 * time.Minute)
	if _, _, err := cache.Resolve(context.Background(), "test://key"); err != nil {
		t.Fatalf("resolve after expiry: %v", err)
	}
	if got := prov.count(); got != 2 {
		t.Errorf("%d provider calls after expiry, want 2 — the entry never went stale", got)
	}
}

// step2Singleflight — N goroutines meeting a cold cache produce ONE call.
func step2Singleflight(t *testing.T) {
	prov := &countingProvider{scheme: "test", material: "s3cret", block: make(chan struct{})}
	cache := credential.New([]config.Provider{prov})

	const goroutines = 64
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		errs  []error
		start = make(chan struct{})
	)

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := cache.Resolve(context.Background(), "test://key")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}

	close(start)
	// Let them pile up behind the blocked provider, then release.
	waitFor(t, func() bool { return prov.count() > 0 }, "no goroutine reached the provider")
	time.Sleep(20 * time.Millisecond)
	close(prov.block)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d of %d resolves failed; first: %v", len(errs), goroutines, errs[0])
	}
	if got := prov.count(); got != 1 {
		t.Errorf("%d provider calls from %d concurrent cold resolves, want 1. Every cold "+
			"start would otherwise stampede the secret manager (§4.3.2)", got, goroutines)
	}
}

// step3JitterIsPerInstance — two caches with identical config must not expire
// together.
//
// The failure this catches looks correct: jitter derived from the reference is
// deterministic, so every replica computes the SAME expiry and refreshes in
// lockstep — which is the stampede jitter exists to prevent.
func step3JitterIsPerInstance(t *testing.T) {
	clock := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	newCache := func() *credential.Cache {
		return credential.New([]config.Provider{&countingProvider{scheme: "test", material: "x"}},
			credential.WithTTL(5*time.Minute),
			credential.WithClock(func() time.Time { return clock }))
	}

	const replicas = 8
	expiries := map[time.Time]int{}
	for range replicas {
		c := newCache()
		if _, _, err := c.Resolve(context.Background(), "test://key"); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		expiries[c.ExpiryFor("test://key")]++
	}

	if len(expiries) < replicas {
		t.Errorf("%d distinct expiry times across %d replicas resolving the SAME reference "+
			"at the same instant — jitter that is identical across the fleet defeats itself, "+
			"which is what deriving it from the key would do", len(expiries), replicas)
	}

	// And it must stay within the declared band, or "jitter" is just noise.
	for exp := range expiries {
		delta := exp.Sub(clock)
		lo := time.Duration(float64(5*time.Minute) * (1 - credential.DefaultJitter))
		hi := time.Duration(float64(5*time.Minute) * (1 + credential.DefaultJitter))
		if delta < lo || delta > hi {
			t.Errorf("expiry %v is outside the ±%.0f%% band [%v, %v]",
				delta, credential.DefaultJitter*100, lo, hi)
		}
	}
}

// Compile-time proof the steps match the signature the table expects.
var _ = []func(*testing.T){
	step1CachedResolution, step2Singleflight, step3JitterIsPerInstance,
	step38PoolKeyCannotBePrinted,
}

// step38PoolKeyCannotBePrinted — D112, at the acceptance level.
//
// Asserted here as well as in pkg/connector's own tests because the acceptance
// run is what a reviewer reads: "a credential reference never reaches a log" is
// a claim about the SYSTEM, and it should be checked where the system's claims
// are collected rather than only where the type is defined.
func step38PoolKeyCannotBePrinted(t *testing.T) {
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "fullstory:prod", Kind: "fullstory", Tenant: "acme", Residency: "eu",
		CredentialVersion: "gcp-sm://projects/acme-prod/secrets/fs-token/versions/7#2",
		Credential:        connector.Secret("material"),
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("pooling", "key", tgt.PoolKey())

	renderings := []string{
		tgt.PoolKey().String(),
		fmt.Sprintf("%v", tgt.PoolKey()),
		fmt.Sprintf("%#v", tgt.PoolKey()),
		buf.String(),
	}
	for _, r := range renderings {
		for _, leak := range []string{"acme-prod", "fs-token", "versions/7", "material"} {
			if strings.Contains(r, leak) {
				t.Errorf("a rendering leaks %q: %s", leak, r)
			}
		}
	}

	// Non-vacuous: the useful half must survive, or a key printing nothing passes.
	if got := tgt.PoolKey().String(); !strings.Contains(got, "fullstory:prod") {
		t.Errorf("String() = %q — a key that redacts everything is useless in a log", got)
	}
}

// --- step 54: the provider seam (D130) --------------------------------------

// expiringProvider reports an expiry and a version, and can change its material
// independently of both — which is exactly the combination a refreshable
// credential produces and a static one never does.
type expiringProvider struct {
	mu       sync.Mutex
	calls    int
	material string
	version  string
	expiry   time.Time
}

func (p *expiringProvider) Scheme() string { return "test" }

func (p *expiringProvider) Resolve(context.Context, string) (config.Resolution, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return config.Resolution{
		Material: []byte(p.material),
		Version:  p.version,
		Expiry:   p.expiry,
	}, nil
}

func (p *expiringProvider) set(material, version string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.material, p.version = material, version
}

// step54ProviderExpiryAndVersion is D130, and both halves were live defects.
//
// The cache discarded the provider's expiry and applied its own TTL, which is
// invisible while every provider reports zero and becomes a four-minute outage
// per cycle the moment one reports sixty seconds. And D123 derived the pool
// generation by digesting MATERIAL, which is correct for a static secret and
// tears down an MCP session on a timer for a refreshable one — the precise
// thing §4.7.1's table promises will not happen.
func step54ProviderExpiryAndVersion(t *testing.T) {
	base := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	newCache := func(prov config.Provider, jitter float64, clock *time.Time) *credential.Cache {
		return credential.New([]config.Provider{prov},
			credential.WithTTL(5*time.Minute),
			credential.WithJitterSource(func() float64 { return jitter }),
			credential.WithClock(func() time.Time { return *clock }))
	}

	// --- the provider's expiry is honoured, and is a CEILING ----------------
	//
	// Asserted at both jitter extremes, because early-only is the property:
	// a +1 swing must not push expiry past what the issuer said.
	for _, jitter := range []float64{-1, 0, 1} {
		clock := base
		prov := &expiringProvider{material: "tok", version: "7", expiry: base.Add(60 * time.Second)}
		cache := newCache(prov, jitter, &clock)

		if _, _, err := cache.Resolve(context.Background(), "test://k"); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		got := cache.ExpiryFor("test://k")

		if got.After(base.Add(60 * time.Second)) {
			t.Errorf("jitter %+.0f: cached until %v, past the provider's expiry of %v. "+
				"Jitter against a hard deadline must only ever move EARLIER — a positive "+
				"swing hands out material that is already dead", jitter, got, base.Add(60*time.Second))
		}
		if !got.Before(base.Add(5 * time.Minute)) {
			t.Errorf("jitter %+.0f: cached until %v, which is the configured TTL rather "+
				"than the provider's 60s expiry. This is the defect D130 names: a token "+
				"cached four minutes past its life fails every call in between", jitter, got)
		}
	}

	// --- a REFRESH must not bump the generation -----------------------------
	//
	// Different bytes, same version. D47's table: "refresh is invisible to
	// pooling". D123's material digest broke that silently.
	clock := base
	prov := &expiringProvider{material: "token-A", version: "secret-v7", expiry: base.Add(60 * time.Second)}
	cache := newCache(prov, 0, &clock)

	_, first, err := cache.Resolve(context.Background(), "test://k")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	prov.set("token-B", "secret-v7") // refreshed token, SAME client secret
	clock = clock.Add(2 * time.Minute)

	mat, second, err := cache.Resolve(context.Background(), "test://k")
	if err != nil {
		t.Fatalf("resolve after refresh: %v", err)
	}
	if string(mat) != "token-B" {
		t.Fatalf("material = %q, want token-B — the entry never actually refetched, so "+
			"the assertion below would pass vacuously", mat)
	}
	if second != first {
		t.Errorf("credVer moved %q -> %q on a token REFRESH. The pooled client is evicted "+
			"and, for a session-oriented target, the MCP session is re-initialised — on a "+
			"timer, for a credential that never rotated (§4.7.1, D130)", first, second)
	}

	// --- a ROTATION must bump it. Non-vacuity for the assertion above -------
	prov.set("token-C", "secret-v8") // the client secret itself rotated
	clock = clock.Add(2 * time.Minute)

	_, third, err := cache.Resolve(context.Background(), "test://k")
	if err != nil {
		t.Fatalf("resolve after rotation: %v", err)
	}
	if third == second {
		t.Errorf("credVer stayed %q across a client-secret rotation v7 -> v8. Nothing "+
			"invalidates the pooled client, so it keeps using a superseded credential "+
			"(D99) — and the check above is satisfied by a version that never moves", third)
	}
}
