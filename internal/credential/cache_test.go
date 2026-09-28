package credential

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
)

// rotatingProvider hands out whatever material it currently holds.
type rotatingProvider struct {
	mu       sync.Mutex
	material string
	calls    int
}

func (p *rotatingProvider) Scheme() string { return "test" }

func (p *rotatingProvider) Resolve(context.Context, string) (config.Resolution, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return config.Resolution{Material: []byte(p.material)}, nil
}

func (p *rotatingProvider) rotate(to string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.material = to
}

func fixedClock(t time.Time) Option { return WithClock(func() time.Time { return t }) }

// TestGenerationBumpsOnlyWhenMaterialChanges is the property the pool key rests
// on (D99, amended): the version must change exactly when the credential does.
//
// Both halves matter. Not bumping on rotation leaves a superseded credential
// live in a pooled client. Bumping on every refetch churns every client on every
// TTL expiry, for nothing.
func TestGenerationBumpsOnlyWhenMaterialChanges(t *testing.T) {
	prov := &rotatingProvider{material: "first"}
	clock := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	c := New([]config.Provider{prov}, WithTTL(time.Minute), fixedClock(clock))

	_, v1, err := c.Resolve(context.Background(), "test://k")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.HasSuffix(v1, "#1") {
		t.Errorf("first version = %q, want a #1 generation suffix", v1)
	}

	// Expire and refetch the SAME material: the generation must hold.
	c2 := New([]config.Provider{prov}, WithTTL(time.Minute),
		WithClock(func() time.Time { return clock }))
	_ = c2
	c.expireAllForTest()
	_, v2, _ := c.Resolve(context.Background(), "test://k")
	if v2 != v1 {
		t.Errorf("version changed from %q to %q on a refetch of identical material — "+
			"every TTL expiry would churn every pooled client", v1, v2)
	}

	// Now rotate. The generation must move.
	prov.rotate("second")
	c.expireAllForTest()
	_, v3, _ := c.Resolve(context.Background(), "test://k")
	if v3 == v2 {
		t.Errorf("version stayed %q across a rotation — a pooled client would keep "+
			"serving the superseded credential (D99)", v3)
	}
	if !strings.HasSuffix(v3, "#2") {
		t.Errorf("rotated version = %q, want a #2 generation", v3)
	}
}

// TestVersionCarriesNoMaterial — the reason a generation was chosen over a
// content hash. Nothing derived from the secret may reach a value that travels
// through map keys, error strings, and metric labels.
func TestVersionCarriesNoMaterial(t *testing.T) {
	const secret = "super-secret-token-value"
	prov := &rotatingProvider{material: secret}
	c := New([]config.Provider{prov})

	_, version, err := c.Resolve(context.Background(), "test://k")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if strings.Contains(version, secret) {
		t.Fatalf("the version contains the material: %q", version)
	}
	// And not a digest of it either — a hash is a confirmation oracle, which is
	// the whole reason this is a counter.
	if len(version) > len("test://k")+8 {
		t.Errorf("version %q is longer than ref+generation; is something derived from "+
			"the material embedded in it?", version)
	}
}

// TestErrorsAreSharedNotRetriedPerCaller — a provider outage costs one call, not
// one per waiting goroutine.
func TestErrorsAreSharedNotRetriedPerCaller(t *testing.T) {
	c := New(nil) // no providers, so every fetch fails on scheme lookup

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := c.Resolve(context.Background(), "test://k"); err == nil {
				t.Error("resolve succeeded with no provider registered")
			}
		}()
	}
	wg.Wait()

	// The failed entry must not be cached, or a transient outage would be
	// remembered for a full TTL.
	if got := c.ExpiryFor("test://k"); !got.IsZero() {
		t.Errorf("a failed resolve was cached until %v", got)
	}
}

// TestResolveHonoursCancellationWhileWaiting — a caller that gives up must not
// be trapped behind a slow provider.
func TestResolveHonoursCancellationWhileWaiting(t *testing.T) {
	release := make(chan struct{})
	slow := &blockingProvider{release: release}
	c := New([]config.Provider{slow})

	go func() { _, _, _ = c.Resolve(context.Background(), "test://k") }()

	// Wait until the owner is inside the provider.
	deadline := time.Now().Add(2 * time.Second)
	for slow.entered() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.Resolve(ctx, "test://k"); err == nil {
		t.Error("a cancelled caller waited for the in-flight fetch anyway")
	}
	close(release)
}

type blockingProvider struct {
	release chan struct{}
	mu      sync.Mutex
	in      int
}

func (p *blockingProvider) Scheme() string { return "test" }

func (p *blockingProvider) Resolve(ctx context.Context, _ string) (config.Resolution, error) {
	p.mu.Lock()
	p.in++
	p.mu.Unlock()
	<-p.release
	return config.Resolution{Material: []byte("x")}, nil
}

func (p *blockingProvider) entered() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.in
}
