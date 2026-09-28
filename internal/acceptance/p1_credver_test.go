package acceptance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/credver"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// steppingProvider is a secret manager whose `latest` we control, which is the
// only way to exercise a platform behaviour nobody has documented.
type steppingProvider struct {
	scheme  string
	version atomic.Value // string
}

func (p *steppingProvider) Scheme() string { return p.scheme }

func (p *steppingProvider) Resolve(_ context.Context, _ string) (config.Resolution, error) {
	v, _ := p.version.Load().(string)
	// Material CHANGES WITH THE VERSION, or the cache's content digest would
	// keep returning a cached entry and the guard would never be reached.
	return config.Resolution{Material: []byte("material-for-" + v), Version: v}, nil
}

func stepping(scheme, v string) *steppingProvider {
	p := &steppingProvider{scheme: scheme}
	p.version.Store(v)
	return p
}

// step67ATrackingReferenceCannotResolveBackwards proves D152.
//
// The question this replaces: does `gcp-sm://…/versions/latest` fall back to an
// older ENABLED version when the newest is disabled? Google's documentation says
// only that a version may be "a version number as a string (e.g. '5') or an
// alias (e.g. 'latest')" and nothing at all about disabled versions — checked,
// not assumed. **An unspecified behaviour is not a contract**, and a
// characterisation test would have reported what one project did on one day
// while Sekizui's break-glass guarantee rested on the accident.
//
// So the guard removes the dependency rather than resolving it. If `latest`
// fails, break-glass works. If it falls back, this refuses the fallback. Correct
// under either behaviour, and on a platform nobody has characterised.
func step67ATrackingReferenceCannotResolveBackwards(t *testing.T) {
	ctx := context.Background()
	const ref = "sm://projects/p/secrets/s/versions/latest"

	// EVERY RESOLVE IS A CACHE MISS HERE, on purpose.
	//
	// The guard is reached only on a miss, which is correct — while the newer
	// version is cached, Sekizui is serving the newer version and there is
	// nothing to refuse. The first version of this step did not force a miss and
	// two arms failed while a third passed, which is precisely what pinned the
	// property down: the arm that used a FRESH cache saw the downgrade and the
	// arms reusing one did not.
	//
	// A zero TTL rather than a fake clock, because the seam being exercised is
	// the guard and not the expiry policy — expiry has its own steps (1, 3) and
	// borrowing their machinery here would couple two independent things.
	newCache := func(t *testing.T, p config.Provider, store credver.Store) *credential.Cache {
		t.Helper()
		c := credential.New([]config.Provider{p},
			credential.WithTTL(0),
			credential.WithVersionMarks(store),
			credential.WithLogger(quietLogger()))
		if _, err := c.RehydrateMarks(ctx); err != nil {
			t.Fatalf("rehydrating marks: %v", err)
		}
		return c
	}

	// --- 67a: FORWARD IS FINE, and the mark advances ------------------------
	t.Run("a rotation forward is permitted", func(t *testing.T) {
		p := stepping("sm", "projects/p/secrets/s/versions/6")
		store := credential.NewMarkFileStore(filepath.Join(t.TempDir(), "audit.jsonl.credver"))
		c := newCache(t, p, store)

		if _, _, err := c.Resolve(ctx, ref); err != nil {
			t.Fatalf("v6: %v", err)
		}
		p.version.Store("projects/p/secrets/s/versions/7")
		if _, _, err := c.Resolve(ctx, ref); err != nil {
			t.Fatalf("v7 after v6 was refused: %v. D99's tracking references exist so "+
				"rotation needs no config change — a guard that blocked forward motion "+
				"would remove their entire point", err)
		}

		marks, err := store.Load(ctx)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(marks) != 1 || marks[0].Ordinal != 7 {
			t.Errorf("marks = %+v, want one mark at ordinal 7", marks)
		}
	})

	// --- 67b: BACKWARDS IS REFUSED — the whole decision --------------------
	t.Run("a resolution to an older version is refused", func(t *testing.T) {
		p := stepping("sm", "projects/p/secrets/s/versions/7")
		store := credential.NewMarkFileStore(filepath.Join(t.TempDir(), "audit.jsonl.credver"))
		c := newCache(t, p, store)

		if _, _, err := c.Resolve(ctx, ref); err != nil {
			t.Fatalf("v7: %v", err)
		}

		// THE BREAK-GLASS SCENARIO. v7 is declared compromised and disabled; the
		// platform answers `latest` with v6, which is enabled and older.
		p.version.Store("projects/p/secrets/s/versions/6")

		_, _, err := c.Resolve(ctx, ref)
		if err == nil {
			t.Fatal("a tracking reference resolved BACKWARDS and was accepted. That is a " +
				"credential somebody revoked as compromised silently back in service, " +
				"with every log line reporting a successful resolution")
		}
		// **`unauthenticated` SINCE D201, AND THIS ARM FAILED WHEN IT CHANGED** —
		// the suite doing its job on a decision change, as it did to steps 61 and
		// 64 when D158 landed. The kind moved because the STAGE the audit row
		// names is derived from the attribution (D200): `denied` is attributed to
		// the CALLER, which recorded this refusal as a policy or residency
		// decision. It is neither — the credential offered is not acceptable for
		// use — and the row is what somebody reviews six months later.
		//
		// Nothing the caller sees coarsely has changed: both kinds are deliberate
		// refusals mapping to STATUS_DENIED.
		if got := fault.KindOf(err); got != fault.KindUnauthenticated {
			t.Errorf("kind = %v, want %v", got, fault.KindUnauthenticated)
		}
		if !fault.KindOf(err).Deliberate() {
			t.Error("the downgrade refusal is not deliberate, so it would reach a caller " +
				"as a transport error and the audit row would name no stage at all")
		}
		// BOTH VERSIONS NAMED, and the remedy. An operator told only that
		// something is wrong cannot tell a platform fallback from an attacker,
		// and the legitimate case — a deliberate rollback — needs the pin named
		// or they have no way forward.
		for _, want := range []string{"versions/6", "versions/7", "PIN"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q: %v", want, err)
			}
		}
	})

	// --- 67c: DURABLE, or a restart is the way to clear it -----------------
	//
	// D145's lesson applied before it could be repeated: an in-memory mark makes
	// a restart the way to permit a downgrade, and a restart is the most routine
	// operation a deployment has.
	t.Run("the mark survives a restart", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl.credver")
		store := credential.NewMarkFileStore(path)

		p := stepping("sm", "projects/p/secrets/s/versions/7")
		if _, _, err := newCache(t, p, store).Resolve(ctx, ref); err != nil {
			t.Fatalf("v7: %v", err)
		}

		// A SECOND CACHE OVER THE SAME STORE IS A RESTART for this purpose.
		p.version.Store("projects/p/secrets/s/versions/6")
		if _, _, err := newCache(t, p, credential.NewMarkFileStore(path)).Resolve(ctx, ref); err == nil {
			t.Error("a fresh process accepted the downgrade its predecessor refused, so " +
				"restarting is how an operator clears the guard — which is exactly what " +
				"D145 found wrong with withdrawals")
		}
	})

	// --- 67d: NO ORDER, NO GUARD — the arm that keeps file:// working ------
	//
	// Without this the step would pass against a guard that refused every
	// second resolution, and `file://` — whose version is a CONTENT DIGEST, per
	// §4.7.2 — would break on every legitimate edit. There is no such thing as
	// an older digest.
	t.Run("an unordered version is not compared", func(t *testing.T) {
		p := stepping("sm", "")
		store := credential.NewMarkFileStore(filepath.Join(t.TempDir(), "audit.jsonl.credver"))
		c := newCache(t, p, store)

		if _, _, err := c.Resolve(ctx, ref); err != nil {
			t.Fatalf("empty version: %v", err)
		}
		for _, v := range []string{"sha256:beef", "sha256:0000", ""} {
			p.version.Store(v)
			if _, _, err := c.Resolve(ctx, ref+"#"+v); err != nil {
				t.Errorf("version %q was compared as if it had an order: %v. A digest has "+
					"no older or newer, and inventing one refuses legitimate edits about "+
					"half the time", v, err)
			}
		}
	})

	// --- 67e: A STORE THAT CANNOT LOAD FAILS THE BOOT ---------------------
	t.Run("a corrupt store refuses to start", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl.credver")
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		c := credential.New([]config.Provider{stepping("sm", "versions/1")},
			credential.WithVersionMarks(credential.NewMarkFileStore(path)),
			credential.WithLogger(quietLogger()))

		if _, err := c.RehydrateMarks(ctx); err == nil {
			t.Error("a corrupt mark file started clean. An unreadable set of marks is not " +
				"evidence that nothing has been seen — it permits every downgrade the " +
				"marks existed to refuse")
		}
	})

	// --- 67f: A STORE THAT CANNOT WRITE DOES NOT BREAK SERVING -------------
	//
	// THE ASYMMETRY WITH 67e, AND IT IS D150'S RULE. Failing to load is a
	// silently-weakened guarantee, so it fails closed. Failing to WRITE would
	// turn a defence into an outage — the credential resolved correctly and is
	// in force — and fail-closed is the attack when the threat is to
	// availability.
	t.Run("a store that cannot record does not refuse the credential", func(t *testing.T) {
		c := credential.New([]config.Provider{stepping("sm", "versions/1")},
			credential.WithTTL(0),
			credential.WithVersionMarks(brokenMarkStore{}),
			credential.WithLogger(quietLogger()))
		if _, err := c.RehydrateMarks(ctx); err != nil {
			t.Fatalf("rehydrate: %v", err)
		}

		if _, _, err := c.Resolve(ctx, ref); err != nil {
			t.Errorf("a credential that resolved correctly was refused because the guard "+
				"could not write its bookkeeping: %v. That makes a defence into an "+
				"outage, which is the failure D150 names", err)
		}
	})
}

// brokenMarkStore loads fine and never records.
type brokenMarkStore struct{}

func (brokenMarkStore) Load(context.Context) ([]credver.Mark, error) { return nil, nil }
func (brokenMarkStore) Put(context.Context, credver.Mark) error {
	return errors.New("disk full")
}
