package acceptance

import (
	"bytes"
	"sync"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// P1 step 53: credential material is LENT, never handed over (D127).

// step53CredentialIsLentNotHandedOver proves the four properties lending exists
// for, and the fourth is the one that replaces D110's drain.
func step53CredentialIsLentNotHandedOver(t *testing.T) {
	newTarget := func(material string) connector.Target {
		t.Helper()
		tgt, err := connector.NewTarget(connector.TargetParams{
			Ref: "kata:alpha", Kind: "kata", Tenant: "alpha", Residency: "eu",
			CredentialVersion: "v#1", Credential: connector.Secret([]byte(material)),
		})
		if err != nil {
			t.Fatalf("NewTarget: %v", err)
		}
		return tgt
	}

	// --- 1. the borrow yields the real material -----------------------------
	tgt := newTarget("live-token")
	var seen string
	if err := tgt.Use(func(m connector.Material) error {
		b, err := m.AppendTo(nil)
		seen = string(b)
		return err
	}); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if seen != "live-token" {
		t.Fatalf("Use lent %q; every assertion below would be vacuous", seen)
	}

	// --- 2. after a wipe, Use REFUSES rather than lending zeroes ------------
	//
	// The whole of §4.7.10's argument in one assertion. Zeroed bytes are not a
	// refusal: a driver handed them sends an all-zeros credential and the audit
	// records whatever the upstream made of it — "the target returned 401"
	// instead of "an operator revoked this".
	tgt.WipeCredential()

	err := tgt.Use(func(connector.Material) error {
		t.Error("Use lent material from a WIPED credential — the driver would send " +
			"zeroes to the upstream and the audit would blame the target")
		return nil
	})
	if err == nil {
		t.Fatal("a wiped credential lent successfully")
	}
	if !fault.KindOf(err).Deliberate() {
		t.Errorf("a wiped credential refused with kind %v, which is classified as a "+
			"FAILURE. Revocation is the system saying no on purpose, and logging it "+
			"beside a target being down is the defect D125 exists to prevent",
			fault.KindOf(err))
	}

	// --- 3. a driver that STASHES the slice gains nothing --------------------
	//
	// Lending cannot stop a driver retaining the slice — Go has no way to
	// invalidate a []byte — so D127 states that as a contract rather than a
	// guarantee. This is the honest half: retention is useless, because the
	// bytes it kept are the bytes that get zeroed.
	tgt2 := newTarget("stashed-token")

	// (a) A retained MATERIAL is inert: the lease ends with the callback.
	var leaked connector.Material
	if err := tgt2.Use(func(m connector.Material) error { leaked = m; return nil }); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if _, err := leaked.AppendTo(nil); err == nil {
		t.Error("a Material retained past its callback still yielded material. The " +
			"lease is what makes 'lent for the duration of the call' literally true " +
			"rather than a convention nobody can enforce")
	}
	if n := leaked.Len(); n != 0 {
		t.Errorf("an expired lease reported Len = %d, want 0", n)
	}

	// (b) UseRaw is the acknowledged hole, and retention through it gains
	// nothing: the bytes kept are the bytes that get zeroed.
	var stashed []byte
	if err := tgt2.UseRaw(func(m []byte) error { stashed = m; return nil }); err != nil {
		t.Fatalf("UseRaw: %v", err)
	}
	tgt2.WipeCredential()

	if !bytes.Equal(stashed, make([]byte, len(stashed))) {
		t.Error("a slice retained past UseRaw still holds live material after a wipe. " +
			"Retention would then be a working way to outlive revocation, which is the " +
			"opposite of what lending is for")
	}

	// --- 4. concurrent borrows and a wipe are SYNCHRONISED -------------------
	//
	// THIS IS WHAT REPLACES D110'S DRAIN, and `-race` is the judge rather than
	// this test's own assertions. Many goroutines borrow while one wipes; the
	// RWMutex means no borrow can observe a half-zeroed credential, which is
	// exactly the tearing §4.7.10 rejects: "clear() concurrent with a read can
	// tear, producing a partially-valid credential non-deterministically".
	//
	// Remove the lock and this still passes its assertions most runs — and
	// `make test` hardcodes `-race`, which fails it every run. That is the
	// point: the guarantee is enforced by the build, not by an assertion that
	// happens to be lucky.
	const (
		material  = "concurrent-token"
		borrowers = 64
	)
	tgt3 := newTarget(material)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		partial []string
	)
	start := make(chan struct{})

	for range borrowers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = tgt3.UseRaw(func(m []byte) error {
				// Either the whole credential or nothing. A borrow that sees
				// SOME zeroed bytes has read through a concurrent wipe.
				got := string(m)
				if got != material && !bytes.Equal(m, make([]byte, len(m))) {
					mu.Lock()
					partial = append(partial, got)
					mu.Unlock()
				}
				return nil
			})
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		tgt3.WipeCredential()
	}()

	close(start)
	wg.Wait()

	if len(partial) > 0 {
		t.Errorf("%d borrow(s) observed a PARTIALLY zeroed credential, e.g. %q. That is "+
			"the tearing §4.7.10 rejects — the driver sends a half-valid credential and "+
			"the failure is non-deterministic", len(partial), partial[0])
	}
	if !tgt3.CredentialWiped() {
		t.Error("the wipe never completed while borrows were in flight; a revocation " +
			"that waits on borrowers forever is the attack surface lending removes")
	}
}
