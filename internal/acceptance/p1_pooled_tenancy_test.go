package acceptance

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step24MixedTenancyHoldsWithPooling re-runs P0 step 14's property against the
// component that can actually break it.
//
// THE STEP'S ORIGINAL PREMISE HAS EXPIRED, and saying so is more useful than
// quietly writing to it. It read "P0 step 14 proved this with no pool" — true
// when declared, and false since CONTRACTS §4 item 35 put the pool in the
// enforcement path: the harness now builds `kata.New(kata.WithPool(clientPool))`,
// so step 14 has been running pooled for some time without anyone updating the
// sentence that said it was not.
//
// So the property step 14 already covers — no tenant bleed under concurrent load
// — is not re-proven here. What this adds is the part a bleed-only assertion
// cannot see: that the pool KEPT ONE CLIENT PER TENANT and REUSED them. A pool
// that built a fresh client per call would pass every bleed check ever written,
// because a client used once cannot be handed to the wrong tenant — and it would
// also mean §6's cache-key argument was never exercised.
func step24MixedTenancyHoldsWithPooling(t *testing.T) {
	ctx := context.Background()
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(ctx)
	}
	if r.localOnly(t, "the pool's entry count is read from this process") {
		return
	}

	// Four tenants, each its own target, all reachable by one principal — the
	// realistic shape, and the only one where a leak is possible at all.
	tenants := map[string]string{
		"kata:alpha": "alpha", "kata:gamma": "gamma",
		"kata:delta": "delta", "kata:epsilon": "epsilon",
	}

	before := r.pool.Len()

	const perTenant = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		bleeds []string
		errs   []error
	)

	bulk := r.as(t, "agent:bulk")
	for ref, want := range tenants {
		for range perTenant {
			wg.Add(1)
			go func(ref, want string) {
				defer wg.Done()
				resp, err := bulk.Execute(ctx, execute("kata.create_issue", ref,
					map[string]any{"project": "PROJ", "title": "pooled " + want}))

				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, err)
					return
				}
				res := resp.GetResult()
				if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
					errs = append(errs, fmt.Errorf("%s: %s", ref, res.GetReason()))
					return
				}
				// The tenant the DRIVER saw, echoed back — not what this test
				// believes it asked for.
				if got, _ := res.GetResult().AsMap()["tenant"].(string); got != want {
					bleeds = append(bleeds, fmt.Sprintf(
						"a command for %s ran against tenant %q", ref, got))
				}
			}(ref, want)
		}
	}
	wg.Wait()

	if len(bleeds) > 0 {
		t.Fatalf("TENANT BLEED through the pool — %d of %d commands reached the wrong "+
			"tenant:\n  %s\n\n§6 opens with 'every cross-tenant leak is a cache key "+
			"missing a dimension', and this is where that is decided",
			len(bleeds), len(tenants)*perTenant, strings.Join(bleeds, "\n  "))
	}
	if len(errs) > 0 {
		t.Fatalf("%d of %d concurrent commands failed; first: %v",
			len(errs), len(tenants)*perTenant, errs[0])
	}

	// --- THE POOL WAS ACTUALLY USED, AND KEYED PER TENANT -------------------
	//
	// 32 commands across 4 tenants must leave FOUR entries, not thirty-two and
	// not one. Thirty-two would mean the key carries a dimension it should not
	// and every call built a client; one would mean it is missing the tenant,
	// which is the leak §6 names. Both extremes pass a bleed check under this
	// driver, which is exactly why the count is asserted separately.
	added := r.pool.Len() - before
	if added != len(tenants) {
		t.Errorf("the pool gained %d entries for %d tenants over %d commands, want %d. "+
			"Too many means a key dimension that should not be there and no reuse at "+
			"all; too few means a MISSING dimension, which is how one tenant receives "+
			"another's client", added, len(tenants), len(tenants)*perTenant, len(tenants))
	}

	r.detail(t, "%d commands across %d tenants reused %d pooled clients, one per tenant",
		len(tenants)*perTenant, len(tenants), added)
}
