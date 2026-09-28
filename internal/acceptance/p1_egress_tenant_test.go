package acceptance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// step25TheEgressTenantAssertionFiresAgainstABrokenPool proves §6 mechanism 3.
//
// **BY SABOTAGE RATHER THAN INSPECTION, and the sabotage is not contrived.**
// `PoolKey` is `{kind, ref, credVer}` — **tenant is not in it**. So two targets
// sharing a ref and a credential version collide in the pool however carefully
// each was constructed, which is exactly the failure §6 describes: "a pooled
// client keyed on a stale or incomplete PoolKey will eventually hand back a
// client belonging to another tenant, and no amount of care at construction
// prevents that — the bug is in the cache, not the constructor".
//
// Configuration cannot produce that collision today, because a ref maps to one
// tenant. That is a property of the config schema rather than of the pool, and
// §6 lists two mechanisms precisely so neither is trusted alone: the day a
// multi-tenant ref, a rewritten key, or a driver-supplied target arrives, this is
// the check that has to be already there.
func step25TheEgressTenantAssertionFiresAgainstABrokenPool(t *testing.T) {
	ctx := context.Background()

	var built []string
	p := pool.New(func(_ context.Context, tgt connector.Target) (any, error) {
		built = append(built, tgt.Tenant())
		return "client-for-" + tgt.Tenant(), nil
	}, quietLogger())

	// TWO TENANTS, ONE POOL KEY. Same kind, same ref, same credential version —
	// the incomplete key, built the only way it can be built: honestly, through
	// the validating constructor, twice.
	alpha := collidingTarget(t, "alpha")
	beta := collidingTarget(t, "beta")

	if alpha.PoolKey() != beta.PoolKey() {
		t.Skip("PoolKey now distinguishes these targets — the collision this step " +
			"sabotages no longer exists, and the step needs rewriting rather than " +
			"passing vacuously")
	}

	// Alpha borrows first and populates the entry.
	if err := p.Do(ctx, alpha, func(context.Context, any) error { return nil }); err != nil {
		t.Fatalf("alpha: %v", err)
	}

	// **BETA NOW ASKS, AND THE POOL HAS ALPHA'S CLIENT UNDER BETA'S KEY.**
	var handed string
	err := p.Do(ctx, beta, func(_ context.Context, c any) error {
		handed, _ = c.(string)
		return nil
	})

	if err == nil {
		t.Fatalf("the pool handed tenant beta a client built for %q and nothing "+
			"objected. That is one tenant's credential inside another tenant's "+
			"request — the cross-pollination §6 exists to make structurally "+
			"impossible, and the failure a constructor cannot see", handed)
	}

	// IT MUST READ AS OUR BUG, not as a policy refusal. A tenant mismatch is
	// Sekizui about to leak a credential; classifying it as a denial would file
	// it with the ordinary refusals nobody investigates.
	if !strings.Contains(err.Error(), "TENANT MISMATCH") {
		t.Errorf("the refusal does not name the mismatch: %v", err)
	}

	// AND NOTHING WAS HANDED OVER. Catching it after the callback ran would be
	// a report rather than a defence.
	if handed != "" {
		t.Errorf("the callback ran with %q before the mismatch was caught; the check "+
			"must fire BEFORE the outbound call, not after it", handed)
	}

	// NON-VACUITY: the same pool serves a target it genuinely built for.
	if err := p.Do(ctx, alpha, func(context.Context, any) error { return nil }); err != nil {
		t.Errorf("the pool refused a target it built for: %v. A check that refuses "+
			"everything is not a check", err)
	}
	if len(built) != 1 {
		t.Errorf("builds = %d, want 1 — alpha's entry should have been reused", len(built))
	}
}

// collidingTarget builds a target that shares a PoolKey with its siblings and
// differs only in tenant.
func collidingTarget(t *testing.T, tenant string) connector.Target {
	t.Helper()

	target, err := connector.NewTarget(connector.TargetParams{
		// SAME ref, kind and credential version for every tenant. Nothing here
		// is invalid — each target is well-formed and would pass every check
		// §6 makes at construction. That is the point.
		Ref: "kata:shared", Kind: "kata", CredentialVersion: "v1",
		Tenant: tenant, BaseURL: "https://shared.invalid",
	})
	if err != nil {
		t.Fatalf("target for %s: %v", tenant, err)
	}
	return target
}
