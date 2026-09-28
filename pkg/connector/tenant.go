package connector

import "context"

// tenantKey is the context key for the request's tenant.
//
// An UNEXPORTED type, which is the standard Go idiom for context keys: a value
// of this type cannot be constructed outside this package, so no other package
// can collide with the key or overwrite the value — even accidentally, even with
// the same underlying string. A bare string key would be collidable by anyone.
type tenantKey struct{}

// WithTenant binds a tenant to the request context.
//
// Called ONCE, immediately after the target is resolved, at the top of request
// handling. Everything downstream compares against it rather than re-deriving
// it — the whole point is to have an independent second opinion.
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}

// TenantFrom returns the request's tenant, or "" if none was bound.
//
// PUBLIC because third-party drivers must call it (D35). The connector
// definition-of-done requires every driver to assert `ctx` tenant against
// `Target.Tenant()` before each outbound call, and an obligation placed on
// external code cannot be served by an internal package — the same reasoning
// that moved the error taxonomy into pkg/fault.
//
// Returns "" rather than a bool, and Target.Assert treats "" as a REFUSAL
// rather than a pass. An unbound tenant means someone skipped WithTenant, and
// assuming a match is precisely how a leak starts.
func TenantFrom(ctx context.Context) string {
	tenant, _ := ctx.Value(tenantKey{}).(string)
	return tenant
}

// AssertTenant is the egress check in the form a driver actually calls it —
// §6 mechanism 3, "assert before every egress… nanoseconds; catches every
// pooling bug".
//
// WHY THIS CATCHES SOMETHING THE CONSTRUCTOR CANNOT. Mechanism 1 guarantees a
// Target has a tenant. It says nothing about whether THIS Target is the right
// one for THIS request — and it cannot, because the substitution happens later,
// in the client pool. A pooled client keyed on a stale or under-specified
// PoolKey hands back a connection belonging to another tenant, and no amount of
// care at construction sees it. This does.
func AssertTenant(ctx context.Context, t Target) error {
	return t.Assert(TenantFrom(ctx))
}
