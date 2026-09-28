package connector

import (
	"context"
	"fmt"
	"sort"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// ClientBuilder is the OPTIONAL interface a Driver implements when it has a
// client worth pooling (D190).
//
// **OPTIONAL RATHER THAN PART OF `Driver`, and §4.7.4's classes are why.** A
// class 1 driver's client is credential-FREE — one shared `http.Client` holding
// nothing — so there is no per-target object to cache, and forcing every driver
// to implement this would make most of them return a marker. Boilerplate that
// reads as meaningful is worse than an absence that is checked: a reviewer
// seeing `BuildClient` on the Fullstory driver would reasonably conclude
// something per-target is being built there, and nothing is.
//
// Discovered by assertion rather than declared, which is the idiom this
// codebase already uses for exactly this shape (GO-PRIMER §2.2): `pool.Closer`
// is optional too, and its comment says why — "a driver that needs no teardown
// says nothing".
//
// **A DRIVER THAT DOES NOT IMPLEMENT IT STILL GETS A POOL ENTRY.** That is not a
// detail: the pool is what makes break-glass reach a call already in flight
// (CONTRACTS 35, D128), and a driver skipped by the pool would be invisible to
// `revoke_credential` — which would evict an empty pool and truthfully report
// cancelling nothing. The entry is a marker; the cancellation is real.
type ClientBuilder interface {
	// BuildClient constructs the pooled client for one target.
	//
	// Called lazily, on the first call for a given PoolKey, so it runs long
	// after wiring. §4.7.4 class 2 and class 3 take the credential here — the
	// SDK case, where there is no per-call seam — which is why D99's
	// content-addressed PoolKey is load-bearing rather than tidy: rotating a
	// credential must produce a different key, or the pool serves the old one.
	BuildClient(ctx context.Context, t Target) (any, error)
}

// Registry is the one map from driver kind to Driver.
//
// **IT EXISTS BECAUSE THE SECOND DRIVER MADE THE OLD WIRING UNTENABLE (D190).**
// `pool.New` takes ONE build function for the whole pool, and `cmd/sekizui`
// passed `kata.BuildClient` — correct while there was one driver, and with two
// kinds sharing a pool the build has to dispatch on `t.Kind()`. The obvious fix,
// a `map[string]Build` beside the existing `map[string]Driver`, is two maps
// keyed identically and kept in step by hand: the divergent-lists failure this
// package's `fault` sibling cites Lexicon for.
//
// **KEYED ON `Driver.Kind()`, NEVER ON A LITERAL, which closes a defect the old
// shape allowed.** `map[string]Driver{kata.Kind: kata.New()}` lets the key and
// the driver's own `Kind()` disagree — a typo, or a copied line — and the
// symptom is a target resolving to the wrong driver entirely. `Register` takes
// only the driver and reads the kind off it, so the two cannot differ.
//
// **AND IT BREAKS A WIRING CYCLE.** The pool needs a driver's build; a driver
// needs the pool so `Execute` can route through `Do`. `Build` is a method value
// that reads the map at CALL time — which is after wiring completes, because the
// pool only builds a client when a command arrives — so the pool can be
// constructed with `registry.Build` before any driver exists.
type Registry struct {
	byKind map[string]Driver
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byKind: map[string]Driver{}}
}

// Register adds a driver, refusing a duplicate kind.
//
// A DUPLICATE IS A BOOT REFUSAL RATHER THAN A SILENT OVERWRITE. Two drivers
// claiming one kind means every target of that kind reaches whichever was
// registered last, which depends on wiring order and is invisible in every
// artefact a reviewer would inspect.
func (r *Registry) Register(d Driver) error {
	const op = "connector.Registry.Register"

	if d == nil {
		return fault.New(fault.KindConfig, op, "a nil driver was registered")
	}
	kind := d.Kind()
	if kind == "" {
		return fault.New(fault.KindConfig, op,
			"a driver reported an empty Kind, so no target could ever name it")
	}
	if existing, taken := r.byKind[kind]; taken {
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"two drivers claim kind %q (%T and %T). Every target of that kind would "+
				"reach whichever was registered last, which depends on wiring order and "+
				"is invisible in every artefact a reviewer would inspect",
			kind, existing, d))
	}
	r.byKind[kind] = d
	return nil
}

// Drivers returns the map the gateway dispatches on.
//
// A COPY, so a caller cannot mutate the registry through it. Cheap at this size,
// and the alternative is an aliased map that turns "the gateway's drivers" and
// "the registry's drivers" into one thing two owners can edit.
func (r *Registry) Drivers() map[string]Driver {
	out := make(map[string]Driver, len(r.byKind))
	for kind, d := range r.byKind {
		out[kind] = d
	}
	return out
}

// Kinds returns the registered kinds, sorted. For boot reporting.
func (r *Registry) Kinds() []string {
	out := make([]string, 0, len(r.byKind))
	for kind := range r.byKind {
		out = append(out, kind)
	}
	sort.Strings(out)
	return out
}

// Build is the pool's `Build`: it asks the target's own driver for its client.
//
// **FAIL-CLOSED ON AN UNKNOWN KIND**, which also catches the wiring mistake this
// type exists to prevent. A pool asked to build for a kind nobody registered
// has, by construction, no idea what to construct — and returning a nil client
// would let the call proceed with the driver silently unpooled, so break-glass
// would evict nothing while reporting success.
func (r *Registry) Build(ctx context.Context, t Target) (any, error) {
	const op = "connector.Registry.Build"

	d, known := r.byKind[t.Kind()]
	if !known {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q names driver kind %q, which is not registered. Registered: %v",
			t.Ref(), t.Kind(), r.Kinds()))
	}

	// THE OPTIONAL HALF. A driver with nothing per-target to build says nothing
	// and gets a marker, so it is still POOLED — which is what keeps it reachable
	// by revocation — without pretending it constructed something.
	if b, ok := d.(ClientBuilder); ok {
		return b.BuildClient(ctx, t)
	}
	return credentialFreeClient{kind: t.Kind()}, nil
}

// CredentialFreeClient is the marker a driver returns from `BuildClient` when
// THIS target has nothing per-target to build (D213).
//
// **PUBLISHED BECAUSE ONE DRIVER CAN SERVE BOTH CLASSES, which the optional
// interface alone cannot express.** `ClientBuilder` is implemented per DRIVER
// and §4.7.4's class is a property of a TARGET: the MCP driver is class 3 on a
// stateful revision and class 1 on a sessionless one, so it must implement the
// interface and then answer "nothing" for half its targets. Without this it
// would invent a private marker, and a pool dump would carry two spellings of
// the same fact — which is the divergent-lists failure `pkg/fault` cites Lexicon
// for, in the place a human looks during an incident.
//
// The value is identical to what `Registry.Build` supplies for a driver that
// declines the interface, and that is the point: whether a class 1 entry came
// from a driver saying so or from a driver saying nothing must not be visible.
func CredentialFreeClient(kind string) any { return credentialFreeClient{kind: kind} }

// credentialFreeClient is the pool entry for a §4.7.4 class 1 driver.
//
// NAMED RATHER THAN `struct{}{}`, so a human reading a pool dump or a panic
// sees WHY the entry holds nothing instead of wondering what was lost. It
// carries the kind for the same reason.
type credentialFreeClient struct{ kind string }

func (c credentialFreeClient) String() string {
	return "credential-free client for " + c.kind + " (§4.7.4 class 1; pooled so " +
		"break-glass can cancel in-flight calls, not because there is a client to cache)"
}
