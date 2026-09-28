package kata

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// tenantCtx binds a tenant to the context, as request handling does immediately
// after resolving a target. Without it every driver call is refused — which is
// the point of §6 mechanism 3, and which every test below would otherwise have
// to rediscover.

// idemFor builds the idempotency a given action declares, with a fixed key.
//
// DERIVED FROM Actions() RATHER THAN HARDCODED PER TEST, so a class change on an
// action does not need every call site edited — and so a test cannot accidentally
// assert against a placement the driver no longer uses, which is the drift D155
// warns about arriving through a test fixture.
func idemFor(action string) connector.Idempotency {
	for _, spec := range New().Actions() {
		if spec.Name == action {
			return connector.Idempotency{
				Class:     spec.Idempotency,
				Placement: spec.IdempotencyPlacement,
				Key:       "ik-test",
			}
		}
	}
	// An unknown action: hand back nothing and let the driver refuse, which is
	// what a test naming a non-existent action should see.
	return connector.Idempotency{}
}

func tenantCtx(tenant string) context.Context {
	return connector.WithTenant(context.Background(), tenant)
}

func target(t *testing.T, ref, tenant string) connector.Target {
	t.Helper()
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: ref, Kind: Kind, Tenant: tenant, Residency: "eu",
		BaseURL:           "https://" + tenant + ".invalid",
		CredentialVersion: "v1", Credential: connector.Secret("fake-token"),
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tgt
}

// TestActionsMatchImplementation is the connector definition-of-done item
// "Actions() matches what is implemented, exactly; no advertised-but-absent
// action".
//
// Enforced by CALLING every advertised action rather than by reading the list.
// A driver that advertises something it cannot do produces a capability catalog
// (§4.9) that lies to an agent, which then burns turns discovering it.
func TestActionsMatchImplementation(t *testing.T) {
	d := New()
	tgt := target(t, "kata:alpha", "alpha")
	ctx := tenantCtx("alpha")

	if len(d.Actions()) == 0 {
		t.Fatal("no actions advertised")
	}

	for _, spec := range d.Actions() {
		t.Run(spec.Name, func(t *testing.T) {
			if !strings.HasPrefix(spec.Name, Kind+".") {
				t.Errorf("action %q is not prefixed with the driver kind %q", spec.Name, Kind)
			}
			if spec.InputSchema == "" {
				t.Error("no input schema registered; the DoD requires one per action")
			}

			var err error
			if spec.Mutating {
				// FROM THE SPEC ITSELF, which is the point of this loop: it ranges
				// over every advertised action, so a new one is covered the moment
				// it is declared rather than when somebody remembers to extend the
				// test (§15q).
				_, err = d.Execute(ctx, tgt, spec.Name, map[string]any{},
					connector.Idempotency{
						Class:     spec.Idempotency,
						Placement: spec.IdempotencyPlacement,
						Key:       "ik-conformance",
					})
			} else {
				_, err = d.Query(ctx, tgt, spec.Name, map[string]any{})
			}
			if err != nil {
				t.Errorf("advertised action is not implemented: %v", err)
			}
		})
	}
}

func TestUnknownActionIsNotFound(t *testing.T) {
	_, err := New().Execute(tenantCtx("a"), target(t, "kata:a", "a"), "kata.nope", nil, idemFor("kata.nope"))
	if err == nil {
		t.Fatal("unknown action accepted")
	}
	if !errors.Is(err, fault.KindNotFound) {
		t.Errorf("kind = %v, want KindNotFound", fault.KindOf(err))
	}
}

// TestPlanesAreNotInterchangeable. §4.1.1 keeps reads and writes distinguishable
// in policy, audit, and metrics — a mutating action reached through Query would
// be a write that both recorded as a read.
func TestPlanesAreNotInterchangeable(t *testing.T) {
	d, tgt, ctx := New(), target(t, "kata:a", "a"), tenantCtx("a")

	if _, err := d.Query(ctx, tgt, "kata.create_issue", nil); err == nil {
		t.Error("a mutating action was accepted through Query")
	}
	if _, err := d.Execute(ctx, tgt, "kata.read", nil, idemFor("kata.read")); err == nil {
		t.Error("a non-mutating action was accepted through Execute")
	}
}

// TestExternalRefIsDeterministic. §5.4 needs the audit trail to join to the
// target system's own records, so the same call must yield the same reference —
// and a counter would be driver state, which D4 forbids.
func TestExternalRefIsDeterministic(t *testing.T) {
	d, tgt, ctx := New(), target(t, "kata:a", "a"), tenantCtx("a")
	args := map[string]any{"project": "PROJ", "title": "hello"}

	first, err := d.Execute(ctx, tgt, "kata.create_issue", args, idemFor("kata.create_issue"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	second, err := d.Execute(ctx, tgt, "kata.create_issue", args, idemFor("kata.create_issue"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if first.ExternalRef != second.ExternalRef {
		t.Errorf("same call produced %q then %q", first.ExternalRef, second.ExternalRef)
	}
	if first.ExternalRef == "" {
		t.Error("no external ref; the audit trail would not join to anything")
	}

	// Different arguments, different call, different reference.
	other, _ := d.Execute(ctx, tgt, "kata.create_issue", map[string]any{"project": "OTHER"}, idemFor("kata.create_issue"))
	if other.ExternalRef == first.ExternalRef {
		t.Error("different arguments produced the same external ref")
	}

	// Different TENANT must differ even with identical arguments, or two
	// tenants' audit rows would collide on the joining key.
	otherTenant, _ := d.Execute(tenantCtx("b"), target(t, "kata:b", "b"), "kata.create_issue", args, idemFor("kata.create_issue"))
	if otherTenant.ExternalRef == first.ExternalRef {
		t.Error("two tenants produced the same external ref for the same arguments")
	}
}

// TestExternalRefIgnoresArgumentOrder. Map iteration order is randomised
// (GO-PRIMER §15), so folding args into the hash must be order-independent or
// determinism holds only by luck — and would fail intermittently, which is the
// worst way to find out.
func TestExternalRefIgnoresArgumentOrder(t *testing.T) {
	d, tgt, ctx := New(), target(t, "kata:a", "a"), tenantCtx("a")

	args := map[string]any{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6}
	want, err := d.Execute(ctx, tgt, "kata.create_issue", args, idemFor("kata.create_issue"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Rebuilding the map many times exercises different iteration orders.
	for range 50 {
		rebuilt := map[string]any{}
		for k, v := range args {
			rebuilt[k] = v
		}
		got, err := d.Execute(ctx, tgt, "kata.create_issue", rebuilt, idemFor("kata.create_issue"))
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if got.ExternalRef != want.ExternalRef {
			t.Fatalf("external ref varied with map iteration order: %q vs %q",
				got.ExternalRef, want.ExternalRef)
		}
	}
}

// TestControlArgsDoNotChangeIdentity — _fail and _latency steer the kata, they
// are not part of what the call IS.
func TestControlArgsDoNotChangeIdentity(t *testing.T) {
	d, tgt, ctx := New(), target(t, "kata:a", "a"), tenantCtx("a")

	plain, _ := d.Execute(ctx, tgt, "kata.create_issue", map[string]any{"x": 1}, idemFor("kata.create_issue"))
	withLatency, _ := d.Execute(ctx, tgt, "kata.create_issue",
		map[string]any{"x": 1, LatencyKey: "1ms"}, idemFor("kata.create_issue"))

	if plain.ExternalRef != withLatency.ExternalRef {
		t.Error("a control argument changed the identity of the call")
	}
}

// TestFailureInjectionCoversTheTaxonomy. The enforcement path has to handle
// every failure a real driver can produce, and injecting them by NAME means the
// kata stays in step with fault.Kind rather than hard-coding a subset.
func TestFailureInjectionCoversTheTaxonomy(t *testing.T) {
	d, tgt, ctx := New(), target(t, "kata:a", "a"), tenantCtx("a")

	for _, kind := range []fault.Kind{
		fault.KindTargetUnavailable,
		fault.KindTargetError,
		fault.KindRateLimited,
		fault.KindConflict,
		fault.KindTimeout,
	} {
		t.Run(kind.String(), func(t *testing.T) {
			_, err := d.Execute(ctx, tgt, "kata.create_issue",
				map[string]any{FailKey: kind.String()}, idemFor("kata.create_issue"))
			if err == nil {
				t.Fatal("injected failure did not fail")
			}
			if !errors.Is(err, kind) {
				t.Errorf("kind = %v, want %v", fault.KindOf(err), kind)
			}
		})
	}
}

func TestUnknownFailKindIsRejected(t *testing.T) {
	_, err := New().Execute(tenantCtx("a"), target(t, "kata:a", "a"),
		"kata.create_issue", map[string]any{FailKey: "not_a_kind"}, idemFor("kata.create_issue"))

	if err == nil {
		t.Fatal("an unknown fault kind was accepted")
	}
	if !errors.Is(err, fault.KindInvalidArgument) {
		t.Errorf("kind = %v, want KindInvalidArgument", fault.KindOf(err))
	}
}

// TestHonoursCancellation is a definition-of-done item: "every method takes ctx
// and honours cancellation and deadlines".
func TestHonoursCancellation(t *testing.T) {
	d, tgt := New(), target(t, "kata:a", "a")

	ctx, cancel := context.WithCancel(tenantCtx("a"))
	cancel()

	if _, err := d.Execute(ctx, tgt, "kata.create_issue", nil, idemFor("kata.create_issue")); !errors.Is(err, fault.KindTimeout) {
		t.Errorf("Execute on a cancelled context: kind = %v, want KindTimeout", fault.KindOf(err))
	}
	if _, err := d.Query(ctx, tgt, "kata.read", nil); !errors.Is(err, fault.KindTimeout) {
		t.Errorf("Query on a cancelled context: kind = %v, want KindTimeout", fault.KindOf(err))
	}
}

// TestDeadlineBeatsSlowCall is the shape of a real driver meeting a slow
// upstream: the result is a TIMEOUT, not a target error. The distinction
// matters because one is retryable and the other needs investigation.
func TestDeadlineBeatsSlowCall(t *testing.T) {
	ctx, cancel := context.WithTimeout(tenantCtx("a"), 20*time.Millisecond)
	defer cancel()

	_, err := New().Execute(ctx, target(t, "kata:a", "a"), "kata.create_issue",
		map[string]any{LatencyKey: "5s"}, idemFor("kata.create_issue"))

	if !errors.Is(err, fault.KindTimeout) {
		t.Errorf("kind = %v, want KindTimeout", fault.KindOf(err))
	}
	if !fault.KindTimeout.Retryable() {
		t.Error("precondition: a timeout should be retryable")
	}
}

// TestSafeForConcurrentUseAcrossTenants is §6 item 5 in miniature: "the
// highest-value test in the project". Run under -race, which make test forces.
//
// A driver is one instance shared by every tenant (D4), so any per-instance
// state would surface here as a race or as one tenant's answer reaching another.
func TestSafeForConcurrentUseAcrossTenants(t *testing.T) {
	d := New()

	tenants := []string{"alpha", "beta", "gamma", "delta"}
	targets := make(map[string]connector.Target, len(tenants))
	for _, name := range tenants {
		targets[name] = target(t, "kata:"+name, name)
	}

	var wg sync.WaitGroup
	for range 50 {
		for _, name := range tenants {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Each goroutine's context carries ITS OWN tenant, which is
				// what makes a cross-tenant substitution detectable here.
				res, err := d.Execute(tenantCtx(name), targets[name], "kata.create_issue",
					map[string]any{"project": "PROJ"}, idemFor("kata.create_issue"))
				if err != nil {
					t.Errorf("%s: %v", name, err)
					return
				}
				// THE PROPERTY THAT MATTERS: the response belongs to the tenant
				// that asked. A shared mutable driver would fail here.
				if got := res.Data["tenant"]; got != name {
					t.Errorf("tenant %s received a response for %v", name, got)
				}
			}()
		}
	}
	wg.Wait()
}

// TestEgressAssertionIsWired is the difference between a mechanism that EXISTS
// and one that RUNS.
//
// Target.Assert had tests and no callers for a while: a method with full
// coverage and zero call sites, which reads as a guarantee and is not one. These
// cases call the driver the way the enforcement path will, and fail if the
// assertion is ever removed from it.
func TestEgressAssertionIsWired(t *testing.T) {
	d := New()
	alpha := target(t, "kata:alpha", "alpha")

	t.Run("no tenant on the request is refused", func(t *testing.T) {
		// context.Background(), NOT tenantCtx: nobody called WithTenant.
		_, err := d.Execute(context.Background(), alpha, "kata.create_issue", nil, idemFor("kata.create_issue"))
		if err == nil {
			t.Fatal("a call with no request tenant reached the driver")
		}
		if !errors.Is(err, fault.KindInternal) {
			t.Errorf("kind = %v, want KindInternal", fault.KindOf(err))
		}
	})

	t.Run("wrong tenant is refused", func(t *testing.T) {
		// THE POOLING BUG THIS EXISTS FOR: the request is for beta, but a
		// target belonging to alpha arrived — exactly what an under-keyed
		// client pool hands back.
		_, err := d.Execute(tenantCtx("beta"), alpha, "kata.create_issue", nil, idemFor("kata.create_issue"))
		if err == nil {
			t.Fatal("alpha's target was used to serve beta's request")
		}
		if !strings.Contains(err.Error(), "TENANT MISMATCH") {
			t.Errorf("the loudest possible failure was not loud: %v", err)
		}
	})

	t.Run("reads are guarded too", func(t *testing.T) {
		// A read leaks just as effectively as a write; §4.1.1 governs both.
		if _, err := d.Query(tenantCtx("beta"), alpha, "kata.read", nil); err == nil {
			t.Error("Query bypassed the egress assertion")
		}
	})

	t.Run("matching tenant proceeds", func(t *testing.T) {
		if _, err := d.Execute(tenantCtx("alpha"), alpha, "kata.create_issue", nil, idemFor("kata.create_issue")); err != nil {
			t.Errorf("a correct call was refused: %v", err)
		}
	})
}
