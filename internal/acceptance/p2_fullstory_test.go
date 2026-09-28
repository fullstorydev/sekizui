package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step2TheFullstoryDriverIsStatelessUnderConcurrentLoad proves D4, and can
// FALSIFY it (D189).
//
// **THE ONE STEP IN THIS PHASE THAT CAN DISPROVE A DECISION RATHER THAN CONFIRM
// ONE.** D4's claim is that a driver holds no credentials and no per-instance
// state, which is what makes ONE instance safe to share across tenants — and
// §12 P2's stated INVALIDATION SIGNAL is a Fullstory that needs per-instance
// state the `Driver` cannot hold. Cheap to check here at two functions;
// expensive to discover at P4, where the tenancy model is the whole phase.
//
// **THE DECLARED MECHANISM WAS AMENDED, and the reason is the same shape as step
// 30's** — recorded rather than substituted, because a declaration commits to a
// PROPERTY and D154's named failure is a step rewritten to pass. It said the
// driver's targets would be "entered into the mixed-tenant property test under
// distinct tenants in one residency, so P0 step 14's 48 concurrent commands
// exercise them". That cannot work:
//
//   - **Step 14's targets come from `acceptance.yaml`, which is loaded once
//     before any step runs.** A Fullstory target there needs a `base_url`, and
//     the only honest values are the real API — which would make the acceptance
//     run call Fullstory and need an account, breaking D156 — or a fixed local
//     port, which makes the whole suite depend on a listener and fail as a port
//     conflict.
//   - **A test server's address is not known until it starts**, and there is no
//     seam for injecting one into a `base_url` at config load.
//
// So the PROPERTY is proven the way P1 step 34 proves D140's default: this step
// builds its own document, gateway and pool, and drives them against a
// Fullstory that answers. What is preserved is everything the property needs —
// the REAL enforcement path (identity, policy, resolver, pool, driver), distinct
// tenants in one residency, every command in flight at once, and `-race`.
//
// **THE ASSERTION IS NOT "IT DID NOT CRASH".** Each command carries a value only
// its own tenant should produce, and the fake upstream records which
// Authorization header and which tenant arrived together. A target substituted
// under concurrency shows up as a MISMATCH, which is the only shape in which
// tenant bleed is detectable at all (§6 item 5).
func step2TheFullstoryDriverIsStatelessUnderConcurrentLoad(t *testing.T) {
	ctx := context.Background()

	// --- a Fullstory that answers, and remembers who called ----------------
	var mu sync.Mutex
	arrived := map[string]string{} // event name -> Authorization it came with

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		name, _ := payload["name"].(string)

		mu.Lock()
		arrived[name] = req.Header.Get("Authorization")
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"` + name + `"}`))
	}))
	defer srv.Close()

	// --- four tenants, one residency, one driver instance -------------------
	//
	// ONE PRINCIPAL SPANNING TENANTS is the realistic shape — a shared mesh
	// serving several customers — and it is also the only shape in which a leak
	// is possible. A principal confined to one tenant cannot bleed into another.
	tenants := []string{"alpha", "beta", "gamma", "delta"}

	doc := &config.Document{}
	grant := config.GrantSpec{Principal: "agent:bulk"}
	for _, tenant := range tenants {
		ref := "fs:" + tenant
		// A DISTINCT CREDENTIAL PER TENANT, so a borrowed credential reaching the
		// wrong request is VISIBLE rather than coincidentally identical. The
		// driver's own package test uses one secret and can only catch an EMPTY
		// header; this catches a swapped one.
		t.Setenv("SEKIZUI_FS_"+tenant, "fs-token-"+tenant)
		doc.Targets = append(doc.Targets, config.TargetSpec{
			Ref: ref, Kind: fullstory.Kind, Tenant: tenant, Residency: "eu",
			BaseURL: srv.URL, CredentialRef: "env://SEKIZUI_FS_" + tenant,
		})
		grant.Allow = append(grant.Allow,
			config.CapabilitySpec{Action: fullstory.ActionCreateEvent, TargetRef: ref})
	}
	doc.Grants = []config.GrantSpec{grant}

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer func() { _ = sink.Stop(ctx) }()

	// **THE CLOCK IS MUTEX-GUARDED, and the first draft's was not.** `Enforce`
	// calls `Now` on every command, so 48 concurrent commands read and write this
	// closure's captured variable at once — a data race in the TEST, which
	// `-race` reported against `gateway.Server.Enforce` and which reads at first
	// glance like a product defect. The main acceptance harness already does it
	// this way for exactly this reason (P0 step 14 is 48 concurrent commands);
	// copying the shape without the mutex is how the lesson gets relearned.
	var (
		clockMu sync.Mutex
		clock   = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	)
	tick := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(time.Millisecond)
		return clock
	}

	// THROUGH THE POOL, because that is what puts break-glass on the path
	// (CONTRACTS 35, D128) and because the pool is where a tenant substitution
	// can actually happen — the constructor cannot see it, since it occurs after
	// construction.
	// **THROUGH THE REGISTRY, EXERCISING THE MARKER PATH (D190).** The Fullstory
	// driver is §4.7.4 class 1 — its client is credential-FREE, so there is no
	// per-target object to cache — and it therefore does NOT implement
	// `connector.ClientBuilder`. The registry gives it a marker pool entry
	// anyway, which is the half that matters: the pool is on the path for
	// BREAK-GLASS rather than for performance, and a driver the pool skipped
	// would be invisible to `revoke_credential`, which would evict nothing and
	// truthfully report cancelling nothing (CONTRACTS 35, D128).
	//
	// Wired the way the binary wires it, so this step exercises production's
	// path rather than a fixture's (D107).
	registry := connector.NewRegistry()
	clientPool := pool.New(registry.Build,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	driver := fullstory.New(
		fullstory.WithHTTPClient(srv.Client()), fixtureHost(srv.URL),
		fullstory.WithPool(clientPool))
	if err := registry.Register(driver); err != nil {
		t.Fatalf("registering the Fullstory driver: %v", err)
	}

	srvGW := gateway.New(gateway.Config{
		Doc:      doc,
		Pool:     clientPool,
		Policy:   policy.NewGrantEngine(doc, nil),
		Resolver: resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}),
		Drivers:  registry.Drivers(),
		Guards:   anzen.New(nil),
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc), auditwal.WithClock(tick)),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      tick,
	})

	// --- every command in flight at once -----------------------------------
	const perTenant = 12
	var wg sync.WaitGroup
	for _, tenant := range tenants {
		for i := range perTenant {
			wg.Add(1)
			go func(tenant string, n int) {
				defer wg.Done()
				event := fmt.Sprintf("%s-%02d", tenant, n)

				res, err := srvGW.Enforce(ctx, assertedIdentity("agent:bulk"), &sekizuiv1.Command{
					Action: fullstory.ActionCreateEvent, TargetRef: "fs:" + tenant,
					Args: mustArgs(t, map[string]any{"name": event}),
				})
				if err != nil {
					t.Errorf("%s: %v", event, err)
					return
				}
				if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
					t.Errorf("%s: status %v, reason %q", event, res.GetStatus(), res.GetReason())
				}
			}(tenant, i)
		}
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	// --- 2a: NOTHING WAS LOST OR COLLIDED ----------------------------------
	if want := len(tenants) * perTenant; len(arrived) != want {
		t.Errorf("the upstream saw %d distinct events, want %d. Calls were lost, "+
			"collided, or the driver serialised them into each other", len(arrived), want)
	}

	// --- 2b: EVERY CALL CARRIED ITS OWN TENANT'S CREDENTIAL ----------------
	//
	// **THE ARM WITH TEETH, and the reason each tenant has a distinct secret.**
	// Under per-instance state the failure is not a crash: it is tenant B's
	// credential on tenant A's request, which succeeds, is audited as
	// successful, and writes A's event into B's org. That is the exact
	// catastrophe D4 exists to make impossible, and a driver holding one
	// `Authorization` field would produce it under precisely this load.
	for event, auth := range arrived {
		tenant, _, _ := splitEvent(event)
		if want := "Basic fs-token-" + tenant; auth != want {
			t.Errorf("event %q arrived with Authorization %q, want %q. A credential "+
				"crossing tenants under concurrency means the driver is HOLDING one — "+
				"which is D4 falsified and §12 P2's invalidation signal fired",
				event, auth, want)
		}
	}

	// --- 2c: A CREDENTIAL-FREE DRIVER IS STILL POOLED (D190) ---------------
	//
	// **THE OPTIONAL INTERFACE'S LOAD-BEARING HALF.** The Fullstory driver does
	// NOT implement `connector.ClientBuilder`, because §4.7.4 class 1 means its
	// client is credential-free and there is nothing per-target to build. The
	// registry gives it a marker entry anyway — and that entry is the whole
	// reason break-glass works: the pool is what lets `revoke_credential` cancel
	// a call already in flight (CONTRACTS 35, D128), so a driver the pool skipped
	// would be invisible to revocation, which would evict an empty pool and
	// truthfully report cancelling nothing.
	//
	// Asserted on the pool's own count rather than on the registry's return
	// value: what matters is that entries EXIST after real traffic, not that a
	// function returned non-nil (D159).
	if _, isBuilder := any(driver).(connector.ClientBuilder); isBuilder {
		t.Error("the Fullstory driver now implements ClientBuilder, so this arm no " +
			"longer exercises the OPTIONAL path — which is the case D190's marker entry " +
			"exists for. Point it at a driver that does not, or the guarantee goes " +
			"unproven")
	}
	if got := clientPool.Len(); got == 0 {
		t.Errorf("the pool holds %d entries after %d commands. A credential-free driver "+
			"must still be POOLED, or `revoke_credential` evicts nothing and reports "+
			"cancelling nothing while every log line says it worked",
			got, len(tenants)*perTenant)
	}

	r := &run{path: path}
	r.detail(t, "D4/D189: one Fullstory driver instance served %d concurrent commands "+
		"across %d tenants, each with its own credential, through policy, the resolver "+
		"and the pool — no credential crossed a tenant boundary",
		len(tenants)*perTenant, len(tenants))
}

// splitEvent pulls the tenant back out of an event name.
func splitEvent(event string) (tenant, n string, ok bool) {
	for i := len(event) - 1; i >= 0; i-- {
		if event[i] == '-' {
			return event[:i], event[i+1:], true
		}
	}
	return event, "", false
}
