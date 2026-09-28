package fullstory_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
)

// The published Driver contract, and the HTTP one selected explicitly (D167).
//
// **THIS DRIVER'S OWN TESTS ALREADY COVER ITS STATUS MAPPING, and that is not a
// reason to skip the suite — it is the reason to run it.** D160's finding was
// that a provider's own tests assert what their author believed; two authors
// believing different things about a 401 is exactly what a shared contract is
// for, and here the 401 is load-bearing (it is the only producer of
// `unauthenticated` that a fresh mint may fix — D203).

func conformanceDoc(baseURL string) *config.Document {
	return &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "fs:conf", Kind: fullstory.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: baseURL, CredentialRef: "env://SEKIZUI_FS_CONF_TOK",
		}},
	}
}

func resolveConf(ctx context.Context, doc *config.Document) (connector.Target, error) {
	return resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}).
		Resolve(ctx, "fs:conf")
}

// concurrentTenants are the tenants the statelessness arm drives, declared once
// so the credentials and the Case cannot name different sets.
//
//nolint:gochecknoglobals // immutable fixture data
var concurrentTenants = []string{"alpha", "beta", "gamma", "delta"}

func TestDriverConformance(t *testing.T) {
	t.Setenv("SEKIZUI_FS_CONF_TOK", "conformance-token")

	// **EVERY TENANT'S CREDENTIAL SET BEFORE ANY GOROUTINE STARTS.** `t.Setenv`
	// mutates process-wide state and the first version called it from inside the
	// concurrent closure, which races with itself and with anything else reading
	// the environment.
	for _, tenant := range concurrentTenants {
		t.Setenv("SEKIZUI_FS_CONF_"+tenant, "tok-"+tenant)
	}

	doc := conformanceDoc("https://api.invalid")

	// ONE driver, given a client that trusts the suite's self-signed servers, so
	// the statelessness arm exercises a shared instance rather than a fresh one.
	// The suite's servers are loopback, on ports chosen after this driver is
	// built — so loopback is admitted by NAME (P3 step 24).
	drv := fullstory.New(fullstory.WithHTTPClient(conformance.InsecureClient()),
		fullstory.WithHosts("127.0.0.1"))

	conformance.Run(t, drv, conformance.Case{
		UnknownAction: "fullstory.delete_everything",

		// FOUR TENANTS, EACH WITH ITS OWN CREDENTIAL. A shared one could only
		// catch an EMPTY header; distinct ones catch a SWAPPED one, which is the
		// failure that actually happens (P2 step 2's reasoning, and the reason
		// the blueprint's step 10 says the same).
		Tenants:    concurrentTenants,
		Concurrent: concurrentCall(t, drv),
		Command:    commandCall(drv),
		Refuse: func(ctx context.Context) error {
			target, err := resolveConf(ctx, doc)
			if err != nil {
				return err
			}
			_, err = drv.Execute(ctx, target, "fullstory.delete_everything", nil,
				connector.Idempotency{})
			return err
		},
	})
}

// concurrentCall returns the far side's view of one call for one tenant.
//
// **A RECORDING SERVER PER CALL, which removes the correlation problem
// entirely.** One shared server would need every request to carry a marker the
// closure could look itself up by, and the obvious markers are the very things
// under test. A server per call has exactly one request to report, so what it
// saw IS this call's answer. Distinct base URLs across tenants are also the
// realistic shape — targets in different orgs rarely share a host.
//
// **THE DRIVER IS THE SHARED ONE, and the first version of this fixture built a
// FRESH driver per call — which proves nothing at all.** Per-instance state
// cannot cross between instances that do not exist yet, so that version would
// have passed against a driver holding an `Authorization` field, which is the
// exact bug the arm is for. Only the base URL varies per call, and it comes
// from the TARGET, so one driver serves every tenant the way production does.
//
// **`seen` IS MUTEX-GUARDED AND THE FIRST VERSION'S WAS NOT.** The handler runs
// on the server's goroutine and the closure reads on the caller's, so `-race`
// reported it immediately — against the suite, where it reads like a product
// defect. P2 step 2's clock carries the same warning for the same reason.
func concurrentCall(t *testing.T, drv *fullstory.Driver) func(context.Context, string) (string, error) {
	t.Helper()

	return func(ctx context.Context, tenant string) (string, error) {
		var (
			mu   sync.Mutex
			seen string
		)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = r.Header.Get("Authorization")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"evt"}`))
		}))
		defer srv.Close()

		doc := &config.Document{Targets: []config.TargetSpec{{
			Ref: "fs:" + tenant, Kind: fullstory.Kind, Tenant: tenant, Residency: "eu",
			BaseURL: srv.URL, CredentialRef: "env://SEKIZUI_FS_CONF_" + tenant,
		}}}

		target, err := resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}).
			Resolve(ctx, "fs:"+tenant)
		if err != nil {
			return "", err
		}

		if _, err := drv.Execute(connector.WithTenant(ctx, tenant), target,
			fullstory.ActionCreateEvent, map[string]any{"user_id": "u-1", "name": "c"},
			connector.Idempotency{Class: connector.IdempotencyNone}); err != nil {
			return "", err
		}

		mu.Lock()
		defer mu.Unlock()
		// The credential maps back to the tenant that owns it. A crossing shows
		// up as another tenant's name here.
		return strings.TrimPrefix(strings.TrimPrefix(seen, "Basic "), "tok-"), nil
	}
}

// commandCall drives a real Execute against a target owned by Tenants[0], with
// whatever tenant the suite puts on the context (D218).
func commandCall(drv *fullstory.Driver) func(context.Context, string, string) error {
	return func(ctx context.Context, baseURL, ctxTenant string) error {
		own := concurrentTenants[0]
		doc := &config.Document{Targets: []config.TargetSpec{{
			Ref: "fs:" + own, Kind: fullstory.Kind, Tenant: own, Residency: "eu",
			BaseURL: baseURL, CredentialRef: "env://SEKIZUI_FS_CONF_" + own,
		}}}
		target, err := resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}).
			Resolve(ctx, "fs:"+own)
		if err != nil {
			return err
		}
		_, err = drv.Execute(connector.WithTenant(ctx, ctxTenant), target,
			fullstory.ActionCreateEvent, map[string]any{"user_id": "u-1", "name": "c"},
			connector.Idempotency{Class: connector.IdempotencyNone})
		return err
	}
}

func TestHTTPConformance(t *testing.T) {
	t.Setenv("SEKIZUI_FS_CONF_TOK", "conformance-token")

	conformance.RunHTTP(t, conformance.HTTPCase{
		Tenant: "acme",
		// `Authorization: Basic <token>`, unencoded — Fullstory's server API
		// takes the key as the whole credential, so the configured value is
		// exactly what a packet capture shows.
		SecretOnTheWire: "conformance-token",
	}, func(ctx context.Context, baseURL, tenant string) error {
		doc := conformanceDoc(baseURL)

		// **RESOLVED WITH CANCELLATION DETACHED, NOT WITH A FRESH CONTEXT.** The
		// resolver honours cancellation, so resolving with the caller's context
		// would make the suite's cancellation arm pass on the RESOLVER's
		// behaviour and say nothing about the driver's — a vacuous arm that looks
		// exactly like a passing one. `context.WithoutCancel` is the idiom for
		// this (§15ab): it keeps the context's values and drops only the
		// cancellation, where `context.Background()` would discard both and is
		// what `contextcheck` rightly objects to.
		target, err := resolveConf(context.WithoutCancel(ctx), doc)
		if err != nil {
			return err
		}

		// The suite's servers are loopback, on ports chosen after this driver is
		// built — so loopback is admitted by NAME (P3 step 24).
		drv := fullstory.New(fullstory.WithHTTPClient(conformance.InsecureClient()),
			fullstory.WithHosts("127.0.0.1"))

		// **THE TENANT THE SUITE GIVES US, NOT THE TARGET'S (D218).** This line
		// used to read `target.Tenant()`, and that is why the suite could not
		// check §6 mechanism 3 at all: derived from the target, the request
		// tenant always matched and the assertion could never be seen to fire.
		// Threading the parameter is the whole change, and it lets one invoker
		// serve both the matching call and the mismatched one.
		ctx = connector.WithTenant(ctx, tenant)

		// **THE DECLARED CLASS, NOT A ZERO VALUE — and the first version of this
		// fixture used the zero and every HTTP arm passed judgement on the wrong
		// error.** `Idempotency{}` has an empty class, which this driver refuses
		// as a configuration fault BEFORE building a request (D163, D186), so
		// all six arms were classifying that refusal rather than any status the
		// server returned. `create_event` is class `none` because the upstream
		// cannot deduplicate at all.
		_, err = drv.Execute(ctx, target, fullstory.ActionCreateEvent, map[string]any{
			"user_id": "u-1",
			"name":    "conformance",
		}, connector.Idempotency{Class: connector.IdempotencyNone})
		return err
	})
}

// TestRefinerConformance runs the published suite over the rules this connector
// ships (D317): they parse in the closed vocabulary and refine and write only
// Fullstory's own types.
func TestRefinerConformance(t *testing.T) {
	conformance.RunRefiner(t, fullstory.New())
}

// TestPresetterConformance runs the published suite over the presets this
// connector suggests (D327): a fragment a deployment can drop in, only
// Fullstory's actions, and every `mirrors:` claim held to the snapshot's levels.
func TestPresetterConformance(t *testing.T) {
	conformance.RunPresetter(t, fullstory.New())
}
