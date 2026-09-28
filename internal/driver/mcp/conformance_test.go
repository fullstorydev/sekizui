package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
)

// **THIS PACKAGE HAD NO TESTS OF ITS OWN AT ALL until now — 1,354 lines, and
// what drove it was four acceptance steps whose subject is drift.** The
// transport was the part nobody had touched: `httpFault`, `protocolFault`,
// `transportFault` and the Base64 sentinel in `headerValue` are roughly 200
// lines of status-to-taxonomy mapping, and a mapping is exactly the shape D156
// says to prove by enumeration rather than by measuring a vendor.
//
// **AND IT IS THE PUBLISHED SUITE RATHER THAN ASSERTIONS WRITTEN HERE**, for
// D160's reason in its own words: `file` and `ambient` both ignored a cancelled
// context and *"neither provider's own tests caught it: they were written by
// whoever wrote the provider and asserted what that person believed"*.

const specTool = `{"type":"object","properties":{"query":{"type":"string"}}}`

// searchResult is the data schema a read tool's vetted spec carries (D279).
const searchResult = `{"type":"object","properties":{"title":{"type":"string"}}}`

func conformanceDoc(baseURL string) *config.Document {
	return &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "conf-mcp", Kind: mcp.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: baseURL, CredentialRef: "env://SEKIZUI_CONF_TOK",
		}},
		MCPSpecs: map[string]config.MCPSpec{
			"conf-mcp": {
				Server: "conf", Host: hostOf(baseURL),
				Tools: []config.MCPToolSpec{{
					Name:        "search",
					Description: "Search the conformance fixture.",
					InputSchema: json.RawMessage(specTool),
					OutputType:  "conf.search_result.v1",
					DataSchema:  json.RawMessage(searchResult),
				}},
			},
		},
	}
}

// concurrentTenants are the tenants the statelessness arm drives.
//
//nolint:gochecknoglobals // immutable fixture data
var concurrentTenants = []string{"alpha", "beta", "gamma", "delta"}

// concurrentSpecs is ONE vetted-spec map covering every tenant's target, so one
// driver instance serves them all — which is the property under test. A driver
// per call could not cross into anything.
func concurrentSpecs() map[string]config.MCPSpec {
	specs := map[string]config.MCPSpec{}
	for _, tenant := range concurrentTenants {
		specs["conf-"+tenant] = config.MCPSpec{
			Server: tenant, Host: "127.0.0.1",
			Tools: []config.MCPToolSpec{{
				Name:        "search",
				Description: "Search the conformance fixture.",
				InputSchema: json.RawMessage(specTool),
				// ONE TYPE ACROSS TENANTS, as one server's tool would have.
				OutputType: "conf.search_result.v1",
				DataSchema: json.RawMessage(searchResult),
			}},
		}
	}
	return specs
}

// concurrentCall returns the far side's view of one call for one tenant.
//
// **THE FIXTURE ANSWERS RUBBISH ON PURPOSE, and the suite's contract permits
// it.** `Drift` is this driver's one unconditional round trip, and making the
// fixture speak enough MCP to satisfy it would mean reproducing the protocol
// server that `p2_mcp_drift_test.go` already carries — a hundred lines of
// initialize, protocol-version headers and session preflight, none of which
// this arm is about. What the arm needs is that the REQUEST went out carrying
// this tenant's credential, so the server records the header and replies with
// something unparseable; the resulting error is swallowed here rather than
// returned, because `Concurrent` reports the observation and reserves its error
// for a call that could not be made at all.
//
// If the driver failed BEFORE sending, `seen` stays empty and the observation
// mismatches — so swallowing the protocol error costs no coverage.
func concurrentCall(t *testing.T, drv *mcp.Driver) func(context.Context, string) (string, error) {
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
			_, _ = w.Write([]byte(`not an rpc envelope`))
		}))
		defer srv.Close()

		ref := "conf-" + tenant
		doc := &config.Document{
			Targets: []config.TargetSpec{{
				Ref: ref, Kind: mcp.Kind, Tenant: tenant, Residency: "eu",
				BaseURL: srv.URL, CredentialRef: "env://SEKIZUI_CONF_" + tenant,
			}},
			MCPSpecs: concurrentSpecs(),
		}

		target, err := resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}).
			Resolve(ctx, ref)
		if err != nil {
			return "", err
		}

		// The protocol error is expected and discarded; the observation is not.
		_, _ = drv.Drift(connector.WithTenant(ctx, tenant), target)

		mu.Lock()
		defer mu.Unlock()
		return strings.TrimPrefix(strings.TrimPrefix(seen, "Bearer "), "tok-"), nil
	}
}

// commandCall drives a real Execute against a target owned by Tenants[0].
func commandCall(drv *mcp.Driver) func(context.Context, string, string) error {
	return func(ctx context.Context, baseURL, ctxTenant string) error {
		own := concurrentTenants[0]
		ref := "conf-" + own
		doc := &config.Document{
			Targets: []config.TargetSpec{{
				Ref: ref, Kind: mcp.Kind, Tenant: own, Residency: "eu",
				BaseURL: baseURL, CredentialRef: "env://SEKIZUI_CONF_" + own,
			}},
			MCPSpecs: concurrentSpecs(),
		}
		target, err := resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}).
			Resolve(ctx, ref)
		if err != nil {
			return err
		}
		_, err = drv.Execute(connector.WithTenant(ctx, ctxTenant), target,
			"mcp."+own+".search", map[string]any{"query": "q"},
			connector.Idempotency{Class: connector.IdempotencyNone})
		return err
	}
}

func TestDriverConformance(t *testing.T) {
	t.Setenv("SEKIZUI_CONF_TOK", "conformance-token")
	// Set before any goroutine starts: `t.Setenv` mutates process-wide state.
	for _, tenant := range concurrentTenants {
		t.Setenv("SEKIZUI_CONF_"+tenant, "tok-"+tenant)
	}

	doc := conformanceDoc("https://conf.invalid")

	// ONE driver, holding every tenant's vetted spec and a client that trusts
	// the suite's self-signed servers.
	specs := doc.MCPSpecs
	for ref, spec := range concurrentSpecs() {
		specs[ref] = spec
	}
	drv := mcp.New(specs, mcp.WithHTTPClient(conformance.InsecureClient()))

	conformance.Run(t, drv, conformance.Case{
		Tenants:    concurrentTenants,
		Concurrent: concurrentCall(t, drv),

		// **`Execute`, NOT the `Drift` this package's HTTP invoker uses — and
		// that distinction is what moved this arm out of `RunHTTP` (D218).**
		// `Drift` is deliberately not tenant-scoped: it runs off the command
		// path for a watcher acting for nobody, so it has no request tenant to
		// assert against. Asserting §6 mechanism 3 through it would have
		// demanded a check that must not exist.
		Command: commandCall(drv),

		// A tool no vetted spec declares. The unvetted case matters more here
		// than for any other driver: D46 makes the action set come from
		// configuration, so "an action this driver does not implement" is a
		// question about a document rather than about compiled code.
		UnknownAction: "mcp.conf.exfiltrate",

		// **AGAINST A RESOLVED TARGET, so the refusal is the UNVETTED one.**
		// With a zero target this driver has no spec to consult and refuses for
		// that instead — a real refusal, and not the one under test. The
		// transport is never reached: `toolFor` runs before any request is
		// built, which is step 8's third layer.
		Refuse: func(ctx context.Context) error {
			res := resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{})
			target, err := res.Resolve(ctx, "conf-mcp")
			if err != nil {
				return err
			}
			_, err = drv.Execute(ctx, target, "mcp.conf.exfiltrate", nil,
				connector.Idempotency{})
			return err
		},
	})
}

// TestHTTPConformance selects the transport contract (D167).
//
// **RESOLUTION HAPPENS WITH CANCELLATION DETACHED, and that is not a detail.**
// `resolver.Resolve` honours cancellation, so resolving with the caller's
// context would make the suite's cancellation arm pass on the RESOLVER's
// behaviour and say nothing about the driver's — a vacuous arm that looks
// identical to a passing one. The target is fixture setup; only the driver call
// is under test.
func TestHTTPConformance(t *testing.T) {
	t.Setenv("SEKIZUI_CONF_TOK", "conformance-token")

	conformance.RunHTTP(t, conformance.HTTPCase{
		Tenant: "acme",
		// `Authorization: Bearer <material>` — the configured value, verbatim.
		SecretOnTheWire: "conformance-token",
	}, func(ctx context.Context, baseURL, tenant string) error {
		doc := conformanceDoc(baseURL)

		res := resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{})
		// Cancellation DETACHED rather than a fresh context (§15ab): the values
		// carry over and only the cancellation is dropped, which is what makes
		// the suite's cancellation arm a statement about the driver.
		target, err := res.Resolve(context.WithoutCancel(ctx), "conf-mcp")
		if err != nil {
			return err
		}

		drv := mcp.New(doc.MCPSpecs, mcp.WithHTTPClient(conformance.InsecureClient()))

		// **THE SUITE'S TENANT, NOT THE TARGET'S (D218)** — derived from the
		// target it always matched, which is why §6 mechanism 3 could not be
		// checked here at all.
		ctx = connector.WithTenant(ctx, tenant)

		// `Drift` is the driver's ONE unconditional transport round trip:
		// `Actions()` comes from the vetted spec and never touches the network
		// (D45, D46), and `Execute`/`Query` would need an action, arguments and
		// an idempotency class before reaching the wire — so a status mapping
		// asserted through them would be asserted through three other gates.
		_, err = drv.Drift(ctx, target)
		return err
	})
}

// compile-time proof the fixture builds a real driver rather than a stub.
var _ connector.Driver = (*mcp.Driver)(nil)

// hostOf is a URL's hostname, for a vetted spec's `host` (D289).
func hostOf(raw string) string {
	u, _ := url.Parse(raw)
	return u.Hostname()
}

// TestDriftConformance — the MCP driver is a Drifter, and the Fullstory MCP
// connector is built on it, so it runs the suite every Drifter must (D311):
// against two fixture servers, one serving exactly the vetted tool and one that
// dropped it and shipped an unvetted one.
func TestDriftConformance(t *testing.T) {
	t.Setenv("SEKIZUI_CONF_TOK", "conformance-token")
	serve := func(tools string) *httptest.Server {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ID any `json:"id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"tools":%s}}`, jsonOf(req.ID), tools)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	clean := serve(`[{"name":"search","inputSchema":` + specTool + `}]`)
	drifted := serve(`[{"name":"delete_all","inputSchema":{"type":"object"}}]`)

	spec := func(url string) config.MCPSpec {
		return config.MCPSpec{Server: "conf", Host: hostOf(url), Tools: []config.MCPToolSpec{{
			Name: "search", Description: "Search the conformance fixture.",
			InputSchema: json.RawMessage(specTool), OutputType: "conf.search_result.v1",
			DataSchema: json.RawMessage(searchResult),
		}}}
	}
	doc := &config.Document{
		Targets: []config.TargetSpec{
			{Ref: "conf-clean", Kind: mcp.Kind, Tenant: "acme", Residency: "eu",
				BaseURL: clean.URL, CredentialRef: "env://SEKIZUI_CONF_TOK"},
			{Ref: "conf-drifted", Kind: mcp.Kind, Tenant: "acme", Residency: "eu",
				BaseURL: drifted.URL, CredentialRef: "env://SEKIZUI_CONF_TOK"},
		},
		MCPSpecs: map[string]config.MCPSpec{"conf-clean": spec(clean.URL), "conf-drifted": spec(drifted.URL)},
	}
	res := resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{})
	resolve := func(ref string) connector.Target {
		tgt, err := res.Resolve(context.Background(), ref)
		if err != nil {
			t.Fatalf("resolving %s: %v", ref, err)
		}
		return tgt
	}
	drv := mcp.New(doc.MCPSpecs, mcp.WithHTTPClient(conformance.InsecureClient()))
	conformance.RunDrift(t, drv, conformance.DriftCase{
		Clean: resolve("conf-clean"), Diverged: resolve("conf-drifted"), OtherTenant: "globex",
	})
}

func jsonOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil || v == nil {
		return "null"
	}
	return string(b)
}
