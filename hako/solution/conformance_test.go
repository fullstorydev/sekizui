package notes_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fullstorydev/sekizui/hako/solution"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
)

// The kata's solution runs the FULL published contract, and that is what keeps
// the teaching artefact honest (D218).
//
// **AN EXERCISE CANNOT BE GUARDED BY A RUNNER THAT REQUIRES GREEN** — it is
// meant to fail. So the pair is: an exercise that fails on purpose, and this,
// which passes in CI. If the suite gains an arm, this breaks, and the blueprint
// the kata teaches gets updated in the same turn rather than a release later.
//
// **EVERY LINE HERE USES `pkg/` ONLY**, including `connector.NewTarget`. That is
// the point of the file: `internal/` is unreachable from outside this module, so
// this is the whole surface a third-party driver author (D35) actually has —
// and if the contract could not be satisfied from it, the suite would be
// unrunnable by the population it exists for.

//nolint:gochecknoglobals // immutable fixture data
var tenants = []string{"alpha", "beta", "gamma", "delta"}

// target builds a resolved Target the way the resolver would, from pkg/ alone.
func target(t *testing.T, tenant, baseURL, secret string) connector.Target {
	t.Helper()

	tg, err := connector.NewTarget(connector.TargetParams{
		Ref: "notes:" + tenant, Kind: notes.Kind, Tenant: tenant, Residency: "eu",
		BaseURL: baseURL, CredentialVersion: "v1",
		Credential: connector.Secret(secret),
	})
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}
	return tg
}

func TestDriverConformance(t *testing.T) {
	drv := notes.New(notes.WithHTTPClient(conformance.InsecureClient()))

	conformance.Run(t, drv, conformance.Case{
		UnknownAction: "notes.delete_workspace",
		Refuse: func(ctx context.Context) error {
			_, err := drv.Execute(ctx, target(t, "alpha", "https://notes.invalid", "tok"),
				"notes.delete_workspace", nil,
				connector.Idempotency{Class: connector.IdempotencyNone})
			return err
		},

		// BLUEPRINT STEP 11: a distinct credential per tenant, so a crossing is
		// VISIBLE rather than coincidentally identical. One shared secret could
		// only ever catch an empty header.
		Tenants: tenants,
		Concurrent: func(ctx context.Context, tenant string) (string, error) {
			var (
				mu   sync.Mutex
				seen string
			)
			srv := httptest.NewTLSServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					seen = r.Header.Get("Authorization")
					mu.Unlock()
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"id":"n-1"}`))
				}))
			defer srv.Close()

			if _, err := drv.Execute(connector.WithTenant(ctx, tenant),
				target(t, tenant, srv.URL, "tok-"+tenant),
				notes.ActionCreateNote, map[string]any{"body": "hello"},
				connector.Idempotency{
					Class: connector.IdempotencyHeader, Placement: "Idempotency-Key",
					Key: "k-" + tenant,
				}); err != nil {
				return "", err
			}

			mu.Lock()
			defer mu.Unlock()
			return strings.TrimPrefix(strings.TrimPrefix(seen, "Bearer "), "tok-"), nil
		},

		// The target always belongs to Tenants[0]; the suite decides what goes on
		// the context, and calls twice.
		Command: func(ctx context.Context, baseURL, ctxTenant string) error {
			own := tenants[0]
			_, err := drv.Execute(connector.WithTenant(ctx, ctxTenant),
				target(t, own, baseURL, "tok-"+own),
				notes.ActionCreateNote, map[string]any{"body": "hello"},
				connector.Idempotency{
					Class: connector.IdempotencyHeader, Placement: "Idempotency-Key",
					Key: "k-1",
				})
			return err
		},
	})
}

func TestHTTPConformance(t *testing.T) {
	drv := notes.New(notes.WithHTTPClient(conformance.InsecureClient()))

	conformance.RunHTTP(t, conformance.HTTPCase{
		Tenant:          tenants[0],
		SecretOnTheWire: "tok-alpha",
	}, func(ctx context.Context, baseURL, tenant string) error {
		_, err := drv.Execute(connector.WithTenant(ctx, tenant),
			target(t, tenants[0], baseURL, "tok-alpha"),
			notes.ActionCreateNote, map[string]any{"body": "hello"},
			connector.Idempotency{
				Class: connector.IdempotencyHeader, Placement: "Idempotency-Key",
				Key: "k-1",
			})
		return err
	})
}

// TestSourceConformance runs the SOURCE half of the published contract.
//
// **SELECTED SEPARATELY, because most connectors are not sources** — the same
// reason `RunHTTP` is chosen by drivers that speak HTTP. A write-only connector
// simply does not have this test, and the suite has no opinion about that.
//
// The fixture is a REAL HTTPS server returning a real page of notes, so what is
// exercised is the driver's own parsing, truncation and cursor arithmetic
// rather than a stub agreeing with it (D222).
func TestSourceConformance(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/notes") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// A PAGE THAT RESPECTS `since`, because the arm that matters polls
		// twice and requires the second window to be new. A fixture returning
		// the same page for every cursor would fail the suite it exists to
		// satisfy — which is the right outcome, and worth knowing before
		// somebody "fixes" the fixture instead of the driver.
		since := r.URL.Query().Get("since")
		body := `{"notes":[
		  {"id":"1","updated_at":"2026-01-01T00:00:01Z","text":"first"},
		  {"id":"2","updated_at":"2026-01-01T00:00:02Z","text":"second"},
		  {"id":"3","updated_at":"2026-01-01T00:00:03Z","text":"third"}
		]}`
		if since >= "2026-01-01T00:00:02Z" {
			body = `{"notes":[{"id":"4","updated_at":"2026-01-01T00:00:04Z","text":"fourth"}]}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	// THE SPY IS WIRED AT CONSTRUCTION (D255): the borrow arm can only see a
	// pool the driver was actually built with.
	spy := conformance.NewPoolSpy()
	drv := notes.New(notes.WithHTTPClient(conformance.InsecureClient()),
		notes.WithPool(spy))

	tg, err := connector.NewTarget(connector.TargetParams{
		Ref: "notes:alpha", Kind: notes.Kind, Tenant: "alpha", Residency: "eu",
		BaseURL: srv.URL, CredentialVersion: "v1", Credential: connector.Secret("tok"),
		// DECLARED, because without it this target's honest answer is
		// RecoveryUnable — and the suite would then hold it to the other
		// obligation instead. Neither branch is a free pass.
		Settings: map[string]string{notes.SettingAppendOnly: "true"},
	})
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}

	conformance.RunSource(t, drv, conformance.SourceCase{
		Target: tg, Limit: 2, Tenant: "alpha", Pool: spy,
	})
}

// TestDriftConformance — BLUEPRINT STEP "REPORT DRIFT" (D311). A connector that
// reports drift runs RunDrift: a vendor offering exactly what was vetted
// reports nothing, one that dropped `read_note` and shipped `delete_all` is
// graded in the published vocabulary, a comparison only reads, and it asserts
// the tenant before the GET.
func TestDriftConformance(t *testing.T) {
	serve := func(ops string) string {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/capabilities" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"operations":` + ops + `}`))
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	clean := target(t, "alpha", serve(`["create_note","read_note","poll"]`), "tok-alpha")
	drifted := target(t, "alpha", serve(`["create_note","poll","delete_all"]`), "tok-alpha")

	conformance.RunDrift(t, notes.New(notes.WithHTTPClient(conformance.InsecureClient())),
		conformance.DriftCase{Clean: clean, Diverged: drifted, OtherTenant: "beta"})
}
