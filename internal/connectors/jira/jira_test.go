package jira_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/jira"
	"github.com/fullstorydev/sekizui/internal/retry"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// TestDriverConformance is the published suite, wired from the first commit
// rather than at the end (blueprint step 2).
//
// **THE SUITE ASSERTS WHAT THE SYSTEM REQUIRES; THIS PACKAGE'S OWN TESTS ASSERT
// WHAT I BELIEVE.** D160 built the same instrument for `config.Provider` and it
// found two of four providers violating the contract on its first run, one of
// them written after reading a comment predicting that exact violation.
func TestDriverConformance(t *testing.T) {
	drv := jira.New(jira.WithHTTPClient(conformance.InsecureClient()))

	conformance.Run(t, drv, conformance.Case{
		UnknownAction: "jira.delete_issue",
		Refuse: func(ctx context.Context) error {
			tg, err := target(t, "acme", "https://jira.invalid", "dG9rOmFjbWU=")
			if err != nil {
				return err
			}
			_, err = drv.Execute(ctx, tg, "jira.delete_issue", nil,
				connector.Idempotency{Class: connector.IdempotencyNone})
			return err
		},

		Tenants: []string{"acme", "globex"},

		// **THE CREDENTIAL CARRIES THE TENANT.** A shared token could only catch
		// an EMPTY header; the failure that actually happens is tenant B's
		// credential on tenant A's request, and only distinct credentials see it.
		// A server per call, because these run concurrently under `-race`.
		Concurrent: func(ctx context.Context, tenant string) (string, error) {
			var seen string
			srv := httptest.NewTLSServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					seen = strings.TrimPrefix(r.Header.Get("Authorization"), "Basic tok-")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"id":"10001"}`))
				}))
			defer srv.Close()

			tg, err := target(t, tenant, srv.URL, "tok-"+tenant)
			if err != nil {
				return "", err
			}

			// The error is swallowed on purpose: the subject is who the far side
			// thought was calling, not whether the exchange completed.
			_, _ = drv.Execute(connector.WithTenant(ctx, tenant), tg,
				jira.ActionCommentIssue,
				map[string]any{"issue": "PROJ-72", "body": "hello"},
				connector.Idempotency{Class: connector.IdempotencyNone})
			return seen, nil
		},

		Command: func(ctx context.Context, baseURL, ctxTenant string) error {
			tg, err := target(t, "acme", baseURL, "tok-acme")
			if err != nil {
				return err
			}
			_, err = drv.Execute(connector.WithTenant(ctx, ctxTenant), tg,
				jira.ActionCommentIssue,
				map[string]any{"issue": "PROJ-72", "body": "hello"},
				connector.Idempotency{Class: connector.IdempotencyNone})
			return err
		},
	})
}

// TestHTTPConformance is the transport half: 401, 403, 429 and 5xx, plus the
// credential never appearing in an error.
func TestHTTPConformance(t *testing.T) {
	drv := jira.New(jira.WithHTTPClient(conformance.InsecureClient()))

	// **THE INVOKER THREADS THE TENANT IT IS GIVEN RATHER THAN DERIVING ONE.**
	// Deriving it from the target would reproduce the check inside the fixture,
	// and the suite needs to be able to pass a WRONG tenant and watch nothing
	// leave.
	conformance.RunHTTP(t, conformance.HTTPCase{
		Tenant: "acme",
		// What a packet capture would show. Jira's credential IS the wire value
		// — no exchange, no signing — so the arm that proves the secret never
		// reaches an error has something real to look for.
		SecretOnTheWire: "tok-acme",
	}, func(ctx context.Context, baseURL, tenant string) error {
		tg, err := target(t, "acme", baseURL, "tok-acme")
		if err != nil {
			return err
		}
		_, err = drv.Query(connector.WithTenant(ctx, tenant), tg,
			jira.ActionReadIssue, map[string]any{"issue": "PROJ-72"})
		return err
	})
}

// --- what the suite does not fix, and is therefore ours -----------------------

// TestNotFoundIsTheCallersProblem pins the 404 decision.
//
// **THE SUITE DELIBERATELY DOES NOT COVER 404**, because it has no single right
// answer: MCP reads a bare 404 as a legacy endpoint and therefore a
// CONFIGURATION fault, while an absent Jira issue is the caller's. So the choice
// is this driver's and belongs in this driver's tests.
//
// The arm that matters is the ATTRIBUTION one: a missing issue must not
// implicate the target, or a few typos open a breaker on a healthy Jira.
func TestNotFoundIsTheCallersProblem(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessages":["Issue does not exist"]}`))
	}))
	defer srv.Close()

	drv := jira.New(jira.WithHTTPClient(conformance.InsecureClient()))
	tg, err := target(t, "acme", srv.URL, "tok-acme")
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}

	_, err = drv.Query(connector.WithTenant(context.Background(), "acme"), tg,
		jira.ActionReadIssue, map[string]any{"issue": "NOPE-1"})
	if err == nil {
		t.Fatal("a 404 succeeded")
	}
	if kind := fault.KindOf(err); kind != fault.KindNotFound {
		t.Errorf("a 404 was classified %q, want %q", kind, fault.KindNotFound)
	}
	if fault.KindOf(err).ImplicatesTarget() {
		t.Error("a missing issue implicates the TARGET. Jira answered correctly and " +
			"promptly; attributing this to it opens a breaker on a healthy vendor " +
			"over a caller's typo (D200)")
	}
}

// TestCommentIsClassNoneAndTheGateAgrees is D182, and the reason
// `comment_issue` is class `none`.
//
// **THE DRIVER DECLARES; THE ENFORCEMENT PATH ENFORCES (blueprint step 2).** A
// driver does not call the retry policy — D140–D143 put it on the path
// deliberately so it cannot be forgotten by one driver or implemented
// differently by each. So the driver's obligation is the DECLARATION, and this
// test asserts both halves: that the class is what a human chose, and that the
// declaration actually closes the gate rather than being a label.
//
// **A CLOSED GATE THAT HANDS BACK A RETRYABLE ERROR HAS MOVED THE DOUBLE-WRITE
// HAZARD, NOT REMOVED IT** — the agent retries instead of the path, and Jira
// gets two comments either way.
func TestCommentIsClassNoneAndTheGateAgrees(t *testing.T) {
	var spec connector.ActionSpec
	for _, s := range jira.New().Actions() {
		if s.Name == jira.ActionCommentIssue {
			spec = s
		}
	}
	if spec.Name == "" {
		t.Fatal("comment_issue is not declared")
	}
	if spec.Idempotency != connector.IdempotencyNone {
		t.Errorf("comment_issue is class %q, want %q. Atlassian documents no "+
			"idempotency mechanism for creating a comment, so a repeat duplicates it",
			spec.Idempotency, connector.IdempotencyNone)
	}

	why, unsafe := retry.UnsafeToRetry(spec.Mutating, spec.Idempotency, "")
	if !unsafe {
		t.Errorf("the path reports a class %q comment SAFE to retry (%s). The "+
			"declaration is then a label rather than a gate", spec.Idempotency, why)
	}
}

// TestAttributionIsStampedIntoTheAction is blueprint step 12 (§10.4).
//
// The audit log records what Sekizui did. This is what lets somebody reading
// JIRA's record see that an agent did it — and nothing in the system checks it,
// which is why it has a test here.
func TestAttributionIsStampedIntoTheAction(t *testing.T) {
	var body map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"10042"}`))
	}))
	defer srv.Close()

	drv := jira.New(jira.WithHTTPClient(conformance.InsecureClient()))
	tg, err := target(t, "acme", srv.URL, "tok-acme")
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}

	res, err := drv.Execute(connector.WithTenant(context.Background(), "acme"), tg,
		jira.ActionCommentIssue,
		map[string]any{"issue": "PROJ-72", "body": "triaged automatically"},
		connector.Idempotency{Class: connector.IdempotencyNone})
	if err != nil {
		t.Fatalf("commenting: %v", err)
	}

	// The join key, without which a governed action and the thing it did are two
	// facts nobody can connect.
	if res.ExternalRef != "10042" {
		t.Errorf("ExternalRef is %q, want the comment id the vendor returned", res.ExternalRef)
	}

	props, _ := body["properties"].([]any)
	if len(props) == 0 {
		t.Fatal("the create carried no `properties`, so nothing reading Jira's own " +
			"record can tell that an agent wrote this comment")
	}
	first, _ := props[0].(map[string]any)
	if first["key"] != "sekizui.attribution" {
		t.Errorf("the attribution property is keyed %v", first["key"])
	}

	// **AND IT IS NOT IN THE COMMENT TEXT.** A stamp appended to the body mutates
	// content a human will read and quote; metadata belongs in metadata.
	raw, _ := json.Marshal(body["body"])
	if strings.Contains(string(raw), "sekizui") {
		t.Error("the attribution leaked into the comment BODY. That is somebody's " +
			"issue thread, not a place to write our own metadata")
	}
}

// TestTheCredentialIsSentAsBasic pins the auth scheme against Atlassian's
// documented format — the one thing about this vendor that was VERIFIED rather
// than assumed.
func TestTheCredentialIsSentAsBasic(t *testing.T) {
	var got string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"key":"PROJ-72"}`))
	}))
	defer srv.Close()

	drv := jira.New(jira.WithHTTPClient(conformance.InsecureClient()))
	// The material is ALREADY base64(email:token): Jira's credential is a
	// composite and `SetAuthorization` emits `<scheme> <material>` with no way to
	// compose one. Recorded as a blueprint gap rather than worked around here.
	tg, err := target(t, "acme", srv.URL, "ZW1haWxAYWNtZS5jb206dG9rZW4=")
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}

	if _, err := drv.Query(connector.WithTenant(context.Background(), "acme"), tg,
		jira.ActionReadIssue, map[string]any{"issue": "PROJ-72"}); err != nil {
		t.Fatalf("reading: %v", err)
	}
	if want := "Basic ZW1haWxAYWNtZS5jb206dG9rZW4="; got != want {
		t.Errorf("Authorization is %q, want %q — Jira Cloud is Basic with the "+
			"base64 pair, not Bearer", got, want)
	}
}

// TestAssumptionsAreRecorded keeps the honest half honest.
//
// **A DRIVER BUILT FROM DOCUMENTATION HAS ASSUMPTIONS AND THE ONLY QUESTION IS
// WHETHER THEY ARE WRITTEN DOWN.** This driver has never spoken to Jira, so its
// fixtures agree with it by construction and prove nothing about the vendor.
// Emptying the list would make the package look verified.
func TestAssumptionsAreRecorded(t *testing.T) {
	got := jira.Assumptions()
	if len(got) < 3 {
		t.Fatalf("%d assumptions recorded. This driver has never met a real Jira; a "+
			"short list means somebody deleted the evidence rather than gathered it",
			len(got))
	}
	var verified int
	for _, a := range got {
		if strings.HasPrefix(a, "VERIFIED") {
			verified++
		}
	}
	if verified == 0 {
		t.Error("nothing in the list is marked VERIFIED, so the list cannot " +
			"distinguish what was checked from what was guessed")
	}
}

// target builds a resolved Target the way the resolver would.
func target(t *testing.T, tenant, baseURL, secret string) (connector.Target, error) {
	t.Helper()

	return connector.NewTarget(connector.TargetParams{
		Ref: "jira:" + tenant, Kind: jira.Kind, Tenant: tenant, Residency: "eu",
		BaseURL: baseURL, CredentialVersion: "v1",
		Credential: connector.Secret(secret),
	})
}
