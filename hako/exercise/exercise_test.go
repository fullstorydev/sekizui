//go:build hako

// The exercise's own run. **BUILD-TAGGED BECAUSE IT IS MEANT TO FAIL.**
//
// `go test ./...` must stay green, and a teaching artefact that must fail cannot
// live inside a runner that requires green — so this is behind `-tags hako` and
// `make hako` is how a human runs it. The half that IS guarded in CI is the
// solution next door, which runs the same suite and passes.
//
// Work top to bottom. Each failure names the blueprint step that closes it.
package notes_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/hako/exercise"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
)

// TestTheMechanicalContract is the published suite. It fails on step 3 until the
// mutating action declares how it is idempotent.
func TestTheMechanicalContract(t *testing.T) {
	drv := notes.New(notes.WithHTTPClient(conformance.InsecureClient()))

	conformance.Run(t, drv, conformance.Case{
		UnknownAction: "notes.delete_workspace",
		Refuse: func(ctx context.Context) error {
			tg, err := connector.NewTarget(connector.TargetParams{
				Ref: "notes:acme", Kind: notes.Kind, Tenant: "acme",
				BaseURL: "https://notes.invalid", Credential: connector.Secret("tok"),
			})
			if err != nil {
				return err
			}
			_, err = drv.Execute(ctx, tg, "notes.delete_workspace", nil,
				connector.Idempotency{Class: connector.IdempotencyNone})
			return err
		},
		// HAKO STEP 11: `Concurrent` and `Command` are unwired, so the suite
		// refuses to run its statelessness and tenant arms and says so.
		//
		// **DELIBERATELY NOT `WhyNoFarSide`, and the first version of this file
		// set it — which made the gap PASS.** That field is a legitimate
		// ledgered opt-out for a driver with nothing a caller can observe, and
		// Notes has an HTTP far side, so claiming it here would have taught the
		// opposite of the lesson: the exercise went green with the two arms
		// silently skipped. Found by working the kata.
		//
		// Wire them: a recording server per call, and a DISTINCT credential per
		// tenant — a shared one could only ever catch an empty header, never a
		// swapped one, and swapped is the failure that actually happens.
	})
}

// TestTheAuditTrailJoins is HAKO STEP 12 — the obligations nothing else checks.
//
// **A GAP WITH NO CHECK IS A TODO COMMENT.** It teaches nothing, nobody notices
// when it stops applying, and it makes the exercise look more thorough than it
// is. So every marker in this kata has a failure behind it, and this is step
// 11's.
func TestTheAuditTrailJoins(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"note-42"}`))
	}))
	defer srv.Close()

	tg, err := connector.NewTarget(connector.TargetParams{
		Ref: "notes:acme", Kind: notes.Kind, Tenant: "acme",
		BaseURL: srv.URL, Credential: connector.Secret("tok"),
	})
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}

	drv := notes.New(notes.WithHTTPClient(conformance.InsecureClient()))
	res, err := drv.Execute(connector.WithTenant(context.Background(), "acme"), tg,
		notes.ActionCreateNote, map[string]any{"body": "hello"},
		connector.Idempotency{
			Class: connector.IdempotencyHeader, Placement: "Idempotency-Key", Key: "k-1",
		})
	if err != nil {
		t.Fatalf("the call failed before this step could be reached: %v", err)
	}

	if res.ExternalRef == "" {
		t.Error("HAKO STEP 12: the vendor returned a note id and Result.ExternalRef is " +
			"empty. That field is how an audit row joins to the vendor's own record — " +
			"without it, a governed action and the thing it did are two facts nobody " +
			"can connect, and the audit log answers 'an agent created a note' without " +
			"being able to say which")
	}
}

// TestTheGovernanceHalf is steps 5 to 9, and it is the whole reason this kata
// exists. A connector with none of this works perfectly and governs nothing.
func TestTheGovernanceHalf(t *testing.T) {
	raw, err := os.ReadFile("notes.yaml")
	if err != nil {
		t.Fatalf("reading the configuration: %v", err)
	}
	var doc config.Document
	if err := yaml.UnmarshalStrict(raw, &doc); err != nil {
		t.Fatalf("the configuration does not load: %v", err)
	}

	if len(doc.Shin) == 0 {
		t.Error("HAKO STEP 7: no shin lens. This vendor returns an author's email " +
			"address on every read and an agent has no use for it. Nothing in the " +
			"system will ever tell you this is missing — that is the point of the step")
	}
	if len(doc.Anzen) == 0 {
		t.Error("HAKO STEP 8: no anzen guard. A grant is written by whoever needs a " +
			"capability; a ceiling is written once by whoever is accountable for the " +
			"blast radius, and it is checked FIRST")
	}
	for _, g := range doc.Grants {
		for _, c := range g.Allow {
			if c.TargetRef == "" {
				t.Errorf("HAKO STEP 6: %q names no target, so it authorises that action "+
					"against every target of this kind — including ones added later by "+
					"somebody who never read this grant", c.Action)
			}
		}
	}
	// **STEP 4 AND STEP 7 ARE CHECKED TOGETHER, because they are coupled and a
	// learner who does one without the other gets a lens that withholds
	// nothing.** A query action with no `OutputType` is lensable only by the
	// type-less jurisdiction rules, so the lens below has no type to name.
	//
	// This lives here rather than in the conformance suite on purpose: D167
	// makes omitting `OutputType` a LEDGERED EXCEPTION with a reason, not a
	// refusal, and `ActionSpec` has no field for the reason — so a suite arm
	// would refuse a shape the design permits.
	declared := map[string]bool{}
	for _, spec := range notes.New().Actions() {
		if spec.Mutating {
			continue
		}
		if spec.OutputType == "" {
			t.Errorf("HAKO STEP 4: %q is a query action and declares no OutputType, so "+
				"nothing knows the SHAPE of what it returns — and the lens in step 7 has "+
				"no type to name", spec.Name)
			continue
		}
		declared[spec.OutputType] = true
	}
	for _, lens := range doc.Shin {
		if lens.Type != "" && !declared[lens.Type] {
			t.Errorf("HAKO STEP 7: lens %q is typed %q and no action declares that "+
				"OutputType. A lens on a type nothing produces is INERT — it reads in "+
				"review as a control in force and withholds nothing",
				lens.Name, lens.Type)
		}
	}

	for _, tg := range doc.Targets {
		if tg.Limits == nil {
			t.Errorf("HAKO STEP 5: target %q sets no limits, so an operator cannot "+
				"narrow its rate without a redeploy", tg.Ref)
		}
	}
}

// TestTheSourceContract is the SOURCE half of the published suite.
//
// A connector that is polled selects this as well; a write-only one does not
// have it at all. Two gaps are open here, and they fail differently on purpose
// — one is caught by a response check, the other only by calling.
func TestTheSourceContract(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// THE VENDOR IGNORES `limit`, which is the realistic half of HAKO STEP
		// 2: you cannot fix this at the vendor, only decline to pass it on.
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

	tg, err := connector.NewTarget(connector.TargetParams{
		Ref: "notes:acme", Kind: notes.Kind, Tenant: "acme", Residency: "eu",
		BaseURL: srv.URL, CredentialVersion: "v1", Credential: connector.Secret("tok"),
		Settings: map[string]string{notes.SettingAppendOnly: "true"},
	})
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}

	spy := conformance.NewPoolSpy()
	conformance.RunSource(t,
		notes.New(notes.WithHTTPClient(conformance.InsecureClient()), notes.WithPool(spy)),
		conformance.SourceCase{Target: tg, Limit: 2, Tenant: "acme", Pool: spy})
}
