package acceptance

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// jurisdictionalGuards is step 60's own document.
//
// NOT acceptance.yaml, and the reason is itself evidence the feature works. A
// guard scoped to a class an instance does not serve is refused at boot by
// UnservedScopes — correctly, because it would govern nothing there. `make run`
// serves us (D326), so this document's `jp` guard in the shared fixture would
// break the live instance every other step drives. The step owns the document.
//
// THREE GUARDS, chosen so composition is observable:
//
//	no-destructive-actions  UNSCOPED  — the ceiling that must still cover
//	                                    everything, including unclassified
//	no-create-in-us         us        — adds a refusal in one jurisdiction only
//	burst-cap-jp            jp        — a SECOND axis on the concurrency form,
//	                                    proving this is not forbid-only
const jurisdictionalGuards = `
targets:
  - {ref: kata:eu, kind: kata, tenant: a, residency: eu, base_url: https://eu.invalid, credential: env://SEKIZUI_ACCEPT_TOK}
  - {ref: kata:us, kind: kata, tenant: b, residency: us, base_url: https://us.invalid, credential: env://SEKIZUI_ACCEPT_TOK}
  - {ref: kata:jp, kind: kata, tenant: c, residency: jp, base_url: https://jp.invalid, credential: env://SEKIZUI_ACCEPT_TOK}
  - {ref: kata:anywhere, kind: kata, tenant: d, base_url: https://any.invalid, credential: env://SEKIZUI_ACCEPT_TOK}

grants:
  - principal: agent:worldwide
    allow:
      - {action: kata.create_issue, target: kata:eu, where: {target_residency: [eu]}}
      - {action: kata.create_issue, target: kata:us, where: {target_residency: [us]}}
      - {action: kata.create_issue, target: kata:anywhere}
      - {action: kata.delete_project, target: kata:eu, where: {target_residency: [eu]}}
      - {action: kata.delete_project, target: kata:anywhere}

anzen:
  - name: no-destructive-actions
    enabled: true
    mode: enforce
    forbids: ["*.delete_*"]

  - name: no-create-in-us
    enabled: true
    mode: enforce
    forbids: ["kata.create_issue"]
    target_residency: [us]

  - name: burst-cap-jp
    enabled: true
    mode: enforce
    max_concurrent: 1
    target_residency: [jp]
`

// step60AnzenScopesByResidency proves D137's second scoping axis.
func step60AnzenScopesByResidency(t *testing.T) {
	ctx := context.Background()

	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		t.Skip("needs a deployment serving eu,us,jp with jurisdictional guards; the " +
			"live instance serves us, and a jp-scoped guard is refused at boot there " +
			"— which is the feature, not an obstacle")
	}

	srv, sink, logPath := guardedInstance(t, jurisdictionalGuards, []string{"eu", "us", "jp"})
	defer func() { _ = sink.Close(ctx) }()

	cases := []struct {
		name   string
		action string
		target string

		wantStatus sekizuiv1.Status
		wantBy     sekizuiv1.RefusedBy
	}{
		// THE SCOPED GUARD ADDS A REFUSAL where the unscoped ones say nothing.
		// `kata.create_issue` is forbidden on us-resident targets and nowhere else.
		{
			name:   "a scoped guard refuses in its own jurisdiction",
			action: "kata.create_issue", target: "kata:us",
			wantStatus: sekizuiv1.Status_STATUS_DENIED,
			wantBy:     sekizuiv1.RefusedBy_REFUSED_BY_ANZEN,
		},

		// NON-VACUITY, and the whole point of scoping. The same action on an
		// eu-resident target is allowed, by the same guard set, for the same
		// principal. Without this the case above proves only that the action is
		// forbidden everywhere.
		{
			name:   "the same action is permitted outside that jurisdiction",
			action: "kata.create_issue", target: "kata:eu",
			wantStatus: sekizuiv1.Status_STATUS_OK,
		},

		// THE UNSCOPED CEILING STILL COVERS EVERYTHING, which is what makes the
		// composition additive rather than a set of exemptions. Scoping one rule
		// to `us` must not have carved a hole in a rule that named no class.
		{
			name:   "an unscoped guard still covers a classified target",
			action: "kata.delete_project", target: "kata:eu",
			wantStatus: sekizuiv1.Status_STATUS_DENIED,
			wantBy:     sekizuiv1.RefusedBy_REFUSED_BY_ANZEN,
		},

		// THE CASE THE WHOLE ADDITIVE RULE EXISTS FOR. An UNCLASSIFIED target has
		// no class, so no scoped rule matches it. If a scoped rule could be the
		// only rule governing an action, an undeclared target would escape the
		// safety control entirely — fail-open, the one direction nothing else
		// here fails. The unscoped ceiling must still catch it.
		{
			name:   "an unscoped guard still covers an UNCLASSIFIED target",
			action: "kata.delete_project", target: "kata:anywhere",
			wantStatus: sekizuiv1.Status_STATUS_DENIED,
			wantBy:     sekizuiv1.RefusedBy_REFUSED_BY_ANZEN,
		},

		// AND A SCOPED RULE DOES NOT REACH AN UNCLASSIFIED TARGET, which is the
		// other half of "additive": `no-create-in-us` must not creep onto a target
		// that declares nothing just because it cannot prove it is elsewhere.
		{
			name:   "a scoped guard does not reach an unclassified target",
			action: "kata.create_issue", target: "kata:anywhere",
			wantStatus: sekizuiv1.Status_STATUS_OK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := srv.Enforce(ctx, assertedIdentity("agent:worldwide"),
				&sekizuiv1.Command{
					Action: c.action, TargetRef: c.target,
					Args:           mustArgs(t, map[string]any{"project": "PROJ"}),
					IdempotencyKey: "acc-60-" + c.action + "-" + c.target,
				})
			if err != nil {
				t.Fatalf("refused as a transport ERROR (%v); a guard refusal is a "+
					"CommandResult like every other deliberate refusal (D135)", err)
			}
			if got := res.GetStatus(); got != c.wantStatus {
				t.Fatalf("status = %v, want %v (reason %q)",
					got, c.wantStatus, res.GetReason())
			}
			if c.wantStatus == sekizuiv1.Status_STATUS_OK {
				return
			}

			var rec *sekizuiv1.Decision
			for _, d := range readLog(t, logPath) {
				if d.GetId() == res.GetDecisionId() {
					rec = d
				}
			}
			if rec == nil {
				t.Fatalf("no record for decision %q", res.GetDecisionId())
			}
			if got := rec.GetRefusedBy(); got != c.wantBy {
				t.Errorf("refused_by = %v, want %v", got, c.wantBy)
			}
		})
	}

	// --- the CONCURRENCY form scopes too, not forbids alone ------------------
	//
	// Reached through the guards API rather than through Enforce, because a
	// concurrency cap is about two calls being in flight AT ONCE and a table of
	// sequential commands cannot express that. `burst-cap-jp` caps jp at one.
	//
	// Worth asserting rather than assuming: forbid and cap are separate loops in
	// Check, so scoping one says nothing about the other — and a rule declared in
	// the fixture that no test exercises is exactly the shape of this codebase's
	// most persistent defect.
	t.Run("the concurrency form scopes by residency too", func(t *testing.T) {
		var doc config.Document
		if err := yaml.Unmarshal([]byte(jurisdictionalGuards), &doc); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		guards := anzen.New(doc.Anzen)

		// One in flight against jp is admitted; the second is not.
		if _, _, err := guards.Check("agent:worldwide", "kata.create_issue", "jp"); err != nil {
			t.Fatalf("first jp call refused: %v", err)
		}
		if _, _, err := guards.Check("agent:worldwide", "kata.create_issue", "jp"); err == nil {
			t.Error("a second concurrent jp call was admitted; burst-cap-jp caps it at one")
		}

		// AND THE CAP DOES NOT FOLLOW THE PRINCIPAL ACROSS THE BORDER. Same
		// principal, already at its jp ceiling, acting on an eu target: the jp
		// rule does not apply, so nothing refuses. Without this the case above
		// would pass on a cap that ignored residency entirely.
		if _, _, err := guards.Check("agent:worldwide", "kata.create_issue", "eu"); err != nil {
			t.Errorf("an eu call was refused by a jp-scoped cap: %v", err)
		}

		// NOR ONTO AN UNCLASSIFIED TARGET, the additive rule's other half.
		if _, _, err := guards.Check("agent:worldwide", "kata.create_issue", ""); err != nil {
			t.Errorf("an unclassified call was refused by a jp-scoped cap: %v", err)
		}
	})

	// --- a guard that governs nothing here is refused at boot ----------------
	//
	// Document.Validate catches a class NO TARGET declares, which is the typo.
	// This is the other shape: a real class, declared by a target, simply not
	// served by this instance — a `jp` guard in a `de,fr` deployment. The config
	// is shared across deployments, so it is well-formed and inert, and the file
	// still states plainly that the control exists.
	t.Run("a guard scoped to an unserved class is refused at boot", func(t *testing.T) {
		var doc config.Document
		if err := yaml.Unmarshal([]byte(jurisdictionalGuards), &doc); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		guards := anzen.New(doc.Anzen)

		unserved := guards.UnservedScopes([]string{"eu"})
		if len(unserved) != 2 {
			t.Errorf("UnservedScopes([eu]) = %v, want the us and jp guards — a "+
				"defensive rule matching nothing is worse than an absent one", unserved)
		}

		// SERVED MEANS SILENT, or the check would refuse every legitimate
		// multi-jurisdiction deployment.
		if got := guards.UnservedScopes([]string{"eu", "us", "jp"}); got != nil {
			t.Errorf("UnservedScopes(all three) = %v, want none", got)
		}

		// UNCONSTRAINED SERVES EVERYTHING, matching §7.1's reading of the flag.
		if got := guards.UnservedScopes(nil); got != nil {
			t.Errorf("UnservedScopes(nil) = %v, want none", got)
		}
	})

	// --- and the reactive form does not get this axis ------------------------
	//
	// A reactive rule already names ONE subject, so its residency is whatever
	// that target declares. A constraint could only agree, in which case it is
	// noise, or contradict, in which case the rule silently never fires.
	t.Run("a reactive rule cannot be residency-scoped", func(t *testing.T) {
		var doc config.Document
		if err := yaml.Unmarshal([]byte(jurisdictionalGuards+`
  - name: compromise
    enabled: true
    mode: enforce
    watches: credential_stale
    do: revoke_credential
    subject: kata:eu
    target_residency: [eu]
`), &doc); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		if err := doc.Validate(); err == nil {
			t.Error("a reactive rule with target_residency was accepted; the field can " +
				"never mean anything there, and a field that can never mean anything is " +
				"this codebase's most persistent defect")
		}
	})
}

// guardedInstance stands a Server up over a caller-supplied document.
//
// Step 59's multiResidencyInstance loads acceptance.yaml; this one takes the
// document as an argument, because D137's subject is the anzen block and the
// shared fixture cannot hold a us-scoped guard without breaking `make run`.
func guardedInstance(t *testing.T, docYAML string, permitted []string) (
	*gateway.Server, *auditwal.JSONLSink, string) {

	t.Helper()

	t.Setenv("SEKIZUI_ACCEPT_TOK", "acceptance-token")

	var doc config.Document
	if err := yaml.Unmarshal([]byte(docYAML), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	// THE SAME VALIDATION A DEPLOYMENT USES. A step over configuration that
	// would be refused at boot proves nothing — and this step adds two boot
	// checks of its own.
	if err := doc.Validate(); err != nil {
		t.Fatalf("the step's config would be refused at boot: %v", err)
	}

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(context.Background()); err != nil {
		t.Fatalf("audit sink: %v", err)
	}

	profile := runtime.Detect(func(k string) string {
		if k == "SEKIZUI_REGION" {
			return "europe-west1"
		}
		return ""
	}, runtime.Override{})

	clock := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	tick := func() time.Time { clock = clock.Add(time.Second); return clock }

	return gateway.New(gateway.Config{
		Doc:      &doc,
		Policy:   policy.NewGrantEngine(&doc, permitted),
		Resolver: resolver.New(&doc, profile, permitted, config.EnvProvider{}),
		Drivers:  map[string]connector.Driver{kata.Kind: kata.New()},
		Guards:   anzen.New(doc.Anzen),
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, &doc), auditwal.WithClock(tick)),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      tick,
	}), sink, path
}
