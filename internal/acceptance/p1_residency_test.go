package acceptance

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

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

// step59ResidencyIsACeilingPlusAGrant proves D136's two layers, both required.
//
// WHY THIS STEP BUILDS ITS OWN DEPLOYMENT. Residency is the one control whose
// meaning is set by the DEPLOYMENT rather than by the document: the same
// acceptance.yaml behaves differently under `-residency us` and under
// `-residency eu,us`, and that difference is the entire subject here. The main
// run is single-class on purpose, so every step written before D136 keeps its
// meaning; this one stands a second, multi-residency instance beside it rather
// than changing the ceiling underneath fifty-eight other assertions.
//
// AND WHY IT CALLS Enforce DIRECTLY rather than going over mTLS. A second
// listener would prove the transport twice and the property once. Enforce IS the
// enforcement path — that is what D18 and D69 buy, and the reflex engine is
// already a first-class caller of it — so the layers under test are identical to
// the ones a wire command traverses. Nothing between the certificate and here
// contributes to a residency decision.
func step59ResidencyIsACeilingPlusAGrant(t *testing.T) {
	ctx := context.Background()

	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		t.Skip("needs a deployment whose -residency ceiling this step controls; the " +
			"live instance is started with its own, and widening it from here would " +
			"assert against a configuration nobody deployed")
	}

	// --- the deployment, widened ---------------------------------------------
	//
	// us AND eu, so `kata:beta` (eu) becomes reachable at the ceiling and the
	// grant layer switches on. `kata:tokyo` is jp: outside this ceiling however
	// wide it got, which is what makes the first case a CEILING refusal rather
	// than a policy one.
	permitted := []string{"eu", "us"}
	srv, sink, logPath := multiResidencyInstance(t, permitted)
	defer func() { _ = sink.Close(ctx) }()

	cases := []struct {
		name   string
		who    string
		target string

		wantStatus sekizuiv1.Status
		wantBy     sekizuiv1.RefusedBy
	}{
		// THE CEILING WINS OVER A GRANT THAT FULLY PERMITS. agent:crossborder is
		// granted kata.create_issue on kata:tokyo AND names jp in its
		// target_residency constraint, so policy would allow this outright. The
		// deployment does not serve jp, so it is refused anyway — and refused as
		// RESIDENCY rather than POLICY. That ordering is D71's: a compliance
		// invariant the party wanting the data cannot grant itself.
		{
			name: "ceiling refuses what a grant fully permits", who: "agent:crossborder",
			target:     "kata:tokyo",
			wantStatus: sekizuiv1.Status_STATUS_DENIED,
			wantBy:     sekizuiv1.RefusedBy_REFUSED_BY_RESIDENCY,
		},

		// THE CEILING IS REPORTED WHEN BOTH LAYERS WOULD REFUSE, and this is the
		// case that proves the ORDER rather than merely the outcome.
		//
		// agent:global has no capability on kata:tokyo at all, so policy denies
		// by default; jp is outside the ceiling, so residency denies too. The
		// case above does not discriminate — with the ceiling checked only
		// inside Resolve, as it was before D136, a grant that ALLOWS still ends
		// up refused by residency. Here a grant that DENIES would have won the
		// race and reported REFUSED_BY_POLICY, sending an operator to review a
		// grant about a target this deployment was never permitted to touch.
		// §7.1 item 2 exists so nobody has to infer which refusal happened.
		{
			name: "the ceiling is reported even when a grant would also refuse",
			who:  "agent:global", target: "kata:tokyo",
			wantStatus: sekizuiv1.Status_STATUS_DENIED,
			wantBy:     sekizuiv1.RefusedBy_REFUSED_BY_RESIDENCY,
		},

		// THE GRANT LAYER, ON A CROSSING THE CEILING NOW PERMITS. agent:global
		// holds `{action: kata.create_issue, target: kata:beta}` with no
		// residency constraint — a grant written when the deployment served one
		// class and nobody had a border to think about. Widening the ceiling
		// does NOT silently extend it across that border. This is the failure
		// CONTRACTS item 39 exists for: an operator who needs one legitimate
		// crossing widening `-residency` globally and losing the guarantee.
		{
			name: "a grant silent about the crossing does not authorise it", who: "agent:global",
			target:     "kata:beta",
			wantStatus: sekizuiv1.Status_STATUS_DENIED,
			wantBy:     sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
		},

		// NON-VACUITY. Same action, same target, same widened ceiling — and a
		// grant that names the crossing. Without this the two rows above prove
		// only that something refuses everything.
		{
			name: "ceiling and grant together permit the crossing", who: "agent:crossborder",
			target:     "kata:beta",
			wantStatus: sekizuiv1.Status_STATUS_OK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args, err := structpb.NewStruct(map[string]any{"project": "PROJ"})
			if err != nil {
				t.Fatalf("args: %v", err)
			}

			res, err := srv.Enforce(ctx, assertedIdentity(c.who), &sekizuiv1.Command{
				Action: "kata.create_issue", TargetRef: c.target, Args: args,
				IdempotencyKey: "acc-59-" + c.who + "-" + c.target,
			})
			if err != nil {
				t.Fatalf("refused as a transport ERROR (%v); every deliberate refusal "+
					"is a CommandResult (D135), and residency is the stage that proved it",
					err)
			}
			if got := res.GetStatus(); got != c.wantStatus {
				t.Fatalf("status = %v, want %v (reason %q)",
					got, c.wantStatus, res.GetReason())
			}
			if res.GetDecisionId() == "" {
				t.Fatal("no decision id: a refusal with no record is the row §5.4 " +
					"calls the highest-value one")
			}
			if c.wantStatus == sekizuiv1.Status_STATUS_OK {
				return
			}

			// WHICH STAGE REFUSED, which is the whole point of having two. A
			// ceiling refusal and a grant refusal are different work for an
			// operator — move the workload versus review a grant — and §7.1
			// item 2 exists so that nobody has to infer which.
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
				t.Errorf("refused_by = %v, want %v. Two layers are only worth having "+
					"if the record says which one spoke", got, c.wantBy)
			}
		})
	}

	// --- the hole both layers would otherwise leave --------------------------
	//
	// An UNCLASSIFIED target is permitted by the ceiling (Profile.ResidencyPermitted
	// treats an empty class as always-permitted, which is right for an instance
	// that has not thought about residency) and unconstrained by every grant
	// (there is no border to authorise). Composed in a multi-residency
	// deployment that is an unpoliced route into any served class, reachable
	// with an ordinary grant — so the deployment refuses to boot instead.
	t.Run("an undeclared residency is refused at boot, not tolerated", func(t *testing.T) {
		doc := &config.Document{
			Targets: []config.TargetSpec{
				{Ref: "kata:classified", Kind: kata.Kind, Tenant: "a", Residency: "eu"},
				{Ref: "kata:nowhere", Kind: kata.Kind, Tenant: "b"},
			},
		}

		orphans := policy.NewGrantEngine(doc, permitted).UnclassifiedTargets()
		if len(orphans) != 1 || orphans[0] != "kata:nowhere" {
			t.Errorf("UnclassifiedTargets() = %v, want [kata:nowhere]. An undeclared "+
				"target nothing reports is the hole both layers leave", orphans)
		}

		// SILENT ON A SINGLE-CLASS DEPLOYMENT, which cannot have the hole —
		// otherwise every existing single-region config would be refused for a
		// border it does not have.
		if got := policy.NewGrantEngine(doc, []string{"eu"}).UnclassifiedTargets(); got != nil {
			t.Errorf("UnclassifiedTargets() = %v on a single-class deployment, want none", got)
		}
	})

	// --- what widening the ceiling just switched off -------------------------
	//
	// residencyCovered is modal on the deployment, so a grant cannot be read for
	// sufficiency on its own. An operator who is not told will read the denials
	// above as a bug in Sekizui, so the instance says at boot which capabilities
	// stopped working and how to fix each.
	t.Run("boot names the grants the crossing rule just disabled", func(t *testing.T) {
		doc := loadAcceptanceDoc(t)

		crossings := policy.NewGrantEngine(doc, permitted).UncoveredCrossings()
		if len(crossings) == 0 {
			t.Fatal("no uncovered crossings reported, but agent:global holds an " +
				"unconstrained capability on eu-resident kata:beta")
		}
		var found bool
		for _, c := range crossings {
			if c.Principal == "agent:global" && c.TargetRef == "kata:beta" {
				found = true
				if c.Residency != "eu" {
					t.Errorf("crossing residency = %q, want eu", c.Residency)
				}
			}
			if c.Principal == "agent:crossborder" {
				t.Errorf("agent:crossborder names the crossing in its grant and must "+
					"not be reported as uncovered: %+v", c)
			}
		}
		if !found {
			t.Errorf("agent:global on kata:beta missing from %+v", crossings)
		}

		// SILENT WHERE THE RULE IS OFF, for the same reason as above.
		if got := policy.NewGrantEngine(doc, acceptanceResidency).UncoveredCrossings(); got != nil {
			t.Errorf("UncoveredCrossings() = %+v on a single-class deployment, want none", got)
		}
	})
}

// multiResidencyInstance stands a Server over the acceptance document up with a
// caller-chosen ceiling, and returns the path its records land in.
//
// THE CEILING REACHES BOTH the resolver and the grant engine from ONE parameter,
// because the two disagreeing is the silent failure D136 is most exposed to: a
// resolver serving eu,us beside an engine believing the deployment is
// single-class turns the grant layer off while every refusal still looks
// correct.
func multiResidencyInstance(t *testing.T, permitted []string) (
	*gateway.Server, *auditwal.JSONLSink, string) {

	t.Helper()

	t.Setenv("SEKIZUI_ACCEPT_TOK", "acceptance-token")
	doc := loadAcceptanceDoc(t)

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

	clock := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	tick := func() time.Time { clock = clock.Add(time.Second); return clock }

	return gateway.New(gateway.Config{
		Doc:      doc,
		Policy:   policy.NewGrantEngine(doc, permitted),
		Resolver: resolver.New(doc, profile, permitted, config.EnvProvider{}),
		Drivers:  map[string]connector.Driver{kata.Kind: kata.New()},
		Guards:   anzen.New(doc.Anzen),
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc), auditwal.WithClock(tick)),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      tick,
	}), sink, path
}

// loadAcceptanceDoc loads and VALIDATES the acceptance document.
//
// Validated for the reason newRun gives: a run over configuration a deployment
// would refuse at boot proves nothing. That matters more here than usual,
// because D136 added a boot check to this very file's grants.
func loadAcceptanceDoc(t *testing.T) *config.Document {
	t.Helper()

	doc, err := config.NewFileSource("acceptance.yaml").Load(context.Background())
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("the acceptance config would be refused at boot: %v", err)
	}
	return doc
}

// mustArgs builds a Struct or fails the test, so a step's table stays readable.
func mustArgs(t *testing.T, args map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(args)
	if err != nil {
		t.Fatalf("args: %v", err)
	}
	return s
}

// assertedIdentity builds a standalone identity — a delegation chain of length
// one (D6), the shape reflex.IdentityFor produces.
//
// AUTH_METHOD_INTERNAL rather than the zero value, for the reason D57 gives: an
// audit row must be able to tell a deliberate in-process action from a field
// somebody forgot to populate.
func assertedIdentity(principal string) *sekizuiv1.Identity {
	return &sekizuiv1.Identity{
		Caller: &sekizuiv1.Caller{
			Principal:    principal,
			Method:       sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL,
			CredentialId: "acceptance:step59",
		},
		Subject: &sekizuiv1.Subject{
			Principal: principal,
			Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED,
		},
		Chain: []string{principal},
	}
}
