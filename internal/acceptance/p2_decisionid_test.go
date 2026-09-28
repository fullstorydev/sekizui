package acceptance

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step41AFailureNamesTheRowThatExplainsIt proves D202.
//
// **THE ASYMMETRY WAS COMPLETE AND NOBODY HAD LOOKED FOR IT.** Every deliberate
// refusal reaches the caller as a `CommandResult` carrying its decision id
// (D135). Every FAILURE reached it as a transport error carrying none — while
// `recordFailure` called `recorder.Terminal`, which RETURNS the id of the row it
// just wrote, and discarded it with `_`. The row existed; the only party who
// needed to find it had no key.
//
// **WHY IT MATTERS MORE LATER, which is how the maintainer put it.** At one replica an
// operator finds the row by timestamp. Across replicas under concurrent load the
// id is the join key and there is no substitute — and the callers are frequently
// not humans reading our logs: a reflex holds `Outcome{Err}` and an agent holds
// a gRPC error. **Instance ~seventeen of the recurring class, in its quietest
// form yet:** a value produced, recorded, and dropped between the two, where
// every artefact a reviewer inspects is present and correct.
//
// ASSERTED AGAINST THE ROW, not merely for non-emptiness. An id that does not
// name the row it claims to is worse than no id, because it sends somebody
// looking with confidence.
func step41AFailureNamesTheRowThatExplainsIt(t *testing.T) {
	ctx := context.Background()

	// **A DRIVER THAT FAILS, AND THIS FIXTURE HAS NOW EXPIRED TWICE — the second
	// time is the more instructive.**
	//
	// The first draft used a target whose DRIVER KIND nothing implements, which
	// this step's own non-vacuity arm rejected: that produces `KindConfig`, and
	// D201 had just made `KindConfig` a deliberate REFUSAL, so it already
	// carried an id and would have proven nothing about the path that did not.
	//
	// The second used an unknown TARGET REF, on the reasoning — written into
	// this comment — that "an unknown target ref is `KindNotFound`, a genuine
	// failure". **D211 made that false**: `not_found` became a deliberate
	// refusal and the resolver's own site became `KindConfig`, so the fixture
	// stopped measuring a failure and the arm caught it again, on the first run
	// after the taxonomy changed.
	//
	// **THE LESSON IS ABOUT FIXTURES THAT DEPEND ON A CLASSIFICATION.** Both
	// premises were true when written and neither was load-bearing to the thing
	// under test — D202 is about a FAILURE carrying its row's id, and any
	// non-deliberate error proves it. So the fixture now MAKES a failure rather
	// than borrowing one from the taxonomy: a driver whose Execute returns a
	// target error is a genuine failure by construction, and stays one however
	// the kinds are reclassified.
	t.Setenv("SEKIZUI_D202_TOK", "decision-id-token")
	doc := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "kata:failing", Kind: kata.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://kata.invalid", CredentialRef: "env://SEKIZUI_D202_TOK",
		}},
		Grants: []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "kata.create_issue", TargetRef: "kata:failing"},
				// For 41c's arm: a governed verb on an instance with no pool,
				// which is a non-deliberate failure through `recordFailure`.
				{Action: verb.RevokeCredential, TargetRef: "kata:failing"},
			},
		}},
	}

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer func() { _ = sink.Stop(ctx) }()

	gw := gateway.New(gateway.Config{
		Doc:      doc,
		Policy:   policy.NewGrantEngine(doc, nil),
		Resolver: resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}),
		Drivers:  map[string]connector.Driver{kata.Kind: failingDriver{}},
		Guards:   anzen.New(nil),
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc)),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	_, err := gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "kata.create_issue", TargetRef: "kata:failing",
		Args: mustArgs(t, map[string]any{"project": "PROJ"}),
	})
	if err == nil {
		t.Fatal("41: the failing driver's command succeeded, so this is not measuring a " +
			"failure at all")
	}

	// --- 41a: IT IS A FAILURE, NOT A REFUSAL -------------------------------
	//
	// NON-VACUITY FOR THE WHOLE STEP: refusals already carried an id, so if this
	// arrived as one the step would prove nothing about the path that did not.
	if fault.KindOf(err).Deliberate() {
		t.Fatalf("41a: this arrived as a deliberate refusal (%v), which already carried "+
			"a decision id. The step needs the FAILURE path", fault.KindOf(err))
	}

	// --- 41b: THE FAILURE NAMES ITS ROW ------------------------------------
	id := fault.DecisionIDOf(err)
	if id == "" {
		t.Fatal("41b: the failure carries no decision id. The row was written and the " +
			"caller cannot name it — which for an agent or a reflex means the " +
			"explanation exists and is unreachable")
	}

	rows := readLog(t, path)
	if len(rows) == 0 {
		t.Fatal("41b: no audit row was written at all")
	}
	var matched *sekizuiv1.Decision
	for _, r := range rows {
		if r.GetId() == id {
			matched = r
		}
	}
	if matched == nil {
		t.Fatalf("41b: the failure names decision %q and no row has that id. An id that "+
			"does not name its row is worse than none: it sends somebody looking with "+
			"confidence", id)
	}
	// AND THE ROW EXPLAINS THE SAME FAILURE. An id pointing at an unrelated row
	// would satisfy the arm above.
	//
	// **THE EXPLANATION LIVES IN A DIFFERENT FIELD FOR THIS SHAPE OF ROW, and
	// that is worth knowing rather than working around.** A refusal recorded
	// through `recordFailure` is a TERMINAL row and carries its `reason`; a
	// command that was authorised, called and then failed at the far side is an
	// INTENT row completed by an OUTCOME, and the far side's error lands in
	// `effect.error`. Both are reachable from the id, which is the guarantee —
	// so the step accepts either rather than demanding the field that happens to
	// suit one path. Asserting only `reason` is what made this arm fail when the
	// fixture moved to a genuinely failing driver: the row explained the failure
	// perfectly, in the other column.
	explanation := matched.GetReason() + " " + matched.GetEffect().GetError()
	if !strings.Contains(explanation, "kata:failing") &&
		!strings.Contains(explanation, "the far side blew up") {
		t.Errorf("41b: the named row does not explain this failure. reason=%.80q "+
			"effect.error=%.80q", matched.GetReason(), matched.GetEffect().GetError())
	}

	// --- 41c: AND THE OTHER PATH, WHICH THIS STEP LOST WHEN 41a MOVED --------
	//
	// **D202's CLAIM SPANS TWO PATHS AND THE FIXTURE CAN ONLY STAND IN ONE, so
	// the step drives both — and the mutation audit is what said so.** The arms
	// above go through the INTENT/OUTCOME pair: a command authorised, called,
	// and failed at the far side. Rebuilding them around a failing driver moved
	// the step off `recordFailure`, the funnel D202's original fix went into —
	// and `make mutate` immediately reported the original D202 mutation as
	// SURVIVED, because nothing else drove it. Coverage had moved rather than
	// grown, which no assertion here could have noticed.
	//
	// A revocation on an instance with no client pool is `KindUnavailable` — a
	// genuine failure, refusing rather than reporting a clean no-op, because an
	// operator told a revocation succeeded when nothing can revoke stops
	// looking. It reaches the caller through the funnel, so its id comes from
	// `recordFailure` rather than from the outcome row.
	_, rerr := gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: verb.RevokeCredential, TargetRef: "kata:failing",
		Args: mustArgs(t, map[string]any{"reason": "step 41c"}),
	})
	if rerr == nil {
		t.Fatal("41c: a revocation on an instance with no pool succeeded, so this arm is " +
			"not measuring a failure through the funnel")
	}
	if fault.KindOf(rerr).Deliberate() {
		t.Fatalf("41c: the funnel arm produced a DELIBERATE %q, which reaches the caller "+
			"as a result and therefore proves nothing about a failure carrying its id",
			fault.KindOf(rerr))
	}
	funnelID := fault.DecisionIDOf(rerr)
	if funnelID == "" {
		t.Error("41c: a failure recorded through `recordFailure` carries no decision id — " +
			"D202's original defect, on the path D202 fixed")
	}
	if funnelID == id {
		t.Errorf("41c: both arms report the same decision id %q, so one of them is not "+
			"naming its own row", funnelID)
	}

	// **THE REMOTE HALF IS ASSERTED IN `internal/gateway`'s OWN PACKAGE TEST**
	// (`TestToStatusCarriesTheDecisionID`), where `toStatus` is directly
	// reachable. Deliberately not here: proving it from this package would need
	// a test-only EXPORT on the gateway, and an exported symbol whose only
	// caller is a test is the thing `archcheck` exists to object to. The
	// property is one function's, and it is tested where that function lives.

	r := &run{path: path}
	r.detail(t, "D202: a genuine failure now carries decision %s and the row with that "+
		"id explains the same failure; before this the row was written and the caller "+
		"had no key to it", id)
}

// failingDriver fails every call with a genuine (non-deliberate) target error.
//
// **MADE RATHER THAN BORROWED, and that is the fix for a fixture that expired
// twice.** D202's claim is that a FAILURE carries the id of the row explaining
// it, so the step needs any error the taxonomy calls a failure — and picking one
// by kind ties the fixture to a classification that later decisions move
// (`KindConfig` in D201, `KindNotFound` in D211). A driver that returns a target
// error is a failure by construction: `target_error` is what the breaker exists
// for, and nothing will reclassify a vendor blowing up as a decision.
type failingDriver struct{}

func (failingDriver) Kind() string { return kata.Kind }

func (failingDriver) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{{
		Name: "kata.create_issue", Mutating: true,
		Idempotency: connector.IdempotencyNatural,
		Description: "Create an issue, and fail doing it.",
	}}
}

func (failingDriver) Execute(_ context.Context, _ connector.Target, action string,
	_ map[string]any, _ connector.Idempotency) (connector.Result, error) {

	return connector.Result{}, fault.New(fault.KindTargetError, "failingDriver.Execute",
		"the far side blew up performing "+action)
}

func (failingDriver) Query(_ context.Context, _ connector.Target, action string,
	_ map[string]any) (connector.Rows, error) {

	return connector.Rows{}, fault.New(fault.KindTargetError, "failingDriver.Query",
		"the far side blew up performing "+action)
}

func (failingDriver) Health(context.Context, connector.Target) error { return nil }

// Schemas: this double declares no output type, so it ships no schema (D279).
func (failingDriver) Schemas() ([]connector.Schema, error) { return nil, nil }
func (failingDriver) Meter() connector.Meter               { return connector.Meter{} }
