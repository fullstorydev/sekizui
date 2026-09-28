package acceptance

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/mistenant"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step26ADriftConditionRaisesSpecDrift proves criterion 11 (D158, D167).
//
// **FIVE OF THE SIX ANZEN SIGNALS HAD NO PRODUCER, AND `acceptance.yaml` ALREADY
// WATCHED ONE OF THEM.** That is CONTRACTS 65 in its most exact form: a rule that
// boot validates, that an operator reads as a control in force, and that can
// never fire. `spec_drift` is the one P2 closes, because MCP drift detection is
// where the condition arises.
//
// **THE PRODUCER EXISTS ALREADY — `internal/drift/watcher.go` CALLS `Observe`.**
// So what this step proves is not that somebody wrote a call, which a grep would
// settle, but the three properties that make the call USEFUL and that a wrong
// implementation would satisfy the grep without having:
//
//  1. a rule watching the signal actually fires when the condition rises,
//  2. the latch is keyed on (signal, SUBJECT) so a drifting target cannot fire a
//     rule scoped to a healthy one (D158), and
//  3. the latch RE-ARMS when the condition clears.
//
// **THE THIRD IS THE ONE WORTH THE MOST.** A latch that never releases turns the
// first incident into permanent deafness — which is worse than the flood it was
// built to prevent, because a flood is visible and silence is not.
//
// **DRIVEN THROUGH THE REAL DISPATCHER AND REAL COMPILED RULES**, not a fake:
// `anzen.New` compiles the same `config.AnzenSpec` shape a deployment writes, and
// `Observe` is the same method the drift watcher calls. What is substituted is
// only the FIRER — the callback that would run a rule's action through the
// enforcement path — because the subject here is which rules fire and when, and
// D18 already owns what happens after.
func step26ADriftConditionRaisesSpecDrift(t *testing.T) {
	r := &run{path: auditPath(t)}
	ctx := context.Background()

	// Two rules watching ONE signal, scoped to DIFFERENT subjects. One target
	// drifts; the other is healthy throughout.
	guards := anzen.New([]config.AnzenSpec{
		{
			Name: "quarantine-the-drifting-one", Enabled: true, Mode: "enforce",
			Watches: "spec_drift", Do: "quarantine_target", Subject: "mcp:drifting",
		},
		{
			Name: "quarantine-the-healthy-one", Enabled: true, Mode: "enforce",
			Watches: "spec_drift", Do: "quarantine_target", Subject: "mcp:healthy",
		},
		// **A SHADOW RULE ON THE SAME SIGNAL AND THE SAME SUBJECT**, because
		// shadow mode exists so an operator can watch what a rule WOULD do before
		// trusting it, and a shadow rule that acted would make the mode
		// meaningless.
		{
			Name: "observe-the-drifting-one", Enabled: true, Mode: "shadow",
			Watches: "spec_drift", Do: "quarantine_target", Subject: "mcp:drifting",
		},
	})

	var mu sync.Mutex
	var fired []string
	dispatch := anzen.NewDispatcher(guards, func(_ context.Context, rule string) error {
		mu.Lock()
		defer mu.Unlock()
		fired = append(fired, rule)
		return nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// The shape the drift watcher publishes: subject -> why. Only actionable
	// severities reach it, which is the vocabulary doing its job — a vendor
	// ADDING a tool is `unvetted` and must not quarantine anything.
	drifting := map[string]string{
		"mcp:drifting": "2 tools withheld: the vetted spec and the live surface disagree",
	}
	healthy := map[string]string{}

	drained := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), fired...)
		fired = nil
		return out
	}

	// --- 26a: THE CONDITION RISES AND THE WATCHING RULE FIRES --------------
	t.Run("a drift condition fires the rule that watches it", func(t *testing.T) {
		got := dispatch.Observe(ctx, "spec_drift", drifting)
		if len(got) != 1 || got[0] != "quarantine-the-drifting-one" {
			t.Fatalf("the rising edge fired %v, want exactly "+
				"[quarantine-the-drifting-one]. A signal nothing acts on is the "+
				"inert-rule state CONTRACTS 65 records", got)
		}
		if ran := drained(); len(ran) != 1 {
			t.Errorf("the firer ran %d time(s), want 1. `Observe` returning a name "+
				"without the action running would report a response nobody made", len(ran))
		}
	})

	// --- 26b: AND NOTHING FIRES FOR THE HEALTHY SUBJECT --------------------
	//
	// **THE ARM WITH TEETH, and D158 records why it exists.** The first version
	// of the dispatcher fired EVERY watcher whenever the signal rose for ANY
	// subject — so one target's problem would quarantine a different, healthy
	// target. That is attacker-reachable: cause one drain to stick and the
	// compliance layer withdraws something else, which is the mechanism becoming
	// the weapon.
	t.Run("a drifting target does not fire a rule scoped to a healthy one", func(t *testing.T) {
		// Already covered by 26a's exact-match assertion, and asserted again from
		// the other direction: the healthy subject's rule must never have run.
		dispatch.Observe(ctx, "spec_drift", drifting)
		for _, name := range drained() {
			if name == "quarantine-the-healthy-one" {
				t.Error("a rule scoped to mcp:healthy fired while only mcp:drifting " +
					"diverged. One target's problem must not withdraw another's")
			}
		}
	})

	// --- 26c: THE LATCH HOLDS, THEN RE-ARMS -------------------------------
	//
	// **THE SIGNALS ARE LEVELS, NOT EVENTS, so firing on the level fires every
	// time anybody looks.** One stuck target becomes a revocation attempt per
	// tick, per replica, for as long as it is stuck — and every one of them is
	// individually correct. The edge is what makes it one response.
	//
	// **AND THE FALL IS WHAT MAKES THE EDGE SAFE.** A latch that never releases
	// is permanent deafness for that subject; the flood at least announces
	// itself.
	t.Run("the latch holds while raised and re-arms when it falls", func(t *testing.T) {
		// STILL RAISED — no second response.
		if got := dispatch.Observe(ctx, "spec_drift", drifting); len(got) != 0 {
			t.Errorf("a still-raised signal fired %v. The condition was already "+
				"responded to; responding again is the flood the latch exists to "+
				"prevent", got)
		}

		// FELL — nothing fires, and the rule is re-armed.
		if got := dispatch.Observe(ctx, "spec_drift", healthy); len(got) != 0 {
			t.Errorf("a FALLING signal fired %v. A rule must act on the condition "+
				"arising, not on it clearing", got)
		}
		_ = drained()

		// ROSE AGAIN — and this is the property the whole arm exists for.
		got := dispatch.Observe(ctx, "spec_drift", drifting)
		if len(got) != 1 || got[0] != "quarantine-the-drifting-one" {
			t.Fatalf("the SECOND incident fired %v, want the rule again. A latch "+
				"that never re-arms turns the first incident into permanent deafness "+
				"for that subject — worse than the flood, because nobody notices it",
				got)
		}
		if ran := drained(); len(ran) != 1 {
			t.Errorf("the firer ran %d time(s) on the second incident, want 1", len(ran))
		}
	})

	// --- 26d: A SHADOW RULE RECORDS AND DOES NOT ACT ----------------------
	t.Run("a shadow rule on the same signal never acts", func(t *testing.T) {
		// Fall, then rise, so every rule watching this subject sees a fresh edge.
		dispatch.Observe(ctx, "spec_drift", healthy)
		_ = drained()
		dispatch.Observe(ctx, "spec_drift", drifting)

		for _, name := range drained() {
			if name == "observe-the-drifting-one" {
				t.Error("a SHADOW rule fired. Shadow exists so an operator can watch " +
					"what a rule would have done before trusting it; one that acted " +
					"would make the mode meaningless")
			}
		}
	})

	// --- 26e: AND A SHADOW RULE DOES NOT SILENCE AN ENFORCING ONE (D225) ---
	//
	// **THIS STEP FOUND A REAL DEFECT WHILE BEING WRITTEN, and this arm is it.**
	// The latch was keyed on (signal, subject) and SHARED BY EVERY RULE watching
	// that pair, so whichever rule the sort reached first set it and the rest saw
	// "already raised" and skipped. `observe-the-drifting-one` sorts before
	// `quarantine-the-drifting-one`, so the shadow rule consumed the edge and the
	// enforcing rule never fired — which is why 26a failed on its first run
	// against code that had been green for two phases.
	//
	// **THE CONSEQUENCE IS THAT SHADOW MODE WAS AN OFF SWITCH.** §4.11.4 item 3
	// tells an operator to watch a rule in shadow before trusting it; doing that
	// beside an existing enforcing rule on the same subject silently disabled the
	// enforcing one. Nothing logged it. The control read as present in every
	// artefact a reviewer inspects.
	//
	// Asserted from BOTH DIRECTIONS, because the passing direction alone would
	// have passed before the fix too: the enforcing rule fires, and the shadow
	// rule does not.
	t.Run("a shadow rule does not consume an enforcing rule's edge", func(t *testing.T) {
		dispatch.Observe(ctx, "spec_drift", healthy)
		_ = drained()

		got := dispatch.Observe(ctx, "spec_drift", drifting)
		if len(got) != 1 || got[0] != "quarantine-the-drifting-one" {
			t.Fatalf("with a shadow rule watching the same signal and subject, the "+
				"rising edge fired %v. A shadow rule that consumes the edge turns "+
				"§4.11.4's recommended practice — observe before trusting — into an "+
				"off switch for the control beside it (D225)", got)
		}
	})

	r.detail(t, "criterion 11: a drift condition raises `spec_drift`, the rule "+
		"watching that SUBJECT fires exactly once, a rule scoped to a healthy target "+
		"does not, a shadow rule records without acting, and the latch re-arms on the "+
		"fall so the second incident is answered as well as the first (D158). Building "+
		"it found D225: the latch was shared across rules, so a shadow rule silently "+
		"disabled the enforcing rule beside it")
}

// step45AFailedEgressAssertionRaisesTenantMismatch proves criterion 23 (D226).
//
// **THE ASSERTION IS NOT THE GAP.** §6 mechanism 3 fires today and refuses the
// call — `Target.Assert` compares the request's tenant against the target's
// immediately before the outbound call, and P0 step 14 and the conformance
// suite both prove it. What did not exist is the step from ONE refused call to a
// CONDITION an anzen rule can act on, which left `tenant_mismatch` a vocabulary
// entry a configuration could watch, boot would validate, and nothing could ever
// raise. That is CONTRACTS 65 exactly, and the init ledger carried the entry
// until this step retired it.
//
// **THE ARM WITH TEETH IS THE SECOND-ORIGIN ONE, and it is why 26 and 45 are a
// pair.** `spec_drift` is produced OFF the command path, by a watcher comparing
// a surface on a ticker. This one arises INSIDE the enforcement path, while a
// command is being refused. Together they prove the dispatcher takes a signal
// from either origin rather than from the one shape it was built against — and
// a single-origin dispatcher would pass step 26 alone.
//
// **THE PRODUCER IS A TALLY AND A WATCHER, NOT A DIRECT PUBLISH, and that is a
// correctness constraint rather than a style.** The dispatcher's firer runs a
// rule's action THROUGH the enforcement path (D18), so publishing synchronously
// from inside `Enforce` would re-enter `Enforce` from within itself. Every
// signal source in this tree polls, for this reason.
func step45AFailedEgressAssertionRaisesTenantMismatch(t *testing.T) {
	r := &run{path: auditPath(t)}
	ctx := context.Background()

	// --- 45a: A REFUSED EGRESS BECOMES A LEVEL ----------------------------
	//
	// The tally is what the enforcement path writes on a mismatch. One occurrence
	// raises it: there is no normal rate for "we nearly sent one customer's
	// credential to another customer", so a threshold above one would be a
	// decision to ignore the first.
	tally := mistenant.New()

	t.Run("one refused egress raises the level", func(t *testing.T) {
		if got := tally.Mistenanted(); len(got) != 0 {
			t.Fatalf("the tally starts non-empty: %v. Every arm below would then "+
				"pass without the enforcement path having written anything", got)
		}
		tally.Record("fs:beta")

		got := tally.Mistenanted()
		if len(got) != 1 || got["fs:beta"] == "" {
			t.Fatalf("after one refused egress the level is %v, want fs:beta raised "+
				"with a reason. A signal with no detail tells an operator a rule "+
				"fired and nothing about why", got)
		}
		if !strings.Contains(got["fs:beta"], "TENANT MISMATCH") {
			t.Errorf("the detail is %q and does not name the condition", got["fs:beta"])
		}
	})

	// --- 45b: AND A WATCHING RULE FIRES, FROM THIS SECOND ORIGIN -----------
	guards := anzen.New([]config.AnzenSpec{
		{
			Name: "quarantine-the-mistenanted", Enabled: true, Mode: "enforce",
			Watches: "tenant_mismatch", Do: "quarantine_target", Subject: "fs:beta",
		},
		{
			Name: "quarantine-a-bystander", Enabled: true, Mode: "enforce",
			Watches: "tenant_mismatch", Do: "quarantine_target", Subject: "fs:alpha",
		},
	})

	var mu sync.Mutex
	var fired []string
	dispatch := anzen.NewDispatcher(guards, func(_ context.Context, rule string) error {
		mu.Lock()
		defer mu.Unlock()
		fired = append(fired, rule)
		return nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	t.Run("the rule watching that target fires and no other does", func(t *testing.T) {
		got := dispatch.Observe(ctx, "tenant_mismatch", tally.Mistenanted())
		if len(got) != 1 || got[0] != "quarantine-the-mistenanted" {
			t.Fatalf("the rising edge fired %v, want exactly "+
				"[quarantine-the-mistenanted]. Before this step the signal had no "+
				"producer at all, so a rule watching it was permanently inert", got)
		}

		mu.Lock()
		defer mu.Unlock()
		for _, name := range fired {
			if name == "quarantine-a-bystander" {
				t.Error("a rule scoped to fs:alpha fired because fs:beta was " +
					"mis-tenanted. One target's defect must not withdraw another's " +
					"(D158)")
			}
		}
	})

	// --- 45c: THE LEVEL DOES NOT DECAY, AND THAT IS DELIBERATE -------------
	//
	// **THE ASYMMETRY WITH `spec_drift` IS THE POINT, not an omission.** A
	// drifting target recovers when the vendor's surface matches its vetted spec
	// again, so that signal falls and step 26 proves the rule re-arms. Nothing
	// about a later successful call says the defect that mis-bound a target has
	// been fixed, so a decay here would be invented evidence — and the invented
	// version is the dangerous direction: it would re-arm a quarantine rule on a
	// target still capable of crossing tenants.
	t.Run("the level persists, and the latch does not fire twice", func(t *testing.T) {
		if got := dispatch.Observe(ctx, "tenant_mismatch", tally.Mistenanted()); len(got) != 0 {
			t.Errorf("a still-raised signal fired %v again. The condition was already "+
				"responded to", got)
		}
		tally.Record("fs:beta")
		if got := tally.Mistenanted(); len(got) != 1 {
			t.Errorf("a second mismatch on the same target changed the level to %v; "+
				"it is one condition, counted for the operator's benefit", got)
		}
	})

	// --- 45d: AND THE ENFORCEMENT PATH ACTUALLY FEEDS THE TALLY ------------
	//
	// **THE MUTATION AUDIT ASKED FOR THIS ARM BY SURVIVING WITHOUT IT.** The arms
	// above prove the tally turns refusals into a level and that the dispatcher
	// fires on it — and every one of them passes with the gateway's escalation
	// DELETED, because none of them drives the enforcement path. `make mutate`
	// reported `D226: a refused egress is never escalated to a condition` as a
	// SURVIVOR, which is precisely the state D162 built it to find: a guarantee
	// the suite accepts and nothing proves.
	//
	// **THE ERROR COMES FROM A DRIVER, WHICH IS WHERE IT COMES FROM IN
	// PRODUCTION.** `Target.Assert` is called by the driver immediately before
	// its outbound call, so a stub returning the wrapped sentinel stands in for
	// exactly that. It cannot be produced through `Enforce` with ordinary inputs —
	// the gateway binds the context tenant from the resolved target, so the two
	// agree by construction. The mismatch is a POOL substitution handing back
	// another tenant's client, which is a bug this assertion exists to catch and
	// not a shape a caller can request.
	t.Run("a mismatch inside the path reaches the tally", func(t *testing.T) {
		pathTally := mistenant.New()

		doc := &config.Document{
			Targets: []config.TargetSpec{{
				Ref: "stub:one", Kind: "stubmis", Tenant: "one", Residency: "eu",
				BaseURL: "https://stub.invalid", CredentialRef: "env://SEKIZUI_ACCEPT_TOK",
			}},
			Grants: []config.GrantSpec{{
				Principal: "agent:triage",
				Allow: []config.CapabilitySpec{
					{Action: "stubmis.write", TargetRef: "stub:one"},
				},
			}},
		}
		t.Setenv("SEKIZUI_ACCEPT_TOK", "tok")

		sink := auditwal.NewJSONLSink(auditPath(t))
		if err := sink.Start(ctx); err != nil {
			t.Fatalf("sink: %v", err)
		}
		defer func() { _ = sink.Stop(ctx) }()

		registry := connector.NewRegistry()
		if err := registry.Register(&mistenantStubDriver{}); err != nil {
			t.Fatalf("registering the stub driver: %v", err)
		}

		clock := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
		tick := func() time.Time { clock = clock.Add(time.Millisecond); return clock }

		srvGW := gateway.New(gateway.Config{
			Doc:      doc,
			Policy:   policy.NewGrantEngine(doc, nil),
			Resolver: resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}),
			Drivers:  registry.Drivers(),
			Guards:   anzen.New(nil),
			// THE SEAM UNDER TEST.
			Mistenant: pathTally,
			Recorder:  auditwal.NewRecorder(sink, mustIdentity(t, doc), auditwal.WithClock(tick)),
			Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
			Now:       tick,
		})

		_, _ = srvGW.Enforce(ctx, assertedIdentity("agent:triage"), &sekizuiv1.Command{
			Action: "stubmis.write", TargetRef: "stub:one",
			Args: mustArgs(t, map[string]any{}),
		})

		got := pathTally.Mistenanted()
		if len(got) != 1 || got["stub:one"] == "" {
			t.Fatalf("after a driver refused egress on a tenant mismatch, the tally "+
				"holds %v — want stub:one raised. The escalation from the enforcement "+
				"path to the condition is what makes `tenant_mismatch` raisable at all; "+
				"without it the signal is a vocabulary entry nothing can produce, and "+
				"every arm above still passes", got)
		}
	})

	r.detail(t, "criterion 23: a refused egress assertion is escalated from ONE call "+
		"to a level, and a watching anzen rule fires on it — the signal's SECOND "+
		"origin, arising inside the enforcement path where `spec_drift` arises off "+
		"it, which is what proves the dispatcher takes either shape. The init-ledger "+
		"entry for `signal:tenant_mismatch` is retired (D226)")
}

// mistenantStubDriver stands in for a driver whose egress assertion refused.
//
// **IT RETURNS THE WRAPPED SENTINEL RATHER THAN CALLING `AssertTenant`, and the
// difference is deliberate.** Calling the real assertion would need a Target
// whose tenant disagrees with the context's, and the gateway binds the context
// tenant FROM the resolved target — so the two agree by construction and the
// mismatch is unreachable from outside. What the arm needs to prove is that the
// GATEWAY escalates the error, not that `Target.Assert` produces it; the latter
// is proven by the conformance suite against every driver.
type mistenantStubDriver struct{}

func (*mistenantStubDriver) Kind() string { return "stubmis" }

func (*mistenantStubDriver) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{{
		Name: "stubmis.write", Mutating: true,
		Idempotency: connector.IdempotencyNone,
		InputSchema: "sekizui://schema/stubmis/write.v1",
		Description: "A write that always refuses egress on a tenant mismatch.",
	}}
}

func (*mistenantStubDriver) Execute(context.Context, connector.Target, string,
	map[string]any, connector.Idempotency) (connector.Result, error) {

	return connector.Result{}, fault.Wrap(fault.KindInternal, "stubmis.Execute",
		"TENANT MISMATCH: refusing egress (§6 mechanism 3)", connector.ErrTenantMismatch)
}

func (*mistenantStubDriver) Query(context.Context, connector.Target, string,
	map[string]any) (connector.Rows, error) {

	return connector.Rows{}, fault.New(fault.KindInvalidArgument, "stubmis.Query",
		"this stub implements no reads")
}

func (*mistenantStubDriver) Health(context.Context, connector.Target) error { return nil }

// Schemas: this double declares no output type, so it ships no schema (D279).
func (*mistenantStubDriver) Schemas() ([]connector.Schema, error) { return nil, nil }
func (*mistenantStubDriver) Meter() connector.Meter               { return connector.Meter{} }
