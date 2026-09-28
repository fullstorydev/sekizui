package acceptance

import (
	"context"
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

// step17ADeniedActionAgainstARealSystemIsRefusedAndAudited proves criterion 5.
//
// **THE ARM WORTH HAVING IS THE ONE THAT COUNTS REQUESTS AT THE FAR SIDE.** That
// a refusal comes back as a refusal is the easy half, and the kata already
// proves it; what criterion 5 is really asking of a phase whose subject is a
// REAL upstream is whether the forbidden action HAPPENED. A policy engine that
// calls Fullstory and then declines to return the answer has leaked the action
// it forbade, written the event it was refusing, and produced an audit record
// saying it refused — which is worse than no engine at all, because the log now
// asserts something false. The observation has to be made at the upstream (D159:
// assert at the far side, not from our own intent), so this step drives the real
// `fullstory.Driver` against an `httptest` server that records every request it
// receives, and the assertion is on that recording.
//
// **BOTH DENIAL STAGES, BECAUSE THE CALLER CANNOT TELL THEM APART AND THE RECORD
// MUST.** A policy denial and an anzen forbid rule both reach the caller as
// `STATUS_DENIED` with `kind: "denied"` — deliberately, since D138 makes `kind`
// answer RETRYABILITY rather than name a stage, and neither is retryable. So the
// only artefact that can say WHICH ceiling refused is the decision record, and
// criterion 5's "and audited" is the whole weight of the step: `refused_by`
// names the stage (D135) and `matched_rule` names the rule (D96) — `default_deny`
// for the missing grant, `anzen:<name>` for the ceiling.
//
// **THE CONTROL ARM IS NOT OPTIONAL.** "No request reached Fullstory" passes
// perfectly against a fixture nothing could ever have reached — a wrong
// `base_url`, an unregistered driver, a target that fails to resolve. It is the
// vacuous shape this suite has produced twice before (step 14a, and P1 step 68's
// first version passing for the wrong reason), and it is invisible because the
// broken run and the correct run print the same thing. So the last arm sends the
// SAME action the first arm was denied, differing only in the target it names,
// and requires it to arrive.
func step17ADeniedActionAgainstARealSystemIsRefusedAndAudited(t *testing.T) {
	ctx := context.Background()

	// --- a Fullstory that records everything that reaches it ---------------
	var (
		mu      sync.Mutex
		reached []string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		reached = append(reached, req.URL.Path)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"evt-1"}`))
	}))
	defer srv.Close()

	arrived := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), reached...)
	}

	// --- two targets, one granted action, one ceiling ----------------------
	//
	// TWO TARGETS RATHER THAN TWO ACTIONS for the policy arm, because the
	// Fullstory driver implements exactly two actions and the anzen arm needs
	// one of them to be GRANTED. Denying by target keeps the control arm honest
	// in the way that matters: the allowed call and the denied call are the same
	// action, through the same driver, at the same server, and the only variable
	// is the target ref the grant names.
	t.Setenv("SEKIZUI_FS_DENIAL", "fs-token-denial")

	target := func(ref, tenant string) config.TargetSpec {
		return config.TargetSpec{
			Ref: ref, Kind: fullstory.Kind, Tenant: tenant, Residency: "eu",
			BaseURL: srv.URL, CredentialRef: "env://SEKIZUI_FS_DENIAL",
		}
	}
	doc := &config.Document{
		Targets: []config.TargetSpec{target("fs:acme", "acme"), target("fs:other", "other")},
		Grants: []config.GrantSpec{{
			Principal: "agent:triage",
			Allow: []config.CapabilitySpec{
				{Action: fullstory.ActionCreateEvent, TargetRef: "fs:acme"},
				// GRANTED, AND FORBIDDEN BY THE CEILING BELOW. D71's ordering is
				// only observable where the two disagree: a grant nobody wrote
				// would be refused by policy and the anzen arm would pass for the
				// wrong reason, which is the shape that got P1 step 68 rewritten.
				{Action: fullstory.ActionUpsertUser, TargetRef: "fs:acme"},
			},
		}},
		Anzen: []config.AnzenSpec{{
			Name: "no-user-writes", Enabled: true, Mode: "enforce",
			Forbids:   []string{fullstory.ActionUpsertUser},
			AppliesTo: []string{"agent:triage"},
		}},
	}

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer func() { _ = sink.Stop(ctx) }()

	clock := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	tick := func() time.Time {
		clock = clock.Add(time.Millisecond)
		return clock
	}

	// Wired the way the binary wires it — registry, pool, real driver — so the
	// step exercises production's path rather than a fixture's (D107, D190).
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := connector.NewRegistry()
	clientPool := pool.New(registry.Build, quiet)
	if err := registry.Register(fullstory.New(
		fullstory.WithHTTPClient(srv.Client()), fixtureHost(srv.URL),
		fullstory.WithPool(clientPool))); err != nil {
		t.Fatalf("registering the Fullstory driver: %v", err)
	}

	recorder := auditwal.NewRecorder(sink, mustIdentity(t, doc), auditwal.WithClock(tick))
	newGateway := func(guards *anzen.Guards) *gateway.Server {
		return gateway.New(gateway.Config{
			Doc:      doc,
			Pool:     clientPool,
			Policy:   policy.NewGrantEngine(doc, nil),
			Resolver: resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}),
			Drivers:  registry.Drivers(),
			Guards:   guards,
			Recorder: recorder,
			Log:      quiet,
			Now:      tick,
		})
	}
	governed := newGateway(anzen.New(doc.Anzen))

	call := func(t *testing.T, gw *gateway.Server, action, targetRef string) *sekizuiv1.CommandResult {
		t.Helper()
		res, err := gw.Enforce(ctx, assertedIdentity("agent:triage"), &sekizuiv1.Command{
			Action: action, TargetRef: targetRef,
			Args: mustArgs(t, map[string]any{"name": "denied-event", "uid": "u-1"}),
		})
		if err != nil {
			// A DELIBERATE REFUSAL IS A RESULT, NEVER AN ERROR (D135). Reaching
			// this line is itself a finding, so it fails rather than skipping the
			// arms below with a nil result.
			t.Fatalf("%s on %s came back as a transport error rather than a "+
				"refusal result: %v", action, targetRef, err)
		}
		return res
	}

	// A refusal's own record is the LAST one written, and both refusals are
	// terminal, so the tail is the row under test.
	lastRecord := func(t *testing.T) *sekizuiv1.Decision {
		t.Helper()
		records := readLog(t, path)
		if len(records) == 0 {
			t.Fatal("no decision record was written for a refusal — §5.4 makes a " +
				"denial the highest-value row in the log, and the row is absent")
		}
		return records[len(records)-1]
	}

	assertRefused := func(t *testing.T, res *sekizuiv1.CommandResult, rec *sekizuiv1.Decision,
		by sekizuiv1.RefusedBy, rule string) {

		t.Helper()

		// --- the caller's half: a RESULT with a kind (D135, D138) -----------
		if res.GetStatus() != sekizuiv1.Status_STATUS_DENIED {
			t.Errorf("status = %v, want STATUS_DENIED", res.GetStatus())
		}
		if res.GetKind() != "denied" {
			t.Errorf("kind = %q, want \"denied\". D138 puts the taxonomy name beside "+
				"the coarse status precisely so an in-process caller can ask about "+
				"retryability without parsing prose", res.GetKind())
		}
		if res.GetDecisionId() == "" {
			t.Error("the refusal carries no decision id, so a caller told `denied` " +
				"cannot find the row that explains it (D135, D201)")
		}
		if res.GetReason() == "" {
			t.Error("the refusal carries no reason, so an agent learns that it failed " +
				"and not what to ask for instead")
		}

		// --- the record's half: WHICH stage, and WHICH rule -----------------
		if rec.GetVerdict() != sekizuiv1.Verdict_VERDICT_DENY {
			t.Errorf("the record's verdict is %v, want VERDICT_DENY", rec.GetVerdict())
		}
		if rec.GetRefusedBy() != by {
			t.Errorf("the record says refused_by = %v, want %v. The caller cannot tell "+
				"the two ceilings apart — both are `denied` — so a record naming the "+
				"wrong stage sends whoever reads it to the wrong configuration file",
				rec.GetRefusedBy(), by)
		}
		if rec.GetMatchedRule() != rule {
			t.Errorf("the record's matched_rule is %q, want %q. §5.4: an unexplainable "+
				"refusal is not an audit record, it is a log line",
				rec.GetMatchedRule(), rule)
		}
		if rec.GetId() != res.GetDecisionId() {
			t.Errorf("the caller was given decision id %q and the log wrote %q — an id "+
				"that does not join is worse than none",
				res.GetDecisionId(), rec.GetId())
		}
	}

	// --- 17a: NO GRANT NAMES THIS TARGET (REFUSED_BY_POLICY) ----------------
	t.Run("a denial by policy is refused and audited", func(t *testing.T) {
		res := call(t, governed, fullstory.ActionCreateEvent, "fs:other")
		assertRefused(t, res, lastRecord(t), sekizuiv1.RefusedBy_REFUSED_BY_POLICY, "default_deny")
	})

	// --- 17b: A CEILING FORBIDS IT DESPITE THE GRANT (REFUSED_BY_ANZEN) -----
	t.Run("a denial by an anzen ceiling is refused and audited", func(t *testing.T) {
		res := call(t, governed, fullstory.ActionUpsertUser, "fs:acme")
		assertRefused(t, res, lastRecord(t), sekizuiv1.RefusedBy_REFUSED_BY_ANZEN,
			"anzen:no-user-writes")
	})

	// --- 17c: NOTHING REACHED FULLSTORY ------------------------------------
	//
	// **THE ARM CRITERION 5 IS ACTUALLY ABOUT.** Checked before the control arm
	// runs, so the count is unambiguous rather than a subtraction.
	t.Run("no request reached the upstream", func(t *testing.T) {
		if got := arrived(); len(got) != 0 {
			t.Errorf("Fullstory received %v after two refusals. A denial that refuses "+
				"the RESPONSE has already performed the action it forbade, and the "+
				"audit record saying `denied` is then false about the only thing that "+
				"matters", got)
		}
	})

	// --- 17d: AND THE UPSTREAM WAS REACHABLE ALL ALONG ----------------------
	//
	// Two calls, one per refused stage, each removing exactly one variable: the
	// same action against the target the grant DOES name, and the forbidden
	// action against a gateway with no ceiling. Without these, 17c passes
	// against a fixture nothing could ever have reached — and would pass
	// unchanged if the grant were missing, the driver unregistered or the
	// `base_url` wrong.
	t.Run("the same action against a granted target arrives", func(t *testing.T) {
		res := call(t, governed, fullstory.ActionCreateEvent, "fs:acme")
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("the granted call was refused: status %v, reason %q. 17c is then "+
				"vacuous — nothing reached Fullstory because nothing could",
				res.GetStatus(), res.GetReason())
		}
		if got := arrived(); len(got) != 1 || got[0] != "/v2/events" {
			t.Errorf("the upstream saw %v, want exactly one POST to /v2/events", got)
		}
	})

	t.Run("the forbidden action was authorised by a grant", func(t *testing.T) {
		res := call(t, newGateway(anzen.New(nil)), fullstory.ActionUpsertUser, "fs:acme")
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("with the ceiling removed the same command was still refused: "+
				"status %v, reason %q. 17b then proves only that SOMETHING refused "+
				"before policy, not that a ceiling beat a grant (D71)",
				res.GetStatus(), res.GetReason())
		}
		if got := arrived(); len(got) != 2 || got[1] != "/v2/users" {
			t.Errorf("the upstream saw %v, want the granted event followed by one POST "+
				"to /v2/users", got)
		}
	})

	r := &run{path: path}
	r.detail(t, "criterion 5: a denial by policy (`default_deny`) and a denial by an "+
		"anzen ceiling (`anzen:no-user-writes`) each reached the caller as a result "+
		"with kind `denied` and a decision id, each named its stage on the record, "+
		"and NEITHER reached Fullstory — proven against an upstream the same "+
		"configuration then called successfully twice")
}
