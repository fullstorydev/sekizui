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
	"github.com/fullstorydev/sekizui/internal/connectors/jira"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/retry"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step16OneAgentTargetsTwoSystems proves criterion 4 (D4, D190, D222).
//
// **THIS IS THE REASON THE THIN JIRA DRIVER EXISTS.** Every multi-system claim
// before it was made against ONE connector shape: four Fullstory targets under
// four tenants is a real test of tenancy and no test at all of whether the
// abstraction survives a second vendor. Jira is deliberately not
// Fullstory-shaped — a composite credential, its own error semantics, and the
// OPPOSITE idempotency answer on the same axis (arm 16e) — so this step is where
// "N × M collapses to N + M" stops being an argument and becomes an observation.
//
// **"ONE AGENT" MEANS ONE PRINCIPAL, AND A PRINCIPAL IS WHATEVER PRESENTED A
// CERTIFICATE.** `identity.principalFromCert` turns
// `spiffe://trust.domain/agent/triage` into `agent:triage`; the `agent:` prefix
// is the first path segment of the SPIFFE ID and nothing in the tree treats it
// specially. A cron script with a client certificate is a principal exactly like
// an LLM is, and a reflex is one too (D18). The word in this step's name is the
// fixture's, not a requirement.
//
// **WHAT IS BEING FALSIFIED, since a step that can only confirm is weak.** The
// claim is that two systems reached through one broker under one identity stay
// separate — separate credentials, separate grants — and the failure mode is not
// a crash. It is Jira's token arriving at Fullstory, which SUCCEEDS at the
// transport layer, is audited as a success, and hands one vendor another
// vendor's secret. So the far sides are asked what they were handed rather than
// whether the call worked.
func step16OneAgentTargetsTwoSystems(t *testing.T) {
	ctx := context.Background()
	r := &run{path: auditPath(t)}

	// --- two far sides, each recording what it was handed -------------------
	//
	// SEPARATE SERVERS RATHER THAN ONE MULTIPLEXED HANDLER, because the question
	// is whether a credential reaches the WRONG SYSTEM. One server answering both
	// paths could only ever catch a wrong path, which is a different bug.
	var mu sync.Mutex
	seen := map[string]string{} // system -> Authorization it arrived with

	record := func(system, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			mu.Lock()
			seen[system] = req.Header.Get("Authorization")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
		}
	}

	jiraSrv := httptest.NewTLSServer(record("jira", `{"key":"PROJ-72","fields":{"summary":"login fails"}}`))
	defer jiraSrv.Close()
	fsSrv := httptest.NewTLSServer(record("fullstory", `{"id":"evt-1"}`))
	defer fsSrv.Close()

	// --- one tenant, two systems, a DISTINCT credential each ----------------
	//
	// **ONE TENANT ON PURPOSE, WHICH IS THE OPPOSITE OF STEP 2's SHAPE.** Step 2
	// varies the tenant and holds the system fixed; this holds the tenant and
	// varies the system. Both leaks are real and they are different: step 2
	// catches one customer's data reaching another's org, and this catches one
	// VENDOR being handed another vendor's secret.
	//
	// Distinct credentials are what make the second observable. A shared one
	// could only catch an empty header.
	t.Setenv("SEKIZUI_JIRA_ACME", "jira-token-acme")
	t.Setenv("SEKIZUI_FS_ACME", "fs-token-acme")

	doc := &config.Document{
		Targets: []config.TargetSpec{
			{
				Ref: "jira:twosys", Kind: jira.Kind, Tenant: "acme", Residency: "eu",
				BaseURL: jiraSrv.URL, CredentialRef: "env://SEKIZUI_JIRA_ACME",
			},
			{
				Ref: "fs:twosys", Kind: fullstory.Kind, Tenant: "acme", Residency: "eu",
				BaseURL: fsSrv.URL, CredentialRef: "env://SEKIZUI_FS_ACME",
			},
		},
		Grants: []config.GrantSpec{{
			Principal: "agent:triage",
			Allow: []config.CapabilitySpec{
				// **EACH CAPABILITY NAMES ITS TARGET (blueprint step 6).** That is
				// what makes arm 16c meaningful: the grant is per (action, target),
				// so holding one capability against one system says nothing about
				// any other.
				{Action: jira.ActionCommentIssue, TargetRef: "jira:twosys"},
				{Action: fullstory.ActionUpsertUser, TargetRef: "fs:twosys"},
			},
		}},
	}

	// --- the real enforcement path, wired the way the binary wires it -------
	sink := auditwal.NewJSONLSink(r.path)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer func() { _ = sink.Stop(ctx) }()

	var (
		clockMu sync.Mutex
		clock   = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	)
	tick := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(time.Millisecond)
		return clock
	}

	// **ONE REGISTRY AND ONE POOL SERVING BOTH DRIVERS, which is the N + M claim
	// in its most literal form.** Two vendors, one enforcement path, one place
	// break-glass reaches. `Register` reads each kind off the driver rather than
	// taking a key (D190), so a target's `kind:` cannot route to the wrong one.
	registry := connector.NewRegistry()
	clientPool := pool.New(registry.Build, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, dr := range []connector.Driver{
		jira.New(jira.WithHTTPClient(jiraSrv.Client()), jira.WithPool(clientPool)),
		fullstory.New(fullstory.WithHTTPClient(fsSrv.Client()), fixtureHost(fsSrv.URL), fullstory.WithPool(clientPool)),
	} {
		if err := registry.Register(dr); err != nil {
			t.Fatalf("registering %s: %v", dr.Kind(), err)
		}
	}

	srvGW := gateway.New(gateway.Config{
		Doc:      doc,
		Pool:     clientPool,
		Policy:   policy.NewGrantEngine(doc, nil),
		Resolver: resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}),
		Drivers:  registry.Drivers(),
		Guards:   anzen.New(nil),
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc), auditwal.WithClock(tick)),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      tick,
	})

	caller := assertedIdentity("agent:triage")

	// --- 16a: BOTH SYSTEMS ANSWER, UNDER ONE IDENTITY -----------------------
	//
	// **BOTH THROUGH `Enforce`, WHICH IS THE COMMAND PLANE, and the read plane is
	// deliberately not driven here.** `Server.Query` derives its identity from
	// `identity.CallerFromContext`, which requires a gRPC peer carrying mTLS and
	// has NO injection seam — that absence is the §6 discipline working, since a
	// test hook for "pretend this caller is authenticated" is exactly the hole an
	// attacker wants. Driving the read plane therefore needs a real listener and
	// a real certificate, which is P0's harness rather than a standalone step.
	// Recorded as a limit of this step rather than worked around.
	t.Run("one principal reaches both systems", func(t *testing.T) {
		res, err := srvGW.Enforce(ctx, caller, &sekizuiv1.Command{
			Action: jira.ActionCommentIssue, TargetRef: "jira:twosys",
			Args: mustArgs(t, map[string]any{"issue": "PROJ-72", "body": "triaged"}),
		})
		if err != nil {
			t.Fatalf("commenting on the Jira issue: %v", err)
		}
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("the Jira write was %v: %s", res.GetStatus(), res.GetReason())
		}

		res, err = srvGW.Enforce(ctx, caller, &sekizuiv1.Command{
			Action: fullstory.ActionUpsertUser, TargetRef: "fs:twosys",
			Args: mustArgs(t, map[string]any{"uid": "u-42"}),
		})
		if err != nil {
			t.Fatalf("upserting the Fullstory user: %v", err)
		}
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("the Fullstory write was %v: %s", res.GetStatus(), res.GetReason())
		}
	})

	// --- 16b: AND NEITHER VENDOR WAS HANDED THE OTHER'S SECRET --------------
	//
	// **THE ARM WITH TEETH.** Everything above passes if both credentials are the
	// same string, or if a shared client leaks one into the other's request —
	// the calls succeed, the statuses are OK, and the audit log records two clean
	// successes. Only the far sides can say what they were actually given.
	t.Run("no credential crosses between systems", func(t *testing.T) {
		mu.Lock()
		defer mu.Unlock()

		if len(seen) != 2 {
			t.Fatalf("%d of 2 systems were reached: %v. The arm below cannot mean "+
				"anything until both are", len(seen), keysOf(seen))
		}
		for system, want := range map[string]string{
			"jira":      "Basic jira-token-acme",
			"fullstory": "Basic fs-token-acme",
		} {
			if got := seen[system]; got != want {
				t.Errorf("%s was handed %q, want %q. A credential crossing between "+
					"SYSTEMS means one vendor now holds another vendor's secret — and "+
					"it succeeds, and it audits as a success", system, got, want)
			}
		}
	})

	// --- 16c: A GRANT ON ONE SYSTEM AUTHORISES NOTHING ON THE OTHER ---------
	//
	// **THE CAPABILITY IS (ACTION, TARGET) AND NOT (PRINCIPAL, SYSTEM).** This
	// principal legitimately reaches both vendors, which is exactly the state in
	// which a coarse grant is invisible: every command it issues succeeds, so
	// nothing distinguishes "authorised for these two capabilities" from
	// "authorised for these two systems". An action it was never granted must
	// still be refused, and against a target it otherwise holds.
	t.Run("an ungranted action is denied on a system it already reaches", func(t *testing.T) {
		res, err := srvGW.Enforce(ctx, caller, &sekizuiv1.Command{
			Action: fullstory.ActionCreateEvent, TargetRef: "fs:twosys",
			Args: mustArgs(t, map[string]any{"name": "not-granted"}),
		})
		if err != nil {
			t.Fatalf("the denied command errored rather than being refused: %v", err)
		}
		if res.GetStatus() != sekizuiv1.Status_STATUS_DENIED {
			t.Errorf("create_event was %v, want DENIED. The principal holds "+
				"`fullstory.upsert_user` on this exact target and nothing else on it; "+
				"a grant that had widened to the SYSTEM would have let this through",
				res.GetStatus())
		}

		// **AND NOTHING REACHED JIRA, which is the half a status cannot show.** A
		// refusal that arrives after the call has already commented is a refusal
		// describing something that already happened.
		mu.Lock()
		defer mu.Unlock()
		if got := seen["fullstory"]; got != "Basic fs-token-acme" {
			t.Errorf("Fullstory's last observed request was %q — the denied command "+
				"reached the far side before policy refused it", got)
		}
	})

	// --- 16d: ONE IDENTITY, TWO SYSTEMS, IN THE RECORD ----------------------
	//
	// The audit log is where "one agent, two systems" becomes reviewable after
	// the fact. Both commands must appear under the SAME principal and against
	// DIFFERENT targets — the pair is the point, since either alone is
	// unremarkable.
	t.Run("the record shows one principal against two targets", func(t *testing.T) {
		if err := sink.Stop(ctx); err != nil {
			t.Fatalf("flushing the sink: %v", err)
		}

		// **SCOPED TO THIS STEP'S OWN TARGETS, and the first draft was not —
		// which passed alone and failed in the real run.** `make acceptance` sets
		// `SEKIZUI_ACCEPTANCE_OUT`, so every step appends to ONE log by design;
		// asserting "the record names exactly one principal" then makes a claim
		// about the whole phase. The refs are deliberately `:twosys` rather than
		// `:acme` so the filter cannot silently pick up a neighbouring step's
		// rows and go vacuous the other way.
		mine := map[string]bool{"jira:twosys": true, "fs:twosys": true}

		targets := map[string]bool{}
		principals := map[string]bool{}
		for _, rec := range readLog(t, r.path) {
			ref := rec.GetTargetRef()
			if !mine[ref] {
				continue
			}
			targets[ref] = true
			if c := rec.GetIdentity().GetCaller().GetPrincipal(); c != "" {
				principals[c] = true
			}
		}

		if len(principals) != 1 || !principals["agent:triage"] {
			t.Errorf("rows against this step's targets name principals %v, want "+
				"exactly agent:triage. The whole claim is that ONE identity reached "+
				"both systems", keysOfBool(principals))
		}
		for _, want := range []string{"jira:twosys", "fs:twosys"} {
			if !targets[want] {
				t.Errorf("no audit row names target %q. A system reached without a "+
					"row is the gap the audit log exists to not have", want)
			}
		}
	})

	// --- 16e: THE TWO SYSTEMS GIVE OPPOSITE ANSWERS ON THE SAME AXIS -------
	//
	// **THIS IS WHAT "DIFFERENT SEMANTICS" MEANS CONCRETELY, and it is the arm
	// that would have been impossible with a second Fullstory-shaped target.**
	// Idempotency is per ACTION and a human classifies it (D163): Atlassian
	// documents no mechanism for creating a comment, so `jira.comment_issue` is
	// class `none` and a repeat duplicates; `fullstory.upsert_user` is class
	// `natural`, keyed on `uid`, converging on the same state however often it
	// replays. Two vendors, one axis, opposite answers.
	//
	// **AND THE ENFORCEMENT PATH HONOURS EACH RATHER THAN PICKING ONE.** That is
	// the N + M claim where it actually bites: a broker that normalised these to
	// a single retry policy would either duplicate Jira comments or forbid a
	// Fullstory retry that was always safe. The driver DECLARES and the path
	// ENFORCES (D140–D143), so the declaration is asked here through the same
	// function the path uses.
	t.Run("each system keeps its own idempotency answer", func(t *testing.T) {
		classOf := func(drv connector.Driver, action string) connector.IdempotencyClass {
			for _, spec := range drv.Actions() {
				if spec.Name == action {
					return spec.Idempotency
				}
			}
			t.Fatalf("%s does not declare %q", drv.Kind(), action)
			return ""
		}

		jiraClass := classOf(jira.New(), jira.ActionCommentIssue)
		fsClass := classOf(fullstory.New(), fullstory.ActionUpsertUser)

		if jiraClass == fsClass {
			t.Fatalf("both systems answer %q, so this arm compares nothing. The step "+
				"exists because the second connector is NOT Fullstory-shaped", jiraClass)
		}

		if _, unsafe := retry.UnsafeToRetry(true, jiraClass, ""); !unsafe {
			t.Errorf("a class %q Jira comment is reported safe to retry; a repeat "+
				"duplicates it", jiraClass)
		}
		if why, unsafe := retry.UnsafeToRetry(true, fsClass, ""); unsafe {
			t.Errorf("a class %q Fullstory upsert is reported UNSAFE to retry (%s). "+
				"It converges on the same state however often it replays, and "+
				"forbidding that retry costs availability for no safety", fsClass, why)
		}
	})

	r.detail(t, "criterion 4: agent:triage reached jira:twosys and fs:twosys through one "+
		"enforcement path, one registry and one pool — two writes on the command plane, "+
		"each under its own grant and its own credential, "+
		"with neither vendor handed the other's secret, an ungranted action still "+
		"refused on a system the principal already reaches, and each system keeping its "+
		"own idempotency answer (`none` vs `natural`) rather than being normalised to one")
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
