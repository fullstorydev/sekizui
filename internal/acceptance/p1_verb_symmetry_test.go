package acceptance

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step68EveryCeilingAppliesToReadsToo proves D155.
//
// FOUND BY TRYING TO BUILD STEP 35. "A non-mutating action retries freely on a
// 429" could not be built: a non-mutating action is refused on Execute, so it
// can only run through Query, and Query had no retry. Pulling that thread found
// the retry was the least of it — Query ran admission, identity and policy, and
// skipped the runtime grant suspension (D146), the anzen guard (D65, D71), the
// withdrawal check (D133), and all three of §4.3.4's controls.
//
// **THE ONE THAT MATTERED:** a throwaway probe revoked a credential with
// `sekizui.revoke_credential` and then read from the target. STATUS_OK, one row.
// A read succeeded with a credential an operator had just declared compromised,
// which is a hole in break-glass rather than a missing nicety — and §4.1.1's own
// words are that "an agent running an unbounded scan across BigQuery is a
// data-exfiltration path".
//
// D18 forbids this in twelve words: "No second code path, no hole in the audit
// log." It was written about reflexes, and the principle is not about reflexes.
func step68EveryCeilingAppliesToReadsToo(t *testing.T) {
	ctx := context.Background()

	// --- 68a: BREAK-GLASS COVERS READS ------------------------------------
	t.Run("a read is refused against a withdrawn target", func(t *testing.T) {
		// newRun takes *testing.T rather than a context: it is the acceptance
		// harness, and it owns its own sink and listener lifecycle via t.Cleanup.
		//nolint:contextcheck // harness manages its own lifecycle via *testing.T
		r := newRun(t)
		if r.localOnly(t, "break-glass state is per-instance") {
			return
		}

		// ONE TARGET, READ BEFORE AND AFTER, so the revocation is the only
		// variable. The first version used a second target for non-vacuity and
		// failed for the wrong reason: only `kata:alpha` is granted for
		// `kata.read`, so the "refused" arm was being refused by POLICY and the
		// test would have passed while proving nothing about withdrawal. The
		// giveaway was `refused_by = UNSPECIFIED` — the field added for exactly
		// this, telling the test which stage had actually answered.
		const target = "kata:alpha"

		before, err := r.as(t, "agent:triage").Query(ctx, &sekizuiv1.QueryRequest{
			Action: "kata.read", TargetRef: target,
		})
		if err != nil || before.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("the target could not be read BEFORE revocation: err=%v status=%v. "+
				"Without this the arm below passes against a Query that refuses "+
				"everything", err, before.GetStatus())
		}

		rev := execute("sekizui.revoke_credential", target, map[string]any{
			"severity": "revoke", "reason": "step 68: proving reads are covered",
		})
		rev.Command.IdempotencyKey = "acc-68-revoke"
		if _, err := r.as(t, "operator:oncall").Execute(ctx, rev); err != nil {
			t.Fatalf("revoking: %v", err)
		}

		after, err := r.as(t, "agent:triage").Query(ctx, &sekizuiv1.QueryRequest{
			Action: "kata.read", TargetRef: target,
		})
		if err != nil {
			t.Fatalf("the refusal arrived as a transport error (%v); every deliberate "+
				"refusal is a result (D135), on this verb too", err)
		}
		if after.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Fatalf("a read returned %d row(s) against a target whose credential was "+
				"revoked as compromised. `revoke_credential` is an operator's statement "+
				"that a credential IS compromised, and a read with a compromised "+
				"credential is an exfiltration path", len(after.GetRows()))
		}
		if len(after.GetRows()) != 0 {
			t.Errorf("refused and still returned %d row(s)", len(after.GetRows()))
		}

		// **WHICH STAGE REFUSED IT** (D135, D155). `CommandResult` has carried
		// this since D135 and `QueryResponse` did not, so a caller told only
		// STATUS_DENIED about a read could not tell a missing grant from a
		// suspended principal from a credential revoked twenty minutes ago —
		// and neither could this test, which is how the mistake above surfaced.
		if got := after.GetRefusedBy(); got != sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL {
			t.Errorf("refused_by = %v, want %v", got, sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL)
		}
	})

	// --- 68a2: THE CEILINGS THEMSELVES, ON A READ ------------------------
	//
	// **ADDED BY THE MUTATION AUDIT, WHICH FOUND THIS SURVIVING.** Breaking
	// Query's call to `ceilings` — leaving the call in place but passing it an
	// empty action and target — was caught by NOTHING. 68a proves the withdrawal
	// check, which sits after resolve and is separate; the AST arm proves the
	// call exists. Neither proves the ceilings actually decide anything on this
	// verb, so a Query that consulted them and ignored the answer looked correct
	// from both sides.
	t.Run("a suspended principal cannot read", func(t *testing.T) {
		//nolint:contextcheck // harness manages its own lifecycle via *testing.T
		r := newRun(t)
		if r.localOnly(t, "suspension state is per-instance") {
			return
		}

		before, err := r.as(t, "agent:global").Query(ctx, &sekizuiv1.QueryRequest{
			Action: "kata.read", TargetRef: "kata:alpha",
		})
		if err != nil || before.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Skipf("agent:global cannot read kata:alpha to begin with (%v, %v), so "+
				"suspending it would prove nothing", err, before.GetStatus())
		}

		susp := execute("sekizui.revoke_grant", "principal:agent:global", map[string]any{
			"reason": "step 68: proving ceilings apply to reads",
		})
		susp.Command.IdempotencyKey = "acc-68-suspend"
		// **THE SUSPENSION MUST ACTUALLY HAVE HAPPENED, and checking the error
		// is not checking that.** D135 makes every deliberate refusal a
		// CommandResult rather than a transport error, so a policy denial arrives
		// with `err == nil` — and the first version of this arm suspended nothing,
		// read successfully, and reported a suspended principal reading. The
		// third time today that this shape has produced a wrong conclusion.
		suspRes, err := r.as(t, "operator:oncall").Execute(ctx, susp)
		if err != nil {
			t.Fatalf("suspending: %v", err)
		}
		if suspRes.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("the suspension itself was refused (%s), so nothing below tests "+
				"what it claims", suspRes.GetResult().GetReason())
		}

		after, err := r.as(t, "agent:global").Query(ctx, &sekizuiv1.QueryRequest{
			Action: "kata.read", TargetRef: "kata:alpha",
		})
		if err != nil {
			t.Fatalf("the refusal arrived as a transport error: %v", err)
		}
		if after.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Error("a SUSPENDED principal read successfully. D146's lever covers half " +
				"the surface it appears to if a suspended caller can still read, and " +
				"reads are where §4.1.1 locates the exfiltration path")
		}
	})

	// --- 68a3: A READ DRAWS ON THE SHARED BUDGET -------------------------
	//
	// **THE ARM THAT WAS MISSING FOR A PHASE, AND ITS ABSENCE IS THE POINT
	// (D253, CONTRACTS 118).** D155 recorded three §4.3.4 controls as fixed on
	// reads. The breaker and the retry landed; `s.rate.Allow` stayed at exactly
	// one call site in the tree, inside `enforceOnce`. So the defect D155
	// describes in its own words — *"a deployment configured for 100/hr sent
	// 100 writes plus unlimited reads at an upstream that counts both"* —
	// remained true, stated as fixed in three documents.
	//
	// Nothing caught it because **step 23 drives `limiter.Local` DIRECTLY**: it
	// proves the algorithm shares a budget fairly and cannot say whether any
	// verb consults it. The harness did not even wire a limiter into the
	// gateway. An algorithm proven in isolation and a path that never calls it
	// is this repository's recurring class with the halves swapped.
	//
	// **ASSERTED ON A READ FOLLOWED BY A WRITE, not on two reads.** Two reads
	// would show reads are metered somehow — possibly by a bucket of their own,
	// which is the thing §4.3.4 exists to prevent, since the upstream meters
	// per instance and counts both. The pair is what shows ONE bucket.
	t.Run("a read draws on the same budget as a write", func(t *testing.T) {
		//nolint:contextcheck // harness manages its own lifecycle via *testing.T
		r := newRun(t)
		if r.localOnly(t, "the budget is this instance's; a live instance has its own") {
			return
		}
		c := r.as(t, "agent:metered")

		// `burst: 1` — the FIRST call of the pair takes the only token.
		read, err := c.Query(ctx, &sekizuiv1.QueryRequest{
			Action: "kata.read", TargetRef: "kata:metered",
		})
		if err != nil {
			t.Fatalf("68a3: the first read failed: %v", err)
		}
		if read.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("68a3: the first read was refused (%s), so it consumed nothing "+
				"and the arm below would pass for the wrong reason", read.GetReason())
		}

		// THE WRITE MUST NOW BE REFUSED. If reads are unmetered the token is
		// still there and this succeeds — which is exactly what happened for a
		// phase.
		wrote, err := c.Execute(ctx, &sekizuiv1.ExecuteRequest{
			Command: &sekizuiv1.Command{
				Action: "kata.create_issue", TargetRef: "kata:metered",
				Args: mustArgs(t, map[string]any{"project": "PROJ", "title": "t"}),
				// **REQUIRED, AND LEAVING IT OUT COST THIS ARM ITS TEETH.**
				// `kata.create_issue` is HEADER class (D163), so without a key
				// it is refused `invalid_argument` whatever the budget says —
				// which meant the write was refused either way and only the
				// KIND distinguished the two worlds. The sabotage is what
				// exposed it: reverting the fix still failed the arm, but on
				// the secondary assertion, with the primary one unreachable.
				IdempotencyKey: "acc-68a3-write",
			},
		})
		if err != nil {
			t.Fatalf("68a3: the write failed as a transport error: %v", err)
		}
		got := wrote.GetResult()
		if got.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Fatal("68a3: a read did not consume the shared budget — the write that " +
				"followed it still had the only token. §4.3.4 keys the budget on the " +
				"TARGET because the upstream meters per instance and counts reads and " +
				"writes alike, so `rate_per_hr` means CALLS. This is D155's unfixed " +
				"third control (CONTRACTS 118)")
		}
		if got.GetKind() != fault.KindRateLimited.String() {
			t.Errorf("68a3: the write was refused as %q, want %q — a refusal that does "+
				"not name the budget sends an operator to read a grant",
				got.GetKind(), fault.KindRateLimited.String())
		}
	})

	// --- 68b: THE STRUCTURAL GUARD FOR THE CLASS -------------------------
	//
	// D155 records that NO existing mechanism catches this: every guard here
	// checks that a declared thing exists and is reached — a caller, a step, a
	// populated field — and none checks that two entry points enforce the SAME
	// SET, because that is a claim about a relationship between paths rather than
	// about any one path.
	//
	// So this arm is that guard, and it is the durable half of the step. The
	// behavioural arm above proves the hole is closed today; this one fails when
	// a third verb arrives, or when somebody removes the call from one of the two.
	assertBothVerbsApplyTheCeilings(t)
	assertEveryAdmitDelegates(t)
}

// targetResolvingVerbs are the entry points that resolve a target and must
// therefore apply the whole enforcement sequence.
//
// NAMED RATHER THAN INFERRED, which is the point: a list somebody has to edit
// is a list a reviewer sees, and inferring "which methods resolve targets"
// would silently cover nothing the day the inference broke.
//
// `CancelJob` is absent deliberately — it resolves no target and reaches no
// driver.
//
// **`makesTheCall` IS NOT BOOKKEEPING — IT IS THE JOB'S ASYMMETRY, AND THIS
// GUARD IS WHAT FORCED IT TO BE WRITTEN DOWN.** The first version of the table
// required every stage of every verb and failed immediately on `StartJob` not
// metering. That was the guard being right about the code and the TABLE being
// wrong about the path: for a synchronous verb one RPC is one outbound call,
// so admitting and metering are the same moment. A job breaks that — one
// `StartJob` produces N calls over time, and a recurrence produces them for
// ever — so the meter belongs to the poll, in `Admit`, and metering at
// submission would take one token for unbounded work.
//
//nolint:gochecknoglobals // immutable table, read once
var targetResolvingVerbs = []verbUnderTest{
	{name: "enforceOnce", makesTheCall: true},
	{name: "Query", makesTheCall: true},

	// ADMITS BUT DOES NOT CALL. The runner does, later and repeatedly.
	{name: "StartJob", makesTheCall: false},

	// THE CALLS SEKIZUI MAKES UNASKED: a poll and a drift comparison, one
	// admission sequence (D249, D311). It was `Admit` — jobGate's — until the
	// drift gate's first version copied only the ceilings and skipped the
	// withdrawal check and the meter; the sequence moved into one function
	// both gates delegate to, and `assertEveryAdmitDelegates` holds them to it.
	{name: "admitUnasked", makesTheCall: true},
}

// verbUnderTest is an entry point and whether it reaches an upstream itself.
type verbUnderTest struct {
	name         string
	makesTheCall bool
}

// enforcementStage is one shared stage of the path, and the fields are what
// the two guards below derive from.
type enforcementStage struct {
	// call is the name every verb must invoke.
	call string

	// when says where in the sequence it runs, so the table reads as the path.
	when string

	// controls are the Server fields this stage OWNS. No verb may touch them
	// directly; reaching one outside a stage is how a fourth abbreviated copy
	// begins.
	controls []string

	// inline marks a stage that is not an extracted function — the verb calls
	// the control's own method by name. `Withdrawn` is the only one, and it is
	// exempt from the control check because the call IS the stage.
	inline bool

	// atCall marks a stage that belongs to the OUTBOUND CALL rather than to
	// admission, so it is owed only by a verb that makes one. See
	// targetResolvingVerbs for why a job is the verb that separates them.
	atCall bool
}

// enforcementStages IS THE ENFORCEMENT PATH, DECLARED ONCE (D253).
//
// **THE TABLE EXISTS BECAUSE THE PREVIOUS INSTRUMENT ENCODED WHAT WE KNEW WHEN
// WE WROTE IT.** D155 extracted `ceilings`, and the guard it left behind asks
// each verb for `ceilings` and `Withdrawn` by name. §4.3.4's meters were never
// extracted, so they were never asked for, so `Query` spent a phase not
// consuming the rate budget while its own comment, DESIGN §12 and CONTRACTS 54
// all said it did — and the job binding was about to inherit the same hole as
// a third copy.
//
// **A GUARD SCOPED TO THE PREVIOUS INSTANCE OF A CLASS DOES NOT COVER THE
// NEXT ONE.** So the table is the spec, both guards derive from it, and the
// second guard below asks the question a name list cannot: not "did you call
// the stages we remembered" but "did you reach an enforcement control outside
// a stage at all".
//
//nolint:gochecknoglobals // immutable table, read once
var enforcementStages = []enforcementStage{
	{
		call: "ceilings", when: "before policy",
		controls: []string{"revocations", "guards"},
	},
	{
		call: "Withdrawn", when: "after resolve",
		controls: []string{"pool"}, inline: true,
	},
	{
		call: "meters", when: "immediately before the call",
		controls: []string{"rate", "breaker"}, atCall: true,
	},
}

// assertNoVerbTouchesAnEnforcementControlDirectly is the half that survives the
// NEXT stage rather than the last one (D253).
//
// **THE INVERSION IS THE WHOLE IDEA.** Asking "did this verb call the stages we
// listed" is answerable only about stages somebody remembered to list. Asking
// "did this verb reach `s.rate`, `s.breaker`, `s.guards` or `s.revocations` at
// all" is answerable about a control nobody has extracted yet — because the
// first thing a fourth abbreviated copy does is touch one of these fields
// inline, exactly as `enforceOnce`'s steps 8a and 8b did for a phase.
//
// `pool` is exempt and the table says so: `Withdrawn` is an inline stage, so
// the verb legitimately writes `s.pool.Withdrawn(...)`, and guard one already
// requires it by name.
func assertNoVerbTouchesAnEnforcementControlDirectly(t *testing.T) {
	t.Helper()

	forbidden := map[string]string{}
	for _, st := range enforcementStages {
		if st.inline {
			continue
		}
		for _, c := range st.controls {
			forbidden[c] = st.call
		}
	}

	// EVERY VERB, INCLUDING ONE THAT MAKES NO CALL. `StartJob` is owed no
	// meter and is still forbidden from touching the limiter: "this stage does
	// not apply to me" and "I may reach its controls myself" are different
	// claims, and only the first one is true.
	verbs := map[string]bool{}
	for _, v := range targetResolvingVerbs {
		verbs[v.name] = true
	}

	for _, name := range []string{"server.go", "job.go"} {
		path := filepath.Join(repoRoot(t), "internal", "gateway", name)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || !verbs[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				// The receiver is `s` on Server and `s := g.s` inside the job
				// gate, so one shape covers both.
				base, ok := sel.X.(*ast.Ident)
				if !ok || base.Name != "s" {
					return true
				}
				stage, isControl := forbidden[sel.Sel.Name]
				if !isControl {
					return true
				}
				t.Errorf("%s touches the enforcement control `s.%s` directly, at %s.\n\n"+
					"That control belongs to the %q stage and must be reached through it. "+
					"An inline copy is how a verb grows an abbreviated enforcement path one "+
					"omission at a time (D155) — and it is how `Query` spent a phase not "+
					"consuming the rate budget while three documents said it did, because "+
					"the meters were inline and therefore invisible to a guard that asks "+
					"for stages by name (CONTRACTS 118).",
					fn.Name.Name, sel.Sel.Name, fset.Position(sel.Pos()), stage)
				return true
			})
		}
	}
}

// assertBothVerbsApplyTheCeilings walks the AST and requires every
// target-resolving entry point to call the shared ceiling sequence (D155).
//
// AN AST WALK RATHER THAN A BEHAVIOURAL SWEEP, for the reason archcheck exists:
// behaviour can only show that a path did the right thing for the cases a test
// thought to try, and the failure mode here is a path nobody thought to try.
func assertBothVerbsApplyTheCeilings(t *testing.T) {
	t.Helper()

	// THE ENTRY POINTS, NAMED. A new verb that resolves a target must be added
	// here — which is the point: a list somebody has to edit is a list a reviewer
	// sees, and the alternative (inferring which methods resolve targets) would
	// silently cover nothing the day the inference broke.
	//
	// **`Enforce` BECAME `enforceOnce` WITH D204, AND THIS GUARD IS WHY THE
	// RENAME IS SAFE.** The exported entry point is now a loop that traverses the
	// path twice; the thing that must apply the ceilings is the traversal. The
	// guard caught the rename immediately rather than silently guarding a method
	// that no longer existed, which is what its own error message promises.
	// **DERIVED FROM THE STAGE TABLE, NOT WRITTEN OUT (D253).** This map used
	// to be a literal naming `ceilings` and `Withdrawn` per verb, and item 118
	// is what that cost: the meters were never extracted into a function, so
	// they were never in the list, so the guard could not ask about them — and
	// `Query` went a phase without consuming the rate budget while three
	// documents said it did. **A list of the stages we remembered cannot ask
	// about the one nobody extracted.** Adding a stage to `enforcementStages`
	// now obliges every verb at build time.
	required := map[string][]string{}
	for _, v := range targetResolvingVerbs {
		for _, st := range enforcementStages {
			if st.atCall && !v.makesTheCall {
				continue
			}
			required[v.name] = append(required[v.name], st.call)
		}
	}

	// TWO FILES, because `StartJob` and the gate adapter live in `job.go` and
	// the guard would otherwise report them MISSING — which it would do
	// loudly, but for the wrong reason. Listed rather than globbed: a new
	// gateway file holding a new verb should have to be added here, since that
	// edit is the one a reviewer needs to see.
	found := map[string]map[string]bool{}
	for _, name := range []string{"server.go", "job.go"} {
		path := filepath.Join(repoRoot(t), "internal", "gateway", name)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			if _, wanted := required[fn.Name.Name]; !wanted {
				continue
			}
			calls := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					calls[sel.Sel.Name] = true
				}
				return true
			})
			found[fn.Name.Name] = calls
		}
	}

	assertReestablishmentReEnters(t)
	assertNoVerbTouchesAnEnforcementControlDirectly(t)

	for verb, needs := range required {
		calls, seen := found[verb]
		if !seen {
			t.Errorf("no method named %q on Server — if a verb was renamed, this guard "+
				"stopped guarding it and says so rather than passing", verb)
			continue
		}
		for _, need := range needs {
			if !calls[need] {
				t.Errorf("%s does not call %q. Every ceiling must apply to every verb "+
					"(D18, D155): Query once ran admission, identity and policy only, and "+
					"a read succeeded against a credential an operator had revoked as "+
					"compromised. Shared code, not copied checks — copying is how the two "+
					"paths drift again, silently", verb, need)
			}
		}
	}
}

// assertReestablishmentReEnters requires the second attempt to be a TRAVERSAL
// (D204).
//
// **THE GUARD IS THE DECISION.** D203 placed the second attempt inside the path
// at step 5 — invalidate, re-resolve, call again — and D204 refused that,
// because a re-attempt from step 5 skips the runtime revocation check, policy,
// break-glass placement, the limiter, the breaker and the intent record. The
// difference between the two designs is not visible in behaviour on a healthy
// deployment: both re-mint and both succeed. It is visible only when something
// changes BETWEEN the attempts, and the behavioural arms drive exactly that.
//
// This is the structural half, and it is the one that survives a refactor
// nobody drove: `Enforce` must reach the far side through `enforceOnce`, and
// must not learn to resolve a target or call a driver itself. An inlined
// resolve-plus-call would pass every behavioural test written against a
// deployment where nothing changes mid-command.
func assertReestablishmentReEnters(t *testing.T) {
	t.Helper()

	path := filepath.Join(repoRoot(t), "internal", "gateway", "reestablish.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing reestablish.go: %v", err)
	}

	var calls map[string]bool
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil || fn.Name.Name != "Enforce" {
			continue
		}
		calls = map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				calls[sel.Sel.Name] = true
			}
			return true
		})
	}
	if calls == nil {
		t.Fatal("no Enforce method in internal/gateway/reestablish.go. The exported " +
			"entry point is the re-establishment loop (D204); if it moved, this guard " +
			"stopped guarding it and says so rather than passing")
	}

	if !calls["enforceOnce"] {
		t.Error("Enforce does not call enforceOnce. The second attempt must be a whole " +
			"traversal of the enforcement path, or it skips every ceiling above step 5 — " +
			"the runtime revocation check (D146), policy, break-glass placement (D129), " +
			"the rate limiter (D143) and the breaker (D141)")
	}
	// **THE INLINE FORM IS WHAT THIS FORBIDS**, named rather than implied. Both
	// of these are how a well-meaning change would reintroduce D203's placement:
	// resolve here and call the driver here, "to avoid the second audit row".
	for _, banned := range []string{"Resolve", "Execute"} {
		if calls[banned] {
			t.Errorf("Enforce calls %q directly. That is D203's placement arriving by "+
				"refactor: a resolve-plus-call in the loop is an ABBREVIATED traversal, "+
				"which is the shape ceilings() records Query growing one omission at a "+
				"time. Call enforceOnce and let the path do its own work", banned)
		}
	}
}

// step35ANonMutatingActionRetriesFreely proves the other half of D113's
// conjunction — and needed D155 fixed before it could be built at all.
//
// Step 21 varies the KEY with mutation held constant, proving the key matters.
// This varies MUTATION with the key held absent, proving the refusal is about
// mutation rather than about retrying. D113's rule is a conjunction —
// `mutating && no key` — and one arm each is what proves a conjunction.
//
// IT COULD NOT BE BUILT BEFORE, and that is how D155 was found: a non-mutating
// action is refused on Execute, so it can only run through Query, and Query had
// no retry. The step was right and the system was missing the behaviour.
func step35ANonMutatingActionRetriesFreely(t *testing.T) {
	// Deliberately reads the same structural guarantee rather than re-driving
	// traffic: retry on the read path is now wired through the same Runner, and
	// what this step adds beyond step 21 is the MUTATION axis. See the note in
	// the step table for why the behavioural half is deferred to the controls
	// work rather than asserted here on a path whose retry has just landed.
	assertReadPathSharesTheRetryRunner(t)
}

// assertReadPathSharesTheRetryRunner is the honest assertion available today.
func assertReadPathSharesTheRetryRunner(t *testing.T) {
	t.Helper()

	path := filepath.Join(repoRoot(t), "internal", "gateway", "server.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing server.go: %v", err)
	}

	var queryBody string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "Query" {
			continue
		}
		start := fset.Position(fn.Pos()).Offset
		end := fset.Position(fn.End()).Offset
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("reading Query: %v", rerr)
		}
		queryBody = string(raw[start:end])
	}
	if queryBody == "" {
		t.Fatal("Query not found")
	}

	// A read is the SAFE thing to retry — D113 refuses unkeyed mutations
	// precisely because reads carry no double-write hazard. So the path that may
	// retry freely was the one with no retry at all, which is backwards.
	if !strings.Contains(queryBody, "s.retry") {
		t.Error("the read path does not use the retry Runner. A read is the one thing " +
			"D113 says is always safe to retry, and it was the path with no retry — " +
			"while Execute, which must often refuse, had it. §4.3.4's controls belong " +
			"on both verbs (D155)")
	}
}

// assertEveryAdmitDelegates — every gate's Admit in internal/gateway calls
// admitUnasked (D311). A third gate that grew its own shorter sequence would
// otherwise be invisible to the table above, which asks for stages by name in
// the functions it lists — the drift gate's first version was exactly that.
func assertEveryAdmitDelegates(t *testing.T) {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "internal", "gateway")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	gates := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || fn.Name.Name != "Admit" {
				continue
			}
			gates++
			delegates := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "admitUnasked" {
					delegates = true
				}
				return true
			})
			if !delegates {
				t.Errorf("%s: an Admit that does not delegate to admitUnasked — a gate with its own "+
					"admission sequence is how the drift gate first skipped the withdrawal check and "+
					"the meter (D155, D311)", fset.Position(fn.Pos()))
			}
		}
	}
	if gates < 2 {
		t.Errorf("found %d Admit method(s) in internal/gateway; the poll and drift gates are two — "+
			"this check is looking at nothing", gates)
	}
}
