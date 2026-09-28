package acceptance

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// P2's graduation run, declared before it is built (D114).
//
// Same instrument as P1's, and the reason it exists is the same: every step the
// phase must prove is here from the start, and an unbuilt one SKIPS LOUDLY with
// the assertion it will make rather than being absent. An absent step is
// indistinguishable from a step nobody thought of; a skipped one is a commitment
// with a name attached.
//
// WRITING THIS TABLE ALREADY PAID FOR ITSELF TWICE, which is the argument for
// writing it before the code rather than beside it:
//
//   - The deliverables added by D163–D168 had NO exit criteria. Five criteria
//     (8–12) were added to DESIGN §12 P2 as a result. A deliverable with no
//     criterion is a thing the phase builds and never has to prove.
//   - `phaseDecisions` could not see a RANGE citation, so `(D45–D51)` hid D46,
//     D49 and D50 — the three MCP decisions CONTRACTS items 9 and 10 exist for.
//     The guard reported full coverage over a set missing them.

// p2Step is one planned assertion. Same shape as p1Step, deliberately: two
// tables that describe the same kind of thing differently is how the reporting
// drifts.
type p2Step struct {
	n int

	// what is the narration, in the same voice as the P0 and P1 runs.
	what string

	// asserts is what this step will prove. REQUIRED even while unbuilt.
	asserts string

	// covers names the P2 exit criteria from DESIGN §12 this step discharges.
	covers []int

	// decides names the decision records this step proves, where one exists.
	decides []string

	// run is nil until the step is built.
	run func(t *testing.T)
}

// p2ExitCriteria is DESIGN §12 P2's numbered list, restated so the mapping is
// mechanical rather than a claim in a comment.
//
//nolint:gochecknoglobals // immutable table, read once
var p2ExitCriteria = map[int]string{
	1:  "an agent writes a real server-side event to Fullstory through the full stack: mTLS -> policy -> driver -> audit",
	2:  "the same agent reaches Fullstory through BOTH paths, and an action denied on one is not obtainable through the other",
	3:  "a decision record carries agent and trace attribution, in the local audit log; the warehouse is descoped (D169)",
	4:  "one agent targets two different systems (Fullstory and Jira) in one session",
	5:  "a denied action is refused and audited",
	6:  "a retried timed-out command either produces exactly one effect, or is refused with the reason",
	7:  "a tool added to the Fullstory MCP server is not callable and is reported as unvetted",
	8:  "every operator verb derives its repeat-and-escalation response from one registry, and an escalation still acts",
	9:  "Describe writes a chain-carried record naming the shin lenses and anzen rules that shaped what it advertised",
	10: "a Decision field nothing populates fails the run unless ledgered, and the census is watched failing before it is trusted",
	11: "a driver package that does not run the conformance suite fails the build, and a spec_drift condition raises the signal",
	12: "the MCP schema authoring tool cannot mint vendor provenance",
	13: "the README's derived claims are checked against their sources, and a fifth artefact cannot land unnamed",
	14: "every mutation the artefact table says a decision owes exists in the harness, once that decision's code is built",
	15: "nothing in the catalog is synthesised: an action with no description fails the load, and a granted action nothing implements cannot load at all",
	16: "an MCP server on a stateful revision is spoken in full — the session is established, carried and terminated — or refused, never half",
	17: "a credential minted by the client-credentials grant reaches an MCP call, and refreshing the token does not evict the pool",
	18: "a credential that cannot be sent as a header is refused as a local configuration fault, not as an unreachable target",
	19: "a fault attributed to the credential or to Sekizui never opens the target's breaker, and a target fault still does",
	20: "the audit row names the stage that actually refused, and a configuration fault reaches the caller as a result rather than an opaque error",
	21: "a genuine failure names the audit row that explains it, and the id survives to a remote caller",
	22: "a rejected credential is re-established and retried exactly once, bounded and switchable off, and the churn is signalled",
	23: "a failed egress assertion raises tenant_mismatch, and a watching rule sees it",
	24: "the connector contract is stated once — the blueprint's enforced table is derived from the suite, an arm added or removed fails the build, and every kata gap names a real blueprint step",
}

// p2Complete is flipped when P2 graduates. TestP2CompletionIsHonest fails if it
// is true while any step is unbuilt, so "declared" cannot quietly become "done".
const p2Complete = true

// p2StepTable is the declared run.
//
// **A FUNCTION RATHER THAN A VAR, and Go forced it — instructively.** Step 33
// checks the README's step COUNTS against this table, so the step function
// refers to the table and the table refers to the step function. As a package
// variable that is an initialization cycle and the build fails:
//
//	initialization cycle for p2Steps
//	  p2Steps refers to step33TheReadmeCannotDriftFromItsSources
//	  step33TheReadmeCannotDriftFromItsSources refers to p2Steps
//
// **Go's cycle rule is about VARIABLES, not functions** (§15z). Two functions
// may refer to each other freely, because neither has to be fully evaluated
// before the other exists; two variables cannot, because initialization is
// ordered and there is no order that works. Turning the table into a function
// removes the cycle without an `init()`, without a package-level `func` variable
// assigned at start-up, and without the mutable global §6 item 4 bans.
//
// P1's table moved with it. Two tables describing the same kind of thing
// differently is how the reporting drifts, which is the reason p2Step mirrors
// p1Step in the first place.
func p2StepTable() []p2Step {
	return []p2Step{
		// --- the first real connector, end to end (criterion 1) ------------------
		{
			n: 1, covers: []int{1}, decides: []string{"D4"},
			run:  step1AnAgentWritesARealEventToFullstory,
			what: "an agent writes a real server-side event to Fullstory through the full stack",
			asserts: "The phase's headline claim, and the first time any of this touches a system " +
				"nobody here controls. A command from a real gRPC client holding a CA-signed " +
				"certificate traverses mTLS, identity, the ceilings, policy, the resolver, the pool " +
				"and the driver, and the event appears in Fullstory. The audit row carries " +
				"`ExternalRef` so the trail joins to Fullstory's own record of it, which is what " +
				"makes the log checkable against the far side rather than only against itself.",
		},
		{
			n: 2, covers: []int{1}, decides: []string{"D4", "D189", "D190"},
			run:  step2TheFullstoryDriverIsStatelessUnderConcurrentLoad,
			what: "the Fullstory driver is stateless and safe under concurrent multi-tenant load",
			asserts: "D4's claim is that a driver holds no credentials and no per-instance state, " +
				"which is what makes one instance safe to share across tenants — and P2's stated " +
				"INVALIDATION SIGNAL is a Fullstory that needs per-instance state the Driver cannot " +
				"hold. So this is the step that can falsify a decision rather than confirm it. The " +
				"driver's targets are entered into the mixed-tenant property test under distinct " +
				"tenants in one residency, so P0 step 14's 48 concurrent commands exercise them, " +
				"and `make verify` runs it under -race. Cheap to prove at two functions; expensive " +
				"to discover at P4. **THE MECHANISM WAS AMENDED ON BUILDING IT (D189), recorded " +
				"rather than substituted** — the same treatment step 30 got, and for the same " +
				"underlying reason: the declaration predicted a mechanism before the code existed. " +
				"Step 14's targets come from `acceptance.yaml`, loaded once before any step runs, " +
				"and a Fullstory target there needs a `base_url` whose only honest values are the " +
				"real API — which would make the whole suite call Fullstory and need an account, " +
				"breaking D156 — or a fixed local port, which makes the suite depend on a listener " +
				"and fail as a port conflict. A test server's address is not known until it " +
				"starts, and no seam injects one at config load. So the PROPERTY is proven the way " +
				"P1 step 34 proves D140: this step builds its own document, gateway and pool " +
				"against a Fullstory that answers, preserving everything the property needs — the " +
				"real enforcement path, distinct tenants in one residency, every command in flight " +
				"at once, and -race. **A DISTINCT CREDENTIAL PER TENANT**, which the driver's own " +
				"package test cannot have: with one secret the only detectable failure is an EMPTY " +
				"Authorization header, and the catastrophe D4 exists to prevent is tenant B's " +
				"credential on tenant A's request — which SUCCEEDS, audits as successful, and " +
				"writes A's event into B's org. **AND IT CARRIES D190's LOAD-BEARING HALF**: the " +
				"Fullstory driver does NOT implement `connector.ClientBuilder`, because a class 1 " +
				"client is credential-free and there is nothing per-target to build — so the " +
				"registry's MARKER entry is what keeps it pooled, and the pool is what lets " +
				"break-glass cancel a call already in flight. A driver the pool skipped would be " +
				"invisible to `revoke_credential`, which would evict an empty pool and truthfully " +
				"report cancelling nothing. Asserted on the pool's own entry count after real " +
				"traffic, plus an arm that FAILS if the driver ever starts implementing the " +
				"interface, since the optional path would then go unproven.",
		},

		// --- idempotency by declared class (criterion 6, D163) -------------------
		{
			n: 3, covers: []int{6}, decides: []string{"D163", "D182"},
			run:  step3ANoneClassActionRefusesToRetry,
			what: "a `none`-class mutating action refuses to retry, and says why",
			asserts: "Fullstory's `POST /v2/events` documents no idempotency mechanism of any kind, " +
				"so it is class `none` and a retried timeout would duplicate the event. The refusal " +
				"is the guarantee: the command is refused as a RESULT rather than an error (D135), " +
				"carrying a kind a caller can act on, and the reason names the class rather than " +
				"saying `retry not permitted` — an operator who cannot tell WHY cannot fix it. " +
				"NON-VACUITY MATTERS HERE: the arm must show the retry would otherwise have " +
				"happened, or it passes against a call that was never retryable.",
		},
		{
			n: 4, covers: []int{6}, decides: []string{"D163"},
			run:  step4ANaturalClassActionRetriesAndProducesOneEffect,
			what: "a `natural`-class action retries and produces exactly one effect",
			asserts: "Fullstory's `POST /v2/users` is a create-or-update keyed on `uid`, so replaying " +
				"it is harmless and it needs no key at all. The other half of criterion 6, and the " +
				"half that shows the classification is doing work rather than refusing everything: a " +
				"driver that refused every retry would pass step 3 and be useless. Asserted at the " +
				"far side — one user, with the last write's values — not merely by counting local " +
				"calls.",
		},
		{
			n: 5, covers: []int{6}, decides: []string{"D163"},
			run:  step5AMutatingActionWithNoIdempotencyClassFailsTheLoad,
			what: "a mutating action with no declared idempotency class fails the LOAD",
			asserts: "The rule D163 borrows from §4.9a.1's treatment of `mutating`: classified by a " +
				"human, never inferred from a vendor hint, and an absent classification on a " +
				"mutating action is a boot refusal rather than a default. The failure direction is " +
				"the point — a default of `none` would be safe and silent, and a default of anything " +
				"else permits a double-write nobody chose. Boot refusal, so it belongs in " +
				"`make demo-refusals` as well as here.",
		},
		{
			n: 6, covers: []int{6}, decides: []string{"D163"},
			run:  step6EveryIdempotencyClassHasADrivenCase,
			what: "every idempotency class in the vocabulary has a driven case, and the key lands where the class declares",
			asserts: "INVERTED FROM THE FIRST DRAFT, which drove one class and looked for its header " +
				"— proving one case and going stale the moment a sixth class exists. This RANGES OVER " +
				"`IdempotencyClasses()` and FAILS when a declared class has no driven case, so a new " +
				"class arrives with its proof rather than with somebody remembering to extend a test. " +
				"Same structural obligation as TestEveryProviderRunsTheConformanceSuite, and §15q's " +
				"set-predicate-enumerator shape. For each class the assertion is on the WIRE, through " +
				"a fake transport: a `header` class puts the key in the named header, a `field` class " +
				"at the named body path, a `natural` class sends none and retries anyway, a `none` " +
				"class refuses. Asking Sekizui which key it used would compare a value with itself " +
				"(D159).",
		},
		{
			n: 30, covers: []int{6}, decides: []string{"D163", "D186"},
			run:  step30ADeclaredButUnimplementedClassRefuses,
			what: "a declared but unimplemented idempotency class REFUSES at load, and the gap is disclosed",
			asserts: "THE RULE THAT MAKES A SKELETON HONEST (D53): run or refuse, never silently " +
				"succeed at nothing. The maintainer's direction is that the vocabulary is built whole even " +
				"where a class is not fleshed out, so the blueprint can show a connector author the " +
				"full shape — and the failure mode that creates is a class sitting declared and " +
				"inert, which is this codebase's recurring defect wearing a taxonomy. So a target " +
				"selecting an unimplemented class FAILS THE LOAD, naming the class and the phase " +
				"that will build it, and the class carries an init-ledger entry so a boot reports it " +
				"and CONTRACTS 48's expiry guard makes it rot loudly rather than quietly. The " +
				"alternative — leaving the class out until somebody needs it — was considered and " +
				"loses the blueprint's whole value, which is showing the shape before the need. " +
				"**AMENDED ON BUILDING IT (D186), AND THE AMENDMENT IS RECORDED RATHER THAN " +
				"SUBSTITUTED** — the same treatment P1 step 34 gave a declaration that turned out " +
				"to duplicate step 21, because the declaration commits to a PROPERTY and D154's " +
				"failure is a step rewritten to pass. Two clauses do not survive contact: (1) " +
				"\"naming the PHASE that will build it\" — `conditional` has no phase, because no " +
				"connector needs ETag/If-Match, and an entry claiming one would use the exact hole " +
				"TestLedgerEntriesInLivePhasesNameTheirSteps documents in its own comment; (2) the " +
				"INIT-LEDGER ENTRY — the ledger's expiry keys on STEPS BUILT rather than on the " +
				"thing existing, so `ProvenBy: [30]` would make building THIS STEP retire an entry " +
				"that is still true, and the guard would demand deleting a live disclaimer. A " +
				"ledger entry would also make /readyz report DEGRADED because a taxonomy member is " +
				"unfleshed, which is D77's crying-wolf failure aimed at the readiness signal. So " +
				"the disclosure is a boot WARNING, and the EXPIRY already exists and is stronger: " +
				"step 6 ranges the vocabulary and FAILS the moment an implemented class has no " +
				"driven case, so `conditional` becoming real breaks the run until it is exercised.",
		},
		{
			n: 31, covers: []int{6}, decides: []string{"D163", "D186"},
			run:  step31APlacementThatCannotBeSatisfiedRefusesTheCall,
			what: "a class whose placement cannot be satisfied refuses the call rather than sending without the key",
			asserts: "FAIL-CLOSED, and the positive form of step 6 cannot express it. If an action " +
				"declares `header` and the driver cannot place the header — a transport that strips " +
				"it, a class whose configuration names a field the payload has no room for — the " +
				"call must be REFUSED, not sent unkeyed. Sending it would produce exactly the " +
				"condition D163 exists to prevent while every log line reports a successful " +
				"idempotent write, which is the shape §4.7.10 keeps warning about: the operator " +
				"watches the guarantee appear to work. Same failure direction as D163's load refusal. " +
				"**WRITING IT MOVED PLACEMENT OUT OF THE DRIVER AND FOUND A DEFECT (D186).** " +
				"`kata.placeKey` owned placement and wrote the key OVER whatever sat at the " +
				"configured body path, so a caller supplying a field of that name had its value " +
				"silently REPLACED — the upstream then acted on a request the agent did not make, " +
				"and the audit record echoed ours rather than theirs. That IS the declared case " +
				"\"a class whose configuration names a field the payload has no room for\", and " +
				"overwriting is the one resolution that lies about it. Placement and its " +
				"verification now live in `pkg/connector` (D175: placement is governance, not " +
				"transport), so the second driver inherits both rather than reimplementing them " +
				"subtly differently — which is CONTRACTS 63's shape. The stripped-header case " +
				"needs a driver seam to be reachable at all, because a middleware eating a header " +
				"cannot be provoked from outside; `kata.StripKeyPlacement` is that seam, in the " +
				"shape FailKey already established.",
		},

		// --- MCP: the vetted spec and drift (criterion 7) ------------------------
		{
			n: 7, covers: []int{7}, decides: []string{"D45", "D46"},
			run:  step7ActionsDerivesFromTheCommittedSpec,
			what: "`Actions()` derives from the committed spec, never from a live `tools/list`",
			asserts: "D46 makes the vetted spec CONFIGURATION, so what the server currently offers " +
				"cannot change what Sekizui will call. Asserted by divergence: the live server " +
				"advertises a tool the spec does not carry, and `Actions()` is unmoved. This is the " +
				"structural reason drift is detectable at all — a driver that asked the server what " +
				"it could do would have nothing to compare against, and would adopt an attacker's " +
				"answer as its own capability set.",
		},
		{
			n: 8, covers: []int{7}, decides: []string{"D48", "D195"},
			run:  step8AnUnvettedToolIsNotCallableAndIsReportedAsUnvetted,
			what: "a tool added to the MCP server is not callable and is reported as unvetted",
			asserts: "Criterion 7 verbatim. Two arms, because either alone is weak: the call is " +
				"REFUSED, and the condition is REPORTED as unvetted rather than as a missing action " +
				"— an agent told `no such action` learns the wrong thing about a tool that plainly " +
				"exists on the server it is talking to.",
		},
		{
			n: 9, covers: []int{7}, decides: []string{"D48", "D197", "D206"},
			run:  step9DriftSeveritiesAreDistinguished,
			what: "drift severities are distinguished: an unvetted tool is harmless, an inputSchema divergence refuses the target",
			asserts: "D48's whole point, and the definition-of-done says a single `schema mismatch` " +
				"log conflates them. The harmless case is unreachable BY CONSTRUCTION — an unvetted " +
				"tool is not in `Actions()`, so nothing can call it — while an `inputSchema` " +
				"divergence on a VETTED tool means the arguments a human approved are no longer the " +
				"arguments the server will act on, and the target is refused. Asserting both in one " +
				"step because the failure being guarded against is treating them alike.",
		},
		{
			n: 10, covers: []int{7}, decides: []string{"D51"},
			run:  step10OutputSchemaAbsenceIsNeverDrift,
			what: "`outputSchema` absence is never drift, and only vendor-provenance schemas are compared",
			asserts: "Much of the MCP ecosystem publishes no output schema, so absence must read as " +
				"`the system does not describe its output` rather than as divergence. Two arms: a " +
				"tool with no `outputSchema` produces no drift finding at any severity; and a " +
				"`local`-provenance schema is never compared against the live source, because we " +
				"wrote it and the vendor asserts nothing to diverge from. The second arm is what " +
				"stops D168's authoring tool manufacturing false incidents.",
		},
		{
			n: 11, covers: []int{7}, decides: []string{"D49", "D192"},
			run:  step11BootRefusesAnMCPActionContradictingItsTargetRef,
			what: "boot refuses an MCP action name that contradicts its target ref",
			asserts: "CONTRACTS item 10. `{action: \"mcp.fixture.*\", target_ref: \"gitlab-mcp\"}` names " +
				"one server in the action and another in the ref, and must be rejected AT LOAD " +
				"rather than discovered at call time — a grant that cannot mean anything is a grant " +
				"somebody believes they have. Offline, so it blocks the load (D50).",
		},
		{
			n: 12, covers: []int{7}, decides: []string{"D50", "D206"},
			run:  step12OfflineBlocksLoadLiveGatesReadinessPerTarget,
			what: "offline validation blocks the load; live comparison gates readiness per target, not start",
			asserts: "The split D50 draws, and getting it backwards fails in both directions: an " +
				"offline error that only warned would let a contradictory config serve, and a live " +
				"comparison that blocked start would make one unreachable MCP server prevent the " +
				"whole instance from booting — including every target that has nothing to do with " +
				"it. So the offline arm refuses the load, and the live arm leaves the process up " +
				"with THAT TARGET not ready.",
		},
		{
			n: 13, covers: []int{7}, decides: []string{"D48"},
			run:  step13AnUnreachableServerIsNotDrift,
			what: "an unreachable MCP server is an availability condition, never a divergence",
			asserts: "The definition-of-done's own words: conflating them turns a network blip into " +
				"what reads as a security incident. Asserted on the classification rather than the " +
				"log text — the fault kind is an availability kind, no drift finding is recorded, " +
				"and `spec_drift` is NOT raised. The last arm matters most now that D167 makes " +
				"something act on that signal: a rule that quarantines on drift must not fire " +
				"because a server was briefly down.",
		},

		// --- D52 coexistence (criterion 2) --------------------------------------
		{
			n: 14, covers: []int{2}, decides: []string{"D52"},
			run:  step14AnActionDeniedOnOnePathIsNotObtainableThroughTheOther,
			what: "an action denied on one path is not obtainable through the other",
			asserts: "D52's union property, which DESIGN calls a governance claim currently carried " +
				"on faith — Fullstory is the only system where both paths exist, so this is the only " +
				"place it can be tested. Both directions, because they can fail independently: " +
				"denied natively and attempted over MCP, and denied over MCP and attempted natively. " +
				"A one-directional test would pass on a system where the union held by accident in " +
				"the direction somebody happened to check.",
		},
		{
			n: 15, covers: []int{2}, decides: []string{"D52", "D208", "D209", "D210"},
			run:  step15TwoTargetsFrontingOneUpstreamShareOneBudget,
			what: "an MCP target and a native driver fronting one upstream share one limiter budget",
			asserts: "CONTRACTS item 11, promoted to a P2 BLOCKER by the phase restructure: §4.3.4 " +
				"keys the rate limit on TARGET, so two targets fronting one Fullstory org carry " +
				"independent buckets while consuming one quota, and Sekizui under-counts by a factor " +
				"of two. That is also P2's second stated invalidation signal. Asserted by exhausting " +
				"the budget through one path and finding the other already limited — not by reading " +
				"configuration back, which would prove only that a field was set.",
		},

		// --- the multi-tenancy thesis, and refusal (criteria 4, 5) --------------
		{
			n: 16, covers: []int{4}, decides: []string{"D222"},
			run:  step16OneAgentTargetsTwoSystems,
			what: "one agent targets two different systems in one session",
			asserts: "Criterion 4, and the reason the thin Jira driver exists: a SECOND connector " +
				"that is not Fullstory-shaped. One principal, one session, two systems with " +
				"different semantics, each reached under its own grant and its own credential, with " +
				"no leakage of either into the other. The multi-tenancy thesis demonstrated rather " +
				"than asserted.",
		},
		{
			n: 17, covers: []int{5},
			run:  step17ADeniedActionAgainstARealSystemIsRefusedAndAudited,
			what: "a denied action against a real system is refused and audited",
			asserts: "Criterion 5, against a real upstream rather than the kata. The denial reaches " +
				"the caller as a RESULT with a kind (D135, D138), the decision record names the rule " +
				"that refused it, and — the arm worth having — NO REQUEST REACHES FULLSTORY. A " +
				"denial that refuses the response after making the call is a policy engine that " +
				"leaks the action it forbade.",
		},

		// --- attribution, in our own log (criterion 3, D169) --------------------
		{
			n: 18, covers: []int{3}, decides: []string{"D169", "D216"},
			run:  step18ADecisionRecordCarriesAgentAndTraceAttribution,
			what: "a decision record carries agent and trace attribution",
			asserts: "§10.4's attribution stamping, and the half of the old criterion 3 that was ever " +
				"P2's business. The record names the AGENT that acted and the TRACE it belonged to, " +
				"so an auditor can join a governed action to the conversation that produced it. " +
				"Asserted on the record in the LOCAL JSONL sink, which §5.2.2 already makes the " +
				"durability boundary — D169 descopes the warehouse, so this phase writes its own " +
				"logs and the destination question waits for the konbini port.",
		},
		{
			n: 19, covers: []int{3}, decides: []string{"D169"},
			run:  step19AttributionSurvivesADriverThatNeverSeesIt,
			what: "attribution survives a driver that never sees it",
			asserts: "THE ARM WITH TEETH, and it exists because the easy version of step 18 proves " +
				"nothing: attribution is stamped by Sekizui, so a test that sets it and reads it back " +
				"compares a value with itself (D159). What must hold is that a DRIVER cannot strip, " +
				"forge or influence it — the agent identity comes from mTLS and the trace from the " +
				"request context, and neither is reachable through `args`. Asserted by a driver that " +
				"tries: it returns a Result claiming a different agent, and the record is unmoved.",
		},

		// --- the verb registry (criterion 8, D165) ------------------------------
		{
			n: 20, covers: []int{8}, decides: []string{"D158", "D165"},
			run:  step20EveryOperatorVerbObeysD158,
			what: "every operator verb, driven twice, obeys D158's rule",
			asserts: "The step RANGES OVER THE REGISTRY rather than naming verbs, so a verb added " +
				"later is covered by existing rather than by somebody extending this test — which is " +
				"the whole reason D165 makes the rule a mechanism. For each verb: a repeat whose " +
				"POSTCONDITION is already met is confirmed with STATUS_OK naming who got there first " +
				"and when, and a call whose PRECONDITION is false is refused with " +
				"STATUS_INVALID_ARGUMENT. Also asserted: a suspension's confirmation states that it " +
				"lasts only until redeploy, because a bare acknowledgement implies a permanence " +
				"D146 does not give it.",
		},
		{
			n: 21, covers: []int{8}, decides: []string{"D165"},
			run:  step21EscalationIsNotARepeat,
			what: "escalation is not a repeat: quarantine then revoke still acts",
			asserts: "The hazard D158 names and the dangerous half of the registry. An operator " +
				"escalating an already-quarantined target to a full revocation has decided the " +
				"target is not merely misbehaving but COMPROMISED, and swallowing that as `already " +
				"withdrawn` would leave calls running with a credential just declared unsafe. " +
				"Asserted on the effect — cancellations, evictions and teardowns are non-zero — not " +
				"on the status, because a confirmation and an escalation can both return OK.",
		},

		// --- Describe records what shaped it (criterion 9, D166) ----------------
		{
			n: 22, covers: []int{9}, decides: []string{"D166", "D205"},
			run: step22DescribeWritesAChainCarriedRecord,
			what: "Describe writes a chain-carried record naming the lenses and guards that shaped it, " +
				"and refuses to describe a principal the caller may not speak for",
			asserts: "D166 amends D79's audit half. The record carries the principal described, the " +
				"imposed and selected shin lenses, and the anzen rules that filtered anything out; " +
				"it is IN THE HASH CHAIN, which is the property the previous INFO log line did not " +
				"have and CONTRACTS 28 says rotation would lose; and it carries a distinct kind, so " +
				"`every row is an action` survives as a filter. The chain arm is the one with teeth: " +
				"removing the row must break verification, or the reconnaissance trace is still " +
				"deniable.\n\n" +
				"**AND IT CARRIES D205's ARM, WHICH THE MUTATION AUDIT ASKED FOR.** §4.9's " +
				"reconnaissance refusal — naming another principal in a Describe requires a " +
				"may_speak_for grant, because a capability listing is the map of what to try after " +
				"compromising something else — has NO acceptance coverage at all, which the audit " +
				"found the only way it could be found: D205's mutation, breaking the one predicate " +
				"that now answers it, SURVIVED the whole suite. The package tests catch it and " +
				"`make mutate` runs the acceptance suite by design (D161), so what survived is a " +
				"real statement about the phase's evidence rather than about the code. The arm " +
				"drives ONE Describe as a principal with the grant and one without, through the " +
				"catalog the gateway actually holds, so the refusal and the record are proven " +
				"together. **The mutation lands WITH this step** and not before, which is D184's " +
				"rule: a mutation against unbuilt acceptance coverage cannot be applied, so " +
				"requiring it up front would break the run until the phase finished.",
		},
		{
			n: 23, covers: []int{9}, decides: []string{"D166"},
			run:  step23AWithheldCapabilityIsExplained,
			what: "a capability withheld by an anzen guard is explained rather than silently absent",
			asserts: "CONTRACTS 64: `Forbids` returns the guard name and `catalog.go:205` discarded " +
				"it with `_`, so a consumer saw an absence with no explanation. The response names " +
				"the rule that withheld the capability. NON-VACUITY: the same principal, with the " +
				"guard removed, must see the capability — otherwise the step passes against an " +
				"action the grant never allowed, which is the failure mode P1 step 68 hit and caught " +
				"only because `refused_by` said which stage had answered.",
		},

		// --- the population census (criterion 10, D164) -------------------------
		{
			n: 24, covers: []int{10}, decides: []string{"D164"},
			run:  step24TheCensusFailsOnAnUnpopulatedField,
			what: "the Decision population census fails on a deliberately unpopulated field",
			asserts: "SABOTAGE AS A STEP, because the thing under test IS a guard and a guard nobody " +
				"has watched fail is a guard nobody should trust (CONTRACTS 59, and step 28's " +
				"precedent for the globals lint). A field is added to `Decision` that nothing " +
				"populates, and the census must fail naming it; ledgered with a reason, the same " +
				"run must pass. Both arms, because a census that failed on everything would pass the " +
				"first arm and be useless.",
		},

		// --- the connector blueprint (criterion 11, D167) -----------------------
		{
			n: 25, covers: []int{11}, decides: []string{"D167"},
			run:  step25EveryDriverPackageRunsTheConformanceSuite,
			what: "a driver package that does not run the conformance suite fails the build",
			asserts: "D160's guard aimed at `Driver` instead of `Provider`, and mandatory for the " +
				"same reason: a conformance suite nobody is required to run is documentation with a " +
				"test harness attached. The check is deliberately crude — a package under the driver " +
				"tree must mention the suite in its tests — because a crude check that fires is " +
				"worth more than a precise one nobody wrote. Asserted by planting a driver package " +
				"that omits it and requiring the guard to reject it.",
		},
		{
			n: 26, covers: []int{11}, decides: []string{"D167", "D158"},
			run:  step26ADriftConditionRaisesSpecDrift,
			what: "a drift condition raises `spec_drift`, and a watching rule sees it",
			asserts: "Five of the six anzen signals have no producer (CONTRACTS 65), and " +
				"`acceptance.yaml` already WATCHES `spec_drift` with nothing to raise it — a rule " +
				"that boot validates and that can never fire. P2 is the phase that closes it, " +
				"because MCP drift detection is where the condition arises. The signal reaches the " +
				"dispatcher, is keyed on (signal, subject) so a drifting target does not fire a rule " +
				"scoped to a healthy one (D158), and the edge latch RE-ARMS — a latch that never " +
				"releases turns the first incident into permanent deafness, which is worse than the " +
				"flood because nobody notices it.",
		},
		{
			n: 27, covers: []int{11}, decides: []string{"D167", "D222"},
			run:  step27TheThinJiraDriverIsBuiltFromTheBlueprint,
			what: "the thin Jira driver is built from the blueprint alone",
			asserts: "The only honest test of a reusable artefact is its SECOND user. Fullstory " +
				"shapes the blueprint; Jira follows it without consulting the Fullstory driver's " +
				"source, and anything Jira needed that the blueprint did not say is recorded as a " +
				"defect IN THE BLUEPRINT rather than fixed silently in the driver. The step asserts " +
				"the mechanical half — Jira passes `pkg/connector/conformance`, declares an " +
				"idempotency class per action, ships a lens and a preventive guard, and registers a " +
				"payload schema for its query action — and names the prose half as a limit, because " +
				"whether a document was FOLLOWED is not machine-checkable.",
		},

		// --- the schema authoring tool (criterion 12, D168) ---------------------
		{
			n: 28, covers: []int{12}, decides: []string{"D168", "D51"},
			run:  step28TheAuthoringToolCannotMintVendorProvenance,
			what: "the MCP schema authoring tool cannot mint `vendor` provenance for a schema it inferred",
			asserts: "AMENDED BY D287: a schema the server ADVERTISES is copied and marked vendor, " +
				"because it is — and it is drift-checked live against the server's tools/list. " +
				"The whole security argument for the tool. D51 exists to stop a hand-written " +
				"guess masquerading as a vendor guarantee, and a GENERATED guess is the same thing " +
				"with more confidence behind it. Asserted structurally rather than behaviourally " +
				"where possible — the tool has no path that emits `SchemaFromVendor` — plus the " +
				"consequence: a schema it produced is never drift-checked, so it fails as `we " +
				"guessed wrong` rather than as a security incident.",
		},
		// --- information is never lost to a type error (D177) -------------------
		{
			n: 32, covers: []int{3, 5}, decides: []string{"D177", "D178"},
			run:  step32AnUnrepresentableValueLosesNothing,
			what: "an unrepresentable or oversized payload loses nothing silently and cannot flood the WAL",
			asserts: "CONTRACTS 73, and it is a security control rather than a tidy-up. " +
				"`structpb.NewStruct` fails ALL-OR-NOTHING, and the gateway discarded the error " +
				"at three sites — so one awkward value made an effect detail vanish while the " +
				"record still said success, blanked a command result, and DROPPED a query row " +
				"from a result set. Drivers are third-party and echo upstream responses, so the " +
				"shape is attacker-influenceable, and the all-or-nothing behaviour meant control " +
				"of ONE field erased every field including Sekizui's own. Four arms: nothing " +
				"Sekizui wrote is lost; the substitution is NAMED so an unrepresentable field is " +
				"distinguishable from an absent one (D77); the marker carries the TYPE and never " +
				"the value, since an arbitrary struct holding a Secret does not inherit its " +
				"self-redaction; and a driver writing the reserved key cannot forge a clean bill " +
				"of health about itself. Two further arms cover D178's DENIAL OF SERVICE, which is a " +
				"different attack down the same path: the payload reaches the audit detail, the WAL " +
				"and an fsync, so an unbounded driver result is a write amplifier aimed at " +
				"Sekizui's own disk — and a full audit volume fails CLOSED, turning a disk attack " +
				"into a total outage. It is bounded while BUILDING rather than measured afterwards, " +
				"and the truncation is DETERMINISTIC because the object is hashed into the audit " +
				"chain and a record that varies run to run makes VerifyChain report tampering for a " +
				"system working correctly.",
		},

		// --- the entry point, and the one document nothing reads back (D183) ----
		{
			n: 33, covers: []int{13}, decides: []string{"D183", "D191", "D214"},
			run:  step33TheReadmeCannotDriftFromItsSources,
			what: "the README cannot drift from the sources it summarises",
			asserts: "**THE THIRTY-THIRD STEP, ADDED AFTER THE TABLE WAS DECLARED, which is worth " +
				"saying rather than hiding**: D114's rule is that a phase's steps precede its " +
				"code, not that the list can never grow — and the honest record is that this " +
				"deliverable was the maintainer's and arrived mid-phase. A repository with 700KB of " +
				"authoritative Markdown and no entry point is a repository only its author can " +
				"read. What makes a README dangerous rather than merely stale is that it is the " +
				"one document nothing reads back: three of P0's four real defects were a " +
				"documented property with no implementation, and prose drifting from code is " +
				"caught by no tool here. So the README states nothing it is the only source of, " +
				"and this step is the mechanism. EIGHT ARMS, seven of them drift and one of them " +
				"coverage: the phase table is byte-identical to §12.2's; the step counts are the " +
				"step tables' own; the phase called in flight is the one whose completion flag " +
				"is false; the decision count is DECISIONS.md's entry count; every `make` target named is " +
				"defined; every guard named still exists; the short glossary is a SUBSET of §13 " +
				"rather than a second copy; and all four artefacts are named, so a fifth landing " +
				"unmentioned fails — the same shape as an exit criterion with no step. IT FAILS " +
				"WITH THE REPLACEMENT TEXT, because a guard whose remedy is a puzzle is a guard " +
				"people learn to silence, and this one fires during ordinary work. **EXTENDED TO " +
				"CONTRACTS AND TO EVERY DOCUMENT LINK (D191)**, because guarding one document's " +
				"numbers while a sibling drifts unwatched is this decision's own reasoning applied " +
				"inconsistently — and inconsistency in a guard is worse than absence, since it " +
				"implies coverage. An audit found CONTRACTS claiming 35 packages and 366 test " +
				"functions while the tree held 43 and 434, unchecked since P0.",
		},

		// --- the harness checks itself (D184) ----------------------------------
		{
			n: 34, covers: []int{14}, decides: []string{"D184", "D185"},
			run:  step34EveryOwedMutationExists,
			what: "every mutation the artefact table says a decision owes exists in the harness",
			asserts: "**D162 IS BLIND TO A MUTATION THAT WAS NEVER WRITTEN.** Its rule that an " +
				"UNAPPLIED mutation fails catches an anchor that rots when a guard is " +
				"refactored away, and has earned its keep three times — but a guarantee whose " +
				"mutation was never added produces no anchor to go missing, so the harness " +
				"reports full coverage over a short set. THAT WAS LIVE: §12 P2's artefact table " +
				"has named THREE mutations for D163 since it was written and `mutate.py` " +
				"carried two, so `21 caught, 0 survived` was printed over a stated obligation " +
				"nobody had met, for as long as the column existed. The coverage turned out " +
				"fine; the bookkeeping did not, and nothing could tell the difference. So the " +
				"table becomes the source and the harness the copy — the same shape as " +
				"TestP2CoversItsExitCriteria, aimed one layer down. **THE OBLIGATION ATTACHES " +
				"TO THE STEP, NOT TO THE TABLE**, and inverting that would make the guard " +
				"unusable: most rows are for unbuilt steps, a mutation against code that does " +
				"not exist cannot be applied, and D162 makes an unapplied one FAIL — so " +
				"requiring them up front would demand every mutation break the run until its " +
				"phase finished. Once any step deciding a decision is BUILT, that decision's " +
				"owed mutations must exist; until then the obligation is reported rather than " +
				"enforced, because one nobody can see is one nobody is holding. Second arm: the " +
				"obligation set must be NON-EMPTY and at least one decision both built and " +
				"owed, or the first arm compared nothing (CONTRACTS 59 aimed at the guard). " +
				"Also decides D185, `internal/docref`: writing this guard would have been the " +
				"SECOND reader to parse decision citations out of a document, and the first " +
				"one's inability to see a range citation is CONTRACTS 67 — a coverage guard " +
				"reporting success over three unproven decisions. Six functions walked up to " +
				"go.mod, two pairs of them in one package under different names.",
		},

		// --- nothing is synthesised (criterion 15) ------------------------------
		{
			n: 35, covers: []int{15}, decides: []string{"D196"},
			run:  step35NothingInTheCatalogIsSynthesised,
			what: "nothing in the catalog is synthesised: a description comes from the driver or the load fails",
			asserts: "**FOUND BY PROBING `Describe` RATHER THAN BY READING CODE**, which is why " +
				"it is worth a step of its own: a grant naming an action no driver implements " +
				"was advertised to the agent as a capability, and the catalog SYNTHESISED its " +
				"description from the identifier — `mcp.fixture.exfiltrate on fixture-mcp.` in " +
				"the field §4.9 property 2 exists to fill. The maintainer's objection is the general " +
				"one and it is already the house rule three times over: D119 makes a posture " +
				"NIL rather than zero-valued because an empty message reads as an assertion, " +
				"D75 keeps `cannot confirm` apart from `refuted`, D51 pins provenance so a " +
				"schema we wrote cannot pass as one the vendor published. Four arms: an " +
				"action with no description fails the load, with a described one loading as " +
				"the non-vacuity half; every action this build serves — driver actions AND " +
				"governed verbs, ranged rather than sampled — carries one; the advertised " +
				"sentence is the driver's own text rather than the identifier; and an action " +
				"nothing describes cannot be granted at all (D195), because otherwise " +
				"removing the fallback moves the failure from a misleading description to an " +
				"error at Describe time, which is a different bug rather than a fix.",
		},

		// --- the stateful MCP revision, and the grant that pays for it ----------
		{
			n: 36, covers: []int{16}, decides: []string{"D198", "D213"},
			run:  step36AStatefulMCPRevisionIsSpokenInFullOrRefused,
			what: "an MCP server on revision 2025-06-18 is spoken in full, or refused, and never half",
			asserts: "**D192a REFUSED THE STATEFUL REVISIONS AND THE REAL SERVER IS ON ONE.** " +
				"Fullstory's MCP is not yet sessionless, so the choice D192a framed as " +
				"`incompatibility rather than half-served` is now a choice between speaking " +
				"2025-06-18 properly and not reaching the vendor at all — and the maintainer ruled for " +
				"speaking it. The step asserts the WHOLE lifecycle against an httptest " +
				"server, because the failure that matters is a partial one: `initialize` is " +
				"sent and its `Mcp-Session-Id` is carried on every subsequent request, a " +
				"server that mints no session on a revision that requires one is REFUSED " +
				"rather than proceeding sessionless, and the session is TERMINATED on close " +
				"so a withdrawn credential does not leave an authorised session behind. " +
				"**THE SESSION LIVES IN THE POOL, NOT THE DRIVER** — it is §4.7.4 class 3 " +
				"state and `pool.Closer` has always said so, which also means the MCP driver " +
				"gains `connector.ClientBuilder` for this revision and keeps the marker path " +
				"for the sessionless one. The P7 cost is STATED rather than hidden: a session " +
				"is per-process, so a second replica does not hold it, which is the same " +
				"limit CONTRACTS 41 already records for break-glass.",
		},
		{
			n: 37, covers: []int{17}, decides: []string{"D198", "D130", "D131"},
			run:  step37AClientCredentialsTokenReachesAnMCPCall,
			what: "a client-credentials token reaches an MCP call, and a refresh does not evict the pool",
			asserts: "**THE GROUNDWORK, SCOPED TO A PROOF (the maintainer: skeleton it and show we can " +
				"hit it; the API key is the focus).** `oauth-cc://` was built in P1 (D131) " +
				"and is already in the binary's provider slice, so this is configuration plus " +
				"evidence rather than machinery — the client secret chains to `file://` and " +
				"is resolved INNER-FIRST by the cache, so the provider never holds a resolver " +
				"it could point at another secret. The arm with teeth is the second: " +
				"`Version` reports the INNER secret's version and never the token, so a token " +
				"refresh must NOT change the pool key. Getting it backwards evicts every " +
				"pooled client on every refresh — and on the stateful revision above that " +
				"re-runs `initialize` on a timer, destroying server-side state for a " +
				"credential that never rotated, which is the failure §4.7.1's table was " +
				"drawn to prevent and which nothing has yet driven.",
		},

		// --- credential placement is governance (criterion 18) ------------------
		{
			n: 38, covers: []int{18}, decides: []string{"D199"},
			run:  step38AMalformedCredentialIsALocalRefusalNotAnOutage,
			what: "a credential that cannot be a header value is refused locally, and the target is not blamed",
			asserts: "**THE FAILURE THIS PREVENTS IS A MISDIAGNOSIS, WHICH IS WHY IT IS EASY " +
				"TO LEAVE.** A credential file written with `echo` ends in a newline; Go " +
				"refuses to send a header containing one — verified against the standard " +
				"library, which also settles the injection question, since CRLF never " +
				"reaches the wire — and the error arrives as `target_unavailable`. That " +
				"kind is RETRYABLE, so the retry loop runs and the breaker OPENS on a " +
				"vendor that is fine, while every signal an operator can see points at " +
				"them. D48 separates an availability condition from a governance one; " +
				"this is a CONFIGURATION condition wearing the first. Placement moves " +
				"into `pkg/connector` for D186's reason — three drivers hand-rolled the " +
				"same borrow-and-append and none checked the bytes — with an archcheck " +
				"guard so a fourth cannot, and `kata` is not a false positive because it " +
				"sets no header at all. **The breaker arm is why a package test does not " +
				"suffice**: that proves the helper refuses, and only a command through the " +
				"real stack proves the refusal is WIRED and carries a kind the enforcement " +
				"path treats as deliberate. Also asserted: the message names `printf` " +
				"rather than only the fault (D97), and the material appears nowhere in the " +
				"record (D119).",
		},

		// --- whose fault is it (criterion 19) -----------------------------------
		{
			n: 39, covers: []int{19}, decides: []string{"D200", "D141"},
			run:  step39ACredentialFaultDoesNotOpenTheTargetsBreaker,
			what: "a credential fault does not open the target's breaker, and a target fault still does",
			asserts: "**THE TAXONOMY COULD NAME FOUR PARTIES AND EXPRESSED THREE.** Every " +
				"`fault.Kind` says WHAT happened; the breaker and the log level need to " +
				"know ABOUT WHOM, and both derived it from `Deliberate()` — which decides " +
				"D135's WIRE SHAPE and merely correlated with fault. So anything not " +
				"deliberate counted against the TARGET, including a broken local " +
				"configuration and an unreachable token endpoint: `pkg/provider/oauth` " +
				"mapped a token-endpoint outage to `target_unavailable`, so ONE IdP blip " +
				"opened the breaker on every target whose credential chained through it, " +
				"with every log line naming the innocent party. `Kind.Attribution()` adds " +
				"the missing axis (caller / sekizui / target / credential) and " +
				"`ImplicatesTarget()` is what the breaker asks now. Three arms, and the " +
				"third is what stops the first two being vacuous: a credential fault must " +
				"not count, a target error MUST, and a 429 must still not — because a " +
				"rate limit is the clearest evidence there is that the target is alive, " +
				"and D141's rule is the easiest thing to lose while rewriting the rule " +
				"around it.",
		},

		// --- the row names the right stage (criterion 20) -----------------------
		{
			n: 40, covers: []int{20}, decides: []string{"D201", "D152"},
			run:  step40TheAuditRowNamesTheStageThatActuallyRefused,
			what: "the audit row names the stage that actually refused, and a config fault is a result",
			asserts: "**PROVEN WITH A THROWAWAY PROBE BEFORE IT WAS FIXED, and the output is " +
				"the whole argument:** `refused_by=REFUSED_BY_RESIDENCY` beside a reason " +
				"reading `credential resolved to a version OLDER than…`. D152's monotonic " +
				"guard — the control that stops a credential somebody revoked as " +
				"compromised coming back into service — was recorded in the audit log as a " +
				"DATA RESIDENCY refusal, because the resolve stage gated on `Deliberate()` " +
				"as a stand-in for `is this residency`. The control fired correctly and the " +
				"row explained it wrongly, which is worse than either alone: the row is " +
				"what somebody reviews six months later. **And the label it chose is the " +
				"one stage that cannot fire there** — the ceiling is checked before policy " +
				"(D136) and Resolve re-checks it only as defence in depth, off the same " +
				"predicate. Driven through the REAL credential cache rather than a stubbed " +
				"resolver, because the kind under test has to be the one the system " +
				"produces (D159). Four arms: forward resolution works so there is a mark " +
				"to move backwards from; the downgrade is refused and the row names the " +
				"CREDENTIAL; residency keeps its own stage, which is what stops the fix " +
				"being `relabel everything`; and the maintainer's half — a configuration fault " +
				"reaches the caller as a STATUS_MISCONFIGURED result carrying a kind and a " +
				"decision id, rather than an opaque error whose audit row it cannot name.",
		},

		// --- a failure can be named (criterion 21) ------------------------------
		{
			n: 41, covers: []int{21}, decides: []string{"D202", "D211"},
			run:  step41AFailureNamesTheRowThatExplainsIt,
			what: "a genuine failure names the audit row that explains it",
			asserts: "**AND D211 ADDED THE ARM THAT MATTERS MOST HERE.** Reclassifying `not_found` moved this step off the funnel it was written for: its fixture had used an unknown target ref on the reasoning that this was a genuine failure, which stopped being true — so the step now drives BOTH paths, a driver that fails at the far side and a governed verb refused through `recordFailure`, because D202 claims something about each and a fixture can only stand in one. The mutation audit is what said so: moving the fixture reported the ORIGINAL D202 mutation as SURVIVED, coverage having moved rather than grown, which no assertion here could have noticed. D211's taxonomy half — `not_found` deliberate, caller-attributed, carrying STATUS_INVALID_ARGUMENT — is proven in `pkg/fault`'s totality tables and by the driver conformance suite, which is where a classification belongs. **THE ASYMMETRY WAS COMPLETE AND NOBODY HAD LOOKED FOR IT.** Every " +
				"deliberate refusal reaches the caller as a CommandResult carrying its " +
				"decision id (D135); every FAILURE reached it as a transport error " +
				"carrying none — while `recordFailure` called `recorder.Terminal`, which " +
				"RETURNS the id of the row it just wrote, and dropped it with `_`. The row " +
				"existed and the only party who needed it had no key. **Instance " +
				"~seventeen of the recurring class, in its quietest form yet:** a value " +
				"produced, recorded and discarded between the two, with every artefact a " +
				"reviewer inspects present and correct. The maintainer's framing is what makes it " +
				"urgent rather than tidy — at one replica an operator finds the row by " +
				"timestamp, and across replicas under concurrent load the id is the join " +
				"key with no substitute, for callers who are frequently not humans reading " +
				"our logs (a reflex holds `Outcome{Err}`, an agent holds a gRPC error). " +
				"Fixed at the ONE FUNNEL rather than at the ~40 error sites, for D149's " +
				"reason: an error built deep in a driver cannot know the id of a row that " +
				"does not exist yet. Three arms: the condition really is a FAILURE and not " +
				"a refusal (refusals already carried an id, so this is the step's " +
				"non-vacuity); the id names a row that explains THIS failure rather than " +
				"merely being non-empty, since an id pointing at the wrong row sends " +
				"somebody looking with confidence; and the remote half is asserted in " +
				"`internal/gateway`'s own package test, because proving it here would need " +
				"a test-only export and that is what archcheck objects to.",
		},

		// --- re-establish and retry, bounded (criterion 22) ---------------------
		{
			n: 42, covers: []int{22}, decides: []string{"D203", "D204"},
			run:  step42ACredentialIsReestablishedByRetraversingThePath,
			what: "a credential the far side rejects is re-established and the call retried exactly once, through a WHOLE second traversal",
			asserts: "**THE MARKER IS PER-ERROR AND THE EVIDENCE SETTLES IT (D203):** " +
				"`KindUnauthenticated` has five producers with three different correct " +
				"remedies, and for two of them — D199's header-placement refusal and " +
				"D152's downgrade guard — retrying is useless or is what the attacker " +
				"wants. So the step drives all of them and asserts that ONLY a far-side " +
				"401 re-establishes. Then: the retry happens exactly once (a second " +
				"mint returns the same credential); it is gated by D163's idempotency " +
				"class, so a `none`-class action is never silently repeated even though a " +
				"401 usually means the far side did not act; and `reestablish_attempts: 1` " +
				"switches it off entirely, which is expressible because it copies " +
				"`RetryAttempts`'s own escape from the zero-means-unlimited trap. " +
				"**THE SECOND ATTEMPT IS A RE-ENTRY, AND THAT IS WHAT THIS STEP FALSIFIES " +
				"(D204).** A nested attempt at step 5 would skip the runtime revocation " +
				"check, policy, break-glass placement, the limiter and the breaker — so " +
				"three arms suspend the principal, exhaust the budget and open the breaker " +
				"BETWEEN the two attempts, and each must refuse attempt 2 and say it " +
				"refused a re-establishment rather than reporting a call nobody made. " +
				"The audit half needs no new field: two intent rows and two outcome rows " +
				"exist, attempt 2's `causation.parent_id` names attempt 1, and their " +
				"`credential_posture.version` values differ — which is the whole trace. " +
				"**AND `Cache.Invalidate` DROPS THE ENTRY WITHOUT TOUCHING THE VERSION " +
				"MARK**: a downgrade offered after a forced invalidation is still refused " +
				"by D152's guard, because an Invalidate that cleared both would hand that " +
				"guard amnesia on exactly the path an attacker uses to trigger it.",
		},
		{
			n: 44, covers: []int{3}, decides: []string{"D215"},
			run:  step44CallerControlledStringsCannotAmplifyOntoTheAuditDisk,
			what: "a caller-controlled string cannot amplify onto the audit disk",
			asserts: "**D178's ARGUMENT WITH THE OTHER SIDE DONE, found by the maintainer asking whether " +
				"the identity being passed around could be used for nefarious means.** That " +
				"decision bounds a DRIVER's result at 256 KiB because an unbounded one reaches " +
				"the audit detail, the WAL and an fsync; `trace_id` was TrimSpace of a gRPC " +
				"header and `idempotency_key` was whatever fitted in a 4 MiB message, and both " +
				"reach `Decision` at INTENT and at OUTCOME — two fsynced records per command, " +
				"four when a credential is re-established. The caller path is therefore worse " +
				"per command than the driver path and needs no compromised upstream. Refused " +
				"rather than truncated, inverting D178 deliberately: the caller is the party " +
				"at fault and can fix it, and a shortened identifier is a DIFFERENT identifier " +
				"— for an idempotency key, a false deduplication of exactly the kind D163's " +
				"classes exist to prevent. Four arms: the trace ceiling with a " +
				"one-byte-under non-vacuity check, a control character in a trace, and an " +
				"oversized key refused WITHOUT writing the record that would have carried it.",
		},

		// --- the contract is stated ONCE (criterion 24, D218) ------------------
		{
			n: 46, covers: []int{24}, decides: []string{"D218"},
			run:  step46TheConnectorContractIsStatedOnce,
			what: "the connector contract is stated once, and the document is generated from the suite",
			asserts: "CONTRACTS 93: the connector contract was stated in THREE places and no " +
				"two agreed — §5's thirty checkboxes, D167's sentence naming what the " +
				"conformance suite asserts, and the suite's code. D167 named seven and the " +
				"suite made four, and NOTHING COULD TELL, because a sentence in a decision " +
				"has nothing to be checked against. Two more instances (items 91, 92) were " +
				"found the same hour by reading §5 against the tree. The fix is not a " +
				"fourth statement: `conformance.Arms()` is the source and the blueprint's " +
				"table is generated from it (D183's and D214's instrument, aimed at the " +
				"contract). **The first arm guards the SOURCE**, or `Arms()` becomes the " +
				"fourth statement itself — three sets must be equal, DECLARED, CALLED and " +
				"LISTED, and the middle one is what a registry usually lacks (D139): an arm " +
				"that exists and is never invoked passes a declaration check and asserts " +
				"nothing.",
		},

		// --- the second signal this phase PRODUCES (criterion 23, D167) --------
		{
			n: 45, covers: []int{23}, decides: []string{"D167", "D226"},
			run:  step45AFailedEgressAssertionRaisesTenantMismatch,
			what: "a failed egress assertion raises `tenant_mismatch`, and a watching rule sees it",
			asserts: "ADDED MID-PHASE ON THE MAINTAINER'S RULING, moving the signal from P4 to P2 — the " +
				"same reason step 44 was added, that a commitment without a step is a " +
				"commitment nothing checks. **The assertion is not the gap.** §6 mechanism 3 " +
				"fires today and refuses the call; what does not exist is the step from ONE " +
				"refused call to a CONDITION an anzen rule can act on, which is CONTRACTS 65's " +
				"shape exactly: a vocabulary entry a config may already watch, validated at " +
				"boot, permanently inert. The arm with teeth is the SECOND-ORIGIN one — " +
				"`spec_drift` is raised by comparing a surface OFF the command path, and this " +
				"one arises INSIDE the enforcement path while a command is being refused, so " +
				"the two together prove the dispatcher takes a signal from either origin " +
				"rather than from the one shape it was built against. Retires " +
				"`signal:tenant_mismatch` from the init ledger, and the ledger's expiry guard " +
				"is what fails if this step is built and the entry is left behind.",
		},
		{
			n: 43, covers: []int{22}, decides: []string{"D204"},
			run:  step43ChurnIsALevelThatQuarantinesTheTarget,
			what: "a churning target raises credential_churn, is quarantined by a watching rule, and the cost of the extra rows is measured",
			asserts: "**THE SIGNAL IS THE ARM THAT MATTERS**: nothing else can tell a human " +
				"that a target is forcing churn, because a 401 is deliberate and D141 " +
				"correctly counts it as the target being alive — so the breaker never " +
				"opens and the amplification is invisible. **IT IS A LEVEL, NOT AN " +
				"EVENT**, and both wrong wirings are driven: raised per re-establishment " +
				"with no fall it latches forever and masks every later churn, and " +
				"raised-then-fallen it fires on the first LEGITIMATE expiry. So the step " +
				"asserts one expiry does NOT raise it and a churning target DOES, and " +
				"that the level falls when the window empties so the rule re-arms. " +
				"**THE RULE IS LOAD-BEARING RATHER THAN ADVISORY:** `quarantine_target` " +
				"stops resolving, which is where the mint happens, and it is what keeps " +
				"the accepted per-target outage from becoming fleet-wide through the " +
				"shared WAL and the shared secret-manager quota (CONTRACTS 78). The " +
				"withdrawal must survive a restart and must NOT auto-lift. " +
				"**THE COUNTER IS EXPORTED**, because the audit log is local and the " +
				"warehouse is descoped (D169), so the counter is the only thing a " +
				"perimeter can see while the attack is happening — driven through " +
				"`metrics.Registry.WriteTo` rather than read off the struct. " +
				"**AND THE FSYNC COST IS MEASURED, NOT ASSUMED:** the step records a " +
				"re-established command's enforcement-path latency against a plain one, " +
				"so the accepted price of keeping the chatter is a number in the output.",
		},

		// --- the observability half of the definition-of-done -------------------
		{
			n: 29, covers: []int{1, 11},
			run:  step29EveryOutboundCallCarriesASpan,
			what: "every outbound call carries a span with the delegation chain, and RED metrics keyed by target, action and outcome",
			asserts: "THE INIT LEDGER'S `obs:otel` ENTRY LANDS IN P2 AND NOTHING PROVED IT. Found by " +
				"giving P2 a step table: the ledger guard exempts phases with no table, so the entry " +
				"had been sitting unprovable rather than unproven, and creating the table is what " +
				"made it owe evidence. `obs` landed in P0 as logging and redaction; the OTel half " +
				"deliberately waited for a real driver, because a span per outbound call is what it " +
				"exists to record. Three arms, all from the connector definition-of-done's " +
				"observability section: a span per outbound call carrying the delegation chain in " +
				"its attributes; RED metrics keyed `(target, action, outcome)`; and vendor errors " +
				"mapped to `pkg/fault` rather than surfacing as raw upstream strings. The tracer " +
				"provider becomes a spine Component, because Stop must flush pending spans or the " +
				"last trace before a shutdown is the one nobody sees. " +
				"**AND IT INHERITS D216's SHAPE, which is why that decision was settled before this " +
				"step rather than during it.** A bare `trace_id` cannot parent a span, so building " +
				"the first arm against today's field would place every governed call as a detached " +
				"ROOT beside the work that requested it — buildable, green, and misleading. So the " +
				"step also owes: the emitted span is a CHILD of the caller's, taken from the inbound " +
				"span id; the caller's sampling flag is PROPAGATED unchanged rather than overridden, " +
				"because inflating somebody else's telemetry bill is not our decision to make; and " +
				"NO metric carries a trace id as a label, which is unbounded cardinality and would " +
				"take the scrape down.",
		},
	}
}

// TestP2Acceptance runs what exists and reports what does not.
func TestP2Acceptance(t *testing.T) {
	built := 0
	for _, s := range p2StepTable() {
		if s.run != nil {
			built++
		}
	}
	t.Logf("P2 acceptance: %d/%d steps built", built, len(p2StepTable()))

	for _, s := range p2StepTable() {
		t.Run(fmt.Sprintf("%02d_%s", s.n, slug(s.what)), func(t *testing.T) {
			// THE EVIDENCE LEDGER IS OPENED HERE, NOT INSIDE THE STEPS. All
			// P2 steps then cite their audit lines without any of them
			// knowing the ledger exists, which is what made this affordable
			// across a hundred-odd steps written before it did.
			st := evidence.open("P2", s.n, s.what, firstSentence(s.asserts), s.covers, s.decides)
			// A CLEANUP, BECAUSE t.Skipf AND t.Fatalf LEAVE THROUGH
			// runtime.Goexit. Recorded after the call and every skipped step
			// would be reported as having passed.
			t.Cleanup(func() { st.finish(t.Skipped(), t.Failed()) })
			if s.run == nil {
				t.Skipf("NOT BUILT — will assert: %s", s.asserts)
			}
			s.run(t)
		})
	}
}

// TestP2StepsAreWellFormed. A placeholder with no stated assertion is a step
// nobody has thought through, and it will be written to pass rather than to
// prove.
func TestP2StepsAreWellFormed(t *testing.T) {
	seen := map[int]bool{}
	for _, s := range p2StepTable() {
		if s.what == "" || s.asserts == "" {
			t.Errorf("step %d has no narration or no stated assertion", s.n)
		}
		if len(s.covers) == 0 {
			t.Errorf("step %d (%s) discharges no exit criterion; either it is not P2's "+
				"business or the criteria list is missing one", s.n, s.what)
		}
		for _, c := range s.covers {
			if _, ok := p2ExitCriteria[c]; !ok {
				t.Errorf("step %d claims exit criterion %d, which does not exist", s.n, c)
			}
		}
		if seen[s.n] {
			t.Errorf("step number %d is used twice", s.n)
		}
		seen[s.n] = true
	}
}

// TestP2CoversItsExitCriteria — a criterion with no step is a criterion nobody
// will prove. It caught five on its first run, which is how DESIGN §12 P2
// acquired criteria 8-12.
func TestP2CoversItsExitCriteria(t *testing.T) {
	covered := map[int]bool{}
	for _, s := range p2StepTable() {
		for _, c := range s.covers {
			covered[c] = true
		}
	}

	var orphans []string
	for c, desc := range p2ExitCriteria {
		if !covered[c] {
			orphans = append(orphans, fmt.Sprintf("%d: %s", c, desc))
		}
	}
	sort.Strings(orphans)

	if len(orphans) > 0 {
		t.Errorf("%d P2 exit criterion/criteria have no acceptance step:\n  %s\n\n"+
			"Add a step, or move the criterion — an exit criterion nobody proves is a "+
			"phase that graduates on a claim.", len(orphans), strings.Join(orphans, "\n  "))
	}
}

func TestP2CompletionIsHonest(t *testing.T) {
	if !p2Complete {
		return
	}
	var unbuilt []string
	for _, s := range p2StepTable() {
		if s.run == nil {
			unbuilt = append(unbuilt, fmt.Sprintf("%d: %s", s.n, s.what))
		}
	}
	if len(unbuilt) > 0 {
		t.Errorf("P2 is marked complete with %d unbuilt step(s):\n  %s\n\n"+
			"Either build them or move them out of the phase — a step that skips is a "+
			"commitment, and marking the phase done turns it into a claim.",
			len(unbuilt), strings.Join(unbuilt, "\n  "))
	}
}
