package acceptance

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// P3's graduation run, declared before it is built (D114).
//
// Same instrument as P1's and P2's, for the same reason: every step the phase
// must prove is here from the start, and an unbuilt one SKIPS LOUDLY with the
// assertion it will make rather than being absent. An absent step is
// indistinguishable from a step nobody thought of; a skipped one is a
// commitment with a name attached.
//
// WRITING THIS TABLE PAID FOR ITSELF BEFORE A LINE OF KYUUSHIN EXISTED, which is
// the third time in three phases:
//
//   - **§12 P3's deliverable list still specified a dependency D173 ruled out.**
//     It read "`cursor` store (embedded Bolt)", and D173 — which cites §12 P3 in
//     its own reference line — refused an embedded database and took the
//     atomic-file pattern instead, a pattern that has since landed as
//     `internal/atomicfile` with all three of its callers converted. A session
//     following HANDOFF's reading order reaches that line fourth and would have
//     added the dependency. D240 settles it: the file store is v1's, and Bolt is
//     an OPTIONAL later-phase store rather than a deleted idea.
//   - **`pkg/connector.Source.Poll` mandated what D174 refused to mandate.** Its
//     doc comment said implementations MUST be resumable, citing this phase's
//     exit criterion 3 — and D174 is titled "RESUMABILITY IS NOT ASSUMED" and
//     restated criterion 6 away from exactly that wording. The comment is on the
//     PUBLISHED surface, so the population it misleads is D35's out-of-tree
//     driver author, which is this repository's recurring class in its usual
//     shape. D241 settles it.
//
// Neither was found by a guard. Both were found by writing down what the phase
// owes and reading what the phase already says.

// p3Step is one planned assertion. Same shape as p1Step and p2Step,
// deliberately: two tables that describe the same kind of thing differently is
// how the reporting drifts.
type p3Step struct {
	n int

	// what is the narration, in the same voice as the P0, P1 and P2 runs.
	what string

	// asserts is what this step will prove. REQUIRED even while unbuilt.
	asserts string

	// covers names the P3 exit criteria from DESIGN §12 this step discharges.
	covers []int

	// decides names the decision records this step proves, where one exists.
	decides []string

	// run is nil until the step is built.
	run func(t *testing.T)
}

// p3ExitCriteria is DESIGN §12 P3's numbered list, restated so the mapping is
// mechanical rather than a claim in a comment.
//
//nolint:gochecknoglobals // immutable table, read once
var p3ExitCriteria = map[int]string{
	1:  "Fullstory sessions polled -> translated -> published -> consumed (D265)",
	2:  "causation chain and depth present and correct on every envelope",
	3:  "restart resumes from cursor with no duplicates and no gaps across a kill -9",
	4:  "envelope round-trips protobuf <-> protojson losslessly",
	5:  "the stage-monotonicity checker rejects a deliberately cyclic subject config at boot (D21)",
	6:  "an interrupted poll either recovers by the connector's declared policy, or records a gap (D174)",
	7:  "a scan that would exceed the capability's max_bytes is refused before it runs (CONTRACTS 70)",
	8:  "one reflex rule closes the loop end to end, in shadow mode (D172)",
	9:  "an envelope produced by a REAL connector is lensed on the bus",
	10: "sekizui-mcpspec calls the tools itself, and an operator selects them from tools/list",
	11: "a Fullstory slice, taken only where P3's own criteria need it (D239)",
	12: "the events we wrote are read back from the session, and it closes CONTRACTS 102",
	13: "guidance on using agentic session review ships with it",

	// --- THE RE-PLAN (D247, D248). Appended from 14 rather than renumbered,
	// because D239 cites criteria 9-13 and renumbering a list other documents
	// cite is the defect this project keeps finding.
	14: "a caller asks for a JOB and receives its results as lensed envelopes",
	15: "finished, failed and still-running are distinguishable from the audit log",
	16: "cancelling a job stops the WORK, not just the subscription",
	17: "a job cannot outlive its authorisation: a suspended grant or a revoked credential stops it",
	18: "a job is bounded before it runs, and this is the path where the CALLER chooses the size",
	19: "an enrichment reflex shapes a result on the way back, and an actuating one cannot",

	// --- D259, 2026-09-22. Appended for the same reason 14-19 were.
	20: "a subscription is scoped to the targets it names, as a command is",
	21: "an armed rule is bounded, and a rule never reads as bounded when it is not",
}

// p3Complete is flipped when P3 graduates. TestP3CompletionIsHonest fails if it
// is true while any step is unbuilt, so "declared" cannot quietly become "done"
// (D114).
const p3Complete = true

// p3StepTable is P3's graduation run, declared before it is built.
//
// A FUNCTION RATHER THAN A VAR, matching P1's and P2's: Go's initialization-cycle
// rule applies to variables and not to functions (§15z), and the cross-phase
// guards refer to every table.
func p3StepTable() []p3Step {
	return []p3Step{
		// --- the cursor, which is the state the whole plane rests on ------------
		{
			n: 1, covers: []int{3}, decides: []string{"D173", "D240"},
			what: "a cursor survives a kill -9 and the poll resumes from it",
			asserts: "D173's file store, proven the way step 14 proves `-mode=ingest` polls: a REAL " +
				"process, a REAL SIGKILL, and a second process over the same directory that polls " +
				"from what the first committed and publishes nothing again. (This once said \"the " +
				"way the withdrawal store was (P1 step 63)\"; step 63 used neither a process nor a " +
				"kill.) Not a unit test against an interface — the failure this guards is the one " +
				"D145 found in break-glass, where a durability claim was true within one process " +
				"lifetime. THE FAILURE DIRECTIONS ARE D240's READING OF D150: a store that cannot " +
				"LOAD fails the BOOT, because an absent cursor is every source replayed from the " +
				"beginning; a store that cannot WRITE fails the POLL before anything is published, " +
				"and the next tick retries rather than skips. A kill cannot be aimed between two " +
				"envelopes without a crash hook in the production binary, which is attack surface; " +
				"the mid-publish state is staged in steps 3, 11 and 12. The assertions are on the " +
				"store's interface, never its file (D240)",
			run: p3Step1,
		},
		{
			n: 2, covers: []int{3}, decides: []string{"D275", "D293"},
			what: "the cursor advances only after the envelope is published and marked",
			asserts: "ORDERING IS THE WHOLE PROPERTY and it is the one a reasonable implementation " +
				"gets backwards, because advancing first is what the code reads like. **\"DURABLE\" " +
				"WAS THE WRONG WORD (D293):** nothing durable holds an envelope — the bus is " +
				"at-most-once (D24) — so what the cursor waits for is the envelope PUBLISHED and " +
				"the fsynced progress mark covering it (D275). Commit before that and a crash " +
				"loses rows nothing can reconstruct — D170's point that you cannot deduplicate " +
				"your way to data you never fetched. Proven by faults injected between the " +
				"writes: a failed mark stops the poll uncommitted, a failed commit leaves every " +
				"mark, and an ordinary poll's commit is its last write",
			run: p3Step2,
		},
		{
			n: 3, covers: []int{3}, decides: []string{"D170", "D240"},
			what: "a restart does not re-deliver, and the dedupe record is ours rather than the audit log's",
			asserts: "D170 decomposed exit criterion 3 and only half of it is somebody else's " +
				"problem: NO DUPLICATES is answerable from our own side. The record is the " +
				"attempt's at-risk ids and the mark covering them, in the CURSOR STORE, bounded " +
				"to the uncommitted window and deleted on commit (D240 — D170's \"embedded Bolt\" " +
				"was superseded by D173). A restart over a window whose every id is marked " +
				"re-reads it and delivers nothing, and the log records a recovery, not the events " +
				"again. A source that cannot re-read, stopped with everything published, writes " +
				"no gap: both were false records until this step found them. The import-graph " +
				"half — the poller may not reach the audit log's code — is step 42a's arm, " +
				"transitive, and not repeated here",
			run: p3Step3,
		},

		// --- the afferent path, end to end (criterion 1) -------------------------
		{
			n: 4, covers: []int{1, 11}, decides: []string{"D24", "D265"},
			what: "Fullstory sessions are polled, translated, published, and consumed",
			asserts: "**FULLSTORY, NOT JIRA (D265)**, and inside criterion 11's slice: the poll is " +
				"`GET /sessions/v2` for a configured user — a READ, admitted against the live org " +
				"by D217 and still gated under `make acceptance-live` because reaching out is an " +
				"intent — with a fixture server for the ordinary run. The shape is INHERITED from " +
				"`lexicon/Fullstory.js`'s `listSessions`, as P2's write shapes were, and the user " +
				"polled is the uid P2 step 4 upserts; no `since` parameter, so the cursor is the " +
				"highest `createdTime` and dedupe is by `sessionId`. " +
				"THE PHASE'S HEADLINE, and it is the first time anything external fills the bus " +
				"— the only producer today is `PublishForTest`, named that way so it could not be " +
				"mistaken for a supported entry point. The chain is real at every link: a real " +
				"poll through the governed path, a real translation to a CloudEvents envelope, a " +
				"real publish, and a subscriber that receives over the subscribe stream P0 step 16 " +
				"already drives over mTLS. D24's at-most-once is what the delivery half claims and " +
				"step 6 is where the honesty of that claim is asserted",
			run: p3Step4,
		},
		{
			n: 5, covers: []int{1}, decides: []string{"D18", "D155", "D249", "D266"},
			what: "a scheduled run is governed by the same path a caller's job is, not a side door",
			asserts: "D18's twelve words — `No second code path, no hole in the audit log` — aimed " +
				"at the afferent plane before it has a chance to grow one. D155 is why this is a " +
				"step rather than an assumption: `Query` grew an abbreviated copy of the " +
				"enforcement path one omission at a time, and each omission was invisible because " +
				"the shorter path READ like a shorter version rather than a weaker one. A poller " +
				"is the easiest place in the system to make that mistake, because it has no caller " +
				"to authorise and the temptation is to skip identity entirely. So: the poll " +
				"resolves a target through the resolver, borrows through the pool, passes the " +
				"ceilings, and produces a decision record — and the arm that matters is the AST " +
				"one from P1 step 68, extended to the runner, because a behavioural arm only shows " +
				"it did not happen this time. " +
				"**AND D249 IS WHY THIS IS ONE ARM RATHER THAN TWO.** A poller and a job doing " +
				"almost the same work through different code would be the second path built " +
				"deliberately, with the evidence already in hand — so the assertion is that a " +
				"SCHEDULED run and a CALLER'S job reach the ceilings through the same sequence, " +
				"and the AST arm names both triggers so adding a third is visible.",
			run: p3Step5,
		},
		{
			n: 6, covers: []int{1}, decides: []string{"D24", "D271"},
			what: "at-most-once is honest: the bus drops rather than queues, and Ack is a no-op that says so",
			asserts: "A SKELETON MUST DO ITS JOB FOR ONE REAL INPUT OR REFUSE LOUDLY, and never " +
				"silently succeed at nothing (§12.0 principle 4). The bus landed at P0 with " +
				"at-most-once, no replay and `Ack` as a no-op, which is a legitimate v1 and is " +
				"exactly the shape that reads as more than it is once a real producer arrives. " +
				"Proven rather than documented: a slow consumer DROPS and the drop is observable, " +
				"and the audit log must never (D118's line between the bus and the record). The " +
				"step exists because criterion 1 is otherwise satisfiable by a consumer that " +
				"happened to keep up",
			run: p3Step6,
		},
		{
			n: 14, covers: []int{1},
			what: "`-mode=ingest` genuinely polls, and the stub warning is retired",
			asserts: "§12.0's walking-skeleton guardrail, collected. §3 records that `-mode=ingest` " +
				"was briefly a STUB — it passed a capability check and then polled nothing — and " +
				"the remedy was a startup warning, which is the honest thing to do with a mode " +
				"that does nothing and the wrong thing to leave behind once it does something. " +
				"The step asserts both directions: the mode polls, and the warning is GONE. A " +
				"warning that outlives its cause is D77's crying wolf aimed at the boot report, " +
				"and CONTRACTS 48 is the same defect in the init ledger — a disclaimer that keeps " +
				"applying after it stopped being true",
			run: p3Step14,
		},
		{
			n: 15, covers: []int{1}, decides: []string{"D273"},
			what: "the raw-envelope dev tap captures for a human, rehearses offline, and cannot be mistaken for a producer",
			asserts: "The deliverable is a manual replay tap, and the risk it carries is the one " +
				"`PublishForTest` was named against: a debugging affordance that becomes an " +
				"unsupported ingestion path because nothing stopped it. The step asserts the tap " +
				"is reachable only where a human is driving it, and that it is not wired into the " +
				"gateway surface an agent can reach",
			run: p3Step15,
		},
		{
			n: 16, covers: []int{1, 2}, decides: []string{"D269"},
			what: "one projection, generated as a stateless enrichment rule shape",
			asserts: "The projection deliverable, and it is deliberately the SHAPE of a stateless " +
				"enrichment rule even though the reflex engine's policy half is P5's. " +
				"`internal/reflex` already holds the pure functions from P0 — matching, " +
				"enrichment and command construction, all functions of (envelope, rule) — so a " +
				"projection is those functions applied to a real envelope rather than new " +
				"machinery. The step asserts the projection is a function of the envelope and " +
				"nothing else: same envelope, same output, no reachable state",
			run: p3Step16,
		},

		// --- causation (criterion 2) --------------------------------------------
		{
			n: 7, covers: []int{2}, decides: []string{"D19", "D272"},
			what: "every envelope carries a causation chain and a depth, and the translated event names the poll that produced it",
			asserts: "PRESENT AND CORRECT are two assertions and the second is the one that gets " +
				"skipped. D232's lesson at P2 was a field the census found populated by no row; " +
				"the inverse here is a field populated with something plausible. So the step " +
				"asserts the chain names the POLL DECISION that produced the envelope — joinable " +
				"back to an audit row — rather than merely being non-empty, which is the " +
				"distinction P1 step 65 had to make about `config_identity` after a required " +
				"parameter was satisfied with `test-config`",
			run: p3Step7,
		},
		{
			n: 8, covers: []int{2}, decides: []string{"D271"},
			what: "depth is bounded, and a self-caused loop is refused rather than counted",
			asserts: "§4.11's runaway risk, reached from the afferent side: reflex A creates a Jira " +
				"issue, the Jira poller emits it, and the rule matches again. Depth is the " +
				"instrument and a bound is what makes it one — an unbounded counter records a " +
				"loop rather than stopping it. The step asserts the refusal is a DELIBERATE one " +
				"in D135's sense, with a mapped status and a decision id, and not a transport " +
				"error: a bounded loop is a governance outcome and belongs on the record as one",
			run: p3Step8,
		},

		// --- the envelope on the wire (criterion 4) ------------------------------
		{
			n: 9, covers: []int{4}, decides: []string{"D271"},
			what: "the envelope round-trips protobuf and protojson losslessly",
			asserts: "A PROPERTY TEST OVER GENERATED ENVELOPES, not a handful of examples, because " +
				"the values that break this are the ones nobody writes down: an unset optional " +
				"beside a zero value, a `Struct` holding a NaN, a timestamp at the boundary, and " +
				"extension attributes whose names are legal in one encoding and not the other. " +
				"D177 is the neighbouring failure and it is why this matters beyond tidiness — " +
				"`structpb` fails ALL-OR-NOTHING on an awkward type, and `internal/safestruct` " +
				"exists because one unrepresentable field erased a whole object. An envelope that " +
				"does not survive a round trip loses data in the same shape, and the data is a " +
				"vendor's",
			run: p3Step9,
		},

		// --- the subject namespace (criterion 5) ---------------------------------
		{
			n: 10, covers: []int{5}, decides: []string{"D21"},
			what: "boot refuses a deliberately cyclic subject config, and names the cycle",
			asserts: "D21's stage-monotonicity checker, and the assertion is on the MESSAGE as much " +
				"as the refusal. A cycle in the subject namespace is a configuration somebody " +
				"wrote and has to fix, so a refusal that says `cycle detected` names a fact and " +
				"not an action — the shape D97's per-target repetition was corrected for, where " +
				"the reason is the unit of action. The step asserts the path is printed. " +
				"Non-vacuity matters here too: an acyclic config of the same size must LOAD, or " +
				"the checker could be refusing everything",
			run: p3Step10,
		},

		// --- resumability is not assumed (criterion 6, D174) ---------------------
		{
			n: 11, covers: []int{6}, decides: []string{"D174", "D241", "D275"},
			what: "an interrupted poll recovers by the connector's declared recovery policy",
			asserts: "D174's first arm, against a source deliberately made hostile: kill the poller " +
				"mid-window, restart, and the rows arrive exactly once because the CONNECTOR " +
				"declared it could re-query the window and the SPINE invoked that policy. The " +
				"split is D171's metaphor — the spine knows the last poll did not commit, the hand " +
				"knows what re-querying costs — and the reason it is a declaration rather than a " +
				"probe is the maintainer's own objection to his first form of it: a connector that DETECTED " +
				"an unclosed entry would need read access to the audit log, which is an attack " +
				"surface in a component designed to be third-party-written (D35). D241 is the " +
				"interface change this needs, and the step is what stops it being declared and " +
				"never consulted",
			run: p3Step11,
		},
		{
			n: 12, covers: []int{6}, decides: []string{"D174", "D275"},
			what: "a source that declares itself unable produces a gap marker, written by Sekizui",
			asserts: "D174's second arm, and the more important one: a source that cannot be " +
				"re-queried LOSES ROWS on a crash and no design changes that — what a design " +
				"changes is whether the loss is VISIBLE. So the step asserts a gap marker in the " +
				"audit log naming what was lost and the window it covers, written by the spine and " +
				"NEVER by the connector, which is what keeps the attack surface closed. D53's rule " +
				"applied to ingestion: run or refuse, never silently succeed at nothing. And D77's " +
				"distinction is the one the record has to carry — a gap somebody DECLARED is not a " +
				"gap somebody is hiding, so the marker must be distinguishable from an absence",
			run: p3Step12,
		},
		{
			n: 13, covers: []int{6}, decides: []string{"D174"},
			what: "the connector cannot read the audit log, asserted on the import graph",
			asserts: "The guard for the attack surface D174 dissolved rather than accepted, and it " +
				"is on the IMPORT GRAPH for P1 step 43's reason: behaviour only shows it did not " +
				"happen this time. `Source` is published (D35), so the population this protects is " +
				"an out-of-tree driver author who could otherwise be handed a reader by a future " +
				"convenience. Stated as a rule rather than an observation, because the current " +
				"answer is that no connector imports it and that is true by accident until " +
				"something asserts it",
			run: p3Step13,
		},

		// --- the second producer: BigQuery (D169, D170) --------------------------
		// **STEP 17 WAS HERE — the konbini dialect port — and moved to P6 with
		// BigQuery (D274).** Its number is retired rather than reused, so every
		// citation of "step 17" stays about the thing it was about.
		{
			n: 18, covers: []int{3, 6}, decides: []string{"D274"},
			what: "Fullstory session events are polled by timestamp window, and they are a differently-shaped producer",
			asserts: "The second producer, now from the vendor v1 is about (D274, replacing D170's BigQuery " +
				"source). Generate Context read per session by TIMESTAMP window: an event stream rather " +
				"than a list, ISO timestamps rather than epoch strings, and NO vendor event id — so the " +
				"source's event id (what a cursor, an attempt and a gap marker name) is derived, deterministically, from session, timestamp and type, and the " +
				"arm asserts the same event yields the same id on a re-read. The source declares " +
				"`requery`, and the step asserts what that promises: re-reading a closed window returns " +
				"the same events — a property of the VENDOR's history, confirmed by looking once live " +
				"before it is relied on, as D170 asked of the table it replaces. Since D276 the step " +
				"also holds the source to its declaration: a kind the document does not declare, and " +
				"a declared kind whose payload does not conform, are refused before publish and " +
				"counted in the poll's decision",
			run: p3Step18,
		},

		// --- the meter nobody has enforced (criterion 7, CONTRACTS 70) -----------
		{
			n: 19, covers: []int{7}, decides: []string{"D257", "D274"},
			what: "a read that would exceed the capability's max_bytes is refused before it is sent",
			asserts: "CONTRACTS 70's other path. Step 35 bounds a JOB before it runs; this bounds a READ, " +
				"and since D283 by a UNIVERSAL rule: every result is rows of objects capped by one " +
				"per-object budget, so a call's declared cost is rows × that budget, and the connector " +
				"supplies only its Bound. An explicit request over budget is refused BEFORE the call " +
				"with the cost, the budget and the number that would fit named; a default is lowered " +
				"to fit through the action's own argument; and a connector returning more than it " +
				"declared is cut to what was priced, flagged — because a bound checked after the " +
				"vendor was called is an accountant rather than a control",
			run: p3Step19,
		},
		{
			n: 20, covers: []int{7}, decides: []string{"D171", "D274", "D284"},
			what: "the meter is the connector's, the budget is the target's, and the deployment's ceiling may only be narrowed",
			asserts: "D171's three layers, with Fullstory's meter — CALLS — rather than BigQuery's bytes " +
				"(D274): the connector declares what is metered and a safe default, the target declares " +
				"the budget, the deployment declares a ceiling, and a target asking for more than the " +
				"ceiling is REFUSED AT BOOT while one asking for less is honoured. Collapsing any two " +
				"reproduces what D142 was written to prevent — a control an operator can only change by " +
				"shipping a binary. The vocabulary stays OPEN (the maintainer's correction to D171): one unit of " +
				"arithmetic, however an upstream charges. And since D284 every call and POLL is priced " +
				"in that unit before it is sent — a Fullstory events poll is one sessions call plus a " +
				"context read per session, and it was charged as one call",
			run: p3Step20,
		},

		// --- the loop closes, in shadow (criterion 8, D172) ----------------------
		{
			n: 21, covers: []int{8}, decides: []string{"D172"},
			what: "a polled row becomes an envelope, a rule matches it, and the command traverses the same enforcement path an agent's would",
			asserts: "D172's closed loop, and the phrase that carries the weight is THE SAME " +
				"enforcement path: identity, ceilings, policy, driver, audit, with no shortcut " +
				"earned by the command having been produced internally. `engine.go` already calls " +
				"the enforcer rather than a driver, so the step asserts that property holds once " +
				"there is a real envelope driving it — and asserts it on the DECISION RECORD, " +
				"which should be indistinguishable from an agent's except in who the principal is. " +
				"A reflex-produced command that took a shorter path would be D18's second code " +
				"path arriving in the place D18 was actually written about",
			run: p3Step21,
		},
		{
			n: 22, covers: []int{8, 21}, decides: []string{"D172", "D262"},
			what: "shadow is the default, and arming is a deliberate act in reviewed configuration",
			asserts: "The safety half of D172's amendment to P3's non-goals, and it is the half a " +
				"green loop makes easy to lose. A rule matching a thousand rows must not put a " +
				"thousand commands in flight, and `max_concurrent` — the guard that would say so — " +
				"is P5's. So the step asserts the DEFAULT rather than the capability: a rule with " +
				"no mode declared records and does not fire, and firing requires a value somebody " +
				"wrote into reviewed configuration. Same two-keys shape D157 gave anzen's reactive " +
				"form, and the reason it is asserted rather than documented is that a default is " +
				"exactly what a later refactor changes without noticing",
			run: p3Step22,
		},

		// --- shin governs data we did not invent (criterion 9) -------------------
		{
			n: 23, covers: []int{9}, decides: []string{"D239", "D279", "D292"},
			what: "an envelope produced by a real connector result is lensed on the bus",
			asserts: "The maintainer's question at the close of P2, and the gap is in EVIDENCE rather than in " +
				"the mechanism: P0 step 16 lensed an envelope the suite shaped itself. Here the real " +
				"Fullstory driver polls session events (D274 moved BigQuery to P6; this step once " +
				"said a BigQuery row), and the target lists `User Login`, which carries a person's " +
				"email and name and restates both in its description — the FIRST TIME SHIN GOVERNS " +
				"DATA SEKIZUI DID NOT INVENT. The maintainer asked for exactly this demonstration. Checked " +
				"against each envelope's actual bytes: an ALLOWLIST lens removes the name and email " +
				"everywhere; with no lens both arrive (non-vacuity); a DENYLIST lens naming the two " +
				"fields removes them and the email arrives anyway, in description — asserted on " +
				"purpose, because a denylist must know every carrier and an allowlist does not. The " +
				"allowlist keeps `event_properties.is_host`, resolved through the family (D292); a " +
				"typed lens withholding a misspelled carrier refuses the boot, and a misspelled " +
				"property under the open custom kind is pinned as the limit",
			run: p3Step23,
		},

		// --- the Fullstory slice, bounded by this phase's questions (criterion 11)
		{
			n: 24, covers: []int{11}, decides: []string{"D239", "D288"},
			what: "the Fullstory slice is bounded by P3's own criteria, and the boundary is checkable",
			asserts: "D239's ruling that this is a SLICE rather than a phase move, and the boundary " +
				"is THE QUESTION EACH PHASE ASKS rather than the connector's name: a fuller " +
				"Fullstory answers P4's question about tenancy and residency, a callable one " +
				"answers P3's about the inbound plane. Taking it on that basis is what stops P3 " +
				"quietly becoming two phases, and a boundary nobody can check is a boundary that " +
				"moves — so the step asserts what the slice does NOT take: multi-org, multi-DC, " +
				"and the 2,069-line surface stay P4's, and the driver refuses rather than " +
				"half-serves a target that asks for them. Since the maintainer's ruling this is CONCRETE: " +
				"one target is one org in one data centre by construction (one credential, one " +
				"host), and the driver dials ONLY Fullstory's API hosts — refused at boot and on " +
				"every call, before anything is sent, because the credential goes where " +
				"base_url points (CONTRACTS 117)",
			run: p3Step24,
		},
		{
			n: 25, covers: []int{13}, decides: []string{"D289", "D290"},
			what: "the Fullstory MCP's session-review tools are callable through the governed path, as the shipped vetted spec says",
			asserts: "MOVED UNDER CRITERION 13 (the maintainer, 2026-09-24): D270 took criterion 12's read-back to the " +
				"native API, so the MCP session tools serve agentic session review, not the read-back. " +
				"Built from a LIVE read of the Fullstory MCP, and every arm is a finding of it: the " +
				"shipped spec (host api.fullstory.com, org_id pinned — the MCP reaches any org by " +
				"argument — session_open never retried, the screenshot's seven-day signed URL " +
				"caller-only) validates beside a real target; session_open's JSON-as-text arrives " +
				"shaped and the accessibility tree as text; the pinned org reaches the server while " +
				"another org, an argument nobody vetted and a wrong type are refused before it sees " +
				"anything; the caller gets the URL and the record holds a trace and no copy of it, " +
				"text included; a type break is refused and an added field is stripped and raised as " +
				"tool_nonconforming",
			run: p3Step25,
		},

		// --- the drafter reads what the user's agent fetched (criterion 10, D287) -
		{
			n: 26, covers: []int{10}, decides: []string{"D287", "D168"},
			what: "sekizui-mcpspec never talks to an MCP server: the user's agent does, and the CLI cannot dial",
			asserts: "D287 REPLACED `the drafter becomes a client`. The maintainer: users reach MCP through an " +
				"LLM, and a CLI handling auth is feature creep — and a CLI that authenticated to the " +
				"server would hold the very credential Sekizui exists to govern. So the agent calls " +
				"the tool, under its own permission prompt, which is where a HUMAN chooses what is " +
				"called (§4.9a.1: which tools are safe cannot be inferred), and pipes the raw MCP " +
				"JSON. Asserted structurally — the command's import graph reaches no net, net/http, " +
				"crypto/tls, MCP driver or connector contract, so it cannot quietly become a client " +
				"again — and behaviourally on the binary: a tools/list entry and a tools/call result " +
				"are read; prose, an error result, a tool advertising no outputSchema and a file " +
				"argument are refused, each saying what to pipe instead",
			run: p3Step26,
		},
		{
			n: 27, covers: []int{10}, decides: []string{"D233", "D287"},
			what: "the observation never lands on disk, and no value from it is printed",
			asserts: "A tools/call result is customer data — session ids, emails, page URLs, click " +
				"text. The CLI reads stdin only and refuses a file, so nothing has to be saved to be " +
				"drafted from; neither package writes a file; and the output — list, schemas, " +
				"warnings — carries TYPES, never a value: a result seeded with sentinel values is " +
				"drafted and not one sentinel appears anywhere the command prints. Residual, " +
				"stated: a map keyed by data in a SINGLE observation is indistinguishable from a " +
				"record, so its keys are printed as field names (P2 step 28's map arm needs two)",
			run: p3Step27,
		},
		{
			n: 28, covers: []int{10}, decides: []string{"D287", "D279", "D51"},
			what: "the list, the output schema and the data schema are renderings of one inference",
			asserts: "One pass, three renderings. `output_schema` is the MCP's contract — copied and " +
				"`vendor` when the server advertises one (drift-checked live, so a wrong copy fails " +
				"as drift), inferred and `local` when it does not; `data_schema` is its CLOSED " +
				"subset in the vocabulary schemareg enforces, every loss warned; the list walks the " +
				"data_schema, so a listed field is exactly an admitted one. Asserted: every " +
				"drafted data_schema LOADS in the real schemareg (the CLI keeps its own keyword " +
				"list, since importing schemareg would reach the network, and this is what stops " +
				"the copy drifting); list and data_schema name the same paths; and the vendor " +
				"copy passes CompareToSpec against the server it came from and DRIFTS against one " +
				"advertising something else. Replaces the draft that emitted a local output_schema " +
				"and no data_schema — pasted, it quarantined the whole MCP connector (D282)",
			run: p3Step28,
		},

		// --- the read-back that closes CONTRACTS 102 (criterion 12) --------------
		{
			n: 29, covers: []int{12}, decides: []string{"D229", "D270"},
			what: "the event we wrote is read back from the session, and it runs only under `make acceptance-live`",
			asserts: "**CONTRACTS 102 CLOSED, AND P2 CRITERION 1's HUMAN UI CHECK BECOMES AN ARM (D270).** " +
				"`POST /v2/events` answers 200 with no identifier and `GET /v2/events` is 405, so " +
				"ingestion was confirmed by a person, twice. Generate Context (`POST " +
				"/v2/sessions/{id}/context`, confirmed live 2026-09-23) returns a session's events, " +
				"server-side custom ones included, with their properties: the step writes an event " +
				"stamped with a value no other run can carry, then reads the session back through a " +
				"GOVERNED query until the stamp appears or a deadline passes. The property is `run`, " +
				"not the `run_str` this assertion once named — live, it comes back under the name it " +
				"was written with. **THE POLL IS SLOW AND BOUNDED TWICE**: every ten seconds for at " +
				"most five minutes by default (SEKIZUI_READBACK_INTERVAL_S / _DEADLINE_S, floored so " +
				"it cannot become a load test), and every read is metered by `fs:live`'s rate_per_hr, " +
				"so one that outran it is refused by Sekizui rather than sent. READ-ONLY IN SPIRIT AND " +
				"GATED (D229) — it also writes the stamped event, so it is gated twice over",
			run: p3Step29,
		},

		// --- THE JOB: the first consumer of this plane that WANTS the data ------
		{
			n: 31, covers: []int{14, 9}, decides: []string{"D247", "D250", "D251", "D267"},
			what: "a caller asks for a job and receives its results as lensed envelopes",
			asserts: "**THE RE-PLAN'S HEADLINE, AND IT REPLACES CRITERION 1's TEST SUBSCRIBER.** " +
				"D172 had already called that thin — a consumer that exists only to prove delivery — " +
				"and the honest question, asked twice, was who consumes an envelope at all: reflexes " +
				"are P5, the gold loop closes at P5 (D170), and nothing else was waiting. A JOB has a " +
				"caller with a grant and a reason to be there. So the step drives the whole plane from " +
				"one request: admitted by the same ceilings and policy an `Execute` takes (D18 forbids " +
				"a second path), run, translated, and delivered TO THE CALLER ALONE over JobResults " +
				"(D267) — attached after the job has finished, which the bus could never allow, and " +
				"ending when the job does — NARROWED BY SHIN for that consumer, asserted against the " +
				"row's actual bytes rather than named fields. **NOBODY ELSE RECEIVES THEM**: a " +
				"bystander subscribed with a grant matching every row sees a later sentinel first, " +
				"and another principal asking for the results is told NOT_FOUND, as for a made-up " +
				"id, with the probe recorded. **It is also the honest way " +
				"to get criterion 9**: an envelope from a real connector result rather than from a " +
				"fixture that agrees with us by construction, which is the shape that cost the " +
				"blueprint three defects (D222)",
			run: p3Step31,
		},
		{
			n: 32, covers: []int{15}, decides: []string{"D247", "D254"},
			what: "finished, failed and still-running are distinguishable from the audit log",
			asserts: "**A JOB WHOSE END IS UNOBSERVABLE IS THE MELT IN A DIFFERENT COAT** — the caller " +
				"waits for ever and nothing says so. Three states and all three are asserted, because " +
				"the pair that actually gets conflated is FAILED and FINISHED-WITH-NOTHING-TO-SAY: " +
				"both produce no envelopes, and a log that cannot tell them apart tells an operator " +
				"the wrong thing at the moment they most need the right one. Asserted on the RECORD " +
				"rather than on a heartbeat somebody has to correlate, and the end is a record rather " +
				"than an absence — D77's rule that an expected boundary must be distinguishable from " +
				"a silence",
			run: p3Step32,
		},
		{
			n: 33, covers: []int{16}, decides: []string{"D247", "D255"},
			what: "cancelling a job stops the work, not just the subscription",
			asserts: "**THE ARM THAT MATTERS IS THE FAR SIDE.** A caller who unsubscribes from a job " +
				"that keeps running has bought nothing, the credential it borrowed stays borrowed, " +
				"and the vendor keeps being billed for work nobody will read. So the step asserts the " +
				"OUTBOUND CALL is cancelled, not that the stream closed — which is what `pool.Do`'s " +
				"call-through exists to make unforgettable (D128), and which a test against the " +
				"subscription alone would pass while the guarantee was absent. The same shape as P1 " +
				"step 52's non-vacuity problem: the observable that is easy to assert is not the one " +
				"the guarantee is about",
			run: p3Step33,
		},
		{
			n: 34, covers: []int{17}, decides: []string{"D129", "D146", "D247", "D256"},
			what: "a job cannot outlive its authorisation",
			asserts: "**THIS IS THE WIDEST WINDOW IN THE SYSTEM BETWEEN AUTHORISATION AND USE**, and " +
				"that is why it is a criterion rather than an implication. A command is authorised and " +
				"used in one breath; a poll re-admits every tick precisely because the window would " +
				"otherwise be open; a job holds it open for as long as the work takes. Two arms, " +
				"because the two revocations differ in kind and in durability: a grant SUSPENDED " +
				"mid-job (D146, in-memory, until config is redeployed) and a credential REVOKED " +
				"mid-job (D129, durable per D145). Both must stop it, and the record must say which " +
				"— P1 step 68 is the precedent for why `refused_by` matters, since its first version " +
				"passed for the wrong reason with the stage unnamed",
			run: p3Step34,
		},
		{
			n: 35, covers: []int{18, 7}, decides: []string{"D247", "D257"},
			what: "a job is bounded before it runs, and the caller chose the size",
			asserts: "**CONTRACTS 70 AGAIN, AND THIS IS THE PATH THAT MAKES TOLERATING IT UNTENABLE.** " +
				"`CapabilitySpec.MaxBytes` is advertised to agents and enforced nowhere; step 19 " +
				"closes it for a scan, and a job closes it for the case where THE CALLER CHOOSES THE " +
				"NUMBER — `review five sessions` and `review five million` are the same sentence. " +
				"BEFORE IT RUNS is the load-bearing half: a bound checked after the work is paid for " +
				"is an accountant rather than a control. The refusal names the declared cost and the " +
				"budget it exceeded, because a refusal that does not say by how much is one nobody " +
				"can act on",
			run: p3Step35,
		},
		{
			n: 36, covers: []int{19}, decides: []string{"D248", "D269"},
			what: "an enrichment reflex shapes a result on the way back, and an actuating one is refused eligibility",
			asserts: "**BOTH HALVES ARE THE CRITERION, and the second is the one with teeth.** " +
				"`Envelope.projection` was always specified as generated by a stateless enrichment " +
				"reflex (§4.6.2) and was only ever wired for envelopes, so the first arm is that " +
				"projection reaching a caller who asked — the maintainer's `already improves the output`. The " +
				"second arm REFUSES a rule that dispatches a command from running on the synchronous " +
				"path, because a reflex reachable by any read makes READING A WAY TO TRIGGER WRITES: " +
				"a caller holding only a read grant reaches every action the rule's principal holds, " +
				"with the rule's grant as the blast radius rather than the caller's (D7, §4.11.7). " +
				"**Asserted on ELIGIBILITY rather than on outcome** — a behavioural arm shows only " +
				"that no such rule happened to match this time, which is P1 step 43's reasoning for " +
				"putting the guard on the import graph instead",
			run: p3Step36,
		},

		// --- WHO ELSE RECEIVES IT: the bus scoped as the command plane is -------
		{
			n: 37, covers: []int{20}, decides: []string{"D60", "D258", "D259", "D260"},
			what: "a subscription is scoped to the targets it names, as a command is",
			asserts: "**THE COMMAND PLANE COULD ALWAYS SAY `ONLY CUSTOMER X` AND THE BUS COULD " +
				"NOT.** `allow` is action × target; `subscribe` was a subject alone, and D60 keeps " +
				"the target out of the subject, so a consumer granted a type received every org's " +
				"events of it — which the maintainer found by asking whether a job scheduled for one " +
				"customer would be visible to everyone. Four arms: a target named nowhere is " +
				"withheld; the PAIRING holds, so a subject granted for one target confers nothing " +
				"from another; the establishment record names the targets, since D93 makes it the " +
				"only place a reviewer can learn them; and the boot refuses a bare subject, a " +
				"missing target, a wildcard and an undeclared one, each naming the fix. **ORDER IS " +
				"THE INSTRUMENT**: every envelope that must be withheld is published before the " +
				"one that must arrive, so a leak is the first thing received rather than an " +
				"absence waited out. It also carries D258, because every pattern it grants " +
				"matches on the DERIVED subject and the fixture's entity is not one",
			run: p3Step37,
		},

		{
			n: 38, covers: []int{20, 8}, decides: []string{"D261"},
			what: "a reflex consumes as its principal, through the scope an agent's subscription takes",
			asserts: "**A RULE'S `consumes` IS NOT ITS AUTHORISATION; ITS PRINCIPAL'S GRANT IS.** " +
				"Before D261 the engine had no subscription, and the obvious one to give it — one " +
				"engine-wide reader — would have read every tenant's events for every rule, which " +
				"is D259's gap reopened from the inside. So each rule subscribes AS its principal " +
				"through the same scoped path a remote agent's Subscribe takes (D260): a row from a " +
				"target the principal is not granted produces nothing even though the pattern " +
				"matches it, published first so a leak would be processed first; the subscription " +
				"is recorded once as that principal, INTERNAL, naming its targets; and the boot " +
				"refuses a rule whose principal may not consume what it consumes, because such a " +
				"rule would be enabled, valid and permanently deaf",
			run: p3Step38,
		},

		{
			n: 39, covers: []int{21, 8}, decides: []string{"D263"},
			what: "a reflex's `where` is a declarative predicate, checked against the schema at boot",
			asserts: "**NO LANGUAGE AND NO DEPENDENCY (D263, superseding D25).** A field path and " +
				"one of eq, in, exists, gt, gte, lt, lte, evaluated over the envelope's payload by " +
				"the engine's live loop. Three arms: a predicate that does not hold stops a " +
				"matching rule from firing, asserted on the record rather than on a unit; a path " +
				"the registered schema does not declare refuses the boot, which is D42 applied to " +
				"the predicate; and an unknown operator refuses the boot naming the set, because " +
				"an operator that parsed and did nothing is D262's defect again",
			run: p3Step39,
		},
		{
			n: 40, covers: []int{21, 8}, decides: []string{"D264"},
			what: "arming a rule requires a firing budget, and exhausting it refuses the firing",
			asserts: "**TWO DELIBERATE ACTS TO ARM, as anzen's reactive form (D157).** `mode: " +
				"enforce` without `max_firings_per_hour` refuses the boot. The budget is enforced " +
				"in the live loop: the firing past it is REFUSED and recorded, not silently " +
				"skipped, and it raises `budget_exceeded` — the first producer CONTRACTS 65 has " +
				"had for it. Debounce by key and window lands beside it. Both counters are PER " +
				"REPLICA and the step says so rather than implying a fleet-wide bound",
			run: p3Step40,
		},
		{
			n: 41, covers: []int{3}, decides: []string{"D285"},
			what: "a schedule keeps its cadence across a restart: the first poll is due one interval after the last one started",
			asserts: "CONTRACTS 134, closed by D285. The first poll used to come one WHOLE " +
				"interval after the process started and every restart reset it, so a source " +
				"whose interval exceeded the deploy cadence never polled — healthy process, " +
				"nothing in Stopped(). Criterion 3's \"no gaps\", in time rather than in rows. " +
				"Three arms on an HOURLY schedule through the real runner, because at the " +
				"one-second intervals every other step uses the defect is invisible: restarted " +
				"half a second before due, it polls when due; never polled, it polls at once; a " +
				"stored time a year ahead counts as NOW — whoever can write the store must not " +
				"be able to silence a source by dating its last poll in the future",
			run: p3Step41,
		},
		{
			n: 42, covers: []int{6}, decides: []string{"D286"},
			what: "the afferent path cannot be turned into a read of the audit log",
			asserts: "The maintainer's question — can the poller be used to reach the audit log? Its own code " +
				"never did, and nothing enforced that; and a credential reference turned out to be " +
				"a read of any file the process could open, sent off-host as the Authorization " +
				"header of every call, on a poll's cadence. So: no afferent package — runner, " +
				"cursor store, translator, connector contract, any driver, any credential " +
				"provider — reaches internal/auditwal even transitively; a file:// credential " +
				"outside every declared root refuses the boot, chained or not; the audit " +
				"directory is refused even inside a root; a symlink is judged by where it lands, " +
				"at boot and again at every read; and with no root, the published provider " +
				"refuses by default",
			run: p3Step42,
		},
		{
			n: 43, covers: []int{13}, decides: []string{"D291"},
			what: "a stateful handle is closed when it goes idle and when the process drains, as its opener; break-glass closes nothing",
			asserts: "Fullstory's session_open allocates a slot in the org's concurrent-session budget; " +
				"The maintainer's skill pairs every open with a close as the AGENT's discipline, and the maintainer ruled " +
				"Sekizui should guarantee it. The vetted spec DECLARES the pairing (opens, closes, " +
				"uses), and a principal granted the opener but not the closer is refused at load. A " +
				"handle idle past its limit is closed through the enforcement path — credited to the " +
				"opener, with an internal caller naming `sekizui:handle-expiry`, its causation joined " +
				"to the open's decision; a handle in use is not idle; one its caller closed is " +
				"forgotten; the drain closes the rest. Break-glass closes NOTHING: closing needs the " +
				"credential break-glass revoked, and the vendor expires the slot",
			run: p3Step43,
		},

		// --- the teaching artefact ships with it (criterion 13) ------------------
		{
			n: 30, covers: []int{13}, decides: []string{"D239", "D289", "D291"},
			what: "the guidance on agentic session review ships with the capability, and is written from the skill",
			asserts: "The teaching rule: guidance ships WITH a subsystem, not as prose trailing it. " +
				"Written from the maintainer's expert skill (2026-09-24) AND from the live read of the Fullstory " +
				"MCP the same day — which wins where they disagree, since the skill still names the " +
				"removed session_view. What a reader needs is WHICH TOOL ANSWERS WHICH QUESTION (D237 " +
				"reached for org metadata when it wanted session review), what the lifecycle costs, " +
				"and what reaches them and what never does. Asserted as far as prose can be: the " +
				"document exists, every governed action it names is a tool in the shipped vetted spec " +
				"or a native Fullstory action, the tools it calls unvetted are, and criterion 13 " +
				"cites it",
			run: p3Step30,
		},
	}
}

// TestP3Acceptance runs what exists and reports what does not.
func TestP3Acceptance(t *testing.T) {
	built := 0
	for _, s := range p3StepTable() {
		if s.run != nil {
			built++
		}
	}
	t.Logf("P3 acceptance: %d/%d steps built", built, len(p3StepTable()))

	for _, s := range p3StepTable() {
		t.Run(fmt.Sprintf("%02d_%s", s.n, slug(s.what)), func(t *testing.T) {
			// The evidence ledger is opened here and not inside the steps, as
			// P2's is, so every P3 step cites its audit lines without knowing
			// the ledger exists (D227).
			st := evidence.open("P3", s.n, s.what, firstSentence(s.asserts), s.covers, s.decides)
			// BOUND, because P3's steps narrate: `run.narrate` writes into this
			// entry instead of opening a phantom P0 one.
			evidence.bind(t.Name(), st)
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

// TestP3StepsAreWellFormed. A placeholder with no stated assertion is a step
// nobody has thought through, and it will be written to pass rather than to
// prove.
func TestP3StepsAreWellFormed(t *testing.T) {
	seen := map[int]bool{}
	for _, s := range p3StepTable() {
		if s.what == "" || s.asserts == "" {
			t.Errorf("step %d has no narration or no stated assertion", s.n)
		}
		if len(s.covers) == 0 {
			t.Errorf("step %d (%s) discharges no exit criterion; either it is not P3's "+
				"business or the criteria list is missing one", s.n, s.what)
		}
		for _, c := range s.covers {
			if _, ok := p3ExitCriteria[c]; !ok {
				t.Errorf("step %d claims exit criterion %d, which does not exist", s.n, c)
			}
		}
		if seen[s.n] {
			t.Errorf("step number %d is used twice", s.n)
		}
		seen[s.n] = true
	}
}

// TestP3CoversItsExitCriteria — a criterion with no step is a criterion nobody
// will prove. P2's caught five on its first run, which is how DESIGN §12 P2
// acquired criteria 8-12.
func TestP3CoversItsExitCriteria(t *testing.T) {
	covered := map[int]bool{}
	for _, s := range p3StepTable() {
		for _, c := range s.covers {
			covered[c] = true
		}
	}

	var orphans []string
	for c, desc := range p3ExitCriteria {
		if !covered[c] {
			orphans = append(orphans, fmt.Sprintf("%d: %s", c, desc))
		}
	}
	sort.Strings(orphans)

	if len(orphans) > 0 {
		t.Errorf("%d P3 exit criterion/criteria have no acceptance step:\n  %s\n\n"+
			"Add a step, or move the criterion — an exit criterion nobody proves is a "+
			"phase that graduates on a claim.", len(orphans), strings.Join(orphans, "\n  "))
	}
}

func TestP3CompletionIsHonest(t *testing.T) {
	if !p3Complete {
		return
	}
	var unbuilt []string
	for _, s := range p3StepTable() {
		if s.run == nil {
			unbuilt = append(unbuilt, fmt.Sprintf("%d: %s", s.n, s.what))
		}
	}
	if len(unbuilt) > 0 {
		t.Errorf("P3 is marked complete with %d unbuilt step(s):\n  %s\n\n"+
			"Either build them or move them out of the phase — a step that skips is a "+
			"commitment, and marking the phase done turns it into a claim.",
			len(unbuilt), strings.Join(unbuilt, "\n  "))
	}
}
