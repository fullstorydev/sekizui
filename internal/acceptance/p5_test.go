package acceptance

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// P5's graduation run, declared before it is built (D114).
//
// Same instrument as P1's to P4's: every step the phase must prove is here from
// the start, and an unbuilt one SKIPS LOUDLY with the assertion it will make
// rather than being absent.
//
// WRITING THIS TABLE MOVED WORK OUT OF THE PHASE AS WELL AS INTO IT (D327):
//
//   - **The lookup half of `refines:` had no rule to serve.** D297 and D298 ruled
//     its budgets and deadline, and the flagship derives from one Generate Context
//     result and looks nothing up. Criteria written for it would have been proven
//     against a rule invented to satisfy them, so it moved to P6.
//   - **Connector presets joined** (the maintainer, 2026-09-27): a vendor recommends and
//     explains named sets of its actions, a sysadmin owns the copy deployed. v1
//     needs them, which is the reason they are here, and not that P5 was next.
//   - **Criteria 3 and 4 were enforced in P0** and are re-asserted here with a
//     Fullstory-shaped rule, as P4 step 11 re-ran P1's property: a cumulative
//     run proves an old guarantee still holds over the new surface.

// p5Step is one planned assertion. Same shape as the earlier tables,
// deliberately: two tables that describe the same kind of thing differently is
// how the reporting drifts.
type p5Step struct {
	n int

	// what is the narration, in the same voice as the earlier runs.
	what string

	// asserts is what this step will prove. REQUIRED even while unbuilt.
	asserts string

	// covers names the P5 exit criteria from DESIGN §12 this step discharges.
	covers []int

	// decides names the decision records this step proves, where one exists.
	decides []string

	// run is nil until the step is built.
	run func(t *testing.T)
}

// p5ExitCriteria is DESIGN §12 P5's numbered list, restated so the mapping is
// mechanical rather than a claim in a comment.
//
//nolint:gochecknoglobals // immutable table, read once
var p5ExitCriteria = map[int]string{
	1: "an actuating rule's shadow run over recorded traffic yields firings that survive review (D298)",
	2: "enforce over the same recorded input fires exactly what shadow predicted (D298)",
	3: "a deliberately cyclic rule is rejected at boot",
	4: "a rule granted an action its principal lacks is rejected at boot",
	5: "a budget trip halts the reflex and alerts",
	6: "a rage-click burst produces one ticket per debounce key per window",

	// --- appended when the table was declared (2026-09-27, D327).
	7:  "rules sharing a budget exhaust it together, and the refusal names the shared budget (D264)",
	8:  "a rule's firings are serialised, and a principal's concurrency is bounded by the anzen cap (D335)",
	9:  "denial_storm is raised and names the principal monopolising a budget (D143)",
	10: "a connector's presets ship as a suggested fragment and a preset: grant expands at boot to a fixed action list (D327)",
	11: "a preset never widens on upgrade: a vendor suggestion ahead of the deployment's copy is a finding (D327)",
	12: "a preset mirroring a vendor level holds no action above it, and the anzen ceiling holds after expansion (D304, D327)",

	// --- D328, the maintainer, 2026-09-27: the phase that completes v1 leaves every
	// contract with a worked form, so a contributor knows what to do.
	13: "kata, the demo and hako are complete: every contract has a worked form in the reference driver, on the running demo, and in hako (D328)",

	// --- D329, the maintainer, 2026-09-27: v1 is published, so its front door is part of
	// the release, not an afterthought to it.
	14: "the README is ready for public consumption: why, what and how, its features each backed by proof, a platform first, and Fullstory as the connector that shows what it can do (D329)",
}

// p5Complete is flipped when P5 graduates. TestP5CompletionIsHonest fails if it
// is true while any step is unbuilt (D114). Flipped at the maintainer's sign-off (D339):
// with P4, this is v1 (D294).
const p5Complete = true

// p5StepTable is P5's graduation run, declared before it is built. A function
// rather than a var, matching the earlier phases (§15z).
func p5StepTable() []p5Step {
	return []p5Step{
		// --- the replay proof (criteria 1, 2) ----------------------------------
		{
			n: 1, covers: []int{1}, decides: []string{"D298"},
			what: "an actuating rule's shadow run over a recorded capture lists the firings it would make",
			asserts: "A REPLAY, NOT A CALENDAR WEEK (D298). The recorded traffic is P4 step 18's capture " +
				"(`testdata/seiren/web.json`: 148 real session events from EXAMPLE, fetched through the " +
				"real binary) — the poll's envelope type, fullstory.session_event.v1, so no second live " +
				"capture (the maintainer, 2026-09-27). Each row, wrapped as the poller wraps it, is replayed through an actuating bus→driver " +
				"rule in shadow: every would-be firing is recorded WOULD_HAVE_FIRED with the envelope " +
				"that caused it, nothing reaches the driver, and the list is readable by a reviewer — " +
				"rule, cause, action, target — without the audit log's other fields",
			run: p5Step1,
		},
		{
			n: 2, covers: []int{2}, decides: []string{"D298"},
			what: "enforce over the same recording fires exactly what shadow predicted",
			asserts: "The same recorded input through the same rule in `enforce`: the set of firings " +
				"equals step 1's, compared by causing envelope and command, not by count. A firing in " +
				"one set and not the other fails, naming it — the engine is deterministic, so any " +
				"difference is a defect rather than traffic",
			run: p5Step2,
		},

		// --- the boot refusals, re-asserted over Fullstory (criteria 3, 4) -----
		{
			n: 3, covers: []int{3},
			what: "a cyclic rule over Fullstory envelopes is refused at boot and the cycle is named",
			asserts: "DISCHARGED BY CITATION (the maintainer, D330): P3 step 10 already refuses a cyclic rule over " +
				"Fullstory types at boot, naming the cycle, in every cumulative run — re-asserting it would " +
				"prove nothing new. This step finds it in P3's table, requires it built, about a cycle, and " +
				"over a Fullstory type in its code, and RUNS it, so P5's criterion falls if P3's step does",
			run: p5Step3,
		},
		{
			n: 4, covers: []int{4},
			what: "a Fullstory rule granted an action its principal lacks is refused at boot",
			asserts: "A rule whose command is a Fullstory action its `reflex:` principal holds no " +
				"grant for refuses the boot, naming rule, principal and action (§4.11.4b). Including " +
				"an action withheld by the connector's suggested anzen ceiling under a wildcard grant: " +
				"the rule cannot reach what the ceiling forbids",
			run: p5Step4,
		},

		// --- budgets and the alert (criteria 5, 7, 8), and the rage-click criterion (6)
		{
			n: 5, covers: []int{5}, decides: []string{"D264"},
			what: "a budget trip halts the reflex and the alert reaches an anzen rule",
			asserts: "HALTING WAS P3's (step 40); ALERTING IS WHAT IS LEFT. A rule exhausting its " +
				"firing budget stops firing, `budget_exceeded` is raised once on the transition, and " +
				"an anzen rule watching it acts — the alert has a consumer, not only a producer. The " +
				"record names the rule and the budget",

			run: p5Step5,
		},
		// --- the rage-click criterion (criterion 6) ----------------------------
		{
			n: 6, covers: []int{6}, decides: []string{"D30", "D333"},
			what: "a rage-click burst files one ticket per debounce key per window",
			asserts: "The rage-clicks of a real captured session (the step-18 capture has 19) replayed " +
				"through a rule debounced on the session: exactly one `kata.create_issue` per key per " +
				"window, and the suppressed firings are counted, not silent. A second window files a " +
				"second ticket",

			run: p5Step6,
		},

		{
			n: 7, covers: []int{7}, decides: []string{"D264", "D334"},
			what: "two rules sharing one budget exhaust it together",
			asserts: "`reflex:policy`'s cross-rule budget: two rules naming one shared budget, each " +
				"below its own firing budget; once their combined firings reach the shared one, the " +
				"next firing of EITHER is refused, and the refusal names the shared budget rather " +
				"than the rule's own",

			run: p5Step7,
		},
		{
			n: 8, covers: []int{8}, decides: []string{"D335"},
			what: "a rule's firings are serialised, and a principal's concurrency is bounded by the anzen cap",
			asserts: "CRITERION 8 AS THE ARCHITECTURE GUARANTEES IT (the maintainer, D335): Engine.Run reads each rule's " +
				"stream on one goroutine, so a rule never has two firings in flight — a per-rule " +
				"`max_concurrent` could never exceed 1, and would be a knob with no effect. So: one rule, " +
				"three events on a write that blocks (kata:slow), one in flight; five rules of one " +
				"principal at once, three in flight and two refused by anzen's reflex-burst-cap, each " +
				"recorded as that guard's",
			run: p5Step8,
		},

		// --- the monopoliser (criterion 9) --------------------------------------
		{
			n: 9, covers: []int{9}, decides: []string{"D143"},
			what: "denial_storm is raised and names the principal monopolising the budget",
			asserts: "The last unkept anzen signal (CONTRACTS 65). One principal drains a shared " +
				"target budget below its reserve while others are refused: `denial_storm` is raised " +
				"naming the MONOPOLISER as well as the victims, an anzen rule watching it acts, and " +
				"the ledger entry `signal:denial_storm` is deleted by its expiry guard",

			run: p5Step9,
		},

		// --- connector presets (criteria 10, 11, 12) ---------------------------
		{
			n: 10, covers: []int{10}, decides: []string{"D327"},
			what: "the Fullstory connector's presets ship as a suggested fragment and a preset grant expands at boot",
			asserts: "`internal/connectors/fullstory/presets.yaml` loads as a config fragment, as P4 step " +
				"33 loads `anzen.yaml` — what ships is what is tested. A grant `{preset: " +
				"fullstory.standard, target: fs:live}` expands at boot to the preset's actions, " +
				"`Describe` lists them, and a decision it authorises names the preset in " +
				"`matched_rule`. An unknown preset, or one naming an action the connector lacks, " +
				"refuses the boot",
			run: p5Step10,
		},
		{
			n: 11, covers: []int{11}, decides: []string{"D327"},
			what: "a vendor preset that grew is a finding and widens no grant",
			asserts: "NEVER WIDEN ON UPGRADE. The connector's suggested preset gains an action the " +
				"deployment's copy lacks: the deployment's grants authorise exactly what they did " +
				"(the new action is refused), and the difference is reported as an informational " +
				"finding naming the preset and the action",
			run: p5Step11,
		},
		{
			n: 12, covers: []int{12}, decides: []string{"D304", "D327"},
			what: "a preset's vendor level is checked against the snapshot, and the anzen ceiling holds after expansion",
			asserts: "A preset declaring `mirrors: Standard` that holds an operation the reference " +
				"snapshot marks Architect or Admin is refused by the connector-folder check, naming " +
				"the action and its level. And a preset expanding to an action the connector's " +
				"suggested anzen ceiling forbids is still refused at the ceiling, and `Describe` " +
				"reports it withheld by the rule",
			run: p5Step12,
		},

		// --- v1's contributor surface (criterion 13) — LAST, and built last,
		// because it guards everything above it; only step 14 follows ---------
		{
			n: 13, covers: []int{13}, decides: []string{"D328"},
			what: "kata, the demo and hako are complete, so a v1 contributor has a worked form of every contract",
			asserts: "THE SURFACE IS DERIVED FROM THE CODE, NOT LISTED BESIDE IT. (a) KATA: every exported " +
				"interface in `pkg/connector` that a driver may implement (found by go/types; the " +
				"infrastructure ones a driver never implements — ClientPool, Resolver — excluded by a " +
				"named list) is implemented by kata and its published conformance suite is run, or an " +
				"exemption names why not (HostBound: kata dials no host) — so kata's README sentence " +
				"\"complete in every contract a driver can implement\" becomes checked. (b) HAKO: every " +
				"fragment a connector folder may ship (anzen.yaml, reflexes.yaml, presets.yaml, mcp.yaml, " +
				"reference/) and every top-level config section a deployment writes has a worked form in " +
				"`hako/reference` or kata's folder, and every optional contract has a BLUEPRINT section " +
				"naming it; an exemption states its reason. (c) DEMO: every contract and config section " +
				"is exercised by an acceptance step with a remote arm under `make demo`, or is named " +
				"local-only with the reason. A new interface, fragment kind or config section fails " +
				"this step until kata, hako and the demo carry it — or someone writes down why not",

			run: p5Step13,
		},

		// --- v1's front door (criterion 14) — THE ACTUAL FINAL STEP, after 13,
		// because the README describes what the phase finished ----------------
		{
			n: 14, covers: []int{14}, decides: []string{"D329"},
			what: "the README is ready for public consumption, and every feature it claims is proven",
			asserts: "THE HALF A CHECK CAN HOLD, HELD; THE HALF IT CANNOT, SIGNED. The README carries, in " +
				"order: WHY Sekizui exists (governance and trust brought back to the front, for any " +
				"industry and anyone); WHAT it is; HOW it works; FEATURES; A PLATFORM FIRST (connectors are " +
				"the product surface, the core is vendor-neutral); WHY FULLSTORY SHIPS AS A CONNECTOR (to " +
				"demonstrate what a connector built on the platform can do, not because the platform is " +
				"Fullstory's); and CONTRIBUTING, pointing at kata, hako, the blueprint and step 13's " +
				"exemptions. EVERY FEATURE ROW CITES the acceptance step or decision that proves it, in a " +
				"derived block like the glossary, and a row citing a step that does not exist, or is " +
				"unbuilt, fails — a public feature list is a claim, and P2 step 33 already holds the " +
				"README's other claims. The PROSE is the maintainer's to sign, recorded in D329 beside p5Complete, " +
				"because whether it says the right thing is the one judgement no guard can make",

			run: p5Step14,
		},
	}
}

func TestP5Acceptance(t *testing.T) {
	built := 0
	for _, s := range p5StepTable() {
		if s.run != nil {
			built++
		}
	}
	t.Logf("P5 acceptance: %d/%d steps built", built, len(p5StepTable()))

	for _, s := range p5StepTable() {
		t.Run(fmt.Sprintf("%02d_%s", s.n, slug(s.what)), func(t *testing.T) {
			st := evidence.open("P5", s.n, s.what, firstSentence(s.asserts), s.covers, s.decides)
			evidence.bind(t.Name(), st)
			// A CLEANUP, BECAUSE t.Skipf AND t.Fatalf LEAVE THROUGH
			// runtime.Goexit (see P3's runner).
			t.Cleanup(func() { st.finish(t.Skipped(), t.Failed()) })
			if s.run == nil {
				t.Skipf("NOT BUILT — will assert: %s", s.asserts)
			}
			s.run(t)
		})
	}
}

// TestP5StepsAreWellFormed. A placeholder with no stated assertion will be
// written to pass rather than to prove.
func TestP5StepsAreWellFormed(t *testing.T) {
	seen := map[int]bool{}
	for _, s := range p5StepTable() {
		if s.what == "" || s.asserts == "" {
			t.Errorf("step %d has no narration or no stated assertion", s.n)
		}
		if len(s.covers) == 0 {
			t.Errorf("step %d (%s) discharges no exit criterion; either it is not P5's "+
				"business or the criteria list is missing one", s.n, s.what)
		}
		for _, c := range s.covers {
			if _, ok := p5ExitCriteria[c]; !ok {
				t.Errorf("step %d claims exit criterion %d, which does not exist", s.n, c)
			}
		}
		if seen[s.n] {
			t.Errorf("step number %d is used twice", s.n)
		}
		seen[s.n] = true
	}
}

// TestP5CoversItsExitCriteria — a criterion with no step is a criterion nobody
// will prove.
func TestP5CoversItsExitCriteria(t *testing.T) {
	covered := map[int]bool{}
	for _, s := range p5StepTable() {
		for _, c := range s.covers {
			covered[c] = true
		}
	}

	var orphans []string
	for c, desc := range p5ExitCriteria {
		if !covered[c] {
			orphans = append(orphans, fmt.Sprintf("%d: %s", c, desc))
		}
	}
	sort.Strings(orphans)

	if len(orphans) > 0 {
		t.Errorf("%d P5 exit criterion/criteria have no acceptance step:\n  %s\n\n"+
			"Add a step, or move the criterion — an exit criterion nobody proves is a "+
			"phase that graduates on a claim.", len(orphans), strings.Join(orphans, "\n  "))
	}
}

func TestP5CompletionIsHonest(t *testing.T) {
	if !p5Complete {
		return
	}
	var unbuilt []string
	for _, s := range p5StepTable() {
		if s.run == nil {
			unbuilt = append(unbuilt, fmt.Sprintf("%d: %s", s.n, s.what))
		}
	}
	if len(unbuilt) > 0 {
		t.Errorf("P5 is marked complete with %d unbuilt step(s):\n  %s\n\n"+
			"Either build them or move them out of the phase — a step that skips is a "+
			"commitment, and marking the phase done turns it into a claim.",
			len(unbuilt), strings.Join(unbuilt, "\n  "))
	}
}
