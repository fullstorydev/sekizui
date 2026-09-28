package acceptance

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// P4's graduation run, declared before it is built (D114).
//
// Same instrument as P1's, P2's and P3's: every step the phase must prove is
// here from the start, and an unbuilt one SKIPS LOUDLY with the assertion it
// will make rather than being absent.
//
// WRITING THIS TABLE PAID FOR ITSELF BEFORE A LINE OF P4 EXISTED, the fourth
// time in four phases:
//
//   - **Criterion 7 checked one direction of "in full".** It proves every
//     endpoint the driver CALLS is documented, and nothing proved every
//     documented endpoint is CALLED — so a driver implementing three endpoints
//     would have graduated a phase titled "Fullstory, in full". Criterion 9.
//   - **D52's second coexistence obligation had no criterion.** Shared upstream
//     limiter keying is a deliverable of this phase, and without a step the
//     native driver and the MCP target would each spend the org's quota
//     believing they had all of it. Criterion 15.
//   - **The ledger's `audit:ship` still said "the operator's configured
//     warehouse".** D274 moved the warehouse to P6 and kept P4's sink
//     non-warehouse; registering this table is what made the entry owe steps,
//     and naming them is what exposed the stale wording.
//
// None of the three was found by a guard. All were found by writing down what
// the phase owes and reading what the phase already says.

// p4Step is one planned assertion. Same shape as p1Step, p2Step and p3Step,
// deliberately: two tables that describe the same kind of thing differently is
// how the reporting drifts.
type p4Step struct {
	n int

	// what is the narration, in the same voice as the earlier runs.
	what string

	// asserts is what this step will prove. REQUIRED even while unbuilt.
	asserts string

	// covers names the P4 exit criteria from DESIGN §12 this step discharges.
	covers []int

	// decides names the decision records this step proves, where one exists.
	decides []string

	// run is nil until the step is built.
	run func(t *testing.T)
}

// p4ExitCriteria is DESIGN §12 P4's numbered list, restated so the mapping is
// mechanical rather than a claim in a comment.
//
//nolint:gochecknoglobals // immutable table, read once
var p4ExitCriteria = map[int]string{
	1: "two Fullstory orgs in different DCs, one agent reading both",
	2: "a cross-region resolve is refused, with the refusal audited",
	3: "EU-resident decision records land in an EU-resident audit destination (D29 item 4)",
	4: "P1's property test re-run with Fullstory in the mix, still green",
	5: "an agent denied a capability on the native driver cannot obtain it through the MCP target (D52)",
	6: "the MCP target carries residency and refuses a cross-region resolve as the native driver does",
	7: "every endpoint the native driver calls is in the committed reference snapshot (D294, D299)",
	8: "the built-in refines: rules turn a real Generate Context result into seiren, per audience (D297, D298)",

	// --- appended when the table was declared (2026-09-26), as P3's 14-21 were.
	9:  "every snapshot endpoint is implemented or excluded by a named decision (D294, D301)",
	10: "silver and seiren arrive in one response, seiren over the whole result with its window (D300)",
	11: "a rule runs when its own inputs survived the lens; the rest is declared unavailable (D300)",
	12: "refinement rules are closed and checked at boot (D263, D292, D300)",
	13: "a connector's reflexes ship embedded and available, not imposed; a bare template refuses (D299, D301)",
	14: "reference drift is caught by the live run and never by the build (D299)",
	15: "the native driver and the MCP target share one upstream limiter key per org (D52)",

	// --- D302, D303, 2026-09-26. Appended for the same reason 9-15 were.
	16: "Describe advertises the refinements imposed on a principal (D298, D302)",
	17: "a subject signed by a pinned issuer is verified and recorded SIGNED; anything else refuses (D303)",
	18: "a role selects Sekizui's own grant set, and a token may only narrow it (D303)",

	// --- D308, 2026-09-26.
	19: "the Fullstory MCP connector ships every tool it serves, vetted; grants decide exposure (D307, D308)",

	// --- D311, 2026-09-26.
	20: "every drift comparison is admitted and leaves a decision record; a finding survives a restart (D311)",

	// --- D314, 2026-09-26.
	21: "the Fullstory connector suggests anzen ceilings for its irreversible and recording-configuration writes, and they hold under any grant (D314)",

	// --- D316, 2026-09-26.
	22: "every in-tree connector is one complete folder, and the build refuses one that is not (D316)",
}

// p4Complete is flipped when P4 graduates. TestP4CompletionIsHonest fails if it
// is true while any step is unbuilt (D114). Flipped at the maintainer's sign-off (D325).
const p4Complete = true

// p4StepTable is P4's graduation run, declared before it is built. A function
// rather than a var, matching the earlier phases (§15z).
func p4StepTable() []p4Step {
	return []p4Step{
		// --- the reference and the endpoint surface (criteria 7, 9, 14) --------
		{
			n: 1, covers: []int{7}, decides: []string{"D299", "D304"},
			what: "the connector declares a dated reference revision, and the snapshot behind it is committed",
			asserts: "THE DATE IS THE LABEL, THE SNAPSHOT IS THE EVIDENCE (D299). " +
				"`internal/connectors/fullstory/reference/<YYYY-MM>/` holds an endpoint manifest — " +
				"method, path, tier (v2, v1, beta), docs URL, date fetched — and the driver's " +
				"declared revision names exactly that directory. A revision with no snapshot, a " +
				"snapshot no revision names, or an entry missing a field fails. The manifest is " +
				"extracted, not a vendor file: the reference publishes no machine-readable spec",
			run: p4Step1,
		},
		{
			n: 2, covers: []int{7}, decides: []string{"D294", "D299"},
			what: "every endpoint the driver calls is in the snapshot",
			asserts: "DERIVED FROM THE DRIVER, NOT FROM A LIST BESIDE IT. The set of (method, path) " +
				"pairs the driver can send is read from the code — the same way archcheck reads " +
				"the tree — and each must match a manifest entry. An undocumented call is one the " +
				"vendor never promised (D294). Sabotaged by adding a path the manifest lacks: the " +
				"step must name it",
			run: p4Step2,
		},
		{
			n: 3, covers: []int{9}, decides: []string{"D294", "D301", "D314"},
			what: "every snapshot endpoint is implemented or excluded by a named decision",
			asserts: "THE OTHER DIRECTION OF \"IN FULL\", which criterion 7 does not check. Each " +
				"manifest entry is either reached by an advertised action or marked excluded with " +
				"the decision that excluded it — the data and segment export families by D301, " +
				"because data export is legacy. An entry that is neither fails, naming it. The " +
				"operations API is excluded only where it polls an export; any other use is " +
				"carried",
			run: p4Step3,
		},
		{
			n: 4, covers: []int{9}, decides: []string{"D294"},
			what: "every endpoint Lexicon's Fullstory.js calls is classified",
			asserts: "The Lexicon audit is an ARTEFACT, not a memory: each endpoint `Fullstory.js` " +
				"calls is listed as carried, not carried (undocumented) or excluded (a decision), " +
				"and the list is complete against a read-only parse of the file. An undocumented " +
				"endpoint Lexicon found convenient is recorded as not carried, so its omission " +
				"is a decision rather than a gap somebody later fills",
			run: p4Step4,
		},
		{
			n: 5, covers: []int{14}, decides: []string{"D299", "D311"},
			what: "reference drift fails the live run and never the build",
			asserts: "The ordinary run checks against the committed snapshot and touches no network, " +
				"so the build is reproducible offline. Under `make acceptance-live` an arm compares " +
				"the snapshot with the currently published reference and fails naming each " +
				"endpoint added, removed or moved between tiers, GRADED IN THE PUBLISHED DRIFT " +
				"VOCABULARY (D311): newly published is `unvetted`, gone from the documentation is " +
				"`withheld`, a tier move is `informational` — the API half of the hybrid Fullstory " +
				"connector drifts at release, its MCP half at run time, and an operator reads both " +
				"in one language. `sekizui-mcpspec`'s vendor drift check is the precedent. Proven both ways against a fixture reference: an identical " +
				"one passes, a drifted one fails with the three kinds of difference named. A newly " +
				"published export endpoint still surfaces: excluded is a decision about KNOWN " +
				"endpoints, not a filter on the comparison",
			run: p4Step5,
		},

		// --- residency (criteria 1, 2, 3, 6) ------------------------------------
		{
			n: 6, covers: []int{1}, decides: []string{"D29", "D304", "D320"},
			what: "one agent reads two Fullstory orgs in different DCs",
			asserts: "An na1 target and an eu1 target, one agent granted both, and a read that " +
				"succeeds against each through its own host (D288's allowlist holds per DC). " +
				"Residency is on the Target and on every envelope the eu1 org produces. PROVEN WITH " +
				"TWO FIXTURE DCs: an eu1 target dials `api.eu1.fullstory.com`, the dedicated EU1 DC " +
				"(D304), and an na1 target `api.fullstory.com`. A real eu1 org proves only the " +
				"vendor's half, and there is no live arm: no eu1 key can be had and the endpoints are " +
				"confirmed by the maintainer (D324). The DCs are fixtures behind their " +
				"REAL hostnames, so D288's allowlist runs as shipped and each fixture asserts the " +
				"host and org key it received (D320)",
			run: p4Step6,
		},
		{
			n: 7, covers: []int{2}, decides: []string{"D29"},
			what: "a cross-region resolve is refused, and the refusal is audited",
			asserts: "A deployment ceiling of one class and a target of another: the command is " +
				"refused BEFORE resolve with `refused_by` naming residency, and the decision record " +
				"carries it. Asserted on the record's stage and status, never `!= STATUS_OK` — a " +
				"negative assertion is satisfied by the absence of an answer (D138's lesson)",
			run: p4Step7,
		},
		{
			n: 8, covers: []int{6}, decides: []string{"D29", "D52", "D320"},
			what: "the MCP target refuses a cross-region resolve exactly as the native driver does",
			asserts: "Otherwise it is the hole in the guarantee P4 exists to establish. The same " +
				"cross-region pair through the MCP target yields the same refusal — same stage, " +
				"status and kind — and the same audit shape as step 7",
			run: p4Step8,
		},
		{
			n: 9, covers: []int{3}, decides: []string{"D29"},
			what: "EU-resident decision records land in an EU-resident audit destination",
			asserts: "THE TRAP IN D29 ITEM 4: the command is correctly regional and its audit row is " +
				"not. A residency-partitioned asynchronous sink (D274: non-warehouse — the " +
				"warehouse is P6's) routes each record by the residency of what it records; an eu1 " +
				"decision is found in the EU destination and absent from every other. Retires the " +
				"ledger's `audit:ship`",
			run: p4Step9,
		},
		{
			n: 10, covers: []int{3}, decides: []string{"D29"},
			what: "a sink that cannot accept records raises audit_unavailable, and nothing is lost",
			asserts: "§5.2.2's one unacceptable failure. The sink is asynchronous, so the record is " +
				"durable locally first (D147: audit fails closed but LOCALLY) and shipping catches " +
				"up; a destination refusing records raises the `audit_unavailable` signal an anzen " +
				"rule can act on. Retires the ledger's `signal:audit_unavailable`",
			run: p4Step10,
		},

		// --- properties and coexistence (criteria 4, 5, 15) ---------------------
		{
			n: 11, covers: []int{4},
			what: "P1's property test holds with Fullstory in the mix",
			asserts: "The randomised tenancy property from P1 re-run over a population that " +
				"includes both Fullstory DCs and the MCP target: no command reaches a target its " +
				"principal's grants and the residency ceiling do not both admit. Seeded, and the " +
				"seed is printed so a failure replays",
			run: p4Step11,
		},
		{
			n: 12, covers: []int{5}, decides: []string{"D52", "D323"},
			what: "a capability denied on the native driver cannot be obtained through the MCP target",
			asserts: "D52's union property, by test rather than review: an agent denied a read on " +
				"the native driver, and granted the MCP target for other tools, cannot reach the " +
				"same data through any MCP tool. Grant review reports the UNION of what a principal " +
				"reaches across both targets, so a reviewer sees one answer, not two. ENFORCED WHERE " +
				"A HUMAN DECLARED IT (D323): each vetted tool on a target sharing a budget with native " +
				"ones states what it mirrors — actions, `none`, or `opaque`, the whole surface — and " +
				"is refused unless the caller holds it; Describe pairs each tool with its relation",
			run: p4Step12,
		},
		{
			n: 13, covers: []int{15}, decides: []string{"D52"},
			what: "the native driver and the MCP target share one upstream limiter key per org",
			asserts: "Two targets, one vendor quota. A 429 through either drains the shared bucket " +
				"(P1: the upstream is the authority on its own quota), and the other target sees " +
				"the reduced budget on its next call. Without this each spends the org's quota " +
				"believing it has all of it",
			run: p4Step13,
		},

		// --- reflex files and the vocabulary (criteria 12, 13) ------------------
		{
			n: 14, covers: []int{13}, decides: []string{"D298", "D299"},
			what: "a connector's reflexes ship embedded and are available, not imposed",
			asserts: "`reflexes.yaml` is embedded in the driver beside `schemas.yaml` and offered by " +
				"name; a rule reaches a caller only through the deployment's `refinements:`. A " +
				"driver version that adds a rule changes nothing any caller receives until a " +
				"deployment imposes it — upgrading a driver must never silently change an agent's " +
				"input. `mode:` on a refines: rule refuses the boot: it never actuates, so it is " +
				"staged by audience, not shadow (D298)",
			run: p4Step14,
		},
		{
			n: 15, covers: []int{13}, decides: []string{"D301"},
			what: "the login template refuses to be imposed bare, and defaults its window to 60 seconds",
			asserts: "Imposed without `signin_prefix` or `success_prefix` the boot refuses, naming " +
				"the parameter. With both, `within_s` is 60 unless the imposition says otherwise — the " +
				"window runs from arriving on the sign-in page, so it holds the person typing as well as " +
				"the redirects (D317 revising D301's 15)",
			run: p4Step15,
		},
		{
			n: 16, covers: []int{12}, decides: []string{"D263", "D300"},
			what: "the refinement vocabulary is closed",
			asserts: "An unknown operator, output shape or field refuses the boot; so does a pairing " +
				"inside a pairing (ONE level). `prefix` is in the shared operator set and a bus " +
				"rule may use it. Adding to the vocabulary is a code change and a review, never a " +
				"config trick (D263)",
			run: p4Step16,
		},
		{
			n: 17, covers: []int{12}, decides: []string{"D292", "D300"},
			what: "a rule's paths, windows, limits and keys are checked at boot",
			asserts: "Paths resolve through the family NARROWED BY THE RULE'S OWN `event_type`: " +
				"`event_properties.fs-form-name` resolves under `event_type: click` and is refused " +
				"unpinned (D292). `within_s` and `duration_s` refuse unless the time path is " +
				"declared `format: date-time`. `limit` is required and at most the input bound. " +
				"Two rules imposed on one target and audience that write one key refuse the boot. " +
				"Each arm sabotaged",
			run: p4Step17,
		},

		// --- seiren (criteria 8, 10, 11) -------------------------------------------
		{
			n: 18, covers: []int{8}, decides: []string{"D297", "D298", "D301"},
			what: "the four built-ins turn a real Generate Context result into seiren",
			asserts: "Over one real web session from EXAMPLE, captured THROUGH THE REAL BINARY as shaped " +
				"rows (`make capture-seiren`, D317) and replayed from the committed fixture: `login` pairs " +
				"`/checkout#login` with `/checkout#billing` 24.386s later — a login the old 15s window would " +
				"have missed (D317 revising D301); `errors` lists the error-click AND finds it as the cause " +
				"of the console error (+153ms) and the network error (+198ms); `frustration` counts 19 " +
				"rage-clicks on one search page; `path` lists every page with its dwell; the window is the " +
				"whole session. The rules are Fullstory's worked EXAMPLE of the Refiner contract, and mobile " +
				"is not asserted (the maintainer, D317)",
			run: p4Step18,
		},
		{
			n: 19, covers: []int{8}, decides: []string{"D298"},
			what: "seiren reaches the audience it is imposed on and nobody else",
			asserts: "Imposed `for: [agent:a]`: agent:a's response carries seiren, agent:b's — same " +
				"call, same target — carries none. Staging by audience is the whole of the " +
				"staging mechanism for refines:, so this is the step that makes \"widen once the " +
				"seiren looks right\" a property rather than advice",
			run: p4Step19,
		},
		{
			n: 20, covers: []int{10}, decides: []string{"D297", "D300"},
			what: "silver and seiren arrive in one response",
			asserts: "`QueryResponse.rows` stays silver and `seiren` is one typed field beside it; " +
				"`CommandResult` carries it beside `result`. Seiren is IMPOSED — the caller sets " +
				"nothing — and it never replaces silver",
			run: p4Step20,
		},
		{
			n: 21, covers: []int{10}, decides: []string{"D300"},
			what: "seiren is computed over the whole result before paging, and states its window",
			asserts: "A login click on page 1 and its navigate on page 2 pair. `window` carries the " +
				"first and last event time and `truncated`, true when Generate Context returned " +
				"its LAST events rather than the session — so \"no login in the last 200 events\" " +
				"cannot read as \"no login in this session\"",
			run: p4Step21,
		},
		{
			n: 22, covers: []int{11}, decides: []string{"D300"},
			what: "a rule runs when its own inputs survived the lens, and seiren says what did not",
			asserts: "A lens withholding `page_url`: `errors` is present, `path` and `frustration` " +
				"are listed under `unavailable` with the reason. Boot refuses an imposed rule that " +
				"can never build under its audience's imposed lens; a caller-chosen lens is checked " +
				"at run time. A row removed under a refines: rule is refused, because it would " +
				"silently falsify a sequence",
			run: p4Step22,
		},
		{
			n: 23, covers: []int{10}, decides: []string{"D300"},
			what: "seiren is deterministic",
			asserts: "The same rows in a shuffled vendor order produce byte-identical seiren: the " +
				"engine sorts by time and breaks ties by response position rather than trusting " +
				"the vendor. D298's replay proof rests on this. An unparseable time is an error, " +
				"not a false (D42)",
			run: p4Step23,
		},
		{
			n: 24, covers: []int{8, 11}, decides: []string{"D297"},
			what: "seiren is built only from lensed rows, and a withheld value appears nowhere",
			asserts: "D269's disclosure path, aimed at seiren: a field the caller's lens withholds is " +
				"absent from the response's BYTES — rows, seiren, and `unavailable`'s reason text " +
				"alike. Sabotaged by building seiren before the lens",
			run: p4Step24,
		},

		// --- discovery and identity (criteria 16, 17, 18) -----------------------
		{
			n: 25, covers: []int{16}, decides: []string{"D298", "D302"},
			what: "Describe reports every refinement imposed on the principal asking",
			asserts: "`imposed_refinements` names each rule, its seiren type's schema URI, the key it " +
				"writes and whether it makes lookups — derived from the same `refinements:` the " +
				"engine reads, so it cannot advertise seiren that does not arrive or omit seiren that " +
				"does. A principal with nothing imposed sees an empty list, not an absent field. " +
				"Sabotaged by imposing a rule the catalog does not read",
			run: p4Step25,
		},
		{
			n: 26, covers: []int{17}, decides: []string{"D303"},
			what: "a token from the pinned issuer names the subject, and the record says SIGNED",
			asserts: "The caller still proves itself by mTLS; the token, in metadata, names the " +
				"subject. The decision record carries the subject as `SIGNED` with its issuer, " +
				"beside D57's `ASSERTED`, and the chain is unchanged in shape — tier two is a " +
				"verification upgrade, not a schema migration (§4.4.2)",
			run: p4Step26,
		},
		{
			n: 27, covers: []int{17}, decides: []string{"D303"},
			what: "a token that is not a valid one from a configured issuer refuses before policy",
			asserts: "One arm per check, each refusing loudly with its reason and never reaching " +
				"policy: an unknown issuer; `alg: none`; an HMAC token against an RSA key; `aud` " +
				"naming another service; expired; not yet valid; a bad signature; an unknown role. " +
				"The in-perimeter adversary REPLAYS tokens, so the replay arms (audience, time) " +
				"are the ones this step exists for",
			run: p4Step27,
		},
		{
			n: 28, covers: []int{17}, decides: []string{"D303"},
			what: "a token bound to another certificate refuses, and an unbound one refuses by default",
			asserts: "RFC 8705: `cnf.x5t#S256` is compared with the connection's certificate (the " +
				"hash `identity.fingerprint` already computes). A mismatch ALWAYS refuses. An " +
				"unbound token refuses unless its issuer sets `require_bound: false`, and then the " +
				"record says `unbound`. Through a mesh, the token bound to the mesh's certificate " +
				"is accepted from the mesh and refused from the agent it names",
			run: p4Step28,
		},
		{
			n: 29, covers: []int{17}, decides: []string{"D303"},
			what: "issuer keys come through file://, rotate, and cost no network on the request path",
			asserts: "The issuer's public keys resolve through the `file://` provider under its " +
				"credential root (D286); a rotated key file is picked up and a token signed by the " +
				"retired key then refuses. Asserted with no network reachable, because a key fetch " +
				"on the request path is the dependency the skeleton exists to avoid",
			run: p4Step29,
		},
		{
			n: 30, covers: []int{18}, decides: []string{"D303"},
			what: "a role selects Sekizui's grant set, and a token may only narrow it",
			asserts: "The token's role selects a grant set from Sekizui's own configuration; the " +
				"record names the individual subject. Grants listed in the token intersect with " +
				"the role's, lenses listed in it add. A token claiming a grant its role lacks gets " +
				"the role's grants only, and the record notes the excess claim — a forged " +
				"\"architect\" token gets architect's grants and nothing beyond",
			run: p4Step30,
		},

		// --- the whole MCP (criterion 19) ------------------------------------------
		{
			n: 31, covers: []int{19}, decides: []string{"D306", "D307", "D308"},
			what: "the Fullstory MCP ships every tool it serves, vetted, and grants decide exposure",
			asserts: "The shipped fragment holds exactly the tools the live tools/list served on " +
				"2026-09-26 but the deprecated `session_view`; every JSON tool's output schema is " +
				"COPIED (origin vendor); the ten tools that allocate or save something are mutating " +
				"with their ruled idempotency, so a grant can withhold them; it validates beside a " +
				"real target and every tool is an advertised action; and compute_metric's value and " +
				"its comparison survive the closed boundary (D306). Whether the LIVE server still " +
				"serves exactly these is the drift check's question",
			run: p4Step31,
		},

		// --- drift, recorded (criterion 20) ------------------------------------------
		{
			n: 32, covers: []int{20}, decides: []string{"D311"},
			what: "every drift comparison is admitted and recorded like a poll, and a finding survives a restart",
			asserts: "A drift comparison is an outbound call with the target's credential, so it passes " +
				"the ceilings a poll passes and leaves a decision record as the built-in " +
				"`sekizui:drift-watcher`: a CLEAN comparison records `drift:clean` (a check that found " +
				"nothing still happened), a divergence records `drift:diverged` with every finding, " +
				"and a comparison the ceilings refuse is recorded as refused and never reaches the " +
				"server. The state persists beside the audit log: a withdrawn tool is still withheld " +
				"after a restart, and only a fresh clean comparison releases it",
			run: p4Step32,
		},

		// --- anzen, suggested by the connector (criterion 21) ------------------------
		{
			n: 33, covers: []int{21}, decides: []string{"D314"},
			what: "the Fullstory connector's suggested anzen ceiling holds under a wildcard grant",
			asserts: "The connector ships `internal/connectors/fullstory/anzen.yaml` (blueprint step 8): two rules " +
				"forbidding its three IRREVERSIBLE operations and nine RECORDING-CONFIGURATION writes, " +
				"every name a real write it advertises. Loaded beside a WILDCARD grant, each is " +
				"refused — recorded refused_by anzen with its rule, reported by Describe as withheld " +
				"by that rule — and none reaches Fullstory; a write the ceiling does not name passes " +
				"anzen and policy under the same grant, so the refusals are the ceiling's",
			run: p4Step33,
		},

		// --- the connector folder (criterion 22) -------------------------------------
		{
			n: 34, covers: []int{22}, decides: []string{"D316"},
			what: "every in-tree connector is one complete folder, and the build refuses one that is not",
			asserts: "Every folder under `internal/connectors/` passes `connectorcheck.Check`, the function " +
				"the build guard runs: a README; a driver folder ships schemas.yaml, is registered in " +
				"internal/builtin, and runs conformance.Run plus RunSource and RunDrift for what the " +
				"registered driver implements; a folder with no code ships an mcp.yaml that validates; " +
				"anzen.yaml, mcp.yaml, reflexes.yaml and reference/ load when present. Every registered " +
				"driver lives in a folder or is a shared driver, `internal/driver/` holds only shared " +
				"drivers, and `specs/` is gone. A planted tree missing each of those is refused, beside " +
				"a complete MCP-only folder that is not; and the guards that find connectors by walking " +
				"the tree examine every registered driver",
			run: p4Step34,
		},
	}
}

func TestP4Acceptance(t *testing.T) {
	built := 0
	for _, s := range p4StepTable() {
		if s.run != nil {
			built++
		}
	}
	t.Logf("P4 acceptance: %d/%d steps built", built, len(p4StepTable()))

	for _, s := range p4StepTable() {
		t.Run(fmt.Sprintf("%02d_%s", s.n, slug(s.what)), func(t *testing.T) {
			st := evidence.open("P4", s.n, s.what, firstSentence(s.asserts), s.covers, s.decides)
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

// TestP4StepsAreWellFormed. A placeholder with no stated assertion will be
// written to pass rather than to prove.
func TestP4StepsAreWellFormed(t *testing.T) {
	seen := map[int]bool{}
	for _, s := range p4StepTable() {
		if s.what == "" || s.asserts == "" {
			t.Errorf("step %d has no narration or no stated assertion", s.n)
		}
		if len(s.covers) == 0 {
			t.Errorf("step %d (%s) discharges no exit criterion; either it is not P4's "+
				"business or the criteria list is missing one", s.n, s.what)
		}
		for _, c := range s.covers {
			if _, ok := p4ExitCriteria[c]; !ok {
				t.Errorf("step %d claims exit criterion %d, which does not exist", s.n, c)
			}
		}
		if seen[s.n] {
			t.Errorf("step number %d is used twice", s.n)
		}
		seen[s.n] = true
	}
}

// TestP4CoversItsExitCriteria — a criterion with no step is a criterion nobody
// will prove.
func TestP4CoversItsExitCriteria(t *testing.T) {
	covered := map[int]bool{}
	for _, s := range p4StepTable() {
		for _, c := range s.covers {
			covered[c] = true
		}
	}

	var orphans []string
	for c, desc := range p4ExitCriteria {
		if !covered[c] {
			orphans = append(orphans, fmt.Sprintf("%d: %s", c, desc))
		}
	}
	sort.Strings(orphans)

	if len(orphans) > 0 {
		t.Errorf("%d P4 exit criterion/criteria have no acceptance step:\n  %s\n\n"+
			"Add a step, or move the criterion — an exit criterion nobody proves is a "+
			"phase that graduates on a claim.", len(orphans), strings.Join(orphans, "\n  "))
	}
}

func TestP4CompletionIsHonest(t *testing.T) {
	if !p4Complete {
		return
	}
	var unbuilt []string
	for _, s := range p4StepTable() {
		if s.run == nil {
			unbuilt = append(unbuilt, fmt.Sprintf("%d: %s", s.n, s.what))
		}
	}
	if len(unbuilt) > 0 {
		t.Errorf("P4 is marked complete with %d unbuilt step(s):\n  %s\n\n"+
			"Either build them or move them out of the phase — a step that skips is a "+
			"commitment, and marking the phase done turns it into a claim.",
			len(unbuilt), strings.Join(unbuilt, "\n  "))
	}
}
