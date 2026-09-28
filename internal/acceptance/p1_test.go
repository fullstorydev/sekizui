package acceptance

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// P1's graduation run, declared before it is built.
//
// WHY THE SKELETON COMES FIRST. P0's init ledger worked because everything the
// phase still owed was declared where a boot would report it, so nothing could
// be quietly forgotten. This is the same instrument aimed at the acceptance run:
// every step P1 must prove exists here from the start, and an unbuilt one SKIPS
// LOUDLY with the assertion it will make rather than being absent.
//
// The difference between absent and skipped is the whole point. An absent step
// is indistinguishable from a step nobody thought of; a skipped one is a
// commitment with a name attached, and `go test -v` prints the list.
//
// Each step names the P1 exit criteria it discharges. TestP1CoversItsExitCriteria
// fails when a criterion has no step, which is what stops the run drifting away
// from the phase it is supposed to graduate.

// p1Step is one planned assertion.
type p1Step struct {
	n int

	// what is the narration, in the same voice as the P0 run.
	what string

	// asserts is what this step will prove. REQUIRED even when unbuilt, because
	// a placeholder with no stated assertion is a step nobody has thought
	// through, and it will be written to pass rather than to prove.
	asserts string

	// covers names the P1 exit criteria from DESIGN §12 this step discharges.
	covers []int

	// decides names the decision records this step proves, where one exists.
	// Optional: many steps discharge a criterion without a decision behind them.
	decides []string

	// run is nil until the step is built.
	run func(t *testing.T)
}

// p1ExitCriteria is DESIGN §12 P1's numbered list, restated so the mapping is
// mechanical rather than a claim in a comment.
//
//nolint:gochecknoglobals // immutable table, read once
var p1ExitCriteria = map[int]string{
	1:  "interleaved N-tenant streams: every response's tenant matches its request's",
	2:  "-race clean under that load",
	3:  "rotation invalidates the pooled client, under BOTH a pinned and a tracking ref",
	4:  "CI lint rejects package-level mutable state",
	12: "no pool entry outlives max_lifetime; a target cannot exceed the deployment ceiling",
	13: "credential_stale reaches zero after rotation, and anzen can act on it",
	14: "a mutating action with no idempotency key refuses to retry on a 429",
	15: "PoolKey cannot be printed",
	5:  "egress-time tenant assertion fires in a deliberately-broken-pool test",
	7:  "boot refuses env:// off-bare, a cross-cloud ambient claim, and an empty credential",
	8:  "a credential is resolved once per TTL, not once per command",
	9:  "Secret.Wipe is called on cache eviction",
	10: "break-glass is correct under EITHER platform behaviour for a tracking reference, and a pinned reference that stops resolving fails closed",
	11: "a subPath-mounted credential reports rotation=NONE at boot",
	16: "every decision record names the CONFIGURATION that authorised it, by content",
	17: "boot refuses a configuration the deployment did not ship, on the DEPLOYER's word rather than a peer's",
	18: "a TRACKING credential reference cannot resolve backwards, and the mark survives a restart",
	19: "every ceiling and control applies to READS as well as writes — one enforcement path, not two",
}

// p1Complete is flipped when P1 graduates. TestP1CompletionIsHonest fails if it
// is true while any step is unbuilt, so "declared" cannot quietly become "done"
// (D114).
const p1Complete = true

// repoRoot returns the module root.
//
// KEPT AS A NAME AND NOT AS AN IMPLEMENTATION (D185). It was one of SIX walks up
// to go.mod — `moduleRoot` was a second one in this same package — and the walk
// now lives in docref.Root. The name stays because a dozen call sites read
// better with it than with a two-line error check each.
func repoRoot(t *testing.T) string {
	t.Helper()
	return mustRoot(t)
}

// p1StepTable is P1's graduation run, complete and signed off.
//
// A FUNCTION RATHER THAN A VAR, moved with P2's for the reason that file records:
// Go's initialization-cycle rule applies to variables and not to functions
// (§15z), and step 33 refers to both tables. Kept in the same shape as P2's
// deliberately — two tables describing the same kind of thing differently is how
// the reporting drifts.
func p1StepTable() []p1Step {
	return []p1Step{
		// --- one enforcement path, not two (D155) --------------------------------
		{
			n: 68, covers: []int{19}, decides: []string{"D18", "D155", "D253"},
			run:     step68EveryCeilingAppliesToReadsToo,
			what:    "every ceiling and control applies to reads as well as writes",
			asserts: "found by trying to build step 35, and the retry was the least of it. `Query` ran admission, identity and policy, and skipped the runtime grant suspension (D146), the anzen guard (D65, D71), the withdrawal check (D133) and all three of §4.3.4's controls. THE PROOF DESERVES STATING: a probe revoked a credential with `sekizui.revoke_credential` and then read from the target — STATUS_OK, one row. A read succeeded with a credential an operator had just declared compromised, which is a hole in break-glass rather than a missing nicety, and §4.1.1's own words are that an unbounded scan is a data-exfiltration path. D18 forbids it in twelve words — `No second code path, no hole in the audit log` — written about reflexes, and the principle is not about reflexes: the second path arrived as a verb growing its own abbreviated copy, each omission invisible because Query reads like a shorter version rather than a weaker one. Fixed with SHARED CODE, not copied checks, because copying is how two paths drift again and silently. Two arms: the behavioural one proves break-glass now covers reads and that the refusal names WHICH stage (QueryResponse had no `refused_by` either, so a refused read could not distinguish a missing grant from a revoked credential); and an AST arm requires every target-resolving verb to call the shared sequence, which is the guard for a class D155 records as otherwise unguarded — every other mechanism here checks that a declared thing exists and is reached, and none checks that two entry points enforce the same SET, because that is a claim about a relationship between paths rather than about any one of them",
		},

		// --- credential versions only move forward (D152) ------------------------
		{
			n: 67, covers: []int{18}, decides: []string{"D152"},
			run:     step67ATrackingReferenceCannotResolveBackwards,
			what:    "a TRACKING credential reference cannot resolve backwards",
			asserts: "replaces a question rather than answering it. CONTRACTS item 26 asked what `gcp-sm://.../versions/latest` does when the newest version is DISABLED — which is the break-glass action §4.7.10 depends on. Google's documentation was read, not assumed: it says only that a version may be \"a version number as a string (e.g. '5') or an alias (e.g. 'latest')\" and nothing whatever about disabled versions. AN UNSPECIFIED BEHAVIOUR IS NOT A CONTRACT, and D105's characterisation test would have reported what one project in one region against one API version did on one day, leaving break-glass resting on the accident. THE AMBIGUITY IS THE ATTACK: if `latest` fails, disabling the newest version IS break-glass; if it falls back to the newest ENABLED version, then disabling a compromised version silently reverts every caller to the previous credential while every log line reports success. So the guard removes the dependency — a tracking reference may only move FORWARD. Six arms. Forward is permitted and the mark advances, or D99's tracking references lose their entire point. Backwards is REFUSED, naming both versions and the PIN remedy, because an operator told only that something is wrong cannot tell a platform fallback from an attacker and has no way forward for a deliberate rollback. The mark is DURABLE, or a restart is how the guard gets cleared — D145's lesson applied before it could be repeated. An UNORDERED version is not compared at all, which is what keeps `file://` working, since a content digest has no older or newer and inventing one would refuse legitimate edits. A store that cannot LOAD fails the boot; a store that cannot WRITE does NOT refuse the credential — the asymmetry is D150's rule, that fail-closed is right against integrity and IS the attack against availability",
		},

		// --- what a record says authorised it (D149, D150) ----------------------
		{
			n: 66, covers: []int{17}, decides: []string{"D150"},
			run:     step66BootRefusesAConfigurationTheDeploymentDidNotShip,
			what:    "boot refuses a configuration the deployment did not ship, and the authority is the DEPLOYER not a peer",
			asserts: "The maintainer's question found the hole in D148: self-adjudication moved the AUTHORITY inside the replica and left the EVIDENCE outside it, so forging a peer majority makes every honest replica withdraw ITSELF — the fleet-wide outage refusing peer enforcement was supposed to prevent, one layer in and harder to see because each replica's own decision is locally correct. The rule made explicit: never let attacker-influenceable input cause an automatic REDUCTION IN SERVICE, because fail-closed is right against confidentiality and integrity and IS the attack against availability. The fix needs no peers at all — the pipeline that shipped a configuration knows what it shipped, and an attacker who can set the flag already owns the deployment, which is outside the trust boundary the way the credential-source killswitch is. BOOT, NOT RUNTIME: a refusal is a deploy that fails, visible and contained, leaving the replicas already running untouched (§4.9a.2's rule that a rejected config leaves the previous one in force); the same signal at runtime is the outage. Proven on four axes. The shipped hash is accepted and hex case is not a mismatch, or the guard fails on presentation and gets switched off. AN UNSET EXPECTATION DOES NOT REFUSE — the load-bearing default, because a guard that refuses when nobody configured it turns an unset flag into exactly the fleet-wide failure this decision exists to avoid. A mismatch names BOTH hashes, since an operator told only that theirs is wrong cannot tell a stale deploy from a tampered file. And a MALFORMED expectation is KindInvalidArgument rather than KindConfig — D138's split, because a hash truncated by a copy-paste must not read as a compromised deployment. Non-vacuity ties it to the document rather than to string comparison: rewriting a grant's principal must make the shipped hash stop matching",
		},

		{
			n: 65, covers: []int{16}, decides: []string{"D149"},
			run:     step65ConfigIdentityIsOnEveryRecord,
			what:    "every decision record names the configuration that authorised it, by CONTENT",
			asserts: "§4.9a.2 and pkg/config/file.go both stated that `Document.Version` is recorded on decisions so an audit row names the spec that authorised the call. Nothing recorded it: it was logged once at boot and reached no record — CONTRACTS item 23's class, an unpopulated proto field, where the log reads as complete because the column is ABSENT rather than wrong. Version could not have kept the promise either, and fails in both directions: it defaults to `<file>@<mtime>`, so the same configuration deployed to two replicas differs, and `touch -r` makes two different configurations agree — the second silently. So the record carries an IDENTITY derived from the compiled document. Proven on four axes: provenance does not move it (or two replicas serving identical policy attest as divergent forever, which is what D148 needs); reformatting does not move it (an integrity signal that fires on whitespace is one operators learn to ignore); a changed grant DOES (non-vacuity — everything else is satisfied by a constant); and a grant REORDER does too, deliberately, because `matched_rule` reads `agent:triage#allow[0]` and two documents differing in order do not explain their own records identically. Then end-to-end: every row carries it, every row agrees, and the value is the document's real identity rather than merely non-empty — a non-empty check is satisfied by any placeholder a wiring site passes, which is the assertion shape D138 caught being satisfied by the absence of an answer",
		},

		// --- the cache, which everything else depends on ------------------------
		{
			n: 1, covers: []int{8}, run: step1CachedResolution,
			what:    "credential resolved once per TTL, not once per command",
			asserts: "N commands against one target produce exactly ONE provider call. This is §4.7.6's blocker: with gcp-sm:// the current behaviour is an API call per command",
		},
		{
			n: 2, covers: []int{8}, run: step2Singleflight,
			what:    "concurrent first-resolves are singleflighted",
			asserts: "N goroutines meeting a cold cache produce one provider call, not N — otherwise every cold start stampedes the secret manager",
		},
		{
			n: 3, covers: []int{8}, run: step3JitterIsPerInstance,
			what:    "TTL jitter is per-instance, not per-key",
			asserts: "two Resolvers with identical config refresh at DIFFERENT times. Jitter derived from the key alone is identical across replicas and defeats itself",
		},

		// --- rotation and eviction ----------------------------------------------
		{
			n: 4, covers: []int{3}, decides: []string{"D99"}, run: step4RotationPinned,
			what:    "rotation under a PINNED ref invalidates the pooled client",
			asserts: "changing versions/7 to versions/8 produces a different PoolKey and a rebuilt client",
		},
		{
			n: 5, covers: []int{3}, decides: []string{"D99"}, run: step5RotationTracking,
			what:    "rotation under a TRACKING ref invalidates the pooled client",
			asserts: "the ref string is unchanged, so only content-addressing (D99) can detect this. The case the whole mechanism exists for",
		},
		{
			n: 6, covers: []int{3}, run: step6SupersededIsEvicted,
			what:    "the superseded pooled client is EVICTED, not merely superseded",
			asserts: "after rotation, no entry keyed on the old credential remains. A new key alone leaves the old client — holding a revoked credential — alive until idle eviction",
		},
		{
			n: 7, covers: []int{9}, run: step7WipeOnEviction,
			what:    "Secret.Wipe runs on eviction and the backing array is zeroed",
			asserts: "invariant 4 of §4.7.5, which has had no caller since it was written",
		},
		{
			n: 8, covers: []int{9, 2},
			what:    "eviction never races an in-flight call",
			decides: []string{"D110"},
			run:     step8EvictionNeverRacesInFlight,
			asserts: "a driver holding a Secret mid-call is unaffected by eviction, because eviction DRAINS before it wipes (D110). Under -race, since Secret is a slice and clear() reaches every holder of the backing array",
		},

		// --- credential binding classes (D101) -----------------------------------
		{
			n: 50, covers: []int{3}, decides: []string{"D101", "D132"},
			run:     step50Class1IsCredentialFree,
			what:    "a stateless driver picks up a rotated credential with no eviction",
			asserts: "class 1: the pooled client is genuinely credential-free, so a wiped credential stops the NEXT call rather than being cached somewhere. §4.7.1 said rotation is therefore instant; D132 declines to act on that — PoolKey carries credVer for every class without exception, because §6's rule that a key never drops a dimension is worth more than a rebuild class 1 could have skipped",
		},
		{
			n: 51, covers: []int{3}, decides: []string{"D101"},
			run:     step51Class2NeedsEviction,
			what:    "a credential-bound driver requires eviction to see a rotation",
			asserts: "class 2: the client was constructed WITH the credential and has no per-call seam, so nothing changes until PoolKey does. The case content-addressing exists for",
		},
		{
			n: 52, covers: []int{3}, decides: []string{"D101"},
			run:     step52Class3IsTornDown,
			what:    "a session-oriented driver is TORN DOWN, not dropped, on eviction",
			asserts: "class 3: dropping a pooled BigQuery client costs nothing; dropping an MCP session leaves server-side state and possibly a live authorised session. Proven by observing the close, not by inspecting the pool",
		},

		// --- break-glass (D106) --------------------------------------------------
		{
			n: 9, covers: []int{3}, decides: []string{"D106", "D127", "D128"},
			run:     step9RevocationCancelsInFlight,
			what:    "revoke_credential cancels in-flight calls",
			asserts: "an in-flight command fails with a cancellation, deterministically — not by receiving zeroed bytes and asking the upstream what it thinks. Asserted on the REASON: the driver reports context.Canceled, and the error reaching the record must still say `revoked`",
		},
		{
			n: 10, covers: []int{3}, decides: []string{"D106", "D129"},
			run:     step10BreakGlassIsRecorded,
			what:    "revocation writes a decision record naming what it cancelled",
			asserts: "the credential, the trigger, and the COUNT of cancelled in-flight calls — the number an incident review asks for and nothing else can reconstruct. Driven over mTLS as a granted principal (D129), with the non-vacuity half: an UNGRANTED principal is refused, or break-glass is a side door rather than a governed verb",
		},
		{
			n: 11, covers: []int{3}, decides: []string{"D106"},
			run:     step11SeveritiesDiffer,
			what:    "quarantine_target lets in-flight finish; revoke_credential does not",
			asserts: "the two severities are actually different, rather than one being an alias someone will later collapse. Same pool, same driver, one differing row of §4.7.10's table",
		},

		// --- boot refusals (D97, D98, D102) --------------------------------------
		{
			n: 12, covers: []int{7}, decides: []string{"D97"},
			run:     step12BootRefusesEnvOffADeveloperMachine,
			what:    "boot refuses env:// off a developer machine",
			asserts: "Execution != ExecutionBare refuses, and the message names -allow-env-credentials. Keyed on execution, so on-prem k8s does not escape",
		},
		{
			n: 13, covers: []int{7}, decides: []string{"D98", "D102"},
			run:     step13BootRefusesACrossCloudAmbientClaim,
			what:    "boot refuses a cross-cloud ambient claim",
			asserts: "ambient://gcp while the profile reports AWS, with the remedy named — tier 1, no I/O",
		},
		{
			n: 14, covers: []int{7}, decides: []string{"D98"},
			run:     step14BootRefusesAnEmptyCredential,
			what:    "boot refuses an empty credential, and a scheme with no provider",
			asserts: "an absence is no longer a silent 'no credential needed' (D98) — it conflated 'this target authenticates through workload identity' with 'somebody forgot the reference', and the refusal names ambient:// so an operator learns what to say instead rather than only that silence is wrong. A SECOND SILENCE, found while building the first: a scheme with no registered provider failed at FIRST USE, because the cache looks it up per resolve, so a target naming a scheme §4.7.2's table lists as P1 and nothing implements would boot clean and refuse its first command. That is what D42 exists to move to boot, and nothing was checking the table against the binary. The accepted set is DERIVED from the provider list rather than written beside it, because a hand-maintained list is correct when written and silently wrong the first time a provider is added — the recurring defect, in the guard rather than in the thing guarded",
		},
		{
			n: 15, covers: []int{7}, decides: []string{"D102"},
			run:     step15AmbientTierOneAndAHalfConfirmsFromLocalFiles,
			what:    "ambient tier 1.5 confirms from local files, with no network",
			asserts: "EKS and AKS fixtures resolve from AWS_WEB_IDENTITY_TOKEN_FILE / AZURE_FEDERATED_TOKEN_FILE alone",
		},
		{
			n: 16, covers: []int{7}, decides: []string{"D102"},
			run:     step16AmbientTierTwoProbesRetriesAndBoundsItsTimeout,
			what:    "ambient tier 2 probes, retries, and bounds its timeout",
			asserts: "against a fake metadata server: success, hard failure refuses, a slow server hits the bound rather than hanging, and a server that is late-but-ready is retried into success",
		},

		// --- posture reporting (D104) --------------------------------------------
		{
			n: 17, covers: []int{11}, decides: []string{"D103", "D104"},
			run:     step17AProjectedVolumeReportsRotationLive,
			what:    "a projected volume reports rotation=live",
			asserts: "against a real ..data symlink structure, not a mock",
		},
		{
			n: 18, covers: []int{11}, decides: []string{"D103", "D104"},
			run:     step18ASubPathMountReportsRotationNoneAndWarns,
			what:    "a subPath mount reports rotation=NONE and warns",
			asserts: "the silent failure of §4.7.8 becomes a stated fact. Warns rather than refuses: a static credential is legitimate, believing it rotates is not",
		},
		{
			n: 19, covers: []int{11}, decides: []string{"D100", "D104", "D119"},
			run:     step19PostureReachesTheDecisionRecord,
			what:    "posture reaches the decision record, not only the boot log",
			asserts: "D104's boot report states the posture ONCE, to whoever is watching a terminal at startup, and that is the wrong artefact for the question an auditor asks — `which targets were reachable with an unrotatable credential last quarter` needs it per ACTION, from a record that stands alone (§5.4). D100 specified the SCHEME alone; D119 widened it to scheme, resolved version, rotation, audited-reads and at_rest, and what makes the widening safe is D118 — decisions provably reach no bus consumer, so the reconnaissance concern that argued for restraint does not apply. Proven against a REAL ..data symlink tree, so `rotation=live` on the record is a fact the step established rather than a string it asked for. THE FIELD IS `at_rest`, NEVER `material`, on D119's explicit ruling: a field name is the only documentation most readers get, and an earlier draft called it `material`, which read as though the bytes might be in there. The step asserts that too, bluntly — the credential material must appear NOWHERE in the record, checked against the actual bytes rather than against named fields, because a field added later with a plausible name is the only way this could be lost",
		},

		// --- limiter -------------------------------------------------------------
		{
			n: 20, covers: []int{1}, decides: []string{"D14", "D140"},
			run:     step20RetryAfterIsHonouredAndBounded,
			what:    "429 and Retry-After are honoured with bounded backoff",
			asserts: "the upstream's own number is used where present, and backoff is capped rather than unbounded",
		},
		{
			n: 21, covers: []int{1, 14}, decides: []string{"D113"},
			run:     step21RetryNeverDuplicatesAnUnkeyedWrite,
			what:    "a retry never duplicates a mutating action without an idempotency key",
			asserts: "P1 brings retries and P2 brings the dedupe window, so this ordering hazard is real: a retried 429 on a mutating call must refuse rather than risk a double write",
		},
		{
			n: 22, covers: []int{1}, decides: []string{"D141"},
			run:     step22BreakerOpensHalfOpensAndCloses,
			what:    "the breaker opens, half-opens, and closes",
			asserts: "and a breaker open on one target does not affect another — health is a property of the upstream, not of the process, and a mis-keyed breaker is a global kill switch whose symptom is a healthy target going dark for reasons its own metrics cannot explain. Half-open admits exactly ONE probe: everyone else waits for its answer rather than joining it, or the stampede the breaker was opened to prevent is merely rescheduled to the instant the cooldown expires. A failed probe re-opens FROM NOW; a successful one closes outright, because the trip counts CONSECUTIVE failures and one success already breaks the streak",
		},
		{
			n: 23, covers: []int{1}, decides: []string{"D143"},
			run:     step23FairnessUnderASharedTargetLimit,
			what:    "per-principal fairness under a shared target limit",
			asserts: "BOTH of §4.3.4's named failures, because avoiding either alone is easy and wrong. A LONE principal uses the whole budget — fixed equal shares would cap the only agent working at a third of a quota nobody else wants, and a control that over-throttles gets switched off. Under CONTENTION a saturating principal is cut off before the budget is gone AND a quiet one still gets through; asserting only the first would pass on a limiter that had simply run the target dry. Plus: the monopolising principal is NAMEABLE, because `denial_storm` fires on the victims and sends an operator to the wrong principal — a monopoliser is not itself denied at first, it causes others to be. A lone principal is never reported, or the signal fires on every single-agent deployment. And a 429 DRAINS the local bucket rather than merely being recorded",
		},

		// --- tenancy, under a real pool ------------------------------------------
		{
			n: 24, covers: []int{1, 2},
			run:     step24MixedTenancyHoldsWithPooling,
			what:    "mixed-tenant concurrency still holds WITH pooling",
			asserts: "the declared premise EXPIRED before this was built and the step says so: it read 'P0 step 14 proved this with no pool', true when written and false since CONTRACTS item 35 put the pool in the enforcement path — step 14 has been running pooled ever since. So the bleed property is not re-proven; what is added is what a bleed check cannot see. 32 commands across 4 tenants must leave exactly FOUR pooled entries: thirty-two means no reuse and a key dimension that should not be there, one means a MISSING dimension, which is §6's 'every cross-tenant leak is a cache key missing a dimension'. Both extremes pass a bleed assertion, which is why the entry count is asserted separately",
		},
		{
			n: 25, covers: []int{5},
			run:     step25TheEgressTenantAssertionFiresAgainstABrokenPool,
			what:    "the egress tenant assertion fires against a deliberately broken pool",
			asserts: "§6 mechanism 3, proven by sabotage rather than inspection — a pool rigged to hand back another tenant's client must be caught before the outbound call",
		},

		// --- pool lifetime and staleness (D108, D109) ---------------------------
		{
			n: 29, covers: []int{12}, decides: []string{"D108"},
			run:     step29NoPoolEntryOutlivesMaxLifetime,
			what:    "no pool entry outlives max_lifetime",
			asserts: "with a clock seam, not a sleep. This is the bound that does NOT depend on our invalidation path being correct — if eviction has a bug, nothing survives past it anyway",
		},
		{
			n: 30, covers: []int{12}, decides: []string{"D108"},
			run:     step30ATargetMayNarrowMaxLifetimeButNeverWidenIt,
			what:    "a target may narrow max_lifetime but never widen it",
			asserts: "deployment ceiling than target request, refused at boot. The fourth instance of the house form (D71, D59, D84, D108)",
		},
		{
			n: 31, covers: []int{13}, decides: []string{"D109"},
			run:     step31CredentialStaleCountsSupersededButLiveEntries,
			what:    "credential_stale counts superseded-but-live pool entries",
			asserts: "D99's gap made countable. Zero expected; non-zero is a bug or a rotation in progress, and the entry age says which",
		},
		{
			n: 32, covers: []int{13}, decides: []string{"D109", "D157"},
			run:     step32AnAnzenRuleWatchingCredentialStaleCanFire,
			what:    "an anzen rule watching credential_stale can fire revoke_credential",
			asserts: "closing the loop without a human: D99 leaves the gap, D109 detects it, D106 repairs it",
		},
		{
			n: 33, covers: []int{13}, decides: []string{"D109"},
			run:     step33AStalePoolEntryDoesNotAffectReadiness,
			what:    "a stale pool entry does NOT affect readiness",
			asserts: "a security condition is not an inability to serve, and conflating them makes /readyz flap on something a load balancer cannot act on",
		},

		// --- retry-safety (D113) -------------------------------------------------
		{
			n: 34, covers: []int{14}, decides: []string{"D113", "D140"},
			run:     step34AnUnknownActionIsTreatedAsMutating,
			what:    "an action the driver does not declare is treated as MUTATING",
			asserts: "REPLACES the step declared here, which duplicated step 21 exactly — same claim, same criterion, same decision, and step 21 already proves it by varying the KEY with mutation held constant (step 35 supplies the other axis). What neither covers is the branch D140 wrote for the case nobody expects to reach — an UNKNOWN action is treated as mutating, because guessing read-only about an action nobody can describe is how a double write happens: the first call may have landed, and a 429 does not say which side of the write it died on. A default nothing exercises is a default nobody has checked, and this one sits between an authorised command and a possible duplicate write. Real drivers refuse an undeclared action before the retry policy could matter, which is correct and is exactly why the default had never been reached — so the step supplies a driver that executes what it does not declare. Three arms: undeclared refuses to retry; a DECLARED non-mutating action retries, which is non-vacuity and also pins this as a default rather than a blanket rule; and a declared mutating one still refuses without a key",
		},
		{
			n: 35, covers: []int{14}, decides: []string{"D113", "D155"},
			run:     step35ANonMutatingActionRetriesFreely,
			what:    "a NON-mutating action retries freely on a 429",
			asserts: "the other half of D113's CONJUNCTION. Step 21 varies the KEY with mutation held constant, proving the key matters; this varies MUTATION with the key held absent, proving the refusal is about mutation and not about retrying at all. **IT COULD NOT BE BUILT, AND THAT IS HOW D155 WAS FOUND**: a non-mutating action is refused on Execute, so it can only run through Query — and Query had no retry. The step was right and the system was missing the behaviour, which is the inverse of the usual finding here. Asserted structurally on the read path sharing the same Runner, because a read is the ONE thing D113 says is always safe to retry and it was the path with no retry, while Execute — which must often refuse — had it",
		},

		// --- posture policy (D111) and PoolKey redaction (D112) -----------------
		{
			n: 36, covers: []int{7}, decides: []string{"D111"},
			run:     step36CredentialPolicyRefusesAMissingProperty,
			what:    "credential_policy refuses a provider missing a required property",
			asserts: "providers declare facts, the deployment declares its bar, boot checks the intersection. THE MESSAGE NAMES THE MISSING PROPERTY, NOT THE SCHEME, which is the whole reason the mechanism is worth generalising: `file:// is not allowed here` tells an operator nothing about what to reach for, and `cannot satisfy audited_reads` tells them what to look for in an alternative. Non-vacuity through `audited_reads`, which a mounted file cannot offer and workload identity can, because the cloud logs every token it mints — without that arm the step passes against a check that refuses everything. A provider that declares NO posture fails every requirement, which is D111's stated fail-safe direction and matters because Provider is published (D35) and a third-party implementation predates this mechanism. And a MISSPELLED property refuses the boot naming the available set: `require: [audited_read]` that parsed and did nothing would read as a compliance bar in force and enforce nothing, which is this codebase's most persistent defect in the one place where the consequence is somebody's audit",
		},
		{
			n: 37, covers: []int{7}, decides: []string{"D111", "D153"},
			run:     step37TheEnvRefusalIsDerivedNotHardcoded,
			what:    "D97's env:// refusal is a derived rule, not a hardcoded case",
			asserts: "the hardcoded `switch scheme { case \"env\": }` is gone; `env://` is refused off-bare because it declares no version and the default policy requires one. Proven by REMOVING the requirement — an explicit empty policy permits `env://`, and if it stayed refused the rule would be decoration beside a special case still doing the work. THE ARM THAT CAUGHT D111 BEING WRONG (D153): D111 said the default off-bare should require `rotatable_live`, but a static file cannot offer that — nor a subPath mount, nor anything Vault Agent writes to an emptyDir — so that default would refuse the exact configuration D104 rules must only WARN, on the explicit grounds that a static credential is legitimate and what is illegitimate is believing it rotates. `versioned` separates them, since a file is versioned by content even when it never changes. `rotatable_live` is DEMOTED rather than deleted and must still work when a regulated deployment asks for it. And the override goes through the same mechanism — it drops `versioned` rather than special-casing a scheme, and NARROWLY: it must not drop a requirement an operator stated explicitly, or one flag quietly disables a bar somebody wrote down",
		},
		{
			n: 38, covers: []int{15}, decides: []string{"D112"}, run: step38PoolKeyCannotBePrinted,
			what:    "PoolKey cannot be printed",
			asserts: "%v, %s, String(), and LogValue() all yield kind:ref with no credential hash. Secret's pattern applied a second time, which is what makes it a pattern",
		},

		// --- the lint guarantee, which IS testable ------------------------------
		{
			n: 28, covers: []int{4},
			run:     step28ThePackageLevelStateLintIsEnabledAndNonVacuous,
			what:    "the package-level-state lint is enabled and non-vacuous",
			asserts: "§6 item 4's claim that 'a lint rule makes regression structurally impossible'. The rule existed once before while the enforcement did not, and internal/auditwal shipped a package-level counter that review missed. Assert the linter is configured AND that a planted global would fail it",
		},

		// --- drain-then-wipe (D110) ----------------------------------------------
		{
			n: 40, covers: []int{9}, decides: []string{"D110"},
			run:     step40EvictionWaitsForInFlightCallsBeforeWiping,
			what:    "eviction waits for in-flight calls before wiping",
			asserts: "the wipe does not happen while a call still holds the material — proven by observing the order, not by timing. Uses the per-target in-flight registry D106 already needs",
		},
		{
			n: 41, covers: []int{9}, decides: []string{"D110"},
			run:     step41ADrainThatDoesNotCompleteIsBoundedThenForced,
			what:    "a drain that does not complete is bounded, then forced",
			asserts: "a hung driver cannot postpone a wipe forever: the drain races a deadline, after which stragglers are cancelled and the material zeroed. Same shape as Listener.Stop racing GracefulStop",
		},

		// --- posture disclosure is shin's (D116) ---------------------------------
		{
			n: 42, covers: []int{7}, decides: []string{"D118", "D154"},
			run:     step42DecisionRecordsNeverReachTheBus,
			what:    "a decision record never reaches a bus consumer",
			asserts: "REPLACES the step declared here, and D154 records why. It was `credential posture on a decision record is withholdable by a lens` (D116) — a projection over a path D118 removed. D116's disclosure half assumes consumers can subscribe to decision records; D118 ruled decisions never travel on the bus at all, because the bus is designed to DROP and the audit log is designed never to, and one pipe cannot have both properties. With no bus consumer there is nothing for a lens to withhold from, and D119 says the control over who reads posture in the warehouse is the WAREHOUSE's column access rather than shin. A declared step for a mechanism that cannot be built is the recurring defect at the level of the PHASE PLAN — a commitment that could only be written to pass. Repurposed rather than deleted because D118's guarantee is the more valuable thing and NOTHING PROVED IT: D119's widening of the record turns on the word *provably*. Three parts. The TYPE SYSTEM carries most of it — `Publish` accepts an Envelope and nothing else, asserted as a function type so widening the signature fails here. RUNTIME: a subscriber on the broadest pattern the bus accepts receives nothing while both an allowed and a REFUSED command are decided, the refusal being §5.4's highest-value record and exactly the one a SIEM would want to subscribe to. And the RESIDUAL is named rather than guarded: `Envelope.Data` is a free-form Struct, so a decision could be copied into one, and the obvious structural check — no publishing file may mention Decision — false-positives on the only file that publishes, which records a decision ABOUT a subscription. A guard weakened on its first real file is worse than a stated limit",
		},
		{
			n: 43, covers: []int{7}, decides: []string{"D116", "D154"},
			run:     step43ThePostureCheckIsNotRoutedThroughShin,
			what:    "the posture CHECK is not routed through shin",
			asserts: "non-vacuity for the category distinction: a deployment with no lenses configured still refuses a provider missing a required property. The check is boot-time admission; only the disclosure is a projection",
		},

		// --- the house form (D117) -----------------------------------------------
		{
			n: 44, covers: []int{7}, decides: []string{"D117"},
			run:     step44AnUndeclaredPropertyIsNotOffered,
			what:    "an undeclared credential property is treated as NOT offered",
			asserts: "a provider predating a newly-added posture field reports false for it, so a policy requiring it refuses. The direction of a missing declaration is refusal — the third instance of the house form after MCP tools (D46) and shin lenses (D84)",
		},

		// --- the governance path (D120-D122) -------------------------------------
		{
			n: 45, covers: []int{7}, decides: []string{"D120"},
			run:     step45DecisionRecordsReachEverySinkAndNoneIsDropped,
			what:    "decision records reach every configured sink, and none is dropped",
			asserts: "delivery over audit.Sink rather than a second bus — since D319 an asynchronous shipper from the local WAL, which replaced D120's synchronous fan-out. A slow destination must not cost a record or hold up the others, and a refusing one is named and catches up — the never-drop property is what separates this path from the data bus (D118)",
		},
		{
			n: 46, covers: []int{7}, decides: []string{"D120"},
			run:     step46SinkResidenciesRoutesRatherThanRefuses,
			what:    "Sink.Residencies routes rather than merely refuses",
			asserts: "with an eu destination and a us destination configured, each receives only what it may (shipped since D319). With ONE sink that method can only refuse (D89) — it was written for this; a served class no destination accepts refuses the boot",
		},
		{
			n: 47, covers: []int{7}, decides: []string{"D121"},
			run:     step47AnzenObservesDecisionsButNotTheDataBus,
			what:    "anzen observes decisions but cannot subscribe to the data bus",
			asserts: "config declaring an anzen rule that consumes a bus subject is refused at boot — the boundary that keeps the closed vocabulary meaningful",
		},
		{
			n: 48, covers: []int{7}, decides: []string{"D121", "D122", "D157"},
			run:     step48AnzenDoesNotReactToItsOwnDecisions,
			what:    "anzen does not react to its own decisions",
			asserts: "an anzen action produces a record like everything else (no privileged path), so without this rule A triggers B triggers A. Proven by a rule whose own action would match its own signal",
		},
		{
			n: 49, covers: []int{7}, decides: []string{"D122", "D157"},
			run:     step49TheAnzenNamespaceIsReservedAndCarried,
			what:    "the anzen: namespace is reserved and an anzen action carries one",
			asserts: "a grant declaring an anzen: principal is refused at boot, and a dispatched action records anzen:<rule> — which is what makes the recursion guard structural rather than a convention",
		},

		// --- the live demo (D115) ------------------------------------------------
		{
			n: 39, covers: []int{1}, decides: []string{"D115"},
			run:     step39DemoDrivesALiveInstance,
			what:    "the run executes against a LIVE Sekizui over the network",
			asserts: "`make run` in one terminal, `make demo` in another. The wire-traversable steps drive a real instance, so the evidence is watched rather than believed. Steps that cannot run remotely — reflexes, which are in-process by design (D69) — say so rather than skipping silently",
		},

		{
			n: 56, covers: []int{3}, decides: []string{"D133"},
			run:     step56RestoreLiftsAWithdrawal,
			what:    "a withdrawal is lifted by an explicit governed verb, never by a side effect",
			asserts: "`sekizui.restore_target` over mTLS, authorised by grant and recorded like the revocation it lifts. Restoring a target nobody withdrew is REFUSED rather than silently succeeding, so a typo'd ref is a failure and not a false reassurance. Runs against a LIVE instance, which is what makes break-glass demonstrable at all — before this, revoking anything in a demo left it dead until the process restarted",
		},

		{
			n: 57, covers: []int{3}, decides: []string{"D134"},
			run:     step57AnzenDecidesAHumanFires,
			what:    "anzen supplies the DECISION; a human only pulls the lever",
			asserts: "`sekizui.fire_anzen` names a RULE, not a target — so the operator chooses neither the subject nor the severity at 03:00, and the grant reads 'may fire credential-compromise' rather than 'may revoke anything'. A shadow-mode rule is REFUSED, because an observation period that a human can fire on demand is not an observation period. And the improvised path stays open but is RECORDED AS A GAP: a withdrawal with no rule behind it sets decided_by empty and logs it as something to patch, so the log surfaces missing rules instead of letting their absence look like health",
		},

		{
			n: 58, covers: []int{3, 7}, decides: []string{"D135", "D138"},
			run:     step58RefusalsShareOneShape,
			what:    "every deliberate refusal reaches the caller the SAME way, and the record names which stage refused",
			asserts: "a refusal is a CommandResult with its mapped Status and a decision id — never a transport error — whichever stage produced it, so a client catches one category one way. Non-vacuity in two directions: a genuine FAILURE still arrives as an error (the shape must not swallow everything), and `refused_by` differs across stages rather than being a constant. Also that the stdout line carries a decision id on a withdrawal refusal, which D124 requires and which read `decision=\"\"` before this. And that every refusal carries the fine TAXONOMY (`kind`) beside the coarse status, asserted as a RELATIONSHIP — more distinct kinds than statuses across the stages — because Status collapses denied/unauthenticated/residency into one and a field that merely respelled it would be worth deleting",
		},

		{
			n: 59, covers: []int{3}, decides: []string{"D136"},
			run:     step59ResidencyIsACeilingPlusAGrant,
			what:    "residency is a CEILING the deployment sets plus a GRANT policy checks — both must permit",
			asserts: "the groundwork, not the data classes. A crossing the deployment forbids is refused whatever a grant says (REFUSED_BY_RESIDENCY), and a crossing the deployment permits is still refused when the grant does not cover it (REFUSED_BY_POLICY) — so the compliance invariant cannot be granted away by the party that wants the data, and a legitimate crossing no longer forces an operator to widen -residency globally and lose the guarantee. Non-vacuity: with the ceiling widened and the grant present, the same command SUCCEEDS, or the test proves only that something refuses everything. Two further properties the rule owes: an UNCLASSIFIED target escapes both layers — permitted by the ceiling, unconstrained by every grant — so a multi-residency deployment refuses to boot with one rather than leaving an unpoliced route into a served class; and because the rule is modal on the deployment, boot NAMES the capabilities that widening just disabled, or an operator reads the new denials as a bug",
		},

		{
			n: 60, covers: []int{3, 7}, decides: []string{"D137"},
			run:     step60AnzenScopesByResidency,
			what:    "an anzen guard scopes by the TARGET's residency as well as by principal, and only ever adds",
			asserts: "the second axis beside applies_to, for one instance serving several jurisdictions. A guard scoped to `us` refuses there and NOT in eu — same action, same principal, same guard set — so a control that applies in one jurisdiction is sayable without running three deployments. The load-bearing property is that scoping is STRICTLY ADDITIVE: an unscoped guard still covers every target INCLUDING an unclassified one, and a scoped guard never reaches an unclassified target. Both halves are asserted, because the composition is what stops a guard being routed around by pointing at a target in another class — a principal axis has no equivalent of `unclassified`, which is why this is not just `applies_to` on a different field. Also on the concurrency form, not forbids alone. Boot refuses a guard scoped to a class this DEPLOYMENT does not serve (a real class, declared, simply not here) — Document.Validate cannot see the ceiling, so the check is split. And the REACTIVE form is refused the field outright: it already names one subject, so a constraint could only agree or contradict",
		},

		{
			n: 64, covers: []int{3, 7}, decides: []string{"D146"},
			run:     step64GrantVerbsSuspendAPrincipalAtRuntime,
			what:    "a principal's grants are suspended at RUNTIME by a governed verb, not by a config reload",
			asserts: "the alternative to hot reload, and narrower on purpose. `sekizui.revoke_grant` names a PRINCIPAL in target_ref — so the grant reads 'may suspend agent:global' rather than 'may suspend anybody', the narrowing fire_anzen gets by naming a rule. Proven by the refusal CHANGING ITS REASON rather than merely appearing: the probe is refused on RESIDENCY before, and the suspension outranks that after, because it is checked before the anzen guard and before policy — it answers 'may this principal do anything at all right now', which is blunter than either. Reinstatement returns it to exactly the refusal it had before, or the lift changed something it should not have. A second suspension is CONFIRMED rather than refused (D158, superseding D146's conclusion and keeping its concern): an error at 03:00 reads as `it did not work` and sends a second on-call engineer after a bigger hammer, so the answer names WHO suspended it, WHEN, and — because this one is not durable — that it lasts only until a redeploy, and a suspension with NO STATED REASON is refused, because a default reason would be a sentence nobody wrote appearing in the audit log as though somebody had",
		},

		{
			n: 63, covers: []int{3}, decides: []string{"D145"},
			run:     step63WithdrawalsSurviveARestart,
			what:    "a withdrawal survives a restart, and a corrupt store refuses to boot",
			asserts: "D133's guarantee was true within ONE PROCESS LIFETIME and nowhere else — the withdrawal set was a map in memory, so every restart lifted every revocation. A restart is not authorised, not audited as a restoration, not explicit and not by a named principal, which are the four things D133 requires; it is also the most routine operation a deployment has, so this was an unaudited mass-restoration triggered by a deploy. A second pool over the same store IS a restart for this purpose. The SEVERITY survives too, not just the fact: §4.7.10 splits quarantine from revocation on whether in-flight calls are cancelled, and downgrading across a restart would leave calls running with a credential believed compromised. Non-vacuity: an explicit restore must also persist, or a store that never deletes passes everything above while making a target impossible to bring back. And a CORRUPT store refuses the boot rather than starting empty — an empty withdrawal set is not a degraded start, it is every revoked credential silently live again",
		},

		{
			n: 62, covers: []int{1}, decides: []string{"D142"},
			run:     step62TargetLimitsComeFromConfigBoundedByACeiling,
			what:    "a target's operational limits come from CONFIG, bounded by a deployment ceiling",
			asserts: "the shared rate was already read from `limits.rate_per_hr`; retry and breaker bounds were not, and their config fields were deliberately ABSENT until they were — four fields that parse and do nothing would be the defect class committed on purpose. Landing them found the retry policy was not merely unconfigurable but UNWIRED: gateway defaults `Retry` to `retry.DefaultPolicy()` when the field is nil and main never set it, so the policy was a constant in the binary. This step proves the two halves of D142: a target that NARROWS the deployment default is honoured, and a target that tries to EXCEED it is refused at boot rather than silently clamped, because a target quietly given less than it asked for is a target whose operator believes something false. D108's shape (`max_lifetime` as a ceiling a target may only narrow) and D71's asymmetry: how hard anything here may retry is written once by whoever owns the blast radius",
		},

		{
			n: 61, covers: []int{3, 7}, decides: []string{"D144"},
			run:     step64GrantVerbsSuspendAPrincipalAtRuntime,
			what:    "hot reload is ruled out, and the urgent config change is a governed verb instead",
			asserts: "shares step 64's run because it is the same evidence read for a different claim: D144 is the RULING (no watcher, no document swap) and D146 is the mechanism that makes ruling it out affordable. What would otherwise be unproven is the negative — that no reload path exists — and the positive proof is that the urgent case is served without one. `Source.Watch` stays on the interface: it is how a self-hoster supplies a source that pushes, and FileSource returning nil is the honest answer for a file",
		},

		// --- credential lending and the provider seam (D127, D130, D131) ---------
		{
			n: 53, covers: []int{8, 9}, decides: []string{"D127"},
			run:     step53CredentialIsLentNotHandedOver,
			what:    "credential material is LENT for a callback, and a driver that stashes it is caught",
			asserts: "Use lends for the duration of fn and the wipe blocks only on that window, not on the outbound call — so revocation needs no deadline. The non-vacuity half is the one that matters: a deliberately misbehaving driver that keeps the slice past fn RACES the wipe, and -race must report it. D127 cannot make that contract structural, so the build has to be the guard",
		},
		{
			n: 54, covers: []int{8}, decides: []string{"D130"},
			run:     step54ProviderExpiryAndVersion,
			what:    "the cache honours the PROVIDER's expiry, and the version is the credential's identity",
			asserts: "a provider reporting a 60s expiry is not cached for the configured 5m — the defect that was inert only because every provider returned zero. Jitter moves expiry EARLIER and never past it. Separately: two resolutions yielding DIFFERENT material under the same reported version must NOT bump the generation, which is D47's 'refresh is invisible to pooling' and what D123's material digest silently broke",
		},
		{
			n: 55, covers: []int{7, 8}, decides: []string{"D131"},
			run:     step55ChainedReferencesResolveInnerFirst,
			what:    "a chained reference resolves inner-first, and dynamic chaining is refused at boot",
			asserts: "oauth-cc:// with a nested gcp-sm:// client_secret resolves the inner ref through the cache — so the inner read is audited, singleflighted and versioned once — and the provider never receives a resolver it could point at any other secret. Boot refuses a chain whose inner reference is not statically declared, rather than accommodating it",
		},

		// --- characterisation, the only credential-gated steps -------------------
		{
			n: 26, covers: []int{10}, decides: []string{"D152", "D156"},
			run:     step26BreakGlassIsCorrectUnderEitherPlatformBehaviour,
			what:    "break-glass is correct under EITHER platform behaviour for a tracking reference",
			asserts: "UNGATED by inverting the question (D156). This was a characterisation test against a real GCP project — the only thing in P1 needing a cloud account — asking what `gcp-sm://.../versions/latest` resolves to when the newest version is disabled. Google's documentation does not say; it was checked, not assumed. D152 established that measuring it would be evidence about ONE project, in one region, against one API version, on one day, and that break-glass must not rest on that. The same argument disqualifies the test and says what to prove instead: ENUMERATE the behaviours and be safe under each. There are exactly two — the alias fails, or it resolves to the newest still-enabled version — and both are simulated. Under the first the failure IS the refusal; under the second D152's monotonic guard refuses the downgrade and names it, because an operator has to understand that a compromised credential was about to be replaced by an OLDER one nobody chose. Strictly more than the characterisation test would have given: it covers the platform nobody has characterised, and the one whose behaviour changes next year",
		},
		{
			n: 27, covers: []int{10}, decides: []string{"D99", "D156"},
			run:     step27ADisabledPinnedVersionFailsClosed,
			what:    "a pinned version that stops resolving fails closed",
			asserts: "MIS-SCHEDULED as a platform question, and it is not one (D156). `A disabled pinned version fails closed` is a claim about SEKIZUI: when a reference naming one specific version stops resolving, the cache must not go on serving the material it already holds, must not substitute another version, and must not swallow the failure into a success. None of that needs a cloud. What a real project could have told us is only whether GCP returns an error or an empty result for a disabled version — a detail the provider adapts, and P2's first real provider is where it belongs. THE ARM WITH TEETH IS THE THIRD: everything else concerns one resolution, and that one concerns the entry the cache is ALREADY HOLDING. A cache answering from it after the version was disabled would give a compromised credential a second life bounded only by the TTL, and it would look fine because the first resolution was legitimate. Also asserted: the failure does not mention another version, since a pinned reference names one and must never resolve to a different one; and it carries a real fault kind, because swallowed into an unclassified failure it would look transient and something would retry a credential an operator deliberately took out of service",
		},
	}
}

// TestP1Acceptance runs what exists and reports what does not.
func TestP1Acceptance(t *testing.T) {
	built := 0
	for _, s := range p1StepTable() {
		if s.run != nil {
			built++
		}
	}
	t.Logf("P1 acceptance: %d/%d steps built", built, len(p1StepTable()))

	for _, s := range p1StepTable() {
		t.Run(fmt.Sprintf("%02d_%s", s.n, slug(s.what)), func(t *testing.T) {
			// THE EVIDENCE LEDGER IS OPENED HERE, NOT INSIDE THE STEPS. All
			// P1 steps then cite their audit lines without any of them
			// knowing the ledger exists, which is what made this affordable
			// across a hundred-odd steps written before it did.
			st := evidence.open("P1", s.n, s.what, firstSentence(s.asserts), s.covers, s.decides)
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

// TestP1StepsAreWellFormed. A placeholder with no stated assertion is a step
// nobody has thought through, and it will be written to pass rather than to
// prove — which is how an acceptance run becomes decoration.
func TestP1StepsAreWellFormed(t *testing.T) {
	seen := map[int]bool{}
	for _, s := range p1StepTable() {
		if s.what == "" || s.asserts == "" {
			t.Errorf("step %d has no narration or no stated assertion", s.n)
		}
		if len(s.covers) == 0 {
			t.Errorf("step %d (%s) discharges no exit criterion; either it is not P1's "+
				"business or the criteria list is missing one", s.n, s.what)
		}
		for _, c := range s.covers {
			if _, ok := p1ExitCriteria[c]; !ok {
				t.Errorf("step %d claims exit criterion %d, which does not exist", s.n, c)
			}
		}
		if seen[s.n] {
			t.Errorf("step number %d is used twice", s.n)
		}
		seen[s.n] = true
	}
}

// TestP1CoversItsExitCriteria is what stops the run drifting away from the phase
// it graduates. A criterion with no step is a criterion nobody will prove.
func TestP1CoversItsExitCriteria(t *testing.T) {
	covered := map[int]bool{}
	for _, s := range p1StepTable() {
		for _, c := range s.covers {
			covered[c] = true
		}
	}

	var orphans []string
	for c, desc := range p1ExitCriteria {
		if !covered[c] {
			orphans = append(orphans, fmt.Sprintf("%d: %s", c, desc))
		}
	}
	sort.Strings(orphans)

	if len(orphans) > 0 {
		t.Errorf("%d P1 exit criterion/criteria have no acceptance step:\n  %s\n\n"+
			"Add a step, or move the criterion — an exit criterion nobody proves is a "+
			"phase that graduates on a claim.", len(orphans), strings.Join(orphans, "\n  "))
	}
}

func TestP1CompletionIsHonest(t *testing.T) {
	if !p1Complete {
		return
	}
	var unbuilt []string
	for _, s := range p1StepTable() {
		if s.run == nil {
			unbuilt = append(unbuilt, fmt.Sprintf("%d: %s", s.n, s.what))
		}
	}
	if len(unbuilt) > 0 {
		t.Errorf("P1 is marked complete with %d unbuilt step(s):\n  %s\n\n"+
			"Either build them or move them out of the phase — a step that skips is a "+
			"commitment, and marking the phase done turns it into a claim.",
			len(unbuilt), strings.Join(unbuilt, "\n  "))
	}
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
