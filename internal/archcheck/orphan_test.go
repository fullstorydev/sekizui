// Package archcheck holds architectural invariants as tests.
//
// WHY A TEST AND NOT A LINT. golangci-lint's `unused` treats every EXPORTED
// identifier as used, because it cannot know whether something outside the
// module imports it. That is correct for `pkg/`, which is a published API — and
// wrong for `internal/`, which Go's own toolchain guarantees nobody outside this
// module can import. Nothing off the shelf draws that distinction, and
// `make verify` reported 0 issues throughout every instance below.
//
// THE BUG CLASS THIS EXISTS FOR. P0 hit "a declared contract that silently does
// nothing" nine times. Five were missing implementations, which review and tests
// eventually catch. Four were missing CALLERS, which nothing catches, because
// everything you would inspect is present and correct:
//
//	schemareg.FieldPathExists   D42's boot check           — zero callers
//	audit.Sink.Residencies      D29 item 4                 — zero callers
//	shin.Deliver                the bus delivery path      — zero callers
//	auditwal.TailPathFor        the tail-path convention   — zero callers, and
//	                            cmd/sekizui built a DIFFERENT path inline
//
// Each was found by hand, by grepping. This is that grep, made structural.
package archcheck

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/ledger"

	"github.com/fullstorydev/sekizui/internal/docref"
)

// deferred names packages whose exported surface is deliberately unreferenced,
// with the ledger entry or decision that says when it lands.
//
// AN ALLOWLIST WITH REASONS, not a list of names. An exception whose
// justification is "it was already failing" is how a guard rots into noise; one
// that must name a phase stays reviewable, and the entry has to be deleted when
// the phase arrives.
//
//nolint:gochecknoglobals // immutable table, read once
var deferred = map[string]string{
	// **`internal/reflex` WAS HERE UNTIL D261**, deferred to P5 as
	// `reflex:engine`. The engine now consumes the bus as each rule's principal
	// and is started by `cmd/sekizui`'s `reflexRunner`, so the entry expired
	// and this guard said so the turn it happened. The POLICY that bounds a
	// rule, ledgered as `reflex:policy`, landed in P5 (D334, D335).

	// **`internal/cursor`, `internal/translate` AND `internal/kyuushin` WERE
	// HERE UNTIL STEP 31 AND THEIR DELETION IS THE STEP'S RECEIPT.** All three
	// entries predicted the same caller — the `kyuushin` ledger entry — and
	// the `internal/kyuushin` line said in as many words that "what has no
	// caller is the gateway binding". The binding exists now (D250), so the
	// three reasons stopped being true on the same commit and the lines went
	// with them. That is what a deferral is for: a claim with an expiry date
	// somebody has to come back and honour.
}

// testOnly names packages whose ENTIRE PURPOSE is supporting the guards, where a
// caller set consisting only of tests is correct rather than suspicious.
//
// **A CATEGORY THIS GUARD DID NOT HAVE, and `internal/docref` is what needed it
// (D185).** The exclusion of test callers below is deliberate and well argued —
// every one of the four historical cases had passing tests, and being exercised
// by a test is what made them look implemented. That reasoning is sound and this
// does not weaken it. What it does is name the one shape that INVERTS the guard's
// premise: for a package built so the guards can read the design documents,
// having no production caller is the design rather than the defect.
//
// **THE REGISTRATION IS CHECKED, so this cannot become a hiding place.** A
// package listed here must have NO non-test caller at all —
// TestTestOnlyPackagesStillHaveNoProductionCaller fails when one appears, because
// at that point it IS production code and its exports owe the ordinary
// justification. Same shape as TestRegisteredSymbolsAreStillUnused: an allowlist
// entry that stops being true has to fail rather than sit there.
//
// A PACKAGE RATHER THAN SIX SYMBOLS. Listing `Text`, `Section`, `Between`,
// `Marked`, `Rows`, `Cells` and `Decisions` under "deliberate test seams" would
// be seven lines of noise asserting the wrong category — a seam is a hook on a
// production type, and none of these is.
//
//nolint:gochecknoglobals // immutable table, read once
var testOnly = map[string]string{
	// D164's population census. It walks the `Decision` corpus an acceptance run
	// produced and asks whether any ROW carries each field — a question about
	// EVIDENCE, not about the running system, so the binary has no business
	// calling it and a production caller would mean it had become something
	// else. Its callers are P2 step 24 and the report writer that fails
	// `make acceptance` when the corpus is incomplete.
	"internal/census": "asks whether the acceptance corpus populates every Decision field " +
		"(D164, D232). A census is a claim about the evidence a RUN produced, so having no " +
		"production caller is the design; the binary would have nothing to census",

	"internal/signedsubject/sstest": "mints subject tokens — valid ones and every kind D303 refuses — " +
		"against keys it generates, for the verifier's tests and P4 steps 26-30 (D318). Test support " +
		"by construction; a production caller would mean a signing key in the binary",

	"internal/connectorcheck": "answers whether every in-tree connector folder is complete " +
		"(D316). Its callers are its own build guard and P4 step 34 by construction — the maintainer " +
		"ruled both run ONE check — and it examines the repository's layout, which a running " +
		"binary has no business reading",

	"internal/docref": "exists so the guards read the design documents through ONE parser " +
		"whose extractors FAIL rather than returning empty (D185). Its callers are " +
		"acceptance steps and archcheck tests by construction; a production caller " +
		"would mean it had become something else",
}

// permitted names individual symbols with no non-test caller, and why that is
// correct rather than a defect.
//
// KEYED `package:Symbol` FOR A FUNCTION AND `package:Receiver.Method` FOR A
// METHOD. The first version keyed on the bare name, which meant allowlisting
// `credential.Stats` silently permitted EVERY package's `Stats` — and `Close`,
// `Handle` and `Stats` are exactly the names a new package is most likely to
// reuse. Found while adding `pool.Len`: `pool.Stats` was not flagged, and it
// should have been.
//
// **THE RECEIVER JOINED THE KEY WHEN THE GUARD BECAME TYPE-RESOLVED, and the
// measurement is the argument.** `package:Symbol` fixed the collision ACROSS
// packages and left it WITHIN one: `internal/driver/mcp` declares both
// `(Findings).RefusesTarget` and `(Severity).RefusesTarget`, so one key covered
// two unrelated methods. The declaration set had the same flaw and it was
// worse — 298 exported declarations in `internal/` reduced to 202 distinct
// names, so 96 were never examined at all.
//
// EVERY ENTRY NAMES ITS CATEGORY. An allowlist whose justification is "it was
// already failing" rots into noise within a phase; one where each line has to
// state a reason stays reviewable, and an entry whose reason stops being true
// becomes obvious on the next read — or, since CONTRACTS 79 closed, fails the
// build (TestPermittedOrphansAreStillOrphans).
//
//nolint:gochecknoglobals // immutable table, read once
var permitted = map[string]string{
	// `internal/reflex:Engine.Dispatch` WAS HERE as a test seam until D273: the
	// dev tap's rehearsal became its production caller, and this guard said so.

	// --- deliberate test seams on the tracer (D236) -------------------------
	//
	// `internal/tracing` is a SKELETON whose only production consumer is the
	// gateway's `Begin` and spine's `Start`/`Stop`. These two exist so a step
	// can assert on what was recorded rather than on what a collector received,
	// which is the whole reason a skeleton is assertable at all.
	//
	// **A THIRD EXPORT WAS DELETED RATHER THAN LISTED HERE.** `Span.Duration`
	// had no caller anywhere, test or otherwise — I wrote it because a span
	// obviously has a duration. That is the same hour-old dead code D139 caught
	// in `pkg/provider/ambient` (`WithSleep`, `WithStat`), and the right answer
	// is a deletion, not an entry.
	"internal/tracing:Provider.Recorded": "P2 step 29 reads the spans an outbound call " +
		"produced. A production caller would be a health surface reporting span counts, " +
		"which is speculation until somebody asks for it",
	"internal/tracing:WithClock": "deterministic span timings in the acceptance harness, the " +
		"same seam auditwal.WithClock and gateway's Now already are",

	// --- the runner's REPORT half, whose consumer is a watcher (D243) -------
	//
	// **THE PACKAGE STOPPED BEING DEFERRED AND THESE TWO DID NOT LAND WITH
	// IT**, which is the distinction between the two tables working. Step 31
	// gave `internal/kyuushin` a production caller, so its package-level
	// deferral was deleted — but the gateway binding calls `Submit` and
	// `Cancel`, not these. D243 splits the runner in two: what it BOUNDS
	// (truncation, deadlines, the melt guard — unconditional, wired, exercised)
	// and what it REPORTS. The reports are now published — `sourceWatcher`
	// (D280), in the shape of `churnWatcher` and `mistenantWatcher` — but it
	// reads them through an interface, which this guard does not resolve; the
	// entries below say so rather than claim nothing reads them.
	//
	// LISTED PER SYMBOL RATHER THAN BY RE-DEFERRING THE PACKAGE, because a
	// package-level entry would now be false about `Submit` and `Cancel` — and
	// an allowlist entry that is false about most of what it covers is the rot
	// CONTRACTS 48 records.
	"internal/kyuushin:Runner.Nonconforming": "D243's REPORT half, published as `source_nonconforming` by " +
		"cmd/sekizui's sourceWatcher (D280) — which reads it through the `sourceReports` interface, " +
		"a call this guard does not resolve to the method",
	"internal/kyuushin:Runner.Stopped": "the melt guard's report, published as `source_stopped` by the " +
		"same sourceWatcher through the same interface (D280)",
	"internal/kyuushin:Runner.Undeclared": "D277/D279's report, published as `source_undeclared` by the " +
		"same sourceWatcher through the same interface (D280) — a level a rule may only alert on",

	// --- implementations of interfaces defined OUTSIDE this module ----------
	//
	// The caller is the standard library, gRPC, or slog. This guard walks only
	// our tree, so it cannot see them — and it never will. The type-resolved
	// version does not propagate through a FOREIGN interface for exactly this
	// reason: the call site is code we cannot read, so an in-tree reference to
	// `io.Closer.Close` is evidence about somebody else's type (typeref_test.go
	// explains the boundary).
	"internal/gateway:statusError.Unwrap":     "errors.Unwrap calls it",
	"internal/gateway:statusError.GRPCStatus": "grpc/status calls it to derive a code",
	"internal/gateway:statusError.Error": "the `error` interface calls it. NEWLY VISIBLE: `Error` is one of the " +
		"most reused method names in the tree, so the bare-name matcher counted somebody " +
		"else's every time",
	"internal/runtime:Profile.LogValue":       "slog calls it (slog.LogValuer)",
	"internal/obs:RedactingHandler.Handle":    "slog calls it (slog.Handler)",
	"internal/obs:RedactingHandler.WithAttrs": "slog calls it (slog.Handler)",
	"internal/obs:RedactingHandler.WithGroup": "slog calls it (slog.Handler)",
	"internal/obs:RedactingHandler.Enabled": "slog calls it (slog.Handler). NEWLY VISIBLE for the same reason as " +
		"statusError.Error — three of this handler's four methods were registered and the " +
		"fourth was hidden, which is the collision doing its quietest damage: a partial " +
		"registration reads as a complete one",
	"internal/driver/mcp:session.String": "fmt calls it (fmt.Stringer), and it is the reason the type has a " +
		"String at all: a pooled MCP session would otherwise render as a struct pointer in a " +
		"pool dump or a panic, and the field it must NOT render is the session id — a bearer " +
		"credential for the session's lifetime, which §4.3.3 makes self-redacting by type " +
		"everywhere else (D213)",
	"internal/bus:subscription.Ack": "consumers call it; a no-op under at-most-once (D24)",
	"internal/bus:subscription.Err": "`pkg/bus.Subscription` REQUIRES it — \"Err returns why the subscription " +
		"ended, or nil for a clean close\" — and D35 puts the consumer that reads it out of " +
		"tree, exactly like Ack above. Compulsory to compile and consulted by nobody here, " +
		"which is a distinction this table now has to state rather than imply",

	// --- deliberate test seams ----------------------------------------------
	//
	// Options exist so a test can substitute a clock or an id generator without
	// the production path carrying a flag for it.
	"internal/credential:WithClock": "test seam: substitutes the clock, so audit timestamps are deterministic",
	"internal/connectors/fullstory:WithHosts": "test seam: admits a TLS fixture's host to a driver that " +
		"otherwise dials only Fullstory's own API hosts (P3 step 24, D288). The binary never passes it, " +
		"and a production caller appearing is exactly what this registry should then report",
	"internal/retry:WithClock": "test seam: substitutes clock AND sleep together, so backoff is asserted " +
		"without waiting — P1 exit criterion 12's house rule (step 20)",
	"internal/auditwal:WithClock": "test seam: substitutes the clock. NEWLY VISIBLE — five packages declare " +
		"`WithClock` and a bare-name key checked exactly one of them, which is the collision " +
		"this table's own comment predicted and could not see",
	"internal/churn:WithClock": "test seam: substitutes the clock, so D204's fifteen-minute churn window is " +
		"crossed without waiting (step 43). NEWLY VISIBLE, one of the five",
	"internal/pool:WithClock": "test seam: substitutes the clock, so D108's max_lifetime expires without " +
		"waiting (steps 29-30). NEWLY VISIBLE, one of the five",
	"internal/limiter:WithBreakerClock":      "test seam: crosses the breaker's cooldown without sleeping (step 22)",
	"internal/limiter:WithLocalClock":        "test seam: drains and refills a bucket without waiting an hour (step 23)",
	"internal/auditwal:WithIDFunc":           "test seam: substitutes id generation",
	"internal/gateway:Server.PublishForTest": "named for what it is; goes when P3 brings a real ingress",
	"internal/gateway:Listener.Addr": "test seam: hands a test the EPHEMERAL port it asked the kernel for, so " +
		"`make acceptance` and the gateway's own tests dial a real listener without a fixed " +
		"port. Production logs the address through `ln.Addr()` directly (serve.go:186) and " +
		"never needs this",
	"internal/gateway:Server.Metrics": "test seam: hands a test the registry to scrape, which is how the " +
		"D204 counter assertions pin whole exposition lines. Production reaches /metrics " +
		"through the registry `cmd/sekizui` already holds, not through the server",
	"internal/driver/mcp:WithHTTPClient": "test seam: substitutes the transport, so the JSON-RPC shapes, the " +
		"required metadata headers, the protocol/execution error split and D48's drift severities " +
		"are all provable against an httptest server rather than against somebody's MCP " +
		"deployment (D192a)",
	"internal/connectors/jira:WithHTTPClient": "test seam: substitutes the transport, so the whole driver is provable " +
		"against an httptest server — which is the ONLY way it is provable, because this connector " +
		"has deliberately never spoken to a real Jira (the maintainer's ruling, P2 step 27). Production " +
		"wiring never sets it.",
	"internal/connectors/jira:Assumptions": "**THE HONEST HALF OF A DRIVER BUILT FROM DOCUMENTATION.** This " +
		"connector was written from Atlassian's published docs and never exercised against a live " +
		"instance, so its fixtures agree with it by construction and prove nothing about the " +
		"vendor. The list separates what was VERIFIED from what was ASSUMED, and it is exported so " +
		"the package's own test can refuse an empty one — a list somebody quietly deleted would " +
		"make the driver look verified. Its real caller is whoever first points this at a real " +
		"site; it has no in-tree one because that has not happened.",
	"internal/connectors/fullstory:WithHTTPClient": "test seam: substitutes the transport, so every arm of the driver " +
		"except \"the real Fullstory accepts this\" is provable against an httptest server — the " +
		"status-to-taxonomy mapping, the Basic auth header, the tenant assertion, and " +
		"statelessness under concurrent load. Production wiring never sets it, which is why it " +
		"is an option rather than a parameter (D189)",
	"internal/bus:InProcess.Subscribers":   "test seam: lets the acceptance run wait for a subscription to register",
	"internal/auditwal:Segments":           "test seam: counts chain segments across restarts (D78)",
	"internal/credential:WithTTL":          "test seam: makes expiry assertable without sleeping (P1 step 1)",
	"internal/credential:WithJitterSource": "test seam: lets two caches differ predictably (P1 step 3)",
	"internal/credential:Cache.ExpiryFor":  "test seam: asserts jitter differs per instance (P1 step 3)",
	"internal/pool:Pool.Len": "test seam whose real caller is D109's staleness report, declared as " +
		"P1 acceptance steps 31-33 and not yet built. An allowlist entry must name a " +
		"DECLARED future caller, never a vague intention",
	"internal/pool:Pool.Stats": "test seam; the pool's own counters reach /metrics via D109's " +
		"staleness report, steps 31-33",
	"internal/credential:Cache.Stats": "test seam. Production reporting goes through the metrics registry via " +
		"Incr, not through this — it was originally documented as serving both, which " +
		"would have made it the bug class again",

	// --- a one-line accessor OVER the centralised vehicle -------------------
	//
	// **THE MAINTAINER'S RULING, AND IT REPLACED A PROPOSAL TO DELETE ALL FOUR:** *"they
	// were made for a reason but if this highlights that it should have been a
	// centralised vehicle then they should refer to that and use that, right?
	// Reuse instead of throw away?"* He was right, and the reason is visible in
	// the diffs: each of these had a DUPLICATED BODY somewhere, so deleting the
	// symbol would have left the duplication behind and lost the readable name.
	// Each now delegates, so there is one implementation, and each is
	// registered here because a named accessor with no caller yet is still
	// something somebody has to justify.
	"internal/resolver:New": "a convenience constructor that now DELEGATES to NewWithCache — the two " +
		"bodies were identical but for the credential cache, and a field added to the " +
		"struct would have been initialised in whichever one the author was looking at. " +
		"Production shares one cache and so calls NewWithCache; this is what the tests " +
		"build with, and the delegation is why keeping it costs nothing",
	"internal/spine:Spine.Ready": "the named readiness PREDICATE, now delegating to Status so there is one " +
		"derivation of it (the old body recomputed `Started && no unhealthy` a second " +
		"way). /readyz reads Status, because it needs Degraded and the unhealthy names " +
		"too; the declared caller for the bare predicate is the gate in front of the " +
		"gRPC interceptor chain, §4.10.3",
	"internal/verb:Is": "§15q's PREDICATE beside the set — the shape `Severity.Known` and " +
		"`IdempotencyClass.Known` already have — now delegating to Lookup so there is " +
		"ONE read of the `verbs` map. Its caller is `internal/actionset`'s test today; a " +
		"registry whose predicate reaches into the map itself is one normalisation rule " +
		"away from two readers disagreeing",
	"internal/credential:Refusal.String": "the fmt.Stringer for one refusal. The boot error goes through Render, " +
		"which groups by REASON (D97) and must not repeat the reason per target — so the " +
		"two share how a target is NAMED, and that is now `Refusal.target()` rather than " +
		"a copy in each. Registered rather than deleted for the reason above; the " +
		"duplication it was hiding is gone either way",

	// --- a DECLARED future caller, in internal/ -----------------------------
	//
	// The `pkg/` equivalent is public_test.go's `aheadOfItsPhase`, and the rule
	// is the same one: an entry names the step that brings the caller, never an
	// intention. All four below were hidden by the bare-name matcher.
	"internal/pool:Pool.InFlight": "D109's drain census, sibling of Len and Stats above: the number is read " +
		"by the staleness report the anzen dispatcher consumes (steps 31-33). Separate " +
		"from `gateway:Admission.InFlight`, which HAS a caller in the drain path — two " +
		"unrelated methods that one bare-name key had been answering for",
	"internal/limiter:Breaker.State": "COMPULSORY: `var _ limiter.Breaker = (*Breaker)(nil)` at breaker.go:68 " +
		"binds it to the published interface, so it cannot be deleted while `pkg/limiter` " +
		"declares it. Its CONSUMER is §4.8's target-health view at P6 — read-only, unlike " +
		"Allow, because an operator refreshing a dashboard must not advance the state " +
		"machine. **THIS IS THE SYMBOL THAT MOTIVATED THE TYPE-RESOLVED GUARD**: it passed " +
		"for as long as the bare-name matcher existed because `internal/identity` writes " +
		"`tlsInfo.State.PeerCertificates`, a stdlib struct field in an unrelated package",
	"internal/connectors/kata:Driver.Poll": "kata's afferent half, and the FORM a source connector fills in (D176, D243). " +
		"Its caller is the poller, declared in the init ledger as `kyuushin` landing P3 — the same " +
		"reason `internal/cursor` is in `deferred` above. **NOT deferred as a package**, because " +
		"`internal/connectors/kata`'s efferent half has callers everywhere and deferring the package " +
		"would blind this guard to all of it. D243 is why the shape landed before its consumer: " +
		"the runtime bounds that make the spine survive a badly written connector can only be " +
		"proven against a source that misbehaves on purpose, so the hostile source is the fixture " +
		"the guards are written against rather than a thing built after them.",
	"internal/connectors/kata:Driver.Recovery": "D174's declaration, D241's method, taking a Target per D171's layering. " +
		"Same caller and same phase as `Driver.Poll` above: the spine asks it when it finds an " +
		"uncommitted attempt, which is machinery the poller brings.",
	"internal/connectors/kata:Driver.Health": "**NOTHING IN THE TREE CALLS `connector.Driver.Health`, AND STEPS 9 AND 12 " +
		"LANDED WITHOUT CHANGING THAT — the reason is worth reading before assuming per-target " +
		"health is wired.** This entry used to name those steps as its future caller. They are " +
		"built, and they consume `drift.Reporter.Drift` instead: the watcher needs FINDINGS (which " +
		"action, which severity, what to withhold) and `Health` collapses all of that into one " +
		"error, which cannot say which capability to drop from the catalog. So the interface " +
		"method's real consumer is §4.8's target-health VIEW at P6, which wants exactly the " +
		"boolean this returns. Recorded rather than re-pointed at another step: an entry naming a " +
		"step that arrives and does not use it is how an allowlist rots, and this one already did " +
		"it once. CONTRACTS 86.",
	"internal/connectors/fullstory:Driver.Health": "see `internal/connectors/kata:Driver.Health` — declared, implemented " +
		"three times, called nowhere, and NOT retired by steps 9 and 12 as this entry " +
		"previously predicted. §4.8's panel at P6 is the consumer.",
	"internal/connectors/jira:Driver.Health": "see `internal/connectors/kata:Driver.Health`. Four implementations now, " +
		"still no caller; §4.8's panel at P6 is the consumer.",

	// **FOUR ENTRIES LEFT THIS TABLE WHEN THE DRIFT VOCABULARY MOVED (D206),
	// and the inversion is what made it a build failure rather than a habit.**
	// `Severities`, `Severity.Explain`, `Severity.Known` and `Findings.Withheld`
	// were registered here against `internal/driver/mcp`, three of them naming
	// step 9 as their future caller. Step 9 arrived, the vocabulary moved to
	// `internal/drift` so the catalog and readiness could read it without
	// importing a driver, and all four gained REAL callers —
	// `Store.Record` validates a severity and names the vocabulary in its
	// refusal, `writeTargetDrift` explains one to an operator, and
	// `State.Withheld` is what the catalog withholds from. So the entries are
	// deleted rather than re-keyed, which is the outcome an allowlist entry
	// naming a declared future caller is supposed to have.
	//
	// TestPermittedOrphansAreStillOrphans reported all four the moment the move
	// landed, by the "names a symbol that is not declared" arm — the arm written
	// the same morning because re-keying entries onto receivers makes a typo an
	// exemption of nothing. Its first real catch was a legitimate refactor.

	// --- the MCP driver is WIRED; what remains is one method (D198, D213) ----
	//
	// **THIS BLOCK USED TO OPEN "the MCP driver is BUILT AND NOT WIRED" and to
	// state that no non-test file imports the package at all. Both went false
	// when D213 wired it**, and the paragraph below already said so two sentences
	// later — a contradiction that survived because the guard has nothing to
	// check a REASON against. Found by the Feierabend read on 2026-09-09;
	// `cmd/sekizui/main.go` has imported the package since D213.
	//
	// Registered SYMBOL BY SYMBOL rather than as a package, unlike
	// `internal/docref` above, for two reasons: each symbol's caller arrives with
	// a DIFFERENT step, and a package-level exemption would hide every future
	// orphan in 1,354 lines of code under active development.
	// `internal/driver/mcp:New` AND `:WithPool` WERE HERE UNTIL D213 WIRED THE
	// DRIVER, and their deletion is the intended lifecycle of a registration
	// that names a declared future caller: the step arrives, the symbol gets a
	// real one, the line goes. `TestPermittedOrphansAreStillOrphans` is what
	// made it a build failure rather than a rot — it named both on the first run
	// after `cmd/sekizui` registered the driver.
	"internal/driver/mcp:Driver.Health": "see `internal/connectors/kata:Driver.Health`. §4.8's panel at P6 is the " +
		"consumer; D197 chose `Drift` for the watcher (CONTRACTS 86). **The reason used to add " +
		"\"and doubly unreachable, since nothing constructs this driver either\", which stopped " +
		"being true when D213 wired the driver into the binary** — the entry stayed valid and half " +
		"its justification did not, which is the failure mode a registry cannot catch about itself",

	// --- offline and operator tooling ---------------------------------------
	"internal/auditwal:VerifyChain": "an offline audit operation; the acceptance run is its caller, and a " +
		"CLI or /debugz endpoint for it is worth adding when someone needs to verify " +
		"a log they did not just produce",
	"internal/konbini:Explain": "a per-term glossary lookup; `Render` serves -glossary today, and this is " +
		"what a /debugz/glossary/<term> route would call",
	"internal/anzen:Guards.InFlight": "read by the catalog's budget test and by anzen's own; the " +
		"gateway's separate InFlight now has a real caller in the drain path",
}

// TestNoOrphanedExportsInInternal is the guard.
//
// For every exported declaration in `internal/`, something outside its own
// package must reference it. A symbol nobody names is either dead or — far
// worse — a guarantee documented somewhere and enforced nowhere.
//
// TYPE-RESOLVED SINCE CONTRACTS 79 CLOSED. It used to compare a bare-name
// declaration set against a bare-name reference set, and both halves were
// wrong: `internal/limiter:(*Breaker).State` passed because `internal/identity`
// writes `tlsInfo.State.PeerCertificates`, and 96 of 298 declarations were
// never examined at all because a `map[symbol]where` collapses `New` 17 ways.
// See typeref_test.go for what replaced it and why it needed a module.
func TestNoOrphanedExportsInInternal(t *testing.T) {
	root := repoRoot(t)

	syms := loadSymbols(t, root, "internal")

	var orphans []string
	for key, where := range syms.declared {
		pkg := strings.SplitN(key, ":", 2)[0]
		if _, ok := deferred[pkg]; ok {
			continue
		}
		if _, ok := testOnly[pkg]; ok {
			continue
		}
		if _, ok := permitted[key]; ok {
			continue
		}
		// CALLED FROM ANY NON-TEST FILE ANYWHERE, including its own package.
		//
		// Two earlier attempts got this predicate wrong, in opposite directions.
		// The first accepted a reference from the declaring package, which is
		// true of every symbol ever written — the declaration is itself an
		// identifier — so the guard passed unconditionally and passed on a
		// deliberately planted orphan.
		//
		// The second required a caller OUTSIDE the package, which flagged 36
		// legitimate package-internal helpers. That is the wrong line: an
		// exported symbol used only within its package is a visibility question,
		// not a broken guarantee. `schemareg.FieldPathExists` is called from
		// `check.go` in its own package and is correctly enforced — what made it
		// a defect was having no non-test caller AT ALL.
		//
		// Tests are excluded from the count deliberately. Every one of the four
		// historical cases had passing tests; being exercised by a test is what
		// made them look implemented.
		if syms.used(key) {
			continue
		}
		orphans = append(orphans, key+" ("+where+")")
	}

	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("%d exported symbol(s) in internal/ have no caller outside their own "+
			"package.\n\nEach is either dead code, or a documented guarantee that runs "+
			"nowhere — the second is the shape D88, D89 and D91 came from, and no linter "+
			"reports it.\n\n  %s\n\nIf one is deliberately unreferenced until a later "+
			"phase, add its package to `deferred` with the ledger entry that says when it "+
			"lands.", len(orphans), strings.Join(orphans, "\n  "))
	}
}

// TestPermittedOrphansAreStillOrphans is the inversion, and it is the half
// CONTRACTS 79 was open for.
//
// `permitted` was checked in ONE DIRECTION only: the main guard consults it to
// SUPPRESS a finding, and nothing ever asked whether the suppression was still
// warranted. So an entry survives its own justification — the phase arrives,
// the caller lands, and the line stays, now asserting something false about a
// symbol nobody rechecks. Its sibling `aheadOfItsPhase` has had this inversion
// since P1 (TestRegisteredSymbolsAreStillUnused), so two allowlists in one
// package were held to different standards and the weaker one rotted first:
// `internal/metrics:Incr` was registered as "a counter helper the RED path does
// not need; Observe covers every current call site" and D204's churn counter
// made that false. It was found by hand and deleted by hand.
//
// **IT COULD NOT BE WRITTEN BEFORE THE TYPE LOAD, AND WAS WITHDRAWN ONCE FOR
// TRYING.** On bare names it reported five false positives, because
// `recorder.Intent`, `lenses.Deliver` and their like are reached through an
// interface-typed field and never appear with a package qualifier. A guard
// weakened on its first real file is worse than a stated limit, so the limit
// was stated (CONTRACTS 79) and the guard waited for the mechanism.
//
// TWO FAILURE MODES, DELIBERATELY SEPARATE, because the fix differs:
//
//  1. THE SYMBOL IS GONE. An entry naming something that no longer exists
//     checks nothing, and it is the way this very change could have gone wrong:
//     re-keying 28 entries onto receivers turns any typo into a silent
//     exemption of nothing. `testOnly` already guards its own paths this way.
//  2. THE SYMBOL HAS A CALLER. The reason has stopped being true.
//
// CONSULTS `direct` AND NOT `viaInterface`, which is the one place this guard
// and the main one deliberately disagree. The main guard may err toward a
// MISSED orphan; this one must never err toward a FALSE ACCUSATION, and
// interface propagation is the permissive half — a single-method in-module
// interface marks every implementer's method of that name reachable once any
// one of them is called through it. The residual is named rather than guarded:
// an entry whose caller arrives only through such an interface stays registered
// after it stops being an orphan.
func TestPermittedOrphansAreStillOrphans(t *testing.T) {
	root := repoRoot(t)

	syms := loadSymbols(t, root, "internal")

	var missing, called []string
	for key, why := range permitted {
		if _, exists := syms.declared[key]; !exists {
			missing = append(missing, key)
			continue
		}
		if syms.direct[key] {
			called = append(called, key+" — registered as: "+firstClause(why))
		}
	}

	sort.Strings(missing)
	sort.Strings(called)

	if len(missing) > 0 {
		t.Errorf("%d `permitted` entr(ies) name a symbol that is not declared in "+
			"internal/, so each one exempts NOTHING and would go on passing if the "+
			"symbol it was written for came back as an orphan.\n\nEither the symbol was "+
			"renamed or deleted — delete the line — or the key is wrong. Keys are "+
			"`package:Func` and `package:Receiver.Method`, with the receiver's type name "+
			"and no pointer star.\n\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	if len(called) > 0 {
		t.Errorf("%d `permitted` entr(ies) now name a symbol with a real non-test "+
			"caller, so their stated reasons are false.\n\nDelete each line: the symbol "+
			"no longer needs an exemption, and an allowlist entry whose reason stopped "+
			"being true is worse than no entry at all (CONTRACTS 48's lesson, arriving "+
			"in an allowlist).\n\n  %s",
			len(called), strings.Join(called, "\n  "))
	}
}

// firstClause trims a registration reason to its opening sentence, so a failure
// message carries the CLAIM being contradicted without reprinting a paragraph.
func firstClause(why string) string {
	if i := strings.Index(why, ". "); i > 0 {
		return why[:i]
	}
	if len(why) > 120 {
		return why[:120] + "..."
	}
	return why
}

// TestTestOnlyPackagesStillHaveNoProductionCaller keeps the new category honest.
//
// A `testOnly` registration says "no production code calls this, and that is
// correct". The moment production code does, the claim is false and the package
// owes the ordinary justification for every export — so the entry must be
// deleted rather than silently covering a package that has changed character.
//
// THE FAILURE DIRECTION IS THE POINT. Without this, `testOnly` is a permanent
// exemption a package keeps after outgrowing it, which is CONTRACTS 48's lesson
// (the init ledger had no expiry) arriving in an allowlist.
func TestTestOnlyPackagesStillHaveNoProductionCaller(t *testing.T) {
	root := repoRoot(t)

	// **ASSERTED ON IMPORTS, NOT ON CALLED NAMES, and the first draft got this
	// wrong in a way worth recording.** It asked `calledNames`, which returns a
	// set of BARE identifiers — so `Rows`, `Load`, `Name`, `Err` and `Root` all
	// appeared "used" because other packages happen to declare `connector.Rows`
	// and `config.Load`. That is the precise defect the `permitted` map's own
	// comment records one screen above: keying on a bare name silently matches
	// every package's version of it.
	//
	// The main guard can live with that coarseness because it errs toward false
	// NEGATIVES — a symbol wrongly considered used is a missed orphan, which is
	// the quiet direction. This check needs the opposite answer, so it asks a
	// question a bare name cannot answer: does any non-test file IMPORT the
	// package? An import cannot be a coincidence.
	for pkg, why := range testOnly {
		if _, err := os.Stat(filepath.Join(root, pkg)); err != nil {
			t.Errorf("%s is registered as test-only and does not exist — the entry is "+
				"checking nothing. Delete it, or fix the path", pkg)
			continue
		}

		path := "github.com/fullstorydev/sekizui/" + pkg
		fset := token.NewFileSet()

		walkGo(t, filepath.Join(root, "internal"), func(file string) {
			if strings.HasSuffix(file, "_test.go") || strings.HasPrefix(file, filepath.Join(root, pkg)) {
				return
			}
			parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parsing %s: %v", file, err)
			}
			for _, imp := range parsed.Imports {
				if strings.Trim(imp.Path.Value, `"`) != path {
					continue
				}
				rel, _ := filepath.Rel(root, file)
				t.Errorf("%s is imported by NON-TEST file %s, so it is no longer "+
					"test-only. Delete its `testOnly` entry — the reason given (%q) has "+
					"stopped being true, and every export then owes the ordinary "+
					"justification", pkg, rel, why)
			}
		})
	}
}

// TestDeferredPackagesStillHaveNoProductionCaller is `deferred`'s EXPIRY, and
// it is the one of the four allowlists that did not have one.
//
// **WRITTEN THE DAY THREE OF ITS ENTRIES WENT STALE AT ONCE, AND NOTHING
// FAILED.** Step 31 (D250) gave `internal/cursor`, `internal/translate` and
// `internal/kyuushin` production callers. All three deferrals were then false
// — one of them said, in as many words, that "what has no caller is the
// gateway binding" — and every test in this package went on passing. They were
// deleted because the author happened to remember, which is precisely the
// assurance an allowlist exists to replace.
//
// **THE ASYMMETRY WAS VISIBLE AND NOBODY LOOKED FOR IT.** `permitted` expires
// through TestPermittedOrphansAreStillOrphans, `testOnly` through
// TestTestOnlyPackagesStillHaveNoProductionCaller, and `aheadOfItsPhase`
// through TestRegisteredSymbolsAreStillUnused, each carrying a comment about
// CONTRACTS 48's lesson that an exemption without an expiry rots. `deferred`
// had only a cross-reference to the ledger — a check that the entry NAMES a
// phase, never that the phase has not arrived. D139's own rule is the one that
// was missing here: a registered symbol that gains a caller must FAIL.
//
// ASSERTED ON IMPORTS, for the reason the test above gives at length: a bare
// called name matches every package's version of it, and this check needs the
// answer that errs toward a false POSITIVE rather than a quiet miss.
func TestDeferredPackagesStillHaveNoProductionCaller(t *testing.T) {
	root := repoRoot(t)

	for pkg, why := range deferred {
		if _, err := os.Stat(filepath.Join(root, pkg)); err != nil {
			t.Errorf("%s is deferred and does not exist, so the entry exempts "+
				"nothing. Delete it, or fix the path", pkg)
			continue
		}

		path := "github.com/fullstorydev/sekizui/" + pkg
		fset := token.NewFileSet()
		reported := false

		// **`cmd/` IS WALKED AS WELL AS `internal/`, WHICH THE testOnly CHECK
		// DOES NOT DO.** A deferred package's caller is usually the wiring
		// site, and `cmd/sekizui` is where wiring lives — checking only
		// `internal/` would have let `internal/kyuushin` keep its deferral
		// while `cmd/sekizui/jobs.go` constructed the runner, which is exactly
		// the case that produced this test.
		for _, tree := range []string{"internal", "cmd"} {
			walkGo(t, filepath.Join(root, tree), func(file string) {
				if reported || strings.HasSuffix(file, "_test.go") ||
					strings.HasPrefix(file, filepath.Join(root, pkg)) {
					return
				}
				parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
				if err != nil {
					t.Fatalf("parsing %s: %v", file, err)
				}
				for _, imp := range parsed.Imports {
					if strings.Trim(imp.Path.Value, `"`) != path {
						continue
					}
					rel, _ := filepath.Rel(root, file)
					reported = true
					t.Errorf("%s is deferred, and NON-TEST file %s imports it. The "+
						"deferral says %q — a phase that has now arrived. Delete the "+
						"entry: its exports owe the ordinary justification from here "+
						"on, and any that genuinely still have no caller belong in "+
						"`permitted` per symbol rather than the whole package staying "+
						"exempt", pkg, rel, firstClause(why))
					return
				}
			})
		}
	}
}

// TestDeferredPackagesAreDeclaredInTheLedger keeps the allowlist honest.
//
// An exception is only acceptable when the gap is REPORTED — which is D53's
// whole argument. Without this, `deferred` becomes a place to hide things.
//
// READS THE LEDGER ITSELF, not `cmd/sekizui/main.go` as text. It used to grep
// that file for a quoted name, which worked exactly as long as the table stayed
// inline: moving the ledger to internal/ledger (so it could be tested at all)
// broke every check here at once, and a substring match would have gone on
// passing if the table had merely been reformatted. Cross-referencing the
// package is the check that was meant.
func TestDeferredPackagesAreDeclaredInTheLedger(t *testing.T) {
	declared := map[string]bool{}
	for _, p := range ledger.Planned() {
		declared[p.Name] = true
	}

	for pkg, reason := range deferred {
		if !strings.Contains(reason, "lands P") {
			continue // interface-only packages with a live implementation
		}
		name := strings.SplitN(strings.TrimPrefix(reason, "declared in the init ledger as `"), "`", 2)[0]
		if !declared[name] {
			t.Errorf("%s is allowlisted as deferred (%q) but the init ledger never "+
				"declares %q, so no boot reports the gap (D53).\n\nEither the ledger "+
				"entry was deleted because the work landed — in which case this "+
				"allowlist entry should go too — or the name drifted.",
				pkg, reason, name)
		}
	}
}

// --- the walk ---------------------------------------------------------------

func walkGo(t *testing.T, dir string, fn func(path string)) {
	t.Helper()

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// **A FILE THAT VANISHED MID-WALK IS NOT A FAILURE, and the guards
			// pay for this being tolerated.** Go runs test PACKAGES in parallel,
			// and two acceptance steps deliberately plant files in the tree and
			// remove them — P1 step 28 plants a global in `internal/acceptance`
			// to prove the linter rejects one, and P2 step 25 plants a driver
			// package to prove the conformance requirement is enforced. An
			// archcheck walk running at that moment saw `lstat ...: no such file
			// or directory` and failed the whole guard, which is a flake in a
			// check whose job is to be believed.
			//
			// Skipped rather than aborted: a file that is gone cannot violate an
			// invariant, and the walk's OTHER findings are still valid. Any
			// other error still stops the walk, because a permission problem or
			// a broken symlink means the guard is reading less than it thinks.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		// Generated protobuf is not ours to restructure (D34), and it exports a
		// great deal that only a consumer would call.
		if info.IsDir() && (info.Name() == "schema" || info.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			fn(path)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walking %s: %v", dir, err)
	}
}

func posOf(fset *token.FileSet, p token.Pos) string {
	pos := fset.Position(p)
	return filepath.Base(pos.Filename) + ":" + itoa(pos.Line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// repoRoot returns the module root.
//
// One of SIX walks up to go.mod (D185); two of them were in this package. The
// implementation is docref.Root now, and the error is handled HERE rather than
// through a shared helper because this file is `package archcheck` while the
// helpers are `package archcheck_test` (§15w) — two packages in one directory
// cannot share an unexported function, and one call site does not need one.
func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := docref.Root()
	if err != nil {
		t.Fatalf("%v", err)
	}
	return root
}
