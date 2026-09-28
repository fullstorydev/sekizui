// Package ledger holds the init ledger — everything the skeleton still owes
// (D53).
//
// A PACKAGE OF ITS OWN SO THE ROADMAP IS TESTABLE. The table lived inside
// `cmd/sekizui.run`, where nothing could read it, and the consequence was
// exactly what an untested table does: `pool` and `limiter` landed in P1 and
// their entries stayed, so every boot reported `implemented=5/12` and /readyz
// said DEGRADED for two reasons the same binary contradicted.
//
// Moving it here lets the acceptance package cross-reference it against the step
// table that says what is actually built, which is the only way an entry can be
// made to expire rather than to rot.
//
// DESIGN.md references: §4.10, D53, D139.
package ledger

import "github.com/fullstorydev/sekizui/internal/spine"

// Planned is everything not yet implemented, in CONTRACTS §6 build order.
//
// A subsystem lands by DELETING its entry and calling Register instead — and
// TestLedgerEntriesHaveNotLanded now fails the build until the deletion happens,
// which is what the original comment claimed a compiler would enforce and no
// compiler ever did.
func Planned() []spine.Planned {
	return []spine.Planned{
		// **`audit:ship` BEGAN AS THE BIGQUERY SINK DESCOPED FROM P2 (D169)**,
		// moved to P4 as "v1-ish" (§5.2.2a); D274 then split it — P4's
		// residency-partitioned sink NON-warehouse, the warehouse sink P6's,
		// with no entry here until P6 declares a step table. (This paragraph
		// said the entry "sits in P4 until somebody rules otherwise" for a day
		// after D319 deleted it; the 2026-09-27 Feierabend read found it.)
		// **`audit:ship` IS RETIRED (D319).** P4 steps 9-10 built it: the recorder
		// writes the local WAL alone and a shipper delivers each record to the
		// destinations its residency permits, asynchronously and at least once.
		// DELETED RATHER THAN RE-POINTED, D53's rule.
		// obs landed as logging + redaction; the OTel half waits for a real
		// driver, since a span per outbound call is what it exists to record.
		// It becomes a spine Component then — a tracer provider needs Stop to
		// flush pending spans.
		// **`obs:otel` IS RETIRED, AND A SKELETON IS WHAT RETIRED IT (D235).**
		// Its Why asked for "traces with the delegation chain in span
		// attributes; RED metrics" — only its NAME said otel — and
		// `internal/tracing` delivers both, in process, with no vendor SDK. The
		// bus landed at P0 the same way (D91), and OTel remains an EXPORTER for
		// whenever spans must leave the process, which is P4/P6 operations work
		// rather than a gap this table should report.
		//
		// **DELETED RATHER THAN RE-POINTED**, which is D53's rule and what
		// CONTRACTS 48 was about: `pool` and `limiter` kept their entries after
		// landing, so every boot reported `implemented=5/12` while the code sat
		// in the same binary. An entry REPORTS a gap and does not close one.
		// The BUS itself landed in P0 as a skeleton (D91) — authorised, audited,
		// and lensed delivery over an in-process transport. What P3 adds is the
		// INGRESS that fills it.
		// **NARROWED ON 2026-09-22, AND THE OLD WORDING IS WHY THE FEIERABEND
		// AUDIT EXISTS.** It read "nothing external publishes into them yet",
		// which stopped being true the moment step 31 landed: a caller's job
		// polls a real source, translates, and publishes envelopes a
		// subscriber receives over mTLS. So every boot reported the afferent
		// path as absent while it was running jobs — **CONTRACTS 48's
		// disclaimer-that-keeps-applying, in the ledger entry whose own
		// comment four lines up warns about exactly that.**
		//
		// The GUARD could not catch it. `ProvenBy` named steps 1, 4 and 5 —
		// the POLLER's — and none is built, so the expiry test correctly said
		// nothing. D247's re-plan made the JOB the first caller and this
		// field was never re-pointed, so the entry was keyed on the half that
		// had not landed while describing the half that had.
		//
		// What is genuinely still missing is the SCHEDULED trigger: a
		// deployment that polls with nobody asking. `ProvenBy` names the
		// steps that close THAT, which is what the entry is now about.
		// **THE ENTRY EXPIRED ON 2026-09-23, AND THE GUARD SAID SO.** Steps 4,
		// 5 and 14 were its proof; step 4 (the Fullstory sessions source, D265)
		// was the last to land, and TestLedgerEntriesHaveNotLanded failed until
		// this entry was deleted. The afferent plane is no longer a gap any boot
		// needs to report: jobs, schedules and a real connector's Source all run.
		// **NARROWED AGAIN AT THE 2026-09-23 FEIERABEND.** Its Why still said a
		// rule was "bounded by nothing until this lands" after D264 built the
		// firing budget, debounce and depth cap, and still listed Rego after
		// D263 removed it — so every boot reported an unbounded engine that was
		// bounded. The expiry guard could not see it: the entry's remaining
		// half had not landed. Only reading it did.
		//
		// **NARROWED BY D261, as `kyuushin` was by D252.** The ENGINE runs: it
		// consumes the bus as each rule's principal through the scoped path,
		// matches with the structural pre-filter, and dispatches through
		// Enforce, shadow by default (D172). What it does NOT have is anything
		// that BOUNDS it — which is why a rule may be armed only by a
		// deliberate `mode: enforce`, and why this entry must not read as if
		// the whole engine were absent.
		// **`reflex:policy` WAS HERE UNTIL P5 STEPS 7 AND 8 (D334, D335)**: shared
		// reflex budgets built, and a rule's serialisation plus the anzen principal
		// cap proven in place of a per-rule max_concurrent that could never exceed
		// one. TestLedgerEntriesHaveNotLanded demanded the deletion.
		// --- THE ANZEN SIGNALS NOTHING RAISES (D167, CONTRACTS 65) -----------
		//
		// **A VOCABULARY ENTRY IS A PROMISE, AND SINCE D336 EVERY ONE IS KEPT** —
		// twelve of twelve signals have producers, from four of seven unkept. An
		// anzen rule may WATCH any member of the closed signal set; boot
		// validates the name against that set and says nothing further. So a
		// rule watching one of these is well-formed, enabled, enforcing —
		// and permanently inert, with the operator told nothing. That is the
		// shape of CONTRACTS 65, and it was already live: `acceptance.yaml`
		// watched `spec_drift` before anything raised it.
		//
		// **LEDGER ENTRIES RATHER THAN A COMMENT, because the comment already
		// existed and reached nobody.** An entry makes the boot report say the
		// gap out loud, and CONTRACTS 48's expiry guard makes it rot loudly
		// once a producer lands — the same instrument that caught `pool` and
		// `limiter` claiming to be unimplemented from inside a binary that
		// implemented them.
		//
		// All twelve signals have producers and correctly have no entry here:
		// `audit_unavailable` (the audit shipper, D319 — missing from this list
		// until the v1 Feierabend read, which is the list going stale while no
		// guard could see it), `denial_storm` (denialStormWatcher, D336),
		// `spec_drift` (internal/drift/watcher.go),
		// `credential_stale`, `credential_churn` and `tenant_mismatch`
		// (cmd/sekizui), `budget_exceeded` (the reflex engine, D264), and the
		// four levels sourceWatcher publishes — `source_nonconforming`,
		// `source_stopped`, `source_undeclared` (D280), `connector_quarantined`
		// (D282), and `tool_nonconforming` (D289, published by the same
		// watcher from the MCP driver's tally; these counts read "eleven" for a
		// day after it landed, until the Feierabend read). The
		// PHASES BELOW ARE A PROPOSAL, not a ruling — each is placed where the
		// detection it needs already lands, and any of them can move.
		// `signal:budget_exceeded` WAS HERE until D264: the reflex engine
		// raises it on the transition into an exhausted firing budget, into the
		// same anzen dispatcher the watchers feed. The entry left with its
		// producer's arrival, which is what an expiring disclaimer is for.
		// --- THE ANZEN ACTIONS NO FIRING PATH IMPLEMENTS (D331, CONTRACTS 157) ---
		//
		// Validated vocabulary that fired as a CREDENTIAL REVOCATION of the rule's
		// subject until D331, because the withdrawal path read every action but
		// quarantine as revoke. Boot now refuses an enforcing rule doing one of
		// these; the entries are held equal to config.UnbuiltAnzenActions, so
		// building one deletes it from both. Phases are a proposal.
		{
			Name: "anzen:restrict_shin", LandsIn: "P6", ProvenBy: []int{11},
			Why: "tighten a lens on a consumer being overwhelmed (D85); unscheduled, placed with the panel as a proposal",
		},
		// **`anzen:revoke_grant` WAS HERE UNTIL D340**, a v1 hotfix: fired from a
		// rule, it suspends the principal the rule names through the governed verb.
		// **`signal:denial_storm` WAS HERE UNTIL P5 STEP 9 (D336)**: the gateway's
		// meter tallies rate refusals with who the limiter named over share, and
		// denialStormWatcher raises the level keyed by the monopoliser. The last
		// signal CONTRACTS 65 counted; every member of the set now has a producer.
		// **`signal:tenant_mismatch` WAS HERE AND IS GONE, WHICH IS THE ENTRY
		// DOING ITS JOB (D226, CONTRACTS 48).** It read: "a failed egress
		// assertion raises the signal; the assertion fires today and refuses the
		// call, and what does not exist is the escalation from one refused call
		// to a condition an anzen rule can act on." P2 step 45 built that
		// escalation — `internal/mistenant` tallies the refusals and
		// `mistenantWatcher` publishes the level — so the entry is DELETED rather
		// than re-pointed at a later phase. An entry that outlives the gap it
		// describes is how a ledger becomes decoration.
		// **`signal:audit_unavailable` IS RETIRED WITH IT (D319):** a destination
		// refusing records is a level the source watcher publishes, naming the
		// destination and why, and shipping catches up when it recovers.
		{
			Name: "leader", LandsIn: "P8",
			Why: "lease-based leader election; starts and stops ingest components mid-life",
		},
	}
}

// PhasesWithStepTables are the phases whose acceptance steps exist, so an entry
// landing in one of them can be checked against what is built.
//
// AN ENTRY IN ONE OF THESE MUST NAME ITS STEPS. Elsewhere ProvenBy is allowed to
// be empty, because a phase with no step table has nothing to name yet — and
// that is a real hole in this guard, stated rather than hidden: an entry could
// dodge the check by claiming a later phase. What stops that is the phase plan
// being reviewed, not this test.
//
//nolint:gochecknoglobals // immutable table, read once
var PhasesWithStepTables = map[string]bool{"P0": true, "P1": true, "P2": true, "P3": true, "P4": true, "P5": true, "P6": true}
