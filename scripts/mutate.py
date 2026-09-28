#!/usr/bin/env python3
"""Mutation harness: break one guarantee at a time, see which step notices.

WHY THIS EXISTS. A test that has never been made to fail is a test whose passing
means nothing (CONTRACTS 59). Sabotaging steps one at a time by hand does not
scale to 68 of them, and — worse — it checks the steps somebody thought to check.
This inverts the question: break a real guarantee in the PRODUCT and ask which
step notices. A mutation nothing catches is a guarantee nothing proves.

Each mutation is a (file, before, after) triple naming a specific guarantee, and
the Scope of acceptance steps expected to catch it (D281).
The output is the part that matters: SURVIVORS — mutations the whole suite
accepted.
"""
import os
import shutil
import re
import subprocess
import sys
import tempfile

GO = os.environ.get("GO") or shutil.which("go") or "go"


class Scope:
    """The acceptance steps expected to kill a mutation (D281).

    **WHY A MUTATION RUNS ONLY ITS SCOPE.** Every mutation used to re-run the
    whole acceptance suite, so the audit's cost was mutations x suite — and both
    grow every phase: `make ci` went from ten minutes (D242, 76 mutations) to
    over thirty (82) as P3 added forty steps. A mutation's job is to show that
    the step guarding its guarantee NOTICES; the other two hundred steps prove
    nothing about it.

    **THE FAILURE DIRECTION IS THE SAFE ONE.** A scope that is too narrow can
    only turn a caught mutation into a SURVIVOR, which fails the run loudly; it
    can never report a catch that did not happen. A scope naming a step that no
    longer exists is refused like a missing anchor, so a renamed step cannot
    quietly make a mutation test nothing.

    `steps` are step-name PREFIXES (`31_a_caller_asks`), matched in every phase.
    `Scope.FULL` runs the whole suite, for a mutation only the suite as a whole
    can see — D228's is caught by the REPORT refusing to be written after every
    step passes — and for a recorded equivalent, whose claim is that NOTHING
    catches it. The initial scopes are the killers a full run measured
    (2026-09-23), not guesses. `make mutate-full` ignores every scope.
    """

    def __init__(self, *steps, full=False):
        self.steps, self.full = steps, full

    def __repr__(self):
        return "Scope.FULL" if self.full else f"Scope{self.steps!r}"


Scope.FULL = Scope(full=True)


def parse_entry(entry):
    """(label, edits, scope) — THE ONE READING of an entry's shape, shared by
    the audit loop and check_clean: (label, file, before, after[, Scope]) or
    (label, [(file, before, after), ...][, Scope]). scope is None when absent."""
    label, *rest = entry
    scope = rest.pop() if rest and isinstance(rest[-1], Scope) else None
    edits = rest[0] if len(rest) == 1 else [tuple(rest)]
    return label, edits, scope


# Each entry: (label, file, before, after, Scope) or (label, [edits], Scope).
# `before` must appear exactly once; the Scope is REQUIRED (D281).
MUTATIONS = [
    # D197's two clauses. Both are reachable only because P2 steps 9 and 12
    # exist: the artefact table has owed them since the decision landed, and
    # D184's rule attaches the obligation to the STEP rather than the table, so
    # they arrive with the code that can be broken.
    ("D197: withholding stops reaching the catalog",
     "internal/catalog/catalog.go",
     "\t\tif c.drift != nil && c.drift.Withholds(spec.TargetRef, action) {",
     "\t\tif false && c.drift != nil && c.drift.Withholds(spec.TargetRef, action) {",
     Scope("09_drift_severities_are_distinguished_an_unv")),

    # D167 and D197 both own a clause about the signal, and they are DIFFERENT
    # failures at different points: this one stops the publish reaching the
    # dispatcher at all, so a watching rule never hears anything; D197's below
    # leaves the publish in place and empties the subjects, so the level is
    # reported as "nothing is diverged". The first is silence, the second is a
    # lie, and step 9's arms distinguish them.
    ("D167: drift stops raising the signal",
     "internal/drift/watcher.go",
     "\tif d.Observer != nil {",
     "\tif false && d.Observer != nil {",
     Scope("09_drift_severities_are_distinguished_an_unv", "12_offline_validation_blocks_the_load_live_c")),

    ("D197: the degraded signal stops being raised",
     "internal/drift/watcher.go",
     "\t\tif st.Degraded() || st.Refused() {",
     "\t\tif false && (st.Degraded() || st.Refused()) {",
     Scope("09_drift_severities_are_distinguished_an_unv")),

    # D206's two. The first is the fail-open direction on the store's own
    # bookkeeping and the second is the outage/drift confusion step 13 settled;
    # both were watched failing by hand before being written down here.
    ("D206: a failed attempt reads as a completed comparison",
     "internal/drift/store.go",
     "\tst.Ref, st.Err, st.AttemptedAt = ref, err, at",
     "\tst.Ref, st.Err, st.AttemptedAt, st.At = ref, err, at, at",
     Scope("12_offline_validation_blocks_the_load_live_c")),

    ("D206: an outage becomes a drift finding",
     "internal/drift/store.go",
     "\t// `At` is deliberately NOT advanced",
     "\tst.Findings = append(st.Findings, Finding{Severity: SeverityWithheld, Tool: \"?\",\n\t\tAction: \"?\", Detail: err.Error()})\n\t// `At` is deliberately NOT advanced",
     Scope("12_offline_validation_blocks_the_load_live_c")),

    # D71's ceiling, and it is the permanent form of the sabotage step 17 was
    # watched failing under. Every enforcing forbid rule behaves as SHADOW, so a
    # forbidden action is admitted, reaches the real driver and lands at the
    # upstream — the failure criterion 5 is actually about, since a refusal that
    # arrives after the call has already performed the action it forbade.
    ("D71: an enforcing anzen ceiling admits what it forbids",
     "internal/anzen/anzen.go",
     "\t\tif !r.enforcing {",
     "\t\tif true {",
     Scope("17_a_denied_action_against_a_real_system_is_", "58_every_deliberate_refusal_reaches_the_call", "60_an_anzen_guard_scopes_by_the_targets_resi")),

    ("D155: Query skips the shared ceilings",
     "internal/gateway/server.go",
     "\t_, releaseCeilings, ceilingRef := s.ceilings(ctx, id, subject,\n\t\treq.GetAction(), req.GetTargetRef(), \"\", nil)",
     "\t_, releaseCeilings, ceilingRef := s.ceilings(ctx, id, \"\",\n\t\t\"\", \"\", \"\", nil)",
     Scope("68_every_ceiling_and_control_applies_to_read")),

    ("D159: the pool stops asserting the entry's tenant",
     "internal/pool/pool.go",
     "\t\t\tif err := e.target.Assert(t.Tenant()); err != nil {",
     "\t\t\tif err := error(nil); err != nil {",
     Scope("25_the_egress_tenant_assertion_fires_against")),

    ("D149: config identity stops reaching the record",
     "internal/auditwal/recorder.go",
     "\td.ConfigIdentity = r.configIdentity",
     "\t_ = r.configIdentity",
     Scope("65_every_decision_record_names_the_configura")),

    ("D152: the monotonic downgrade guard stops refusing",
     "internal/credential/cache.go",
     "\tif seen && ordinal < prev.Ordinal {",
     "\tif false {",
     Scope("26_break_glass_is_correct_under_either_platf", "40_the_audit_row_names_the_stage_that_actual", "42_a_credential_the_far_side_rejects_is_re_e")),

    ("D108: pooled clients stop expiring",
     "internal/pool/pool.go",
     "\tif limit <= 0 || e.born.IsZero() {\n\t\treturn false\n\t}",
     "\tif true {\n\t\treturn false\n\t}",
     Scope("29_no_pool_entry_outlives_max_lifetime", "30_a_target_may_narrow_max_lifetime_but_neve")),

    # EQUIVALENT MUTANT, kept and marked rather than deleted.
    #
    # Removing the ACTION check does not change behaviour: an `anzen:` subject
    # must still name its own rule as the target, and the verbs that then remain
    # reachable are refused a layer below. That is defence in depth working, and
    # the honest response is to record it — contorting a test until it fails
    # would be testing the mutation rather than the system.
    #
    # It stays in the list because an equivalent mutant that stops being
    # equivalent is worth knowing about: if the second layer is ever removed,
    # this starts surviving for a real reason and the label is already written.
    ("D122: an anzen subject may do anything [EQUIVALENT]",
     "internal/gateway/server.go",
     "\tif cmd.GetAction() != verb.FireAnzen {",
     "\tif false {",
     Scope.FULL),

    ("D111/D153: credential requirements stop being checked",
     "internal/credential/boot.go",
     "\tif len(required) == 0 {\n\t\treturn nil\n\t}",
     "\tif true {\n\t\treturn nil\n\t}",
     Scope("12_boot_refuses_env_off_a_developer_machine", "36_credential_policy_refuses_a_provider_miss", "37_d97s_env_refusal_is_a_derived_rule_not_a_")),

    ("D98: an empty credential is accepted",
     "internal/credential/boot.go",
     "\t\tif t.CredentialRef == \"\" {",
     "\t\tif false {",
     Scope("14_boot_refuses_an_empty_credential_and_a_sc")),

    # RE-ANCHORED BY D319: the synchronous fan-out was retired and routing by
    # residency now happens where the shipper chooses each destination's
    # records. Caught first by the anchor guard added the same day.
    ("D120: audit shipping stops routing by residency",
     "internal/auditwal/ship.go",
     "\t\t\tif accepts(d.sink.Residencies(), rec.GetResidency()) {",
     "\t\t\tif accepts(d.sink.Residencies(), \"\") {",
     Scope("46_sinkresidencies_routes_rather_than_merely", "09_eu_resident_decision_records_land_in_an_eu")),

    ("D157: the edge latch stops suppressing repeats",
     "internal/anzen/dispatch.go",
     "\t\tif was {\n\t\t\t// STILL RAISED for this subject.",
     "\t\tif false {\n\t\t\t// STILL RAISED for this subject.",
     Scope("26_a_drift_condition_raises_spec_drift_and_a", "32_an_anzen_rule_watching_credential_stale_c", "43_a_churning_target_raises_credential_churn")),

    # D178's two guarantees. The first is the bound itself; the second is the
    # determinism the bound depends on, which is the subtle half — an unsorted
    # truncation drops different fields every run, and the object is hashed into
    # the audit chain.
    ("D178: the payload budget stops bounding",
     "internal/safestruct/safestruct.go",
     "\t\tif spent >= budget {",
     "\t\tif false {",
     Scope("32_an_unrepresentable_or_oversized_payload_l")),

    ("D178: truncation stops being deterministic",
     "internal/safestruct/safestruct.go",
     "\tsort.Strings(keys)",
     "\t_ = keys",
     Scope("32_an_unrepresentable_or_oversized_payload_l")),

    # D177's three guarantees, one per site, because they fail differently.
    #
    # Each mutation restores the exact code that was there before — the
    # `err == nil` guard — so a survivor would mean the defect could return
    # unnoticed. The query-row one is the sharpest: it is selective row
    # suppression by whoever controls the data.
    ("D177: one bad field erases the whole object",
     "internal/safestruct/safestruct.go",
     "\treturn &structpb.Struct{Fields: fields}, rep",
     "\treturn nil, rep",
     Scope("04_fullstory_sessions_are_polled_translated_", "18_fullstory_session_events_are_polled_by_ti", "19_attribution_survives_a_driver_that_never_")),

    ("D177: a substituted field is not recorded as substituted",
     "internal/safestruct/safestruct.go",
     "\tif len(substituted) > 0 {\n\t\tsort.Strings(substituted)",
     "\tif false {\n\t\tsort.Strings(substituted)",
     Scope("32_an_unrepresentable_or_oversized_payload_l")),

    ("D177: a driver's own claim about substitutions is believed",
     "internal/safestruct/safestruct.go",
     "\t\tif k == UnrepresentableKey || k == TruncatedKey {\n\t\t\tcontinue\n\t\t}",
     "\t\tif false {\n\t\t\tcontinue\n\t\t}",
     Scope("32_an_unrepresentable_or_oversized_payload_l")),

    # D163's two guarantees, arriving with the code that introduced them (D162).
    #
    # The first is the retry gate: the class decides, not the presence of a key.
    # That IS the defect CONTRACTS 63 recorded — a non-empty key opened the gate
    # on a call nothing made safe — so the mutation restores the old behaviour.
    # RE-ANCHORED when UnsafeToRetry began returning its REASON alongside the
    # verdict (D182). The old anchor included the bare `return true` that no
    # longer exists; the guarantee did not move, only the lines holding it. This
    # is the second time a D163 anchor has needed re-pointing after a refactor,
    # and both times `make mutate` REFUSED rather than reporting the guarantee as
    # covered — which is the whole argument for D162's amendment putting it in
    # `make ci`.
    ("D163: the idempotency class stops gating retry",
     "internal/retry/retry.go",
     "\tif !class.AllowsRetry() {",
     "\tif false {",
     Scope("03_a_none_class_mutating_action_refuses_to_r", "16_one_agent_targets_two_different_systems_i", "34_an_action_the_driver_does_not_declare_is_")),

    # The second is the load refusal. An unclassified mutating action must fail
    # the load, because there is no safe default — one direction forbids retries
    # the upstream supports, the other permits a double-write nobody chose.
    ("D163: an unclassified mutating action loads cleanly",
     "pkg/connector/connector.go",
     "\t\tif spec.Idempotency == \"\" {",
     "\t\tif false {",
     Scope("05_a_mutating_action_with_no_declared_idempo")),

    # THE THIRD MUTATION D163's ARTEFACT TABLE OWED AND NOBODY WROTE. DESIGN §12
    # P2 names three for D163 — the class gating retry, the load refusal, and the
    # key reaching the outbound call — and only the first two were here. D162
    # makes an UNAPPLIED mutation fail, which catches an anchor that rots; it
    # cannot catch one that was never written, and the report said "21 caught, 0
    # survived" over a set missing an obligation the design had already stated.
    # The gap was in the bookkeeping rather than in the coverage: the guarantee
    # turns out to be well defended, which is only knowable now that something
    # asks. §12 P2's table now records the structural fix — derive this list from
    # that column.
    ("D163: the caller's idempotency key stops reaching the outbound call",
     "internal/gateway/server.go",
     "\t\tKey:       cmd.GetIdempotencyKey(),",
     "\t\tKey:       \"\",",
     Scope("06_at_most_once_is_honest_the_bus_drops_rath", "10_revocation_writes_a_decision_record_namin", "19_posture_reaches_the_decision_record_not_o")),

    # D182's two guarantees, arriving with the code (D162). Both are about what
    # the CALLER is told, which is why neither was covered by D163's mutations:
    # the retry gate was already closed and correct in both cases.
    #
    # The first is the refusal reaching the caller at all. Without it Sekizui
    # declines to retry and then hands back the upstream's timeout — retryable in
    # the taxonomy, DeadlineExceeded on the wire — so the double-write hazard is
    # relocated to an agent rather than removed.
    ("D182: the refusal to retry stops reaching the caller",
     "internal/gateway/server.go",
     "\tif unsafe && fault.KindOf(execErr).Indeterminate() {",
     "\tif false {",
     Scope("03_a_none_class_mutating_action_refuses_to_r")),

    # The second is the distinction between "could a repeat succeed" and "do we
    # know whether the first one did". This mutation IS the first draft of D182:
    # it reads plausibly, and it reports every rate-limited `none`-class command
    # as an unknown outcome — sending an operator to reconcile a write that
    # demonstrably never happened, and suppressing the RetryAfter that says when
    # to come back. P1 steps 21 and 34 both drive that exact command and neither
    # notices, which is why P2 step 3 carries an arm for it.
    ("D182: a determinate failure is reported as an unknown outcome",
     "internal/gateway/server.go",
     "\tif unsafe && fault.KindOf(execErr).Indeterminate() {",
     "\tif unsafe && retry.Retryable(execErr) {",
     Scope("03_a_none_class_mutating_action_refuses_to_r")),

    # RE-ANCHORED when `isMutating` was folded into the one call site that needed
    # it (D163's wiring). The old anchor was that function's `return true`, and
    # deleting the function left the mutation pointing at nothing — so `make
    # mutate` REFUSED rather than reporting the guarantee as covered, which is
    # exactly what D162 makes an unapplied mutation for. The guarantee did not
    # move; only the line holding it did.
    # D186's two guarantees, arriving with the code (D162). Both are FAIL-CLOSED
    # checks on the write path, and both were unreachable before placement moved
    # into pkg/connector — which is the argument D175 makes for the distinction:
    # placement is governance, not transport.
    #
    # The first is the post-placement verification. Without it a middleware that
    # eats a header produces an unkeyed request that every log line reports as
    # idempotent, and the retry that follows double-writes.
    ("D186: a key that never reached the wire is sent anyway",
     "internal/connectors/kata/kata.go",
     "\tif err := idem.Verify(op, args, headers); err != nil {",
     "\tif err := error(nil); err != nil {",
     Scope("31_a_class_whose_placement_cannot_be_satisfi")),

    # The second is the collision refusal, and it is the defect the move found:
    # the driver-local placement wrote the key OVER a caller's field of the same
    # name, so the upstream acted on a request the agent did not make while the
    # record echoed ours rather than theirs.
    ("D186: a caller's own field is silently overwritten by the key",
     "pkg/connector/connector.go",
     "\tif _, taken := args[i.Placement]; taken {",
     "\tif false {",
     Scope("31_a_class_whose_placement_cannot_be_satisfi")),

    # D189's guarantee, arriving with the code (D162). ONE mutation rather than
    # several, because `make mutate` runs the ACCEPTANCE suite and step 2 is the
    # only built Fullstory step — a mutation nothing can catch SURVIVES and fails
    # the run, which is the right failure but the wrong reason. The status-mapping
    # and base-URL refusals are covered by the driver's own package tests under
    # `make verify`; they gain acceptance-level mutations with step 1.
    #
    # This is D4 falsified: the credential stops following the target, so every
    # request goes out with an empty one. Under concurrent multi-tenant load the
    # real version of this defect is worse than an empty header — it is tenant
    # B's credential on tenant A's request, which SUCCEEDS and audits as success.
    #
    # RE-POINTED WHEN D199 MOVED PLACEMENT INTO `pkg/connector`, and the choice
    # of new anchor matters: mutating the shared helper would break the
    # credential for EVERY driver, which is a broader question than the one this
    # mutation asks. Aimed at the CALL instead, so it stays a question about the
    # Fullstory driver and about step 2, which is what proves it. D162 caught
    # the orphan on the first run after the refactor — the second time in one
    # session.
    ("D189: the credential stops reaching the outbound request",
     "internal/connectors/fullstory/fullstory.go",
     "\tif err := connector.SetAuthorization(req.Header, t, \"Basic\"); err != nil {",
     "\tif err := error(nil); err != nil {",
     Scope("02_the_fullstory_driver_is_stateless_and_saf", "16_one_agent_targets_two_different_systems_i")),

    # D190's guarantee. A driver the pool SKIPPED would be invisible to
    # break-glass: `revoke_credential` would evict an empty pool and truthfully
    # report cancelling nothing (CONTRACTS 35). The marker entry is what keeps a
    # credential-free driver reachable, so removing it is the guarantee breaking.
    ("D190: a credential-free driver is silently unpooled",
     "pkg/connector/registry.go",
     "\treturn credentialFreeClient{kind: t.Kind()}, nil",
     "\treturn nil, fault.New(fault.KindConfig, op, \"unpooled\")",
     Scope("02_the_fullstory_driver_is_stateless_and_saf", "04_fullstory_sessions_are_polled_translated_", "16_one_agent_targets_two_different_systems_i")),

    ("D140: an unknown action is assumed read-only",
     "internal/gateway/server.go",
     "\t\tspec = connector.ActionSpec{\n\t\t\tMutating:    true,",
     "\t\tspec = connector.ActionSpec{\n\t\t\tMutating:    false,",
     Scope("34_an_action_the_driver_does_not_declare_is_")),

    ("D127: a wipe no longer waits for a borrow",
     "pkg/connector/credential.go",
     "func (c *Credential) UseRaw(fn func(material []byte) error) error {",
     "func (c *Credential) UseRaw(fn func(material []byte) error) error {\n\tif true {\n\t\treturn fn(c.material)\n\t}",
     Scope("40_eviction_waits_for_in_flight_calls_before")),

    ("D150: -expect-config stops comparing",
     "pkg/config/identity.go",
     "\tif !strings.EqualFold(expected, actual) {",
     "\tif !strings.EqualFold(expected, expected) {",
     Scope("66_boot_refuses_a_configuration_the_deployme")),

    ("D89: the recorder stops refusing records a sink may not receive",
     "internal/auditwal/recorder.go",
     "\tif err := sinkAccepts(r.sink, d.GetResidency()); err != nil {",
     "\tif err := error(nil); err != nil {",
     Scope("46_sinkresidencies_routes_rather_than_merely")),

    ("D133: a withdrawn target is servable again",
     "internal/pool/pool.go",
     "\t\tif rec, ok := p.withdrawn[t.Ref()]; ok {",
     "\t\tif rec, ok := p.withdrawn[t.Ref()]; false && ok {",
     Scope("09_revoke_credential_cancels_in_flight_calls", "11_quarantine_target_lets_in_flight_finish_r")),

    # D195's two, and the first reproduces the repository's own prior state:
    # before the expansion the catalog handed an agent the literal pattern, and
    # a grant naming an action nothing implements was advertised beside it.
    ("D195: the catalog advertises the pattern instead of what it covers",
     "internal/actionset/actionset.go",
     "func (s *Set) Covers(spec config.CapabilitySpec) []string {\n\tvar out []string",
     "func (s *Set) Covers(spec config.CapabilitySpec) []string {\n\treturn []string{spec.Action}\n\t//nolint\n\tvar out []string",
     Scope("08_a_tool_added_to_the_mcp_server_is_not_cal", "09_drift_severities_are_distinguished_an_unv", "14_an_action_denied_on_one_path_is_not_obtai")),

    ("D195: boot stops refusing an action nothing implements",
     "internal/grantcheck/grantcheck.go",
     "\t\t\t\tif len(set.Covers(spec)) > 0 {",
     "\t\t\t\tif true {",
     Scope("08_a_tool_added_to_the_mcp_server_is_not_cal", "35_nothing_in_the_catalog_is_synthesised_a_d")),

    # D203. The mutation is the STATIC form the decision refuses — a marker read
    # off the kind rather than off the producer. It re-establishes on all five of
    # `unauthenticated`'s producers, including D152's downgrade guard, where a
    # retry is the attacker's goal.
    #
    # **THE ANCHOR ROTTED WHEN D213 TYPED THE MARKER, and D162 caught it the only
    # way it can be caught: the audit SKIPPED with "anchor not found".** The
    # predicate is the same one; it now reads a `Reestablishment` rather than a
    # bool, so the static form has to produce one too.
    ("D203: re-establishment fires on any unauthenticated, not only a far-side 401",
     "internal/gateway/server.go",
     "\tif what := fault.ReestablishOf(outcomeErr); !unsafe && what != fault.ReestablishNone {",
     "\tif what := map[bool]fault.Reestablishment{true: fault.ReestablishCredential}[fault.KindOf(outcomeErr) == fault.KindUnauthenticated]; !unsafe && what != fault.ReestablishNone {",
     Scope("36_an_mcp_server_on_revision_2025_06_18_is_s", "42_a_credential_the_far_side_rejects_is_re_e")),

    # D204. The label is what makes the counter actionable rather than merely
    # present: a perimeter told that churn is happening somewhere cannot scope a
    # response, and scoping a response is most of what a perimeter does.
    #
    # **ANCHOR MOVED BY D213**: the credential remedy is now one arm of
    # `Server.reestablish` rather than inline in `Enforce`, so the target arrives
    # as `ref` instead of `cmd.GetTargetRef()`. Same line, same guarantee, one
    # indent deeper.
    ("D204: the churn counter loses its target label",
     "internal/gateway/reestablish.go",
     '\t\ts.metrics.IncrFor("credential_churn_total", ref)',
     '\t\ts.metrics.Incr("credential_churn_total")',
     Scope("43_a_churning_target_raises_credential_churn")),

    # D204. The per-target switch, which is the block an operator asked for.
    # Removed, `reestablish_attempts: 1` stops meaning "never" and a target an
    # operator has deliberately opted out is re-established anyway.
    #
    # **THIS REPLACED A MUTATION THAT SURVIVED, and the survivor was the useful
    # result.** The first version removed a causation-based DEPTH gate in the same
    # function; it survived because `Enforce` calls `enforceOnce` at most twice by
    # construction, so there was no third traversal for that gate to stop. The
    # gate was deleted rather than the mutation weakened — a safety guard nothing
    # can reach reads as a bound somebody has checked.
    ("D204: reestablish_attempts stops switching re-establishment off",
     "internal/gateway/reestablish.go",
     "\treturn attempts > 1",
     "\treturn true",
     Scope("42_a_credential_the_far_side_rejects_is_re_e")),

    # D204. Instance ~eighteen of the recurring class, written out: a new code
    # path discards the state of a guard it had no reason to know about. The
    # downgrade guard then loses its memory on the one path an attacker can
    # trigger on demand.
    ("D204: Invalidate clears D152's version mark along with the cache entry",
     "internal/credential/cache.go",
     "\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n\tdelete(c.entries, ref)\n}",
     "\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n\tdelete(c.entries, ref)\n\tc.markMu.Lock()\n\tdelete(c.marks, ref)\n\tc.markMu.Unlock()\n}",
     Scope("42_a_credential_the_far_side_rejects_is_re_e")),

    # D204. Churn published as an EVENT rather than a level: the threshold drops
    # to one, so the signal fires on a single legitimate expiry and quarantines a
    # target for rotating its own credential.
    ("D204: credential_churn fires on one legitimate expiry",
     "internal/churn/churn.go",
     "const Threshold = 2",
     "const Threshold = 1",
     Scope("43_a_churning_target_raises_credential_churn")),

    # D198. The session stops being carried after the handshake, which is the
    # partial support §4.7.10 keeps naming: `initialize` succeeds, the target
    # looks configured, and every subsequent request is one a server requiring a
    # session answers 400 to.
    ("D198: the MCP session is established and then not carried",
     "internal/driver/mcp/mcp.go",
     "\tif sess != nil {\n\t\treq.Header.Set(sessionHeader, sess.id)\n\t}",
     "\tif sess != nil && false {\n\t\treq.Header.Set(sessionHeader, sess.id)\n\t}",
     Scope("36_an_mcp_server_on_revision_2025_06_18_is_s", "37_a_client_credentials_token_reaches_an_mcp")),

    # D198/D130. A pool key that moves when the credential has NOT rotated re-runs
    # `initialize` on whatever clock moved it, destroying server-side state for a
    # credential nobody changed — the failure §4.7.1's table was drawn to prevent.
    #
    # **RE-ANCHORED ONTO THE REAL LINE WHEN STEP 37 LANDED, which the handoff said
    # to check.** While step 37 was unbuilt this had to be driven through the
    # credential cache's generation counter — the same key and the same
    # consequence, but a stand-in. `Version: secret.Version` in the oauth provider
    # is the actual guarantee, it is one line, and its comment says it is "what
    # keeps D47's promise that refresh is invisible to pooling". Step 37b counts
    # the sessions the far side minted, so the mutation now fails with the
    # consequence spelled out rather than with a cache-level symptom.
    ("D198: the token's version reaches the pool key, so a refresh evicts the pool",
     "pkg/provider/oauth/oauth.go",
     "\t\tVersion: secret.Version,",
     "\t\tVersion: tok.AccessToken,",
     Scope("37_a_client_credentials_token_reaches_an_mcp")),

    # D213. The silent downgrade, and the reason Sekizui is stricter than the
    # protocol here: `Mcp-Session-Id` is a RESPONSE header, so an intermediary
    # that drops one turns a stateful deployment sessionless with every call
    # still succeeding and nothing recording that the shape changed.
    ("D213: a server minting no session is accepted and served sessionless",
     "internal/driver/mcp/session.go",
     "\tsid := header.Get(sessionHeader)\n\tif sid == \"\" {",
     "\tsid := header.Get(sessionHeader)\n\tif sid == \"\" && false {",
     Scope("36_an_mcp_server_on_revision_2025_06_18_is_s")),

    # D213. The typed marker collapsed back to "re-establish something". A session
    # expiry then runs the CREDENTIAL remedy: a forced mint against the secret
    # manager for a credential nobody rejected, plus a `credential_churn` tick
    # that an anzen rule quarantines on — a routine server-side expiry promoted
    # to a governance event.
    ("D213: a session expiry runs the credential remedy",
     "internal/driver/mcp/mcp.go",
     "\t\treturn nil, fault.SessionRejected(op, fmt.Sprintf(",
     "\t\treturn nil, fault.CredentialRejected(op, fmt.Sprintf(",
     Scope("36_an_mcp_server_on_revision_2025_06_18_is_s")),

    # D216. The caller's span is dropped, so the span step 29 emits cannot be a
    # CHILD of the work that requested it — every governed call becomes a
    # detached root beside its own cause, which looks like a trace and shows the
    # wrong causal shape.
    ("D216: the caller's parent span is dropped from the record",
     "internal/identity/identity.go",
     "\treturn &sekizuiv1.Trace{TraceId: traceID, ParentSpanId: spanID, Sampled: sampled}",
     "\treturn &sekizuiv1.Trace{TraceId: traceID, Sampled: sampled}",
     Scope("18_a_decision_record_carries_agent_and_trace", "29_every_outbound_call_carries_a_span_with_t")),

    # D216. An all-zero trace id is what a broken propagator emits, and the
    # specification calls it invalid. Accepted as real it groups every such
    # caller's decisions under one id — the correlation equivalent of a shared
    # primary key.
    ("D216: an all-zero trace id is accepted as a real trace",
     "internal/identity/identity.go",
     "\tif !isHex(traceID, 32) || traceID == strings.Repeat(\"0\", 32) {",
     "\tif !isHex(traceID, 32) {",
     Scope("18_a_decision_record_carries_agent_and_trace")),

    # D215. The trace bound removed: one gRPC header puts an unbounded string on
    # two fsynced audit records per command — D178's disk amplification through
    # the party we authenticate rather than the party we do not control.
    ("D215: an unbounded trace id reaches the audit records",
     "internal/identity/identity.go",
     "\tif len(trace) > MaxTraceIDBytes {",
     "\tif false {",
     Scope("44_a_caller_controlled_string_cannot_amplify")),

    # D215. The refusal echoes the value it refused, which spends exactly the
    # disk the bound was protecting and makes the whole check a formality.
    ("D215: the refusal records the oversized key it refused",
     "internal/gateway/server.go",
     "\t\t\tMatchedRule: \"request_bounds\",\n\t\t}, sekizuiv1.RefusedBy_REFUSED_BY_REQUEST, err)",
     "\t\t\tMatchedRule: \"request_bounds\",\n\t\t\tIdempotencyKey: cmd.GetIdempotencyKey(),\n\t\t}, sekizuiv1.RefusedBy_REFUSED_BY_REQUEST, err)",
     Scope("44_a_caller_controlled_string_cannot_amplify")),

    # D169. The inbound trace never reaches the identity, so no governed action
    # can be joined to the conversation that produced it — §10.4's correlation
    # half, silently absent rather than wrong.
    #
    # **THE ANCHOR MOVED ON THE DAY IT WAS WRITTEN, and D162 caught it.** D215
    # hoisted the read into a local so the bound could be applied before the
    # value is recorded, so `TraceId:` is no longer the read site. Same
    # guarantee, one line up.
    ("D169: the inbound trace never reaches the decision record",
     "internal/identity/identity.go",
     "\ttrace := traceIDFromContext(ctx)",
     "\ttrace := \"\"",
     Scope("18_a_decision_record_carries_agent_and_trace", "19_attribution_survives_a_driver_that_never_", "44_a_caller_controlled_string_cannot_amplify")),

    # D169. The subject collapses into the caller, so every row names the mesh
    # that carried the call rather than the agent that made it — and §4.4's
    # confused-deputy defence becomes unauditable.
    ("D169: the recorded subject collapses into the caller",
     "internal/identity/identity.go",
     "\treturn &sekizuiv1.Identity{\n\t\tCaller:  caller,\n\t\tSubject: subject,",
     "\tsubject.Principal = caller.Principal\n\treturn &sekizuiv1.Identity{\n\t\tCaller:  caller,\n\t\tSubject: subject,",
     Scope("18_a_decision_record_carries_agent_and_trace", "19_attribution_survives_a_driver_that_never_")),

    # D208. Budget membership ignored, so two targets fronting one upstream go
    # back to independent buckets — Sekizui under-counting by a factor of two
    # against one org quota, discovered as 429s (CONTRACTS 11).
    ("D208: two targets fronting one upstream stop sharing a budget",
     "internal/limiter/local.go",
     "\tif b, ok := l.of[targetRef]; ok && b != \"\" {\n\t\treturn b\n\t}",
     "\tif b, ok := l.of[targetRef]; ok && b != \"\" && false {\n\t\treturn b\n\t}",
     Scope("15_an_mcp_target_and_a_native_driver_frontin")),

    # D209. The allocation path stops executing. At one instance the local
    # allocator returns the configured budget, so nothing observable changes
    # TODAY — which is exactly the trap: the P7 mechanism would rot unexercised
    # and first run in production. The scripted allocator in step 15 is what
    # makes it visible.
    ("D209: the capacity allocator is never consulted",
     "internal/limiter/allocation.go",
     "\tif l.alloc == nil {\n\t\treturn\n\t}\n\n\tl.mu.Lock()\n\tnames := make([]string, 0, len(l.targets))",
     "\tif l.alloc == nil || true {\n\t\treturn\n\t}\n\n\tl.mu.Lock()\n\tnames := make([]string, 0, len(l.targets))",
     Scope("15_an_mcp_target_and_a_native_driver_frontin")),

    # D210. The narrowing ceiling removed. An allocation is an input from OUTSIDE
    # the process at P7, so without it, spoofing the coordinator removes the rate
    # limit fleet-wide in one step — the control switched off by the mechanism
    # built to distribute it.
    ("D210: an allocation may widen the budget past its configured ceiling",
     "internal/limiter/allocation.go",
     "\tif cap <= 0 || cap > b.configuredCap {",
     "\tif cap <= 0 {",
     Scope("15_an_mcp_target_and_a_native_driver_frontin")),

    # D210. Keep-last with no decay: a partitioned fleet spends its full budget
    # per replica for as long as the outage lasts, which is the twenty-instance
    # case the budget exists to prevent.
    ("D210: a lost allocator never decays to the floor",
     "internal/limiter/allocation.go",
     "\tif l.missed >= missedRefreshesBeforeDecay {",
     "\tif l.missed >= missedRefreshesBeforeDecay && false {",
     Scope("15_an_mcp_target_and_a_native_driver_frontin")),

    # D210. The per-TARGET entitlement stops binding, so a surface is granted a
    # fresh per-principal share every time a principal arrives and can take
    # almost the whole shared budget from the surface it is contending with.
    ("D210: a target's entitlement within a shared budget stops binding",
     "internal/limiter/local.go",
     "\t\tif b.usedTargets[r.TargetRef]+cost > entitlement {",
     "\t\tif false {",
     Scope("15_an_mcp_target_and_a_native_driver_frontin")),

    # D52. The two paths' namespaces are disjoint by construction, and a matcher
    # that spanned them would silently DOUBLE every grant on a dual-path system:
    # `fullstory.*` would confer every `mcp.fullstory.*` tool and vice versa,
    # which is §4.9a.8's hazard arriving through the mechanism rather than through
    # the review process it warns about.
    # RE-ANCHORED (D330): the rule moved to pkg/config, where boot's reflex check
    # can reach it; policy.ActionMatches delegates, so every caller still asks it.
    ("D52: the action glob matches across the two paths' namespaces",
     "pkg/config/validate.go",
     "\treturn ok && strings.HasPrefix(action, prefix)",
     "\treturn ok && strings.Contains(action, strings.TrimSuffix(prefix, \".\"))",
     Scope("14_an_action_denied_on_one_path_is_not_obtai")),

    # D213. The wipe suppression removed, so discarding a pooled client to
    # re-handshake also zeroes material the very next traversal is about to use —
    # invariant 4 of §4.7.5 applied to an eviction whose credential was never in
    # question.
    ("D213: a session discard wipes a credential nobody rejected",
     "internal/pool/pool.go",
     "\t\tif e.keepCredential {\n\t\t\treturn\n\t\t}",
     "\t\tif e.keepCredential && false {\n\t\t\treturn\n\t\t}",
     Scope("36_an_mcp_server_on_revision_2025_06_18_is_s")),

    # D202. The mutation IS the line as it was: `recordFailure` minted the id,
    # wrote the row, and discarded it — so the row existed and the caller had no
    # key to it.
    # D202's UNMET HALF, found by D211's work. `recordFailure` was the funnel the
    # original fix went into, and this is the sibling path: a command authorised,
    # called, and failed at the far side — the commonest failure there is. Step
    # 41 asserted D202's claim and only ever drove the other path, because its
    # fixture used an unknown target ref and was refused before any driver ran.
    ("D202: a far-side failure stops carrying its decision id",
     "internal/gateway/server.go",
     "\t\treturn nil, fault.WithDecisionID(outcomeErr, decisionID)",
     "\t\treturn nil, outcomeErr",
     Scope("41_a_genuine_failure_names_the_audit_row_tha")),

    ("D202: a failure stops naming the row that explains it",
     "internal/gateway/server.go",
     "\treturn fault.WithDecisionID(cause, id)",
     "\t_ = id\n\treturn cause",
     Scope("41_a_genuine_failure_names_the_audit_row_tha")),

    # D201. The mutation IS the defect as it existed — the resolve stage gating
    # on deliberateness — so it reproduces an audit row that named data
    # residency for a credential downgrade.
    ("D201: the resolve stage labels every deliberate refusal as residency",
     "internal/gateway/server.go",
     "\t\tcase kind == fault.KindResidency:",
     "\t\tcase kind.Deliberate(), kind == fault.KindResidency:",
     Scope("40_the_audit_row_names_the_stage_that_actual", "42_a_credential_the_far_side_rejects_is_re_e")),

    # D200. The anchor is the PREDICATE the breaker asks, and the mutation is
    # literally the old rule — so this reproduces the repository's prior state
    # exactly, the same way D184's did.
    ("D200: the breaker goes back to blaming whoever is not deliberate",
     "pkg/fault/fault.go",
     "\treturn k.Attribution() == AttributionTarget && !k.Deliberate()",
     "\treturn !k.Deliberate()",
     Scope("39_a_credential_fault_does_not_open_the_targ")),

    ("D199: material that cannot be a header value is sent anyway",
     "pkg/connector/authheader.go",
     "\t\tif err := refuseUnsafeHeaderBytes(op, t.Ref(), scheme, buf); err != nil {",
     "\t\tif err := error(nil); err != nil {",
     Scope("38_a_credential_that_cannot_be_a_header_valu")),

    # D196. The anchor is the REQUIREMENT rather than the catalog's fallback,
    # because the fallback is gone: with the load refusal off, an undescribed
    # action reaches the catalog and there is nothing for it to say.
    ("D196: an action with no description loads",
     "pkg/connector/connector.go",
     "\t\tif strings.TrimSpace(spec.Description) == \"\" {",
     "\t\tif false {",
     Scope("35_nothing_in_the_catalog_is_synthesised_a_d")),

    # **D222's GUARANTEE IS THAT A DRIVER IS REACHABLE, which is the one every
    # other check passes without.** An unregistered or unroutable driver
    # compiles, tests green, and satisfies the whole conformance suite — its
    # Execute, Query and Actions all LOOK reached because they satisfy
    # connector.Driver and the gateway calls that interface. Emptying Kind() is
    # the smallest expression of "nothing can route to this", and step 27 is
    # what must notice. Kept as a mutation rather than left as a hand sabotage
    # because it targets a PRODUCT guarantee (README: three kinds of deliberate
    # breakage).
    # **D225's GUARANTEE IS THAT ONE RULE'S LATCH DOES NOT SILENCE ANOTHER'S.**
    # Dropping the rule name from the key restores the exact defect step 26
    # found: whichever rule sorts first consumes the edge, so a shadow rule
    # disables the enforcing rule beside it. The mutation is one field of a
    # string concatenation, which is what the defect was.
    ("D225: the edge latch goes back to being shared across rules",
     "internal/anzen/dispatch.go",
     "\t\tkey := signal + \"\\x00\" + rule.Subject + \"\\x00\" + rule.Name",
     "\t\tkey := signal + \"\\x00\" + rule.Subject",
     Scope("26_a_drift_condition_raises_spec_drift_and_a")),

    # **D226's GUARANTEE IS THAT A REFUSED EGRESS BECOMES A CONDITION.** Without
    # the escalation the assertion still refuses the call — so every test of the
    # ASSERTION passes — and `tenant_mismatch` goes back to being a vocabulary
    # entry nothing can raise, which is the state CONTRACTS 65 describes and the
    # one no behavioural test of the refusal can see.
    ("D226: a refused egress is never escalated to a condition",
     "internal/gateway/server.go",
     "\tif s.mistenant != nil && errors.Is(execErr, connector.ErrTenantMismatch) {",
     "\tif false && errors.Is(execErr, connector.ErrTenantMismatch) {",
     Scope("45_a_failed_egress_assertion_raises_tenant_m")),

    # **NOTHING IS TRACKED** — every handle an agent forgets holds a vendor slot until the vendor's own expiry.
    ("D291: an opener's handle is not recorded",
     "internal/gateway/handles.go",
     "\t\ts.handles.open[handleKey(target, v)] = &openHandle{",
     "\t\t_ = &openHandle{",
     Scope("43_a_stateful_handle")),

    # **A HANDLE IN USE IS CLOSED UNDER ITS CALLER** — the sweep takes the session away mid-review.
    ("D291: using a handle does not keep it alive",
     "internal/gateway/handles.go",
     "\t\t\t\te.lastUsed = s.now()\n",
     "\t\t\t\t_ = e\n",
     Scope("43_a_stateful_handle")),

    # **THE TABLE FORGETS NOTHING** — a second close of a released slot, credited to someone who already closed it.
    ("D291: a handle its caller closed is closed again",
     "internal/gateway/handles.go",
     "\t\t\tdelete(s.handles.open, handleKey(target, v))\n",
     "\t\t\t_ = v\n",
     Scope("43_a_stateful_handle")),

    # **THE DRAIN REACHES FOR A COMPROMISED CREDENTIAL** — refused by the withdrawal check, but attempted, which the maintainer ruled out.
    ("D291: break-glass handles are closed through the revoked credential",
     "internal/gateway/handles.go",
     "\t\t\tif _, withdrawn := s.pool.Withdrawn(e.target); withdrawn {",
     "\t\t\tif _, withdrawn := s.pool.Withdrawn(e.target); withdrawn && false {",
     Scope("43_a_stateful_handle")),

    # **THE RECORD LIES ABOUT WHO CLOSED** — a system-initiated close written as though the agent's certificate made it.
    ("D291: an automatic close claims the opener's own credential",
     "internal/gateway/handles.go",
     "Method: sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL,",
     "Method: sekizuiv1.AuthMethod_AUTH_METHOD_MTLS,",
     Scope("43_a_stateful_handle")),

    # **EVERY AUTOMATIC CLOSE BECOMES A REFUSAL** — the opener's grant does not cover the closer Sekizui calls as them.
    ("D291: a principal may open a handle it may not close",
     "pkg/config/mcp_validate.go",
     "\t\t\tif opens && !closes {",
     "\t\t\tif false && opens && !closes {",
     Scope("43_a_stateful_handle")),

    # Criterion 3, D240's reading of D150. **AN UNLOADABLE CURSOR STORE BOOTS**,
    # and every tick then fails to load it and retries for ever — a process
    # that is up and does nothing, where the contract says the boot refuses.
    # Caught by step 1c, which starts the real binary over an unloadable store.
    ("criterion 3: an unloadable cursor store does not fail the boot",
     "internal/kyuushin/kyuushin.go",
     "\t\tst, err := p.store.Load(ctx, j.Target.Ref())\n\t\tif err != nil {",
     "\t\tst, err := p.store.Load(ctx, j.Target.Ref())\n\t\tif false && err != nil {",
     Scope("01_a_cursor_survives_a_kill")),

    # Criterion 3. **A POLL WHOSE ATTEMPT WAS NOT WRITTEN PUBLISHES ANYWAY** — a
    # crash then loses events nothing can name. Caught by step 1d.
    ("criterion 3: a poll publishes although its attempt could not be recorded",
     "internal/kyuushin/tick.go",
     "\tif berr := p.begin(ctx, j, att); berr != nil {",
     "\tif berr := p.begin(ctx, j, att); false && berr != nil {",
     Scope("01_a_cursor_survives_a_kill")),

    # D293. **THE CURSOR ADVANCES BEFORE ANYTHING IS PUBLISHED** — the ordering
    # a reasonable implementation gets backwards. A crash mid-publish then
    # resumes past rows no consumer received. Caught by step 2a (the cursor
    # moved on a poll that stopped) and 2c (the commit is not the last write).
    ("D293: the cursor is committed before the envelopes are published",
     "internal/kyuushin/tick.go",
     "\tdeclared := declaredOutputs(j)\n",
     "\t_ = p.commit(ctx, j, next)\n\tdeclared := declaredOutputs(j)\n",
     Scope("02_the_cursor_advances_only")),

    # D275/D293. **PUBLISHING GOES ON PAST A MARK THAT FAILED**, so the mark no
    # longer says what reached the bus and recovery trusts a lie. Caught by
    # step 2a, which delivers rows 1 and 2 after the mark after row 0 failed.
    ("D293: publishing continues past a progress mark that could not be written",
     "internal/kyuushin/tick.go",
     "\t\tif perr := p.progress(ctx, j, i+1); perr != nil {\n\t\t\treturn false, published + 1, perr\n\t\t}",
     "\t\t_ = p.progress(ctx, j, i+1)",
     Scope("02_the_cursor_advances_only")),

    # Criterion 3. **A FULLY PUBLISHED WINDOW IS RECORDED AS A GAP** — the
    # false record step 3 found: "0 event(s) may never have been delivered".
    # Caught by step 3e.
    ("criterion 3: a window that lost nothing writes a gap record",
     "internal/kyuushin/tick.go",
     "\t\t\tif len(lost) == 0 {",
     "\t\t\tif false && len(lost) == 0 {",
     Scope("03_a_restart_does_not")),

    # Criterion 3. **A RECOVERY WITH NOTHING LEFT IS LOGGED AS THE EVENTS
    # AGAIN** — `poll:completed "3 events"` for a window that published none,
    # the other false record step 3 found. Caught by step 3c.
    ("criterion 3: a recovered window is recorded as its events again",
     "internal/kyuushin/tick.go",
     "\tif atRisk := len(toPublish); atRisk > 0 || note != \"\" {",
     "\tif atRisk := len(toPublish); atRisk > 0 || (false && note != \"\") {",
     Scope("03_a_restart_does_not")),

    # D292. **A TYPED LENS'S WITHHOLDS GO UNCHECKED AGAIN** — the state before
    # D292: a typo in `fields` refused the boot and a typo in `withholds`
    # withheld nothing, silently. Caught by step 23d, which boots a misspelled
    # carrier.
    ("D292: a typed lens may withhold a path no kind of its type could carry",
     "internal/schemareg/check.go",
     "\t\tfor _, path := range l.Withholds {",
     "\t\tfor _, path := range l.Withholds[:0] {",
     Scope("23_an_envelope_produced_by_a_real_connector")),

    # D292. **AN OPEN KIND STOPS MAKING A PROPERTY PLAUSIBLE** — the state
    # before D292, when only the family's envelope was consulted and no custom
    # event's property could be named in a lens at all. Caught by step 23, whose
    # allowlist keeps `event_properties.is_host` and would not boot.
    ("D292: a property under an open kind cannot be named in a lens",
     "internal/schemareg/schemareg.go",
     "\tif fam.open != nil {\n\t\treturn true, nil\n\t}",
     "\tif false && fam.open != nil {\n\t\treturn true, nil\n\t}",
     Scope("23_an_envelope_produced_by_a_real_connector")),

    # Criterion 9 on a real connector's data. **A NESTED ALLOWLIST PATH COPIES
    # ITS WHOLE CARRIER**: keeping `event_properties.is_host` keeps every
    # property beside it, the email and the name included. Caught by step 23a.
    ("criterion 9: an allowlisted nested path keeps everything beside it",
     "internal/shin/shin.go",
     "\tif len(segments) == 1 {\n\t\tto[head] = v",
     "\tif len(segments) >= 1 {\n\t\tto[head] = v",
     Scope("23_an_envelope_produced_by_a_real_connector")),


    # D306. **CONFORMANCE STOPS FOLLOWING `$ref`** — the state before D306: a
    # reference node has no `type` and no `properties`, so the walk checked
    # nothing beneath one, and compute_metric's whole result passed whatever
    # arrived. Caught by P4 step 31f through the governed path.
    ("D306: the conformance check stops expanding the contract's references",
     "internal/driver/mcp/result.go",
     "\tschema = expanded\n",
     "\t_ = expanded\n",
     Scope("31_the_fullstory_mcp_ships_every_tool")),

    # D311. **AN UNASKED CALL SKIPS THE WITHDRAWAL CHECK** — the drift gate's
    # first version: it copied only the ceilings, so a quarantined target was
    # still compared, with its credential. Both unasked calls now share one
    # sequence; step 32d catches its withdrawal stage going.
    ("D311: an unasked call is not refused on a withdrawn target",
     "internal/gateway/job.go",
     "\t\tif sev, withdrawn := s.pool.Withdrawn(targetRef); withdrawn {",
     "\t\tif sev, withdrawn := s.pool.Withdrawn(targetRef); false && withdrawn {",
     Scope("32_every_drift_comparison")),

    # D311. **A CLEAN COMPARISON LEAVES NO TRACE** — the state before D311,
    # where only divergence was logged and a check that found nothing was
    # indistinguishable from one that never ran.
    ("D311: a clean drift comparison is not recorded",
     "internal/gateway/driftgate.go",
     "\tfindings := make([]*structpb.Value, 0, len(c.Findings))\n",
     "\tif c.Outcome == drift.OutcomeClean {\n\t\treturn nil\n\t}\n\tfindings := make([]*structpb.Value, 0, len(c.Findings))\n",
     Scope("32_every_drift_comparison")),

    # D311. **A RESTART FORGETS THE FINDING** — never auto-restore trust: a
    # store that loaded nothing would put a withdrawn tool back in the catalog.
    ("D311: persisted drift state is forgotten on restart",
     "internal/drift/store.go",
     "\traw, err := os.ReadFile(path)",
     "\traw, err := os.ReadFile(path + \".forgotten\")",
     Scope("32_every_drift_comparison")),

    # D294. **THE DRIVER CALLS AN UNDOCUMENTED ENDPOINT** — Lexicon's one
    # not-carried call, `POST /v2/sessions/search`, put back. Step 2a names it.
    ("D294: the Fullstory driver declares an endpoint the reference does not document",
     "internal/connectors/fullstory/endpoints.go",
     "epListSessions   = endpoint{http.MethodGet, \"/sessions/v2\"}",
     "epListSessions   = endpoint{http.MethodPost, \"/v2/sessions/search\"}",
     Scope("02_every_endpoint_the_driver_calls")),

    # D299. **A REQUEST IS BUILT OUTSIDE THE DECLARED SURFACE** — a literal path,
    # so `Surface()` under-reports what the driver calls. Step 2b reads the
    # source and names the site.
    ("D299: the Fullstory driver builds a request outside its declared surface",
     "internal/connectors/fullstory/source.go",
     "req, err := http.NewRequestWithContext(ctx, ep.method, base+ep.path(params...)+query, rdr)",
     "req, err := http.NewRequestWithContext(ctx, ep.method, base+\"/v2/sessions/search\"+query, rdr)",
     Scope("02_every_endpoint_the_driver_calls")),

    # D314. **A DOCUMENTED OPERATION IS NOT DERIVED** — marked hand-built when
    # no hand-built action reaches it, so it silently drops out of "in full".
    ("D314: a documented Fullstory operation is silently not implemented",
     "internal/connectors/fullstory/api.go",
     "\t\"POST /v2/sessions/{session_id}/context\": true, \"GET /sessions/v2\": true,",
     "\t\"POST /v2/sessions/{session_id}/context\": true, \"GET /sessions/v2\": true, \"GET /v2/organization/quotas\": true,",
     Scope("03_every_snapshot_endpoint")),

    # D314. **THE SUGGESTED CEILING FORGETS AN IRREVERSIBLE ACTION.**
    ("D314: the suggested Fullstory anzen ceiling omits an irreversible action",
     "internal/connectors/fullstory/anzen.yaml",
     "      - fullstory.delete_user              # DELETE /v2/users/{id}\n",
     "",
     Scope("33_the_fullstory_connectors_suggested")),

    # D290. **THE LENS STOPS AT EXECUTE** — the state before D290: shin reached
    # Query rows, the bus and job results, and never an MCP tool's output, so
    # no deployment could keep an agent from receiving a tool's prose.
    ("D290: an imposed lens is not applied to an Execute result",
     "internal/gateway/server.go",
     "\t\treturned = projected\n",
     "\t\t_ = projected\n",
     Scope("25_the_fullstory_mcps")),

    # **AN UNVETTED ARGUMENT REACHES THE SERVER** — the state before D289, when ActionSpec.InputSchema's doc comment claimed a check nothing made.
    ("D289: MCP arguments reach the server unchecked",
     "internal/driver/mcp/mcp.go",
     "\targs, err = admitArgs(op, t, tool, args)\n",
     "\targs, err = args, error(nil)\n",
     Scope("25_the_fullstory_mcps")),

    # **THE TARGET'S ORG IS NOT SENT** — the server falls back to 'the org of the connection', which is exactly the implicit tenancy the pin exists to make explicit.
    ("D289: a pinned argument is not injected",
     "internal/driver/mcp/result.go",
     "\t\tout[name] = want\n",
     "\t\t_ = want\n",
     Scope("25_the_fullstory_mcps")),

    # **THE SIGNED URL REACHES THE LOG THROUGH `text`** — the hole the screenshot receipt showed: the whole text carries the value the field withholds.
    ("D289: a caller-only value is not scrubbed from other recorded strings",
     "internal/gateway/record.go",
     "val = strings.ReplaceAll(val, sec.value, ",
     "val = strings.ReplaceAll(val, sec.value+\"\\x00\", ",
     Scope("25_the_fullstory_mcps")),

    # **D177's 'CALLER AND RECORD AGREE' RESTORED** — a seven-day bearer link fsynced into the audit log.
    ("D289: the recorded copy is the returned copy",
     "internal/gateway/server.go",
     "safestruct.Convert(s.forRecord(spec, res.Data), safestruct.DefaultBudget)",
     "safestruct.Convert(res.Data, safestruct.DefaultBudget)",
     Scope("25_the_fullstory_mcps")),

    # **THE DRIVER AND THE DRAFT DISAGREE AGAIN** — Fullstory's JSON-as-text refused, every drafted data_schema shaping nothing.
    ("D289: JSON returned as text is not parsed",
     "internal/driver/mcp/result.go",
     "\tif err := json.Unmarshal([]byte(full), &obj); err == nil && obj != nil {",
     "\tif err := json.Unmarshal([]byte(\"\"), &obj); err == nil && obj != nil {",
     Scope("25_the_fullstory_mcps")),

    # **A CHANGED TYPE IS SHAPED AND PASSED** — CONTRACTS 137's gap: nothing notices a vendor changing a tool after vetting.
    ("D289: a result that breaks its output contract's types is admitted",
     "internal/driver/mcp/result.go",
     "\t\tif !typeAdmits(s[\"type\"], v) {",
     "\t\tif false && !typeAdmits(s[\"type\"], v) {",
     Scope("25_the_fullstory_mcps")),

    # **THE MULTI-BLOCK RULE IS GONE** — the driver joins blocks the draft treated as samples.
    ("D289: several JSON blocks are not refused without a declared combine",
     "internal/driver/mcp/result.go",
     "\tif len(blocks) > 1 {",
     "\tif false && len(blocks) > 1 {",
     Scope("25_the_fullstory_mcps")),

    # **A VETTED SPEC POINTED ANYWHERE** — its tools and credential sent to a server nobody reviewed (CONTRACTS 117).
    ("D289: the MCP driver dials a host its spec was not vetted against",
     "internal/driver/mcp/mcp.go",
     "\tif err != nil || u.User != nil || spec.Host == \"\" || u.Hostname() != spec.Host {",
     "\tif false && (err != nil || u.User != nil || spec.Host == \"\" || u.Hostname() != spec.Host) {",
     Scope("25_the_fullstory_mcps")),

    # **THE LOAD-TIME HALF OF THE VETTED HOST** — a mismatched target boots and fails only at its first call.
    ("D289: config admits a vetted spec pointed at another host",
     "pkg/config/mcp_validate.go",
     "\t\tcase err == nil && baseURL != \"\" && (u.Hostname() != spec.Host || u.User != nil):",
     "\t\tcase false && err == nil && baseURL != \"\" && (u.Hostname() != spec.Host || u.User != nil):",
     Scope("25_the_fullstory_mcps")),

    # **THE KEYWORD PARSES AND DOES NOTHING** — the shape D278 exists to refuse, a constraint that reads as in force.
    ("D289: the registry ignores callerOnly",
     "internal/schemareg/schemareg.go",
     "\t\tif p != nil && p.CallerOnly {",
     "\t\tif p != nil && false {",
     Scope("25_the_fullstory_mcps")),

    # P3 STEP 24. **THE CALL STOPS CHECKING THE HOST** — boot still refuses a
    # bad document, but a target reaching the driver any other way sends its
    # credential wherever base_url points (CONTRACTS 117).
    ("P3 step 24: the Fullstory driver dials a host without checking it",
     "internal/connectors/fullstory/fullstory.go",
     "\tif err := d.AdmitBaseURL(t.Ref(), raw); err != nil {\n\t\treturn \"\", err\n\t}\n\treturn raw, nil",
     "\tif err := d.AdmitBaseURL(t.Ref(), raw); err != nil && false {\n\t\treturn \"\", err\n\t}\n\treturn raw, nil",
     Scope("24_the_fullstory_slice")),

    # P3 STEP 24. **THE USERINFO TRICK PASSES** — only if the host were read
    # from the string rather than the parsed URL; here, the check dropped.
    ("P3 step 24: a base_url carrying userinfo is admitted",
     "internal/connectors/fullstory/fullstory.go",
     "\tif parsed.User != nil {",
     "\tif parsed.User != nil && false {",
     Scope("24_the_fullstory_slice")),

    # P3 STEP 24. **A LOOK-ALIKE PASSES** — a suffix match instead of an exact
    # one, so api.fullstory.com.example.test is "Fullstory".
    ("P3 step 24: a look-alike Fullstory host is admitted",
     "internal/connectors/fullstory/fullstory.go",
     "\tif (apiHosts[parsed.Host] && parsed.Port() == \"\") || d.testHosts[parsed.Host] ||",
     "\tif (apiHosts[parsed.Host] && parsed.Port() == \"\") || strings.HasPrefix(parsed.Host, \"api.fullstory.com\") || d.testHosts[parsed.Host] ||",
     Scope("24_the_fullstory_slice")),

    # D287. **THE CLI CAN DIAL AGAIN** — one import away from becoming the
    # MCP client that holds a credential Sekizui governs. Caught by 26a.
    ("D287: the schema drafting CLI can reach the network",
     "cmd/sekizui-mcpspec/main.go",
     "\t\"github.com/fullstorydev/sekizui/internal/mcpspec\"\n)",
     "\t\"github.com/fullstorydev/sekizui/internal/mcpspec\"\n\t_ \"net/http\"\n)",
     Scope("26_sekizui_mcpspec_never_talks")),

    # D287. **PROSE IS ACCEPTED** — an agent's paraphrase of a result, the
    # lossy path at its worst, reaches the drafter.
    ("D287: a result holding only prose is not refused as prose",
     "internal/mcpspec/mcpspec.go",
     "\t\tif len(obs.Samples) == 0 {",
     "\t\tif false && len(obs.Samples) == 0 {",
     Scope("26_sekizui_mcpspec_never_talks")),

    # D233. **THE OBSERVATION IS PRINTED** — customer data on the terminal and
    # in whatever captures it. Caught by 27c's sentinels.
    ("D233: the drafting CLI prints the observation it was given",
     "cmd/sekizui-mcpspec/main.go",
     "\tif caution := mcpspec.WarnOnSize([][]byte{obs.Raw}); caution != \"\" {",
     "\tif caution := string(obs.Raw); caution != \"\" {",
     Scope("27_the_observation_never_lands")),

    # D287. **THE DATA SCHEMA IS THE CONTRACT, NOT ITS CLOSED SUBSET** —
    # unenforced keywords and an open root pasted into the allowlist, which the
    # boot then refuses. Caught by 28a loading it in schemareg.
    ("D287: the data_schema is not reduced to what schemareg enforces",
     "internal/mcpspec/mcpspec.go",
     "\tdata := closedSubset(source, \"\", &dataWarnings)\n",
     "\tdata := source\n",
     Scope("28_the_list_the_output_schema")),

    # D287. **AN ADVERTISED SCHEMA IS COPIED AS LOCAL** — never drift-checked,
    # so a vendor change goes unnoticed: the opposite of what copying it is for.
    ("D287: a copied vendor schema is marked local",
     "internal/mcpspec/mcpspec.go",
     "\treturn fragment(tool, outputType, \"vendor\", schema, 0, nil,",
     "\treturn fragment(tool, outputType, originLocal, schema, 0, nil,",
     Scope("28_the_list_the_output_schema")),

    # D286. **THE READ STOPS CONFINING** — only boot checks, so a symlink
    # re-pointed at the audit log after boot is read and sent off-host.
    ("D286: a file credential is confined at boot and not at read",
     "pkg/provider/file/file.go",
     "\tpath, root, err := p.confined(ref)\n",
     "\tpath, err := PathOf(ref)\n\tvar root string\n",
     Scope("42_the_afferent_path")),

    # D286. **THE AUDIT DIRECTORY IS READABLE AGAIN** from inside a root.
    ("D286: the audit directory is not denied",
     "pkg/provider/file/confine.go",
     "\t\tif within(resolved, evaluatedOrClean(d)) {",
     "\t\tif false && within(resolved, evaluatedOrClean(d)) {",
     Scope("42_the_afferent_path")),

    # D286. **A SYMLINK IS JUDGED BY ITS NAME** — lexical confinement, which a
    # link inside the root pointing anywhere passes.
    ("D286: symlinks are not followed before confining",
     "pkg/provider/file/confine.go",
     "\tresolved, err = evaluate(path)\n",
     "\tresolved, err = filepath.Abs(path)\n",
     Scope("42_the_afferent_path")),

    # D286. **A CHAINED REFERENCE ESCAPES THE BOOT CHECK** — a file hidden in an
    # oauth-cc:// client secret, which the cache will still resolve.
    ("D286: the boot does not walk chained references",
     "internal/credential/boot.go",
     "\t\t\t\twalk(target, inner, depth+1)\n",
     "\t\t\t\t_ = inner\n",
     Scope("42_the_afferent_path")),

    # D286. **THE PUBLISHED PROVIDER READS ANYTHING BY DEFAULT** again.
    ("D286: with no root declared, any file is readable",
     "pkg/provider/file/confine.go",
     "\t\tif !p.allowUnrooted {",
     "\t\tif false && !p.allowUnrooted {",
     Scope("42_the_afferent_path")),

    # D285. **THE FIRST POLL IS A WHOLE INTERVAL AWAY AGAIN** — CONTRACTS 134's
    # state: every restart resets the wait, and a source whose interval exceeds
    # the deploy cadence never polls. Caught by step 41a's hourly schedule.
    ("D285: every restart waits a whole interval before polling",
     "internal/kyuushin/kyuushin.go",
     "func firstDelay(last, now time.Time, every time.Duration) time.Duration {\n\tswitch {",
     "func firstDelay(last, now time.Time, every time.Duration) time.Duration {\n\tif every > 0 {\n\t\treturn every\n\t}\n\tswitch {",
     Scope("41_a_schedule_keeps")),

    # D285. **A FUTURE POLL TIME IS TRUSTED** — whoever can write the cursor
    # store silences a source by dating its last poll next year.
    ("D285: a poll time in the future silences the source",
     "internal/kyuushin/kyuushin.go",
     "\tcase last.After(now):\n\t\treturn every\n",
     "\tcase last.After(now) && false:\n\t\treturn every\n",
     Scope("41_a_schedule_keeps")),

    # D285. **A TICK DOES NOT RECORD ITS TIME** — a quiet source's time goes
    # stale, so a restart polls at once; the store never learns the cadence.
    ("D285: a tick does not record when it polled",
     "internal/kyuushin/kyuushin.go",
     "if err := p.store.Polled(ctx, j.Target.Ref(), p.opts.Now()); err != nil {",
     "if err := error(nil); err != nil && p.store.Polled(ctx, j.Target.Ref(), p.opts.Now()) == nil {",
     Scope("41_a_schedule_keeps")),

    # CONTRACTS 135. **THE BOOT CHECK GOES BACK TO KNOWING KATA ALONE** — the
    # binary's D42 check blind to every other connector's types, so a rule naming
    # a Fullstory type is refused in production while in-process tests pass.
    # Caught by step 14, which boots the REAL binary on acceptance.yaml.
    ("CONTRACTS 135: the binary's schema check knows kata's types alone",
     "cmd/sekizui/main.go",
     "return builtin.ByKind(doc, nil) }, log))",
     "return map[string]connector.Driver{\"kata\": builtin.ByKind(doc, nil)[\"kata\"]} }, log))",
     Scope("14_modeingest")),

    # D172. **A REFLEX TAKES A SHORTER PATH** — the one D18 was written
    # about: an internally produced command skips a stage an agent's passes
    # through. Here the credential posture goes unstamped for internal callers,
    # so a reflex's record is silently thinner than an agent's while every
    # verdict is unchanged. Caught by step 21's whole-record comparison.
    ("D172: a reflex's command skips a stage an agent's passes through",
     "internal/gateway/server.go",
     "\tstampPosture(base, s.resolver, cmd.GetTargetRef())\n",
     "\tif id.GetCaller().GetMethod() != sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL {\n"
     "\t\tstampPosture(base, s.resolver, cmd.GetTargetRef())\n\t}\n",
     Scope("21_a_polled_row_becomes_an_envelope")),

    # D284. **A POLL IS CHARGED ONE CALL AGAIN**, which is the state D284
    # found: a Fullstory events poll making twenty-one calls against a budget
    # that counted one. Every record still reads as a metered admission.
    ("D284: a poll is charged as one call whatever it costs",
     "internal/gateway/job.go",
     "\tmeterRef, merr := s.meters(ctx, subject, action, targetRef, u.budgetRef, cost)",
     # cost/cost, not a literal 1: with the literal, `cost` is unused and the
     # tree does not COMPILE — a build failure that looked like a catch until
     # it was run by hand.
     "\tmeterRef, merr := s.meters(ctx, subject, action, targetRef, u.budgetRef, cost/cost)",
     Scope("20_the_meter_is_the_connectors")),

    # D284. **AN ABSENT BUDGET MEANS UNLIMITED AGAIN** — the universal default
    # computed as zero, which the limiter reads as "no bucket". The exact shape
    # of the `:=` shadow step 20a caught while this was being written.
    ("D284: a target nobody sized is unmetered",
     "internal/meter/meter.go",
     "\t\t\t\trate, source = universal, ",
     "\t\t\t\trate, source = 0, ",
     Scope("20_the_meter_is_the_connectors")),

    # D284. **"NEVER" IS REPORTED AS "LATER"** — a poll costing more than its
    # bucket can hold refused as a rate limit, with a RetryAfter that cannot
    # come true, for ever.
    ("D284: a request that can never fit is told to retry",
     "internal/gateway/meter.go",
     "metered && int64(cost) > capacity {",
     "metered && false && int64(cost) > capacity {",
     Scope("20_the_meter_is_the_connectors")),

    # D284. **THE CEILING STOPS BOUNDING WHAT A TARGET ASKS FOR** — D108's
    # refusal gone, so a target's budget is whatever its config says and the
    # deployment's flag bounds only the defaults.
    ("D284: a target may budget past the deployment's ceiling",
     "internal/meter/meter.go",
     "\t\t\tif capped && rate > ceiling {\n\t\t\t\trefusals",
     "\t\t\tif false && capped && rate > ceiling {\n\t\t\t\trefusals",
     Scope("20_the_meter_is_the_connectors")),

    # D257. **THE BUDGET GOES BACK TO BEING ADVERTISED AND UNENFORCED**, which
    # is CONTRACTS 70's state for three phases: decoded from config, copied
    # into the catalog, checked by nobody. Passing zero reads as "uncapped",
    # so every job is admitted and nothing in the response or the record looks
    # wrong — the catalog goes on telling agents a limit exists.
    ("D257: a capability's max_bytes is advertised and enforced nowhere",
     "internal/gateway/job.go",
     "\tlimit, lerr := s.jobSize(cmd, dec.MaxBytes)",
     "\tlimit, lerr := s.jobSize(cmd, 0)",
     Scope("35_a_job_is_bounded_before_it_runs_and_the_c")),

    # D256. **BREAK-GLASS STOPS REACHING WORK ALREADY RUNNING.** The suspension
    # still lands, so `revoke_grant` still refuses the NEXT admission and every
    # test of that passes — what is lost is the half a job makes visible: an
    # operator sees a successful revocation while the work carries on under the
    # grant they just pulled. This is the exact state the verb was in before
    # criterion 17 was built, and nothing but an in-flight job can see it.
    ("D256: a suspended principal's running jobs are left running",
     "internal/gateway/grant_verb.go",
     "\t\tstopped = s.jobs.CancelFor(principal)",
     "\t\tstopped = nil",
     Scope("34_a_job_cannot_outlive_its_authorisation")),

    # D254. **THE OWNERSHIP CHECK IS THE WHOLE AUTHORISATION OF THIS VERB.**
    # `JobStatus` takes no grant — a job is its owner's own — so identity
    # equality with the principal on the job is not one control among several,
    # it is the only one. Removed, every caller reads every caller's jobs:
    # what they ran, against what, when, and whether it failed. Nothing else
    # in the path would notice, because there is nothing else in the path.
    #
    # ANCHORED WITH THE LINE BEFORE IT since D267 copied the same check into
    # JobResults: the bare `if st.Principal != asked {` matched twice, the run
    # refused the ambiguous anchor, and JobStatus's guard went unmutated.
    ("D254: any principal may read any other principal's job status",
     "internal/gateway/job.go",
     "\t\treturn unknown, nil\n\t}\n\tif st.Principal != asked {",
     "\t\treturn unknown, nil\n\t}\n\tif false && st.Principal != asked {",
     Scope("32_finished_failed_and_still_running_are_dis")),

    # D267. **THE SAME GUARD ON THE OTHER VERB, AND IT HAD NO MUTATION.**
    # JobResults streams a job's ENVELOPES — the data itself, not its status —
    # to the caller who asked, and ownership is again the whole of its
    # authorisation. Removed, any caller who learns a job id reads another
    # caller's results. It arrived as a copy of D254's check, which is exactly
    # how it was missed: the old anchor started matching twice.
    ("D267: any principal may stream any other principal's job results",
     "internal/gateway/job.go",
     "\t\treturn unknown\n\t}\n\tif st.Principal != asked {",
     "\t\treturn unknown\n\t}\n\tif false && st.Principal != asked {",
     Scope("31_a_caller_asks_for_a_job_and_receives_its_")),

    # D253. **THE METER IS CALLED AND ASKED ABOUT THE WRONG TARGET**, which is
    # the shape that hid the original defect rather than the obvious deletion.
    # The audit found exactly this once before, on `ceilings`: "leaving the
    # call in place but passing it an empty action and target — was caught by
    # NOTHING". A reviewer sees a metered verb; the budget it consults belongs
    # to a target nobody configured, so every read is free and `rate_per_hr`
    # goes back to meaning writes only.
    ("D253: the read plane meters against a target nobody configured",
     "internal/gateway/server.go",
     "\tmeterRef, merr := s.meters(ctx, subject, req.GetAction(), req.GetTargetRef(), req.GetTargetRef(), cost)",
     "\tmeterRef, merr := s.meters(ctx, subject, req.GetAction(), req.GetTargetRef(), \"unmetered:decoy\", cost)",
     Scope("68_every_ceiling_and_control_applies_to_read")),

    # D255. **A POLL THAT DIALS PRIVATELY IS INVISIBLE TO BREAK-GLASS.** The
    # work still runs and every response arm still passes, because the rows
    # come back exactly as before — what changes is that `revoke_credential`
    # evicts an empty set for this target, truthfully reports cancelling
    # nothing, and the poll keeps running on a credential an operator has just
    # declared compromised. On a timer. The conformance arm catches it too,
    # and this audit cannot see a unit test (CONTRACTS 107), so the acceptance
    # step is the half that has to hold here.
    ("D255: the reference driver's poll stops borrowing from the pool",
     "internal/connectors/kata/source.go",
     "\t} else if err := d.pool.Do(ctx, t, work); err != nil {",
     "\t} else if err := work(ctx, nil); err != nil {",
     Scope("33_cancelling_a_job_stops_the_work_not_just_", "34_a_job_cannot_outlive_its_authorisation", "35_a_job_is_bounded_before_it_runs_and_the_c")),

    ("D222: the thin Jira driver becomes unroutable",
     "internal/connectors/jira/jira.go",
     "func (d *Driver) Kind() string { return Kind }",
     "func (d *Driver) Kind() string { return \"\" }",
     Scope("03_a_none_class_mutating_action_refuses_to_r", "04_fullstory_sessions_are_polled_translated_", "05_a_scheduled_run_is_governed_by_the_same_p")),

    # D168. **THE AUTHORING TOOL MINTS A VENDOR CLAIM.** D51 exists to stop a
    # hand-written guess masquerading as a vendor guarantee, and a GENERATED
    # guess is the same thing with more confidence behind it — the schema would
    # then be drift-checked against a server that never asserted it, so a wrong
    # draft surfaces as a security incident rather than as "we guessed wrong".
    # Caught twice by step 28: structurally, and on what the draft emits.
    # RE-ANCHORED BY D287: the inference path now hands its origin to the one
    # renderer both paths share, so the guess-posing-as-vendor mutation is an
    # inferred draft passing `vendor` there.
    ("D168: the schema authoring tool mints vendor provenance",
     "internal/mcpspec/mcpspec.go",
     "\treturn fragment(tool, outputType, originLocal, schema, len(samples), warnings,",
     "\treturn fragment(tool, outputType, \"vendor\", schema, len(samples), warnings,",
     Scope("28_the_mcp_schema_authoring_tool_cannot_mint")),

    # D164. **THE LEDGER LOSES ITS EXPIRY.** The census still names an
    # unpopulated field, so the arm everybody thinks of keeps passing — what
    # goes is `Result.Stale`, which fails when a LEDGERED path starts being
    # populated. Without it the table only ever grows, and D53's init ledger is
    # the worked example: its entries said a subsystem was unimplemented, two of
    # them landed, and every boot went on reporting `implemented=5/12` while the
    # code sat in the same binary. Caught by step 24's third arm.
    ("D164: a stale census ledger entry is accepted forever",
     "internal/census/census.go",
     "\t\t\tif _, excused := ledger[p]; excused {\n\t\t\t\tres.Stale = append(res.Stale, p)\n\t\t\t}",
     "",
     Scope("24_the_decision_population_census_fails_on_a")),

    # D166. **THE DISCLOSURE ROW IS NEVER WRITTEN.** The enumeration trace goes
    # back to being a log line — and self-describe is DEBUG (D126), so a default
    # deployment holds no durable record that an agent enumerated the fleet,
    # while CONTRACTS 28 says that log silently loses records on rotation. This
    # is D79's original position, which D166 amended on tamper-evidence grounds.
    ("D166: Describe stops writing a disclosure record",
     "internal/gateway/server.go",
     "\tif _, rerr := s.recorder.Terminal(ctx, base); rerr != nil {",
     "\tif _, rerr := \"\", error(nil); rerr != nil {",
     Scope("22_describe_writes_a_chain_carried_record_na")),

    # D166. **THE ROW STOPS NAMING THE RULES THAT WITHHELD A CAPABILITY.** The
    # row still exists and still says somebody enumerated, so every count and
    # every other field is intact — what is lost is which anzen rule shaped the
    # advertisement, which is the half CONTRACTS 64 is about and the half a
    # reviewer needs to answer "why was this absent".
    ("D166: the disclosure row stops naming the guards that withheld capabilities",
     "internal/gateway/server.go",
     "\tfor _, w := range resp.GetWithheld() {",
     "\tfor _, w := range []*sekizuiv1.WithheldCapability(nil) {",
     Scope("22_describe_writes_a_chain_carried_record_na")),

    # D205. **THE RECONNAISSANCE REFUSAL IS DISARMED**, and this mutation is the
    # reason step 22 carries its second arm: written before that step existed it
    # SURVIVED the whole acceptance suite, because §4.9's rule that naming
    # another principal needs a may_speak_for grant had no acceptance coverage
    # at all. The package tests caught it and `make mutate` runs the acceptance
    # suite by design (D161), so the survivor was a true statement about the
    # phase's evidence rather than about the code.
    ("D205: any principal may enumerate any other principal's capabilities",
     "internal/catalog/catalog.go",
     "\tif target != subject && !c.identity.MaySpeakFor(subject, target) {",
     "\tif false && target != subject && !c.identity.MaySpeakFor(subject, target) {",
     Scope("22_describe_writes_a_chain_carried_record_na")),

    # D165/D230. **THE ESCALATION EXCEPTION, WHICH IS THE DANGEROUS HALF OF THE
    # REGISTRY.** Remove it and quarantine → revoke is answered as a repeat: the
    # operator is told a credential they have just declared compromised was
    # already handled, STATUS_OK, while the calls using it keep running. Caught
    # by step 21 on the audit row's cancellation count, because a confirmation
    # and an escalation both return OK and only the effect differs.
    ("D165: escalation is answered as a repeat, so quarantine then revoke does nothing",
     "internal/verb/verb.go",
     "\t\tif spec.Escalates && prior.Escalating {\n\t\t\treturn Response{}, false\n\t\t}\n",
     "",
     Scope("21_escalation_is_not_a_repeat_quarantine_the")),

    # D165/D158's OTHER HALF. **THE CONFIRMATION STOPS SAYING HOW LONG THE
    # EFFECT LASTS.** A bare "already suspended" implies a permanence D146 does
    # not give: the suspension ends at the next deploy, and an operator who reads
    # permanence into it never edits configuration, so the principal comes back
    # with nobody deciding that it should. Caught by step 20, which asserts the
    # registry's own `Lifetime` phrase appears in the sentence — and asserts the
    # phrase is non-empty first, because a `Contains` against "" passes against
    # everything (found by sabotage).
    ("D165: a repeat is confirmed without saying how long the effect lasts",
     "internal/verb/verb.go",
     "\tlifetime := \"\"\n\tif spec.Lifetime != \"\" {\n\t\tlifetime = \", and \" + spec.Lifetime\n\t}",
     "\tlifetime := \"\"",
     Scope("20_every_operator_verb_driven_twice_obeys_d1", "61_hot_reload_is_ruled_out_and_the_urgent_co", "64_a_principals_grants_are_suspended_at_runt")),

    # D228. **BOTH GUARDS AT ONCE, BECAUSE EACH MASKS THE OTHER** — see the loop
    # below for why an entry may carry a list. The floor in `gateway.refuse` and
    # the totality of `fault.Kind.Verdict()` over the deliberate kinds each keep
    # the record correct on their own, so this entry SURVIVED on its first run as
    # a single edit against either one. Removing both reproduces the original
    # defect exactly: three refusals recorded as VERDICT_ALLOW beside the
    # `matched_rule` that "authorised" them, and one with no verdict at all.
    #
    # Caught only by the acceptance REPORT refusing to be written, after every
    # step has PASSED — which is why `run_suite` sets the shared audit log and
    # names that refusal as a failure carrying no step label.
    ("D228: a refusal keeps whatever verdict an earlier stage had set (both guards)", [
        ("internal/gateway/server.go",
         "\tbase.Verdict = sekizuiv1.Verdict_VERDICT_DENY\n\tif v, ok := kind.Verdict(); ok {",
         "\tif v, ok := kind.Verdict(); ok {"),
        ("pkg/fault/fault.go",
         "\tif k.Deliberate() {\n\t\treturn sekizuiv1.Verdict_VERDICT_DENY, true\n\t}",
         "\tif k == KindDenied || k == KindUnauthenticated || k == KindResidency {\n\t\treturn sekizuiv1.Verdict_VERDICT_DENY, true\n\t}"),
    ],
     Scope.FULL),

    # D316. **A CONNECTOR FOLDER THE BINARY NEVER BUILDS.** The folder is all
    # there — driver, schemas, suites, README — and internal/builtin forgot it,
    # so it exists only in the tree. The import is blanked rather than deleted
    # so the mutant COMPILES; step 34a reports the folder as unregistered.
    ("D316: a connector folder is dropped from internal/builtin", [
        ("internal/builtin/builtin.go",
         '\t"github.com/fullstorydev/sekizui/internal/connectors/jira"\n',
         '\t_ "github.com/fullstorydev/sekizui/internal/connectors/jira"\n'),
        ("internal/builtin/builtin.go",
         "\t\tjira.New(jira.WithPool(pool)),\n",
         ""),
    ],
     Scope("34_every_in_tree_connector_is_one_complete_fo")),

    # D316. **THE GUARD STOPS ASKING A DRIFTER FOR ITS SUITE.** The real tree
    # still complies — kata runs RunDrift anyway — so only an arm that PLANTS a
    # Drifter skipping it can see this; step 34c is that arm.
    ("D316: the connector guard stops requiring RunDrift of a Drifter",
     "internal/connectorcheck/connectorcheck.go",
     '\t\t\tsuites = append(suites, "RunDrift")',
     "\t\t\t_ = ok",
     Scope("34_every_in_tree_connector_is_one_complete_fo")),

    # D298. **A REFINES RULE IS STAGED BY SHADOW AFTER ALL.** `mode:` on a rule
    # that never actuates would compute a refinement nobody receives; the rule is
    # staged by audience, so the field is refused, naming why.
    ("D298: a refines rule's `mode:` is accepted",
     "pkg/config/refine.go",
     '\tif r.Mode != "" {',
     '\tif r.Mode != "" && false {',
     Scope("14_a_connectors_reflexes_ship_embedded_and_are")),

    # D299. **THE LOGIN TEMPLATE IMPOSED BARE.** Without its prefixes it would
    # match nothing, or the wrong page, in every session.
    ("D299: a template imposed without its required params binds",
     "pkg/config/refine.go",
     "\tif len(missing) > 0 {",
     "\tif len(missing) > 0 && false {",
     Scope("15_the_login_template_refuses_to_be_imposed_bare")),

    # D300. **ONE PAIRING LEVEL, SAID BY NAME.** Strict decoding would still
    # refuse the nested pairing — as an unknown field, which tells the author
    # nothing; the step holds the message to the vocabulary's reason.
    ("D300: a pairing inside a pairing is refused only as an unknown field",
     "pkg/config/refine.go",
     "\t\t\tif _, ok := probe[nested]; ok {",
     "\t\t\tif _, ok := probe[nested]; ok && false {",
     Scope("16_the_refinement_vocabulary_is_closed")),

    # D300. **`prefix` MATCHES ANYTHING.** The shared operator a bus rule and a
    # login template both rely on, answering true for any non-empty field.
    ("D300: the shared prefix operator holds for any non-empty string",
     "internal/predicate/predicate.go",
     "\t\treturn strings.HasPrefix(got, want), nil",
     '\t\treturn got != "" || want == "", nil',
     Scope("16_the_refinement_vocabulary_is_closed")),

    # D292, D300. **A KIND'S FIELD READ UNPINNED.** `event_properties.fs-form-name`
    # resolves under a click; unpinned it cannot be confirmed for any row the rule
    # will see, and a schema change silently stops the rule matching (D42).
    ("D300: an unpinned kind field resolves",
     "internal/schemareg/refine.go",
     "\tif len(kinds) == 0 {",
     "\tif len(kinds) == 0 && false {",
     Scope("17_a_rules_paths_windows_limits_and_keys_are")),

    # D317. **NO TIME, AND NOBODY SAYS SO.** A rule sorts and pairs by time; an
    # input type naming none leaves replay unprovable and every within_s a guess.
    ("D317: a refines rule over an input with no time path is accepted",
     "internal/schemareg/refine.go",
     '\t\tadd("%v", err)\n\t}\n\n\t// PATHS',
     "\t\t_ = err\n\t}\n\n\t// PATHS",
     Scope("17_a_rules_paths_windows_limits_and_keys_are")),

    # D300. **A LIMIT OVER THE INPUT BOUND.** A list promising 500 items over a
    # 200-row result reads as a session-sized answer it can never be.
    ("D300: a refines rule's limit is not held to the input bound",
     "internal/schemareg/refine.go",
     "\t\tif b := inputBound(d, rule.Refines); limit > b {",
     "\t\tif b := inputBound(d, rule.Refines); limit > b && false {",
     Scope("17_a_rules_paths_windows_limits_and_keys_are")),

    # D63, D88. **A CARRIED FIELD THE SEIREN TYPE CANNOT HOLD.** Shaping would strip
    # it on the way out, and the rule would silently lose what it was written to
    # carry.
    ("D300: a carried field need not exist in the seiren schema",
     "internal/schemareg/refine.go",
     "\tif err := r.seirenSlot(rule.Into, rule.Key, shape, carried); err != nil {",
     "\tif err := r.seirenSlot(rule.Into, rule.Key, shape, carried); err != nil && false {",
     Scope("17_a_rules_paths_windows_limits_and_keys_are")),

    # D300. **TWO WRITERS OF ONE KEY.** Which one wins would be decided by config
    # order, silently.
    ("D300: two impositions may write one key for overlapping audiences",
     "internal/schemareg/refine.go",
     "\t\t\tcase a.Rule.Key == b.Rule.Key:",
     "\t\t\tcase a.Rule.Key == b.Rule.Key && false:",
     Scope("17_a_rules_paths_windows_limits_and_keys_are")),

    # D298, D300. **THE VENDOR'S ORDER TRUSTED.** Without the time sort a seiren
    # depends on the order rows arrived in, and replay proves nothing.
    ("D300: the refinement engine keeps the response's row order instead of sorting by time",
     "internal/refine/refine.go",
     "\t\t\treturn sorted[i].at.Before(sorted[j].at)",
     "\t\t\treturn sorted[i].pos < sorted[j].pos",
     Scope("23_seiren_is_deterministic")),

    # D300. **TIES BROKEN THE OTHER WAY.** Deterministic still, and wrong: a
    # tie follows the response's position, which is what a replay reproduces.
    ("D300: tied rows are ordered against their response position",
     "internal/refine/refine.go",
     "\t\treturn sorted[i].pos < sorted[j].pos",
     "\t\treturn sorted[i].pos > sorted[j].pos",
     Scope("23_seiren_is_deterministic")),

    # D42. **AN UNPARSEABLE TIME READ AS THE ZERO TIME.** The row sorts first and
    # silently corrupts every sequence it touches.
    ("D42: an unparseable event time is treated as the zero time rather than refused",
     "internal/refine/refine.go",
     "\t\tat, err := schemareg.ParseDateTime(str)\n\t\tif err != nil {",
     "\t\tat, err := schemareg.ParseDateTime(str)\n\t\tif err != nil && false {",
     Scope("23_seiren_is_deterministic")),

    # D298. **THE AUDIENCE IGNORED.** Staging by audience is the whole of the
    # staging mechanism for refines:; without it every caller of the target
    # receives what one principal was meant to try first.
    ("D298: a refinement reaches callers outside its audience",
     "internal/refine/refine.go",
     "\t\tif r.Target == target && r.Rule.Refines == typ && AudienceCovers(r.For, principal) {",
     "\t\tif r.Target == target && r.Rule.Refines == typ {",
     Scope("19_seiren_reaches_the_audience_it_is_imposed_on")),

    # D300. **A LAST SLICE CALLED THE SESSION.** A full Generate Context slice
    # reported complete, so "no login in these 200 events" reads as "no login".
    ("D300: a Generate Context read that filled its limit is not reported truncated",
     "internal/connectors/fullstory/context.go",
     "\treturn connector.Rows{Rows: rows, Truncated: returned >= limit}, nil",
     "\treturn connector.Rows{Rows: rows, Truncated: false}, nil",
     Scope("21_seiren_is_computed_over_the_whole_result_befor")),

    # D300. **A RULE RUNS OVER WHAT ITS CALLER MAY NOT SEE.** Without the
    # rule-level check the page rules run over rows the lens stripped, write
    # partial answers, and declare nothing unavailable — a partial view that
    # reads as complete.
    ("D300: a rule whose read path the caller's lens withholds runs anyway, undeclared",
     "internal/gateway/seiren.go",
     "\tcomputed, err := refine.Refine(rs, rows, truncated, withheld)",
     "\tcomputed, err := refine.Refine(rs, rows, truncated, func() refine.Withheld { _ = withheld; return nil }())",
     Scope("24_seiren_is_built_only_from_lensed_rows_and_a_w")),

    # D297, D269. **THE SEIREN BUILT BEFORE THE LENS, AND UNCHECKED.** Each
    # defence alone keeps a withheld value out (the ORDER, and the rule-level
    # check): building from unlensed rows with the check intact is equivalent,
    # because no rule reading a withheld path runs. With BOTH gone the value
    # rides out in the seiren — the disclosure step 24 exists for.
    ("D297: the seiren is built from unlensed rows with no withheld check",
     [("internal/gateway/server.go",
       "\tseiren, serr := s.seirenFor(req.GetTargetRef(), lensReq, lensed, rows.Truncated, refused)",
       "\tseiren, serr := s.seirenFor(req.GetTargetRef(), lensReq, rows.Rows, rows.Truncated, refused)"),
      ("internal/gateway/seiren.go",
       "\tcomputed, err := refine.Refine(rs, rows, truncated, withheld)",
       "\tcomputed, err := refine.Refine(rs, rows, truncated, func() refine.Withheld { _ = withheld; return nil }())")],
     Scope("24_seiren_is_built_only_from_lensed_rows_and_a_w")),

    # D300. **A RULE NOBODY CAN RECEIVE BOOTS.** An imposed lens blocking a
    # rule for its whole audience is static, so it is refused now — otherwise
    # every response carries an `unavailable` nobody can ever clear.
    ("D300: an imposition an imposed lens blocks for its whole audience boots",
     "internal/schemareg/refine.go",
     "\tproblems = append(problems, neverBuilds(out, doc)...)",
     "\tproblems = append(problems, neverBuilds(nil, doc)...)",
     Scope("22_a_rule_runs_when_its_own_inputs_survived_the")),

    # CONTRACTS 146. **A LIST CUT AT ITS LIMIT, SILENTLY.** Fifty errors read
    # as the session's errors when there were sixty.
    ("CONTRACTS 146: a list cut at its limit declares no truncated gap",
     "internal/refine/refine.go",
     "\t\tif len(matches) > rule.List.Limit {",
     "\t\tif len(matches) > rule.List.Limit && false {",
     Scope("22_a_rule_runs_when_its_own_inputs_survived_the")),

    # D298, D317. **THE ERRORS RULE LOSES ITS CAUSES.** Shrinking the cause
    # window to a tenth of a second drops the error-click that caused the test org's
    # console error (+153ms) and network error (+198ms) — the real session's
    # answer to "what did the user do just before it broke".
    ("D298: the errors rule's cause window no longer reaches a real cause",
     "internal/connectors/fullstory/reflexes.yaml",
     "    within_s: 5\n",
     "    within_s: 0.1\n",
     Scope("18_the_four_built_ins_turn_a_real_generate_conte")),

    # D302. **A SEIREN THAT ARRIVES UNDECLARED.** The catalog stops reading
    # the refinements the gateway serves, so Describe advertises nothing while
    # the seiren still arrives — the gap D302 exists to close.
    ("D302: Describe does not read the refinements the gateway serves",
     "internal/catalog/catalog.go",
     "\t\trefinements: cfg.Refinements,",
     "\t\trefinements: nil,",
     Scope("25_describe_reports_every_refinement_imposed_on")),

    # D303, D318. **THE HEADER PICKS THE ALGORITHM** — the confusion attack's precondition.
    ("D318: the token's header chooses the algorithm",
     'internal/signedsubject/signedsubject.go',
     '\tif header.Alg != key.Alg {',
     '\tif header.Alg != key.Alg && false {',
     Scope("27_a_token_that_is_not_a_valid_one_from_a_confi")),

    # D303. **REPLAY ACROSS SERVICES** — the in-perimeter adversary's first move.
    ('D303: a token minted for another service is accepted (audience unchecked)',
     'internal/signedsubject/signedsubject.go',
     '\tif !audienceHas(c["aud"], p.Audience) {',
     '\tif false && !audienceHas(c["aud"], p.Audience) {',
     Scope("27_a_token_that_is_not_a_valid_one_from_a_confi")),

    # D303. **REPLAY LATER** — a leaked token that never stops working.
    ('D303: an expired token is accepted',
     'internal/signedsubject/signedsubject.go',
     '\tif now.After(exp.Add(p.Leeway)) {',
     '\tif false && now.After(exp.Add(p.Leeway)) {',
     Scope("27_a_token_that_is_not_a_valid_one_from_a_confi")),

    # D303. **A MISMATCHED BINDING ACCEPTED** — a token stolen from one workload, presented by another.
    ('D303: a token bound to another certificate is accepted',
     'internal/signedsubject/signedsubject.go',
     '\t\tif want == "" || want != certThumbprint {',
     '\t\tif want == "" {',
     Scope("28_a_token_bound_to_another_certificate_refuses")),

    # D303. **UNBOUND BY DEFAULT** — the relaxation that was meant to be a visible act.
    ('D303: binding is not required by default',
     'internal/signedsubject/signedsubject.go',
     '\t} else if p.RequireBound {',
     '\t} else if false && p.RequireBound {',
     Scope("28_a_token_bound_to_another_certificate_refuses")),

    # D318. **THE ISSUER'S CALLERS UNENUMERATED** — an unbound issuer's tokens from anything inside.
    ("D318: any caller may present an issuer's tokens",
     'internal/identity/signed.go',
     '\tif !slices.Contains(is.Callers, caller.GetPrincipal()) {',
     '\tif false && !slices.Contains(is.Callers, caller.GetPrincipal()) {',
     Scope("27_a_token_that_is_not_a_valid_one_from_a_confi")),

    # D303. **A ROLE CLAIM TREATED AS AN AUTHORISATION** before anyone checked it exists.
    ('D303: a token naming an unknown role is not refused at identity',
     'internal/identity/signed.go',
     '\tif !hasRole {',
     '\tif !hasRole && false {',
     Scope("27_a_token_that_is_not_a_valid_one_from_a_confi")),

    # D303. **A FORGED CLAIM GOES UNNOTED** — the probe at the edge leaves no trace.
    ("D303: a token's excess grant claim is not noted",
     'internal/identity/signed.go',
     '\t\tif !coveredBy(allowed, g) {',
     '\t\tif false && !coveredBy(allowed, g) {',
     Scope("30_a_role_selects_sekizuis_grant_set_and_a_toke")),

    # D318. **THE ROLE IGNORED** — the individual has no grant, so the role is the only grant set.
    ('D318: a signed subject is evaluated by its name, not its role',
     'internal/policy/policy.go',
     '\tdec := e.evaluate(sub.GetRole(), req)',
     '\tdec := e.evaluate(sub.GetPrincipal(), req)',
     Scope("26_a_token_from_the_pinned_issuer_names_the_sub", "30_a_role_selects_sekizuis_grant_set_and_a_toke")),

    # D303. **A TOKEN CANNOT NARROW** — the upstream's restriction silently dropped.
    ("D303: a token's grant list does not narrow",
     'internal/policy/policy.go',
     '\tif dec.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW || len(sub.GetTokenGrants()) == 0 {',
     '\tif true || dec.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW || len(sub.GetTokenGrants()) == 0 {',
     Scope("30_a_role_selects_sekizuis_grant_set_and_a_toke")),

    # D303. **A TOKEN'S LENS IGNORED** — the restriction an upstream asked for, not applied.
    ("D303: a token's added lenses are not applied",
     'internal/shin/shin.go',
     '\tfor _, name := range req.Added {',
     '\tfor _, name := range req.Added[:0] {',
     Scope("30_a_role_selects_sekizuis_grant_set_and_a_toke")),

    # D303. **TIER TWO NEVER RUNS** — every token silently falls back to the caller acting as itself.
    ('D303: a presented subject token is ignored',
     'internal/identity/identity.go',
     '\tif token := firstMetadataValue(ctx, SubjectTokenHeader); token != "" {',
     '\tif token := firstMetadataValue(ctx, SubjectTokenHeader); token != "" && false {',
     Scope("26_a_token_from_the_pinned_issuer_names_the_sub")),

    # D29 item 4, D319. **A REFUSAL RECORDED WITH NO CLASS.** A command refused
    # on residency — about a us target — was recorded unclassified, so the
    # shipper sent it to every destination, EU included. P4 step 9 found it.
    ("D319: a record's residency class is not taken from the configured target",
     "internal/gateway/server.go",
     "\t\t\treturn t.Residency",
     "\t\t\treturn \"\"",
     Scope("09_eu_resident_decision_records_land_in_an_eu")),

    # D319. **A REFUSING DESTINATION GOES UNNAMED.** Records wait in the WAL and
    # nothing says why a SIEM is hours behind — `audit_unavailable` exists so an
    # operator, or an anzen rule, can act on it.
    ("D319: a refusing audit destination is not named as unavailable",
     "internal/auditwal/ship.go",
     "\t\t\t\ts.unavailable[d.name] = err.Error()",
     "\t\t\t\t_ = err",
     Scope("10_a_sink_that_cannot_accept_records_raises_audi", "45_decision_records_reach_every_configured_si")),

    # D319. **A CLASS WITH NOWHERE TO GO BOOTS.** The unroutable record is then
    # discovered at run time, in the WAL, by nobody.
    ("D319: a served residency class no destination accepts is not reported",
     "internal/auditwal/ship.go",
     "\t\t\tout = append(out, class)",
     "\t\t\t_ = class",
     Scope("09_eu_resident_decision_records_land_in_an_eu", "46_sinkresidencies_routes_rather_than_merely")),

    # D29, D136. **THE GATEWAY'S CEILING NEVER SPEAKS.** Resolve still refuses
    # the crossing as defence in depth — which is why a step must assert the
    # STAGE and not the outcome: an outcome-only check survives this.
    ("D136: the residency ceiling is not checked ahead of policy",
     "internal/gateway/server.go",
     "\tif ceilingRefused {",
     "\tif ceilingRefused && false {",
     Scope("07_a_cross_region_resolve_is_refused_and_the_", "08_the_mcp_target_refuses_a_cross_region_reso")),

    # D29, P4 step 7. **A READ REFUSED AS A CROSSING, RECORDED WITH NO STAGE.**
    # Query and the job gate write the ceiling's decision straight to the
    # recorder; the stage is stamped where the refusal is built. P4 step 7 found
    # it unstamped.
    ("P4 step 7: a ceiling refusal's record does not name the stage that refused",
     "internal/gateway/server.go",
     "\td.RefusedBy = by\n",
     "\t_ = by\n",
     Scope("07_a_cross_region_resolve_is_refused_and_the_")),

    # D288, D304. **EVERY TARGET DIALS NA1.** An eu1 org's key, and its data,
    # travel to the US data centre — the allowlist still passes, because both
    # hosts are on it. Only the far side can see this.
    ("D304: a Fullstory target dials NA1 whatever its base_url says",
     "internal/connectors/fullstory/fullstory.go",
     "\treturn raw, nil\n}",
     "\treturn \"https://api.fullstory.com\", nil\n}",
     Scope("06_one_agent_reads_two_fullstory_orgs_in_diff")),

    # D29. **AN eu1 ENVELOPE WITH NO CLASS.** A consumer filtering by residency
    # (StreamRequest.residency) cannot decline what does not say where it is from.
    ("D29: a published envelope does not carry its target's residency",
     "internal/translate/translate.go",
     "\t\tResidency:    t.Residency(),",
     "\t\tResidency:    \"\",",
     Scope("06_one_agent_reads_two_fullstory_orgs_in_diff")),

    # D321. **A WAL THAT SHRANK UNDER ITS CURSOR IS SKIPPED IN SILENCE.** The
    # seek past the end reads nothing, the destination goes quiet for good, and
    # the level says all is well — found that way, by stale acceptance cursors.
    ("D321: a WAL shorter than a destination's cursor is not refused",
     "internal/auditwal/ship.go",
     "\tif offset > info.Size() {",
     "\tif offset > info.Size() && false {",
     Scope("10_a_sink_that_cannot_accept_records_raises_audi")),

    # D322. **A RECORD THAT CONTINUES NO CHAIN SHIPS.** A WAL replaced and grown
    # past the cursor, or a record altered before it left, reaches every
    # destination as if it were the log.
    ("D322: the shipper does not check a record continues the chain",
     "internal/auditwal/ship.go",
     "\t\t\tmismatch := prev != nil && len(rec.GetPrevHash()) != 0 && !bytesEqual(rec.GetPrevHash(), prev)",
     "\t\t\tmismatch := prev != nil && len(rec.GetPrevHash()) != 0 && !bytesEqual(rec.GetPrevHash(), prev) && false",
     Scope("10_a_sink_that_cannot_accept_records_raises_audi")),

    # D52, D323. **THE UNION IS NEVER CONSULTED.** A native denial is one MCP
    # call away again — the leak P2 step 14b demonstrated, with every
    # declaration in place and read by nothing.
    ("D323: a declared MCP tool is not held to what it mirrors",
     "internal/policy/policy.go",
     "\tif m, declared := e.mirrors[req.TargetRef][req.Action]; declared {",
     "\tif m, declared := e.mirrors[req.TargetRef][req.Action]; declared && false {",
     Scope("12_a_capability_denied_on_the_native_driver_ca", "11_p1s_property_test_holds_with_fullstory_in")),

    # D323. **OPAQUE READ AS NONE.** The one declaration that exists for tools
    # nobody can bound admits them on their own grant.
    ("D323: an opaque tool is not held to the whole native surface",
     "internal/policy/policy.go",
     "\t\t\t\t\tm.opaque = true",
     "\t\t\t\t\t_ = m.opaque",
     Scope("11_p1s_property_test_holds_with_fullstory_in", "12_a_capability_denied_on_the_native_driver_ca")),

    # D323. **A COMPOSITE HELD TO ITS FIRST ACTION ONLY.** Every mirrored
    # action must be held; one that is not must refuse.
    ("D323: the union stops at a mirrored action's first linked target",
     "internal/policy/policy.go",
     "\t\tcase sekizuiv1.Verdict_VERDICT_DENY:\n\t\t\twhat := \"mirrors\"",
     "\t\tcase sekizuiv1.Verdict_VERDICT_UNSPECIFIED:\n\t\t\twhat := \"mirrors\"",
     Scope("11_p1s_property_test_holds_with_fullstory_in", "12_a_capability_denied_on_the_native_driver_ca")),

    # D323. **DESCRIBE DROPS THE RELATION.** Grant review reads two doors as
    # unrelated again — the visibility half of the union, gone silently.
    ("D323: Describe does not report an MCP tool's native relation",
     "internal/catalog/catalog.go",
     "\t\t\tNative:      c.native[spec.TargetRef][action],",
     "\t\t\tNative:      nil,",
     Scope("12_a_capability_denied_on_the_native_driver_ca")),

    # D52, D208. **A 429 DRAINS ONLY ITS OWN TARGET.** The other door on the
    # same org spends a quota the upstream has already refused.
    ("D52: a 429 does not drain the shared budget",
     "internal/limiter/local.go",
     "\tb := l.targets[l.budgetOf(r.TargetRef)]\n\tif b == nil {\n\t\treturn\n\t}\n\tb.refill(l.now())\n\tb.tokens = 0",
     "\tb := l.targets[l.budgetOf(r.TargetRef)]\n\tif b == nil {\n\t\treturn\n\t}\n\tb.refill(l.now())\n\t_ = b",
     Scope("13_the_native_driver_and_the_mcp_target_share")),

    # D324. **A SEGMENT START READ AS A RESTART WHERE NONE CAN HAPPEN.** The
    # binary persists its tail, so an unchained record mid-stream is a lost
    # tail or a replaced WAL — shipped anyway, it is D322's blind spot again.
    ("D324: a segment start is not a break where the chain tail is persisted",
     "internal/auditwal/ship.go",
     "\t\t\tsegmentStart := prev != nil && len(rec.GetPrevHash()) == 0 && s.continuous",
     "\t\t\tsegmentStart := prev != nil && len(rec.GetPrevHash()) == 0 && s.continuous && false",
     Scope("10_a_sink_that_cannot_accept_records_raises_audi")),

    # D324. **A RESET THAT VOUCHES FOR NOTHING.** Removing the cursor re-ships
    # to the same mid-file break and stops again: the refusal names a remedy
    # that does not work — found by spot-checking the real binary.
    ("D324: a fresh cursor does not vouch for the WAL as it stands",
     "internal/auditwal/ship.go",
     "\tif fresh {\n\t\tvouched = info.Size()\n\t}",
     "\tif fresh {\n\t\tvouched = 0\n\t}",
     Scope("10_a_sink_that_cannot_accept_records_raises_audi")),

    # D327, P5 step 10. **A PRESET'S RECORD POINTS AT A LINE NOBODY WROTE.**
    # Expansion shifts every capability after the preset, so without its origin
    # `matched_rule` names its place in the expanded list, and the preset
    # vanishes from the record.
    ("D327: matched_rule forgets a capability's written position and its preset",
     "internal/policy/policy.go",
     "	if c.Origin != nil {\n\t\ti = c.Origin.Index\n\t}\n\treturn fmt.Sprintf(\"%s#%s[%d]%s\", principal, list, i, c.Origin.RuleSuffix())",
     "\treturn fmt.Sprintf(\"%s#%s[%d]\", principal, list, i)",
     Scope("10_the_fullstory_connectors_presets_ship_as_a_")),

    # D327, P5 step 11. **A CONNECTOR RELEASE GROWS A PRESET AND NOBODY IS
    # TOLD.** Grants still follow the deployment's copy — the finding is what
    # makes taking the change a decision rather than an accident of a diff.
    ("D327: a preset behind its connector's suggestion is not reported",
     "internal/grantcheck/grantcheck.go",
     "\t\t\tadded, removed := diff(s.Actions, d.Actions)",
     "\t\t\tadded, removed := []string(nil), []string(nil); _ = d",
     Scope("11_a_vendor_preset_that_grew_is_a_finding_and_")),

    # D327, P5 step 11. **A READ REFUSED BY POLICY NAMES NO STAGE** — the defect
    # step 11 found: Enforce and the job gate stamped it, Query did not.
    ("D327: Query records a policy refusal with no stage",
     "internal/gateway/server.go",
     "\tif dec.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {\n\t\tbase.RefusedBy = sekizuiv1.RefusedBy_REFUSED_BY_POLICY\n\t\tdecisionID, rerr := s.recorder.Terminal(ctx, base)\n\t\tif rerr != nil {\n\t\t\treturn nil, toStatus(rerr)",
     "\tif dec.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {\n\t\tdecisionID, rerr := s.recorder.Terminal(ctx, base)\n\t\tif rerr != nil {\n\t\t\treturn nil, toStatus(rerr)",
     Scope("11_a_vendor_preset_that_grew_is_a_finding_and_")),

    # D327, P5 step 12. **A PRESET CLAIMS A VENDOR LEVEL IT EXCEEDS.** A
    # sysadmin granting `mirrors: Standard` believes they granted Standard; an
    # Architect action inside it is authority nobody chose.
    ("D327: a preset's mirrors claim is not held to the vendor's grading",
     "internal/grantcheck/grantcheck.go",
     "\tif slices.Index(levels, got) > ceiling {",
     "\tif false && slices.Index(levels, got) > ceiling {",
     Scope("12_a_presets_vendor_level_is_checked_against_t")),

    # D330, P5 step 4. **A REFLEX THE CEILING FORBIDS BOOTS AND DENIES FOREVER.**
    # Granted and enabled, it reads as automation and every firing is refused.
    ("D330: boot admits a reflex whose every firing the anzen ceiling refuses",
     "internal/gateway/server.go",
     "\t\t\tif dead := s.guards.ForbiddenReflexes(s.doc.Reflexes, s.configuredResidency); len(dead) > 0 {",
     "\t\t\tif dead := s.guards.ForbiddenReflexes(s.doc.Reflexes, s.configuredResidency); len(dead) > 0 && false {",
     Scope("04_a_fullstory_rule_granted_an_action_its_prin")),

    # D330, P5 step 4. **A SECOND ANSWER TO "WHAT DID THIS GRANT PERMIT".** A
    # literal lookup refuses a reflex a wildcard grant covers, telling the
    # operator a grant they wrote does not exist.
    ("D330: the reflex grant check matches literally, not by the enforcer's rule",
     "pkg/config/validate.go",
     "\t\tif ActionMatches(pattern, r.Action) {",
     "\t\tif pattern == r.Action {",
     Scope("04_a_fullstory_rule_granted_an_action_its_prin")),

    # D298, P5 step 1. **SHADOW ACTS.** The staging mechanism most automation
    # lacks becomes the automation: a rule under review files real tickets.
    ("D298: a shadow rule's command is executed, not dry-run",
     "internal/reflex/reflex.go",
     "\t\tDryRun: rule.Mode != \"enforce\",",
     "\t\tDryRun: false,",
     Scope("01_an_actuating_rules_shadow_run_over_a_record")),

    # D298, P5 step 2. **ENFORCE IS NOT WHAT SHADOW REVIEWED.** A path that
    # evaluates a rule differently once armed makes the reviewed prediction a
    # description of some other rule.
    ("D298: an enforcing rule skips its where predicate",
     "internal/reflex/reflex.go",
     "\tif len(rule.Where) > 0 {",
     "\tif len(rule.Where) > 0 && rule.Mode != \"enforce\" {",
     Scope("02_enforce_over_the_same_recording_fires_exact")),

    # D331, P5 step 5d. **AN UNBUILT ANZEN ACTION IS CARRIED OUT, NOT REFUSED.**
    # The fall-through that made `alert` a credential revocation (CONTRACTS 157).
    ("D331: the withdrawal path does not refuse an action it does not implement",
     "internal/gateway/server.go",
     "\tcase verb.QuarantineTarget, verb.RevokeCredential:\n\tdefault:",
     "\tcase verb.QuarantineTarget, verb.RevokeCredential:\n\tcase \"never\":",
     Scope("05_a_budget_trip_halts_the_reflex_and_the_ale")),

    # D332, P5 step 5b. **AN ALERT WITHDRAWS SOMETHING.** `alert` reaches the
    # withdrawal path instead of being recorded — refused now, by D331's
    # backstop, where it used to revoke.
    ("D332: an alert rule is not recorded as an alert",
     "internal/gateway/server.go",
     "\t\tcase \"alert\":\n\t\t\treturn s.anzenAlert(ctx, base, rule)",
     "\t\tcase \"alert-never\":\n\t\t\treturn s.anzenAlert(ctx, base, rule)",
     Scope("05_a_budget_trip_halts_the_reflex_and_the_ale")),

    # D332, P5 step 5c. **A DISABLED REFLEX KEEPS FIRING.** The response is
    # recorded and nothing stops: the halt a budget trip asked for is a claim.
    ("D332: the engine ignores a rule an anzen rule disabled",
     "internal/reflex/engine.go",
     "\tif e.isDisabled(rule.Name) {",
     "\tif false && e.isDisabled(rule.Name) {",
     Scope("05_a_budget_trip_halts_the_reflex_and_the_ale")),

    # D333, P5 step 6b. **THE WINDOW IS THE CLOCK THAT PROCESSED IT.** A burst
    # replayed or delivered in one batch collapses into one window, so shadow
    # over a replay stops predicting enforce (D298).
    ("D333: a debounce window is measured on processing time, not the event's",
     "internal/reflex/engine.go",
     "\tif t := env.GetTime(); t.IsValid() && !t.AsTime().IsZero() {\n\t\tat = t.AsTime()\n\t}",
     "\tif t := env.GetTime(); false && t.IsValid() {\n\t\tat = t.AsTime()\n\t}",
     Scope("06_a_rage_click_burst_files_one_ticket_per_deb")),

    # D333, P5 step 6c. **A LATE BURST FILES AGAIN.** One anchor per key, so an
    # old burst re-delivered after a newer one is a new burst.
    ("D333: debounce remembers only a key's latest window",
     "internal/reflex/engine.go",
     "\tanchors = append(anchors, at)",
     "\tanchors = []time.Time{at}",
     Scope("06_a_rage_click_burst_files_one_ticket_per_deb")),

    # D334, P5 step 7. **A SHARED BUDGET THAT IS NEVER SPENT.** Declared,
    # validated, named by rules, and a storm across them runs unbounded.
    ("D334: a rule's shared reflex budget is never spent",
     "internal/reflex/engine.go",
     "\tif limit, ok := e.shared[rule.Budget]; ok && rule.Budget != \"\" {",
     "\tif limit, ok := e.shared[rule.Budget]; false && ok && rule.Budget != \"\" {",
     Scope("07_two_rules_sharing_one_budget_exhaust_it_tog")),

    # D335, P5 step 8a. **A RULE'S FIRINGS RUN IN PARALLEL.** The property that
    # makes a per-rule max_concurrent unnecessary stops holding, and nothing
    # bounds one rule's burst but the principal cap.
    ("D335: a rule's events are handled in parallel",
     "internal/reflex/engine.go",
     "\t\t\t\te.handle(ctx, l.rule, env, publish)",
     "\t\t\t\tgo e.handle(ctx, l.rule, env, publish)",
     Scope("08_a_rules_firings_are_serialised_and_a_princi")),

    # D335, P5 step 8b. **THE PRINCIPAL CAP ADMITS EVERYTHING.** A reflex
    # principal's rules all fire at once, and reflex-burst-cap reads as a bound.
    ("D335: anzen's concurrency cap admits every firing",
     "internal/anzen/anzen.go",
     "func (g *Guards) acquire(principal string, r capRule) error {\n\tg.mu.Lock()",
     "func (g *Guards) acquire(principal string, r capRule) error {\n\tif principal != \"\" {\n\t\treturn nil\n\t}\n\tg.mu.Lock()",
     Scope("08_a_rules_firings_are_serialised_and_a_princi")),

    # D336, P5 step 9a. **THE STORM IS NEVER TALLIED.** The limiter names the
    # monopoliser on each refusal and nothing adds them up, so denial_storm has
    # a producer that produces nothing — CONTRACTS 65's shape again.
    ("D336: a rate refusal is not tallied for denial_storm",
     "internal/gateway/meter.go",
     "\t\t\tif s.denials != nil {\n\t\t\t\ts.denials.Record(budgetRef, subject, over)",
     "\t\t\tif s.denials != nil && false {\n\t\t\t\ts.denials.Record(budgetRef, subject, over)",
     Scope("09_denial_storm_is_raised_and_names_the_princi")),

    # D336, P5 step 9a. **THE VICTIMS ARE NAMED.** A rule acting on the level
    # throttles the agents caught in the storm instead of the one causing it.
    ("D336: denial_storm names the victim, not the monopoliser",
     "internal/denial/denial.go",
     "\t\t\tk := key{m, r.budget}",
     "\t\t\tk := key{r.victim, r.budget}",
     Scope("09_denial_storm_is_raised_and_names_the_princi")),

    # D340, CONTRACTS 158 (a v1 hotfix), P1 step 64. **A SUSPENSION WHOSE RECORD
    # SAYS NOTHING OF WHY.** The verb requires a reason for the record and
    # wrote it everywhere but the record — the state until the hotfix.
    ("D340: a grant suspension's reason is not written into its decision record",
     "internal/gateway/grant_verb.go",
     "\tbase.Reason = reason\n",
     "\t_ = reason\n",
     Scope("64_a_principals_grants_are_suspended_at_runtime")),

    # D340 (a v1 hotfix), P6 step 9. **A STORM NAMES THE AGENT AND NOTHING
    # SUSPENDS IT.** The rule doing revoke_grant falls through to D331's
    # backstop and is refused, and the monopoliser keeps draining the budget.
    ("D340: an anzen rule doing revoke_grant is not fired through the governed verb",
     "internal/gateway/server.go",
     "\t\tcase \"revoke_grant\":\n\t\t\treturn s.anzenRevokeGrant(ctx, base, rule)",
     "\t\tcase \"revoke_grant-never\":\n\t\t\treturn s.anzenRevokeGrant(ctx, base, rule)",
     Scope("09_an_anzen_rule_suspends_the_principal_a_deni")),

    # D344 (the security best-practices hotfix), P6 step 12. **A DURABLE WRITE
    # FOLLOWS A PLANTED LINK.** The fixed `.tmp` name, opened O_TRUNC, as it was
    # before a SAST scan: a link planted there has its target overwritten.
    ("D344: a durable write opens a predictable temp name that follows a planted symlink",
     "internal/atomicfile/atomicfile.go",
     "\tf, err := os.CreateTemp(dir, filepath.Base(path)+\".tmp-*\")\n",
     "\tf, err := os.OpenFile(path+\".tmp\", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)\n",
     Scope("12_the_security_best_practices_hotfix_holds_no")),

    # D344, P6 step 12. **THE CHECK AND THE READ ARE TWO WALKS AGAIN.** A rooted
    # read opened by name instead of through os.Root: a directory swapped for a
    # link out of the root mid-read escapes. Caught by a race; 5 of 5 by hand.
    ("D344: a file credential is re-walked by name instead of read through its root",
     "pkg/provider/file/file.go",
     "\tif root == \"\" {\n\t\treturn os.Open(path)\n",
     "\tif root == \"\" || true {\n\t\treturn os.Open(path)\n",
     Scope("12_the_security_best_practices_hotfix_holds_no")),

    # D344, P6 step 12. **VERIFICATION OFF AND EVERY VERSION ACCEPTED.**
    ("D344: the conformance suite's insecure client accepts TLS below 1.3",
     "pkg/connector/conformance/conformance.go",
     "InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}",
     "InsecureSkipVerify: true}",
     Scope("12_the_security_best_practices_hotfix_holds_no")),

    # D343, P6 step 12. **CI BUILDS WITH THE UNPATCHED FLOOR.** setup-go v5
    # ignores go.mod's toolchain line and installs go 1.25.0 exactly.
    ("D343: the CI workflow's setup-go ignores the toolchain line",
     ".github/workflows/verify.yml",
     "      - uses: actions/setup-go@v6\n",
     "      - uses: actions/setup-go@v5\n",
     Scope("12_the_security_best_practices_hotfix_holds_no")),
]


def run_suite(scope=None):
    """Returns (passed, failing_step_labels, unmatched_scope_steps).

    `scope` limits the run to its steps (D281); None or Scope.FULL runs the
    whole suite. A scope step that matched NO step is returned in
    `unmatched_scope_steps` — the caller refuses it like a missing anchor.

    **THE SHARED AUDIT LOG IS SET, AND IT POINTS AT A TEMPORARY DIRECTORY.**
    Without it every step writes to its own t.TempDir and the whole-log checks on
    the report's path never run — so a mutation against one of them would SURVIVE
    while `make acceptance` catches it immediately. That is the harness measuring
    less than the suite it is auditing, which is the one thing a mutation harness
    must not do.

    It must NOT be ./out/acceptance.jsonl. That file is the artefact a human
    reads, and 68 mutation runs would each overwrite it with the output of a
    deliberately broken tree — leaving, on any interrupted run, a report that
    looks like evidence and describes sabotage.
    """
    pattern = "TestP[0-9]+Acceptance"
    if scope is not None and not scope.full:
        pattern += "/^(" + "|".join(re.escape(step) for step in scope.steps) + ")"
    with tempfile.TemporaryDirectory(prefix="sekizui-mutate-") as out:
        # NO LIVE SWITCH REACHES A MUTANT: a deliberately broken tree must never hold a real key
        # or write to a real org, whatever the calling shell exported.
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("SEKIZUI_FULLSTORY_", "SEKIZUI_LIVE_", "SEKIZUI_FS_LIVE",
                                    "SEKIZUI_DEMO_LIVE", "SEKIZUI_CAPTURE_"))}
        env["SEKIZUI_ACCEPTANCE_OUT"] = os.path.join(out, "acceptance.jsonl")
        r = subprocess.run(
            [GO, "test", "-count=1", "-run", pattern, "-v", "./internal/acceptance/"],
            capture_output=True, text=True, env=env)
    failing = sorted(set(re.findall(r"--- FAIL: TestP\d+Acceptance/([^\s/]+)", r.stdout)))
    ran = set(re.findall(r"=== RUN   TestP\d+Acceptance/([^\s/]+)", r.stdout))
    unmatched = []
    if scope is not None and not scope.full:
        unmatched = [st for st in scope.steps if not any(name.startswith(st) for name in ran)]

    # THE REPORT'S OWN REFUSAL IS A FAILURE WITH NO STEP LABEL, because it
    # happens in TestMain after every step has passed — which is exactly the
    # case D228 was found in. Named so a survivor report cannot read as
    # "nothing noticed".
    if r.returncode != 0 and not failing and "REFUSING TO WRITE THE ACCEPTANCE REPORT" in (r.stdout + r.stderr):
        failing = ["<the acceptance report refused to be written>"]
    return r.returncode == 0, failing, unmatched


def check_clean():
    """Refuse if the tree still carries an applied mutation, or if any
    mutation's anchor no longer matches exactly once.

    **BECAUSE KILLING THIS SCRIPT LEAVES THE TREE MUTATED, SILENTLY.** Each
    mutation is applied, tested and restored in a `finally`, which covers a
    normal failure and an exception — and not a SIGKILL. Interrupting a run the
    hard way (a `pkill -9`, a laptop lid, a CI timeout) leaves one file changed,
    and the next `make ci` then fails somewhere with no relation to whatever
    anybody was working on: the leftover found this way was D177's, and it
    surfaced as `the record does not say which field was substituted` in an
    acceptance step nobody had touched.

    **DETECTS THE CONDITION RATHER THAN THE CAUSE**, which is why it is this and
    not a signal handler. A stale mutation from a SIGKILL, a botched manual
    revert, or a merge that resurrected one all look the same to a reader and
    all produce the same confusing failure. Checked in `verify`, because that is
    what everybody runs first.
    """
    dirty, stranded = [], []
    for entry in MUTATIONS:
        # ONE READING OF THE ENTRY SHAPE, shared with the audit loop below. This
        # unpacked the 4-tuple directly and broke the moment an entry carried a
        # list of edits (D228) — a leftover-detector that crashes is a
        # leftover-detector that is not running, and `verify` calls it first.
        label, edits, _ = parse_entry(entry)
        for path, before, after in edits:
            with open(path) as f:
                src = f.read()
            # BOTH CONDITIONS, or a mutation whose `after` merely resembles
            # ordinary code would cry wolf: the anchor must be GONE and the
            # replacement PRESENT for the file to be mutated.
            if before not in src and after in src:
                dirty.append((label, path))
            # **A STRANDED ANCHOR FAILS HERE, NOT TEN MINUTES INTO `make ci`.**
            # An edit to a file carrying mutation anchors could leave one
            # matching nothing — HANDOFF listed it as a known trap — and the
            # audit only noticed at the end of its run, reporting the mutation
            # SKIPPED (D317: the gold→seiren rename renamed a mutation's label
            # and not its anchor). The audit needs every anchor to match EXACTLY
            # once, so `verify` now says so first, naming the mutation.
            elif src.count(before) != 1:
                stranded.append((label, path, src.count(before)))

    if stranded:
        print("A MUTATION'S ANCHOR NO LONGER MATCHES EXACTLY ONCE, so that mutation "
              "would test nothing:\n")
        for label, path, n in stranded:
            print(f"  {path}: found {n} time(s)\n    {label}")
        print("\nRe-anchor it to the code that now carries the guarantee, apply it by "
              "hand (it must COMPILE, and its scoped step must FAIL), or delete it "
              "deliberately with the reason.")
    if not dirty:
        return 1 if stranded else 0

    print("THE TREE STILL CARRIES AN APPLIED MUTATION, so every test result is "
          "about sabotaged code:\n")
    for label, path in dirty:
        print(f"  {path}\n    {label}")
    print("\nThis is what an interrupted `make mutate` leaves behind — the restore "
          "runs in a `finally`, which a SIGKILL skips. Revert the file above and "
          "re-run. (`git diff` on it shows exactly one hunk.)")
    return 1


def main(full=False):
    """`full` ignores every Scope and re-runs the whole suite per mutation —
    `make mutate-full`, the unscoped audit (D281)."""
    survivors, killed, broken = [], [], []

    # **THE BASELINE, AND WITHOUT IT EVERY NUMBER BELOW IS MEANINGLESS.**
    # `run_suite` answers "did the acceptance suite fail", and a mutation is
    # called CAUGHT when it did. So a suite that was ALREADY failing reports
    # every mutation as caught — including a genuinely surviving one, and
    # including the recorded equivalent mutant, which is how this was found:
    # D122's `[EQUIVALENT]` entry came back CAUGHT "by" step 33, the README
    # drift guard, while a step count in a document was stale. The audit read
    # 45 caught / 0 survived on a tree where nothing had been proven at all.
    #
    # `make ci` cannot reach this state, because make stops at the failing
    # `verify` or `acceptance` target before `mutate` runs — which is exactly
    # why it went unnoticed: the hole is only reachable by running this script
    # directly, which is what anybody debugging one mutation does.
    ok, failing, _ = run_suite()
    if not ok:
        print("REFUSING TO RUN: the acceptance suite fails BEFORE any mutation is "
              "applied, so every mutation would be reported as caught.\n")
        for step in failing[:10]:
            print(f"  failing already: {step}")
        print("\nFix the suite, then run the audit. A mutation audit measures what the "
              "suite NOTICES, and a suite that is already red notices nothing.")
        return 1

    for entry in MUTATIONS:
        label, edits, scope = parse_entry(entry)
        # **A SCOPE IS REQUIRED (D281)**, so a new mutation cannot arrive
        # unscoped by accident — which would be harmless (it runs everything)
        # and is still refused, because "harmless and slower" is how the full
        # suite crept back into every entry last time.
        if scope is None:
            broken.append((label, "NO SCOPE — name the acceptance steps expected to catch it, "
                                  "or Scope.FULL if only the whole suite can (D281)"))
            continue
        if full:
            scope = Scope.FULL
        # **A MUTATION MAY EDIT MORE THAN ONE FILE, AND D228 IS WHY.**
        #
        # The model was one (file, before, after) per entry, which is the right
        # default: a single fault injection, and a guarantee that needs two edits
        # to break is usually a sign the entry is really two entries. D228 is the
        # exception that earned the generalisation. Its invariant — a refusal
        # never records as permission — is enforced twice on purpose, by a floor
        # in `gateway.refuse` and by `fault.Kind.Verdict()` being total over the
        # deliberate kinds. The two live in different packages, are edited for
        # different reasons, and **each one completely masks the other**: remove
        # either and the audit log is still correct, so neither single-point
        # mutation is observable and the entry SURVIVED on its first run.
        #
        # Splitting it into two survivors would report two gaps that do not
        # exist. Deleting it would leave the invariant unmeasured. So an entry
        # may carry a LIST of edits, its label says it removes both, and what is
        # being asserted is what the harness exists to assert: that the suite
        # notices this guarantee being broken.
        originals = {}
        anchor_failed = False
        for path, before, _ in edits:
            if path not in originals:
                with open(path) as f:
                    originals[path] = f.read()
            if originals[path].count(before) != 1:
                anchor_failed = (path, originals[path].count(before))
                break
        if anchor_failed:
            path, count = anchor_failed
            # **AN UNMATCHED ANCHOR IS A FAILURE, NOT A SKIP.** If a guard is
            # refactored away or renamed, its mutation silently stops running and
            # the report keeps saying the guarantee is covered — which is the
            # exact defect class this project keeps finding, arriving in the tool
            # built to find it. A mutation that cannot be applied is a guarantee
            # nobody is checking.
            # TWO DIFFERENT FAILURES, NAMED APART: a missing anchor means the
            # guard moved; a repeated one means it was COPIED, and the copy is
            # a guard with no mutation of its own (D267's JobResults was found
            # this way, under a message that said "not found").
            if count == 0:
                why = (f"ANCHOR NOT FOUND in {path} — the guard was renamed or removed; "
                       f"fix the mutation or delete it deliberately")
            else:
                why = (f"ANCHOR AMBIGUOUS ({count} matches) in {path} — the guarded text was "
                       f"copied; anchor each copy uniquely and give each its own mutation")
            broken.append((label, why))
            continue

        for path, before, after in edits:
            with open(path) as f:
                current = f.read()
            with open(path, "w") as f:
                f.write(current.replace(before, after))
        try:
            build = subprocess.run([GO, "build", "./..."], capture_output=True, text=True)
            if build.returncode != 0:
                broken.append((label, "mutation does not compile"))
                continue
            ok, failing, unmatched = run_suite(scope)
            if unmatched:
                # A SCOPE NAMING A STEP THAT DOES NOT EXIST is a mutation that
                # tested nothing — refused like a missing anchor, never read
                # as a survivor or a catch.
                broken.append((label, f"SCOPE MATCHES NO STEP: {', '.join(unmatched)} — the step "
                                      f"was renamed or removed; fix the scope"))
            elif ok:
                survivors.append(label)
            else:
                killed.append((label, failing))
        finally:
            for path, text in originals.items():
                with open(path, "w") as f:
                    f.write(text)

    print("=" * 72)
    for label, steps in killed:
        shown = ", ".join(s[:44] for s in steps[:3]) or "(suite failed, no step named)"
        print(f"CAUGHT   {label}\n           by: {shown}")
    for label, why in broken:
        print(f"SKIPPED  {label}\n           {why}")
    real = [s for s in survivors if "[EQUIVALENT]" not in s]
    for label in survivors:
        tag = "EQUIVALENT" if "[EQUIVALENT]" in label else "SURVIVED  "
        print(f"{tag} {label}")
    print("=" * 72)
    print(f"{len(killed)} caught, {len(real)} SURVIVED, "
          f"{len(survivors) - len(real)} equivalent, {len(broken)} skipped")

    # A REAL SURVIVOR OR AN UNAPPLIED MUTATION FAILS. An equivalent mutant is a
    # fact about the system, not a gap in the suite — but a mutation whose anchor
    # has vanished is a guarantee that stopped being checked without anyone
    # deciding so.
    return 1 if (real or broken) else 0


if __name__ == "__main__":
    if "--check-clean" in sys.argv:
        sys.exit(check_clean())
    sys.exit(main(full="--full" in sys.argv))
