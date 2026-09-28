package config

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Validate checks a Document for internal coherence.
//
// WHOLE-DOCUMENT, because the invariants are cross-cutting: a grant references a
// target, a reflex references a grant, a reflex predicate references a payload
// schema. Checking each piece as it is parsed cannot see those relationships.
//
// Collects every problem rather than returning the first, for the same reason
// spine.Validate does: an operator fixing configuration wants the whole list,
// not one error per restart.
func (d *Document) Validate() error {
	const op = "config.Document.Validate"

	var p problems

	targets := d.validateTargets(&p)
	d.validatePresets(&p)
	d.validateReflexBudgets(&p)
	grants := d.validateGrants(&p, targets)
	d.validateReflexes(&p, targets, grants)
	d.validateRefinements(&p, targets)
	d.validateIssuers(&p)
	d.validateAnzen(&p, grants)
	d.validateShin(&p, grants)
	d.validateSubscriptions(&p, targets)
	d.validateReflexConsumption(&p)
	d.validateSources(&p, targets, grants)
	if d.Jobs.ResultsTTLSec > MaxResultsTTLSec {
		p.addf("jobs.results_ttl_s is %d; the ceiling is %d (one day). Results held longer are "+
			"storage, and each held result is memory until it is collected (D268)",
			d.Jobs.ResultsTTLSec, MaxResultsTTLSec)
	}

	// THE OFFLINE HALF OF D50, which BLOCKS THE LOAD. Everything it checks is
	// answerable from this document alone; the live `tools/list` comparison gates
	// readiness per target and never start (§4.9a.7).
	d.validateMCP(&p, targets)

	if len(p) > 0 {
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%d problem(s):\n  - %s", len(p), strings.Join(p, "\n  - ")))
	}
	return nil
}

type problems []string

func (p *problems) addf(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

func (d *Document) validateTargets(p *problems) map[string]bool {
	targets := make(map[string]bool, len(d.Targets))
	d.validateBudgets(p)

	for i, t := range d.Targets {
		if t.Ref == "" {
			p.addf("targets[%d]: missing ref", i)
			continue
		}
		if t.Kind == "" {
			p.addf("target %q: missing kind", t.Ref)
		}
		if targets[t.Ref] {
			p.addf("target %q: declared twice", t.Ref)
		}
		targets[t.Ref] = true

		// §4.7: configuration carries credential REFERENCES, never material. A
		// value that is not a ref is either a mistake or a secret pasted into a
		// file that lives in version control; both must fail loudly.
		if t.CredentialRef != "" && !strings.Contains(t.CredentialRef, "://") {
			p.addf("target %q: credential %q is not a reference; configuration carries "+
				"references like env://NAME or gcp-sm://..., never credential material (§4.7)",
				t.Ref, t.CredentialRef)
		}
	}
	return targets
}

// grantIndex is what a principal may do: action -> set of target refs.
type grantIndex map[string]map[string]map[string]bool

// hasReactiveRule reports whether an enabled rule of that name declares an
// action. Mirrors what anzen.Guards retains, so a grant that validates at boot
// is a grant that can actually be fired.
func (d *Document) hasReactiveRule(name string) bool {
	for _, a := range d.Anzen {
		if a.Name == name && a.Enabled && a.Do != "" {
			return true
		}
	}
	return false
}

func (d *Document) validateGrants(p *problems, targets map[string]bool) grantIndex {
	granted := make(grantIndex, len(d.Grants))
	seen := make(map[string]bool, len(d.Grants))

	// Principals declared anywhere in the document, for the `principal:` refs a
	// grant verb uses. Built up front because grants are validated in order and
	// a verb may name a principal declared later in the file.
	seenPrincipal := make(map[string]bool, len(d.Grants))
	for _, g := range d.Grants {
		seenPrincipal[g.Principal] = true
	}

	// Target ref -> declared residency, for the `where: {target_residency: ...}`
	// check below. Built here rather than threaded through validateTargets
	// because it is the only validator that needs the VALUE rather than mere
	// existence.
	residencyOf := make(map[string]string, len(d.Targets))
	for _, t := range d.Targets {
		residencyOf[t.Ref] = t.Residency
	}

	for i, g := range d.Grants {
		if g.Principal == "" {
			p.addf("grants[%d]: missing principal", i)
			continue
		}
		// THE `anzen:` NAMESPACE IS RESERVED (D122).
		//
		// Anzen's authority comes from its CLOSED VOCABULARY, not from a grant —
		// that is the whole reason the class can be trusted with signals a reflex
		// cannot (§4.11). A grant naming an anzen principal would misstate where
		// its power comes from, and would let arbitrary capabilities be attached
		// to something an audit log reads as anzen.
		//
		// It also makes D121's recursion guard STRUCTURAL rather than a
		// convention: anzen ignores decisions whose subject sits in this
		// namespace, and nothing else can produce one.
		//
		// `reflex:` is deliberately NOT reserved. A reflex is a principal that
		// needs its own grant (D18); the asymmetry is exactly where the two draw
		// authority from.
		if strings.HasPrefix(g.Principal, "anzen:") {
			p.addf("principal %q is in the reserved `anzen:` namespace. Anzen's authority "+
				"comes from its closed vocabulary rather than from a grant (§4.11), so a grant "+
				"here would both misstate where its power comes from and let arbitrary "+
				"capabilities be attached to something an audit log reads as anzen",
				g.Principal)
			continue
		}

		if seen[g.Principal] {
			p.addf("principal %q: declared twice; merge the grants, because two blocks "+
				"means one of them is silently ignored", g.Principal)
		}
		seen[g.Principal] = true
		granted[g.Principal] = map[string]map[string]bool{}

		for _, c := range append(append([]CapabilitySpec(nil), g.Allow...), g.Escalate...) {
			if c.Preset != "" {
				p.addf("principal %q: preset %q was never expanded; a document is expanded by "+
					"its loader (Document.ExpandPresets), and one that skipped it grants nothing "+
					"it appears to (D327)", g.Principal, c.Preset)
				continue
			}
			if c.Action == "" {
				p.addf("principal %q: capability with no action", g.Principal)
				continue
			}
			// A grant naming a target that does not exist is dead config. Not
			// dangerous, but always a mistake, and finding it at boot beats
			// finding it when an agent is denied for reasons nobody can explain.
			//
			// AN `anzen:` REFERENCE IS A RULE, NOT A TARGET (D134). Firing a
			// pre-declared decision means the capability's subject IS the rule —
			// "may fire credential-compromise" rather than "may revoke this
			// target" — so it is checked against the rule names instead. Same
			// property, different namespace: a grant naming a rule nobody
			// declared is still dead config, and still fails at boot.
			switch {
			case c.TargetRef == "":
			case strings.HasPrefix(c.TargetRef, "principal:"):
				// A GRANT VERB NAMES A PRINCIPAL, NOT A TARGET (D146).
				// `sekizui.revoke_grant` suspends somebody's grants, so its
				// capability reads "may revoke agent:crawler" rather than "may
				// revoke anybody" — the same narrowing verb.FireAnzen gets by
				// naming a rule. Checked against the declared principals for the
				// same reason a target ref is checked against targets: naming
				// one nobody declared is dead config, and finding it at boot
				// beats finding it when the lever does not work.
				name := strings.TrimPrefix(c.TargetRef, "principal:")
				if !seenPrincipal[name] && !d.declaresPrincipal(name) {
					p.addf("principal %q: capability %q references unknown principal %q. "+
						"A grant verb suspends a principal that configuration declares",
						g.Principal, c.Action, name)
				}
			case strings.HasPrefix(c.TargetRef, "anzen:"):
				name := strings.TrimPrefix(c.TargetRef, "anzen:")
				if !d.hasReactiveRule(name) {
					p.addf("principal %q: capability %q references unknown anzen rule %q. "+
						"Only an ENABLED rule with a `do` can be fired", g.Principal, c.Action, name)
				}
			case !targets[c.TargetRef]:
				p.addf("principal %q: capability %q references unknown target %q",
					g.Principal, c.Action, c.TargetRef)
			}

			d.validateResidencyConstraint(p, g.Principal, c, residencyOf)
			if granted[g.Principal][c.Action] == nil {
				granted[g.Principal][c.Action] = map[string]bool{}
			}
			granted[g.Principal][c.Action][c.TargetRef] = true
		}

		// §4.4.1: may_speak_for MUST BE ENUMERATED, NOT WILDCARDED. "agent:*"
		// recreates the confused-deputy problem the delegation model exists to
		// solve, so it is rejected rather than warned about.
		for _, sf := range g.MaySpeakFor {
			if strings.Contains(sf, "*") {
				p.addf("principal %q: may_speak_for %q is wildcarded; it must be enumerated, "+
					"or anything reaching Sekizui as this principal could impersonate any agent (§4.4.1)",
					g.Principal, sf)
			}
		}
	}
	return granted
}

// declaresPrincipal reports whether any reflex or grant names this principal.
//
// REFLEXES COUNT. A reflex is a principal that needs its own grant (D18), and a
// misbehaving one downstream of a model is among the likeliest things an
// operator suspends — §4.11.7's whole concern. Checking only grants would refuse
// a legitimate capability at boot.
func (d *Document) declaresPrincipal(name string) bool {
	for _, r := range d.Reflexes {
		if r.Principal == name {
			return true
		}
	}
	return false
}

// validateResidencyConstraint refuses a `where: {target_residency: ...}` that
// can never match the target it is written against (D136).
//
// STATICALLY DECIDABLE, SO IT IS DECIDED AT BOOT. A capability names its target
// by exact ref, and a target declares exactly one residency, so whether the
// constraint can ever be satisfied is knowable from the document alone —
// nothing about the request changes the answer. Leaving it to runtime would
// produce a grant that silently denies every command forever, which is the
// hardest kind of config bug to find: everything a reviewer would inspect is
// present and correct.
//
// This is the SAME rule as a capability naming an unknown target, applied one
// level down. Both are dead config; both fail here rather than confusing an
// operator later.
//
// THE ABSENT CASE IS NOT AN ERROR and must not become one. A capability with no
// residency constraint is legitimate — in a single-class deployment it is the
// only sensible form, and in a multi-class one it means "this principal does not
// cross the border", which is a posture rather than a mistake. Whether absence
// denies is a DEPLOYMENT question that this document cannot see; the grant
// engine answers it, and cmd/sekizui reports it at boot.
func (d *Document) validateResidencyConstraint(p *problems, principal string,
	c CapabilitySpec, residencyOf map[string]string) {

	want, declared := c.Where[TargetResidencyFacet]
	if !declared {
		return
	}

	// Neither an anzen RULE (D134) nor a PRINCIPAL (D146) is a target, and
	// neither has a residency. Both are fired or suspended rather than resolved,
	// so a residency constraint on one can never mean anything — and a
	// constraint that can never mean anything is the defect class, not a nuance.
	for prefix, what := range map[string]string{
		"anzen:":     "an anzen RULE reference",
		"principal:": "a PRINCIPAL reference",
	} {
		if strings.HasPrefix(c.TargetRef, prefix) {
			p.addf("principal %q: capability %q constrains %s on %s %q, which is not "+
				"resolved and has no residency to constrain",
				principal, c.Action, TargetResidencyFacet, what, c.TargetRef)
			return
		}
	}

	class, known := residencyOf[c.TargetRef]
	if !known {
		// Already reported as an unknown target; one problem per mistake.
		return
	}
	if class == "" {
		p.addf("principal %q: capability %q constrains %s, but target %q declares no "+
			"residency — the constraint can never match. Declare a residency on the "+
			"target, or drop the constraint",
			principal, c.Action, TargetResidencyFacet, c.TargetRef)
		return
	}
	if !ConstraintSatisfied(want, class) {
		p.addf("principal %q: capability %q permits %s %v, but target %q is %q-resident "+
			"— this capability can never fire",
			principal, c.Action, TargetResidencyFacet, want, c.TargetRef, class)
	}
}

// validateAnzenResidency refuses a guard scoped to a class no target declares
// (D137).
//
// DEAD CONFIG THAT READS AS PROTECTION is the worst thing a defensive rule can
// be. `target_residency: [ue]` for `eu` compiles, loads, and guards nothing,
// while the file states plainly that destructive actions are forbidden in the
// EU — and the failure is invisible until somebody deletes something. Same rule
// as a capability naming an unknown target, applied to the other axis.
//
// CHECKED AGAINST THE DOCUMENT, NOT THE DEPLOYMENT. Whether the running instance
// SERVES the class is a second question this document cannot answer — the
// ceiling is a flag — and cmd/sekizui asks it at wiring. Here the weaker,
// always-available question catches the typo.
func (d *Document) validateAnzenResidency(p *problems, label string, a AnzenSpec) {
	if len(a.TargetResidency) == 0 {
		return
	}

	declared := map[string]bool{}
	for _, t := range d.Targets {
		if t.Residency != "" {
			declared[t.Residency] = true
		}
	}

	for _, class := range a.TargetResidency {
		if strings.TrimSpace(class) == "" {
			p.addf("%s: has an empty target_residency entry", label)
			continue
		}
		if !declared[class] {
			p.addf("%s: is scoped to target_residency %q, which no target declares. "+
				"A guard that matches nothing reads as protection and provides none",
				label, class)
		}
	}
}

// validateReflexes enforces the rules P3 and P5 both require to hold AT BOOT.
//
// REFLEX EXECUTION IS P5; REFLEX VALIDATION IS P0. The split is deliberate:
// matching, firing, debounce, and budgets all need the bus, which arrives in P3.
// But three exit criteria in later phases are phrased as boot-time refusals —
// P3 exit 5 (a cyclic subject config is rejected at boot), P5 exit 3 (a cyclic
// rule is rejected at boot, "not detected at runtime"), and P5 exit 4 (a rule
// granted an action its principal lacks is rejected at boot) — and every one of
// those is pure configuration analysis that needs nothing which does not exist.
//
// Building it now means the rules are enforced from the first commit that can
// carry a reflex, rather than arriving with the engine and retroactively
// invalidating whatever people wrote in the meantime.
func (d *Document) validateReflexes(p *problems, targets map[string]bool, granted grantIndex) {
	stages := d.stageOrder()
	seen := make(map[string]bool, len(d.Reflexes))

	for i, r := range d.Reflexes {
		if r.Name == "" {
			p.addf("reflexes[%d]: missing name", i)
			continue
		}
		label := fmt.Sprintf("reflex %q", r.Name)

		if seen[r.Name] {
			p.addf("%s: declared twice", label)
		}
		seen[r.Name] = true

		// D18: A REFLEX IS A PRINCIPAL, NOT A BYPASS. It needs its own grant and
		// its command traverses the identical enforcement path. A reflex with no
		// principal would be exactly the bypass D18 exists to forbid.
		// A PROJECTION ACTS AS NOBODY (D269): its whole shape is checked in
		// validateProjection, and none of what follows applies to it.
		if r.Projects {
			d.validateProjection(p, label, r)
			continue
		}

		if r.Principal == "" {
			p.addf("%s: missing principal; a reflex is a principal, not a bypass (D18)", label)
		} else if _, ok := granted[r.Principal]; !ok {
			p.addf("%s: principal %q has no grant; a reflex needs its own grant like any "+
				"other principal (D18)", label, r.Principal)
		}

		d.refuseUnenforcedReflexFields(p, label, r)

		switch r.Mode {
		case "", "shadow", "enforce":
			// Empty means shadow. §4.11.4 item 3: every reflex should run
			// shadow first, so the safe value is the default.
		default:
			p.addf("%s: mode %q is neither shadow nor enforce", label, r.Mode)
		}

		if r.Consumes == "" {
			p.addf("%s: missing consumes", label)
		} else if d.consumesLLMStage(r.Consumes) && !r.AcknowledgesLLMInput {
			// D64. Not a safety mechanism — setting the flag changes nothing.
			// It exists because NOTHING otherwise distinguishes a reflex fed by
			// a vendor webhook from one fed by a model's output, and the second
			// can be steered by a prompt injection into pulling whatever trigger
			// this rule's grant permits.
			//
			// The blast radius is the grant, and the grant should be written
			// knowing a model can fire it. Refusing the load is how that gets
			// said out loud rather than assumed.
			p.addf("%s: consumes %q, which carries agent output, without "+
				"acknowledges_llm_input. A prompt injection reaching that agent can trigger "+
				"this rule, so its grant is the blast radius — set the flag to confirm the "+
				"grant was written with that in mind, and consider an anzen rule watching it (D64)",
				label, r.Consumes)
		}

		// D31: ONE RULE, ONE ACTION. Multiple actions are multiple rules —
		// avoiding partial-failure semantics inside one rule, where there is no
		// good answer for what the rule's outcome was.
		hasAction, hasPublish := r.Action != "", r.PublishTo != ""
		switch {
		case hasAction && hasPublish:
			p.addf("%s: has both an action and publish_to; a rule does exactly one thing (D31)", label)
		case !hasAction && !hasPublish:
			p.addf("%s: has neither an action nor publish_to; it can never do anything", label)
		}

		if hasAction {
			d.validateReflexAction(p, label, r, targets, granted)
		}
		if hasPublish {
			validateStageMonotonicity(p, label, r, stages, d.stageEdges(stages))
		}

		// D42's "expects_type has a registered schema" is schemareg's check
		// since D279: most types are now a CONNECTOR's, which this function —
		// run without drivers — cannot see. The boot runs both.
	}
}

// validateReflexAction is §4.11.4b and P5 exit criterion 4.
func (d *Document) validateReflexAction(p *problems, label string, r ReflexSpec,
	targets map[string]bool, granted grantIndex) {

	if r.TargetRef == "" {
		p.addf("%s: action %q with no target", label, r.Action)
		return
	}
	if !targets[r.TargetRef] {
		p.addf("%s: references unknown target %q", label, r.TargetRef)
		return
	}
	if r.Principal == "" {
		return // already reported
	}

	// THE CHECK P5 EXIT 4 NAMES. A reflex whose principal lacks the action it
	// performs would fire, be denied by the enforcer, and produce a stream of
	// denials nobody expected — the rule looks enabled and does nothing. Caught
	// at boot, it is a config error with a name attached.
	//
	// **BY THE ENFORCER'S RULE, NOT A LITERAL LOOKUP (D330).** This read
	// `granted[principal][action]`, so a reflex covered by `fullstory.*` was
	// refused as "not granted" while the enforcer would have allowed every
	// firing — safe, and a false statement to the operator reading it.
	actionGranted, onTarget := false, false
	for pattern, targets := range granted[r.Principal] {
		if ActionMatches(pattern, r.Action) {
			actionGranted = true
			onTarget = onTarget || targets[r.TargetRef]
		}
	}
	switch {
	case !actionGranted:
		p.addf("%s: principal %q is not granted action %q; the rule would fire and be "+
			"denied on every event (§4.11.4b)", label, r.Principal, r.Action)
	case !onTarget:
		p.addf("%s: principal %q is granted %q but not on target %q",
			label, r.Principal, r.Action, r.TargetRef)
	}
}

// ActionMatches is THE answer to "does a granted action pattern cover this
// action": exact, or a trailing-star prefix — "mcp.github.*", "*".
//
// PREFIX ONLY, deliberately. A general glob invites "*.delete_*", which reads as
// narrowing and is easy to get subtly wrong in the permissive direction. The
// grant engine, the catalog, grantcheck and this package's reflex check all ask
// it here (policy.ActionMatches delegates), so there is one answer (D195, D330).
func ActionMatches(pattern, action string) bool {
	if pattern == action {
		return true
	}
	prefix, ok := strings.CutSuffix(pattern, "*")
	return ok && strings.HasPrefix(action, prefix)
}

// validateStageMonotonicity is D21/D43 and P3 exit criterion 5.
//
// PREVENTION BY TOPOLOGY, NOT DETECTION BY DEPTH (§4.11.6). Bus→bus reflexes
// make cycles the default hazard rather than an edge case, so the runtime depth
// cap is no longer sufficient as the primary guarantee. Requiring every reflex
// to publish to a strictly LATER stage than it consumes makes a cycle impossible
// by construction — there is no ordering of stages in which a loop can close.
// stageEdge is one bus->bus rule as an edge between stage indices.
type stageEdge struct {
	rule     string
	from, to int
}

// stageEdges lists every publishing rule whose stages resolve, for naming the
// rest of a cycle a backward edge would close (P3 step 10).
func (d *Document) stageEdges(stages map[string]int) []stageEdge {
	var out []stageEdge
	for _, r := range d.Reflexes {
		if r.PublishTo == "" {
			continue
		}
		from, ok1 := stageOf(r.Consumes, stages)
		to, ok2 := stageOf(r.PublishTo, stages)
		if ok1 && ok2 {
			out = append(out, stageEdge{rule: r.Name, from: from, to: to})
		}
	}
	return out
}

// closingPath finds rules leading FROM stage `start` TO stage `goal` — the
// part of a loop the backward edge goal->start would close. Breadth-first, so
// the path named is the shortest, which is the one an operator reads first.
func closingPath(edges []stageEdge, start, goal int, stages map[string]int) string {
	type hop struct {
		at   int
		path []string
	}
	queue, seen := []hop{{at: start}}, map[int]bool{start: true}
	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		for _, e := range edges {
			if e.from != h.at || e.to <= e.from || seen[e.to] {
				continue
			}
			path := append(append([]string(nil), h.path...),
				fmt.Sprintf("%s (%s -> %s)", e.rule, stageFor(e.from, stages), stageFor(e.to, stages)))
			if e.to == goal {
				return strings.Join(path, ", then ")
			}
			seen[e.to] = true
			queue = append(queue, hop{at: e.to, path: path})
		}
	}
	return ""
}

func validateStageMonotonicity(p *problems, label string, r ReflexSpec, stages map[string]int,
	edges []stageEdge) {
	if len(stages) == 0 {
		p.addf("%s: publishes to %q but no stages are configured; monotonicity cannot be "+
			"checked, and an unchecked bus→bus reflex can form a cycle (D43)", label, r.PublishTo)
		return
	}

	from, okFrom := stageOf(r.Consumes, stages)
	to, okTo := stageOf(r.PublishTo, stages)

	if !okFrom {
		p.addf("%s: consumes %q names no configured stage %v", label, r.Consumes, stageNames(stages))
		return
	}
	if !okTo {
		p.addf("%s: publish_to %q names no configured stage %v", label, r.PublishTo, stageNames(stages))
		return
	}

	if to <= from {
		rel := "the same stage as"
		if to < from {
			rel = "an earlier stage than"
		}
		// NAME THE LOOP, NOT JUST THE EDGE (P3 step 10). A backward edge is
		// refused on its own; when other rules already lead from where it lands
		// back to where it starts, those rules are the rest of a real cycle,
		// and naming them is what tells the operator WHICH rule is the mistake.
		loop := ""
		if path := closingPath(edges, to, from, stages); path != "" {
			loop = fmt.Sprintf(" It would close a cycle: %s, then this rule back to %q.",
				path, stageFor(to, stages))
		}
		p.addf("%s: publishes to %s it consumes from (%q -> %q); a reflex may only publish "+
			"to a strictly later stage, which is what makes cycles impossible by "+
			"construction rather than merely detectable (D21).%s",
			label, rel, stageFor(from, stages), stageFor(to, stages), loop)
	}
}

// stageOrder maps stage name -> position.
func (d *Document) stageOrder() map[string]int {
	out := make(map[string]int, len(d.Stages))
	for i, s := range d.Stages {
		out[s] = i
	}
	return out
}

// stageOf extracts the stage from a subject pattern.
//
// Subjects look like "sekizui.raw.fullstory.rage_click" or "enriched.*", so the
// stage is whichever dot-separated token is a configured stage name. Matching by
// token rather than by substring matters: a source called "rawlogs" must not be
// read as the "raw" stage.
func stageOf(subject string, stages map[string]int) (int, bool) {
	for _, tok := range strings.Split(subject, ".") {
		if i, ok := stages[tok]; ok {
			return i, true
		}
	}
	return 0, false
}

func stageFor(idx int, stages map[string]int) string {
	for name, i := range stages {
		if i == idx {
			return name
		}
	}
	return fmt.Sprintf("stage(%d)", idx)
}

func stageNames(stages map[string]int) []string {
	out := make([]string, len(stages))
	for name, i := range stages {
		out[i] = name
	}
	return out
}

// anzenSignals are the internal conditions an anzen rule may watch (D65).
//
// A CLOSED SET. These are Sekizui's own governance signals, not bus subjects —
// an anzen rule that could consume business events would be a reflex wearing a
// different name, and would lose the property that makes the class trustworthy.
//
//nolint:gochecknoglobals // immutable vocabulary, fixed at compile time
var anzenSignals = map[string]string{
	"budget_exceeded":   "a reflex exhausted its firing budget (§4.11.4 item 4)",
	"spec_drift":        "an MCP target's live surface diverged from its vetted spec (D48)",
	"tenant_mismatch":   "an egress assertion failed (§6 mechanism 3)",
	"denial_storm":      "a principal is being denied repeatedly, suggesting a misconfigured or compromised caller",
	"audit_unavailable": "the audit sink cannot accept records (§5.2.2's one unacceptable failure)",

	// D109. Content-addressing PoolKey creates a NEW entry on rotation and does
	// not remove the old one, which still holds the superseded credential — and
	// for a session-oriented target, a live authorised session. Rather than
	// reasoning about whether eviction is correct, the pool counts entries whose
	// credential is no longer current and publishes the number. Zero is expected.
	"credential_stale": "a pooled client is still holding a superseded credential (D99's gap, made visible)",

	// D203, D204. A target forcing re-mints is either holding a broken
	// credential or trying to make us churn against the secret manager, and
	// NOTHING ELSE WOULD TELL A HUMAN EITHER WAY: a 401 is deliberate, so D141
	// correctly counts it as the target being alive and the breaker never opens.
	// The amplification is invisible without this.
	//
	// A LEVEL, not an event — see internal/churn for why that distinction is the
	// difference between a signal that works and one that either latches forever
	// or fires on the first legitimate expiry.
	"credential_churn": "a target is forcing repeated credential re-establishments (D203's amplification, made visible)",

	// D280: the job runner's three reports, published as levels by the source
	// watcher. THE FIRST TWO ARE THE CONNECTOR'S FAULT: it broke the Source
	// contract (D243), or claimed progress it did not make until the melt
	// guard stopped it.
	"source_nonconforming": "a source broke the Source contract — a duplicate id, a page over the limit, a payload that contradicts its own schema (D243)",
	"source_stopped":       "the melt guard stopped polling a source that returned rows and never advanced its cursor (D243)",
	// THE THIRD IS NOT. A source that emitted a kind or field its connector's
	// schema does not declare is behaving; nothing undeclared was published,
	// and the remedy is the connector owner's. See anzenSignalActions.
	"source_undeclared": "a source emitted a kind or field its connector's schema does not declare — withheld or stripped, never published (D277, D279)",

	// D282: a connector whose schemas are not sound was quarantined at boot.
	// The quarantine IS the protective action, already taken; what is left is
	// telling a human, so it is alert-only below.
	"connector_quarantined": "a connector's schemas are not sound, so it was quarantined at boot and its targets are refused (D282)",

	// D289: an MCP result ADDED fields its tool's output_schema does not
	// declare. A type break or a missing required field is REFUSED instead; an
	// addition is stripped by the data_schema anyway, so what is left is telling
	// a human the vendor changed the tool — alert-only below.
	"tool_nonconforming": "an MCP tool returned fields its vetted output_schema does not declare — stripped, and the vendor has changed the tool since it was vetted (D289)",
}

// anzenSignalActions narrows what a rule watching a signal may do (D280).
// A signal absent here takes any action in anzenActions.
//
// **`source_undeclared` MAY ONLY ALERT, AND THIS IS WHERE THAT IS STRUCTURAL.**
// A Fullstory user adding a custom event raises it; an operator wiring it to
// `revoke_grant` or `quarantine_target` would stop polling a healthy source the
// first time anyone adds an event — the compliance layer turned against the
// data it exists to deliver. Refused at boot, so no configuration can do it.
//
//nolint:gochecknoglobals // immutable vocabulary, fixed at compile time
var anzenSignalActions = map[string][]string{
	"source_undeclared":     {"alert"},
	"connector_quarantined": {"alert"},
	"tool_nonconforming":    {"alert"},
}

// anzenActionsUnbuilt are vocabulary entries no firing path implements yet, each
// with where it lands (D331). A vocabulary entry is a PROMISE (CONTRACTS 65), and
// an enforcing rule relying on one is refused at boot. Each has a ledger entry
// `anzen:<action>`, and the two lists are held equal, so building one means
// deleting it from both — the entry expires rather than rots.
//
//nolint:gochecknoglobals // immutable, fixed at compile time
var anzenActionsUnbuilt = map[string]string{
	// `alert` and `disable_reflex` WERE HERE until P5 step 5 built them (D332) —
	// the list shrinking is the instrument working.
	"restrict_shin": "unscheduled",
	// `revoke_grant` WAS HERE until D340, a v1 hotfix: fired from a rule, it
	// suspends the principal the rule names, through the governed verb.
}

// UnbuiltAnzenActions names them, sorted, for the ledger's guard.
func UnbuiltAnzenActions() []string { return sortedKeys(anzenActionsUnbuilt) }

// anzenActions are the protective actions an anzen rule may take (D65).
//
// CLOSED, AND DELIBERATELY INTERNAL-ONLY. Not one of these reaches a customer
// system. That is the structural difference from a reflex, and it is why an
// anzen rule can be trusted with signals a reflex cannot — its blast radius is
// bounded by the vocabulary rather than by a grant an operator might write too
// broadly.
//
//nolint:gochecknoglobals // immutable vocabulary, fixed at compile time
var anzenActions = map[string]string{
	"quarantine_target": "stop resolving a target; in-flight calls finish, new ones are refused",
	"disable_reflex":    "set a reflex to disabled, as though config had said so",
	// UNTIL CONFIG IS REDEPLOYED, not reloaded (D146). The original wording
	// assumed hot reload, which was designed, never built, and then ruled out —
	// the machinery's security cost turned out to exceed the convenience, and a
	// governed verb serves the urgent case without a document swap. So the
	// suspension lives in memory and a redeploy reasserts what configuration
	// says. That asymmetry with D133 is defensible for one reason: configuration
	// is the authority on grants and is not the authority on whether a
	// credential is compromised.
	"revoke_grant": "drop a principal's grants until config is redeployed",
	"alert":        "record and surface; changes no behaviour",

	// THE GENTLEST VERB HERE, and the only one that degrades rather than stops
	// (D85). Until this existed, the answer to a consumer drowning in payload was
	// quarantine_target — cutting it off entirely to stop overwhelming it.
	//
	// Safe to automate for a reason specific to shin: every lens operation is
	// strictly REDUCING (D83), so tightening one can only ever cause a consumer
	// to receive less. No value of this action can send anything anywhere new,
	// which is what keeps it inside "cannot touch a customer system" despite
	// changing what a customer system receives.
	"restrict_shin": "apply a tighter lens to a consumer's deliveries; sends strictly less, never more",

	// THE HARD SEVERITY, and the only verb here that cancels work already in
	// flight (D106). `quarantine_target` lets in-flight calls finish, which is
	// right for a misbehaving target and wrong for a compromised credential.
	//
	// Cancels via context, never by wiping the cached material: zeroed bytes are
	// not a refusal, the wipe would be a data race, and it would silently spare
	// any driver that had already copied the credential — including every SDK
	// client constructed with it (§4.7.4 class 2).
	"revoke_credential": "evict and wipe a credential, tear down clients using it, and CANCEL in-flight calls",
}

func (d *Document) validateAnzen(p *problems, granted grantIndex) {
	seen := make(map[string]bool, len(d.Anzen))

	for i, a := range d.Anzen {
		if a.Name == "" {
			p.addf("anzen[%d]: missing name", i)
			continue
		}
		label := fmt.Sprintf("anzen %q", a.Name)

		if seen[a.Name] {
			p.addf("%s: declared twice", label)
		}
		seen[a.Name] = true

		switch a.Mode {
		case "", "shadow", "enforce":
		default:
			p.addf("%s: mode %q is neither shadow nor enforce", label, a.Mode)
		}

		// D31's shape applied to anzen: a rule is EITHER reactive (watches+do)
		// or preventive (forbids / max_concurrent), never both. Two behaviours
		// in one rule has no good answer for what the rule's outcome was.
		reactive := a.Watches != "" || a.Do != ""
		preventive := len(a.Forbids) > 0 || a.MaxConcurrent > 0

		// TARGET RESIDENCY IS A PREVENTIVE-ONLY AXIS (D137). A reactive rule
		// already names ONE subject, so its residency is fixed by that target and
		// a constraint here could only agree — in which case it is noise — or
		// contradict, in which case the rule silently never applies. Refused
		// rather than accepted as a field that can never mean anything, which is
		// this codebase's most persistent defect.
		if reactive && len(a.TargetResidency) > 0 {
			p.addf("%s: is reactive and sets target_residency, which only scopes "+
				"PREVENTIVE rules. A reactive rule already names one subject (%q), so its "+
				"residency is whatever that target declares — drop the field", label, a.Subject)
		}
		d.validateAnzenResidency(p, label, a)

		switch {
		case reactive && preventive:
			p.addf("%s: is both reactive (watches/do) and preventive (forbids/max_concurrent); "+
				"a rule does exactly one thing (D31)", label)
			continue
		case !reactive && !preventive:
			p.addf("%s: has neither a signal to watch nor a constraint to impose; "+
				"it can never do anything", label)
			continue
		case preventive:
			// A guard scoped to nobody is dead config that reads as protection.
			for _, pattern := range a.Forbids {
				if strings.TrimSpace(pattern) == "" {
					p.addf("%s: has an empty forbids pattern", label)
				}
			}
			if a.MaxConcurrent == 0 && len(a.Forbids) == 0 {
				p.addf("%s: preventive rule constrains nothing", label)
			}
			continue
		}

		if a.Watches == "" {
			p.addf("%s: missing `watches`; an anzen rule watches one internal signal %v",
				label, sortedKeys(anzenSignals))
		} else if _, ok := anzenSignals[a.Watches]; !ok {
			p.addf("%s: `watches: %s` is not an internal signal. Anzen rules watch Sekizui's own "+
				"health, not bus subjects — an anzen rule consuming business events would be "+
				"a reflex, and would lose the bounded reach that makes the class trustworthy. "+
				"Valid: %v", label, a.Watches, sortedKeys(anzenSignals))
		}

		if a.Do == "" {
			p.addf("%s: missing `do`; valid protective actions are %v",
				label, sortedKeys(anzenActions))
		} else if _, ok := anzenActions[a.Do]; !ok {
			p.addf("%s: `do: %s` is not a protective action. The anzen vocabulary is CLOSED "+
				"and internal-only — no anzen rule may reach a customer system, which is "+
				"exactly what makes the class safe to trigger from signals a reflex could "+
				"not be trusted with. Valid: %v", label, a.Do, sortedKeys(anzenActions))
		}
		// **AN ENFORCING RULE MAY ONLY DO WHAT A FIRING PATH IMPLEMENTS (D331).**
		// Until D331 the gateway read every action but quarantine as a REVOKE, so
		// `do: alert` fired as a credential revocation of its subject. The
		// backstop there now refuses; this refuses the configuration first, so an
		// operator learns at boot, not at 03:00. Shadow rules only log, and stay.
		if unbuilt, ok := anzenActionsUnbuilt[a.Do]; ok && a.Enabled && a.Mode == "enforce" {
			p.addf("%s: does %q in enforce mode, and no firing path implements %q yet (%s) — fired, it "+
				"would be refused. Run it in shadow until it lands (ledger `anzen:%s`)",
				label, a.Do, a.Do, unbuilt, a.Do)
		}
		if allowed, narrowed := anzenSignalActions[a.Watches]; narrowed && a.Do != "" &&
			!slices.Contains(allowed, a.Do) {
			p.addf("%s: watches %q and does %q; a rule watching %s may only %v — the source is "+
				"behaving and nothing undeclared was published, so stopping it would turn the "+
				"compliance layer against the data it delivers (D280)", label, a.Watches, a.Do,
				a.Watches, allowed)
		}

		if a.Subject == "" {
			p.addf("%s: missing `subject`; %q needs something to act on", label, a.Do)
		}
		// A RULE THAT DISABLES A REFLEX NAMES ONE THAT EXISTS (D332): a typo
		// here is a response that finds nothing to stop, at the moment it fires.
		if a.Do == "disable_reflex" && a.Subject != "" && !d.declaresReflex(a.Subject) {
			p.addf("%s: disables reflex %q, which no reflex rule declares", label, a.Subject)
		}
		// A RULE THAT SUSPENDS A PRINCIPAL NAMES ONE CONFIGURATION DECLARES
		// (D340), bare — `agent:x`, as a signal names it — never `principal:agent:x`.
		if a.Do == "revoke_grant" && a.Subject != "" && !d.hasGrantBlock(a.Subject) && !d.declaresPrincipal(a.Subject) {
			p.addf("%s: suspends principal %q, which configuration does not declare; name it bare "+
				"(`agent:x`), as signals such as denial_storm do", label, a.Subject)
		}

		// An anzen rule does NOT need a grant, unlike a reflex (D18). It cannot
		// reach a customer system, so there is nothing for a grant to bound —
		// and requiring one would imply it could act outward.
		if _, hasGrant := granted[a.Name]; hasGrant {
			p.addf("%s: has a grant. Anzen rules act only on Sekizui and need none; "+
				"a grant implies outward reach the class does not have", label)
		}
	}
}

// consumesLLMStage reports whether a subject pattern reaches a stage carrying
// agent output.
//
// Configured, not hardcoded (D64): the stage set is extensible (D43), so
// "judged" is a convention rather than a keyword, and a deployment adding a
// second agent-output stage must be able to say so.
func (d *Document) consumesLLMStage(consumes string) bool {
	tokens := strings.Split(consumes, ".")
	for _, stage := range d.LLMStages {
		for _, tok := range tokens {
			if tok == stage {
				return true
			}
		}
		// A trailing ">" swallows everything after it, including an LLM stage.
		// "sekizui.>" consumes judged whether the author noticed or not, which
		// is exactly the case worth catching.
		if i := indexOf(tokens, ">"); i >= 0 && i <= len(tokens)-1 {
			if stageReachableAfter(tokens[:i], stage) {
				return true
			}
		}
	}
	return false
}

// stageReachableAfter reports whether a ">" following the given prefix could
// match a subject on the named stage. Conservative: when the prefix does not
// pin a different stage, assume it can.
func stageReachableAfter(prefix []string, stage string) bool {
	for _, tok := range prefix {
		if tok == stage {
			return true
		}
	}
	// "sekizui.>" pins nothing beyond the root, so it reaches every stage.
	return len(prefix) <= 1
}

func indexOf(xs []string, want string) int {
	for i, x := range xs {
		if x == want {
			return i
		}
	}
	return -1
}

// sortedKeys returns a map's keys sorted, so a boot refusal listing several
// problems reads the same on every run — a message whose order changes is one an
// operator cannot diff against the last one.
//
// GENERIC SINCE D192: the MCP validations key on `MCPSpec` and on `string`, and
// a second copy differing only in its value type is how two helpers come to
// disagree about ordering.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// refuseUnenforcedReflexFields refuses every reflex field the engine does not
// yet ENFORCE (D262) — and, now that D263 and D264 have made them real, checks
// the shape of the ones it does.
//
// **ACCEPTED AND IGNORED IS THE WORST OF THE THREE STATES A FIELD CAN BE IN,
// and since D261 these were in it on a live engine.** `where`, `debounce_key`,
// `debounce_window` and `max_firings_per_hour` parsed, `debounce_key` was even
// checked against the payload schema — and nothing read any of them. So an
// ARMED rule written `where: "input.clicks > 5"` fired on EVERY envelope its
// subject matched, and one declaring `max_firings_per_hour: 50` fired without
// limit, while its configuration read as bounded. Each line below is deleted by
// the change that makes its field real; until then the operator is told what
// the field would have done, rather than being left to believe it did.
func (d *Document) refuseUnenforcedReflexFields(p *problems, label string, r ReflexSpec) {
	// `where` WAS HERE until D263 made it real; its checks are validatePredicate.
	d.validatePredicate(p, label, r)
	// DEBOUNCE AND THE FIRING BUDGET WERE HERE until D264 made them real.
	if (r.DebounceKey == "") != (r.DebounceWindowSec == 0) {
		p.addf("%s: debounce_key and debounce_window_s come together — a key with no window "+
			"suppresses nothing, a window with no key suppresses everything into one bucket (D264)",
			label)
	}
	if r.DebounceKey != "" && r.ExpectsType == "" {
		p.addf("%s: debounce_key needs expects_type, so the key's path can be checked "+
			"against a registered schema (D42, D264)", label)
	}
	if r.Mode == "enforce" && r.MaxFiringsPerHour == 0 {
		p.addf("%s: mode: enforce needs max_firings_per_hour. Arming a rule is two deliberate "+
			"acts — the mode and the budget that bounds it (D264, D157); an armed rule with "+
			"no budget fires as often as its subject matches", label)
	}
}

// validateSources checks the scheduled trigger (D266).
//
// **THE GRANT IS CHECKED HERE AND AGAIN ON EVERY TICK, AND THE TWO ARE NOT
// REDUNDANT.** The tick's check is authorisation — it is what `revoke_grant`
// reaches. This one is D261's argument for reflexes: a source whose principal
// has no grant would be configured, valid, started — and refused on every
// tick, which reads in the log as a source that exists and never produces.
func (d *Document) validateSources(p *problems, targets map[string]bool, granted grantIndex) {
	kindOf := make(map[string]string, len(d.Targets))
	for _, t := range d.Targets {
		kindOf[t.Ref] = t.Kind
	}
	seen := map[string]bool{}
	for i, src := range d.Sources {
		label := fmt.Sprintf("sources[%d] (%q)", i, src.TargetRef)
		switch {
		case src.TargetRef == "":
			p.addf("sources[%d]: names no target", i)
			continue
		case !targets[src.TargetRef]:
			p.addf("%s: references unknown target %q", label, src.TargetRef)
			continue
		}
		if seen[src.TargetRef] {
			p.addf("%s: declared twice — two schedules on one target share one cursor and "+
				"would each re-read what the other committed", label)
		}
		seen[src.TargetRef] = true

		if src.EverySec == 0 {
			p.addf("%s: every_s is zero; a schedule needs an interval in seconds", label)
		}
		if src.Limit == 0 {
			p.addf("%s: limit is zero; a poll that may ask for nothing returns nothing, forever", label)
		}

		action := kindOf[src.TargetRef] + ".poll"
		if !granted[src.Principal()][action][src.TargetRef] {
			p.addf("%s: its principal %q has no grant for %s on %s. A schedule runs as "+
				"`source:<target>` (D250, D266) and is admitted like any principal, so without "+
				"the grant it would be refused on every tick", label, src.Principal(),
				action, src.TargetRef)
		}
	}
}

// validateProjection checks a `projects: true` rule (D269).
//
// **EVERY FIELD THAT WOULD LET IT ACT IS REFUSED, BY NAME.** The eligibility
// line D248 draws — enrichment may run on the synchronous path, actuation may
// not — is only as good as the guarantee that a projection cannot actuate, and
// the cheapest place to make that guarantee is before the rule exists.
func (d *Document) validateProjection(p *problems, label string, r ReflexSpec) {
	actuating := map[string]bool{
		"principal":            r.Principal != "",
		"action":               r.Action != "",
		"target":               r.TargetRef != "",
		"publish_to":           r.PublishTo != "",
		"publishes_type":       r.PublishesType != "",
		"mode":                 r.Mode != "",
		"max_firings_per_hour": r.MaxFiringsPerHour != 0,
		"debounce_key":         r.DebounceKey != "",
		"debounce_window_s":    r.DebounceWindowSec != 0,
	}
	for _, field := range []string{"principal", "action", "target", "publish_to",
		"publishes_type", "mode", "max_firings_per_hour", "debounce_key", "debounce_window_s"} {
		if actuating[field] {
			p.addf("%s: a projection may not declare %s. It shapes a view at delivery and acts "+
				"as nobody — which is the only reason it may run on the synchronous path "+
				"(D248, D269)", label, field)
		}
	}
	if r.Consumes == "" {
		p.addf("%s: missing consumes; a projection needs a subject pattern to know which "+
			"envelopes it shapes", label)
	}
	if r.ExpectsType == "" {
		p.addf("%s: a projection needs expects_type, so what it carries is checked against a "+
			"registered schema at boot (D42, D269)", label)
	}
	// Whether expects_type is registered is schemareg's (D279), as above.
	if len(r.Carry) == 0 && len(r.With) == 0 {
		p.addf("%s: carries nothing and adds nothing, so its projection would always be empty", label)
	}
	d.validatePredicate(p, label, r)
}

// validatePredicate checks a reflex's `where` (D263).
//
// SHAPE HERE, PATHS IN schemareg: the payload schema lives with the drivers, so
// "does this path exist" is D42's boot check, and this is everything answerable
// from the document alone — which is also why `expects_type` is required.
func (d *Document) validatePredicate(p *problems, label string, r ReflexSpec) {
	if len(r.Where) == 0 {
		return
	}
	if r.ExpectsType == "" {
		p.addf("%s: `where` needs `expects_type`, so its paths can be checked against a "+
			"registered payload schema at boot (D42, D263). A predicate over a shape nobody "+
			"declared stops matching silently the day the shape changes", label)
	}
	checkConditions(p, label+": where", r.Where, false)
}

// checkConditions is the SHAPE check every `where` gets — a bus rule's and a
// `refines:` rule's alike, so there is one reading of the shared operator set
// (D300). allowParams admits `{param: name}` as a value, which only a template
// may use (D299, D301); the caller checks the name is declared.
func checkConditions(p *problems, label string, conds Predicate, allowParams bool) {
	for i, c := range conds {
		cl := fmt.Sprintf("%s[%d]", label, i)
		if strings.TrimSpace(c.Path) == "" {
			p.addf("%s: names no path", cl)
		}
		if name, isParam := ParamRef(c.Value); isParam {
			if !allowParams {
				p.addf("%s: `{param: %s}` is a template parameter, and only a connector's "+
					"`refines:` rule declares parameters (D299)", cl, name)
			}
			if c.Op == OpExists || c.Op == OpIn {
				p.addf("%s: %q cannot take a parameter", cl, c.Op)
			}
			continue
		}
		switch c.Op {
		case OpExists:
			if c.Value != nil {
				p.addf("%s: `exists` takes no value; it asks whether %q is present", cl, c.Path)
			}
		case OpIn:
			if _, ok := c.Value.([]any); !ok {
				p.addf("%s: `in` needs a list of values", cl)
			}
		case OpGt, OpGte, OpLt, OpLte:
			if _, ok := c.Value.(float64); !ok {
				p.addf("%s: %q compares numbers, and %v is not one", cl, c.Op, c.Value)
			}
		case OpEq:
			switch c.Value.(type) {
			case string, float64, bool:
			default:
				p.addf("%s: `eq` needs a string, number or boolean", cl)
			}
		case OpPrefix:
			if v, ok := c.Value.(string); !ok || v == "" {
				p.addf("%s: `prefix` needs a non-empty string", cl)
			}
		default:
			// AN UNKNOWN OPERATOR REFUSES THE BOOT. One that parsed and did
			// nothing is D262's defect again, one level down.
			p.addf("%s: unknown operator %q; the set is %v (D263)", cl, c.Op, PredicateOps())
		}
	}
}

// validateReflexConsumption refuses a rule whose principal may not consume what
// the rule consumes (D18, D261).
//
// **A REFLEX IS A PRINCIPAL, NOT A BYPASS, ON THE WAY IN AS WELL AS OUT.** Its
// commands already needed its principal's `allow` grant; since D261 the engine
// SUBSCRIBES as that principal, through the same scoped path an agent does, so
// its `consumes` needs a `subscribe` entry covering it — and the entries'
// targets are what bound which tenants' events the rule ever sees. Refused at
// boot rather than at the rule's first subscription, because a rule that
// validated and then could not subscribe would be enabled, well-formed and
// permanently inert: the recurring shape, arriving through the grant table.
//
// DISABLED RULES INCLUDED: enabling one is a config edit and a redeploy, and
// that redeploy is the wrong moment to learn its grant was never written.
func (d *Document) validateReflexConsumption(p *problems) {
	byPrincipal := map[string][]SubscriptionSpec{}
	for _, g := range d.Grants {
		byPrincipal[g.Principal] = append(byPrincipal[g.Principal], g.Subscribe...)
	}
	for _, r := range d.Reflexes {
		if r.Consumes == "" || r.Principal == "" || r.Projects {
			// Each of the first two is reported by validateReflexes; a
			// projection never subscribes, so it needs no subscribe grant (D269).
			continue
		}
		covered := false
		for _, sub := range byPrincipal[r.Principal] {
			if bus.PatternCovers(sub.Subject, r.Consumes) {
				covered = true
				break
			}
		}
		if !covered {
			p.addf("reflex %q: principal %q may not consume %q. A reflex subscribes AS its "+
				"principal (D18, D261), so that principal needs a subscribe entry covering "+
				"the pattern — one per target the rule may read from", r.Name, r.Principal, r.Consumes)
		}
	}
}

// validateSubscriptions checks bus subject grants (D92, D259).
func (d *Document) validateSubscriptions(p *problems, targets map[string]bool) {
	for _, g := range d.Grants {
		seen := map[SubscriptionSpec]bool{}
		for _, sub := range g.Subscribe {
			pattern := sub.Subject
			label := fmt.Sprintf("principal %q: subscribe %q from %q", g.Principal, pattern, sub.TargetRef)

			// THE TARGET FIRST, because it is the half D259 added and the one an
			// upgraded config is likeliest to be missing.
			switch {
			case strings.TrimSpace(sub.TargetRef) == "":
				p.addf("%s: names no target. A subscription is subject × target, as a "+
					"capability is action × target (D259); without one it would read every "+
					"target's events, which the command plane has never been able to grant", label)
			case !targets[sub.TargetRef]:
				// NO WILDCARD, and this is where one would be caught: "*" is not a
				// declared target, so it is refused here with the rest.
				p.addf("%s: references unknown target %q. Targets are matched exactly, "+
					"as a capability's are — enumerate them, one entry each (D259)",
					label, sub.TargetRef)
			}
			if seen[sub] {
				p.addf("%s: declared twice", label)
			}
			seen[sub] = true

			if strings.TrimSpace(pattern) == "" {
				p.addf("%s: empty subject pattern", label)
				continue
			}
			// A bare ">" grants every subject on the bus, forever, including
			// stages and sources added later. That is the confused-deputy shape
			// MaySpeakFor refuses a wildcard for, applied to data instead of
			// identity — and a subscription is a standing read, so the blast
			// radius is continuous rather than per-call.
			if pattern == ">" || pattern == "*" {
				p.addf("%s: subscribes to EVERYTHING, including stages and sources added "+
					"later. Name the subjects deliberately — a subscription is a standing "+
					"read, so this is continuous rather than per-call", label)
				continue
			}
			// ">" is only meaningful last: "a.>.b" matches nothing in NATS, so a
			// grant written that way silently confers no access at all.
			if i := strings.Index(pattern, ">"); i >= 0 && i != len(pattern)-1 {
				p.addf("%s: `>` matches trailing tokens and is only valid at the end, so "+
					"this pattern matches nothing and the grant confers no access", label)
			}
		}
	}
}

// validateShin checks the lens set as a whole (D83–D86).
//
// THE COMPOSITION CHECK IS THE INTERESTING ONE. A requestable lens that names a
// field its imposed ceiling excludes is refused HERE, at boot, rather than
// silently narrowed at delivery. A consumer that asks for a field and never
// receives it has hit the "declared contract that silently does nothing" shape
// with a network in the middle — the hardest possible place to debug it.
func (d *Document) validateShin(p *problems, granted grantIndex) {
	seen := make(map[string]bool, len(d.Shin))

	// Imposed ceilings indexed by the principals they cover, so a requestable
	// lens can be checked against what will actually sit above it.
	var imposed []ShinSpec
	for _, s := range d.Shin {
		if s.Enabled && s.Mode != "requestable" {
			imposed = append(imposed, s)
		}
	}

	for i, s := range d.Shin {
		if s.Name == "" {
			p.addf("shin[%d]: missing name", i)
			continue
		}
		label := fmt.Sprintf("shin %q", s.Name)

		if seen[s.Name] {
			p.addf("%s: declared twice", label)
		}
		seen[s.Name] = true

		switch s.Mode {
		case "", "imposed", "requestable":
		default:
			p.addf("%s: mode %q is neither imposed nor requestable", label, s.Mode)
		}

		// Same rule as anzen: a lens that silently drops a field is
		// indistinguishable from a bug six months later.
		if strings.TrimSpace(s.Because) == "" {
			p.addf("%s: missing `because`. A lens removes data, and \"why does this "+
				"consumer never see that field\" must be answerable from configuration "+
				"rather than from whoever wrote it", label)
		}

		// A lens that removes nothing and caps nothing is dead config that reads
		// as governance.
		if len(s.Fields) == 0 && len(s.Withholds) == 0 && s.MaxBytes == 0 {
			p.addf("%s: selects no fields, withholds none, and caps nothing — it can "+
				"never change what a consumer receives", label)
		}

		// "Anyone may select this" is almost never intended, and it turns a lens
		// offer into an open menu.
		if s.Mode == "requestable" && len(s.AppliesTo) == 0 {
			p.addf("%s: is requestable but names no `applies_to`, so every principal "+
				"could select it. Name the consumers deliberately", label)
		}

		// A lens scoped to a principal nobody granted is dead config. Not an
		// error for wildcards, which legitimately cover principals added later.
		for _, who := range s.AppliesTo {
			if strings.HasSuffix(who, "*") {
				continue
			}
			if _, ok := granted[who]; !ok {
				p.addf("%s: applies_to %q, which has no grant. A lens for a principal "+
					"that can do nothing shapes nothing", label, who)
			}
		}

		// A type-scoped lens must name a REGISTERED type — schemareg's check
		// since D279, because the type is usually a connector's, which this
		// function cannot see.

		// A lens with field paths but no type cannot be checked against a schema,
		// and D42 exists precisely so that a path nobody validated does not
		// silently stop matching.
		if s.Type == "" && len(s.Fields) > 0 {
			p.addf("%s: names fields but no `type`, so no schema can confirm those paths "+
				"exist. Either scope the lens to a type, or use `withholds`, which is "+
				"meaningful across every payload", label)
		}

		if s.Mode == "requestable" {
			checkUnderCeiling(p, label, s, imposed)
		}
	}
}

// checkUnderCeiling refuses a requestable lens that promises what an imposed
// lens above it will remove.
func checkUnderCeiling(p *problems, label string, req ShinSpec, imposed []ShinSpec) {
	for _, ceiling := range imposed {
		if ceiling.Type != "" && req.Type != "" && ceiling.Type != req.Type {
			continue
		}
		if !overlaps(ceiling.AppliesTo, req.AppliesTo) {
			continue
		}

		for _, field := range req.Fields {
			for _, withheld := range ceiling.Withholds {
				if field == withheld || strings.HasPrefix(field, withheld+".") {
					p.addf("%s: offers field %q, which imposed lens %q withholds (%s). A "+
						"requestable lens composes UNDER the imposed ceiling and can only "+
						"narrow further (D84) — a consumer selecting this would ask for a "+
						"field it can never receive",
						label, field, ceiling.Name, ceiling.Because)
				}
			}
			// The ceiling's allow-list is equally binding: a field it does not
			// keep is a field that never arrives.
			if len(ceiling.Fields) > 0 && !covered(field, ceiling.Fields) {
				p.addf("%s: offers field %q, which imposed lens %q does not keep (it keeps "+
					"%v). The imposed lens runs first, so this field is gone before this "+
					"one is applied", label, field, ceiling.Name, ceiling.Fields)
			}
		}

		if ceiling.MaxBytes > 0 && req.MaxBytes > ceiling.MaxBytes {
			p.addf("%s: caps payloads at %d bytes, above imposed lens %q's %d. The tighter "+
				"cap always wins, so this value is decoration",
				label, req.MaxBytes, ceiling.Name, ceiling.MaxBytes)
		}
	}
}

func covered(field string, kept []string) bool {
	for _, k := range kept {
		if field == k || strings.HasPrefix(field, k+".") || strings.HasPrefix(k, field+".") {
			return true
		}
	}
	return false
}

// overlaps reports whether two applies_to sets can cover a common principal.
// An empty ceiling set covers everyone.
func overlaps(ceiling, req []string) bool {
	if len(ceiling) == 0 {
		return true
	}
	for _, c := range ceiling {
		for _, r := range req {
			if c == r {
				return true
			}
			if prefix, ok := strings.CutSuffix(c, "*"); ok && strings.HasPrefix(r, prefix) {
				return true
			}
			if prefix, ok := strings.CutSuffix(r, "*"); ok && strings.HasPrefix(c, prefix) {
				return true
			}
		}
	}
	return false
}

// burstWords renders a declared burst, naming zero for what it means.
func burstWords(b uint32) string {
	if b == 0 {
		return "none (derived from the rate)"
	}
	return fmt.Sprint(b)
}

// validateBudgets refuses a shared budget whose members disagree about it
// (D208).
//
// **TWO TARGETS NAMING ONE BUDGET WITH TWO RATES IS AMBIGUOUS, AND PICKING ONE
// SILENTLY IS THE DEFECT CLASS.** The limiter builds one bucket per budget and
// the first member it happens to read supplies the capacity — which depends on
// map iteration order, so the same configuration would throttle at 100/hr on one
// boot and 500/hr on the next. The consequence is a quota that is double or half
// what somebody wrote down, discovered as 429s.
//
// **THE SHARES ARE CHECKED TOO, AND OVER-SUBSCRIPTION IS THE FAILURE.** Explicit
// shares summing past 100% cannot all be honoured; below 100% is legitimate,
// because what is left is divided equally among the members that declared none
// (D210).
func (d *Document) validateBudgets(p *problems) {
	type member struct {
		ref     string
		perHour uint32
		burst   uint32
	}
	rated := map[string][]member{}
	shareOf := map[string]uint32{}
	members := map[string]int{}

	for _, t := range d.Targets {
		if t.Limits == nil || t.Limits.Budget == "" {
			continue
		}
		members[t.Limits.Budget]++
		if t.Limits.RatePerHr > 0 {
			rated[t.Limits.Budget] = append(rated[t.Limits.Budget],
				member{ref: t.Ref, perHour: t.Limits.RatePerHr, burst: t.Limits.Burst})
		} else if t.Limits.Burst > 0 {
			// **A BURST NOTHING READS (D284).** The bucket is sized from a RATED
			// member, so a rate-less member's burst is never consulted — and a
			// field that cannot be consulted must not be set, or a reviewer
			// reads it as in force.
			p.addf("target %q declares burst %d in budget %q and no rate_per_hr. A budget's "+
				"bucket is sized by the members that declare its rate, so this burst is never "+
				"read — declare it on those members, or remove it",
				t.Ref, t.Limits.Burst, t.Limits.Budget)
		}
		shareOf[t.Limits.Budget] += t.Limits.Share
	}

	for _, name := range sortedKeys(rated) {
		ms := rated[name]
		for _, m := range ms[1:] {
			if m.perHour != ms[0].perHour {
				p.addf("budget %q is declared with rate_per_hr %d by target %q and %d by "+
					"target %q. A budget is ONE shared quota (D208), so its members must "+
					"agree about how big it is — picking one silently would make the "+
					"effective limit depend on map iteration order, and the symptom would "+
					"be 429s at whichever of the two is wrong",
					name, ms[0].perHour, ms[0].ref, m.perHour, m.ref)
				break
			}
		}
		// **THE BURST IS PART OF HOW BIG THE BUDGET IS, SO IT AGREES TOO (D284).**
		// It was not checked: the limiter built the bucket from whichever rated
		// member it read first, so two members declaring bursts of 10 and 100
		// gave a bucket of either — map order, the exact defect the rate check
		// above exists for, one field over. Compared AS DECLARED, zero meaning
		// derived: comparing effective values would pass `burst: 30` beside a
		// derived 30 until somebody edits one rate and they silently diverge.
		for _, m := range ms[1:] {
			if m.burst != ms[0].burst {
				p.addf("budget %q is declared with burst %s by target %q and %s by target %q. "+
					"A budget is ONE bucket (D208), and its burst decides how much of it may be "+
					"spent at once — declare the same burst on every rated member, or none",
					name, burstWords(ms[0].burst), ms[0].ref, burstWords(m.burst), m.ref)
				break
			}
		}
	}

	for _, name := range sortedKeys(shareOf) {
		if shareOf[name] > 100 {
			p.addf("budget %q has explicit shares summing to %d%%, which cannot all be "+
				"honoured. Shares are percentages of ONE budget (D210); leaving them "+
				"BELOW 100 is fine and means the remainder is divided equally among the "+
				"members that declared none", name, shareOf[name])
		}
	}

	for _, name := range sortedKeys(members) {
		if len(rated[name]) == 0 {
			p.addf("budget %q is named by %d target(s) and none of them declares a "+
				"rate_per_hr, so the budget has no capacity and limits nothing. A "+
				"shared budget that enforces nothing reads as a control in force (D53)",
				name, members[name])
		}
	}
}

// declaresReflex reports whether a reflex rule of that name is declared.
func (d *Document) declaresReflex(name string) bool {
	for _, r := range d.Reflexes {
		if r.Name == name {
			return true
		}
	}
	return false
}

// validateReflexBudgets holds shared reflex budgets to their shape (D334): named
// once, a positive rate, named by a rule, and every rule's `budget:` declared.
// An unnamed budget bounds nothing and reads as a bound; a rule naming a
// missing one would fire unbounded by the budget its author meant.
func (d *Document) validateReflexBudgets(p *problems) {
	declared := map[string]bool{}
	for _, b := range d.ReflexBudgets {
		switch {
		case b.Name == "":
			p.addf("reflex_budgets: an entry has no name")
			continue
		case declared[b.Name]:
			p.addf("reflex_budgets[%q]: declared twice", b.Name)
		case b.MaxFiringsPerHour == 0:
			p.addf("reflex_budgets[%q]: max_firings_per_hour is 0, which refuses every firing of every "+
				"rule naming it; remove the rules or give it a rate", b.Name)
		}
		declared[b.Name] = true
	}
	used := map[string]bool{}
	for _, r := range d.Reflexes {
		if r.Budget == "" {
			continue
		}
		used[r.Budget] = true
		if !declared[r.Budget] {
			p.addf("reflex %q: spends budget %q, which reflex_budgets does not declare", r.Name, r.Budget)
		}
	}
	for _, b := range d.ReflexBudgets {
		if b.Name != "" && !used[b.Name] {
			p.addf("reflex_budgets[%q]: no rule spends it, so it bounds nothing", b.Name)
		}
	}
}

// hasGrantBlock reports whether a principal has grants of its own. With
// declaresPrincipal (reflex principals), what "configuration declares this
// principal" means — the pair the grant verbs' target check uses (D146, D340).
func (d *Document) hasGrantBlock(name string) bool {
	for _, g := range d.Grants {
		if g.Principal == name {
			return true
		}
	}
	return false
}
