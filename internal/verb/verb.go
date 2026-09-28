// Package verb is the closed set of GOVERNED VERBS — the actions Sekizui serves
// itself rather than through a driver.
//
// **ONE SET, READ BY THREE PLACES THAT WERE ABOUT TO KEEP THREE LISTS.** The
// gateway dispatches them, the catalog advertises them, and boot validation
// refuses a grant naming one this build does not serve (D195). Before this
// package the set existed only as the union of two boolean expressions in
// `internal/gateway`, which meant it could be TESTED and could not be ASKED —
// so the check that every granted action exists would have had to restate it,
// and a restated list is right until somebody adds the seventh verb.
//
// **A DOWN PAYMENT ON D165, NOT A COMPETING SOURCE.** The operator-verb registry
// D165 owes also carries each verb's repeat-and-escalation response (D158), so
// that `restore_target` on a healthy target refuses while a repeated withdrawal
// confirms and names who got there first. That half lands with P2 step 20 and
// belongs HERE when it does; what this carries now is the three facts the
// enforcement path, the catalog and boot validation already asked for.
//
// **WHY IT IS NOT IN `internal/gateway`, which owns the dispatch.** The catalog
// needs each verb's description and the gateway imports the catalog, so a
// catalog reading the gateway's table would be an import cycle — the compiler
// finding a layering answer before the argument had to be made, which is how
// D119's posture landed on the resolver rather than on `connector.Target`.
//
// DESIGN.md references: §4.11, D129, D133, D134, D146, D158, D165, D195, D196.
package verb

import (
	"fmt"
	"sort"
	"time"
)

// The governed verbs. `sekizui.` NAMESPACED BECAUSE THEY ACT ON SEKIZUI, not on
// a customer system — the prefix is what tells a grant reviewer that at a
// glance, and it matches anzen's rule that its vocabulary "cannot touch a
// customer system" (§4.11).
const (
	RevokeCredential = "sekizui.revoke_credential"
	QuarantineTarget = "sekizui.quarantine_target"
	RestoreTarget    = "sekizui.restore_target"
	FireAnzen        = "sekizui.fire_anzen"
	RevokeGrant      = "sekizui.revoke_grant"
	ReinstateGrant   = "sekizui.reinstate_grant"
)

// Spec is one governed verb.
type Spec struct {
	Name string

	// Description is what the catalog advertises, and it is REQUIRED for the
	// same reason a driver action's is (D196): a governed verb reaching an
	// operator's tooling as its own name restates the identifier and describes
	// nothing.
	Description string

	// Withdrawal: dispatched after policy and before resolve, by the same
	// enforcement path everything else takes (D129).
	Withdrawal bool

	// GrantVerb: suspends or reinstates a PRINCIPAL rather than acting on a
	// target (D146).
	GrantVerb bool

	// Ref says what this verb's `target_ref` names, because three of the six do
	// not name a target at all and a reviewer reading a grant needs to know
	// which (D134, D146).
	Ref RefKind

	// Repeat is D158's rule for a SECOND call, and it is the half of D165 this
	// package owed. **Refuse when the caller's BELIEF is wrong; confirm when
	// their GOAL is already met.**
	Repeat Repeat

	// Escalates says a second call may still ACT when it raises severity — the
	// hazard D158 names and the dangerous half of this registry. Only the
	// withdrawal family has a severity to raise.
	Escalates bool

	// State is what this verb's completion is CALLED, in the past tense —
	// "withdrawn", "suspended". One word, used by both halves of D158's rule:
	// a confirmation says the ref was already in that state, and a refusal says
	// it is not in it. The two families are opposites over the SAME word, which
	// is why one field serves both.
	State string

	// Does is the bare action word — "restore", "reinstate" — and only a
	// refusing verb needs one, to say what there is nothing of.
	Does string

	// Lifetime is what a confirmation must say about how long the effect lasts,
	// and it is REQUIRED of a confirming verb.
	//
	// **BECAUSE A BARE ACKNOWLEDGEMENT IMPLIES A PERMANENCE D146 DOES NOT
	// GIVE.** A withdrawal is durable across restarts (D145); a grant suspension
	// lasts until this instance is redeployed. An operator who reads "already
	// suspended" and infers the first will not edit configuration, and the
	// principal comes back at the next deploy. Carried as a phrase rather than a
	// boolean so the sentence is written once, here, beside the verb it
	// describes.
	Lifetime string
}

// Repeat is which side of D158's rule a verb falls on.
type Repeat string

const (
	// RepeatConfirm — the caller's GOAL is already met, so a repeat is
	// CONFIRMED with the state and who reached it first. An error at 03:00
	// reads as "it did not work", which sends a second on-call engineer after a
	// bigger hammer for a condition already handled; on a fleet it produces one
	// false alarm per healthy replica, and a control that alarms on correctness
	// is a control that gets switched off.
	RepeatConfirm Repeat = "confirm"

	// RepeatRefuse — the caller's BELIEF about the state is wrong, so the call
	// is REFUSED. `restore_target` on a healthy target and `reinstate_grant` on
	// a principal nobody suspended are both an operator acting on a mistaken
	// picture, and during an incident a mistyped ref that answers OK is worse
	// than one that says no.
	RepeatRefuse Repeat = "refuse"
)

// Prior is what the runtime knows about the state a verb is about to act on.
//
// **THE REGISTRY DECLARES THE RULE AND THE RUNTIME SUPPLIES THE FACTS**, which
// is what keeps this package out of `internal/pool` and `internal/policy`. A
// withdrawal and a grant suspension are different types held by different
// components; what D158's rule needs of both is whether one exists, who got
// there first, when, and one line of detail.
type Prior struct {
	// Present is whether the verb's work has already been done.
	Present bool

	// At and By are the answer to what an operator actually needs from a
	// confirmation — WHO got there first and WHEN — which an error cannot carry.
	At time.Time
	By string

	// Detail is one phrase of state: the withdrawal's severity, or the
	// suspension's reason.
	Detail string

	// Escalating is whether THIS call raises severity above the prior one. The
	// runtime decides it because severity is the pool's vocabulary, not this
	// package's.
	Escalating bool
}

// Response is what a second call gets, and `decided` reports whether the rule
// answered at all.
type Response struct {
	// Confirm is STATUS_OK: the goal was already met, nothing further to do.
	Confirm bool

	// Refuse is STATUS_INVALID_ARGUMENT: the precondition is false.
	Refuse bool

	// Reason is the sentence, composed ONCE HERE. Two hand-written copies of
	// this message existed before D165 and only one of them handled escalation
	// (§15q's defect: three copies of a decision, and the third was already
	// wrong before anyone noticed).
	Reason string
}

// Repeated derives D158's response for a call whose work may already be done.
//
// **ONE TABLE-DRIVEN RULE OVER ALL SIX VERBS, and the symmetry is the reason it
// is one function rather than two.** The two families read as opposites and are
// the same statement:
//
//	prior present, RepeatConfirm  -> confirm (unless this call escalates)
//	prior present, RepeatRefuse   -> proceed, this is the call that acts
//	prior absent,  RepeatConfirm  -> proceed, there is work to do
//	prior absent,  RepeatRefuse   -> refuse, the caller's belief is wrong
//
// Written as four hand-rolled branches across two files, three of the four
// existed and the fourth — escalation — was implemented in one family and
// absent from the other. Adding a P2 verb then meant remembering D158; **telling
// the next author to remember a decision reproduces the condition that produced
// CONTRACTS 57.**
func Repeated(spec Spec, ref string, prior Prior) (Response, bool) {
	switch {
	case prior.Present && spec.Repeat == RepeatConfirm:
		// **ESCALATION IS NOT A REPEAT.** quarantine → revoke on an
		// already-quarantined target must ACT: the operator has decided the
		// target is not merely misbehaving but COMPROMISED, and swallowing that
		// as "already withdrawn" would leave calls running with a credential
		// just declared unsafe — a far worse bug than the one confirmation
		// fixes.
		if spec.Escalates && prior.Escalating {
			return Response{}, false
		}
		return Response{Confirm: true, Reason: confirmation(spec, ref, prior)}, true

	case !prior.Present && spec.Repeat == RepeatRefuse:
		return Response{Refuse: true, Reason: refusal(spec, ref)}, true
	}
	return Response{}, false
}

// confirmation is the sentence a repeat gets.
//
// WHO AND WHEN ARE THE POINT. That is what an operator under stress needs and
// what an error cannot carry; the lifetime is there because a bare
// acknowledgement implies a permanence a suspension does not have.
func confirmation(spec Spec, ref string, prior Prior) string {
	detail := ""
	if prior.Detail != "" {
		detail = " (" + prior.Detail + ")"
	}
	lifetime := ""
	if spec.Lifetime != "" {
		lifetime = ", and " + spec.Lifetime
	}
	return fmt.Sprintf("%s was already %s%s at %s by %s%s. Nothing further to do — "+
		"this is confirmation, not a failure.",
		ref, spec.State, detail,
		prior.At.UTC().Format(time.RFC3339), prior.By, lifetime)
}

// refusal is the sentence a false precondition gets.
func refusal(spec Spec, ref string) string {
	return fmt.Sprintf("%s is not %s, so there is nothing to %s. Refused rather than "+
		"reported as a no-op: during an incident, a mistyped ref that answers OK sends "+
		"somebody away believing they have acted (D158).",
		ref, spec.State, spec.Does)
}

// validate refuses a registry entry that cannot produce the sentences D158
// requires.
//
// **UNEXPORTED, AND `internal/archcheck` IS WHY.** It was `Validate` for an
// hour and `TestNoOrphanedExportsInInternal` failed: its only caller is this
// package's own test, because the registry is a compile-time constant and a
// boot-time check over it would be theatre — nothing can change between the
// build and the boot. An exported method with no outside caller is either dead
// code or a documented guarantee that runs nowhere (D139), and this is neither
// once it is spelled correctly.
//
// **A VERB WITH NO `Lifetime` IS THE DEFECT D158 NAMES BY NAME**, so it is not
// something to discover by reading a confirmation in an incident. A refusing
// verb with no `Does` produces "there is nothing to " and stops, which is the
// unpopulated-field class arriving in a sentence instead of a column.
func (s Spec) validate() error {
	switch s.Repeat {
	case RepeatConfirm:
		if s.State == "" || s.Lifetime == "" {
			return fmt.Errorf("%s confirms a repeat and must declare both State and "+
				"Lifetime: a confirmation has to say what state the ref is already in and "+
				"how long that lasts, or an operator reads permanence into a suspension "+
				"that ends at the next deploy (D158)", s.Name)
		}
	case RepeatRefuse:
		if s.State == "" || s.Does == "" {
			return fmt.Errorf("%s refuses a false precondition and must declare both State "+
				"and Does, or its refusal reads \"is not , so there is nothing to \"", s.Name)
		}
	default:
		return fmt.Errorf("%s declares no Repeat rule, so a second call to it is decided by "+
			"whoever wrote the handler — which is the condition D165 exists to remove", s.Name)
	}
	return nil
}

// RefKind is what a verb's `target_ref` names.
type RefKind string

const (
	// RefTarget — an ordinary target ref, `kata:alpha`.
	RefTarget RefKind = "target"

	// RefPrincipal — `principal:agent:crawler`, so a grant reads "may suspend
	// agent:crawler" rather than "may suspend anybody" (D146).
	RefPrincipal RefKind = "principal"

	// RefRule — `anzen:credential-compromise`. The grant names the RULE, so
	// nobody composes a subject and a severity at 03:00 (D134).
	RefRule RefKind = "rule"
)

// verbs is the vocabulary, WITH THE REASONING THAT SHAPED EACH ONE.
//
// The arguments below were written against the constants in
// `internal/gateway/server.go` and moved here with them: a verb's reasoning
// belongs where the verb is defined, or the next person to add one reads the
// dispatch code and not the case for it (D187's argument, at one-file scale).
//
//nolint:gochecknoglobals // immutable vocabulary, fixed at compile time
var verbs = map[string]Spec{
	// The first of the two break-glass verbs (D129). GOVERNED VERBS ON THE
	// ORDINARY mTLS SURFACE: authorised by grant, recorded by the one
	// enforcement path, dispatched after policy and before resolve — because a
	// second path for the urgent case is a hole in the audit log at exactly the
	// moment the log matters most (D18).
	RevokeCredential: {
		Name: RevokeCredential, Withdrawal: true, Ref: RefTarget,
		Repeat: RepeatConfirm, Escalates: true, State: "withdrawn",
		Lifetime: "stays withdrawn until an authorised sekizui.restore_target lifts it, " +
			"across restarts (D145)",
		Description: "Declare a target's credential compromised: stop resolving it, and " +
			"cancel calls already in flight. Reversed only by sekizui.restore_target.",
	},
	QuarantineTarget: {
		Name: QuarantineTarget, Withdrawal: true, Ref: RefTarget,
		// **ESCALATES, AND THIS IS THE ENTRY THAT MATTERS.** An operator raising
		// an already-quarantined target to a full revocation has decided it is
		// compromised rather than misbehaving, and that call must act.
		Repeat: RepeatConfirm, Escalates: true, State: "withdrawn",
		Lifetime: "stays withdrawn until an authorised sekizui.restore_target lifts it, " +
			"across restarts (D145)",
		Description: "Stop resolving a target. Calls already in flight are allowed to " +
			"finish, which is what separates this from revoking a credential.",
	},
	// LIFTS EITHER WITHDRAWAL (D133), and is symmetric with the two above on
	// purpose: the same surface, grant table, recorder and hash chain, because
	// un-revoking is at least as consequential as revoking and must be at least
	// as auditable.
	//
	// **DELIBERATELY NOT AN ANZEN VERB, unlike the two it reverses.** Anzen's
	// vocabulary exists so a rule can react to a signal without a human at
	// 03:00 — which is right for WITHDRAWING and wrong for restoring. A rule
	// that could lift a revocation is a rule that can auto-restore trust in a
	// credential believed compromised, so `anzenActions` does not contain this
	// and a config naming it is refused at boot.
	RestoreTarget: {
		Name: RestoreTarget, Withdrawal: true, Ref: RefTarget,
		Repeat: RepeatRefuse, State: "withdrawn", Does: "restore",
		Description: "Lift a withdrawal from a target. Refused on a healthy one, because " +
			"the caller's belief about the state is then wrong (D158).",
	},
	// INVOKES A PRE-DECLARED RULE, WHICH SUPPLIES BOTH THE SUBJECT AND THE
	// SEVERITY (D134). `target_ref` names the RULE rather than a target —
	// `anzen:credential-compromise`. That is the whole point: the operator pulls
	// a lever and fills in nothing, so nobody is deciding at 03:00 between "the
	// target is misbehaving" and "the credential is compromised", a distinction
	// §4.7.10 draws precisely and which is easy to invert under pressure. The
	// grant narrows to match — "may fire credential-compromise" is a more
	// reviewable sentence than "may revoke anything on this target".
	FireAnzen: {
		Name: FireAnzen, Withdrawal: true, Ref: RefRule,
		// CONFIRMS LIKE THE VERB IT DELEGATES TO, and escalates for the same
		// reason: the rule supplies the severity, so a rule declaring `revoke`
		// fired at an already-quarantined target IS an escalation and must act.
		Repeat: RepeatConfirm, Escalates: true, State: "withdrawn",
		Lifetime: "stays withdrawn until an authorised sekizui.restore_target lifts it, " +
			"across restarts (D145)",
		Description: "Fire a pre-declared anzen rule by name. The rule supplies the " +
			"subject and the severity, so nobody composes either under pressure.",
	},
	// SUSPENDS A PRINCIPAL'S GRANTS AT RUNTIME (D146). **THE ALTERNATIVE WAS HOT
	// RELOAD, AND THIS IS NARROWER.** §4.5 and D10 promise that a rule change
	// does not require a redeploy, and the machinery for that — a watcher, an
	// atomic document swap — turned out to have a security problem larger than
	// the convenience: three pieces of state gate the command path (withdrawals,
	// breaker counts, limiter buckets), and rebuilding any of them makes a config
	// edit the way to undo it. D133 had already refused that for one of the three.
	//
	// A governed verb needs none of it. There is no document to swap and no
	// derived state to rebuild, so there is nothing to launder — and it produces
	// an audit record rather than a config diff, which is the better artefact for
	// the case it exists to serve.
	RevokeGrant: {
		Name: RevokeGrant, GrantVerb: true, Ref: RefPrincipal,
		// **NO ESCALATION, AND THE ASYMMETRY IS REAL RATHER THAN AN OMISSION.** A
		// suspension has no severity to raise: a principal is suspended or it is
		// not. There is nothing a second call could mean beyond the first.
		Repeat: RepeatConfirm, State: "suspended",
		// D146's half of D158: NOT durable, deliberately, because configuration
		// is the authority on grants. The confirmation has to say so or an
		// operator will not go and edit config, and the principal returns at the
		// next deploy.
		Lifetime: "stays suspended only until this instance is redeployed, so " +
			"configuration must be edited as well (D146)",
		Description: "Suspend a principal's grants until this instance is redeployed. " +
			"Requires a reason, which is written into the record.",
	},
	ReinstateGrant: {
		Name: ReinstateGrant, GrantVerb: true, Ref: RefPrincipal,
		Repeat: RepeatRefuse, State: "suspended", Does: "reinstate",
		Description: "Lift a suspension, restoring what configuration already says the " +
			"principal may do.",
	},
}

// Lookup returns the verb's spec.
func Lookup(name string) (Spec, bool) {
	s, ok := verbs[name]
	return s, ok
}

// Is reports whether the action names a governed verb.
//
// §15q's PREDICATE beside the set, the shape `Severity.Known` and
// `IdempotencyClass.Known` already have — a caller asking "is this one of ours"
// should not have to discard a Spec to find out, and should not reach into the
// map to do it. DELEGATES to Lookup so there is ONE read of `verbs`: the
// two-line version read the map itself, which is the duplication that lets a
// registry gain a lookup rule (a normalisation, an alias) that one of its two
// readers does not apply.
func Is(name string) bool { _, ok := Lookup(name); return ok }

// Names enumerates the vocabulary, sorted.
//
// §15q's enumerator: an assertion or a refusal message ranging over the whole
// set covers the verb somebody adds next year, where one naming members is
// right until they do.
func Names() []string {
	out := make([]string, 0, len(verbs))
	for name := range verbs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
