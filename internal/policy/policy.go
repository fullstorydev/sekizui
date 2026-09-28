// Package policy answers "may this principal do this?" — deny by default.
//
// PRIVATE (D35).
//
// NOT REGO, YET (D58). D25 chose OPA/Rego and that stands; what changed after
// looking at the dependency rather than assuming it is the ORDER. §4.5.2 already
// mandates a cheap structural pre-filter ahead of Rego, because "evaluating
// every rule against every envelope will not hold at volume" — so this component
// has to exist either way. P0's grants are action globs, target equality, and
// membership constraints, all of which it covers. Rego arrives at P5 with
// ReflexSpec.Where, which genuinely needs a language.
//
// THE INTERSECTION IS HERE, NOT IN CONFIGURATION (D59). Effective permission is
// caller ∩ subject. Policy decides what each principal may do; how two
// principals COMPOSE is an invariant, not a policy, and a deployment does not
// get to redefine it.
//
// DESIGN.md references: §4.4, §4.5, §4.5.3, §5.4, D18, D25, D26, D58, D59.
package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Request is what the enforcer asks about.
type Request struct {
	Identity  *sekizuiv1.Identity
	Action    string
	TargetRef string

	// Args are the command arguments, checked against each capability's `where`
	// constraints.
	Args map[string]any
}

// reservedFacet reports whether a `where:` key is answered by Sekizui rather
// than by the caller's arguments.
//
// A RESERVED KEY, NOT A NEW FIELD (D136). CONTRACTS item 39 wanted the two-layer
// residency structure to ride machinery that already exists, and `where:` is it
// — a grant author already knows the syntax, and the semantics (a list means
// membership, a scalar means equality) carry over unchanged.
//
// ANSWERED FROM CONFIGURATION, NEVER FROM THE REQUEST, and that is the whole
// security property. The engine reads the target's class out of the document it
// compiled; nothing on the wire contributes to it. The rejected alternative was
// a `Residency` field on Request, populated by the enforcement path — which is
// this codebase's thirteen-times-repeated defect waiting to happen, because a
// caller that forgets to set it turns every residency constraint into a silent
// refusal, and a second Engine implementation (Rego, P5) would have to remember
// independently. Worse, it puts the value one refactor away from being sourced
// from Args, where a command carrying `target_residency: "eu"` would satisfy its
// own constraint.
//
// A CLOSED SET, AND IT IS TOTAL. Every key in it is answered for every request,
// so "the constraint names a facet" and "the facet has a value" are separate
// questions — an absent value refuses, exactly as an absent argument does. The
// cost is that an action taking a genuine argument named `target_residency`
// cannot be constrained on it; that is deliberate, because the alternative is a
// key whose meaning depends on which driver sits behind the target.
func reservedFacet(key string) bool {
	return config.IsReservedWhereKey(key)
}

// Decision is the answer, in the shape the audit record needs.
type Decision struct {
	Verdict sekizuiv1.Verdict

	// Rule identifies WHAT decided, e.g. "agent:triage#allow[0]" or
	// "default_deny". §5.4: without this, "allowed" is unexplainable — and an
	// unexplainable allow is not an audit record, it is a log line.
	Rule string

	// Reason is populated for DENY and ESCALATE. An operator reading a denial
	// needs to know which of several possible refusals happened.
	Reason string

	// MaxBytes is the byte budget of the capability that AUTHORISED this call.
	// Zero means uncapped.
	//
	// **RETURNED BY THE ENGINE RATHER THAN LOOKED UP BY THE CALLER, because
	// the question is not "what budget does this principal have" but "what
	// budget did the capability that just said yes carry".** A principal may
	// hold several capabilities on one target with different budgets, so any
	// second lookup would be a second evaluation of which one matched — two
	// answers to one question, able to drift, which is D155's shape. The rule
	// string is an INDEX (`agent:triage#allow[0]`), so the alternative is
	// parsing it, which is worse.
	//
	// CONTRACTS 70 is what this exists to close: advertised to agents in the
	// catalog and enforced nowhere.
	MaxBytes uint64
}

// narrowest returns the tighter of two byte budgets, where zero means
// uncapped.
//
// **D59'S "STRICTEST WINS", APPLIED TO A NUMBER RATHER THAN A VERDICT.** A
// command is authorised by the caller's grant AND the subject's, and taking
// either budget alone would let a delegation widen a bound that the other
// party's grant states — which is the same widening the verdict intersection
// exists to prevent, arriving through an integer.
//
// ZERO IS UNCAPPED AND THEREFORE LOSES EVERY COMPARISON, which is the opposite
// of what a naive `min` does: `min(0, 1GB)` is 0, and a budget of zero bytes
// would refuse every call rather than none.
func narrowest(a, b uint64) uint64 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}

// Engine evaluates authorisation.
//
// An interface so Rego can become a second implementation at P5 without the
// enforcement path changing — the Decision it returns is what audit records, and
// that shape does not depend on how the answer was reached.
type Engine interface {
	Authorise(ctx context.Context, req Request) (Decision, error)
}

// GrantEngine evaluates the structured grants from configuration.
type GrantEngine struct {
	// byPrincipal is the compiled grant table. Built once from a Document and
	// never mutated, so it is safe to share across goroutines.
	byPrincipal map[string]principalGrants

	// multiResidency is true when the deployment declares MORE THAN ONE
	// residency class, which is what turns the grant layer on (D136).
	multiResidency bool

	// residencyOf is target ref -> declared class, compiled from the same
	// Document as the grants so the two cannot disagree.
	residencyOf map[string]string

	// mirrors is MCP target ref -> MCP action -> what it mirrors on the native
	// targets that target is linked to (D323). Absent: no declared relation.
	mirrors map[string]map[string]mirror

	// surfaces names every action a native kind implements, for `[opaque]`
	// (WithSurfaces). Nil denies every opaque tool on a linked target: an
	// engine that cannot enumerate the surface cannot show it is all held.
	surfaces func(kind string) []string
}

// mirror is one MCP tool's declared relation, resolved against its links.
type mirror struct {
	native []string            // the mirrored actions; empty with opaque
	opaque bool                // reaches the linked targets' whole surface
	peers  map[string][]string // native kind -> linked target refs
}

// Option configures a GrantEngine.
type Option func(*GrantEngine)

// WithSurfaces tells the engine each native kind's actions, so an `[opaque]`
// tool can be held to the whole surface of the targets it is linked to (D323).
// `main` and the harness pass the registered drivers' actions.
func WithSurfaces(f func(kind string) []string) Option {
	return func(e *GrantEngine) { e.surfaces = f }
}

type principalGrants struct {
	allow    []config.CapabilitySpec
	escalate []config.CapabilitySpec
}

var _ Engine = (*GrantEngine)(nil)

// NewGrantEngine compiles a Document's grants against a deployment ceiling.
//
// `permitted` is the deployment's residency ceiling — the same list the
// resolver enforces, and the same one `-residency` sets. Passed rather than
// derived, because it is a property of the DEPLOYMENT and not of the document:
// the identical config serves a single-region instance and a multi-region one,
// and the grant rule differs between them.
//
// A REQUIRED PARAMETER RATHER THAN AN OPTION, so adding it is a compile error at
// every wiring site. A site that silently defaulted to nil would turn the grant
// layer off, which is the direction that loses the guarantee quietly.
func NewGrantEngine(doc *config.Document, permitted []string, opts ...Option) *GrantEngine {
	e := &GrantEngine{
		byPrincipal:    make(map[string]principalGrants, len(doc.Grants)),
		multiResidency: len(permitted) > 1,
		residencyOf:    make(map[string]string, len(doc.Targets)),
		mirrors:        map[string]map[string]mirror{},
	}
	for _, g := range doc.Grants {
		e.byPrincipal[g.Principal] = principalGrants{allow: g.Allow, escalate: g.Escalate}
	}
	for _, t := range doc.Targets {
		e.residencyOf[t.Ref] = t.Residency
	}
	for ref, byAction := range doc.NativeRelations() {
		peers := map[string][]string{}
		for _, p := range doc.NativePeers(ref) {
			peers[p.Kind] = append(peers[p.Kind], p.Ref)
		}
		compiled := map[string]mirror{}
		for action, relation := range byAction {
			m := mirror{peers: peers}
			for _, a := range relation {
				switch a {
				case config.NativeNone:
				case config.NativeOpaque:
					m.opaque = true
				default:
					m.native = append(m.native, a)
				}
			}
			if m.opaque || len(m.native) > 0 {
				compiled[action] = m
			}
		}
		e.mirrors[ref] = compiled
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Authorise returns the effective decision for the request.
//
// TWO EVALUATIONS, INTERSECTED (D59). The caller is evaluated, the subject is
// evaluated, and the STRICTER answer wins. Where caller == subject — the
// standalone case, a chain of one — the second evaluation is the same question
// and costs a map lookup.
func (e *GrantEngine) Authorise(ctx context.Context, req Request) (Decision, error) {
	const op = "policy.Authorise"

	if err := ctx.Err(); err != nil {
		return Decision{}, fault.Wrap(fault.KindTimeout, op, "context done", err)
	}
	if req.Identity.GetCaller().GetPrincipal() == "" || req.Identity.GetSubject().GetPrincipal() == "" {
		// Not a denial: policy was asked to decide without an established
		// identity, which is a bug in the caller, not a refusal of the request.
		return Decision{}, fault.New(fault.KindInternal, op,
			"authorisation requested with no caller or subject")
	}

	caller := req.Identity.GetCaller().GetPrincipal()
	subject := req.Identity.GetSubject().GetPrincipal()

	callerDec := e.evaluate(caller, req)
	if caller == subject {
		return callerDec, nil
	}

	subjectDec := e.evaluate(subject, req)
	if sub := req.Identity.GetSubject(); sub.GetAssertion() == sekizuiv1.Assertion_ASSERTION_SIGNED {
		subjectDec = e.evaluateSigned(sub, req)
	}
	return intersect(callerDec, subjectDec, caller, subject), nil
}

// evaluateSigned answers for a SIGNED subject (D303, D318): its ROLE selects
// the grant set — `role:architect` in Sekizui's own configuration — and the
// token may only NARROW it. A token listing grants limits the subject to the
// actions those grants cover; a grant it lists that the role lacks allows
// nothing (identity has already noted it as excess). A role claim is an input,
// never an authorisation.
func (e *GrantEngine) evaluateSigned(sub *sekizuiv1.Subject, req Request) Decision {
	dec := e.evaluate(sub.GetRole(), req)
	if dec.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW || len(sub.GetTokenGrants()) == 0 {
		return dec
	}
	for _, g := range sub.GetTokenGrants() {
		if ActionMatches(g, req.Action) {
			return dec
		}
	}
	return Decision{
		Verdict: sekizuiv1.Verdict_VERDICT_DENY,
		Rule:    "token_narrowed",
		Reason: fmt.Sprintf("%s's role %s allows %q, and the token narrows the subject to %v (D303)",
			sub.GetPrincipal(), sub.GetRole(), req.Action, sub.GetTokenGrants()),
	}
}

// intersect applies deny > escalate > allow.
//
// The asymmetry is deliberate: a DENY anywhere in the chain denies, and an
// ESCALATE anywhere escalates. Delegation can only ever NARROW what is
// permitted — "the mesh holds less than the agent" is the case P0 exit criterion
// 3 names, and it must reduce the agent's effective permission to the mesh's.
func intersect(callerDec, subjectDec Decision, caller, subject string) Decision {
	strictest := func(a, b Decision, who string) Decision {
		out := a
		out.Reason = fmt.Sprintf("%s (via %s)", a.Reason, who)
		out.Rule = a.Rule
		return out
	}

	// Deny wins outright, and the reason names WHICH principal lacked the
	// permission — otherwise an operator sees "denied" and has two grants to
	// go read.
	if callerDec.Verdict == sekizuiv1.Verdict_VERDICT_DENY {
		return strictest(callerDec, subjectDec, "caller "+caller)
	}
	if subjectDec.Verdict == sekizuiv1.Verdict_VERDICT_DENY {
		return strictest(subjectDec, callerDec, "subject "+subject)
	}
	if callerDec.Verdict == sekizuiv1.Verdict_VERDICT_ESCALATE {
		return strictest(callerDec, subjectDec, "caller "+caller)
	}
	if subjectDec.Verdict == sekizuiv1.Verdict_VERDICT_ESCALATE {
		return strictest(subjectDec, callerDec, "subject "+subject)
	}

	// Both allow. Record BOTH rules: the audit row should show that two grants
	// had to agree, not just the last one consulted.
	return Decision{
		Verdict:  sekizuiv1.Verdict_VERDICT_ALLOW,
		Rule:     callerDec.Rule + "+" + subjectDec.Rule,
		MaxBytes: narrowest(callerDec.MaxBytes, subjectDec.MaxBytes),
	}
}

// evaluate answers for one principal.
//
// DENY BY DEFAULT (§4.5), non-negotiable "because agents are non-deterministic:
// you cannot enumerate what they will try, so a blocklist is structurally
// wrong". Every path that does not find a matching allow returns DENY.
func (e *GrantEngine) evaluate(principal string, req Request) Decision {
	dec := e.evaluateGrants(principal, req)
	if dec.Verdict == sekizuiv1.Verdict_VERDICT_DENY {
		return dec
	}
	if m, declared := e.mirrors[req.TargetRef][req.Action]; declared {
		return e.union(principal, req, dec, m)
	}
	return dec
}

// union holds an MCP tool to what it was declared to mirror (D52, D323): the
// principal must also hold each native action on each linked target of its
// kind — every one, since a tool cannot say which it reaches — and an
// `[opaque]` tool the whole surface of every linked target. The strictest
// answer wins. It only narrows: it never turns a refusal into an allow.
//
// **NO ARGUMENTS ARE CARRIED ACROSS.** MCP arguments cannot be mapped onto a
// native action's, so a native capability whose `where:` names one does not
// hold — fail closed, which is whereMatches' behaviour on an absent argument.
func (e *GrantEngine) union(principal string, req Request, dec Decision, m mirror) Decision {
	type door struct{ action, target string }
	var doors []door
	for _, a := range m.native {
		kind, _, _ := strings.Cut(a, ".")
		for _, ref := range m.peers[kind] {
			doors = append(doors, door{a, ref})
		}
	}
	if m.opaque {
		for _, kind := range sortedKinds(m.peers) {
			var surface []string
			if e.surfaces != nil {
				surface = e.surfaces(kind)
			}
			if len(surface) == 0 {
				return Decision{
					Verdict: sekizuiv1.Verdict_VERDICT_DENY,
					Rule:    "union:opaque",
					Reason: fmt.Sprintf("%s is declared [opaque] and this engine cannot enumerate %s's "+
						"actions, so it cannot show %q holds all of them (D323)", req.Action, kind, principal),
				}
			}
			for _, a := range surface {
				for _, ref := range m.peers[kind] {
					doors = append(doors, door{a, ref})
				}
			}
		}
	}
	var escalate *Decision
	for _, d := range doors {
		nd := e.evaluateGrants(principal, Request{Identity: req.Identity, Action: d.action, TargetRef: d.target})
		switch nd.Verdict {
		case sekizuiv1.Verdict_VERDICT_DENY:
			what := "mirrors"
			if m.opaque {
				what = "is declared [opaque], so is taken to reach all of what is reachable through"
			}
			return Decision{
				Verdict: sekizuiv1.Verdict_VERDICT_DENY,
				Rule:    "union:" + d.action + "@" + d.target,
				Reason: fmt.Sprintf("%s on %s %s %s on %s, which %q is not granted — the same "+
					"capability through another door is not granted either (D52, D323)",
					req.Action, req.TargetRef, what, d.action, d.target, principal),
			}
		case sekizuiv1.Verdict_VERDICT_ESCALATE:
			if escalate == nil {
				escalate = &Decision{
					Verdict: sekizuiv1.Verdict_VERDICT_ESCALATE,
					Rule:    "union:" + d.action + "@" + d.target,
					Reason: fmt.Sprintf("%s mirrors %s on %s, which requires human approval (D323)",
						req.Action, d.action, d.target),
				}
			}
		}
	}
	if escalate != nil && dec.Verdict == sekizuiv1.Verdict_VERDICT_ALLOW {
		return *escalate
	}
	return dec
}

func sortedKinds(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ruleName is a capability's `matched_rule`: the principal, the list and the
// position AS WRITTEN, and the preset it came from (D327) — so the record points
// at a line a reader can find, not at its place in the expanded list.
func ruleName(principal, list string, i int, c config.CapabilitySpec) string {
	if c.Origin != nil {
		i = c.Origin.Index
	}
	return fmt.Sprintf("%s#%s[%d]%s", principal, list, i, c.Origin.RuleSuffix())
}

// evaluateGrants is one principal's grant table, read alone.
func (e *GrantEngine) evaluateGrants(principal string, req Request) Decision {
	grants, ok := e.byPrincipal[principal]
	if !ok {
		return Decision{
			Verdict: sekizuiv1.Verdict_VERDICT_DENY,
			Rule:    "default_deny",
			Reason:  fmt.Sprintf("principal %q has no grant", principal),
		}
	}

	// Escalate is checked FIRST. A capability appearing in both blocks means the
	// operator asked for human approval on it, and silently allowing because
	// allow was scanned first would quietly discard that.
	for i, c := range grants.escalate {
		if e.matches(c, req) {
			return Decision{
				Verdict: sekizuiv1.Verdict_VERDICT_ESCALATE,
				Rule:    ruleName(principal, "escalate", i, c),
				Reason:  fmt.Sprintf("%s on %s requires human approval", req.Action, req.TargetRef),
			}
		}
	}

	for i, c := range grants.allow {
		if e.matches(c, req) {
			return Decision{
				Verdict: sekizuiv1.Verdict_VERDICT_ALLOW,
				Rule:    ruleName(principal, "allow", i, c),
				// THE BUDGET OF THE CAPABILITY THAT MATCHED, not of the
				// principal. See Decision.MaxBytes.
				MaxBytes: c.MaxBytes,
			}
		}
	}

	return Decision{
		Verdict: sekizuiv1.Verdict_VERDICT_DENY,
		Rule:    "default_deny",
		Reason: fmt.Sprintf("principal %q is not granted %q on %q",
			principal, req.Action, req.TargetRef),
	}
}

// --- what the D136 rule owes an operator AT BOOT ---------------------------
//
// residencyCovered is modal on the deployment, so a grant cannot be read for
// sufficiency on its own. These two exist to pay that back: between them, a
// multi-residency instance says at boot exactly where the guarantee has a hole
// and exactly which capabilities the grant layer has just switched off. Neither
// is derivable from the config file alone, which is why neither lives in
// Document.Validate.

// Crossing is one capability the grant layer will refuse for want of a
// residency constraint.
type Crossing struct {
	Principal string
	Action    string
	TargetRef string
	Residency string
}

// UncoveredCrossings lists the capabilities that stopped working the moment this
// deployment declared a second residency class.
//
// REPORTED, NOT REFUSED. Every entry may be exactly what the operator intends —
// "this principal has no business crossing the border" is a legitimate posture,
// and refusing the config would force a residency constraint onto grants whose
// author deliberately wants them confined. What is NOT acceptable is silence:
// widening `-residency` would otherwise change the effective permission of every
// grant in the file with nothing said about it, and an agent would start being
// denied for a reason nobody can find. Same argument §4.11.4 makes for shadow
// mode — an observation period that teaches an operator nothing is not one.
//
// Empty in a single-class or unconstrained deployment, where the rule is off.
func (e *GrantEngine) UncoveredCrossings() []Crossing {
	if !e.multiResidency {
		return nil
	}

	var out []Crossing
	for principal, grants := range e.byPrincipal {
		for _, c := range append(append([]config.CapabilitySpec(nil), grants.allow...),
			grants.escalate...) {

			if _, declared := c.Where[config.TargetResidencyFacet]; declared {
				continue
			}
			if class := e.residencyOf[c.TargetRef]; class != "" {
				out = append(out, Crossing{
					Principal: principal, Action: c.Action,
					TargetRef: c.TargetRef, Residency: class,
				})
			}
		}
	}

	// SORTED, because a boot log an operator diffs between restarts is worth
	// more than one that reshuffles with Go's map iteration order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Principal != out[j].Principal {
			return out[i].Principal < out[j].Principal
		}
		if out[i].TargetRef != out[j].TargetRef {
			return out[i].TargetRef < out[j].TargetRef
		}
		return out[i].Action < out[j].Action
	})
	return out
}

// UnclassifiedTargets lists targets declaring no residency, which is a HOLE in a
// multi-residency deployment rather than a nuance.
//
// AN UNCLASSIFIED TARGET ESCAPES BOTH LAYERS. The ceiling permits it —
// Profile.ResidencyPermitted treats an empty class as "always permitted", which
// is right for a single-region instance that has not thought about residency —
// and residencyCovered permits it too, because there is no border to authorise.
// In a deployment serving `de,fr,jp` that composition means one undeclared
// target is an unpoliced route to any of them, reachable by anybody with an
// ordinary grant.
//
// The caller REFUSES on a non-empty result (see cmd/sekizui). This is the third
// place the house form appears — a missing declaration refuses, as with MCP
// tools (D46) and shin lenses (D84) — and the direction is the safe one: a
// single-region deployment can never trigger it, and a multi-region one is
// asked to say something it has, by construction, already thought about.
func (e *GrantEngine) UnclassifiedTargets() []string {
	if !e.multiResidency {
		return nil
	}

	var out []string
	for ref, class := range e.residencyOf {
		if class == "" {
			out = append(out, ref)
		}
	}
	sort.Strings(out)
	return out
}

// matches reports whether one capability covers the request.
func (e *GrantEngine) matches(c config.CapabilitySpec, req Request) bool {
	return ActionMatches(c.Action, req.Action) &&
		c.TargetRef == req.TargetRef &&
		e.residencyCovered(c, req) &&
		whereMatches(c.Where, req.Args)
}

// residencyCovered is the GRANT half of D136's two layers.
//
// THE CEILING ANSWERS "IS THIS CROSSING POSSIBLE AT ALL"; this answers "may THIS
// principal, for THIS action, use one the deployment permits". Both must say
// yes. D71 is the reason it cannot be one or the other: a grant is written per
// principal by whoever needs the capability, a ceiling once by whoever is
// accountable for the damage, and residency is a compliance invariant — so the
// party that wants the data across the border must not be able to grant itself
// the crossing.
//
// THE RULE IS MODAL ON THE DEPLOYMENT, and that is the point. A single-class
// deployment (`-residency eu`, or unconstrained) has no crossing to authorise,
// so a grant says nothing and nothing changes. A deployment declaring two or
// more classes — `eu,us`, or `de,fr,jp` — has made every residency-bearing
// target a crossing, and every capability must then name the classes it covers.
//
// WIDENING THE CEILING THEREFORE ESCALATES RATHER THAN ERODES. The failure
// CONTRACTS item 39 names is an operator who needs one legitimate crossing,
// widens `-residency` globally, and loses the guarantee entirely — because a
// control that is too strict gets disabled. Here the widening switches the grant
// layer on instead: existing grants keep working within their own class and stop
// at the border, rather than silently reaching across it.
//
// The cost, stated because it is real: the same grant means different things
// under different flags, so sufficiency cannot be read from the grant alone.
// UncoveredCrossings exists to pay that back at boot.
func (e *GrantEngine) residencyCovered(c config.CapabilitySpec, req Request) bool {
	class := e.residencyOf[req.TargetRef]

	if want, declared := c.Where[config.TargetResidencyFacet]; declared {
		// AGAINST THE TARGET'S CLASS, NEVER THE ARGUMENTS. An unclassified
		// target does not satisfy a constraint that names classes, for the same
		// reason whereMatches refuses a missing argument: absence is not
		// consent, and treating it as one makes the constraint escapable.
		return class != "" && valueSatisfies(want, class)
	}

	// No constraint. Sufficient in a single-class deployment, and sufficient for
	// an unclassified target anywhere — there is no crossing to authorise in
	// either case. Otherwise the capability is silent about a border it would
	// have to cross, and silence denies.
	return !e.multiResidency || class == ""
}

// ActionMatches supports a trailing-star glob: "mcp.github.*" or "*".
//
// PREFIX ONLY, deliberately. A general glob invites "*.delete_*", which reads
// as narrowing and is easy to get subtly wrong in the permissive direction. A
// prefix is what namespaced action names (D49) are shaped for, and it is
// obvious what it covers.
//
// **EXPORTED BECAUSE THE CATALOG AND BOOT VALIDATION ASK THE SAME QUESTION
// (D195).** The catalog expands a granted pattern into the concrete actions it
// covers, so an agent is told `mcp.github.search` rather than `mcp.github.*`;
// boot refuses a pattern that covers nothing. Both had to decide what a pattern
// covers, and a second implementation of that would be a second answer to "what
// did this grant permit" — §4.9 property 1's failure with the enforcer on one
// side of it.
//
// **THE RULE ITSELF LIVES IN pkg/config SINCE P5 STEP 4 (D330)**, because config's
// own boot check of a reflex's grant needs it and cannot import this package.
// It had answered with a LITERAL lookup instead — a second answer — and refused
// a reflex a wildcard grant covered as "not granted".
func ActionMatches(pattern, action string) bool { return config.ActionMatches(pattern, action) }

// whereMatches checks each constraint against the arguments.
//
// A CONSTRAINT WITH NO CORRESPONDING ARGUMENT FAILS. The grant says "only
// project PROJ"; a command omitting `project` has not satisfied that, and
// treating absence as a pass would let an argument be dropped to escape a
// constraint — the most obvious way to attack this check.
//
// RESERVED FACETS ARE SKIPPED HERE, not checked twice. residencyCovered has
// already answered them against Sekizui's own knowledge of the target, and
// falling through to the args map afterwards would hand the caller a second
// chance at a constraint it is not allowed to answer.
func whereMatches(where map[string]any, args map[string]any) bool {
	for key, want := range where {
		if reservedFacet(key) {
			continue
		}
		got, present := args[key]
		if !present {
			return false
		}
		if !valueSatisfies(want, got) {
			return false
		}
	}
	return true
}

// valueSatisfies handles the two constraint forms: a list means membership, a
// scalar means equality.
//
// DELEGATES TO config, which owns the rule, so that Document.Validate refusing a
// constraint as unsatisfiable and this engine deciding whether one is satisfied
// can never disagree (D136).
func valueSatisfies(want, got any) bool {
	return config.ConstraintSatisfied(want, got)
}
