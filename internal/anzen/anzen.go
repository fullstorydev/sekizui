// Package anzen (安全, "safety") is the defensive class (D65).
//
// PRIVATE (D35).
//
// TWO FORMS, and an immune system has both:
//
//	PREVENTIVE — barriers. A ceiling on what any principal may do, checked
//	             before policy so a grant cannot exceed it. Implemented here.
//	REACTIVE   — responses. Watch an internal signal, take a protective action.
//	             Config and validation exist; the dispatcher lands with the
//	             signals it consumes (P5).
//
// WHY THE PREVENTIVE FORM MATTERS MOST. §4.11.7 concluded that a reflex
// downstream of a model has its GRANT as the blast radius, and that the answer
// is not to forbid the rule but to bound and watch it. A grant is written per
// principal by whoever needs the capability. A guard is written once by whoever
// is accountable for the damage. Those are different people with different
// incentives, and the second needs a lever the first cannot override.
//
// DESIGN.md references: §4.3.4, §4.11.7, §6, §7.1, D31, D65, D71.
package anzen

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Guards evaluates the preventive rules.
//
// Safe for concurrent use: the rule set is fixed at construction and never
// mutated, and the only mutable state is the in-flight counter, which is
// mutex-guarded.
type Guards struct {
	forbid []forbidRule
	caps   []capRule

	// reactive is the rules that DECIDE a protective action, kept by name so a
	// human can fire one rather than composing the decision themselves (D134).
	//
	// These were validated at boot and then discarded, because the dispatcher
	// that consumes their signals lands at P5. Retaining them costs nothing and
	// closes a gap that had nothing to do with the dispatcher: an operator
	// invoking break-glass was choosing the subject and the severity in the
	// moment, when the whole point of an anzen rule is that somebody
	// accountable already chose both, in daylight.
	reactive map[string]Reactive

	mu       sync.Mutex
	inFlight map[string]uint32 // principal -> current
}

type forbidRule struct {
	name      string
	patterns  []string
	appliesTo []string
	residency []string
	enforcing bool
}

// Reactive is a rule that decides a protective action (§4.11).
//
// EXPORTED because the enforcement path fires one on an operator's behalf, and
// the record names it. The fields are exactly what a withdrawal needs and
// nothing else: what to do, and to what.
type Reactive struct {
	Name string

	// Do is a verb from anzen's closed vocabulary; Subject is what it acts on.
	Do      string
	Subject string

	// Watches is the internal signal this rule responds to (D65).
	//
	// **RETAINED, AND IT WAS NOT.** The field existed in configuration, boot
	// validated it against the closed signal set, and the compiled rule dropped
	// it — so a rule could declare what it watched, be checked for declaring it
	// correctly, and have nothing in the process able to find it again. That is
	// this codebase's recurring defect in its quietest form: not a missing
	// implementation and not a missing caller, but a value discarded between the
	// two, where every artefact a reviewer inspects is present and correct.
	Watches string

	// Enforcing is false in shadow mode. A shadow rule CANNOT be fired by a
	// human (D134): §4.11.4 item 3 wants a rule observed before it is trusted,
	// and an observation somebody can discharge on demand is not one.
	Enforcing bool
}

type capRule struct {
	name      string
	max       uint32
	appliesTo []string
	residency []string
	enforcing bool
}

// New compiles the preventive guards from configuration.
func New(specs []config.AnzenSpec) *Guards {
	g := &Guards{inFlight: map[string]uint32{}, reactive: map[string]Reactive{}}

	for _, s := range specs {
		if !s.Enabled {
			continue
		}
		// Mode empty means shadow, as everywhere else: a defensive rule that
		// fires wrongly disables working automation, so the safe value is the
		// default (§4.11.4 item 3).
		enforcing := s.Mode == "enforce"

		if len(s.Forbids) > 0 {
			g.forbid = append(g.forbid, forbidRule{
				name: s.Name, patterns: s.Forbids, appliesTo: s.AppliesTo,
				residency: s.TargetResidency, enforcing: enforcing,
			})
		}
		if s.Do != "" {
			g.reactive[s.Name] = Reactive{
				Name: s.Name, Do: s.Do, Subject: s.Subject,
				Watches: s.Watches, Enforcing: enforcing,
			}
		}
		if s.MaxConcurrent > 0 {
			g.caps = append(g.caps, capRule{
				name: s.Name, max: s.MaxConcurrent, appliesTo: s.AppliesTo,
				residency: s.TargetResidency, enforcing: enforcing,
			})
		}
	}
	return g
}

// Check reports whether a principal may attempt an action.
//
// CALLED BEFORE POLICY. A forbidden action is refused even where a grant
// permits it — that ordering is what makes a guard a ceiling rather than an
// opinion. Running policy first would let a broad grant win, and the guard would
// be advisory.
//
// Returns a release function when admitted, which must be called when the action
// completes. A nil error always comes with a non-nil release.
//
// ALSO RETURNS THE GUARD'S NAME on refusal, because the decision record needs it
// as a field rather than buried in prose. `matched_rule: "anzen"` told a reviewer
// that some guard refused and left them parsing the reason to learn which —
// exactly the gap D96 closed for reflexes, where several rules share a principal
// and the record could not say which one fired.
//
// TWO SCOPING AXES, AND BOTH MUST ADMIT (D137). `applies_to` scopes by
// principal, `target_residency` by the class of the target being acted on.
// `targetResidency` is the resolved target's declared class, empty for an
// unclassified target or for an action with no resolvable target at all.
func (g *Guards) Check(principal, action, targetResidency string) (guard string, release func(), err error) {
	for _, r := range g.forbid {
		if !covers(r.appliesTo, principal) {
			continue
		}
		if !coversResidency(r.residency, targetResidency) {
			continue
		}
		if !matchesAny(r.patterns, action) {
			continue
		}
		if !r.enforcing {
			// Shadow: the guard would have refused. Reported by the caller
			// rather than silently allowed, so a week of shadow tells an
			// operator what enforcing would do.
			continue
		}
		return r.name, nil, fault.New(fault.KindDenied, "anzen.Check", fmt.Sprintf(
			"action %q is forbidden by anzen guard %q, which applies to %s regardless of "+
				"grants — a guard is a ceiling, not an opinion (D71)",
			action, r.name, describeScope(r.appliesTo)))
	}

	for i, r := range g.caps {
		if !covers(r.appliesTo, principal) || !r.enforcing {
			continue
		}
		if !coversResidency(r.residency, targetResidency) {
			continue
		}
		if err := g.acquire(principal, r); err != nil {
			// Release anything already taken from earlier cap rules, or a
			// refusal by the second guard would leak a slot held by the first.
			g.releaseUpTo(principal, i)
			return r.name, nil, err
		}
	}

	return "", func() { g.releaseAll(principal) }, nil
}

// UnservedScopes names the preventive guards scoped to a residency class this
// DEPLOYMENT does not serve (D137).
//
// THE SECOND HALF OF A CHECK Document.Validate CANNOT FINISH. Validation refuses
// a guard scoped to a class no TARGET declares, which catches the typo. This
// catches the other shape: a class that is perfectly real, declared by targets,
// and simply not served here — a `jp` guard in a `de,fr` deployment. The rule is
// well-formed, the config is shared across deployments, and the guard silently
// governs nothing on this instance.
//
// The caller REFUSES on a non-empty result. A defensive rule that matches
// nothing is worse than an absent one: the file says the control exists, so
// nobody goes looking for why it did not fire.
//
// `permitted` empty means unconstrained, and then nothing is unserved — the same
// reading §7.1 gives the flag.
func (g *Guards) UnservedScopes(permitted []string) []string {
	if len(permitted) == 0 {
		return nil
	}
	served := make(map[string]bool, len(permitted))
	for _, class := range permitted {
		served[class] = true
	}

	var out []string
	report := func(name string, scope []string) {
		for _, class := range scope {
			if !served[class] {
				out = append(out, fmt.Sprintf("%s (scoped to %q)", name, class))
			}
		}
	}
	for _, r := range g.forbid {
		report(r.name, r.residency)
	}
	for _, r := range g.caps {
		report(r.name, r.residency)
	}

	sort.Strings(out)
	return out
}

// Rule returns a reactive rule by name.
//
// Only ENABLED rules are here at all — a disabled rule is absent from
// configuration's point of view, so it is absent from this map and firing it
// fails the same way a misspelled name does. Shadow rules ARE returned, with
// Enforcing false, so the caller can refuse them by naming the mode rather than
// pretending they do not exist.
func (g *Guards) Rule(name string) (Reactive, bool) {
	r, ok := g.reactive[name]
	return r, ok
}

// DeclaredFor names the enforcing reactive rules that act on a subject.
//
// EXISTS TO TELL TWO GAPS APART (D134). A withdrawal with no rule behind it is
// either "nobody has decided what to do about this target" or "somebody has,
// and the operator did not use it". The first is a decision to make; the second
// is a decision being bypassed, which is the worse of the two and invisible if
// both produce the same warning.
func (g *Guards) DeclaredFor(subject string) []string {
	var names []string
	for name, r := range g.reactive {
		if r.Subject == subject && r.Enforcing {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// WatchersOf returns every reactive rule watching a signal, shadow rules
// included (D109).
//
// SHADOW RULES ARE RETURNED RATHER THAN FILTERED, so the dispatcher can log what
// one WOULD have done. Filtering here would make shadow mode silent, and a
// shadow week that teaches an operator nothing is a week spent not deciding.
func (g *Guards) WatchersOf(signal string) []Reactive {
	var out []Reactive
	for _, r := range g.reactive {
		if r.Watches == signal {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Forbids reports whether an enforcing forbid rule bans this action outright,
// naming the guard. CONSUMES NOTHING — no slot is taken and nothing is released.
//
// EXISTS FOR THE CATALOG, and the distinction it draws is the point.
// `Check` answers "may this proceed right now", which folds two different things
// together: a permanent ceiling (forbid) and a transient concurrency limit
// (cap). The catalog must respect the first and ignore the second — an action at
// its concurrency ceiling is still a capability, and hiding it would make the
// catalog flicker with load.
//
// Calling Check to enumerate would be worse than wrong: it acquires in-flight
// slots for every cap rule, so describing a principal's capabilities would
// consume the budget of the work it was about to do.
func (g *Guards) Forbids(principal, action, targetResidency string) (guard string, forbidden bool) {
	for _, r := range g.forbid {
		if r.enforcing && covers(r.appliesTo, principal) &&
			coversResidency(r.residency, targetResidency) && matchesAny(r.patterns, action) {
			return r.name, true
		}
	}
	return "", false
}

// ForbiddenReflexes names every enabled bus→driver reflex whose command an
// ENFORCING guard forbids for its principal and its target's class (P5 step 4).
//
// **A RULE CONFIGURATION GUARANTEES CAN NEVER ACT IS REFUSED AT BOOT**, as a
// `refines:` rule an imposed lens blocks for its whole audience is (D300): its
// every firing would be refused by the ceiling, so it reads as automation and
// does nothing — a declaration that silently does nothing (D53). Shadow guards
// are not counted; they refuse nothing. residencyOf answers a target's
// declared class, as the gateway's ceiling check does.
func (g *Guards) ForbiddenReflexes(reflexes []config.ReflexSpec, residencyOf func(string) string) []string {
	var out []string
	for _, r := range reflexes {
		if !r.Enabled || r.Action == "" {
			continue
		}
		if guard, forbidden := g.Forbids(r.Principal, r.Action, residencyOf(r.TargetRef)); forbidden {
			out = append(out, fmt.Sprintf("reflex %q acts as %s with %s on %s, which anzen rule %q forbids — "+
				"every firing would be refused, so the rule can never act; scope the guard, or drop the rule",
				r.Name, r.Principal, r.Action, r.TargetRef, guard))
		}
	}
	return out
}

// WouldRefuse reports which shadow-mode guards would have refused this action.
//
// Shadow mode is only useful if somebody is told. §4.11.4 item 3 wants a rule
// observed for a week before it enforces, and that week produces nothing unless
// the near-misses are visible.
func (g *Guards) WouldRefuse(principal, action, targetResidency string) []string {
	var names []string
	for _, r := range g.forbid {
		if !r.enforcing && covers(r.appliesTo, principal) &&
			coversResidency(r.residency, targetResidency) && matchesAny(r.patterns, action) {
			names = append(names, r.name)
		}
	}
	return names
}

func (g *Guards) acquire(principal string, r capRule) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.inFlight[principal] >= r.max {
		return fault.New(fault.KindRateLimited, "anzen.Check", fmt.Sprintf(
			"principal %q already has %d actions in flight; anzen guard %q caps it at %d. "+
				"This bounds blast radius at an instant, which a rate limit does not — a rule "+
				"matching a thousand events at once should not put a thousand commands in flight",
			principal, g.inFlight[principal], r.name, r.max))
	}
	g.inFlight[principal]++
	return nil
}

func (g *Guards) releaseUpTo(principal string, n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for range n {
		if g.inFlight[principal] > 0 {
			g.inFlight[principal]--
		}
	}
}

func (g *Guards) releaseAll(principal string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// One decrement per cap rule that admitted this principal.
	for _, r := range g.caps {
		if covers(r.appliesTo, principal) && r.enforcing && g.inFlight[principal] > 0 {
			g.inFlight[principal]--
		}
	}
	if g.inFlight[principal] == 0 {
		delete(g.inFlight, principal)
	}
}

// InFlight reports current counts, for diagnostics and the panel.
func (g *Guards) InFlight() map[string]uint32 {
	g.mu.Lock()
	defer g.mu.Unlock()

	out := make(map[string]uint32, len(g.inFlight))
	for k, v := range g.inFlight {
		out[k] = v
	}
	return out
}

// covers reports whether a scope list includes a principal.
//
// EMPTY MEANS EVERY PRINCIPAL. That is the right default for a blocklist: an
// action nobody should perform is not a per-principal question, and requiring
// the list to be enumerated would mean a new principal silently escapes it.
func covers(appliesTo []string, principal string) bool {
	if len(appliesTo) == 0 {
		return true
	}
	return matchesAny(appliesTo, principal)
}

// coversResidency is the target-class axis (D137), and it is STRICTLY ADDITIVE.
//
// An unscoped rule covers EVERYTHING, including a target that declares no
// residency. A scoped rule covers only the classes it names, and never an
// unclassified target. So a scoped rule can only ever add refusals on top of the
// unscoped ones — composition is monotone, and no rule can be routed around by
// pointing at a target in another class.
//
// THE UNCLASSIFIED CASE IS THE WHOLE REASON THIS IS NOT `covers`. A principal
// axis has no equivalent: every request has a principal, so a scoped rule always
// has a well-defined subject and an empty list can mean "all" without
// consequence. A target may declare no class at all, and if a scoped rule were
// the only rule governing an action, an undeclared target would escape the
// safety control entirely. That is fail-OPEN, and it is the direction nothing
// else in this codebase fails.
//
// EXACT MATCH, NOT A GLOB, unlike matchesAny. A residency class is a short
// closed identifier an operator types deliberately — `eu`, `jp`, `de` — not a
// namespaced name with structure to match on. `e*` covering `eu` today and a
// hypothetical `ee` tomorrow is a way for a guard's scope to change without
// anyone editing it.
func coversResidency(scope []string, targetResidency string) bool {
	if len(scope) == 0 {
		return true
	}
	if targetResidency == "" {
		return false
	}
	for _, class := range scope {
		if class == targetResidency {
			return true
		}
	}
	return false
}

// matchesAny reports whether any pattern matches, with `*` as a wildcard
// ANYWHERE — "*.delete_*", "reflex:*", "kata.*_project".
//
// A FULLER GLOB THAN GRANTS USE, and deliberately so. §4.5.3 restricts grants to
// a trailing-star prefix because a general glob is easy to get wrong in the
// PERMISSIVE direction, and a grant that permits too much is a security hole.
//
// A blocklist inverts that entirely:
//
//	allowlist (grant)  — too broad permits too much   -> DANGEROUS
//	                     too narrow permits too little -> annoying
//	blocklist (anzen)  — too broad blocks too much     -> annoying
//	                     too narrow MISSES something   -> DANGEROUS
//
// So expressiveness is a safety FEATURE here and a hazard there. Importing the
// grant restriction would have forced an operator to enumerate every destructive
// action by name, and the one they forgot is exactly the one that matters.
//
// Written by hand rather than via regexp: the pattern language stays small
// enough to explain in a sentence, and an operator cannot accidentally write a
// regex that means something other than it looks like.
func matchesAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if globMatch(p, s) {
			return true
		}
	}
	return false
}

// globMatch matches s against a pattern where `*` stands for any run of
// characters, including none.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s // no wildcard: exact
	}

	// The first and last segments are anchored; the middle ones may float.
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}
	return strings.HasSuffix(s, last)
}

func describeScope(appliesTo []string) string {
	if len(appliesTo) == 0 {
		return "every principal"
	}
	return strings.Join(appliesTo, ", ")
}
