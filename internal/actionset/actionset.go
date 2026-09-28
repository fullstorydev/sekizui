// Package actionset answers one question: what does a granted action pattern
// actually cover in THIS deployment (D195)?
//
// **IT EXISTS BECAUSE TWO PLACES NEEDED THE ANSWER AND A SECOND IMPLEMENTATION
// WOULD HAVE BEEN A SECOND ANSWER.** The catalog expands a pattern so an agent
// is told `mcp.github.search` rather than `mcp.github.*`; boot validation
// refuses a grant whose pattern covers nothing. If those two disagreed, the
// disagreement would be silent and in the worst direction — boot accepting a
// grant the catalog then drops, so a permission reads as in force and is
// advertised nowhere, or the reverse.
//
// **THE SET IS THE DRIVERS' ACTIONS PLUS THE GOVERNED VERBS, AND NOTHING
// ELSE.** That is what "an action this deployment can actually perform" means:
// a driver implements it, or Sekizui serves it itself (`internal/verb`). An
// action outside both is a grant that cannot mean anything, which is a grant
// somebody believes they have.
//
// DESIGN.md references: §4.9, D35, D49, D165, D195, D196.
package actionset

import (
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// Set is every action this deployment serves, with what it takes to describe
// one.
type Set struct {
	// actions is action name -> spec, across every registered driver.
	actions map[string]connector.ActionSpec

	// kinds is target ref -> driver kind. A pattern expands only into actions
	// the TARGET's own driver implements, because `c.actions` is flat and `*` on
	// a Jira target must not cover Fullstory's.
	kinds map[string]string
}

// New builds the set from the document's targets and the registered drivers.
func New(doc *config.Document, drivers map[string]connector.Driver) *Set {
	s := &Set{
		actions: map[string]connector.ActionSpec{},
		kinds:   make(map[string]string, len(doc.Targets)),
	}
	for _, t := range doc.Targets {
		s.kinds[t.Ref] = t.Kind
	}
	for _, d := range drivers {
		for _, spec := range d.Actions() {
			s.actions[spec.Name] = spec
		}
	}
	return s
}

// Covers resolves a capability's action pattern into the concrete actions it
// grants on its target, sorted.
//
// **KIND-SCOPED BY THE TARGET, not by the flatness of the action map.** Action
// names carry their driver's kind as a prefix — `connector.ValidateActions`
// enforces it and D49 makes it load-bearing for MCP — so the kind IS the scope,
// and no second lookup is needed to apply it.
//
// GOVERNED VERBS ARE NEVER KIND-SCOPED: Sekizui serves them itself, and their
// `target_ref` may name a target, a principal or an anzen rule (D134, D146).
//
// AN UNKNOWN TARGET REF COVERS NO DRIVER ACTION, deliberately. Boot already
// refuses a grant naming a target nobody declared, and widening the candidate
// set on an invalid document would answer permissively about configuration
// nobody can run.
func (s *Set) Covers(spec config.CapabilitySpec) []string {
	var out []string

	kind, isTarget := s.kinds[spec.TargetRef]
	if isTarget || spec.TargetRef == "" {
		prefix := kind + "."
		for name := range s.actions {
			// An empty target ref narrows nothing: the grant names no target, so
			// every driver action is a candidate.
			if spec.TargetRef != "" && !strings.HasPrefix(name, prefix) {
				continue
			}
			if policy.ActionMatches(spec.Action, name) {
				out = append(out, name)
			}
		}
	}
	for _, name := range verb.Names() {
		if policy.ActionMatches(spec.Action, name) {
			out = append(out, name)
		}
	}

	sort.Strings(out)
	return out
}

// Describe returns what the driver or the verb registry says an action does,
// and reports whether anything said anything at all.
//
// TWO SOURCES AND NO THIRD (D196). The identifier is not a description, so an
// action nothing describes returns false rather than its own name.
func (s *Set) Describe(action string) (string, bool) {
	if spec, ok := s.actions[action]; ok {
		return spec.Description, spec.Description != ""
	}
	if spec, ok := verb.Lookup(action); ok {
		return spec.Description, spec.Description != ""
	}
	return "", false
}

// Names enumerates every action this deployment serves, sorted.
//
// For a refusal message: an operator told "no such action" needs to see the set
// they could have meant, and the set is derived rather than restated.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.actions)+len(verb.Names()))
	for name := range s.actions {
		out = append(out, name)
	}
	out = append(out, verb.Names()...)
	sort.Strings(out)
	return out
}

// Surfaces answers each native kind's actions from the registered drivers,
// sorted — what the grant engine holds an `[opaque]` MCP tool to (D323). ONE
// READING, shared by `main` and the acceptance harness, so the surface a
// deployment enforces is the one its tests prove.
func Surfaces(drivers map[string]connector.Driver) func(kind string) []string {
	return func(kind string) []string {
		d, ok := drivers[kind]
		if !ok {
			return nil
		}
		var out []string
		for _, a := range d.Actions() {
			out = append(out, a.Name)
		}
		sort.Strings(out)
		return out
	}
}
