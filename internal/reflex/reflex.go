// Package reflex turns events into actions, deterministically and without an
// LLM (§4.11).
//
// PRIVATE (D35).
//
// THIS FILE IS THE PURE FUNCTIONS; engine.go IS THE ENGINE. Matching,
// enrichment and command construction are functions of (envelope, rule) with no
// dependency on a bus, a subscription or a scheduler — built and tested in P0,
// before the bus existed. The engine that subscribes and dispatches arrived in
// P3 (D261), with the debounce and firing budget that bound an armed rule
// (D264). What P5 still owes is POLICY: cross-rule budgets and whatever needs
// more than a counter.
//
// This split follows §12.0 principle 4: build the whole shape thinly, but only
// where the thin version genuinely runs. These functions run — they take a real
// Envelope and return a real Envelope or a real Command.
//
// STRUCTURAL MATCHING, AND NO REGO AT ALL (D58, D263). §4.5.2 mandated a
// "cheap structural pre-filter — an index on (stage, source, type)" ahead of
// Rego, because "evaluating every rule against every envelope will not hold at
// volume". The pre-filter is Match's first half. D263 removed the Rego that was
// to follow it: ReflexSpec.Where is a declarative predicate over the payload,
// evaluated by internal/predicate — still AFTER the pre-filter, so the cheap
// question is still asked first.
//
// DESIGN.md references: §4.5.2, §4.11, §4.11.1, §4.11.6, §12.0, D19, D21, D23,
// D31, D42, D58, D263.
package reflex

import (
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fullstorydev/sekizui/internal/predicate"
	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// MaxDepth caps a causation chain (§4.11.4 item 2).
//
// THE BACKSTOP, NOT THE PRIMARY GUARANTEE. Cycles are prevented structurally by
// stage monotonicity (D21), validated at boot. Depth catches what monotonicity
// cannot: a bug in the stage checker, and agent-produced events re-entering the
// pipeline from outside the stage model.
const MaxDepth = 8

// Match reports whether an envelope satisfies a rule: the structural pre-filter
// over (stage, type), then the rule's `where` over the payload (D263).
//
// THE ORDER IS D26's TWO STAGES: a rule failing the cheap structural question
// is eliminated without its predicate being evaluated at all, which is the
// whole point at event volume. A predicate that cannot be evaluated — the
// payload disagreeing with its schema — is an ERROR, never a quiet non-match.
func Match(env *sekizuiv1.Envelope, rule config.ReflexSpec) (bool, error) {
	const op = "reflex.Match"

	if env == nil {
		return false, fault.New(fault.KindInternal, op, "nil envelope")
	}

	// A disabled rule never matches. Checked first because it is the cheapest
	// possible rejection and the most common one in a config with history.
	if !rule.Enabled {
		return false, nil
	}

	if !subjectMatches(rule.Consumes, env) {
		return false, nil
	}

	// D42: a rule declaring an expected payload type must not fire on a
	// different one. Boot validation checks the schema is REGISTERED; this
	// checks the envelope in hand actually carries it — the two are different
	// questions and the second can only be asked at match time.
	if rule.ExpectsType != "" && rule.ExpectsType != env.GetType() {
		return false, nil
	}

	// §4.11.4 item 2. A matched rule on an over-deep envelope is a runaway, and
	// refusing to match is what stops it — silently, per event, without needing
	// a circuit breaker.
	if env.GetCausation().GetDepth() >= MaxDepth {
		return false, fault.New(fault.KindBudgetExceeded, op, fmt.Sprintf(
			"envelope %q is at causation depth %d (max %d); refusing to match rule %q — "+
				"stage monotonicity should have prevented this, so treat it as a bug",
			env.GetId(), env.GetCausation().GetDepth(), MaxDepth, rule.Name))
	}

	// THE SECOND STAGE (D263). Only rules that survived the pre-filter reach it.
	if len(rule.Where) > 0 {
		ok, err := predicate.Holds(rule.Where, env.GetData().AsMap())
		if err != nil {
			return false, fault.Wrap(fault.KindInvalidArgument, op, fmt.Sprintf(
				"rule %q could not evaluate its where on envelope %q", rule.Name, env.GetId()), err)
		}
		return ok, nil
	}
	return true, nil
}

// subjectMatches compares an envelope against a NATS-style subject pattern.
//
// **THE BUS'S DERIVATION AND THE BUS'S MATCHER, NOT COPIES OF THEM (D258).**
// This package carried its own `envelopeSubject` and `tokensMatch`, and they
// were the CORRECT half: they implemented D60 while the bus matched on the
// entity field. Two readers of one contract is how that happened, so there is
// now one of each and both planes call it — a rule and a subscriber with the
// same pattern see the same envelopes by construction rather than by care.
//
// D60's reasoning — why the source is not its own token, why the instance is
// absent, why the version trails — lives on `pkgbus.SubjectOf` and in
// DECISIONS.md rather than being restated here.
func subjectMatches(pattern string, env *sekizuiv1.Envelope) bool {
	if pattern == "" {
		return false
	}
	return pkgbus.SubjectMatches(pattern, pkgbus.SubjectOf(env))
}

// Enrich produces the bus→bus envelope a rule publishes (§4.11.6).
//
// THE HIGHER-IMPACT HALF, per §4.11.6: deterministic enrichment runs before
// expensive inference, exists once instead of in every agent, and removes a
// whole class of agent work — "correlation, joining, reshaping, deduping,
// redacting, formatting".
//
// Returns a NEW envelope. The input is not mutated: it has already been
// delivered to other subscribers, and editing it would change what they see
// after they have seen it.
func Enrich(env *sekizuiv1.Envelope, rule config.ReflexSpec, newID string) (*sekizuiv1.Envelope, error) {
	const op = "reflex.Enrich"

	if env == nil {
		return nil, fault.New(fault.KindInternal, op, "nil envelope")
	}
	if rule.PublishTo == "" {
		return nil, fault.New(fault.KindInternal, op, fmt.Sprintf(
			"rule %q has no publish_to; Enrich is for bus->bus rules only", rule.Name))
	}

	stage, err := stageOf(rule.PublishTo)
	if err != nil {
		return nil, err
	}

	// D19: causation from the first commit. Depth increments per hop, and the
	// root is preserved across the whole chain rather than being rewritten —
	// "what triggered this", as distinct from identity.chain's "who authorised
	// this".
	//
	// ONE CONSTRUCTION of a reflex's causation (causationFrom), shared with
	// BuildCommand and with a firing refused by its budget (D264), so all three
	// name their origin identically.
	cause := causationFrom(env, rule)

	// Explicitly carried fields plus the rule's own additions (D63).
	data, err := buildPayload(env.GetData(), rule)
	if err != nil {
		return nil, fault.Wrap(fault.KindInvalidArgument, op,
			fmt.Sprintf("rule %q: building enriched payload", rule.Name), err)
	}

	return &sekizuiv1.Envelope{
		Id:          newID,
		Source:      env.GetSource(),
		SpecVersion: env.GetSpecVersion(),
		// Type is versioned per D41 because the rule DECLARES it (D88) — deriving
		// it from the bus subject produced an unversioned type while this comment
		// claimed otherwise. The enriched form is a different type from what was
		// consumed, so a consumer can subscribe to one and not the other.
		Type:    enrichedType(rule),
		Subject: env.GetSubject(),
		Time:    env.GetTime(),
		Data:    data,
		Stage:   stage,
		// Residency travels with the data (D29). Losing it here would make the
		// enriched copy exportable to a region the original was not.
		Residency:    env.GetResidency(),
		TraceId:      env.GetTraceId(),
		ObservedTime: timestamppb.Now(),
		Causation:    cause,
	}, nil
}

// enrichedType returns the DECLARED published type.
//
// It used to derive one from the bus subject's last segment, which produced
// "friction_detected" — unversioned, unregistered, and therefore outside both
// D41 and D42, while the comment at the call site claimed the opposite. Boot
// validation now requires publishes_type whenever a rule publishes (D88), so the
// fallbacks below are unreachable through a validated document.
//
// They remain because this function is also reachable from tests and from a
// future caller that skips validation, and returning "" would produce an
// envelope with no type at all — which is worse than an honest marker that fails
// loudly downstream.
func enrichedType(rule config.ReflexSpec) string {
	if rule.PublishesType != "" {
		return rule.PublishesType
	}
	if t := lastToken(rule.PublishTo); t != "" {
		return t
	}
	return rule.Name
}

// BuildCommand produces the command a bus→driver rule issues (§4.11.1).
//
// A REFLEX IS A PRINCIPAL, NOT A BYPASS (D18). The command returned here goes
// through the identical enforcement path as one from an agent — identity,
// policy, audit — and carries the rule's own principal. There is deliberately no
// path from a reflex to a driver that skips it.
func BuildCommand(env *sekizuiv1.Envelope, rule config.ReflexSpec) (*sekizuiv1.Command, error) {
	const op = "reflex.BuildCommand"

	if env == nil {
		return nil, fault.New(fault.KindInternal, op, "nil envelope")
	}
	if rule.Action == "" || rule.TargetRef == "" {
		return nil, fault.New(fault.KindInternal, op, fmt.Sprintf(
			"rule %q has no action/target; BuildCommand is for bus->driver rules only", rule.Name))
	}

	args, err := structpb.NewStruct(rule.With)
	if err != nil {
		return nil, fault.Wrap(fault.KindInvalidArgument, op,
			fmt.Sprintf("rule %q: building command args", rule.Name), err)
	}

	cause := causationFrom(env, rule)

	return &sekizuiv1.Command{
		Action:    rule.Action,
		TargetRef: rule.TargetRef,
		Args:      args,
		// Derived from the envelope, so a redelivery of the same event produces
		// the same key and therefore one side effect rather than two. A random
		// key would defeat the idempotency the DoD requires.
		IdempotencyKey: fmt.Sprintf("reflex:%s:%s", rule.Name, env.GetId()),
		Causation:      cause,
		// §4.11.4 item 3: every reflex should run shadow first. Shadow sets
		// dry_run, which produces a real audit row with VERDICT_WOULD_HAVE_FIRED
		// and no side effect — the built-in staging mechanism most automation
		// lacks.
		DryRun: rule.Mode != "enforce",
	}, nil
}

// CarryAll in a rule's Carry list propagates every source field.
//
// The escape hatch for a rule that genuinely wants the whole payload. Explicit,
// so it appears in a diff and a reviewer sees it — unlike a merge default, which
// is invisible precisely where it matters.
const CarryAll = "*"

// buildPayload assembles the enriched payload: carried source fields, then the
// rule's own additions (D63).
//
// NO IMPLICIT MERGE. §10.2 originally leaned merge for consumer friendliness and
// the cost was hidden: unbounded payload growth per hop, blurred provenance, and
// an enriched schema permanently coupled to its source. Naming the carried
// fields fixes all three, and costs one line of configuration.
//
// A carried field that does not exist in the source is an ERROR, not a silent
// omission. The rule states a dependency on the source's shape; if the source
// changed and the field is gone, the rule is broken and should say so rather
// than quietly emitting a smaller payload — which is D42's silent-stop failure
// arriving through a different door.
func buildPayload(src *structpb.Struct, rule config.ReflexSpec) (*structpb.Struct, error) {
	const op = "reflex.buildPayload"

	source := src.AsMap()
	out := map[string]any{}

	carryAll := false
	for _, f := range rule.Carry {
		if f == CarryAll {
			carryAll = true
			break
		}
	}

	switch {
	case carryAll:
		for k, v := range source {
			out[k] = v
		}
	default:
		var missing []string
		for _, field := range rule.Carry {
			v, ok := source[field]
			if !ok {
				missing = append(missing, field)
				continue
			}
			out[field] = v
		}
		if len(missing) > 0 {
			sort.Strings(missing) // map iteration is randomised; the error must not be
			return nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"rule %q carries field(s) %v that the source payload does not have; "+
					"the source shape changed, or the rule names the wrong field (D63)",
				rule.Name, missing))
		}
	}

	// The rule's own additions. A collision with a carried field is refused
	// (D61) — a rule intending to ADD a field must not silently destroy one it
	// chose to carry.
	var collisions []string
	for k, v := range rule.With {
		if _, exists := out[k]; exists {
			collisions = append(collisions, k)
			continue
		}
		out[k] = v
	}
	if len(collisions) > 0 {
		sort.Strings(collisions)
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"rule %q sets field(s) %v that it also carries from the source; "+
				"drop them from carry, or rename the addition (D61)", rule.Name, collisions))
	}

	return structpb.NewStruct(out)
}

// stageOf extracts the stage token from a subject pattern.
func stageOf(subject string) (string, error) {
	parts := strings.Split(subject, ".")
	if len(parts) < 2 {
		return "", fault.New(fault.KindConfig, "reflex.stageOf", fmt.Sprintf(
			"subject %q has no stage token", subject))
	}
	// "sekizui.enriched.friction" -> "enriched"
	if parts[0] == "sekizui" {
		return parts[1], nil
	}
	return parts[0], nil
}

func lastToken(subject string) string {
	parts := strings.Split(subject, ".")
	last := parts[len(parts)-1]
	if last == "*" || last == ">" {
		return ""
	}
	return last
}
