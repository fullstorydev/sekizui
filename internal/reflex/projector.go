package reflex

import (
	"fmt"
	"sort"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Projector shapes `Envelope.projection` on the synchronous path (D248, D269).
//
// **THE HALF OF THE ENGINE THAT MAY RUN INSIDE A REQUEST, AND ITS SHAPE IS THE
// GUARANTEE.** It holds rules and nothing else: no Enforcer, no bus, no
// recorder — there is no field through which it could dispatch a command or
// publish an envelope, so "a read cannot trigger a write" is a property of the
// TYPE rather than of the rules someone happened to configure. P3 step 36
// asserts that on the type, not on an outcome (D248: a behavioural arm shows
// only that no actuating rule happened to match this time).
//
// PURE: Project reads an envelope and returns a Struct; it mutates nothing.
type Projector struct {
	rules []config.ReflexSpec
}

// NewProjector builds a Projector over the document's projection rules.
//
// **AN INELIGIBLE RULE IS REFUSED, NOT FILTERED OUT.** Silently skipping a rule
// that dispatches would make the Projector's safety depend on its caller
// passing the right subset; refusing makes a wrong subset a loud boot failure.
// Boot validation (D269) already refuses a projection declaring an action, so
// this is the defence behind it.
func NewProjector(rules []config.ReflexSpec) (*Projector, error) {
	var kept []config.ReflexSpec
	for _, r := range rules {
		if !r.Projects {
			continue
		}
		if r.Action != "" || r.TargetRef != "" || r.PublishTo != "" || r.Principal != "" {
			return nil, fault.New(fault.KindConfig, "reflex.NewProjector", fmt.Sprintf(
				"rule %q is a projection that declares an action, target, publish_to or "+
					"principal; a projection acts as nobody, and one that could dispatch "+
					"must not run on the synchronous path (D248, D269)", r.Name))
		}
		kept = append(kept, r)
	}
	return &Projector{rules: kept}, nil
}

// OnlyDispatching is Engine's other half of the split: the rules that dispatch
// or publish, with every projection removed. The engine never sees a
// projection rule, so it can never subscribe one or try to fire it.
func OnlyDispatching(rules []config.ReflexSpec) []config.ReflexSpec {
	var out []config.ReflexSpec
	for _, r := range rules {
		if !r.Projects {
			out = append(out, r)
		}
	}
	return out
}

// Project returns the projection for env from every matching rule, or nil when
// none matches. The names of the rules that contributed come back too.
//
// **ALL OR NOTHING.** Several rules may shape one envelope, and their fields
// merge; a key two of them produce, or a rule that cannot build its payload —
// a carried field the lens already removed, most usefully — fails the WHOLE
// projection. A partial view would read as complete to the agent consuming it,
// which is the silent loss this repository keeps refusing.
func (p *Projector) Project(env *sekizuiv1.Envelope) (*structpb.Struct, []string, error) {
	const op = "reflex.Project"
	merged := map[string]any{}
	var applied []string
	for _, r := range p.rules {
		ok, err := Match(env, r)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue
		}
		part, err := buildPayload(env.GetData(), r)
		if err != nil {
			return nil, nil, fault.Wrap(fault.KindInvalidArgument, op, fmt.Sprintf(
				"projection %q could not be shaped from what this consumer may see", r.Name), err)
		}
		for k, v := range part.AsMap() {
			if _, taken := merged[k]; taken {
				return nil, nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
					"projections %v and %q both produce %q; which one wins is not a question "+
						"a projection should answer silently", applied, r.Name, k))
			}
			merged[k] = v
		}
		applied = append(applied, r.Name)
	}
	if len(applied) == 0 {
		return nil, nil, nil
	}
	sort.Strings(applied)
	out, err := structpb.NewStruct(merged)
	if err != nil {
		return nil, nil, fault.Wrap(fault.KindInternal, op, "encoding the projection", err)
	}
	return out, applied, nil
}
