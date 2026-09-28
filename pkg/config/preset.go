package config

import (
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// PresetSpec is a named set of actions a connector SUGGESTS and a deployment
// owns (D327).
//
// **A SUGGESTED FRAGMENT, NEVER EMBEDDED AS A GRANT SOURCE.** A connector folder
// ships `presets.yaml`; a deployment drops it into its config directory, as it
// does `anzen.yaml` (D314), or writes its own. Grants expand from the COPY the
// deployment reviewed, so a connector release that adds an action to a preset
// changes nothing anyone may do. Had the connector's file been the grant source,
// every grant naming the preset would have widened on upgrade — the reason the
// embedded shape was rejected. The driver may embed the same file, but only so
// boot can say when the vendor's suggestion has moved (grantcheck).
//
// **`preset`, NOT `role`,** because `role:` is already a signed-subject
// principal (D318): one word with two meanings in one grant table is how a
// reviewer misreads it.
type PresetSpec struct {
	// Name is dotted and namespaced by whoever owns it: `fullstory.standard`
	// from the connector, `acme.support` from a deployment. Two files declaring
	// one name are refused — nothing overrides (D278).
	Name string `json:"name"`

	// Mirrors names the vendor level this preset claims to match — Fullstory's
	// `Standard`, `Architect`, `Admin`. Optional. When set, boot holds the claim
	// to the connector's own grading: no action above that level (grantcheck).
	Mirrors string `json:"mirrors,omitempty"`

	// Explain is for the human choosing a preset: what it is for, and what it
	// deliberately leaves out. Required — a preset nobody can read is a
	// wildcard with extra steps.
	Explain string `json:"explain"`

	// Actions are CONCRETE action names. No patterns: a preset is a fixed list,
	// and `fullstory.*` inside one would reintroduce exactly the widening the
	// fragment exists to prevent.
	Actions []string `json:"actions"`
}

// CapabilityOrigin is where an expanded capability came from in the grant the
// author wrote. Not serialised: the document's identity is its content, and the
// preset's content is already in `presets:`.
type CapabilityOrigin struct {
	// Index is the capability's position in the list AS WRITTEN, so
	// `matched_rule` points at a line a reader can find.
	Index int
	// Preset names the preset this capability was expanded from; "" for a
	// capability the author wrote as an action.
	Preset string
}

// RuleSuffix is what a decision's `matched_rule` appends for a capability
// expanded from a preset, so the record names the preset as well as the line.
func (o *CapabilityOrigin) RuleSuffix() string {
	if o == nil || o.Preset == "" {
		return ""
	}
	return "/preset:" + o.Preset
}

// ExpandPresets replaces every `{preset: X}` capability with one capability per
// action of X, carrying the target, `where` and `max_bytes` it was written with
// (D327).
//
// **EXPANDED AT LOAD, INTO ORDINARY CAPABILITIES, and that is the design.**
// Every consumer of a capability — the grant engine, the catalog, grantcheck,
// the reflex boot check, residency crossings, the union — then sees plain
// actions, so no path can reach a grant around the preset's list. Teaching the
// engine about presets would have left each of the others to be taught too,
// and the one that was not would be the hole.
//
// Every capability in a list that held a preset records its position AS
// WRITTEN, because expansion shifts the rest: `allow[1]` in the file would
// otherwise be recorded as `allow[5]`.
//
// Idempotent: an expanded document has no `preset:` left to expand.
func (d *Document) ExpandPresets() error {
	byName := map[string]PresetSpec{}
	for _, ps := range d.Presets {
		byName[ps.Name] = ps
	}
	var problems []string
	expand := func(principal, list string, caps []CapabilitySpec) []CapabilitySpec {
		has := false
		for _, c := range caps {
			if c.Preset != "" {
				has = true
			}
		}
		if !has {
			return caps
		}
		out := make([]CapabilitySpec, 0, len(caps))
		for i, c := range caps {
			if c.Preset == "" {
				c.Origin = &CapabilityOrigin{Index: i}
				out = append(out, c)
				continue
			}
			where := fmt.Sprintf("principal %q: %s[%d] preset %q", principal, list, i, c.Preset)
			ps, ok := byName[c.Preset]
			switch {
			case c.Action != "":
				problems = append(problems, where+" also names action "+fmt.Sprintf("%q", c.Action)+
					"; a capability names an action OR a preset")
				continue
			case !ok:
				problems = append(problems, where+" is not declared in `presets:`. A connector's "+
					"presets reach a deployment only when its presets.yaml is dropped into the config "+
					"directory (D327)")
				continue
			case c.RatePerHr != 0:
				problems = append(problems, where+" sets rate_per_hr, which would be read as a rate "+
					"PER ACTION of the preset; put the limit on the target, or list the actions")
				continue
			}
			for _, a := range ps.Actions {
				e := c
				e.Action, e.Preset = a, ""
				e.Origin = &CapabilityOrigin{Index: i, Preset: ps.Name}
				out = append(out, e)
			}
		}
		return out
	}
	for gi := range d.Grants {
		g := &d.Grants[gi]
		g.Allow = expand(g.Principal, "allow", g.Allow)
		g.Escalate = expand(g.Principal, "escalate", g.Escalate)
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%d preset problem(s):\n  - %s", len(problems), strings.Join(problems, "\n  - "))
	}
	return nil
}

// validatePresets holds each preset to its shape. Whether its actions EXIST,
// and whether `mirrors` is true, needs the drivers — grantcheck's question.
func (d *Document) validatePresets(p *problems) {
	seen := map[string]bool{}
	for _, ps := range d.Presets {
		switch {
		case ps.Name == "" || !strings.Contains(ps.Name, "."):
			p.addf("preset %q: a name is dotted and namespaced by its owner, e.g. fullstory.standard", ps.Name)
			continue
		case seen[ps.Name]:
			p.addf("preset %q: declared twice; nothing overrides (D278), so two files naming one "+
				"preset is a conflict to resolve, not a precedence to guess", ps.Name)
		case strings.TrimSpace(ps.Explain) == "":
			p.addf("preset %q: no `explain`; a preset a reader cannot understand is a wildcard with "+
				"extra steps", ps.Name)
		case len(ps.Actions) == 0:
			p.addf("preset %q: no actions", ps.Name)
		}
		seen[ps.Name] = true
		acts := map[string]bool{}
		for _, a := range ps.Actions {
			switch {
			case strings.ContainsAny(a, "*?"):
				p.addf("preset %q: action %q is a pattern; a preset is a FIXED list, and a pattern "+
					"inside one widens with every connector release (D327)", ps.Name, a)
			case acts[a]:
				p.addf("preset %q: action %q listed twice", ps.Name, a)
			}
			acts[a] = true
		}
	}
}

// ParsePresets reads a connector's `presets.yaml` (D327): a fragment declaring
// `presets:` and nothing else, strictly — the same parse a deployment's copy
// gets, so the file a vendor ships is the file a deployment can drop in.
func ParsePresets(raw []byte) ([]PresetSpec, error) {
	j, err := yaml.YAMLToJSONStrict(raw)
	if err != nil {
		return nil, err
	}
	var frag struct {
		Presets []PresetSpec `json:"presets"`
	}
	if err := strictJSON(j, &frag); err != nil {
		return nil, fmt.Errorf("a presets fragment declares `presets:` and nothing else: %w", err)
	}
	var p problems
	(&Document{Presets: frag.Presets}).validatePresets(&p)
	if len(p) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(p, "; "))
	}
	return frag.Presets, nil
}
