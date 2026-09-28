// Package grantcheck refuses a document whose grants name actions this
// deployment cannot perform (D195).
//
// **THE DEFECT IT CLOSES WAS LIVE AND WAS FOUND BY PROBING THE CATALOG.** A
// grant naming `mcp.github.exfiltrate` — a tool no human vetted, on a server
// that may well offer it — loaded cleanly and was ADVERTISED to the agent as a
// capability, because `Describe` walked the grant table and never asked whether
// anything implemented what it found. `internal/catalog`'s own comment claimed
// the opposite guarantee in the same file: "a description cannot advertise
// something no driver implements". Nothing enforced it.
//
// **WHY IT IS A COMPONENT RATHER THAN PART OF `config.Document.Validate`**, and
// it is `schemareg.Checker`'s reason verbatim: the question needs the DRIVERS,
// which live in `internal/`, and `pkg/config` cannot import them without
// inverting D35's layering. The document and the drivers meet in a
// `spine.Validator` and nowhere else.
//
// **A PATTERN COVERING NOTHING IS REFUSED TOO.** `mcp.github.*` on a server
// whose vetted spec is empty reads as a broad permission and grants nothing —
// the same defect as a typo'd literal, wearing a wildcard. Both are what D53
// calls a declaration that silently does nothing, on the surface where the
// consequence is somebody's authorisation model.
//
// DESIGN.md references: §4.9, D42, D49, D53, D165, D195, D196.
package grantcheck

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/actionset"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Validate refuses every grant that cannot mean anything, collecting all of
// them.
//
// COLLECTS RATHER THAN RETURNING THE FIRST, matching `config.Document.Validate`
// and `schemareg.Checker`: an operator fixing configuration wants the whole
// list, not one error per restart.
//
// **CALLED FROM `gateway.Server.Validate`, which is already "the only place that
// knows both halves"** — the registry knows which kinds are implemented, the
// document knows what the grants name. A second `spine.Validator` would have
// needed the driver set before the wiring that builds it exists, and ordering a
// check against a map that is populated later is how a check comes to run
// against an empty one.
func Validate(doc *config.Document, drivers map[string]connector.Driver) error {
	const op = "grantcheck.Validate"

	set := actionset.New(doc, drivers)
	known := set.Names()

	var problems []string
	for _, g := range doc.Grants {
		for _, list := range []struct {
			name  string
			specs []config.CapabilitySpec
		}{
			{"allow", g.Allow},
			{"escalate", g.Escalate},
		} {
			for _, spec := range list.specs {
				if len(set.Covers(spec)) > 0 {
					continue
				}
				problems = append(problems, describeMiss(g.Principal, list.name, spec, known))
			}
		}
	}
	problems = append(problems, nativeMisses(doc, set)...)
	problems = append(problems, PresetMisses(doc.Presets, drivers, set)...)
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)

	return fault.New(fault.KindConfig, op, fmt.Sprintf(
		"%d grant(s) or native relation(s) name an action nothing here can perform:\n  - %s",
		len(problems), strings.Join(problems, "\n  - ")))
}

// describeMiss says which of the two shapes went wrong, because the fixes
// differ.
//
// A LITERAL that matches nothing is a typo, an unvetted MCP tool, or a driver
// this build does not compile in. A PATTERN that matches nothing is usually a
// segment with no tools behind it — and it is the more dangerous of the two to
// leave, because a wildcard reads to a reviewer as MORE permission rather than
// none.
func describeMiss(principal, list string, spec config.CapabilitySpec, known []string) string {
	where := fmt.Sprintf("grants[%q].%s: action %q", principal, list, spec.Action)
	if spec.Origin != nil && spec.Origin.Preset != "" {
		where += fmt.Sprintf(" (from preset %q)", spec.Origin.Preset)
	}
	if spec.TargetRef != "" {
		where += fmt.Sprintf(" on target %q", spec.TargetRef)
	}

	if strings.HasSuffix(spec.Action, "*") {
		return where + fmt.Sprintf(" covers no action this deployment serves. A pattern "+
			"matching nothing reads to a reviewer as a BROAD permission and confers none. "+
			"Known actions: %v", known)
	}
	return where + fmt.Sprintf(" is implemented by no registered driver and is not a "+
		"governed verb, so no command naming it could ever succeed — and until now the "+
		"catalog advertised it to the agent anyway (D195). Known actions: %v", known)
}

// nativeMisses refuses a `native:` relation naming an action no linked
// connector implements (D323). Config has already refused a kind no budget
// peer carries; this is the half that needs the drivers. A typo here would
// otherwise restrict nothing — the fail-open direction.
func nativeMisses(doc *config.Document, set *actionset.Set) []string {
	var out []string
	for ref, spec := range doc.MCPSpecs {
		peers := doc.NativePeers(ref)
		for _, tool := range spec.Tools {
			for _, a := range tool.Native {
				if a == config.NativeNone || a == config.NativeOpaque {
					continue
				}
				implemented := false
				for _, peer := range peers {
					for _, got := range set.Covers(config.CapabilitySpec{Action: a, TargetRef: peer.Ref}) {
						implemented = implemented || got == a
					}
				}
				if !implemented {
					out = append(out, fmt.Sprintf("mcp_specs[%q].tools[%q].native: %q is not an action any "+
						"linked target's connector implements, so it would restrict nothing (D323)", ref, tool.Name, a))
				}
			}
		}
	}
	return out
}

// PresetMisses refuses a preset that could mislead whoever grants it (D327):
// an action nothing implements, or a `mirrors:` claim the connector's own
// grading contradicts. Every preset, granted or not — a dropped-in fragment
// with a typo is a declaration that silently does nothing (D53).
//
// EXISTENCE IS ASKED OF THE DRIVERS, not of the deployment's action set: a
// connector's fragment may be dropped in before any target of its kind, and
// its actions must still be real. MCP tools and governed verbs have no driver
// to ask, so they are held to what this deployment serves.
//
// Exported because the connector-folder check holds a shipped presets.yaml to
// the same rule (P5 step 12) — one rule, two callers, as the payload rule is.
func PresetMisses(presets []config.PresetSpec, drivers map[string]connector.Driver, set *actionset.Set) []string {
	var out []string
	served := map[string]bool{}
	if set != nil {
		for _, n := range set.Names() {
			served[n] = true
		}
	}
	for _, ps := range presets {
		for _, a := range ps.Actions {
			kind, _, _ := strings.Cut(a, ".")
			d, native := drivers[kind]
			if native && kind == "mcp" {
				native = false
			}
			if !native {
				if !served[a] {
					out = append(out, fmt.Sprintf("presets[%q]: action %q is served by nothing in this "+
						"deployment, so granting the preset would grant less than it says", ps.Name, a))
				}
				if ps.Mirrors != "" {
					out = append(out, fmt.Sprintf("presets[%q]: mirrors %q, and action %q has no connector "+
						"that can grade it; a claim nobody can check is not made", ps.Name, ps.Mirrors, a))
				}
				continue
			}
			if !implements(d, a) {
				out = append(out, fmt.Sprintf("presets[%q]: action %q is not implemented by the %s connector",
					ps.Name, a, kind))
				continue
			}
			if ps.Mirrors == "" {
				continue
			}
			out = append(out, levelMiss(ps, a, d)...)
		}
	}
	return out
}

func implements(d connector.Driver, action string) bool {
	for _, spec := range d.Actions() {
		if spec.Name == action {
			return true
		}
	}
	return false
}

// levelMiss holds one action to its preset's `mirrors:` claim, in the vendor's
// own vocabulary — the connector says which levels exist and in what order.
func levelMiss(ps config.PresetSpec, action string, d connector.Driver) []string {
	lv, ok := d.(connector.Leveled)
	if !ok {
		return []string{fmt.Sprintf("presets[%q]: mirrors %q, and the connector for %q grades no "+
			"levels; drop `mirrors:` or grade the connector (connector.Leveled)", ps.Name, ps.Mirrors, action)}
	}
	levels := lv.VendorLevels()
	ceiling := slices.Index(levels, ps.Mirrors)
	if ceiling < 0 {
		return []string{fmt.Sprintf("presets[%q]: mirrors %q, which is not one of the vendor's levels %v",
			ps.Name, ps.Mirrors, levels)}
	}
	got, ok := lv.ActionLevel(action)
	if !ok {
		return []string{fmt.Sprintf("presets[%q]: mirrors %q, and the connector cannot say what level %q "+
			"needs", ps.Name, ps.Mirrors, action)}
	}
	if slices.Index(levels, got) > ceiling {
		return []string{fmt.Sprintf("presets[%q]: mirrors %q and holds %q, which the vendor places at %s — "+
			"a preset claiming a level may hold nothing above it (D327)", ps.Name, ps.Mirrors, action, got)}
	}
	return nil
}

// PresetFindings compares each preset a deployment runs with the connector's
// CURRENT suggestion of the same name (D327). INFORMATIONAL: the deployment's
// copy is what grants expand from, so a suggestion that grew has widened
// nothing — this says so, naming what differs, and the operator decides whether
// to take the change in a reviewed commit.
func PresetFindings(presets []config.PresetSpec, drivers map[string]connector.Driver) []string {
	mine := map[string]config.PresetSpec{}
	for _, ps := range presets {
		mine[ps.Name] = ps
	}
	var out []string
	for _, kind := range sortedKeys(drivers) {
		p, ok := drivers[kind].(connector.Presetter)
		if !ok {
			continue
		}
		suggested, err := config.ParsePresets(p.SuggestedPresets())
		if err != nil {
			out = append(out, fmt.Sprintf("the %s connector's suggested presets do not parse: %v", kind, err))
			continue
		}
		for _, s := range suggested {
			d, adopted := mine[s.Name]
			if !adopted {
				continue
			}
			added, removed := diff(s.Actions, d.Actions)
			if len(added) == 0 && len(removed) == 0 {
				continue
			}
			f := fmt.Sprintf("preset %q differs from the %s connector's suggestion:", s.Name, kind)
			if len(added) > 0 {
				f += fmt.Sprintf(" the connector suggests %v, which this deployment's copy does not grant;", added)
			}
			if len(removed) > 0 {
				f += fmt.Sprintf(" this deployment's copy grants %v, which the connector no longer suggests;", removed)
			}
			out = append(out, f+" grants follow the deployment's copy")
		}
	}
	return out
}

// diff returns what want holds that have lacks, and what have holds that want
// lacks, each sorted.
func diff(want, have []string) (added, removed []string) {
	in := func(xs []string, x string) bool { return slices.Contains(xs, x) }
	for _, w := range want {
		if !in(have, w) {
			added = append(added, w)
		}
	}
	for _, h := range have {
		if !in(want, h) {
			removed = append(removed, h)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func sortedKeys(m map[string]connector.Driver) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
