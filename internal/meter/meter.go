// Package meter composes D171's three layers into the rate table the limiter
// enforces (D284): the CONNECTOR's meter and default, the TARGET's budget, the
// DEPLOYMENT's ceiling.
//
// **ONE FUNCTION FOR THE BINARY AND THE ACCEPTANCE HARNESS.** Both used to build
// the rate table with their own copy of the same loop, and this decision
// changes that loop's arithmetic — a second copy is how the suite would go on
// proving the old behaviour while the binary ran the new one (D155).
package meter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/limiter"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// DefaultCallsPerHour is the built-in value of `-meter-default-calls`: the
// universal budget, in calls, for a target whose connector declares none and
// which declares none itself (D284).
//
// **ONE A SECOND, ON AVERAGE, WITH A BURST OF 360.** Conservative on purpose — a
// default is what applies when nobody thought about it, and the cost of it
// being too low is a refusal naming `rate_per_hr`, while the cost of it being
// too high is somebody else's invoice or somebody else's 429s.
const DefaultCallsPerHour = 3600

// Bounds is the deployment's layer: a ceiling per unit, and the universal
// calls default. From flags, never from the document (D142, D108).
type Bounds struct {
	// Ceilings maps a unit to the most a target may budget per hour in it. A
	// unit with no entry has no ceiling, as every other bound does at zero.
	Ceilings map[string]uint32

	// DefaultCalls is the universal default, in calls per hour. Zero means
	// DefaultCallsPerHour.
	DefaultCalls uint32
}

// Plan is the composed result.
type Plan struct {
	// Rates is the limiter's table, one entry per metered target.
	Rates map[string]limiter.Rate

	// Units maps each target to its connector's unit.
	Units map[string]string

	// Notes are what boot should log: every default applied and every default
	// the ceiling lowered. Sorted.
	Notes []string
}

// Build composes the layers, or refuses the deployment.
//
// **REFUSED, WITH EVERY PROBLEM NAMED AT ONCE:**
//   - a target asking for more than its unit's ceiling (D108 — a target quietly
//     given less than it asked for is an operator believing something false);
//   - a shared budget (D208) whose members are metered in different units;
//   - a scheduled source whose poll costs more than its budget's burst — it
//     could never be admitted, and the limiter would say "later" for ever.
//
// **LOWERED, AND SAID:** a connector default, or the universal one, above the
// ceiling. Nobody asked for that number, so refusing the boot would punish no
// one's mistake.
//
// Targets of a quarantined connector, or of a kind no driver serves, are
// skipped: they are refused elsewhere, loudly, and have nothing to meter.
func Build(doc *config.Document, drivers map[string]connector.Driver,
	quarantined map[string]string, b Bounds) (*Plan, error) {

	const op = "meter.Build"
	universal := b.DefaultCalls
	if universal == 0 {
		universal = DefaultCallsPerHour
	}
	p := &Plan{Rates: map[string]limiter.Rate{}, Units: map[string]string{}}
	var refusals []string
	budgetUnits := map[string]map[string][]string{} // budget -> unit -> target refs
	specs := map[string]config.TargetSpec{}

	for _, t := range doc.Targets {
		d, ok := drivers[t.Kind]
		if !ok {
			continue
		}
		if _, q := quarantined[t.Kind]; q {
			continue
		}
		specs[t.Ref] = t
		m := d.Meter()
		unit := m.UnitName()
		p.Units[t.Ref] = unit
		ceiling, capped := b.Ceilings[unit]

		var lim config.TargetLimits
		if t.Limits != nil {
			lim = *t.Limits
		}
		if lim.Budget != "" {
			if budgetUnits[lim.Budget] == nil {
				budgetUnits[lim.Budget] = map[string][]string{}
			}
			budgetUnits[lim.Budget][unit] = append(budgetUnits[lim.Budget][unit], t.Ref)
		}

		rate := lim.RatePerHr
		switch {
		case rate > 0:
			// THE TARGET ASKED. Over the ceiling is refused, never clamped.
			if capped && rate > ceiling {
				refusals = append(refusals, fmt.Sprintf(
					"target %q asks for rate_per_hr %d %s, above the deployment ceiling of %d "+
						"(-meter-ceiling %s=%d). Lower it, or raise the ceiling where the deployment "+
						"is reviewed", t.Ref, rate, unit, ceiling, unit, ceiling))
				continue
			}
		case lim.Budget != "":
			// A RATE-LESS MEMBER OF A NAMED BUDGET GETS NO DEFAULT. It draws on
			// the bucket a rated member declares (validateBudgets requires one),
			// and a default here would compete to size that bucket — which the
			// limiter settles by map order (D208).
		default:
			// NOBODY ASKED: the connector's default, else the universal one.
			//
			// **`=` AND NOT `:=`, AND STEP 20a IS WHY.** Written as
			// `rate, source := …` this declared a NEW `rate` scoped to this
			// case, shadowing the outer one: the default was computed and
			// discarded, and every defaulted target left unmetered — "absent
			// means unlimited" again, inside the function written to end it.
			// It compiled because `source` was new, which is what `:=` needs.
			var source string
			rate, source = m.DefaultPerHour, "the connector's default"
			if rate == 0 {
				rate, source = universal, "the universal default (-meter-default-calls)"
			}
			if capped && rate > ceiling {
				p.Notes = append(p.Notes, fmt.Sprintf("target %q: %s of %d %s/hr is above the "+
					"ceiling, so it is LOWERED to %d", t.Ref, source, rate, unit, ceiling))
				rate = ceiling
			} else {
				p.Notes = append(p.Notes, fmt.Sprintf("target %q declares no rate_per_hr: %s, "+
					"%d %s/hr", t.Ref, source, rate, unit))
			}
		}
		p.Rates[t.Ref] = limiter.Rate{
			PerHour: rate, Burst: lim.Burst, Budget: lim.Budget, Share: lim.Share,
		}

		// THE SYSTEM BUDGET (D311): a Drifter's comparisons draw on a bucket of
		// their own, at the rate the CONNECTOR declared, so consumers never pay
		// for Sekizui's safety checks. Never shared, never a target's to widen.
		if _, drifts := drivers[t.Kind].(connector.Drifter); drifts && m.SystemPerHour > 0 {
			sys := connector.SystemBudgetRef(t.Ref)
			p.Rates[sys] = limiter.Rate{PerHour: m.SystemPerHour}
			p.Units[sys] = unit
			cost, err := m.Drift(connector.Configuration(t.Ref, t.Settings))
			switch {
			case err != nil:
				refusals = append(refusals, fmt.Sprintf("target %q: %v", t.Ref, err))
			case int64(cost) > p.BurstFor(sys) && p.BurstFor(sys) > 0:
				refusals = append(refusals, fmt.Sprintf("target %q: one drift comparison costs %d %s "+
					"and the connector's system budget holds at most %d at once, so no comparison "+
					"could ever be admitted — lower the spec's list_pages (D311)", t.Ref, cost, unit,
					p.BurstFor(sys)))
			}
		}
	}

	for _, name := range sortedKeys(budgetUnits) {
		byUnit := budgetUnits[name]
		if len(byUnit) < 2 {
			continue
		}
		var parts []string
		for _, u := range sortedKeys(byUnit) {
			parts = append(parts, fmt.Sprintf("%s by %v", u, byUnit[u]))
		}
		refusals = append(refusals, fmt.Sprintf("budget %q is drawn on in more than one unit (%s). "+
			"A budget is one bucket, and tokens of different units in one bucket are a number "+
			"with no meaning (D284)", name, strings.Join(parts, "; ")))
	}

	for _, src := range doc.Sources {
		t, ok := specs[src.TargetRef]
		if !ok {
			continue
		}
		cost, err := drivers[t.Kind].Meter().Poll(connector.Configuration(t.Ref, t.Settings))
		if err != nil {
			// An unpriceable poll is the connector's defect and quarantines it
			// (CheckMeter); reaching here means a price of zero.
			refusals = append(refusals, fmt.Sprintf("source %q: %v", t.Ref, err))
			continue
		}
		if burst := p.BurstFor(t.Ref); burst > 0 && int64(cost) > burst {
			refusals = append(refusals, fmt.Sprintf(
				"source %q: one poll costs %d %s and its budget holds at most %d at once "+
					"(burst), so it could never be admitted. Raise the target's burst or "+
					"rate_per_hr, or make the poll cheaper (for Fullstory events, "+
					"sessions_per_poll)", t.Ref, cost, p.Units[t.Ref], burst))
		}
	}

	if len(refusals) > 0 {
		sort.Strings(refusals)
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%d metering problem(s):\n  - %s", len(refusals), strings.Join(refusals, "\n  - ")))
	}
	sort.Strings(p.Notes)
	return p, nil
}

// BurstFor is the capacity of the bucket targetRef draws on — the SAME number
// the limiter will build (limiter.BurstOf), found through its budget. Zero
// means unmetered.
func (p *Plan) BurstFor(targetRef string) int64 {
	r, ok := p.Rates[targetRef]
	if !ok {
		return 0
	}
	if r.Budget == "" {
		return limiter.BurstOf(r)
	}
	for _, other := range p.Rates {
		if other.Budget == r.Budget && other.PerHour > 0 {
			return limiter.BurstOf(other)
		}
	}
	return 0
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
