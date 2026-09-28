package connector

import (
	"fmt"
	"regexp"
)

// UnitCalls is the one meter unit Sekizui assumes when a connector names none,
// and the only unit the deployment's universal default is expressed in (D284).
const UnitCalls = "calls"

// Meter is what a connector's upstream meters, and what a call costs in it
// (D171, D284).
//
// **THE HAND KNOWS HOW HOT A SURFACE IT CAN TOLERATE; THE SPINE DECIDES WHEN TO
// MOVE.** This is vendor knowledge — Jira counts calls, a warehouse bills bytes
// scanned — so it lives in the driver, beside the code that makes the calls.
// The BUDGET is the target's (`limits.rate_per_hr`, in this unit) and the
// CEILING is the deployment's (`-meter-ceiling <unit>=N`). The connector never
// enforces anything: the spine prices every call with these functions and
// takes the tokens before the call is sent.
//
// **THE UNIT IS AN OPEN VOCABULARY** (the maintainer's correction to D171): Sekizui cannot
// know every way an upstream charges, and enforcement is arithmetic in whatever
// unit is named. What must agree is the unit — a shared budget spanning two
// units is refused at boot.
//
// **THE ZERO VALUE IS A SOUND METER FOR A CALLS-METERED CONNECTOR WITHOUT A
// SOURCE**: one call costs one, and the deployment's universal default rate
// applies. Anything else must be declared, and `CheckMeter` says what.
type Meter struct {
	// Unit is what the upstream meters: "calls", "bytes_scanned", "records".
	// Empty means calls. Lower case, letters and underscores.
	Unit string

	// DefaultPerHour is the safe budget, in Unit, for a target that declares
	// none. Zero means the deployment's universal default — which is a CALLS
	// rate, so a connector declaring any other unit must set this.
	//
	// **ZERO IS THE HONEST ANSWER WHEN THE VENDOR PUBLISHES NO NUMBER.** A
	// default is knowledge (D67); a figure nobody documented is not.
	DefaultPerHour uint32

	// ActionCost prices one Execute or Query call, in Unit, BEFORE it is sent.
	// Nil means one per call — correct for calls, and refused for any other
	// unit, because only the connector knows what a call costs in bytes.
	ActionCost func(action string, args map[string]any) (uint64, error)

	// PollCost prices one Poll, in Unit, at WORST CASE — every upstream call
	// the poll can make, whether or not it makes them (D284). REQUIRED for a
	// driver that implements Source, whatever its unit: a poll that fans out
	// is exactly what a default of one would under-count. Takes the target
	// because what a poll does is often the target's declaration (Fullstory's
	// `poll: events` reads twenty sessions; unset, it reads one list).
	//
	// **NO REFUND.** The spine takes this many tokens and never gives any back
	// on the driver's say-so, because a refund is a channel through which a
	// driver that lies about what it spent wins budget back.
	PollCost func(t Configured) uint64

	// SystemPerHour is the connector's OWN allowance, in Unit, for Sekizui's
	// system traffic against one target — drift comparisons — charged to a
	// separate SYSTEM budget, never to the consumers' (the maintainer, D311): agents must
	// not pay for Sekizui's safety checks. REQUIRED for a Drifter, and refused
	// on anything else, because a budget for traffic that never happens is a
	// number nobody can check. The vendor still counts every call, so this is
	// accounting inside the vendor's quota (D52), not extra quota.
	SystemPerHour uint32

	// DriftCost prices one drift comparison, in Unit, at WORST CASE and before
	// it is sent (D284, D311) — every page a comparison may read. REQUIRED for a
	// Drifter. Takes the target because how much a comparison reads is often
	// the target's declaration (an MCP spec's `list_pages`).
	DriftCost func(t Configured) uint64
}

// Configured is the part of a target a PRICE may depend on: its ref and its
// settings — its reviewed configuration, and nothing resolved.
//
// **NARROWER THAN Target ON PURPOSE.** The spine prices a poll at boot, to
// refuse one that can never fit its budget, and again at admission, before
// anything is resolved. A Target cannot exist then without a credential, and
// building one without would weaken NewTarget's single-constructor guarantee
// for the sake of a price. So a price reads configuration, by construction —
// no pricing function can touch a credential. Target satisfies this.
type Configured interface {
	Ref() string
	Setting(key string) string
}

// Configuration is a Configured built from a target's declaration, for the
// spine's pricing. It carries no credential and cannot reach a driver call.
func Configuration(ref string, settings map[string]string) Configured {
	return configured{ref: ref, settings: settings}
}

type configured struct {
	ref      string
	settings map[string]string
}

func (c configured) Ref() string               { return c.ref }
func (c configured) Setting(key string) string { return c.settings[key] }

var unitPattern = regexp.MustCompile(`^[a-z][a-z_]*$`)

// UnitName is the meter's unit, with the empty default made explicit.
func (m Meter) UnitName() string {
	if m.Unit == "" {
		return UnitCalls
	}
	return m.Unit
}

// Cost prices one Execute or Query call. A declared cost of zero is refused
// rather than admitted free: nothing an upstream does costs nothing, and a zero
// would be a way past the budget.
func (m Meter) Cost(action string, args map[string]any) (uint64, error) {
	if m.ActionCost == nil {
		return 1, nil
	}
	c, err := m.ActionCost(action, args)
	if err != nil {
		return 0, err
	}
	if c == 0 {
		return 0, fmt.Errorf("the connector priced action %q at zero %s; a call is never free", action, m.UnitName())
	}
	return c, nil
}

// Poll prices one poll of t, or says why it cannot.
func (m Meter) Poll(t Configured) (uint64, error) {
	if m.PollCost == nil {
		return 0, fmt.Errorf("the connector declares no poll cost, so a poll of %q cannot be priced "+
			"before it is sent (D284)", t.Ref())
	}
	c := m.PollCost(t)
	if c == 0 {
		return 0, fmt.Errorf("the connector priced a poll of %q at zero %s; a poll is never free", t.Ref(), m.UnitName())
	}
	return c, nil
}

// Drift prices one drift comparison of t (D311), refusing an unpriceable one
// exactly as Poll does: a comparison is never free.
func (m Meter) Drift(t Configured) (uint64, error) {
	if m.DriftCost == nil {
		return 0, fmt.Errorf("the connector declares no drift cost, so a comparison of %q cannot be "+
			"priced before it is sent (D284, D311)", t.Ref())
	}
	c := m.DriftCost(t)
	if c == 0 {
		return 0, fmt.Errorf("the connector priced a comparison of %q at zero %s; a comparison is "+
			"never free", t.Ref(), m.UnitName())
	}
	return c, nil
}

// SystemBudgetRef is the limiter key of targetRef's SYSTEM budget — where drift
// comparisons are charged, apart from the consumers' budget (D311). One place
// names it, so the plan that builds the bucket and the gate that draws on it
// cannot disagree.
func SystemBudgetRef(targetRef string) string { return targetRef + "#system" }

// CheckMeter names what is unsound about a driver's meter (D284). Empty means
// sound. A connector with problems here is QUARANTINED (D282), and the
// published conformance suite runs the same check.
func CheckMeter(d Driver) []string {
	m := d.Meter()
	var problems []string
	if m.Unit != "" && !unitPattern.MatchString(m.Unit) {
		problems = append(problems, fmt.Sprintf("meter unit %q is not lower-case letters and underscores", m.Unit))
	}
	if m.UnitName() != UnitCalls {
		if m.DefaultPerHour == 0 {
			problems = append(problems, fmt.Sprintf("it is metered in %q and declares no DefaultPerHour; the "+
				"deployment's universal default is a CALLS rate and means nothing in %q, so a connector "+
				"with its own unit must say what is safe in it", m.UnitName(), m.UnitName()))
		}
		if m.ActionCost == nil {
			problems = append(problems, fmt.Sprintf("it is metered in %q and declares no ActionCost; one "+
				"per call is right only for calls", m.UnitName()))
		}
	}
	if _, isSource := d.(Source); isSource && m.PollCost == nil {
		problems = append(problems, "it implements Source and declares no PollCost; only the connector "+
			"knows how many upstream calls a poll makes, and a poll priced at one under-counts every "+
			"poll that fans out (D284)")
	}
	// A DRIFTER DECLARES ITS SYSTEM BUDGET AND ITS PRICE, AND NOTHING ELSE DOES
	// (D311). A comparison is an outbound call with the target's credential, so
	// it is priced and budgeted like a poll — in its own bucket.
	_, isDrifter := d.(Drifter)
	switch {
	case isDrifter && (m.SystemPerHour == 0 || m.DriftCost == nil):
		problems = append(problems, "it implements Drifter and does not declare both SystemPerHour and "+
			"DriftCost; a drift comparison is an outbound call with the target's credential, priced "+
			"before it is sent and charged to the connector's own system budget, never the consumers' (D311)")
	case !isDrifter && (m.SystemPerHour != 0 || m.DriftCost != nil):
		problems = append(problems, "it declares SystemPerHour or DriftCost and does not implement "+
			"Drifter; a system budget for comparisons that never happen is a number nobody can check (D311)")
	}
	return problems
}
