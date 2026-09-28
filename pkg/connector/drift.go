package connector

import (
	"context"
	"fmt"
	"sort"
)

// DRIFT, PUBLISHED (D311). A connector whose action set is pinned against
// something its vendor controls — an MCP server's tool list, an API reference,
// an SDK version — can diverge from it, and reports how by implementing
// Drifter. The vocabulary below says what a divergence MEANS; the connector
// says what diverged.
//
// **IT WAS `internal/drift` UNTIL D311, AND THAT MADE IT IN-TREE ONLY.** D35
// makes `pkg/` the surface an out-of-tree connector author builds against, and
// a Reporter returning `internal/drift.Findings` was an interface nobody outside
// this repository could implement — while the blueprint taught that a connector
// can do anything an in-tree one can. `internal/drift` keeps the watcher and the
// store, and aliases these names so its callers read as they did.
//
// DESIGN.md references: §4.9a.3, §4.9a.3a, D48, D50, D51, D197, D206, D311.

// DriftSeverity is how bad one divergence between the live surface and the
// vetted surface is (D48). FOUR SEVERITIES, NOT ONE LOG LINE: the cases differ
// in KIND — a supply-chain signal, a definition-of-done violation at runtime,
// and a dangerous one — not in degree.
type DriftSeverity string

// The vocabulary. Adding a severity is a code change and a review; a driver
// reporting one that is not here is REFUSED by the store, because an unknown
// severity answers false to every predicate and would read as a finding while
// acting as nothing.
const (
	// DriftUnvetted — live, and NOT in the vetted surface. HARMLESS BY
	// CONSTRUCTION: actions come from the vetted surface, so nothing can call
	// it. The supply-chain win made visible; it feeds the review queue.
	DriftUnvetted DriftSeverity = "unvetted"

	// DriftWithheld — vetted, and no longer live. The action is dropped from
	// the catalog: advertising it would send an agent at a call that fails.
	DriftWithheld DriftSeverity = "withheld"

	// DriftRefused — the INPUT shape of a vetted action diverges. The whole
	// target is refused: what a human approved is not what the vendor will act on.
	DriftRefused DriftSeverity = "refused"

	// DriftInformational — an OUTPUT-shape change worth knowing about (D51).
	// Never a refusal.
	DriftInformational DriftSeverity = "informational"
)

// driftSeverities is the one source (§15q).
//
//nolint:gochecknoglobals // immutable vocabulary, fixed at compile time
var driftSeverities = map[DriftSeverity]struct {
	refusesTarget, withholdsAction bool
	why                            string
}{
	DriftUnvetted: {why: "something the vendor offers that no human has vetted; not callable, " +
		"because actions come from the vetted surface"},
	DriftWithheld: {withholdsAction: true, why: "a vetted action the vendor no longer offers; " +
		"advertising it would send an agent at a call that fails"},
	DriftRefused: {refusesTarget: true, why: "the input shape a human approved is not the " +
		"one the vendor will act on"},
	DriftInformational: {why: "an output-shape change; never a refusal, because absence is " +
		"the common case and a local schema has nothing to diverge from"},
}

// Known reports whether s is in the vocabulary.
func (s DriftSeverity) Known() bool { _, ok := driftSeverities[s]; return ok }

// RefusesTarget reports whether this divergence makes the target unusable.
func (s DriftSeverity) RefusesTarget() bool { return driftSeverities[s].refusesTarget }

// WithholdsAction reports whether the specific action is dropped from the catalog.
func (s DriftSeverity) WithholdsAction() bool { return driftSeverities[s].withholdsAction }

// Explain returns the one-line rationale, for logs, readiness and the panel.
func (s DriftSeverity) Explain() string { return driftSeverities[s].why }

// DriftSeverities enumerates the vocabulary, sorted — so an assertion can range
// over the whole set and cover the severity somebody adds next year (§15q).
func DriftSeverities() []DriftSeverity {
	out := make([]DriftSeverity, 0, len(driftSeverities))
	for s := range driftSeverities {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DriftFinding is one divergence.
type DriftFinding struct {
	Severity DriftSeverity

	// Tool is the vendor's own name for the diverged thing, unqualified — a
	// tool, an endpoint, an operation.
	Tool string

	// Action is the namespaced Sekizui action, where one exists. Something the
	// vendor offers and nobody vetted has none, which is why it is harmless.
	Action string

	// Detail is what diverged, in one operator-readable clause.
	Detail string
}

func (f DriftFinding) String() string {
	if f.Action != "" {
		return fmt.Sprintf("%s: %s (%s) — %s", f.Severity, f.Tool, f.Action, f.Detail)
	}
	return fmt.Sprintf("%s: %s — %s", f.Severity, f.Tool, f.Detail)
}

// DriftFindings is the result of one comparison.
type DriftFindings []DriftFinding

// RefusesTarget reports whether any finding makes the target unusable. ASKED
// RATHER THAN COUNTED, so no caller gets the severity logic subtly different.
func (fs DriftFindings) RefusesTarget() bool {
	for _, f := range fs {
		if f.Severity.RefusesTarget() {
			return true
		}
	}
	return false
}

// Withheld returns the actions to drop from the catalog, sorted.
func (fs DriftFindings) Withheld() []string {
	var out []string
	for _, f := range fs {
		if f.Severity.WithholdsAction() && f.Action != "" {
			out = append(out, f.Action)
		}
	}
	sort.Strings(out)
	return out
}

// Of returns the findings at one severity.
func (fs DriftFindings) Of(s DriftSeverity) DriftFindings {
	var out DriftFindings
	for _, f := range fs {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

// Drifter is the OPTIONAL interface a driver implements when its action set is
// pinned against a surface its vendor controls (D311, formerly
// `internal/drift.Reporter`).
//
// **OPTIONAL AND TYPE-ASSERTED (GO-PRIMER §2.2)**: D35 forbids adding a required
// method to Driver, and a connector with nothing to diverge from is not asked.
//
// **A DRIFTER DECLARES WHAT ITS COMPARISONS COST, AND THEY ARE NOT BILLED TO
// CONSUMERS.** A comparison is an outbound call with the target's credential,
// so it is priced (`Meter.DriftCost`) and admitted like a poll — but charged to
// the target's SYSTEM budget (`Meter.SystemPerHour`), declared by the connector
// for itself, so agents never pay for Sekizui's own safety traffic (the maintainer,
// D311). The conformance suite's RunDrift holds a Drifter to both.
type Drifter interface {
	// Drift compares the live surface with the vetted one. It must only READ.
	//
	// An error means the ATTEMPT failed — unreachable, protocol fault,
	// cancelled — and is NOT drift: an outage is retryable, a divergence is not.
	// Findings AND an error is not a shape a caller handles; the error wins.
	Drift(ctx context.Context, t Target) (DriftFindings, error)
}
