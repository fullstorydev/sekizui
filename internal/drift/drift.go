// Package drift holds the spec-drift vocabulary and the per-target state that
// three unrelated consumers read.
//
// **WHY THIS IS NOT IN THE DRIVER, WHICH IS WHERE IT STARTED (D206).** The
// severities and their responses were declared in `internal/driver/mcp`, and
// that was right while the only consumer was the driver's own `Health`. Steps 9
// and 12 give the answers three consumers OUTSIDE the driver — the catalog
// withholds an action, readiness reports a target degraded, and anzen's
// dispatcher takes a signal — none of which may import a driver: the catalog is
// driver-agnostic by construction (it reaches drivers through
// `connector.Driver`), and `cmd/sekizui` must not import the MCP driver until
// step 36 wires it.
//
// **AND THE SEVERITIES ARE GOVERNANCE RATHER THAN PROTOCOL.** D48 grades a
// divergence and D197 decides the response; neither says anything about
// JSON-RPC, `tools/list` or cursor pagination. What IS MCP-specific is the
// COMPARISON — reading a live tool list and grading it against a vetted spec —
// and that stays in `internal/driver/mcp`, which produces `drift.Findings` from
// it. The seam is: this package says what a divergence MEANS, the driver says
// what diverged.
//
// **DRIFT IS NOT AN MCP CONCEPT AT ALL, and the maintainer's framing is the reason this
// package is not called `mcpdrift`:** *"drift isn't only mcp specific, we will
// have other connectors driven by api, sdk or other sources, so drift is
// universal."* Any connector whose action set is pinned against something a
// vendor controls can diverge from it — a REST API whose OpenAPI document gains
// a required field, an SDK whose minor version renames an argument, a GraphQL
// schema that deprecates a mutation. The severities already say the right thing
// about all of them: a capability the vendor withdrew is `withheld`, an
// argument shape that changed under a vetted action is `refused`, something new
// nobody vetted is `unvetted`.
//
// What each connector supplies is its own COMPARISON — `Reporter` below is the
// seam — and what none of them supplies is a second opinion about what a
// divergence means. That is the divergent-lists failure `pkg/fault` cites
// Lexicon for, and the reason the vocabulary is one package rather than one per
// driver.
//
// **THE VOCABULARY AND THE SEAM ARE PUBLISHED SINCE D311** — `connector.Drifter`,
// `connector.DriftFinding`, `connector.DriftSeverity` in `pkg/connector` — because
// an out-of-tree connector could not implement a Reporter that returned an
// internal type. This package keeps the watcher and the store, and the names
// below are ALIASES, so every caller reads exactly as it did.
//
// DESIGN.md references: §4.9a.3, §4.9a.3a, D48, D50, D51, D197, D206, D311.
package drift

import "github.com/fullstorydev/sekizui/pkg/connector"

// Severity is connector.DriftSeverity (D48, D311).
type Severity = connector.DriftSeverity

// The vocabulary, from its one source in pkg/connector (§15q).
const (
	SeverityUnvetted      = connector.DriftUnvetted
	SeverityWithheld      = connector.DriftWithheld
	SeverityRefused       = connector.DriftRefused
	SeverityInformational = connector.DriftInformational
)

// Severities enumerates the vocabulary, sorted.
func Severities() []Severity { return connector.DriftSeverities() }

// Finding is connector.DriftFinding.
type Finding = connector.DriftFinding

// Findings is connector.DriftFindings.
type Findings = connector.DriftFindings

// Reporter is connector.Drifter: the optional interface a driver implements when
// its action set is pinned against a surface its vendor controls. Declared in
// pkg/connector since D311, so an out-of-tree connector can implement it.
type Reporter = connector.Drifter
