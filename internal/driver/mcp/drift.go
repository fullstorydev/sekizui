// Package mcp is the generic MCP driver: one implementation, N servers (D45).
//
// **THE FIRST DRIVER WHOSE ACTION SET COMES FROM CONFIGURATION RATHER THAN
// CODE** (§4.9a.4). `Actions()` for `jira` is fixed at compile time; for `mcp` it
// varies per deployment, derived from the vetted spec in `config.Document`
// (D46, D192). That is not a contract violation — the definition-of-done's
// "`Actions()` matches what is implemented, exactly" holds trivially against a
// PINNED spec, and is unholdable against a live tool list that changes under you.
//
// **SEKIZUI IS A CLIENT HERE, NOT A SERVER.** D3 dropped MCP inbound; this is the
// efferent path, calling out to somebody else's server through the governance
// layer. Nothing in this package serves MCP.
//
// **THE PROTOCOL IS TAKEN FROM THE SPECIFICATION, NOT FROM RECALL** — JSON-RPC
// 2.0, `tools/list` with cursor pagination, `tools/call` with a `content` array
// and optional `structuredContent`, and TWO distinct error mechanisms that a
// naive driver collapses into one. Three things it says are worth repeating here
// because they shaped the code:
//
//  1. **`tools/list` IS PAGINATED** (`nextCursor`). A client that ignores it sees
//     a PARTIAL tool list — which for drift detection is worse than useless: an
//     unvetted tool on page two is invisible, and every vetted tool that happens
//     to sit there gets reported as withdrawn.
//  2. **Protocol errors and tool-execution errors are different things.** A
//     JSON-RPC `error` means the request was wrong; `result.isError: true` means
//     the tool RAN and failed, and the spec calls that actionable feedback a
//     model can self-correct from. Both are DETERMINATE — the call was received
//     — which matters for D182.
//  3. **"Clients MUST consider tool annotations to be untrusted unless they come
//     from trusted servers."** That is D46's argument in the specification's own
//     words, and the reason `mutating` is a human's judgement here rather than a
//     vendor hint.
//
// DESIGN.md references: §4.9a, D3, D45, D46, D48, D49, D50, D51, D163, D182, D192.
package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/drift"
)

// THE DRIFT VOCABULARY LIVES IN `internal/drift` (D206).
//
// `Severity`, `drift.Finding` and `drift.Findings` were declared here, which was right while
// the driver's own `Health` was the only consumer. Steps 9 and 12 gave the
// answers three consumers outside the driver — the catalog withholds an action,
// readiness reports the target degraded, and anzen's dispatcher takes the
// `spec_drift` signal — and none of them may import a driver. What stayed is
// the part that is genuinely MCP: reading a live tool list and grading it
// against the vetted spec. What moved is what a grade MEANS.

// CompareToSpec grades the live tool list against the vetted spec (D48, D51).
//
// **A PURE FUNCTION OVER TWO LISTS, deliberately.** The comparison is the part
// with the judgement in it, and keeping it free of transport means every case in
// §4.9a.3's table and §4.9a.3a's state matrix is reachable from a test without a
// server — which is what makes the severities assertable rather than asserted.
//
// `server` is the segment for action naming (D49); it is passed rather than
// derived, because the spec's own `Server` field is what the grants use and a
// second derivation here would be a second source of truth (D155).
func CompareToSpec(server string, spec []SpecTool, live []LiveTool) drift.Findings {
	var out drift.Findings

	byName := make(map[string]LiveTool, len(live))
	for _, l := range live {
		byName[l.Name] = l
	}
	inSpec := make(map[string]bool, len(spec))

	for _, s := range spec {
		inSpec[s.Name] = true
		action := ActionName(server, s.Name)

		l, present := byName[s.Name]
		if !present {
			out = append(out, drift.Finding{
				Severity: drift.SeverityWithheld, Tool: s.Name, Action: action,
				Detail: "vetted and no longer offered by the server",
			})
			continue
		}

		// **`inputSchema` IS MANDATORY IN MCP**, so it is always available to
		// compare and always checked. This is the divergence that refuses.
		if !sameSchema(s.InputSchema, l.InputSchema) {
			out = append(out, drift.Finding{
				Severity: drift.SeverityRefused, Tool: s.Name, Action: action,
				Detail: "inputSchema diverges from the vetted one, so arguments " +
					"validated against the pinned schema would be sent to a server " +
					"expecting a different shape",
			})
		}

		out = append(out, compareOutputSchema(s, l, action)...)
	}

	// IN LIVE, NOT IN SPEC. Harmless by construction and the most interesting
	// line in the report: a vendor shipped something and nobody can call it yet.
	//
	// SORTED, so a report listing four unvetted tools reads the same on every
	// run — map iteration order would make it undiffable.
	var extra []string
	for name := range byName {
		if !inSpec[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		out = append(out, drift.Finding{
			Severity: drift.SeverityUnvetted, Tool: name,
			Detail: "offered by the server and absent from the vetted spec, so it is " +
				"not in Actions() and nothing can call it",
		})
	}
	return out
}

// compareOutputSchema is D51's state matrix.
//
// **ONLY `vendor` PROVENANCE IS COMPARED, and that is the whole reason
// provenance is pinned rather than inferred.** A `local` schema was authored by
// a maintainer from observed responses: the vendor never claimed it, so there is
// nothing to diverge FROM, and comparing one would manufacture incidents out of
// our own guesses — which is also what stops D168's authoring tool creating
// false alarms.
func compareOutputSchema(s SpecTool, l LiveTool, action string) drift.Findings {
	if s.OutputSchemaOrigin == "local" {
		return nil
	}

	switch {
	case len(s.OutputSchema) == 0 && len(l.OutputSchema) == 0:
		// The common case today. Nothing to check, and NOT drift — treating
		// absence as divergence would make the check useless against most real
		// servers.
		return nil

	case len(s.OutputSchema) == 0 && len(l.OutputSchema) > 0:
		// The vendor ADDED output typing. New information, not a break; the
		// authoring tool offers it for pinning on the next run (D168).
		return drift.Findings{{
			Severity: drift.SeverityInformational, Tool: s.Name, Action: action,
			Detail: "the server now publishes an outputSchema and the spec pins none; " +
				"new information rather than a break",
		}}

	case len(s.OutputSchema) > 0 && len(l.OutputSchema) == 0:
		// The vendor WITHDREW the advertisement. Logged loudly, and validation
		// continues against the pinned schema — dropping it would silently stop
		// checking output at all.
		return drift.Findings{{
			Severity: drift.SeverityInformational, Tool: s.Name, Action: action,
			Detail: "the server withdrew an outputSchema the spec pins as `vendor`; " +
				"still validating against the pinned one",
		}}

	case !sameSchema(s.OutputSchema, l.OutputSchema):
		return drift.Findings{{
			Severity: drift.SeverityInformational, Tool: s.Name, Action: action,
			Detail: "the vendor's outputSchema changed; a result conforming to the " +
				"pinned schema may no longer conform to theirs",
		}}
	}
	return nil
}

// sameSchema compares two JSON Schemas structurally.
//
// **BYTE COMPARISON WOULD BE WRONG AND WOULD FIRE CONSTANTLY.** A server is free
// to reorder keys, change whitespace, or re-marshal a schema between releases,
// and none of those changes what it accepts — so a naive `bytes.Equal` reports
// drift on a server that did nothing, and `drift.SeverityRefused` means an operator is
// woken for it. Unmarshalling into `any` and comparing the values normalises key
// order and formatting while keeping every semantic difference.
//
// An UNPARSEABLE schema counts as different, which is the fail-closed direction:
// we cannot confirm the shape a human approved is still in force.
func sameSchema(spec, live json.RawMessage) bool {
	if len(spec) == 0 && len(live) == 0 {
		return true
	}
	var a, b any
	if err := json.Unmarshal(spec, &a); err != nil {
		return false
	}
	if err := json.Unmarshal(live, &b); err != nil {
		return false
	}
	return normalised(a) == normalised(b)
}

// normalised renders a decoded JSON value with map keys in sorted order.
//
// `reflect.DeepEqual` would do for equality, and this is used instead so a
// difference can be PRINTED in a finding if that is ever wanted — and because a
// stable rendering is what makes the comparison testable against a literal.
func normalised(v any) string {
	var b strings.Builder
	writeNormalised(&b, v)
	return b.String()
}

func writeNormalised(b *strings.Builder, v any) {
	switch t := v.(type) {
	case map[string]any:
		b.WriteByte('{')
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(b, "%q:", k)
			writeNormalised(b, t[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeNormalised(b, e)
		}
		b.WriteByte(']')
	default:
		fmt.Fprintf(b, "%v", t)
	}
}

// ActionName builds the namespaced action for a tool (D49).
//
// `mcp.<server>.<tool>`, with `Kind()` staying `"mcp"`. ONE PLACE builds it,
// because the server segment also appears in every grant and in `config`'s
// contradiction check — three constructions of one name is how they come to
// disagree about a separator.
func ActionName(server, tool string) string {
	return mcpPrefix + server + "." + tool
}

// mcpPrefix is the action namespace. Kept in step with pkg/config's own copy by
// TestTheActionPrefixMatchesConfig, because the two packages cannot import each
// other and a silent divergence would make every grant unmatchable.
const mcpPrefix = "mcp."
