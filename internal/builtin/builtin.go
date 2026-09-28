// Package builtin is the set of connectors this binary ships, built in one
// place (D279).
//
// **ONE LIST, BECAUSE TWO WOULD DRIFT.** The gateway registers these drivers,
// and the dev tap needs the same set to build the registry a deployment
// validates against — the connectors own their schemas now, so a registry
// without them knows none of their types. A second hand-written list in the
// tap is exactly the copy that goes stale the day a fifth connector lands.
package builtin

import (
	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/connectors/jira"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// Drivers builds every shipped connector. `pool` is the client pool each
// borrows from (D255); nil for a process that never calls out, like the tap's
// offline rehearsal. The MCP driver takes the document's vetted specs,
// because for MCP the spec IS the action set and the data schemas (D46, D279).
func Drivers(doc *config.Document, pool connector.ClientPool) []connector.Driver {
	return []connector.Driver{
		kata.New(kata.WithPool(pool)),
		fullstory.New(fullstory.WithPool(pool)),
		mcp.New(doc.MCPSpecs, mcp.WithPool(pool)),
		jira.New(jira.WithPool(pool)),
	}
}

// ByKind is Drivers keyed by each driver's own Kind.
func ByKind(doc *config.Document, pool connector.ClientPool) map[string]connector.Driver {
	out := map[string]connector.Driver{}
	for _, d := range Drivers(doc, pool) {
		out[d.Kind()] = d
	}
	return out
}
