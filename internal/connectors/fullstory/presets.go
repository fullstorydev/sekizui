package fullstory

import (
	_ "embed"
	"encoding/json"
	"slices"
	"strings"
	"sync"

	"github.com/fullstorydev/sekizui/internal/apiref"
)

// presetsYAML is the connector's suggested presets (D327) — embedded so boot can
// compare a deployment's copy with the vendor's current suggestion, never so a
// grant can expand from it. See connector.Presetter.
//
//go:embed presets.yaml
var presetsYAML []byte

// SuggestedPresets implements connector.Presetter.
func (d *Driver) SuggestedPresets() []byte { return presetsYAML }

// vendorLevels are Fullstory's documented permission levels, least privileged
// first — each operation's `x-fullstory-permission-level`, recorded in the
// reference snapshot as `permission:` (D304).
//
//nolint:gochecknoglobals // immutable vendor vocabulary
var vendorLevels = []string{"Standard", "Architect", "Admin"}

// VendorLevels implements connector.Leveled.
func (d *Driver) VendorLevels() []string { return slices.Clone(vendorLevels) }

// handOperations are the operations each hand-built action calls. A poll reads
// the session list and each session's context, so it needs the higher of the
// two levels.
//
//nolint:gochecknoglobals // immutable, fixed at compile time
var handOperations = map[string][]endpoint{
	ActionSessionEvents: {epSessionContext},
	ActionCreateEvent:   {epCreateEvent},
	ActionUpsertUser:    {epUpsertUser},
	ActionPoll:          {epListSessions, epSessionContext},
}

// ActionLevel implements connector.Leveled: the level the reference snapshot
// records for the action's operation, from the same embedded contracts the
// derived actions are built from — one source for the grading and the surface.
func (d *Driver) ActionLevel(action string) (string, bool) {
	levels, err := operationLevels()
	if err != nil {
		return "", false
	}
	if eps, hand := handOperations[action]; hand {
		best := -1
		for _, ep := range eps {
			i := slices.Index(vendorLevels, levels[ep.method+" "+ep.template])
			if i < 0 {
				return "", false
			}
			best = max(best, i)
		}
		return vendorLevels[best], true
	}
	derived, err := apiActions()
	if err != nil {
		return "", false
	}
	for _, a := range derived {
		if a.spec.Name == action {
			l := a.op.Permission
			return l, slices.Contains(vendorLevels, l)
		}
	}
	return "", false
}

// operationLevels maps "METHOD /path" to the vendor level for every embedded
// contract, hand-built operations included.
var operationLevels = sync.OnceValues(func() (map[string]string, error) { //nolint:gochecknoglobals // derived once
	entries, err := contractFS.ReadDir("reference/2026-09/contracts")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := contractFS.ReadFile("reference/2026-09/contracts/" + e.Name())
		if err != nil {
			return nil, err
		}
		var op apiref.Operation
		if err := json.Unmarshal(raw, &op); err != nil {
			return nil, err
		}
		out[op.Key()] = op.Permission
	}
	return out, nil
})
