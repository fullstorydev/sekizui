package connector

// Presetter is a driver whose connector folder SUGGESTS presets (D327): named
// sets of its actions, each explaining itself and optionally stating the vendor
// level it mirrors.
//
// OPTIONAL, for the reason Refiner is: D35 forbids adding a required method to
// Driver, and a connector with no presets to suggest is not asked.
//
// **EMBEDDED FOR COMPARISON, NEVER AS A GRANT SOURCE.** Grants expand from the
// copy a deployment dropped into its own config directory (config.PresetSpec).
// This is the vendor's CURRENT suggestion, so boot can say when a preset the
// deployment runs has fallen behind or moved ahead of it — an informational
// finding. Reading grants from here instead would widen every grant naming a
// preset whenever a connector release added an action to it.
type Presetter interface {
	// SuggestedPresets returns the raw `presets.yaml` the connector folder
	// ships: a config fragment declaring `presets:` and nothing else.
	SuggestedPresets() []byte
}

// Leveled is a driver whose vendor grades its operations by permission level —
// Fullstory's Standard, Architect and Admin (D327).
//
// It lets boot hold a preset's `mirrors:` claim to the vendor's own grading
// without Sekizui knowing any vendor's vocabulary: the connector says which
// levels exist, in which order, and which one each action needs.
type Leveled interface {
	// VendorLevels are the vendor's levels, LEAST privileged first. A level
	// grants everything below it.
	VendorLevels() []string

	// ActionLevel is the level the vendor requires for action; false when the
	// connector cannot say, which a `mirrors:` claim then cannot survive.
	ActionLevel(action string) (level string, ok bool)
}
