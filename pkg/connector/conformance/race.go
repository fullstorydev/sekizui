//go:build race

package conformance

// raceEnabled reports whether the race detector is compiled in.
//
// **A BUILD TAG IS THE ONLY WAY TO ASK, and the statelessness arm needs the
// answer (D218).** Half of what that arm proves belongs to the detector: it
// drives every tenant's call at once and checks each one came back with its own
// tenant's answer, which catches a driver that HOLDS a credential — and a
// driver that merely RACES on an unsynchronised field can produce correct
// answers on a quiet laptop and wrong ones under load.
//
// So the arm REFUSES rather than skips when this is false. A skipped arm in a
// suite D167 made mandatory is an arm nobody notices missing, which is the
// failure this package exists to prevent one level down.
const raceEnabled = true
