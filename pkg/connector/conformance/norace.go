//go:build !race

package conformance

// raceEnabled is false in an ordinary build. See race.go.
const raceEnabled = false
