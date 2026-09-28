package bus

import (
	"testing"

	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/bus/conformance"
)

// TestConformance runs the published bus suite against the in-process driver,
// so the reference transport is held to exactly what an out-of-tree one is
// (D35, D260).
func TestConformance(t *testing.T) {
	conformance.Run(t, func(*testing.T) pkgbus.Bus { return New(quiet(), 8) })
}
