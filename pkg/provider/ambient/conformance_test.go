package ambient_test

import (
	"testing"

	"github.com/fullstorydev/sekizui/pkg/provider/ambient"
	"github.com/fullstorydev/sekizui/pkg/provider/conformance"
)

// TestConformance runs the published Provider contract against this provider.
//
// NoMaterial IS SET, and it is the case that field exists for: workload identity
// means the platform authenticates and the SDK picks the identity up, so there is
// nothing for a broker to hold (§4.7.2's "n/a; the platform rotates"). Without
// the field the suite would have to choose between failing a correct provider and
// never checking that material arrives at all.
func TestConformance(t *testing.T) {
	conformance.Run(t, ambient.New(), []conformance.Case{
		{Name: "gcp workload identity", Ref: "ambient://gcp", NoMaterial: true},
	})
}
