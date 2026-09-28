package conformance

import (
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// runMeterSound requires the connector's meter to be one the spine can price
// every call and every poll with, before sending it (D284).
//
// **THE SAME VERDICT THE BOOT REACHES** — read from `schemareg.ForDeployment`,
// the one place a quarantine is decided — so passing here means the meter
// cannot be why a deployment quarantines this connector.
func runMeterSound(t *testing.T, d connector.Driver) {
	t.Helper()
	t.Run("the meter can price every call and poll before it is sent", func(t *testing.T) {
		reg, err := schemareg.ForDeployment(&config.Document{}, map[string]connector.Driver{d.Kind(): d})
		if err != nil {
			t.Fatalf("the connector's registry did not build: %v", err)
		}
		if _, problems := reg.QuarantineOf(d.Kind()); len(problems) > 0 {
			t.Errorf("the meter is not sound, and a deployment would QUARANTINE this connector:\n  - %s\n\n"+
				"Return a connector.Meter from Meter(). Calls-metered and not a Source: the zero value "+
				"is sound. A Source: set PollCost to the WORST CASE of one poll — every upstream "+
				"request it can make. Any unit other than calls: set DefaultPerHour and ActionCost, "+
				"because the deployment's universal default is a calls rate",
				strings.Join(problems, "\n  - "))
		}
	})
}
