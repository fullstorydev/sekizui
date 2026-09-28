package conformance

import (
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// RunRefiner is the mandatory suite for a connector that implements
// connector.Refiner (D317). A connector's rules are imposed by a deployment
// that did not write them, onto agents that never asked, so the least the
// connector owes is that its file parses in the closed vocabulary and every
// rule refines and writes its OWN types (D279, D299, D300).
//
// **THE SAME CHECKS A DEPLOYMENT MAKES, NOT A COPY.** The file is read by
// `config.ParseReflexes`, the boot's parser, and ownership is judged by
// `schemareg.ForDeployment` with this driver alone — so a connector that passes
// here cannot be quarantined at boot for its rules, and one quarantined there
// cannot pass here.
func RunRefiner(t *testing.T, d connector.Driver) {
	t.Helper()
	rf, ok := d.(connector.Refiner)
	if !ok {
		t.Fatalf("RunRefiner was called for %q, which does not implement connector.Refiner", d.Kind())
	}
	runRefinerParses(t, d.Kind(), rf)
	runRefinerOwnsItsTypes(t, d)
}

// runRefinerParses: the file loads in the closed vocabulary, every rule under
// the connector's kind.
func runRefinerParses(t *testing.T, kind string, rf connector.Refiner) {
	t.Helper()
	t.Run("the shipped rules parse in the closed vocabulary", func(t *testing.T) {
		rules, err := config.ParseReflexes(rf.Reflexes())
		if err != nil {
			t.Fatalf("reflexes.yaml does not load: %v\n\nThe vocabulary is Sekizui's and closed (D300): "+
				"`where`, one `preceded_by` and one `followed_by`, and exactly one of list, count or first", err)
		}
		if len(rules) == 0 {
			t.Error("the connector is a Refiner and ships no rules — drop the method, or ship one")
		}
		for _, r := range rules {
			if !strings.HasPrefix(r.Name, kind+".") {
				t.Errorf("rule %q is not named under %q", r.Name, kind+".")
			}
		}
	})
}

// runRefinerOwnsItsTypes: every rule refines and writes the connector's own
// types, judged by the boot's own registry.
func runRefinerOwnsItsTypes(t *testing.T, d connector.Driver) {
	t.Helper()
	t.Run("every rule refines and writes the connector's own types", func(t *testing.T) {
		reg, err := schemareg.ForDeployment(&config.Document{}, map[string]connector.Driver{d.Kind(): d})
		if err != nil {
			t.Fatalf("the connector's schemas do not load: %v", err)
		}
		if faults, _ := reg.QuarantineOf(d.Kind()); faults != "" {
			t.Errorf("a deployment would QUARANTINE this connector: %s\n\nA rule reads a type one of your "+
				"actions returns and writes a seiren type your schemas.yaml declares — one type, one owner (D279, D299)",
				faults)
		}
	})
}
