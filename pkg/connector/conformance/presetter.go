package conformance

import (
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/grantcheck"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// RunPresetter is the mandatory suite for a connector that implements
// connector.Presetter (D327). A deployment drops the connector's presets.yaml
// into its config directory and grants name them, so the least the connector
// owes is that the file is a fragment a deployment can use as it stands, that
// every preset names only the connector's own actions, and that every
// `mirrors:` claim holds against the connector's own grading.
//
// **THE SAME CHECKS A DEPLOYMENT MAKES, NOT A COPY** (RunRefiner's rule). The
// file is read by `config.ParsePresets`, the parse a deployment's copy gets, and
// judged by `grantcheck.PresetMisses`, the rule boot applies — so a connector
// that passes here cannot have its presets refused at boot, and an out-of-tree
// author (D35), who has this suite and not the in-tree folder check, finds out
// here rather than at somebody's deploy.
func RunPresetter(t *testing.T, d connector.Driver) {
	t.Helper()
	p, ok := d.(connector.Presetter)
	if !ok {
		t.Fatalf("RunPresetter was called for %q, which does not implement connector.Presetter", d.Kind())
	}
	runPresetterParses(t, d.Kind(), p)
	runPresetterHoldsItsClaims(t, d, p)
}

// runPresetterParses: the file is a fragment declaring presets and nothing
// else, and every preset is named under the connector's kind.
func runPresetterParses(t *testing.T, kind string, p connector.Presetter) {
	t.Helper()
	t.Run("the suggested presets are a fragment a deployment can drop in", func(t *testing.T) {
		presets, err := config.ParsePresets(p.SuggestedPresets())
		if err != nil {
			t.Fatalf("presets.yaml does not load: %v\n\nIt is a config FRAGMENT: `presets:` and nothing "+
				"else, each preset with a dotted name, an `explain:` and a fixed list of actions (D327)", err)
		}
		if len(presets) == 0 {
			t.Error("the connector is a Presetter and suggests no presets — drop the method, or suggest one")
		}
		for _, ps := range presets {
			if !strings.HasPrefix(ps.Name, kind+".") {
				t.Errorf("preset %q is not named under %q; a deployment's own presets share the namespace, "+
					"and a connector's must say whose they are", ps.Name, kind+".")
			}
		}
	})
}

// runPresetterHoldsItsClaims: every action is the connector's own, and every
// `mirrors:` claim holds against the connector's connector.Leveled grading.
func runPresetterHoldsItsClaims(t *testing.T, d connector.Driver, p connector.Presetter) {
	t.Helper()
	t.Run("every preset names your actions and holds its mirrors claim", func(t *testing.T) {
		presets, err := config.ParsePresets(p.SuggestedPresets())
		if err != nil {
			t.Skipf("the file does not load; the parse arm says why")
		}
		for _, miss := range grantcheck.PresetMisses(presets, map[string]connector.Driver{d.Kind(): d}, nil) {
			t.Error(miss)
		}
	})
}
