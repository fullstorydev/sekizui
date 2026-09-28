package gateway

import (
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// TestARowDroppedAtShapingMakesEveryRuleUnavailable holds D300's row rule:
// a lens withholds fields, and a ROW removed from under a sequence would
// silently falsify it — so when shaping dropped any row, no rule runs and the
// seiren says why. Fullstory cannot reach this through the acceptance run (its
// family admits unknown kinds as open, so shaping drops none), which is why it
// is held here.
func TestARowDroppedAtShapingMakesEveryRuleUnavailable(t *testing.T) {
	rule := func(name, key string) schemareg.Refinement {
		return schemareg.Refinement{Target: "fs:t", For: []string{"agent:a"}, TimePath: "event_time",
			Rule: config.RefineRule{Name: name, Refines: "fs.event.v1", Into: "fs.context.v1", Key: key}}
	}
	s := &Server{refinements: []schemareg.Refinement{rule("fs.path", "path"), rule("fs.errors", "errors")}}
	got, err := s.seirenFor("fs:t", shin.Request{Principal: "agent:a", Type: "fs.event.v1"},
		[]map[string]any{{"event_time": "2026-09-24T19:28:49.934Z"}}, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetValue() != nil || len(got.GetRules()) != 0 || len(got.GetGaps()) != 2 {
		t.Fatalf("a result with a dropped row produced %v; want no value and both rules unavailable", got)
	}
	for _, u := range got.GetGaps() {
		if u.GetKind() != sekizuiv1.SeirenGapKind_SEIREN_GAP_KIND_UNAVAILABLE ||
			!strings.Contains(u.GetReason(), "not admitted at shaping") {
			t.Errorf("%s: reason %q", u.GetKey(), u.GetReason())
		}
	}
}
