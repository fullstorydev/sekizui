package actionset

import (
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

func testSet() *Set {
	doc := &config.Document{Targets: []config.TargetSpec{
		{Ref: "kata:alpha", Kind: kata.Kind},
		{Ref: "other:one", Kind: "fullstory"},
	}}
	return New(doc, map[string]connector.Driver{kata.Kind: kata.New()})
}

// TestCoversScopesByTheTargetsDriver is the property the catalog depends on and
// the one a flat action map makes easy to get wrong: `*` on a target must not
// reach another driver's actions.
func TestCoversScopesByTheTargetsDriver(t *testing.T) {
	s := testSet()

	all := s.Covers(config.CapabilitySpec{Action: "*", TargetRef: "kata:alpha"})
	if len(all) == 0 {
		t.Fatal("`*` on a kata target covered nothing")
	}
	for _, a := range all {
		if got := a[:5]; got != "kata." && got != "sekiz" {
			t.Errorf("`*` on a kata target covered %q, which is neither a kata action "+
				"nor a governed verb", a)
		}
	}

	// THE SAME PATTERN ON A TARGET WHOSE DRIVER IS NOT REGISTERED covers only
	// the governed verbs — never another driver's actions, which is the failure
	// a flat map invites.
	other := s.Covers(config.CapabilitySpec{Action: "*", TargetRef: "other:one"})
	for _, a := range other {
		if !verb.Is(a) {
			t.Errorf("`*` on a fullstory target covered %q with no fullstory driver "+
				"registered", a)
		}
	}
}

// TestALiteralCoversItselfOrNothing — the boot check's whole question.
func TestALiteralCoversItselfOrNothing(t *testing.T) {
	s := testSet()

	for _, tc := range []struct {
		action string
		want   int
	}{
		{"kata.create_issue", 1},
		{"kata.create_isue", 0}, // a typo
		{"sekizui.revoke_credential", 1},
		{"sekizui.revoke_everything", 0},
	} {
		got := s.Covers(config.CapabilitySpec{Action: tc.action, TargetRef: "kata:alpha"})
		if len(got) != tc.want {
			t.Errorf("%q covers %v, want %d action(s)", tc.action, got, tc.want)
		}
	}
}

// TestAnUnknownTargetCoversNoDriverAction — an invalid document must not be
// answered permissively. Boot refuses a grant naming an undeclared target, and
// widening the candidate set here would describe a deployment nobody can run.
func TestAnUnknownTargetCoversNoDriverAction(t *testing.T) {
	s := testSet()
	got := s.Covers(config.CapabilitySpec{Action: "kata.create_issue", TargetRef: "nope"})
	if len(got) != 0 {
		t.Errorf("an undeclared target ref covered %v", got)
	}
}

// TestAnEmptyTargetRefNarrowsNothing — `target_ref` is optional on a capability,
// and an absent one means the grant names no target rather than an impossible
// one.
func TestAnEmptyTargetRefNarrowsNothing(t *testing.T) {
	s := testSet()
	got := s.Covers(config.CapabilitySpec{Action: "kata.*"})
	if len(got) != len(kata.New().Actions()) {
		t.Errorf("`kata.*` with no target ref covers %d action(s), want %d",
			len(got), len(kata.New().Actions()))
	}
}

// TestDescribeHasTwoSourcesAndNoThird is D196: the identifier is not a
// description, so an action nothing describes reports false rather than its own
// name.
func TestDescribeHasTwoSourcesAndNoThird(t *testing.T) {
	s := testSet()

	if got, ok := s.Describe("kata.create_issue"); !ok || got == "kata.create_issue" {
		t.Errorf("a driver action described as %q (ok=%v)", got, ok)
	}
	if got, ok := s.Describe(verb.RevokeCredential); !ok || got == verb.RevokeCredential {
		t.Errorf("a governed verb described as %q (ok=%v)", got, ok)
	}
	if got, ok := s.Describe("kata.nothing"); ok {
		t.Errorf("an action nothing implements described as %q", got)
	}
}
