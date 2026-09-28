package config

import (
	"strings"
	"testing"
)

// TestSharedBudgetMembersAgree — D208's rule, and D284's extension of it to the
// burst: a budget is ONE bucket, so its members agree about its size, and a
// member may not declare a field the bucket never reads.
func TestSharedBudgetMembersAgree(t *testing.T) {
	member := func(ref string, rate, burst uint32) TargetSpec {
		return TargetSpec{Ref: ref, Limits: &TargetLimits{Budget: "fs", RatePerHr: rate, Burst: burst}}
	}
	for _, tc := range []struct {
		name    string
		targets []TargetSpec
		want    string // "" = accepted
	}{
		{"one rate, one burst", []TargetSpec{member("a", 100, 20), member("b", 100, 20)}, ""},
		{"one rate, both derived", []TargetSpec{member("a", 100, 0), member("b", 100, 0)}, ""},
		{"a rate-less member draws on the rated one", []TargetSpec{member("a", 100, 20), member("b", 0, 0)}, ""},
		{"rates disagree", []TargetSpec{member("a", 100, 0), member("b", 500, 0)}, "rate_per_hr 100"},
		{"bursts disagree", []TargetSpec{member("a", 100, 10), member("b", 100, 100)}, "burst 10"},
		{"declared beside derived", []TargetSpec{member("a", 100, 10), member("b", 100, 0)}, "none (derived from the rate)"},
		{"a burst nothing reads", []TargetSpec{member("a", 100, 10), member("b", 0, 30)}, "this burst is never read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p problems
			(&Document{Targets: tc.targets}).validateBudgets(&p)
			got := strings.Join(p, "\n")
			switch {
			case tc.want == "" && got != "":
				t.Errorf("an agreeing budget was refused: %s", got)
			case tc.want != "" && !strings.Contains(got, tc.want):
				t.Errorf("want a refusal containing %q, got %q", tc.want, got)
			}
		})
	}
}
