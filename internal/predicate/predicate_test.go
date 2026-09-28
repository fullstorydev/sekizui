package predicate

import (
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
)

// TestHolds covers every operator, both outcomes, and the two edges that
// matter: an absent field is false (not an error), and a type mismatch is an
// error (not a false), because the second would make a rule stop matching in
// silence.
func TestHolds(t *testing.T) {
	payload := map[string]any{
		"ordinal": float64(7), "url": "/checkout", "ok": true,
		"user": map[string]any{"plan": "pro"},
	}
	for _, tc := range []struct {
		name string
		c    config.Condition
		want bool
	}{
		{"eq number", config.Condition{Path: "ordinal", Op: "eq", Value: float64(7)}, true},
		{"eq string miss", config.Condition{Path: "url", Op: "eq", Value: "/home"}, false},
		{"eq bool", config.Condition{Path: "ok", Op: "eq", Value: true}, true},
		{"in hit", config.Condition{Path: "url", Op: "in", Value: []any{"/cart", "/checkout"}}, true},
		{"in miss", config.Condition{Path: "url", Op: "in", Value: []any{"/cart"}}, false},
		{"exists nested", config.Condition{Path: "user.plan", Op: "exists"}, true},
		{"exists absent", config.Condition{Path: "user.email", Op: "exists"}, false},
		{"gt", config.Condition{Path: "ordinal", Op: "gt", Value: float64(5)}, true},
		{"gt equal", config.Condition{Path: "ordinal", Op: "gt", Value: float64(7)}, false},
		{"gte equal", config.Condition{Path: "ordinal", Op: "gte", Value: float64(7)}, true},
		{"lt", config.Condition{Path: "ordinal", Op: "lt", Value: float64(5)}, false},
		{"lte equal", config.Condition{Path: "ordinal", Op: "lte", Value: float64(7)}, true},
		{"absent is false", config.Condition{Path: "missing", Op: "eq", Value: "x"}, false},
	} {
		got, err := Holds(config.Predicate{tc.c}, payload)
		if err != nil || got != tc.want {
			t.Errorf("%s: Holds = %v, %v; want %v, nil", tc.name, got, err, tc.want)
		}
	}

	if _, err := Holds(config.Predicate{{Path: "url", Op: "gt", Value: float64(1)}}, payload); err == nil {
		t.Error("comparing a string field with gt answered without error; a rule would stop " +
			"matching silently when the schema and the data disagree")
	}
	if ok, _ := Holds(config.Predicate{
		{Path: "ordinal", Op: "gt", Value: float64(5)},
		{Path: "url", Op: "eq", Value: "/home"},
	}, payload); ok {
		t.Error("two conditions with one false held; conditions are ANDed")
	}
}
