// Package predicate evaluates a reflex's `where` over an envelope's payload
// (D263).
//
// PRIVATE (D35), AND DELIBERATELY THE WHOLE EVALUATOR. Sekizui takes no Rego;
// a fork that wants a policy language replaces this package, and nothing else
// in the engine knows how a predicate is decided. No public seam is published
// until somebody needs one — an interface with one implementation is surface
// bought for a user who does not exist yet.
//
// NOT THE BOOT CHECKS. The operator vocabulary and value shapes are validated
// in pkg/config, and paths against the payload schema in schemareg (D42); by
// the time Holds runs, a condition is well-formed and its path is declared.
// What can still go wrong here is the PAYLOAD, and that is an error rather than
// a false, because a rule that silently stops matching is D42's named failure.
//
// DESIGN.md references: §4.5.1, §4.11, D42, D58, D262, D263.
package predicate

import (
	"fmt"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Holds reports whether every condition holds over payload. An empty predicate
// holds.
func Holds(p config.Predicate, payload map[string]any) (bool, error) {
	for i, c := range p {
		ok, err := holds(c, payload)
		if err != nil {
			return false, fault.Wrap(fault.KindInvalidArgument, "predicate.Holds",
				fmt.Sprintf("where[%d] (%s %s)", i, c.Path, c.Op), err)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func holds(c config.Condition, payload map[string]any) (bool, error) {
	v, present := Lookup(payload, c.Path)
	if c.Op == config.OpExists {
		return present, nil
	}
	if !present {
		// ABSENT IS FALSE, NOT AN ERROR, for every operator but exists: the
		// schema declares the field, and an optional field left out is the
		// payload saying "no", not a malformed one.
		return false, nil
	}
	switch c.Op {
	case config.OpEq:
		return equal(v, c.Value), nil
	case config.OpIn:
		list, _ := c.Value.([]any)
		for _, want := range list {
			if equal(v, want) {
				return true, nil
			}
		}
		return false, nil
	case config.OpPrefix:
		got, ok := v.(string)
		if !ok {
			return false, fmt.Errorf("the payload's %q is %T, not a string — `prefix` tests text, "+
				"and the schema and the data disagree", c.Path, v)
		}
		want, _ := c.Value.(string)
		return strings.HasPrefix(got, want), nil
	case config.OpGt, config.OpGte, config.OpLt, config.OpLte:
		got, ok := number(v)
		if !ok {
			return false, fmt.Errorf("the payload's %q is %T, not a number — the schema and "+
				"the data disagree, which a comparison must not paper over", c.Path, v)
		}
		want, _ := number(c.Value)
		switch c.Op {
		case config.OpGt:
			return got > want, nil
		case config.OpGte:
			return got >= want, nil
		case config.OpLt:
			return got < want, nil
		default:
			return got <= want, nil
		}
	}
	// Boot refuses an unknown operator; reaching here means validation was
	// bypassed, and answering false would be a silent non-match.
	return false, fmt.Errorf("unknown operator %q", c.Op)
}

// Lookup walks a dotted path into nested objects. EXPORTED because the reflex
// engine's debounce key is a payload path too, and a second walker would be a
// second answer to what `a.b` means (D264).
func Lookup(payload map[string]any, path string) (any, bool) {
	var cur any = payload
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// number normalises the numeric types a payload arrives in. A structpb payload
// is always float64; the others cover a payload built in Go before conversion.
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// equal compares numbers by value regardless of their Go type, and everything
// else exactly.
func equal(a, b any) bool {
	if x, ok := number(a); ok {
		y, ok := number(b)
		return ok && x == y
	}
	return a == b
}
