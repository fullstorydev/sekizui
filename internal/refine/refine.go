// Package refine computes a SEIREN (精錬) — the third tier, silver refined by a
// connector's `refines:` rules — over the rows of ONE result (D297-D301, D317).
//
// **PURE, AND A LEAF, BECAUSE THAT IS THE GUARANTEE.** P4's engine only derives
// (D317): no lookup, no call, no publish. It holds rules and nothing else — no
// Enforcer, no bus, no recorder, no pool — so "a read cannot trigger a write"
// is a property of its import graph, which a test holds, rather than of the
// rules someone configured. The Projector has the same shape for the same
// reason (D248, D269). Lookups are P5's, and will arrive as a separate type an
// operator can review on its own (D297 ruling 3).
//
// **DETERMINISTIC, BECAUSE REPLAY RESTS ON IT (D298, D300).** Rows are sorted by
// the input type's time path, ties broken by their position in the response —
// the vendor's order is never trusted — and every output is ordered by rule,
// not by map iteration. The same rows in any order give the same seiren. A time
// that does not parse is an ERROR, never a false (D42): a rule that silently
// stops pairing is the failure this repository keeps refusing.
//
// DESIGN.md references: §4.11.8, D22, D63, D263, D297, D298, D300, D317.
package refine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/internal/predicate"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Seiren is what the rules produced for one result — the engine's half of the
// wire's `Seiren` message.
type Seiren struct {
	// Type is the seiren type every applied rule writes `into` (boot refuses
	// two types for one target, input type and audience).
	Type string

	// Value holds one key per rule that ran and matched. A `first` that found
	// nothing writes no key: "no login" is an absent key read with `Window`.
	Value map[string]any

	// Window is the span of rows the seiren was computed over.
	Window Window

	// Gaps names each key the seiren could not give in full, and why — so a
	// partial seiren never reads as complete (D300, D317).
	Gaps []Gap

	// Rules names every rule that ran, sorted.
	Rules []string
}

// Window states what the seiren covers (D300): the first and last event time
// in the result, and whether the result was cut short — Generate Context
// returns a session's LAST events, so "no login in these 200 events" must not
// read as "no login in this session".
type Window struct {
	FirstEventTime string
	LastEventTime  string
	Truncated      bool
}

// GapKind is what a gap means for its key.
type GapKind int

const (
	// GapUnavailable: the key is ABSENT — the rule could not run.
	GapUnavailable GapKind = iota + 1
	// GapTruncated: the key is PRESENT and PARTIAL — a limit kept fewer items
	// than there were (CONTRACTS 146).
	GapTruncated
)

// Gap is one key the seiren could not give in full.
type Gap struct {
	Key    string
	Kind   GapKind
	Reason string
}

// Withheld reports whether the caller's lens withholds a path of the input
// type, and names the lens. Nil withholds nothing.
type Withheld func(path string) (lens string, withheld bool)

// For selects the refinements imposed on principal for target's results of
// type typ, in configuration order. Audience patterns match as a lens's
// `applies_to` does: exact, or a trailing star (shin's coversPrincipal).
func For(rs []schemareg.Refinement, target, principal, typ string) []schemareg.Refinement {
	var out []schemareg.Refinement
	for _, r := range rs {
		if r.Target == target && r.Rule.Refines == typ && AudienceCovers(r.For, principal) {
			out = append(out, r)
		}
	}
	return out
}

// AudienceCovers reports whether a refinement's `for:` reaches principal —
// exported so Describe answers with the engine's own reading (D302).
func AudienceCovers(patterns []string, principal string) bool {
	for _, p := range patterns {
		if prefix, star := strings.CutSuffix(p, "*"); p == principal || (star && strings.HasPrefix(principal, prefix)) {
			return true
		}
	}
	return false
}

// row is one input row with its parsed time and response position.
type row struct {
	data map[string]any
	at   time.Time
	pos  int
}

// Refine computes the seiren over rows — the WHOLE result, before any paging
// or response budget, already shaped and lensed for the caller (D297, D300).
// It returns nil when rs is empty: no rule, no seiren.
func Refine(rs []schemareg.Refinement, rows []map[string]any, truncated bool, withheld Withheld) (*Seiren, error) {
	const op = "refine.Refine"
	if len(rs) == 0 {
		return nil, nil
	}
	timePath := rs[0].TimePath
	sorted := make([]row, 0, len(rows))
	for i, data := range rows {
		raw, ok := predicate.Lookup(data, timePath)
		str, isStr := raw.(string)
		if !ok || !isStr {
			return nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"row %d carries no %q string; a refines rule sorts by it, and a row it cannot place would "+
					"silently fall out of every sequence (D42)", i, timePath))
		}
		at, err := schemareg.ParseDateTime(str)
		if err != nil {
			return nil, fault.Wrap(fault.KindInvalidArgument, op, fmt.Sprintf(
				"row %d's %q is %q, not an RFC 3339 date-time — an error, never a false (D42)", i, timePath, str), err)
		}
		sorted = append(sorted, row{data: data, at: at, pos: i})
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].at.Equal(sorted[j].at) {
			return sorted[i].at.Before(sorted[j].at)
		}
		return sorted[i].pos < sorted[j].pos
	})

	out := &Seiren{Type: rs[0].Rule.Into, Value: map[string]any{}, Window: Window{Truncated: truncated}}
	if len(sorted) > 0 {
		first, _ := predicate.Lookup(sorted[0].data, timePath)
		last, _ := predicate.Lookup(sorted[len(sorted)-1].data, timePath)
		out.Window.FirstEventTime, out.Window.LastEventTime = first.(string), last.(string)
	}

	for _, r := range rs {
		rule := r.Rule
		if lens, path, blocked := blockedBy(rule, timePath, withheld); blocked {
			out.Gaps = append(out.Gaps, Gap{Key: rule.Key, Kind: GapUnavailable, Reason: fmt.Sprintf(
				"rule %s reads %s, which lens %s withholds from this caller", rule.Name, path, lens)})
			continue
		}
		v, wrote, cut, err := run(rule, sorted)
		if err != nil {
			return nil, fault.Wrap(fault.KindInvalidArgument, op, "rule "+rule.Name, err)
		}
		if wrote {
			out.Value[rule.Key] = v
		}
		if cut != "" {
			out.Gaps = append(out.Gaps, Gap{Key: rule.Key, Kind: GapTruncated, Reason: cut})
		}
		out.Rules = append(out.Rules, rule.Name)
	}
	sort.Strings(out.Rules)
	sort.Slice(out.Gaps, func(i, j int) bool { return out.Gaps[i].Key < out.Gaps[j].Key })
	return out, nil
}

// blockedBy reports the first path the rule reads that the caller's lens
// withholds — the unit is the RULE (D300): a field withheld from a path it
// never reads does not touch it.
func blockedBy(rule config.RefineRule, timePath string, withheld Withheld) (lens, path string, blocked bool) {
	if withheld == nil {
		return "", "", false
	}
	for _, p := range rule.ReadPaths(timePath) {
		if lens, w := withheld(p); w {
			return lens, p, true
		}
	}
	return "", "", false
}

// match is one selected row and its pairings.
type match struct {
	row      row
	pairs    map[string]paired // by `as`, only those that held
	declared map[string]bool   // every `as` the rule declares, held or not
}

type paired struct {
	row      row
	duration float64 // seconds, millisecond precision
}

// run returns the key's value, whether it was written, and — when a limit
// kept fewer items than there were — the reason, for a TRUNCATED gap.
func run(rule config.RefineRule, rows []row) (any, bool, string, error) {
	declared := map[string]bool{}
	for _, pr := range []*config.Pairing{rule.PrecededBy, rule.FollowedBy} {
		if pr != nil {
			declared[pr.As] = true
		}
	}
	var matches []match
	for i, rw := range rows {
		ok, err := predicate.Holds(rule.Where, rw.data)
		if err != nil {
			return nil, false, "", err
		}
		if !ok {
			continue
		}
		m := match{row: rw, pairs: map[string]paired{}, declared: declared}
		for _, side := range []struct {
			pr   *config.Pairing
			step int
		}{{rule.PrecededBy, -1}, {rule.FollowedBy, +1}} {
			if side.pr == nil {
				continue
			}
			p, found, err := nearest(rows, i, side.step, side.pr)
			if err != nil {
				return nil, false, "", err
			}
			if found {
				m.pairs[side.pr.As] = p
			}
		}
		matches = append(matches, m)
	}

	switch {
	case rule.List != nil:
		items := make([]any, 0, min(len(matches), rule.List.Limit))
		for _, m := range matches {
			if len(items) == rule.List.Limit {
				break
			}
			items = append(items, carry(m, rule.List.Carry))
		}
		var cut string
		if len(matches) > rule.List.Limit {
			cut = fmt.Sprintf("kept the first %d of %d items (limit %d)", rule.List.Limit, len(matches), rule.List.Limit)
		}
		return items, true, cut, nil
	case rule.Count != nil:
		groups, total := count(matches, rule.Count)
		var cut string
		if total > rule.Count.Limit {
			cut = fmt.Sprintf("kept the %d most frequent of %d groups (limit %d)", rule.Count.Limit, total, rule.Count.Limit)
		}
		return groups, true, cut, nil
	case rule.First != nil:
		for _, m := range matches {
			if len(m.pairs) == len(declared) { // EVERY declared pairing held
				return carry(m, rule.First.Carry), true, "", nil
			}
		}
		return nil, false, "", nil
	}
	return nil, false, "", fmt.Errorf("the rule declares no output shape, which boot refuses")
}

// nearest scans from rows[i] in one direction for the closest row matching the
// pairing's `where`, stopping once past `within_s`. Rows are time-sorted, so
// the first beyond the window ends the scan.
func nearest(rows []row, i, step int, pr *config.Pairing) (paired, bool, error) {
	var within time.Duration
	if w, ok := pr.WithinS.(float64); ok {
		within = time.Duration(w * float64(time.Second))
	}
	for j := i + step; j >= 0 && j < len(rows); j += step {
		gap := rows[j].at.Sub(rows[i].at)
		if gap < 0 {
			gap = -gap
		}
		if within > 0 && gap > within {
			return paired{}, false, nil
		}
		ok, err := predicate.Holds(pr.Where, rows[j].data)
		if err != nil {
			return paired{}, false, err
		}
		if ok {
			return paired{row: rows[j], duration: float64(gap.Milliseconds()) / 1000}, true, nil
		}
	}
	return paired{}, false, nil
}

// carry builds one output object: each carried path set at its own dotted
// place, a paired row's fields under its `as` name, `<as>.duration_s` the gap.
// An absent value is left out, never written as null (D63).
func carry(m match, paths []string) map[string]any {
	obj := map[string]any{}
	for _, p := range paths {
		if v, ok := valueOf(m, p); ok {
			setPath(obj, p, v)
		}
	}
	return obj
}

func valueOf(m match, path string) (any, bool) {
	head, rest, nested := strings.Cut(path, ".")
	if nested && m.declared[head] {
		pr, held := m.pairs[head]
		switch {
		case !held:
			return nil, false // the pairing did not hold, so nothing it carries exists
		case rest == "duration_s":
			return pr.duration, true
		default:
			return predicate.Lookup(pr.row.data, rest)
		}
	}
	return predicate.Lookup(m.row.data, path)
}

func setPath(obj map[string]any, path string, v any) {
	segs := strings.Split(path, ".")
	cur := obj
	for _, s := range segs[:len(segs)-1] {
		next, ok := cur[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[s] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = v
}

// count groups the matches by their `by` values, most frequent first, ties by
// the values themselves, so the order is a function of the data alone.
func count(matches []match, spec *config.RefineCount) (groups []any, total int) {
	type bucket struct {
		key   string
		obj   map[string]any
		count int
	}
	byKey := map[string]*bucket{}
	for _, m := range matches {
		obj := carry(m, spec.By)
		parts := make([]string, len(spec.By))
		for i, p := range spec.By {
			if v, ok := valueOf(m, p); ok {
				parts[i] = fmt.Sprintf("%v", v)
			} else {
				parts[i] = "\x00" // absent sorts before any value, and is its own bucket
			}
		}
		k := strings.Join(parts, "\x1f")
		if b, ok := byKey[k]; ok {
			b.count++
			continue
		}
		byKey[k] = &bucket{key: k, obj: obj, count: 1}
	}
	buckets := make([]*bucket, 0, len(byKey))
	for _, b := range byKey {
		buckets = append(buckets, b)
	}
	sort.Slice(buckets, func(i, j int) bool {
		if buckets[i].count != buckets[j].count {
			return buckets[i].count > buckets[j].count
		}
		return buckets[i].key < buckets[j].key
	})
	out := make([]any, 0, min(len(buckets), spec.Limit))
	for _, b := range buckets {
		if len(out) == spec.Limit {
			break
		}
		b.obj["count"] = b.count
		out = append(out, b.obj)
	}
	return out, len(buckets)
}
