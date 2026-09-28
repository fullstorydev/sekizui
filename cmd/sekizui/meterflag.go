package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// meterCeilings is `-meter-ceiling unit=N`, repeatable: the deployment's
// ceiling per meter unit (D284).
//
// **A flag.Value, BECAUSE THE UNITS ARE NOT KNOWN WHEN THE FLAGS ARE.** The
// vocabulary is open (D171), so one flag per unit cannot be declared ahead of
// time; `flag.Var` calls Set once per occurrence, and a map collects them.
type meterCeilings map[string]uint32

func (m meterCeilings) String() string {
	units := make([]string, 0, len(m))
	for u := range m {
		units = append(units, u)
	}
	sort.Strings(units)
	parts := make([]string, len(units))
	for i, u := range units {
		parts[i] = fmt.Sprintf("%s=%d", u, m[u])
	}
	return strings.Join(parts, ",")
}

// Set parses one `unit=N`. A unit given twice is REFUSED rather than
// last-one-wins: two ceilings for one unit in a reviewed manifest is a mistake
// in one of them, and silently keeping the later is how the wrong one ships.
func (m meterCeilings) Set(v string) error {
	unit, n, ok := strings.Cut(v, "=")
	if !ok || unit == "" {
		return fmt.Errorf("want unit=N (e.g. calls=3600), got %q", v)
	}
	perHour, err := strconv.ParseUint(n, 10, 32)
	if err != nil || perHour == 0 {
		return fmt.Errorf("the ceiling for %q must be a positive whole number per hour, got %q", unit, n)
	}
	if prev, dup := m[unit]; dup {
		return fmt.Errorf("-meter-ceiling for %q given twice (%d and %d); say it once", unit, prev, perHour)
	}
	m[unit] = uint32(perHour)
	return nil
}

// pathList is a repeatable string flag — `-file-credential-root` (D286).
type pathList []string

func (p *pathList) String() string { return strings.Join(*p, ",") }

// Set appends one occurrence. A path given twice is refused, as
// meterCeilings refuses a unit given twice: one of the two is a mistake.
func (p *pathList) Set(v string) error {
	for _, have := range *p {
		if have == v {
			return fmt.Errorf("%q given twice; say it once", v)
		}
	}
	*p = append(*p, v)
	return nil
}
