package acceptance

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// P6's graduation run, declared before it is built (D114) — v1.1.
//
// DECLARED EARLY, AND SAID SO (D341). The maintainer: "we should file the hotfix as a p6
// step, so it is not hidden." D340 landed on the signed v1 as a hotfix, proven
// by a test outside any table, where `make mutate` could not see it. This table
// is where it lives now, as step 9, BUILT. Steps 1-8 restate DESIGN §12 P6's
// own exit criteria and are refined when P6 opens; 10 and 11 carry what earlier
// decisions moved here (D327's lookups, the one unbuilt anzen action). 12 is
// the second hotfix filed the same way: the security best practices (D344).

type p6Step struct {
	n       int
	what    string
	asserts string
	covers  []int
	decides []string
	run     func(t *testing.T)
}

//nolint:gochecknoglobals // immutable table, read once
var p6ExitCriteria = map[int]string{
	1: "all five connectors pass the P1 property test together",
	2: "Describe(principal) output generates working tool definitions for one agent framework",
	3: "the panel surfaces a deliberately-expired credential before it causes a failure",
	4: "break-glass revoke takes effect within the credential cache TTL and is audited",
	5: "two principals with different grants against one MCP spec receive different Describe output",
	6: "an access token expiring mid-flight refreshes without invalidating the pooled client, once under concurrency",
	7: "sekizui-mcpspec re-run against an unchanged server produces an empty diff, and preserves human classifications",
	8: "the panel shows one system reachable by two paths as a single effective capability set (D52)",

	// --- appended when the table was declared (2026-09-27, D341).
	9:  "an anzen rule suspends the principal a signal names, through the governed verb, and the record says why (D340)",
	10: "a refines: lookup reads on the caller's behalf, charges both budgets, and stops at a deadline (D297, D298, D327)",
	11: "restrict_shin tightens a lens on an overwhelmed consumer, strictly reducing (D85, D331)",

	// --- appended 2026-09-28: the security best-practices hotfix (D344).
	12: "a durable write never follows a planted name, a file credential is read through its root, TLS 1.3 is the floor of the insecure client, and the dependency floor carries the CVE fixes (D343, D344)",
}

// p6Complete is flipped when P6 graduates (D114).
const p6Complete = false

// restated marks a step declared from DESIGN's criterion alone, to be refined
// when P6 opens: the assertion is the criterion until then.
const restated = " RESTATED FROM DESIGN §12 P6 when the table was declared early (D341); refined when P6 opens."

func p6StepTable() []p6Step {
	return []p6Step{
		{n: 1, covers: []int{1}, decides: []string{"D274", "D169", "D170"},
			what:    "all five connectors pass the P1 property test together",
			asserts: "Atlassian in full, GCP (BigQuery source and warehouse sink, the konbini dialect port), Snowflake and Slack join Fullstory, and P1's randomised property holds over all five at once." + restated},
		{n: 2, covers: []int{2},
			what:    "Describe output generates working tool definitions for one agent framework",
			asserts: "A principal's Describe output renders into one agent framework's tool definitions, and the agent can call each through Sekizui." + restated},
		{n: 3, covers: []int{3},
			what: "the panel surfaces a deliberately-expired credential before it causes a failure",
			asserts: "The read-only panel shows a credential nearing expiry before any command fails on it — §4.8's motivating scenario. " +
				"And every operator HTTP surface — the panel and the probes — answers with a declared Content-Type and " +
				"X-Content-Type-Options: nosniff on a running instance: carried from D344, whose probe headers only a unit test holds." + restated},
		{n: 4, covers: []int{4},
			what:    "break-glass revoke takes effect within the credential cache TTL and is audited",
			asserts: "A revocation reaches every path holding the credential within one cache TTL, with the record naming what it cancelled." + restated},
		{n: 5, covers: []int{5},
			what:    "two principals with different grants against one MCP spec receive different Describe output",
			asserts: "The catalog agrees with the enforcer: what Describe advertises is exactly what each principal may call (§4.9a.5)." + restated},
		{n: 6, covers: []int{6}, decides: []string{"D47"},
			what:    "a token expiring mid-flight refreshes once, without invalidating the pooled client",
			asserts: "The oauth-cc chained provider refreshes a token expiring mid-flight without evicting the pooled client, and concurrent expiry produces exactly one refresh (§4.7.1)." + restated},
		{n: 7, covers: []int{7}, decides: []string{"D46"},
			what:    "sekizui-mcpspec produces an empty diff for an unchanged server and preserves human classifications",
			asserts: "Re-drafting against an unchanged server is an empty diff; against a changed one, every human `mutating` classification it did not need to touch survives (§4.9a.1)." + restated},
		{n: 8, covers: []int{8}, decides: []string{"D52"},
			what:    "the panel shows one system reachable by two paths as one capability set",
			asserts: "A native connector and its MCP server appear in the panel as a single effective capability set, so D52's union is reviewable." + restated},
		{n: 9, covers: []int{9}, decides: []string{"D340"},
			what: "an anzen rule suspends the principal a denial storm names, and the record says why",
			asserts: "D340, THE v1 HOTFIX, FILED HERE SO IT IS NOT HIDDEN. A real storm on the gateway names the agent " +
				"draining kata:metered; a rule doing revoke_grant on that bare principal fires through the governed verb, " +
				"recorded as the rule's with a reason naming the signal (CONTRACTS 158); the agent is refused and a victim " +
				"is still served",
			run: p6Step9},
		{n: 10, covers: []int{10}, decides: []string{"D297", "D298", "D327"},
			what:    "a refines: lookup reads on the caller's behalf, charges both budgets, and stops at a deadline",
			asserts: "Moved from P5 by D327 with D297/D298's design: a lookup's chain is [caller, reflex:R] within the caller's grants; it charges the caller's budget and the rule's; a deadline flag sets the default and ceiling and a rule may only narrow it; reaching it delivers silver alone, recorded. Built when a connector gives a rule something to look up."},
		{n: 11, covers: []int{11}, decides: []string{"D85", "D331"},
			what:    "restrict_shin tightens a lens on an overwhelmed consumer, strictly reducing",
			asserts: "The one unbuilt anzen action (D331): fired, it tightens a named consumer's lens — every lens operation is strictly reducing (D83), so it can only remove — until config is redeployed; boot refuses an enforcing rule using it until then. Design first: which lens, and what 'tighter' means at runtime."},
		{n: 12, covers: []int{12}, decides: []string{"D343", "D344"},
			what: "the security best practices hotfix holds: no planted name, no escaped root, no weak floor",
			asserts: "D343 AND D344, THE SECURITY BEST-PRACTICES HOTFIX, FILED HERE SO IT IS NOT HIDDEN. A durable " +
				"write beside a symlink planted at the old temp name leaves the link's target untouched; a file:// " +
				"credential whose directory is swapped for a link out of its root, again and again while it is being " +
				"read, never yields the file outside; the conformance suite's insecure client refuses below TLS 1.3; " +
				"go.mod requires the fixed gRPC, x/net and x/mod over a go 1.25.0 floor with toolchain go1.26.7, and " +
				"the CI workflow installs that toolchain",
			run: p6Step12},
	}
}

func TestP6Acceptance(t *testing.T) {
	built := 0
	for _, s := range p6StepTable() {
		if s.run != nil {
			built++
		}
	}
	t.Logf("P6 acceptance: %d/%d steps built", built, len(p6StepTable()))
	for _, s := range p6StepTable() {
		t.Run(fmt.Sprintf("%02d_%s", s.n, slug(s.what)), func(t *testing.T) {
			st := evidence.open("P6", s.n, s.what, firstSentence(s.asserts), s.covers, s.decides)
			evidence.bind(t.Name(), st)
			t.Cleanup(func() { st.finish(t.Skipped(), t.Failed()) })
			if s.run == nil {
				t.Skipf("NOT BUILT — will assert: %s", s.asserts)
			}
			s.run(t)
		})
	}
}

func TestP6StepsAreWellFormed(t *testing.T) {
	seen := map[int]bool{}
	for _, s := range p6StepTable() {
		if s.what == "" || s.asserts == "" || len(s.covers) == 0 {
			t.Errorf("step %d lacks narration, assertion or a criterion", s.n)
		}
		for _, c := range s.covers {
			if _, ok := p6ExitCriteria[c]; !ok {
				t.Errorf("step %d claims exit criterion %d, which does not exist", s.n, c)
			}
		}
		if seen[s.n] {
			t.Errorf("step number %d is used twice", s.n)
		}
		seen[s.n] = true
	}
}

func TestP6CoversItsExitCriteria(t *testing.T) {
	covered := map[int]bool{}
	for _, s := range p6StepTable() {
		for _, c := range s.covers {
			covered[c] = true
		}
	}
	var orphans []string
	for c, desc := range p6ExitCriteria {
		if !covered[c] {
			orphans = append(orphans, fmt.Sprintf("%d: %s", c, desc))
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("P6 exit criteria with no step:\n  %s", strings.Join(orphans, "\n  "))
	}
}

func TestP6CompletionIsHonest(t *testing.T) {
	if !p6Complete {
		return
	}
	for _, s := range p6StepTable() {
		if s.run == nil {
			t.Errorf("P6 is marked complete with step %d unbuilt", s.n)
		}
	}
}
