package drift_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/drift"
)

// **WHY THESE ARE PACKAGE TESTS AND NOT ACCEPTANCE ARMS.** P2 steps 9 and 12
// drive this store through a real MCP comparison, which is where its INTEGRATION
// belongs. What they cannot reach is the store's own edge semantics: an acceptance
// step gets its findings from a driver, so it can never hand the store a severity
// the vocabulary does not grade, and it cannot separate "the attempt failed" from
// "the comparison found nothing" without a second server going down mid-step.
//
// The unknown-severity refusal in particular had no test of any kind when it was
// written, and it is a FAIL-OPEN guard: without it, an ungraded severity answers
// false to both predicates, so it reads as a finding in every operator surface
// and acts as nothing.

func TestRecordRefusesASeverityTheVocabularyDoesNotGrade(t *testing.T) {
	s := memoryStore(t)

	err := s.Record("mcp:acme", drift.Findings{{
		Severity: "catastrophic", Tool: "search", Action: "mcp.acme.search",
		Detail: "invented by a driver that has not read the vocabulary",
	}}, time.Now())

	if err == nil {
		t.Fatal("an ungraded severity was recorded. `severities` is a map, so an " +
			"unregistered member answers false to RefusesTarget AND WithholdsAction — " +
			"it would appear in /debugz/targets as a finding and change nothing, which " +
			"is the fail-open direction on a governance signal")
	}
	// THE MESSAGE NAMES THE VOCABULARY, so whoever hits it learns what to say
	// rather than only that they were wrong.
	for _, want := range []string{"catastrophic", "mcp:acme", string(drift.SeverityWithheld)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	if _, ok := s.Of("mcp:acme"); ok {
		t.Error("the refused finding was stored anyway, so the refusal is a report rather " +
			"than a defence")
	}
}

func TestRecordAcceptsEverySeverityInTheVocabulary(t *testing.T) {
	// THE NON-VACUITY HALF: a Record that refused everything would pass the test
	// above and break the system. Ranged over the vocabulary (§15q) so a new
	// severity is covered the day it lands.
	for _, sev := range drift.Severities() {
		s := memoryStore(t)
		if err := s.Record("mcp:acme", drift.Findings{{
			Severity: sev, Tool: "search", Action: "mcp.acme.search", Detail: "x",
		}}, time.Now()); err != nil {
			t.Errorf("severity %q is in the vocabulary and was refused: %v", sev, err)
		}
	}
}

func TestAFailedAttemptKeepsTheLastKnownFindings(t *testing.T) {
	s := memoryStore(t)
	compared := time.Now().Add(-time.Hour)

	if err := s.Record("mcp:acme", drift.Findings{{
		Severity: drift.SeverityWithheld, Tool: "report",
		Action: "mcp.acme.report", Detail: "vetted and no longer offered",
	}}, compared); err != nil {
		t.Fatalf("recording: %v", err)
	}

	failed := time.Now()
	s.RecordFailure("mcp:acme", errors.New("dial tcp: connection refused"), failed)

	st, ok := s.Of("mcp:acme")
	if !ok {
		t.Fatal("the target vanished from the store")
	}

	// **THE FAIL-CLOSED DIRECTION.** Clearing the findings would put the
	// withdrawn capability back in the catalog on the strength of a check that
	// did not happen.
	if len(st.Withheld()) != 1 {
		t.Errorf("a failed attempt cleared the withheld action: %+v. The tool is still "+
			"gone; an unreachable server is not evidence that it came back", st.Findings)
	}
	if !st.At.Equal(compared) {
		t.Errorf("At = %v, want the last COMPLETED comparison at %v. Advancing it on a "+
			"failure makes a target unreachable for an hour read as freshly verified",
			st.At, compared)
	}
	if !st.AttemptedAt.Equal(failed) {
		t.Errorf("AttemptedAt = %v, want the failed attempt at %v — the timestamp that "+
			"tells a dead poll loop apart from an unreachable vendor", st.AttemptedAt, failed)
	}
	if st.Err == nil {
		t.Error("the failure was not recorded, so nothing says the comparison is not running")
	}
	if !st.Checked() {
		t.Error("a target with a completed comparison reports as never checked")
	}
}

func TestAFailureBeforeAnyComparisonImpliesNothing(t *testing.T) {
	s := memoryStore(t)
	s.RecordFailure("mcp:acme", errors.New("unreachable"), time.Now())

	st, _ := s.Of("mcp:acme")
	if st.Checked() {
		t.Error("a target that has never been compared reports as CHECKED — D75's " +
			"cannot-confirm read as refuted")
	}
	if len(st.Findings) != 0 {
		t.Errorf("findings appeared from a failed attempt: %+v", st.Findings)
	}
	if st.Degraded() || st.Refused() {
		t.Error("an unreachable server was graded as a divergence. An outage is " +
			"`target_unavailable` and retryable; drift is `spec_drift` and is not")
	}
}

func TestWithholdsIsPerTargetAndPerAction(t *testing.T) {
	s := memoryStore(t)
	now := time.Now()

	if err := s.Record("mcp:alpha", drift.Findings{{
		Severity: drift.SeverityWithheld, Tool: "report",
		Action: "mcp.alpha.report", Detail: "withdrawn",
	}}, now); err != nil {
		t.Fatalf("recording alpha: %v", err)
	}
	if err := s.Record("mcp:beta", nil, now); err != nil {
		t.Fatalf("recording beta: %v", err)
	}

	if !s.Withholds("mcp:alpha", "mcp.alpha.report") {
		t.Error("the withdrawn action is not withheld for its own target")
	}
	// **THE ARM THAT MATTERS: one target's divergence must not withhold
	// another's capabilities.** The same defect the stale signal had before it
	// gained a subject dimension — one stuck target revoking a healthy one.
	if s.Withholds("mcp:beta", "mcp.alpha.report") {
		t.Error("a finding against mcp:alpha withheld an action for mcp:beta")
	}
	if s.Withholds("mcp:alpha", "mcp.alpha.search") {
		t.Error("an action with no finding against it was withheld")
	}
}

func TestAnInformationalFindingWithholdsNothing(t *testing.T) {
	s := memoryStore(t)
	if err := s.Record("mcp:acme", drift.Findings{{
		Severity: drift.SeverityInformational, Tool: "export",
		Action: "mcp.acme.export", Detail: "the vendor's outputSchema changed",
	}}, time.Now()); err != nil {
		t.Fatalf("recording: %v", err)
	}

	st, _ := s.Of("mcp:acme")
	if st.Degraded() || st.Refused() {
		t.Errorf("an informational finding degraded or refused the target: %+v", st)
	}
	if s.Withholds("mcp:acme", "mcp.acme.export") {
		t.Error("an informational finding withheld the action. Much of the ecosystem " +
			"publishes no output schema at all, so an output-schema change cannot be " +
			"allowed to remove a capability")
	}
}

func TestStatesIsSortedSoAnOperatorCanDiffIt(t *testing.T) {
	s := memoryStore(t)
	now := time.Now()
	for _, ref := range []string{"mcp:gamma", "mcp:alpha", "mcp:beta"} {
		if err := s.Record(ref, nil, now); err != nil {
			t.Fatalf("recording %s: %v", ref, err)
		}
	}

	var got []string
	for _, st := range s.States() {
		got = append(got, st.Ref)
	}
	want := []string{"mcp:alpha", "mcp:beta", "mcp:gamma"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("States() = %v, want %v — map iteration order reaching an operator "+
				"surface makes two refreshes of the same state undiffable", got, want)
		}
	}
}

// memoryStore is a drift store held in memory only (D311: OpenStore("")).
func memoryStore(t testing.TB) *drift.Store {
	t.Helper()
	s, err := drift.OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
