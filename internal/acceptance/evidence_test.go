package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The evidence ledger: which lines of the shared audit log each step produced.
//
// WHY THIS EXISTS. The Markdown report used to narrate what the run did and
// print the log beside it, which asks a reader to take the narration's word for
// the connection between the two. It also described 117 of the log's 519 lines
// while claiming to be derived from it, because it was written at the end of
// TestP0Acceptance and P1's 68 steps and P2's 46 append to the same file
// afterwards. A step's claim and the records that back it were in one document
// and had no link.
//
// So every step now CITES the lines it wrote — `acceptance.jsonl:441-447` — and
// the report renders those records under the claim they prove. The citation is
// derived from the log's own length at each step boundary, never declared, for
// the reason the report itself is derived: a declared range could be wrong, and
// a wrong citation is worse than no citation because it looks checkable.
//
// **RANGES ARE HALF-OPEN BY CONSTRUCTION, WHICH IS WHAT MAKES THE PARTITION
// COMPLETE.** A step owns every line from the moment it opened until the moment
// the NEXT step opened — not "until it returned". The difference is load-bearing:
// a step's `t.Cleanup` (a listener draining, a WAL closing) can write records
// after the step function returns, and an end-at-return range would orphan them.
// Attributing them to the step whose teardown produced them is both correct and
// leaves no line unaccounted for, which `evidenceLedger.audit` then checks
// rather than assumes.
//
// GLOBAL STATE, DELIBERATELY, AND THE LINT DIRECTIVE IS NOT A SHRUG. P0, P1 and
// P2 are three separate top-level tests writing one audit log; the ledger spans
// all three, so it cannot hang off any one of them. It carries a mutex for the
// reason GO-PRIMER §15e gives and this very file learned once already: the
// acceptance clock was a closure over local state, which was correct until step
// 14 put 48 commands in flight. Nothing here is touched concurrently today —
// steps are sequential and no step opens another — and "nothing does it today"
// is not what makes concurrent access safe.
//
//nolint:gochecknoglobals // one log, three top-level tests; see above
var evidence = &evidenceLedger{}

type evidenceLedger struct {
	mu     sync.Mutex
	steps  []*evidenceStep
	scrape string

	// bound is the entry a phase loop opened for a subtest, by test name, so a
	// step that narrates (`run.narrate`) writes into ITS phase's entry. Without
	// it narrate opened a second entry labelled "P0 step 1" and every P3 step's
	// citations and details went there, leaving the real P3 entry reading "no
	// audit records" — found reviewing the live run for P3's sign-off.
	bound map[string]*evidenceStep

	// inherited is the log's length when the process STARTED, and it is almost
	// always zero because `make acceptance` deletes the log first.
	//
	// **IT IS NOT THE SAME AS "records written before the first step opened",
	// AND CONFLATING THEM MADE A TARGETED RUN FAIL.** `go test -run
	// TestP2Acceptance/33` with the shared log set is an ordinary thing to do
	// while working on one step, and it appends its handful of records to
	// whatever the last full run left behind. The citations are then correct and
	// the file has 513 records nothing in THIS process observed being written —
	// so the audit refused, correctly by its own rule and uselessly to whoever
	// typed the command. A report is owed only by a run that watched the whole
	// log appear.
	inherited int

	// broken records the first failure to read the log's length. It makes the
	// REPORT refuse rather than the run fail, and that direction is deliberate:
	// the run's own assertions are the phase's evidence and they are unaffected
	// by our inability to count lines. What must not happen is a document full
	// of citations computed from a zero we swallowed.
	broken error
}

// evidenceStep is one step of one phase, and the position the log had reached
// when it opened.
type evidenceStep struct {
	phase string
	n     int

	// what is the narration, in the step table's own words.
	what string

	// claim is what the step says it proves — the first sentence of a P1/P2
	// step's `asserts`. P0 narrates without a separate claim and leaves it empty.
	claim string

	// details are observations a step attached as it ran (P0's `detail`), which
	// are the only part of this document a step writes in prose.
	details []string

	covers  []int
	decides []string

	// led is the ledger this step belongs to. A BACK-POINTER RATHER THAN THE
	// GLOBAL, so the mechanism can be tested against a private ledger — a test
	// that drove `evidence` would insert fabricated steps into the document the
	// same run is about to write.
	led *evidenceLedger

	// at is the number of records in the log when this step opened, so the
	// step's first line is at+1.
	at int

	skipped bool
	failed  bool
}

// observedWholeLog reports whether this process watched every record appear, and
// is therefore in a position to say which step wrote which line.
func (l *evidenceLedger) observedWholeLog() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inherited == 0
}

// wholeSuiteRan reports whether every step of every phase opened a range.
//
// **THE CENSUS NEEDS A COMPLETE CORPUS AND THE CITATIONS DO NOT, which is the
// distinction this exists to draw.** `go test -run TestP2Acceptance/29_` writes
// valid citations for the one step that ran, and leaves 29 of the 70 `Decision`
// field paths unpopulated — every one of them because no step touched them, not
// because nothing writes them. Refusing the report there is the census
// answering a question nobody asked, and it failed a run that did nothing
// wrong.
//
// DERIVED FROM THE STEP TABLES rather than a count written here, so a step added
// at P3 raises the bar by existing. P0 narrates rather than tabling, so the only
// honest requirement for it is "at least one" — a run that skipped P0 entirely
// has no records to census anyway.
func (l *evidenceLedger) wholeSuiteRan() bool {
	l.mu.Lock()
	byPhase := map[string]int{}
	for _, st := range l.steps {
		byPhase[st.phase]++
	}
	l.mu.Unlock()

	return byPhase["P0"] > 0 &&
		byPhase["P1"] >= len(p1StepTable()) &&
		byPhase["P2"] >= len(p2StepTable())
}

// stepsRan is how many steps opened a range.
func (l *evidenceLedger) stepsRan() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.steps)
}

// begin records the log's length before any test runs.
func (l *evidenceLedger) begin() {
	path := evidenceLogPath()
	if path == "" {
		return
	}
	n, err := evidenceLines(path)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.inherited = n
	if err != nil && l.broken == nil {
		l.broken = fmt.Errorf("reading the audit log's length before the run: %w", err)
	}
}

// evidenceLogPath is the shared log, or "" when there is none.
//
// THE SAME GATE THE REPORT ALREADY USED. Without SEKIZUI_ACCEPTANCE_OUT every
// step writes to its own t.TempDir (so there is no shared log to cite), and with
// SEKIZUI_ACCEPTANCE_TARGET the log belongs to another process on its own disk —
// citing line numbers in a file we did not watch being written would be a
// fabrication, which is why this returns nothing in that case rather than
// something plausible.
func evidenceLogPath() string {
	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		return ""
	}
	return os.Getenv("SEKIZUI_ACCEPTANCE_OUT")
}

// evidenceLines counts the records in the shared log without parsing them.
//
// Counting rather than protojson-unmarshalling because this runs at every step
// boundary — about 130 times a run — and the report parses the file once at the
// end, where a malformed line is a failure worth reporting rather than an
// interruption to a position count.
func evidenceLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// BEFORE THE FIRST RECORD, not an error. `make acceptance` removes the
		// log and the first step's sink creates it.
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return len(splitLines(string(data))), nil
}

// open starts a step's range at the log's current end and returns it, so the
// caller can report the outcome without the ledger having to guess which step
// is current.
func (l *evidenceLedger) open(phase string, n int, what, claim string,
	covers []int, decides []string) *evidenceStep {

	st := &evidenceStep{phase: phase, n: n, what: what, claim: claim,
		covers: covers, decides: decides, led: l}

	path := evidenceLogPath()
	l.mu.Lock()
	defer l.mu.Unlock()
	// RECORDED IN EVERY MODE, the audit range only where there is an audit log
	// (P5 step 13, D328). Driving a live instance writes no log here, and this
	// returned before recording the step — so under `make demo` nothing could
	// ask which steps ran and what they narrated, which is the demo half of step
	// 13. The report is still written only with a log.
	if path == "" {
		l.steps = append(l.steps, st)
		return st
	}

	at, err := evidenceLines(path)
	if err != nil && l.broken == nil {
		l.broken = fmt.Errorf("reading the audit log's length at %s step %d: %w", phase, n, err)
	}
	st.at = at
	l.steps = append(l.steps, st)
	return st
}

// bind records st as the entry for the named test; narrate then uses it.
func (l *evidenceLedger) bind(test string, st *evidenceStep) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bound == nil {
		l.bound = map[string]*evidenceStep{}
	}
	l.bound[test] = st
}

// boundTo returns the entry a phase loop bound to the named test or to the
// nearest test enclosing it, or nil. ENCLOSING, because a step may narrate from
// its own subtests (step 34 does), and the first version matched the exact
// name only — leaving that step's six records in a phantom P0 entry.
func (l *evidenceLedger) boundTo(test string) *evidenceStep {
	l.mu.Lock()
	defer l.mu.Unlock()
	for name := test; ; {
		if st := l.bound[name]; st != nil {
			return st
		}
		i := strings.LastIndex(name, "/")
		if i < 0 {
			return nil
		}
		name = name[:i]
	}
}

// detail attaches an observation to a step.
func (st *evidenceStep) detail(msg string) {
	st.led.mu.Lock()
	defer st.led.mu.Unlock()
	st.details = append(st.details, msg)
}

// finish records how the step ended. Called from a t.Cleanup rather than after
// the step returns, because t.Skipf and t.Fatalf leave through runtime.Goexit
// and nothing written after the call would run — which would report every
// skipped step as having passed.
func (st *evidenceStep) finish(skipped, failed bool) {
	st.led.mu.Lock()
	defer st.led.mu.Unlock()
	st.skipped, st.failed = skipped, failed
}

// metrics stashes the scrape from the run that produced it.
//
// P0's, and the report says so. Each P1/P2 step builds its own gateway with its
// own registry, so there is no single scrape for the whole file and a section
// labelled "metrics from this run" would be quietly untrue about 129 of the 130
// steps.
func (l *evidenceLedger) metrics(scrape string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.scrape = scrape
}

// evidenceRange is a step and the lines it owns, 1-based and inclusive.
// count == 0 means the step wrote nothing, which is a legitimate result for the
// many steps that assert about boot, the import graph or the AST.
type evidenceRange struct {
	step  *evidenceStep
	from  int
	to    int
	count int
}

// ranges derives each step's citation from the next step's start.
func (l *evidenceLedger) ranges(total int) []evidenceRange {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]evidenceRange, 0, len(l.steps))
	for i, st := range l.steps {
		end := total
		if i+1 < len(l.steps) {
			end = l.steps[i+1].at
		}
		r := evidenceRange{step: st, from: st.at + 1, to: end, count: end - st.at}
		if r.count <= 0 {
			r.count, r.from, r.to = 0, 0, 0
		}
		out = append(out, r)
	}
	return out
}

// audit is the guard on the citations, and the report REFUSES TO BE WRITTEN if
// it fails.
//
// It checks the one property that makes a line number worth printing: every
// record in the log belongs to exactly one step, and every citation is inside
// the file. A partition is what the half-open construction above is FOR, so this
// asserts the construction held rather than hoping it did — the difference
// between a mechanism and a belief about a mechanism.
//
// A LEADING GAP IS THE ONE THING IT CANNOT RULE OUT AND MUST REPORT: records
// written before the first step opened belong to no step, and they would be
// invisible in a document organised by step. It names them rather than dropping
// them.
func (l *evidenceLedger) audit(total int) error {
	if l.broken != nil {
		return l.broken
	}

	ranges := l.ranges(total)
	if len(ranges) == 0 {
		// NO STEPS RAN, SO NO REPORT IS OWED — and this must not be an error.
		// `go test -run TestSomethingElse` with the shared log set is an
		// ordinary thing to do while working on a non-step test, and it writes
		// records nothing cites. Refusing there fails a run that did nothing
		// wrong; `writeEvidenceReport` skips instead.
		return nil
	}

	seen := 0
	prev := 0
	for _, r := range ranges {
		if r.count == 0 {
			continue
		}
		if r.from != prev+1 && prev != 0 {
			return fmt.Errorf("%s step %d cites lines %d-%d but the previous citation ended at %d — "+
				"the ranges do not partition the log", r.step.phase, r.step.n, r.from, r.to, prev)
		}
		if r.to > total {
			return fmt.Errorf("%s step %d cites line %d and the log has %d records",
				r.step.phase, r.step.n, r.to, total)
		}
		seen += r.count
		prev = r.to
	}

	lead := ranges[0].step.at
	if seen+lead != total {
		return fmt.Errorf("the steps cite %d records, %d were written before the first step opened, "+
			"and the log holds %d — every record must belong to exactly one step or the "+
			"citations are decoration", seen, lead, total)
	}
	return nil
}

// TestEvidenceCitationsFollowTheAuditLog tests the position arithmetic directly,
// against a log it writes by hand.
//
// **`evidenceLedger.audit` CANNOT DO THIS, AND THE GAP IS WORTH STATING.** That
// check proves the citations PARTITION the log, which is a property the
// half-open construction gives for free — and a degenerate ledger where one step
// claims every record satisfies it perfectly. Completeness and correct
// attribution are different claims, and only the second is what a reader of the
// document is trusting. Nothing internal to a finished run can tell them apart,
// so the arithmetic is proven here where the answer is known in advance.
//
// It drives a PRIVATE ledger. Driving the global one would insert three invented
// steps into the report the same run then writes, which is the shape of defect
// this whole mechanism exists to remove.
func TestEvidenceCitationsFollowTheAuditLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acceptance.jsonl")
	t.Setenv("SEKIZUI_ACCEPTANCE_TARGET", "")
	t.Setenv("SEKIZUI_ACCEPTANCE_OUT", path)

	var log []string
	write := func(n int) {
		for i := 0; i < n; i++ {
			log = append(log, `{"id":"dec_x"}`)
		}
		if err := os.WriteFile(path, []byte(strings.Join(log, "\n")+"\n"), 0o600); err != nil {
			t.Fatalf("writing the fake log: %v", err)
		}
	}

	led := &evidenceLedger{}

	// A step that writes nothing, a step that writes two, a step that writes one
	// AFTER it has returned — the teardown case the half-open range exists for.
	write(1) // a record before any step opens: the leading gap
	led.open("P9", 1, "writes nothing", "", nil, nil)
	led.open("P9", 2, "writes two", "", nil, nil)
	write(2)
	led.open("P9", 3, "writes one in its teardown", "", nil, nil)
	write(1)

	got := led.ranges(len(log))
	want := []struct{ n, from, to, count int }{
		{1, 0, 0, 0}, // no records: cited as nothing rather than as an empty range
		{2, 2, 3, 2},
		{3, 4, 4, 1},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d ranges, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.step.n != w.n || g.from != w.from || g.to != w.to || g.count != w.count {
			t.Errorf("step %d cited lines %d-%d (%d records); want %d-%d (%d)",
				g.step.n, g.from, g.to, g.count, w.from, w.to, w.count)
		}
	}

	// THE LEADING GAP IS REPORTED, NOT ABSORBED. A record written before the
	// first step belongs to no step, and the audit must say so rather than
	// letting step 1 adopt it.
	if err := led.audit(len(log)); err != nil {
		t.Errorf("audit rejected a correct ledger: %v", err)
	}
	if lead := got[0].step.at; lead != 1 {
		t.Errorf("the leading gap is %d records, want 1", lead)
	}

	// **A TRAILING GAP IS UNDETECTABLE, AND THE TEST SAYS SO RATHER THAN
	// PRETENDING.** The last step's range ends at the log's end by construction,
	// so a record written after every step has finished is indistinguishable
	// from one written by the last step's own teardown — and the second is both
	// legitimate and common. `audit(total+1)` therefore PASSES, which was the
	// first draft's failed assertion, and the finding is real: the leading gap
	// is nameable and the trailing one is not.
	if err := led.audit(len(log) + 1); err != nil {
		t.Errorf("the last step absorbs the tail by construction, so this must pass "+
			"rather than being asserted against: %v", err)
	}

	// WHAT IS DETECTABLE IS THE DANGEROUS DIRECTION: a citation pointing past
	// the end of the file. That is a line number a reader would look up and not
	// find, which is the one failure worse than no citation at all.
	if err := led.audit(len(log) - 2); err == nil {
		t.Error("audit accepted citations that run past the end of the log; a reader " +
			"following one would land on a line that does not exist")
	}
}
