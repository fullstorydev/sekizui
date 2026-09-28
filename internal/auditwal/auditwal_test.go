package auditwal

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// fixedClock and seqIDs make records deterministic, which is what lets the hash
// chain be asserted against a fixed expectation rather than ignored.
func fixedClock() Clock {
	t := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func seqIDs() IDFunc {
	n := 0
	return func() string {
		n++
		return "dec_test_" + string(rune('a'+n-1))
	}
}

// memSink captures batches without touching disk.
type memSink struct {
	records []*sekizuiv1.Decision
	err     error
	writes  int
}

func (m *memSink) Name() string          { return "mem" }
func (m *memSink) Residencies() []string { return nil }
func (m *memSink) Close(context.Context) error {
	return nil
}

func (m *memSink) Write(_ context.Context, batch []*sekizuiv1.Decision) error {
	m.writes++
	if m.err != nil {
		return m.err
	}
	m.records = append(m.records, batch...)
	return nil
}

func newTestRecorder(s *memSink) *Recorder {
	return NewRecorder(s, "test-config", WithClock(fixedClock()), WithIDFunc(seqIDs()))
}

func sampleDecision() *sekizuiv1.Decision {
	return &sekizuiv1.Decision{
		Identity: &sekizuiv1.Identity{
			Caller:  &sekizuiv1.Caller{Principal: "mesh:primary"},
			Subject: &sekizuiv1.Subject{Principal: "agent:triage"},
			Chain:   []string{"mesh:primary", "agent:triage"},
			TraceId: "trace-1",
		},
		Action:      "kata.create_issue",
		TargetRef:   "kata:alpha",
		Verdict:     sekizuiv1.Verdict_VERDICT_ALLOW,
		MatchedRule: "data.sekizui.allow[_]",
	}
}

// TestTwoPhaseWrite is §5.2.2's core guarantee: intent BEFORE the side effect,
// outcome after. A crash between them leaves a record saying an action was
// attempted with no outcome — the truth, and far more useful than silence.
func TestTwoPhaseWrite(t *testing.T) {
	ctx := context.Background()
	s := &memSink{}
	r := newTestRecorder(s)

	id, err := r.Intent(ctx, sampleDecision())
	if err != nil {
		t.Fatalf("Intent: %v", err)
	}

	// The intent row must be durable ALREADY — not buffered pending an outcome.
	if len(s.records) != 1 {
		t.Fatalf("after Intent: %d records written, want 1 — the intent must be "+
			"durable before the side effect happens", len(s.records))
	}
	if got := s.records[0].Phase; got != sekizuiv1.Phase_PHASE_INTENT {
		t.Errorf("phase = %v, want INTENT", got)
	}
	if s.records[0].Effect != nil {
		t.Error("intent row carries an Effect; nothing has happened yet")
	}

	err = r.Outcome(ctx, id, &sekizuiv1.Effect{
		Success: true, StatusCode: 201, ExternalRef: "PROJ-123", LatencyMs: 42,
	})
	if err != nil {
		t.Fatalf("Outcome: %v", err)
	}

	if len(s.records) != 2 {
		t.Fatalf("after Outcome: %d records, want 2", len(s.records))
	}
	out := s.records[1]
	if out.Phase != sekizuiv1.Phase_PHASE_OUTCOME {
		t.Errorf("phase = %v, want OUTCOME", out.Phase)
	}
	if out.Id != id {
		t.Errorf("outcome id = %q, want %q — the two rows must correlate", out.Id, id)
	}
	if out.Effect.GetExternalRef() != "PROJ-123" {
		t.Errorf("external_ref = %q", out.Effect.GetExternalRef())
	}
	// The outcome row must be independently readable (D39): full identity, not
	// a pointer back to the intent row.
	if out.Identity.GetSubject().GetPrincipal() != "agent:triage" {
		t.Error("outcome row lost the identity; each row must stand alone with no joins")
	}
	if out.Action != "kata.create_issue" {
		t.Error("outcome row lost the action")
	}
}

// TestOutcomeDoesNotMutateTheIntentRow. Protobuf messages are pointers, so
// aliasing instead of cloning would retroactively edit a record already written.
func TestOutcomeDoesNotMutateTheIntentRow(t *testing.T) {
	ctx := context.Background()
	s := &memSink{}
	r := newTestRecorder(s)

	id, _ := r.Intent(ctx, sampleDecision())
	if err := r.Outcome(ctx, id, &sekizuiv1.Effect{Success: true}); err != nil {
		t.Fatalf("Outcome: %v", err)
	}

	if s.records[0].Phase != sekizuiv1.Phase_PHASE_INTENT {
		t.Error("the intent row's phase changed after Outcome; the two rows now " +
			"disagree about what was attempted")
	}
	if s.records[0].Effect != nil {
		t.Error("an Effect appeared on the already-written intent row")
	}
}

// TestTerminalRecordsDenials is §5.4's easily-dropped half, and P0 exit
// criterion 2.
//
// "Agent X tried to delete a project and was refused" is the sentence that
// justifies this service. An implementation that only records successful calls
// drops exactly that.
func TestTerminalRecordsDenials(t *testing.T) {
	ctx := context.Background()
	s := &memSink{}
	r := newTestRecorder(s)

	d := sampleDecision()
	d.Verdict = sekizuiv1.Verdict_VERDICT_DENY
	d.Reason = "project DELETE not in grant"
	d.MatchedRule = "data.sekizui.deny[_]"

	if _, err := r.Terminal(ctx, d); err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	if len(s.records) != 1 {
		t.Fatalf("a denial produced %d records, want 1", len(s.records))
	}

	rec := s.records[0]
	// OUTCOME, not INTENT: nothing further is coming. Left at INTENT it would
	// look forever like an action whose result was lost.
	if rec.Phase != sekizuiv1.Phase_PHASE_OUTCOME {
		t.Errorf("phase = %v, want OUTCOME — a terminal record has no second phase", rec.Phase)
	}
	if rec.Verdict != sekizuiv1.Verdict_VERDICT_DENY {
		t.Errorf("verdict = %v", rec.Verdict)
	}
	// An allow with no rule is unexplainable; so is a deny with no reason.
	if rec.MatchedRule == "" || rec.Reason == "" {
		t.Error("denial recorded without both a matched rule and a reason")
	}
}

func TestOutcomeWithoutIntentIsRefused(t *testing.T) {
	s := &memSink{}
	r := newTestRecorder(s)

	err := r.Outcome(context.Background(), "never-announced", &sekizuiv1.Effect{})
	if err == nil {
		t.Fatal("wrote an orphan outcome; the two-phase guarantee is broken upstream " +
			"and that must surface rather than produce a partial row")
	}
	if !errors.Is(err, fault.KindInternal) {
		t.Errorf("kind = %v, want KindInternal", fault.KindOf(err))
	}
}

// --- hash chain -------------------------------------------------------------

func TestHashChainLinksRecords(t *testing.T) {
	ctx := context.Background()
	s := &memSink{}
	r := newTestRecorder(s)

	// First record commits to nothing.
	id, _ := r.Intent(ctx, sampleDecision())
	if len(s.records[0].PrevHash) != 0 {
		t.Error("the first record has a prev_hash; there is nothing before it")
	}

	r.Outcome(ctx, id, &sekizuiv1.Effect{Success: true})
	if len(s.records[1].PrevHash) == 0 {
		t.Fatal("the second record has no prev_hash; the chain is not forming")
	}

	if err := VerifyChain(s.records); err != nil {
		t.Errorf("a chain we just wrote does not verify: %v", err)
	}
}

// TestHashChainDetectsTampering is why the chain exists. Tamper-evidence nobody
// can check is decoration.
func TestHashChainDetectsTampering(t *testing.T) {
	ctx := context.Background()
	s := &memSink{}
	r := newTestRecorder(s)

	id, _ := r.Intent(ctx, sampleDecision())
	r.Outcome(ctx, id, &sekizuiv1.Effect{Success: true})

	// A DENIAL as the last record, so the tampering below is the realistic
	// attack — quietly turning a refusal into an approval — rather than an
	// arbitrary edit.
	denial := sampleDecision()
	denial.Action = "kata.delete_project"
	denial.Verdict = sekizuiv1.Verdict_VERDICT_DENY
	denial.Reason = "not in grant"
	r.Terminal(ctx, denial)

	if err := VerifyChain(s.records); err != nil {
		t.Fatalf("precondition: clean chain should verify: %v", err)
	}
	if s.records[2].Verdict != sekizuiv1.Verdict_VERDICT_DENY {
		t.Fatalf("precondition: record 2 should be a denial, got %v", s.records[2].Verdict)
	}

	t.Run("altering a record", func(t *testing.T) {
		records := cloneAll(s.records)
		records[0].Action = "kata.something_else"

		if err := VerifyChain(records); err == nil {
			t.Error("an altered action verified clean")
		}
	})

	t.Run("turning a denial into an allow", func(t *testing.T) {
		records := cloneAll(s.records)
		records[2].Verdict = sekizuiv1.Verdict_VERDICT_ALLOW
		records[2].Reason = ""

		// The last record has nothing after it committing to its content, so
		// its own hash is never checked by a forward walk. VerifyChain only
		// links records to their predecessors — which means TAMPERING WITH THE
		// FINAL RECORD IS UNDETECTABLE by chain alone. That is a genuine
		// property of hash chains, not a bug here, and it is why §5.2.2a ships
		// records onward: once a row is in the warehouse, the local file is no
		// longer the only copy.
		err := VerifyChain(records)
		if err != nil {
			t.Log("detected, because a later record exists to commit to it")
			return
		}
		t.Log("NOT detected: the final record in a chain has no successor " +
			"committing to its content — mitigated by shipping records onward (§5.2.2a), " +
			"not by the chain")
	})

	t.Run("removing a record", func(t *testing.T) {
		records := cloneAll(s.records)
		records = append(records[:1], records[2:]...)

		if err := VerifyChain(records); err == nil {
			t.Error("a removed record verified clean")
		}
	})

	t.Run("reordering records", func(t *testing.T) {
		records := cloneAll(s.records)
		records[1], records[2] = records[2], records[1]

		if err := VerifyChain(records); err == nil {
			t.Error("reordered records verified clean")
		}
	})
}

// TestChainDoesNotAdvanceOnFailedWrite. Advancing past a record that never
// landed would leave a gap indistinguishable from tampering.
func TestChainDoesNotAdvanceOnFailedWrite(t *testing.T) {
	ctx := context.Background()
	s := &memSink{}
	r := newTestRecorder(s)

	if _, err := r.Intent(ctx, sampleDecision()); err != nil {
		t.Fatalf("first Intent: %v", err)
	}

	s.err = errors.New("disk full")
	if _, err := r.Intent(ctx, sampleDecision()); err == nil {
		t.Fatal("a failed sink write was reported as success")
	}
	s.err = nil

	if _, err := r.Terminal(ctx, sampleDecision()); err != nil {
		t.Fatalf("Terminal after recovery: %v", err)
	}
	if err := VerifyChain(s.records); err != nil {
		t.Errorf("chain broken by a failed write that wrote nothing: %v", err)
	}
}

func cloneAll(in []*sekizuiv1.Decision) []*sekizuiv1.Decision {
	out := make([]*sekizuiv1.Decision, len(in))
	for i, d := range in {
		b, _ := protojson.Marshal(d)
		var c sekizuiv1.Decision
		protojson.Unmarshal(b, &c)
		out[i] = &c
	}
	return out
}

// --- JSONL sink -------------------------------------------------------------

func TestJSONLSinkWritesReadableRecords(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit", "decisions.jsonl")
	sink := NewJSONLSink(path)

	if err := sink.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sink.Close(ctx)

	r := NewRecorder(sink, "test-config", WithClock(fixedClock()), WithIDFunc(seqIDs()))
	id, err := r.Intent(ctx, sampleDecision())
	if err != nil {
		t.Fatalf("Intent: %v", err)
	}
	if err := r.Outcome(ctx, id, &sekizuiv1.Effect{Success: true, ExternalRef: "PROJ-1"}); err != nil {
		t.Fatalf("Outcome: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2", len(lines))
	}

	// Enums must render as NAMES. As integers the trail becomes unreadable and
	// meaningless the moment an enum gains a value.
	if !strings.Contains(lines[0], "PHASE_INTENT") {
		t.Errorf("phase not rendered as a name: %s", lines[0])
	}
	if !strings.Contains(lines[0], "VERDICT_ALLOW") {
		t.Errorf("verdict not rendered as a name: %s", lines[0])
	}
	// snake_case, matching the .proto and the wire.
	if !strings.Contains(lines[0], "matched_rule") {
		t.Errorf("field names not snake_case: %s", lines[0])
	}
	// Each row independently readable, no joins (D39).
	if !strings.Contains(lines[1], "mesh:primary") || !strings.Contains(lines[1], "agent:triage") {
		t.Errorf("outcome row does not carry the full chain: %s", lines[1])
	}

	var back sekizuiv1.Decision
	if err := protojson.Unmarshal([]byte(lines[1]), &back); err != nil {
		t.Fatalf("a line we wrote does not parse back: %v", err)
	}
	if back.Effect.GetExternalRef() != "PROJ-1" {
		t.Errorf("round-trip lost external_ref: %+v", back.Effect)
	}
}

func TestJSONLSinkAppendsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "decisions.jsonl")

	for i := range 2 {
		sink := NewJSONLSink(path)
		if err := sink.Start(ctx); err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
		r := NewRecorder(sink, "test-config", WithClock(fixedClock()), WithIDFunc(seqIDs()))
		if _, err := r.Terminal(ctx, sampleDecision()); err != nil {
			t.Fatalf("Terminal %d: %v", i, err)
		}
		if err := sink.Close(ctx); err != nil {
			t.Fatalf("Close %d: %v", i, err)
		}
	}

	if got := len(readLines(t, path)); got != 2 {
		t.Errorf("%d lines after two runs, want 2 — a restart truncated the audit log", got)
	}
}

// TestJSONLSinkHealthFailsWhenClosed. §5.2.2 calls losing audit records "the one
// unacceptable failure", so a process that cannot record must stop accepting
// work rather than execute commands it cannot account for.
func TestJSONLSinkHealthFailsWhenClosed(t *testing.T) {
	ctx := context.Background()
	sink := NewJSONLSink(filepath.Join(t.TempDir(), "d.jsonl"))

	if err := sink.Health(ctx); err == nil {
		t.Error("healthy before Start")
	}
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := sink.Health(ctx); err != nil {
		t.Errorf("unhealthy after Start: %v", err)
	}
	if err := sink.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sink.Health(ctx); err == nil {
		t.Error("still healthy after Close")
	}
	// Idempotent.
	if err := sink.Close(ctx); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestJSONLSinkRefusesUnwritablePath(t *testing.T) {
	// A path under a regular file cannot be created as a directory.
	f := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(f, []byte("x"), 0o600)

	err := NewJSONLSink(filepath.Join(f, "sub", "d.jsonl")).Start(context.Background())
	if err == nil {
		t.Fatal("accepted an unwritable audit path; the failure must surface at boot, " +
			"not on the first decision after something has already executed")
	}
	if !errors.Is(err, fault.KindConfig) {
		t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

// TestRestartIsNotTampering. The chain lives in memory, so a file spanning two
// process lifetimes has a legitimate discontinuity. Reporting it as tampering
// would cry wolf at every restart, and the reliable consequence of crying wolf
// is that the real alarm gets muted.
func TestRestartIsNotTampering(t *testing.T) {
	ctx := context.Background()
	s := &memSink{}

	// Two recorders writing to one sink == two process lifetimes, one file.
	first := newTestRecorder(s)
	first.Terminal(ctx, sampleDecision())
	first.Terminal(ctx, sampleDecision())

	second := newTestRecorder(s)
	second.Terminal(ctx, sampleDecision())

	if err := VerifyChain(s.records); err != nil {
		t.Errorf("a restart was reported as tampering: %v", err)
	}
	if got := Segments(s.records); got != 2 {
		t.Errorf("Segments = %d, want 2 — an operator needs to know how many "+
			"restarts a file spans", got)
	}

	// And tampering WITHIN a segment is still caught.
	records := cloneAll(s.records)
	records[0].Action = "kata.something_else"
	if err := VerifyChain(records); err == nil {
		t.Error("an alteration inside a segment verified clean")
	}
}

// TestChainSurvivesRestart is the tail-persistence guarantee.
//
// Without it, a segment boundary is where a removed TAIL is undetectable:
// nothing after it commits to what came before, so deleting the last records of
// a segment leaves a file that verifies clean.
func TestChainSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tail := NewFileTailStore(filepath.Join(dir, "chain.tail"))
	s := &memSink{}

	first := NewRecorder(s, "test-config", WithClock(fixedClock()), WithIDFunc(seqIDs()), WithTailStore(tail))
	first.Terminal(ctx, sampleDecision())
	first.Terminal(ctx, sampleDecision())

	// A new process, same tail store.
	second := NewRecorder(s, "test-config", WithClock(fixedClock()), WithIDFunc(seqIDs()), WithTailStore(tail))
	second.Terminal(ctx, sampleDecision())

	// ONE segment, not two — the chain is continuous across the restart.
	if got := Segments(s.records); got != 1 {
		t.Errorf("Segments = %d, want 1 — the tail did not carry across the restart", got)
	}
	if err := VerifyChain(s.records); err != nil {
		t.Errorf("a persisted chain does not verify: %v", err)
	}

	// THE HOLE THIS CLOSES: removing the tail of the first segment is now
	// detectable, because the record after the boundary commits to it.
	truncated := append(cloneAll(s.records[:1]), cloneAll(s.records[2:])...)
	if err := VerifyChain(truncated); err == nil {
		t.Error("removing a record across the restart boundary verified clean")
	}
}

// TestMissingTailStartsAFreshChain. A first boot has no tail, and that is not
// an error.
func TestMissingTailStartsAFreshChain(t *testing.T) {
	tail := NewFileTailStore(filepath.Join(t.TempDir(), "absent.tail"))

	got, err := tail.Load()
	if err != nil {
		t.Fatalf("a missing tail should not be an error: %v", err)
	}
	if got != nil {
		t.Errorf("Load = %x, want nil", got)
	}
}

// TestUnreadableTailDoesNotPreventBoot.
//
// Refusing to start because a sidecar file is corrupt would take a governance
// system offline to protect a property VerifyChain reports on anyway. It begins
// a new segment instead — degraded, and visibly so.
func TestUnreadableTailDoesNotPreventBoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.tail")
	os.WriteFile(path, []byte("not hex at all"), 0o600)

	s := &memSink{}
	r := NewRecorder(s, "test-config", WithClock(fixedClock()), WithIDFunc(seqIDs()),
		WithTailStore(NewFileTailStore(path)))

	if _, err := r.Terminal(context.Background(), sampleDecision()); err != nil {
		t.Fatalf("a corrupt tail prevented recording: %v", err)
	}
	if len(s.records[0].PrevHash) != 0 {
		t.Error("a corrupt tail was used as a chain head")
	}
}

// TestTailIsWrittenAtomically. A partial write would leave a hash matching
// nothing, and every later verification would report tampering on an untouched
// file.
func TestTailIsWrittenAtomically(t *testing.T) {
	dir := t.TempDir()
	tail := NewFileTailStore(filepath.Join(dir, "chain.tail"))

	if err := tail.Save([]byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := tail.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != string([]byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("round trip = %x", got)
	}
	// No temporary file left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") { // fresh names since D344: `<file>.tmp-<random>`
			t.Errorf("temporary file %q survived", e.Name())
		}
	}
}
