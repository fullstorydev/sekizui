package kyuushin_test

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/internal/kyuushin"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/internal/translate"
	"github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// --- doubles ----------------------------------------------------------------

type capturingBus struct {
	mu   sync.Mutex
	sent []*sekizuiv1.Envelope
}

func (b *capturingBus) Publish(_ context.Context, e *sekizuiv1.Envelope) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, e)
	return nil
}
func (b *capturingBus) Subscribe(context.Context, bus.Filter) (bus.Subscription, error) {
	return nil, nil
}
func (b *capturingBus) Close(context.Context) error { return nil }
func (b *capturingBus) ids() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.sent))
	for _, e := range b.sent {
		out = append(out, e.GetSubject())
	}
	return out
}

type openGate struct {
	refused bool
	mu      *sync.Mutex
	records *[]int

	// admitted records the principal each poll was admitted under, and
	// attributed the principal each completed poll was RECORDED under, so a
	// test can assert WHO the job ran as rather than only that it ran (D250).
	//
	// **TWO SLICES BECAUSE THEY COME FROM TWO PLACES AND ONE SABOTAGE PROVED
	// IT.** `Admit` is handed the identity; `Record` is handed
	// `Job.Principal()`. A first version of the D250 test asserted only the
	// first, so reverting `Principal()` to `source:<ref>` left it GREEN — the
	// guard inert in exactly the way it exists to prevent, because the
	// admission reads the identity directly and never consults `Principal()`
	// at all. Attribution is the half that only the audit row can lose.
	admitted   *[]string
	attributed *[]string

	// recordedIDs are the identities handed to Record, kept whole so a test
	// can assert the DELEGATION CHAIN survived rather than only the subject.
	recordedIDs *[]*sekizuiv1.Identity

	// endings are the job ends this gate was told about (criterion 15).
	endings *[]ending
}

func newGate() openGate {
	return openGate{mu: &sync.Mutex{}, records: &[]int{},
		admitted: &[]string{}, attributed: &[]string{},
		recordedIDs: &[]*sekizuiv1.Identity{}, endings: &[]ending{}}
}

func (g openGate) Admit(_ context.Context, id *sekizuiv1.Identity, _, _ string) error {
	if g.mu != nil && g.admitted != nil {
		g.mu.Lock()
		*g.admitted = append(*g.admitted, id.GetSubject().GetPrincipal())
		g.mu.Unlock()
	}
	if g.refused {
		return fault.New(fault.KindDenied, "test.Admit", "refused")
	}
	return nil
}

func (g openGate) admittedAs() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), *g.admitted...)
}

// Begin stands in for a productive poll's intent (D272) and records its count
// where Record would, so the tests about what a poll records still see it.
func (g openGate) Begin(ctx context.Context, id *sekizuiv1.Identity, a, t string, atRisk int, _ string) (string, error) {
	return "poll-intent", g.Record(ctx, id, a, t, atRisk)
}

// Gap records nothing here; the recovery arms are proven in P3 steps 11-12.
func (g openGate) Gap(context.Context, *sekizuiv1.Identity, string, string, []string, cursor.Attempt, string) error {
	return nil
}

// Complete closes the stand-in intent; the count was already recorded by Begin.
func (g openGate) Complete(context.Context, string, int) error { return nil }

func (g openGate) Record(_ context.Context, id *sekizuiv1.Identity, _, _ string, events int) error {
	principal := id.GetSubject().GetPrincipal()
	if g.mu == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	*g.records = append(*g.records, events)
	if g.attributed != nil {
		*g.attributed = append(*g.attributed, principal)
	}
	if g.recordedIDs != nil {
		*g.recordedIDs = append(*g.recordedIDs, id)
	}
	return nil
}

// finished records how each job ENDED, so an arm can assert the three states
// criterion 15 must keep apart.
type ending struct {
	decisionID string
	events     int
	err        error
}

func (g openGate) Finish(_ context.Context, decisionID string, events int, cause error) error {
	if g.mu == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	*g.endings = append(*g.endings, ending{decisionID: decisionID, events: events, err: cause})
	return nil
}

func (g openGate) endingsSeen() []ending {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]ending(nil), *g.endings...)
}

func (g openGate) attributedTo() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), *g.attributed...)
}

func (g openGate) recorded() []int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]int(nil), *g.records...)
}

// scriptedSource returns what the test tells it to, including badly.
type scriptedSource struct {
	mu       sync.Mutex
	rows     int
	stall    bool
	panics   bool
	overBy   int
	polls    int
	blockFor time.Duration
}

func (s *scriptedSource) Poll(ctx context.Context, t connector.Target, cur string, limit int) (
	[]connector.RawEvent, string, error,
) {
	s.mu.Lock()
	s.polls++
	rows, stall, panics, overBy, block := s.rows, s.stall, s.panics, s.overBy, s.blockFor
	s.mu.Unlock()

	if panics {
		panic("scripted panic")
	}
	if block > 0 {
		select {
		case <-ctx.Done():
			return nil, cur, ctx.Err()
		case <-time.After(block):
		}
	}
	from := 0
	if cur != "" {
		from, _ = strconv.Atoi(cur)
	}
	var out []connector.RawEvent
	for i := from; i < from+limit+overBy && i < rows; i++ {
		out = append(out, connector.RawEvent{
			ID: "e" + strconv.Itoa(i), Type: "kata.row.v1", Subject: "e" + strconv.Itoa(i),
			At: time.Unix(int64(i)+1, 0).UTC(), Data: map[string]any{"n": float64(i)},
		})
	}
	if len(out) == 0 {
		return nil, cur, nil
	}
	if stall {
		return out, cur, nil
	}
	return out, strconv.Itoa(from + len(out)), nil
}

func (s *scriptedSource) Recovery(connector.Target) connector.RecoveryPolicy {
	return connector.RecoveryPolicy{Mode: connector.RecoveryRequery, Why: "scripted"}
}

func (s *scriptedSource) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.polls }

func target(t *testing.T) connector.Target {
	t.Helper()
	tg, err := connector.NewTarget(connector.TargetParams{
		Ref: "kata:alpha", Kind: "kata", Tenant: "alpha", Residency: "eu",
		BaseURL: "https://alpha.invalid", CredentialVersion: "v1",
		Credential: connector.Secret("tok"),
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tg
}

type harness struct {
	p     *kyuushin.Runner
	b     *capturingBus
	store cursor.Store
	src   *scriptedSource
}

func build(t *testing.T, src *scriptedSource, gate kyuushin.Gate, opts kyuushin.Options) harness {
	t.Helper()
	return buildWith(t, src, gate, opts, time.Millisecond, cursor.NewFileStore(t.TempDir()))
}

// buildWith is build with the interval and the cursor store chosen — for the
// arms about WHEN a schedule polls, which a millisecond interval cannot show.
func buildWith(t *testing.T, src *scriptedSource, gate kyuushin.Gate, opts kyuushin.Options,
	every time.Duration, store cursor.Store) harness {
	t.Helper()
	tr, err := translate.New("raw", 4096)
	if err != nil {
		t.Fatalf("translate.New: %v", err)
	}
	b := &capturingBus{}
	// **THE COUNTER NEEDS A MUTEX, AND THIS HARNESS LEARNED IT THE SAME WAY
	// `newRun` DID.** It was `n := 0; func() string { n++; ... }` — a closure
	// over local state, exactly GO-PRIMER §15e — and that was correct while
	// every test submitted one job at a time. The moment the status-table
	// bound put 1200 jobs in flight the race detector caught it, which is the
	// identical sequence the acceptance harness records for its clock.
	//
	// **Worth keeping as a comment rather than quietly fixing: closure state
	// is PRIVATE, not SYNCHRONISED**, and privacy is not what makes concurrent
	// access safe. Which job gets which id no longer has a predictable order,
	// and nothing depends on that.
	var (
		idMu sync.Mutex
		n    int
	)
	// A PERMISSIVE VALIDATOR: these arms are about the runner, and the
	// declared-and-conforming property is proven end to end (P3 step 18, D276).
	if opts.Payloads == nil {
		opts.Payloads = permissive{}
	}
	if opts.NewID == nil {
		opts.NewID = func() string {
			idMu.Lock()
			defer idMu.Unlock()
			n++
			return "env-" + strconv.Itoa(n)
		}
	}
	p, err := kyuushin.New(
		[]kyuushin.Job{{Target: target(t), Driver: src, Every: every, Limit: 2,
			Outputs: []string{"kata.row.v1"}}},
		store, tr, b, gate, slog.New(slog.NewTextHandler(io.Discard, nil)), opts)
	if err != nil {
		t.Fatalf("kyuushin.New: %v", err)
	}
	return harness{p: p, b: b, store: store, src: src}
}

func runFor(t *testing.T, h harness, d time.Duration) {
	t.Helper()
	if err := h.p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(d)
	if err := h.p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// --- the arms ---------------------------------------------------------------

// THE WALKING SKELETON: a real poll becomes real envelopes on a real bus, and
// the cursor advances.
func TestAPolledRowReachesTheBusAndTheCursorAdvances(t *testing.T) {
	h := build(t, &scriptedSource{rows: 4}, newGate(), kyuushin.Options{})
	// WAIT FOR THE CONDITION, NOT A FIXED SLEEP. This slept 60ms and hoped for
	// two polls; D275 made every published envelope a synced write, which is
	// its stated cost, and under -race in the full package the second poll no
	// longer fitted. A deadline on the fact asserted is what the test meant.
	if err := h.p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(h.b.ids()) < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := h.p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if got := h.b.ids(); len(got) < 4 {
		t.Fatalf("want 4 events delivered, got %v", got)
	}
	st, err := h.store.Load(context.Background(), "kata:alpha")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Cursor == "" {
		t.Error("the cursor did not advance")
	}
	if st.Pending != nil {
		t.Errorf("an attempt was left uncommitted: %+v", st.Pending)
	}
}

// NO DUPLICATES ACROSS A CLEAN RUN. The dedupe that matters across a crash is
// the pending set; this is the simpler property it rests on.
func TestNoEventIsDeliveredTwice(t *testing.T) {
	h := build(t, &scriptedSource{rows: 6}, newGate(), kyuushin.Options{})
	runFor(t, h, 80*time.Millisecond)

	seen := map[string]bool{}
	for _, id := range h.b.ids() {
		if seen[id] {
			t.Errorf("%q was delivered twice", id)
		}
		seen[id] = true
	}
}

// **THE MELT GUARD.** A source returning rows with no cursor progress must not
// be published and must stop being polled — without any anzen rule existing.
func TestAStalledSourceIsStoppedAndPublishesNothing(t *testing.T) {
	src := &scriptedSource{rows: 4, stall: true}
	h := build(t, src, newGate(), kyuushin.Options{StallsBeforeStopping: 2})
	runFor(t, h, 80*time.Millisecond)

	if got := h.b.ids(); len(got) != 0 {
		t.Errorf("a stalled source published %v; that window cannot be advanced past, so "+
			"publishing it is the melt happening once per tick", got)
	}
	stopped := h.p.Stopped()
	if _, ok := stopped["kata:alpha"]; !ok {
		t.Fatalf("the source was not stopped; Stopped() = %v", stopped)
	}
	if !strings.Contains(stopped["kata:alpha"], "no cursor progress") {
		t.Errorf("the reason does not say what happened: %q", stopped["kata:alpha"])
	}
	before := src.count()
	time.Sleep(20 * time.Millisecond)
	if src.count() != before {
		t.Error("the source is still being polled after being stopped")
	}
}

// A DRIVER THAT PANICS TAKES ITS OWN SOURCE DOWN, NOT THE PROCESS.
func TestAPanickingDriverDoesNotTakeTheProcess(t *testing.T) {
	h := build(t, &scriptedSource{rows: 4, panics: true}, newGate(), kyuushin.Options{})
	runFor(t, h, 40*time.Millisecond)

	stopped := h.p.Stopped()
	if why, ok := stopped["kata:alpha"]; !ok || !strings.Contains(why, "panicked") {
		t.Errorf("a panicking driver was not stopped with a reason: %v", stopped)
	}
}

// A BLOCKING DRIVER IS BOUNDED BY THE SPINE'S DEADLINE, not by its manners.
func TestABlockingDriverIsBoundedByTheDeadline(t *testing.T) {
	h := build(t, &scriptedSource{rows: 4, blockFor: time.Hour}, newGate(),
		kyuushin.Options{PollTimeout: 10 * time.Millisecond})

	done := make(chan struct{})
	go func() { runFor(t, h, 60*time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return; a blocking driver held the poller open")
	}
}

// OVER-LIMIT IS TRUNCATED AND RECORDED, not passed through.
func TestAnOverLimitPageIsTruncatedAndTallied(t *testing.T) {
	h := build(t, &scriptedSource{rows: 20, overBy: 5}, newGate(), kyuushin.Options{})
	runFor(t, h, 40*time.Millisecond)

	level := h.p.Nonconforming()
	why, ok := level["kata:alpha"]
	if !ok {
		t.Fatalf("an over-limit page raised no level: %v", level)
	}
	if !strings.Contains(why, "over_limit") {
		t.Errorf("the level does not name the violation: %q", why)
	}
}

// THE GATE IS CONSULTED BEFORE EVERY POLL. A refused source fetches nothing.
func TestARefusedSourceNeverReachesTheDriver(t *testing.T) {
	src := &scriptedSource{rows: 4}
	h := build(t, src, openGate{refused: true}, kyuushin.Options{})
	runFor(t, h, 40*time.Millisecond)

	if src.count() != 0 {
		t.Errorf("the driver was polled %d times despite the gate refusing", src.count())
	}
	if got := h.b.ids(); len(got) != 0 {
		t.Errorf("a refused source published %v", got)
	}
}

// EVERY DEPENDENCY IS REQUIRED.
//
// **"NO SOURCES" IS NO LONGER ONE OF THEM, AND ITS ARM MOVED RATHER THAN BEING
// DELETED (D252).** §12.0's guardrail still holds — a skeleton does its job for
// one real input or refuses loudly — but a gateway serving `StartJob`
// configures no recurring sources, so the refusal belongs where the mode is
// known. `cmd/sekizui` carries it now, and `TestIngestWithNothingToPollIsRefused`
// is the arm.
func TestTheConstructorRefusesWhatWouldRunAndLookHealthy(t *testing.T) {
	tr, _ := translate.New("raw", 4096)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	src := []kyuushin.Job{{Target: target(t), Driver: &scriptedSource{}, Every: time.Second, Limit: 1}}
	opts := kyuushin.Options{NewID: func() string { return "x" },
		Payloads: permissive{}}

	for name, call := range map[string]func() error{
		"no gate": func() error {
			_, err := kyuushin.New(src, cursor.NewFileStore(t.TempDir()), tr, &capturingBus{}, nil, log, opts)
			return err
		},
		"no store": func() error {
			_, err := kyuushin.New(src, nil, tr, &capturingBus{}, newGate(), log, opts)
			return err
		},
		"no bus": func() error {
			_, err := kyuushin.New(src, cursor.NewFileStore(t.TempDir()), tr, nil, newGate(), log, opts)
			return err
		},
		"no id generator": func() error {
			_, err := kyuushin.New(src, cursor.NewFileStore(t.TempDir()), tr, &capturingBus{}, newGate(), log,
				kyuushin.Options{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Error("accepted; this is a poller that runs and reports healthy")
			}
		})
	}
}

// **A QUIET SOURCE IS RECORDED BY THE HEARTBEAT AND NOT BY EVERY TICK.** Ten
// sources at thirty seconds is ~29k records a day, almost all of them "nothing
// new" — D178's disk amplification with Sekizui as the hostile party. The
// heartbeat is what makes the omission safe: without it a quiet source and a
// stopped one are indistinguishable in the log.
func TestAQuietSourceCostsAHeartbeatRatherThanARecordPerTick(t *testing.T) {
	gate := newGate()
	// rows: 0, so every tick is an empty window.
	h := build(t, &scriptedSource{rows: 0}, gate, kyuushin.Options{
		HeartbeatEvery: time.Hour,
	})
	runFor(t, h, 60*time.Millisecond)

	// EXACTLY ONE: the first poll, which records that polling began. Every
	// later empty tick inside the heartbeat window costs nothing.
	got := gate.recorded()
	if len(got) != 1 {
		t.Errorf("a quiet source wrote %d records in 60ms of ticking: %v. Want exactly "+
			"one — the first poll, saying polling began — and nothing after it, because "+
			"a record per empty poll is the amplification the heartbeat exists to avoid",
			len(got), got)
	}
}

// AND A HEARTBEAT THAT IS DUE IS WRITTEN, or a stopped source looks like a
// quiet one for ever.
func TestADueHeartbeatIsWritten(t *testing.T) {
	gate := newGate()
	h := build(t, &scriptedSource{rows: 0}, gate, kyuushin.Options{
		// Due on the first tick.
		HeartbeatEvery: time.Nanosecond,
	})
	runFor(t, h, 40*time.Millisecond)

	if got := gate.recorded(); len(got) == 0 {
		t.Error("no heartbeat was written, so a source that stopped and a source with " +
			"nothing new are the same thing in the audit log")
	}
}

// A POLL THAT PRODUCED EVENTS IS ALWAYS RECORDED, heartbeat or not.
func TestAProductivePollIsAlwaysRecorded(t *testing.T) {
	gate := newGate()
	h := build(t, &scriptedSource{rows: 4}, gate, kyuushin.Options{
		HeartbeatEvery: time.Hour,
	})
	runFor(t, h, 60*time.Millisecond)

	got := gate.recorded()
	if len(got) == 0 {
		t.Fatal("a poll that produced events wrote no record")
	}
	for _, n := range got {
		if n == 0 {
			t.Errorf("a record claims 0 events while the heartbeat was an hour away; "+
				"got %v", got)
		}
	}
}

// A ONE-SHOT JOB RUNS ONCE, CARRIES ITS OWN ID AS THE CAUSATION ROOT, AND
// LEAVES NO CURSOR. The cursor answers "where did I leave off", which only a
// recurrence asks (D249).
func TestASubmittedJobRunsOnceAndLeavesNoCursor(t *testing.T) {
	gate := newGate()
	src := &scriptedSource{rows: 3}
	h := build(t, src, gate, kyuushin.Options{})

	// Every: 0 — a caller asked, nothing is scheduled.
	job := kyuushin.Job{Outputs: []string{"kata.row.v1"}, Target: target(t), Driver: src, Limit: 10}

	id, err := h.p.Submit(context.Background(), job)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if id == "" {
		t.Fatal("Submit returned no job id, so nothing can subscribe to its results")
	}
	if err := h.p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// ADDRESSED TO THE CALLER, NOT THE BUS (D267). Nothing may reach the
	// shared bus, where every principal whose grant matched would receive it.
	h.b.mu.Lock()
	onBus := len(h.b.sent)
	h.b.mu.Unlock()
	if onBus != 0 {
		t.Fatalf("a caller's job put %d envelope(s) on the shared bus; its results are the "+
			"caller's alone (D267)", onBus)
	}
	sent := drainResults(t, h.p, id)
	if len(sent) != 3 {
		t.Fatalf("want the job's 3 events in its results, got %d", len(sent))
	}
	for _, e := range sent {
		if got := e.GetCausation().GetRootId(); got != id {
			t.Errorf("an envelope carries root %q, not the job id %q — a caller "+
				"subscribing on the root receives nothing", got, id)
		}
	}

	st, err := h.store.Load(context.Background(), "kata:alpha")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Cursor != "" || st.Pending != nil {
		t.Errorf("a one-shot job left cursor state %+v. Nothing is remembered on a "+
			"caller's behalf; the cursor belongs to a recurrence", st)
	}
}

// CANCELLING STOPS THE WORK. False is not an error — "it already finished" is
// the outcome the caller wanted.
func TestCancellingAJob(t *testing.T) {
	gate := newGate()
	src := &scriptedSource{rows: 3, blockFor: time.Hour}
	h := build(t, src, gate, kyuushin.Options{PollTimeout: time.Hour})

	id, err := h.p.Submit(context.Background(),
		kyuushin.Job{Outputs: []string{"kata.row.v1"}, Target: target(t), Driver: src, Limit: 10})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if !h.p.Cancel(id) {
		t.Error("cancelling a running job reported nothing to cancel")
	}
	if h.p.Cancel("no-such-job") {
		t.Error("cancelling an unknown id reported success")
	}

	done := make(chan struct{})
	go func() { _ = h.p.Stop(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return: the cancellation did not reach the work, only " +
			"the caller's view of it")
	}
}

// **A JOB RUNS AS WHOEVER ASKED FOR IT, AND A SCHEDULE RUNS AS THE SOURCE
// (D250).** The arm that matters is the FIRST one: `Principal()` answered
// `source:<ref>` for both triggers, so a caller's job was admitted against a
// principal the caller had never heard of — which needs a second grant, names
// the wrong actor on the audit row, and leaves P3 criterion 17 unprovable
// because the grant being suspended is not the one the job runs on.
//
// Asserted on WHAT THE GATE WAS ASKED, not on what the job produced: a job
// admitted as the wrong principal still delivers its events when the gate
// happens to say yes, which is exactly why the old behaviour survived two
// tests.
func TestAJobRunsAsWhoeverAskedForIt(t *testing.T) {
	caller := &sekizuiv1.Identity{
		Caller:  &sekizuiv1.Caller{Principal: "agent:triage"},
		Subject: &sekizuiv1.Subject{Principal: "agent:triage"},
		Chain:   []string{"agent:triage"},
	}

	for name, tc := range map[string]struct {
		id   *sekizuiv1.Identity
		want string
	}{
		"a caller's job": {id: caller, want: "agent:triage"},
		"a schedule's":   {id: nil, want: "source:kata:alpha"},
	} {
		t.Run(name, func(t *testing.T) {
			gate := newGate()
			src := &scriptedSource{rows: 1}
			h := build(t, src, gate, kyuushin.Options{})

			if _, err := h.p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"},
				Target: target(t), Driver: src, Limit: 10, Identity: tc.id,
			}); err != nil {
				t.Fatalf("Submit: %v", err)
			}
			if err := h.p.Stop(context.Background()); err != nil {
				t.Fatalf("Stop: %v", err)
			}

			got := gate.admittedAs()
			if len(got) == 0 {
				t.Fatal("the poll was never admitted: the job ran ungoverned, " +
					"which D18 forbids in twelve words")
			}
			if got[0] != tc.want {
				t.Errorf("the poll was admitted as %q, want %q", got[0], tc.want)
			}

			// **AND THE AUDIT ROW NAMES THE SAME PRINCIPAL.** This arm is the
			// one the first version of this test was missing: admission reads
			// the identity, attribution reads `Principal()`, and only the
			// second can silently name a synthetic actor while everything
			// works. §5.4's whole value is that the row says WHO.
			rec := gate.attributedTo()
			if len(rec) == 0 {
				t.Fatal("the completed poll was never recorded, so the log cannot " +
					"say the job ran at all")
			}
			if rec[0] != tc.want {
				t.Errorf("the audit row attributes the poll to %q, want %q — the "+
					"log names an actor who did not ask", rec[0], tc.want)
			}
		})
	}
}

// **THE CALLER'S DELEGATION CHAIN SURVIVES THE SEAM**, which is why the job
// carries an Identity rather than the principal string it carried first.
//
// D59 decides `caller ∩ subject, strictest wins`. A string is one of the two,
// so rebuilding an identity from it yields a chain of one and the job is
// admitted against a BROADER question than the gateway asked seconds earlier —
// a narrowing quietly not carried across a seam, which is `ceilings`' own
// story from the other end.
func TestADelegatedCallersChainReachesTheAdmission(t *testing.T) {
	gate := newGate()
	src := &scriptedSource{rows: 1}
	h := build(t, src, gate, kyuushin.Options{})

	delegated := &sekizuiv1.Identity{
		Caller:  &sekizuiv1.Caller{Principal: "agent:triage"},
		Subject: &sekizuiv1.Subject{Principal: "human:alice"},
		Chain:   []string{"agent:triage", "human:alice"},
	}
	if _, err := h.p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"},
		Target: target(t), Driver: src, Limit: 10, Identity: delegated,
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if err := h.p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := gate.admittedAs()
	if len(got) == 0 {
		t.Fatal("the poll was never admitted")
	}
	if got[0] != "human:alice" {
		t.Errorf("admitted as subject %q, want %q", got[0], "human:alice")
	}

	// **THE CHAIN ON THE AUDIT ROW IS THE ARM WITH TEETH.** D39 embeds the
	// identity WHOLE into every Decision, so the row is where a dropped chain
	// becomes permanent: `agent:triage on behalf of human:alice` recorded as
	// `human:alice` alone is a true statement that answers the wrong question,
	// and nothing downstream can recover the half that was not written.
	gate.mu.Lock()
	recorded := append([]*sekizuiv1.Identity(nil), *gate.recordedIDs...)
	gate.mu.Unlock()
	if len(recorded) == 0 {
		t.Fatal("the completed poll was never recorded")
	}
	chain := recorded[0].GetChain()
	if len(chain) != 2 || chain[0] != "agent:triage" || chain[1] != "human:alice" {
		t.Errorf("the audit row carries chain %v, want [agent:triage human:alice] — "+
			"the delegation did not survive the seam, so the record names one of "+
			"the two principals that produced this poll", chain)
	}
}

// **A RUNNER WITH NO CONFIGURED SOURCES IS ORDINARY NOW (D252).** A gateway
// that serves `StartJob` configures no recurring sources at all, so zero jobs
// is its steady state. §12.0's guardrail did not go away — `cmd/sekizui`
// refuses `-mode=ingest` with nothing to poll, where the mode is known.
func TestARunnerWithNoConfiguredSourcesStillServesSubmissions(t *testing.T) {
	tr, err := translate.New("raw", 4096)
	if err != nil {
		t.Fatalf("translate.New: %v", err)
	}
	b := &capturingBus{}
	n := 0
	p, err := kyuushin.New(nil, cursor.NewFileStore(t.TempDir()), tr, b, newGate(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		kyuushin.Options{NewID: func() string { n++; return "env-" + strconv.Itoa(n) },
			Payloads: permissive{}})
	if err != nil {
		t.Fatalf("a gateway-mode runner could not be built: %v", err)
	}

	src := &scriptedSource{rows: 2}
	id, err := p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"},
		Target: target(t), Driver: src, Limit: 10,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if sent := len(drainResults(t, p, id)); sent != 2 {
		t.Fatalf("want the submitted job's 2 events in its results, got %d", sent)
	}
	if id == "" {
		t.Error("no job id, so nothing can subscribe to the results")
	}
}

// **FINISHED AND FINISHED-WITH-NOTHING-TO-SAY AND FAILED ARE THREE DIFFERENT
// ENDINGS, and the middle one is why this test exists (P3 criterion 15).**
//
// A job that found nothing and a job that fell over both publish zero
// envelopes. "No envelopes" is therefore not a distinction, and a log that
// offers only that tells an operator the wrong thing at the moment they most
// need the right one. The count and the cause together are what separate them.
func TestAJobsEndIsRecordedAndSaysWhichEndItWas(t *testing.T) {
	for name, tc := range map[string]struct {
		src        *scriptedSource
		wantEvents int
		wantErr    bool
	}{
		"finished with results":    {src: &scriptedSource{rows: 3}, wantEvents: 3},
		"finished with nothing":    {src: &scriptedSource{rows: 0}, wantEvents: 0},
		"failed before publishing": {src: &scriptedSource{rows: 3, panics: true}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			gate := newGate()
			h := build(t, tc.src, gate, kyuushin.Options{})

			if _, err := h.p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"},
				Target: target(t), Driver: tc.src, Limit: 10,
				DecisionID: "dec_under_test",
			}); err != nil {
				t.Fatalf("Submit: %v", err)
			}
			if err := h.p.Stop(context.Background()); err != nil {
				t.Fatalf("Stop: %v", err)
			}

			got := gate.endingsSeen()
			if len(got) != 1 {
				t.Fatalf("the job's end was recorded %d times, want exactly once. A job "+
					"whose end is unobservable is the melt in a different coat: the "+
					"caller waits for ever and nothing says so", len(got))
			}
			end := got[0]
			if end.decisionID != "dec_under_test" {
				t.Errorf("the end closed decision %q, not the one the job was admitted "+
					"under — the log then holds an orphaned intent beside an unrelated "+
					"outcome, which nothing joins", end.decisionID)
			}
			if tc.wantErr && end.err == nil {
				t.Error("a job that FAILED was recorded as having finished. This is the " +
					"conflation criterion 15 names: it published nothing, and so did a " +
					"job that simply found nothing")
			}
			if !tc.wantErr && end.err != nil {
				t.Errorf("a job that finished was recorded as failed: %v", end.err)
			}
			if end.events != tc.wantEvents {
				t.Errorf("the end records %d events, want %d — the count is what makes "+
					"finished-with-nothing legible as a success rather than as a silence",
					end.events, tc.wantEvents)
			}
		})
	}
}

// **A SCHEDULE HAS NO END TO RECORD, AND MUST NOT INVENT ONE (D249).** A
// recurrence has no caller and no intent row; writing an outcome against an
// empty decision id would be a row joined to nothing, and doing it once per
// tick would be D178's amplification on a timer.
func TestARecurrenceRecordsNoEnding(t *testing.T) {
	gate := newGate()
	src := &scriptedSource{rows: 4}
	h := build(t, src, gate, kyuushin.Options{})

	runFor(t, h, 50*time.Millisecond)

	if got := gate.endingsSeen(); len(got) != 0 {
		t.Errorf("a recurrence recorded %d ending(s) (%+v). It has no caller, no intent "+
			"row and no end; the per-poll records and the heartbeat are what say it is "+
			"still running", len(got), got)
	}
}

// **A JOB'S STATUS IS KNOWN THE MOMENT `Submit` RETURNS (D254).** A caller
// holds the id immediately, so a status written by the worker goroutine would
// leave a window where the honest answer is `unknown` — and `unknown` means
// "no such job". Reporting a job that is about to run as one that never
// existed is the defect this verb exists to prevent, arriving as a race.
func TestAJobIsKnownAsRunningBeforeItFinishes(t *testing.T) {
	gate := newGate()
	src := &scriptedSource{rows: 3, blockFor: time.Hour}
	h := build(t, src, gate, kyuushin.Options{PollTimeout: time.Hour})

	id, err := h.p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"},
		Target: target(t), Driver: src, Limit: 10,
		Identity:   assertedFor("agent:triage"),
		DecisionID: "dec_running",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	st, known := h.p.Status(id)
	if !known {
		t.Fatal("a job that Submit just returned is not known, so a caller asking " +
			"immediately is told its own job does not exist")
	}
	if st.State != kyuushin.StateRunning {
		t.Errorf("state is %v, want running", st.State)
	}
	if st.Principal != "agent:triage" {
		t.Errorf("the job records owner %q; without the right owner the gateway "+
			"cannot tell the caller's own job from somebody else's", st.Principal)
	}

	h.p.Cancel(id)
	_ = h.p.Stop(context.Background())
}

// THE TERMINAL STATES REACH THE REGISTRY, not only the audit log. The record
// is the operator's; this is what a caller can be told (D254).
func TestAFinishedJobsStateIsQueryable(t *testing.T) {
	for name, tc := range map[string]struct {
		src   *scriptedSource
		want  kyuushin.State
		count int
	}{
		"finished": {src: &scriptedSource{rows: 2}, want: kyuushin.StateFinished, count: 2},
		"failed":   {src: &scriptedSource{rows: 2, panics: true}, want: kyuushin.StateFailed},
	} {
		t.Run(name, func(t *testing.T) {
			h := build(t, tc.src, newGate(), kyuushin.Options{})
			id, err := h.p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"},
				Target: target(t), Driver: tc.src, Limit: 10,
				Identity: assertedFor("agent:triage"), DecisionID: "dec_x",
			})
			if err != nil {
				t.Fatalf("Submit: %v", err)
			}
			if err := h.p.Stop(context.Background()); err != nil {
				t.Fatalf("Stop: %v", err)
			}

			st, known := h.p.Status(id)
			if !known {
				t.Fatal("the job is not known after it ended")
			}
			if st.State != tc.want {
				t.Errorf("state is %v, want %v", st.State, tc.want)
			}
			if st.Events != tc.count {
				t.Errorf("events is %d, want %d", st.Events, tc.count)
			}
			if tc.want == kyuushin.StateFailed && st.Err == nil {
				t.Error("a failed job carries no error, so the caller is told it failed " +
					"and not why")
			}
		})
	}
}

// AN UNKNOWN ID IS NOT KNOWN, which is the property the gateway builds its
// non-oracle answer on.
func TestAnUnknownJobIsNotKnown(t *testing.T) {
	h := build(t, &scriptedSource{}, newGate(), kyuushin.Options{})
	if _, known := h.p.Status("no-such-job"); known {
		t.Error("an id nobody minted is reported as known")
	}
}

// **THE REGISTRY IS BOUNDED, AND A RUNNING JOB IS NEVER THE THING EVICTED.**
// An unbounded map of every job a replica ever ran is D178's amplification
// with a slow clock; evicting a job still in flight would answer "unknown"
// for the one case this verb exists to serve.
func TestTheStatusTableIsBoundedAndKeepsRunningJobs(t *testing.T) {
	src := &scriptedSource{rows: 1}
	h := build(t, src, newGate(), kyuushin.Options{})

	// One job that stays running for the duration.
	blocker := &scriptedSource{rows: 1, blockFor: time.Hour}
	running, err := h.p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"},
		Target: target(t), Driver: blocker, Limit: 1,
		Identity: assertedFor("agent:triage"), DecisionID: "dec_block",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitUntil(t, func() bool {
		st, ok := h.p.Status(running)
		return ok && st.State == kyuushin.StateRunning
	}, "the blocking job never registered as running")

	// The FIRST finished job, whose eviction is the observable bound.
	//
	// ASSERTED ON BEHAVIOUR RATHER THAN ON A COUNT, because a `StatusCount`
	// accessor would be an export whose only caller is this test — the shape
	// `archcheck` refuses, and one this test does not need: "the oldest
	// finished job is forgotten" IS the bound, stated the way a caller
	// experiences it.
	oldest, err := h.p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"},
		Target: target(t), Driver: src, Limit: 1,
		Identity: assertedFor("agent:triage"), DecisionID: "dec_first",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitUntil(t, func() bool {
		st, ok := h.p.Status(oldest)
		return ok && st.State == kyuushin.StateFinished
	}, "the first job never finished")

	// Then enough finished jobs to push the table past its bound.
	for range 1200 {
		if _, err := h.p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"},
			Target: target(t), Driver: src, Limit: 1,
			Identity: assertedFor("agent:triage"), DecisionID: "dec_y",
		}); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	waitUntil(t, func() bool {
		_, ok := h.p.Status(oldest)
		return !ok
	}, "the oldest finished job was never evicted, so the status table grows "+
		"without limit for the lifetime of the replica")

	if _, ok := h.p.Status(running); !ok {
		t.Error("the RUNNING job was evicted. A caller whose job is still working " +
			"was told it does not exist, which is the one answer this verb must " +
			"never give wrongly")
	}

	h.p.Cancel(running)
	_ = h.p.Stop(context.Background())
}

// assertedFor is the identity shape a caller's job carries.
func assertedFor(principal string) *sekizuiv1.Identity {
	return &sekizuiv1.Identity{
		Caller:  &sekizuiv1.Caller{Principal: principal},
		Subject: &sekizuiv1.Subject{Principal: principal},
		Chain:   []string{principal},
	}
}

// waitUntil polls a condition, so a concurrency test does not depend on a
// sleep somebody tuned once.
func waitUntil(t *testing.T, cond func() bool, whatFailed string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(whatFailed)
}

// drainResults attaches to a finished job's results and reads them to the end.
// The stream ENDS when the job does (D267), so this returns rather than waiting
// out a deadline — and hanging here would itself be the failure.
func drainResults(t *testing.T, p *kyuushin.Runner, id string) []*sekizuiv1.Envelope {
	t.Helper()
	res, ok := p.Results(id)
	if !ok {
		t.Fatalf("job %s has no results held for its caller", id)
	}
	if err := res.Attach(); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := res.Attach(); err == nil {
		t.Error("a second reader attached to the same job's results; each would receive " +
			"part of them and neither could tell")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out []*sekizuiv1.Envelope
	for {
		env, ok := res.Next(ctx)
		if !ok {
			if ctx.Err() != nil {
				t.Fatal("the results stream did not end with the job")
			}
			return out
		}
		out = append(out, env)
	}
}

// TestUncollectedResultsExpireAfterTheConfiguredTTL is D268: the TTL is the
// deployment's, and a value that parsed and was ignored would be D262's defect
// in the jobs plane. A short TTL drops the results; before it, they are held.
func TestUncollectedResultsExpireAfterTheConfiguredTTL(t *testing.T) {
	gate := newGate()
	src := &scriptedSource{rows: 2}
	h := build(t, src, gate, kyuushin.Options{ResultsTTL: 100 * time.Millisecond})

	id, err := h.p.Submit(context.Background(), kyuushin.Job{Outputs: []string{"kata.row.v1"}, Target: target(t), Driver: src, Limit: 10})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if err := h.p.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, held := h.p.Results(id); !held {
		t.Fatal("the results were gone the moment the job finished; the TTL was not applied")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, held := h.p.Results(id); !held {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("uncollected results outlived a 100ms TTL by seconds; the configured value is ignored")
}

// permissive shapes nothing and accepts everything: these arms are about the
// runner, and shaping and validation are proven end to end (P3 step 18,
// D276, D277) and in `internal/schemareg`.
type permissive struct{}

func (permissive) Shape(_ string, p map[string]any) (map[string]any, schemareg.Shaped) {
	return p, schemareg.Shaped{}
}
func (permissive) Validate(string, map[string]any) error { return nil }

func (s *scriptedSource) pollCount() int { s.mu.Lock(); defer s.mu.Unlock(); return s.polls }

// TestARestartKeepsTheCadence is CONTRACTS 134: the first poll after a start is
// due one interval after the last poll STARTED, as the store remembers it —
// not one whole interval after the process came up, which reset on every
// restart and let a source with a long interval never poll at all.
func TestARestartKeepsTheCadence(t *testing.T) {
	const every = time.Second
	for _, tc := range []struct {
		name       string
		last       func(now time.Time) time.Time // zero func: never polled
		pollBy     time.Duration                 // a poll must have happened by then
		quietUntil time.Duration                 // and none before then
	}{
		{"never polled: at once", nil, 300 * time.Millisecond, 0},
		{"overdue: at once", func(n time.Time) time.Time { return n.Add(-time.Hour) }, 300 * time.Millisecond, 0},
		{"mid-interval: when due, not a whole interval later",
			func(n time.Time) time.Time { return n.Add(-800 * time.Millisecond) }, 600 * time.Millisecond, 0},
		{"in the future: counts as now, so one interval and no further",
			func(n time.Time) time.Time { return n.Add(24 * time.Hour) }, 1500 * time.Millisecond, 600 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := cursor.NewFileStore(t.TempDir())
			if tc.last != nil {
				if err := store.Polled(context.Background(), "kata:alpha", tc.last(time.Now())); err != nil {
					t.Fatal(err)
				}
			}
			src := &scriptedSource{}
			h := buildWith(t, src, newGate(), kyuushin.Options{}, every, store)
			began := time.Now()
			if err := h.p.Start(context.Background()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer func() { _ = h.p.Stop(context.Background()) }()
			if tc.quietUntil > 0 {
				time.Sleep(tc.quietUntil)
				if n := src.pollCount(); n != 0 {
					t.Fatalf("polled %d time(s) within %v; a poll time in the future counts as NOW, "+
						"and a restart must not poll before one interval", n, tc.quietUntil)
				}
			}
			for src.pollCount() == 0 && time.Since(began) < tc.pollBy {
				time.Sleep(10 * time.Millisecond)
			}
			if src.pollCount() == 0 {
				t.Fatalf("no poll within %v of the start; the last poll time says it was due", tc.pollBy)
			}
		})
	}
}

// TestEveryTickRecordsItsTimeAndKeepsTheRest — the time is written on an EMPTY
// poll too (a quiet source's time must not go stale), before the poll, and a
// Commit keeps it while Polled keeps the cursor.
func TestEveryTickRecordsItsTimeAndKeepsTheRest(t *testing.T) {
	ctx := context.Background()
	store := cursor.NewFileStore(t.TempDir())
	if err := store.Commit(ctx, "kata:alpha", "c-7"); err != nil {
		t.Fatal(err)
	}
	src := &scriptedSource{} // returns nothing: a quiet source
	h := buildWith(t, src, newGate(), kyuushin.Options{}, time.Hour, store)
	before := time.Now().Add(-time.Second)
	runFor(t, h, 200*time.Millisecond)
	st, err := store.Load(ctx, "kata:alpha")
	if err != nil {
		t.Fatal(err)
	}
	if st.LastPoll.Before(before) {
		t.Errorf("an empty poll left LastPoll at %v; a quiet source whose time goes stale polls at "+
			"once on every restart", st.LastPoll)
	}
	if st.Cursor != "c-7" {
		t.Errorf("recording the poll time changed the cursor to %q", st.Cursor)
	}
	stamped := st.LastPoll
	if err := store.Commit(ctx, "kata:alpha", "c-8"); err != nil {
		t.Fatal(err)
	}
	if st, _ = store.Load(ctx, "kata:alpha"); !st.LastPoll.Equal(stamped) {
		t.Errorf("Commit wiped the poll time (%v -> %v)", stamped, st.LastPoll)
	}
}
