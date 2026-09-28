package acceptance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// P3 steps 1-3 — exit criterion 3: "restart resumes from cursor with no
// duplicates and no gaps across a kill -9". D170 split it: NO DUPLICATES is
// ours to answer, NO GAPS is the connector's to declare (steps 11, 12).
//
// **WHAT "DURABLE" MEANS HERE (D293).** Nothing durable holds an envelope: the
// bus is at-most-once (D24). What the cursor waits for is the envelope
// PUBLISHED and the fsynced progress mark covering it (D275) — so a crash
// re-publishes at most the one envelope between a publish and its mark, and
// never loses one. At-least-once delivery to a subscriber is JetStream's, a
// driver swap.

// ingestInstance is the real `sekizui` binary under `-mode=ingest`, over a
// write-ahead directory the caller owns — so a second instance can be started
// over the SAME directory after a SIGKILL (P3 steps 1, 14).
type ingestInstance struct {
	cmd    *exec.Cmd
	logs   *strings.Builder
	probe  string
	killed bool
}

// buildSekizui builds the binary once per step, into a temporary directory.
func buildSekizui(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sekizui")
	build := exec.Command(goTool(t), "build", "-o", bin, "./cmd/sekizui")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the binary: %v\n%s", err, out)
	}
	return bin
}

// startIngest starts an instance and does NOT wait for it: a step asserting a
// boot refusal needs the process that refused.
func startIngest(t *testing.T, bin, root, certs, wal string) *ingestInstance {
	t.Helper()
	grpcAddr, probeAddr := freePort(t), freePort(t)
	cmd := exec.Command(bin,
		"-mode", "ingest",
		// A LAPTOP HAS NO LEADER ELECTION, and ingest refuses without it (§5.3).
		// The override is the documented one for coordination provided
		// externally; here there is exactly one process at a time.
		"-leader-election", "true",
		"-config", filepath.Join(root, "internal", "acceptance", "acceptance.yaml"),
		"-grpc-addr", grpcAddr, "-addr", probeAddr,
		"-wal", wal, "-residency", strings.Join(acceptanceResidency, ","), "-log-text", "-log-level", "info",
		"-tls-cert", filepath.Join(certs, "server.crt"),
		"-tls-key", filepath.Join(certs, "server.key"),
		"-tls-client-ca", filepath.Join(certs, "ca.crt"),
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SEKIZUI_ACCEPT_TOK=local-development-token",
		"SEKIZUI_REGION=europe-west1",
	)
	inst := &ingestInstance{cmd: cmd, logs: &strings.Builder{}, probe: probeAddr}
	cmd.Stdout, cmd.Stderr = inst.logs, inst.logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the instance: %v", err)
	}
	t.Cleanup(func() {
		inst.kill()
		if t.Failed() {
			t.Logf("the instance's own log:\n%s", inst.logs.String())
		}
	})
	return inst
}

func (i *ingestInstance) ready(t *testing.T) {
	t.Helper()
	waitForReady(t, i.probe, i.logs)
}

// kill is a SIGKILL — `os.Process.Kill` on unix — and then `exec.Cmd.Wait`,
// which returns only once exec's copy of the child's output has finished, so
// the log may be read afterwards without a race (GO-PRIMER §15an).
func (i *ingestInstance) kill() {
	if i.killed {
		return
	}
	i.killed = true
	_ = i.cmd.Process.Kill()
	_ = i.cmd.Wait()
}

// realInstanceStep resolves what a real-binary step needs, or skips it.
func realInstanceStep(t *testing.T) (root, certs string) {
	t.Helper()
	root = mustRoot(t)
	certs = filepath.Join(root, "dev", "certs")
	if _, err := os.Stat(filepath.Join(certs, "ca.crt")); err != nil {
		t.Skip("no development certificates; run `make dev-certs`")
	}
	return root, certs
}

// p3Step1 — a cursor survives a kill -9 and the poll resumes from it (P3
// criterion 3, D173, D240).
//
// **THE REAL BINARY AND A REAL SIGKILL**, the way step 14 proves `-mode=ingest`
// polls at all: what is in question is that the cursor a process wrote is the
// cursor the NEXT process reads, which no in-process runner can show.
//
// **WHAT A KILL CANNOT BE AIMED AT.** A SIGKILL from outside cannot be timed
// between two envelopes without a crash hook in the production binary, and a
// hook that kills the process on a signal is attack surface this step will not
// add. So the mid-publish state is STAGED in steps 3, 11 and 12, and this step
// proves the part only a real process can: what survived the kill, and that
// the restart acted on it.
func p3Step1(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "a cursor survives a kill -9 and the poll resumes from it")
	if r.localOnly(t, "this step launches its own instances") {
		return
	}
	root, certs := realInstanceStep(t)
	bin := buildSekizui(t, root)
	wal := t.TempDir()
	audit := filepath.Join(wal, "audit.jsonl")
	// THE SEAM, NOT THE FILE (D240): the store the binary wires over `-wal`,
	// read through its interface. Its layout is its own business.
	store := cursor.NewFileStore(filepath.Join(wal, "cursors"))
	ctx := context.Background()

	// 1a — THE FIRST INSTANCE POLLS kata:alpha's three rows and commits; then
	// it is killed, not stopped.
	first := startIngest(t, bin, root, certs, wal)
	first.ready(t)
	waitFor(t, func() bool {
		st, err := store.Load(ctx, "kata:alpha")
		return err == nil && st.Cursor != "" && st.Pending == nil
	}, "the first instance never committed a cursor for kata:alpha")
	first.kill()

	before, err := store.Load(ctx, "kata:alpha")
	if err != nil || before.Cursor != "3" || before.Pending != nil {
		t.Fatalf("step 1a: after the SIGKILL the store holds cursor %q, pending %v (err %v); want "+
			"the committed cursor past kata:alpha's three rows", before.Cursor, before.Pending, err)
	}
	published := publishingIntents(t, audit, "kata:alpha")
	if len(published) != 1 {
		t.Fatalf("step 1a: the first instance wrote %d publishing intents for kata:alpha (%q); want "+
			"the one poll that published its three rows", len(published), published)
	}
	recordsBefore := len(readLog(t, audit))

	// 1b — THE SECOND INSTANCE, OVER THE SAME DIRECTORY, POLLS FROM THE
	// CURSOR: it polls kata:alpha, and publishes nothing, because nothing is
	// past the cursor. A restart that lost the cursor re-reads from the
	// beginning and writes a second publishing intent for the same rows.
	second := startIngest(t, bin, root, certs, wal)
	second.ready(t)
	waitFor(t, func() bool {
		for _, d := range readLog(t, audit)[recordsBefore:] {
			if d.GetTargetRef() == "kata:alpha" && d.GetMatchedRule() == "poll:completed" {
				return true
			}
		}
		return false
	}, "the restarted instance never recorded a poll of kata:alpha")
	second.kill()
	if again := publishingIntents(t, audit, "kata:alpha"); len(again) != len(published) {
		t.Errorf("step 1b: the restarted instance published kata:alpha's rows again (%q, was %q) — "+
			"the cursor did not survive the kill, or was not read", again, published)
	}
	for _, d := range readLog(t, audit)[recordsBefore:] {
		if d.GetTargetRef() == "kata:alpha" && d.GetMatchedRule() == "poll:completed" &&
			d.GetReason() != "0 events" {
			t.Errorf("step 1b: the restarted instance's poll of kata:alpha says %q; past the "+
				"cursor there is nothing", d.GetReason())
		}
	}
	if after, err := store.Load(ctx, "kata:alpha"); err != nil || after.Cursor != before.Cursor {
		t.Errorf("step 1b: the cursor moved from %q to %q (err %v) with nothing to poll",
			before.Cursor, after.Cursor, err)
	}

	// 1c — A STORE THAT CANNOT LOAD FAILS THE BOOT (D240's reading of D150).
	// An absent cursor is not a degraded start: it is every source replayed
	// from the beginning. Made unloadable at the seam's location, not its
	// layout: the directory the binary wires is a file.
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "cursors"), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("step 1c: %v", err)
	}
	refused := startIngest(t, bin, root, certs, broken)
	exited := make(chan error, 1)
	go func() { exited <- refused.cmd.Wait() }()
	select {
	case err := <-exited:
		refused.killed = true
		if err == nil {
			t.Error("step 1c: an instance whose cursor store cannot load exited 0")
		}
		if !strings.Contains(strings.ToLower(refused.logs.String()), "cursor") {
			t.Errorf("step 1c: the boot refusal does not name the cursor store:\n%s", refused.logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Error("step 1c: an instance whose cursor store cannot load was still running after 20s")
		_ = refused.cmd.Process.Kill()
		<-exited // the one Wait, already running
		refused.killed = true
	}

	// 1d — A STORE THAT CANNOT WRITE FAILS THE POLL BEFORE ANYTHING IS
	// PUBLISHED, and the next tick retries rather than skips: nothing was
	// lost, because nothing was sent.
	p3Step1CannotWrite(t, r)

	r.detail(t, "a real instance committed kata:alpha's cursor, was SIGKILLed, and a second instance "+
		"over the same directory polled from it and published nothing again; an unloadable store "+
		"refused the boot; an unwritable one failed the poll before publishing, and the retry lost nothing")
}

// publishingIntents returns the productive polls of a source in a log, as
// their reasons — which say how many events each put at risk.
//
// **ONE POLL, BY DECISION ID — NOT ONE PER ROW.** A productive poll writes its
// intent before publishing and its OUTCOME, under the same id with `effect`
// set, after the commit. Counting rows counted one poll twice whenever the
// SIGKILL landed after `Complete` rather than before it: roughly one run in
// five, and it read as the binary publishing its rows twice.
func publishingIntents(t *testing.T, audit, ref string) []string {
	t.Helper()
	var out []string
	seen := map[string]bool{}
	for _, d := range readLog(t, audit) {
		if d.GetTargetRef() == ref && d.GetMatchedRule() == "poll:publishing" && !seen[d.GetId()] {
			seen[d.GetId()] = true
			out = append(out, d.GetReason())
		}
	}
	return out
}

// p3Step1CannotWrite is step 1d, in process: a store whose Begin fails.
func p3Step1CannotWrite(t *testing.T, r *run) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sub, err := r.as(t, "agent:scoped").Subscribe(ctx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.raw.kata.>"}})
	if err != nil {
		t.Fatalf("step 1d: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 }, "the subscription never registered")

	store := &faultStore{Store: cursor.NewFileStore(t.TempDir())}
	store.set(func(f *faultStore) { f.failBegin = true })
	runner := newRunnerFor(t, r, ctx,
		[]config.SourceSpec{{TargetRef: "kata:alpha", EverySec: 1, Limit: 10}}, store)
	if err := runner.Start(ctx); err != nil {
		t.Fatalf("step 1d: %v", err)
	}
	defer func() { _ = runner.Stop(context.Background()) }()
	waitFor(t, func() bool { return store.count("Begin") >= 2 },
		"the runner never retried a poll whose attempt could not be written")

	// NOTHING PUBLISHED: the first delivery is a sentinel published after two
	// failed ticks.
	sentinel := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": 1})
	sentinel.Id, sentinel.Source = "1d-sentinel", "kata:alpha"
	if err := r.srv.PublishForTest(sentinel); err != nil {
		t.Fatalf("step 1d: %v", err)
	}
	if m, err := sub.Recv(); err != nil || m.GetEnvelope().GetId() != "1d-sentinel" {
		t.Fatalf("step 1d: a poll that could not record its attempt published %q anyway (err %v) "+
			"— a crash now would lose it with nothing to name it by", m.GetEnvelope().GetId(), err)
	}
	if st, _ := store.Load(ctx, "kata:alpha"); st.Cursor != "" {
		t.Fatalf("step 1d: the cursor advanced to %q through a store that cannot write", st.Cursor)
	}

	// HEALED, THE NEXT TICK PUBLISHES ALL THREE: the failure direction is a
	// retry, never a skip.
	store.set(func(f *faultStore) { f.failBegin = false })
	for i := range 3 {
		m, err := sub.Recv()
		if err != nil || m.GetEnvelope().GetSubject() != fmt.Sprintf("row/%d", i) {
			t.Fatalf("step 1d: after the store healed, delivery %d was %q (err %v); want row/%d — "+
				"the failed ticks lost rows", i, m.GetEnvelope().GetSubject(), err, i)
		}
	}
}

// p3Step2 — the cursor advances only after every envelope is published and
// marked (P3 criterion 3, D275, D293).
//
// Proven by faults injected between the steps, not by reading the code: a mark
// that cannot be written stops the poll uncommitted; a commit that fails
// leaves every mark in place; and in an ordinary poll the commit is the last
// write, made only once the mark covers every event.
func p3Step2(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the cursor advances only after the envelope is published and marked")
	if r.localOnly(t, "the runner and its cursor store are this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sub, err := r.as(t, "agent:scoped").Subscribe(ctx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.raw.kata.>"}})
	if err != nil {
		t.Fatalf("step 2: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 }, "the subscription never registered")

	// ONE TICK AT A TIME: each arm starts a runner, lets it poll, and stops it
	// before looking, so a retry tick cannot blur what the fault did.
	once := func(store *faultStore) {
		t.Helper()
		runner := newRunnerFor(t, r, ctx,
			[]config.SourceSpec{{TargetRef: "kata:alpha", EverySec: 60, Limit: 10}}, store)
		if err := runner.Start(ctx); err != nil {
			t.Fatalf("step 2: %v", err)
		}
		waitFor(t, func() bool { return store.count("Begin") >= 1 && store.settled() },
			"the poll never finished its tick")
		_ = runner.Stop(context.WithoutCancel(ctx))
	}
	drainUntilSentinel := func(arm string) []string {
		t.Helper()
		sentinel := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": 1})
		sentinel.Id, sentinel.Source = arm+"-sentinel", "kata:alpha"
		if err := r.srv.PublishForTest(sentinel); err != nil {
			t.Fatalf("step %s: %v", arm, err)
		}
		var got []string
		for {
			m, err := sub.Recv()
			if err != nil {
				t.Fatalf("step %s: %v", arm, err)
			}
			if m.GetEnvelope().GetId() == arm+"-sentinel" {
				return got
			}
			got = append(got, m.GetEnvelope().GetSubject())
		}
	}

	// 2a — THE MARK AFTER ROW 0 FAILS: row 0 went out, the poll stops there, and the
	// cursor has not moved. The mark says 0 — the failed write never landed —
	// so a recovery re-publishes row 0: one duplicate, the direction D275 chose.
	a := &faultStore{Store: cursor.NewFileStore(t.TempDir())}
	a.set(func(f *faultStore) { f.failProgressAt = 1 })
	once(a)
	if got := drainUntilSentinel("2a"); strings.Join(got, ",") != "row/0" {
		t.Errorf("step 2a: with the mark after row 0 failing, the poll delivered %v; want row/0 "+
			"and nothing after — publishing on past a mark that no longer tracks is the state the "+
			"mark exists to prevent", got)
	}
	if st, _ := a.Load(ctx, "kata:alpha"); st.Cursor != "" || st.Pending == nil || st.Pending.Published != 0 {
		t.Errorf("step 2a: after the failed mark the store holds cursor %q, pending %+v; want no "+
			"cursor and the attempt pending at mark 0", st.Cursor, st.Pending)
	}

	// 2b — THE COMMIT FAILS: all three published and marked, the cursor
	// unmoved, the attempt pending at its full mark — step 3's starting point.
	b := &faultStore{Store: cursor.NewFileStore(t.TempDir())}
	b.set(func(f *faultStore) { f.failCommit = true })
	once(b)
	if got := drainUntilSentinel("2b"); strings.Join(got, ",") != "row/0,row/1,row/2" {
		t.Errorf("step 2b: the poll delivered %v; want the three rows", got)
	}
	if st, _ := b.Load(ctx, "kata:alpha"); st.Cursor != "" || st.Pending == nil || st.Pending.Published != 3 {
		t.Errorf("step 2b: after the failed commit the store holds cursor %q, pending %+v; want no "+
			"cursor and the attempt pending at mark 3", st.Cursor, st.Pending)
	}

	// 2c — THE ORDER OF AN ORDINARY POLL: Begin, a mark per event, and the
	// commit LAST, made only once the mark covers every at-risk event.
	c := &faultStore{Store: cursor.NewFileStore(t.TempDir())}
	once(c)
	_ = drainUntilSentinel("2c")
	if got := strings.Join(c.writes(), " "); got != "Begin(3) Progress(1) Progress(2) Progress(3) Commit(3)" {
		t.Errorf("step 2c: the store saw %q; the cursor must be the last write, after every mark", got)
	}
	r.detail(t, "a failed mark stopped the poll after row 0 with the cursor unmoved; a failed commit "+
		"left all three marked and the cursor unmoved; an ordinary poll wrote Begin, three marks, "+
		"then the commit")
}

// p3Step3 — a restart does not re-deliver, and the dedupe record is ours
// rather than the audit log's (P3 criterion 3, D170, D240).
func p3Step3(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "a restart does not re-deliver, and the dedupe record is ours rather than the audit log's")
	if r.localOnly(t, "the runner and its cursor store are this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sub, err := r.as(t, "agent:scoped").Subscribe(ctx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.raw.kata.>"}})
	if err != nil {
		t.Fatalf("step 3: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 }, "the subscription never registered")

	// 3a — THE RECORD IS THE RUNNER'S OWN, IN THE CURSOR STORE: a poll whose
	// commit failed (step 2b's state) left the at-risk ids and the mark
	// covering them, readable through the store's interface. Nothing about it
	// is in, or read from, the audit log.
	store := &faultStore{Store: cursor.NewFileStore(t.TempDir())}
	store.set(func(f *faultStore) { f.failCommit = true })
	first := newRunnerFor(t, r, ctx,
		[]config.SourceSpec{{TargetRef: "kata:alpha", EverySec: 60, Limit: 10}}, store)
	if err := first.Start(ctx); err != nil {
		t.Fatalf("step 3: %v", err)
	}
	waitFor(t, func() bool { return store.count("Commit") >= 1 }, "the poll never reached its commit")
	_ = first.Stop(context.Background())
	for range 3 {
		if _, err := sub.Recv(); err != nil {
			t.Fatalf("step 3: %v", err)
		}
	}
	st, err := store.Load(ctx, "kata:alpha")
	if err != nil || st.Pending == nil || st.Pending.Published != 3 ||
		strings.Join(st.Pending.IDs, ",") != "kata:alpha#0,kata:alpha#1,kata:alpha#2" {
		t.Fatalf("step 3a: the store holds pending %+v (err %v); want the three at-risk ids, all "+
			"marked published — the dedupe record, in the runner's own store", st.Pending, err)
	}
	recordsBefore := len(readLog(t, r.path))

	// 3b — THE RESTART RE-DELIVERS NOTHING: a new runner over the same store
	// re-reads the window (kata declares `requery`), finds every id marked, and
	// publishes none of them. The sentinel is the first delivery after it.
	// A ONE-SECOND CADENCE: the first runner recorded when it polled, and a
	// restart waits one interval from then (D285, step 41) — at 60s, a minute.
	store.set(func(f *faultStore) { f.failCommit = false })
	second := newRunnerFor(t, r, ctx,
		[]config.SourceSpec{{TargetRef: "kata:alpha", EverySec: 1, Limit: 10}}, store)
	if err := second.Start(ctx); err != nil {
		t.Fatalf("step 3: %v", err)
	}
	waitFor(t, func() bool {
		st, err := store.Load(ctx, "kata:alpha")
		return err == nil && st.Pending == nil && st.Cursor == "3"
	}, "the restarted runner never committed past the recovered window")
	_ = second.Stop(context.Background())
	sentinel := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": 1})
	sentinel.Id, sentinel.Source = "3b-sentinel", "kata:alpha"
	if err := r.srv.PublishForTest(sentinel); err != nil {
		t.Fatalf("step 3b: %v", err)
	}
	if m, err := sub.Recv(); err != nil || m.GetEnvelope().GetId() != "3b-sentinel" {
		t.Fatalf("step 3b: the restart delivered %q before the sentinel (err %v); every id was "+
			"marked published, so nothing should have been", m.GetEnvelope().GetSubject(), err)
	}

	// 3c — THE LOG SAYS "RECOVERED, NOTHING LEFT", NOT "THREE EVENTS AGAIN".
	// The first version recorded the re-read window as `poll:completed "3
	// events"`, indistinguishable in the log from a real re-delivery.
	recovered := false
	for _, d := range readLog(t, r.path)[recordsBefore:] {
		if d.GetTargetRef() != "kata:alpha" {
			continue
		}
		if d.GetMatchedRule() == "poll:completed" && d.GetReason() != "0 events" {
			t.Errorf("step 3c: the restart recorded %q for a window it published nothing from",
				d.GetReason())
		}
		if d.GetMatchedRule() == "poll:publishing" &&
			strings.Contains(d.GetReason(), "recovering an interrupted poll: 3 of 3") {
			recovered = true
		}
	}
	if !recovered {
		t.Error("step 3c: no intent records the recovery; the log shows nothing where the spine " +
			"invoked the connector's recovery policy")
	}

	// 3d — THE RECORD IS BOUNDED: committed, the ids are gone (D240). The
	// store keeps the uncommitted window, never a history of every id seen.
	if st, _ := store.Load(ctx, "kata:alpha"); st.Pending != nil {
		t.Errorf("step 3d: after the commit the store still holds %+v; the dedupe record must be "+
			"deleted on commit, or it grows for ever", st.Pending)
	}

	// 3e — A SOURCE THAT CANNOT RE-READ, STOPPED WITH EVERYTHING PUBLISHED,
	// LOST NOTHING — and says so by writing no gap. The first version wrote
	// "0 event(s) may never have been delivered" on every such restart.
	gapStore := cursor.NewFileStore(t.TempDir())
	if err := gapStore.Begin(ctx, "kata:gap", cursor.Attempt{To: "3",
		IDs: []string{"kata:gap#0", "kata:gap#1", "kata:gap#2"}, At: time.Now().UTC()}); err != nil {
		t.Fatalf("step 3e: %v", err)
	}
	if err := gapStore.Progress(ctx, "kata:gap", 3); err != nil {
		t.Fatalf("step 3e: %v", err)
	}
	recordsBefore = len(readLog(t, r.path))
	gapRunner := newRunnerFor(t, r, ctx,
		[]config.SourceSpec{{TargetRef: "kata:gap", EverySec: 60, Limit: 10}}, gapStore)
	if err := gapRunner.Start(ctx); err != nil {
		t.Fatalf("step 3e: %v", err)
	}
	waitFor(t, func() bool {
		st, err := gapStore.Load(ctx, "kata:gap")
		return err == nil && st.Pending == nil && st.Cursor == "3"
	}, "kata:gap never committed past its fully published window")
	_ = gapRunner.Stop(context.Background())
	for _, d := range readLog(t, r.path)[recordsBefore:] {
		if d.GetVerdict() == sekizuiv1.Verdict_VERDICT_GAP {
			t.Errorf("step 3e: a window whose every event was published produced a gap record: %q",
				d.GetReason())
		}
	}
	// The import-graph half of "ours rather than the audit log's" — nothing on
	// the afferent path reaches internal/auditwal, transitively — is step 42a's
	// arm; it is not repeated here.
	r.detail(t, "the at-risk ids and their mark lived in the cursor store; a restart re-read the "+
		"window and delivered nothing again, recorded a recovery rather than three events, and "+
		"deleted the record on commit; a fully published window of a source that cannot re-read "+
		"wrote no gap")
}

// faultStore wraps a cursor store to fail chosen writes and remember every
// write it saw, in order (P3 steps 1-3).
type faultStore struct {
	cursor.Store
	mu             sync.Mutex
	failBegin      bool
	failCommit     bool
	failProgressAt int // fail Progress(n) for this n; 0 = never
	log            []string
	inFlight       bool
}

var errInjected = errors.New("injected store fault")

func (f *faultStore) set(change func(*faultStore)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *faultStore) note(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, s)
}

func (f *faultStore) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.log {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

// writes is every Begin, Progress and Commit, in order — Polled excluded, as
// the cadence's write and not the attempt's.
func (f *faultStore) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

// settled reports that the attempt begun last has ended: committed, or failed.
func (f *faultStore) settled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.inFlight
}

func (f *faultStore) Begin(ctx context.Context, source string, a cursor.Attempt) error {
	// ONE CRITICAL SECTION: noted and in flight together, or `settled` can
	// see a Begin that has not yet started its attempt.
	f.mu.Lock()
	f.log = append(f.log, fmt.Sprintf("Begin(%d)", len(a.IDs)))
	fail := f.failBegin
	f.inFlight = !fail
	f.mu.Unlock()
	if fail {
		return errInjected
	}
	return f.Store.Begin(ctx, source, a)
}

func (f *faultStore) Progress(ctx context.Context, source string, n int) error {
	f.note(fmt.Sprintf("Progress(%d)", n))
	f.mu.Lock()
	fail := f.failProgressAt == n
	if fail {
		f.inFlight = false
	}
	f.mu.Unlock()
	if fail {
		return errInjected
	}
	return f.Store.Progress(ctx, source, n)
}

func (f *faultStore) Commit(ctx context.Context, source string, c string) error {
	f.note("Commit(" + c + ")")
	f.mu.Lock()
	fail := f.failCommit
	f.inFlight = false
	f.mu.Unlock()
	if fail {
		return errInjected
	}
	return f.Store.Commit(ctx, source, c)
}
