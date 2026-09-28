package acceptance

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// crashedMidPublish leaves the durable state a kill -9 between the first and
// second envelope of a three-row poll leaves: the attempt recorded, the mark at
// one, nothing committed. Step 1 proves a REAL SIGKILL leaves this state; these
// steps prove what the spine does with it.
func crashedMidPublish(t *testing.T, ref string) cursor.Store {
	t.Helper()
	store := cursor.NewFileStore(t.TempDir())
	ctx := context.Background()
	if err := store.Begin(ctx, ref, cursor.Attempt{
		From: "", To: "3", IDs: []string{ref + "#0", ref + "#1", ref + "#2"},
		At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("staging the crash: %v", err)
	}
	if err := store.Progress(ctx, ref, 1); err != nil {
		t.Fatalf("staging the crash: %v", err)
	}
	return store
}

// p3Step11 — an interrupted poll recovers by the connector's declared recovery
// policy (P3 criterion 6, D174, D241, D275).
func p3Step11(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "an interrupted poll recovers by the connector's declared recovery policy")
	if r.localOnly(t, "the runner and its cursor store are this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sub, err := r.as(t, "agent:scoped").Subscribe(ctx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.raw.kata.>"},
	})
	if err != nil {
		t.Fatalf("step 11: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 }, "the subscription never registered")

	// kata:alpha declares `requery`: its rows are derived from the cursor.
	runner := newRunnerFor(t, r, ctx, nil, crashedMidPublish(t, "kata:alpha"))
	if err := runner.Start(ctx); err != nil {
		t.Fatalf("step 11: %v", err)
	}
	defer func() { _ = runner.Stop(context.Background()) }()

	// EXACTLY THE ROWS AFTER THE MARK, and row 0 — published before the stop —
	// never again. A sentinel after them proves nothing else followed.
	var got []string
	for len(got) < 2 {
		m, err := sub.Recv()
		if err != nil {
			t.Fatalf("step 11: %d of the 2 rows after the mark arrived before %v — the recovery "+
				"skipped what it should have published, which is the silent loss D275 replaced", len(got), err)
		}
		got = append(got, m.GetEnvelope().GetSubject()+"@"+m.GetEnvelope().GetCausation().GetDecisionId())
	}
	_ = runner.StopSchedule(context.Background())
	sentinel := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": 1})
	sentinel.Id, sentinel.Source = "11-sentinel", "kata:alpha"
	if err := r.srv.PublishForTest(sentinel); err != nil {
		t.Fatalf("step 11: %v", err)
	}
	m, err := sub.Recv()
	if err != nil || m.GetEnvelope().GetId() != "11-sentinel" {
		t.Fatalf("step 11: after rows 1 and 2, the next delivery was %q, not the sentinel — the "+
			"recovery published more than the unpublished rest (err %v)", m.GetEnvelope().GetId(), err)
	}
	for _, g := range got {
		if strings.HasPrefix(g, "row/0@") {
			t.Fatalf("step 11: row 0 was published again; the mark said it had reached the bus (D275)")
		}
	}
	if !strings.HasPrefix(got[0], "row/1@") || !strings.HasPrefix(got[1], "row/2@") {
		t.Fatalf("step 11: recovery delivered %v, want rows 1 and 2 in order", got)
	}

	// AND THE LOG SAYS IT WAS A RECOVERY.
	found := false
	for _, d := range readLog(t, r.path) {
		if d.GetMatchedRule() == "poll:publishing" && strings.Contains(d.GetReason(),
			"recovering an interrupted poll: 1 of 3") {
			found = true
		}
	}
	if !found {
		t.Error("step 11: no poll intent records the recovery; the log would show an ordinary " +
			"poll where the spine in fact invoked the connector's recovery policy")
	}
	r.detail(t, "a poll stopped after 1 of 3 rows was recovered by re-reading the window: rows 1 "+
		"and 2 published exactly once, row 0 not again, and the intent names the recovery")
}

// p3Step12 — a source that declares itself unable produces a gap marker,
// written by Sekizui (P3 criterion 6, D174, D275).
func p3Step12(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "a source that declares itself unable produces a gap marker, written by Sekizui")
	if r.localOnly(t, "the runner and its cursor store are this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	store := crashedMidPublish(t, "kata:gap")
	runner := newRunnerFor(t, r, ctx,
		[]config.SourceSpec{{TargetRef: "kata:gap", EverySec: 1, Limit: 10}}, store)
	if err := runner.Start(ctx); err != nil {
		t.Fatalf("step 12: %v", err)
	}
	defer func() { _ = runner.Stop(context.Background()) }()

	var gap *sekizuiv1.Decision
	waitFor(t, func() bool {
		for _, d := range readLog(t, r.path) {
			if d.GetVerdict() == sekizuiv1.Verdict_VERDICT_GAP {
				gap = d
				return true
			}
		}
		return false
	}, "an interrupted poll of a source that cannot re-read left no gap marker — the loss is silent")
	_ = runner.StopSchedule(context.Background())

	lost := gap.GetEffect().GetDetail().AsMap()["lost"]
	switch {
	case gap.GetIdentity().GetSubject().GetPrincipal() != "source:kata:gap" || gap.GetMatchedRule() != "poll:gap":
		t.Errorf("step 12: the marker is %s by %s; want poll:gap by source:kata:gap",
			gap.GetMatchedRule(), gap.GetIdentity().GetSubject().GetPrincipal())
	case !sameStrings(lost, []string{"kata:gap#1", "kata:gap#2"}):
		t.Errorf("step 12: the marker names %v as lost; the mark said row 0 was published, so "+
			"exactly rows 1 and 2 were at risk", lost)
	case !strings.Contains(gap.GetReason(), "cannot be re-read"):
		t.Errorf("step 12: the marker does not carry the connector's own reason: %q", gap.GetReason())
	}
	st, err := store.Load(ctx, "kata:gap")
	if err != nil || st.Pending != nil || st.Cursor != "3" {
		t.Errorf("step 12: after the gap the cursor is %q with pending %v (err %v); the poll must "+
			"resume after the lost window, not re-read it", st.Cursor, st.Pending, err)
	}
	r.detail(t, "an interrupted poll of kata:gap, which declares it cannot re-read, left VERDICT_GAP "+
		"naming kata:gap#1 and #2 with the connector's reason, and the cursor resumed after the window")
}

func sameStrings(v any, want []string) bool {
	list, _ := v.([]any)
	if len(list) != len(want) {
		return false
	}
	for i, x := range list {
		if x != want[i] {
			return false
		}
	}
	return true
}

// p3Step13 — the connector cannot read the audit log, asserted on the import
// graph (P3 criterion 6, D174).
//
// The connector never DETECTS an unclosed window — the spine hands it a cursor
// and it declares what re-reading can do — so it never needs the log, and a
// published Source (D35) must not be one convenience away from it. Every
// connector package: the in-tree drivers, the published connector surface, and
// hako's reference and solution.
func p3Step13(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the connector cannot read the audit log, asserted on the import graph")
	root := mustRoot(t)
	forbidden := []string{"internal/auditwal", "pkg/audit", "internal/cursor", "internal/kyuushin"}
	// THE DRIVER PACKAGES COME FROM `driverPackageDirs` (D316): this walk was
	// rooted at `internal/driver`, and after the connectors moved out of it the
	// step went on passing while examining none of them.
	bases := append(driverPackageDirs(t), "pkg/connector", "hako")
	var dirs []string
	for _, base := range bases {
		_ = filepath.Walk(filepath.Join(root, base), func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				dirs = append(dirs, path)
			}
			return nil
		})
	}
	checked := 0
	for _, dir := range dirs {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("step 13: %v", err)
			}
			checked++
			for _, imp := range f.Imports {
				for _, bad := range forbidden {
					if strings.HasSuffix(strings.Trim(imp.Path.Value, `"`), "/"+bad) {
						rel, _ := filepath.Rel(root, filepath.Join(dir, e.Name()))
						t.Errorf("step 13: %s imports %s — a connector one import from the audit "+
							"log or the spine's own state is the attack surface D174 dissolved", rel, bad)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("step 13: no connector files were found; the arm checked nothing")
	}
	r.detail(t, "%d connector source files import none of %v", checked, forbidden)
}
