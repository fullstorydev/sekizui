package acceptance

import (
	"context"
	"fmt"
	"github.com/fullstorydev/sekizui/internal/builtin"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/internal/kyuushin"
	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/internal/translate"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step5 — a scheduled run is governed by the same path a caller's job is,
// not a side door (P3 criterion 1, D18, D155, D249, D266).
//
// **AND IT IS THE FIRST TIME ANYTHING BUT `PublishForTest` FILLS THE BUS.**
// The maintainer's ask: a skeleton that publishes, even from a reference source. The
// source is `kata`, governed the way `hako/reference` governs it; Fullstory
// replaces it as the phase's headline in step 4 (D265).
func p3Step5(t *testing.T) {
	r := newRun(t)

	r.narrate(t, "a scheduled run is governed by the same path a caller's job is, not a side door")

	// 5c FIRST, because it needs no instance: THE STRUCTURAL ARM. Exactly one
	// function in the runner reaches the gate, and BOTH triggers reach it.
	step5OnePathForBothTriggers(t)

	if r.localOnly(t, "the runner, the bus and the audit log are this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runner := newScheduleRunner(t, r, ctx)

	// SUBSCRIBE BEFORE THE FIRST TICK (D24): agent:scoped is granted raw kata
	// rows from kata:alpha, which is what the schedule polls.
	sub, err := r.as(t, "agent:scoped").Subscribe(ctx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.raw.kata.>"},
	})
	if err != nil {
		t.Fatalf("step 5: subscribing: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 }, "the subscription never registered")

	if err := runner.Start(ctx); err != nil {
		t.Fatalf("step 5: starting the schedule: %v", err)
	}
	t.Cleanup(func() { _ = runner.Stop(context.Background()) })

	// 5a — THE BUS IS FILLED BY A SCHEDULE, NOT BY A TEST HOOK.
	got, err := sub.Recv()
	if err != nil {
		t.Fatalf("step 5a: no envelope arrived from the schedule: %v", err)
	}
	if env := got.GetEnvelope(); env.GetSource() != "kata:alpha" || env.GetStage() != "raw" {
		t.Fatalf("step 5a: received source=%q stage=%q, want a raw row from kata:alpha",
			env.GetSource(), env.GetStage())
	}

	// 5b — AND IT WAS ADMITTED AS ITS PRINCIPAL, ON THE RECORD. No caller, so
	// configuration is the caller: `source:kata:alpha`, through the same gate.
	var polled *sekizuiv1.Decision
	waitFor(t, func() bool {
		for _, d := range readLog(t, r.path) {
			if d.GetIdentity().GetSubject().GetPrincipal() == "source:kata:alpha" &&
				d.GetAction() == "kata.poll" {
				polled = d
				return true
			}
		}
		return false
	}, "the scheduled poll left no decision record")
	if polled.GetVerdict() != sekizuiv1.Verdict_VERDICT_ALLOW {
		t.Errorf("step 5b: the scheduled poll recorded %s, want ALLOW", polled.GetVerdict())
	}
	r.detail(t, "a one-second schedule on kata:alpha published a raw row to agent:scoped, "+
		"admitted and recorded as source:kata:alpha")
}

// step5OnePathForBothTriggers is 5c: the AST arm P1 step 68 gave the command
// path, aimed at the runner.
//
// A behavioural arm shows the schedule went through the gate THIS time. This
// shows there is only one way to: a single function in internal/kyuushin
// calls `.Admit(`, and both the recurrence loop and a caller's Submit call that
// function. A third trigger has to name itself here to be allowed.
func step5OnePathForBothTriggers(t *testing.T) {
	t.Helper()
	dir := filepath.Join(mustRoot(t), "internal", "kyuushin")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("step 5c: %v", err)
	}
	admitters := map[string]bool{}
	callers := map[string]map[string]bool{} // function -> functions it calls on p
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("step 5c: %v", err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if sel.Sel.Name == "Admit" {
						admitters[name] = true
					}
					if callers[name] == nil {
						callers[name] = map[string]bool{}
					}
					callers[name][sel.Sel.Name] = true
				}
				return true
			})
		}
	}
	if len(admitters) != 1 || !admitters["run"] {
		t.Fatalf("step 5c: the functions calling Admit are %v, want exactly `run`. A second "+
			"caller of the gate is a second admission path — D155's shape, in the plane with "+
			"no caller to authorise (D18, D249)", keys(admitters))
	}
	for _, trigger := range []string{"recur", "Submit"} {
		if !callers[trigger]["run"] {
			t.Errorf("step 5c: %s does not call run, so that trigger reaches the source some "+
				"other way (D249: one mechanism, two triggers)", trigger)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// p3Step14 — `-mode=ingest` genuinely polls, and the stub warning is retired
// (P3 criterion 1, D252, D266).
//
// **THE REAL BINARY**, because what is in question is the WIRING: that
// `-mode=ingest` reads `sources:`, builds the jobs, starts the schedule after
// the reflexes, and polls. An in-process runner (step 5) proves the runner; it
// cannot prove `cmd/sekizui` ever starts one.
func p3Step14(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "`-mode=ingest` genuinely polls, and the stub warning is retired")
	if r.localOnly(t, "this step launches its own instance") {
		return
	}
	root := mustRoot(t)
	certs := filepath.Join(root, "dev", "certs")
	if _, err := os.Stat(filepath.Join(certs, "ca.crt")); err != nil {
		t.Skip("no development certificates; run `make dev-certs`")
	}

	wal := t.TempDir()
	inst := startIngest(t, buildSekizui(t, root), root, certs, wal)
	inst.ready(t)

	// 14a — IT POLLS: a decision record as the source's principal, in the audit
	// log the INSTANCE wrote.
	audit := filepath.Join(wal, "audit.jsonl")
	waitFor(t, func() bool {
		if _, err := os.Stat(audit); err != nil {
			return false
		}
		for _, d := range readLog(t, audit) {
			if d.GetIdentity().GetSubject().GetPrincipal() == "source:kata:alpha" &&
				d.GetAction() == "kata.poll" && d.GetVerdict() == sekizuiv1.Verdict_VERDICT_ALLOW {
				return true
			}
		}
		return false
	}, "-mode=ingest ran and never polled its configured source")

	// STOP THE INSTANCE BEFORE READING ITS LOG. The buffer is written by the
	// goroutine exec uses to copy the child's output, and reading it while the
	// child runs is a data race — `-race` caught this step doing exactly that.
	// `exec.Cmd.Wait` returns only once that copying has finished; the
	// `os.Process.Wait` the refusal tests use reaps the child and does NOT, which
	// is why my first version of this fix still raced (GO-PRIMER §15an).
	inst.kill()

	// 14b — AND NOTHING SAYS IT IS A STUB. D252 replaced the warning with a
	// refusal of an ingest deployment with nothing to poll; a warning that
	// outlived its cause would be D77's crying wolf in the boot report.
	for _, stale := range []string{"stub", "polls nothing", "not yet implemented"} {
		if strings.Contains(strings.ToLower(inst.logs.String()), stale) {
			t.Errorf("step 14b: the ingest instance's log still says %q, about a mode that "+
				"now polls", stale)
		}
	}
	r.detail(t, "the real binary under -mode=ingest polled kata:alpha as source:kata:alpha")
}

// newScheduleRunner builds a runner over the acceptance document's `sources:`
// the way `-mode=ingest` does — ScheduledJobs, the server's JobGate, the bus —
// with a temporary cursor store. Not started.
func newScheduleRunner(t *testing.T, r *run, ctx context.Context) *kyuushin.Runner {
	t.Helper()
	return newRunnerFor(t, r, ctx, nil, cursor.NewFileStore(t.TempDir()))
}

// newRunnerFor is newScheduleRunner over chosen sources (nil = the document's)
// and a chosen cursor store — so a step can hand the runner the exact state a
// crash leaves (P3 steps 11, 12).
func newRunnerFor(t *testing.T, r *run, ctx context.Context, specs []config.SourceSpec,
	store cursor.Store) *kyuushin.Runner {
	t.Helper()
	// LOADED WITH THE CONTEXT THIS WAS GIVEN, and validated as a boot would.
	doc, err := config.NewFileSource("acceptance.yaml").Load(ctx)
	if err == nil {
		err = doc.Validate()
	}
	if err != nil {
		t.Fatalf("loading the acceptance document: %v", err)
	}
	if specs == nil {
		specs = doc.Sources
	}
	jobs, err := r.srv.ScheduledJobs(ctx, specs)
	if err != nil {
		t.Fatalf("the acceptance sources could not become jobs: %v", err)
	}
	tr, err := translate.New(doc.Stages[0], safestruct.DefaultBudget)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var mu sync.Mutex
	seq := 0
	registry, err := schemareg.ForDeployment(doc, builtin.ByKind(doc, nil))
	if err != nil {
		t.Fatalf("%v", err)
	}
	runner, err := kyuushin.New(jobs, store, tr, r.bus,
		r.srv.JobGate(), slog.New(slog.NewTextHandler(io.Discard, nil)),
		kyuushin.Options{Payloads: registry, NewID: func() string {
			mu.Lock()
			defer mu.Unlock()
			seq++
			return fmt.Sprintf("env_sched_%06d", seq)
		}})
	if err != nil {
		t.Fatalf("%v", err)
	}
	return runner
}
