package acceptance

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/fullstorydev/sekizui/internal/reflex"
	"github.com/fullstorydev/sekizui/pkg/audit"
	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step36 — an enrichment reflex shapes a result on the way back, and an
// actuating one is refused eligibility (P3 criterion 19, D248, D269).
//
// **BOTH HALVES ARE THE CRITERION, AND THE SECOND IS ASSERTED ON ELIGIBILITY.**
// The maintainer's "already improves the output" is 36a; the line D248 draws — enrichment
// may, actuation may not — is 36c, asserted on the TYPE that runs on the
// synchronous path, because a behavioural arm shows only that no actuating rule
// happened to match this time.
func p3Step36(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "an enrichment reflex shapes a result on the way back, and an actuating one "+
		"is refused eligibility")

	// 36c FIRST: ELIGIBILITY, which needs no instance.
	step36Eligibility(t)

	if r.localOnly(t, "the job runner and the bus are this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caller := r.as(t, "agent:jobs")

	runJob := func(include bool) []*sekizuiv1.Envelope {
		t.Helper()
		started, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
			Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:alpha"},
		})
		if err != nil || started.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("step 36: StartJob: %v %s", err, started.GetReason())
		}
		stream, err := caller.JobResults(ctx, &sekizuiv1.JobResultsRequest{
			JobId: started.GetJobId(), IncludeProjection: include,
		})
		if err != nil {
			t.Fatalf("step 36: JobResults: %v", err)
		}
		var out []*sekizuiv1.Envelope
		for {
			got, rerr := stream.Recv()
			if errors.Is(rerr, io.EOF) {
				return out
			}
			if rerr != nil {
				t.Fatalf("step 36: receiving: %v", rerr)
			}
			out = append(out, got.GetEnvelope())
		}
	}

	// 36a — THE PROJECTION REACHES A CALLER WHO ASKED. Rows 0 and 1 carry
	// `row-summary`'s view: `ordinal`, which the caller's lens keeps, and the
	// rule's own `kind`.
	rows := runJob(true)
	if len(rows) != 3 {
		t.Fatalf("step 36a: %d rows, want 3", len(rows))
	}
	for _, env := range rows {
		ordinal := env.GetData().AsMap()["ordinal"]
		proj := env.GetProjection().AsMap()
		switch ordinal {
		case float64(0), float64(1):
			if proj["kind"] != "kata row" || proj["ordinal"] != ordinal {
				t.Errorf("step 36a: row %v has projection %v, want {kind: kata row, ordinal: %v} "+
					"— the caller asked and the view did not reach it (D248)", ordinal, proj, ordinal)
			}
		case float64(2):
			// 36b — SHAPED AFTER THE LENS, SO IT CANNOT CARRY WHAT THE LENS
			// REMOVED. `leaky-summary` carries `ref`, which job-results-lite
			// withholds from agent:jobs: the row arrives WITHOUT a projection,
			// and the withheld value is nowhere in what was delivered.
			if env.GetProjection() != nil {
				t.Errorf("step 36b: row 2 arrived with projection %v; it carries `ref`, which "+
					"the caller's lens withholds, so it must fail to shape (D269)", proj)
			}
			if strings.Contains(renderStruct(t, env.GetData())+renderStruct(t, env.GetProjection()), "kata:alpha") {
				t.Error("step 36b: the withheld `ref` value reached the caller")
			}
		}
	}

	// 36a, the other direction — NOT ASKED, NOT SHAPED. `include_projection`
	// was on the wire for three phases and read by nothing.
	for _, env := range runJob(false) {
		if env.GetProjection() != nil {
			t.Errorf("step 36a: a caller that did not ask received a projection on row %v",
				env.GetData().AsMap()["ordinal"])
		}
	}

	// 36d — AN INBOUND PROJECTION IS NEVER CARRIED THROUGH. shin used to clone
	// `projection` through untouched, lensing only `data`; an envelope arriving
	// with one is stripped, whether or not the consumer asked for a projection.
	subCtx, cancelSub := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSub()
	sub, err := r.as(t, "agent:scoped").Subscribe(subCtx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.raw.kata.>"}, IncludeProjection: true,
	})
	if err != nil {
		t.Fatalf("step 36d: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 }, "the subscription never registered")
	smuggled := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": 50})
	smuggled.Id, smuggled.Source = "36d-smuggled", "kata:alpha"
	smuggled.Projection, _ = structpb.NewStruct(map[string]any{"secret": "carried-from-upstream"})
	if err := r.srv.PublishForTest(smuggled); err != nil {
		t.Fatalf("step 36d: %v", err)
	}
	got, err := sub.Recv()
	if err != nil {
		t.Fatalf("step 36d: %v", err)
	}
	if p := got.GetEnvelope().GetProjection(); p != nil && p.AsMap()["secret"] != nil {
		t.Fatalf("step 36d: a projection arriving on the envelope reached the consumer untouched "+
			"(%v); shin must strip it, because it was shaped from data no lens looked at (D269)", p.AsMap())
	}
	r.detail(t, "rows 0-1 carried row-summary's view; row 2's leaky-summary could not be shaped "+
		"after the lens and arrived without one; no projection without asking; an inbound one "+
		"stripped")
}

// step36Eligibility is 36c: the synchronous path CANNOT actuate, asserted on
// the type and on the refusals, not on a run.
func step36Eligibility(t *testing.T) {
	t.Helper()

	// THE TYPE. No field of reflex.Projector can dispatch, record or publish:
	// nothing implementing the engine's Enforcer, an audit Recorder or a bus,
	// and no function value that could be one in disguise.
	enforcer := reflect.TypeOf((*reflex.Enforcer)(nil)).Elem()
	recorder := reflect.TypeOf((*audit.Recorder)(nil)).Elem()
	bus := reflect.TypeOf((*pkgbus.Bus)(nil)).Elem()
	pt := reflect.TypeOf(reflex.Projector{})
	for i := 0; i < pt.NumField(); i++ {
		f := pt.Field(i)
		switch {
		case f.Type.Kind() == reflect.Func,
			f.Type.Implements(enforcer), f.Type.Implements(recorder), f.Type.Implements(bus),
			f.Type.Kind() == reflect.Interface:
			t.Errorf("step 36c: reflex.Projector has field %s of type %s, through which the "+
				"synchronous path could act. It must hold rules and nothing else (D248)", f.Name, f.Type)
		}
	}

	// THE CONSTRUCTOR refuses an ineligible rule rather than filtering it.
	if _, err := reflex.NewProjector([]config.ReflexSpec{{
		Name: "sneaky", Projects: true, Action: "kata.create_issue", TargetRef: "kata:alpha",
	}}); err == nil {
		t.Error("step 36c: NewProjector accepted a projection that declares an action")
	}

	// THE BOOT refuses a projection declaring any field that would let it act.
	base, err := os.ReadFile("acceptance.yaml")
	if err != nil {
		t.Fatalf("step 36c: %v", err)
	}
	const anchor = "  - name: row-summary\n    projects: true\n"
	if !strings.Contains(string(base), anchor) {
		t.Fatalf("step 36c: acceptance.yaml no longer carries %q", anchor)
	}
	for _, field := range []string{"    principal: reflex:friction\n",
		"    action: kata.create_issue\n    target: kata:alpha\n", "    mode: enforce\n"} {
		path := filepath.Join(t.TempDir(), "acceptance.yaml")
		src := strings.Replace(string(base), anchor, anchor+field, 1)
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatalf("step 36c: %v", err)
		}
		doc, err := config.NewFileSource(path).Load(context.Background())
		if err == nil {
			err = doc.Validate()
		}
		if err == nil || !strings.Contains(err.Error(), "a projection may not declare") {
			t.Errorf("step 36c: a projection declaring %q booted (got %v); it acts as nobody (D269)",
				strings.TrimSpace(field), err)
		}
	}

	// AND THE DISPATCHING HALF NEVER HOLDS ONE.
	for _, r := range reflex.OnlyDispatching([]config.ReflexSpec{{Name: "p", Projects: true}}) {
		t.Errorf("step 36c: OnlyDispatching kept projection %q; the engine would subscribe it", r.Name)
	}
}
