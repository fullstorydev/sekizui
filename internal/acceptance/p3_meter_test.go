package acceptance

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/builtin"
	"github.com/fullstorydev/sekizui/internal/meter"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step20 — D171's three layers, with Fullstory's meter (D284).
//
// Two halves. The BOOT half composes the layers the way a deployment does —
// `meter.Build`, the one function `cmd/sekizui` and this harness both call —
// against the real drivers, plus one connector metered in something other
// than calls, because the vocabulary is open and a step that only ever saw
// `calls` could not tell an open vocabulary from a hardcoded one. The RUN half
// drives Fullstory events polls through the real job gate against step 18's
// fixture, because what D284 found was a poll charged as one call while it
// made twenty-one — and only the enforcement path can show what it charges.
func p3Step20(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the meter is the connector's, the budget is the target's, and the "+
		"deployment's ceiling may only be narrowed")

	doc, err := config.NewFileSource("acceptance.yaml").Load(context.Background())
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	drivers := map[string]connector.Driver{}
	for _, d := range builtin.Drivers(doc, nil) {
		drivers[d.Kind()] = d
	}
	drivers["ledgerco"] = recordsDriver{}
	doc.Targets = append(doc.Targets,
		config.TargetSpec{Ref: "ledger:quiet", Kind: "ledgerco", Tenant: "ledger"},
		config.TargetSpec{Ref: "ledger:sized", Kind: "ledgerco", Tenant: "ledger",
			Limits: &config.TargetLimits{RatePerHr: 5000}})

	build := func(b meter.Bounds) (*meter.Plan, error) { return meter.Build(doc, drivers, nil, b) }

	// 20a — THE CONNECTOR DECLARES THE METER; THE DEFAULT FALLS THROUGH IN ORDER.
	plan, err := build(meter.Bounds{})
	if err != nil {
		t.Fatalf("20a: the acceptance document does not compose: %v", err)
	}
	switch {
	case plan.Units["fs:events"] != connector.UnitCalls:
		t.Errorf("20a: fs:events is metered in %q; Fullstory counts CALLS (D274)", plan.Units["fs:events"])
	case plan.Units["ledger:quiet"] != "records":
		t.Errorf("20a: ledger:quiet is metered in %q; its connector declares records", plan.Units["ledger:quiet"])
	case plan.Rates["fs:events"].PerHour != meter.DefaultCallsPerHour:
		// Fullstory publishes no number, so it declares no default of its own.
		t.Errorf("20a: fs:events, with no rate_per_hr and a connector declaring no default, got %d/hr; "+
			"want the universal %d. An absent budget no longer means unlimited",
			plan.Rates["fs:events"].PerHour, meter.DefaultCallsPerHour)
	case plan.Rates["ledger:quiet"].PerHour != recordsDefault:
		t.Errorf("20a: ledger:quiet got %d/hr; its connector's own default is %d, and a universal "+
			"CALLS number means nothing in records", plan.Rates["ledger:quiet"].PerHour, recordsDefault)
	}
	r.detail(t, "no rate_per_hr: Fullstory → the universal %d calls/hr (it publishes no number); "+
		"a records connector → its own %d records/hr", meter.DefaultCallsPerHour, recordsDefault)

	// 20b — THE TARGET'S BUDGET IS HONOURED UNDER THE CEILING.
	plan, err = build(meter.Bounds{Ceilings: map[string]uint32{"calls": 1000}})
	if err != nil {
		t.Fatalf("20b: a ceiling above every declared calls budget refused the boot: %v", err)
	}
	if got := plan.Rates["fs:live"].PerHour; got != 600 {
		t.Errorf("20b: fs:live declares 600/hr under a 1000 ceiling and got %d", got)
	}
	// 20c — A DEFAULT ABOVE THE CEILING IS LOWERED, AND SAID.
	if got := plan.Rates["fs:events"].PerHour; got != 1000 {
		t.Errorf("20c: the universal default of %d is above the 1000 ceiling and became %d; "+
			"nobody asked for it, so it is LOWERED, not refused", meter.DefaultCallsPerHour, got)
	}
	if !anyContains(plan.Notes, `"fs:events"`, "LOWERED to 1000") {
		t.Errorf("20c: the lowering was not said. Notes: %v", plan.Notes)
	}
	// 20d — THE CEILING IS PER UNIT: a calls ceiling does not bound records.
	if got := plan.Rates["ledger:sized"].PerHour; got != 5000 {
		t.Errorf("20d: ledger:sized asks 5000 records/hr and got %d under a CALLS ceiling; "+
			"a ceiling is arithmetic in its own unit", got)
	}
	r.detail(t, "-meter-ceiling calls=1000: fs:live's 600 honoured, the universal default "+
		"lowered to 1000, 5000 records/hr untouched")

	// 20e — A TARGET ASKING FOR MORE THAN THE CEILING REFUSES THE BOOT.
	_, err = build(meter.Bounds{Ceilings: map[string]uint32{"calls": 500, "records": 4000}})
	for _, want := range []string{`"fs:live"`, "600", "-meter-ceiling calls=500", `"ledger:sized"`, "5000"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("20e: a target over its unit's ceiling must refuse the boot naming %q; got %v", want, err)
		}
	}
	r.detail(t, "over the ceiling: refused at boot, every target named — %d-line error",
		strings.Count(err.Error(), "\n"))

	// 20f — ONE BUDGET, ONE UNIT.
	mixed := *doc
	mixed.Targets = append([]config.TargetSpec(nil), doc.Targets...)
	for i := range mixed.Targets {
		if mixed.Targets[i].Ref == "ledger:sized" || mixed.Targets[i].Ref == "fs:live" {
			mixed.Targets[i].Limits = &config.TargetLimits{RatePerHr: 600, Budget: "shared-mixed"}
		}
	}
	if _, err := meter.Build(&mixed, drivers, nil, meter.Bounds{}); err == nil ||
		!strings.Contains(err.Error(), `budget "shared-mixed" is drawn on in more than one unit`) {
		t.Errorf("20f: a budget shared by a calls target and a records target must refuse; got %v", err)
	}

	// 20g — A SOURCE WHOSE POLL CAN NEVER FIT REFUSES THE BOOT.
	starved := *doc
	starved.Targets = append([]config.TargetSpec(nil), doc.Targets...)
	for i := range starved.Targets {
		if starved.Targets[i].Ref == "fs:events" {
			starved.Targets[i].Limits = &config.TargetLimits{RatePerHr: 100}
		}
	}
	starved.Sources = []config.SourceSpec{{TargetRef: "fs:events", EverySec: 30, Limit: 10}}
	_, err = meter.Build(&starved, drivers, nil, meter.Bounds{})
	for _, want := range []string{`source "fs:events"`, "costs 21 calls", "at most 10", "sessions_per_poll"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("20g: a source whose poll costs more than its burst must refuse naming %q; got %v", want, err)
		}
	}
	r.detail(t, "an events poll costs 21 calls and 100/hr holds 10: refused at boot, naming sessions_per_poll")

	// --- through the real job gate ------------------------------------------
	if r.localOnly(t, "the job runner and its budget are this instance's") {
		return
	}

	// 20h/20i — A POLL IS CHARGED WHAT IT COSTS. Burst 21: the first events
	// poll (one sessions call + twenty context reads) is admitted and empties
	// the bucket; the second is refused. Charged one, as before D284, the
	// second would have found twenty tokens left.
	runA := eventsRunWith(t, config.TargetLimits{RatePerHr: 36, Burst: 21}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	callerA := runA.as(t, "agent:jobs")
	if st, why := pollEventsOnce(t, ctx, callerA); st != sekizuiv1.JobState_JOB_STATE_FINISHED {
		t.Fatalf("20h: the first poll, costing exactly the burst, did not finish (%s: %s). A meter "+
			"that refuses everything is one an operator switches off", st, why)
	}
	st, why := pollEventsOnce(t, ctx, callerA)
	if st == sekizuiv1.JobState_JOB_STATE_FINISHED || !strings.Contains(why, "budget") {
		t.Fatalf("20i: the second poll ended %s (%q). The first cost 1 + 20 calls and the bucket held "+
			"21; admitting a second means a poll is still charged as one call", st, why)
	}
	if !loggedMeterRefusal(t, runA, "fs:events", "exhausted") {
		t.Error("20i: no REFUSED_BY_METER record for the second poll")
	}
	r.detail(t, "burst 21: poll 1 admitted (1 + 20 calls), poll 2 refused by the meter")

	// 20j — "NEVER" IS NOT "LATER". Burst 20 cannot hold a 21-call poll, and
	// the refusal says so rather than promising a retry that cannot succeed.
	runB := eventsRunWith(t, config.TargetLimits{RatePerHr: 3600, Burst: 20}, nil)
	st, why = pollEventsOnce(t, ctx, runB.as(t, "agent:jobs"))
	if st == sekizuiv1.JobState_JOB_STATE_FINISHED || !strings.Contains(why, "can never be admitted") {
		t.Fatalf("20j: a 21-call poll against a 20-token bucket ended %s (%q); want a refusal "+
			"saying it can NEVER be admitted — a rate limit would promise a retry that cannot work", st, why)
	}

	// 20k — THE SETTING IS THE PRICE. Nineteen sessions: 1 + 19 = 20, fits.
	runC := eventsRunWith(t, config.TargetLimits{RatePerHr: 3600, Burst: 20},
		map[string]string{"sessions_per_poll": "19"})
	if st, why := pollEventsOnce(t, ctx, runC.as(t, "agent:jobs")); st != sekizuiv1.JobState_JOB_STATE_FINISHED {
		t.Fatalf("20k: sessions_per_poll=19 prices the poll at 20, which the bucket holds, and it "+
			"ended %s (%s)", st, why)
	}
	r.detail(t, "burst 20: the default poll can never fit and is told so; sessions_per_poll=19 fits")
}

// eventsRunWith is a run whose fs:events target polls step 18's fixture under
// the given limits and extra settings.
func eventsRunWith(t *testing.T, lim config.TargetLimits, settings map[string]string,
	extra ...func(*config.Document)) *run {
	t.Helper()
	fx, _ := eventsFixtureServer(t)
	t.Setenv("SEKIZUI_FS_LIVE", "fixture-token")
	return newRunWith(t, runOpts{
		patch: func(d *config.Document) {
			for i := range d.Targets {
				if d.Targets[i].Ref != "fs:events" {
					continue
				}
				d.Targets[i].BaseURL = fx.URL
				l := lim
				d.Targets[i].Limits = &l
				merged := map[string]string{}
				for k, v := range d.Targets[i].Settings {
					merged[k] = v
				}
				for k, v := range settings {
					merged[k] = v
				}
				d.Targets[i].Settings = merged
			}
			for _, e := range extra {
				e(d)
			}
		},
		fullstoryClient: trustingSystemAnd(t, fx),
	})
}

// pollEventsOnce runs one fs:events poll job to its end and reports how it
// ended. A job refused at admission ends FAILED, with the refusal as reason.
func pollEventsOnce(t *testing.T, ctx context.Context, caller sekizuiv1.GatewayServiceClient) (
	sekizuiv1.JobState, string) {
	t.Helper()
	started, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "fullstory.poll", TargetRef: "fs:events"},
	})
	if err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	if started.GetJobId() == "" {
		return sekizuiv1.JobState_JOB_STATE_UNSPECIFIED, started.GetReason()
	}
	stream, err := caller.JobResults(ctx, &sekizuiv1.JobResultsRequest{JobId: started.GetJobId()})
	if err != nil {
		t.Fatalf("JobResults: %v", err)
	}
	for {
		if _, rerr := stream.Recv(); rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				t.Logf("results ended: %v", rerr)
			}
			break
		}
	}
	st, err := caller.JobStatus(ctx, &sekizuiv1.JobStatusRequest{JobId: started.GetJobId()})
	if err != nil {
		t.Fatalf("JobStatus: %v", err)
	}
	return st.GetState(), st.GetReason()
}

func loggedMeterRefusal(t *testing.T, r *run, target, phrase string) bool {
	t.Helper()
	for _, d := range readLog(t, r.path) {
		if d.GetTargetRef() == target && d.GetRefusedBy() == sekizuiv1.RefusedBy_REFUSED_BY_METER &&
			strings.Contains(d.GetReason(), phrase) {
			return true
		}
	}
	return false
}

func anyContains(lines []string, parts ...string) bool {
	for _, l := range lines {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(l, p)
		}
		if all {
			return true
		}
	}
	return false
}

// recordsDriver is a connector metered in something other than calls — the
// open vocabulary's witness. It declares its own default and action cost, as
// CheckMeter requires of any unit but calls. Never dispatched to.
type recordsDriver struct{}

const recordsDefault = 250

func (recordsDriver) Kind() string                                   { return "ledgerco" }
func (recordsDriver) Actions() []connector.ActionSpec                { return nil }
func (recordsDriver) Schemas() ([]connector.Schema, error)           { return nil, nil }
func (recordsDriver) Health(context.Context, connector.Target) error { return nil }
func (recordsDriver) Meter() connector.Meter {
	return connector.Meter{Unit: "records", DefaultPerHour: recordsDefault,
		ActionCost: func(string, map[string]any) (uint64, error) { return 10, nil }}
}
func (recordsDriver) Execute(context.Context, connector.Target, string, map[string]any,
	connector.Idempotency) (connector.Result, error) {
	return connector.Result{}, errors.New("recordsDriver is never dispatched to")
}
func (recordsDriver) Query(context.Context, connector.Target, string, map[string]any) (connector.Rows, error) {
	return connector.Rows{}, errors.New("recordsDriver is never dispatched to")
}
