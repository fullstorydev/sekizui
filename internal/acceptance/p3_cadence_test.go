package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/pkg/config"
)

// p3Step41 — a schedule keeps its cadence across a restart (D285, CONTRACTS 134).
//
// **AN HOURLY SCHEDULE, ON PURPOSE.** The defect was invisible at the one-second
// intervals every other schedule step uses: the first poll came one whole
// interval after the process started, so at one second nobody could tell, and
// at an hour — with a deploy every thirty minutes — the source never polled.
// Each arm starts the REAL runner over the real gate against a cursor store in
// a chosen state, and reads what happened from the store and the audit log.
func p3Step41(t *testing.T) {
	r := newRun(t)
	if r.localOnly(t, "the runner and its cursor store are this instance's") {
		return
	}
	r.narrate(t, "a schedule keeps its cadence across a restart: the first poll is due one "+
		"interval after the last one started")
	hourly := []config.SourceSpec{{TargetRef: "kata:alpha", EverySec: 3600, Limit: 10}}

	start := func(t *testing.T, store cursor.Store) func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		runner := newRunnerFor(t, r, ctx, hourly, store)
		if err := runner.Start(ctx); err != nil {
			cancel()
			t.Fatalf("step 41: the schedule did not start: %v", err)
		}
		return func() { _ = runner.Stop(context.Background()); cancel() }
	}
	lastPoll := func(t *testing.T, store cursor.Store) time.Time {
		t.Helper()
		st, err := store.Load(context.Background(), "kata:alpha")
		if err != nil {
			t.Fatalf("step 41: %v", err)
		}
		return st.LastPoll
	}
	// A POLL IS READ FROM THE AUDIT LOG, NOT FROM THE STORE, so an arm that
	// fails says which half broke: the poll not happening, or its time not
	// being recorded.
	polls := func() int {
		n := 0
		for _, d := range readLog(t, r.path) {
			if d.GetAction() == "kata.poll" && d.GetIdentity().GetSubject().GetPrincipal() == "source:kata:alpha" {
				n++
			}
		}
		return n
	}
	pollWithin := func(before int, within time.Duration) bool {
		deadline := time.Now().Add(within)
		for time.Now().Before(deadline) {
			if polls() > before {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}

	// 41a — RESTARTED MID-INTERVAL, IT POLLS WHEN DUE. The store says the last
	// poll started an hour less half a second ago; the old runner waited an hour.
	store := cursor.NewFileStore(t.TempDir())
	seeded := time.Now().Add(-time.Hour + 500*time.Millisecond)
	if err := store.Polled(context.Background(), "kata:alpha", seeded); err != nil {
		t.Fatal(err)
	}
	before := polls()
	stop := start(t, store)
	if !pollWithin(before, 5*time.Second) {
		stop()
		t.Fatalf("step 41a: an hourly source whose last poll started 59m59.5s ago did not poll " +
			"within 5s of a restart. A first poll one WHOLE interval after start means a source " +
			"whose interval exceeds the deploy cadence never polls (CONTRACTS 134)")
	}
	stop()
	if !lastPoll(t, store).After(seeded) {
		t.Errorf("step 41a: the poll ran and the store still says %v; a tick that does not record "+
			"its time lets the next restart poll at once, or never", lastPoll(t, store))
	}
	r.detail(t, "an hourly source restarted half a second before it was due polled when due")

	// 41b — NEVER POLLED: AT ONCE. A missing time costs one priced call; a
	// silent source is the defect.
	fresh := cursor.NewFileStore(t.TempDir())
	before = polls()
	stop = start(t, fresh)
	if !pollWithin(before, 3*time.Second) {
		stop()
		t.Fatalf("step 41b: a source never polled did not poll at start")
	}
	stop()

	// 41c — A TIME IN THE FUTURE COUNTS AS NOW. Whoever can write the store
	// could otherwise set next year's date and silence the source; so the next
	// poll is one interval away — not now, and not next year.
	//
	// **A ONE-SECOND SCHEDULE HERE, AND THE HOURLY ONE COULD NOT PROVE IT.**
	// Its first version used the hourly source and asserted no poll within
	// 1.5s — which a runner TRUSTING the future time passes too, because "one
	// interval away" and "a year away" look identical for an hour. Its mutation
	// survived. Only an interval short enough to wait out tells them apart.
	future := cursor.NewFileStore(t.TempDir())
	if err := future.Polled(context.Background(), "kata:alpha", time.Now().Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := newRunnerFor(t, r, ctx,
		[]config.SourceSpec{{TargetRef: "kata:alpha", EverySec: 1, Limit: 10}}, future)
	before = polls()
	if err := runner.Start(ctx); err != nil {
		t.Fatalf("step 41c: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	early := polls() - before
	late := pollWithin(before, 3*time.Second)
	_ = runner.Stop(context.Background())
	switch {
	case early != 0:
		t.Fatalf("step 41c: a store dated next year saw %d poll(s) at start; a future time counts "+
			"as NOW, so the next poll is one interval away", early)
	case !late:
		t.Fatalf("step 41c: a store dated next year saw no poll within 3s on a one-second schedule. " +
			"Trusting a future time lets whoever can write the store silence the source")
	}
	r.detail(t, "never polled: polled at start; a poll time a year ahead: treated as now — "+
		"nothing at start, a poll one interval later")
}
