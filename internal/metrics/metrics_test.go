package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestCountsAndSumsPerSeries(t *testing.T) {
	r := New()
	r.Observe("kata:alpha", "kata.create_issue", "ok", 100*time.Millisecond)
	r.Observe("kata:alpha", "kata.create_issue", "ok", 200*time.Millisecond)
	r.Observe("kata:alpha", "kata.create_issue", "denied", 0)

	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	out := b.String()

	for _, want := range []string{
		`sekizui_actions_total{target="kata:alpha",action="kata.create_issue",outcome="ok"} 2`,
		`sekizui_actions_total{target="kata:alpha",action="kata.create_issue",outcome="denied"} 1`,
		`sekizui_action_duration_milliseconds_total{target="kata:alpha",action="kata.create_issue",outcome="ok"} 300`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing series:\n  %s\ngot:\n%s", want, out)
		}
	}
}

// TestOutputIsSorted. Map iteration is randomised, so an unsorted scrape
// reorders every time — unreadable in a diff and useless to anything comparing
// two scrapes.
func TestOutputIsSorted(t *testing.T) {
	r := New()
	for _, a := range []string{"z.action", "a.action", "m.action"} {
		r.Observe("t", a, "ok", time.Millisecond)
	}
	var first, second strings.Builder
	r.WriteTo(&first)
	r.WriteTo(&second)

	if first.String() != second.String() {
		t.Fatal("two scrapes of unchanged counters differ")
	}
	ai := strings.Index(first.String(), `action="a.action"`)
	zi := strings.Index(first.String(), `action="z.action"`)
	if ai > zi {
		t.Error("series are not sorted by action")
	}
}

func TestNamedCounters(t *testing.T) {
	r := New()
	r.Incr("config_reloads")
	r.Incr("config_reloads")

	var b strings.Builder
	r.WriteTo(&b)
	if !strings.Contains(b.String(), "sekizui_config_reloads 2") {
		t.Errorf("named counter missing:\n%s", b.String())
	}
}

// TestConcurrentObservationIsSafe — one registry is written by every request
// path at once, so -race is the point of this test.
func TestConcurrentObservationIsSafe(t *testing.T) {
	r := New()
	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 100 {
				r.Observe("t", "a", "ok", time.Millisecond)
				r.Incr("events")
			}
		}()
	}
	for range 8 {
		<-done
	}

	var b strings.Builder
	r.WriteTo(&b)
	if !strings.Contains(b.String(), `outcome="ok"} 800`) {
		t.Errorf("lost observations under concurrency:\n%s", b.String())
	}
}

// TestEmptyRegistryStillEmitsHeaders. A scraper meeting a body with no HELP or
// TYPE lines cannot tell "no data yet" from "wrong endpoint".
func TestEmptyRegistryStillEmitsHeaders(t *testing.T) {
	var b strings.Builder
	New().WriteTo(&b)
	if !strings.Contains(b.String(), "# TYPE sekizui_actions_total counter") {
		t.Errorf("an empty registry emitted no type information:\n%q", b.String())
	}
}

// TestNamedCountersCarryTheirTargetLabel is D204's half of the exposition.
//
// The churn counter exists so a perimeter can react while an amplification is
// happening, and one that says churn is happening without saying WHERE cannot
// scope a response.
func TestNamedCountersCarryTheirTargetLabel(t *testing.T) {
	r := New()
	r.IncrFor("credential_churn_total", "fullstory:prod")
	r.IncrFor("credential_churn_total", "fullstory:prod")
	r.IncrFor("credential_churn_total", "jira:eu")

	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	got := b.String()

	for _, want := range []string{
		`sekizui_credential_churn_total{target="fullstory:prod"} 2`,
		`sekizui_credential_churn_total{target="jira:eu"} 1`,
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}

	// ONE `# TYPE` PER NAME, not per series. A repeated TYPE line for one metric
	// is malformed, and a labelled counter has a line per target — so the
	// obvious loop emits it N times.
	if n := strings.Count(got, "# TYPE sekizui_credential_churn_total counter"); n != 1 {
		t.Errorf("%d TYPE lines for one metric, want 1:\n%s", n, got)
	}
}

// TestMixedLabelShapesAreRefused keeps one careless call site from blanking
// every metric this process exposes.
//
// **PROMETHEUS REJECTS THE WHOLE SCRAPE** for a metric whose series carry
// inconsistent label sets — not the offending line, the scrape. So emitting it
// leaves a dashboard that is empty rather than wrong, and empty is the state
// nobody investigates. Refused here, where the error has somewhere to go.
func TestMixedLabelShapesAreRefused(t *testing.T) {
	r := New()
	r.Incr("credential_churn_total")
	r.IncrFor("credential_churn_total", "jira:eu")

	var b strings.Builder
	_, err := r.WriteTo(&b)
	if err == nil {
		t.Fatalf("a metric recorded both with and without a label was emitted anyway:\n%s",
			b.String())
	}
	if !strings.Contains(err.Error(), "credential_churn_total") {
		t.Errorf("the refusal does not name the metric: %v", err)
	}
}
