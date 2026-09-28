package gateway

import (
	"strings"
	"testing"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// TestEveryExitPathIsMetered is the regression guard for hand-keyed
// instrumentation.
//
// The first version observed at two of eight exit paths, with two different
// vocabularies and Query unmetered entirely. This drives each path and asserts a
// series exists for it — so a path added later that skips the deferred
// observation fails here rather than going unnoticed until a dashboard is empty.
func TestEveryExitPathIsMetered(t *testing.T) {
	h := newHarness(t)
	ctx := callerCtx(t, "agent:triage")

	// 1. success
	if _, err := h.srv.Execute(ctx, cmd("kata.create_issue", "kata:alpha",
		map[string]any{"project": "PROJ"})); err != nil {
		t.Fatalf("success path: %v", err)
	}
	// 2. policy denial
	h.srv.Execute(ctx, cmd("kata.comment", "kata:alpha", nil))
	// 3. escalation
	h.srv.Execute(ctx, cmd("kata.delete_project", "kata:alpha", nil))
	// 4. dry run
	dry := cmd("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"})
	dry.Command.DryRun = true
	h.srv.Execute(ctx, dry)
	// 5. residency refusal
	h.srv.Execute(callerCtx(t, "agent:global"), cmd("kata.create_issue", "kata:beta", nil))
	// 6. driver failure, injected
	h.srv.Execute(ctx, cmd("kata.create_issue", "kata:alpha",
		map[string]any{"project": "PROJ", "_fail": "target_unavailable"}))
	// 7. a read
	h.srv.Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
	// 8. a denied read
	h.srv.Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:beta"})

	var b strings.Builder
	if _, err := h.srv.Metrics().WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	scrape := b.String()

	for _, want := range []string{
		`outcome="ok"`,
		`outcome="denied"`,
		`outcome="escalated"`,
		`outcome="would_have_fired"`,
		`outcome="residency"`,          // the fault kind, from the error path
		`outcome="target_unavailable"`, // injected driver failure
		`action="kata.read"`,           // Query is metered at all
	} {
		if !strings.Contains(scrape, want) {
			t.Errorf("no series with %s — an exit path is unmetered:\n%s", want, scrape)
		}
	}
}

// TestScrapeOutputIsStable. Map iteration is randomised, so an unsorted scrape
// reorders every time — unreadable in a diff and useless to anything comparing
// two scrapes.
func TestScrapeOutputIsStable(t *testing.T) {
	h := newHarness(t)
	ctx := callerCtx(t, "agent:triage")

	for _, action := range []string{"kata.comment", "kata.create_issue", "kata.delete_project"} {
		h.srv.Execute(ctx, cmd(action, "kata:alpha", map[string]any{"project": "PROJ"}))
	}

	var first, second strings.Builder
	h.srv.Metrics().WriteTo(&first)
	h.srv.Metrics().WriteTo(&second)

	if first.String() != second.String() {
		t.Error("two scrapes of unchanged counters differ; the output is not sorted")
	}
}

// TestLabelsUseStableVocabulary. The label space is the union of fault kinds and
// wire statuses, both of which are stable identifiers that also appear in the
// audit log — so a dashboard and a decision record read as the same word.
func TestLabelsUseStableVocabulary(t *testing.T) {
	if got := statusLabel(sekizuiv1.Status_STATUS_OK); got != "ok" {
		t.Errorf("OK label = %q", got)
	}
	if got := statusLabel(sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED); got != "would_have_fired" {
		t.Errorf("WOULD_HAVE_FIRED label = %q", got)
	}
	// Derived from the enum, so a status added to the proto needs no code change
	// here — the failure mode this refactor removed.
	if got := statusLabel(sekizuiv1.Status_STATUS_RATE_LIMITED); got != "rate_limited" {
		t.Errorf("RATE_LIMITED label = %q", got)
	}
	if got := statusLabel(sekizuiv1.Status_STATUS_UNSPECIFIED); got != "unknown" {
		t.Errorf("UNSPECIFIED label = %q", got)
	}
}
