package acceptance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/identity"
	"github.com/fullstorydev/sekizui/internal/tracing"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
	"google.golang.org/grpc/metadata"
)

// P2 step 29: a span per outbound call, RED metrics, and no trace id on a label.

// step29EveryOutboundCallCarriesASpan proves the observability half of criteria
// 1 and 11, and retires the init ledger's `obs:otel` entry.
//
// **A SKELETON, WHICH IS D91's PRECEDENT (D235).** The maintainer asked whether this
// really needs OpenTelemetry. It does not: the ledger entry asks for "traces
// with the delegation chain in span attributes; RED metrics", and only its NAME
// says otel — the bus landed at P0 the same way, over an in-process transport.
// OTel is an exporter, and export is an operations concern for a later phase.
//
// **THE ARMS INHERIT D216's SHAPE, which is why that decision was settled
// first.** A bare `trace_id` cannot parent a span, so a span built against
// today's field would place every governed call as a detached ROOT beside the
// work that requested it — buildable, green, and misleading.
func step29EveryOutboundCallCarriesASpan(t *testing.T) {
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	if r.localOnly(t, "it reads the tracer this process holds") {
		return
	}

	// A CALLER THAT IS ALREADY TRACING. The header is the real one
	// `identity.Verify` reads, so the span below is parented off a value that
	// crossed the wire rather than one this test handed to the tracer.
	const (
		callerTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
		callerSpan  = "00f067aa0ba902b7"
	)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		identity.SubjectHeader, "agent:triage",
		identity.TraceparentHeader, "00-"+callerTrace+"-"+callerSpan+"-01",
	))

	resp, err := r.as(t, "mesh:primary").Execute(ctx,
		execute("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"}))
	if err != nil {
		t.Fatalf("the traced command: %v", err)
	}
	if s := resp.GetResult().GetStatus(); s != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("status = %v, want OK: %s", s, resp.GetResult().GetReason())
	}

	spans := r.tracer.Recorded()
	if len(spans) == 0 {
		t.Fatal("the outbound call produced NO span. The init ledger's `obs:otel` entry " +
			"claims traces with the delegation chain, and an entry that reports a gap it " +
			"no longer has is D53's defect — but so is one that reports a capability " +
			"nothing delivers")
	}
	var span tracing.Span
	for _, s := range spans {
		if s.Name == "kata.create_issue" {
			span = s
		}
	}
	if span.SpanID == "" {
		t.Fatalf("no span named for the action; got %d span(s)", len(spans))
	}

	t.Run("the span is a CHILD of the caller's, not a detached root", func(t *testing.T) {
		if span.TraceID != callerTrace {
			t.Errorf("the span's trace is %q, want the caller's %q — a governed call in its "+
				"own trace cannot be found from the work that requested it",
				span.TraceID, callerTrace)
		}
		if span.ParentSpanID != callerSpan {
			t.Errorf("the span's parent is %q, want the caller's span %q. **A BARE TRACE ID "+
				"CANNOT PARENT ANYTHING (D216)** — without this the span is a ROOT beside "+
				"the work it serves, which looks correct in a UI and answers no question",
				span.ParentSpanID, callerSpan)
		}
		if span.SpanID == span.ParentSpanID {
			t.Error("the span reused the caller's span id rather than minting its own")
		}
		if len(span.SpanID) != 16 {
			t.Errorf("the span id is %d hex characters, want 16 (8 bytes, W3C's shape) — an "+
				"exporter added later reads this unchanged", len(span.SpanID))
		}
	})

	t.Run("the caller's sampling flag is propagated, never overridden", func(t *testing.T) {
		if !span.Sampled {
			t.Error("the caller sampled this trace (flags 01) and the span says otherwise")
		}
		// **AND THE OTHER DIRECTION, WHICH IS THE ARM WITH TEETH (D216):** an
		// UNSAMPLED caller must stay unsampled. The tempting move is to
		// force-keep any trace that produced a governed decision, since that is
		// the most interesting trace there is — and inflating somebody else's
		// telemetry bill is not our decision to make. Without this arm, a
		// provider that hardcoded `Sampled: true` would pass the check above.
		unsampled := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
			identity.SubjectHeader, "agent:triage",
			identity.TraceparentHeader, "00-"+callerTrace+"-"+callerSpan+"-00",
		))
		before := len(r.tracer.Recorded())
		if _, err := r.as(t, "mesh:primary").Execute(unsampled,
			execute("kata.create_issue", "kata:alpha",
				map[string]any{"project": "PROJ"})); err != nil {
			t.Fatalf("the unsampled command: %v", err)
		}
		after := r.tracer.Recorded()
		if len(after) <= before {
			t.Fatal("the unsampled command produced no span at all; the flag is CARRIED, " +
				"not a decision about whether to record locally")
		}
		if last := after[len(after)-1]; last.Sampled {
			t.Error("the caller did NOT sample this trace (flags 00) and the span says it " +
				"did — Sekizui overrode somebody else's sampling decision")
		}
	})

	t.Run("the delegation chain is on the span, not reconstructed", func(t *testing.T) {
		chain := span.Attributes["sekizui.chain"]
		for _, want := range []string{"mesh:primary", "agent:triage"} {
			if !strings.Contains(chain, want) {
				t.Errorf("the span's chain %q does not name %q. \"Who asked for this\" is "+
					"the question a span with only the subject cannot answer (D7, §4.4.1)",
					chain, want)
			}
		}
		for attr, want := range map[string]string{
			"sekizui.target": "kata:alpha",
			"sekizui.action": "kata.create_issue",
			"sekizui.caller": "mesh:primary",
		} {
			if got := span.Attributes[attr]; got != want {
				t.Errorf("span attribute %s = %q, want %q", attr, got, want)
			}
		}
		// THE SPAN AND THE AUDIT ROW JOIN IN BOTH DIRECTIONS.
		if got := span.Attributes["sekizui.decision_id"]; got == "" {
			t.Error("the span names no decision id, so a trace cannot be taken back to the " +
				"row that authorised it")
		}
	})

	t.Run("the decision record names the span", func(t *testing.T) {
		var found bool
		for _, rec := range readLog(t, r.path) {
			if rec.GetTrace().GetSpanId() == span.SpanID {
				found = true
			}
		}
		if !found {
			t.Errorf("no audit record carries span id %q. `Trace.span_id` lands WITH its "+
				"writer (D216), and a field the writer does not populate is the defect the "+
				"note it replaced existed to prevent", span.SpanID)
		}
	})

	t.Run("no metric carries a trace id as a label", func(t *testing.T) {
		var scrape strings.Builder
		if _, err := r.srv.Metrics().WriteTo(&scrape); err != nil {
			t.Fatalf("metrics: %v", err)
		}
		text := scrape.String()
		for _, id := range []string{callerTrace, span.TraceID, span.SpanID} {
			if strings.Contains(text, id) {
				t.Errorf("the scrape contains %q. A trace id as a label is UNBOUNDED "+
					"CARDINALITY — one series per request — and it takes the scrape down "+
					"long before anybody queries it", id)
			}
		}
		// RED, KEYED THE WAY THE CRITERION ASKS: target, action, outcome.
		if !strings.Contains(text, `sekizui_actions_total{target="kata:alpha",action="kata.create_issue",outcome="ok"}`) {
			t.Errorf("the scrape does not carry RED metrics keyed (target, action, "+
				"outcome):\n%s", text)
		}
	})

	t.Run("Stop flushes pending spans, and is idempotent", func(t *testing.T) {
		// **WITHOUT THIS THE LAST TRACE BEFORE A SHUTDOWN IS THE ONE NOBODY
		// SEES**, and a shutdown is exactly when somebody is looking. It is why
		// the provider is a spine Component rather than a value the gateway
		// owns.
		var flushed int
		p := tracing.New(tracing.WithSink(func(s []tracing.Span) { flushed += len(s) }))
		p.Begin("", "", false, "x", nil).End()
		if err := p.Stop(context.Background()); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if flushed != 1 {
			t.Errorf("Stop flushed %d span(s), want 1", flushed)
		}
		if err := p.Stop(context.Background()); err != nil {
			t.Fatalf("second Stop: %v", err)
		}
		if flushed != 1 {
			t.Errorf("a second Stop re-delivered spans (%d); shutdown races and leader "+
				"churn both call Stop more than once", flushed)
		}
	})
}
