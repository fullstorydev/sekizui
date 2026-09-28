// Package tracing mints spans for outbound calls, in process, with no vendor
// SDK.
//
// **A SKELETON, AND THAT IS D91's PRECEDENT RATHER THAN A SHORTCUT (D235).**
// The maintainer asked whether step 29 really needs OpenTelemetry. It does not: the init
// ledger's `obs:otel` entry asks for *"traces with the delegation chain in span
// attributes; RED metrics"*, and only its NAME says otel. The bus landed at P0
// the same way — "authorised, audited, and lensed delivery over an in-process
// transport" — and was filled in later. **OTel is an EXPORTER, wanted when spans
// must leave the process, which is an operations concern for P4/P6.** Deferring
// it keeps D58's deliberate-dependency posture: an SDK here would SHIP in the
// binary, unlike D205's test-only `x/tools`.
//
// **W3C-SHAPED IDS, so the wire format is right before anything exports.** 16
// random bytes for a trace, 8 for a span, rendered as lowercase hex — the
// `traceparent` shapes `Trace.trace_id` and `Trace.parent_span_id` already use
// (D216). An exporter added later reads these unchanged; getting the shape wrong
// now would mean re-minting ids in a phase where consumers already hold them.
//
// **WHAT THIS DELIBERATELY DOES NOT DO:** sample. The caller's flag is carried
// and never overridden (D216) — inflating somebody else's telemetry bill is not
// Sekizui's decision to make — and a span this package records is recorded
// regardless, because the record is local and costs a slice append.
//
// DESIGN.md references: §10.4, §12 P2, D58, D91, D115, D205, D216, D235.
package tracing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Span is one outbound call.
//
// A VALUE A TEST CAN READ, which is the point of a skeleton: the assertion is
// about what Sekizui RECORDS, not about what a collector received. An exporter
// translates this; nothing has to change here for it to.
type Span struct {
	TraceID      string
	SpanID       string
	ParentSpanID string

	// Sampled is the CALLER's decision, carried through untouched (D216).
	Sampled bool

	Name       string
	Started    time.Time
	Ended      time.Time
	Attributes map[string]string
}

// Provider mints spans and holds finished ones until Stop flushes them.
//
// **IT IS A `spine.Component` BECAUSE `Stop` MUST FLUSH.** Without that, the
// last trace before a shutdown is the one nobody sees — and a shutdown is
// exactly when somebody is looking. The spine already sequences Stop against the
// drain (D207: readiness is withdrawn before the drain), so spans for calls that
// were in flight at shutdown are flushed after those calls finish rather than
// discarded with them.
type Provider struct {
	mu      sync.Mutex
	spans   []Span
	sink    func([]Span)
	now     func() time.Time
	stopped bool
}

// Option configures a Provider.
type Option func(*Provider)

// WithSink installs the destination Stop flushes to.
//
// **A FUNCTION, NOT AN INTERFACE, AND NOT AN EXPORTER.** The only in-tree
// consumers are the acceptance step, which reads the slice, and a logger. An
// interface here would be a published seam with one implementation and a
// speculative second — the shape D35 is careful about and `archcheck` refuses.
func WithSink(fn func([]Span)) Option { return func(p *Provider) { p.sink = fn } }

// WithClock substitutes time, for deterministic tests.
func WithClock(now func() time.Time) Option { return func(p *Provider) { p.now = now } }

// New returns a Provider.
func New(opts ...Option) *Provider {
	p := &Provider{now: time.Now}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name identifies the component. Stable: it appears in readiness output.
func (p *Provider) Name() string { return "obs:tracing" }

// Start is a no-op: there is nothing to connect to.
//
// HONEST RATHER THAN DECORATIVE. A skeleton that pretended to dial something
// would report a health it does not have, which is D77's crying wolf inverted.
func (p *Provider) Start(context.Context) error { return nil }

// Stop flushes.
//
// IDEMPOTENT, because shutdown races and leader-election churn both call it more
// than once (spine.Component's contract), and a second call must not re-deliver
// the same spans to a sink that has already written them.
func (p *Provider) Stop(context.Context) error {
	p.mu.Lock()
	pending, already := p.spans, p.stopped
	p.spans, p.stopped = nil, true
	sink := p.sink
	p.mu.Unlock()

	if already || sink == nil || len(pending) == 0 {
		return nil
	}
	sink(pending)
	return nil
}

// Begin starts a span for an outbound call, as a CHILD of the caller's.
//
// **THE PARENT IS THE CALLER'S SPAN, AND D216 SETTLED THAT BEFORE THIS EXISTED.**
// A bare `trace_id` cannot parent anything, so a span built against it would
// place every governed call as a detached ROOT beside the work that requested
// it — buildable, green, and misleading, which is why D216 landed first.
//
// An EMPTY parent is legitimate and common: a caller that sent no `traceparent`
// has no span to be a child of, and this span is then the root of a trace
// Sekizui started.
func (p *Provider) Begin(traceID, parentSpanID string, sampled bool,
	name string, attrs map[string]string) *Live {

	if traceID == "" {
		traceID = newID(16)
	}
	return &Live{
		provider: p,
		span: Span{
			TraceID:      traceID,
			SpanID:       newID(8),
			ParentSpanID: parentSpanID,
			Sampled:      sampled,
			Name:         name,
			Started:      p.now(),
			Attributes:   attrs,
		},
	}
}

// Live is a span in progress.
type Live struct {
	provider *Provider
	span     Span
	ended    bool
}

// SpanID is the id this span will carry, available before it ends so the
// decision record can name it.
//
// NIL-TOLERANT, like End. A deployment with no tracer produces a nil *Live, and
// the enforcement path must not branch on observability being configured — the
// empty string then flows through `audit.WithSpan`, which ignores it, and the
// field is written as absent rather than as a fiction.
func (l *Live) SpanID() string {
	if l == nil {
		return ""
	}
	return l.span.SpanID
}

// End records the span. Idempotent.
func (l *Live) End() {
	if l == nil || l.ended {
		return
	}
	l.ended = true
	l.span.Ended = l.provider.now()

	l.provider.mu.Lock()
	defer l.provider.mu.Unlock()
	// AFTER Stop, A SPAN IS DROPPED RATHER THAN QUEUED FOREVER. A call that
	// outlives the flush has nowhere to go, and holding it would grow a slice
	// nobody will ever read.
	if l.provider.stopped {
		return
	}
	l.provider.spans = append(l.provider.spans, l.span)
}

// Recorded returns the spans held so far, for a test or a health surface.
func (p *Provider) Recorded() []Span {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Span(nil), p.spans...)
}

// newID mints n random bytes as lowercase hex, W3C's shape.
//
// `crypto/rand` rather than `math/rand`: a predictable span id lets somebody
// else's trace be joined to ours, and the cost is nothing on this path.
func newID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// **CANNOT HAPPEN, AND IF IT DOES A ZERO ID IS THE HONEST ANSWER.**
		// crypto/rand.Read never returns an error on any supported platform.
		// Panicking would take a governed command down for an observability
		// concern, which inverts what this is for.
		return ""
	}
	return hex.EncodeToString(b)
}
