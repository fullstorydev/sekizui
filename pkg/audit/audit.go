// Package audit defines the decision-record sink seam.
//
// PUBLIC API (D35). "Ships to whatever warehouse the operator already has"
// (D32) only works if third parties can add sinks without forking — and a SIEM
// integration is the most likely thing a self-hoster needs and we do not have.
//
// DESIGN.md references: §5.2.2, §5.2.2a, §5.4, D12, D23, D32, D39.
package audit

import (
	"context"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Sink is a durable destination for decision records.
//
// The WAL is the DURABILITY BOUNDARY; a Sink is the DESTINATION. Records are
// fsynced locally first, then shipped here in batches (§5.2.2). A Sink may
// therefore be slow or briefly unavailable without losing records — but it must
// not silently drop them.
//
// BATCH, NEVER ROW-BY-ROW. BigQuery streaming inserts carry per-row cost and
// quota; batched loads are dramatically cheaper at audit volume (§5.2.2a).
type Sink interface {
	// Name identifies this sink in logs and metrics: "bigquery", "splunk-hec".
	Name() string

	// Write persists a batch. Must be atomic per batch or safely retryable:
	// records carry IDs and a hash chain, so at-least-once delivery to the sink
	// is acceptable and duplicates are detectable. Losing a batch is not.
	Write(ctx context.Context, batch []*sekizuiv1.Decision) error

	// Residencies returns which residency classifications this sink may receive,
	// or nil for any.
	//
	// THE EASILY-MISSED REQUIREMENT (D29 item 4): shipping EU-resident decision
	// records to a US warehouse makes the audit log itself the violation. Audit
	// config is usually set once globally and never revisited per tenant, which
	// is exactly why this belongs on the interface rather than in a comment.
	Residencies() []string

	// Close flushes and releases. Called during drain, within
	// RuntimeProfile.GracePeriod (§4.10.2).
	Close(ctx context.Context) error
}

// Recorder is what the enforcement path uses. Implemented by the internal WAL;
// on the interface here because drivers and reflexes both record through it.
//
// TWO PHASES, DELIBERATELY (§5.2.2). Intent is written BEFORE the side effect and
// outcome after, so a crash mid-call cannot leave zero trace of an action that may
// well have succeeded. Single-phase recording is the most common way an audit log
// becomes untrustworthy without anyone noticing.
// OutcomeOption carries a fact the intent row could not have known.
type OutcomeOption func(*sekizuiv1.Decision)

// WithSpan names the span that covered the outbound call (§10.4, D216, D235).
//
// ON THE OUTCOME ROW AND NOT THE INTENT, because that is the row that describes
// the call. Both rows share a decision id, so a reader holding either can reach
// the other; what would be dishonest is an intent row naming a span for a
// command that was refused before any call was made.
func WithSpan(spanID string) OutcomeOption {
	return func(d *sekizuiv1.Decision) {
		if spanID == "" {
			return
		}
		if d.Trace == nil {
			d.Trace = &sekizuiv1.Trace{}
		}
		d.Trace.SpanId = spanID
	}
}

type Recorder interface {
	// Intent records what is about to be attempted. Returns the decision ID.
	// Must be durable before it returns.
	Intent(ctx context.Context, d *sekizuiv1.Decision) (string, error)

	// Outcome records what happened, correlated by decision ID.
	//
	// **THE VARIADIC IS FOR FACTS THE INTENT ROW COULD NOT HAVE KNOWN (D235).**
	// `Trace.span_id` is the first: a span covers the OUTBOUND CALL, which
	// begins long after the intent row is durable — after the limiter, the
	// breaker and the resolver — so stamping it on the intent would either name
	// a span that does not exist yet or name one for a command that never
	// reached a driver. Variadic rather than a new parameter so the three
	// existing call sites are untouched, which is the same reason
	// `NewRecorder`'s options are options.
	Outcome(ctx context.Context, decisionID string, e *sekizuiv1.Effect,
		opts ...OutcomeOption) error

	// Terminal records a decision with no external effect — a denial, an
	// escalation, or a tripped budget. One call, no outcome phase.
	//
	// DENIALS AND ESCALATIONS ARE THE HIGHEST-VALUE ROWS. "Agent X tried to
	// delete a project and was refused" is the sentence that justifies this
	// entire service, and implementations that only record successful calls drop
	// exactly that (§5.4).
	Terminal(ctx context.Context, d *sekizuiv1.Decision) (string, error)
}

// reflexNameKey types the context value, per GO-PRIMER §15d.
type reflexNameKey struct{}

// WithReflexName attributes a decision to the rule that caused it.
//
// LIVES HERE, not in internal/reflex or internal/gateway, because attribution is
// an AUDIT concern and both of those would otherwise need to import the other.
// The reflex engine depends only on its own Enforcer interface, which is what
// keeps it testable without a gateway; routing the attribution through pkg/audit
// preserves that.
//
// WHY IT IS NEEDED AT ALL: `Decision.reflex_name` existed in the proto and
// nothing wrote it, so every reflex-driven record named only the PRINCIPAL. The
// acceptance configuration has three rules sharing `reflex:friction`, which
// meant the audit log could not say which of the three fired — and "why did this
// ticket get created" is exactly the question the log exists to answer (D96).
func WithReflexName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, reflexNameKey{}, name)
}

// ReflexNameFrom returns the attributed rule, or "" for an agent-driven command.
func ReflexNameFrom(ctx context.Context) string {
	if name, ok := ctx.Value(reflexNameKey{}).(string); ok {
		return name
	}
	return ""
}
