// Package bus is the in-process event bus (D24).
//
// PRIVATE (D35); the interface it satisfies is pkg/bus.
//
// A SKELETON, AND HONEST ABOUT WHICH PART. At-most-once delivery, no
// persistence, no replay, no queue groups — everything JetStream brings at P7.
// What it DOES provide is the governed path: a subscription is authorised,
// audited, and lensed before an envelope reaches a consumer, and those are the
// questions worth settling before a real broker arrives to make them expensive
// to change.
//
// WHY IT EXISTS IN P0 AT ALL (D91). `shin.Deliver` was written, tested,
// documented as the bus delivery path — and called by nothing. That is the
// fourth instance in this phase of a contract declared and never invoked, the
// class D88 and D89 came from. Leaving the transport to P3 would have left the
// lens layer's production path unexercised for three phases, which is precisely
// how the earlier four survived.
//
// BOUNDED BUFFERS, DROP WITH A COUNTER. pkg/bus requires "never unbounded
// buffering, which converts a slow consumer into an OOM (§7.1)". A dropped
// envelope is counted and logged rather than silently discarded, because a
// consumer that quietly misses events reaches confident wrong conclusions — the
// same argument §4.1.1 makes about truncated query results.
//
// DESIGN.md references: §4.6, §4.11.2, §7.1, D21, D24, D43, D91.
package bus

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// DefaultBuffer is how many envelopes one subscription may lag by.
//
// Small on purpose. A large buffer hides a slow consumer until the process runs
// out of memory; a small one surfaces it as a drop counter within seconds,
// which is a metric someone can act on.
const DefaultBuffer = 256

// InProcess is a Bus with no broker behind it.
type InProcess struct {
	log    *slog.Logger
	buffer int

	mu     sync.RWMutex
	subs   map[*subscription]struct{}
	closed bool

	// dropped counts envelopes a full subscription could not take, over the
	// process lifetime; Dropped() reads it for the shutdown summary. The
	// PER-SUBSCRIPTION count below is what reaches the metrics scrape and the
	// consumer itself (P3 step 6): this comment used to say the scrape read
	// THIS field, and nothing did.
	//
	// ATOMIC, NOT GUARDED BY mu, AND THE REASON IS A TRAP WORTH NAMING. Publish
	// holds mu as a READ lock, deliberately — many publishers should proceed at
	// once. A read lock permits concurrency; it does not make a write safe, so
	// `b.dropped++` inside that critical section is two publishers incrementing
	// the same word with no ordering between them. It is a genuine data race,
	// and it shipped: `-race` reported it the moment a code change invalidated
	// the cached test result that had been hiding it.
	//
	// Promoting the lock to a write lock would fix it and serialise every
	// publish behind the slowest subscriber's channel send — paying a
	// throughput cost on the hot path to protect a counter. An atomic costs one
	// instruction and leaves the read lock doing what it was chosen for.
	dropped atomic.Uint64
}

// New returns an in-process bus.
func New(log *slog.Logger, buffer int) *InProcess {
	if buffer <= 0 {
		buffer = DefaultBuffer
	}
	return &InProcess{log: log, buffer: buffer, subs: map[*subscription]struct{}{}}
}

// Compile-time proof that the public interface is satisfied, per GO-PRIMER §2.
var _ bus.Bus = (*InProcess)(nil)

// Name identifies this component in the init ledger and readiness output.
func (b *InProcess) Name() string { return "bus" }

// Start is a no-op: an in-process bus has nothing to connect to. It exists so
// the component participates in the lifecycle, and so replacing it with a
// broker-backed implementation at P7 is a substitution rather than a rewiring.
func (b *InProcess) Start(ctx context.Context) error { return nil }

// Stop closes every subscription. Idempotent, as the Component contract
// requires.
func (b *InProcess) Stop(ctx context.Context) error { return b.Close(ctx) }

// Publish fans an envelope out to every matching subscription.
//
// DOES NOT VALIDATE stage monotonicity or payload schemas, as pkg/bus requires:
// both happen upstream, at config load and publish time, so a misconfiguration
// fails at boot rather than at 3am (D21, D42).
func (b *InProcess) Publish(ctx context.Context, env *sekizuiv1.Envelope) error {
	const op = "bus.Publish"

	if env == nil {
		return fault.New(fault.KindInvalidArgument, op, "nil envelope")
	}
	// A STAGE AND A TYPE, because those are what the subject is made of (D60,
	// D258). This used to accept an envelope with an entity subject and no type,
	// which was consistent only with matching on the entity — the reading D258
	// removed.
	if env.GetStage() == "" || env.GetType() == "" {
		return fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"envelope %q has stage %q and type %q; its bus subject is sekizui.<stage>.<type> "+
				"(D60) and cannot be formed without both, so nothing could match it",
			env.GetId(), env.GetStage(), env.GetType()))
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return fault.New(fault.KindUnavailable, op, "the bus is closed")
	}

	for sub := range b.subs {
		if !sub.matches(env) {
			continue
		}
		select {
		case sub.ch <- env:
		default:
			// FULL. Drop and count, never block: blocking here would let one
			// slow consumer stall every publisher, and unbounded buffering
			// would turn it into an OOM (§7.1).
			b.dropped.Add(1)
			b.log.Warn("dropped an envelope for a lagging subscription",
				"consumer", sub.consumer, "subject", bus.SubjectOf(env),
				"buffer", cap(sub.ch), "dropped_total", sub.dropped.Add(1))
		}
	}
	return nil
}

// Subscribe registers a filter and returns the stream.
//
// AUTHORISATION IS NOT DONE HERE. The bus is transport; deciding whether a
// principal may consume a subject is the gateway's job, and putting it here
// would create a second enforcement path — the thing D18 exists to prevent.
func (b *InProcess) Subscribe(ctx context.Context, f bus.Filter) (bus.Subscription, error) {
	const op = "bus.Subscribe"

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, fault.New(fault.KindUnavailable, op, "the bus is closed")
	}
	if f.QueueGroup != "" {
		// Competing consumption needs a broker. Refusing is honest; silently
		// giving every member a copy would fire one reflex N times at N
		// replicas, and it looks completely fine at one replica (§4.11.2).
		return nil, fault.New(fault.KindConfig, op,
			"queue groups need a broker and land with JetStream at P7. The in-process bus "+
				"would give every member a copy, which fires a reflex once per replica — a "+
				"bug invisible at one replica")
	}

	// NO SCOPE IS REFUSED, NOT READ AS "EVERYTHING" (D260). The two readings
	// an empty scope could have are both wrong: everything makes forgetting it
	// the widest grant there is, and nothing gives the consumer an idle stream
	// it cannot tell from a quiet bus. So it is an error, naming the fix.
	if len(f.Scope) == 0 && !f.Unscoped {
		return nil, fault.New(fault.KindInvalidArgument, op,
			"a subscription with no scope: every Subscribe carries the (subject, source) "+
				"pairs its consumer's grant authorises (D259, D260), built by "+
				"gateway.ScopeFor from configuration. Unscoped is for test files only")
	}

	sub := &subscription{
		ch:       make(chan *sekizuiv1.Envelope, b.buffer),
		filter:   f,
		consumer: consumerFrom(ctx),
		bus:      b,
	}
	b.subs[sub] = struct{}{}
	return sub, nil
}

// Close ends every subscription.
func (b *InProcess) Close(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true
	for sub := range b.subs {
		sub.closeOnce()
	}
	b.subs = map[*subscription]struct{}{}
	return nil
}

// Dropped reports how many envelopes were discarded for lagging subscriptions.
//
// EXPOSED so the number reaches a scrape. A drop counter nobody reads is the
// same as dropping silently, which is what the bounded buffer exists to avoid.
func (b *InProcess) Dropped() uint64 {
	// No lock: the counter carries its own synchronisation now, and taking mu
	// here would suggest mu is what protects it — which is exactly the belief
	// that produced the race in Publish.
	return b.dropped.Load()
}

// Subscribers reports the current subscription count, for readiness and tests.
func (b *InProcess) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

type subscription struct {
	ch       chan *sekizuiv1.Envelope
	filter   bus.Filter
	consumer string
	bus      *InProcess

	// Atomic for the same reason as InProcess.dropped: incremented under a READ
	// lock, which orders nothing.
	dropped atomic.Uint64

	once sync.Once
	err  error
}

func (s *subscription) Events() <-chan *sekizuiv1.Envelope { return s.ch }

// Dropped is how many envelopes this subscription's full buffer refused — the
// count an at-most-once consumer is owed (P3 step 6, D24). An OPTIONAL method,
// type-asserted by the gateway, so pkg/bus.Subscription does not grow a
// required method an out-of-tree driver would break on (D35, GO-PRIMER §2.2).
func (s *subscription) Dropped() uint64 { return s.dropped.Load() }
func (s *subscription) Err() error      { return s.err }

// Ack is a NO-OP under at-most-once (D24). It exists so consumer code written
// today needs no change when JetStream arrives. Calling it is always correct.
func (s *subscription) Ack(id string) error { return nil }

func (s *subscription) Close() error {
	s.bus.mu.Lock()
	delete(s.bus.subs, s)
	s.bus.mu.Unlock()

	s.closeOnce()
	return nil
}

func (s *subscription) closeOnce() { s.once.Do(func() { close(s.ch) }) }

// matches applies the filter. An empty filter matches everything the caller was
// authorised for — the gateway has already narrowed that.
func (s *subscription) matches(env *sekizuiv1.Envelope) bool {
	// AUTHORISATION FIRST (D260): the grant's scope, through the one matcher the
	// gateway asserts with on receipt. Unscoped is refused in production code by
	// archcheck, not here.
	if !s.filter.Unscoped && !bus.InScope(s.filter.Scope, env) {
		return false
	}
	// THE DERIVED SUBJECT, NOT `env.GetSubject()` — that field is the ENTITY
	// (D258), and matching on it is what made every real connector's envelope
	// invisible to every subscription.
	if len(s.filter.Subjects) > 0 && !subjectMatches(s.filter.Subjects, bus.SubjectOf(env)) {
		return false
	}
	if len(s.filter.Types) > 0 && !contains(s.filter.Types, env.GetType()) {
		return false
	}
	if s.filter.Residency != "" && s.filter.Residency != env.GetResidency() {
		return false
	}
	return true
}

func subjectMatches(patterns []string, subject string) bool {
	for _, p := range patterns {
		if bus.SubjectMatches(p, subject) {
			return true
		}
	}
	return false
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// consumerKey types the context value, per GO-PRIMER §15d.
type consumerKey struct{}

// WithConsumer labels a subscription with the principal that owns it, for logs
// and drop counters.
func WithConsumer(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, consumerKey{}, principal)
}

func consumerFrom(ctx context.Context) string {
	if p, ok := ctx.Value(consumerKey{}).(string); ok {
		return p
	}
	return "unknown"
}
