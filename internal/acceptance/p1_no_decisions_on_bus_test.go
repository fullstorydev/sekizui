package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/bus"
	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step42DecisionRecordsNeverReachTheBus proves D118 — and it exists because D119
// leaned on the word *provably* and nothing did the proving (D154).
//
// **THIS STEP REPLACED A DIFFERENT ONE.** It was declared as "credential posture
// on a decision record is withholdable by a lens" (D116), which cannot be built:
// D116's disclosure half assumes consumers can subscribe to decision records,
// and D118 then ruled that decisions never travel on the bus at all — the bus is
// designed to DROP and the audit log is designed never to. With no bus consumer
// there is nothing for a lens to withhold from, and the control over who reads
// posture in the warehouse is the WAREHOUSE's column access, not shin.
//
// So a declared step existed for a mechanism D118 had removed, which is the
// recurring "declared contract that does nothing" defect at the level of the
// phase plan. It is repurposed rather than deleted because D118's guarantee is
// the more valuable thing, and D119's widening of the record rests on it.
// envelopeOnlyPublisher is 42a: the compile-time half of D118's guarantee.
//
// `pkgbus.Bus` must satisfy a Publish that accepts an ENVELOPE and nothing else,
// so a `*Decision` cannot be published as one. Widen the real signature — to
// `any`, or to a second parameter — and `pkgbus.Bus` stops satisfying this and
// the package does not compile.
//
// AS A PACKAGE-LEVEL ASSERTION RATHER THAN A LOCAL VARIABLE, and that took two
// attempts worth recording. The obvious form is
// `var publish func(context.Context, *sekizuiv1.Envelope) error = b.Publish`,
// where the explicit type IS the assertion — and staticcheck's ST1023 objects
// that the type should be inferred, which would delete the only part that
// checks anything. The `var _ I = (T)(nil)` form asserts the same thing in the
// idiom the linter and the rest of this tree already expect.
type envelopeOnlyPublisher interface {
	Publish(context.Context, *sekizuiv1.Envelope) error
}

var _ envelopeOnlyPublisher = (pkgbus.Bus)(nil)

func step42DecisionRecordsNeverReachTheBus(t *testing.T) {
	ctx := context.Background()

	// --- 42b: RUNTIME — a subscriber sees nothing while decisions are made -
	t.Run("a subscriber receives nothing while commands flow", func(t *testing.T) {
		eventBus := bus.New(quietLogger(), bus.DefaultBuffer)
		if err := eventBus.Start(ctx); err != nil {
			t.Fatalf("bus: %v", err)
		}
		defer func() { _ = eventBus.Stop(ctx) }()

		// THE BROADEST PATTERN THE BUS ACCEPTS. Subscribing narrowly would prove
		// only that decisions do not arrive on the subject guessed at here.
		sub, err := eventBus.Subscribe(ctx, pkgbus.Filter{Unscoped: true, Subjects: []string{">"}})
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}

		// multiResidencyInstance takes *testing.T rather than a context because it
		// owns its own sink lifecycle through t.Cleanup — test scaffolding, not a
		// call in the enforcement path.
		//nolint:contextcheck // fixture manages its own lifecycle via *testing.T
		srv, sink, _ := multiResidencyInstance(t, acceptanceResidency)
		defer func() { _ = sink.Stop(ctx) }()

		// BOTH AN ALLOWED AND A REFUSED COMMAND. A refusal is §5.4's
		// highest-value record and the one a SIEM would most want to subscribe
		// to, which is exactly the temptation D118 refuses.
		for _, who := range []string{"agent:triage", "agent:global"} {
			res, err := srv.Enforce(ctx, assertedIdentity(who), &sekizuiv1.Command{
				Action: "kata.create_issue", TargetRef: "kata:alpha",
				Args:           mustArgs(t, map[string]any{"project": "PROJ"}),
				IdempotencyKey: "acc-42-" + who,
			})
			if err != nil {
				t.Fatalf("%s: %v", who, err)
			}
			requireAllowedThenRefused(t, "42b", who, res)
		}

		// A SHORT WAIT, because delivery is asynchronous and asserting an
		// absence immediately would pass against a bus that simply had not got
		// round to it yet.
		select {
		case env := <-sub.Events():
			t.Errorf("a subscriber received %v while commands were being decided. If "+
				"decision records reach the bus then §5.2.2's one unacceptable failure "+
				"— losing an audit record — becomes reachable through a transport that "+
				"DROPS on overflow by design", env)
		case <-time.After(100 * time.Millisecond):
		}
	})

	// --- 42c: THE RESIDUAL, NAMED RATHER THAN GUARDED --------------------
	//
	// `Envelope.Data` is a free-form Struct, so a decision COULD be copied into
	// one field by field. Nothing does.
	//
	// The obvious structural guard — no file that calls `Publish` may mention
	// `Decision` — was written and abandoned: it FALSE-POSITIVES on
	// internal/gateway/subscribe.go, which legitimately does both, because it
	// records a decision ABOUT a subscription while publishing envelopes for it.
	// A guard that has to be weakened on its first real file is worse than a
	// limit somebody wrote down, so this is the limit written down (D154).
	t.Run("the residual path is Envelope.Data, and it is stated", func(t *testing.T) {
		env := &sekizuiv1.Envelope{}
		if env.GetData() != nil {
			t.Fatal("a zero Envelope has non-nil Data")
		}
		// Asserting the SHAPE of the hole rather than its absence: Data is a
		// Struct, which by design carries anything, and that is why this is a
		// review obligation rather than a check.
		t.Log("Envelope.Data is a free-form Struct: a decision could be copied into it " +
			"field by field, and no mechanism prevents that. Nothing in the tree does it. " +
			"Recorded in D154 as a limit rather than papered over with a guard that " +
			"false-positives on the only file that publishes.")
	})
}
