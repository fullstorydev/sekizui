package acceptance

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/retry"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// undeclaringDriver executes an action it does not declare, and always fails
// retryably.
//
// A DRIVER WRITTEN TO REACH THE ONE CASE `isMutating` CANNOT OTHERWISE BE ASKED
// ABOUT. The real drivers refuse an undeclared action before the retry policy
// could matter, which is correct and is exactly why the default has never been
// exercised.
type undeclaringDriver struct {
	kind    string
	declare []connector.ActionSpec
	calls   atomic.Int32
}

func (d *undeclaringDriver) Kind() string                    { return d.kind }
func (d *undeclaringDriver) Actions() []connector.ActionSpec { return d.declare }

func (d *undeclaringDriver) Execute(_ context.Context, _ connector.Target, _ string,
	_ map[string]any, _ connector.Idempotency) (connector.Result, error) {

	d.calls.Add(1)
	return connector.Result{}, &fault.Error{
		Kind: fault.KindRateLimited, Op: "undeclaring.Execute", Msg: "429",
	}
}

func (d *undeclaringDriver) Query(context.Context, connector.Target, string,
	map[string]any) (connector.Rows, error) {
	return connector.Rows{}, nil
}

// Health is part of the Driver contract. Nil: this fixture's failures are the
// ones it injects, and reporting unhealthy would refuse the call before the
// retry decision this step is about.
func (d *undeclaringDriver) Health(context.Context, connector.Target) error { return nil }

// step34AnUnknownActionIsTreatedAsMutating proves D140's safety default.
//
// **THE STEP AS DECLARED DUPLICATED STEP 21.** Both said "a mutating action with
// no idempotency key refuses to retry on a 429", both covered exit criterion 14,
// both decided D113 — and step 21 already proves it, varying the KEY with
// mutation held constant. Step 35 supplies the other axis. What neither covers is
// the branch D140 wrote for the case nobody expects to reach:
//
//	AN UNKNOWN ACTION IS TREATED AS MUTATING. "It should not be reachable —
//	policy authorised it and the driver is about to run it — but if it ever is,
//	the safe answer is the one that refuses to retry. Guessing 'read-only' about
//	an action nobody can describe is how a double write happens."
//
// A default nothing exercises is a default nobody has checked, and this one sits
// on the path between an authorised command and a possible duplicate write.
func step34AnUnknownActionIsTreatedAsMutating(t *testing.T) {
	ctx := context.Background()

	run := func(t *testing.T, declared []connector.ActionSpec) int32 {
		t.Helper()

		// THE CREDENTIAL MUST RESOLVE, or the command is refused before the
		// driver is reached and every arm reports zero attempts — which is what
		// the first version of this step did, and it would have read as "the
		// refusal worked" for all three cases including the one that must retry.
		t.Setenv("SEKIZUI_ACCEPT_TOK", "step-34-token")

		const kind = "undeclaring"
		const action = "undeclaring.do_something"

		d := &undeclaringDriver{kind: kind, declare: declared}
		doc := &config.Document{
			Targets: []config.TargetSpec{{
				Ref: "u:one", Kind: kind, Tenant: "t", BaseURL: "https://u.invalid",
				CredentialRef: "env://SEKIZUI_ACCEPT_TOK",
			}},
			Grants: []config.GrantSpec{{
				Principal: "agent:triage",
				Allow:     []config.CapabilitySpec{{Action: action, TargetRef: "u:one"}},
			}},
		}

		path := auditPath(t)
		sink := auditwal.NewJSONLSink(path)
		if err := sink.Start(ctx); err != nil {
			t.Fatalf("sink: %v", err)
		}
		defer func() { _ = sink.Stop(ctx) }()

		clock := time.Date(2026, 8, 31, 17, 0, 0, 0, time.UTC)
		tick := func() time.Time { clock = clock.Add(time.Second); return clock }

		srv := gateway.New(gateway.Config{
			Doc:      doc,
			Policy:   policy.NewGrantEngine(doc, nil),
			Resolver: resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}),
			Drivers:  map[string]connector.Driver{kind: d},
			Guards:   anzen.New(nil),
			Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc), auditwal.WithClock(tick)),
			// Retries are POSSIBLE, so a refusal to retry is a decision rather
			// than an absence. Without this the step passes against a gateway
			// that never retries anything.
			Retry: retry.New(retry.Policy{
				MaxAttempts: 3, Base: time.Millisecond,
				Cap: time.Millisecond, Budget: time.Second,
			}),
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Now: tick,
		})

		// NO IDEMPOTENCY KEY. D113's hazard needs both halves; this supplies one
		// and the driver's declaration decides the other.
		res, err := srv.Enforce(ctx, assertedIdentity("agent:triage"), &sekizuiv1.Command{
			Action: action, TargetRef: "u:one",
			Args: mustArgs(t, map[string]any{}),
		})

		// **A 429 IS A RESULT, NOT AN ERROR (D135)**, and asserting on the error
		// was wrong: every deliberate refusal reaches the caller as a
		// CommandResult with a mapped status, and only genuine failures stay
		// transport errors. The first version of this step asserted `err != nil`
		// and reported "the injected rate limit did not surface" for a rate limit
		// that had surfaced exactly as designed.
		if err != nil {
			t.Fatalf("the rate limit arrived as a transport error: %v", err)
		}
		if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Fatal("the injected rate limit did not surface")
		}
		return d.calls.Load()
	}

	// --- 34a: UNDECLARED MEANS MUTATING, SO NO RETRY --------------------
	t.Run("an action the driver does not declare is not retried", func(t *testing.T) {
		if got := run(t, nil); got != 1 {
			t.Errorf("attempts = %d for an action nobody declared, want 1. D140: "+
				"guessing read-only about an action nobody can describe is how a "+
				"double write happens — the first call may have landed, and a 429 "+
				"does not say which side of the write it died on", got)
		}
	})

	// --- 34b: NON-VACUITY — a DECLARED non-mutating action does retry --
	//
	// Without this the step passes against a gateway that never retries, and the
	// safety default would be indistinguishable from the feature being absent.
	// It also pins the default as a DEFAULT rather than a blanket rule: the
	// answer changes when the driver actually answers.
	t.Run("a declared non-mutating action retries", func(t *testing.T) {
		got := run(t, []connector.ActionSpec{{
			Name: "undeclaring.do_something", Mutating: false,
		}})
		if got < 2 {
			t.Errorf("attempts = %d for a declared READ, want more than 1. D113's "+
				"refusal is about mutation, not about retrying — and a read carries no "+
				"double-write hazard", got)
		}
	})

	// --- 34c: AND A DECLARED MUTATING ONE STILL REFUSES ---------------
	t.Run("a declared mutating action is not retried without a key", func(t *testing.T) {
		if got := run(t, []connector.ActionSpec{{
			Name: "undeclaring.do_something", Mutating: true,
		}}); got != 1 {
			t.Errorf("attempts = %d for a declared WRITE with no key, want 1", got)
		}
	})
}

// Schemas: this double declares no output type, so it ships no schema (D279).
func (d *undeclaringDriver) Schemas() ([]connector.Schema, error) { return nil, nil }
func (d *undeclaringDriver) Meter() connector.Meter               { return connector.Meter{} }
