package acceptance

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step3ANoneClassActionRefusesToRetry proves D163's refusal half and D182.
//
// **THE REFUSAL IS THE GUARANTEE, AND HALF OF IT WAS MISSING.** D163's gate was
// closed correctly — a `none`-class action was attempted once and not repeated —
// and then the upstream's own error went back to the caller unchanged. That
// error is a TIMEOUT, which fault.Retryable calls retryable and gRPC maps to
// DeadlineExceeded, so an agent consulting either one retries and produces
// exactly the duplicate the gate refused to produce. Writing this step is what
// surfaced it: the assertion "the command is refused as a RESULT carrying a kind
// a caller can act on" had nothing to assert against. See D182.
//
// **NON-VACUITY IS NOT A GARNISH HERE.** A driver that refused every retry
// passes the first three arms and is useless, and — worse — is indistinguishable
// from a Sekizui whose retry loop is broken. Arm 3e holds the injected failure,
// the target, the principal and the key constant and varies ONLY the declared
// class, so what the first arms observe can only be the classification.
//
// The far-side count — one effect, not two — is deliberately NOT asserted here.
// It is step 4's, against the real Fullstory, where "exactly one user with the
// last write's values" is a fact about somebody else's system rather than about
// our own retry loop (D159).
func step3ANoneClassActionRefusesToRetry(t *testing.T) {
	ctx := context.Background()
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(ctx)
	}

	// A TIMEOUT, NOT A 429, and the choice is load-bearing (D182). A rate limit
	// is an explicit statement from the far side that it did NOT act, so the
	// outcome is known and `rate_limited` remains the honest answer — P1 step 21
	// drives that case. A timeout is the one where nobody can tell which side of
	// the write it died on, which is D113's founding sentence and the only
	// failure shape for which this refusal is the truth.
	// call issues one command as agent:idempotency, with a failure of the named
	// kind injected into the driver, and returns what the client received: a
	// result, or a transport error.
	//
	// THE INJECTED KIND IS A PARAMETER rather than fixed, because arm 3f's whole
	// point is that varying it changes the answer.
	call := func(t *testing.T, action, key string, inject fault.Kind) (*sekizuiv1.CommandResult, error) {
		t.Helper()
		args, err := structpb.NewStruct(map[string]any{
			"project":          "PROJ",
			kata.FailKey:       inject.String(),
			kata.RetryAfterKey: "1ms",
		})
		if err != nil {
			t.Fatalf("building args: %v", err)
		}
		resp, err := r.as(t, "agent:idempotency").Execute(ctx, &sekizuiv1.ExecuteRequest{
			Command: &sekizuiv1.Command{
				Action: action, TargetRef: "kata:alpha", Args: args, IdempotencyKey: key,
			},
		})
		return resp.GetResult(), err
	}

	// attemptsFor reads what the audit log recorded, or -1 when the log belongs
	// to another process.
	attemptsFor := func(t *testing.T, action, key string) int {
		t.Helper()
		if r.remote {
			return -1
		}
		for _, d := range readLog(t, r.path) {
			if d.GetAction() == action && d.GetIdempotencyKey() == key && d.GetEffect() != nil {
				return int(d.GetEffect().GetAttempts())
			}
		}
		t.Fatalf("no outcome record for %s with key %q", action, key)
		return 0
	}

	const noneAction, naturalAction = "kata.append_event", "kata.upsert_record"

	// --- 3a: THE REFUSAL IS A RESULT, WITH A KIND (D135, D138) -------------
	//
	// Not a transport error. The reflex engine calls Enforce directly (D18, D69)
	// and receives a CommandResult, so a refusal delivered as an error is a
	// refusal the in-process caller cannot see at all — and from P5 that caller
	// is the one deciding whether to retry.
	res, err := call(t, noneAction, "acc-p2-3-keyed", fault.KindTimeout)
	if err != nil {
		t.Fatalf("3a: the refusal arrived as a transport error: %v. Every deliberate "+
			"refusal reaches the caller as a CommandResult (D135); an error here is "+
			"invisible to the reflex path, which never unwraps one", err)
	}
	if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Fatal("3a: a `none`-class action whose call timed out reported STATUS_OK")
	}
	if got := res.GetKind(); got != fault.KindIndeterminate.String() {
		t.Errorf("3a: kind = %q, want %q. `status` is deliberately coarser than the "+
			"taxonomy (D138), so `kind` is the only place a caller learns that the "+
			"effect is UNKNOWN rather than known-failed — and %q is what tells it not "+
			"to retry", got, fault.KindIndeterminate, fault.KindIndeterminate)
	}

	// --- 3b: THE REASON NAMES THE CLASS ------------------------------------
	//
	// `retry not permitted` is a true sentence that teaches an operator nothing.
	// The two reasons a repeat is refused have OPPOSITE remedies — `none` has no
	// remedy at all, while a missing key has the cheapest one in the system — and
	// a message that does not distinguish them leaves a limitation looking like a
	// misconfiguration somebody could fix.
	reason := res.GetReason()
	if !strings.Contains(reason, string(connector.IdempotencyNone)) {
		t.Errorf("3b: reason = %q, which does not name the idempotency class. An "+
			"operator who cannot tell WHY cannot tell a limitation of the upstream "+
			"from a mistake in our configuration", reason)
	}
	// AND IT NAMES THE UPSTREAM'S FAILURE TOO. The cause is wrapped rather than
	// replaced, so one string carries both the timeout and the refusal — which is
	// what makes `attempts: 1` under a policy permitting three legible as a
	// decision rather than as a broken retry loop.
	if !strings.Contains(reason, fault.KindTimeout.String()) {
		t.Errorf("3b: reason = %q, which does not name the underlying failure. The "+
			"refusal explains why we did not retry; the cause explains what went "+
			"wrong, and a record carrying only one of them is half a story", reason)
	}

	// --- 3c: AND IT REALLY WAS ATTEMPTED ONCE ------------------------------
	if got := attemptsFor(t, noneAction, "acc-p2-3-keyed"); got == -1 {
		r.detail(t, "SKIPPED against a live instance — attempts are read from this "+
			"process's audit log")
	} else if got != 1 {
		t.Errorf("3c: attempts = %d for a `none`-class action, want 1", got)
	}

	// --- 3d: A KEY DOES NOT BUY A RETRY (CONTRACTS 63) ---------------------
	//
	// THE ARM THAT KILLS THE OLD PREDICATE. `UnsafeToRetry` used to read
	// `mutating && idempotencyKey == ""`, so ANY non-empty key opened the gate —
	// while the key reached that predicate and the decision record and nothing
	// else, because Driver.Execute had no parameter carrying it. Arm 3a already
	// supplied a key and was refused; this pins the inverse, so the pair proves
	// the answer does not depend on the key at all. The class is a statement
	// about what the far side can do, and no local string changes it.
	unkeyed, err := call(t, noneAction, "", fault.KindTimeout)
	if err != nil {
		t.Fatalf("3d: the refusal arrived as a transport error: %v", err)
	}
	if got := unkeyed.GetKind(); got != fault.KindIndeterminate.String() {
		t.Errorf("3d: kind = %q with no idempotency key, want %q — the same answer 3a "+
			"got WITH one. A class that could be talked out of its refusal by a "+
			"caller-supplied string is CONTRACTS 63 restored", got, fault.KindIndeterminate)
	}
	if got := attemptsFor(t, noneAction, ""); got != -1 && got != 1 {
		t.Errorf("3d: attempts = %d, want 1", got)
	}

	// --- 3e: NON-VACUITY — THE RETRY WOULD OTHERWISE HAVE HAPPENED ---------
	//
	// Same injected timeout, same target, same principal, same absent key. The
	// ONLY difference is the declared class: `natural` is repeat-safe by
	// construction and needs no key, so the retry runs. Without this arm every
	// assertion above is satisfied by a Sekizui that retries nothing, and the
	// refusal is indistinguishable from the feature being absent — which is the
	// failure D154 named and exit criterion 6 was amended to avoid.
	naturalRes, naturalErr := call(t, naturalAction, "", fault.KindTimeout)

	if got := attemptsFor(t, naturalAction, ""); got != -1 && got < 2 {
		t.Errorf("3e: attempts = %d for a `natural`-class action, want more than 1. "+
			"The refusal above proves nothing if nothing ever retries — a driver that "+
			"refused every repeat would pass arms 3a to 3d and be useless", got)
	}

	// AND THE FAILURE IT REPORTS IS A DIFFERENT ONE, which is the half a count
	// cannot show. A `natural` action that exhausts its retries is a plain
	// retryable timeout and reaches the caller as a transport error, because
	// coming back later IS the right advice for it. The `none` action got a
	// non-retryable RESULT saying the opposite. Two classes, one injected
	// failure, opposite guidance — asserted so a change that collapsed the two
	// into one answer fails here rather than looking like a tidy-up.
	if naturalErr == nil {
		t.Errorf("3e: a `natural`-class action whose every attempt timed out returned "+
			"result %v and no error. A retryable failure is not a deliberate refusal, "+
			"and turning it into one would tell a caller not to retry something it "+
			"safely can", naturalRes)
	} else if got := status.Code(naturalErr); got != codes.DeadlineExceeded {
		// ASSERTED ON THE gRPC CODE because that is all a transport error carries
		// once it has crossed the wire — fault.KindOf would answer `unknown` for
		// any of them and pass. DeadlineExceeded is the timeout's own code and one
		// clients retry; FailedPrecondition is KindIndeterminate's, chosen because
		// they do not. Getting this arm's code is how the two guidances stay
		// distinguishable to a stock interceptor that reads nothing else.
		t.Errorf("3e: a `natural`-class failure reached the caller as %v, want %v. "+
			"%v is what KindIndeterminate carries, and it tells a client not to "+
			"retry something that is repeat-safe by construction",
			got, codes.DeadlineExceeded, codes.FailedPrecondition)
	}

	// --- 3f: A DETERMINATE FAILURE IS NOT DRESSED UP AS AN UNKNOWN ONE -----
	//
	// **THE MISTAKE D182's FIRST DRAFT MADE, and the arm that exists because
	// nothing else would have caught it.** The gateway's condition was
	// `retry.Retryable(err)`, which reads plausibly and is wrong on the commonest
	// retryable kind there is. A 429 is an explicit statement from the far side
	// that it did NOT act: the effect is known not to have happened, coming back
	// later is safe, and the upstream even said when. Reporting that as an
	// unknown outcome would send an operator to reconcile against a write that
	// demonstrably never landed, and would suppress the RetryAfter telling the
	// caller when to return.
	//
	// P1 steps 21 and 34 both drive a rate-limited unkeyed mutation and neither
	// notices the difference — they assert on the attempt count and on "not OK",
	// which the wrong answer satisfies. So the guarantee that the two questions
	// stay separate has exactly one witness, and it is this.
	limited, err := call(t, noneAction, "acc-p2-3-limited", fault.KindRateLimited)
	if err != nil {
		t.Fatalf("3f: the rate limit arrived as a transport error: %v", err)
	}
	if got := limited.GetKind(); got != fault.KindRateLimited.String() {
		t.Errorf("3f: kind = %q for a RATE-LIMITED `none`-class action, want %q. "+
			"Retryability and indeterminacy are different questions: the upstream "+
			"declined to act, so there is nothing unknown and nothing to reconcile — "+
			"and %q would tell the caller never to come back",
			got, fault.KindRateLimited, fault.KindIndeterminate)
	}

	r.detail(t, "D163/D182: `%s` is idempotency class `none`, so a timed-out call is "+
		"attempted once and refused as `%s` — with or without a key — while `%s` is "+
		"`natural` and retries under the policy",
		noneAction, fault.KindIndeterminate, naturalAction)
}
