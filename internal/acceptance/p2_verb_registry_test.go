package acceptance

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/verb"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// P2 steps 20 and 21: D158's rule is a MECHANISM (D165), and escalation is not a
// repeat.

// verbRefs is the ref each governed verb is driven against, and the grants for
// all six are in `acceptance.yaml` under `operator:oncall`.
//
// **A TABLE HERE AND A LOOP OVER THE REGISTRY, WHICH IS THE POINT.** The refs
// cannot be derived: `quarantine_target` is granted on `kata:alpha` and
// `revoke_credential` on `kata:sdk`, because a grant names a target and the
// configuration is what decides which. What the registry gives is the
// ENUMERATION — step 20 ranges over `verb.Names()` and FAILS on a verb missing
// from this map, so a verb added at P3 cannot be silently skipped by a test that
// looks like it covers everything. That is the property D165 asks for: covered
// by existing rather than by somebody remembering.
//
//nolint:gochecknoglobals // immutable table, read once
var verbRefs = map[string]string{
	verb.RevokeCredential: "kata:sdk",
	verb.QuarantineTarget: "kata:alpha",
	verb.RestoreTarget:    "kata:restore",

	// THE RULE, NOT A TARGET (D134). `credential-compromise` declares
	// `do: revoke_credential` on `subject: kata:restore`, so firing it twice
	// exercises the same confirmation the verb it delegates to would give.
	verb.FireAnzen: "anzen:credential-compromise",

	verb.RevokeGrant:    "principal:agent:global",
	verb.ReinstateGrant: "principal:agent:global",
}

// rfc3339 finds the timestamp inside a confirmation.
//
// WHO AND WHEN ARE WHAT D158 SAYS AN OPERATOR NEEDS, and "when" is the half a
// substring check on a principal name would miss. Matched as a shape rather than
// as a value, because the pool stamps it from its own clock.
//
//nolint:gochecknoglobals // compiled once
var rfc3339 = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)

// step20EveryOperatorVerbObeysD158 drives every governed verb twice.
//
// **THE STEP RANGES OVER THE REGISTRY RATHER THAN NAMING VERBS**, which is the
// whole reason D165 makes D158's rule a mechanism instead of advice. Before it,
// the rule lived as four hand-written branches across two files: three of the
// four existed, and ESCALATION — the dangerous one — was implemented in the
// withdrawal family and absent from the grant family. No test of a single verb
// can expose that, because each verb only ever visits two of the rule's four
// cells.
//
// The two arms are the rule's two halves. A repeat whose POSTCONDITION is
// already met is confirmed with STATUS_OK naming who got there first and when; a
// call whose PRECONDITION is false is refused with STATUS_INVALID_ARGUMENT.
//
// **ORDER MATTERS AND IS DELIBERATE: the refusing arm runs FIRST.** It needs a
// clean state — `restore_target` on a target nobody withdrew, `reinstate_grant`
// on a principal nobody suspended — and `fire_anzen` withdraws `kata:restore` in
// the arm below. Run the other way round, the refusing arm would fail for the
// wrong reason and look like a defect in the rule.
func step20EveryOperatorVerbObeysD158(t *testing.T) {
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	if r.localOnly(t, "it reads this process's audit log to check what a repeat recorded") {
		return
	}

	ctx := context.Background()
	oncall := r.as(t, "operator:oncall")

	// NON-VACUITY, AND THE GUARD THAT MAKES THE LOOP WORTH LOOPING. A verb the
	// registry knows and this step cannot drive is a verb whose repeat rule
	// nothing checks.
	for _, name := range verb.Names() {
		if _, ok := verbRefs[name]; !ok {
			t.Errorf("the registry declares %s and this step has no ref to drive it against, "+
				"so its repeat rule is unproven. Add a grant for operator:oncall in "+
				"acceptance.yaml and an entry to verbRefs — D165 exists so the rule is not "+
				"left to whoever writes the next verb", name)
		}
	}
	if len(verb.Names()) < 6 {
		t.Fatalf("only %d verbs enumerated; the registry is not being read", len(verb.Names()))
	}

	// --- the caller's BELIEF is wrong: refused --------------------------------
	t.Run("a call whose precondition is false is refused, and says what there is nothing of",
		func(t *testing.T) {
			var driven int
			for _, name := range verb.Names() {
				spec, _ := verb.Lookup(name)
				if spec.Repeat != verb.RepeatRefuse {
					continue
				}
				driven++

				resp, err := oncall.Execute(ctx,
					execute(name, verbRefs[name], map[string]any{"reason": "step 20"}))
				// A RESULT, NOT AN ERROR (D135). A deliberate refusal reaches the
				// caller the way a policy denial does.
				if err != nil {
					t.Errorf("%s arrived as a transport error (%v); a deliberate refusal is "+
						"a result carrying a decision id", name, err)
					continue
				}
				got := resp.GetResult()
				if got.GetStatus() != sekizuiv1.Status_STATUS_INVALID_ARGUMENT {
					t.Errorf("%s on an untouched ref returned %v, want INVALID_ARGUMENT: %s",
						name, got.GetStatus(), got.GetReason())
				}
				// DERIVED FROM THE REGISTRY, so the assertion cannot drift from
				// the sentence the code composes.
				for _, want := range []string{"is not " + spec.State, "nothing to " + spec.Does} {
					if !strings.Contains(got.GetReason(), want) {
						t.Errorf("%s's refusal does not say %q:\n  %s", name, want, got.GetReason())
					}
				}
				if got.GetDecisionId() == "" {
					t.Errorf("%s's refusal names no decision id, so nothing joins it to the "+
						"row that explains it", name)
				}
			}
			if driven < 2 {
				t.Errorf("drove %d refusing verbs, want at least 2 (restore_target, "+
					"reinstate_grant)", driven)
			}
		})

	// --- the caller's GOAL is already met: confirmed --------------------------
	t.Run("a repeat whose postcondition is met is confirmed, naming who and when",
		func(t *testing.T) {
			var driven int
			for _, name := range verb.Names() {
				spec, _ := verb.Lookup(name)
				if spec.Repeat != verb.RepeatConfirm {
					continue
				}
				driven++
				ref := verbRefs[name]
				args := map[string]any{"reason": "step 20 drives every verb twice"}

				// THE FIRST CALL DOES THE WORK.
				first, err := oncall.Execute(ctx, execute(name, ref, args))
				if err != nil {
					t.Errorf("%s (first call) over the wire: %v", name, err)
					continue
				}
				if s := first.GetResult().GetStatus(); s != sekizuiv1.Status_STATUS_OK {
					t.Errorf("%s (first call) returned %v, want OK: %s",
						name, s, first.GetResult().GetReason())
					continue
				}

				// THE SECOND IS THE STEP.
				second, err := oncall.Execute(ctx, execute(name, ref, args))
				if err != nil {
					t.Errorf("%s (repeat) arrived as a transport error (%v); a confirmation "+
						"is a result, and under stress an error reads as \"it did not work\"",
						name, err)
					continue
				}
				got := second.GetResult()
				if got.GetStatus() != sekizuiv1.Status_STATUS_OK {
					t.Errorf("%s repeated returned %v, want OK. An error at 03:00 sends a "+
						"second on-call engineer after a bigger hammer for a condition "+
						"already handled: %s", name, got.GetStatus(), got.GetReason())
					continue
				}

				reason := got.GetReason()
				if !strings.Contains(reason, "already "+spec.State) {
					t.Errorf("%s's confirmation does not say the ref was already %s:\n  %s",
						name, spec.State, reason)
				}
				// **WHO GOT THERE FIRST, AND WHEN.** The thing an error cannot
				// carry, and the reason D158 chose confirmation over refusal.
				if !strings.Contains(reason, "operator:oncall") {
					t.Errorf("%s's confirmation does not name who got there first:\n  %s",
						name, reason)
				}
				if !rfc3339.MatchString(reason) {
					t.Errorf("%s's confirmation carries no timestamp, so it does not say "+
						"WHEN:\n  %s", name, reason)
				}
				// THE LIFETIME, ASSERTED FROM THE REGISTRY ITSELF — AND THE
				// REGISTRY IS CHECKED FIRST, WHICH SABOTAGE FOUND THE HARD WAY.
				//
				// `strings.Contains(reason, spec.Lifetime)` with an EMPTY
				// `Lifetime` is satisfied by every string there is, so blanking
				// the field left this arm passing while the confirmation stopped
				// saying anything about how long a suspension lasts. Only the
				// registry's own test noticed. **D138's lesson in a new costume:
				// an assertion satisfied by the absence of an answer.**
				if spec.Lifetime == "" {
					t.Errorf("%s confirms a repeat and declares no Lifetime, so its "+
						"confirmation cannot say how long the effect lasts — and a "+
						"`Contains` against an empty string would pass here regardless",
						name)
				} else if !strings.Contains(reason, spec.Lifetime) {
					t.Errorf("%s's confirmation does not state how long the effect lasts. "+
						"D158 requires it because a bare acknowledgement implies a permanence "+
						"a suspension does not have:\n  want: %s\n  got:  %s",
						name, spec.Lifetime, reason)
				}
			}
			if driven < 4 {
				t.Errorf("drove %d confirming verbs, want at least 4", driven)
			}
		})

	// --- a repeat did no work, and the record says so ------------------------
	//
	// THE PAIR TO STEP 21, and the reason both exist. A confirmation must be
	// distinguishable from work in the audit log: zeroes recorded truthfully
	// here, non-zero effects there. A repeat that reported the FIRST call's
	// counts again would make an incident review believe two revocations
	// cancelled two sets of calls.
	t.Run("a confirmed repeat records zeroes truthfully", func(t *testing.T) {
		records := readLog(t, r.path)
		var checked int
		for _, rec := range records {
			rev := rec.GetRevocation()
			if rev == nil || !strings.Contains(rec.GetReason(), "already withdrawn") {
				continue
			}
			checked++
			if rev.GetCancelledInFlight() != 0 || rev.GetEvicted() != 0 || rev.GetTornDown() != 0 {
				t.Errorf("a confirmed repeat of %s recorded cancelled=%d evicted=%d "+
					"torn_down=%d; nothing was left to act on, and a row claiming otherwise "+
					"makes a repeat indistinguishable from work",
					rec.GetAction(), rev.GetCancelledInFlight(), rev.GetEvicted(),
					rev.GetTornDown())
			}
		}
		if checked == 0 {
			t.Error("no confirmed withdrawal repeat reached the audit log, so this arm " +
				"asserted nothing")
		}
	})
}

// step21EscalationIsNotARepeat is the hazard D158 names and the dangerous half
// of the registry.
//
// **AN OPERATOR ESCALATING AN ALREADY-QUARANTINED TARGET TO A FULL REVOCATION
// HAS DECIDED IT IS COMPROMISED RATHER THAN MISBEHAVING.** Swallowing that as
// "already withdrawn" would leave calls running with a credential just declared
// unsafe — a far worse bug than the one confirmation fixes, and it would report
// STATUS_OK while doing nothing.
//
// **ASSERTED ON THE EFFECT, NOT ON THE STATUS**, which is the step's own reason
// for existing: a confirmation and an escalation both return OK, so a status
// check would pass against a system that swallowed the revocation entirely. The
// audit row's cancellation count is the only place the difference is visible —
// and it cannot be reconstructed later by anybody, which is why D106 records it
// at the instant it happens.
func step21EscalationIsNotARepeat(t *testing.T) {
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	if r.localOnly(t, "it reads this process's audit log for the cancellation count") {
		return
	}

	ctx := context.Background()
	oncall := r.as(t, "operator:oncall")

	// A REAL COMMAND IN FLIGHT, so there is something for the escalation to
	// cancel. Without it the counts are vacuously zero and the arm passes
	// against a system that swallowed the revocation — the same trap
	// CONTRACTS 35 caught in the revocation path itself.
	slow := make(chan sekizuiv1.Status, 1)
	go func() {
		resp, _ := r.as(t, "agent:binding").Execute(ctx,
			execute("kata.create_issue", "kata:alpha", map[string]any{
				"project":       "PROJ",
				kata.LatencyKey: "30s",
			}))
		slow <- resp.GetResult().GetStatus()
	}()
	waitFor(t, func() bool { return r.pool.InFlight("kata:alpha") > 0 },
		"no command reached the pool for kata:alpha, so the escalation below would "+
			"cancel nothing and this step would pass vacuously")

	// 1. QUARANTINE. The milder severity: stop resolving, and let calls already
	//    in flight finish. That is the difference that makes the two severities
	//    two, and it is why the in-flight command is still running below.
	quarantine, err := oncall.Execute(ctx, execute(verb.QuarantineTarget, "kata:alpha", nil))
	if err != nil {
		t.Fatalf("quarantine_target over the wire: %v", err)
	}
	if s := quarantine.GetResult().GetStatus(); s != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("quarantine_target returned %v, want OK: %s", s,
			quarantine.GetResult().GetReason())
	}
	if r.pool.InFlight("kata:alpha") == 0 {
		t.Fatal("the in-flight command was gone after a QUARANTINE, which is supposed to " +
			"let it finish. There is then nothing left for the escalation to cancel and " +
			"the assertion below would be vacuous")
	}

	// 2. ESCALATE to a full revocation of the same target.
	escalate, err := oncall.Execute(ctx, execute(verb.RevokeCredential, "kata:alpha", nil))
	if err != nil {
		t.Fatalf("revoke_credential (escalation) over the wire: %v", err)
	}
	got := escalate.GetResult()
	if got.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("the escalation returned %v, want OK: %s", got.GetStatus(), got.GetReason())
	}

	// **THE ASSERTION THAT MATTERS.** A swallowed escalation returns exactly
	// this status with exactly this shape, and differs only here.
	if strings.Contains(got.GetReason(), "already withdrawn") {
		t.Fatalf("the escalation was answered as a repeat: %q. An operator who has decided "+
			"a credential is compromised was told it was handled, and the calls using it "+
			"kept running", got.GetReason())
	}

	// The in-flight command must have been cancelled, which a quarantine would
	// not have done.
	select {
	case status := <-slow:
		if status != sekizuiv1.Status_STATUS_DENIED {
			t.Errorf("the in-flight command returned %v after its credential was revoked "+
				"by escalation, want DENIED", status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight command never returned after the escalation, so the " +
			"revocation reported success and cancelled nothing")
	}

	records := readLog(t, r.path)
	var rec *sekizuiv1.Decision
	for _, d := range records {
		if d.GetId() == got.GetDecisionId() {
			rec = d
		}
	}
	if rec == nil {
		t.Fatalf("no audit record for the escalation's decision id %q", got.GetDecisionId())
	}
	rev := rec.GetRevocation()
	if rev == nil {
		t.Fatal("the escalation's record carries no Revocation, so nothing says what it did")
	}
	// **THE ANZEN VERB, NOT A SHORTHAND.** The proto records this "matching the
	// anzen verb exactly" so a query joins to the vocabulary rather than to an
	// enum kept in step with it — and the first draft of this assertion wanted
	// "revoke", which is the shorthand nothing writes.
	if rev.GetSeverity() != "revoke_credential" {
		t.Errorf("the escalation recorded severity %q, want revoke_credential — the row must "+
			"say which of the two ran, or a review cannot tell an escalation from the "+
			"quarantine it replaced", rev.GetSeverity())
	}
	// NON-ZERO IS THE WHOLE STEP: the escalation ACTED.
	if acted := rev.GetCancelledInFlight() + rev.GetEvicted() + rev.GetTornDown(); acted == 0 {
		t.Errorf("the escalation recorded cancelled=%d evicted=%d torn_down=%d — all zero, "+
			"so it was confirmed as a repeat while an operator believed a compromised "+
			"credential had been withdrawn",
			rev.GetCancelledInFlight(), rev.GetEvicted(), rev.GetTornDown())
	}
}
