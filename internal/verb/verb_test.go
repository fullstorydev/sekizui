package verb

import (
	"strings"
	"testing"
	"time"
)

// TestEveryVerbDeclaresItsRepeatRule is what makes D165 a MECHANISM rather than
// a convention.
//
// D158 stated the rule and left its application to whoever wrote the next verb.
// This ranges over the registry, so a verb added at P3 is covered by EXISTING
// rather than by somebody remembering a decision — which is the difference the
// whole package turns on, and the condition that produced CONTRACTS 57 was
// exactly "each author applied their own judgement".
func TestEveryVerbDeclaresItsRepeatRule(t *testing.T) {
	for _, name := range Names() {
		spec, _ := Lookup(name)
		if err := spec.validate(); err != nil {
			t.Errorf("%v", err)
		}
	}
	if len(Names()) < 6 {
		t.Errorf("only %d verbs enumerated; the registry is not being read and this test "+
			"proves nothing", len(Names()))
	}
}

// TestTheWithdrawalFamilySpeaksWithONEVoice.
//
// **THREE VERBS PUT A TARGET INTO THE SAME STATE, so there must be one sentence
// describing it.** `revoke_credential`, `quarantine_target` and a `fire_anzen`
// that delegates to either all end with a withdrawal that D145 makes durable —
// and `gateway.withdraw` looks the spec up by the action AS REWRITTEN, so a
// lever firing `revoke` reads whichever entry the rule named. If the three
// disagreed about `State` or `Lifetime`, the same condition would be described
// two ways depending on which door the operator came through. §15q's defect,
// arriving in prose.
func TestTheWithdrawalFamilySpeaksWithOneVoice(t *testing.T) {
	var first Spec
	var seen int
	for _, name := range Names() {
		spec, _ := Lookup(name)
		if !spec.Withdrawal || spec.Repeat != RepeatConfirm {
			continue
		}
		seen++
		if first.Name == "" {
			first = spec
			continue
		}
		if spec.State != first.State {
			t.Errorf("%s says a withdrawn target is %q and %s says %q", spec.Name,
				spec.State, first.Name, first.State)
		}
		if spec.Lifetime != first.Lifetime {
			t.Errorf("%s and %s describe how long a withdrawal lasts differently:\n  %s\n  %s",
				spec.Name, first.Name, spec.Lifetime, first.Lifetime)
		}
		// **ESCALATION MUST BE UNIFORM ACROSS THE FAMILY**, or a lever escalates
		// where the verb it pulls does not.
		if spec.Escalates != first.Escalates {
			t.Errorf("%s escalates=%v and %s escalates=%v; a fire_anzen delegating to one "+
				"of them would then behave differently from calling it directly",
				spec.Name, spec.Escalates, first.Name, first.Escalates)
		}
	}
	if seen < 3 {
		t.Errorf("found %d confirming withdrawal verbs, want at least 3 "+
			"(revoke_credential, quarantine_target, fire_anzen)", seen)
	}
}

// TestRepeatedIsTheWholeTruthTable drives all four quadrants of D158's rule,
// plus the escalation exception that is the dangerous half.
//
// THE TABLE IS THE POINT. Written as branches across two files, three of the
// four existed and escalation was implemented in one family and absent from the
// other — a shape no test of a single verb can expose, because each verb only
// ever visits two of the four cells.
func TestRepeatedIsTheWholeTruthTable(t *testing.T) {
	at := time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC)
	confirming, _ := Lookup(QuarantineTarget)
	refusing, _ := Lookup(RestoreTarget)

	t.Run("present and confirming is confirmed, naming who and when", func(t *testing.T) {
		resp, decided := Repeated(confirming, "kata:alpha", Prior{
			Present: true, At: at, By: "operator:oncall", Detail: "quarantine",
		})
		if !decided || !resp.Confirm {
			t.Fatalf("a repeat was not confirmed: decided=%v %+v", decided, resp)
		}
		for _, want := range []string{
			"kata:alpha", "already withdrawn", "quarantine",
			"2026-09-10T03:00:00Z", "operator:oncall",
			// THE LIFETIME, which is the arm D158 asks for by name.
			"until an authorised sekizui.restore_target lifts it",
			"confirmation, not a failure",
		} {
			if !strings.Contains(resp.Reason, want) {
				t.Errorf("the confirmation does not say %q:\n  %s", want, resp.Reason)
			}
		}
	})

	t.Run("absent and confirming proceeds", func(t *testing.T) {
		if _, decided := Repeated(confirming, "kata:alpha", Prior{}); decided {
			t.Error("a first withdrawal was answered by the repeat rule instead of doing the work")
		}
	})

	t.Run("absent and refusing is refused, and says what there is nothing of", func(t *testing.T) {
		resp, decided := Repeated(refusing, "kata:alpha", Prior{})
		if !decided || !resp.Refuse {
			t.Fatalf("restoring a healthy target was not refused: decided=%v %+v", decided, resp)
		}
		for _, want := range []string{"is not withdrawn", "nothing to restore"} {
			if !strings.Contains(resp.Reason, want) {
				t.Errorf("the refusal does not say %q:\n  %s", want, resp.Reason)
			}
		}
	})

	t.Run("present and refusing proceeds", func(t *testing.T) {
		if _, decided := Repeated(refusing, "kata:alpha", Prior{Present: true, At: at}); decided {
			t.Error("restoring a withdrawn target was refused as a repeat; that is the call " +
				"that does the work")
		}
	})

	// **THE ARM WITH TEETH.** Escalation is not a repeat: an operator raising a
	// quarantine to a revocation has decided the target is compromised rather
	// than misbehaving, and swallowing it as "already withdrawn" leaves calls
	// running with a credential just declared unsafe.
	t.Run("escalation is not a repeat", func(t *testing.T) {
		if _, decided := Repeated(confirming, "kata:alpha", Prior{
			Present: true, At: at, By: "operator:oncall", Detail: "quarantine",
			Escalating: true,
		}); decided {
			t.Error("quarantine then revoke was confirmed as a repeat, so the revocation " +
				"never happened and the audit row says it was handled")
		}
	})

	// NON-VACUITY ON THE EXCEPTION ITSELF: a verb that does not escalate must
	// confirm even when the runtime reports an escalation, or `Escalates` is
	// doing nothing and the arm above passes for the wrong reason.
	t.Run("a verb with no severity to raise still confirms", func(t *testing.T) {
		suspend, _ := Lookup(RevokeGrant)
		if suspend.Escalates {
			t.Fatal("revoke_grant declares Escalates; a suspension has no severity to raise")
		}
		resp, decided := Repeated(suspend, `"agent:crawler"`, Prior{
			Present: true, At: at, By: "operator:oncall", Escalating: true,
		})
		if !decided || !resp.Confirm {
			t.Fatalf("a repeated suspension was not confirmed: decided=%v %+v", decided, resp)
		}
		if !strings.Contains(resp.Reason, "until this instance is redeployed") {
			t.Errorf("the confirmation does not state D146's lifetime, so an operator can "+
				"read permanence into it and never edit config:\n  %s", resp.Reason)
		}
	})
}
