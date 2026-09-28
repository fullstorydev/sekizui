package acceptance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step47AnzenObservesDecisionsButNotTheDataBus proves D121's boundary.
//
// The distinction is what makes the class trustworthy: **an anzen rule that could
// consume business events would be a reflex wearing a different name.** Decisions
// are Sekizui's OWN signals, so observing them is within anzen's charter;
// business events are not, and a rule that could reach them would have a reflex's
// blast radius with anzen's privileges — which is the one combination the split
// exists to prevent.
func step47AnzenObservesDecisionsButNotTheDataBus(t *testing.T) {
	// A rule watching a BUS SUBJECT rather than an internal signal.
	doc := &config.Document{
		Stages: []string{"raw", "enriched"},
		Anzen: []config.AnzenSpec{{
			Name: "sneaky", Enabled: true, Mode: "enforce",
			Watches: "sekizui.enriched.fullstory.rage_click",
			Do:      "revoke_credential", Subject: "kata:alpha",
		}},
	}

	err := doc.Validate()
	if err == nil {
		t.Fatal("an anzen rule watching a bus subject was accepted. That rule has a " +
			"reflex's reach and anzen's privileges, which is the one combination the " +
			"preventive/reactive split exists to prevent")
	}
	// THE CLOSED SET IS NAMED, so an operator learns what anzen CAN watch rather
	// than only that this is not it.
	if !strings.Contains(err.Error(), "credential_stale") {
		t.Errorf("the refusal does not name the signals anzen may watch: %v", err)
	}
}

// step49TheAnzenNamespaceIsReservedAndCarried proves D122 — and this step exists
// because building D157's dispatcher got it wrong first.
//
// The first version acted as a single `anzen:dispatcher` principal and assumed an
// operator would grant it "may fire credential-compromise". D122 rules that out
// twice: the namespace is refused to configuration, so no such grant can exist,
// and anzen's authority is meant to come from its closed vocabulary because a
// grant "would misstate where the power comes from and would let arbitrary
// capabilities be attached to something an audit log reads as anzen".
func step49TheAnzenNamespaceIsReservedAndCarried(t *testing.T) {
	ctx := context.Background()

	// --- 49a: A GRANT NAMING AN anzen: PRINCIPAL IS REFUSED AT BOOT ------
	t.Run("configuration cannot mint an anzen principal", func(t *testing.T) {
		doc := &config.Document{
			Grants: []config.GrantSpec{{
				Principal: "anzen:credential-compromise",
				Allow: []config.CapabilitySpec{{
					Action: "kata.create_issue", TargetRef: "kata:alpha",
				}},
			}},
		}
		err := doc.Validate()
		if err == nil {
			t.Fatal("a grant naming an anzen: principal was accepted. That is what makes " +
				"D121's recursion guard structural: anzen ignores decisions whose subject " +
				"is in the namespace, and the guard is only sound while nothing ELSE can " +
				"produce such a record")
		}
		if !strings.Contains(err.Error(), "reserved") {
			t.Errorf("the refusal does not say the namespace is reserved: %v", err)
		}
	})

	// --- 49b: AN ANZEN SUBJECT MAY FIRE ITS OWN RULE --------------------
	//
	// The authority D122 declares and nothing implemented until now. Without it
	// a dispatched action is denied for lacking a permission it was never
	// allowed to hold.
	//
	// THE FULL HARNESS, because firing a rule WITHDRAWS from a pool. The first
	// version used a pool-less fixture and got
	// "this instance has no client pool, so sekizui.fire_anzen has nothing to
	// withdraw from and cannot honestly report success" — which was the
	// authorisation succeeding and the withdrawal correctly refusing to claim an
	// effect it could not have. A pleasant way to find out the honesty check
	// works.
	//nolint:contextcheck // harness manages its own lifecycle via *testing.T
	r := newRun(t)
	if r.localOnly(t, "firing withdraws from this process's pool") {
		return
	}

	const rule = "credential-compromise"
	res, err := r.srv.Enforce(ctx, anzenSubject("anzen:"+rule), &sekizuiv1.Command{
		Action: "sekizui.fire_anzen", TargetRef: "anzen:" + rule,
	})
	if err != nil {
		t.Fatalf("firing arrived as a transport error: %v", err)
	}
	if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("an anzen subject could not fire its OWN rule: %s. D122 says its "+
			"authority is the closed vocabulary rather than a grant, and a grant is "+
			"impossible because the namespace is reserved — so denying this leaves the "+
			"rule unable to fire at all", res.GetReason())
	}

	// --- 49c: AND NOTHING ELSE -------------------------------------------
	//
	// THE ARM THAT BOUNDS THE AUTHORITY. Anything wider would attach arbitrary
	// capability to something an audit log reads as anzen, which is precisely
	// the misstatement the reservation exists to prevent.
	for _, c := range []struct {
		name   string
		action string
		target string
	}{
		{"acting on a target", "kata.create_issue", "kata:alpha"},
		{"firing a DIFFERENT rule", "sekizui.fire_anzen", "anzen:some-other-rule"},
		{"restoring a target", "sekizui.restore_target", "kata:alpha"},

		// **ADDED BY THE MUTATION AUDIT.** Deleting the ACTION check survived,
		// because every case above also fails the TARGET check — so the two
		// layers were indistinguishable and either could have been removed
		// unnoticed. This case has target_ref EQUAL to the subject, so only the
		// action check can refuse it. Defence in depth is only worth having if
		// each layer is known to work.
		{"another verb on its OWN rule", "sekizui.quarantine_target", "anzen:" + rule},
	} {
		t.Run(c.name+" is refused", func(t *testing.T) {
			out, err := r.srv.Enforce(ctx, anzenSubject("anzen:"+rule), &sekizuiv1.Command{
				Action: c.action, TargetRef: c.target,
				IdempotencyKey: "acc-49-" + c.action,
			})
			if err == nil && out.GetStatus() == sekizuiv1.Status_STATUS_OK {
				t.Errorf("an anzen subject was permitted to %s. Its vocabulary contains "+
					"exactly one thing it may do", c.name)
			}
		})
	}
}

// anzenSubject builds the identity the reactive dispatcher synthesises (D122).
func anzenSubject(principal string) *sekizuiv1.Identity {
	return &sekizuiv1.Identity{
		Caller: &sekizuiv1.Caller{
			Principal:    principal,
			Method:       sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL,
			CredentialId: "anzen:reactive-dispatcher",
		},
		Subject: &sekizuiv1.Subject{
			Principal: principal,
			Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED,
		},
		Chain: []string{principal},
	}
}
