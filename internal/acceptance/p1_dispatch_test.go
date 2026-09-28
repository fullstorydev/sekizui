package acceptance

import (
	"context"
	"errors"
	"testing"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/pkg/config"
)

// staleWatchers is a rule set watching `credential_stale`: one enforcing, one in
// shadow mode, and one watching something else.
func staleWatchers() []config.AnzenSpec {
	return []config.AnzenSpec{
		{
			// `mode: enforce` EXPLICITLY. An empty mode means SHADOW everywhere
			// in anzen (§4.11.4 item 3), because a defensive rule that fires
			// wrongly disables working automation — so the safe value is the
			// default. The first version of this fixture omitted it and nothing
			// fired, which is the design working on the test that forgot it.
			Name: "credential-compromise", Enabled: true, Mode: "enforce",
			Watches: "credential_stale", Do: "revoke_credential", Subject: "kata:alpha",
		},
		{
			Name: "credential-compromise-shadow", Enabled: true, Mode: "shadow",
			Watches: "credential_stale", Do: "revoke_credential", Subject: "kata:beta",
		},
		{
			Name: "storm", Enabled: true, Mode: "enforce",
			Watches: "denial_storm", Do: "quarantine_target", Subject: "kata:gamma",
		},
	}
}

// step32AnAnzenRuleWatchingCredentialStaleCanFire proves D109's loop closes, and
// lays the skeleton D65's reactive form has been missing (D157).
//
// **D99 LEAVES THE GAP, D109 DETECTS IT, D106 REPAIRS IT** — and until now the
// middle link was the only one built. `credential_stale` was in anzen's closed
// signal vocabulary, boot validated a rule watching it, and nothing in the
// process could fire: the compiled `Reactive` rule dropped the `Watches` field
// entirely, so a rule could declare what it watched, be checked for declaring it
// correctly, and be unfindable by anything that wanted to act on it.
//
// A SKELETON ON PURPOSE, following D91's precedent with the bus: the ROUTING is
// real and governed now, and P5 adds the other signals and the policy — windows,
// debounce, thresholds — around them.
func step32AnAnzenRuleWatchingCredentialStaleCanFire(t *testing.T) {
	ctx := context.Background()
	guards := anzen.New(staleWatchers())

	// --- 32a: THE RULE IS FINDABLE BY THE SIGNAL IT WATCHES --------------
	//
	// First, because it is what was actually broken. Everything else is built on
	// being able to answer "who watches this?"
	watchers := guards.WatchersOf("credential_stale")
	if len(watchers) != 2 {
		t.Fatalf("WatchersOf(credential_stale) = %d rules, want 2 (one enforcing, one "+
			"shadow). The compiled rule used to DROP `watches`, so a validated "+
			"declaration was unfindable by anything that wanted to act on it", len(watchers))
	}

	// --- 32b: FIRING GOES THROUGH THE GOVERNED PATH ---------------------
	//
	// **THE LOAD-BEARING ASSERTION, AND IT IS ABOUT D18.** The dispatcher does
	// not revoke anything: it names a rule and hands it to the same path a human
	// uses with `sekizui.fire_anzen`. A dispatcher that revoked directly would be
	// a second enforcement path — unauthorised by any grant, unrecorded, outside
	// the hash chain — which is exactly what D18 forbids and exactly what D155
	// found had already happened once.
	var fired []string
	d := anzen.NewDispatcher(guards, func(_ context.Context, rule string) error {
		fired = append(fired, rule)
		return nil
	}, quietLogger())

	got := d.Observe(ctx, "credential_stale", map[string]string{"kata:alpha": "1 entry draining past max_lifetime"})
	if len(got) != 1 || got[0] != "credential-compromise" {
		t.Errorf("fired = %v, want just credential-compromise", got)
	}
	if len(fired) != 1 || fired[0] != "credential-compromise" {
		t.Errorf("the governed path was asked to run %v, want one rule NAMED — the "+
			"dispatcher must hand over a rule name, not an action, so the rule supplies "+
			"both subject and severity (D134)", fired)
	}

	// --- 32c: A SHADOW RULE DOES NOT FIRE -------------------------------
	//
	// Shadow mode exists so an operator can watch what a rule WOULD do for a week
	// before trusting it. A shadow rule that acted would make the mode
	// meaningless — the same reason `fire_anzen` refuses a shadow rule when a
	// human names one.
	for _, name := range got {
		if name == "credential-compromise-shadow" {
			t.Error("a SHADOW rule fired. An observation somebody can discharge on " +
				"demand is not an observation")
		}
	}

	// --- 32d: A RULE WATCHING A DIFFERENT SIGNAL DOES NOT FIRE ----------
	//
	// Non-vacuity for the routing. Without it, 32b passes against a dispatcher
	// that fires every reactive rule it has.
	for _, name := range got {
		if name == "storm" {
			t.Error("a rule watching denial_storm fired on credential_stale; the " +
				"dispatcher is not routing by signal at all")
		}
	}

	// --- 32e: A REFUSED FIRING DOES NOT STOP THE OTHERS ----------------
	//
	// These are independent protective responses. One that cannot fire — no
	// grant, a target already withdrawn — is not a reason to withhold the rest,
	// and the enforcement path has already recorded why it refused.
	t.Run("one rule failing does not silence the others", func(t *testing.T) {
		two := anzen.New(append(staleWatchers(), config.AnzenSpec{
			Name: "second-responder", Enabled: true, Mode: "enforce",
			Watches: "credential_stale", Do: "quarantine_target", Subject: "kata:delta",
		}))
		var reached []string
		dd := anzen.NewDispatcher(two, func(_ context.Context, rule string) error {
			reached = append(reached, rule)
			if rule == "credential-compromise" {
				return errors.New("no grant for this")
			}
			return nil
		}, quietLogger())

		out := dd.Observe(ctx, "credential_stale", map[string]string{"kata:alpha": "x", "kata:delta": "y"})
		if len(reached) != 2 {
			t.Errorf("the dispatcher stopped after a failure: reached %v", reached)
		}
		if len(out) != 1 || out[0] != "second-responder" {
			t.Errorf("fired = %v; a rule that could not fire must not be reported as "+
				"having fired", out)
		}
	})

	// --- 32e2: AUTOMATIC FIRING IS OPT-IN TWICE ------------------------
	//
	// A rule with no `mode` is SHADOW, which is anzen's default everywhere
	// (§4.11.4 item 3): a defensive rule that fires wrongly disables working
	// automation, so the safe value is the one you get by not deciding. Combined
	// with the grant the dispatcher's principal needs to fire at all, automatic
	// revocation requires an operator to say yes in two separate places — which
	// is the right shape for a mechanism that revokes credentials with no human
	// in the loop.
	t.Run("a rule with no mode does not fire", func(t *testing.T) {
		defaulted := anzen.New([]config.AnzenSpec{{
			Name: "unmoded", Enabled: true,
			Watches: "credential_stale", Do: "revoke_credential", Subject: "kata:alpha",
		}})
		dd := anzen.NewDispatcher(defaulted, func(context.Context, string) error {
			return nil
		}, quietLogger())

		if out := dd.Observe(ctx, "credential_stale", map[string]string{"kata:alpha": "x"}); len(out) != 0 {
			t.Errorf("fired = %v for a rule that never said `mode: enforce`", out)
		}
	})

	// --- 32e3: THE EDGE LATCH — one condition, one response (D158) ------
	//
	// **THE FLOOD THIS PREVENTS.** `credential_stale` is a LEVEL: it stays
	// non-zero for as long as a drain is stuck. Firing on the level fires every
	// time anybody looks — a revocation attempt per tick, per replica, for as
	// long as the condition lasts, each one individually correct. Firing on the
	// RISING EDGE turns one condition into one response.
	//
	// This is where flood protection belongs. Doing it with a status code would
	// have made a machine's rate control into an error message a human reads at
	// 03:00, which is the trade CONTRACTS item 57 settled.
	t.Run("a level that stays raised fires once", func(t *testing.T) {
		var count int
		dd := anzen.NewDispatcher(guards, func(context.Context, string) error {
			count++
			return nil
		}, quietLogger())

		for range 5 {
			dd.Observe(ctx, "credential_stale", map[string]string{"kata:alpha": "still stuck"})
		}
		if count != 1 {
			t.Errorf("fired %d times for one continuous condition, want 1. A stuck drain "+
				"lasts minutes; firing per observation is a revocation storm on a "+
				"target that is already withdrawn", count)
		}

		// AND IT RE-ARMS. A latch that never releases turns the first incident
		// into permanent deafness — the failure mode is silence, which is worse
		// than the flood because nobody notices it.
		dd.Observe(ctx, "credential_stale", nil)
		dd.Observe(ctx, "credential_stale", map[string]string{"kata:alpha": "stuck again"})
		if count != 2 {
			t.Errorf("fired %d times after the signal cleared and rose again, want 2. A "+
				"latch that does not release makes the second incident silent", count)
		}
	})

	// --- 32g: A RULE FIRES ONLY FOR ITS OWN SUBJECT (D158) -------------
	//
	// **THE ATTACK THIS CLOSES.** A rule acts on the target IT names (D134: the
	// operator pre-decides, so nobody composes a subject at 03:00). The first
	// version of the dispatcher fired every watcher whenever the signal rose for
	// ANY subject — so one target's stuck drain would fire a rule scoped to a
	// different, healthy target and revoke it.
	//
	// That is attacker-reachable: make one drain stick, and the compliance layer
	// withdraws something else. D150's class exactly — the mechanism becoming the
	// weapon — and it was reachable in P1 without any of D148's peer machinery.
	t.Run("a stuck target does not fire a rule scoped to another", func(t *testing.T) {
		var fired []string
		dd := anzen.NewDispatcher(guards, func(_ context.Context, rule string) error {
			fired = append(fired, rule)
			return nil
		}, quietLogger())

		// `credential-compromise` is scoped to kata:alpha. Something ELSE is stuck.
		dd.Observe(ctx, "credential_stale", map[string]string{
			"kata:somewhere-else": "stuck",
		})
		if len(fired) != 0 {
			t.Errorf("fired %v because an UNRELATED target was stale. A rule that "+
				"revokes its own subject on somebody else's condition is a "+
				"denial-of-service anybody who can stick one drain can trigger", fired)
		}

		// NON-VACUITY: it fires for its own subject.
		dd.Observe(ctx, "credential_stale", map[string]string{"kata:alpha": "stuck"})
		if len(fired) != 1 || fired[0] != "credential-compromise" {
			t.Errorf("fired = %v for its OWN subject, want credential-compromise", fired)
		}
	})

	// --- 32h: ONE STUCK TARGET DOES NOT MASK ANOTHER ------------------
	//
	// The latch's own failure mode, and the reason it is keyed on the SUBJECT
	// rather than the signal name. Keyed on the signal alone, a target stuck
	// indefinitely holds the level raised — so a second target going stale
	// produces no edge and gets no response at all, and the rate limit becomes a
	// silence. That is the worse failure, because nobody notices it.
	t.Run("a rule still fires while another subject stays stuck", func(t *testing.T) {
		two := anzen.New(append(staleWatchers(), config.AnzenSpec{
			Name: "second-target", Enabled: true, Mode: "enforce",
			Watches: "credential_stale", Do: "quarantine_target", Subject: "kata:delta",
		}))
		var fired []string
		dd := anzen.NewDispatcher(two, func(_ context.Context, rule string) error {
			fired = append(fired, rule)
			return nil
		}, quietLogger())

		// kata:alpha sticks and stays stuck across several observations.
		for range 3 {
			dd.Observe(ctx, "credential_stale", map[string]string{"kata:alpha": "stuck"})
		}
		if len(fired) != 1 {
			t.Fatalf("fired %v for one continuous condition, want one response", fired)
		}

		// Now kata:delta sticks TOO, while kata:alpha is still stuck.
		dd.Observe(ctx, "credential_stale", map[string]string{
			"kata:alpha": "still stuck", "kata:delta": "newly stuck",
		})
		if len(fired) != 2 || fired[1] != "second-target" {
			t.Errorf("fired = %v; a second target going stale while the first is still "+
				"stuck got no response. A latch keyed on the signal alone lets one "+
				"unresolved condition silence every other", fired)
		}
	})

	// --- 32f: NO FIRER MEANS NO AUTOMATIC ACTION -----------------------
	//
	// The default direction. A deployment that has not wired automatic firing
	// gets none, rather than a dispatcher routing into nothing and reporting
	// success — which would be a loop that looks closed and is not.
	t.Run("without a firer nothing fires", func(t *testing.T) {
		if out := anzen.NewDispatcher(guards, nil, quietLogger()).
			Observe(ctx, "credential_stale", map[string]string{"kata:alpha": "x"}); len(out) != 0 {
			t.Errorf("fired = %v with no firer configured", out)
		}
	})
}
