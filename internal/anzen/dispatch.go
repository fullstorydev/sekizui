package anzen

import (
	"context"
	"log/slog"
	"sort"
	"sync"
)

// Dispatcher routes an internal signal to the reactive rules that watch it
// (D65, D109).
//
// **A SKELETON, DELIBERATELY, AND THIS IS WHAT THAT MEANS.** The bus landed the
// same way in P0 (D91) — authorised, audited, lensed delivery over an in-process
// transport, with P3 adding the ingress that fills it. The shape here is the
// same: the ROUTING is real and governed, and P5 adds the signals and the policy
// around them. What P1 lays is a path a signal can travel end to end, so the
// thing P5 builds is a bigger version of something that works rather than the
// first version of something that does not.
//
// P1 CARRIES EXACTLY ONE SIGNAL, `credential_stale`, because P1 is the phase that
// produces it (D109). A signal published in one phase and consumed in another is
// the mismatch that made this necessary: the vocabulary already listed
// `credential_stale`, boot already validated a rule watching it, and nothing
// could ever have fired.
//
// **THRESHOLDS ARE THE CALLER'S BUSINESS UNTIL P5**, and that is a real seam
// rather than an omission. D109 says the AGE distinguishes a rotation in progress
// from a drain that is stuck, and those want opposite responses — so deciding
// "this is worth firing on" needs to know what the number means, which the
// dispatcher does not and the signal's source does. P5 moves thresholds, windows
// and debounce into the rule, where a config author can see them.
//
// DESIGN.md references: §4.11, D18, D65, D91, D106, D109, D134.
type Dispatcher struct {
	guards *Guards

	// mu guards raised, which is the edge latch's whole state.
	mu sync.Mutex

	// raised is each (signal, subject, RULE) triple's last observed level.
	//
	// **KEYED ON THE SUBJECT TOO, and the first version was not.** Keyed on the
	// signal alone, one stuck target kept the level raised, so a SECOND target
	// going stale produced no edge and got no response at all — the latch
	// masking the condition it exists to rate-limit. One target's problem must
	// not silence another's.
	//
	// **AND KEYED ON THE RULE, WHICH THE SECOND VERSION WAS NOT — D225.** The
	// same argument applies one level further and the omission was worse, because
	// it made SHADOW MODE INTO AN OFF SWITCH. Two rules watching one signal for
	// one subject shared a latch entry, so whichever the sort reached first set
	// it and every other rule saw "already raised" and skipped. With a shadow
	// rule sorting before an enforcing one, adding an OBSERVATION silently
	// disabled the control it was added to observe — and nothing logged that it
	// had. An operator doing exactly what §4.11.4 item 3 recommends turned a
	// ceiling off.
	//
	// Each rule now latches independently, which is what "one condition, one
	// response" meant all along: one response PER RULE, not one in total.
	//
	// PER INSTANCE, deliberately:
	// a fleet responding once per replica is N actions for one condition, which
	// is bounded and auditable, where sharing the latch would make one replica's
	// response silence another's — and D155 is the reminder that a control which
	// only works when replicas agree is a control that stops working when they
	// cannot reach each other.
	raised map[string]bool

	// fire runs one rule's action THROUGH THE GOVERNED PATH.
	//
	// A CALLBACK RATHER THAN A DIRECT CALL, and D18 is the whole reason: "No
	// second code path, no hole in the audit log." A dispatcher that revoked a
	// credential itself would be a second enforcement path — unauthorised by any
	// grant, unrecorded by the recorder, outside the hash chain. Instead it does
	// what a human does with `sekizui.fire_anzen`: names the rule and lets the
	// one enforcement path decide, record and act.
	//
	// The consequence is that **automatic firing must be GRANTED**, per rule, to
	// whatever principal the dispatcher acts as. "May fire credential-compromise"
	// is a reviewable sentence, and an operator who has not written it gets no
	// automatic action — which is the right default for a mechanism that revokes
	// credentials without a human.
	fire Firer

	log *slog.Logger
}

// Firer runs the action of one named anzen rule, through the enforcement path.
type Firer func(ctx context.Context, rule string) error

// NewDispatcher builds a Dispatcher.
func NewDispatcher(g *Guards, fire Firer, log *slog.Logger) *Dispatcher {
	return &Dispatcher{guards: g, fire: fire, log: log, raised: map[string]bool{}}
}

// Observe reports a signal's CURRENT STATE and fires on the rising edge (D158).
//
// **EDGE-TRIGGERED, AND THIS IS THE LATCH.** The signals anzen watches are
// LEVELS — `credential_stale` is a count that stays non-zero for as long as the
// condition lasts — and firing on a level fires every time anybody looks. That is
// the flood: one stuck drain becomes a revocation attempt per tick, per replica,
// for as long as it is stuck, and every one of them is individually correct.
//
// So a rule fires when the signal RISES and not again until it has fallen. One
// condition, one response, per instance. On a fleet that is N actions rather than
// N per tick — and since each is idempotent and now CONFIRMED rather than refused
// (D158), the healthy instances neither flood nor alarm.
//
// **A STATUS CODE WAS THE WRONG INSTRUMENT FOR THIS**, which is what the
// CONTRACTS item 57 discussion settled: refusing a repeat would have made a
// machine's flood protection into an error message a human reads at 03:00.
// Suppression belongs here, where nobody is under stress.
//
// P5 GENERALISES IT into the debounce the reflex engine brings — a window, a
// hysteresis band, and a cap. The edge is the part that has to exist first,
// because without it there is no "again" to debounce.
//
// SHADOW RULES DO NOT FIRE, and are logged instead. Shadow mode exists so an
// operator can watch what a rule WOULD have done for a week before trusting it,
// and a shadow rule that acted would make the mode meaningless — the same rule
// `fire_anzen` applies when a human names a shadow rule.
func (d *Dispatcher) Observe(ctx context.Context, signal string, subjects map[string]string) []string {
	var fired []string

	// EVERY RULE IS ASKED ABOUT ITS OWN SUBJECT, and nothing else.
	//
	// **THE FIRST VERSION FIRED EVERY WATCHER WHENEVER THE SIGNAL ROSE FOR ANY
	// SUBJECT**, and a rule acts on the target IT names (D134: the operator
	// pre-decides, so nobody composes a subject at 03:00). So one target's stuck
	// drain would fire a rule scoped to a different, healthy target and revoke
	// it. That is attacker-reachable — cause one drain to stick, and the
	// compliance layer withdraws something else — which is D150's class exactly:
	// the mechanism becoming the weapon.
	for _, rule := range d.guards.WatchersOf(signal) {
		detail, raisedForRule := subjects[rule.Subject]

		// THE RULE'S NAME IS PART OF THE KEY (D225). Names are unique — `Guards`
		// keys `reactive` by name — so this cannot collide, and two rules
		// watching one subject now get an edge each.
		key := signal + "\x00" + rule.Subject + "\x00" + rule.Name
		d.mu.Lock()
		was := d.raised[key]
		d.raised[key] = raisedForRule
		d.mu.Unlock()

		if !raisedForRule {
			if was {
				// SAID OUT LOUD, because the fall is what re-arms the rule. An
				// operator watching a stuck drain clear needs to know the next
				// occurrence will fire again.
				d.log.Info("anzen signal cleared for this subject; the rule is re-armed",
					"signal", signal, "rule", rule.Name, "subject", rule.Subject)
			}
			continue
		}
		if was {
			// STILL RAISED for this subject. Already responded to; responding
			// again would be the flood the latch exists to prevent.
			continue
		}
		if name := d.fireOne(ctx, signal, rule, detail); name != "" {
			fired = append(fired, name)
		}
	}
	sort.Strings(fired)
	return fired
}

// fireOne runs one rule, once its edge has been decided. Returns the rule's name
// when it fired.
func (d *Dispatcher) fireOne(ctx context.Context, signal string, rule Reactive, detail string) string {
	if d.fire == nil {
		// NO FIRER MEANS NO AUTOMATIC ACTION, and the deployment is told once
		// rather than silently getting a dispatcher that routes into nothing.
		return ""
	}

	{
		if !rule.Enforcing {
			d.log.Warn("anzen rule would have fired (shadow mode)",
				"rule", rule.Name, "signal", signal, "do", rule.Do,
				"subject", rule.Subject, "detail", detail)
			return ""
		}

		d.log.Warn("anzen rule firing on an internal signal",
			"rule", rule.Name, "signal", signal, "do", rule.Do,
			"subject", rule.Subject, "detail", detail)

		if err := d.fire(ctx, rule.Name); err != nil {
			// LOGGED, NOT RETURNED. A rule that could not fire must not stop the
			// next one: these are independent protective responses, and the
			// failure of one is not a reason to withhold the others. The
			// enforcement path has already recorded WHY it refused.
			d.log.Error("an anzen rule could not fire",
				"rule", rule.Name, "signal", signal, "err", err)
			return ""
		}
		return rule.Name
	}
}
