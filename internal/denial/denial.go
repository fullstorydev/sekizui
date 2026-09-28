// Package denial tallies rate-limit refusals so `denial_storm` can name the
// principal causing them (D143, D336, CONTRACTS 65).
//
// **THE CAUSE, NOT ONLY THE VICTIMS.** Under contention the principal refused is
// usually not the one responsible: one agent drains a shared budget and the
// others are turned away. The limiter already names who is over their share on
// each refusal (`limiter.Contended`); this turns a window of such refusals into a
// LEVEL an anzen rule can latch on, keyed by the monopoliser — so a rule acts on
// the agent causing the storm, never on the ones caught in it.
//
// Fed by the gateway's meter, the one place every verb's rate refusal passes;
// read by `denialStormWatcher` in cmd/sekizui, which polls rather than being
// called from the refusal, for mistenantWatcher's reason: the dispatcher fires
// through the enforcement path, and observing from inside it would re-enter it.
package denial

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Tally is a window of rate-limit refusals. Safe for concurrent use.
type Tally struct {
	mu      sync.Mutex
	now     func() time.Time
	refused []refusal
}

type refusal struct {
	at             time.Time
	budget, victim string
	over           []string // who the limiter named over their share, worst first
}

// New builds an empty tally, on the wall clock: the window bounds real refusals
// per real minute, as the budget it describes does.
func New() *Tally { return &Tally{now: time.Now} }

// Record notes one rate-limit refusal of victim on budget, with the principals
// the limiter named over their share at that moment. A refusal naming nobody
// over share is still recorded — it is a victim of an exhausted budget — and
// counts toward no storm, because there is no cause to name.
func (t *Tally) Record(budget, victim string, over []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refused = append(t.refused, refusal{at: t.now(), budget: budget, victim: victim, over: over})
}

// Storms is the signal's current LEVEL: every principal that, within window,
// was named over its share on at least threshold refusals of OTHER principals,
// with a detail naming the budget, the count and the victims. The level FALLS
// when the window empties — contention clears, unlike a mis-bound target — so
// the dispatcher re-arms and a later storm fires again.
func (t *Tally) Storms(window time.Duration, threshold int) map[string]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	cut := t.now().Add(-window)
	kept := t.refused[:0]
	for _, r := range t.refused {
		if r.at.After(cut) {
			kept = append(kept, r)
		}
	}
	t.refused = kept

	type key struct{ monopoliser, budget string }
	victims := map[key]map[string]bool{}
	counts := map[key]int{}
	for _, r := range kept {
		for _, m := range r.over {
			if m == r.victim {
				continue // refused for its OWN excess: not a victim of anyone
			}
			k := key{m, r.budget}
			counts[k]++
			if victims[k] == nil {
				victims[k] = map[string]bool{}
			}
			victims[k][r.victim] = true
		}
	}
	out := map[string]string{}
	for k, n := range counts {
		if n < threshold {
			continue
		}
		names := make([]string, 0, len(victims[k]))
		for v := range victims[k] {
			names = append(names, v)
		}
		sort.Strings(names)
		out[k.monopoliser] = fmt.Sprintf("DENIAL STORM: %s is over its share of budget %q, and %d refusal(s) of "+
			"%s followed in the last %s (D143)", k.monopoliser, k.budget, n, strings.Join(names, ", "), window)
	}
	return out
}
