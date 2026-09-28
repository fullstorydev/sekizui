// Package churn counts forced credential re-establishments per target, in a
// window, so the condition can be published as a LEVEL (D203, D204).
//
// **THE SIGNAL IS AN EVENT AND THE DISPATCHER TAKES LEVELS, WHICH IS WHY THIS
// PACKAGE EXISTS.** `anzen.Dispatcher.Observe` fires on a rising edge and
// re-arms on a fall, and its own doc is explicit that what it watches are
// levels: `credential_stale` is *"a count that stays non-zero for as long as the
// condition lasts"*. A re-establishment is not that — it is a thing that
// happened once, at an instant. Feeding it to the latch raw gives one of two
// wrong behaviours, and both of them are the numbing an operator least wants:
//
//	raised, never falling   latched forever: fires once, masks every later
//	                        churn. An analgesic.
//	raised then fallen      an edge per re-establishment, so it fires on the
//	                        first LEGITIMATE expiry — D77's crying wolf, which
//	                        D203 forbids in the sentence that introduced the
//	                        signal.
//
// So the level is *"this target has re-established more than once in the
// window"*, which is true while the condition holds and falls when the window
// empties. **THE THRESHOLD LIVES HERE, AT THE SOURCE**, which is where
// `Dispatcher`'s own comment puts it until P5: *"THRESHOLDS ARE THE CALLER'S
// BUSINESS"* — deciding whether a number is worth firing on needs to know what
// the number means.
//
// **WHY MORE THAN ONE RATHER THAN A TUNED NUMBER.** A single re-establishment is
// what a legitimately expired token looks like, and firing on it would quarantine
// a target for working correctly. Two in a window is not an expiry: a freshly
// minted credential was rejected too, or the target is rejecting deliberately.
// The number is not a sensitivity dial — it is "before the shared resources are
// touched enough to matter", the audit WAL and the secret manager's quota being
// the two that turn a per-target attack into a fleet-wide one (CONTRACTS 78).
//
// DESIGN.md references: §4.7.16, §4.11, D77, D109, D157, D158, D203, D204.
package churn

import (
	"fmt"
	"sync"
	"time"
)

// Threshold is how many re-establishments in one window make a target churning.
//
// TWO, and see the package comment: one is an expiry, two is not.
const Threshold = 2

// DefaultWindow is how long a re-establishment counts towards the level.
//
// **LONG ENOUGH THAT TWO EXPIRIES DO NOT COLLIDE, SHORT ENOUGH THAT THE LEVEL
// FALLS.** A credential expiring twice inside fifteen minutes is already
// abnormal — the cache's own TTL is five minutes (`credential.DefaultTTL`) and a
// minted token that dies faster than that is not a working deployment. And the
// window is what re-arms the rule: too long and a quarantine lifted by hand
// re-fires the moment anybody looks.
const DefaultWindow = 15 * time.Minute

// Counter is a windowed per-target tally of forced re-establishments.
//
// SAFE FOR CONCURRENT USE: the enforcement path writes it from every command's
// goroutine and the watcher reads it from a ticker.
type Counter struct {
	window time.Duration
	now    func() time.Time

	mu   sync.Mutex
	seen map[string][]time.Time
}

// New builds a Counter over the default window.
func New(opts ...Option) *Counter {
	c := &Counter{window: DefaultWindow, now: time.Now, seen: map[string][]time.Time{}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Option configures a Counter.
type Option func(*Counter)

// WithClock substitutes the clock, so a test proves the window without waiting.
//
// THE ONLY OPTION, AND THERE IS NO `WithWindow`. A first draft had one and
// `archcheck.TestNoOrphanedExportsInInternal` was right to reject it: nothing in
// production would have called it, because the window is a property of what the
// signal MEANS rather than a deployment preference — see the package comment for
// why fifteen minutes is derived from `credential.DefaultTTL` rather than
// chosen. A knob nobody turns is a third way to say what the file already says
// once (D144's objection to configuration nobody needs), and it would have to
// be validated, bounded and documented before anyone could use it safely.
// D157 moves thresholds into the rule at P5; until then they belong here, fixed.
func WithClock(now func() time.Time) Option {
	return func(c *Counter) {
		if now != nil {
			c.now = now
		}
	}
}

// Record notes one forced re-establishment against a target.
//
// CALLED FROM THE RE-ESTABLISHMENT LOOP AND NOWHERE ELSE, beside the invalidation
// it accompanies — the two are the same fact and separating them is how one of
// them comes to be forgotten.
func (c *Counter) Record(targetRef string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	c.seen[targetRef] = append(c.trim(c.seen[targetRef], now), now)
}

// Churning reports the LEVEL: every target at or over the threshold, with a
// human-readable detail, in the shape `anzen.Dispatcher.Observe` takes.
//
// **KEYED BY TARGET, NOT A SINGLE BOOLEAN**, for the reason `staleWatcher`
// records: a rule acts on the target IT names (D134), so one target's churn must
// not fire a rule scoped to a different, healthy one. That mistake is
// attacker-reachable — make one target churn and the compliance layer withdraws
// something else — which is D150's class exactly.
//
// PRUNES AS IT READS, so a target that stops churning falls out of the map and
// the dispatcher's latch re-arms. A read that did not prune would hold the level
// raised forever, which is the first of the two failures this package exists to
// avoid.
func (c *Counter) Churning() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	out := map[string]string{}
	for ref, at := range c.seen {
		kept := c.trim(at, now)
		if len(kept) == 0 {
			// FORGOTTEN ENTIRELY rather than kept as an empty slice: the map is
			// keyed by a caller-influenced target ref, and a map that only ever
			// grows is a slow leak on the enforcement path's own process.
			delete(c.seen, ref)
			continue
		}
		c.seen[ref] = kept
		if len(kept) < Threshold {
			continue
		}
		out[ref] = fmt.Sprintf(
			"%s forced %d credential re-establishments in %s; either it is holding a "+
				"broken credential or it is making us churn against the secret manager",
			ref, len(kept), c.window)
	}
	return out
}

// trim drops entries that have fallen out of the window. Callers hold mu.
func (c *Counter) trim(at []time.Time, now time.Time) []time.Time {
	cut := now.Add(-c.window)
	kept := at[:0]
	for _, t := range at {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	return kept
}
