// Package mistenant tallies failed egress tenant assertions, so
// `tenant_mismatch` can be published as a LEVEL an anzen rule can latch on
// (D226, §6 mechanism 3).
//
// **THE ASSERTION ALREADY EXISTED; THE ESCALATION DID NOT.** `Target.Assert`
// refuses the call and returns an internal fault, which is exactly right and
// stops there. What was missing is the step from ONE refused call to a CONDITION
// — and `tenant_mismatch` has been in the closed signal vocabulary since P0, so
// a rule could watch it, boot would validate it, and it could never fire. That
// is CONTRACTS 65's shape, and it is the entry the init ledger carried.
//
// **NO WINDOW AND NO THRESHOLD, WHICH IS THE DIFFERENCE FROM `internal/churn`.**
// Churn is a RATE: one forced re-establishment is routine and ten in a quarter
// hour is a condition, so it needs both. A tenant mismatch has no normal rate.
// ONE is Sekizui about to put one customer's credential on another customer's
// request — our bug, caught by the last check before the wire — and a threshold
// above one would be a decision to ignore the first occurrence.
//
// **AND THE LEVEL DOES NOT FALL ON ITS OWN, which is a deliberate asymmetry.**
// A drifting target recovers when the vendor's surface matches its vetted spec
// again, so `spec_drift` falls and the rule re-arms. There is no equivalent
// event here: nothing about a later successful call says the defect that
// mis-bound a target is fixed. So the target stays raised for the life of the
// process, the rule fires ONCE for it, and a different target still fires
// because the latch is keyed per (signal, subject, rule) — D225. Re-arming is
// proven on the signal that genuinely recovers rather than faked here.
package mistenant

import (
	"fmt"
	"sync"
)

// Tally is the set of targets whose egress assertion has failed.
//
// SAFE FOR CONCURRENT USE: the enforcement path writes it from every command's
// goroutine and the watcher reads it from a ticker.
type Tally struct {
	mu   sync.Mutex
	seen map[string]int
}

// New returns an empty Tally.
func New() *Tally { return &Tally{seen: map[string]int{}} }

// Record notes one refused egress against a target.
//
// **CALLED WHERE THE FAULT IS CLASSIFIED AND NOWHERE ELSE**, beside the breaker
// decision that reads the same error — the two are judgements about one failure,
// and separating them is how one of them comes to be forgotten.
//
// The COUNT is kept although one occurrence already raises the level, because
// the detail an operator reads should say whether this happened once or is
// happening constantly. It changes nothing about when the rule fires.
func (t *Tally) Record(targetRef string) {
	if targetRef == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seen[targetRef]++
}

// Mistenanted returns the current level: subject -> why.
//
// The shape `anzen.Dispatcher.Observe` takes, and the same shape the drift
// watcher publishes, so the dispatcher meets one kind of thing from every
// producer.
func (t *Tally) Mistenanted() map[string]string {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make(map[string]string, len(t.seen))
	for ref, n := range t.seen {
		out[ref] = fmt.Sprintf(
			"%s refused egress on a TENANT MISMATCH %d time(s): the target is bound "+
				"to one tenant and the request carried another. This is Sekizui's own "+
				"defect caught by the last check before the wire (§6 mechanism 3), not "+
				"the vendor's", ref, n)
	}
	return out
}
