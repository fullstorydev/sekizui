package kyuushin

import (
	"context"
	"sort"
	"time"
)

// State is how a job is going: the three states P3 criterion 15 requires be
// distinguishable, plus the absence that means "we have no record of this".
type State uint8

const (
	// StateUnknown is the ZERO VALUE, and it means "no such job here" rather
	// than "a job in an indeterminate state" — D241's rule that a struct
	// nobody filled in must read as the safe answer. A caller told UNKNOWN
	// learns nothing about whether the id ever existed, which is the property
	// the gateway depends on to avoid being an enumeration oracle.
	StateUnknown State = iota
	StateRunning
	StateFinished
	StateFailed
)

// **THERE IS DELIBERATELY NO `String()` HERE.** I wrote one and `archcheck`
// found it with no caller inside the hour — the same catch D139 records for
// `pkg/provider/ambient`'s unused options. The wire vocabulary is
// `sekizuiv1.JobState`, the gateway maps to it with an exhaustive switch, and
// a second set of Go-side names would be one concept with two spellings for
// no reader. Deleted rather than registered: an allowlist entry for something
// nothing uses is the rot the allowlist exists to prevent.

// Status is everything known about one job.
//
// **`Principal` IS HERE FOR THE GATEWAY TO AUTHORISE WITH, AND IT NEVER
// REACHES A CALLER.** A job is its owner's own — the authorisation question is
// identity equality rather than a grant (D254) — so the owning principal has
// to leave this package, and the verb that receives it must not put it on the
// wire. `JobStatusResponse` has no field for it, which is the structural half
// of that promise.
type Status struct {
	Principal  string
	DecisionID string
	State      State
	Events     int

	// Err is the failure, when there was one. A `Status` with StateFailed and
	// a nil Err would be a job that ended badly with nothing to say, which is
	// the shape criterion 15 exists to refuse.
	Err error

	Started time.Time
	Ended   time.Time
}

// statusRetention is how many TERMINAL job statuses are kept.
//
// **BOUNDED, BECAUSE THE OBVIOUS IMPLEMENTATION IS A LEAK WITH A SLOW CLOCK.**
// A map of every job this process ever ran grows without limit for the
// lifetime of a replica, and a recurrence submitting on a thirty-second
// interval reaches six figures in a month. That is D178's amplification with
// Sekizui as the hostile party, arriving through a convenience rather than
// through a payload — which is exactly how the disk-amplification case arrived
// the first time.
//
// **A COUNT RATHER THAN A TTL, and the reason is that a TTL needs a sweeper.**
// A background goroutine to expire entries is a component with a lifecycle, a
// failure mode and a reason to be in the init ledger, for a bound a count
// already gives — and the invariant that matters is BOUNDED MEMORY, which a
// count states directly and a TTL only implies. A busy deployment keeps less
// history and a quiet one keeps more, which is the right way round: history is
// worth most when there is little of it.
//
// RUNNING JOBS ARE NEVER EVICTED. Evicting one would report a job that is
// still working as unknown, and a caller told that has been lied to about the
// one thing this verb exists to answer.
const statusRetention = 1024

// note records a job's state, evicting old TERMINAL entries when the table is
// full.
func (p *Runner) note(id string, s Status) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.status == nil {
		p.status = map[string]Status{}
	}
	p.status[id] = s
	p.evictLocked()
}

// evictLocked drops the oldest terminal statuses until the table fits.
//
// Caller holds p.mu.
func (p *Runner) evictLocked() {
	if len(p.status) <= statusRetention {
		return
	}
	type ended struct {
		id string
		at time.Time
	}
	var done []ended
	for id, s := range p.status {
		if s.State == StateRunning {
			continue
		}
		done = append(done, ended{id: id, at: s.Ended})
	}
	// OLDEST FIRST, so what survives is what a caller is most likely to still
	// be asking about. Sorted rather than sampled: an arbitrary eviction makes
	// "is my job still known" depend on map iteration order, and a caller
	// cannot reason about that at all.
	sort.Slice(done, func(i, j int) bool { return done[i].at.Before(done[j].at) })

	for _, e := range done {
		if len(p.status) <= statusRetention {
			return
		}
		delete(p.status, e.id)
	}
	// **FALLING THROUGH HERE MEANS EVERY ENTRY IS RUNNING**, and the table is
	// over its bound with nothing evictable. That is not a leak — it is a
	// deployment with more than `statusRetention` jobs genuinely in flight,
	// and forgetting one of them to satisfy a constant would be the wrong
	// trade in the only direction that matters.
}

// settle marks a job finished: it stops being cancellable and gains its
// terminal status, ATOMICALLY.
//
// **ONE LOCK FOR BOTH, BECAUSE THEY ARE ONE FACT.** `running` answers "can
// this be cancelled" and `status` answers "how is it going", and a job that
// has ended must answer both consistently or a caller is told contradictory
// things about the same moment. Updating them separately left a window where
// `JobStatus` reported FAILED and `Cancel` reported that it had cancelled
// something — found by P3 step 33d on its first run, which is the arm that
// exists because "it already stopped" must not read as success.
func (p *Runner) settle(id string, s Status) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.running, id)
	if p.status == nil {
		p.status = map[string]Status{}
	}
	p.status[id] = s
	p.evictLocked()
}

// Status reports how a job is going. The bool is false when this process has
// no record of the id — never run here, or evicted.
//
// **IT DOES NOT AUTHORISE, and the split is deliberate.** This package knows
// who owns a job and has no business deciding who may ask: the gateway holds
// the verified caller identity and the enforcement path, and a second place
// that decides access would be the abbreviated copy D155 records. So the
// owning principal is returned and the comparison happens one layer up.
func (p *Runner) Status(id string) (Status, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.status[id]
	return s, ok
}

// CancelFor stops every RUNNING job belonging to a principal, returning their
// ids in a stable order.
//
// **BREAK-GLASS HAS TO REACH WORK ALREADY IN FLIGHT, OR IT ONLY LOOKS LIKE IT
// WORKED (P3 criterion 17).** `revoke_grant` suspends a principal by writing
// to `policy.Revocations`, which `ceilings` consults AT ADMISSION — and a
// one-shot job admits exactly once, at the start of its run. So a suspension
// landing a second later changed nothing about the job already going: the
// operator saw a successful revocation and the work carried on under the
// grant they had just pulled. **That is the widest window in the system
// between authorisation and use**, which is why the criterion names it
// separately rather than treating it as an implication of D146.
//
// **SYMMETRIC WITH `revoke_credential`, DELIBERATELY.** That verb already
// reaches in-flight work, through the pool cancelling the contexts it is
// holding (D128, D129) — so break-glass stopped live work on the credential
// axis and not on the grant axis, for no reason anybody had decided. The two
// halves of break-glass now behave the same way.
//
// **THE CANCEL FUNCS ARE CALLED OUTSIDE THE LOCK.** Cancelling wakes the job's
// goroutine, which takes `p.mu` in `settle` — holding it here would deadlock
// against the very work being stopped, and only under the load where
// cancellation matters.
func (p *Runner) CancelFor(principal string) []string {
	p.mu.Lock()
	var (
		ids     []string
		cancels []context.CancelFunc
	)
	for id, cancel := range p.running {
		// THE PRINCIPAL COMES FROM THE STATUS TABLE, which is the same entry
		// `JobStatus` authorises against — one record of who owns a job,
		// rather than a second answer that could disagree with the first.
		if p.status[id].Principal == principal {
			ids = append(ids, id)
			cancels = append(cancels, cancel)
		}
	}
	p.mu.Unlock()

	for _, c := range cancels {
		c()
	}
	// SORTED, so an operator reading two revocation records of the same
	// incident can diff them. Map iteration order would make the same event
	// render differently on every replica.
	sort.Strings(ids)
	return ids
}
