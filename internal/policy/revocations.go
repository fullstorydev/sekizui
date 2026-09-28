package policy

import (
	"sync"
	"time"
)

// Revocations is the set of principals whose grants are suspended at RUNTIME
// (D146).
//
// SEPARATE FROM GrantEngine, WHICH STAYS IMMUTABLE. The engine's whole
// concurrency story is "built once from a Document and never mutated, so it is
// safe to share across goroutines" — putting a mutable set inside it would put a
// lock on the hottest path in the system to serve an operation that happens
// during incidents. A second, small, mutex-guarded structure consulted before
// the engine costs one uncontended lock and leaves the engine alone.
//
// A CEILING, NOT A GRANT EDIT. This does not rewrite configuration; it refuses a
// principal regardless of what configuration says, in the same shape as an anzen
// guard (D71). Config remains the source of truth (D10) and this is the lever
// for the minutes before config catches up.
//
// **DELIBERATELY NOT DURABLE — "until config is redeployed."** That is the
// asymmetry with D133, which refuses to let a restart lift a credential
// revocation, and it is defensible for one specific reason: CONFIG IS THE
// AUTHORITY ON GRANTS AND IS NOT THE AUTHORITY ON WHETHER A CREDENTIAL IS
// COMPROMISED. A redeploy restoring a grant is configuration reasserting
// something it genuinely knows; a redeploy restoring a revoked credential would
// be configuration overruling a fact it cannot express.
//
// The failure that leaves is an operator revoking in an incident, forgetting to
// edit config, and a later deploy quietly restoring it. Mitigated by saying so
// LOUDLY at the moment of revocation rather than by pretending otherwise — see
// the warning gateway.revokeGrant emits.
type Revocations struct {
	mu sync.RWMutex
	at map[string]Revocation
}

// Revocation is one suspended principal.
type Revocation struct {
	Principal string
	At        time.Time
	Trigger   string
	Reason    string
}

// NewRevocations builds an empty set.
func NewRevocations() *Revocations { return &Revocations{at: map[string]Revocation{}} }

// Revoke suspends a principal's grants. Returns false if already suspended, so
// the caller can refuse a no-op rather than report success for one — D133's
// rule for restore, applied in the other direction.
func (r *Revocations) Revoke(rev Revocation) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, already := r.at[rev.Principal]; already {
		return false
	}
	r.at[rev.Principal] = rev
	return true
}

// Reinstate lifts one, and reports whether there was anything to lift.
func (r *Revocations) Reinstate(principal string) (Revocation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rev, ok := r.at[principal]
	if ok {
		delete(r.at, principal)
	}
	return rev, ok
}

// Revoked reports whether this principal is suspended.
//
// READ LOCK, and the distinction matters under load: this is consulted on every
// command, and an exclusive lock here would serialise the enforcement path
// behind an operation that happens twice a year.
func (r *Revocations) Revoked(principal string) (Revocation, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rev, ok := r.at[principal]
	return rev, ok
}
