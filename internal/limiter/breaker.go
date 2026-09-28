// Package limiter holds the local implementations of the pkg/limiter seams.
//
// PRIVATE (D35). The INTERFACES are public so a multi-replica operator can ship
// a distributed limiter; the local implementations are not, because a
// deployment substituting them wholesale is the supported extension point and
// forking these is not.
//
// DESIGN.md references: §4.3.4, §4.8, §5.2.1, D14.
package limiter

import (
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/pkg/limiter"
)

// Breaker trips per TARGET after consecutive failures.
//
// WHY PER TARGET AND NOT PER PRINCIPAL. A breaker withdraws from an unhealthy
// UPSTREAM; health is a property of the target, not of who is asking. Keyed on
// principal it would let a healthy agent keep hammering a dead Jira because its
// own count was low, which is precisely the thing this exists to stop.
//
// SEPARATE FROM THE LIMITER, following pkg/limiter's own note: a limiter shapes
// healthy traffic and a breaker withdraws from unhealthy targets. The states
// look similar from a call site — both say "not now" — and the reasons are
// opposite, so conflating them makes both harder to reason about and makes the
// metric label meaningless.
type Breaker struct {
	// Trip is the consecutive-failure count that opens the breaker.
	trip int

	// Cooldown is how long it stays open before allowing ONE probe.
	cooldown time.Duration

	// perTarget overrides trip and cooldown for named targets (D142). Built once
	// at wiring and never mutated, so it needs no lock of its own.
	perTarget map[string]Bounds

	now func() time.Time

	mu    sync.Mutex
	state map[string]*targetState
}

// Bounds is one target's breaker configuration, narrowed from the deployment's
// (D142). A zero field falls back to the deployment value rather than to Go's
// zero, because a breaker that never trips because somebody omitted a field is
// indistinguishable from one that is off on purpose.
type Bounds struct {
	Trip     int
	Cooldown time.Duration
}

type targetState struct {
	consecutive int
	openedAt    time.Time

	// probing is true when the cooldown has elapsed and one call has been let
	// through to find out. It exists because half-open must admit exactly ONE
	// caller: a hundred goroutines arriving the instant the cooldown expires
	// would all be admitted and would all hit a target that is probably still
	// down, which is the stampede the breaker was opened to prevent.
	probing bool
}

var _ limiter.Breaker = (*Breaker)(nil)

// NewBreaker builds a breaker. Zero values get modest defaults rather than
// disabling the breaker, because a breaker that is off by accident is
// indistinguishable from one that never trips.
func NewBreaker(trip int, cooldown time.Duration, opts ...BreakerOption) *Breaker {
	b := &Breaker{trip: trip, cooldown: cooldown, now: time.Now, state: map[string]*targetState{}}
	if b.trip < 1 {
		b.trip = 5
	}
	if b.cooldown <= 0 {
		b.cooldown = 30 * time.Second
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// BreakerOption configures a Breaker.
type BreakerOption func(*Breaker)

// WithTargetBounds narrows trip and cooldown for named targets (D142).
//
// THE BOUNDS ARE ALREADY VALIDATED when they arrive here. Boot refuses a target
// more aggressive than the deployment permits (config.ExceedingTargets), so this
// applies them rather than re-checking them — a second check in a different
// place is how two checks come to disagree, and the one an operator sees the
// error from should be the one that runs at boot with the target's name in it.
func WithTargetBounds(m map[string]Bounds) BreakerOption {
	return func(b *Breaker) { b.perTarget = m }
}

// WithBreakerClock substitutes the clock, so a test can cross the cooldown
// without sleeping (P1 exit criterion 12's house rule).
func WithBreakerClock(now func() time.Time) BreakerOption {
	return func(b *Breaker) { b.now = now }
}

// Allow reports whether calls to this target are currently permitted.
//
// NOT A PURE READ, and the name hides that — deliberately, because it is
// pkg/limiter.Breaker's name and the interface is the contract. Crossing from
// open into half-open happens HERE, because it is the only moment the breaker
// learns that the cooldown has elapsed: nothing wakes it up. Doing it in State()
// instead would mean a caller that never asks for the state never recovers.
func (b *Breaker) Allow(targetRef string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	s := b.state[targetRef]
	if s == nil || s.openedAt.IsZero() {
		return true
	}
	if b.now().Sub(s.openedAt) < b.cooldownFor(targetRef) {
		return false
	}
	if s.probing {
		// Half-open and the probe is already out. Everyone else waits for its
		// answer rather than joining it.
		return false
	}
	s.probing = true
	return true
}

// Record feeds an outcome back.
//
// A SUCCESS WHILE PROBING CLOSES THE BREAKER OUTRIGHT, rather than decrementing
// towards closed. The trip counts CONSECUTIVE failures, so a single success is
// already evidence the streak is broken; requiring several would leave the
// target throttled while it is demonstrably serving.
//
// A FAILURE WHILE PROBING RE-OPENS from now, not from the original open. The
// cooldown is "how long before we try again", and it has to restart or a target
// down for an hour is probed on the original schedule forever.
func (b *Breaker) Record(targetRef string, success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	s := b.state[targetRef]
	if s == nil {
		s = &targetState{}
		b.state[targetRef] = s
	}

	if success {
		s.consecutive = 0
		s.openedAt = time.Time{}
		s.probing = false
		return
	}

	s.consecutive++
	if s.probing || s.consecutive >= b.tripFor(targetRef) {
		s.openedAt = b.now()
		s.probing = false
	}
}

// State returns "closed", "open", or "half-open" for the panel's target health
// view (§4.8).
//
// READ-ONLY, unlike Allow. An operator refreshing a dashboard must not advance
// the breaker's state machine — a panel that changes what it observes is worse
// than one that lags, and §4.8 makes the panel read-mostly for exactly this kind
// of reason.
func (b *Breaker) State(targetRef string) string {
	b.mu.Lock()
	defer b.mu.Unlock()

	s := b.state[targetRef]
	switch {
	case s == nil || s.openedAt.IsZero():
		return "closed"
	case b.now().Sub(s.openedAt) >= b.cooldownFor(targetRef):
		return "half-open"
	default:
		return "open"
	}
}

// tripFor and cooldownFor resolve one target's bounds against the deployment's.
//
// TWO METHODS RATHER THAN ONE RETURNING Bounds, because the callers want one
// field each and a struct return would invite a caller to read the field it did
// not need — which is how `cooldown` came to be read where `trip` was meant
// during this change, caught only by the compiler disagreeing about the type.
func (b *Breaker) tripFor(targetRef string) int {
	if o, ok := b.perTarget[targetRef]; ok && o.Trip > 0 {
		return o.Trip
	}
	return b.trip
}

func (b *Breaker) cooldownFor(targetRef string) time.Duration {
	if o, ok := b.perTarget[targetRef]; ok && o.Cooldown > 0 {
		return o.Cooldown
	}
	return b.cooldown
}
