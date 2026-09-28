// Package pool keeps one client per Target, keyed so rotation invalidates it
// (§4.3.2, D99, D110), and is where break-glass revocation cancels (§4.7.10,
// D106).
//
// PRIVATE (D35).
//
// WHAT A POOL IS FOR HERE, and it is not mainly performance. §6 opens by saying
// every cross-tenant leak is a cache key missing a dimension — so the pool is
// the single most dangerous cache in the system, and `connector.PoolKey` exists
// to make its key un-hand-assemblable. Reuse is the benefit; correct keying is
// the requirement.
//
// SUPERSESSION IS THE INTERESTING PART. Content-addressed keys (D123) mean a
// rotated credential produces a NEW entry. They do not remove the old one, which
// still holds the superseded credential — and for a session-oriented driver
// (§4.7.4 class 3) a live authorised session. So an arriving key evicts every
// other key for the same target, rather than merely sitting alongside it.
//
// DRAIN, THEN WIPE (D110). A superseded entry is not torn down while calls are
// still using it. It stops being served immediately, its in-flight callers
// finish, and only then is the client closed and the credential zeroed.
//
// THE IN-FLIGHT REGISTRY IS ONE STRUCTURE SERVING TWO DECISIONS. D110 needs to
// know when the last caller of a credential has left, so it can wipe. D106 needs
// to reach every caller of a credential and cancel it. Those are the same set,
// so `entry.calls` holds a `context.CancelCauseFunc` per borrow: its LENGTH is
// what drain waits on and its VALUES are what revocation fires. D110 says this
// explicitly — the drain is affordable because revocation had already paid for
// the registry.
//
// WHO OWNS THE BYTES. The cache hands out its own slice rather than a copy, and
// drops its reference when the entry expires — so after a rotation the old
// material is reachable only from pooled Targets. That makes the pool the
// correct place to wipe it, and means no copy is needed anywhere.
//
// NOT YET HERE: `max_lifetime` and LRU bounds (D108) and the staleness report
// (D109). Those are steps 29-33 and they build on this.
//
// DESIGN.md references: §4.3.2, §4.7.4, §4.7.10, §4.7.11, §6, D99, D101, D106,
// D110, D123, D127, D128.
package pool

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/withdrawal"
)

// Build constructs a client for a Target. Called at most once per key.
type Build func(ctx context.Context, t connector.Target) (any, error)

// Closer is the OPTIONAL interface a class 3 client implements (§4.7.4).
//
// Dropping a pooled BigQuery client costs nothing; dropping an MCP session
// leaves server-side state and possibly a live authorised session. Discovered by
// assertion rather than declared, so a driver that needs no teardown says
// nothing — GO-PRIMER §2.2.
type Closer interface{ Close() error }

// Severity is which of §4.7.10's two withdrawals ran.
//
// They are NOT interchangeable, and step 11 exists because an alias is exactly
// what someone would later collapse them into. The table:
//
//	                    quarantine_target        revoke_credential
//	new calls           refused                  refused
//	in-flight calls     ALLOWED TO FINISH        CANCELLED
//	pooled clients      left to idle out         evicted and torn down
//	cached material     left to expire           evicted and wiped
//	use it when         a target misbehaves      a credential is compromised
type Severity int

const (
	// SeverityQuarantine stops new work reaching a target and lets existing work
	// finish. Right for a target that is misbehaving, wrong for a credential
	// that is believed compromised.
	SeverityQuarantine Severity = iota + 1

	// SeverityRevoke is break-glass. It cancels.
	SeverityRevoke
)

func (s Severity) String() string {
	switch s {
	case SeverityQuarantine:
		return "quarantine_target"
	case SeverityRevoke:
		return "revoke_credential"
	default:
		return "unknown_severity"
	}
}

// ParseSeverity is String's inverse, for reading a persisted withdrawal back.
//
// DERIVED FROM String RATHER THAN A SECOND SWITCH, so the two cannot disagree.
// A hand-written reverse mapping is the shape that lets a severity be written
// as one thing and read as another after somebody renames a constant — and the
// symptom would be a revocation silently downgraded to a quarantine across a
// restart, which is the difference between cancelling in-flight calls and
// letting them finish with a credential believed compromised.
func ParseSeverity(s string) (Severity, bool) {
	for _, candidate := range []Severity{SeverityQuarantine, SeverityRevoke} {
		if candidate.String() == s {
			return candidate, true
		}
	}
	return 0, false
}

// Withdrawal is what a Quarantine or Revoke actually did.
//
// EVERY FIELD IS HERE BECAUSE THE DECISION RECORD NEEDS IT (D106): "every
// revocation writes a decision record naming the credential, the trigger, and
// the count of in-flight calls it cancelled — that last number is the one an
// incident review asks for and nothing else can reconstruct". A revocation that
// reports only success answers "did it run" and not "what did it stop", and the
// second is the question actually asked at 03:00.
type Withdrawal struct {
	Severity  Severity
	TargetRef string

	// Cancelled is in-flight calls this withdrawal killed. Always zero for a
	// quarantine, and that is the assertion step 11 makes.
	Cancelled int

	// LeftRunning is in-flight calls a quarantine deliberately did NOT touch.
	// Reported rather than ignored: an operator who quarantines a target during
	// an incident needs to know work is still running against it, and "nothing
	// happened" and "four calls are still out there" look identical otherwise.
	LeftRunning int

	// Evicted is pooled entries removed, TornDown those that were class 3 and
	// got a Close.
	Evicted  int
	TornDown int

	// Stragglers is entries whose drain did not complete before the deadline —
	// a driver that ignored its context. Their credential is NOT wiped yet; see
	// Revoke.
	Stragglers int
}

// Pool holds one client per PoolKey.
type Pool struct {
	build Build
	log   *slog.Logger

	mu      sync.Mutex
	entries map[connector.PoolKey]*entry

	// byTarget groups keys by their SAFE half — `kind:ref` — which is exactly
	// the supersession group: same target, different credential.
	//
	// Uses PoolKey.String() rather than reaching for the credential version,
	// which is unexported on purpose (D112). The pool never needs to know what
	// changed, only that something did.
	byTarget map[string]map[connector.PoolKey]bool

	// withdrawn is targets an operator or an anzen rule has taken out of
	// service, and which severity did it.
	//
	// KEYED ON THE TARGET REF — the plain `kata:alpha` string an anzen rule
	// carries in its `subject` — and NOT on a PoolKey. That is deliberate and it
	// is the opposite of §6 item 2's rule about hand-assembling cache keys,
	// because this is not a cache. A cache key must carry every dimension or it
	// leaks across tenants; a withdrawal must carry as FEW as possible, because
	// it has to match a credential that has not been resolved yet and therefore
	// has no generation, no material, and no PoolKey. Keying it on a PoolKey
	// would produce a revocation that fails to refuse the very next resolution.
	// THE WHOLE RECORD, not just the severity (D158). A repeated withdrawal must
	// be able to say WHO withdrew this and WHEN — that is what a second on-call
	// engineer needs at 03:00, and holding only the severity meant the answer
	// existed in the store and nowhere the enforcement path could reach it.
	withdrawn map[string]withdrawal.Record

	// draining is superseded entries whose credential is no longer current and
	// which have not finished tearing down — **D99's gap, made countable**
	// (D109).
	//
	// A SEPARATE MAP FROM `entries`, and it has to be. `supersedeOthers` removes
	// a superseded entry from `entries` immediately, because nothing new must
	// ever borrow it; the entry object then lives on only in the hands of the
	// callers still using it. Counting from `entries` would therefore report
	// zero at exactly the moment the number is interesting. Nothing else in the
	// pool needed to observe that window, which is why it was invisible.
	//
	// ZERO IS THE EXPECTED VALUE. A non-zero count is a rotation in progress or
	// a drain that is not completing, and the AGE tells an operator which — a
	// second-old entry is a rotation, a ten-minute-old one is a bug or a call
	// that will not end.
	draining map[connector.PoolKey]*entry

	// maxLifetime bounds how long an entry may be reused, per target, with a
	// deployment default (D108).
	//
	// **THE GUARANTEE THAT DOES NOT DEPEND ON OUR CORRECTNESS.** Rotation is
	// supposed to supersede an entry (D99) and explicit invalidation is supposed
	// to close it — both are code, and code has bugs. This bound holds whether or
	// not that code is right, which is why §4.3.2a calls it a different KIND of
	// guarantee from the rest of §6: most of this design makes a failure
	// impossible by construction, and this makes one bounded in time regardless
	// of construction.
	maxLifetime    time.Duration
	perTargetLimit map[string]time.Duration

	// now is a seam because P1 exit criterion 12 sets the house rule: proven
	// with a clock seam rather than a sleep. A test that asserts a lifetime by
	// waiting proves the scheduler works.
	now func() time.Time

	// store makes a withdrawal survive a RESTART, which is what D133 already
	// promised and did not deliver: the map above is in memory, so every
	// restart silently restored every revoked credential — an unaudited
	// mass-restoration by an operation nobody reviews as a security action.
	//
	// Optional, and nil means in-memory only. A deployment that has not
	// configured a store is not refused, because P0 shipped without one and
	// forcing it would break every existing test; boot logs the gap instead.
	store withdrawal.Store

	evicted, wiped, torndown, cancelled uint64
}

type entry struct {
	// born is when this entry was created, for the lifetime bound (D108).
	born time.Time

	ready  chan struct{}
	client any
	err    error

	// done is closed by finalise, after the client is closed and the credential
	// zeroed. It is the drain-completion signal Revoke waits on, and it is the
	// only way to observe that a wipe has actually happened rather than been
	// scheduled.
	done chan struct{}

	// target is retained because it holds the credential this client was built
	// with, and that is what gets zeroed once the entry drains.
	target connector.Target

	// calls is the in-flight registry: one cancel function per live borrow.
	// Replaces a bare counter, which could answer "how many" but not "which",
	// and revocation needs to reach them.
	calls    map[uint64]context.CancelCauseFunc
	nextCall uint64

	superseded bool
	closed     bool

	// keepCredential suppresses the wipe in finalise (D213).
	//
	// **THE DECISION HAS TO BE RECORDED HERE RATHER THAN TAKEN AT TEARDOWN, and
	// that is forced rather than stylistic.** An entry that is still in flight
	// when it is evicted is finalised LATER, by `release`, from a call site that
	// knows only that the last borrow left — so by then the reason for the
	// eviction is gone. Every other eviction (a rotated credential, a lifetime
	// expiry, a revocation) means the material this entry holds is dead and
	// invariant 4 of §4.7.5 applies; a session discard means the SERVER forgot
	// us and the credential was never in question. Zeroing it there would wipe
	// material the very next traversal is about to use, turning a routine
	// re-handshake into a `credential_unavailable` on a target that is fine.
	keepCredential bool

	once sync.Once
}

// Compile-time proof that the published borrowing seam is satisfied, per
// GO-PRIMER §2. `connector.ClientPool` exists so revocation can reach
// third-party drivers (D35); this line is what stops the two drifting apart
// silently, since nothing else imports the interface.
var _ connector.ClientPool = (*Pool)(nil)

// New returns a pool.
func New(build Build, log *slog.Logger, opts ...Option) *Pool {
	p := &Pool{
		build:     build,
		log:       log,
		entries:   map[connector.PoolKey]*entry{},
		byTarget:  map[string]map[connector.PoolKey]bool{},
		withdrawn: map[string]withdrawal.Record{},
		draining:  map[connector.PoolKey]*entry{},
		now:       time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Option configures a Pool.
type Option func(*Pool)

// WithStore makes withdrawals durable across restarts (D145).
//
// OPTIONAL RATHER THAN REQUIRED, and the choice is a compromise worth naming. A
// pool without one behaves as it always has: withdrawals live only in memory,
// so a restart lifts them. That is a real gap, and making the store mandatory
// would be the safer default — it would also break every existing caller and
// every test that builds a pool, for a phase that shipped without it. Boot logs
// the absence instead, so a deployment running without durability knows.
func WithStore(s withdrawal.Store) Option { return func(p *Pool) { p.store = s } }

// WithMaxLifetime sets the deployment ceiling and any per-target narrowings
// (D108).
//
// THE PER-TARGET MAP IS ALREADY VALIDATED when it arrives: boot refuses a target
// that tries to WIDEN the ceiling (config.ExceedingTargets), so this applies
// rather than re-checking. A second check in a second place is how two checks
// come to disagree, and the one an operator sees the error from should be the one
// that runs at boot with the target's name in it.
func WithMaxLifetime(deployment time.Duration, perTarget map[string]time.Duration) Option {
	return func(p *Pool) { p.maxLifetime, p.perTargetLimit = deployment, perTarget }
}

// WithClock substitutes the clock.
func WithClock(now func() time.Time) Option { return func(p *Pool) { p.now = now } }

// lifetimeFor resolves one target's bound against the deployment's.
func (p *Pool) lifetimeFor(ref string) time.Duration {
	if d, ok := p.perTargetLimit[ref]; ok && d > 0 {
		return d
	}
	return p.maxLifetime
}

// Do borrows a client for the Target and runs fn against it.
//
// A CALL-THROUGH RATHER THAN A CHECK-OUT, and the change is a correctness one
// (D128). The previous shape returned `(client, release, error)` and left the
// caller holding two obligations: call release, and — once revocation needed a
// cancellable context — use the context the pool derived rather than its own.
// Both are the shape of this project's most persistent bug: a contract that is
// documented, is correct, and does nothing when a caller forgets it. Cancelling
// a context nobody passed to the outbound call is a revocation that reports
// success and stops nothing, which is worse than one that fails.
//
// Inverting the call makes both structural. fn CANNOT be given a context other
// than the cancellable one, because that is its only argument, and release
// CANNOT be forgotten, because the pool defers it.
//
// The borrow lasts exactly as long as fn, which is exactly the in-flight window
// that drain waits on and revocation cancels.
func (p *Pool) Do(ctx context.Context, t connector.Target, fn func(ctx context.Context, client any) error) error {
	client, callCtx, release, err := p.acquire(ctx, t)
	if err != nil {
		return err
	}
	defer release()

	err = fn(callCtx, client)

	// THE CAUSE OUTRANKS THE DRIVER'S OWN ERROR, and this is the whole point of
	// D106 rather than a nicety.
	//
	// A cancelled driver reports whatever its transport made of the abort:
	// `context.Canceled`, a wrapped `connection reset`, an SDK's own retry
	// exhaustion. Returning that verbatim writes an audit row saying the
	// connection dropped — the same category of lie as the all-zeros credential
	// producing a row that says *the target returned 401* rather than *an
	// operator revoked this*. D106 rejects memory-wiping precisely because a
	// memory write cannot be audited; cancellation is only better if the reason
	// survives to the record, and this is where it survives.
	//
	// ONLY WHEN fn ACTUALLY FAILED. If fn returned nil the call completed — the
	// side effect happened, at the external system, before the cancellation
	// landed. Overriding that with a revocation error would claim an effect did
	// not occur when it did, which corrupts the record in the other direction.
	// A revocation that races a completing call loses that race honestly.
	if err != nil {
		if cause := context.Cause(callCtx); cause != nil && fault.KindOf(cause) == fault.KindDenied {
			return cause
		}
	}
	return err
}

// acquire returns a client, a context revocation can cancel, and the release
// that ends the borrow. Only Do calls it, which is what keeps both obligations
// out of reach of anyone else.
func (p *Pool) acquire(ctx context.Context, t connector.Target) (any, context.Context, func(), error) {
	const op = "pool.acquire"

	key := t.PoolKey()

	for {
		p.mu.Lock()

		// Checked FIRST, before the entry lookup. A withdrawn target must refuse
		// even when a perfectly good client is still pooled for it — otherwise
		// quarantine means "no new clients" rather than "no new work", and every
		// existing caller sails straight past it.
		if rec, ok := p.withdrawn[t.Ref()]; ok {
			p.mu.Unlock()
			return nil, nil, nil, withdrawnErr(op, t.Ref(), severityOf(rec))
		}

		// **THE LIFETIME BOUND, CHECKED BEFORE REUSE** (D108). An entry past its
		// lifetime is treated exactly as a superseded one: taken out of the pool
		// and rebuilt. Checked here rather than on a timer because a timer is
		// another moving part that can fail silently, and because the only moment
		// the answer matters is when somebody is about to USE the client.
		//
		// A consequence worth naming: an entry can outlive its lifetime in the
		// map if nothing asks for it again. That is harmless for exposure —
		// nothing is using it — and the idle-eviction half of §4.3.2a is what
		// reclaims it. What this bound guarantees is that no CALL is made with a
		// client older than the limit.
		if e, ok := p.entries[key]; ok && !e.superseded && p.expired(e, t.Ref()) {
			p.log.Info("pooled client reached max_lifetime and is being replaced",
				"target", t.Ref(), "age", p.now().Sub(e.born).String(),
				"limit", p.lifetimeFor(t.Ref()).String())
			e.superseded = true
			idle := p.retireIfIdle(key, e)
			p.mu.Unlock()
			for _, old := range idle {
				p.finalise(old)
			}
			continue
		}

		if e, ok := p.entries[key]; ok && !e.superseded {
			p.mu.Unlock()

			select {
			case <-e.ready:
			case <-ctx.Done():
				return nil, nil, nil, fault.Wrap(fault.KindTimeout, op,
					"context done while waiting for a client for "+key.String(), ctx.Err())
			}
			if e.err != nil {
				return nil, nil, nil, e.err
			}

			p.mu.Lock()
			if e.superseded {
				// Rotated while we waited. Loop; the next pass builds against
				// the current credential rather than handing back a stale one.
				p.mu.Unlock()
				continue
			}

			// **§6 MECHANISM 3, WHERE THE BUG ACTUALLY LIVES.** Target.Assert's
			// own comment says it: "a pooled client keyed on a stale or
			// incomplete PoolKey will eventually hand back a client belonging to
			// another tenant, and no amount of care at construction prevents that
			// — the bug is in the cache, not the constructor". This is the cache,
			// and this is the moment it hands over.
			//
			// **PoolKey IS `{kind, ref, credVer}` AND DOES NOT CARRY TENANT**, so
			// two targets sharing a ref and a credential version collide however
			// carefully each was built. Configuration cannot produce that today,
			// because a ref maps to one tenant — which is a property of the
			// config schema rather than of this pool, and exactly why §6 lists
			// two mechanisms rather than trusting either alone. The day a
			// multi-tenant ref, a rewritten key or a driver-supplied target
			// arrives, this has to be already here.
			//
			// ASSERTS THE ENTRY'S TARGET, NOT THE REQUEST'S. The requested target
			// is right by construction; the question is whether the thing found
			// under its key was built for the same tenant. Comparing the request
			// against itself is what made the driver's own assertion unable to
			// fire — its two inputs were derived from one source.
			//
			// BEFORE THE CALLBACK RUNS. Catching it afterwards would be a report
			// rather than a defence.
			if err := e.target.Assert(t.Tenant()); err != nil {
				p.mu.Unlock()
				return nil, nil, nil, err
			}

			callCtx, release := p.enlist(ctx, e)
			p.mu.Unlock()
			return e.client, callCtx, release, nil
		}

		// This goroutine owns the build.
		e := &entry{
			born:   p.now(),
			ready:  make(chan struct{}),
			done:   make(chan struct{}),
			target: t,
			calls:  map[uint64]context.CancelCauseFunc{},
		}
		p.entries[key] = e
		callCtx, release := p.enlist(ctx, e)
		idle := p.supersedeOthers(key)
		p.mu.Unlock()

		// Synchronous, and before the build: by the time Do runs fn, every
		// superseded-and-idle client is closed and its credential zeroed. That
		// is what makes eviction observable rather than eventual.
		for _, old := range idle {
			p.finalise(old)
		}

		// Built under callCtx, not ctx. A build is in-flight work holding the
		// credential — a class 2 SDK client is CONSTRUCTED with it (§4.7.4) — so
		// a revocation arriving mid-build must reach it. Passing the caller's
		// context here would leave a window where the one operation guaranteed
		// to be touching the material is the one revocation cannot stop.
		e.client, e.err = p.build(callCtx, t)
		close(e.ready)

		if e.err != nil {
			release()
			p.mu.Lock()
			if p.entries[key] == e {
				delete(p.entries, key)
				p.forget(key)
			}
			p.mu.Unlock()
			// NOT wiped. The build failed, so this entry never served anything,
			// and the material still belongs to the cache — which will hand the
			// same slice to the next attempt. Zeroing it here would break a
			// credential that is perfectly good because a network call was not.
			return nil, nil, nil, e.err
		}
		return e.client, callCtx, release, nil
	}
}

// enlist registers one borrow and returns the cancellable context for it.
// Caller holds p.mu.
func (p *Pool) enlist(ctx context.Context, e *entry) (context.Context, func()) {
	// WithCancelCause rather than WithCancel, because the cause IS the audit
	// record's reason. A plain cancel gives the driver `context.Canceled`, which
	// says a call stopped and not why — and "why" is the only reason D106 chose
	// cancellation over a memory wipe. See GO-PRIMER §15n.
	callCtx, cancel := context.WithCancelCause(ctx)

	id := e.nextCall
	e.nextCall++
	e.calls[id] = cancel

	var once sync.Once
	return callCtx, func() {
		once.Do(func() {
			p.release(e, id)
			// Releases the context's own resources. Harmless after a revocation
			// already cancelled with a cause: the first cancel wins, so this
			// cannot overwrite the reason.
			cancel(nil)
		})
	}
}

// supersedeOthers marks every other key for this target as superseded, and
// finalises any that are already idle. Caller holds p.mu.
//
// THIS IS THE STEP D99 LEAVES OUT. A new key on its own means the next caller
// gets a fresh client; it says nothing about the old one, which keeps its
// credential — and its session — until something removes it.
// Returns entries the caller must finalise AFTER releasing the lock.
//
// NOT A GOROUTINE. An earlier version spawned one, because finalise takes the
// lock this function is called under. That made eviction asynchronous, which is
// a correctness problem rather than a style one: nothing downstream could
// observe when a credential had actually been zeroed, and the acceptance step
// asserting "not wiped while in flight" became timing-dependent — it passed
// against a deliberately broken pool. Handing the work back to the caller keeps
// it synchronous and therefore assertable.
func (p *Pool) supersedeOthers(arriving connector.PoolKey) []*entry {
	var idle []*entry

	group := arriving.String()
	if p.byTarget[group] == nil {
		p.byTarget[group] = map[connector.PoolKey]bool{}
	}
	p.byTarget[group][arriving] = true

	for key := range p.byTarget[group] {
		if key == arriving {
			continue
		}
		e, ok := p.entries[key]
		if !ok {
			delete(p.byTarget[group], key)
			continue
		}
		if e.superseded {
			continue
		}
		e.superseded = true
		p.evicted++
		delete(p.entries, key)
		delete(p.byTarget[group], key)

		p.log.Info("pooled client superseded by a rotated credential",
			"target", group, "in_flight", len(e.calls))

		if len(e.calls) == 0 {
			// Nothing to drain, so it can go as soon as the lock is released.
			idle = append(idle, e)
			continue
		}

		// STILL IN USE, AND THEREFORE STILL HOLDING A SUPERSEDED CREDENTIAL.
		// This is precisely the population D109 exists to count: removed from
		// the pool so nothing new can borrow it, alive because somebody is
		// mid-call, and invisible to every other accounting the pool does.
		p.draining[key] = e
	}
	return idle
}

// expired reports whether an entry has outlived its lifetime bound (D108).
//
// A ZERO LIMIT MEANS UNBOUNDED, which is the pre-D108 behaviour and therefore the
// direction that changes nothing for a deployment that has not configured one. A
// zero `born` also means unbounded, for a narrower reason: an entry constructed
// by a test or an older code path has no birth time, and treating "unknown age"
// as "expired" would rebuild a perfectly good client on every single borrow.
func (p *Pool) expired(e *entry, ref string) bool {
	limit := p.lifetimeFor(ref)
	if limit <= 0 || e.born.IsZero() {
		return false
	}
	return p.now().Sub(e.born) >= limit
}

// retireIfIdle takes an expired entry out of the pool, returning it for
// finalising when nothing is using it.
//
// THE SAME SHAPE AS supersedeOthers AND FOR THE SAME REASON: it is called under
// the lock, finalise takes the lock, so the work is handed back to the caller
// rather than spawned into a goroutine. An earlier version of the supersession
// path did spawn one, which made eviction asynchronous and unassertable — and an
// acceptance step asserting "not wiped while in flight" passed against a
// deliberately broken pool. Synchronous is what makes it observable.
//
// AN IN-FLIGHT CALL IS NOT INTERRUPTED. A lifetime bound is about not STARTING
// new work with an old client; cancelling a call in progress is what revocation
// does (D106), and conflating the two would make a routine expiry look like
// break-glass in the audit log.
func (p *Pool) retireIfIdle(key connector.PoolKey, e *entry) []*entry {
	p.evicted++
	delete(p.entries, key)
	p.forget(key)

	if len(e.calls) == 0 {
		return []*entry{e}
	}
	return nil
}

func (p *Pool) forget(key connector.PoolKey) {
	group := key.String()
	if m, ok := p.byTarget[group]; ok {
		delete(m, key)
		if len(m) == 0 {
			delete(p.byTarget, group)
		}
	}
}

// release records that one borrow is done, and finalises a superseded entry
// once the last of them leaves.
func (p *Pool) release(e *entry, id uint64) {
	p.mu.Lock()
	delete(e.calls, id)
	drained := e.superseded && len(e.calls) == 0
	p.mu.Unlock()

	if drained {
		p.finalise(e)
	}
}

// finalise tears the client down and zeroes the credential. Runs once.
//
// ORDER MATTERS: close the client first, then wipe. A class 3 client may need
// its credential to say goodbye — an MCP session close is an authenticated
// call — and wiping first would turn a clean teardown into a failed one.
func (p *Pool) finalise(e *entry) {
	e.once.Do(func() {
		// OUT OF THE STALE COUNT FIRST, before any of the teardown that can
		// fail. A drain that errors half-way has still stopped holding a
		// superseded credential for new work, and leaving it counted would make
		// the gauge report a security condition that has actually cleared —
		// which is the direction that gets a signal ignored (D77).
		p.mu.Lock()
		for key, candidate := range p.draining {
			if candidate == e {
				delete(p.draining, key)
				break
			}
		}
		p.mu.Unlock()

		// Closed LAST, after the wipe, so anything waiting on done observes a
		// completed teardown rather than one in progress. Revoke's straggler
		// accounting depends on this being the final act.
		defer close(e.done)

		if c, ok := e.client.(Closer); ok {
			if err := c.Close(); err != nil {
				// Logged, not returned: the caller that triggered this has
				// already gone, and a teardown failure must not stop the wipe.
				p.log.Warn("closing a superseded pooled client failed",
					"target", e.target.Ref(), "err", err)
			}
			p.mu.Lock()
			p.torndown++
			e.closed = true
			p.mu.Unlock()
		}

		// Invariant 4 of §4.7.5.
		//
		// SAFE WITHOUT THE DRAIN NOW (D127). This used to depend on every
		// in-flight caller having released, because the material was handed out
		// as a bare slice and zeroing it under a reader is a data race that can
		// hand a driver a partially-valid credential. Lending removed that:
		// `WipeCredential` takes the credential's write lock, so it waits only
		// for borrows — a header stamp or a client construction — and every
		// later `Use` refuses rather than reading zeroes.
		//
		// The drain above is therefore about TEARDOWN ORDER, not about the wipe:
		// a class 3 session must be closed before its credential goes, because
		// an MCP session close is itself an authenticated call — which stopped
		// being a hypothetical when D213 made that exact call for real.
		//
		// **AND THE WIPE IS SKIPPED FOR A SESSION DISCARD (D213).** See
		// `keepCredential`: the invariant is about material that is DEAD, and a
		// server forgetting a session says nothing about the credential.
		if e.keepCredential {
			return
		}
		e.target.WipeCredential()

		p.mu.Lock()
		p.wiped++
		p.mu.Unlock()
	})
}

// Quarantine stops new work reaching a target and lets in-flight calls finish
// (§4.7.10, the gentler severity).
//
// DELIBERATELY DOES ALMOST NOTHING, which is the point of step 11. It records a
// refusal for future calls and touches no entry, no client, and no credential.
// The temptation is to "tidy up" the pooled clients while here, and that
// temptation is exactly how the two severities collapse into one and the harder
// one quietly stops existing.
//
// Its pooled entries are left to idle out, which today means they are left,
// full stop: the idle reaper is D108's `max_lifetime` and LRU bound, acceptance
// steps 29-33, and it is not built. Stated rather than implied — a quarantined
// target's client currently survives until the process does.
func (p *Pool) Quarantine(ctx context.Context, ref, trigger string) (Withdrawal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// PERSIST BEFORE MUTATING MEMORY, so a store that cannot record leaves
	// nothing half-done. The other order would withdraw the target in this
	// process, fail to persist, and report an error for a withdrawal that IS in
	// force — and the operator would retry, or worse, believe it had not
	// happened.
	//
	// UNDER THE LOCK, accepting the I/O. Break-glass is rare and a race between
	// two withdrawals of the same target is not a trade worth making for
	// latency nobody measures on this path.
	if err := p.persist(ctx, ref, SeverityQuarantine, trigger); err != nil {
		return Withdrawal{}, err
	}
	p.withdrawn[ref] = withdrawal.Record{
		TargetRef: ref, Severity: SeverityQuarantine.String(), At: p.now(), Trigger: trigger,
	}

	w := Withdrawal{Severity: SeverityQuarantine, TargetRef: ref}
	for _, e := range p.entries {
		if e.target.Ref() == ref && !e.superseded {
			w.LeftRunning += len(e.calls)
		}
	}

	p.log.Info("target quarantined; new calls refused, in-flight calls left to finish",
		"target", ref, "in_flight", w.LeftRunning)
	return w, nil
}

// Revoke is break-glass (D106): new calls refused, in-flight calls CANCELLED,
// pooled clients evicted and torn down, credential wiped.
//
// Blocking, and bounded by ctx. It returns once every affected entry has
// drained and been wiped, which is what lets the decision record state what it
// actually did rather than what it set in motion. D110 notes the drain "returns
// immediately" in this case, and that is because Revoke has already cancelled
// everything it is about to wait for.
//
// ON THE DEADLINE IT DOES NOT WIPE, WHICH AMENDS D110 (see D127). That decision
// says the drain is "raced against a deadline, after which it cancels the
// stragglers and wipes anyway" — correct at shutdown, where the process is
// leaving and nothing can observe a torn credential. Mid-life it is wrong, and
// wrong in the exact way §4.7.10 spends four bullets rejecting: zeroing a slice
// a live driver is reading is a data race, therefore undefined behaviour, able
// to hand that driver a partially-valid credential. Breaking the memory model to
// hurry a wipe on a credential that has ALREADY been cancelled and evicted buys
// nothing.
//
// So a straggler keeps its material until it returns, and then the ordinary
// release path wipes it — the wipe is deferred, never skipped. What the deadline
// bounds is how long an operator waits for an answer, not how long the material
// lives. The count is reported so the gap is visible rather than assumed away.
func (p *Pool) Revoke(ctx context.Context, ref, trigger string) (Withdrawal, error) {
	w := Withdrawal{Severity: SeverityRevoke, TargetRef: ref}

	p.mu.Lock()
	if err := p.persist(ctx, ref, SeverityRevoke, trigger); err != nil {
		p.mu.Unlock()
		return Withdrawal{}, err
	}
	p.withdrawn[ref] = withdrawal.Record{
		TargetRef: ref, Severity: SeverityRevoke.String(), At: p.now(), Trigger: trigger,
	}

	// A SCAN, NOT AN INDEX. byTarget is keyed by `kind:ref` and would serve this
	// with one lookup, at the cost of a second structure that must agree with
	// entries about which keys exist. For a break-glass path, provable
	// completeness beats a constant factor on a map with one element per live
	// credential: the failure mode of a stale index here is a revocation that
	// silently misses the entry it was called for.
	var affected []*entry
	for key, e := range p.entries {
		if e.target.Ref() != ref || e.superseded {
			continue
		}
		e.superseded = true
		p.evicted++
		w.Evicted++
		delete(p.entries, key)
		p.forget(key)

		cause := revokedErr(ref)
		w.Cancelled += len(e.calls)
		p.cancelled += uint64(len(e.calls))
		for _, cancel := range e.calls {
			cancel(cause)
		}
		affected = append(affected, e)
	}
	p.mu.Unlock()

	p.log.Warn("credential revoked (break-glass); in-flight calls cancelled",
		"target", ref, "cancelled", w.Cancelled, "evicted", w.Evicted)

	// Entries with nothing in flight will never get a release to finalise them,
	// so they are finalised here — the same idle case supersedeOthers handles.
	for _, e := range affected {
		p.mu.Lock()
		idle := len(e.calls) == 0
		p.mu.Unlock()
		if idle {
			p.finalise(e)
		}
	}

	for _, e := range affected {
		select {
		case <-e.done:
		case <-ctx.Done():
			w.Stragglers++
		}
	}

	p.mu.Lock()
	for _, e := range affected {
		if e.closed {
			w.TornDown++
		}
	}
	p.mu.Unlock()

	if w.Stragglers > 0 {
		p.log.Warn("revocation drain timed out; material stays until the caller returns",
			"target", ref, "stragglers", w.Stragglers,
			"note", "a driver ignoring its context; the wipe is deferred, not skipped")
	}
	return w, nil
}

// DiscardClients drops every pooled client for a target so the next borrow
// builds a fresh one (D213).
//
// **THE THIRD REASON AN ENTRY LEAVES THE POOL, AND IT IS THE MILDEST OF THE
// THREE.** Supersession means a credential rotated; revocation means break-glass
// ran; this means the FAR SIDE forgot the connection state we established with
// it, which is a thing servers do on a timer. The difference from `Revoke` is
// three-fold and every part of it is deliberate:
//
//   - **Nothing is withdrawn.** The target stays fully servable; there is no
//     record to persist and no severity to name, because nobody decided
//     anything about this target's trustworthiness.
//   - **In-flight calls are NOT cancelled.** A borrow already under way holds a
//     session the server has not necessarily forgotten — only the request that
//     drew the 404 knows its own session is dead — and cancelling siblings would
//     turn one expired session into a burst of failures. This is D108's rule for
//     a lifetime bound, for the same reason: it is about not STARTING new work
//     with a dead client, and interrupting a live call is what revocation does.
//   - **The credential is NOT wiped**, via `keepCredential`. See that field.
//
// **IT DOES NOT WAIT FOR A DRAIN, WHICH `Revoke` DOES, and the asymmetry follows
// from who is waiting.** Revoke blocks until every affected entry has drained
// and been wiped, because an operator asked "is it gone" and the answer must be
// true when it returns. Here the caller is `Enforce` mid-command and the
// guarantee it needs is only that the next `acquire` finds no entry — true the
// moment the map is mutated under the lock. An entry still in flight is left to
// `release`, so a sibling call in progress is never interrupted.
//
// **IT IS NOT FREE, THOUGH, AND THE FIRST VERSION OF THIS COMMENT CLAIMED IT
// WAS.** An IDLE entry is finalised here, synchronously, and finalising a class
// 3 client calls `Close` — for an MCP session that is an HTTP DELETE. So a
// session re-establishment costs one extra round trip on the retry path, to tell
// a server to forget a session it has just told us it has already forgotten.
//
// **KEPT ANYWAY, and the reason is that this method is generic.** It says
// "discard the pooled clients", not "discard clients the far side has already
// dropped": a caller discarding a session that is still LIVE at the server must
// terminate it, or the discard leaks exactly the authorised session
// `pool.Closer` exists to reclaim. Skipping the DELETE would optimise the one
// case we can currently name at the cost of silently leaking in every case we
// cannot. The round trip is bounded by `sessionCloseTimeout` and hits a server
// that is answering — it 404s the DELETE too, which `Close` reads as success.
//
// Returns how many entries it dropped, so a caller can log it and a test can see
// that a discard nobody wired reaches nothing.
func (p *Pool) DiscardClients(ref string) int {
	// A SCAN, NOT AN INDEX, for the reason Revoke's own comment gives: a stale
	// second structure fails by silently missing the entry it was called for.
	var idle []*entry
	discarded := 0

	p.mu.Lock()
	for key, e := range p.entries {
		if e.target.Ref() != ref || e.superseded {
			continue
		}
		e.superseded = true
		e.keepCredential = true
		p.evicted++
		discarded++
		delete(p.entries, key)
		p.forget(key)

		if len(e.calls) == 0 {
			idle = append(idle, e)
			continue
		}
		// STILL IN USE, so it drains through `release` exactly as a superseded
		// entry does — and it is counted in `draining` for the same reason D157
		// gives: an entry out of `entries` and still alive is invisible to every
		// other accounting the pool does.
		p.draining[key] = e
	}
	p.mu.Unlock()

	if discarded > 0 {
		p.log.Info("pooled clients discarded so the next call re-establishes them",
			"target", ref, "discarded", discarded, "in_flight_left_running", len(idle) != discarded)
	}

	// Finalised OUTSIDE the lock, because finalise takes it — the same shape
	// supersedeOthers and Revoke both use.
	for _, e := range idle {
		p.finalise(e)
	}
	return discarded
}

// Restore lifts a withdrawal, and reports which one it lifted (D133).
//
// WRITTEN IN THE SAME TURN AS ITS CALLER, deliberately. An earlier pass wrote
// this method, found nothing called it, and DELETED it rather than allowlist an
// exported symbol with no caller — which was half right. Deleting moved the
// debt instead of discharging it: the refusal messages went on promising a
// remedy, and a revocation stayed a one-way door needing a process restart.
// The fix for an uncalled symbol is its caller.
//
// NOT LIFTED BY A CONFIG RELOAD, which was the obvious reading of §4.11's
// `revoke_grant` precedent. An unrelated config edit silently re-enabling a
// credential somebody revoked as compromised is an attack path, not a
// convenience. Withdrawn stays withdrawn until explicitly told otherwise.
//
// DOES NOT RESURRECT ANYTHING. The pooled clients were torn down and their
// material zeroed when the withdrawal ran; this only stops new work being
// refused, so the next call builds a fresh client against a freshly resolved
// credential. That is correct whether or not the operator rotated the secret in
// between — and if they did not, the record says the restore lifted a
// REVOCATION, which is the question a reviewer will ask.
//
// Reports false when the target was not withdrawn, so a caller can refuse
// rather than report success for a no-op (D133): during an incident, a typo'd
// reference that answers OK is worse than one that fails.
func (p *Pool) Restore(ctx context.Context, ref string) (Severity, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	sev, ok := p.withdrawn[ref]
	if !ok {
		return 0, false, nil
	}
	// PERSIST THE LIFT BEFORE FORGETTING IT. The reverse order would restore the
	// target here, fail to persist, and re-withdraw it on the next restart — a
	// target that comes back from the dead at deploy time, which is the same
	// class of surprise as one that silently un-revokes.
	if p.store != nil {
		if err := p.store.Delete(ctx, ref); err != nil {
			return 0, false, err
		}
	}
	delete(p.withdrawn, ref)

	p.log.Warn("withdrawal lifted; new calls to this target are permitted again",
		"target", ref, "restored_from", severityOf(sev).String())
	return severityOf(sev), true, nil
}

// persist writes one withdrawal through the store, if there is one.
func (p *Pool) persist(ctx context.Context, ref string, sev Severity, trigger string) error {
	if p.store == nil {
		return nil
	}
	return p.store.Put(ctx, withdrawal.Record{
		TargetRef: ref, Severity: sev.String(), At: time.Now(), Trigger: trigger,
	})
}

// Rehydrate restores the withdrawal set from the store at boot.
//
// CALLED BEFORE THE LISTENER BINDS, or there is a window in which the instance
// serves commands against targets it has been told are compromised — short,
// entirely silent, and exactly when an incident is in progress.
//
// A LOAD FAILURE MUST FAIL THE BOOT, and the store's own contract says so: an
// empty withdrawal set is not the safe default, it is the attack. This returns
// the error and the caller refuses to start.
func (p *Pool) Rehydrate(ctx context.Context) (int, error) {
	if p.store == nil {
		return 0, nil
	}
	records, err := p.store.Load(ctx)
	if err != nil {
		return 0, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range records {
		sev, ok := ParseSeverity(r.Severity)
		if !ok {
			return 0, fault.New(fault.KindConfig, "pool.Rehydrate",
				"withdrawal store names severity "+r.Severity+" for "+r.TargetRef+
					", which is not a severity this build knows. Refusing to start: "+
					"guessing would either under-apply a revocation or over-apply a "+
					"quarantine, and both are wrong during an incident")
		}
		p.withdrawn[r.TargetRef] = r
		p.log.Warn("withdrawal restored from the store; this target was withdrawn before "+
			"the process started and stays withdrawn until sekizui.restore_target (D133)",
			"target", r.TargetRef, "severity", sev.String(),
			"withdrawn_at", r.At, "trigger", r.Trigger)
	}
	return len(records), nil
}

// ErrWithdrawn marks a refusal caused by a withdrawal, through any wrapping.
//
// A SENTINEL RATHER THAN A KIND, because the kind is KindDenied — the same as a
// policy denial, deliberately (a revocation IS a denial, and a separate kind to
// say so was not worth the taxonomy). The enforcement path still has to tell
// them apart to record which stage refused (D135), and `errors.Is` against a
// sentinel is how Go says that without inventing a kind for it.
//
//nolint:gochecknoglobals // an immutable sentinel error, the sql.ErrNoRows shape
var ErrWithdrawn = errors.New("target withdrawn")

// Withdrawn reports whether a target is currently withdrawn, and by which
// severity.
//
// EXISTS SO THE GATEWAY CAN REFUSE BEFORE WRITING AN INTENT RECORD. A withdrawn
// target is not a call that was attempted and failed; it is a call that never
// should have started, which is the same shape as a residency conflict. Letting
// it reach the driver produced an intent row saying an action was about to
// happen, followed by an outcome saying it did not — for a command Sekizui
// refused itself.
func (p *Pool) Withdrawn(ref string) (Severity, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.withdrawn[ref]
	return severityOf(rec), ok
}

// WithdrawnErr is the refusal a withdrawn target gives a new call. Exported so
// the enforcement path raises the identical error it would have hit later.
func WithdrawnErr(op, ref string, sev Severity) error { return withdrawnErr(op, ref, sev) }

// withdrawnErr is the refusal a withdrawn target gives a new call.
//
// ONE KIND FOR BOTH SEVERITIES (fault.KindDenied). What the caller must do is
// identical — stop, and tell a human — and the severity that ran is a field on
// the decision record, where the question is actually asked.
func withdrawnErr(op, ref string, sev Severity) error {
	// WRAPS ErrWithdrawn AS THE CAUSE, so `errors.Is` identifies the stage
	// without parsing a message. The kind stays KindDenied — the same as a
	// policy denial, because a revocation IS a denial — and the sentinel is what
	// lets the record say which of the two it was (D135).
	switch sev {
	case SeverityRevoke:
		return fault.Wrap(fault.KindDenied, op,
			"target "+ref+" had its credential revoked (break-glass, D106); new calls are "+
				"refused and in-flight calls were cancelled. Never lifted by a retry, and "+
				"never by a config reload — an authorised principal must issue "+
				"sekizui.restore_target once the credential is known good (D133)",
			ErrWithdrawn)
	case SeverityQuarantine:
		return fault.Wrap(fault.KindDenied, op,
			"target "+ref+" is quarantined (§4.7.10); new calls are refused while calls "+
				"already in flight finish. Lifted by sekizui.restore_target (D133)",
			ErrWithdrawn)
	default:
		return fault.Wrap(fault.KindDenied, op, "target "+ref+" is withdrawn", ErrWithdrawn)
	}
}

// revokedErr is the CAUSE a cancelled in-flight call carries, and the reason
// this is auditable at all.
func revokedErr(ref string) error {
	return fault.New(fault.KindDenied, "pool.Revoke",
		"the credential for target "+ref+" was revoked while this call was in flight "+
			"(break-glass, D106). The call was cancelled by Sekizui; the target did not "+
			"refuse it and may have already applied part of it")
}

// InFlight reports how many borrows are live for a target.
//
// The number D109's staleness report publishes per target, and the one an
// operator wants before quarantining something: "is anything still running
// against this?" Also what lets a test wait for a command to be genuinely in
// flight instead of sleeping and hoping.
func (p *Pool) InFlight(ref string) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	n := 0
	for _, e := range p.entries {
		if e.target.Ref() == ref {
			n += len(e.calls)
		}
	}
	return n
}

// Stats reports evictions, wipes, teardowns, and cancellations.
func (p *Pool) Stats() (evicted, wiped, torndown, cancelled uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.evicted, p.wiped, p.torndown, p.cancelled
}

// Len reports live entries, for tests and for the staleness report (D109).
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// StaleEntry is one pooled client still holding a superseded credential (D109).
type StaleEntry struct {
	TargetRef string

	// Age is how long the entry has existed, which is what tells a rotation in
	// progress from a drain that is not completing. Seconds old is a rotation;
	// minutes old is a bug or a call that will not end.
	Age time.Duration

	// InFlight is how many calls are still using it — the reason it has not
	// been torn down.
	InFlight int
}

// Stale reports pooled clients still holding a superseded credential.
//
// **A BOUND NOBODY CAN SEE IS A BOUND NOBODY TRUSTS** (D109). D99's
// content-addressing creates a new entry on rotation and does not remove the old
// one; explicit invalidation closes that, and rather than reasoning about whether
// the invalidation is correct, the pool counts what is left and publishes the
// number. Zero is expected.
//
// ONE WAY TO ASK, not two. A `StaleCount` sat beside this briefly and was
// deleted: `len(Stale())` answers it, and archcheck caught that the shorter form
// had no caller outside a test. Two ways to ask one question is how the two come
// to disagree.
//
// AGE IS RETURNED BESIDE THE COUNT because the count alone cannot be acted on. A
// non-zero value is either a rotation happening right now — entirely normal, and
// resolving itself as you read it — or a drain that will never complete. Those
// want opposite responses, and only the age tells them apart.
func (p *Pool) Stale() []StaleEntry {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]StaleEntry, 0, len(p.draining))
	for _, e := range p.draining {
		age := time.Duration(0)
		if !e.born.IsZero() {
			age = p.now().Sub(e.born)
		}
		out = append(out, StaleEntry{
			TargetRef: e.target.Ref(),
			Age:       age,
			InFlight:  len(e.calls),
		})
	}
	return out
}

// PriorWithdrawal returns the record already in force for a target, if any
// (D158).
//
// **SO A REPEAT CAN NAME WHO GOT THERE FIRST.** A second on-call engineer firing
// break-glass needs one thing the system could not previously tell them: whether
// somebody else already did it, and who. Returning an error instead would read
// under stress as "it did not work" — which sends them looking for a bigger
// hammer for a condition that is already handled.
func (p *Pool) PriorWithdrawal(ref string) (withdrawal.Record, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.withdrawn[ref]
	return rec, ok
}

// severityOf reads a stored record's severity back into the enum.
//
// THE STRING IS THE DURABLE FORM AND THE ENUM IS THE WORKING ONE — withdrawal.Record
// carries a string deliberately, because "a file outlives any given build and an
// integer whose meaning lives in a Go constant is unreadable in an incident". An
// unrecognised value maps to quarantine, the WEAKER severity, which errs towards
// letting in-flight work finish rather than cancelling on a value nobody
// understands; Rehydrate refuses such a record at boot, so this is defence rather
// than policy.
func severityOf(r withdrawal.Record) Severity {
	if r.Severity == SeverityRevoke.String() {
		return SeverityRevoke
	}
	return SeverityQuarantine
}
