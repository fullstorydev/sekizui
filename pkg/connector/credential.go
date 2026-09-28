package connector

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Credential holds resolved material and LENDS it — it never hands it over
// (D127).
//
// WHY LENDING RATHER THAN A GETTER. Revocation has to be able to zero material
// that a driver may be using, and the two obvious designs both fail. Wiping
// while a driver reads is a data race, and §4.7.10 spends four bullets on why
// that is worse than useless: `clear()` concurrent with a read can TEAR, so the
// driver sends a partially-valid credential and the audit record says *the
// target returned 401* rather than *an operator revoked this*. Waiting for the
// driver to finish instead leaves the material resident for as long as the
// driver takes — and a driver that never returns is precisely what an attacker
// arranges, so the window is attacker-controlled rather than bounded.
//
// Lending removes the dilemma by shrinking the window to something WE control.
// The borrow lasts for the callback, not for the outbound call: stamping a
// header (§4.7.4 class 1) or constructing a client (classes 2 and 3, inside the
// pool's Build). So the wipe takes the write lock and waits microseconds for a
// header stamp, rather than seconds for a network round-trip that may never
// complete. No deadline, no straggler, no copy, and no race.
//
// A WIPED CREDENTIAL REFUSES, which is the property D106 could not get any
// other way. After Wipe, Use returns an error naming the revocation instead of
// lending zeroed bytes — because zeroed bytes are not a refusal, they are a
// request to the upstream with a broken credential.
//
// THE ONE THING THIS CANNOT MAKE STRUCTURAL is a driver that stashes the slice
// and reads it after the callback returns. Go has no way to invalidate a
// []byte. That is a contract, and it is guarded rather than trusted: such a
// driver races any subsequent Wipe, `make test` hardcodes `-race`, and P1 step
// 53 plants exactly that driver to prove the build catches it. A contract whose
// breach fails the build is a different animal from one that fails silently.
//
// DESIGN.md references: §4.3.3, §4.7.4, §4.7.10, §4.7.11, D106, D110, D127.
type Credential struct {
	// RWMutex rather than Mutex because concurrent borrows are the common case
	// — many in-flight calls each stamping a header — and they do not conflict
	// with each other. Only the wipe needs exclusivity.
	mu       sync.RWMutex
	material Secret
	wiped    bool
}

// NewCredential wraps resolved material for lending.
//
// Takes ownership of the slice: the caller must not retain it, because Wipe
// zeroes this backing array and any other holder would observe that.
func NewCredential(material Secret) *Credential {
	return &Credential{material: material}
}

// Material is a LEASE on credential material, valid only inside the callback
// that received it.
//
// WHY NOT JUST HAND OVER THE []byte. The earlier shape did, and D127 recorded
// the residual honestly: a driver could stash the slice and read it later, and
// Go has no way to invalidate a slice. This closes most of that. A driver
// appends the credential into ITS OWN buffer — which a class 1 driver was going
// to do anyway to build `Authorization: Bearer …` — so Sekizui's slice never
// escapes the callback at all, and a stashed Material refuses once the lease
// ends rather than reading material that is about to be wiped.
//
// The remaining hole is UseRaw, which classes 2 and 3 genuinely need and which
// is named so it can be grepped.
type Material struct {
	c *Credential

	// live is per-borrow, set false when the callback returns. A Material that
	// outlives its callback is therefore inert rather than dangerous.
	live *atomic.Bool
}

// AppendTo appends the credential to dst and returns the extended slice, the
// way `strconv.AppendInt` and friends do.
//
// THE ALLOCATION IS THE CALLER'S AND ALREADY EXISTED: building
// `"Bearer " + token` copies the material regardless, so appending into a
// buffer the driver owns costs nothing extra and keeps our slice unexported.
//
// DELIBERATELY DOES NOT RE-LOCK. `Use` holds the credential's read lock for the
// whole callback, so the read below is already protected — and taking the read
// lock again here would DEADLOCK: Go's RWMutex blocks new readers while a
// writer is pending, so a concurrent Wipe would leave this waiting behind a
// writer that is itself waiting for the callback to finish. Re-entrant read
// locking is not a thing in Go, and this is the shape where people discover it.
func (m Material) AppendTo(dst []byte) ([]byte, error) {
	const op = "connector.Material.AppendTo"

	if m.live == nil || !m.live.Load() {
		return dst, fault.New(fault.KindInternal, op,
			"this credential lease has expired: Material is valid only inside the "+
				"callback that received it, and retaining one past that point is the "+
				"contract D127 exists to bound")
	}
	return append(dst, m.c.material...), nil
}

// Len reports the material's length, for a driver that needs to size a buffer
// without seeing the bytes.
func (m Material) Len() int {
	if m.live == nil || !m.live.Load() {
		return 0
	}
	return len(m.c.material)
}

// String and GoString keep a Material as unprintable as everything else here.
func (m Material) String() string   { return Redacted }
func (m Material) GoString() string { return Redacted }

// Use lends the material to fn for the duration of the call and no longer.
//
// KEEP fn SHORT. It holds a read lock, so a revocation cannot complete until
// every in-flight borrow returns. Stamping a header or constructing a client is
// right; making the outbound request inside fn is not — that would recreate
// exactly the unbounded window lending exists to remove.
func (c *Credential) Use(fn func(Material) error) error {
	const op = "connector.Credential.Use"

	c.mu.RLock()
	defer c.mu.RUnlock()

	if err := c.checkUsable(op); err != nil {
		return err
	}

	// One flag per borrow, so ending this lease cannot affect another
	// goroutine's. Cleared before Use returns, which is what makes "valid only
	// inside the callback" literally true rather than a convention.
	live := new(atomic.Bool)
	live.Store(true)
	defer live.Store(false)

	return fn(Material{c: c, live: live})
}

// UseRaw lends the raw slice, for §4.7.4 class 2 and class 3 ONLY.
//
// NAMED TO BE GREPPED. A class 2 driver hands credentials to an SDK constructor
// and a class 3 driver opens an authenticated session; neither can be served by
// appending into a buffer, so raw access has to exist. What it must not be is
// the path a connector author reaches for by default — hence a separate method
// with `Raw` in the name, so `grep -rn UseRaw` enumerates every place in the
// tree where credential bytes are exposed, and a reviewer can check each one.
//
// The same rules apply and are weaker in one respect: fn MUST NOT retain the
// slice, and unlike Material there is nothing here that can stop it.
func (c *Credential) UseRaw(fn func(material []byte) error) error {
	const op = "connector.Credential.UseRaw"

	c.mu.RLock()
	defer c.mu.RUnlock()

	if err := c.checkUsable(op); err != nil {
		return err
	}
	return fn(c.material)
}

// checkUsable is the shared refusal. Caller holds at least the read lock.
func (c *Credential) checkUsable(op string) error {
	if c.wiped {
		// A REFUSAL, NOT ZEROED BYTES. This is the whole of D106's argument for
		// cancellation over memory-wiping, restated at the one place a driver
		// would otherwise pick up a dead credential and ask the upstream what it
		// makes of it.
		return fault.New(fault.KindDenied, op,
			"this credential has been wiped after revocation or eviction; it is refused "+
				"here rather than sent as zeroed bytes, which the target would report as "+
				"an authentication failure and the audit would record as the target's "+
				"refusal rather than ours (§4.7.10)")
	}
	if len(c.material) == 0 {
		return fault.New(fault.KindConfig, op,
			"no credential material was resolved for this target")
	}
	return nil
}

// Wipe zeroes the material and makes every subsequent Use refuse.
//
// Blocks until in-flight borrows return, which is bounded by construction: a
// borrow is a header stamp or a client construction, never a network call.
// Idempotent.
func (c *Credential) Wipe() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.material.Wipe()
	c.wiped = true
}

// Wiped reports whether this credential has been zeroed.
func (c *Credential) Wiped() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.wiped
}

// LogValue keeps a Credential as unprintable as the Secret inside it. The
// self-redacting property is by TYPE (§4.3.3), so it has to survive being
// wrapped in another type — otherwise the wrapper is the hole.
func (c *Credential) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String and GoString cover the fmt verbs, for the same reason Secret does.
func (c *Credential) String() string   { return Redacted }
func (c *Credential) GoString() string { return Redacted }
