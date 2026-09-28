// Package gateway is the serving surface: gRPC over mTLS, and the enforcement
// path behind it.
//
// PRIVATE (D35). Named for the deployment mode it serves (§5.3's
// `sekizui-gateway`), not for a plane — it carries both enshin (commands out)
// and kyuushin (events in), so naming it for either would be half right.
//
// DESIGN.md references: §4.1.1, §4.10.3, §5.3, §7.1, §7.3, D9, D18, D62.
package gateway

import (
	"context"
	"sync"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Admission bounds concurrent in-flight work — §7.1's "bounded everything:
// explicit load shedding with 429/503; never unbounded buffering or unbounded
// goroutine spawn".
//
// DISTINCT FROM pkg/limiter, and the distinction matters. A Limiter is OUTBOUND:
// it stops Sekizui exceeding a vendor's quota (§4.3.4). Admission is INBOUND: it
// stops Sekizui accepting more work than it can serve. One protects the far
// side; this protects us. Conflating them means either shedding load to protect
// Jira, or hammering Jira to protect ourselves.
//
// SHEDDING IS EXPLICIT, per §7.3's "design the seams, ship the simple
// implementation". A semaphore is the simple implementation. What matters is
// that the refusal is a classified error a caller can act on rather than a
// timeout, a queue that grows until the process dies, or a goroutine per request
// with nothing counting them.
type Admission struct {
	slots chan struct{}

	mu       sync.Mutex
	inFlight map[string]int // op -> count, for diagnostics and drain
}

// NewAdmission bounds concurrency to max simultaneous operations.
//
// A CAP, NOT A QUEUE. Excess requests are refused immediately rather than
// buffered: a queue converts overload into latency, and a caller that has
// already given up is served by work nobody is waiting for. §7.1 rules out
// unbounded buffering for exactly this reason.
func NewAdmission(max int) *Admission {
	if max <= 0 {
		max = 1
	}
	return &Admission{
		slots:    make(chan struct{}, max),
		inFlight: make(map[string]int),
	}
}

// Acquire takes a slot, or refuses.
//
// Returns a release function that MUST be called — the usual shape is
// `defer release()` immediately after the error check.
//
// NON-BLOCKING. A blocking acquire would turn a concurrency cap into a queue by
// another name, and the caller's deadline would be spent waiting rather than
// working. Refusing immediately lets a client retry elsewhere or back off, which
// is information it can use.
func (a *Admission) Acquire(ctx context.Context, op string) (release func(), err error) {
	// Honour an already-cancelled context before taking a slot: admitting work
	// nobody is waiting for consumes capacity that live requests need.
	if err := ctx.Err(); err != nil {
		return nil, fault.Wrap(fault.KindTimeout, "gateway.Acquire", "context done", err)
	}

	select {
	case a.slots <- struct{}{}:
	default:
		return nil, fault.New(fault.KindRateLimited, "gateway.Acquire",
			"at concurrency limit; shedding load rather than queueing (§7.1)")
	}

	a.mu.Lock()
	a.inFlight[op]++
	a.mu.Unlock()

	var once sync.Once
	return func() {
		// Idempotent: a double release would free a slot twice and let
		// concurrency drift above the cap, which is worse than leaking one.
		once.Do(func() {
			a.mu.Lock()
			a.inFlight[op]--
			if a.inFlight[op] == 0 {
				delete(a.inFlight, op)
			}
			a.mu.Unlock()
			<-a.slots
		})
	}, nil
}

// InFlight reports current work by operation.
//
// D62'S P0 CONTINGENCY. §7.1 names the ugly case: "a command mid-side-effect
// must still get its audit outcome recorded". Drain cannot honour that without
// knowing whether anything is still running, and a drain that returns
// immediately because nothing counted the work is a drain in name only.
func (a *Admission) InFlight() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make(map[string]int, len(a.inFlight))
	for k, v := range a.inFlight {
		out[k] = v
	}
	return out
}

// Total is the sum across operations.
func (a *Admission) Total() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	var n int
	for _, v := range a.inFlight {
		n += v
	}
	return n
}

// Drain waits for in-flight work to finish, or for ctx to expire.
//
// RETURNS THE COUNT STILL RUNNING rather than an error on timeout, because the
// caller needs to log it: "drained with 3 commands still in flight" is the
// sentence that explains missing audit outcomes afterwards. An error would say
// only that something went wrong.
//
// Polls rather than using a condition variable — drain happens once per process
// lifetime, and a sync.Cond here would be machinery that runs never.
func (a *Admission) Drain(ctx context.Context, poll func()) int {
	for {
		if n := a.Total(); n == 0 {
			return 0
		}
		select {
		case <-ctx.Done():
			return a.Total()
		default:
			poll()
		}
	}
}
