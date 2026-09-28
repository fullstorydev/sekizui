// Capacity as a LEASE: the allocator, the narrowing ceiling, and the decay
// (D209, D210).
//
// **THIS FILE IS THE P7 MECHANISM RUNNING AT P2 WITH ONE INSTANCE, and that is
// The maintainer's constraint rather than an anticipation.** *"The last thing we want is
// 20 instances thinking they all have the same budget, so the mechanism for a
// shared budget in one instance should then also be extendable to the shared
// budget across instances"*, and *"the logic for P7 should already work at p2 as
// it's just 1/1 instances."*
//
// **SO 1-OF-1 IS THE DEGENERATE CASE, NOT A BYPASS.** The allocation path
// executes from P2 against a local allocator that hands back the whole
// configured budget; at P7 the implementation changes and the enforcement path
// does not. A skeleton switched off at one instance is one whose real path first
// executes in production, which is the shape §4.7.10 keeps naming.
//
// DESIGN.md references: §4.3.4, §5.2.1, D14, D142, D143, D147, D208, D209, D210,
// CONTRACTS items 11, 41, 43.
package limiter

import (
	"context"
	"log/slog"
	"time"

	"github.com/fullstorydev/sekizui/pkg/limiter"
)

// LocalAllocator hands each budget its whole configured capacity.
//
// **IT CANNOT SEE PEERS, AND THAT IS REPORTED RATHER THAN IMPLIED (CONTRACTS
// 41's treatment).** An operator running two replicas with this allocator has
// two instances each believing they hold the entire budget, so the fleet spends
// twice what was configured. That is not a defect in this type — it is what a
// local allocator MEANS — and the honest handling is the one break-glass already
// uses: say so at boot, so the limitation is chosen rather than discovered as
// 429s.
type LocalAllocator struct {
	budgets map[string]limiter.Allocation
}

var _ limiter.Allocator = (*LocalAllocator)(nil)

// NewLocalAllocator builds the 1-of-1 allocator from the same rates the limiter
// is built from.
//
// **THE SAME INPUT, DELIBERATELY.** Two sources for one number is how the
// allocator and the ceiling come to disagree, and the disagreement would be
// invisible: the narrowing rule below would silently clamp every allocation to a
// ceiling nobody meant to set.
func NewLocalAllocator(rates map[string]Rate) *LocalAllocator {
	a := &LocalAllocator{budgets: map[string]limiter.Allocation{}}
	for ref, r := range rates {
		if r.PerHour == 0 {
			continue
		}
		name := ref
		if r.Budget != "" {
			name = r.Budget
		}
		if _, seen := a.budgets[name]; seen {
			continue
		}
		// **`For: 0` — NO EXPIRY, WHICH IS THE HONEST ANSWER HERE.** A lease
		// expires so that an instance which has lost contact with a coordinator
		// stops assuming it still holds a share. There is no coordinator to lose
		// contact with, so an expiry would manufacture a decay this deployment
		// can never need and would throttle a single instance for no reason.
		a.budgets[name] = limiter.Allocation{PerHour: r.PerHour, Burst: r.Burst}
	}
	return a
}

func (a *LocalAllocator) Allocate(_ context.Context, budget, _ string) (limiter.Allocation, error) {
	return a.budgets[budget], nil
}

// Peers reports how many instances this allocator can see, and the local one
// sees none.
//
// EXISTS SO BOOT CAN SAY SO. `cmd/sekizui` logs the limitation at WARN when the
// allocator cannot see peers, which is CONTRACTS 41's treatment applied to the
// second piece of state that has the same problem.
func (a *LocalAllocator) Peers() int { return 0 }

// WithAllocator installs the capacity source and this instance's identity.
//
// **THE INSTANCE IDENTITY IS CARRIED FROM THE FIRST VERSION even though the
// local allocator ignores it (D209).** A lease belongs to a replica; adding the
// argument later would change every implementation, including out-of-tree ones
// D35 invites. Absent, this is CONTRACTS 43 repeating — a seam that is correct
// about the problem and cannot express the fix.
func WithAllocator(a limiter.Allocator, instance string) LocalOption {
	return func(l *Local) { l.alloc, l.instance = a, instance }
}

// WithFloorPercent sets the capacity an instance falls back to after k missed
// refreshes, as a percentage of the configured budget.
//
// **A SECURITY DIAL, NOT AN AVAILABILITY CONVENIENCE (D210).** Fleet GROWTH
// during an allocator outage is the exposure — shrinkage is safe, because
// everyone's share ends up too small — so a newcomer taking the floor rather
// than a full share is what bounds `partition + autoscale`. The same floor
// bounds the phantom-instance dilution attack, where unauthenticated fake
// instances shrink every real share until the fleet throttles itself.
func WithFloorPercent(pct int64) LocalOption {
	return func(l *Local) { l.floorNum = pct }
}

// missedRefreshesBeforeDecay is k.
//
// **THREE, AND THE NUMBER IS AN ARGUMENT ABOUT TIME RATHER THAN A CONSTANT.** By
// the time three refreshes have been missed a coordinator is not having a blip,
// it is down — which is a page, not a condition to ride out. Decaying sooner
// throttles a healthy fleet over one dropped packet; decaying later leaves the
// keep-last window open long enough for the fleet to have changed size underneath
// it.
const missedRefreshesBeforeDecay = 3

// Refresh re-reads every budget's allocation and applies it.
//
// **CALLED ON A CLOCK, NEVER PER COMMAND.** §5.2.1 rejects a coordinator hop on
// the command path and D147 gives the coordination node a one-sentence budget:
// agreement primitives only, never consulted synchronously per command. `Allow`
// stays local arithmetic; this is the only thing that talks to an allocator.
//
// **A FAILED REFRESH KEEPS THE LAST LEASE, THEN DECAYS (D210).** Keep-last is
// the only option that fails in neither direction. Reverting to the full budget
// is the twenty-instance case the budget exists to prevent; dropping everyone to
// a floor immediately is D143's over-throttling, a control an operator switches
// off. Keeping the last known share is right for a blip, and the decay is what
// bounds it in TIME rather than trusting the blip to end.
func (l *Local) Refresh(ctx context.Context) {
	if l.alloc == nil {
		return
	}

	l.mu.Lock()
	names := make([]string, 0, len(l.targets))
	for name := range l.targets {
		names = append(names, name)
	}
	l.mu.Unlock()

	failed := false
	for _, name := range names {
		// OUTSIDE THE LOCK. An allocator is a network call at P7, and holding
		// the limiter's mutex across it would stall every `Allow` in the process
		// for the length of somebody else's outage — which is the coordinator
		// dependency §5.2.1 refuses, arriving through a lock instead of a hop.
		got, err := l.alloc.Allocate(ctx, name, l.instance)
		if err != nil {
			failed = true
			continue
		}
		l.applyAllocation(name, got)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if !failed {
		l.missed = 0
		return
	}
	l.missed++
	if l.missed >= missedRefreshesBeforeDecay {
		l.decayToFloor()
	}
}

// applyAllocation narrows a budget to its lease.
func (l *Local) applyAllocation(name string, got limiter.Allocation) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.targets[name]
	if b == nil || got.PerHour == 0 {
		return
	}

	// **AN ALLOCATION MAY ONLY NARROW, NEVER WIDEN — THE LOAD-BEARING GUARD
	// (D210).** It came from the maintainer asking whether lease expiry could be used for
	// nefarious means, and the answer is that at P7 an allocation is an INPUT
	// FROM OUTSIDE THE PROCESS. Without a ceiling, spoofing the coordinator
	// removes the rate limit fleet-wide in one step — the control switched off
	// by the mechanism built to distribute it. D142's shape applied to a new
	// input: config is the ceiling, the runtime value may only tighten it.
	//
	// It also means lowering a budget in config takes effect immediately,
	// outstanding leases and all, which is the behaviour an operator editing a
	// limit during an incident expects.
	rate := float64(got.PerHour) / 3600
	if rate > b.configuredRate {
		rate = b.configuredRate
	}
	cap := int64(got.Burst)
	if cap <= 0 || cap > b.configuredCap {
		cap = b.configuredCap
	}

	b.perSec = rate
	b.capacity = cap
	if b.tokens > float64(cap) {
		b.tokens = float64(cap)
	}
}

// decayToFloor drops every budget to the floor. Called under the lock.
//
// **AN INSTANCE THAT NEVER HELD A LEASE USES THE FLOOR IMMEDIATELY**, which is
// the newcomer case and the one the floor exists for: a replica that starts
// during an allocator outage has no share to keep, and taking a full one is
// exactly the fleet-growth exposure D210 names.
func (l *Local) decayToFloor() {
	for _, b := range l.targets {
		floorRate := b.configuredRate * float64(l.floorNum) / 100
		floorCap := b.configuredCap * l.floorNum / 100
		if floorCap < 1 {
			floorCap = 1
		}
		if b.perSec > floorRate {
			b.perSec = floorRate
		}
		if b.capacity > floorCap {
			b.capacity = floorCap
			if b.tokens > float64(floorCap) {
				b.tokens = float64(floorCap)
			}
		}
	}
}

// StartRefresh runs Refresh on a ticker until ctx is done.
//
// A SEPARATE FUNCTION FROM `Refresh` so a test can drive one cycle without a
// clock, which is the same split `staleWatcher` and `churnWatcher` take.
func (l *Local) StartRefresh(ctx context.Context, every time.Duration, log *slog.Logger) {
	if l.alloc == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Refresh(ctx)
			l.mu.Lock()
			missed := l.missed
			l.mu.Unlock()
			if missed >= missedRefreshesBeforeDecay && log != nil {
				log.Warn("capacity allocator unreachable; budgets have decayed to the floor",
					"missed", missed, "floor_pct", l.floorNum,
					"note", "every budget is now a fraction of its configured rate until "+
						"the allocator answers again")
			}
		}
	}
}
