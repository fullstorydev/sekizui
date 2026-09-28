// Package spine owns process lifecycle: validation, ordered startup, readiness,
// and ordered shutdown.
//
// PRIVATE (D35). §4.10.3 wants "a readiness gate in front of the interceptor
// chain, driven by the same spine lifecycle state that feeds the probe" — one
// source of truth for whether this process can serve, rather than a health
// endpoint that answers optimistically because nothing told it otherwise
// (lexicon/index.js:140).
//
// ARCHITECTED AGAINST THE WHOLE PHASE PLAN, not just P0, because a lifecycle
// layer is expensive to retrofit. Three constraints come from phases far away:
//
//   - P3 exit 5, P5 exits 3 and 4 all say configuration errors are "rejected at
//     boot". So Validate is a SEPARATE PHASE that runs to completion before
//     anything starts — a process half-started and then failed is worse than one
//     that never started.
//   - P3 exit 3 requires kill -9 to resume "with no duplicates and no gaps",
//     which means the poller must stop before the cursor store closes. Hence
//     shutdown in REVERSE registration order.
//   - P8 brings leader election, where components start and stop MID-LIFE on
//     lease gain and loss. Start/Stop are therefore documented as repeatable.
//     Modelling them as start-once would be a rewrite at v2.
//
// DESIGN.md references: §4.5, §4.10.2, §4.10.3, §5.2.2, §12.0 principle 4, D50, D53.
package spine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Component is one subsystem with a lifecycle.
//
// START AND STOP MAY BE CALLED REPEATEDLY, IN ALTERNATION. P8's leader election
// stops components on lease loss and starts them again on re-acquisition, so an
// implementation that assumes a single start is wrong — it just is not wrong
// yet. Stop must leave the component startable.
//
// Start must NOT block for the component's lifetime: launch background work and
// return. Blocking would stall every later component and never reach readiness.
type Component interface {
	// Name identifies the component in logs, readiness output, and the init
	// ledger. Stable: it appears in operator-facing output.
	Name() string

	// Start begins work. Returns when the component is operational, not when
	// it is finished.
	Start(ctx context.Context) error

	// Stop releases resources and halts background work. Must be idempotent —
	// shutdown races and leader-election churn both call it more than once.
	Stop(ctx context.Context) error
}

// Validator is an OPTIONAL interface a Component may also satisfy.
//
// Everything that implements it is validated before ANYTHING starts. This is
// the mechanism behind the "rejected at boot" exit criteria: a cyclic subject
// namespace (P3), a cyclic reflex rule or one referencing an action its
// principal lacks (P5), an MCP action name contradicting its target (D49).
//
// Optional-interface-by-assertion is the same pattern as connector.Source
// alongside connector.Driver: capability is discovered with a type assertion
// rather than forced onto everyone via a no-op method.
type Validator interface {
	Validate(ctx context.Context) error
}

// Needs declares runtime capabilities a component requires.
//
// OPTIONAL, via CapabilityAware. Where a component needs something the profile
// does not offer, spine refuses at boot with the component named — rather than
// the component starting and silently failing to do its job, which is the exact
// failure §5.2.2 describes for the WAL shipper on Cloud Run.
type Needs struct {
	BackgroundWork   bool
	LocalDurableDisk bool
	LeaderElection   bool
}

// CapabilityAware is an OPTIONAL interface. Components with no environmental
// requirements simply do not implement it.
type CapabilityAware interface {
	Needs() Needs
}

// HealthReporter is an OPTIONAL interface for components whose health can
// change AFTER a successful start.
//
// STARTED IS NOT THE SAME AS HEALTHY, and conflating them was the original
// design error here: readiness was a boolean set once by Start and never
// revisited. Two later requirements make that untenable:
//
//   - D50 requires per-target readiness for MCP servers, where a target becomes
//     unusable at runtime through spec drift or unreachability — long after boot.
//   - P3's poller and P5's reflex engine are long-running. If one dies, nothing
//     notices, and /readyz keeps answering "ready" for a process that stopped
//     doing its job.
//
// A component with no runtime failure mode simply does not implement this, and
// counts as healthy for as long as it is started.
type HealthReporter interface {
	// Health returns nil when the component can do its job right now.
	//
	// Must be safe to call concurrently and should be cheap. Where a check
	// needs the network — an MCP tools/list comparison — the component caches
	// internally rather than making the probe pay for it, and consults
	// runtime.Profile.EagerValidation to decide whether a background refresh is
	// even possible (§4.9a.7).
	Health(ctx context.Context) error
}

// Planned is a subsystem that does not exist yet.
//
// D53 AND THE POINT OF THIS TYPE: early phases stand up the whole shape thinly,
// and the danger is that a skeleton reads as complete. Declaring the gaps means
// every boot prints exactly how much is missing, /readyz reports degraded, and
// the list lives in code that must be edited when something lands — unlike a
// checklist in a document, which drifts silently.
type Planned struct {
	// Name matches the Component name it will become, so the ledger entry is
	// replaced rather than duplicated when it lands.
	Name string

	// LandsIn is the phase: "P0", "P3", "P8".
	LandsIn string

	// Why is what it will do, in one operator-readable clause.
	Why string

	// ProvenBy names the acceptance steps whose completion RETIRES this entry.
	//
	// THE ENTRY HAS TO BE ABLE TO EXPIRE, and this is what makes it able to.
	// The comment above the ledger used to say a subsystem "lands by deleting
	// its Plan entry and calling Register instead, which is a change a compiler
	// and a reviewer both see". The compiler saw nothing: deleting the entry was
	// never required by anything, so `pool` and `limiter` landed in P1 steps 1-8
	// and 20-24 and their entries stayed — and /readyz reported DEGRADED for two
	// reasons that had stopped being true, one of which ("pkg/limiter's Limiter
	// and Breaker have no implementation") was flatly contradicted by the code
	// in the same binary.
	//
	// That is this codebase's recurring defect inverted: not a contract that
	// silently does nothing, but a DISCLAIMER that silently keeps applying. It
	// is worse than the usual form in one way — a readiness signal that
	// under-reports trains an operator to ignore it, which is D77's crying-wolf
	// failure pointed at the boot report.
	//
	// So the guard is the same shape as archcheck's `aheadOfItsPhase` (D139):
	// TestLedgerEntriesHaveNotLanded fails when every step named here is built,
	// and an entry in a phase that HAS a step table must name at least one.
	ProvenBy []int
}

// Spine sequences components through their lifecycle.
// Phase is where this process is in its lifecycle.
//
// **THREE STATES BECAUSE A PROBE NEEDS THREE ANSWERS, and one bool gave two
// (CONTRACTS 83).** `ready bool` could not tell NOT STARTED YET from STOPPING —
// both are "not serving" — so `/readyz` answered 503 "initializing" during a
// rollout, which is false at exactly the moment an operator is reading it. The
// direction is not inferable from a bool: `ready` is false before Start and
// false after Stop begins, and nothing in between records which way the process
// was travelling.
//
// **AN ENUM RATHER THAN A SECOND BOOL, so the impossible states cannot be
// written.** `started && stopping` and `!started && stopping-after-stopped` are
// both representable with two bools and mean nothing; a phase makes them
// unspellable, which is §6 mechanism 1's habit applied to a lifecycle instead
// of to a Target.
type Phase uint8

const (
	// PhaseInitializing — registered, and Start has not completed. Includes the
	// window where some components are up and others are not, which is why a
	// partial start unwinds rather than serving.
	PhaseInitializing Phase = iota

	// PhaseServing — Start completed without unwinding.
	PhaseServing

	// PhaseStopping — Stop has BEGUN. Readiness is already withdrawn and
	// components are draining; the process is still answering probes, which is
	// the whole point of dropping readiness first.
	PhaseStopping

	// PhaseStopped — Stop returned. Distinct from Stopping because a drain that
	// is still running and one that finished are different facts about whether
	// in-flight work may still be completing.
	PhaseStopped
)

func (p Phase) String() string {
	switch p {
	case PhaseServing:
		return "serving"
	case PhaseStopping:
		return "stopping"
	case PhaseStopped:
		return "stopped"
	default:
		return "initializing"
	}
}

type Spine struct {
	profile runtime.Profile
	log     *slog.Logger

	mu      sync.RWMutex
	comps   []Component
	planned []Planned
	started []Component // successfully started, in order; the stop list
	phase   Phase
}

// New constructs a Spine bound to a detected runtime profile.
func New(profile runtime.Profile, log *slog.Logger) *Spine {
	return &Spine{profile: profile, log: log}
}

// Register adds a component. Start order is registration order; stop order is
// its reverse, so register in dependency order — stores before their users.
func (s *Spine) Register(c Component) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.comps = append(s.comps, c)
}

// Plan declares a subsystem that does not exist yet (D53).
func (s *Spine) Plan(p Planned) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.planned = append(s.planned, p)
}

// Validate runs every capability check and every Validator, to COMPLETION,
// before anything starts.
//
// Deliberately collects all failures rather than returning the first. An
// operator fixing configuration wants the whole list, not one error per
// restart — and boot validation is precisely where a batch of problems is
// normal rather than exceptional.
func (s *Spine) Validate(ctx context.Context) error {
	const op = "spine.Validate"

	s.mu.RLock()
	comps := append([]Component(nil), s.comps...)
	s.mu.RUnlock()

	var problems []error

	for _, c := range comps {
		if ca, ok := c.(CapabilityAware); ok {
			if err := s.checkNeeds(c.Name(), ca.Needs()); err != nil {
				problems = append(problems, err)
			}
		}
	}

	for _, c := range comps {
		v, ok := c.(Validator)
		if !ok {
			continue
		}
		if err := v.Validate(ctx); err != nil {
			problems = append(problems, fault.Wrap(fault.KindConfig, op,
				fmt.Sprintf("component %q failed validation", c.Name()), err))
			continue
		}
		s.log.Debug("component validated", "component", c.Name())
	}

	if len(problems) > 0 {
		// errors.Join keeps every cause reachable through errors.Is/As while
		// printing them all — better than formatting them into one string,
		// which would discard the classifications.
		return fault.Wrap(fault.KindConfig, op,
			fmt.Sprintf("%d component(s) rejected at boot", len(problems)),
			errors.Join(problems...))
	}
	return nil
}

// checkNeeds refuses a component the environment cannot support.
func (s *Spine) checkNeeds(name string, n Needs) error {
	const op = "spine.checkNeeds"

	var missing []string
	if n.BackgroundWork && !s.profile.BackgroundWork {
		missing = append(missing, "background_work")
	}
	if n.LocalDurableDisk && !s.profile.LocalDurableDisk {
		missing = append(missing, "local_durable_disk")
	}
	if n.LeaderElection && !s.profile.LeaderElection {
		missing = append(missing, "leader_election")
	}
	if len(missing) == 0 {
		return nil
	}
	return fault.New(fault.KindConfig, op, fmt.Sprintf(
		"component %q requires %v, unavailable on %s/%s",
		name, missing, s.profile.Provider, s.profile.Execution))
}

// Start brings components up in registration order.
//
// ON PARTIAL FAILURE, ALREADY-STARTED COMPONENTS ARE STOPPED before returning.
// Leaving three of five running after a failed boot means a process that is
// neither up nor down, holding leases and file handles nothing will release.
func (s *Spine) Start(ctx context.Context) error {
	const op = "spine.Start"

	s.mu.RLock()
	comps := append([]Component(nil), s.comps...)
	s.mu.RUnlock()

	for _, c := range comps {
		if err := c.Start(ctx); err != nil {
			s.log.Error("component failed to start, unwinding",
				"component", c.Name(), "err", err)

			// Explicitly discarded. The START failure is the error worth
			// reporting; an unwind failure on top of it is noise that would
			// bury the cause. stopStarted logs each one at WARN, so nothing is
			// lost — and the `_ =` makes "ignored on purpose" visible rather
			// than looking like an oversight.
			_ = s.stopStarted(ctx)

			return fault.Wrap(fault.KindInternal, op,
				fmt.Sprintf("starting %q", c.Name()), err)
		}

		s.mu.Lock()
		s.started = append(s.started, c)
		s.mu.Unlock()

		s.log.Info("init step complete", "step", c.Name())
	}

	s.mu.Lock()
	s.phase = PhaseServing
	s.mu.Unlock()

	s.logLedger(ctx)
	return nil
}

// BeginStopping withdraws readiness WITHOUT stopping anything.
//
// **THE PRE-STOP HALF OF A GRACEFUL SHUTDOWN, and its absence was a real
// ordering defect rather than a missing convenience.** `Stop` records STOPPING
// before it stops components, which is correct and is also too late: the drain
// runs BEFORE Stop, so a process spent its entire drain window — the longest
// part of a shutdown, and the one with a grace period sized for it — still
// answering `/readyz` with "ready". Stop's own doc comment says "the load
// balancer must stop sending work before the process stops accepting it", and
// the sequence had it the other way around: work kept arriving while in-flight
// work was being waited on.
//
// So a shutdown now says STOPPING first, then drains, then stops components.
// That is the ordinary Kubernetes pattern — fail readiness, let the endpoints
// controller remove the pod, then finish what is in flight — and it is what
// makes `/readyz`'s stopping message reachable for more than milliseconds.
//
// IDEMPOTENT, AND IT NEVER MOVES BACKWARDS. Calling it after Stop has completed
// leaves the phase STOPPED rather than resurrecting a draining process, because
// a shutdown path that races with itself must not be able to un-finish.
func (s *Spine) BeginStopping() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.phase == PhaseStopped {
		return
	}
	s.phase = PhaseStopping
}

// Stop halts components in REVERSE registration order.
//
// Reverse because later components depend on earlier ones: the poller must stop
// before the cursor store closes, or P3's "no duplicates and no gaps across a
// kill -9" is unachievable.
//
// Readiness is dropped FIRST, so load balancers stop sending work before the
// process stops accepting it.
func (s *Spine) Stop(ctx context.Context) error {
	// **STOPPING IS RECORDED BEFORE A SINGLE COMPONENT IS ASKED TO STOP, which
	// is what makes the comment above a guarantee rather than a description.**
	// A component's own Stop can therefore observe the phase and know the
	// process is draining — and `/readyz` reports `stopping` from the first
	// instant rather than `initializing`, which is what CONTRACTS 83 was about.
	s.mu.Lock()
	s.phase = PhaseStopping
	s.mu.Unlock()

	err := s.stopStarted(ctx)

	s.mu.Lock()
	s.phase = PhaseStopped
	s.mu.Unlock()

	return err
}

func (s *Spine) stopStarted(ctx context.Context) error {
	s.mu.Lock()
	started := s.started
	s.started = nil
	s.mu.Unlock()

	var problems []error
	for i := len(started) - 1; i >= 0; i-- {
		c := started[i]
		if err := c.Stop(ctx); err != nil {
			s.log.Warn("component failed to stop cleanly", "component", c.Name(), "err", err)
			problems = append(problems, fmt.Errorf("%s: %w", c.Name(), err))
			continue
		}
		s.log.Debug("component stopped", "component", c.Name())
	}

	if len(problems) > 0 {
		return fault.Wrap(fault.KindInternal, "spine.Stop",
			"one or more components failed to stop cleanly", errors.Join(problems...))
	}
	return nil
}

// Phase reports where the process is in its lifecycle.
//
// THE CHEAP ANSWER: one field read under one RLock, no health poll. `/readyz`
// gates on this before calling Status, so a probe arriving during startup or a
// drain does not poll every component's health to discover the process is not
// serving.
func (s *Spine) Phase() Phase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.phase
}

// Started reports whether Start completed without unwinding.
//
// A LIVENESS answer, not a readiness one: it says the process got up, not that
// it is currently able to serve. Use Ready for the latter.
//
// DERIVED FROM Phase rather than stored beside it — two fields answering one
// question is how the two come to disagree, and this codebase has deleted a
// duplicate accessor for that reason before (`StaleCount` against
// `len(Stale())`). Note it is false while STOPPING, which is the same answer
// the previous `ready bool` gave and the reason a probe needs Phase to say
// which way the process is going.
func (s *Spine) Started() bool { return s.Phase() == PhaseServing }

// Ready reports whether this process can serve RIGHT NOW: started, and every
// HealthReporter currently healthy.
//
// Evaluated per call rather than cached. Health implementations are required to
// be cheap and to cache their own expensive work (see HealthReporter), because
// only the component knows what its check costs and whether the runtime profile
// permits refreshing it in the background.
//
// DELEGATES TO Status, WHICH IS THE ONE DERIVATION. The previous body computed
// the same predicate a second way — `Started()` plus a loop over CheckHealth —
// while Status computes `Ready = Started && no unhealthy component`. Two
// derivations of one answer is how the two come to disagree, and the type-
// resolved orphan guard is what surfaced it: this method has no non-test
// caller, and `Ready` as a bare name is matched by the `Ready` FIELD that
// /readyz actually reads.
//
// **/readyz READS Status, NOT THIS** — it needs `Degraded` and the unhealthy
// components' names for the body as well, so it takes the whole struct. The
// doc comment here used to claim "Feeds /readyz", which was the sort of thing
// that reads as a caller and is not one. The declared caller is the gate in
// front of the gRPC interceptor chain (§4.10.3), which wants the bare
// predicate.
func (s *Spine) Ready(ctx context.Context) bool { return s.Status(ctx).Ready }

// ComponentHealth is one component's current health.
type ComponentHealth struct {
	Name string
	Err  error // nil when healthy
}

// CheckHealth polls every started HealthReporter.
//
// Only STARTED components are polled: one that never started, or was unwound,
// has nothing meaningful to report and would otherwise show as unhealthy for
// the wrong reason.
func (s *Spine) CheckHealth(ctx context.Context) []ComponentHealth {
	s.mu.RLock()
	started := append([]Component(nil), s.started...)
	s.mu.RUnlock()

	var out []ComponentHealth
	for _, c := range started {
		h, ok := c.(HealthReporter)
		if !ok {
			continue // no runtime failure mode; healthy while started
		}
		out = append(out, ComponentHealth{Name: c.Name(), Err: h.Health(ctx)})
	}
	return out
}

// Status is the operator-facing view: what is running, what is unhealthy, and
// what is not built.
type Status struct {
	// Phase is where the process is in its lifecycle. It replaced a `Started`
	// FIELD: a bool could not distinguish "not started yet" from "stopping",
	// so a readiness probe during a rollout reported `initializing`
	// (CONTRACTS 83).
	Phase Phase

	// Ready is the readiness answer. It differs from `Started()` exactly when a
	// started component reports itself unhealthy.
	Ready bool

	Implemented []string
	Planned     []Planned

	// Unhealthy lists started components currently failing their own check.
	Unhealthy []ComponentHealth
}

// Started reports whether Start completed without unwinding.
//
// A METHOD RATHER THAN A FIELD, so it cannot drift from Phase — the same reason
// Degraded below is a method over `Planned` rather than a bool somebody sets.
func (st Status) Started() bool { return st.Phase == PhaseServing }

// Degraded reports whether subsystems remain unbuilt. Ready and Degraded are
// independent: the process genuinely serves what it has, while being honest
// that the shape is incomplete.
func (st Status) Degraded() bool { return len(st.Planned) > 0 }

// Status snapshots the current lifecycle state, including a health poll.
func (s *Spine) Status(ctx context.Context) Status {
	s.mu.RLock()
	impl := make([]string, 0, len(s.comps))
	for _, c := range s.comps {
		impl = append(impl, c.Name())
	}
	st := Status{
		Phase:       s.phase,
		Implemented: impl,
		Planned:     append([]Planned(nil), s.planned...),
	}
	s.mu.RUnlock()

	// Outside the lock: Health implementations are third-party-ish code that
	// may block, and holding s.mu across them would stall Register, Stop, and
	// every concurrent probe.
	for _, h := range s.CheckHealth(ctx) {
		if h.Err != nil {
			st.Unhealthy = append(st.Unhealthy, h)
		}
	}
	st.Ready = st.Started() && len(st.Unhealthy) == 0
	return st
}

// logLedger prints the init summary — §4.10.2's "one line rather than an
// inference", extended by D53 to include what has NOT been built.
//
// Planned entries log at WARN deliberately. INFO would let them scroll past as
// routine; the point is that an incomplete process should be slightly annoying
// to run.
func (s *Spine) logLedger(ctx context.Context) {
	st := s.Status(ctx)

	for _, p := range st.Planned {
		s.log.Warn("init step SKIPPED — not implemented",
			"step", p.Name, "lands_in", p.LandsIn, "will", p.Why)
	}

	total := len(st.Implemented) + len(st.Planned)
	if st.Degraded() {
		missing := make([]string, 0, len(st.Planned))
		for _, p := range st.Planned {
			missing = append(missing, p.Name)
		}
		s.log.Warn("readiness DEGRADED — skeleton incomplete",
			"implemented", fmt.Sprintf("%d/%d", len(st.Implemented), total),
			"missing", missing)
		return
	}
	s.log.Info("all subsystems implemented", "count", len(st.Implemented))
}
