package drift

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// Watcher compares each spec-described target's live surface against its vetted
// spec, in the background (D50's live half, D197's response, D206).
//
// **THE THIRD SIGNAL SOURCE, AND DELIBERATELY THE SAME SHAPE AS THE OTHER TWO.**
// `staleWatcher` and `churnWatcher` both turn a condition nothing else would
// notice into the LEVEL the dispatcher latches on, and this is the third: a
// vendor changing its tool list is invisible to every other mechanism here,
// because nothing in the command path reads a tool list.
//
// **IN `internal/` RATHER THAN `cmd/`, WHICH IS WHERE ITS TWO SIBLINGS LIVE,
// AND THE REASON IS TESTABILITY OF THE WIRING.** A component in `package main`
// can only be driven by re-implementing what it does, and P2 step 12 has to
// prove that an unreachable server leaves the process UP with THAT TARGET not
// ready — a claim about this loop, not about a sequence a test performed by
// hand. D155 is the standing lesson: the second copy of a sequence drifts from
// the first, silently. So the loop lives where the acceptance suite can start
// it, and `cmd/sekizui` only registers it.
//
// **WHY A BACKGROUND POLL RATHER THAN A CHECK INSIDE `Describe`.** D50 splits
// offline validation from live comparison, and the live half must not sit on a
// request path: a Describe that reached out to every MCP server would make an
// agent's capability listing as slow and as failure-prone as the least reliable
// vendor in the deployment, and one unreachable server would deny an agent the
// list of everything else it may do. So the comparison runs on a clock and the
// readers see the last known answer, with `Checked` and both timestamps saying
// how old it is.
type Watcher struct {
	store *Store
	every time.Duration
	log   *slog.Logger

	// deps is evaluated at Start, not at construction.
	//
	// **A CLOSURE RATHER THAN THE FIELDS, because the resolver does not exist
	// yet when this is registered.** Spine registration order is start order, so
	// a component must be registered before the enforcement stack that builds
	// the resolver — `gateway.NewListener` takes a builder function for exactly
	// this reason and is the precedent. Its two siblings share a mutable struct
	// instead, which works and reads worse: a nil field at Start is a race you
	// have to reason about, while a closure returning zero values is a value you
	// can check.
	deps func() Deps

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Deps is what a comparison needs, resolved at Start.
type Deps struct {
	// Resolver is how a `connector.Target` is obtained. Shared with the
	// enforcement path rather than constructed here: §6 mechanism 1 makes a
	// Target unconstructable anywhere else, and a second resolver would be a
	// second credential cache and a second residency view.
	Resolver Resolver

	// Drivers is the registered set, asked per target for the optional
	// Reporter interface.
	Drivers map[string]connector.Driver

	// Targets is what the document declares.
	Targets []config.TargetSpec

	// Observer takes the signal's level. Nil means nothing consumes it, which
	// is legitimate — a deployment can run with no anzen rules — and the
	// comparison still feeds the catalog and readiness.
	Observer Observer

	// Gate admits and RECORDS every comparison (D311): the same ceilings a poll
	// passes, and a decision record per comparison — clean, diverged or failed.
	// REQUIRED BY Start; nil is accepted only by Check, for fixtures that test
	// the comparison and not its record.
	Gate Gate
}

// Gate is the enforcement path's half of a comparison (D311). It is implemented
// by the gateway, which owns the ceilings and the recorder; this package only
// says what happened.
//
// **A COMPARISON IS AN OUTBOUND CALL MADE WITH THE TARGET'S CREDENTIAL**, so it
// is admitted and recorded like the other one Sekizui makes unasked — a poll
// (P3 step 5). Until D311 it was neither: the state lived in memory and a clean
// result left no trace anywhere.
type Gate interface {
	// Admit runs the ceilings for the built-in drift principal against one
	// target, RECORDING a refusal itself (it knows which stage refused).
	Admit(ctx context.Context, targetRef string) error

	// Record writes the comparison's decision record.
	Record(ctx context.Context, targetRef string, c Comparison) error
}

// Outcome is what one comparison concluded.
type Outcome string

// The three outcomes a comparison records. CLEAN is recorded too: a check that
// found nothing is still a check that happened, and its absence from the log
// is indistinguishable from a watcher that never ran.
const (
	OutcomeClean    Outcome = "clean"
	OutcomeDiverged Outcome = "diverged"
	OutcomeFailed   Outcome = "failed"
)

// Comparison is one comparison's result, as the gate records it.
type Comparison struct {
	Outcome  Outcome
	Findings Findings
	Err      error

	// Persisted reports whether the resulting state reached the state file; a
	// record saying it did not is how an operator learns a restart would lose it.
	Persisted bool
}

// Resolver is the narrow slice of the resolver a comparison needs.
type Resolver interface {
	Resolve(ctx context.Context, ref string) (connector.Target, error)
}

// Observer is the narrow slice of anzen's dispatcher a signal needs.
//
// AN INTERFACE RATHER THAN `*anzen.Dispatcher`, so this package does not depend
// on anzen to publish to it — and so a test can capture what was published
// without building a rule set. The signature is `Observe`'s exactly, because a
// paraphrase is how the two come to disagree.
type Observer interface {
	Observe(ctx context.Context, signal string, subjects map[string]string) []string
}

// NewWatcher builds the poll loop. Nothing happens until Start.
func NewWatcher(store *Store, every time.Duration, log *slog.Logger, deps func() Deps) *Watcher {
	return &Watcher{store: store, every: every, log: log, deps: deps}
}

// Name identifies this component in the init ledger and readiness output.
func (w *Watcher) Name() string { return "anzen:drift-watcher" }

// Start begins the poll loop.
//
// **IT DOES NOT GATE THE BOOT, and that is step 12's other half.** An
// unreachable MCP server leaves the process up with THAT TARGET not ready;
// getting it backwards would make one vendor's outage prevent an instance from
// starting, including every target that has nothing to do with it.
func (w *Watcher) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	d := w.deps()
	if d.Resolver == nil {
		// NOT AN ERROR, AND SAID OUT LOUD, for `staleWatcher`'s reason: a
		// deployment can legitimately reach here — `-mode=ingest` builds no
		// enforcement stack — and refusing the boot would turn a watcher into a
		// requirement.
		w.log.Info("anzen drift-watcher idle: no enforcement stack was built",
			"signal", "spec_drift")
		return nil
	}

	// **THE TARGETS THAT REPORT DRIFT AT ALL, named at boot.** A deployment with
	// no spec-described target has nothing to compare, and a watcher that said
	// nothing would be indistinguishable from one that was broken. D53's rule
	// applied to a poll loop: say what is NOT being watched.
	watched := watchable(d)
	if len(watched) == 0 {
		w.log.Info("anzen drift-watcher idle: no target's driver reports spec drift, so "+
			"there is nothing to compare against a vetted spec",
			"signal", "spec_drift", "targets", len(d.Targets))
		return nil
	}

	// **A WATCHER THAT WOULD RECORD NOTHING DOES NOT START (D311).** Every
	// comparison is an outbound call with a credential; running them unrecorded
	// is the gap D311 closed, and a deployment wired without the gate must fail
	// here rather than compare in silence.
	if d.Gate == nil {
		return fmt.Errorf("anzen drift-watcher: %d target(s) to compare and no gate to record "+
			"the comparisons — every comparison is an outbound call with a credential and must "+
			"leave a decision record (D311)", len(watched))
	}

	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	w.cancel = cancel
	w.done = make(chan struct{})

	w.log.Info("anzen drift-watcher watching spec-described targets",
		"signal", "spec_drift", "targets", len(watched), "every", w.every.String())

	go w.loop(loopCtx, d)
	return nil
}

// watchable returns the targets whose driver reports drift.
//
// **THE OPTIONAL INTERFACE, ASKED PER TARGET (GO-PRIMER §2.2).** `kata` and
// `fullstory` implement a fixed action set in code, so there is no vetted spec
// for a vendor to diverge from and nothing to compare — they are not asked
// rather than being asked and answering nil.
func watchable(d Deps) []config.TargetSpec {
	var out []config.TargetSpec
	for _, t := range d.Targets {
		if _, reports := d.Drivers[t.Kind].(Reporter); reports {
			out = append(out, t)
		}
	}
	return out
}

func (w *Watcher) loop(ctx context.Context, d Deps) {
	defer close(w.done)

	// **CHECKED IMMEDIATELY, THEN ON THE TICK.** Waiting a whole interval before
	// the first comparison would leave every spec-described target UNVERIFIED
	// for that long after a deploy — which is exactly when an operator is
	// watching, and exactly when a spec is most likely to be wrong. Done in the
	// goroutine and not in Start, because a slow or unreachable vendor must not
	// hold up the boot.
	w.Check(ctx, d)

	t := time.NewTicker(w.every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Check(ctx, d)
		}
	}
}

// Check compares every watched target once and reports the signal's CURRENT
// LEVEL.
//
// EXPORTED so an acceptance step can drive one comparison deterministically
// rather than waiting for a tick — the same reason `retry.WithClock` and
// `limiter.WithLocalClock` exist. The loop calls exactly this, so a step
// driving it is driving the production sequence.
//
// **A LEVEL, NOT AN EVENT, and the dispatcher fires on the edge (D158).** Drift
// persists until somebody re-vets a spec or the vendor restores the tool, so a
// per-tick event would attempt a response every interval, on every replica, for
// as long as the divergence lasted. Reporting the level and letting the
// dispatcher latch turns one condition into one response.
//
// **KEYED BY SUBJECT, because a rule acts on the target IT names (D134).** The
// lesson `staleWatcher` paid for: a signal with no subject dimension fires
// every rule watching it, so one target's divergence would quarantine a
// different, healthy target — and a latch keyed on the signal alone becomes a
// per-signal SILENCER, where one target stuck diverged means a second target's
// divergence produces no edge and no response at all.
func (w *Watcher) Check(ctx context.Context, d Deps) {
	diverged := map[string]string{}

	for _, t := range watchable(d) {
		reporter, ok := d.Drivers[t.Kind].(Reporter)
		if !ok {
			continue
		}

		// ADMITTED FIRST, as a poll is (D311): withdrawal, residency and anzen
		// can each refuse, and the gate records which one did.
		if d.Gate != nil {
			if err := d.Gate.Admit(ctx, t.Ref); err != nil {
				w.store.RecordFailure(t.Ref, err, time.Now())
				w.log.Debug("drift comparison refused before it ran", "target", t.Ref, "err", err)
				continue
			}
		}

		target, err := d.Resolver.Resolve(ctx, t.Ref)
		if err != nil {
			// **RESOLUTION FAILING IS NOT DRIFT EITHER.** A refused residency, a
			// credential that will not resolve, a quarantined target — all of
			// them stop the comparison and none of them is a statement about the
			// vendor's tool list. Recorded as a failed attempt so an operator can
			// see the comparison is not running, rather than seeing a target that
			// looks verified because nothing contradicted it.
			w.store.RecordFailure(t.Ref, err, time.Now())
			w.log.Debug("drift comparison skipped: the target would not resolve",
				"target", t.Ref, "err", err)
			w.record(ctx, d, t.Ref, Comparison{Outcome: OutcomeFailed, Err: err})
			continue
		}

		// THE TARGET'S TENANT, BOUND AS A POLL BINDS IT (kyuushin's tick), so the
		// connector's egress assertion — §6 mechanism 3 — has something to check
		// against; unbound, every comparison would refuse as "no tenant" (D311).
		findings, err := reporter.Drift(connector.WithTenant(ctx, target.Tenant()), target)
		if err != nil {
			w.store.RecordFailure(t.Ref, err, time.Now())
			w.log.Warn("drift comparison failed; the target's last known state is kept",
				"target", t.Ref, "err", err)
			w.record(ctx, d, t.Ref, Comparison{Outcome: OutcomeFailed, Err: err})
			continue
		}
		if rerr := w.store.Record(t.Ref, findings, time.Now()); rerr != nil {
			// An unknown severity. The driver produced something the vocabulary
			// does not grade, and recording it would read as a finding and act as
			// nothing (see Store.Record).
			w.log.Error("drift comparison produced an ungradeable finding",
				"target", t.Ref, "err", rerr)
			w.record(ctx, d, t.Ref, Comparison{Outcome: OutcomeFailed, Findings: findings, Err: rerr})
			continue
		}
		outcome := OutcomeClean
		if len(findings) > 0 {
			outcome = OutcomeDiverged
		}
		w.record(ctx, d, t.Ref, Comparison{Outcome: outcome, Findings: findings})

		// **ONLY THE ACTIONABLE SEVERITIES RAISE THE SIGNAL, and the two that do
		// not are the point of the vocabulary.** `unvetted` is the supply-chain
		// WIN made visible — a vendor shipped a tool and it is not callable until
		// a human vets it — and `informational` is an output-schema change. An
		// anzen rule that quarantined a target because the vendor ADDED a tool
		// would be D77's crying wolf with a credential revocation attached, and a
		// control that fires on routine vendor housekeeping is one somebody
		// switches off. So the signal carries what withholds or refuses.
		st, _ := w.store.Of(t.Ref)
		if st.Degraded() || st.Refused() {
			diverged[t.Ref] = summarise(t.Ref, findings)
		}
	}

	if len(diverged) > 0 {
		w.log.Warn("targets diverge from their vetted specs; spec_drift is RAISED",
			"targets", len(diverged))
	}
	if d.Observer != nil {
		d.Observer.Observe(ctx, "spec_drift", diverged)
	}
}

// record hands one comparison to the gate, with whether its state persisted.
// A record that cannot be written is logged at ERROR: the comparison happened,
// and the log line is then the only trace of it.
func (w *Watcher) record(ctx context.Context, d Deps, ref string, c Comparison) {
	perr := w.store.PersistErr()
	c.Persisted = perr == nil
	if perr != nil {
		w.log.Error("drift state could not be persisted; a restart would forget it",
			"target", ref, "err", perr)
	}
	if d.Gate == nil {
		return
	}
	if err := d.Gate.Record(ctx, ref, c); err != nil {
		w.log.Error("drift comparison could not be recorded", "target", ref,
			"outcome", string(c.Outcome), "err", err)
	}
}

// summarise renders one target's actionable findings for the signal detail.
func summarise(ref string, fs Findings) string {
	withheld := fs.Withheld()
	switch {
	case fs.RefusesTarget():
		return fmt.Sprintf("%s: the inputSchema a human approved is not the one the server "+
			"will act on (%d finding(s)); the target is refused", ref, len(fs.Of(SeverityRefused)))
	case len(withheld) > 0:
		return fmt.Sprintf("%s: %d vetted tool(s) the server no longer offers, withheld from "+
			"the catalog: %v", ref, len(withheld), withheld)
	default:
		return ref
	}
}

// Stop halts the loop. Idempotent, because shutdown races call it twice.
func (w *Watcher) Stop(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cancel == nil {
		return nil
	}
	w.cancel()
	<-w.done
	w.cancel = nil
	return nil
}
