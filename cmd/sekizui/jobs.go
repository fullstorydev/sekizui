package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/internal/kyuushin"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/internal/translate"
	"github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// buildJobRunner assembles the job runner and the cursor store behind it.
//
// **ONE RUNNER FOR BOTH TRIGGERS, WHICH IS D249 ARRIVING AT THE WIRING SITE.**
// A caller's `StartJob` and a schedule's tick reach the same `kyuushin.Runner`
// through the same gate, so there is one set of bounds and one place to forget
// a check. Two constructors here — one per trigger — would be the split D249
// refused, rebuilt below the line where anybody would notice.
//
// `jobs` is the CONFIGURED RECURRENCES, and it is legitimately empty: a gateway
// serves jobs on demand and schedules none. §12.0's guardrail against a
// skeleton that silently succeeds at nothing has not gone away — it moved here
// as `refuseIngestWithNothingToPoll`, which is the only layer that knows the
// deployment's purpose (D252).
func buildJobRunner(doc *config.Document, reg *schemareg.Registry, jobs []kyuushin.Job, b bus.Bus,
	gate kyuushin.Gate, auditPath string, log *slog.Logger) (*kyuushin.Runner, error) {

	const op = "main.buildJobRunner"

	// THE FIRST STAGE COMES FROM CONFIGURATION, never a literal. `translate.New`
	// refuses an empty one rather than defaulting to "raw", because a stage
	// nobody designed is one D21's monotonicity check has never heard of.
	if len(doc.Stages) == 0 {
		return nil, fault.New(fault.KindConfig, op,
			"no stages configured: every polled event would land in a subject "+
				"namespace nobody designed")
	}
	tr, err := translate.New(doc.Stages[0], safestruct.DefaultBudget)
	if err != nil {
		return nil, err
	}

	// **THE CURSOR DIRECTORY SITS BESIDE THE AUDIT CHAIN, which is where this
	// deployment already keeps spine-owned state** — `<auditPath>.withdrawn`
	// (D145) and `<auditPath>.credver` (D152) are the precedents. A separate
	// flag would be a third path an operator has to get right for a directory
	// that is only written by a RECURRENCE: a one-shot job leaves no cursor at
	// all (D249), so a gateway never touches it.
	store := cursor.NewFileStore(filepath.Join(filepath.Dir(auditPath), "cursors"))

	// THE REGISTRY THE RUNNER SHAPES AND VALIDATES EVERY ENVELOPE AGAINST
	// (D276, D279) — the connectors' own schemas and the document's, the same
	// set boot's schema check read, so a payload is held at runtime to exactly
	// what was reviewed at install.
	return kyuushin.New(jobs, store, tr, b, gate, log, kyuushin.Options{
		NewID:    newEnvelopeID(),
		Payloads: reg,
		// FROM THE DOCUMENT (D268): how long a finished job's results wait for
		// the caller who asked, bounded at boot to a day.
		ResultsTTL: doc.Jobs.ResultsTTL(),
	})
}

// newEnvelopeID mints envelope identifiers.
//
// **THE SAME SHAPE `auditwal.newSequentialID` USES, AND DELIBERATELY NOT
// SHARED WITH IT.** A decision id and an envelope id are different namespaces
// with different readers, and one generator would make `dec_...` and `env_...`
// draw from a counter whose gaps then mean nothing. What they DO share is the
// property that matters: unique within a process lifetime and ordered within
// it, with the process-start prefix keeping two runs apart.
//
// §4.6.1d wants a ULID. `kyuushin.Options.NewID` is the seam that lets it
// become one without touching the runner, which is why it is an option rather
// than a literal inside the package.
func newEnvelopeID() func() string {
	var (
		mu      sync.Mutex
		counter uint64
		prefix  = fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	)
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		counter++
		return fmt.Sprintf("env_%s_%06d", prefix, counter)
	}
}

// refuseIngestWithNothingToPoll is §12.0's guardrail, at the layer that can
// mean it (D252).
//
// **THE CHECK USED TO LIVE IN `kyuushin.New` AND WAS READING THE WRONG
// FACT.** It refused an empty job list, reasoning that "an ingest deployment
// with nothing to poll is a process that reports healthy and does nothing" —
// true, and the job list is not how you tell an ingest deployment from a
// gateway. A gateway serving `StartJob` configures no recurrences at all, so
// the constructor was refusing its most ordinary caller. The mode is known
// here and nowhere below, so the refusal belongs here.
func refuseIngestWithNothingToPoll(mode runtime.Mode, jobs []kyuushin.Job) error {
	if mode != runtime.ModeIngest || len(jobs) > 0 {
		return nil
	}
	return fault.New(fault.KindConfig, "main.refuseIngestWithNothingToPoll",
		"-mode=ingest with no sources configured: this process would elect a "+
			"leader, report healthy and poll nothing. Configure at least one "+
			"source, or run -mode=gateway, which serves jobs on demand and "+
			"schedules none")
}

// jobDrainer stops the job runner on shutdown.
//
// **REGISTERED BEFORE THE LISTENER SO IT STOPS AFTER IT.** `spine.Stop` runs
// components in reverse registration order, and the order matters in both
// directions here: the listener must stop first so no new job is accepted, and
// the audit sink must stop last so a job finishing during the drain can still
// record what it did. A runner stopped after the sink would do its final work
// into a closed log, which is the one outcome §5.4 cannot tolerate.
//
// **A COMPONENT RATHER THAN A LINE IN THE DRAIN PATH**, because the runner does
// not exist when the drain path is written: it is built inside the listener's
// builder, and `enforcementWiring` is this file's only honest way to reach it.
type jobDrainer struct {
	wiring *enforcementWiring
	log    *slog.Logger

	mu sync.Mutex
}

// Name identifies this component in the init ledger and readiness output.
func (d *jobDrainer) Name() string { return "kyuushin:drain" }

// Start does nothing: the runner is started by whoever built it, and a
// recurrence with no schedule has nothing to begin.
//
// PRESENT BECAUSE `spine.Component` REQUIRES IT, and empty rather than absent
// so the asymmetry is visible — this component exists for its Stop.
func (d *jobDrainer) Start(context.Context) error { return nil }

// Stop drains in-flight jobs.
func (d *jobDrainer) Stop(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.wiring == nil || d.wiring.jobs == nil {
		// NOT AN ERROR, for churnWatcher's reason: a deployment can legitimately
		// reach here with no enforcement stack built.
		return nil
	}
	// **A JOB OUTLIVES THE CONNECTION THAT ASKED FOR IT (D247), SO SOMETHING
	// HAS TO OUTLIVE IT IN TURN.** Without this, a process told to stop would
	// exit with work in flight against a vendor, holding a borrowed credential,
	// and the audit log's last word on that job would be its intent row.
	return d.wiring.jobs.Stop(ctx)
}

// scheduleRunner starts and stops the configured recurrences (D266).
//
// SEPARATE FROM `jobDrainer` BECAUSE THE TWO WANT OPPOSITE ENDS OF THE ORDER.
// The drainer is registered BEFORE the listener so it stops after it, letting
// in-flight caller jobs finish. The schedule is registered AFTER the reflex
// engine so it starts once every rule is listening and stops before any rule
// does — with `StopSchedule`, which leaves caller jobs to the drainer.
type scheduleRunner struct {
	wiring *enforcementWiring
}

// Name identifies this component in the init ledger and readiness output.
func (r *scheduleRunner) Name() string { return "kyuushin:schedule" }

// Start loads every source's cursor — an unreadable one FAILS THE BOOT (D150),
// because an absent cursor is that source replayed from its beginning — and
// starts the loops.
func (r *scheduleRunner) Start(ctx context.Context) error {
	if r.wiring == nil || r.wiring.jobs == nil {
		return nil
	}
	return r.wiring.jobs.Start(ctx)
}

// Stop cancels the recurrences and waits for the tick in progress — NOT for
// caller jobs, which `jobDrainer` waits for after the listener has stopped
// accepting more. `Runner.Stop` would wait for both, here, while the listener
// is still up.
func (r *scheduleRunner) Stop(ctx context.Context) error {
	if r.wiring == nil || r.wiring.jobs == nil {
		return nil
	}
	return r.wiring.jobs.StopSchedule(ctx)
}
