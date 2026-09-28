package kyuushin

import (
	"context"
	"fmt"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// tick is one poll, from the cursor to the commit.
//
// **THE ORDER IS THE WHOLE PROPERTY AND IT IS THE ONE A REASONABLE
// IMPLEMENTATION GETS BACKWARDS**, because advancing the cursor first is what
// the code reads like:
//
//	load cursor -> admit -> poll -> validate -> BEGIN (ids recorded) ->
//	translate -> publish -> COMMIT
//
// Commit before the envelopes are durable and a crash in between loses rows
// nothing can reconstruct — you cannot deduplicate your way to data you never
// fetched (D170). Commit after, and a crash re-delivers, which the recorded
// ids make skippable. **We choose duplicate-over-gap and then remove the
// duplicate ourselves**, which is the half of exit criterion 3 that is ours —
// and since D275 the code does what this sentence says: the publish mark lets a
// recovery skip exactly what was published, where it used to skip everything
// at risk and record nothing.
//
// Returns whether the source made progress, which is what the melt guard reads.
func (p *Runner) run(ctx context.Context, j Job, root string) (progressed bool, published int, err error) {
	const op = "kyuushin.tick"
	ref := j.Target.Ref()

	// **A ONE-SHOT JOB HAS NO CURSOR, AND THAT IS THE SPLIT D249 NAMED.** The
	// cursor answers "where did I leave off", which only a RECURRENCE asks. A
	// caller who asked once gets the window the source defines and nothing is
	// remembered on their behalf.
	var st cursor.State
	if j.recurring() {
		var lerr error
		st, lerr = p.store.Load(ctx, ref)
		if lerr != nil {
			return false, 0, lerr
		}
	}

	// **ADMITTED BEFORE EVERY POLL, NEVER CACHED.** A grant suspended at
	// runtime (D146) or a target quarantined by anzen must stop the NEXT tick,
	// not the next restart — and a cached admission is a decision made before
	// the thing that revoked it happened.
	if aerr := p.gate.Admit(ctx, j.identityForAdmission(), j.Action(), ref); aerr != nil {
		return false, 0, aerr
	}

	// **RECOVERY, BY THE CONNECTOR'S DECLARED POLICY (D174, D241, D275).** A
	// pending attempt means the last poll did not commit. The spine knows
	// that; the connector declared what re-reading costs. So:
	//
	//   requery  — re-read the window from where the attempt began, and skip
	//              ONLY what the mark says was published before the stop. The
	//              rest is published now: exactly once, save the one envelope
	//              that may have been in flight at the crash.
	//   unable   — or past the declared lookback: the unpublished events are
	//              RECORDED AS A GAP, by name, and the poll resumes after the
	//              lost window.
	//
	// **THIS REPLACES A SILENT LOSS.** The runner used to skip every at-risk id
	// and record nothing, under a comment claiming duplicate-over-gap.
	already := map[string]bool{}
	note := ""
	if st.Pending != nil {
		pend := *st.Pending
		done := pend.Published
		if done > len(pend.IDs) {
			done = len(pend.IDs)
		}
		pol := j.Driver.Recovery(j.Target)
		why := pol.Why
		recoverable := pol.Mode == connector.RecoveryRequery
		if recoverable && pol.MaxLookback > 0 && p.opts.Now().Sub(pend.At) > pol.MaxLookback {
			recoverable = false
			why = fmt.Sprintf("the attempt is %s old and this source re-reads at most %s back — %s",
				p.opts.Now().Sub(pend.At).Round(time.Second), pol.MaxLookback, pol.Why)
		}
		if recoverable {
			for _, id := range pend.IDs[:done] {
				already[id] = true
			}
			note = fmt.Sprintf("; recovering an interrupted poll: %d of %d at-risk event(s) were "+
				"published before it stopped", done, len(pend.IDs))
		} else {
			lost := pend.IDs[done:]
			// **NOTHING AT RISK IS NOTHING LOST.** A stop after the last mark and
			// before the commit left every event published; a gap record then
			// says "0 event(s) may never have been delivered" about a window
			// that lost nothing — a false alarm in the one log an operator
			// trusts, and it wrote one on every such restart (P3 step 3).
			if len(lost) == 0 {
				p.log.Info("an interrupted poll had published every event before it stopped; "+
					"nothing was lost", "source", ref, "events", len(pend.IDs))
			} else if gerr := p.gate.Gap(ctx, j.identityForAdmission(), j.Action(), ref, lost, pend, why); gerr != nil {
				return false, 0, fault.Wrap(fault.KindInternal, op,
					"recording the gap an interrupted poll left", gerr)
			}
			if cerr := p.commit(ctx, j, pend.To); cerr != nil {
				return false, 0, fault.Wrap(fault.KindInternal, op, "committing past the recorded gap", cerr)
			}
			st.Cursor, st.Pending = pend.To, nil
		}
	}

	events, next, err := p.poll(ctx, j, st.Cursor)
	if err != nil {
		return false, 0, err
	}

	// **THE CONTRACT CHECK RUNS ON EVERY TICK, not only in the suite.** A
	// driver that never ran `RunSource` still reaches this, which is the whole
	// argument for one definition of conforming with two callers (D243).
	violations := connector.ValidatePoll(st.Cursor, j.Limit, events, next)
	if len(violations) > 0 {
		p.tally.Record(ref, violations)
	}

	// TRUNCATE RATHER THAN REFUSE. The rows are already fetched; refusing the
	// batch would lose the ones that were fine, and D177's reasoning applies —
	// the side effect has happened, so record completely rather than pretend.
	if len(events) > j.Limit {
		events = events[:j.Limit]
	}

	// AN EMPTY WINDOW IS ORDINARY AND IS PROGRESS. A source with nothing new
	// is the steady state, and counting it as a stall would stop every quiet
	// source after three ticks.
	//
	// **IT STILL REACHES `record`, AND THE FIRST VERSION OF THIS DID NOT.** It
	// returned here, so the heartbeat could only ever be written by a poll
	// that produced something — which meant a source with nothing new was
	// never recorded at all, and the heartbeat was a mechanism that existed
	// and did nothing. That is the defect class this repository keeps finding,
	// in the guard written to prevent the very failure it was inert against.
	// Caught by the arm that asserts a due heartbeat is written.
	if len(events) == 0 {
		p.record(ctx, j, 0)
		return true, 0, nil
	}

	// NO PROGRESS: rows returned and the cursor unchanged. Do NOT publish them
	// — publishing a window we cannot advance past is the melt happening once
	// per tick — and do not commit. It is still recorded on the heartbeat, or
	// a source stalling its way to a stop leaves nothing in the log to explain
	// why the data stopped arriving.
	if next == st.Cursor {
		p.record(ctx, j, 0)
		return false, 0, nil
	}

	// WHAT THIS ATTEMPT WILL PUBLISH: everything fetched, less what a
	// recovered attempt's mark says already reached the bus.
	toPublish := make([]connector.RawEvent, 0, len(events))
	ids := make([]string, 0, len(events))
	for _, e := range events {
		if already[e.ID] {
			continue
		}
		toPublish = append(toPublish, e)
		ids = append(ids, e.ID)
	}

	// **THE IDS ARE WRITTEN BEFORE PUBLISHING, WHICH LOOKS BACKWARDS AND IS
	// THE POINT.** Writing them afterwards records what was published, which
	// is the question nobody can answer after a crash. Written first they
	// record what was AT RISK — so a restart knows the exact set that may or
	// may not have reached a consumer, and the gap marker can name the events
	// rather than describe a window.
	att := cursor.Attempt{From: st.Cursor, To: next, IDs: ids, At: p.opts.Now().UTC()}
	if berr := p.begin(ctx, j, att); berr != nil {
		// A POLL THAT CANNOT RECORD ITS ATTEMPT DOES NOT PROCEED (D150). An
		// attempt nobody wrote down is a crash whose losses cannot be named.
		return false, 0, fault.Wrap(fault.KindInternal, op,
			"recording the attempt before publishing", berr)
	}

	// **THE POLL'S INTENT, BEFORE ANYTHING IS PUBLISHED (P3 step 7, D272)**,
	// so every envelope can name the decision it was produced under — joinable
	// to the log, where the outcome says how many were published. A poll that
	// cannot write it does not proceed, for the same reason `begin` above does
	// not (D150): envelopes citing a row that does not exist are worse than
	// envelopes citing none.
	// A RECOVERY IS RECORDED EVEN WHEN NOTHING IS LEFT TO PUBLISH (P3 step 3).
	// Without the intent, a recovered window whose every event had already
	// reached the bus fell through to `record(len(events))` — a
	// `poll:completed` claiming the fetched events again, which reads exactly
	// like the re-delivery the recovery just prevented.
	var pollDecision string
	if atRisk := len(toPublish); atRisk > 0 || note != "" {
		id, berr := p.gate.Begin(ctx, j.identityForAdmission(), j.Action(), ref, atRisk, note)
		if berr != nil {
			return false, 0, fault.Wrap(fault.KindInternal, op,
				"recording the poll's intent before publishing", berr)
		}
		pollDecision = id
	}

	declared := declaredOutputs(j)
	for i, e := range toPublish {
		// **SHAPED TO ITS DECLARATION BEFORE ANYTHING ELSE SEES IT (D277).** An
		// undeclared kind becomes its skeleton, a declared kind loses the
		// property names it does not declare — so what was removed never
		// reaches the translator, the bus, or the recorder. What it revealed
		// is the operator's to act on, not the connector's fault.
		shaped, report := p.opts.Payloads.Shape(e.Type, e.Data)
		e.Data = shaped
		p.gaps.Record(ref, report)
		if report.Refused() {
			p.log.Warn("refusing an event of an undeclared kind", "source", ref, "kind", report.Kind)
			if perr := p.progress(ctx, j, i+1); perr != nil {
				return false, published, perr
			}
			continue
		}
		env, _, terr := p.trans.Translate(e, j.Target, p.opts.NewID(), "", root)
		// **DECLARED, AND CONFORMING, OR NOT PUBLISHED (D276).** The type must
		// be one the poll action declares, and the payload must match its
		// schema — and, for a discriminated type, its kind's. A failure is ONE
		// event's (D177): tallied as a violation, marked handled, never
		// published, and the rest of the batch goes on.
		if terr == nil {
			var v *connector.PollViolation
			switch {
			case !declared[env.GetType()]:
				v = &connector.PollViolation{Kind: connector.PollUndeclaredType, Detail: fmt.Sprintf(
					"event %q is of type %q, which %s does not declare", e.ID, env.GetType(), j.Action())}
			default:
				if verr := p.opts.Payloads.Validate(env.GetType(), env.GetData().AsMap()); verr != nil {
					v = &connector.PollViolation{Kind: connector.PollNonconformingPayload,
						Detail: fmt.Sprintf("event %q: %v", e.ID, verr)}
				}
			}
			if v != nil {
				p.tally.Record(ref, []connector.PollViolation{*v})
				p.log.Warn("refusing to publish a nonconforming event", "source", ref, "violation", v.String())
				if perr := p.progress(ctx, j, i+1); perr != nil {
					return false, published, perr
				}
				continue
			}
		}
		if terr == nil {
			env.Causation.DecisionId = pollDecision
		}
		if terr != nil {
			// ONE BAD EVENT DOES NOT DISCARD THE BATCH. D177's rule at the
			// event level: the others are fine and dropping them silently is
			// the selective, invisible loss.
			p.tally.Record(ref, []connector.PollViolation{{
				Kind:   connector.PollViolationUnknown,
				Detail: fmt.Sprintf("event %q could not be translated: %v", e.ID, terr),
			}})
			if perr := p.progress(ctx, j, i+1); perr != nil {
				return false, published, perr
			}
			continue
		}
		// A CALLER'S JOB PUBLISHES TO ITS CALLER, A SCHEDULE TO THE BUS (D267).
		publish := p.bus.Publish
		if j.sink != nil {
			publish = j.sink.Publish
		}
		if perr := publish(ctx, env); perr != nil {
			// **THE COUNT SO FAR TRAVELS WITH THE FAILURE (D177).** A job that
			// published four envelopes and then failed published four;
			// reporting zero because it ended badly would describe a rollback
			// that did not happen.
			return false, published, fault.Wrap(fault.KindInternal, op, "publishing "+e.ID, perr)
		}
		// THE MARK, AFTER THE PUBLISH (D275): recovery trusts it, so a crash
		// between this envelope's publish and its mark re-publishes it — one
		// duplicate, never a loss. A mark that cannot be written stops the
		// poll: publishing on past a mark that no longer tracks is exactly the
		// state the mark exists to make impossible.
		if perr := p.progress(ctx, j, i+1); perr != nil {
			return false, published + 1, perr
		}
		// COUNTED HERE RATHER THAN FROM `len(events)`, because the two differ
		// and the difference is the honest part: a skipped id (at-most-once,
		// D24) and an untranslatable event (D177) are both in `events` and
		// neither reached a consumer.
		published++
	}

	if cerr := p.commit(ctx, j, next); cerr != nil {
		return false, published, fault.Wrap(fault.KindInternal, op, "committing the cursor", cerr)
	}
	if pollDecision != "" {
		// THE INTENT'S OUTCOME, after the commit — the moment the poll's work is
		// durable — carrying the count actually published (D177).
		if ferr := p.gate.Complete(context.WithoutCancel(ctx), pollDecision, published); ferr != nil {
			p.log.Error("the poll's outcome was not recorded", "source", ref, "decision", pollDecision,
				"error", ferr)
		}
		p.markRecorded(ref)
	} else {
		p.record(ctx, j, len(events))
	}
	return true, published, nil
}

// record writes the decision for a completed poll, or lets the heartbeat carry
// it.
//
// **RECORDED AFTER THE COMMIT, NOT BEFORE.** A record saying a poll produced
// eleven events, written before the cursor moved, describes a poll that a
// crash would then repeat — so the log would carry it twice and the second
// would be indistinguishable from a real re-delivery. The commit is what makes
// the poll a fact.
// markRecorded resets the heartbeat clock for a source whose poll was recorded
// as an intent and outcome rather than through record (D272).
func (p *Runner) markRecorded(ref string) {
	p.mu.Lock()
	p.lastRecord[ref] = p.opts.Now()
	p.mu.Unlock()
}

func (p *Runner) record(ctx context.Context, j Job, events int) {
	ref := j.Target.Ref()

	p.mu.Lock()
	// THE ZERO TIME MAKES THE FIRST POLL ALWAYS DUE, and that is wanted rather
	// than incidental: "polling of this source began at T" is the record an
	// operator looks for first, and a source whose very first poll went
	// unrecorded would be one the log never mentions until it produces
	// something — which may be never.
	last := p.lastRecord[ref]
	due := events > 0 || p.opts.Now().Sub(last) >= p.opts.HeartbeatEvery
	if due {
		p.lastRecord[ref] = p.opts.Now()
	}
	p.mu.Unlock()

	if !due {
		return
	}
	if err := p.gate.Record(ctx, j.identityForAdmission(), j.Action(), ref, events); err != nil {
		// **A FAILED RECORD DOES NOT FAIL THE POLL, and the asymmetry is
		// deliberate.** §5.2.2 makes losing a record the one unacceptable
		// failure, which argues the other way — but the rows are already
		// published by here, so refusing now would tell nobody anything and
		// would lose the NEXT poll too. What it must not do is pass silently.
		p.log.Error("the poll decision was not recorded", "source", ref, "error", err)
	}
}

// poll calls the driver with the spine's bounds around it (D243).
//
// **THE DEADLINE IS THE SPINE'S AND THE PANIC IS RECOVERED HERE.** A driver
// that blocks for ever stops only itself; a driver that panics takes its own
// source down and not the process. Neither is configurable away, because a
// badly written connector must not melt a deployment that wrote no rule.
func (p *Runner) poll(ctx context.Context, j Job, from string) (
	events []connector.RawEvent, next string, err error,
) {
	const op = "kyuushin.poll"

	// **THE TENANT ON THE CONTEXT, FOR THE EGRESS ASSERTION THE DRIVER MAKES
	// IMMEDIATELY BEFORE ITS OUTBOUND CALL (§6 mechanism 3).** `Execute` binds
	// it at step 8 from the resolved target, and this is the afferent plane's
	// same moment: a pooled client belonging to another tenant is caught by
	// comparison rather than trusted.
	//
	// **IT WAS MISSING, AND THE SYMPTOM WAS A JOB THAT RAN PERFECTLY AND
	// DELIVERED NOTHING.** `kata.Poll` calls `connector.AssertTenant` — the
	// reference driver refuses to skip it on a read, because D155's lesson is
	// that a read path omitting a check becomes a second enforcement path one
	// omission at a time. So every poll failed the assertion, the failure went
	// to a WARN log inside the goroutine, and the caller saw a job id and an
	// empty stream. **The check worked; the path that was supposed to satisfy
	// it did not exist**, which is the same shape from the other side and the
	// reason the reference driver asserting on reads earns its keep.
	//
	// Bound HERE rather than in `run`, so it sits adjacent to the call it
	// protects and no future branch can reach the driver around it.
	ctx = connector.WithTenant(ctx, j.Target.Tenant())

	// **`context.WithTimeout` ON THE CALL, not a client timeout** — it composes
	// with the parent, so a shutdown cancels an in-flight poll rather than
	// waiting out the budget (GO-PRIMER §15t).
	pollCtx, cancel := context.WithTimeout(ctx, p.opts.PollTimeout)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			// THE STACK IS NOT PROPAGATED TO THE CALLER, and the source stops.
			// A driver that panics once will panic again on the same window,
			// so continuing to poll it is a loop with a log line.
			p.stop(j.Target.Ref(), fmt.Sprintf("driver panicked during Poll: %v", r))
			err = fault.New(fault.KindInternal, op, fmt.Sprintf(
				"the %s driver panicked polling %s: %v", j.Target.Kind(), j.Target.Ref(), r))
			events, next = nil, from
		}
	}()

	started := p.opts.Now()
	events, next, err = j.Driver.Poll(pollCtx, j.Target, from, j.Limit)
	if err != nil {
		return nil, from, err
	}

	// **A DRIVER THAT RETURNED AFTER ITS DEADLINE IGNORED THE CONTEXT**, which
	// is a contract violation rather than slowness — and the two are
	// distinguishable exactly here, because we own the clock (D243).
	if p.opts.Now().Sub(started) > p.opts.PollTimeout {
		p.tally.Record(j.Target.Ref(), []connector.PollViolation{{
			Kind: connector.PollViolationUnknown,
			Detail: fmt.Sprintf("returned after the %v deadline, so it did not honour the "+
				"cancelled context; the spine's bound cannot bound it", p.opts.PollTimeout),
		}})
	}
	return events, next, nil
}

// begin and commit are no-ops for a one-shot, because there is no cursor to
// advance. Kept as named methods rather than inline conditionals so the
// recurrence-only half of the machinery is visible in one place (D249).
func (p *Runner) begin(ctx context.Context, j Job, a cursor.Attempt) error {
	if !j.recurring() {
		return nil
	}
	return p.store.Begin(ctx, j.Target.Ref(), a)
}

// declaredOutputs is the job's declared output set (D276).
func declaredOutputs(j Job) map[string]bool {
	out := make(map[string]bool, len(j.Outputs))
	for _, typ := range j.Outputs {
		out[typ] = true
	}
	return out
}

// progress writes the publish mark for a recurrence (D275). A one-shot job has
// no cursor, so nothing to recover and nothing to mark.
func (p *Runner) progress(ctx context.Context, j Job, n int) error {
	if !j.recurring() {
		return nil
	}
	if err := p.store.Progress(ctx, j.Target.Ref(), n); err != nil {
		return fault.Wrap(fault.KindInternal, "kyuushin.progress", "writing the publish mark", err)
	}
	return nil
}

func (p *Runner) commit(ctx context.Context, j Job, next string) error {
	if !j.recurring() {
		return nil
	}
	return p.store.Commit(ctx, j.Target.Ref(), next)
}
