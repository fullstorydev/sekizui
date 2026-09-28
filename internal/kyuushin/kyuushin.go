// Package kyuushin is the afferent path: the job runner, cursors and the
// translation that fills the bus (求心, centripetal — inward, D66).
//
// # ONE MECHANISM, TWO TRIGGERS (D249)
//
// A JOB is the unit. Either a caller asks for one, or a SCHEDULE fires — and a
// recurring job is simply a job whose caller is configuration. "Run the gold
// transformation overnight" and "poll Jira every thirty seconds" are one shape
// at two intervals.
//
// **THIS WAS TWO SUBSYSTEMS FOR ONE EXCHANGE, AND THE CORRECTION IS THE
// USEFUL PART.** The poller was justified as serving "sources that cannot be
// asked" — which sounded like a fact about the world and is false: Jira has an
// API and an MCP server, BigQuery takes SQL, and asking is precisely what
// polling does. §4.2.1's real sentence is that Jira cannot TELL us anything.
// So the schedule exists for the third initiator — nobody asks and we look
// anyway — whose only genuine consumer is an unattended reflex at P5. Splitting
// it from the job would have produced two admission paths, two sets of bounds
// and two places to forget the same check, which is D18's twelve words and the
// shape D155 records.
//
// Shared by both triggers: the gate, the bounds, the tally, the heartbeat, the
// decision record. Belonging only to a RECURRENCE: the cursor, the stall
// detector, the schedule.
//
// **THE INWARD IS THE DATA, NOT THE CONNECTION.** A poller REACHES OUT to
// fetch, so `Source.Poll` dials a vendor exactly as `Execute` does. That is why
// the egress controls are not this package's to invent (D245) and why it
// borrows its client from the pool rather than holding one: a poller with a
// private client is invisible to revocation, and `revoke_credential` would
// evict the pool, report what it cancelled, and leave an in-flight poll running
// on a compromised credential. **That is P1 step 68's hole on the afferent
// plane, and a poll repeats on a timer.**
//
// # A SOURCE IS A PRINCIPAL (the maintainer's ruling)
//
// `source:<target ref>`, authorised exactly like an agent. D18 already settles
// the principle for the other automatic actor — *"a reflex is a principal like
// any other; none is a bypass"* — and applying it here is what gives the
// afferent plane everything the command plane has for free: an anzen ceiling
// that reaches polls, `revoke_grant` suspending ONE source at runtime (D146), a
// decision record that names who polled, and quarantine stopping it.
//
// **THE COST IS STATED RATHER THAN HIDDEN: a deployment must write a grant per
// source or nothing polls.** That is the same bargain every capability here
// makes, and the alternative — one built-in ingest principal — buys less
// configuration and loses per-source break-glass, which is the control an
// operator reaches for at 03:00.
//
// **AND IT APPLIES TO THE SCHEDULE ONLY (D250).** A job somebody ASKED for
// runs as the asker, because the alternative charges that deployment a second
// grant for a principal nobody asked about, names the wrong actor on the audit
// row, and leaves criterion 17 unprovable. See Job.Submitter.
//
// # What the spine bounds, unconditionally (D243)
//
// Truncate at `limit`; a deadline on every poll; a recovered panic stops that
// source and not the process; a source that keeps handing back the cursor it
// was given stops being polled. **None of these is configurable away**, because
// a badly written connector must not melt a deployment that never wrote an
// anzen rule. What IS configurable is the report: violations are tallied and
// published as a level a rule can watch.
//
// DESIGN.md references: §4.2.1, §5.2.3, §12 P3, D18, D24, D53, D66, D128, D146,
// D171, D173, D174, D243, D245.
package kyuushin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/internal/translate"
	"github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Gate is the enforcement seam every poll passes through.
//
// **AN INTERFACE RATHER THAN A DIRECT CALL INTO `internal/gateway`, and NOT to
// keep options open.** The poller lives below the gateway in the import graph;
// calling up would be a cycle. What matters is that it is REQUIRED — a poller
// constructed without one does not start, so "the poll is governed" cannot
// become something a wiring change quietly drops (D149's required-parameter
// shape).
//
// The implementation is the gateway's shared ceiling sequence, which is the
// same code `Enforce` and `Query` call. D18 forbids a second one and D155 is
// the record of what a second one costs.
type Gate interface {
	// Admit authorises this identity to perform this action on this target,
	// or refuses with a deliberate fault. Called BEFORE every poll, never
	// cached.
	//
	// THE ACTION IS PASSED RATHER THAN IMPLIED, because a poll is an ordinary
	// advertised action — `<kind>.poll` — and not a governed verb: it is
	// served THROUGH a driver, which is exactly the line `internal/verb`
	// draws. So the grant reads like every other grant, D196's
	// implemented-action check applies unchanged, and the catalog advertises
	// which targets are pollable.
	//
	// **AN IDENTITY RATHER THAN A PRINCIPAL STRING, AND THE DIFFERENCE IS A
	// WHOLE POLICY STAGE (D250).** It took a `principal string` until a
	// caller's job could reach it, at which point the string became lossy in
	// a way that only ever widens: D59 decides `caller ∩ subject, strictest
	// wins`, so an `agent:triage` speaking for `human:alice` is TWO principals
	// and a string is one. Rebuilding an identity from it yields a chain of
	// one — the intersection silently dropped, the job admitted against a
	// broader question than the gateway asked seconds earlier. That is
	// `ceilings`' own story from the other end: not a check removed, but a
	// narrowing quietly not carried across a seam.
	//
	// NIL MEANS A SCHEDULE FIRED THIS, with no caller to carry. The
	// implementation constructs the `source:<ref>` identity then, the way
	// `reflex.IdentityFor` does for a rule.
	Admit(ctx context.Context, id *sekizuiv1.Identity, action, targetRef string) error

	// Record writes the decision record for a COMPLETED poll.
	//
	// **NOT CALLED ONCE PER TICK, AND THAT IS A DECISION RATHER THAN AN
	// OPTIMISATION.** Ten sources on a thirty-second interval is ~29,000
	// records a day, almost all of them "polled, nothing new" — which is
	// D178's disk amplification with Sekizui as the hostile party, on a
	// schedule. So the poller records a poll that PRODUCED something, every
	// REFUSAL (which the implementation writes from Admit, where the decision
	// was made), and a periodic HEARTBEAT.
	//
	// **THE HEARTBEAT IS WHAT MAKES THE OMISSION SAFE.** Without it a quiet
	// source and a stopped source are indistinguishable in the log, which is
	// the exact failure the melt guard exists to prevent one layer up — the
	// process healthy, other sources flowing, and one table silently not
	// arriving. D147 reaches for per-replica heartbeats for the same reason.
	//
	// **THE IDENTITY, NOT THE PRINCIPAL, FOR A REASON THE `Admit` ARGUMENT
	// ONLY HALF COVERS.** It took a principal string, and an implementation
	// then had to build an identity to put on the decision — a chain of one,
	// naming the subject and dropping the delegation that produced it. D39
	// embeds the identity WHOLE into every Decision precisely so the row
	// answers who asked, and `agent:triage on behalf of human:alice` is the
	// case where the whole is the point. Found by `archcheck`'s identity-minter
	// registry (CONTRACTS 90) refusing the site that was rebuilding it.
	Record(ctx context.Context, id *sekizuiv1.Identity, action, targetRef string, events int) error

	// Begin writes the INTENT for a productive poll, before its envelopes are
	// published, and returns the decision id each envelope then cites (P3
	// step 7, D272). The poll's end closes it through Finish, with the count
	// published — so a crash between leaves an intent with no outcome, which is
	// the truth: those events were at risk, and the cursor's attempt names them.
	Begin(ctx context.Context, id *sekizuiv1.Identity, action, targetRef string, atRisk int,
		note string) (string, error)

	// Gap records a DECLARED LOSS (D174, D275): an interrupted poll whose
	// source cannot re-read the window, naming the events that may never have
	// been delivered. Written by the spine — the connector only DECLARED it
	// could not recover — and it fails the poll if it cannot be written,
	// because a loss nobody can see is the one outcome worse than the loss.
	Gap(ctx context.Context, id *sekizuiv1.Identity, action, targetRef string,
		lost []string, a cursor.Attempt, why string) error

	// Complete closes a productive poll's intent with the count published.
	//
	// **ITS OWN METHOD, NOT Finish.** The first version reused Finish, which
	// writes the same kind of outcome — and the runner's tests refused it at
	// once, counting every productive poll as a JOB ENDING and a recurrence
	// as having ended twice. Finish means "a job ended"; a poll completing is
	// a different event, and one word for both is how a log starts lying.
	Complete(ctx context.Context, decisionID string, published int) error

	// Finish closes the decision a caller's job was admitted under, saying
	// how it ended.
	//
	// **A JOB WHOSE END IS UNOBSERVABLE IS THE MELT IN A DIFFERENT COAT**
	// (P3 criterion 15). `StartJob` writes an INTENT before submitting —
	// §5.2.2's rule that an action about to happen is recorded before it
	// happens — and until this existed nothing ever wrote the other half, so
	// every job in the log read as one that had been authorised and then
	// vanished.
	//
	// **`events` IS PASSED EVEN WHEN IT IS ZERO, AND THAT IS THE WHOLE
	// POINT.** The pair that actually gets conflated is FAILED and
	// FINISHED-WITH-NOTHING-TO-SAY: both produce no envelopes, and a log that
	// cannot tell them apart tells an operator the wrong thing at the moment
	// they most need the right one. A non-nil `cause` is the failure; the
	// count is what makes the success legible.
	//
	// **A COUNT SURVIVES A FAILURE TOO** (D177): a job that published four
	// envelopes and then failed published four envelopes, and recording zero
	// because it ended badly would describe a rollback that did not happen.
	//
	// CALLED ONLY FOR A JOB A CALLER ASKED FOR. A recurrence has no end and
	// no intent row to close; its per-poll records and its heartbeat are what
	// answer "is this still running" (D249's split).
	Finish(ctx context.Context, decisionID string, events int, cause error) error
}

// Job is one unit of work: what to run, as whom, and — when recurring — how
// often.
//
// **NAMED `Job` RATHER THAN `Source`, AND THAT REMOVED A COLLISION nobody had
// noticed**: it sat one import away from `connector.Source`, the driver
// interface, meaning something entirely different. One name, two referents —
// the class this repository found three times in a single day.
type Job struct {
	// Target is resolved and authorised before it gets here.
	Target connector.Target

	// Driver is the thing that implements Poll for this target's kind.
	Driver connector.Source

	// Every is the recurrence interval. A caller-triggered job leaves it zero
	// and runs once — not yet built, and the field is where that difference
	// will live rather than a second type.
	Every time.Duration

	// Limit is how many events one poll may ask for, and therefore the
	// caller's memory budget rather than a hint (D243).
	Limit int

	// Outputs are the payload types the poll action DECLARES (D276), set by
	// whoever built the job from the driver's ActionSpec. An event of any other
	// type is refused, per event — so an empty set refuses everything, which is
	// the right reading of "declared nothing".
	Outputs []string

	// Identity is WHO ASKED for this job, nil when a schedule fired it.
	//
	// **THE JOB RUNS AS WHOEVER ASKED FOR IT (D250), AND THE FIELD EXISTS
	// BECAUSE `Principal()` USED TO ANSWER `source:<ref>` FOR BOTH TRIGGERS.**
	// Three things were wrong with that once a caller could submit one. The
	// deployment would have needed a SECOND grant — the caller's to start the
	// job, a synthetic source principal's to do the work — and the failure
	// arrived asynchronously, after `StartJob` had already returned OK. The
	// audit row named `source:kata:alpha` when the question §5.4 exists to
	// answer is which AGENT asked. And P3 criterion 17 says a job cannot
	// outlive its authorisation, which cannot hold when the authorisation
	// being suspended belongs to a principal the job never ran as.
	//
	// **`source:<ref>` IS NOT RETIRED, IT IS NARROWED TO ITS REAL CASE.** A
	// schedule has no caller, so D249's "configuration is the caller" needs a
	// principal to name, and the maintainer's source-is-a-principal ruling is what gives
	// an unattended poll an anzen ceiling, a per-source `revoke_grant` and a
	// decision record. Two triggers, two honest answers, one field.
	//
	// **AN IDENTITY RATHER THAN THE PRINCIPAL STRING IT STARTED AS**, for the
	// reason spelled out on Gate.Admit: the string cannot carry a delegation
	// chain, so D59's intersection would be dropped on the way in. Storing the
	// principal beside it would be two fields answering one question, which is
	// the shape D153 corrected for `RotatableLive` — so `Principal()` derives.
	Identity *sekizuiv1.Identity

	// DecisionID is the audit row that admitted this job, empty when a
	// schedule fired it.
	//
	// **CARRIED SO THE JOB'S END CAN CLOSE ITS OWN BEGINNING.** The gateway
	// writes an intent before submitting and hands the caller its id; without
	// it here the runner would have to write a fresh terminal row, and the
	// log would hold an orphaned intent beside an unrelated outcome — two
	// rows about one job that nothing joins, which is worse than one row that
	// is merely incomplete.
	DecisionID string

	// sink is where this job's envelopes go. Set by Submit to the job's own
	// Results for a caller's job (D267); nil for a schedule, which publishes
	// to the bus.
	sink interface {
		Publish(ctx context.Context, env *sekizuiv1.Envelope) error
	}
}

// Principal is the identity this job runs as: whoever asked, or the source
// itself when a schedule fired it (D250).
//
// **NEITHER ANSWER IS CONFIGURED, AND THAT IS THE PROPERTY WORTH KEEPING.**
// The caller's principal arrives from a verified mTLS peer and the schedule's
// is derived from the target ref, so a grant reads "source:kata:alpha may poll
// kata:alpha" and cannot name a principal that does not correspond to
// anything. Same reasoning as D146's `principal:agent:crawler` target ref: the
// name of the thing being governed is not a free-text field.
func (j Job) Principal() string {
	if p := j.Identity.GetSubject().GetPrincipal(); p != "" {
		return p
	}
	// ONE DEFINITION, shared with boot validation of `sources:` (D266), so the
	// grant it checks and the principal admitted here cannot drift apart.
	return config.SourcePrincipal(j.Target.Ref())
}

// identityForAdmission is what this job is admitted under: the caller's own
// identity, or one constructed for the source when a schedule fired it.
//
// CONSTRUCTED HERE RATHER THAN BY THE GATE, so the two triggers hand the
// enforcement path the same kind of thing and the adapter has no branch to get
// wrong. Mirrors `reflex.IdentityFor`, including why the assertion is ASSERTED
// rather than SIGNED: nothing cryptographic happened, and recording SIGNED
// would put a false provenance statement in the audit trail (D57).
func (j Job) identityForAdmission() *sekizuiv1.Identity {
	if j.Identity != nil {
		return j.Identity
	}
	p := j.Principal()
	return &sekizuiv1.Identity{
		Caller: &sekizuiv1.Caller{
			Principal: p,
			// AUTH_METHOD_INTERNAL rather than UNSPECIFIED, for the reason
			// reflex.IdentityFor gives: both mean "no certificate was
			// verified", and only one of them distinguishes a deliberate
			// in-process actor from a field somebody forgot to populate.
			Method:       sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL,
			CredentialId: "schedule:" + j.Target.Ref(),
		},
		Subject: &sekizuiv1.Subject{
			Principal: p,
			Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED,
		},
		Chain: []string{p},
	}
}

// Action is what a poll is authorised against: the driver's advertised
// `<kind>.poll`.
//
// DERIVED, NOT CONFIGURED, for the same reason the principal is — the name of
// the thing being governed is not a free-text field, and a mismatch between
// what a grant says and what the poller asks for would refuse every poll with
// a message about a missing grant.
func (j Job) Action() string { return j.Target.Kind() + ".poll" }

// recurring reports whether a schedule fires this job, as opposed to a caller
// asking for it once. The cursor, the stall detector and the schedule belong
// to a recurrence and to nothing else (D249).
func (j Job) recurring() bool { return j.Every > 0 }

// Submit runs a job ONCE, now, and returns the id its results will carry.
//
// **THE ID IS ALSO THE CAUSATION ROOT OF EVERY ENVELOPE THE JOB PRODUCES**, so
// a caller subscribes and filters on `causation.root_id` rather than needing a
// field on the envelope that would mean nothing on a polled one (D247).
//
// **IT IS RE-ADMITTED, AND THIS COMMENT USED TO SAY IT WAS NOT.** It read
// "already admitted by the caller, and deliberately not re-admitted here",
// reasoning that re-checking as `source:<ref>` would ask a different question
// about a different principal — which was TRUE of the question and FALSE of
// the code six lines away: `run` has always called `gate.Admit` on every poll,
// unconditionally. Both tests passed because the fake gate admits everything,
// so nothing pinned either reading. The repairing half is D250: the job runs
// as the CALLER, so the second admission asks the SAME question of the SAME
// principal and the contradiction dissolves rather than being chosen between.
//
// Cheap, and not redundant: it is the same call a recurrence makes every tick,
// which is what keeps one mechanism rather than two (D249).
func (p *Runner) Submit(ctx context.Context, j Job) (string, error) {
	const op = "kyuushin.Submit"
	if j.Driver == nil || j.Limit <= 0 {
		return "", fault.New(fault.KindInvalidArgument, op,
			"a job needs a source driver and a positive limit")
	}
	id := p.opts.NewID()

	// **THE JOB OUTLIVES THE CONNECTION THAT ASKED FOR IT (D247), so it must
	// NOT inherit the RPC's context** — that is cancelled when the response is
	// written, which would kill every job at the moment it was accepted.
	// `WithoutCancel` keeps the values and drops the cancellation
	// (GO-PRIMER §15ai), and the runner's own lifetime bounds it instead.
	jobCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	// THE RESULTS ARE ADDRESSED TO THE CALLER (D267), created before the job
	// starts so a caller attaching the moment Submit returns finds them.
	results := newResults(j.Limit)
	j.sink = results

	p.mu.Lock()
	if p.running == nil {
		p.running = map[string]context.CancelFunc{}
	}
	p.running[id] = cancel
	if p.results == nil {
		p.results = map[string]*Results{}
	}
	p.results[id] = results
	p.mu.Unlock()

	// **RECORDED AS RUNNING BEFORE THE GOROUTINE STARTS, NOT INSIDE IT.** A
	// caller can hold the job id the moment `Submit` returns, and a status
	// written by the worker would leave a window in which the answer to "how
	// is my job going" is `unknown` — which this verb promises means "no such
	// job". Reporting a job that is about to run as one that never existed is
	// the defect the verb exists to prevent, arriving as a race.
	p.note(id, Status{
		Principal: j.Principal(), DecisionID: j.DecisionID,
		State: StateRunning, Started: p.opts.Now(),
	})

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		// **`cancel()` ONLY. REMOVING THE JOB FROM `running` MOVED INTO
		// `settle`, AND THE SPLIT IS A DEFECT P3 STEP 33 FOUND.**
		//
		// This defer used to do both, which put the two answers to "is this
		// job running" — `p.running` and `p.status` — under different locks
		// at different moments. The terminal status was written first, so
		// there was a window where `JobStatus` said FAILED and `Cancel` still
		// reported that it had cancelled something. Step 33d hit it on its
		// first run: a caller cancelling a job it had just been told was
		// finished was told the cancellation succeeded.
		//
		// Harmless on its own and not harmless as a shape — it is "two fields
		// answering one question" (D153) across a concurrency boundary, where
		// the disagreement is intermittent and therefore the kind nobody
		// reproduces.
		defer cancel()

		_, published, runErr := p.run(jobCtx, j, id)
		// THE STREAM ENDS WITH THE WORK (D267): closed here, whichever way the
		// job went, so a reader draining it reaches a real end.
		p.finishResults(id, results)
		if runErr != nil {
			p.log.Warn("job failed", "job", id, "target", j.Target.Ref(), "error", runErr)
		}

		// **THE END IS A RECORD (P3 criterion 15).** Written whichever way the
		// job went, and written from the goroutine rather than from `Submit`,
		// because `Submit` returned to its caller long before this — which is
		// the whole nature of a job and the reason its end needed recording
		// separately at all.
		//
		// **THE CONTEXT IS NOT `jobCtx`.** A cancelled job must still record
		// that it was cancelled, and `jobCtx` is exactly what cancellation
		// cancels — writing the outcome through it would mean the one ending
		// an operator most wants explained is the one that goes unrecorded.
		// GO-PRIMER §15ai's case, arriving on the afferent plane.
		end := Status{
			Principal: j.Principal(), DecisionID: j.DecisionID,
			State: StateFinished, Events: published,
			Started: p.opts.Now(), Ended: p.opts.Now(),
		}
		if runErr != nil {
			end.State, end.Err = StateFailed, runErr
		}
		p.settle(id, end)

		if j.DecisionID != "" {
			if ferr := p.gate.Finish(context.WithoutCancel(jobCtx),
				j.DecisionID, published, runErr); ferr != nil {
				p.log.Error("a job ended and the log does not say so", "job", id,
					"decision", j.DecisionID, "error", ferr)
			}
		}
	}()
	return id, nil
}

// Cancel stops a running job. Reports whether there was one to stop.
//
// FALSE IS NOT AN ERROR: "it already finished" is the outcome the caller
// wanted, and reporting it as a failure invites a retry loop against something
// that is already gone.
func (p *Runner) Cancel(id string) bool {
	p.mu.Lock()
	cancel, ok := p.running[id]
	p.mu.Unlock()
	if !ok {
		return false
	}
	cancel()
	return true
}

// Options tune the poller. Everything here has a safe default.
type Options struct {
	// PollTimeout bounds one Poll call. D243's deadline.
	PollTimeout time.Duration

	// StallsBeforeStopping is how many consecutive no-progress polls are
	// tolerated before the source stops being polled.
	//
	// NOT ZERO-MEANS-NEVER. Zero takes the default, because "tolerate an
	// infinite number of melts" is not a configuration anybody means to write.
	StallsBeforeStopping int

	// HeartbeatEvery bounds how long a source can go unrecorded.
	//
	// A poll that produced events always writes a record; this is the ceiling
	// for one that did not, so "is this source still being polled" is
	// answerable from the log within that window. Zero takes the default —
	// "never heartbeat" is not a configuration anybody means to write, for the
	// same reason StallsBeforeStopping does not accept it.
	HeartbeatEvery time.Duration

	// ResultsTTL is how long a finished caller's job's results wait for their
	// caller (D267, D268). Zero means config.DefaultResultsTTLSec.
	ResultsTTL time.Duration

	// Clock is the time source, injected for tests (GO-PRIMER §15e).
	Now func() time.Time

	// NewID mints envelope ids. Injected so it can become a ULID (§4.6.1d)
	// without touching this package.
	NewID func() string

	// Payloads shapes every event to its declaration and then validates it
	// (D276, D277) — in production the document's `schemareg.Registry`.
	// REQUIRED: a runner publishing unshaped or unvalidated payloads is the
	// promise `Envelope.data` made for three phases and nothing kept, so New
	// refuses to build one.
	Payloads Payloads
}

// Payloads is what the runner holds every event to (D276, D277).
type Payloads interface {
	Shape(typ string, payload map[string]any) (map[string]any, schemareg.Shaped)
	Validate(typ string, payload map[string]any) error
}

const (
	defaultPollTimeout = 30 * time.Second
	defaultStalls      = 3

	// Long enough that a quiet source costs almost nothing, short enough that
	// "did polling stop" is answerable from the audit log within a quarter of
	// an hour rather than at the next incident review.
	defaultHeartbeat = 15 * time.Minute
)

// Runner runs jobs. Today every job is recurring; a caller-triggered one is
// the same machinery with a different trigger (D247, D249).
//
// A SPINE COMPONENT: Start launches background work and returns, Stop is
// idempotent and leaves it startable, because P8's leader election stops and
// starts components on lease churn (spine.Component).
type Runner struct {
	jobs  []Job
	store cursor.Store
	trans *translate.Translator
	bus   bus.Bus

	// results holds each CALLER'S job's output until that caller reads it
	// (D267); a schedule has none and publishes to the bus.
	results map[string]*Results
	gate    Gate
	log     *slog.Logger
	opts    Options

	mu         sync.Mutex
	stopped    map[string]string             // target ref -> why it stopped being polled
	lastRecord map[string]time.Time          // target ref -> when a decision was last written
	running    map[string]context.CancelFunc // job id -> how to stop it
	status     map[string]Status             // job id -> how it is going (bounded, see status.go)
	tally      *Tally
	gaps       *Gaps

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// loops tracks the RECURRENCES alone, separately from wg (which also
	// counts caller jobs), so the schedule can be stopped early in shutdown
	// without waiting on a caller's job the listener may still be accepting
	// siblings of (D266).
	loops sync.WaitGroup
}

// New returns a Poller. Every dependency is REQUIRED.
//
// **REQUIRED RATHER THAN OPTIONAL, WHICH IS D149's SHAPE.** A poller missing
// its gate would poll ungoverned; missing its store it would re-read the world
// every tick; missing its bus it would fetch and discard. Each of those is a
// thing that runs and looks healthy, so none may be a nil check at call time.
func New(jobs []Job, store cursor.Store, trans *translate.Translator,
	b bus.Bus, gate Gate, log *slog.Logger, opts Options) (*Runner, error) {

	const op = "kyuushin.New"
	switch {
	case store == nil:
		return nil, fault.New(fault.KindConfig, op, "no cursor store: every tick would re-read the source from its beginning")
	case trans == nil:
		return nil, fault.New(fault.KindConfig, op, "no translator: polled rows would reach no envelope")
	case b == nil:
		return nil, fault.New(fault.KindConfig, op, "no bus: the afferent path would fetch and discard")
	case gate == nil:
		return nil, fault.New(fault.KindConfig, op, "no gate: polls would run ungoverned, which D18 forbids in twelve words")
	case log == nil:
		return nil, fault.New(fault.KindConfig, op, "no logger")
	}
	// **NO SOURCES IS ORDINARY HERE, AND THE REFUSAL MOVED TO THE ONLY LAYER
	// THAT CAN MEAN IT (D252).** This function used to refuse an empty job
	// list, citing §12.0's guardrail — a skeleton does its job for one real
	// input or refuses loudly. The guardrail is right and the test was in the
	// wrong package: a gateway that serves `StartJob` configures no recurring
	// sources at all, so zero jobs is its steady state rather than the stub
	// warning. The check was reading the job list as a proxy for "is this an
	// ingest deployment", which is the one fact this constructor cannot know.
	// `cmd/sekizui` knows the mode and refuses there.
	for i, j := range jobs {
		if j.Driver == nil {
			return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
				"job %d (%s) has no driver implementing connector.Source", i, j.Target.Ref()))
		}
		if j.Every <= 0 || j.Limit <= 0 {
			return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
				"source %s has interval %v and limit %d; both must be positive",
				j.Target.Ref(), j.Every, j.Limit))
		}
	}

	if opts.PollTimeout <= 0 {
		opts.PollTimeout = defaultPollTimeout
	}
	if opts.StallsBeforeStopping <= 0 {
		opts.StallsBeforeStopping = defaultStalls
	}
	if opts.Payloads == nil {
		return nil, fault.New(fault.KindConfig, "kyuushin.New",
			"no payload validator: every envelope is checked against its declared schema before "+
				"it is published (D276), and a runner that would skip that is refused rather than "+
				"built")
	}
	if opts.ResultsTTL <= 0 {
		opts.ResultsTTL = config.DefaultResultsTTLSec * time.Second
	}
	if opts.HeartbeatEvery <= 0 {
		opts.HeartbeatEvery = defaultHeartbeat
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewID == nil {
		return nil, fault.New(fault.KindConfig, op,
			"no id generator: an envelope with no id cannot be its own causation root")
	}

	return &Runner{
		jobs: jobs, store: store, trans: trans, bus: b, gate: gate,
		log: log, opts: opts, stopped: map[string]string{},
		lastRecord: map[string]time.Time{}, running: map[string]context.CancelFunc{},
		tally: NewTally(), gaps: NewGaps(),
	}, nil
}

// Name identifies the component in the boot report and /readyz.
func (p *Runner) Name() string { return "kyuushin" }

// Start loads every cursor and launches one goroutine per source.
//
// **THE CURSORS LOAD HERE AND A FAILURE FAILS THE BOOT** (D150): an unreadable
// cursor is not a degraded start, it is that source replayed from its
// beginning — which for a watermark poller is the whole table.
func (p *Runner) Start(ctx context.Context) error {
	const op = "kyuushin.Start"

	first := make(map[string]time.Duration, len(p.jobs))
	for _, j := range p.jobs {
		st, err := p.store.Load(ctx, j.Target.Ref())
		if err != nil {
			return fault.Wrap(fault.KindConfig, op, fmt.Sprintf(
				"cursor for %s", j.Target.Ref()), err)
		}
		first[j.Target.Ref()] = firstDelay(st.LastPoll, p.opts.Now(), j.Every)
	}

	// NOT THE CALLER'S CONTEXT FOR THE LOOPS. Start must return when the
	// component is operational, not when it is finished (spine.Component), so
	// the background work outlives this call and is cancelled by Stop.
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p.cancel = cancel

	for _, s := range p.jobs {
		p.wg.Add(1)
		p.loops.Add(1)
		go func(j Job) {
			defer p.wg.Done()
			defer p.loops.Done()
			p.recur(loopCtx, s, first[s.Target.Ref()])
		}(s)
	}
	p.log.Info("kyuushin started", "sources", len(p.jobs))
	return nil
}

// Stop cancels the loops and waits for them AND every caller job. Idempotent.
func (p *Runner) Stop(ctx context.Context) error {
	if err := p.StopSchedule(ctx); err != nil {
		return err
	}
	p.wg.Wait()
	return nil
}

// StopSchedule cancels the recurrences and waits for the tick in progress, and
// nothing else — caller jobs keep running until Stop (D266). Idempotent.
func (p *Runner) StopSchedule(context.Context) error {
	if p.cancel != nil {
		p.cancel()
	}
	p.loops.Wait()
	return nil
}

// Stopped reports the sources that are no longer being polled, and why.
//
// ON THE SCRAPE SURFACE because a source that has quietly stopped is the
// failure this whole package would otherwise hide: the process is healthy, the
// other sources are flowing, and one table stopped arriving.
func (p *Runner) Stopped() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.stopped))
	for k, v := range p.stopped {
		out[k] = v
	}
	return out
}

// Nonconforming is the level an anzen rule watches (D243).
func (p *Runner) Nonconforming() map[string]string { return p.tally.Nonconforming() }

// Undeclared is what sources emitted that this deployment has not declared
// (D277) — a DIFFERENT condition from Nonconforming, and the difference is
// whose move it is: there the connector broke its contract; here the vendor
// is behaving and the document has not caught up.
func (p *Runner) Undeclared() map[string]string { return p.gaps.Undeclared() }

// firstDelay is how long a schedule waits before its first poll after a start
// (CONTRACTS 134): one interval after the last poll STARTED, as the cursor
// store remembers it.
//
// **IT WAS ALWAYS ONE WHOLE INTERVAL, AND EVERY RESTART RESET IT** — so a
// source whose interval was longer than the deploy cadence never polled, while
// the process was healthy and Stopped() reported nothing. The three rules,
// The maintainer's, each failing toward polling rather than silence:
//
//   - NEVER POLLED (zero): poll now. A missing time costs one priced call; a
//     silent source is the defect.
//   - OVERDUE: poll now.
//   - IN THE FUTURE: counts as NOW, so the next poll is one interval away and
//     no further. Assume the store is compromised — whoever can write it could
//     otherwise set next year's date and silence the source; clock skew
//     between writers lands here too.
func firstDelay(last, now time.Time, every time.Duration) time.Duration {
	switch {
	case last.IsZero():
		return 0
	case last.After(now):
		return every
	}
	if wait := last.Add(every).Sub(now); wait > 0 {
		return wait
	}
	return 0
}

func (p *Runner) recur(ctx context.Context, j Job, first time.Duration) {
	// THE FIRST WAIT IS THE STORE'S ANSWER, THEN THE TICKER RE-ALIGNS TO IT, so
	// the cadence is kept from the first poll rather than drifting by it.
	start := time.NewTimer(first)
	defer start.Stop()
	t := time.NewTicker(j.Every)
	defer t.Stop()
	started := false

	stalls := 0
	for {
		wake := t.C
		if !started {
			wake = start.C
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		}
		if !started {
			started = true
			t.Reset(j.Every)
		}

		// **RECORDED BEFORE THE POLL, ON EVERY TICK (CONTRACTS 134).** Before,
		// so a poll that takes the process down is retried an interval later
		// rather than at once by every restart of a crash loop; every tick,
		// so a quiet source's time does not go stale. A failure to record is
		// LOGGED and the poll goes ahead: its only cost is that a restart
		// polls early, which is the harmless direction.
		if err := p.store.Polled(ctx, j.Target.Ref(), p.opts.Now()); err != nil {
			p.log.Warn("could not record the poll time; a restart may poll early",
				"job", j.Target.Ref(), "error", err)
		}

		// A RECURRENCE'S ENVELOPES ARE EACH THEIR OWN CAUSATION ROOT — empty root.
		// Nothing asked for them, so there is no request to attribute them to, and
		// claiming one would invent an origin. A JOB passes its id instead.
		// THE COUNT IS DISCARDED FOR A RECURRENCE, because there is no intent
		// row to close: a schedule has no caller and no end (D249). Its
		// per-poll records and its heartbeat answer "is this still running".
		progressed, _, err := p.run(ctx, j, "")
		switch {
		case errors.Is(err, context.Canceled):
			return
		case err != nil:
			p.log.Warn("run failed", "job", j.Target.Ref(), "error", err)
			continue
		}

		// **THE MELT GUARD, AND IT IS THE SPINE'S RATHER THAN A RULE'S (D243).**
		// A source returning rows while handing back the cursor it was given
		// re-ingests the same window every tick, for ever, writing an audit
		// record each time. An anzen rule could react to it, and a deployment
		// that wrote no rule must not be the deployment that melts.
		if progressed {
			stalls = 0
			continue
		}
		stalls++
		if stalls >= p.opts.StallsBeforeStopping {
			p.stop(j.Target.Ref(), fmt.Sprintf(
				"stopped after %d consecutive polls that returned rows and no cursor "+
					"progress; the source claims progress and reports none", stalls))
			return
		}
	}
}

func (p *Runner) stop(ref, why string) {
	p.mu.Lock()
	p.stopped[ref] = why
	p.mu.Unlock()
	p.log.Error("source stopped", "source", ref, "why", why)
}
