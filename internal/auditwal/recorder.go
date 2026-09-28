// Package auditwal records decisions durably.
//
// PRIVATE (D35). The Sink interface a self-hoster implements is pkg/audit; this
// is the machinery behind it.
//
// TWO PHASES, NOT ONE (§5.2.2). Intent is written BEFORE the side effect and
// outcome after, because a crash mid-call must not leave zero trace of an action
// that may well have succeeded. Single-phase recording is the most common way an
// audit log becomes untrustworthy without anyone noticing: it records what
// completed, and the interesting failures are the ones that did not.
//
// P0 SCOPE. A synchronous JSONL sink and an in-memory hash chain. The real WAL —
// fsync, batching, crash replay, background shipping — is what §5.2.2 describes
// and it needs BackgroundWork plus LocalDurableDisk, which the runtime profile
// may refuse (D16). What exists here is the AuditSync path from
// runtime.AuditMode: correct, durable per write, and slower than the WAL will be.
//
// DESIGN.md references: §5.2.2, §5.2.2a, §5.4, D23, D32, D39.
package auditwal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fullstorydev/sekizui/pkg/audit"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// TailStore persists the hash-chain tail across process restarts.
//
// WITHOUT ONE, THE CHAIN RESTARTS EVERY BOOT, and a segment boundary is a place
// where a removed TAIL is undetectable — nothing after it commits to what came
// before, so deleting the last N records of a segment leaves a file that
// verifies clean. §5.2.2 calls losing audit records "the one unacceptable
// failure in a governance system", and a record you cannot prove was never
// removed is most of the way to lost.
//
// Deliberately NOT the full §5.2.2 WAL. That machinery — batching, async
// shipping, crash replay — exists to avoid blocking on a REMOTE sink, and there
// is no remote sink until BigQuery at P2. Durability is already met by fsyncing
// each record before the call returns. What was missing is only the tail.
type TailStore interface {
	// Load returns the last chain hash, or nil for a fresh chain.
	Load() ([]byte, error)

	// Save records the hash of the most recent write. Must be durable before it
	// returns, or a crash between the record and the tail leaves them
	// disagreeing about where the chain reached.
	Save(hash []byte) error
}

// IDFunc generates decision IDs. Injected so tests are deterministic and so the
// generator can become a ULID without touching the recorder.
type IDFunc func() string

// Clock returns the current time. Injected for the same reason.
type Clock func() time.Time

// Recorder implements audit.Recorder over a synchronous Sink.
type Recorder struct {
	sink  audit.Sink
	now   Clock
	newID IDFunc

	// configIdentity is stamped on every record (D149) — the hash of the
	// compiled document this instance is enforcing.
	configIdentity string

	// tail persists prevHash across restarts. Nil means a per-process chain.
	tail TailStore

	mu sync.Mutex
	// prevHash chains records for tamper-evidence (§5.4).
	prevHash []byte
	// intents remembers phase-INTENT records awaiting an outcome, so Outcome
	// can emit a complete row rather than a fragment needing a join.
	intents map[string]*sekizuiv1.Decision
}

// Option configures a Recorder.
type Option func(*Recorder)

// WithClock overrides the time source.
func WithClock(c Clock) Option { return func(r *Recorder) { r.now = c } }

// WithIDFunc overrides ID generation.
func WithIDFunc(f IDFunc) Option { return func(r *Recorder) { r.newID = f } }

// WithTailStore makes the hash chain survive a restart.
//
// Without it the chain is per-process, which is honest but leaves the
// boundary-tail hole above. With it, one continuous chain spans every restart
// and a removed tail breaks verification like any other alteration.
func WithTailStore(ts TailStore) Option { return func(r *Recorder) { r.tail = ts } }

// NewRecorder returns a Recorder writing to sink, stamping every record with
// the identity of the configuration in force (D149).
//
// configIdentity IS A REQUIRED PARAMETER RATHER THAN AN OPTION, following
// NewGrantEngine's reasoning: an option a wiring site forgets is a column that
// is silently empty on every row, and CONTRACTS item 23 records that an
// unpopulated proto field is the one member of this codebase's recurring defect
// class that still has no guard. A parameter makes forgetting it a compile
// error at every site instead.
//
// AN EMPTY STRING IS NOT REFUSED AT RUNTIME, deliberately. The failure direction
// that matters here is D145's: not recording is the unacceptable outcome, so a
// recorder must never turn a missing LABEL into a missing RECORD. The compile
// error is the guard; the acceptance step proves the value actually arrives.
func NewRecorder(sink audit.Sink, configIdentity string, opts ...Option) *Recorder {
	r := &Recorder{
		sink:           sink,
		configIdentity: configIdentity,
		now:            time.Now,
		newID:          newSequentialID(),
		intents:        make(map[string]*sekizuiv1.Decision),
	}
	for _, o := range opts {
		o(r)
	}

	// Resume the chain where the last process left it. A failure to READ the
	// tail is deliberately not fatal: refusing to boot because a sidecar file is
	// unreadable would take a governance system offline to protect a property
	// that VerifyChain reports on anyway. It starts a new segment and says so.
	if r.tail != nil {
		if prev, err := r.tail.Load(); err == nil {
			r.prevHash = prev
		}
	}
	return r
}

// Intent records what is about to be attempted, and must be durable before it
// returns.
//
// The write happens BEFORE the side effect. If the process dies between this
// call and the driver returning, the record says an action was attempted with
// no outcome — which is the truth, and is far more useful than silence.
func (r *Recorder) Intent(ctx context.Context, d *sekizuiv1.Decision) (string, error) {
	const op = "auditwal.Intent"

	if d == nil {
		return "", fault.New(fault.KindInternal, op, "nil decision")
	}
	d.Phase = sekizuiv1.Phase_PHASE_INTENT
	return r.write(ctx, op, d)
}

// Terminal records a decision with no external effect — a denial, an
// escalation, or a tripped budget. One call, no outcome phase.
//
// DENIALS ARE THE HIGHEST-VALUE ROWS (§5.4). "Agent X tried to delete a project
// and was refused" is the sentence that justifies this entire service, and an
// implementation that only records successful calls drops exactly that. This
// method exists so a refusal cannot be a code path that simply returns early.
func (r *Recorder) Terminal(ctx context.Context, d *sekizuiv1.Decision) (string, error) {
	const op = "auditwal.Terminal"

	if d == nil {
		return "", fault.New(fault.KindInternal, op, "nil decision")
	}
	// OUTCOME, not INTENT: nothing further is coming. A terminal record left at
	// INTENT would look, forever, like an action whose result was lost.
	d.Phase = sekizuiv1.Phase_PHASE_OUTCOME
	return r.write(ctx, op, d)
}

// Outcome records what happened, correlated by decision ID.
func (r *Recorder) Outcome(ctx context.Context, decisionID string, e *sekizuiv1.Effect,
	opts ...audit.OutcomeOption) error {

	const op = "auditwal.Outcome"

	r.mu.Lock()
	intent, ok := r.intents[decisionID]
	if ok {
		delete(r.intents, decisionID)
	}
	r.mu.Unlock()

	if !ok {
		// Not merely a missing map entry: it means an outcome arrived for
		// something never announced, so the two-phase guarantee is broken
		// somewhere upstream. Refusing loudly beats writing an orphan row.
		return fault.New(fault.KindInternal, op,
			fmt.Sprintf("no intent recorded for decision %q", decisionID))
	}

	// Clone rather than mutate: the intent row is already written and shipped,
	// and editing the struct behind it would make the two rows disagree about
	// what was attempted.
	out := proto.Clone(intent).(*sekizuiv1.Decision)
	out.Phase = sekizuiv1.Phase_PHASE_OUTCOME
	out.Effect = e
	// FACTS THE INTENT COULD NOT HAVE KNOWN, applied to the clone rather than
	// to the intent — the intent row is already written and shipped, and
	// editing the struct behind it would make the two rows disagree about what
	// was attempted.
	for _, opt := range opts {
		opt(out)
	}

	_, err := r.write(ctx, op, out)
	return err
}

// write stamps, chains, and ships one record.
func (r *Recorder) write(ctx context.Context, op string, d *sekizuiv1.Decision) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if d.Id == "" {
		d.Id = r.newID()
	}
	if d.At == nil {
		d.At = timestamppb.New(r.now())
	}

	// STAMPED IN THE ONE FUNNEL, not at the seven sites that build a Decision
	// (D149). Set per exit path they would eventually disagree, and a caller
	// trusting either would be wrong about the other — D138's argument for
	// deriving `status` and `kind` from one constructor, applied to the one
	// field whose whole purpose is that every row agrees on it.
	d.ConfigIdentity = r.configIdentity

	// D29 ITEM 4, ENFORCED RATHER THAN DECLARED. audit.Sink.Residencies has
	// always documented itself as "THE EASILY-MISSED REQUIREMENT — shipping
	// EU-resident decision records to a US warehouse makes the audit log itself
	// the violation", and nothing consulted it. The Decision carried a residency
	// field nobody populated, and the interface method had no callers, so the
	// guarantee existed in three places and ran in none (D89).
	//
	// Checked BEFORE hashing, so a refused record never advances the chain.
	if err := sinkAccepts(r.sink, d.GetResidency()); err != nil {
		return "", fault.Wrap(fault.KindResidency, op, "refusing to write this record", err)
	}

	// §5.4: a hash chain over records is a few lines and makes the log
	// tamper-evident. Each record commits to its predecessor, so removing or
	// editing one breaks every hash after it.
	d.PrevHash = r.prevHash
	h, err := hashDecision(d)
	if err != nil {
		return "", fault.Wrap(fault.KindInternal, op, "hashing decision", err)
	}

	if err := r.sink.Write(ctx, []*sekizuiv1.Decision{d}); err != nil {
		// The chain does NOT advance on a failed write. Advancing it would
		// leave a gap that looks identical to tampering.
		return "", fault.Wrap(fault.KindInternal, op, "writing decision", err)
	}
	r.prevHash = h

	// Persisted AFTER the record is durable. The other order would let a crash
	// leave a tail pointing at a record that was never written, which breaks
	// verification for a file that was never tampered with.
	if r.tail != nil {
		if terr := r.tail.Save(h); terr != nil {
			// The record IS durable; only the tail is not. Failing the call
			// would discard a written record's success over a weaker property.
			return d.Id, fault.Wrap(fault.KindInternal, op,
				"record written but the chain tail was not persisted; the next restart "+
					"will begin a new segment", terr)
		}
	}

	if d.Phase == sekizuiv1.Phase_PHASE_INTENT {
		r.intents[d.Id] = proto.Clone(d).(*sekizuiv1.Decision)
	}
	return d.Id, nil
}

// hashDecision computes the chain hash over a record.
//
// DETERMINISTIC MARSHALLING IS REQUIRED and protobuf does not guarantee it by
// default — map ordering and unknown-field placement can vary between runs and
// between library versions. proto.MarshalOptions{Deterministic: true} pins it.
// Without that, verifying a chain could fail on a record nobody touched.
func hashDecision(d *sekizuiv1.Decision) ([]byte, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(d)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// VerifyChain walks records in order and reports the first break.
//
// Exported because tamper-evidence nobody can check is decoration. The panel
// (§4.8) and any export tooling both need this.
//
// A RESTART IS NOT TAMPERING, and the two are distinguishable. The chain lives
// in memory, so a new process starts a new SEGMENT whose first record has an
// empty prev_hash. A file spanning two runs therefore contains a legitimate
// discontinuity, and reporting it as "a record was altered" would cry wolf at
// every restart — training an operator to ignore the one alarm that matters.
//
//	empty prev_hash mid-file  -> a new segment. Expected.
//	WRONG prev_hash           -> altered, removed, or reordered. Not expected.
//
// The honest limit: a segment boundary is where a removed TAIL becomes
// invisible, because nothing after it commits to what came before. Detecting
// that needs the WAL to persist its tail hash across restarts, which is the
// P1 WAL's job (§5.2.2). Recorded here rather than discovered later.
func VerifyChain(records []*sekizuiv1.Decision) error {
	const op = "auditwal.VerifyChain"

	var prev []byte
	for i, rec := range records {
		switch {
		case bytesEqual(rec.PrevHash, prev):
			// Linked, as expected.
		case len(rec.PrevHash) == 0 && i > 0:
			// A new segment: this process did not write the preceding records.
		default:
			return fault.New(fault.KindInternal, op, fmt.Sprintf(
				"chain broken at record %d (id %q): prev_hash is %s, expected %s — "+
					"a record was altered, removed, or reordered",
				i, rec.Id, short(rec.PrevHash), short(prev)))
		}

		h, err := hashDecision(rec)
		if err != nil {
			return fault.Wrap(fault.KindInternal, op, "hashing", err)
		}
		prev = h
	}
	return nil
}

// Segments counts the chain segments in a record set.
//
// One per process lifetime. An operator verifying an audit file wants to know
// how many restarts it spans, because each boundary is a place where a removed
// tail is undetectable until the WAL persists its tail hash (§5.2.2).
func Segments(records []*sekizuiv1.Decision) int {
	n := 0
	for i, rec := range records {
		if i == 0 || len(rec.PrevHash) == 0 {
			n++
		}
	}
	return n
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func short(b []byte) string {
	if len(b) == 0 {
		return "<none>"
	}
	s := hex.EncodeToString(b)
	if len(s) > 12 {
		s = s[:12]
	}
	return s
}

// newSequentialID returns an ID generator with per-instance state.
//
// PACKAGE-LEVEL MUTABLE STATE IS BANNED (§6 item 4), and this function exists
// because the first version of it broke that rule: a package-level `idCounter`
// plus its mutex, which is "exactly what Lexicon violates everywhere". The
// counter now lives in a closure owned by one Recorder.
//
// That is not pedantry about a counter. Package-level mutable state is shared by
// every test in a package and every tenant in a process — it is the same shape
// as the module singletons §6 exists to eliminate, and the reason it survived
// review is that the CI lint meant to catch it (`gochecknoglobals`) is not
// wired yet.
//
// NOT A ULID, and deliberately not pretending to be. §4.6.1d wants ULIDs for
// envelope IDs; that dependency belongs with the bus in P3. What is needed here
// is uniqueness within a process and ordering within a chain.
func newSequentialID() IDFunc {
	var (
		mu      sync.Mutex
		counter uint64
		prefix  = fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	)
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		counter++
		return fmt.Sprintf("dec_%s_%06d", prefix, counter)
	}
}

// sinkAccepts reports whether a sink may receive a record of this residency.
//
// A NIL RESIDENCY SET MEANS ANY, which is what a local file returns — the
// operator's own disk is in whatever jurisdiction the instance is. An EMPTY
// residency on the record also passes: not every decision resolves a target
// (an unauthenticated refusal has none), and refusing to audit those would lose
// exactly the records §5.4 calls the highest-value ones.
//
// KindResidency, not KindDenied. An operator seeing this has a deployment
// topology problem — a sink in the wrong region — not a grant to review.
func sinkAccepts(sink audit.Sink, residency string) error {
	const op = "auditwal.sinkAccepts"

	permitted := sink.Residencies()
	if len(permitted) == 0 || residency == "" {
		return nil
	}
	for _, p := range permitted {
		if p == residency {
			return nil
		}
	}
	return fault.New(fault.KindResidency, op, fmt.Sprintf(
		"sink %q accepts %v and this decision is %s-resident. Shipping it would make the "+
			"audit log itself the violation (D29 item 4) — route this residency to its own "+
			"sink rather than widening this one",
		sink.Name(), permitted, residency))
}
