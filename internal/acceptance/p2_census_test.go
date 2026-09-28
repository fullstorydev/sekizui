package acceptance

import (
	"context"
	"testing"

	"github.com/fullstorydev/sekizui/internal/census"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
	"google.golang.org/protobuf/proto"
)

// P2 step 24: the population census, proven by sabotage.

// step24TheCensusFailsOnAnUnpopulatedField is SABOTAGE AS A STEP, because the
// thing under test IS a guard — and a guard nobody has watched fail is a guard
// nobody should trust (CONTRACTS 59).
//
// **THE CENSUS ITSELF RUNS IN `TestMain`, NOT HERE, AND THE REASON IS THE SAME
// ONE THAT MOVED THE REPORT THERE (D227).** A census is a claim about the WHOLE
// corpus, and while this step runs the corpus is two thirds written: P2's later
// steps have not appended yet. Asserting completeness here would fail on every
// field a later step populates, and asserting it loosely would be worthless. So
// the completeness check reads the finished log beside D228's and D231's, and
// this step proves the MECHANISM does what that check depends on.
//
// **BOTH DIRECTIONS, because a census that failed on everything would pass the
// first arm and be useless.** A field nothing populates must be NAMED; the same
// field, ledgered with a reason, must pass; and a ledger entry the corpus
// contradicts must FAIL, or the ledger rots into an allowlist nobody re-reads
// (D53's init ledger did exactly that, and reported `implemented=5/12` for a
// phase).
func step24TheCensusFailsOnAnUnpopulatedField(t *testing.T) {
	r := newRun(t)
	if r.localOnly(t, "it reads this process's audit log as its corpus") {
		return
	}

	// **THE STEP DRIVES ITS OWN CORPUS, AND ITS FIRST VERSION DID NOT.** It read
	// whatever the shared log held, which made it pass under `make acceptance`
	// and FAIL under `go test -run TestP2Acceptance/24_` — an ordering
	// dependency on P0 and P1 having run first, invisible until somebody works
	// on this one step. A step that only passes in company is a step nobody can
	// debug.
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	before := logLen(t, r)
	if _, err := r.as(t, "agent:triage").Execute(context.Background(),
		execute("kata.create_issue", "kata:alpha", map[string]any{
			"project": "PROJ",
		})); err != nil {
		t.Fatalf("driving a corpus: %v", err)
	}
	records := readLog(t, r.path)[before:]
	if len(records) == 0 {
		t.Fatal("the command wrote no records, so every arm below would be vacuous")
	}

	// THE FIELD THE SABOTAGE CLEARS. `matched_rule` is populated by any
	// authorised command — asserted rather than assumed, because the whole step
	// turns on the clearing being the only variable.
	const victim = "matched_rule"

	base := census.Of(records, census.Ledgered())
	if !contains(base.Populated, victim) {
		t.Fatalf("%q is not populated in this step's own corpus, so clearing it below "+
			"changes nothing and every arm would pass for the wrong reason", victim)
	}

	// A COPY, CLEARED. `proto.Clone` per record because the slice is shared with
	// everything else in this process — mutating the real records would make a
	// later step's assertions depend on this one having run.
	cleared := make([]*sekizuiv1.Decision, 0, len(records))
	fd := (&sekizuiv1.Decision{}).ProtoReflect().Descriptor().Fields().ByName(victim)
	if fd == nil {
		t.Fatalf("Decision has no field %q; the census would be asked about a path that "+
			"does not exist", victim)
	}
	for _, rec := range records {
		c, ok := proto.Clone(rec).(*sekizuiv1.Decision)
		if !ok {
			t.Fatal("clone returned another type")
		}
		c.ProtoReflect().Clear(fd)
		cleared = append(cleared, c)
	}

	t.Run("a field nothing populates is named", func(t *testing.T) {
		got := census.Of(cleared, census.Ledgered())
		if !contains(got.Missing, victim) {
			t.Errorf("the census did not name %q as unpopulated. Missing = %v.\n\nA declared "+
				"field nothing writes reads as COMPLETE rather than as wrong, which is why "+
				"every instance of this class so far was found by hand (CONTRACTS 23)",
				victim, got.Missing)
		}
		if got.Err() == nil {
			t.Error("the census returned no error for a corpus with an unpopulated field, so " +
				"nothing would fail the run")
		}
	})

	t.Run("ledgered with a reason, the same corpus passes", func(t *testing.T) {
		ledger := census.Ledgered()
		ledger[victim] = "cleared by P2 step 24 to prove this arm"

		got := census.Of(cleared, ledger)
		if contains(got.Missing, victim) {
			t.Errorf("%q is ledgered and the census still reports it missing", victim)
		}
		// **THE NON-VACUITY THE STEP'S OWN DECLARATION ASKS FOR, and it is a
		// RELATIVE claim rather than an absolute one.** A census that failed on
		// everything would satisfy the arm above. Asserting the corpus is
		// otherwise CLEAN cannot work here — a two-record corpus is missing most
		// of the message, and only the finished run has a complete one, which is
		// why `TestMain` owns that question. What is provable on any corpus is
		// that the ledger excuses EXACTLY the path it names and changes nothing
		// else: the census's answer minus one entry.
		if len(got.Missing) != len(base.Missing) {
			t.Errorf("ledgering %q changed the census from %d missing path(s) to %d. It "+
				"must excuse exactly one path and leave every other answer alone, or the "+
				"arm above proved a census that objects to everything.\n  before: %v\n"+
				"  after:  %v", victim, len(base.Missing), len(got.Missing),
				base.Missing, got.Missing)
		}
	})

	t.Run("a ledger entry the corpus contradicts fails", func(t *testing.T) {
		// THE EXPIRY. `revocation.torn_down` was ledgered until P1 step 52 grew
		// an arm that drives a session revocation through the governed verb; an
		// entry that outlives its reason is how an allowlist comes to permit
		// what it was written to catch.
		ledger := census.Ledgered()
		ledger[victim] = "a stale claim: this IS populated"

		got := census.Of(records, ledger)
		if !contains(got.Stale, victim) {
			t.Errorf("the census accepted a ledger entry for %q, which the corpus populates. "+
				"Stale = %v — without this the ledger only ever grows", victim, got.Stale)
		}
		if got.Err() == nil {
			t.Error("a stale ledger entry produced no error")
		}
	})
}
