package acceptance

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/ledger"
	"github.com/fullstorydev/sekizui/pkg/config"
)

// TestLedgerEntriesHaveNotLanded is the expiry the init ledger never had.
//
// D53's ledger declares what the skeleton still owes, and every boot prints it
// while /readyz reports degraded. The comment above it claimed a subsystem
// "lands by deleting its Plan entry and calling Register instead, which is a
// change a compiler and a reviewer both see". **No compiler saw anything.**
// `pool` and `limiter` landed in P1 steps 1-8 and 20-24, their entries stayed,
// and the running binary reported `implemented=5/12` with a reason —
// "pkg/limiter's Limiter and Breaker have no implementation" — that the code in
// the same process flatly contradicted.
//
// That is the recurring defect INVERTED. The usual form is a contract that
// silently does nothing; this is a DISCLAIMER that silently keeps applying, and
// it is worse in one respect: a readiness signal that under-reports is one an
// operator learns to ignore, which is D77's crying-wolf failure aimed at the
// boot report instead of at the audit chain.
//
// Same shape as archcheck's `aheadOfItsPhase` (D139): the entry names what would
// retire it, and the build fails once that is true.
func TestLedgerEntriesHaveNotLanded(t *testing.T) {
	built := builtStepsByPhase()

	var landed []string
	for _, p := range ledger.Planned() {
		if len(p.ProvenBy) == 0 {
			continue
		}
		var unbuilt []int
		for _, n := range p.ProvenBy {
			if !built[p.LandsIn][n] {
				unbuilt = append(unbuilt, n)
			}
		}
		if len(unbuilt) == 0 {
			landed = append(landed, fmt.Sprintf("%s (steps %v are all built)", p.Name, p.ProvenBy))
		}
	}
	sort.Strings(landed)

	if len(landed) > 0 {
		t.Errorf("%d init-ledger entry/entries name work that is now BUILT:\n  %s\n\n"+
			"Delete the entry and register the component instead. Until then every boot "+
			"reports the skeleton as less complete than it is, and /readyz says DEGRADED "+
			"for a reason the binary contradicts — which is how a readiness signal becomes "+
			"something nobody reads.", len(landed), strings.Join(landed, "\n  "))
	}
}

// TestLedgerEntriesInLivePhasesNameTheirSteps is what stops ProvenBy being
// omitted, which would make the guard above vacuous.
//
// AN EMPTY ProvenBy IS THE OBVIOUS WAY TO DODGE AN EXPIRY, and it is the way an
// allowlist entry usually survives: not by anybody arguing for it, but by the
// field that would have retired it never being filled in. So an entry whose
// phase HAS a step table must name at least one step, and every step it names
// must exist.
//
// A phase with no step table is exempt, because there is nothing to name yet.
// That is a real hole — an entry could claim P5 to escape — and the phase plan
// being reviewed is what closes it, not this test. Stated rather than papered
// over, per §0.
func TestLedgerEntriesInLivePhasesNameTheirSteps(t *testing.T) {
	declared := declaredStepsByPhase()

	for _, p := range ledger.Planned() {
		if !ledger.PhasesWithStepTables[p.LandsIn] {
			continue
		}
		if len(p.ProvenBy) == 0 {
			t.Errorf("ledger entry %q lands in %s, which has a step table, and names no "+
				"steps. Without them the entry can never expire, and it will outlive the "+
				"thing it describes", p.Name, p.LandsIn)
			continue
		}
		for _, n := range p.ProvenBy {
			if !declared[p.LandsIn][n] {
				t.Errorf("ledger entry %q names step %d, which is not in %s's step table. "+
					"A guard pointed at a step that does not exist never fires",
					p.Name, n, p.LandsIn)
			}
		}
	}
}

// declaredStepsByPhase and builtStepsByPhase key the step tables on the PHASE,
// and that is a correctness fix rather than tidiness.
//
// **STEP NUMBERS RESTART AT 1 IN EVERY PHASE, AND `ProvenBy` IS A BARE INT.**
// While P1 was the only live table both guards built one flat map from
// `p1StepTable`, which was correct precisely as long as no second table existed.
// The moment P2 declared steps 1-29, an entry landing in P2 and naming step 18
// would have been checked against P1's step 18 — a different assertion entirely,
// already built, so the expiry guard would have reported the entry as LANDED and
// demanded its deletion on the strength of work in another phase.
//
// Latent rather than hypothetical: two entries already name P2 (`audit:ship`,
// `obs:otel`), and they were exempt only because a phase with no step table is
// skipped. Creating the table is what made them owe evidence, and finding this
// is the argument for `PhasesWithStepTables` being data rather than a condition
// somebody remembers.
func declaredStepsByPhase() map[string]map[int]bool {
	out := map[string]map[int]bool{"P1": {}, "P2": {}, "P3": {}, "P4": {}, "P5": {}, "P6": {}}
	for _, s := range p1StepTable() {
		out["P1"][s.n] = true
	}
	for _, s := range p2StepTable() {
		out["P2"][s.n] = true
	}
	for _, s := range p3StepTable() {
		out["P3"][s.n] = true
	}
	for _, s := range p4StepTable() {
		out["P4"][s.n] = true
	}
	for _, s := range p5StepTable() {
		out["P5"][s.n] = true
	}
	for _, s := range p6StepTable() {
		out["P6"][s.n] = true
	}
	return out
}

func builtStepsByPhase() map[string]map[int]bool {
	out := map[string]map[int]bool{"P1": {}, "P2": {}, "P3": {}, "P4": {}, "P5": {}, "P6": {}}
	for _, s := range p1StepTable() {
		if s.run != nil {
			out["P1"][s.n] = true
		}
	}
	for _, s := range p2StepTable() {
		if s.run != nil {
			out["P2"][s.n] = true
		}
	}
	for _, s := range p3StepTable() {
		if s.run != nil {
			out["P3"][s.n] = true
		}
	}
	for _, s := range p4StepTable() {
		if s.run != nil {
			out["P4"][s.n] = true
		}
	}
	for _, s := range p5StepTable() {
		if s.run != nil {
			out["P5"][s.n] = true
		}
	}
	for _, s := range p6StepTable() {
		if s.run != nil {
			out["P6"][s.n] = true
		}
	}
	return out
}

// TestUnbuiltAnzenActionsAreLedgered — config's list of anzen actions no firing
// path implements, and the ledger's `anzen:*` entries, are ONE list (D331).
// Building an action means deleting it from both; forgetting either side fails.
func TestUnbuiltAnzenActionsAreLedgered(t *testing.T) {
	var ledgered []string
	for _, p := range ledger.Planned() {
		if name, ok := strings.CutPrefix(p.Name, "anzen:"); ok {
			ledgered = append(ledgered, name)
		}
	}
	sort.Strings(ledgered)
	if want := config.UnbuiltAnzenActions(); strings.Join(ledgered, ",") != strings.Join(want, ",") {
		t.Errorf("ledger anzen:* entries %v; config says these actions are unbuilt: %v. Build one and "+
			"delete it from both, or add the entry an unbuilt action owes", ledgered, want)
	}
}
