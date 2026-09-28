package acceptance

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/safestruct"
)

// step32AnUnrepresentableValueLosesNothing proves D177.
//
// **THE THREAT IS INFORMATION REMOVAL BY WHOEVER CONTROLS THE DATA.**
// `structpb.NewStruct` fails all-or-nothing on a type it cannot represent, and
// the gateway discarded that error in three places (CONTRACTS 73), giving one
// awkward value three different disappearances:
//
//	591  the audit Effect detail was OMITTED while the record still said success
//	619  the command result became EMPTY
//	1311 a query row was DROPPED from the result set
//
// Drivers are third-party (D35) and legitimately echo upstream responses, so the
// shape is ultimately attacker-influenceable — which makes each of those a way
// to make an effect unauditable, blank a caller's result, or hide chosen rows.
//
// **THE AMPLIFIER WAS THE ALL-OR-NOTHING BEHAVIOUR.** Control of one field
// erased the whole object, including every field Sekizui itself put there. That
// is the property this step pins.
func step32AnUnrepresentableValueLosesNothing(t *testing.T) {
	// --- 32a: NOTHING SEKIZUI WROTE IS LOST -------------------------------
	t.Run("a field Sekizui set survives a field the driver could not represent", func(t *testing.T) {
		got, rep := safestruct.Convert(map[string]any{
			"tenant":  "alpha",
			"action":  "kata.create_issue",
			"target":  "kata:alpha",
			"awkward": map[string]string{"nope": "not a structpb type"},
		}, safestruct.DefaultBudget)
		if got == nil {
			t.Fatal("the whole object was erased by one field")
		}
		for _, k := range []string{"tenant", "action", "target"} {
			if _, ok := got.GetFields()[k]; !ok {
				t.Errorf("%q was lost because a DIFFERENT field could not be represented. "+
					"An attacker controlling one field must not be able to erase the "+
					"others — that amplification is what made this a security issue "+
					"rather than a nuisance", k)
			}
		}
		if len(rep.Substituted) == 0 {
			t.Error("nothing recorded that a substitution happened")
		}
	})

	// --- 32b: THE SUBSTITUTION IS RECORDED, NOT INFERRED ------------------
	//
	// D77's rule: a field nobody could represent must be distinguishable from a
	// field that was never set. Otherwise an auditor cannot tell an awkward type
	// from an absent one, and "the column is empty" reads as "nothing happened".
	t.Run("a substituted field is named in the record", func(t *testing.T) {
		got, _ := safestruct.Convert(map[string]any{"when": time.Now()}, safestruct.DefaultBudget)
		listed := got.GetFields()[safestruct.UnrepresentableKey]
		if listed == nil {
			t.Fatal("the record does not say which field was substituted")
		}
		var found bool
		for _, v := range listed.GetListValue().GetValues() {
			if v.GetStringValue() == "when" {
				found = true
			}
		}
		if !found {
			t.Errorf("the substituted path is not named: %v", listed)
		}
	})

	// --- 32c: THE MARKER NEVER CARRIES THE VALUE --------------------------
	//
	// This string reaches the audit log and the caller. A driver's
	// unrepresentable field may hold credential material, and an arbitrary struct
	// holding a Secret does not inherit Secret's self-redaction (§4.3.3).
	t.Run("the marker names the type and never the value", func(t *testing.T) {
		type wrapper struct{ Token string }
		got, _ := safestruct.Convert(map[string]any{
			"creds": wrapper{Token: "SEKIZUI-SECRET-CANARY"},
		}, safestruct.DefaultBudget)
		if strings.Contains(got.String(), "SEKIZUI-SECRET-CANARY") {
			t.Fatalf("the marker leaked the value it could not represent: %s", got.String())
		}
	})

	// --- 32d: A DRIVER CANNOT FORGE A CLEAN BILL OF HEALTH ----------------
	t.Run("a driver's own claim about substitutions is overwritten", func(t *testing.T) {
		got, _ := safestruct.Convert(map[string]any{
			safestruct.UnrepresentableKey: "nothing was substituted",
			"awkward":                     make(chan int),
		}, safestruct.DefaultBudget)
		claimed := got.GetFields()[safestruct.UnrepresentableKey]
		if claimed.GetStringValue() == "nothing was substituted" {
			t.Fatal("a driver asserted that nothing was substituted and was believed. " +
				"Whatever a driver writes to the reserved key is not evidence about itself")
		}
	})

	// --- 32e: AND THE CASE 32d CANNOT REACH -------------------------------
	//
	// **THE MUTATION AUDIT FOUND THIS ARM MISSING, and the gap was in the test
	// rather than in the code.** Removing the guard that discards a
	// driver-supplied reserved key SURVIVED the whole suite, because 32d supplies
	// an unrepresentable value too — so the real substitution list overwrites the
	// forged one and the assertion passes either way.
	//
	// The guard is load-bearing in exactly the case 32d does not construct: a
	// driver writes the reserved key and NOTHING is unrepresentable, so there is
	// no real list to overwrite the lie with. That is also the more useful lie to
	// tell — "I substituted nothing" is what an attacker wants an auditor to
	// read.
	t.Run("a forged clean claim does not survive when there is nothing to overwrite it", func(t *testing.T) {
		got, rep := safestruct.Convert(map[string]any{
			safestruct.UnrepresentableKey: []any{"definitely", "nothing", "wrong"},
			"ordinary":                    "value",
		}, safestruct.DefaultBudget)
		if len(rep.Substituted) != 0 {
			t.Fatalf("the fixture is wrong: nothing here should be unrepresentable, got %v",
				rep.Substituted)
		}
		if _, present := got.GetFields()[safestruct.UnrepresentableKey]; present {
			t.Error("a driver's forged substitution list survived into the record. With " +
				"no real substitutions there is nothing to overwrite it, so the key must " +
				"be DISCARDED on the way in — otherwise a driver can write Sekizui's own " +
				"bookkeeping and an auditor reads it as ours")
		}
		if got.GetFields()["ordinary"].GetStringValue() != "value" {
			t.Error("discarding the reserved key took a legitimate field with it")
		}
	})

	// --- 32f: THE BUDGET BOUNDS THE OBJECT --------------------------------
	//
	// **A DIFFERENT ATTACK FROM THE SAME PATH (D178).** An unrepresentable value
	// removes information; an unbounded one is a denial of service, and the
	// amplification is what makes it severe. This payload reaches the audit
	// Effect detail, which reaches the WAL, which is FSYNCED — so a hostile
	// upstream returning a large result writes to Sekizui's own disk once per
	// command. Fill the audit volume and the sink fails, and because a governance
	// system cannot execute what it cannot record, that fails CLOSED: an
	// availability attack on the disk becomes a total outage, which is D147's
	// inversion reached from a different direction.
	t.Run("an oversized payload is truncated rather than written whole", func(t *testing.T) {
		huge := map[string]any{}
		for i := range 500 {
			huge[fmt.Sprintf("field_%03d", i)] = strings.Repeat("x", 1024)
		}

		got, rep := safestruct.Convert(huge, safestruct.DefaultBudget)
		if !rep.Truncated {
			t.Fatalf("%d KiB fitted a %d KiB budget; nothing bounds what reaches the WAL",
				len(huge), safestruct.DefaultBudget/1024)
		}
		if size := safestruct.SizeOf(got); size > 2*safestruct.DefaultBudget {
			t.Errorf("converted size %d is more than twice the budget. The bound must "+
				"stop BUILDING rather than measure afterwards — measuring after "+
				"allocation is the allocation being defended against", size)
		}
		if !got.GetFields()[safestruct.TruncatedKey].GetBoolValue() {
			t.Error("the record was shortened and does not say so. A short audit record " +
				"that reads as complete is worse than a missing one, because nobody " +
				"goes looking")
		}
	})

	// --- 32g: AND TRUNCATION IS DETERMINISTIC -----------------------------
	//
	// **A CORRECTNESS REQUIREMENT, NOT TIDINESS, and it is the subtle half.** Go
	// randomises map iteration, so truncating an unsorted walk drops a DIFFERENT
	// set of fields every run — and this object is hashed into the audit chain.
	// The same command would produce a different record each time, two replicas
	// would disagree about a payload they both handled correctly, and a replay
	// would report tampering for a system working perfectly (D77, D78).
	t.Run("truncation drops the same fields every time", func(t *testing.T) {
		input := map[string]any{}
		for i := range 200 {
			input[fmt.Sprintf("k%03d", i)] = strings.Repeat("v", 512)
		}

		first, _ := safestruct.Convert(input, 8*1024)
		for range 25 {
			again, _ := safestruct.Convert(input, 8*1024)
			for k := range first.GetFields() {
				if _, ok := again.GetFields()[k]; !ok {
					t.Fatalf("field %q was kept in one run and dropped in another. A "+
						"non-deterministic record makes VerifyChain report tampering for "+
						"a system working correctly", k)
				}
			}
		}
	})
}
