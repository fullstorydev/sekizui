package safestruct_test

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// big is a budget large enough that nothing truncates, for the tests that are
// about representability rather than size.
const big = 1 << 20

// TestOneBadFieldDoesNotEraseTheOthers is the whole point.
//
// `structpb.NewStruct` is all-or-nothing, so control of ONE field erased the
// WHOLE object — including every field Sekizui itself had put there. That
// amplification is what turned an awkward type into a way to blank an audit
// detail, a command result, or a query row (CONTRACTS 73).
func TestOneBadFieldDoesNotEraseTheOthers(t *testing.T) {
	got, rep := safestruct.Convert(map[string]any{
		"tenant":  "alpha",
		"action":  "kata.create_issue",
		"awkward": map[string]string{"not": "representable"},
	}, big)

	if got == nil {
		t.Fatal("nil struct; one bad field must not erase the object")
	}
	for _, k := range []string{"tenant", "action"} {
		if _, ok := got.GetFields()[k]; !ok {
			t.Errorf("field %q was lost because a DIFFERENT field could not be "+
				"represented. That is the amplification this package removes", k)
		}
	}
	if len(rep.Substituted) != 1 || rep.Substituted[0] != "awkward" {
		t.Errorf("substituted = %v, want [awkward]", rep.Substituted)
	}
	if _, ok := got.GetFields()[safestruct.UnrepresentableKey]; !ok {
		t.Error("nothing records that a field was substituted. A field that vanished " +
			"must be distinguishable from one never set (D77)")
	}
}

// TestTheValueNeverAppears — the marker names the TYPE and never the content.
func TestTheValueNeverAppears(t *testing.T) {
	type holder struct{ Token connector.Secret }

	got, _ := safestruct.Convert(map[string]any{
		"creds": holder{Token: connector.Secret("super-secret-value")},
	}, big)
	if rendered := got.String(); strings.Contains(rendered, "super-secret-value") {
		t.Fatalf("the marker leaked the value: %s", rendered)
	}
}

// TestNestedBadValueDoesNotEraseItsParent — a bad leaf costs the leaf, not the
// branch.
func TestNestedBadValueDoesNotEraseItsParent(t *testing.T) {
	got, rep := safestruct.Convert(map[string]any{
		"outer": map[string]any{"good": "kept", "bad": time.Now()},
	}, big)

	outer := got.GetFields()["outer"].GetStructValue()
	if outer == nil {
		t.Fatal("the parent map was erased by a bad child")
	}
	if outer.GetFields()["good"].GetStringValue() != "kept" {
		t.Error("a sibling of the bad field was lost")
	}
	if len(rep.Substituted) != 1 || rep.Substituted[0] != "outer.bad" {
		t.Errorf("substituted = %v, want [outer.bad] — the PATH, so an operator can "+
			"find it", rep.Substituted)
	}
}

// TestDeepNestingIsBoundedRatherThanFatal. The shape is attacker-supplied, so
// the walk must not be the thing that fails.
func TestDeepNestingIsBoundedRatherThanFatal(t *testing.T) {
	deep := map[string]any{"leaf": "bottom"}
	for range 100 {
		deep = map[string]any{"n": deep}
	}
	got, rep := safestruct.Convert(deep, big)
	if got == nil {
		t.Fatal("deep nesting produced nothing")
	}
	if len(rep.Substituted) == 0 {
		t.Error("nesting past the bound was not recorded as substituted")
	}
}

// TestADriverCannotForgeACleanBillOfHealth — reserved keys are discarded on the
// way in, so a driver cannot write Sekizui's own bookkeeping.
func TestADriverCannotForgeACleanBillOfHealth(t *testing.T) {
	got, rep := safestruct.Convert(map[string]any{
		safestruct.UnrepresentableKey: []any{"definitely", "nothing", "wrong"},
		safestruct.TruncatedKey:       false,
		"ordinary":                    "value",
	}, big)

	if len(rep.Substituted) != 0 || rep.Truncated {
		t.Fatalf("fixture is wrong: nothing should be substituted or truncated, got %+v", rep)
	}
	for _, k := range []string{safestruct.UnrepresentableKey, safestruct.TruncatedKey} {
		if _, present := got.GetFields()[k]; present {
			t.Errorf("a driver's own claim on reserved key %q survived into the record. "+
				"With nothing real to overwrite it, the key must be DISCARDED on the way "+
				"in — otherwise a driver writes Sekizui's bookkeeping and an auditor "+
				"reads it as ours", k)
		}
	}
	if got.GetFields()["ordinary"].GetStringValue() != "value" {
		t.Error("discarding a reserved key took a legitimate field with it")
	}
}

// TestTheBudgetBoundsTheObject — D178's denial-of-service protection.
//
// The payload reaches the audit Effect detail, the WAL, and an fsync, so an
// unbounded driver result is a write amplifier aimed at Sekizui's own disk — and
// a full audit volume fails CLOSED, which turns a disk attack into a total
// outage.
func TestTheBudgetBoundsTheObject(t *testing.T) {
	huge := map[string]any{}
	for i := range 200 {
		huge[fmt.Sprintf("field_%03d", i)] = strings.Repeat("x", 1024)
	}

	got, rep := safestruct.Convert(huge, 8*1024)
	if !rep.Truncated {
		t.Fatal("200 KiB of data fitted an 8 KiB budget; the bound is not applied")
	}
	if size := safestruct.SizeOf(got); size > 16*1024 {
		t.Errorf("converted size %d far exceeds the 8 KiB budget; the bound must stop "+
			"BUILDING, not measure afterwards — measuring after allocation is the "+
			"allocation this defends against", size)
	}
	if !got.GetFields()[safestruct.TruncatedKey].GetBoolValue() {
		t.Error("the object was shortened and does not say so. A silently truncated " +
			"result reads as a complete one")
	}
}

// TestTruncationIsDeterministic is a CORRECTNESS requirement, not tidiness.
//
// Go randomises map iteration, so truncating an unsorted walk would drop a
// different set of fields on every run — and this object is hashed into the
// audit chain. The same command would produce a different record each time, two
// replicas would disagree, and a replay would report tampering for a system
// working correctly (D77, D78).
func TestTruncationIsDeterministic(t *testing.T) {
	input := map[string]any{}
	for i := range 100 {
		input[fmt.Sprintf("k%03d", i)] = strings.Repeat("v", 256)
	}

	first, _ := safestruct.Convert(input, 4*1024)
	for range 20 {
		again, _ := safestruct.Convert(input, 4*1024)
		if len(again.GetFields()) != len(first.GetFields()) {
			t.Fatalf("field count varied between runs: %d then %d",
				len(first.GetFields()), len(again.GetFields()))
		}
		for k := range first.GetFields() {
			if _, ok := again.GetFields()[k]; !ok {
				t.Fatalf("field %q was kept in one run and dropped in another. "+
					"Truncation must be deterministic or the audit chain records a "+
					"different object for the same command", k)
			}
		}
	}
}

// TestNonFiniteNumbersAreSubstituted: structpb accepts NaN and ±Inf, and
// protojson then refuses them — so they are substituted and recorded like any
// other unrepresentable value, and the rest of the object survives (D177).
func TestNonFiniteNumbersAreSubstituted(t *testing.T) {
	s, rep := safestruct.Convert(map[string]any{
		"nan": math.NaN(), "inf": math.Inf(1), "ninf": math.Inf(-1), "ok": 1.5,
	}, safestruct.DefaultBudget)
	if len(rep.Substituted) != 3 {
		t.Errorf("substituted %v, want the three non-finite paths", rep.Substituted)
	}
	if s.GetFields()["ok"].GetNumberValue() != 1.5 {
		t.Error("a finite neighbour was lost with the non-finite values")
	}
	if _, err := protojson.Marshal(s); err != nil {
		t.Errorf("the converted object still cannot be written as protojson: %v", err)
	}
}
