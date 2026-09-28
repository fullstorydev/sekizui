package auditwal

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// D29 item 4 was declared in three places and enforced in none (D89):
// `Decision.residency` existed and nothing populated it, `audit.Sink.Residencies`
// existed and nothing called it, and the interface's own comment named it "THE
// EASILY-MISSED REQUIREMENT". These tests are the enforcement.

// regionSink accepts only the residencies it names.
type regionSink struct {
	accepts []string
	written []*sekizuiv1.Decision
}

func (s *regionSink) Name() string          { return "region" }
func (s *regionSink) Residencies() []string { return s.accepts }
func (s *regionSink) Close(context.Context) error {
	return nil
}

func (s *regionSink) Write(_ context.Context, batch []*sekizuiv1.Decision) error {
	s.written = append(s.written, batch...)
	return nil
}

func decision(residency string) *sekizuiv1.Decision {
	return &sekizuiv1.Decision{
		Identity: &sekizuiv1.Identity{
			Caller:  &sekizuiv1.Caller{Principal: "agent:x"},
			Subject: &sekizuiv1.Subject{Principal: "agent:x"},
		},
		Action: "kata.create_issue", TargetRef: "kata:alpha",
		Verdict: sekizuiv1.Verdict_VERDICT_ALLOW, Residency: residency,
	}
}

// TestASinkRefusesARecordFromAResidencyItMayNotReceive — shipping an EU record
// to a US warehouse makes the audit log itself the violation.
func TestASinkRefusesARecordFromAResidencyItMayNotReceive(t *testing.T) {
	sink := &regionSink{accepts: []string{"us"}}
	r := NewRecorder(sink, "test-config")

	_, err := r.Terminal(context.Background(), decision("eu"))
	if err == nil {
		t.Fatal("a us-only sink accepted an eu-resident decision record")
	}
	if got := fault.KindOf(err); got != fault.KindResidency {
		t.Errorf("kind = %v, want KindResidency — a sink in the wrong region is a "+
			"deployment topology problem, not a grant to review", got)
	}
	if len(sink.written) != 0 {
		t.Error("the record was written despite the refusal")
	}
	if !strings.Contains(err.Error(), "route this residency to its own sink") {
		t.Errorf("the refusal does not say what to do about it: %v", err)
	}
}

// TestARefusedRecordDoesNotAdvanceTheChain. Advancing it would leave a gap
// indistinguishable from tampering — the same rule a failed write follows.
func TestARefusedRecordDoesNotAdvanceTheChain(t *testing.T) {
	sink := &regionSink{accepts: []string{"us"}}
	r := NewRecorder(sink, "test-config")

	if _, err := r.Terminal(context.Background(), decision("eu")); err == nil {
		t.Fatal("the refusal did not happen")
	}
	id, err := r.Terminal(context.Background(), decision("us"))
	if err != nil {
		t.Fatalf("a permitted record was refused: %v", err)
	}
	if len(sink.written) != 1 {
		t.Fatalf("%d records written, want 1", len(sink.written))
	}
	if got := sink.written[0].GetPrevHash(); len(got) != 0 {
		t.Errorf("prev_hash = %x on the first written record; the refused one advanced "+
			"the chain and left a gap that reads as tampering", got)
	}
	if id == "" {
		t.Error("no decision id returned")
	}
}

// TestASinkAcceptingAnythingTakesEveryResidency — nil means any, which is what a
// local file returns: the operator's own disk is in whatever jurisdiction the
// instance is.
func TestASinkAcceptingAnythingTakesEveryResidency(t *testing.T) {
	sink := &regionSink{accepts: nil}
	r := NewRecorder(sink, "test-config")

	for _, residency := range []string{"eu", "us", "apac", ""} {
		if _, err := r.Terminal(context.Background(), decision(residency)); err != nil {
			t.Errorf("a nil-residency sink refused %q: %v", residency, err)
		}
	}
}

// TestARecordWithNoResidencyIsStillAudited. Not every decision resolves a target
// — an unauthenticated refusal has none — and refusing to audit those would lose
// exactly the records §5.4 calls the highest-value ones.
func TestARecordWithNoResidencyIsStillAudited(t *testing.T) {
	sink := &regionSink{accepts: []string{"us"}}
	r := NewRecorder(sink, "test-config")

	if _, err := r.Terminal(context.Background(), decision("")); err != nil {
		t.Fatalf("a record with no residency was refused: %v; denials that never "+
			"reached a target would stop being audited", err)
	}
}

// TestTailPathTravelsWithItsLog — there were briefly two conventions, one in
// this package and one inline in cmd/sekizui, and nothing caught it because each
// was internally consistent.
func TestTailPathTravelsWithItsLog(t *testing.T) {
	got := TailPathFor("/var/audit/audit.jsonl")

	if want := "/var/audit/audit.jsonl.tail"; got != want {
		t.Errorf("TailPathFor = %q, want %q", got, want)
	}
	if strings.HasPrefix(filepathBase(got), ".") {
		t.Error("the tail is a hidden file; an operator archiving with `cp audit.jsonl*` " +
			"would silently leave behind the thing that makes the chain tamper-evident")
	}
	if !strings.HasPrefix(got, "/var/audit/audit.jsonl") {
		t.Error("the tail does not sort beside its log")
	}
}

func filepathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
