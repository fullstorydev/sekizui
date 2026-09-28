package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/reflex"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// THIS FILE IS WHY THE ENGINE SKELETON EXISTS IN P0.
//
// D18 says "a reflex is a principal, not a bypass — it needs its own grant, and
// its command traverses the identical enforcement path." That was prose until
// something other than a gRPC request tried to walk the path, at which point the
// path turned out to begin with mTLS verification an in-process reflex cannot
// satisfy (D69).
//
// These tests assert the property D18 actually claims, so it cannot quietly stop
// being true when the engine grows at P5.

func envelopeFor(t *testing.T, stage, typ string, data map[string]any) *sekizuiv1.Envelope {
	t.Helper()
	d, _ := structpb.NewStruct(data)
	return &sekizuiv1.Envelope{
		Id: "01J0ROOT", Source: "fullstory:o-1", SpecVersion: "1.0",
		Type: typ, Stage: stage, Residency: "eu", TraceId: "trace-1",
		Data: d, Time: timestamppb.Now(), ObservedTime: timestamppb.Now(),
	}
}

func TestReflexTraversesTheIdenticalEnforcementPath(t *testing.T) {
	h := newHarness(t)

	rule := config.ReflexSpec{
		Name: "friction-to-ticket", Enabled: true, Mode: "enforce",
		Principal: "agent:triage", // granted kata.create_issue on kata:alpha
		Consumes:  "sekizui.raw.>",
		Action:    "kata.create_issue", TargetRef: "kata:alpha",
		With: map[string]any{"project": "PROJ"},
	}
	engine := reflex.NewEngine([]config.ReflexSpec{rule}, h.srv, h.srv.recorder, noSignal,
		h.srv.log, func() string { return "01J0NEXT" }, acceptAll)

	env := envelopeFor(t, "raw", "fullstory.rage_click.v1", map[string]any{"session_id": "abc"})
	outcomes := engine.Dispatch(context.Background(), env)

	if len(outcomes) != 1 {
		t.Fatalf("%d outcomes, want 1", len(outcomes))
	}
	if outcomes[0].Err != nil {
		t.Fatalf("reflex failed: %v", outcomes[0].Err)
	}
	if got := outcomes[0].Result.GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("status = %v, reason %q", got, outcomes[0].Result.GetReason())
	}

	// THE SAME TWO RECORDS an agent's command produces. Not a variant, not a
	// summary — the identical path, so the identical audit shape.
	records := h.sink.all()
	if len(records) != 2 {
		t.Fatalf("%d records, want 2 (intent + outcome) — the same as an agent", len(records))
	}
	outcome := records[1]

	if outcome.GetMatchedRule() == "" {
		t.Error("no matched rule; a reflex's action is as unexplainable as an agent's without it")
	}
	// A chain of ONE: the reflex acts as itself, not on behalf of the event's
	// producer. That is what makes its grant the blast radius (§4.11.7).
	if chain := outcome.GetIdentity().GetChain(); len(chain) != 1 || chain[0] != "agent:triage" {
		t.Errorf("chain = %v, want exactly [agent:triage]", chain)
	}
	// Causation records WHAT TRIGGERED it, distinct from who authorised it.
	if got := outcome.GetCausation().GetProducedBy(); got != "reflex:friction-to-ticket" {
		t.Errorf("produced_by = %q", got)
	}
	if got := outcome.GetCausation().GetRootId(); got != "01J0ROOT" {
		t.Errorf("root_id = %q, want the originating envelope", got)
	}
}

// TestReflexIsDeniedLikeAnyPrincipal — D18's actual content. A reflex whose
// principal lacks the grant is refused by the same policy engine, and the
// refusal is audited.
func TestReflexIsDeniedLikeAnyPrincipal(t *testing.T) {
	h := newHarness(t)

	rule := config.ReflexSpec{
		Name: "overreach", Enabled: true, Mode: "enforce",
		Principal: "agent:triage",
		Consumes:  "sekizui.raw.>",
		Action:    "kata.comment", TargetRef: "kata:alpha", // NOT granted
	}
	engine := reflex.NewEngine([]config.ReflexSpec{rule}, h.srv, h.srv.recorder, noSignal, h.srv.log,
		func() string { return "id" }, acceptAll)

	outcomes := engine.Dispatch(context.Background(),
		envelopeFor(t, "raw", "fullstory.rage_click.v1", nil))

	if outcomes[0].Err != nil {
		t.Fatalf("a denial should be a Result, not an error: %v", outcomes[0].Err)
	}
	if got := outcomes[0].Result.GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("status = %v, want DENIED — a reflex is not a bypass (D18)", got)
	}
	if n := len(h.sink.all()); n != 1 {
		t.Errorf("%d records for a denied reflex, want 1", n)
	}
}

// TestShadowReflexProducesARecordAndNoEffect — §4.11.4 item 3's staging
// mechanism, end to end through the real path.
func TestShadowReflexProducesARecordAndNoEffect(t *testing.T) {
	h := newHarness(t)

	rule := config.ReflexSpec{
		Name: "staged", Enabled: true, // Mode unset == shadow
		Principal: "agent:triage",
		Consumes:  "sekizui.raw.>",
		Action:    "kata.create_issue", TargetRef: "kata:alpha",
		With: map[string]any{"project": "PROJ"},
	}
	engine := reflex.NewEngine([]config.ReflexSpec{rule}, h.srv, h.srv.recorder, noSignal, h.srv.log,
		func() string { return "id" }, acceptAll)

	outcomes := engine.Dispatch(context.Background(),
		envelopeFor(t, "raw", "fullstory.rage_click.v1", nil))

	if got := outcomes[0].Result.GetStatus(); got != sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED {
		t.Fatalf("status = %v, want WOULD_HAVE_FIRED", got)
	}
	records := h.sink.all()
	if len(records) != 1 || records[0].GetEffect() != nil {
		t.Error("shadow mode produced an effect, or the wrong number of records")
	}
}

// TestOneBrokenRuleDoesNotDisableTheRest. Rules are independent (D31), so
// aborting the loop would let config ordering decide which rules run.
func TestOneBrokenRuleDoesNotDisableTheRest(t *testing.T) {
	h := newHarness(t)

	broken := config.ReflexSpec{
		Name: "broken", Enabled: true, Mode: "enforce",
		Principal: "agent:triage", Consumes: "sekizui.raw.>",
		PublishTo: "sekizui.enriched.x",
		Carry:     []string{"absent_field"}, // the source has no such field
	}
	working := config.ReflexSpec{
		Name: "working", Enabled: true, Mode: "enforce",
		Principal: "agent:triage", Consumes: "sekizui.raw.>",
		Action: "kata.create_issue", TargetRef: "kata:alpha",
		With: map[string]any{"project": "PROJ"},
	}
	engine := reflex.NewEngine([]config.ReflexSpec{broken, working}, h.srv, h.srv.recorder, noSignal, h.srv.log,
		func() string { return "id" }, acceptAll)

	outcomes := engine.Dispatch(context.Background(),
		envelopeFor(t, "raw", "fullstory.rage_click.v1", map[string]any{"session_id": "abc"}))

	if len(outcomes) != 2 {
		t.Fatalf("%d outcomes, want 2 — a broken rule must not swallow the next", len(outcomes))
	}
	if outcomes[0].Err == nil {
		t.Error("the broken rule reported success")
	}
	if outcomes[1].Err != nil {
		t.Errorf("the working rule was affected by the broken one: %v", outcomes[1].Err)
	}
	if got := outcomes[1].Result.GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Errorf("the working rule did not run: %v", got)
	}
}

// TestBusToBusRuleReturnsAnEnvelopeAndTouchesNoDriver.
func TestBusToBusRuleReturnsAnEnvelopeAndTouchesNoDriver(t *testing.T) {
	h := newHarness(t)

	rule := config.ReflexSpec{
		Name: "enrich", Enabled: true,
		Principal: "agent:triage", Consumes: "sekizui.raw.>",
		PublishTo: "sekizui.enriched.friction",
		Carry:     []string{"session_id"},
		With:      map[string]any{"severity": "high"},
	}
	engine := reflex.NewEngine([]config.ReflexSpec{rule}, h.srv, h.srv.recorder, noSignal, h.srv.log,
		func() string { return "01J0NEXT" }, acceptAll)

	outcomes := engine.Dispatch(context.Background(),
		envelopeFor(t, "raw", "fullstory.rage_click.v1", map[string]any{"session_id": "abc"}))

	if outcomes[0].Err != nil {
		t.Fatalf("enrichment failed: %v", outcomes[0].Err)
	}
	if outcomes[0].Publish == nil {
		t.Fatal("no envelope produced")
	}
	if outcomes[0].Result != nil {
		t.Error("a bus->bus rule produced a command result")
	}
	// NO audit records: no command was issued, so there is no decision. D23
	// notes bus->bus reflexes skip decision records.
	if n := len(h.sink.all()); n != 0 {
		t.Errorf("%d audit records for a bus->bus rule, want 0", n)
	}
	if got := outcomes[0].Publish.GetStage(); got != "enriched" {
		t.Errorf("stage = %q", got)
	}
	if !strings.Contains(outcomes[0].Publish.GetCausation().GetProducedBy(), "enrich") {
		t.Error("causation does not name the rule")
	}
}

// acceptAll passes every payload; none of these tests is about schemas —
// CONTRACTS 128's refusal is `internal/reflex`'s own test.
func acceptAll(string, map[string]any) error { return nil }

// noSignal discards anzen signals; none of these tests is about them.
func noSignal(context.Context, string, map[string]string) {}
