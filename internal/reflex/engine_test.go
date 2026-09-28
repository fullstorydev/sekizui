package reflex

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
)

// TestANonconformingEnrichmentIsNotPublished is CONTRACTS 128: an enrichment
// whose VALUES break the schema of the type it publishes — the one thing boot
// cannot see — is refused as that rule's error, signalled against the rule,
// and never handed to the bus. A conforming one still publishes.
func TestANonconformingEnrichmentIsNotPublished(t *testing.T) {
	rule := config.ReflexSpec{
		Name: "correlate-friction", Enabled: true, Principal: "reflex:friction",
		Consumes:  "sekizui.raw.fullstory.>",
		PublishTo: "sekizui.enriched.friction_detected",
		Carry:     []string{"session_id", "clicks"},
	}
	var signalled map[string]string
	signal := func(_ context.Context, name string, subjects map[string]string) {
		if name == SignalNonconforming {
			signalled = subjects
		}
	}
	// clicks must be a string here, and the rage click carries a number.
	validate := func(typ string, payload map[string]any) error {
		if _, ok := payload["clicks"].(string); !ok {
			return errors.New("clicks: expected string")
		}
		return nil
	}
	e := NewEngine([]config.ReflexSpec{rule}, nil, nil, signal,
		slog.New(slog.NewTextHandler(io.Discard, nil)), func() string { return "01JNEXT" }, validate)

	out := e.Dispatch(context.Background(), rageClick(t))
	if len(out) != 1 {
		t.Fatalf("%d outcomes, want 1", len(out))
	}
	if out[0].Publish != nil {
		t.Error("a nonconforming enrichment was handed to the bus")
	}
	if out[0].Err == nil || !strings.Contains(out[0].Err.Error(), "does not match its schema") {
		t.Errorf("err = %v; want the rule's refusal naming the schema", out[0].Err)
	}
	if signalled["correlate-friction"] == "" {
		t.Errorf("no %s signal against the rule: %v", SignalNonconforming, signalled)
	}

	ok := NewEngine([]config.ReflexSpec{rule}, nil, nil, signal,
		slog.New(slog.NewTextHandler(io.Discard, nil)), func() string { return "01JNEXT" },
		func(string, map[string]any) error { return nil })
	if got := ok.Dispatch(context.Background(), rageClick(t)); got[0].Publish == nil || got[0].Err != nil {
		t.Errorf("a conforming enrichment was not published: %+v", got[0])
	}
}

// TestAnEngineWithoutAValidatorPublishesNothing: a nil validator is a wiring
// mistake, and it fails loudly on the first enrichment rather than publishing
// every one unchecked.
func TestAnEngineWithoutAValidatorPublishesNothing(t *testing.T) {
	rule := config.ReflexSpec{Name: "r", Enabled: true, Principal: "reflex:x",
		Consumes: "sekizui.raw.fullstory.>", PublishTo: "sekizui.enriched.x", Carry: []string{"session_id"}}
	e := NewEngine([]config.ReflexSpec{rule}, nil, nil, func(context.Context, string, map[string]string) {},
		slog.New(slog.NewTextHandler(io.Discard, nil)), func() string { return "id" }, nil)
	if got := e.Dispatch(context.Background(), rageClick(t)); got[0].Publish != nil || got[0].Err == nil {
		t.Errorf("an engine with no validator published: %+v", got[0])
	}
}
