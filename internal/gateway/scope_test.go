package gateway

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/metrics"
	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// leakySubscription is a transport that IGNORED Filter.Scope: it hands over
// whatever it was given.
type leakySubscription struct{ ch chan *sekizuiv1.Envelope }

func (l *leakySubscription) Events() <-chan *sekizuiv1.Envelope { return l.ch }
func (l *leakySubscription) Err() error                         { return nil }
func (l *leakySubscription) Ack(string) error                   { return nil }
func (l *leakySubscription) Close() error                       { return nil }

// TestTheReceiptAssertionCatchesATransportThatIgnoredTheScope is D260's runtime
// half.
//
// The published conformance suite catches a driver whose author ran it. This
// catches the one whose author did not: the bus decides with pkgbus.InScope,
// and the gateway checks with the same function that it did. An out-of-scope
// envelope is DROPPED — fail closed — and logged at ERROR naming D260, because
// what it reports is a broken transport, not a busy one.
func TestTheReceiptAssertionCatchesATransportThatIgnoredTheScope(t *testing.T) {
	leak := &leakySubscription{ch: make(chan *sekizuiv1.Envelope, 4)}
	env := func(id, source string) *sekizuiv1.Envelope {
		return &sekizuiv1.Envelope{Id: id, Stage: "raw", Type: "kata.row.v1", Source: source}
	}
	// Out of scope FIRST, so a missing assertion returns it first.
	leak.ch <- env("other-tenant", "kata:beta")
	leak.ch <- env("mine", "kata:alpha")

	var logged bytes.Buffer
	sub := &ScopedSubscription{
		sub:      leak,
		scope:    []pkgbus.Scope{{Subject: "sekizui.raw.>", Source: "kata:alpha"}},
		consumer: "agent:x", decision: "dec-1",
		log:     slog.New(slog.NewTextHandler(&logged, nil)),
		metrics: metrics.New(),
	}

	got, ok := sub.Next(context.Background())
	if !ok {
		t.Fatal("Next ended before returning the in-scope envelope")
	}
	if got.GetId() != "mine" {
		t.Fatalf("Next returned %q: an envelope from kata:beta reached a consumer scoped to "+
			"kata:alpha, because the transport ignored Filter.Scope and nothing checked on "+
			"receipt (D260)", got.GetId())
	}
	if sub.outOfScope != 1 {
		t.Errorf("outOfScope = %d, want 1 — the drop happened silently", sub.outOfScope)
	}
	if !strings.Contains(logged.String(), "level=ERROR") || !strings.Contains(logged.String(), "D260") {
		t.Errorf("the drop was not logged at ERROR naming D260, so an operator never learns "+
			"the bus driver is broken: %q", logged.String())
	}
}
