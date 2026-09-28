// Package conformance is the contract every `bus.Bus` must satisfy (D35, D260).
//
// **WHY A PUBLISHED SUITE AT ALL.** `bus.Bus` is an extension point — a
// self-hoster who runs Kafka backs the bus with it rather than fork — and since
// D260 the TRANSPORT applies authorisation: `Filter.Scope` says which (subject,
// source) pairs a consumer may receive, and a driver that ignores it delivers
// every tenant's events to every subscriber. The gateway asserts on receipt and
// drops what should not have arrived, so the leak does not reach a consumer; it
// reaches the ERROR log instead, in production, which is the wrong place to
// learn a driver is broken. This suite is the right place.
//
// **WHAT IT DOES NOT TEST: delivery semantics.** At-most-once versus
// at-least-once, buffering and replay are the driver's to document (§4.6.4) and
// the consumer's never to depend on. Every arm here is about WHICH envelopes a
// subscription may see, never about how reliably it sees them — so each arm
// uses ordering on one subscription, which every broker worth backing the bus
// with preserves, rather than waiting out a deadline.
//
// Usage, from a driver's own package:
//
//	func TestConformance(t *testing.T) {
//	    conformance.Run(t, func(t *testing.T) bus.Bus { return mybus.New(...) })
//	}
//
// DESIGN.md references: §4.6.3, §4.6.4, D35, D60, D258, D259, D260.
package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/bus"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Run asserts the Bus contract. newBus returns a fresh, empty bus per arm.
func Run(t *testing.T, newBus func(t *testing.T) bus.Bus) {
	t.Helper()

	t.Run("a subscription with no scope is refused", func(t *testing.T) {
		b := newBus(t)
		if _, err := b.Subscribe(context.Background(), bus.Filter{
			Subjects: []string{"sekizui.raw.>"},
		}); err == nil {
			t.Error("Subscribe accepted a filter with no Scope and Unscoped unset. Reading " +
				"an empty scope as `everything` makes forgetting it the widest grant there " +
				"is; reading it as `nothing` gives the consumer a stream it cannot tell from " +
				"a quiet bus. Refuse it (D260)")
		}
	})

	t.Run("scope is honoured, and its pairs are pairs", func(t *testing.T) {
		b := newBus(t)
		sub := subscribe(t, b, bus.Filter{Scope: []bus.Scope{
			{Subject: "sekizui.raw.>", Source: "t:alpha"},
			{Subject: "sekizui.enriched.>", Source: "t:beta"},
		}})

		// EVERYTHING THAT MUST BE WITHHELD IS PUBLISHED FIRST, so a leak is the
		// first envelope received rather than an absence waited out.
		publish(t, b, "withheld-unnamed-source", "raw", "t:gamma")
		publish(t, b, "withheld-half-pair-1", "raw", "t:beta")
		publish(t, b, "withheld-half-pair-2", "enriched", "t:alpha")
		publish(t, b, "admitted-alpha-raw", "raw", "t:alpha")

		switch id := next(t, sub); id {
		case "admitted-alpha-raw":
		case "withheld-unnamed-source":
			t.Fatal("an envelope from a source no Scope pair names was delivered — the " +
				"driver is not applying Filter.Scope at all. Call bus.InScope (D260)")
		default:
			t.Fatalf("%q was delivered: its subject is scoped for one source and its source "+
				"for another subject. Scope pairs must be matched together — call "+
				"bus.InScope rather than checking the two lists separately (D259)", id)
		}
	})

	t.Run("routing is on the derived subject, not the entity", func(t *testing.T) {
		b := newBus(t)
		sub := subscribe(t, b, bus.Filter{Scope: []bus.Scope{
			{Subject: "sekizui.decoy.>", Source: "t:alpha"},
			{Subject: "sekizui.raw.>", Source: "t:alpha"},
		}})

		// The entity is SHAPED like a subject the scope admits, so a driver
		// routing on it delivers this first.
		decoy := envelope("routed-on-entity", "enriched", "t:alpha")
		decoy.Subject = "sekizui.decoy.entity"
		if err := b.Publish(context.Background(), decoy); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		publish(t, b, "routed-on-subject", "raw", "t:alpha")

		if id := next(t, sub); id != "routed-on-subject" {
			// TWO CAUSES DELIVER THE DECOY, and the message names both: routing
			// on the entity, or not applying Scope at all — in which case the
			// arm above has already failed and is the one to fix first.
			t.Fatalf("received %q first. Either the driver routes on Envelope.subject, "+
				"which is the CloudEvents ENTITY and not a routing key — the bus subject is "+
				"bus.SubjectOf(env), sekizui.<stage>.<type> (D60, D258) — or it does not "+
				"apply Filter.Scope at all, in which case the scope arm fails too and is "+
				"the one to fix first", id)
		}
	})
}

func envelope(id, stage, source string) *sekizuiv1.Envelope {
	return &sekizuiv1.Envelope{
		Id: id, Stage: stage, Type: "conformance.row.v1", Source: source,
		Subject: "row/1", SpecVersion: "1.0", Residency: "eu",
	}
}

func publish(t *testing.T, b bus.Bus, id, stage, source string) {
	t.Helper()
	if err := b.Publish(context.Background(), envelope(id, stage, source)); err != nil {
		t.Fatalf("Publish %s: %v", id, err)
	}
}

func subscribe(t *testing.T, b bus.Bus, f bus.Filter) bus.Subscription {
	t.Helper()
	sub, err := b.Subscribe(context.Background(), f)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Close() })
	return sub
}

// next returns the id of the first envelope delivered. The deadline exists so a
// driver that delivers NOTHING fails with a message rather than hanging the
// suite; no arm depends on it elapsing.
func next(t *testing.T, sub bus.Subscription) string {
	t.Helper()
	select {
	case env, ok := <-sub.Events():
		if !ok {
			t.Fatal("the subscription closed before delivering the admitted envelope")
		}
		return env.GetId()
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was delivered, including the envelope the scope admits — a " +
			"driver that withholds everything passes every refusal and serves nobody")
	}
	return ""
}
