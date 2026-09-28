package bus

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// env builds an envelope routed on `sekizui.<stage>.<typ>` (D60).
//
// THE ENTITY IS A FIXED, SUBJECT-SHAPED DECOY. These tests used to put the
// routing string in `Subject`, which is how they agreed with a bus that routed
// on the wrong field (D258); a decoy that LOOKS like a subject makes any
// regression to matching on it deliver the wrong set rather than happen to work.
func env(stage, typ string) *sekizuiv1.Envelope {
	return &sekizuiv1.Envelope{
		Id: "01J0" + stage + typ, Stage: stage, Type: typ, Residency: "eu",
		Subject: "sekizui.decoy.entity",
	}
}

// TestSubjectMatchingIsNATSDialect. Implementing a DIFFERENT wildcard dialect
// now would mean every subject in configuration changing meaning when JetStream
// lands at P7 — a migration nobody would see coming.
func TestSubjectMatchingIsNATSDialect(t *testing.T) {
	for _, tc := range []struct {
		pattern, subject string
		want             bool
	}{
		{"sekizui.enriched.>", "sekizui.enriched.friction", true},
		{"sekizui.enriched.>", "sekizui.enriched.a.b", true},
		{"sekizui.enriched.>", "sekizui.enriched", false}, // `>` needs >= 1 token
		{"sekizui.enriched.>", "sekizui.raw.friction", false},
		{"sekizui.*.friction", "sekizui.enriched.friction", true},
		{"sekizui.*.friction", "sekizui.a.b.friction", false}, // `*` is exactly one
		{"sekizui.raw", "sekizui.raw", true},
		{"sekizui.raw", "sekizui.raw.jira", false},
	} {
		if got := pkgbus.SubjectMatches(tc.pattern, tc.subject); got != tc.want {
			t.Errorf("SubjectMatches(%q, %q) = %v, want %v",
				tc.pattern, tc.subject, got, tc.want)
		}
	}
}

// TestAFullSubscriptionDropsAndCountsRatherThanBlocking is §7.1: never
// unbounded buffering, which converts a slow consumer into an OOM — and never
// blocking, which lets one slow consumer stall every publisher.
func TestAFullSubscriptionDropsAndCountsRatherThanBlocking(t *testing.T) {
	b := New(quiet(), 2)
	if _, err := b.Subscribe(context.Background(), pkgbus.Filter{Unscoped: true}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Nobody reads. Publishing more than the buffer must still return.
	for i := range 10 {
		if err := b.Publish(context.Background(), env("s", "t")); err != nil {
			t.Fatalf("publish %d blocked or failed: %v", i, err)
		}
	}

	if b.Dropped() == 0 {
		t.Error("a full subscription silently absorbed everything; the buffer is unbounded")
	}
	if b.Dropped() != 8 {
		t.Errorf("dropped = %d, want 8 (10 published, 2 buffered)", b.Dropped())
	}
}

// TestFiltersNarrowDelivery.
func TestFiltersNarrowDelivery(t *testing.T) {
	b := New(quiet(), 8)

	sub, err := b.Subscribe(context.Background(), pkgbus.Filter{
		Unscoped: true,
		Subjects: []string{"sekizui.enriched.>"},
		Types:    []string{"wanted.v1"},
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	ctx := context.Background()
	_ = b.Publish(ctx, env("raw", "wanted.v1"))      // wrong subject
	_ = b.Publish(ctx, env("enriched", "other.v1"))  // wrong type
	_ = b.Publish(ctx, env("enriched", "wanted.v1")) // match
	_ = b.Close(ctx)

	var got []string
	for e := range sub.Events() {
		got = append(got, pkgbus.SubjectOf(e))
	}
	if len(got) != 1 || got[0] != "sekizui.enriched.wanted.v1" {
		t.Errorf("delivered %v, want exactly the matching envelope", got)
	}
}

// TestResidencyFilterDeclinesRatherThanDropping — a consumer can refuse
// envelopes it must not receive rather than receiving and then dropping them
// (D29).
func TestResidencyFilterDeclinesRatherThanDropping(t *testing.T) {
	b := New(quiet(), 8)
	sub, _ := b.Subscribe(context.Background(), pkgbus.Filter{Unscoped: true, Residency: "us"})

	ctx := context.Background()
	_ = b.Publish(ctx, env("s", "t")) // eu
	_ = b.Close(ctx)

	for range sub.Events() {
		t.Error("an eu-resident envelope reached a us-only subscription")
	}
}

// TestQueueGroupsAreRefusedRatherThanFaked. Silently giving every member a copy
// fires one reflex per replica — a bug completely invisible at one replica
// (§4.11.2).
func TestQueueGroupsAreRefusedRatherThanFaked(t *testing.T) {
	b := New(quiet(), 8)
	if _, err := b.Subscribe(context.Background(),
		pkgbus.Filter{Unscoped: true, QueueGroup: "reflexes"}); err == nil {
		t.Fatal("a queue group was accepted by a bus that cannot honour it")
	}
}

// TestPublishAfterCloseIsRefused, rather than silently discarding.
func TestPublishAfterCloseIsRefused(t *testing.T) {
	b := New(quiet(), 8)
	ctx := context.Background()
	_ = b.Close(ctx)

	if err := b.Publish(ctx, env("s", "t")); err == nil {
		t.Error("publishing to a closed bus reported success")
	}
}

// TestCloseIsIdempotent — the Component contract requires it, and closing a
// channel twice panics.
func TestCloseIsIdempotent(t *testing.T) {
	b := New(quiet(), 8)
	if _, err := b.Subscribe(context.Background(), pkgbus.Filter{Unscoped: true}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	ctx := context.Background()
	for i := range 3 {
		if err := b.Close(ctx); err != nil {
			t.Fatalf("Close call %d: %v", i+1, err)
		}
	}
}

// TestSubscriptionCloseUnregisters, so a departed consumer stops costing
// delivery work and stops counting drops.
func TestSubscriptionCloseUnregisters(t *testing.T) {
	b := New(quiet(), 1)
	sub, _ := b.Subscribe(context.Background(), pkgbus.Filter{Unscoped: true})

	if b.Subscribers() != 1 {
		t.Fatalf("subscribers = %d, want 1", b.Subscribers())
	}
	_ = sub.Close()
	if b.Subscribers() != 0 {
		t.Errorf("subscribers = %d after Close, want 0", b.Subscribers())
	}

	for range 5 {
		_ = b.Publish(context.Background(), env("s", "t"))
	}
	if b.Dropped() != 0 {
		t.Errorf("a closed subscription still counted %d drops", b.Dropped())
	}
}

// TestConcurrentPublishAndSubscribe under -race. A bus is shared by every
// publisher and every consumer in the process, which is the definition of a
// place where a data race is likely and catastrophic.
func TestConcurrentPublishAndSubscribe(t *testing.T) {
	b := New(quiet(), 64)
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sub, err := b.Subscribe(ctx, pkgbus.Filter{Unscoped: true})
			if err != nil {
				return
			}
			go func() {
				for range sub.Events() { //nolint:revive // draining
				}
			}()
		}()
	}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				_ = b.Publish(ctx, env("enriched", "t.v1"))
			}
		}()
	}
	wg.Wait()

	if err := b.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestAckIsANoOp — it exists so consumer code written today needs no change
// when JetStream arrives (D24). Calling it must always be correct.
func TestAckIsANoOp(t *testing.T) {
	b := New(quiet(), 4)
	sub, _ := b.Subscribe(context.Background(), pkgbus.Filter{Unscoped: true})

	if err := sub.Ack("01J0anything"); err != nil {
		t.Errorf("Ack returned %v; it is a no-op under at-most-once and calling it "+
			"must always be safe", err)
	}
}

// TestRoutesOnTheDerivedSubjectNotTheEntity is D258.
//
// The bus matched subscription patterns against `Envelope.subject` — the
// CloudEvents ENTITY — while D60 and the reflex engine both said the subject is
// `sekizui.<stage>.<type>`. So a real connector's envelope, whose entity is a
// session id, reached no subscriber at all. Three arms, because each catches a
// different regression: the derived subject delivers; a pattern written
// against the ENTITY does not; and an envelope that cannot form a subject is
// refused at publish rather than silently matching nothing.
func TestRoutesOnTheDerivedSubjectNotTheEntity(t *testing.T) {
	ctx := context.Background()
	b := New(quiet(), 8)

	derived, _ := b.Subscribe(ctx, pkgbus.Filter{Unscoped: true, Subjects: []string{"sekizui.raw.fullstory.>"}})
	entity, _ := b.Subscribe(ctx, pkgbus.Filter{Unscoped: true, Subjects: []string{"session.>"}})

	e := &sekizuiv1.Envelope{
		Id: "01J0real", Stage: "raw", Type: "fullstory.rage_click.v1",
		Subject: "session.4f1c", Residency: "eu",
	}
	if err := b.Publish(ctx, e); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	_ = b.Close(ctx)

	if n := count(derived); n != 1 {
		t.Errorf("a pattern on the derived subject %q received %d envelope(s), want 1 — "+
			"the bus is not routing on sekizui.<stage>.<type> (D60, D258)", pkgbus.SubjectOf(e), n)
	}
	if n := count(entity); n != 0 {
		t.Errorf("a pattern on the ENTITY %q received %d envelope(s), want 0 — the bus is "+
			"routing on Envelope.subject, which is CloudEvents' entity and not a routing key (D258)",
			e.GetSubject(), n)
	}

	b2 := New(quiet(), 8)
	if err := b2.Publish(ctx, &sekizuiv1.Envelope{Id: "01J0nostage", Type: "t.v1"}); err == nil {
		t.Error("an envelope with no stage was published; it has no bus subject and nothing " +
			"could ever match it, so accepting it is a silent drop")
	}
}

func count(sub pkgbus.Subscription) int {
	n := 0
	for range sub.Events() {
		n++
	}
	return n
}

// TestPatternCoversIsTokenwise is D261. The first row is the defect: a grant of
// exactly one token was held to cover a request for one or more.
func TestPatternCoversIsTokenwise(t *testing.T) {
	for _, tc := range []struct {
		grant, want string
		covers      bool
	}{
		{"sekizui.raw.*", "sekizui.raw.>", false},
		{"sekizui.raw.>", "sekizui.raw.*", true},
		{"sekizui.raw.>", "sekizui.raw.kata.>", true},
		{"sekizui.raw.>", "sekizui.raw", false},
		{"sekizui.raw.>", "sekizui.>", false},
		{"sekizui.*.kata", "sekizui.raw.kata", true},
		{"sekizui.*.kata", "sekizui.*.kata", true},
		{"sekizui.raw.kata", "sekizui.raw.*", false},
		{"sekizui.raw.kata", "sekizui.raw.kata", true},
	} {
		if got := pkgbus.PatternCovers(tc.grant, tc.want); got != tc.covers {
			t.Errorf("PatternCovers(%q, %q) = %v, want %v", tc.grant, tc.want, got, tc.covers)
		}
	}
}
