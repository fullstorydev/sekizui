package acceptance

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step6 — at-most-once is honest: the bus drops rather than queues, and the
// consumer is told how much it missed (P3 criterion 1, D24).
//
// **THE ASSERTION IS AN EQUATION.** received + Σ SubscribeResponse.dropped =
// published — exactly, with Σ dropped > 0 so the arm is not vacuous. Before
// this step `dropped` was documented on the wire and set by nothing, and the
// bus's own comment promised a metric nobody emitted: at-most-once was honest
// in the design and silent in the running system.
func p3Step6(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "at-most-once is honest: the bus drops rather than queues, and the consumer is told")
	if r.localOnly(t, "the bus and its buffer are this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sub, err := r.as(t, "agent:scoped").Subscribe(ctx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.raw.kata.>"},
	})
	if err != nil {
		t.Fatalf("step 6: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 }, "the subscription never registered")

	publish := func(id string, size int) {
		t.Helper()
		e := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": 1, "blob": strings.Repeat("x", size)})
		e.Id, e.Source = id, "kata:alpha"
		if err := r.srv.PublishForTest(e); err != nil {
			t.Fatalf("step 6: publishing %s: %v", id, err)
		}
	}

	// 6a — THE FLOOD, WITH NOBODY READING. Large envelopes fill gRPC's flow
	// window, the server blocks in Send, the bus buffer (16) fills, and the
	// rest drop — the slow consumer at-most-once exists for.
	const flood = 40
	for i := 0; i < flood; i++ {
		publish(fmt.Sprintf("6-flood-%02d", i), 100_000)
	}

	// 6b — THE AUDIT LOG NEVER DROPS (D118's line). Commands decided while
	// the bus was shedding all reach the record.
	before := logLen(t, r)
	for i := 0; i < 3; i++ {
		res, err := r.as(t, "agent:triage").Execute(ctx, execute("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"}))
		if err != nil || res.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("step 6b: a command during the flood failed: %v", err)
		}
	}
	if got := logLen(t, r) - before; got < 3 {
		t.Errorf("step 6b: 3 commands during the flood left %d record(s); the audit log must never "+
			"drop what the bus may (D118)", got)
	}

	// Drain, and publish small sentinels until one arrives: the drops after
	// the last flood envelope delivered are reported on the next message, so a
	// message has to come after them.
	recv := make(chan *sekizuiv1.SubscribeResponse, 64)
	go func() {
		for {
			m, err := sub.Recv()
			if err != nil {
				close(recv)
				return
			}
			recv <- m
		}
	}()
	received, reported, sentinels, gotSentinel := 0, uint64(0), 0, false
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for !gotSentinel {
		select {
		case m, ok := <-recv:
			if !ok {
				t.Fatal("step 6: the stream ended before a sentinel arrived")
			}
			received++
			reported += m.GetDropped()
			gotSentinel = strings.HasPrefix(m.GetEnvelope().GetId(), "6-sentinel")
		case <-tick.C:
			sentinels++
			publish(fmt.Sprintf("6-sentinel-%d", sentinels), 10)
		case <-ctx.Done():
			t.Fatal("step 6: no sentinel arrived")
		}
	}

	published := flood + sentinels
	if reported == 0 {
		t.Fatalf("step 6a: nothing was reported dropped after %d envelopes to a consumer that was "+
			"not reading — either the flood did not overflow the buffer (the arm is vacuous) or the "+
			"drops were not reported", flood)
	}
	if uint64(received)+reported != uint64(published) {
		t.Errorf("step 6a: received %d + reported dropped %d = %d, but %d were published. At-most-once "+
			"is honest only if every envelope is either delivered or counted (D24)",
			received, reported, uint64(received)+reported, published)
	}

	// 6c — THE OPERATOR SEES IT TOO: the scrape carries the same count.
	var scrape bytes.Buffer
	_, _ = r.srv.Metrics().WriteTo(&scrape)
	if want := fmt.Sprintf("sekizui_bus_dropped %d", reported); !strings.Contains(scrape.String(), want) {
		t.Errorf("step 6c: the metrics scrape does not carry %q; an operator would learn of the drops "+
			"only from the shutdown log", want)
	}
	r.detail(t, "%d published to a consumer that was not reading: %d delivered, %d reported dropped "+
		"on the wire and on the scrape; 3 commands mid-flood all recorded", published, received, reported)
}
