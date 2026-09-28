package acceptance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step19 — a read that would exceed the capability's max_bytes is refused
// before it is sent (P3 criterion 7, CONTRACTS 70, D257, D283).
//
// **THE RULE IS UNIVERSAL, THE FIXTURE IS FULLSTORY'S.** Every result is rows
// of objects bounded by one per-object budget, so a call's declared cost is
// always rows × that budget; the connector supplies only its Bound — here
// session_events: up to 200 rows, `event_limit` to ask for fewer. The grant on
// fs:bounded allows exactly three results' worth.
func p3Step19(t *testing.T) {
	fx, seen := eventsFixtureServer(t)
	t.Setenv("SEKIZUI_FS_LIVE", "fixture-token")
	r := newRunWith(t, runOpts{
		patch: func(d *config.Document) {
			for i := range d.Targets {
				if d.Targets[i].Ref == "fs:bounded" {
					d.Targets[i].BaseURL = fx.URL
				}
			}
		},
		fullstoryClient: trustingSystemAnd(t, fx),
	})
	r.narrate(t, "a read that would exceed the capability's max_bytes is refused before it is sent")
	if r.localOnly(t, "the gateway's pricing is this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caller := r.as(t, "agent:jobs")
	read := func(args map[string]any) *sekizuiv1.QueryResponse {
		t.Helper()
		resp, err := caller.Query(ctx, &sekizuiv1.QueryRequest{Action: "fullstory.session_events",
			TargetRef: "fs:bounded", Args: mustArgs(t, args)})
		if err != nil {
			t.Fatalf("step 19: the read errored rather than answering: %v", err)
		}
		return resp
	}
	const session = "6606828898126528473:5450116830618425003"

	// 19a — ASKED FOR MORE THAN FITS: refused, BEFORE ANYTHING IS SENT, naming
	// the declared cost, the budget and the number that would fit.
	refused := read(map[string]any{"session_id": session, "event_limit": 50.0})
	if refused.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_REQUEST ||
		!strings.Contains(refused.GetReason(), "asks for 50 rows") ||
		!strings.Contains(refused.GetReason(), "which fits 3") {
		t.Errorf("step 19a: refused_by %v, reason %q; want REFUSED_BY_REQUEST naming 50 asked and 3 that fit",
			refused.GetRefusedBy(), refused.GetReason())
	}
	if seen.calls() != 0 {
		t.Errorf("step 19a: the vendor was called %d time(s); a bound checked after the call is an "+
			"accountant, not a control", seen.calls())
	}

	// 19b — LEFT TO THE DEFAULT: lowered to what fits, through the action's
	// own argument — the vendor is asked for 3, not 50.
	got := read(map[string]any{"session_id": session})
	if got.GetStatus() != sekizuiv1.Status_STATUS_OK || seen.limit() != 3 {
		t.Errorf("step 19b: status %v, the vendor was asked for event_limit %d; want OK and 3",
			got.GetStatus(), seen.limit())
	}

	// 19c — THE DECLARATION IS KEPT, NOT TRUSTED: the fixture ignores the limit
	// and returns more; the gateway delivers what it priced, and says so.
	if n := len(got.GetRows()); n != 3 || !got.GetTruncated() {
		t.Errorf("step 19c: %d rows, truncated=%v; want the 3 priced, flagged truncated", n, got.GetTruncated())
	}

	// 19d — THE REFUSAL IS A RECORD, attributed to the request and the rule.
	var recorded bool
	waitFor(t, func() bool {
		for _, d := range readLog(t, r.path) {
			if d.GetId() == refused.GetDecisionId() && d.GetMatchedRule() == "capability_max_bytes" &&
				d.GetRefusedBy() == sekizuiv1.RefusedBy_REFUSED_BY_REQUEST {
				recorded = true
			}
		}
		return recorded
	}, "the priced refusal was not recorded")
	r.detail(t, "session_events on fs:bounded under max_bytes 786432 (three results): event_limit 50 "+
		"refused before any call, naming the 3 that fit; the default lowered to event_limit 3 at the "+
		"vendor; a fixture returning more cut to the 3 priced, flagged truncated")
}
