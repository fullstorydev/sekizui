package acceptance

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// The session P2 step 1 and this step write into, in the NUMERIC form the
// sessions API and generate-context name it. The write uses lc.Session's
// UUID form, which Fullstory resolves to this one (D265).

// p3Step29 — the event we wrote is read back from the session, and it runs only
// under `make acceptance-live` (P3 criterion 12, D229, D270).
//
// **THIS REPLACES P2 CRITERION 1's HUMAN UI CHECK WITH AN ARM.** `POST
// /v2/events` answers `200 {}` with no identifier, so for two phases ingestion
// was confirmed by a person opening the session. Generate Context returns the
// session's events, server-side custom ones included, with their properties —
// so a write stamped with a value nothing else will ever carry can be found
// again, by a governed read, and the step fails if it is not.
//
// **THE POLL IS SLOW ON PURPOSE, AND IS NOT THE ONLY BOUND.** Every ten seconds
// by default (SEKIZUI_READBACK_INTERVAL_S), for at most five minutes
// (SEKIZUI_READBACK_DEADLINE_S). Each read goes through the governed path, so
// `fs:live`'s `limits.rate_per_hr` is enforced by Sekizui whatever this loop
// does: a read that outran it is refused here, not sent (D142), and the loop
// waits and asks again.
func p3Step29(t *testing.T) {
	lc := liveFullstory(t) // skips unless a live run is asked for; fails if it cannot reach an org
	r := newRun(t)
	r.narrate(t, "the event we wrote is read back from the session")
	if r.localOnly(t, "this step writes through its own instance") {
		return
	}
	interval := readbackSeconds(t, "SEKIZUI_READBACK_INTERVAL_S", 10, 5)
	deadline := readbackSeconds(t, "SEKIZUI_READBACK_DEADLINE_S", 300, 10)

	ctx, cancel := context.WithTimeout(context.Background(), deadline+time.Minute)
	defer cancel()
	triage := r.as(t, "agent:triage")

	// 29a — THE WRITE, stamped with a value no other run can carry.
	stamp := "step29-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	wrote, err := triage.Execute(ctx, &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
		Action: "fullstory.create_event", TargetRef: "fs:live",
		Args: mustArgs(t, map[string]any{
			"name":       "sekizui_acceptance_step29",
			"session":    map[string]any{"id": lc.Session},
			"properties": map[string]any{"run": stamp, "source": "sekizui-acceptance-step29"},
		}),
	}})
	if err != nil || wrote.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 29a: the stamped write failed: %v %s", err, wrote.GetResult().GetReason())
	}

	// 29b — THE READ-BACK, governed, polled until the stamp appears or the
	// deadline passes. `run`, not `run_str`: live, the property comes back
	// under the name it was written with (CONTRACTS 124).
	started := time.Now()
	polls, limited := 0, 0
	var latest string
	for {
		polls++
		res, qerr := triage.Query(ctx, &sekizuiv1.QueryRequest{
			Action: "fullstory.session_events", TargetRef: "fs:live",
			Args: mustArgs(t, map[string]any{"session_id": lc.device + ":" + lc.uiSession, "event_limit": 50}),
		})
		switch {
		case qerr != nil:
			t.Fatalf("step 29b: poll %d failed in transport: %v", polls, qerr)
		case res.GetStatus() == sekizuiv1.Status_STATUS_RATE_LIMITED:
			// SEKIZUI SAID WAIT, so the loop waits — the budget is the control.
			limited++
		case res.GetStatus() != sekizuiv1.Status_STATUS_OK:
			t.Fatalf("step 29b: poll %d was refused: %s (%s)", polls, res.GetReason(), res.GetRefusedBy())
		default:
			for _, row := range res.GetRows() {
				m := row.AsMap()
				if ts, _ := m["event_time"].(string); ts > latest {
					latest = ts
				}
				if props, _ := m["event_properties"].(map[string]any); props["run"] == stamp {
					r.detail(t, "the write stamped %s was read back from session %s after %d poll(s) "+
						"over %s (%d rate-limited by Sekizui), every %s — P2 criterion 1's human UI "+
						"check is now this arm", stamp, lc.device+":"+lc.uiSession, polls,
						time.Since(started).Round(time.Second), limited, interval)
					return
				}
			}
		}
		if time.Since(started)+interval > deadline {
			t.Fatalf("step 29b: the write stamped %s did not appear in session %s after %d poll(s) "+
				"over %s; the latest event seen was at %q. Either ingestion is slower than the "+
				"deadline (raise SEKIZUI_READBACK_DEADLINE_S) or the write did not land — "+
				"which is exactly what this arm exists to tell apart from a 200",
				stamp, lc.device+":"+lc.uiSession, polls, time.Since(started).Round(time.Second), latest)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("step 29b: %v", ctx.Err())
		case <-time.After(interval):
		}
	}
}

// readbackSeconds reads a duration in seconds from the environment, refusing a
// value below floor: a read-back polled faster than that against somebody
// else's API is a load test, and the floor is where that line is drawn.
func readbackSeconds(t *testing.T, name string, def, floor int) time.Duration {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return time.Duration(def) * time.Second
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < floor {
		t.Fatalf("%s=%q: want whole seconds, at least %d", name, v, floor)
	}
	return time.Duration(n) * time.Second
}
