package acceptance

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p5Step9 — denial_storm is raised and names the principal monopolising a
// budget (D143, D336), the last anzen signal nothing raised (CONTRACTS 65).
// Refusals are REAL, through the gateway; the level is the function the
// binary's watcher polls; the dispatcher is the one the harness wires as main.
func p5Step9(t *testing.T) {
	const hog = "agent:metered" // kata:metered: rate 2/hr, burst 1
	victims := []string{"agent:analytics", "agent:support"}
	r := newRunWith(t, runOpts{patch: func(d *config.Document) {
		// INTO THE PRINCIPAL'S OWN BLOCK where it has one: two blocks for one
		// principal is refused, since one would be silently ignored.
		for _, v := range victims {
			c := config.CapabilitySpec{Action: "kata.create_issue", TargetRef: "kata:metered"}
			found := false
			for i := range d.Grants {
				if d.Grants[i].Principal == v {
					d.Grants[i].Allow, found = append(d.Grants[i].Allow, c), true
				}
			}
			if !found {
				d.Grants = append(d.Grants, config.GrantSpec{Principal: v, Allow: []config.CapabilitySpec{c}})
			}
		}
		d.Anzen = append(d.Anzen, config.AnzenSpec{Name: "alert-on-storm", Enabled: true, Mode: "enforce",
			Watches: "denial_storm", Do: "alert", Subject: hog})
	}})
	if r.localOnly(t, "the tally and the dispatcher are this instance's") {
		return
	}
	r.narrate(t, "denial_storm is raised and names the principal monopolising a budget")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	create := func(who, key string) sekizuiv1.Status {
		req := execute("kata.create_issue", "kata:metered", map[string]any{"project": "PROJ"})
		req.Command.IdempotencyKey = key
		resp, err := r.as(t, who).Execute(ctx, req)
		if err != nil {
			t.Fatalf("step 9: %s: %v", who, err)
		}
		return resp.GetResult().GetStatus()
	}

	// 9a — THE HOG TAKES THE BUDGET, THE OTHERS ARE REFUSED, AND THE LEVEL NAMES
	// THE HOG — not the principals refused.
	if s := create(hog, "p5-9-hog"); s != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 9a: the first call on kata:metered was %v", s)
	}
	for _, v := range victims {
		for i := range 2 {
			if s := create(v, fmt.Sprintf("p5-9-%s-%d", v, i)); s != sekizuiv1.Status_STATUS_RATE_LIMITED {
				t.Fatalf("step 9a: %s on the drained budget was %v, want RATE_LIMITED", v, s)
			}
		}
	}
	level := r.denials.Storms(time.Minute, 3)
	detail, named := level[hog]
	switch {
	case !named:
		t.Fatalf("step 9a: the level is %v; want %s, who drained the budget the others were refused on", level, hog)
	case len(level) != 1:
		t.Errorf("step 9a: the level names %v; the victims caused nothing and must not be named", level)
	case !strings.Contains(detail, "agent:analytics") || !strings.Contains(detail, "agent:support"):
		t.Errorf("step 9a: the detail %q does not name who was refused", detail)
	}

	// 9b — AN ANZEN RULE WATCHING IT ACTS, through the enforcement path.
	fired := r.dispatch.Observe(ctx, "denial_storm", level)
	if len(fired) != 1 || fired[0] != "alert-on-storm" {
		t.Fatalf("step 9b: the rising edge fired %v; want [alert-on-storm]", fired)
	}
	var alerted *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetIdentity().GetSubject().GetPrincipal() == "anzen:alert-on-storm" {
			alerted = d
		}
	}
	if alerted == nil || !strings.Contains(alerted.GetReason(), "denial_storm") || !strings.Contains(alerted.GetReason(), hog) {
		t.Errorf("step 9b: the alert's record is %v; want it to name denial_storm and %s", alerted, hog)
	}

	// 9c — THE LEVEL FALLS WHEN THE WINDOW EMPTIES, and the dispatcher re-arms
	// rather than firing on a condition that has cleared.
	time.Sleep(60 * time.Millisecond)
	if cleared := r.denials.Storms(50*time.Millisecond, 3); len(cleared) != 0 {
		t.Errorf("step 9c: after the window the level is still %v; contention clears, and so must this", cleared)
	}
	if again := r.dispatch.Observe(ctx, "denial_storm", map[string]string{}); len(again) != 0 {
		t.Errorf("step 9c: a cleared level fired %v", again)
	}
	r.detail(t, "%s drained kata:metered; 4 refusals of analytics and support attributed to it; the level named "+
		"%s alone, alert-on-storm recorded it, and the level fell when the window emptied", hog, hog)
}
