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

// p6Step9 — D340, a v1 hotfix, FILED AS P6 STEP 9 (D341) so it is not hidden: `revoke_grant`
// fired from a rule. The case it exists for, end to end on the real gateway: a
// denial storm names the agent draining a budget, and a rule suspends THAT
// agent's grants — through the governed verb, recorded as the rule's — while
// the agents it crowded out keep working.
//
// NOT A P5 STEP: v1 is signed on P5's table as it stood (D339); P6's table,
// declared early for it, carries it built, with its mutation.
func p6Step9(t *testing.T) {
	const hog = "agent:metered"
	victims := []string{"agent:analytics", "agent:support"}
	r := newRunWith(t, runOpts{patch: func(d *config.Document) {
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
		d.Anzen = append(d.Anzen, config.AnzenSpec{Name: "suspend-the-hog", Enabled: true, Mode: "enforce",
			Watches: "denial_storm", Do: "revoke_grant", Subject: hog})
	}})
	if r.localOnly(t, "the tally and the dispatcher are this instance's") {
		return
	}
	r.narrate(t, "an anzen rule suspends the principal a denial storm names, and the record says why")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	create := func(who, key string) *sekizuiv1.CommandResult {
		req := execute("kata.create_issue", "kata:metered", map[string]any{"project": "PROJ"})
		req.Command.IdempotencyKey = key
		resp, err := r.as(t, who).Execute(ctx, req)
		if err != nil {
			t.Fatalf("%s: %v", who, err)
		}
		return resp.GetResult()
	}
	if s := create(hog, "hotfix-hog").GetStatus(); s != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("the first call on kata:metered was %v", s)
	}
	for _, v := range victims {
		for i := range 2 {
			create(v, fmt.Sprintf("hotfix-%s-%d", v, i))
		}
	}
	level := r.denials.Storms(time.Minute, 3)
	if _, named := level[hog]; !named {
		t.Fatalf("the storm level %v does not name %s; the rule has nothing to act on", level, hog)
	}

	// THE RULE FIRES, THROUGH THE GOVERNED VERB, RECORDED AS ITS OWN.
	if fired := r.dispatch.Observe(ctx, "denial_storm", level); len(fired) != 1 || fired[0] != "suspend-the-hog" {
		t.Fatalf("the storm fired %v; want [suspend-the-hog]", fired)
	}
	var rec *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetIdentity().GetSubject().GetPrincipal() == "anzen:suspend-the-hog" {
			rec = d
		}
	}
	// THE REASON IS ON THE RECORD — it was not, for any suspension, until this
	// test found it (CONTRACTS 158).
	if rec == nil || rec.GetTargetRef() != "principal:"+hog || !strings.Contains(rec.GetReason(), "denial_storm") {
		t.Errorf("the suspension's record is %v; want target principal:%s and a reason naming the signal", rec, hog)
	}

	// THE HOG IS SUSPENDED, AND ONLY THE HOG.
	read := func(who, target string) *sekizuiv1.QueryResponse {
		resp, err := r.as(t, who).Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: target})
		if err != nil {
			t.Fatalf("%s: %v", who, err)
		}
		return resp
	}
	if got := read(hog, "kata:metered"); got.GetStatus() != sekizuiv1.Status_STATUS_DENIED {
		t.Errorf("%s, suspended by the rule, read kata:metered with %v; want refused", hog, got.GetStatus())
	}
	if got := read("agent:analytics", "kata:alpha"); got.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("agent:analytics, a victim of the storm, was refused a read (%v %s); the rule suspends the "+
			"cause, never the agents it crowded out", got.GetStatus(), got.GetReason())
	}
	r.detail(t, "a storm named %s; suspend-the-hog fired revoke_grant through the governed verb, recorded with "+
		"its reason; %s refused, a victim still served", hog, hog)
}
