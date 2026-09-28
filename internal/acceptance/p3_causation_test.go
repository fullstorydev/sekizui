package acceptance

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step7 — every envelope carries a causation chain and a depth, and the
// translated event names the poll that produced it (P3 criterion 2, D19, D272).
//
// **PRESENT AND CORRECT, AND THE SECOND IS THE ONE THAT GETS SKIPPED.** A
// decision id that is merely non-empty would pass with a plausible value — P1
// step 65's `test-config` lesson — so the arm JOINS it: the id must name an
// INTENT row in the audit log, written before the envelope was published, and
// an OUTCOME for the same id saying how many were published. Both triggers.
func p3Step7(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "every envelope carries a causation chain and a depth, and names the poll that produced it")
	if r.localOnly(t, "the runner and the audit log are this instance's") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 7a — A CALLER'S JOB.
	caller := r.as(t, "agent:jobs")
	started, err := caller.StartJob(ctx, &sekizuiv1.StartJobRequest{
		Command: &sekizuiv1.Command{Action: "kata.poll", TargetRef: "kata:alpha"},
	})
	if err != nil || started.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 7a: StartJob: %v %s", err, started.GetReason())
	}
	stream, err := caller.JobResults(ctx, &sekizuiv1.JobResultsRequest{JobId: started.GetJobId()})
	if err != nil {
		t.Fatalf("step 7a: %v", err)
	}
	var jobEnvs []*sekizuiv1.Envelope
	for {
		m, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("step 7a: %v", rerr)
		}
		jobEnvs = append(jobEnvs, m.GetEnvelope())
	}
	assertCausation(t, r, "7a", jobEnvs, started.GetJobId(), "agent:jobs")

	// 7b — A SCHEDULE: no caller, so its principal is `source:kata:alpha`, and
	// each envelope is its own root.
	sub, err := r.as(t, "agent:scoped").Subscribe(ctx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.raw.kata.>"},
	})
	if err != nil {
		t.Fatalf("step 7b: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 }, "the subscription never registered")
	// 7c rides on the same schedule: a reflex consuming its envelopes.
	runEngine(t, r, "unarmed-ticket")
	runner := newScheduleRunner(t, r, ctx)
	if err := runner.Start(ctx); err != nil {
		t.Fatalf("step 7b: %v", err)
	}
	defer func() { _ = runner.Stop(context.Background()) }()
	got, err := sub.Recv()
	if err != nil {
		t.Fatalf("step 7b: %v", err)
	}
	assertCausation(t, r, "7b", []*sekizuiv1.Envelope{got.GetEnvelope()}, "", "source:kata:alpha")

	// 7c — AND WHAT IT CAUSED NAMES IT TOO. A rule firing on the scheduled
	// envelope records a decision whose causation carries the poll's decision
	// forward, so the log joins poll -> envelope -> command without a guess.
	scheduled := got.GetEnvelope()
	fired := causedBy(t, r, scheduled.GetId(), "the rule never fired on the scheduled envelope")
	if fired.GetCausation().GetDecisionId() != scheduled.GetCausation().GetDecisionId() {
		t.Errorf("step 7c: the command unarmed-ticket fired names decision %q; the envelope that "+
			"caused it was produced under %q — the chain breaks at the reflex",
			fired.GetCausation().GetDecisionId(), scheduled.GetCausation().GetDecisionId())
	}

	r.detail(t, "%d job envelope(s) and a scheduled one each carried depth 0, produced_by "+
		"translator:kata, and a decision_id naming an intent written before publishing and its "+
		"outcome — attributed to agent:jobs and source:kata:alpha respectively", len(jobEnvs))
}

// assertCausation checks each envelope's chain and JOINS its decision_id to the
// audit log. root "" means each envelope must be its own root (a schedule).
func assertCausation(t *testing.T, r *run, arm string, envs []*sekizuiv1.Envelope, root, principal string) {
	t.Helper()
	if len(envs) == 0 {
		t.Fatalf("step %s: no envelopes to check", arm)
	}
	var decision string
	for _, env := range envs {
		c := env.GetCausation()
		wantRoot := root
		if wantRoot == "" {
			wantRoot = env.GetId()
		}
		switch {
		case c.GetRootId() != wantRoot:
			t.Errorf("step %s: root %q, want %q", arm, c.GetRootId(), wantRoot)
		case c.GetDepth() != 0 || c.GetProducedBy() != "translator:kata":
			t.Errorf("step %s: depth %d produced_by %q, want 0 and translator:kata", arm, c.GetDepth(), c.GetProducedBy())
		case c.GetDecisionId() == "":
			t.Fatalf("step %s: envelope %s names no decision; it cannot be joined to the poll that "+
				"produced it (D272)", arm, env.GetId())
		}
		decision = c.GetDecisionId()
	}
	var intent, outcome *sekizuiv1.Decision
	waitFor(t, func() bool {
		intent, outcome = nil, nil
		for _, d := range readLog(t, r.path) {
			if d.GetId() != decision {
				continue
			}
			switch d.GetPhase() {
			case sekizuiv1.Phase_PHASE_INTENT:
				intent = d
			case sekizuiv1.Phase_PHASE_OUTCOME:
				outcome = d
			}
		}
		return intent != nil && outcome != nil
	}, "the poll's decision had no intent and outcome in the log")
	if intent.GetAction() != "kata.poll" || intent.GetIdentity().GetSubject().GetPrincipal() != principal {
		t.Errorf("step %s: decision %s is %s by %s; want kata.poll by %s — the envelope names a row "+
			"about something else", arm, decision, intent.GetAction(),
			intent.GetIdentity().GetSubject().GetPrincipal(), principal)
	}
	if !outcome.GetEffect().GetSuccess() {
		t.Errorf("step %s: the poll's outcome records failure", arm)
	}
}
