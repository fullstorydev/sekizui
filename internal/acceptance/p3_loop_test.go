package acceptance

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step21 — the loop closes on a REAL connector, in shadow (D172, criterion 8).
//
// Step 7c already proves a rule fires on a scheduled kata envelope. What this
// adds is the half the criterion is about: the envelope is a Fullstory session
// event, polled by the real Fullstory driver through the real schedule (step
// 18's fixture standing in for api.fullstory.com), and the command it causes
// is asserted to have taken THE SAME enforcement path as an agent's — on the
// decision record, compared WHOLE against an agent's dry run of the same
// command, with the fields allowed to differ named one by one.
//
// **WHOLE, NOT FIELD BY FIELD.** A check listing the fields it expects to be
// equal passes a reflex path that forgot to stamp a field added next year; a
// comparison of the whole record with an allowlist of what MAY differ fails it.
// The allowlist is the claim, and each entry says why.
func p3Step21(t *testing.T) {
	r := eventsRunWith(t, config.TargetLimits{}, nil)
	if r.localOnly(t, "the runner, the engine and the bus are this instance's") {
		return
	}
	r.narrate(t, "a polled Fullstory event becomes an envelope, a rule matches it, and the "+
		"command traverses the same enforcement path an agent's would")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runEngine(t, r, "session-event-ticket")
	// EVERY SECOND, because the runner's first poll comes one interval after it
	// starts (CONTRACTS 134).
	runner := newRunnerFor(t, r, ctx,
		[]config.SourceSpec{{TargetRef: "fs:events", EverySec: 1, Limit: 10}},
		cursor.NewFileStore(t.TempDir()))
	if err := runner.Start(ctx); err != nil {
		t.Fatalf("step 21: the schedule did not start: %v", err)
	}
	defer func() { _ = runner.Stop(context.Background()) }()

	var fired *sekizuiv1.Decision
	waitFor(t, func() bool {
		for _, d := range readLog(t, r.path) {
			if d.GetReflexName() == "session-event-ticket" {
				fired = d
				return true
			}
		}
		return false
	}, "the rule never fired on a polled Fullstory session event")

	// 21a — THE CAUSE IS A REAL CONNECTOR'S POLL. The firing's causation names
	// the decision that produced its envelope; that decision must be the
	// scheduled Fullstory poll, run as the source's own principal.
	var poll *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetId() == fired.GetCausation().GetDecisionId() && d.GetPhase() == sekizuiv1.Phase_PHASE_INTENT {
			poll = d
		}
	}
	switch {
	case poll == nil:
		t.Fatalf("step 21a: the firing names decision %q, which is not in the log — the command "+
			"cannot be joined to what caused it", fired.GetCausation().GetDecisionId())
	case poll.GetAction() != "fullstory.poll" || poll.GetTargetRef() != "fs:events" ||
		poll.GetIdentity().GetSubject().GetPrincipal() != "source:fs:events":
		t.Fatalf("step 21a: the firing was caused by %s on %s as %s; want the scheduled "+
			"fullstory.poll of fs:events as source:fs:events", poll.GetAction(), poll.GetTargetRef(),
			poll.GetIdentity().GetSubject().GetPrincipal())
	case fired.GetCausation().GetDepth() != 1:
		t.Errorf("step 21a: the firing is at causation depth %d; a command caused by a polled "+
			"envelope is one step from its root", fired.GetCausation().GetDepth())
	}
	// THE `where` IS WHAT MATCHED, NOT THE SUBJECT ALONE: the poll put several
	// kinds of event on the bus, and one is a `navigate`.
	firings := 0
	for _, d := range readLog(t, r.path) {
		if d.GetReflexName() == "session-event-ticket" {
			firings++
		}
	}
	if firings != 1 {
		t.Errorf("step 21a: the rule fired %d times; the poll published one navigate among "+
			"several kinds, and only it matches `event_type eq navigate`", firings)
	}

	// 21b — THE SAME ENFORCEMENT PATH, ON THE RECORD. An agent granted the same
	// action dry-runs the same command, and the two records must be identical
	// once the fields that are ABOUT who asked, and when, are set aside.
	resp, err := r.as(t, "agent:binding").Execute(ctx, &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
		Action: "kata.create_issue", TargetRef: "kata:alpha", DryRun: true,
		Args: mustArgs(t, map[string]any{"project": "PROJ"}),
	}})
	if err != nil {
		t.Fatalf("step 21b: the agent's dry run: %v", err)
	}
	agentID := resp.GetResult().GetDecisionId()
	var theirs *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetId() == agentID {
			theirs = d
		}
	}
	if theirs == nil {
		t.Fatalf("step 21b: the agent's decision %s is not in the log", agentID)
	}
	if got, want := phasesOf(t, r, fired.GetId()), phasesOf(t, r, agentID); !slices.Equal(got, want) {
		t.Errorf("step 21b: the reflex's decision was written in phases %v and the agent's in %v; "+
			"the same path writes the same rows", got, want)
	}
	mine, agents := comparable(fired), comparable(theirs)
	if !proto.Equal(mine, agents) {
		t.Errorf("step 21b: the reflex's decision differs from an agent's in more than who asked. "+
			"A field the reflex path does not stamp — or stamps differently — is a shorter path "+
			"(D18):\n  reflex: %s\n  agent:  %s", protojson.Format(mine), protojson.Format(agents))
	}
	r.detail(t, "the scheduled Fullstory poll published its events; one navigate matched and "+
		"recorded WOULD_HAVE_FIRED, and its record equals an agent's dry run except in the %d "+
		"fields that name who asked and when", len(mayDiffer))
}

// mayDiffer is what may differ between a reflex's decision and an agent's for
// the same command — and nothing else may. Each entry is part of step 21's
// claim, so each says why.
var mayDiffer = []struct{ field, why string }{
	{"id", "per record"},
	{"at", "per record"},
	{"prev_hash", "per record: the chain position"},
	{"identity", "the principal — the ONE difference D172 permits"},
	{"matched_rule", "names the principal's own grant, a function of the principal"},
	{"causation", "an internally produced command says what caused it; an agent's has no parent"},
	{"reflex_name", "which rule produced the command"},
	{"idempotency_key", "the engine keys a firing by (rule, envelope) for dedupe; the agent sent none"},
}

// comparable is the record with every mayDiffer field cleared. A name Decision
// does not have fails loudly, so a renamed field cannot quietly widen the claim.
func comparable(d *sekizuiv1.Decision) *sekizuiv1.Decision {
	c := proto.Clone(d).(*sekizuiv1.Decision)
	fields := c.ProtoReflect().Descriptor().Fields()
	for _, m := range mayDiffer {
		f := fields.ByName(protoreflect.Name(m.field))
		if f == nil {
			panic("step 21: mayDiffer names " + m.field + ", which Decision does not have")
		}
		c.ProtoReflect().Clear(f)
	}
	return c
}

func phasesOf(t *testing.T, r *run, id string) []string {
	t.Helper()
	var out []string
	for _, d := range readLog(t, r.path) {
		if d.GetId() == id {
			out = append(out, d.GetPhase().String())
		}
	}
	slices.Sort(out)
	return out
}
