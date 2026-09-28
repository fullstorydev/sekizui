package gateway

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// DriftPrincipal is the built-in identity every drift comparison runs and is
// recorded as (D311).
//
// **BUILT IN, AND NEEDING NO GRANT (the maintainer, D311).** A drift comparison is a
// SAFETY check: if it ran under an operator's grant, deleting that grant would
// switch drift detection off without a word — anzen's reasoning for its own
// actions (§4.11.7). It is closed to ONE action on ONE kind of target, and it
// still passes every ceiling: a withdrawn target, a residency the deployment
// does not serve, or an anzen guard each refuses it, and the refusal is
// recorded like any other.
const DriftPrincipal = "sekizui:drift-watcher"

// DriftAction is the action a comparison is admitted and recorded under.
const DriftAction = "sekizui.drift_check"

// DriftGate adapts the Server onto drift.Gate (D311).
//
// UNEXPORTED TYPE, CONSTRUCTED ONLY HERE, like JobGate: there is no way to
// build one around anything but the real ceilings and the real recorder.
func (s *Server) DriftGate() drift.Gate {
	return driftGate{s: s, id: driftIdentity()}
}

type driftGate struct {
	s  *Server
	id *sekizuiv1.Identity
}

// driftIdentity mints the drift principal's identity — a NAMED minting site
// (TestOnlyNamedSitesMintAnIdentity). INTERNAL, not UNSPECIFIED, and ASSERTED,
// not SIGNED: nothing cryptographic happened (D57), as for a schedule.
func driftIdentity() *sekizuiv1.Identity {
	return &sekizuiv1.Identity{
		Caller: &sekizuiv1.Caller{
			Principal:    DriftPrincipal,
			Method:       sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL,
			CredentialId: "drift-watcher",
		},
		Subject: &sekizuiv1.Subject{
			Principal: DriftPrincipal,
			Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED,
		},
		Chain: []string{DriftPrincipal},
	}
}

// Admit is admitUnasked — THE sequence a poll takes: ceilings, withdrawal,
// price, meter — with no policy call (the principal is granted nothing, D311)
// and the charge going to the target's SYSTEM budget. Every refusal is
// recorded by the stage that made it.
func (g driftGate) Admit(ctx context.Context, targetRef string) error {
	const op = "gateway.driftGate.Admit"
	s := g.s
	return s.admitUnasked(ctx, g.id, targetRef, unasked{
		op: op, action: DriftAction, authorise: false,
		budgetRef: connector.SystemBudgetRef(targetRef),
		price:     func() (uint64, error) { return s.driftPrice(op, targetRef) },
	})
}

// Record writes one comparison's decision record: `drift:clean`,
// `drift:diverged` with every finding, or `drift:failed` with the error.
//
// **THE FINDINGS GO IN `Effect.detail`**, the carrier a poll's count and a
// gap's lost ids already use (D177) — so the record is the durable history of
// the finding, first seen to last seen, derivable from the log alone.
func (g driftGate) Record(ctx context.Context, targetRef string, c drift.Comparison) error {
	findings := make([]*structpb.Value, 0, len(c.Findings))
	for _, f := range c.Findings {
		findings = append(findings, structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
			"severity": structpb.NewStringValue(string(f.Severity)),
			"tool":     structpb.NewStringValue(f.Tool),
			"action":   structpb.NewStringValue(f.Action),
			"detail":   structpb.NewStringValue(f.Detail),
		}}))
	}
	detail := map[string]*structpb.Value{
		"outcome":         structpb.NewStringValue(string(c.Outcome)),
		"findings":        structpb.NewListValue(&structpb.ListValue{Values: findings}),
		"state_persisted": structpb.NewBoolValue(c.Persisted),
	}
	effect := &sekizuiv1.Effect{Success: c.Outcome != drift.OutcomeFailed,
		Detail: &structpb.Struct{Fields: detail}}
	reason := "the live tool list matches the vetted spec"
	switch c.Outcome {
	case drift.OutcomeDiverged:
		reason = fmt.Sprintf("%d finding(s) against the vetted spec", len(c.Findings))
	case drift.OutcomeFailed:
		reason = "the comparison did not complete; the last known state is kept"
		if c.Err != nil {
			effect.Error = c.Err.Error()
		}
	}
	_, err := g.s.recorder.Terminal(ctx, &sekizuiv1.Decision{
		Identity:    g.id,
		Action:      DriftAction,
		TargetRef:   targetRef,
		Verdict:     sekizuiv1.Verdict_VERDICT_ALLOW,
		MatchedRule: "drift:" + string(c.Outcome),
		Reason:      reason,
		Effect:      effect,
	})
	return err
}
