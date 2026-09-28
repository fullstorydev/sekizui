package meter

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

type callsDriver struct{ poll uint64 }

func (callsDriver) Kind() string                                   { return "k" }
func (callsDriver) Actions() []connector.ActionSpec                { return nil }
func (callsDriver) Schemas() ([]connector.Schema, error)           { return nil, nil }
func (callsDriver) Health(context.Context, connector.Target) error { return nil }
func (d callsDriver) Meter() connector.Meter {
	return connector.Meter{PollCost: func(connector.Configured) uint64 { return d.poll }}
}
func (callsDriver) Query(context.Context, connector.Target, string, map[string]any) (connector.Rows, error) {
	return connector.Rows{}, nil
}
func (callsDriver) Execute(context.Context, connector.Target, string, map[string]any,
	connector.Idempotency) (connector.Result, error) {
	return connector.Result{}, nil
}

// TestARatelessBudgetMemberGetsNoDefault — D208's hazard: a default given to a
// member of a named budget would compete to size the bucket, and the limiter
// settles that by map order. The member draws on what the rated one declares.
func TestARatelessBudgetMemberGetsNoDefault(t *testing.T) {
	doc := &config.Document{Targets: []config.TargetSpec{
		{Ref: "a", Kind: "k", Limits: &config.TargetLimits{RatePerHr: 100, Budget: "b"}},
		{Ref: "c", Kind: "k", Limits: &config.TargetLimits{Budget: "b"}},
	}}
	p, err := Build(doc, map[string]connector.Driver{"k": callsDriver{poll: 1}}, nil, Bounds{})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Rates["c"].PerHour; got != 0 {
		t.Errorf("the rate-less member got %d/hr; it must draw on the budget, not bring a default", got)
	}
	if got := p.BurstFor("c"); got != 10 {
		t.Errorf("BurstFor through the budget = %d; want the rated member's 100/10", got)
	}
}

// TestQuarantinedAndUnknownKindsAreNotMetered — refused elsewhere, loudly.
func TestQuarantinedAndUnknownKindsAreNotMetered(t *testing.T) {
	doc := &config.Document{Targets: []config.TargetSpec{{Ref: "q", Kind: "k"}, {Ref: "u", Kind: "nobody"}}}
	p, err := Build(doc, map[string]connector.Driver{"k": callsDriver{}}, map[string]string{"k": "unsound"}, Bounds{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rates) != 0 {
		t.Errorf("rates for targets nothing can serve: %v", p.Rates)
	}
}

// TestAZeroPricedSourceRefusesTheBoot — a free poll is a way past the budget.
func TestAZeroPricedSourceRefusesTheBoot(t *testing.T) {
	doc := &config.Document{
		Targets: []config.TargetSpec{{Ref: "s", Kind: "k"}},
		Sources: []config.SourceSpec{{TargetRef: "s", EverySec: 30, Limit: 1}},
	}
	_, err := Build(doc, map[string]connector.Driver{"k": callsDriver{poll: 0}}, nil, Bounds{})
	if err == nil || !strings.Contains(err.Error(), "never free") {
		t.Errorf("a source priced at zero booted: %v", err)
	}
}

// TestTheUniversalDefaultIsTheFlagsValue — Bounds.DefaultCalls, not the constant.
func TestTheUniversalDefaultIsTheFlagsValue(t *testing.T) {
	doc := &config.Document{Targets: []config.TargetSpec{{Ref: "t", Kind: "k"}}}
	p, err := Build(doc, map[string]connector.Driver{"k": callsDriver{poll: 1}}, nil, Bounds{DefaultCalls: 42})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Rates["t"].PerHour; got != 42 {
		t.Errorf("-meter-default-calls 42 gave %d/hr", got)
	}
}
