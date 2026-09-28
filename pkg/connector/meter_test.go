package connector

import (
	"context"
	"strings"
	"testing"
)

// meterDriver is a Driver whose only interesting method is Meter.
type meterDriver struct{ m Meter }

func (meterDriver) Kind() string                         { return "metered" }
func (meterDriver) Actions() []ActionSpec                { return nil }
func (meterDriver) Schemas() ([]Schema, error)           { return nil, nil }
func (d meterDriver) Meter() Meter                       { return d.m }
func (meterDriver) Health(context.Context, Target) error { return nil }
func (meterDriver) Query(context.Context, Target, string, map[string]any) (Rows, error) {
	return Rows{}, nil
}
func (meterDriver) Execute(context.Context, Target, string, map[string]any, Idempotency) (Result, error) {
	return Result{}, nil
}

// meterSource is the same, and a Source.
type meterSource struct{ meterDriver }

func (meterSource) Poll(context.Context, Target, string, int) ([]RawEvent, string, error) {
	return nil, "", nil
}
func (meterSource) Recovery(Target) RecoveryPolicy { return RecoveryPolicy{} }

// TestCheckMeter — what quarantines a connector's meter (D284), case by case,
// including the cases that must NOT: the zero value is sound for calls.
func TestCheckMeter(t *testing.T) {
	one := func(Configured) uint64 { return 1 }
	cost := func(string, map[string]any) (uint64, error) { return 3, nil }
	for _, tc := range []struct {
		name string
		d    Driver
		want string // "" = sound
	}{
		{"zero value, calls, not a source", meterDriver{}, ""},
		{"a source with its poll priced", meterSource{meterDriver{Meter{PollCost: one}}}, ""},
		{"a source without", meterSource{}, "declares no PollCost"},
		{"own unit, complete", meterDriver{Meter{Unit: "bytes_scanned", DefaultPerHour: 9, ActionCost: cost}}, ""},
		{"own unit, no default", meterDriver{Meter{Unit: "bytes_scanned", ActionCost: cost}}, "declares no DefaultPerHour"},
		{"own unit, no action cost", meterDriver{Meter{Unit: "records", DefaultPerHour: 9}}, "declares no ActionCost"},
		{"a unit that is not a word", meterDriver{Meter{Unit: "Bytes Scanned", DefaultPerHour: 9, ActionCost: cost}}, "not lower-case"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(CheckMeter(tc.d), "; ")
			switch {
			case tc.want == "" && got != "":
				t.Errorf("a sound meter was refused: %s", got)
			case tc.want != "" && !strings.Contains(got, tc.want):
				t.Errorf("want a problem containing %q, got %q", tc.want, got)
			}
		})
	}
}

// TestMeterRefusesAFreeCall — a price of zero is a way past the budget.
func TestMeterRefusesAFreeCall(t *testing.T) {
	m := Meter{Unit: "records", ActionCost: func(string, map[string]any) (uint64, error) { return 0, nil },
		PollCost: func(Configured) uint64 { return 0 }}
	if _, err := m.Cost("x", nil); err == nil {
		t.Error("an action priced at zero was admitted as free")
	}
	if _, err := m.Poll(Configuration("t", nil)); err == nil {
		t.Error("a poll priced at zero was admitted as free")
	}
	if c, err := (Meter{}).Cost("x", nil); c != 1 || err != nil {
		t.Errorf("the zero meter prices a call at %d (%v); want 1", c, err)
	}
}
