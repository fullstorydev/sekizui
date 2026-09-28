package conformance

import (
	"context"
	"reflect"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/connector"
)

// DriftCase is what RunDrift needs: two targets the connector can compare, and
// a tenant that is not theirs (D311).
type DriftCase struct {
	// Clean is a target whose live surface matches what the connector vetted.
	Clean connector.Target

	// Diverged is a target whose live surface differs: at least one finding
	// must come back, or the grading arm proves nothing.
	Diverged connector.Target

	// OtherTenant is any tenant that is not Clean's, for the egress arm.
	OtherTenant string
}

// RunDrift is the mandatory suite for a connector that implements
// connector.Drifter (D311). A connector reporting drift is making a SAFETY
// claim on a timer, with the target's credential: this is what holds it to it.
func RunDrift(t *testing.T, d connector.Driver, c DriftCase) {
	t.Helper()

	dr, ok := d.(connector.Drifter)
	if !ok {
		t.Fatalf("RunDrift was called for %q, which does not implement connector.Drifter", d.Kind())
	}
	if c.OtherTenant == "" || c.OtherTenant == c.Clean.Tenant() {
		t.Fatal("DriftCase.OtherTenant must be a tenant that is not the Clean target's, or the " +
			"egress arm checks nothing")
	}
	runDriftPriced(t, d, c)
	runDriftClean(t, dr, c)
	runDriftGraded(t, d, dr, c)
	runDriftReadOnly(t, dr, c)
	runDriftTenantAsserted(t, dr, c)
}

func own(t connector.Target) context.Context {
	return connector.WithTenant(context.Background(), t.Tenant())
}

func runDriftPriced(t *testing.T, d connector.Driver, c DriftCase) {
	t.Helper()
	t.Run("a comparison is priced before it is sent and paid from your own system budget", func(t *testing.T) {
		m := d.Meter()
		if m.SystemPerHour == 0 {
			t.Error("Meter.SystemPerHour is zero; a Drifter declares the system budget its comparisons " +
				"are charged to, so consumers never pay for Sekizui's safety checks (D311)")
		}
		cfg := connector.Configuration(c.Clean.Ref(), map[string]string{})
		if _, err := m.Drift(cfg); err != nil {
			t.Errorf("a comparison cannot be priced: %v", err)
		}
	})
}

func runDriftClean(t *testing.T, dr connector.Drifter, c DriftCase) {
	t.Helper()
	t.Run("a surface that matches what was vetted reports nothing", func(t *testing.T) {
		fs, err := dr.Drift(own(c.Clean), c.Clean)
		if err != nil {
			t.Fatalf("comparing the clean target: %v", err)
		}
		if len(fs) != 0 {
			t.Errorf("the clean target reported %d finding(s): %v — a comparison that cries wolf is "+
				"one somebody switches off", len(fs), fs)
		}
	})
}

func runDriftGraded(t *testing.T, d connector.Driver, dr connector.Drifter, c DriftCase) {
	t.Helper()
	t.Run("every difference is graded in the published vocabulary", func(t *testing.T) {
		fs, err := dr.Drift(own(c.Diverged), c.Diverged)
		if err != nil {
			t.Fatalf("comparing the diverged target: %v", err)
		}
		if len(fs) == 0 {
			t.Fatal("the diverged target reported nothing; this arm cannot check a grading it never sees")
		}
		actions := map[string]bool{}
		for _, a := range d.Actions() {
			actions[a.Name] = true
		}
		for _, f := range fs {
			switch {
			case !f.Severity.Known():
				t.Errorf("severity %q is not in the vocabulary %v; an unknown severity reads as a "+
					"finding and acts as nothing, so the store refuses it", f.Severity, connector.DriftSeverities())
			case f.Tool == "":
				t.Errorf("a finding names no tool: %v", f)
			case f.Severity.WithholdsAction() && !actions[f.Action]:
				t.Errorf("%v withholds %q, which you do not advertise — the catalog would withhold "+
					"nothing", f, f.Action)
			}
		}
	})
}

func runDriftReadOnly(t *testing.T, dr connector.Drifter, c DriftCase) {
	t.Helper()
	t.Run("a comparison only reads: two in a row agree", func(t *testing.T) {
		first, err := dr.Drift(own(c.Diverged), c.Diverged)
		if err != nil {
			t.Fatal(err)
		}
		second, err := dr.Drift(own(c.Diverged), c.Diverged)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Errorf("two comparisons of an unchanged target disagree:\n  %v\n  %v\nA safety check "+
				"with a side effect, or one whose answer depends on order, cannot be trusted on a timer",
				first, second)
		}
	})
}

func runDriftTenantAsserted(t *testing.T, dr connector.Drifter, c DriftCase) {
	t.Helper()
	t.Run("a comparison asserts the tenant before any egress", func(t *testing.T) {
		if _, err := dr.Drift(connector.WithTenant(context.Background(), c.OtherTenant), c.Clean); err == nil {
			t.Error("a comparison in another tenant's context was answered; a comparison carries the " +
				"target's credential, so §6 mechanism 3 applies to it as to any call (D311)")
		}
		if _, err := dr.Drift(context.Background(), c.Clean); err == nil {
			t.Error("a comparison with no tenant bound was answered; refuse rather than assume")
		}
	})
}
