package main

import "testing"

// TestMeterCeilingsFlag — repeatable, one unit once, positive, 32-bit.
func TestMeterCeilingsFlag(t *testing.T) {
	m := meterCeilings{}
	for _, ok := range []string{"calls=3600", "bytes_scanned=1000000"} {
		if err := m.Set(ok); err != nil {
			t.Errorf("Set(%q): %v", ok, err)
		}
	}
	if m["calls"] != 3600 || m.String() != "bytes_scanned=1000000,calls=3600" {
		t.Errorf("parsed %v / %q", map[string]uint32(m), m.String())
	}
	for _, bad := range []string{"calls=1", "calls", "=5", "records=0", "records=-1", "records=4294967296", "records=x"} {
		if err := m.Set(bad); err == nil {
			t.Errorf("Set(%q) was accepted", bad)
		}
	}
}
