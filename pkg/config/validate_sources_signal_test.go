package config

import "testing"

// TestAnUndeclaredSourceMayOnlyRaiseAnAlert is D280's structural guarantee:
// `source_undeclared` means a source emitted what its connector's schema does
// not declare — the source is behaving, and nothing undeclared was published —
// so no rule watching it may stop the source. Alert is accepted; the actions
// that would cut the source off are refused at boot. The connector-fault
// signal takes them, because there the connector is at fault.
func TestAnUndeclaredSourceMayOnlyRaiseAnAlert(t *testing.T) {
	// SHADOW for some alert rules below: D331 refused `alert` in enforce until
	// it had a firing path (enforced, it had REVOKED its subject, CONTRACTS
	// 157); P5 step 5 built one (D332), and the last line enforces one.
	rule := func(watches, do, subject string, mode ...string) *Document {
		m := "enforce"
		if len(mode) > 0 {
			m = mode[0]
		}
		return docFromYAML(t, shinBase+`
anzen:
  - name: r
    enabled: true
    mode: `+m+`
    watches: `+watches+`
    do: `+do+`
    subject: `+subject+`
`)
	}
	for _, do := range []string{"quarantine_target", "revoke_credential"} {
		refuses(t, rule("source_undeclared", do, "kata:alpha"), "may only [alert]")
	}
	refuses(t, rule("source_undeclared", "revoke_grant", "agent:triage"), "may only [alert]")
	accepts(t, rule("source_undeclared", "alert", "kata:alpha", "shadow"))
	accepts(t, rule("source_nonconforming", "quarantine_target", "kata:alpha"))
	accepts(t, rule("source_stopped", "alert", "kata:alpha", "shadow"))
	// D282: the quarantine is already the protective action; a rule may alert.
	refuses(t, rule("connector_quarantined", "quarantine_target", "kata:alpha"), "may only [alert]")
	accepts(t, rule("connector_quarantined", "alert", "kata", "shadow"))
	// AND IN ENFORCE since P5 step 5 built `alert` (D332) — it records, and
	// changes nothing, which is what D280 asked of it.
	accepts(t, rule("source_undeclared", "alert", "kata:alpha"))
}
