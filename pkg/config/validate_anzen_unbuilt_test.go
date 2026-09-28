package config

import "testing"

// TestAnEnforcingRuleMayOnlyDoWhatIsBuilt — D331. An enforcing rule doing an
// action no firing path implements is refused at boot, naming the ledger entry;
// the same rule in shadow only logs, and loads.
func TestAnEnforcingRuleMayOnlyDoWhatIsBuilt(t *testing.T) {
	rule := func(mode string) string {
		return base + `
anzen:
  - name: alert-on-budget
    enabled: true
    mode: ` + mode + `
    watches: budget_exceeded
    do: restrict_shin
    subject: kata:alpha
`
	}
	refuses(t, docFromYAML(t, rule("enforce")), "anzen:restrict_shin")
	accepts(t, docFromYAML(t, rule("shadow")))
}

// TestADisableReflexRuleNamesAReflexThatExists — D332: a typo here is a response
// that finds nothing to stop at the moment it fires.
func TestADisableReflexRuleNamesAReflexThatExists(t *testing.T) {
	rule := func(subject string) string {
		return base + `
reflexes:
  - name: friction-to-ticket
    principal: reflex:friction
    enabled: true
    consumes: sekizui.enriched.friction_detected
    action: kata.create_issue
    target: kata:alpha
anzen:
  - name: halt
    enabled: true
    mode: enforce
    watches: budget_exceeded
    do: disable_reflex
    subject: ` + subject + "\n"
	}
	accepts(t, docFromYAML(t, rule("friction-to-ticket")))
	refuses(t, docFromYAML(t, rule("friction-to-tickte")), `disables reflex "friction-to-tickte"`)
}

// TestARevokeGrantRuleNamesADeclaredPrincipalBare — D340: bare, as a signal
// names a principal, and one configuration declares.
func TestARevokeGrantRuleNamesADeclaredPrincipalBare(t *testing.T) {
	rule := func(subject string) string {
		return base + `
anzen:
  - name: suspend
    enabled: true
    mode: enforce
    watches: denial_storm
    do: revoke_grant
    subject: ` + subject + "\n"
	}
	accepts(t, docFromYAML(t, rule("reflex:friction")))
	refuses(t, docFromYAML(t, rule("principal:reflex:friction")), "name it bare")
	refuses(t, docFromYAML(t, rule("agent:nobody")), `suspends principal "agent:nobody"`)
}
