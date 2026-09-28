package config

import (
	"strings"
	"testing"
)

// Shin lenses are validated at boot for the same reason reflex rules are: a
// projection that silently never matches is indistinguishable from one that
// matches and removes nothing, and the symptom appears at a consumer weeks
// later (§4.12.2, D84).

// shinBase is a valid document a lens can hang off, so each test below changes
// exactly one thing.
const shinBase = `
targets:
  - {ref: kata:alpha, kind: kata, credential: env://TOK}
grants:
  - principal: agent:triage
    allow: [{action: kata.read, target: kata:alpha}]
  - principal: agent:analytics
    allow: [{action: kata.read, target: kata:alpha}]
payload_schemas:
  fullstory.rage_click.v1: '{"type":"object"}'
`

func shinDoc(t *testing.T, lenses string) *Document {
	t.Helper()
	return docFromYAML(t, shinBase+"\nshin:\n"+lenses)
}

func refuses(t *testing.T, doc *Document, want string) {
	t.Helper()
	err := doc.Validate()
	if err == nil {
		t.Fatalf("validation passed; expected a refusal mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("refusal does not mention %q:\n%v", want, err)
	}
}

func accepts(t *testing.T, doc *Document) {
	t.Helper()
	if err := doc.Validate(); err != nil {
		t.Fatalf("valid configuration was refused: %v", err)
	}
}

// TestARequestableLensCannotOfferWhatItsCeilingWithholds is the composition
// check, and the reason boot validation exists for lenses at all (D84).
//
// Without it, a consumer selects a lens naming user.email, never receives it,
// and has no way to learn why — "a declared contract that silently does
// nothing", with a network in the middle.
func TestARequestableLensCannotOfferWhatItsCeilingWithholds(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: ceiling
    enabled: true
    mode: imposed
    applies_to: ["agent:analytics"]
    withholds: [user.email]
    because: no lawful basis
  - name: wants-email
    enabled: true
    mode: requestable
    applies_to: ["agent:analytics"]
    type: fullstory.rage_click.v1
    fields: [session_id, user.email]
    because: it would like the email
`), "which imposed lens \"ceiling\" withholds")
}

// TestARequestableLensCannotOfferWhatItsCeilingDropped — the ceiling's
// allow-list binds just as hard as its deny-list. It runs first, so a field it
// does not keep is gone before the second lens is applied.
func TestARequestableLensCannotOfferWhatItsCeilingDropped(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: ceiling
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    type: fullstory.rage_click.v1
    fields: [session_id]
    because: only the identifier leaves
  - name: wants-url
    enabled: true
    mode: requestable
    applies_to: ["agent:triage"]
    type: fullstory.rage_click.v1
    fields: [session_id, url]
    because: it would like the url
`), "does not keep")
}

// TestARequestableCapAboveItsCeilingIsRefused — the tighter cap always wins, so
// a looser value is decoration that reads as configuration.
func TestARequestableCapAboveItsCeilingIsRefused(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: ceiling
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    max_bytes: 1024
    because: this consumer is small
  - name: bigger
    enabled: true
    mode: requestable
    applies_to: ["agent:triage"]
    max_bytes: 65536
    because: it would like more
`), "decoration")
}

// TestNarrowingFurtherIsFine — the whole point of the requestable mode.
func TestNarrowingFurtherIsFine(t *testing.T) {
	accepts(t, shinDoc(t, `
  - name: ceiling
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    withholds: [user.email]
    because: no lawful basis
  - name: narrower
    enabled: true
    mode: requestable
    applies_to: ["agent:triage"]
    type: fullstory.rage_click.v1
    fields: [session_id]
    because: it needs less than the ceiling permits
`))
}

// TestALensMustSayWhy. Same rule as anzen: a lens removes data, and "why does
// this consumer never see that field" must be answerable from configuration
// rather than from whoever wrote it.
func TestALensMustSayWhy(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: silent
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    withholds: [user.email]
`), "missing `because`")
}

// TestALensThatChangesNothingIsRefused — dead config that reads as governance
// is worse than no config, because a reviewer counts it as protection.
func TestALensThatChangesNothingIsRefused(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: inert
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    because: selects nothing, withholds nothing, caps nothing
`), "can never change what a consumer receives")
}

// TestARequestableLensMustNameItsConsumers — "anyone may select this" turns a
// lens offer into an open menu, and is almost never what someone meant.
func TestARequestableLensMustNameItsConsumers(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: open
    enabled: true
    mode: requestable
    withholds: [user.email]
    because: offered to nobody in particular
`), "names no `applies_to`")
}

// TestALensForAnUngrantedPrincipalIsRefused — a lens shaping what a principal
// that can do nothing receives is dead config.
func TestALensForAnUngrantedPrincipalIsRefused(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: ghost
    enabled: true
    mode: imposed
    applies_to: ["agent:ghost"]
    withholds: [user.email]
    because: nobody granted this principal anything
`), "which has no grant")
}

// TestAWildcardScopeIsAcceptedForPrincipalsAddedLater — "reflex:*" legitimately
// covers principals that do not exist yet.
func TestAWildcardScopeIsAcceptedForPrincipalsAddedLater(t *testing.T) {
	accepts(t, shinDoc(t, `
  - name: future
    enabled: true
    mode: imposed
    applies_to: ["reflex:*"]
    max_bytes: 4096
    because: a reflex never needs a whole session replayed
`))
}

// TestFieldsWithoutATypeIsRefused — no schema can confirm the paths, and D42
// exists precisely so that a path nobody validated does not silently stop
// matching.
func TestFieldsWithoutATypeIsRefused(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: untyped
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    fields: [session_id]
    because: no type to check the path against
`), "no schema can confirm those paths")
}

// TestWithholdsNeedsNoType — a withhold is meaningful across every payload,
// which is exactly what a jurisdiction rule needs.
func TestWithholdsNeedsNoType(t *testing.T) {
	accepts(t, shinDoc(t, `
  - name: jurisdiction
    enabled: true
    mode: imposed
    applies_to: ["agent:analytics"]
    withholds: [user.email]
    because: a compliance rule covering only one type would have a hole
`))
}

// TestDuplicateLensNamesAreRefused — a name is how a consumer selects one and
// how an operator finds it in a log.
func TestDuplicateLensNamesAreRefused(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: twice
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    withholds: [user.email]
    because: first
  - name: twice
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    withholds: [user.id]
    because: second
`), "declared twice")
}

// TestAnUnknownModeIsRefused.
func TestAnUnknownModeIsRefused(t *testing.T) {
	refuses(t, shinDoc(t, `
  - name: odd
    enabled: true
    mode: advisory
    applies_to: ["agent:triage"]
    withholds: [user.email]
    because: there is no advisory mode
`), "neither imposed nor requestable")
}

// TestRestrictShinIsInAnzensVocabulary is D85. Proven through configuration
// rather than by reading the map, so the vocabulary and what boot accepts
// cannot drift.
func TestRestrictShinIsInAnzensVocabulary(t *testing.T) {
	accepts(t, docFromYAML(t, shinBase+`
anzen:
  - name: ease-off
    enabled: true
    mode: shadow
    watches: denial_storm
    do: restrict_shin
    subject: agent:analytics
`))
}
