package config

import "testing"

// A `where: {target_residency: ...}` constraint is STATICALLY DECIDABLE (D136):
// a capability names its target by exact ref, and a target declares exactly one
// residency, so whether the constraint can ever match is knowable from the
// document alone. Leaving it to runtime produces a grant that silently denies
// every command forever — the hardest config bug to find, because everything a
// reviewer would inspect is present and correct.

const residencyBase = `
targets:
  - {ref: kata:eu, kind: kata, residency: eu, credential: env://TOK}
  - {ref: kata:us, kind: kata, residency: us, credential: env://TOK}
  - {ref: kata:anywhere, kind: kata, credential: env://TOK}
anzen:
  - {name: compromise, enabled: true, mode: enforce, watches: credential_stale, do: revoke_credential, subject: kata:eu}
`

func residencyGrant(t *testing.T, grants string) *Document {
	t.Helper()
	return docFromYAML(t, residencyBase+"\ngrants:\n"+grants)
}

func TestAResidencyConstraintThatCanNeverMatchIsRefused(t *testing.T) {
	refuses(t, residencyGrant(t, `
  - principal: agent:confused
    allow:
      - {action: kata.read, target: kata:us, where: {target_residency: [eu]}}
`), "can never fire")
}

// A LIST IS MEMBERSHIP, so a constraint naming several classes is satisfiable
// when the target's is among them — matching the engine's rule exactly, because
// both call config.ConstraintSatisfied.
func TestAResidencyConstraintListIsMembership(t *testing.T) {
	accepts(t, residencyGrant(t, `
  - principal: agent:multi
    allow:
      - {action: kata.read, target: kata:us, where: {target_residency: [eu, us, jp]}}
`))

	refuses(t, residencyGrant(t, `
  - principal: agent:multi
    allow:
      - {action: kata.read, target: kata:us, where: {target_residency: [eu, jp]}}
`), "can never fire")
}

// A SCALAR IS EQUALITY, the other form the vocabulary already supports.
func TestAResidencyConstraintScalarIsEquality(t *testing.T) {
	accepts(t, residencyGrant(t, `
  - principal: agent:one
    allow:
      - {action: kata.read, target: kata:eu, where: {target_residency: eu}}
`))
}

// CONSTRAINING A TARGET THAT DECLARES NO RESIDENCY is refused rather than
// treated as always-false at runtime. The author plainly believes the target has
// a class; telling them at boot beats a grant that denies forever.
func TestAResidencyConstraintOnAnUnclassifiedTargetIsRefused(t *testing.T) {
	refuses(t, residencyGrant(t, `
  - principal: agent:hopeful
    allow:
      - {action: kata.read, target: kata:anywhere, where: {target_residency: [eu]}}
`), "declares no residency")
}

// AN ANZEN REFERENCE IS A RULE, NOT A TARGET (D134), so it has no residency to
// constrain. Without this the lookup would miss, the capability would be treated
// as naming an unknown target, and the operator would get a misleading message
// about a rule that exists.
func TestAResidencyConstraintOnAnAnzenRuleIsRefused(t *testing.T) {
	refuses(t, residencyGrant(t, `
  - principal: operator:oncall
    allow:
      - {action: sekizui.fire_anzen, target: anzen:compromise, where: {target_residency: [eu]}}
`), "no residency to constrain")
}

// THE ABSENT CASE IS NOT AN ERROR, and this is the assertion that keeps it that
// way. A capability with no residency constraint is legitimate: in a
// single-class deployment it is the only sensible form, and in a multi-class one
// it means "this principal does not cross the border", which is a posture rather
// than a mistake. Whether absence DENIES is a deployment question this document
// cannot see — the grant engine answers it and cmd/sekizui reports it at boot.
//
// Written as a test because the tempting next commit is to refuse it here.
func TestAMissingResidencyConstraintIsNotAConfigError(t *testing.T) {
	accepts(t, residencyGrant(t, `
  - principal: agent:silent
    allow:
      - {action: kata.read, target: kata:us}
      - {action: kata.read, target: kata:anywhere}
`))
}
