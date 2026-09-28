package acceptance

import (
	"context"
	"testing"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/catalog"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// P2 steps 22 and 23: what `Describe` discloses is recorded, and what it
// withholds is explained.

// step22DescribeWritesAChainCarriedRecord proves D166's audit half and D205's
// unproven refusal.
//
// **D79 REFUSED TO AUDIT `Describe` AND THIS AMENDS THAT HALF.** The dilution
// objection — "a row per enumeration would dilute a log whose value is that
// every row is an action" — is answered by a row shape a query can exclude, and
// D79's volume premise contradicted its own text ("a call agents make rarely").
// What decided it is TAMPER-EVIDENCE: the only identity-carrying trace of
// enumeration was a log line, self-describe is DEBUG (D126), and CONTRACTS 28
// says that log silently loses records on rotation. A default deployment held no
// durable record that an agent had enumerated the fleet.
//
// **THE CHAIN ARM IS THE ONE WITH TEETH.** A row that is merely PRESENT gives an
// attacker the same thing the log line gave: something to delete. The claim is
// that the enumeration trace is now inside the hash chain, and the only way to
// assert that is to remove it and watch verification break.
func step22DescribeWritesAChainCarriedRecord(t *testing.T) {
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	if r.localOnly(t, "it reads this process's audit log and verifies its hash chain") {
		return
	}

	ctx := context.Background()

	// **AN ORDINARY COMMAND FIRST, AND THE CHAIN ARM BELOW IS WHY.**
	//
	// `VerifyChain` accepts a record with an EMPTY `prev_hash` as the start of a
	// new segment — one per process lifetime, and §5.2.2 states the consequence
	// plainly: a removed TAIL is undetectable until the WAL persists its tail
	// hash. Each acceptance step builds its own recorder, so a step whose only
	// record is the one under test writes it as first-of-segment, where deleting
	// it leaves a perfectly valid shorter chain.
	//
	// The first draft of this step asserted the deletion broke verification and
	// FAILED, correctly, against a claim that was structurally impossible for
	// the row it was written about. D78's guarantee is about a record removed
	// from the MIDDLE, so the disclosure row needs a record before it and a
	// record after it from the SAME recorder.
	if _, err := r.as(t, "agent:triage").Execute(ctx,
		execute("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"})); err != nil {
		t.Fatalf("seeding the chain segment: %v", err)
	}

	before := logLen(t, r)

	// SELF-DESCRIBE AS agent:triage, which is the principal whose catalog has
	// something to say on both axes: a selectable shin lens, and an `escalate`
	// grant for `kata.delete_project` that `no-destructive-actions` withholds.
	resp, err := r.as(t, "agent:triage").Describe(ctx, &sekizuiv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("Describe over the wire: %v", err)
	}

	records := readLog(t, r.path)
	if len(records) != before+1 {
		t.Fatalf("a Describe wrote %d audit record(s), want exactly 1", len(records)-before)
	}
	rec := records[len(records)-1]

	// --- the row says what was disclosed, and what shaped it -----------------
	if rec.GetAction() != "sekizui.describe" {
		t.Errorf("the disclosure row's action is %q; D79's \"every row is an action\" survives "+
			"as a FILTER, which needs a distinct value here", rec.GetAction())
	}
	d := rec.GetDisclosure()
	if d == nil {
		t.Fatal("the row carries no Disclosure, so nothing says what was enumerated")
	}
	if d.GetPrincipalDescribed() != "agent:triage" {
		t.Errorf("the row describes %q, want agent:triage", d.GetPrincipalDescribed())
	}
	if got, want := int(d.GetCapabilities()), len(resp.GetCapabilities()); got != want {
		t.Errorf("the row reports %d capabilities and the response carried %d — the record "+
			"must say what the caller was TOLD, or it describes a different answer from the "+
			"one that was given", got, want)
	}
	// **THE LENSES THAT SHAPED IT (§4.12).** Once a consumer learns available
	// data shapes by asking, Describe IS a disclosure surface, and a disclosure
	// shaped by a lens with no record of which lens applied is "why does
	// analytics never see user.email" moved from the payload to the catalog.
	if len(d.GetAvailableLenses()) == 0 && len(d.GetImposedLenses()) == 0 {
		t.Error("the row names no shin lens at all, and agent:triage has a selectable one")
	}
	for _, l := range resp.GetAvailableLenses() {
		if !contains(d.GetAvailableLenses(), l.GetName()) {
			t.Errorf("the response offered lens %q and the row does not name it", l.GetName())
		}
	}
	// THE RULES THAT WITHHELD SOMETHING, which is CONTRACTS 64's half.
	if !contains(d.GetWithheldBy(), "no-destructive-actions") {
		t.Errorf("the row's withheld_by is %v; agent:triage has an escalate grant for "+
			"kata.delete_project and no-destructive-actions forbids it, so the rule that "+
			"shaped the advertisement must be named", d.GetWithheldBy())
	}

	// --- THE ARM WITH TEETH: the row is IN the chain -------------------------
	//
	// Verified by TAMPERING rather than by inspection. A populated `prev_hash`
	// proves the row was chained when written; it does not prove the chain would
	// NOTICE the row going missing, and that is the property which makes a
	// reconnaissance trace undeniable rather than merely present.
	if len(rec.GetPrevHash()) == 0 {
		t.Fatal("the disclosure row starts a new chain segment, so deleting it would leave " +
			"a valid shorter chain and the arm below would prove nothing. The seeding " +
			"command above exists to stop that")
	}

	// A RECORD AFTER IT, so the deletion is from the middle.
	if _, err := r.as(t, "agent:triage").Execute(ctx,
		execute("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"})); err != nil {
		t.Fatalf("closing the chain segment: %v", err)
	}
	full := readLog(t, r.path)
	if err := auditwal.VerifyChain(full); err != nil {
		t.Fatalf("the log does not verify before any tampering: %v", err)
	}

	// EXCISE THE DISCLOSURE ROW, leaving everything on both sides of it.
	tampered := make([]*sekizuiv1.Decision, 0, len(full)-1)
	for _, d := range full {
		if d.GetId() == rec.GetId() {
			continue
		}
		tampered = append(tampered, d)
	}
	if len(tampered) != len(full)-1 {
		t.Fatalf("excised %d records, want exactly 1", len(full)-len(tampered))
	}
	if err := auditwal.VerifyChain(tampered); err == nil {
		t.Error("removing the disclosure row leaves a log that still verifies, so the " +
			"enumeration trace is deniable — which is exactly what it was as a log line " +
			"(CONTRACTS 28), and tamper-evidence is the argument that decided D166")
	}

	// --- AN IMPOSED LENS IS NAMED TOO ---------------------------------------
	//
	// **THE POPULATION CENSUS (D164) ASKED FOR THIS ARM.** agent:triage has a
	// SELECTABLE lens and no imposed one, so the corpus populated
	// `disclosure.available_lenses` and left `disclosure.imposed_lenses`
	// untouched — a field nothing wrote, which is the class CONTRACTS 23 tracks
	// and reads as complete because its parent is populated. agent:analytics
	// carries `no-pii-to-analytics` as a ceiling it cannot decline (§4.12), and
	// the imposed half is the half a consumer cannot discover any other way.
	t.Run("an imposed lens reaches the row, not only a selectable one", func(t *testing.T) {
		at := logLen(t, r)
		if _, err := r.as(t, "agent:analytics").Describe(ctx,
			&sekizuiv1.DescribeRequest{}); err != nil {
			t.Fatalf("Describe as agent:analytics: %v", err)
		}
		after := readLog(t, r.path)
		if len(after) != at+1 {
			t.Fatalf("wrote %d record(s), want 1", len(after)-at)
		}
		if imposed := after[len(after)-1].GetDisclosure().GetImposedLenses(); len(imposed) == 0 {
			t.Error("agent:analytics has an imposed lens and the row names none, so the " +
				"ceiling that shaped its catalog is unrecorded — §4.12's \"why does " +
				"analytics never see user.email\", moved to the catalog")
		}
	})

	// --- D205's arm: the reconnaissance refusal, which nothing proved --------
	//
	// **ITS MUTATION SURVIVED THE WHOLE SUITE**, which is how the gap was found:
	// the package tests catch it and `make mutate` runs the acceptance suite by
	// design (D161), so a survivor there is a statement about this phase's
	// evidence rather than about the code.
	t.Run("naming another principal needs a may_speak_for grant", func(t *testing.T) {
		// ALLOWED: mesh:primary may speak for agent:triage.
		if _, err := r.as(t, "mesh:primary").Describe(ctx,
			&sekizuiv1.DescribeRequest{Principal: "agent:triage"}); err != nil {
			t.Errorf("mesh:primary may speak for agent:triage and was refused: %v", err)
		}

		// REFUSED, and the direction is the whole point: a capability listing is
		// the map of what to try after compromising something else (§4.9).
		at := logLen(t, r)
		_, err := r.as(t, "agent:triage").Describe(ctx,
			&sekizuiv1.DescribeRequest{Principal: "mesh:primary"})
		if err == nil {
			t.Fatal("agent:triage enumerated mesh:primary's capabilities without a " +
				"may_speak_for grant")
		}

		// **AND THE REFUSAL IS RECORDED (D231), WHICH IS THE MORE VALUABLE ROW.**
		// It returned before the INFO line that was the only trace, so the guard
		// most worth having evidence of was the one that produced none.
		after := readLog(t, r.path)
		if len(after) != at+1 {
			t.Fatalf("a refused enumeration wrote %d record(s), want 1", len(after)-at)
		}
		refused := after[len(after)-1]
		if refused.GetVerdict() != sekizuiv1.Verdict_VERDICT_DENY {
			t.Errorf("the refused enumeration recorded verdict %v, want DENY",
				refused.GetVerdict())
		}
		if got := refused.GetDisclosure().GetPrincipalDescribed(); got != "mesh:primary" {
			t.Errorf("the refused row names %q as the principal described; without it the row "+
				"says somebody was refused and not what they were reaching for", got)
		}
	})
}

// step23AWithheldCapabilityIsExplained proves CONTRACTS 64.
//
// `anzen.Guards.Forbids` has always returned the guard's name and
// `catalog.go:205` discarded it with `_`, then silently omitted the capability.
// D157's shape precisely: not a missing implementation, not a missing caller,
// but **a value discarded between the two**. The consumer saw an absence with no
// explanation, indistinguishable from a capability it was never granted.
//
// **NON-VACUITY IS THE ARM THAT MATTERS.** The same principal, with the guard
// removed, must SEE the capability — otherwise the step passes against an action
// the grant never allowed, which is the failure mode P1 step 68 hit and caught
// only because `refused_by` said which stage had answered.
func step23AWithheldCapabilityIsExplained(t *testing.T) {
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}

	ctx := context.Background()

	resp, err := r.as(t, "agent:triage").Describe(ctx, &sekizuiv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("Describe over the wire: %v", err)
	}

	// THE CAPABILITY IS ABSENT, which was always true...
	for _, c := range resp.GetCapabilities() {
		if c.GetAction() == "kata.delete_project" {
			t.Fatal("kata.delete_project is advertised; no-destructive-actions forbids " +
				"*.delete_* and a guard is a ceiling no grant can exceed (D71)")
		}
	}

	// ...AND NOW IT IS EXPLAINED.
	var withheld *sekizuiv1.WithheldCapability
	for _, w := range resp.GetWithheld() {
		if w.GetAction() == "kata.delete_project" {
			withheld = w
		}
	}
	if withheld == nil {
		t.Fatalf("kata.delete_project is absent from the catalog and absent from `withheld`, "+
			"so a consumer sees a capability that simply is not there — unanswerable without "+
			"reading configuration somebody else wrote. Got %d withheld entries",
			len(resp.GetWithheld()))
	}
	if withheld.GetGuard() != "no-destructive-actions" {
		t.Errorf("the withheld capability names guard %q, want no-destructive-actions — a "+
			"name is the thing to take to whoever owns the guard", withheld.GetGuard())
	}
	if withheld.GetTargetRef() != "kata:alpha" {
		t.Errorf("the withheld capability names target %q, want kata:alpha; the same action "+
			"may be forbidden on one target and allowed on another (D137)",
			withheld.GetTargetRef())
	}

	// --- NON-VACUITY: with the guard gone, the capability appears ------------
	//
	// A CATALOG BUILT HERE RATHER THAN THE GATEWAY'S, because the counterfactual
	// is a DEPLOYMENT WITHOUT THAT GUARD and the running instance has one. Every
	// other input is the same document, so the guard is the only variable —
	// which is the property P1 step 68's first version lacked when it changed
	// two things and passed for the wrong reason.
	unguarded := catalog.New(catalog.Config{
		Doc:     r.doc,
		Drivers: map[string]connector.Driver{kata.Kind: kata.New()},
		Policy:  policy.NewGrantEngine(r.doc, acceptanceResidency),
		Guards:  anzen.New(nil),
		Lenses:  shin.New(r.doc.Shin),
	})
	id := &sekizuiv1.Identity{
		Caller:  &sekizuiv1.Caller{Principal: "agent:triage"},
		Subject: &sekizuiv1.Subject{Principal: "agent:triage"},
		Chain:   []string{"agent:triage"},
	}
	free, err := unguarded.Describe(ctx, id, "")
	if err != nil {
		t.Fatalf("describing against a deployment with no guards: %v", err)
	}
	var found bool
	for _, c := range free.GetCapabilities() {
		if c.GetAction() == "kata.delete_project" {
			found = true
		}
	}
	if !found {
		t.Error("with no anzen guard configured, kata.delete_project is STILL absent — so " +
			"the step above proved nothing about the guard: the capability is missing for " +
			"some other reason, most likely a grant that never allowed it")
	}
	if len(free.GetWithheld()) != 0 {
		t.Errorf("a deployment with no guards reported %d withheld capabilities; nothing "+
			"withheld anything", len(free.GetWithheld()))
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
