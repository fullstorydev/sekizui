package acceptance

import (
	"context"
	"strings"
	"testing"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step48AnzenDoesNotReactToItsOwnDecisions proves D121's recursion guard, in the
// form P1 actually has (D122, D157).
//
// **THE HAZARD IS REAL BECAUSE THERE IS NO PRIVILEGED PATH.** An anzen action is
// an ordinary command: authorised, recorded, hash-chained like everything else
// (D18). That is what makes the class trustworthy and it is also what creates the
// loop — a rule whose action produces a record that matches its own signal fires
// forever, and each turn of it is individually correct.
//
// D121's answer is that anzen ignores decisions whose subject sits in the
// `anzen:` namespace, and D122 is what makes that structural rather than a
// convention: configuration cannot mint such a subject, so nothing but anzen can
// produce such a record.
//
// **P5 BRINGS THE DECISION-STREAM TAP; P1 HAS A SIGNAL WATCHER (D157).** So this
// step proves the guard in the shape that exists now — the skeleton cannot be
// driven by its own action — plus the two structural facts the P5 tap will rest
// on. Written this way rather than deferred, because the loop is reachable today:
// the stale watcher fires `revoke_credential`, revocation evicts pooled clients,
// and if those evictions counted as stale the watcher would re-fire on the
// consequence of its own firing.
func step48AnzenDoesNotReactToItsOwnDecisions(t *testing.T) {
	ctx := context.Background()

	//nolint:contextcheck // harness manages its own lifecycle via *testing.T
	r := newRun(t)
	if r.localOnly(t, "firing withdraws from this process's pool") {
		return
	}

	const rule = "credential-compromise"
	const subject = "anzen:" + rule

	// --- 48a: NO PRIVILEGED PATH — the action is recorded like any other --
	res, err := r.srv.Enforce(ctx, anzenSubject(subject), &sekizuiv1.Command{
		Action: "sekizui.fire_anzen", TargetRef: subject,
	})
	if err != nil {
		t.Fatalf("firing: %v", err)
	}
	if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("firing was refused: %s", res.GetReason())
	}

	var found *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetIdentity().GetSubject().GetPrincipal() == subject {
			found = d
			break
		}
	}
	if found == nil {
		t.Fatal("an anzen action produced NO decision record carrying its own subject. " +
			"Either it took a privileged path — which D18 forbids and which would leave " +
			"a hole in the audit log — or the identity is not being carried, and D121's " +
			"guard has nothing to recognise")
	}

	// --- 48b: THE SUBJECT IS WHAT THE GUARD RECOGNISES -------------------
	//
	// The record has to be identifiable as anzen's own from the record alone. A
	// tap that had to consult configuration to decide what to skip would be a
	// convention; this is a shape.
	if !strings.HasPrefix(found.GetIdentity().GetSubject().GetPrincipal(), "anzen:") {
		t.Errorf("subject = %q, want an anzen: principal",
			found.GetIdentity().GetSubject().GetPrincipal())
	}

	// --- 48c: FIRING DOES NOT RAISE THE SIGNAL THAT FIRED IT ------------
	//
	// **THE ARM WITH TEETH, and the loop that is reachable today.** The stale
	// watcher fires `revoke_credential`; revocation evicts pooled clients and
	// cancels their calls. If those evictions were counted as
	// `credential_stale`, the watcher would observe the consequence of its own
	// firing and fire again — a storm of individually-correct actions.
	//
	// They are not counted, and the reason is a real distinction rather than an
	// accident: `credential_stale` means an entry holding a SUPERSEDED
	// credential — D99's rotation gap — and a revoked target is a different
	// condition with a different remedy. The pool's revocation path deletes its
	// entries without entering them in the drain census.
	if stale := r.pool.Stale(); len(stale) != 0 {
		t.Errorf("firing an anzen rule left %d entries counted as credential_stale: %+v.\n"+
			"That is the signal the rule watches, raised by the rule's own action — "+
			"which is exactly the loop D121 exists to prevent, reachable in P1 without "+
			"any decision-stream tap at all", len(stale), stale)
	}

	// --- 48d: A SECOND FIRING DOES NO FURTHER WORK ----------------------
	//
	// Defence in depth for the same hazard: even if something did re-fire, the
	// repeat must be INERT and must be visible as such. It is — the second
	// revocation cancels nothing, evicts nothing and tears down nothing, and the
	// record says so, so a loop would be a stream of provably empty actions
	// rather than work being redone.
	//
	// **WHAT IT IS NOT is refused, and that is an inconsistency worth naming**
	// (CONTRACTS item 57). D146 refuses a second grant suspension on the grounds
	// that "an OK is how somebody concludes they pulled a lever somebody else had
	// already pulled", and D133's restore refuses a target nobody withdrew — with
	// D138 adding STATUS_INVALID_ARGUMENT for exactly that case. A second
	// REVOCATION reports plain STATUS_OK with an empty reason. The audit record
	// can tell the two apart; the caller cannot. Asserted as it behaves rather
	// than as it arguably should, because changing break-glass ergonomics under
	// an incident is a decision and not a tidy-up.
	if _, err := r.srv.Enforce(ctx, anzenSubject(subject), &sekizuiv1.Command{
		Action: "sekizui.fire_anzen", TargetRef: subject,
	}); err != nil {
		t.Fatalf("second firing: %v", err)
	}

	var revocations []*sekizuiv1.Revocation
	for _, d := range readLog(t, r.path) {
		if d.GetIdentity().GetSubject().GetPrincipal() == subject && d.GetRevocation() != nil {
			revocations = append(revocations, d.GetRevocation())
		}
	}
	if len(revocations) < 2 {
		t.Fatalf("found %d revocation records for %s, want both firings recorded — a "+
			"repeat that leaves no record is a loop nobody could see", len(revocations), subject)
	}

	last := revocations[len(revocations)-1]
	if last.GetCancelledInFlight() != 0 || last.GetEvicted() != 0 || last.GetTornDown() != 0 {
		t.Errorf("the second firing did real work: cancelled=%d evicted=%d torn_down=%d. "+
			"A repeat must be inert, or a loop redoes work every turn rather than "+
			"spinning visibly",
			last.GetCancelledInFlight(), last.GetEvicted(), last.GetTornDown())
	}
}
