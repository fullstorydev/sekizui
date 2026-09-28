package gateway

import (
	"context"
	"strings"
	"testing"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// TestDescribeRequiresAVerifiedCaller — the response is scoped entirely to who
// is asking, so answering an unauthenticated caller would leak the grant table.
func TestDescribeRequiresAVerifiedCaller(t *testing.T) {
	h := newHarness(t)
	if _, err := h.srv.Describe(context.Background(), &sekizuiv1.DescribeRequest{}); err == nil {
		t.Fatal("Describe answered a caller with no certificate")
	}
}

// TestDescribeWritesADisclosureRecord is D166 at the gateway boundary, and it is
// the INVERSION of the test that stood here.
//
// **THE OLD TEST ENFORCED D79's REFUSAL TO AUDIT `Describe`** — "a row per
// enumeration would dilute a log whose value is that every row is an action" —
// and it was correct until D166 answered that objection with a row shape a query
// can exclude. Inverted rather than deleted: the claim reversed, so the guard
// must reverse with it, and a deleted test leaves the reversal unproven in the
// place the old one proved it.
//
// What the row must carry is what makes it worth having: the principal
// described, the lenses that shaped the answer, and the rules that withheld
// anything. A row saying only "somebody enumerated" would be a weaker version of
// the log line it replaces, which already said who.
func TestDescribeWritesADisclosureRecord(t *testing.T) {
	h := newHarness(t)
	before := len(h.sink.all())

	if _, err := h.srv.Describe(callerCtx(t, "agent:triage"), &sekizuiv1.DescribeRequest{}); err != nil {
		t.Fatalf("Describe: %v", err)
	}
	records := h.sink.all()
	if len(records) != before+1 {
		t.Fatalf("Describe wrote %d audit record(s), want exactly 1 — the enumeration "+
			"trace was the one trace outside the hash chain (D166)", len(records)-before)
	}

	rec := records[len(records)-1]
	if rec.GetAction() != describeAction {
		t.Errorf("the disclosure row's action is %q, want %q so a query can filter it out "+
			"and keep D79's \"every row is an action\" property", rec.GetAction(), describeAction)
	}
	if rec.GetVerdict() != sekizuiv1.Verdict_VERDICT_ALLOW {
		t.Errorf("the disclosure row's verdict is %v, want ALLOW; a row with no verdict is "+
			"invisible to every query that filters on one (D228)", rec.GetVerdict())
	}
	d := rec.GetDisclosure()
	if d == nil {
		t.Fatal("the row carries no Disclosure, so nothing says what was disclosed — and " +
			"the presence of this sub-message is what makes the row filterable at all")
	}
	if d.GetPrincipalDescribed() != "agent:triage" {
		t.Errorf("the row describes %q, want agent:triage — this is the field an incident "+
			"review greps for", d.GetPrincipalDescribed())
	}
	if d.GetCapabilities() == 0 {
		t.Error("the row reports zero capabilities disclosed, which would make a successful " +
			"enumeration indistinguishable from an empty one")
	}
}

// TestARefusedDescribeIsRecorded — D231, and it is the more valuable of the two
// rows.
//
// **AN AGENT ASKING WHAT A PRINCIPAL IT MAY NOT SPEAK FOR CAN DO IS THE EVENT
// MOST WORTH HAVING IN A TAMPER-EVIDENT LOG, and it was the one event that
// produced nothing.** The refusal returned before the INFO line that was the
// only identity-carrying trace, so §4.9's reconnaissance guard left no record of
// having fired.
func TestARefusedDescribeIsRecorded(t *testing.T) {
	h := newHarness(t)
	before := len(h.sink.all())

	_, err := h.srv.Describe(callerCtx(t, "agent:triage"),
		&sekizuiv1.DescribeRequest{Principal: "mesh:primary"})
	if err == nil {
		t.Fatal("agent:triage described mesh:primary without a may_speak_for grant; a " +
			"capability listing is the map of what to try next (§4.9)")
	}

	records := h.sink.all()
	if len(records) != before+1 {
		t.Fatalf("a refused describe wrote %d record(s), want exactly 1", len(records)-before)
	}
	rec := records[len(records)-1]
	if rec.GetVerdict() != sekizuiv1.Verdict_VERDICT_DENY {
		t.Errorf("the refused enumeration recorded verdict %v, want DENY", rec.GetVerdict())
	}
	// **THE PRINCIPAL THAT WAS ASKED ABOUT, not the one asking.** Without it the
	// row says somebody was refused and not what they were reaching for, which
	// is the whole content of a reconnaissance trace.
	if got := rec.GetDisclosure().GetPrincipalDescribed(); got != "mesh:primary" {
		t.Errorf("the refused row names %q as the principal described, want mesh:primary", got)
	}
	if rec.GetDisclosure().GetCapabilities() != 0 {
		t.Error("a refused describe recorded a non-zero capability count; nothing was disclosed")
	}
}

// TestDescribeIsMetered — D76 requires every RPC to appear in RED, and a method
// added without instrumentation is one nobody notices is missing.
func TestDescribeIsMetered(t *testing.T) {
	h := newHarness(t)
	if _, err := h.srv.Describe(callerCtx(t, "agent:triage"), &sekizuiv1.DescribeRequest{}); err != nil {
		t.Fatalf("Describe: %v", err)
	}

	var scrape strings.Builder
	if _, err := h.srv.Metrics().WriteTo(&scrape); err != nil {
		t.Fatalf("metrics: %v", err)
	}
	if !strings.Contains(scrape.String(), `action="describe",outcome="ok"`) {
		t.Errorf("Describe is absent from the metrics scrape:\n%s", scrape.String())
	}
}

// TestDescribeWithoutACatalogIsAnError — a Server built without a catalog is a
// wiring error, and reporting it as an EMPTY capability list would tell an agent
// it may do nothing, which is indistinguishable from a correct denial.
func TestDescribeWithoutACatalogIsAnError(t *testing.T) {
	h := newHarness(t)
	h.srv.catalog = nil

	if _, err := h.srv.Describe(callerCtx(t, "agent:triage"), &sekizuiv1.DescribeRequest{}); err == nil {
		t.Fatal("a Server with no catalog reported success; an empty capability list " +
			"is indistinguishable from a principal that genuinely may do nothing")
	}
}

// TestDescribeAdmissionIsReleased — Describe takes an admission slot like every
// other RPC, and a leaked slot would eventually stall the process.
func TestDescribeAdmissionIsReleased(t *testing.T) {
	h := newHarness(t)
	for range 32 { // more iterations than the harness's admission limit of 8
		if _, err := h.srv.Describe(callerCtx(t, "agent:triage"),
			&sekizuiv1.DescribeRequest{}); err != nil {
			t.Fatalf("Describe stalled after repeated calls, so a slot leaked: %v", err)
		}
	}
}
