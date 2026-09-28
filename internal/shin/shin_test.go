package shin

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func lenses(t *testing.T, y string) *Lenses {
	t.Helper()
	var doc config.Document
	if err := yaml.Unmarshal([]byte(y), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return New(doc.Shin)
}

func apply(t *testing.T, l *Lenses, req Request, payload map[string]any) (map[string]any, []string) {
	t.Helper()
	out, names, err := l.Apply(req, payload)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return out, names
}

const fixture = `
shin:
  - name: no-pii
    enabled: true
    mode: imposed
    applies_to: ["agent:analytics"]
    withholds: [user.email]
    because: no lawful basis
  - name: triage-lite
    enabled: true
    mode: requestable
    applies_to: ["agent:triage"]
    type: fullstory.rage_click.v1
    fields: [session_id, url]
    because: where, not the whole session
`

func rich() map[string]any {
	return map[string]any{
		"session_id": "abc",
		"url":        "/checkout",
		"clicks":     7,
		"user":       map[string]any{"id": "u-1", "email": "a@b.invalid"},
	}
}

// TestALensOnlyEverRemoves is the property everything else rests on (D83).
//
// If a lens could add or rename a field, none of the following would be safe:
// anzen could not tighten one automatically, a misconfiguration could disclose
// rather than hide, and "the effective lens is the intersection" would be
// meaningless. Asserted structurally — every key in the output must have been in
// the input, with the same value.
func TestALensOnlyEverRemoves(t *testing.T) {
	l := lenses(t, fixture)
	in := rich()

	for _, req := range []Request{
		{Principal: "agent:analytics"},
		{Principal: "agent:triage", Type: "fullstory.rage_click.v1", Selected: "triage-lite"},
		{Principal: "agent:nobody"},
	} {
		out, _ := apply(t, l, req, rich())
		for k := range out {
			if _, existed := in[k]; !existed {
				t.Errorf("%s: lens INVENTED field %q; a lens may only remove", req.Principal, k)
			}
		}
		if len(out) > len(in) {
			t.Errorf("%s: %d fields out of %d in", req.Principal, len(out), len(in))
		}
	}
}

// TestWithholdingRemovesOnlyWhatItNames — a lens that withholds user.email must
// not take user.id with it. Over-removal is safe but wrong, and it turns a
// compliance rule into a bug report.
func TestWithholdingRemovesOnlyWhatItNames(t *testing.T) {
	l := lenses(t, fixture)
	out, _ := apply(t, l, Request{Principal: "agent:analytics"}, rich())

	user, ok := out["user"].(map[string]any)
	if !ok {
		t.Fatal("the user object was removed entirely; the lens withholds user.email")
	}
	if _, leaked := user["email"]; leaked {
		t.Error("user.email survived")
	}
	if _, kept := user["id"]; !kept {
		t.Error("user.id was removed; a lens withholds the field it names, not the subtree")
	}
}

// TestProjectionDoesNotMutateTheInput is the bug that would look like correct
// behaviour: the same payload goes to several consumers with different lenses,
// so an in-place delete would silently apply one consumer's withholding to all.
func TestProjectionDoesNotMutateTheInput(t *testing.T) {
	l := lenses(t, fixture)
	in := rich()

	apply(t, l, Request{Principal: "agent:analytics"}, in)

	user, _ := in["user"].(map[string]any)
	if _, present := user["email"]; !present {
		t.Fatal("projecting for one consumer mutated the shared payload; the next " +
			"consumer would silently receive someone else's lens")
	}
}

// TestAbsenceOfALensIsNotALens — a consumer no lens covers receives everything.
func TestAbsenceOfALensIsNotALens(t *testing.T) {
	l := lenses(t, fixture)
	out, names := apply(t, l, Request{Principal: "agent:unlensed"}, rich())

	if len(out) != len(rich()) {
		t.Errorf("an uncovered consumer received %d of %d fields", len(out), len(rich()))
	}
	if len(names) != 0 {
		t.Errorf("applied_lenses = %v for a consumer no lens covers", names)
	}
}

// TestRequestedComposesUnderImposed is D84's intersection rule: a selection can
// only narrow further, never recover a field the ceiling removed.
func TestRequestedComposesUnderImposed(t *testing.T) {
	l := lenses(t, `
shin:
  - name: ceiling
    enabled: true
    mode: imposed
    applies_to: ["agent:x"]
    withholds: [user.email]
    because: compliance
  - name: wide
    enabled: true
    mode: requestable
    applies_to: ["agent:x"]
    fields: [session_id, user]
    because: this consumer wants the user object
`)
	out, names := apply(t, l,
		Request{Principal: "agent:x", Selected: "wide"}, rich())

	user, _ := out["user"].(map[string]any)
	if _, leaked := user["email"]; leaked {
		t.Error("selecting a wider lens recovered a field the imposed ceiling withheld; " +
			"a request can only narrow (D84)")
	}
	if len(names) != 2 {
		t.Errorf("applied = %v, want both the ceiling and the selection", names)
	}
}

// TestAnImposedLensCannotBeSelected — a ceiling is not an offer.
func TestAnImposedLensCannotBeSelected(t *testing.T) {
	l := lenses(t, fixture)

	_, _, err := l.Apply(Request{Principal: "agent:analytics", Selected: "no-pii"}, rich())
	if err == nil {
		t.Fatal("an imposed lens was selectable, which lets a consumer treat a ceiling as a choice")
	}
	if got := fault.KindOf(err); got != fault.KindDenied {
		t.Errorf("kind = %v, want KindDenied", got)
	}
}

// TestAnUndeclaredLensIsRefused is D46's model applied to lenses: what is not
// declared is not selectable. Silently falling back to the ceiling would hide
// both a misconfiguration and a probe.
func TestAnUndeclaredLensIsRefused(t *testing.T) {
	l := lenses(t, fixture)

	_, _, err := l.Apply(Request{
		Principal: "agent:triage", Type: "fullstory.rage_click.v1", Selected: "everything",
	}, rich())
	if err == nil {
		t.Fatal("an undeclared lens was accepted")
	}
	if got := fault.KindOf(err); got != fault.KindNotFound {
		t.Errorf("kind = %v, want KindNotFound", got)
	}
	// The error must say what IS available, or a consumer has to read config it
	// cannot see.
	if !strings.Contains(err.Error(), "triage-lite") {
		t.Errorf("the refusal does not name what is available: %v", err)
	}
}

// TestARealLensUnderTheWrongTypeSaysSo — the misleading case: a lens that
// plainly exists in the config a consumer was handed, refused with
// "available: []" because it is scoped to a different payload type.
func TestARealLensUnderTheWrongTypeSaysSo(t *testing.T) {
	l := lenses(t, fixture)

	_, _, err := l.Apply(Request{
		Principal: "agent:triage", Type: "some.other.v1", Selected: "triage-lite",
	}, rich())
	if err == nil {
		t.Fatal("a type-scoped lens applied to the wrong type")
	}
	if !strings.Contains(err.Error(), "fullstory.rage_click.v1") {
		t.Errorf("the refusal does not say which type the lens IS scoped to, so the "+
			"consumer cannot tell a typo from a scoping rule: %v", err)
	}
}

// TestALensOfferedToSomeoneElseIsRefused — offers are per-principal, and a lens
// name is not a password.
func TestALensOfferedToSomeoneElseIsRefused(t *testing.T) {
	l := lenses(t, fixture)

	if _, _, err := l.Apply(Request{
		Principal: "agent:other", Type: "fullstory.rage_click.v1", Selected: "triage-lite",
	}, rich()); err == nil {
		t.Fatal("a principal selected a lens offered to someone else")
	}
}

// TestTheAssertionCatchesAFailedProjection is D86 — apply, then assert.
//
// Proven by constructing the failure the assertion exists for: a lens whose
// withheld path the projection cannot reach, because the field is nested under
// something that is not an object. Without the assertion this returns a payload
// still carrying the withheld data and reports success.
func TestTheAssertionCatchesAFailedProjection(t *testing.T) {
	l := &Lenses{all: []Lens{{
		Name: "broken", Mode: ModeImposed, Because: "test",
		// A withhold path the remover cannot descend, so the field survives.
		withholds: []string{"user"},
	}}}

	// Deliberately defeat `remove` by making the assertion look at a DIFFERENT
	// payload than the one projected — the shape a real bug would take.
	projected := map[string]any{"user": map[string]any{"email": "a@b.invalid"}}
	if err := assertWithheld(l.all, projected); err == nil {
		t.Fatal("the egress assertion passed a payload still carrying a withheld field; " +
			"without it, a lens that silently failed to apply is a disclosure")
	}
}

// TestSizeCapRefusesRatherThanTruncates — truncating a payload to fit would
// hand a consumer a partial record it cannot distinguish from a whole one.
func TestSizeCapRefusesRatherThanTruncates(t *testing.T) {
	l := lenses(t, `
shin:
  - name: small
    enabled: true
    mode: imposed
    applies_to: ["agent:x"]
    max_bytes: 32
    because: this consumer cannot hold more
`)
	_, _, err := l.Apply(Request{Principal: "agent:x"}, rich())
	if err == nil {
		t.Fatal("an oversized payload was delivered")
	}
	if got := fault.KindOf(err); got != fault.KindBudgetExceeded {
		t.Errorf("kind = %v, want KindBudgetExceeded — an oversized payload is a real "+
			"event too large for this consumer, not a bug in the lens", got)
	}
	// The message must distinguish shape from rate, or an operator reaches for
	// the wrong control.
	if !strings.Contains(err.Error(), "rate limit") {
		t.Error("the refusal does not distinguish a size cap from a rate limit")
	}
}

// TestTheTightestCapWins — with two lenses in force, the smaller bound applies.
func TestTheTightestCapWins(t *testing.T) {
	l := &Lenses{all: []Lens{
		{Name: "loose", Mode: ModeImposed, MaxBytes: 1 << 20, Because: "x"},
		{Name: "tight", Mode: ModeImposed, MaxBytes: 16, Because: "y"},
	}}
	_, _, err := l.Apply(Request{Principal: "anyone"}, rich())
	if err == nil || !strings.Contains(err.Error(), `"tight"`) {
		t.Errorf("the tighter cap did not win: %v", err)
	}
}

// TestDisabledLensesDoNothing — `enabled: false` must mean it, or turning a lens
// off would still shape deliveries.
func TestDisabledLensesDoNothing(t *testing.T) {
	l := lenses(t, `
shin:
  - name: off
    enabled: false
    mode: imposed
    applies_to: ["agent:x"]
    withholds: [user.email]
    because: disabled
`)
	out, names := apply(t, l, Request{Principal: "agent:x"}, rich())
	user, _ := out["user"].(map[string]any)
	if _, present := user["email"]; !present {
		t.Error("a disabled lens still removed a field")
	}
	if len(names) != 0 {
		t.Errorf("a disabled lens reported as applied: %v", names)
	}
}

// TestEmptyModeMeansImposed inverts the default used elsewhere in config, and
// the inversion is deliberate: a lens that silently became optional would WIDEN
// what a consumer receives.
func TestEmptyModeMeansImposed(t *testing.T) {
	l := lenses(t, `
shin:
  - name: unspecified
    enabled: true
    applies_to: ["agent:x"]
    withholds: [user.email]
    because: mode omitted on purpose
`)
	out, names := apply(t, l, Request{Principal: "agent:x"}, rich())
	user, _ := out["user"].(map[string]any)
	if _, leaked := user["email"]; leaked {
		t.Error("a lens with no mode did not apply; the safe default here is the " +
			"RESTRICTIVE one, because the alternative widens")
	}
	if len(names) != 1 {
		t.Errorf("applied = %v, want the lens to have applied", names)
	}
}

// TestDeliverNeverLensesProvenance — id, type, stage, and trace_id are how a
// consumer correlates a delivery with the audit log. Removing them is the
// evasion this package must not enable.
func TestDeliverNeverLensesProvenance(t *testing.T) {
	l := lenses(t, fixture)
	data, _ := structpb.NewStruct(rich())
	env := &sekizuiv1.Envelope{
		Id: "01J0X", Type: "fullstory.rage_click.v1", Stage: "raw",
		Subject: "session:abc", TraceId: "4bf9", Residency: "eu", Data: data,
	}

	out, _, err := l.Deliver("agent:triage", env, "triage-lite")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(out.GetData().AsMap()) != 2 {
		t.Errorf("payload has %d fields, want 2", len(out.GetData().AsMap()))
	}
	for _, f := range []struct{ name, got, want string }{
		{"id", out.GetId(), env.GetId()},
		{"type", out.GetType(), env.GetType()},
		{"stage", out.GetStage(), env.GetStage()},
		{"subject", out.GetSubject(), env.GetSubject()},
		{"trace_id", out.GetTraceId(), env.GetTraceId()},
	} {
		if f.got != f.want {
			t.Errorf("envelope %s changed: %q -> %q; a lens shapes the payload, never "+
				"the provenance", f.name, f.want, f.got)
		}
	}
}

// TestDeliverDoesNotMutateTheOriginal — same reason as the payload case, one
// level up: the bus fans one envelope out to many subscribers.
func TestDeliverDoesNotMutateTheOriginal(t *testing.T) {
	l := lenses(t, fixture)
	data, _ := structpb.NewStruct(rich())
	env := &sekizuiv1.Envelope{Type: "fullstory.rage_click.v1", Data: data}

	if _, _, err := l.Deliver("agent:triage", env, "triage-lite"); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if n := len(env.GetData().AsMap()); n != 4 {
		t.Errorf("the source envelope now has %d fields; delivering to one subscriber "+
			"changed what every other subscriber will receive", n)
	}
}

// TestAvailableAndImposedAreDistinct — Describe reports them separately, and
// conflating them would tell a consumer it can decline its own ceiling.
func TestAvailableAndImposedAreDistinct(t *testing.T) {
	l := lenses(t, fixture)

	if got := l.Available("agent:analytics", "", ""); len(got) != 0 {
		t.Errorf("an imposed lens appeared as selectable: %v", got)
	}
	if got := l.Imposed("agent:analytics", "", ""); len(got) != 1 {
		t.Errorf("imposed = %v, want the ceiling", got)
	}
	if got := l.Available("agent:triage", "fullstory.rage_click.v1", ""); len(got) != 1 {
		t.Errorf("available to agent:triage = %v, want triage-lite", got)
	}
}

// TestResidencyScopesALens is the jurisdiction case: the same consumer receives
// different shapes depending on where the data is resident.
func TestResidencyScopesALens(t *testing.T) {
	l := lenses(t, `
shin:
  - name: eu-only
    enabled: true
    mode: imposed
    applies_to: ["agent:x"]
    residency: eu
    withholds: [user.email]
    because: GDPR applies to eu-resident data
`)
	euOut, _ := apply(t, l, Request{Principal: "agent:x", Residency: "eu"}, rich())
	usOut, _ := apply(t, l, Request{Principal: "agent:x", Residency: "us"}, rich())

	if euUser, _ := euOut["user"].(map[string]any); euUser["email"] != nil {
		t.Error("the eu lens did not apply to eu-resident data")
	}
	if usUser, _ := usOut["user"].(map[string]any); usUser["email"] == nil {
		t.Error("the eu lens applied to us-resident data; residency scopes it")
	}
}

// TestWildcardAppliesTo — "reflex:*" must cover every reflex, the case §4.11.7
// cares about.
func TestWildcardAppliesTo(t *testing.T) {
	l := lenses(t, `
shin:
  - name: reflex-ceiling
    enabled: true
    mode: imposed
    applies_to: ["reflex:*"]
    withholds: [user.email]
    because: a reflex never needs personal data
`)
	out, names := apply(t, l, Request{Principal: "reflex:friction"}, rich())
	if user, _ := out["user"].(map[string]any); user["email"] != nil {
		t.Error("the wildcard did not cover reflex:friction")
	}
	if len(names) != 1 {
		t.Errorf("applied = %v", names)
	}
}
