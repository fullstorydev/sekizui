package catalog

import (
	"context"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

func build(t *testing.T, docYAML string) *Catalog {
	t.Helper()
	var doc config.Document
	if err := yaml.Unmarshal([]byte(docYAML), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return New(Config{Doc: &doc, Drivers: map[string]connector.Driver{kata.Kind: kata.New()},
		Policy: policy.NewGrantEngine(&doc, nil), Guards: anzen.New(doc.Anzen), Lenses: shin.New(doc.Shin)})
}

func ident(caller, subject string) *sekizuiv1.Identity {
	chain := []string{caller}
	if caller != subject {
		chain = append(chain, subject)
	}
	return &sekizuiv1.Identity{
		Caller:  &sekizuiv1.Caller{Principal: caller},
		Subject: &sekizuiv1.Subject{Principal: subject},
		Chain:   chain,
	}
}

func describe(t *testing.T, c *Catalog, caller, subject, principal string) *sekizuiv1.DescribeResponse {
	t.Helper()
	resp, err := c.Describe(context.Background(), ident(caller, subject), principal)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	return resp
}

const twoPrincipals = `targets:
  - {ref: kata:alpha, kind: kata, tenant: alpha, residency: eu, base_url: https://alpha.invalid}
grants:
  - principal: agent:triage
    allow:
      - action: kata.create_issue
        target: kata:alpha
        where: {project: [PROJ, PLAT]}
        rate_per_hr: 10
    escalate:
      - action: kata.delete_project
        target: kata:alpha
  - principal: mesh:compute
    may_speak_for: [agent:triage]
    allow:
      - action: kata.create_issue
        target: kata:alpha
        where: {project: [PROJ, PLAT]}
`

// residencyConstrained is a grant whose capability carries a RESERVED facet
// alongside an ordinary argument constraint, so the two can be told apart.
const residencyConstrained = `
targets:
  - {ref: kata:alpha, kind: kata, tenant: alpha, residency: eu, base_url: https://alpha.invalid}
grants:
  - principal: agent:triage
    allow:
      - action: kata.create_issue
        target: kata:alpha
        where: {project: [PROJ], target_residency: [eu]}
`

// TestCatalogNeverAdvertisesAReservedFacet.
//
// A reserved `where:` key is answered from configuration; a caller can neither
// send it nor influence it (D136). Advertising one describes a constraint the
// agent must satisfy, and the predictable result is an LLM putting
// `target_residency: "eu"` in its arguments — where the engine ignores it. The
// caller then cannot tell that its request was fine and its permission was not.
//
// NOT COVERED BY TestCatalogAgreesWithTheEnforcer, which is the reason this
// exists separately. That test feeds the published constraints back to the
// enforcer and checks it still allows — and it does, because whereMatches SKIPS
// reserved keys. The round-trip passes while the catalog is lying to the agent.
//
// DERIVED FROM config.ReservedWhereKeys, not written against target_residency.
// A hand-written key would rot silently the moment a second facet is added: the
// test would keep passing, having checked nothing about the new one.
func TestCatalogNeverAdvertisesAReservedFacet(t *testing.T) {
	var doc config.Document
	if err := yaml.Unmarshal([]byte(residencyConstrained), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	eng := policy.NewGrantEngine(&doc, nil)
	c := New(Config{Doc: &doc, Drivers: map[string]connector.Driver{kata.Kind: kata.New()}, Policy: eng,
		Guards: anzen.New(doc.Anzen), Lenses: shin.New(doc.Shin)})

	resp := describe(t, c, "agent:triage", "agent:triage", "")
	if len(resp.GetCapabilities()) == 0 {
		t.Fatal("no capabilities advertised; the test would prove nothing")
	}

	var sawOrdinary bool
	for _, capability := range resp.GetCapabilities() {
		for _, reserved := range config.ReservedWhereKeys() {
			if _, found := capability.GetWhere()[reserved]; found {
				t.Errorf("capability %q advertises reserved facet %q as an argument "+
					"constraint; it is answered from the target's configuration and a "+
					"caller cannot supply it", capability.GetAction(), reserved)
			}
		}
		if _, found := capability.GetWhere()["project"]; found {
			sawOrdinary = true
		}
	}

	// NON-VACUITY. Without this the test passes on a catalog that advertises no
	// constraints at all, which would hide the opposite defect.
	if !sawOrdinary {
		t.Error("no ordinary constraint advertised either; the filter is removing " +
			"more than the reserved facet")
	}
}

// TestCatalogAgreesWithTheEnforcer is the property the whole package exists for
// (§4.9 property 1): anything the catalog advertises, the enforcer allows.
//
// Checked by ASKING BOTH about every advertised capability rather than by
// inspecting the implementation. If the catalog ever grows a shortcut that
// bypasses policy, this fails.
func TestCatalogAgreesWithTheEnforcer(t *testing.T) {
	var doc config.Document
	if err := yaml.Unmarshal([]byte(twoPrincipals), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	eng := policy.NewGrantEngine(&doc, nil)
	c := New(Config{Doc: &doc, Drivers: map[string]connector.Driver{kata.Kind: kata.New()}, Policy: eng,
		Guards: anzen.New(doc.Anzen), Lenses: shin.New(doc.Shin)})

	resp := describe(t, c, "agent:triage", "agent:triage", "")
	if len(resp.GetCapabilities()) == 0 {
		t.Fatal("no capabilities advertised; the test would prove nothing")
	}

	for _, cap := range resp.GetCapabilities() {
		args := map[string]any{}
		for field, con := range cap.GetWhere() {
			// Use the constraint the CATALOG published. If it published one the
			// enforcer will not accept, that is exactly the drift under test.
			args[field] = con.GetIn()[0]
		}
		dec, err := eng.Authorise(context.Background(), policy.Request{
			Identity: ident("agent:triage", "agent:triage"),
			Action:   cap.GetAction(), TargetRef: cap.GetTargetRef(), Args: args,
		})
		if err != nil {
			t.Fatalf("Authorise(%s): %v", cap.GetAction(), err)
		}
		if dec.Verdict == sekizuiv1.Verdict_VERDICT_DENY {
			t.Errorf("catalog advertises %q on %q but the enforcer denies it (%s); "+
				"an agent told about this burns a turn discovering the 403",
				cap.GetAction(), cap.GetTargetRef(), dec.Reason)
		}
	}
}

// TestAnzenForbiddenActionsAreNotAdvertised is the regression test for a defect
// the twelve tests around it all missed: the catalog consulted policy but not
// anzen, so it advertised an action every call would refuse.
//
// None of the other fixtures configure a guard, which is exactly why it hid. The
// acceptance run caught it because it uses the real document. Worth remembering
// as a shape: a unit fixture that omits a component cannot detect forgetting it.
func TestAnzenForbiddenActionsAreNotAdvertised(t *testing.T) {
	c := build(t, `targets:
  - {ref: kata:alpha, kind: kata, tenant: alpha, residency: eu, base_url: https://alpha.invalid}
grants:
  - principal: agent:triage
    allow:
      - {action: kata.create_issue, target: kata:alpha}
    escalate:
      - {action: kata.delete_project, target: kata:alpha}
anzen:
  - name: no-destruction
    enabled: true
    forbids: ["kata.delete_*"]
    mode: enforce
`)
	resp := describe(t, c, "agent:triage", "agent:triage", "")

	for _, cap := range resp.GetCapabilities() {
		if cap.GetAction() == "kata.delete_project" {
			t.Fatal("the catalog advertises an action anzen forbids unconditionally; " +
				"anzen is checked BEFORE policy (D71), so every call is refused and " +
				"the agent is sent at a wall")
		}
	}
	// Non-vacuous: the unforbidden capability must still be there, or this would
	// pass just as well against a catalog that advertises nothing.
	if len(resp.GetCapabilities()) != 1 {
		t.Fatalf("want exactly the 1 unforbidden capability, got %d",
			len(resp.GetCapabilities()))
	}
}

// TestShadowGuardsDoNotHideCapabilities — a shadow guard is observing, not
// enforcing (§4.11.4 item 3). Hiding capabilities during the observation week
// would change behaviour, which is the one thing shadow mode must not do.
func TestShadowGuardsDoNotHideCapabilities(t *testing.T) {
	c := build(t, `targets:
  - {ref: kata:alpha, kind: kata, tenant: alpha, residency: eu, base_url: https://alpha.invalid}
grants:
  - principal: agent:triage
    escalate:
      - {action: kata.delete_project, target: kata:alpha}
anzen:
  - name: no-destruction
    enabled: true
    forbids: ["kata.delete_*"]
    mode: shadow
`)
	resp := describe(t, c, "agent:triage", "agent:triage", "")
	if len(resp.GetCapabilities()) != 1 {
		t.Errorf("a SHADOW guard hid a capability; shadow mode observes and must not "+
			"change what an agent is told it can do (got %d capabilities, want 1)",
			len(resp.GetCapabilities()))
	}
}

// TestDescribeConsumesNoAnzenBudget — enumerating capabilities must not spend
// the in-flight budget of the work about to be done. Calling Check rather than
// Forbids would do exactly that.
func TestDescribeConsumesNoAnzenBudget(t *testing.T) {
	var doc config.Document
	if err := yaml.Unmarshal([]byte(`targets:
  - {ref: kata:alpha, kind: kata, tenant: alpha, residency: eu, base_url: https://alpha.invalid}
grants:
  - principal: agent:triage
    allow:
      - {action: kata.create_issue, target: kata:alpha}
anzen:
  - name: one-at-a-time
    enabled: true
    max_concurrent: 1
    applies_to: ["agent:triage"]
    mode: enforce
`), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	guards := anzen.New(doc.Anzen)
	c := New(Config{Doc: &doc, Drivers: map[string]connector.Driver{kata.Kind: kata.New()},
		Policy: policy.NewGrantEngine(&doc, nil), Guards: guards, Lenses: shin.New(doc.Shin)})

	for range 5 {
		describe(t, c, "agent:triage", "agent:triage", "")
	}

	if n := guards.InFlight()["agent:triage"]; n != 0 {
		t.Errorf("Describe left %d in-flight slot(s) held; describing capabilities "+
			"would then starve the actions it describes", n)
	}
}

// TestEscalateIsAdvertisedAsEscalate — an ESCALATE capability is real but needs
// approval, and hiding it would make an agent believe it cannot act at all.
func TestEscalateIsAdvertisedAsEscalate(t *testing.T) {
	c := build(t, twoPrincipals)
	resp := describe(t, c, "agent:triage", "agent:triage", "")

	got := map[string]sekizuiv1.Disposition{}
	for _, cap := range resp.GetCapabilities() {
		got[cap.GetAction()] = cap.GetDisposition()
	}

	if d := got["kata.create_issue"]; d != sekizuiv1.Disposition_DISPOSITION_ALLOW {
		t.Errorf("create_issue disposition = %v, want ALLOW", d)
	}
	if d := got["kata.delete_project"]; d != sekizuiv1.Disposition_DISPOSITION_ESCALATE {
		t.Errorf("delete_project disposition = %v, want ESCALATE — an escalate grant is a "+
			"capability with a gate, not an absent capability", d)
	}
}

// TestDescriptionInlinesConstraints is §4.9 property 2: "the agent then doesn't
// discover the boundary by hitting 403s".
func TestDescriptionInlinesConstraints(t *testing.T) {
	c := build(t, twoPrincipals)
	resp := describe(t, c, "agent:triage", "agent:triage", "")

	var desc string
	for _, cap := range resp.GetCapabilities() {
		if cap.GetAction() == "kata.create_issue" {
			desc = cap.GetDescription()
		}
	}

	for _, want := range []string{
		"Create an issue", // from the driver's ActionSpec, not hand-written here
		"on kata:alpha",   // which target
		"PLAT or PROJ",    // the constraint, inlined and ordered
		"10 per hour",     // the limit
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("description %q is missing %q", desc, want)
		}
	}
}

// TestWhereIsPopulated guards the bug shape this package nearly shipped with: a
// declared proto field left empty, so a machine consumer reads no constraints
// and concludes there are none.
func TestWhereIsPopulated(t *testing.T) {
	c := build(t, twoPrincipals)
	resp := describe(t, c, "agent:triage", "agent:triage", "")

	for _, cap := range resp.GetCapabilities() {
		if cap.GetAction() != "kata.create_issue" {
			continue
		}
		con := cap.GetWhere()["project"]
		if con == nil {
			t.Fatal("Capability.where is empty for a grant that HAS a where clause; " +
				"a consumer reading this concludes the capability is unconstrained")
		}
		if strings.Join(con.GetIn(), ",") != "PLAT,PROJ" {
			t.Errorf("where.project.in = %v, want [PLAT PROJ]", con.GetIn())
		}
	}
}

// TestDescriptionMatchesTheStructuredConstraint — the prose an LLM reads and the
// field a program reads come from one source, so they cannot disagree.
func TestDescriptionMatchesTheStructuredConstraint(t *testing.T) {
	c := build(t, twoPrincipals)
	resp := describe(t, c, "agent:triage", "agent:triage", "")

	for _, cap := range resp.GetCapabilities() {
		for field, con := range cap.GetWhere() {
			for _, allowed := range con.GetIn() {
				if !strings.Contains(cap.GetDescription(), allowed) {
					t.Errorf("%s: where.%s permits %q but the description never says so: %q",
						cap.GetAction(), field, allowed, cap.GetDescription())
				}
			}
		}
	}
}

// TestDescribingAnotherPrincipalRequiresMaySpeakFor — a capability listing is a
// map of what to try next, so enumerating the fleet needs the same grant as
// acting as it (§4.4.1).
func TestDescribingAnotherPrincipalRequiresMaySpeakFor(t *testing.T) {
	c := build(t, twoPrincipals)

	// mesh:compute may speak for agent:triage, so it may describe it.
	resp := describe(t, c, "mesh:compute", "mesh:compute", "agent:triage")
	if resp.GetPrincipal() != "agent:triage" {
		t.Errorf("principal = %q, want agent:triage", resp.GetPrincipal())
	}

	// agent:triage may not speak for mesh:compute, so it may not describe it.
	_, err := c.Describe(context.Background(),
		ident("agent:triage", "agent:triage"), "mesh:compute")
	if err == nil {
		t.Fatal("agent:triage described mesh:compute without a may_speak_for grant; " +
			"any compromised agent could then enumerate the whole fleet")
	}
	if got := fault.KindOf(err); got != fault.KindUnauthenticated {
		t.Errorf("kind = %v, want KindUnauthenticated", got)
	}
}

// TestDescribeSelfIsAlwaysAllowed — the common case needs no grant at all.
func TestDescribeSelfIsAlwaysAllowed(t *testing.T) {
	c := build(t, twoPrincipals)

	// Empty principal and an explicit self-name must behave identically;
	// otherwise an agent that names itself hits an unexpected denial.
	implicit := describe(t, c, "agent:triage", "agent:triage", "")
	explicit := describe(t, c, "agent:triage", "agent:triage", "agent:triage")

	if implicit.GetPrincipal() != explicit.GetPrincipal() ||
		len(implicit.GetCapabilities()) != len(explicit.GetCapabilities()) {
		t.Errorf("naming yourself differs from omitting the name: %d vs %d capabilities",
			len(implicit.GetCapabilities()), len(explicit.GetCapabilities()))
	}
}

// TestDelegationNarrowsTheCatalog is D59 seen from the catalog: a mesh speaking
// for an agent sees the INTERSECTION, because that is what it can actually do.
func TestDelegationNarrowsTheCatalog(t *testing.T) {
	c := build(t, twoPrincipals)

	// agent:triage alone has create_issue (allow) and delete_project (escalate).
	alone := describe(t, c, "agent:triage", "agent:triage", "")
	if len(alone.GetCapabilities()) != 2 {
		t.Fatalf("agent:triage alone has %d capabilities, want 2", len(alone.GetCapabilities()))
	}

	// mesh:compute speaking AS agent:triage has only create_issue, because the
	// mesh itself was never granted delete_project. Advertising it would promise
	// something the enforcement path refuses.
	delegated := describe(t, c, "mesh:compute", "agent:triage", "")
	if len(delegated.GetCapabilities()) != 1 {
		t.Fatalf("delegated view has %d capabilities, want 1 (the intersection)",
			len(delegated.GetCapabilities()))
	}
	if a := delegated.GetCapabilities()[0].GetAction(); a != "kata.create_issue" {
		t.Errorf("surviving capability = %q, want kata.create_issue", a)
	}
}

// TestUnknownPrincipalIsEmptyNotAnError — erroring would leak whether a
// principal exists, and "you can do nothing" is the accurate answer.
func TestUnknownPrincipalIsEmptyNotAnError(t *testing.T) {
	c := build(t, `targets:
  - {ref: kata:alpha, kind: kata, tenant: alpha, residency: eu, base_url: https://alpha.invalid}
grants:
  - principal: mesh:compute
    may_speak_for: [agent:ghost]
`)
	resp := describe(t, c, "mesh:compute", "mesh:compute", "agent:ghost")
	if len(resp.GetCapabilities()) != 0 {
		t.Errorf("ungranted principal has %d capabilities, want 0", len(resp.GetCapabilities()))
	}
}

// TestPayloadSchemasAreAdvertised is D40: a consumer can fetch the shape of what
// it will receive rather than inferring it from examples.
func TestPayloadSchemasAreAdvertised(t *testing.T) {
	c := build(t, `targets:
  - {ref: kata:alpha, kind: kata, tenant: alpha, residency: eu, base_url: https://alpha.invalid}
grants:
  - principal: agent:triage
    allow: [{action: kata.comment, target: kata:alpha}]
payload_schemas:
  kata.issue_created.v1:
    type: object
    properties: {id: {type: string}}
`)
	resp := describe(t, c, "agent:triage", "agent:triage", "")
	if _, ok := resp.GetPayloadSchemas()["kata.issue_created.v1"]; !ok {
		t.Errorf("payload_schemas = %v, want kata.issue_created.v1",
			resp.GetPayloadSchemas())
	}
}

// TestMaySpeakForIsReported so a mesh can discover its own delegation reach
// rather than probing for it.
func TestMaySpeakForIsReported(t *testing.T) {
	c := build(t, twoPrincipals)
	resp := describe(t, c, "mesh:compute", "mesh:compute", "")

	if len(resp.GetMaySpeakFor()) != 1 || resp.GetMaySpeakFor()[0] != "agent:triage" {
		t.Errorf("may_speak_for = %v, want [agent:triage]", resp.GetMaySpeakFor())
	}
}

// TestDescribeWithoutIdentityIsRefused — the catalog must never answer for an
// unestablished caller, since the whole response is scoped to who is asking.
func TestDescribeWithoutIdentityIsRefused(t *testing.T) {
	c := build(t, twoPrincipals)
	if _, err := c.Describe(context.Background(), &sekizuiv1.Identity{}, ""); err == nil {
		t.Fatal("described capabilities for an empty identity")
	}
}

// TestCapabilitiesAreOrdered — an unstable order makes diffing two catalogs
// noise, and Go randomises map iteration deliberately.
func TestCapabilitiesAreOrdered(t *testing.T) {
	c := build(t, twoPrincipals)
	for range 10 {
		resp := describe(t, c, "agent:triage", "agent:triage", "")
		caps := resp.GetCapabilities()
		for i := 1; i < len(caps); i++ {
			if caps[i-1].GetAction() > caps[i].GetAction() {
				t.Fatalf("capabilities out of order: %q before %q",
					caps[i-1].GetAction(), caps[i].GetAction())
			}
		}
	}
}
