package acceptance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/catalog"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/grantcheck"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// step35NothingInTheCatalogIsSynthesised proves D196.
//
// **THE CATALOG IS WHAT A MODEL READS TO DECIDE WHAT TO ATTEMPT** (§4.9 property
// 2, "the agent then doesn't discover the boundary by hitting 403s"), which
// makes it the one surface where an invented sentence is indistinguishable from
// a described one. It used to invent: an action with no `ActionSpec` fell back to
// its own identifier, so `mcp.fixture.exfiltrate` was advertised as
// *"mcp.fixture.exfiltrate on fixture-mcp."* — a restatement wearing a
// description, for an action no driver implemented.
//
// **THE HOUSE RULE THIS BELONGS TO IS ALREADY WRITTEN THREE TIMES.** D119 makes
// a credential posture NIL rather than zero-valued, because an empty message on
// the wire reads as an assertion and absence does not. D75 keeps *cannot
// confirm* apart from *refuted*. D51 pins schema PROVENANCE so a schema we wrote
// cannot pass as one the vendor published. Same rule, three surfaces: Sekizui
// does not manufacture a claim to fill a field.
//
// FOUR ARMS, and the last two are what stop the first two being cosmetic.
func step35NothingInTheCatalogIsSynthesised(t *testing.T) {
	ctx := context.Background()

	// --- 35a: A DRIVER ACTION WITH NO DESCRIPTION FAILS THE LOAD -----------
	//
	// The refusal has to be at load, because the alternative is a catalog with
	// nothing to say at the moment an agent asks — and "nothing to say" is
	// exactly the pressure that produced the synthesis.
	silent := connector.ActionSpec{
		Name: "kata.create_issue", Mutating: true,
		Idempotency: connector.IdempotencyHeader, IdempotencyPlacement: "Idempotency-Key",
		OutputType: kata.WriteResultType, // D283: every action declares its result
	}
	problems := connector.ValidateActions(kata.Kind, []connector.ActionSpec{silent})
	if len(problems) == 0 {
		t.Error("35a: an action with no description loaded cleanly. The catalog then " +
			"advertises it to a model with nothing but its own name (D196)")
	}

	// NON-VACUITY: the same action WITH a description must load, or 35a passes
	// against a validator that refuses everything (CONTRACTS 59).
	described := silent
	described.Description = "Create an issue."
	if problems := connector.ValidateActions(kata.Kind, []connector.ActionSpec{described}); len(problems) > 0 {
		t.Errorf("35a: a described action was refused, so the arm above proves "+
			"nothing: %v", problems)
	}

	// --- 35b: EVERY ACTION THIS BUILD SERVES CARRIES ONE -------------------
	//
	// RANGED OVER THE WHOLE SET rather than checked on a sample (§15q). A driver
	// added next year is covered by this shape; one naming today's drivers is
	// right until somebody adds the next.
	for _, spec := range kata.New().Actions() {
		if strings.TrimSpace(spec.Description) == "" {
			t.Errorf("35b: %s has no description", spec.Name)
		}
	}
	for _, name := range verb.Names() {
		spec, ok := verb.Lookup(name)
		if !ok || strings.TrimSpace(spec.Description) == "" {
			t.Errorf("35b: governed verb %s has no description. A break-glass verb "+
				"reaching an operator's tooling as its own identifier is the same "+
				"defect as a driver action doing it", name)
		}
	}

	// --- 35c: THE ADVERTISED SENTENCE IS THE DRIVER'S OWN ------------------
	//
	// Not merely non-empty: the actual text. A catalog that passed 35a and 35b
	// and then rendered the identifier anyway would look correct from both.
	doc := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "kata:alpha", Kind: kata.Kind, Tenant: "alpha", Residency: "eu",
			BaseURL: "https://alpha.invalid",
		}},
		Grants: []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "kata.create_issue", TargetRef: "kata:alpha"},
			},
		}},
	}
	drivers := map[string]connector.Driver{kata.Kind: kata.New()}
	cat := catalog.New(catalog.Config{Doc: doc, Drivers: drivers,
		Policy: policy.NewGrantEngine(doc, nil), Guards: anzen.New(nil)})

	resp, err := cat.Describe(ctx, assertedIdentity("agent:dev"), "")
	if err != nil {
		t.Fatalf("35c: Describe: %v", err)
	}
	if len(resp.GetCapabilities()) != 1 {
		t.Fatalf("35c: %d capabilities, want 1", len(resp.GetCapabilities()))
	}
	got := resp.GetCapabilities()[0].GetDescription()
	if !strings.HasPrefix(got, "Create an issue on kata:alpha.") {
		t.Errorf("35c: the advertised description is %q. It must be the driver's own "+
			"sentence with the target attached, not the action name", got)
	}
	if strings.HasPrefix(got, "kata.create_issue") {
		t.Errorf("35c: the catalog rendered the IDENTIFIER as the description: %q", got)
	}

	// --- 35d: AND AN UNDESCRIBABLE ACTION CANNOT BE GRANTED AT ALL (D195) --
	//
	// The arm that makes the other three hold in a running deployment rather
	// than in a fixture. `renderDescription` has no fallback now, so an action
	// nothing describes must not survive boot — otherwise the failure moves from
	// a misleading description to an error at Describe time, which is a
	// different bug rather than a fix.
	typo := &config.Document{
		Targets: doc.Targets,
		Grants: []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "kata.create_isue", TargetRef: "kata:alpha"},
			},
		}},
	}
	err = grantcheck.Validate(typo, drivers)
	if err == nil {
		t.Error("35d: a grant naming an action no driver implements loaded cleanly")
	} else if !strings.Contains(err.Error(), "kata.create_isue") {
		t.Errorf("35d: the refusal does not name the action: %v", err)
	}

	r := &run{}
	r.detail(t, "D196: an action with no description fails the load, all %d kata "+
		"actions and all %d governed verbs carry one, the catalog advertises the "+
		"driver's own sentence rather than the identifier, and an action nothing "+
		"describes cannot be granted",
		len(kata.New().Actions()), len(verb.Names()))
}
