package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// mcpDoc builds a document with one MCP target and its vetted spec, then
// applies an edit.
//
// A HELPER THAT STARTS FROM A VALID DOCUMENT, so every case below varies ONE
// thing. A test that constructs its own broken document from scratch proves the
// validator rejects that document, not that it rejects the property named in the
// test's title.
func mcpDoc(edit func(*Document)) *Document {
	d := &Document{
		Targets: []TargetSpec{{
			Ref: "fixture-mcp", Kind: "mcp", Tenant: "acme", Residency: "eu",
			BaseURL: "https://mcp.invalid", CredentialRef: "env://TOK",
		}},
		MCPSpecs: map[string]MCPSpec{
			"fixture-mcp": {
				Server: "fixture", Host: "mcp.invalid",
				Tools: []MCPToolSpec{{
					Name: "search", Description: "Search the repository.",
					InputSchema: json.RawMessage(`{"type":"object"}`),
				}},
			},
		},
		Grants: []GrantSpec{{
			Principal: "agent:dev",
			Allow: []CapabilitySpec{{
				Action: "mcp.fixture.search", TargetRef: "fixture-mcp",
			}},
		}},
	}
	if edit != nil {
		edit(d)
	}
	return d
}

// problemsOf runs the MCP validations alone, so a case's failure is about MCP
// rather than about whatever else the fixture is missing.
func problemsOf(d *Document) string {
	var p problems
	targets := map[string]bool{}
	for _, t := range d.Targets {
		targets[t.Ref] = true
	}
	d.validateMCP(&p, targets)
	return strings.Join(p, "\n")
}

// TestAValidMCPConfigurationLoads is the non-vacuity arm for every case below.
//
// Without it the file passes against a validator that refuses everything, and
// "the check works" would be indistinguishable from "the check is broken in the
// other direction" (CONTRACTS 59).
func TestAValidMCPConfigurationLoads(t *testing.T) {
	if got := problemsOf(mcpDoc(nil)); got != "" {
		t.Errorf("a valid MCP configuration was refused:\n%s", got)
	}
}

// TestTheMCPValidationsAreWIRED is the arm every other test in this file needs
// and none of them provides.
//
// **THEY ALL CALL `validateMCP` DIRECTLY, so they prove the checks WORK and say
// nothing about whether anything RUNS them.** Found by probing: removing
// `d.validateMCP(&p, targets)` from `Document.Validate` left this package green.
// That is this codebase's signature defect — an implementation with no caller —
// arriving in the tests written to prevent it, and the reason `Validate` is
// exercised here through its PUBLIC entry point rather than its parts.
func TestTheMCPValidationsAreWIRED(t *testing.T) {
	// **NOT `documentFixture()`, and the distinction is worth knowing.** That is a
	// COMPLETENESS fixture — every field non-zero so `TestFixtureIsComplete` can
	// catch a new one — and it is deliberately not a COHERENT document: its
	// reflex has both an action and a publish_to, its anzen rule mixes reactive
	// with a residency scope. Using it here reported five unrelated problems and
	// isolated nothing. `mcpDoc` is coherent, which is what a baseline has to be.
	d := mcpDoc(nil)
	if err := d.Validate(); err != nil {
		t.Fatalf("the baseline document does not validate, so this case cannot isolate "+
			"the MCP half: %v", err)
	}

	// CONTRACTS item 10's exact shape, introduced into an otherwise valid
	// document: the action names one server and the grant targets another.
	d.Targets = append(d.Targets, TargetSpec{
		Ref: "gitlab-mcp", Kind: "jira", Tenant: "acme", Residency: "eu",
		BaseURL: "https://gitlab.invalid", CredentialRef: "env://TOK",
	})
	d.Grants[0].Allow = append(d.Grants[0].Allow, CapabilitySpec{
		Action: "mcp.fixture.create_issue", TargetRef: "gitlab-mcp",
	})

	err := d.Validate()
	if err == nil {
		t.Fatal("Document.Validate accepted a grant whose MCP action contradicts its " +
			"target ref. The checks exist and nothing calls them, which is the defect " +
			"class this whole file is about")
	}
	if !strings.Contains(err.Error(), "mcp.fixture.create_issue") {
		t.Errorf("Validate refused for some other reason than the MCP contradiction, "+
			"so this case is not asserting what it claims: %v", err)
	}
}

// TestAnActionContradictingItsTargetRefIsRefusedAtLoad is CONTRACTS item 10 and
// D49's stated cost.
//
// **THE SERVER SEGMENT DUPLICATES THE TARGET REF, SO THEY CAN DISAGREE.** D49
// chose namespaced action names because `Actions()` takes no Target, and named
// this as the consequence to hold onto. A grant that cannot mean anything is a
// grant somebody believes they have — so it is refused at LOAD rather than
// discovered at call time.
func TestAnActionContradictingItsTargetRefIsRefusedAtLoad(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) {
		d.Targets = append(d.Targets, TargetSpec{
			Ref: "gitlab-mcp", Kind: "mcp", Tenant: "acme", Residency: "eu",
			BaseURL: "https://gitlab.invalid", CredentialRef: "env://TOK",
		})
		d.MCPSpecs["gitlab-mcp"] = MCPSpec{
			Server: "gitlab", Host: "gitlab.invalid",
			Tools: []MCPToolSpec{{Name: "search", Description: "Search.", InputSchema: json.RawMessage(`{}`)}},
		}
		// THE EXACT CASE CONTRACTS ITEM 10 WRITES DOWN.
		d.Grants[0].Allow[0] = CapabilitySpec{
			Action: "mcp.fixture.search", TargetRef: "gitlab-mcp",
		}
	}))

	if got == "" {
		t.Fatal("a grant naming `mcp.fixture.search` on target `gitlab-mcp` loaded " +
			"cleanly. One of the two is wrong, and discovering which at call time " +
			"means an operator believes they granted something they did not")
	}
	for _, want := range []string{"mcp.fixture.search", "fixture-mcp", "gitlab-mcp"} {
		if !strings.Contains(got, want) {
			t.Errorf("the refusal does not name %q, so an operator cannot see which "+
				"half to fix:\n%s", want, got)
		}
	}
}

// TestAnEscalateGrantIsCheckedToo.
//
// THE LIST THAT GETS FORGOTTEN. `allow` and `escalate` are both capability
// lists, and a check that walks only the first leaves the other as a way to
// declare a contradictory grant that boot accepts.
func TestAnEscalateGrantIsCheckedToo(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) {
		d.Grants[0].Escalate = []CapabilitySpec{{
			Action: "mcp.nonexistent.destroy", TargetRef: "fixture-mcp",
		}}
	}))
	if !strings.Contains(got, "mcp.nonexistent.destroy") {
		t.Errorf("an `escalate` capability naming an unknown MCP server was accepted:\n%s", got)
	}
}

// TestAGrantNamingAnUnconfiguredServerIsRefused.
func TestAGrantNamingAnUnconfiguredServerIsRefused(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) {
		d.Grants[0].Allow[0].Action = "mcp.gitlab.search"
	}))
	if !strings.Contains(got, "which no vetted spec declares") {
		t.Errorf("a grant naming a server nobody configured was accepted. It cannot "+
			"authorise anything, and reads as a permission in force:\n%s", got)
	}
}

// TestAnMCPTargetWithoutASpecIsRefused.
//
// **THE VETTED SPEC IS THE CAPABILITY SET (D46)**, so a target without one loads
// cleanly, advertises nothing, and refuses every command that names it — the
// same late failure D190 closed for an unimplemented driver kind, one layer in.
func TestAnMCPTargetWithoutASpecIsRefused(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) { delete(d.MCPSpecs, "fixture-mcp") }))
	if !strings.Contains(got, "no entry in mcp_specs") {
		t.Errorf("an MCP target with no vetted spec loaded cleanly:\n%s", got)
	}
}

// TestASpecForNoTargetIsRefused closes the other direction: far more likely a
// typo'd ref than a deliberate spare.
func TestASpecForNoTargetIsRefused(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) {
		d.MCPSpecs["typo-mcp"] = MCPSpec{
			Server: "typo", Host: "typo.invalid",
			Tools: []MCPToolSpec{{Name: "x", InputSchema: json.RawMessage(`{}`)}},
		}
	}))
	if !strings.Contains(got, "no target with that ref") {
		t.Errorf("a vetted spec keyed to no target was accepted:\n%s", got)
	}
}

// TestTwoTargetsCannotClaimOneServerSegment.
//
// `mcp.fixture.search` would then name a tool on two servers and the enforcement
// path would have to pick, which is not a decision code should make silently.
func TestTwoTargetsCannotClaimOneServerSegment(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) {
		d.Targets = append(d.Targets, TargetSpec{
			Ref: "github-enterprise", Kind: "mcp", Tenant: "acme", Residency: "eu",
			BaseURL: "https://ghe.invalid", CredentialRef: "env://TOK",
		})
		d.MCPSpecs["github-enterprise"] = MCPSpec{
			Server: "fixture", Host: "ghe.invalid", // the collision
			Tools: []MCPToolSpec{{Name: "search", Description: "Search.", InputSchema: json.RawMessage(`{}`)}},
		}
	}))
	if !strings.Contains(got, "both use server segment") {
		t.Errorf("two targets claimed one server segment:\n%s", got)
	}
}

// TestAMutatingToolMustDeclareItsIdempotencyClass is D163 on a configuration
// surface.
//
// There is no safe default: `none` forbids retries the upstream supports, and
// anything else permits a double-write nobody chose. MCP's own `readOnlyHint`
// and `destructiveHint` are the VENDOR's opinion, and this field drives the
// retry gate — so a human sets it, and the load fails when nobody did.
func TestAMutatingToolMustDeclareItsIdempotencyClass(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) {
		d.MCPSpecs["fixture-mcp"].Tools[0].Name = "create_issue"
		spec := d.MCPSpecs["fixture-mcp"]
		spec.Tools[0].Mutating = true
		d.MCPSpecs["fixture-mcp"] = spec
	}))
	if !strings.Contains(got, "declares no idempotency class") {
		t.Errorf("a mutating MCP tool with no idempotency class loaded cleanly:\n%s", got)
	}
}

// TestAReadToolMayNotDeclareAnIdempotencyClass is the paired invariant, in the
// shape OutputSchema and its origin already use: a field that can never be
// consulted must be refused rather than ignored, or a reviewer reads it as a
// guarantee in force.
func TestAReadToolMayNotDeclareAnIdempotencyClass(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) {
		spec := d.MCPSpecs["fixture-mcp"]
		spec.Tools[0].Idempotency = "header"
		d.MCPSpecs["fixture-mcp"] = spec
	}))
	if !strings.Contains(got, "nothing would ever consult") {
		t.Errorf("a READ declaring an idempotency class loaded cleanly:\n%s", got)
	}
}

// TestOutputSchemaAndItsProvenanceAreRequiredTogether is D51.
//
// **A SCHEMA WITH NO ORIGIN IS THE CASE D51 EXISTS TO PREVENT**: a
// locally-authored guess that cannot be told apart from a vendor guarantee, so
// that when it starts failing "they changed" and "we guessed wrong" become
// indistinguishable. An origin with no schema is the inverse — output typing
// that reads as in force and is not.
func TestOutputSchemaAndItsProvenanceAreRequiredTogether(t *testing.T) {
	t.Run("a schema without an origin is refused", func(t *testing.T) {
		got := problemsOf(mcpDoc(func(d *Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Tools[0].OutputSchema = json.RawMessage(`{"type":"object"}`)
			d.MCPSpecs["fixture-mcp"] = spec
		}))
		if !strings.Contains(got, "no output_schema_origin") {
			t.Errorf("an output schema with no provenance was accepted:\n%s", got)
		}
		// AND IT OFFERS THE CHOICES, derived from the vocabulary (§15q) so a new
		// origin appears without anybody editing a message.
		for _, o := range OutputSchemaOrigins() {
			if !strings.Contains(got, o) {
				t.Errorf("the refusal does not offer %q", o)
			}
		}
	})

	t.Run("an origin without a schema is refused", func(t *testing.T) {
		got := problemsOf(mcpDoc(func(d *Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Tools[0].OutputSchemaOrigin = "vendor"
			d.MCPSpecs["fixture-mcp"] = spec
		}))
		if !strings.Contains(got, "with no output_schema") {
			t.Errorf("a provenance with nothing to describe was accepted:\n%s", got)
		}
	})

	t.Run("an unknown origin is refused", func(t *testing.T) {
		got := problemsOf(mcpDoc(func(d *Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Tools[0].OutputSchema = json.RawMessage(`{}`)
			spec.Tools[0].OutputSchemaOrigin = "probably-vendor"
			d.MCPSpecs["fixture-mcp"] = spec
		}))
		if !strings.Contains(got, "not in the vocabulary") {
			t.Errorf("an unknown provenance was accepted. `vendor` is drift-checked and "+
				"`local` is not, so a third value would fall through to whichever "+
				"branch happened to be the default:\n%s", got)
		}
	})

	// **AND ABSENCE IS NEVER A PROBLEM**, which is the whole reason provenance is
	// pinned rather than absence being read as drift: much of the ecosystem
	// publishes no output schema at all (D51).
	t.Run("no output typing at all is fine", func(t *testing.T) {
		if got := problemsOf(mcpDoc(nil)); strings.Contains(got, "output_schema") {
			t.Errorf("a tool with no output typing was faulted for it:\n%s", got)
		}
	})
}

// TestAToolWithoutAnInputSchemaIsRefused.
//
// `inputSchema` is MANDATORY in MCP, so its absence means the spec was
// hand-written without one or the tool does not exist — and without it there is
// nothing to drift-check, which §4.9a.3 calls the most dangerous divergence
// there is.
func TestAToolWithoutAnInputSchemaIsRefused(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) {
		spec := d.MCPSpecs["fixture-mcp"]
		spec.Tools[0].InputSchema = nil
		d.MCPSpecs["fixture-mcp"] = spec
	}))
	if !strings.Contains(got, "no input_schema") {
		t.Errorf("a tool with no input schema was accepted:\n%s", got)
	}
}

func TestMalformedSchemaJSONIsRefused(t *testing.T) {
	got := problemsOf(mcpDoc(func(d *Document) {
		spec := d.MCPSpecs["fixture-mcp"]
		spec.Tools[0].InputSchema = json.RawMessage(`{"type":`)
		d.MCPSpecs["fixture-mcp"] = spec
	}))
	if !strings.Contains(got, "not valid JSON") {
		t.Errorf("a truncated schema was accepted:\n%s", got)
	}
}

func TestAnEmptySpecAndADuplicateToolAreRefused(t *testing.T) {
	t.Run("a spec with no tools", func(t *testing.T) {
		got := problemsOf(mcpDoc(func(d *Document) {
			d.MCPSpecs["fixture-mcp"] = MCPSpec{Server: "fixture"}
		}))
		if !strings.Contains(got, "no tools") {
			t.Errorf("an empty vetted spec was accepted. It advertises a server that "+
				"can do nothing, declared as though it could:\n%s", got)
		}
	})

	t.Run("one tool declared twice", func(t *testing.T) {
		got := problemsOf(mcpDoc(func(d *Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Tools = append(spec.Tools, spec.Tools[0])
			d.MCPSpecs["fixture-mcp"] = spec
		}))
		if !strings.Contains(got, "declared twice") {
			t.Errorf("a tool declared twice was accepted, so which entry is effective "+
				"depends on iteration order:\n%s", got)
		}
	})

	t.Run("a spec with no server segment", func(t *testing.T) {
		got := problemsOf(mcpDoc(func(d *Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Server = ""
			d.MCPSpecs["fixture-mcp"] = spec
		}))
		if !strings.Contains(got, "missing server segment") {
			t.Errorf("a spec with no server segment was accepted:\n%s", got)
		}
	})
}

// TestANonMCPActionIsNotMistakenForOne. The prefix check must not catch
// `mcp_something` or a bare `mcp.`, or every non-MCP grant would be validated
// against a server list it has nothing to do with.
func TestANonMCPActionIsNotMistakenForOne(t *testing.T) {
	for _, action := range []string{
		"kata.create_issue", "mcpsomething.do", "mcp.", "mcp..tool", "sekizui.revoke_credential",
	} {
		if segment, ok := mcpServerSegment(action); ok {
			t.Errorf("%q was read as MCP action naming server %q", action, segment)
		}
	}
	if segment, ok := mcpServerSegment("mcp.fixture.search"); !ok || segment != "fixture" {
		t.Errorf("mcp.fixture.search gave (%q, %v), want (fixture, true)", segment, ok)
	}
}

// --- the declared protocol revision (D193) --------------------------------

// TestTheProtocolRevisionIsDeclaredNeverNegotiated.
//
// **AUTO-NEGOTIATION IS AN ATTACKER-TRIGGERABLE DOWNGRADE, which is the whole
// reason this is a config field.** The specification's backward-compatibility
// flow has a client try a modern request and fall back when the server answers
// `400` with `UnsupportedProtocolVersionError`. A compromised or hostile server
// can therefore CHOOSE to be talked to in an older shape — sessions, a GET
// stream, resumable SSE, an `initialize` handshake — simply by claiming not to
// support the modern one. Nothing about a governed relay should let the far side
// pick the protocol.
func TestTheProtocolRevisionIsDeclaredNeverNegotiated(t *testing.T) {
	t.Run("absent means the modern sessionless revision", func(t *testing.T) {
		// THE SAFE SHAPE IS THE DEFAULT and the weaker shape is the deliberate
		// act. The inverse would make an unreviewed spec inherit sessions.
		if !MCPRevisionImplemented(DefaultMCPRevision) {
			t.Fatalf("the default revision %q is not implemented, so an absent "+
				"declaration would refuse every spec", DefaultMCPRevision)
		}
		if got := problemsOf(mcpDoc(nil)); got != "" {
			t.Errorf("a spec with no declared revision was refused:\n%s", got)
		}
	})

	t.Run("the implemented revision loads", func(t *testing.T) {
		got := problemsOf(mcpDoc(func(d *Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Revision = DefaultMCPRevision
			d.MCPSpecs["fixture-mcp"] = spec
		}))
		if got != "" {
			t.Errorf("the implemented revision was refused:\n%s", got)
		}
	})

	// **A REAL-BUT-UNIMPLEMENTED REVISION REFUSES, AND SAYS WHAT IT WOULD COST.**
	// D53's rule on a protocol vocabulary: the set is declared whole so an
	// operator can see which revisions exist, and choosing one this build cannot
	// speak fails loudly rather than being spoken partially.
	t.Run("a real revision this build cannot speak is refused", func(t *testing.T) {
		var unimplemented string
		for _, r := range MCPRevisions() {
			if !MCPRevisionImplemented(r) {
				unimplemented = r
				break
			}
		}
		if unimplemented == "" {
			t.Skip("every declared revision is implemented, so this arm has nothing " +
				"to prove. Skipping loudly rather than passing")
		}

		got := problemsOf(mcpDoc(func(d *Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Revision = unimplemented
			d.MCPSpecs["fixture-mcp"] = spec
		}))
		if !strings.Contains(got, "NOT implemented in this build") {
			t.Errorf("revision %q loaded cleanly and this build cannot speak it. A "+
				"server that appears to work is the failure §4.7.10 keeps naming:\n%s",
				unimplemented, got)
		}
		// AND IT SAYS WHAT THE OLDER SHAPE COSTS, so an operator can decide
		// whether they want it rather than only learning they cannot have it.
		if !strings.Contains(got, "session") {
			t.Errorf("the refusal does not say what the older revision requires, so an "+
				"operator cannot tell whether to pursue it:\n%s", got)
		}
	})

	t.Run("an invented revision is refused", func(t *testing.T) {
		got := problemsOf(mcpDoc(func(d *Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Revision = "2027-01-01"
			d.MCPSpecs["fixture-mcp"] = spec
		}))
		if !strings.Contains(got, "not a known MCP protocol revision") {
			t.Errorf("an unknown revision was accepted:\n%s", got)
		}
		// THE REFUSAL OFFERS THE VOCABULARY, derived from the set (§15q).
		for _, r := range MCPRevisions() {
			if !strings.Contains(got, r) {
				t.Errorf("the refusal does not offer %q", r)
			}
		}
	})
}

// --- x-mcp-header mirroring (D194) ----------------------------------------

// TestHeaderMirroringIsRefusedUntilReviewed.
//
// **THE SERVER CONTROLS `inputSchema` AND MIRRORING IS A CLIENT `MUST`**, so a
// server can designate any argument to be copied into an `Mcp-Param-*` header —
// where load balancers, proxies, WAFs and logging tiers all see it, and where
// headers are routinely logged in full while bodies are not. The specification
// tells SERVERS they "SHOULD NOT mark sensitive parameters", which is advice to
// the honest party and no protection from a dishonest one.
//
// For a policy enforcement point that is a data-egress decision, so a human
// reads which parameters travel and writes it down.
func TestHeaderMirroringIsRefusedUntilReviewed(t *testing.T) {
	mirroring := func(reviewed bool) *Document {
		return mcpDoc(func(d *Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Tools[0].InputSchema = json.RawMessage(
				`{"type":"object","properties":{"token":{"type":"string","x-mcp-header":"Token"}}}`)
			spec.Tools[0].HeaderMirroringReviewed = reviewed
			d.MCPSpecs["fixture-mcp"] = spec
		})
	}

	t.Run("unreviewed mirroring is refused", func(t *testing.T) {
		got := problemsOf(mirroring(false))
		if !strings.Contains(got, mcpHeaderAnnotation) {
			t.Fatalf("a tool whose schema mirrors an argument into an HTTP header "+
				"loaded cleanly. The caller's value leaves the request BODY and enters "+
				"network-visible metadata, with nothing in the audit record saying "+
				"so:\n%s", got)
		}
		// **THE REFUSAL NAMES WHICH PARAMETER AND WHICH HEADER**, because "this
		// tool mirrors something" is not a reviewable statement. A reviewer needs
		// to know that `token` becomes `Mcp-Param-Token`.
		for _, want := range []string{"token", "Mcp-Param-Token"} {
			if !strings.Contains(got, want) {
				t.Errorf("the refusal does not name %q, so a reviewer cannot see what "+
					"travels:\n%s", want, got)
			}
		}
	})

	t.Run("reviewed mirroring loads", func(t *testing.T) {
		// NON-VACUITY. Without this the arm above passes against a validator that
		// refuses every schema, and the review flag would be decoration.
		if got := problemsOf(mirroring(true)); got != "" {
			t.Errorf("reviewed mirroring was refused, so the flag does nothing:\n%s", got)
		}
	})

	t.Run("a schema with no mirroring is untouched", func(t *testing.T) {
		if got := problemsOf(mcpDoc(nil)); strings.Contains(got, mcpHeaderAnnotation) {
			t.Errorf("a tool with no x-mcp-header was faulted for mirroring:\n%s", got)
		}
	})
}

// TestNestedAndUnreachableAnnotationsAreFoundCorrectly.
//
// The specification confines a VALID annotation to a chain of `properties` keys
// — never through `items`, `oneOf`/`anyOf`/`allOf`/`not`, `if`/`then`/`else` or
// `$ref` — and requires a client to REJECT a tool definition that puts one
// elsewhere. So the walk must find a nested one and must not be fooled into
// treating an array item's schema as a mirrored property.
func TestNestedAndUnreachableAnnotationsAreFoundCorrectly(t *testing.T) {
	t.Run("a nested properties chain is found", func(t *testing.T) {
		got := headerMirroredProperties(json.RawMessage(`{
			"type":"object",
			"properties":{
				"outer":{"type":"object","properties":{
					"inner":{"type":"string","x-mcp-header":"Inner"}}}}}`))
		if len(got) != 1 || !strings.Contains(got[0], "outer.inner") {
			t.Errorf("nested annotation = %v, want one naming outer.inner. A walk that "+
				"only checks top-level properties would miss it, and the specification "+
				"permits nesting as long as every step is a `properties` key", got)
		}
	})

	t.Run("an annotation under items is not a mirrored property", func(t *testing.T) {
		got := headerMirroredProperties(json.RawMessage(`{
			"type":"object",
			"properties":{"list":{"type":"array","items":{
				"type":"object","properties":{"x":{"x-mcp-header":"X"}}}}}}`))
		if len(got) != 0 {
			t.Errorf("found %v under an `items` keyword. The specification makes such an "+
				"annotation INVALID rather than mirrored, so treating it as mirrored "+
				"would demand review for something no conforming client sends", got)
		}
	})

	t.Run("a cyclic or absurdly deep schema does not exhaust the stack", func(t *testing.T) {
		// A HOSTILE SCHEMA AT CONFIG-VALIDATION TIME IS A DENIAL OF SERVICE
		// AGAINST BOOT, which is a different target from the serving path and
		// just as effective. Bounded rather than trusted.
		deep := strings.Repeat(`{"type":"object","properties":{"a":`, 200) +
			`{"type":"string"}` + strings.Repeat("}}", 200)
		if got := headerMirroredProperties(json.RawMessage(deep)); len(got) != 0 {
			t.Errorf("a 200-deep schema produced %v", got)
		}
	})

	t.Run("a malformed schema yields nothing rather than panicking", func(t *testing.T) {
		if got := headerMirroredProperties(json.RawMessage(`{"type":`)); got != nil {
			t.Errorf("a truncated schema produced %v", got)
		}
	})
}
