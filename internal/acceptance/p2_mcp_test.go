package acceptance

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
)

// mcpFixture is a coherent document with one MCP target and its vetted spec.
//
// BUILT IN GO RATHER THAN ADDED TO acceptance.yaml, deliberately. The run's
// shared fixture is loaded once before any step, so a broken variant of it
// cannot exist there — and every case below needs one. P1 step 34 sets the
// precedent for a step that builds its own document.
func mcpFixture(edit func(*config.Document)) *config.Document {
	d := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "fixture-mcp", Kind: "mcp", Tenant: "acme", Residency: "eu",
			BaseURL: "https://mcp.invalid", CredentialRef: "env://SEKIZUI_ACCEPT_TOK",
		}},
		MCPSpecs: map[string]config.MCPSpec{
			"fixture-mcp": {
				Server: "fixture", Host: "mcp.invalid",
				Tools: []config.MCPToolSpec{{
					Name:        "search",
					Description: "Search the repository.",
					InputSchema: json.RawMessage(`{"type":"object"}`),
				}, {
					Name: "create_issue", Description: "Open an issue.", Mutating: true,
					Idempotency:          "header",
					IdempotencyPlacement: "Idempotency-Key",
					InputSchema:          json.RawMessage(`{"type":"object"}`),
				}},
			},
		},
		Grants: []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "mcp.fixture.search", TargetRef: "fixture-mcp"},
			},
		}},
	}
	if edit != nil {
		edit(d)
	}
	return d
}

// step11BootRefusesAnMCPActionContradictingItsTargetRef proves D49 and D192.
//
// **CONTRACTS ITEM 10, VERBATIM.** MCP action names embed the server segment
// (`mcp.fixture.search`) and so can contradict `TargetRef`:
// `{action: "mcp.fixture.*", target_ref: "gitlab-mcp"}` names one server in the
// action and another in the ref, and must be rejected AT LOAD rather than
// discovered at call time — because a grant that cannot mean anything is a grant
// somebody believes they have.
//
// **WHY THE DUPLICATION EXISTS AT ALL, since that is the first question.** D49
// chose namespaced names because `Actions() []ActionSpec` takes no `Target`, so
// one generic `mcp` driver must return one flat list spanning every configured
// server — which forces globally unique names. The alternatives were a `Kind`
// per server, which makes `Kind` a property of the instance rather than the
// type, and `Actions(t Target)`, which churns public API for every driver to
// serve one (D35). D49 named this contradiction as the cost to hold onto; this
// step is where it stops being a note.
//
// OFFLINE, so it BLOCKS THE LOAD (D50). Everything asserted here is answerable
// from the document alone, which is exactly the test for whether a check belongs
// in the blocking half.
func step11BootRefusesAnMCPActionContradictingItsTargetRef(t *testing.T) {
	// --- 11a: THE BASELINE LOADS -------------------------------------------
	//
	// NON-VACUITY FIRST. Every arm below asserts a refusal, and without this the
	// step passes against a validator that refuses everything — "the check works"
	// would be indistinguishable from "the check is broken in the other
	// direction" (CONTRACTS 59).
	if err := mcpFixture(nil).Validate(); err != nil {
		t.Fatalf("11a: a valid MCP configuration was refused, so no refusal below "+
			"proves anything: %v", err)
	}

	// --- 11b: THE CONTRADICTION IS REFUSED ---------------------------------
	t.Run("an action naming one server on another server's target", func(t *testing.T) {
		err := mcpFixture(func(d *config.Document) {
			d.Targets = append(d.Targets, config.TargetSpec{
				Ref: "gitlab-mcp", Kind: "jira", Tenant: "acme", Residency: "eu",
				BaseURL: "https://gitlab.invalid", CredentialRef: "env://SEKIZUI_ACCEPT_TOK",
			})
			d.Grants[0].Allow = []config.CapabilitySpec{{
				Action: "mcp.fixture.search", TargetRef: "gitlab-mcp",
			}}
		}).Validate()

		if err == nil {
			t.Fatal("`{action: mcp.fixture.search, target_ref: gitlab-mcp}` loaded cleanly. " +
				"One of the two is wrong, and discovering which at call time means an " +
				"operator believes they granted something they did not")
		}
		// **THE MESSAGE MUST NAME BOTH HALVES.** An operator told only "invalid " +
		// grant" has to work out which of the two names is the mistake, and the
		// answer is not derivable from the message.
		for _, want := range []string{"mcp.fixture.search", "fixture-mcp", "gitlab-mcp"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %q: %v", want, err)
			}
		}
	})

	// --- 11c: AND A GRANT NAMING NO CONFIGURED SERVER ----------------------
	//
	// The same defect with the other half missing: a segment nobody declared. It
	// cannot authorise anything, and it reads as a permission in force.
	t.Run("an action naming a server nobody configured", func(t *testing.T) {
		err := mcpFixture(func(d *config.Document) {
			d.Grants[0].Allow[0].Action = "mcp.gitlab.search"
		}).Validate()
		if err == nil {
			t.Fatal("a grant naming an unconfigured MCP server loaded cleanly")
		}
		if !strings.Contains(err.Error(), "no vetted spec declares") {
			t.Errorf("the refusal does not say the server is unknown: %v", err)
		}
	})

	// --- 11d: THE VETTED SPEC IS THE CAPABILITY SET, SO IT IS REQUIRED -----
	//
	// **`Actions()` IS GENERATED FROM THE SPEC AND NEVER FROM THE WIRE (D46)**, so
	// an MCP target without one has no capability set at all: it loads cleanly,
	// advertises nothing, and refuses every command that names it. That is the
	// same late failure D190 closed for an unimplemented driver kind, one layer
	// in — and the reason to close it here too rather than note it.
	t.Run("an MCP target with no vetted spec", func(t *testing.T) {
		err := mcpFixture(func(d *config.Document) {
			d.MCPSpecs = nil
		}).Validate()
		if err == nil {
			t.Fatal("an MCP target with no vetted spec loaded cleanly")
		}
		if !strings.Contains(err.Error(), "no entry in mcp_specs") {
			t.Errorf("the refusal does not say the spec is missing: %v", err)
		}
	})

	// --- 11e: A MUTATING TOOL OWES ITS IDEMPOTENCY CLASS (D163) ------------
	//
	// **THE SAME RULE ActionSpec HAS, ON A CONFIGURATION SURFACE — and MCP is
	// where it bites hardest.** A driver's ActionSpec is written by whoever wrote
	// the driver; a vetted spec is written by whoever reviewed a vendor's tool
	// list, and MCP hands them `readOnlyHint` and `destructiveHint` as
	// VENDOR-SUPPLIED hints. D163 forbids inferring the class from those: this
	// field drives the retry gate, and a vendor's opinion about its own
	// destructiveness is not a governance decision.
	t.Run("a mutating tool with no idempotency class", func(t *testing.T) {
		err := mcpFixture(func(d *config.Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Tools[1].Idempotency = ""
			spec.Tools[1].IdempotencyPlacement = ""
			d.MCPSpecs["fixture-mcp"] = spec
		}).Validate()
		if err == nil {
			t.Fatal("a MUTATING MCP tool with no idempotency class loaded cleanly. There " +
				"is no safe default: `none` forbids retries the upstream supports, and " +
				"anything else permits a double-write nobody chose (D163)")
		}
		if !strings.Contains(err.Error(), "declares no idempotency class") {
			t.Errorf("the refusal does not say what is missing: %v", err)
		}
	})

	// --- 11f: AND OUTPUT-SCHEMA PROVENANCE IS PAIRED (D51) -----------------
	//
	// A schema with no origin is the case D51 exists to prevent: a
	// locally-authored guess that cannot be told apart from a vendor guarantee,
	// so that when it starts failing "they changed" and "we guessed wrong" become
	// indistinguishable. Much of the MCP ecosystem publishes no output schema at
	// all, which is why ABSENCE is fine and an unpaired declaration is not.
	t.Run("an output schema with no provenance", func(t *testing.T) {
		err := mcpFixture(func(d *config.Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Tools[0].OutputSchema = json.RawMessage(`{"type":"object"}`)
			d.MCPSpecs["fixture-mcp"] = spec
		}).Validate()
		if err == nil {
			t.Fatal("an output schema with no provenance loaded cleanly, so a schema we " +
				"wrote cannot be told from one the vendor published — and the drift " +
				"check would compare our own guess against the server (D51)")
		}
		for _, o := range config.OutputSchemaOrigins() {
			if !strings.Contains(err.Error(), o) {
				t.Errorf("the refusal does not offer %q, so an author must go reading "+
					"source to find the vocabulary: %v", o, err)
			}
		}
	})

	t.Logf("D49/D192: the offline half of D50 refuses a contradictory grant, an unknown "+
		"server, a specless MCP target, an unclassified mutating tool and an unpaired "+
		"output schema — all from the document alone, with %d provenance values in the "+
		"vocabulary", len(config.OutputSchemaOrigins()))
}
