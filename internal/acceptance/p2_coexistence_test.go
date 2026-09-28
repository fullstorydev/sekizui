package acceptance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// bothPaths adds a NATIVE Fullstory target beside the fixture's MCP one, so one
// system is fronted by two targets — D52's arrangement, permanently.
//
// **THE MCP TOOL IS DELIBERATELY NAMED AFTER THE NATIVE ACTION.** `create_event`
// on both sides is the overlap §4.9a.8 is about: not a duplicate, but the same
// capability reachable through two doors. A fixture that gave them unrelated
// names would model coexistence without modelling the hazard.
//
// **THE NATIVE TARGET IS NEVER SUCCESSFULLY CALLED, AND NO ARM NEEDS IT TO BE.**
// It points at the MCP fixture's TLS server, which the Fullstory driver's own
// HTTP client does not trust — so a call that got past policy would fail on the
// certificate. Every arm here stops at the grant check, which runs long before
// any driver. Stated because a reader could reasonably assume the native path is
// exercised, and because it is exactly what made 14b's first premise check
// worthless: "not OK" was satisfied by `indeterminate` from a TLS failure, which
// says nothing about whether the operator's denial is in force.
func bothPaths(t *testing.T) func(*config.Document) {
	t.Helper()

	return func(d *config.Document) {
		t.Setenv("SEKIZUI_FS_NATIVE", "fs-token")
		d.Targets = append(d.Targets, config.TargetSpec{
			Ref: "fullstory-api", Kind: fullstory.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: d.Targets[0].BaseURL, CredentialRef: "env://SEKIZUI_FS_NATIVE",
		})

		// **THE REF STAYS `fixture-mcp` AND THE SERVER SEGMENT BECOMES
		// `fullstory`, which is not a fixture shortcut — §4.9a.4 says they may
		// disagree and D49 says why.** A ref is an operator's name for an
		// endpoint; the server segment is what appears in every grant and every
		// audit row. Keeping them different here is the realistic shape and it
		// also leaves the rig's own eager resolve, which names the ref, working.
		spec := d.MCPSpecs["fixture-mcp"]
		spec.Server = "fullstory"
		spec.Tools = []config.MCPToolSpec{{
			Name:        "create_event",
			Description: "Record a server-side event.",
			Mutating:    true,
			Idempotency: "natural",
			InputSchema: objectSchema("name"),
		}}
		d.MCPSpecs["fixture-mcp"] = spec
	}
}

// step14AnActionDeniedOnOnePathIsNotObtainableThroughTheOther is criterion 2's
// first half (D52).
//
// **THE STEP AS DECLARED OVERSTATED WHAT D52 PERMITS, AND SAYING SO IS THE
// POINT.** Its brief read "an action denied on one path is not obtainable
// through the other", which sounds like an enforcement guarantee. §4.9a.8
// refuses to make that claim, in terms: *"It cannot be fully automated away:
// whether an MCP tool is equivalent to a native action is a semantic judgement
// about someone else's API, not something derivable from two JSON Schemas."*
// Sekizui cannot know that `mcp.fullstory.create_event` and
// `fullstory.create_event` are the same capability, so it cannot refuse the
// second because you denied the first.
//
// **WRITING THE DECLARED VERSION WOULD HAVE PRODUCED D154's DEFECT** — a step
// that could only be made to pass. The obvious way to make it green is to give
// the principal no MCP grant and then observe that the MCP call is denied, which
// proves that grants are per-action and nothing about union.
//
// **SO THE STEP PROVES THE THREE THINGS THAT ARE TRUE**, which together are what
// §4.9a.8 actually obliges: the namespaces do not collide, so neither path
// silently widens the other (mechanism); the leak IS reachable when an operator
// grants one and denies the other, demonstrated rather than asserted away
// (the hazard, made concrete); and the overlap is VISIBLE in one listing, which
// is the mitigation §4.9a.8 says can be built — *"the panel must show effective
// capability per system, not per target, so an overlap is apparent to a reviewer
// even though a machine cannot adjudicate it."*
func step14AnActionDeniedOnOnePathIsNotObtainableThroughTheOther(t *testing.T) {
	ctx := context.Background()

	// --- 14a: THE NAMESPACES DO NOT COLLIDE, IN BOTH DIRECTIONS ------------
	//
	// **BOTH DIRECTIONS, BECAUSE THEY FAIL INDEPENDENTLY.** A wildcard is the
	// realistic shape of an over-broad grant, and the two wildcards here are the
	// ones an operator would plausibly write. `fullstory.*` must not reach the
	// MCP tool, and `mcp.fullstory.*` must not reach the native action —
	// asserted by driving a REFUSAL through the enforcement path rather than by
	// reading the grant table back, which would prove only that a field was set.
	t.Run("a wildcard on one path does not confer the other", func(t *testing.T) {
		// **THE GRANT AND THE ATTEMPT NAME THE SAME TARGET, which is what makes
		// this about namespaces at all.** Put them on different targets and the
		// refusal comes from the target mismatch — true, and silent about the
		// question. That was this arm's first version.
		for _, tc := range []struct {
			name, grant, attempt, target string
		}{
			{"native wildcard does not reach the MCP tool",
				"fullstory.*", "mcp.fullstory.create_event", "fixture-mcp"},
			{"MCP wildcard does not reach the native action",
				"mcp.fullstory.*", fullstory.ActionCreateEvent, "fullstory-api"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				stack := newCoexistenceStack(ctx, t, on(tc.grant, tc.target))

				res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"),
					&sekizuiv1.Command{
						Action: tc.attempt, TargetRef: tc.target,
						Args: mustArgs(t, map[string]any{"name": "x"}),
					})
				if err != nil {
					t.Fatalf("14a: refusal arrived as a transport error: %v", err)
				}
				if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
					t.Fatalf("14a: a %q grant reached %q. The two namespaces are disjoint "+
						"by construction (D49, §4.9a.8) and a match across them would "+
						"silently double every grant on a dual-path system",
						tc.grant, tc.attempt)
				}

				// **AND IT WAS POLICY THAT REFUSED, NOT SOMETHING BROKEN.** A
				// negative assertion is satisfied by the absence of an answer —
				// D138's review smell, and P1 step 68 caught its own first version
				// this way. Without this arm the native case would pass just as
				// well if the target were unreachable, the driver unregistered or
				// the action unimplemented, none of which say anything about
				// whether one namespace confers the other.
				if got := res.GetKind(); got != fault.KindDenied.String() {
					t.Errorf("14a: kind %q, want %q. `denied` means POLICY evaluated and "+
						"said no, which is the only outcome that says anything about the "+
						"namespaces; anything else means the call did not reach the grant "+
						"check and this arm is measuring whatever broke first: %s",
						got, fault.KindDenied, res.GetReason())
				}
			})
		}
	})

	// --- 14b: AND THE LEAK IS REAL, DEMONSTRATED RATHER THAN ASSUMED -------
	//
	// **THIS ARM IS SUPPOSED TO SUCCEED, WHICH IS WHY IT IS HERE.** §4.9a.8 calls
	// the union "a governance claim carried on faith"; an operator who removes
	// `fullstory.create_event` believing they have withdrawn the capability still
	// has it, through a door Sekizui cannot connect to the one they closed. A
	// step that only proved refusals would leave that on faith too. Making it
	// concrete is what turns "we know this is a risk" into evidence a reviewer
	// can be shown.
	t.Run("granting one path and denying the other leaves the capability reachable", func(t *testing.T) {
		stack := newCoexistenceStack(ctx, t, on("mcp.fullstory.*", "fixture-mcp"))
		stack.up.offer(mcp.LiveTool{Name: "create_event", InputSchema: objectSchema("name")})

		// The NATIVE action is not granted at all — the operator "denied" it.
		res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"),
			&sekizuiv1.Command{
				Action: fullstory.ActionCreateEvent, TargetRef: "fullstory-api",
				Args: mustArgs(t, map[string]any{"name": "x"}),
			})
		if err != nil {
			t.Fatalf("14b: the native refusal arrived as a transport error: %v", err)
		}
		// **`denied`, NOT MERELY NOT-OK — the same hole 14a had.** A driver
		// failure or an unreachable target would satisfy "not reachable" while
		// saying nothing about whether the operator's denial is in force, and the
		// leak below would then be measured against a premise that was never
		// established.
		if got := res.GetKind(); got != fault.KindDenied.String() {
			t.Fatalf("14b: the native path returned %q, want %q. The premise is that "+
				"POLICY denies it; anything else and this is not a leak, it is a "+
				"broken target: %s", got, fault.KindDenied, res.GetReason())
		}

		// AND YET THE SAME CAPABILITY GOES OUT THROUGH THE OTHER DOOR.
		res, err = stack.call(ctx, t, "mcp.fullstory.create_event")
		if err != nil {
			t.Fatalf("14b: %v", err)
		}
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("14b: the MCP path was ALSO refused (%s: %s). That would be a nicer "+
				"world and it is not this one — if Sekizui has gained the ability to "+
				"connect the two paths, §4.9a.8 and this step both need rewriting, "+
				"because the claim they are built on has changed",
				res.GetKind(), res.GetReason())
		}
	})

	// --- 14c: SO THE MITIGATION IS VISIBILITY, AND IT HOLDS ----------------
	//
	// §4.9a.8's own answer: a machine cannot adjudicate equivalence, so what must
	// exist is a listing in which the overlap is APPARENT. One `Describe` shows
	// both doors onto one system, which is what makes union-aware grant review
	// possible rather than theatre.
	t.Run("one Describe shows both doors onto the same system", func(t *testing.T) {
		stack := newCoexistenceStack(ctx, t,
			on("mcp.fullstory.*", "fixture-mcp"),
			on(fullstory.ActionCreateEvent, "fullstory-api"))

		resp, err := stack.catalog.Describe(ctx, assertedIdentity("agent:dev"), "")
		if err != nil {
			t.Fatalf("14c: %v", err)
		}

		var sawNative, sawMCP bool
		for _, c := range resp.GetCapabilities() {
			switch {
			case c.GetAction() == fullstory.ActionCreateEvent:
				sawNative = true
			case c.GetAction() == "mcp.fullstory.create_event":
				sawMCP = true
			}
		}
		if !sawNative || !sawMCP {
			t.Fatalf("14c: Describe showed native=%v mcp=%v, want both. A reviewer "+
				"doing union-aware grant review cannot see an overlap that only one "+
				"listing carries, and §4.9a.8 makes that listing the whole mitigation",
				sawNative, sawMCP)
		}

		// --- NON-VACUITY: the listing follows the grants, not the drivers ---
		//
		// Without this the arm passes against a catalog that advertises every
		// action the binary implements — which would show both doors for a
		// principal granted neither, and would be a far worse bug than the one
		// this is checking for (D195's finding, one layer over).
		only := newCoexistenceStack(ctx, t, on("mcp.fullstory.*", "fixture-mcp"))
		resp, err = only.catalog.Describe(ctx, assertedIdentity("agent:dev"), "")
		if err != nil {
			t.Fatalf("14c: %v", err)
		}
		for _, c := range resp.GetCapabilities() {
			if strings.HasPrefix(c.GetAction(), "fullstory.") {
				t.Errorf("14c: a principal granted only the MCP path was shown the native "+
					"action %q. The catalog is advertising what the binary implements "+
					"rather than what this principal may do (D195)", c.GetAction())
			}
		}
	})
}

// newCoexistenceStack wires one system behind two targets, granting exactly the
// capabilities given.
//
// **THE TARGET IS SPELLED OUT AT EVERY CALL SITE, and the first version inferred
// it from the action prefix — which made 14a vacuous.** Inferring put a
// `fullstory.*` grant on `fullstory-api` while the attempt named `fixture-mcp`,
// so the TARGET mismatched and the action namespaces were never compared at all.
// Sabotaging the glob matcher to `strings.Contains` did not fail the arm, which
// is how it was found. Holding the target constant is the whole point of the
// arm, so it may not be a derived value.
func newCoexistenceStack(ctx context.Context, t *testing.T,
	allow ...config.CapabilitySpec) *mcpStack {

	t.Helper()

	base := bothPaths(t)
	return newMCPStack(ctx, t, func(d *config.Document) {
		base(d)
		d.Grants = []config.GrantSpec{{Principal: "agent:dev", Allow: allow}}
	})
}

// on is a capability, spelled out.
func on(action, target string) config.CapabilitySpec {
	return config.CapabilitySpec{Action: action, TargetRef: target}
}
