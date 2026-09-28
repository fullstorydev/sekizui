package acceptance

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// PROPERTIES AND COEXISTENCE (D52, D323), P4 steps 11-13, over one fleet: the
// two Fullstory DCs behind their real hostnames, Fullstory's MCP server on the
// eu1 org — linked to fs:eu1 by one `limits.budget` — and kata in three
// residency classes.

// The fleet's MCP tools, one per relation D323 allows.
const (
	mcpGetEvents   = "mcp.fullstory.get_session_events" // mirrors fullstory.session_events
	mcpCreateEvent = "mcp.fullstory.create_event"       // mirrors fullstory.create_event
	mcpAskAbout    = "mcp.fullstory.ask_about_data"     // [opaque]
	mcpListNotes   = "mcp.fullstory.list_notes"         // [none]
)

// fleet is a run over the fleet, with its fixtures.
type fleet struct {
	*run
	dc *dcFixtures
	up *mcpUpstream
}

// newFleet builds the fleet under ceiling, adding grants.
func newFleet(t *testing.T, ceiling []string, grants ...config.GrantSpec) *fleet {
	t.Helper()
	fx := newDCFixtures(t)
	up := &mcpUpstream{live: map[string]bool{}}
	srv := up.serve(t)
	up.offer(
		mcp.LiveTool{Name: "get_session_events", InputSchema: objectSchema("session_id")},
		mcp.LiveTool{Name: "create_event", InputSchema: objectSchema("name")},
		mcp.LiveTool{Name: "ask_about_data", InputSchema: objectSchema("question")},
		mcp.LiveTool{Name: "list_notes", InputSchema: objectSchema("query")},
	)
	t.Setenv("SEKIZUI_FS_NA1", na1Key)
	t.Setenv("SEKIZUI_FS_EU1", eu1Key)
	t.Setenv("SEKIZUI_MCP_TOK", "mcp-token")
	generous := func(budget string) *config.TargetLimits {
		return &config.TargetLimits{RatePerHr: 36000, Burst: 5000, Budget: budget}
	}
	r := newRunWith(t, runOpts{
		residency: ceiling,
		patch: func(d *config.Document) {
			d.Targets = append(d.Targets,
				config.TargetSpec{Ref: "fs:na1", Kind: fullstory.Kind, Tenant: "na1", Residency: "us",
					BaseURL: "https://" + na1Host, CredentialRef: "env://SEKIZUI_FS_NA1", Limits: generous("fs-na1")},
				config.TargetSpec{Ref: "fs:eu1", Kind: fullstory.Kind, Tenant: "eu1", Residency: "eu",
					BaseURL: "https://" + eu1Host, CredentialRef: "env://SEKIZUI_FS_EU1", Limits: generous("fs-eu1")},
				// THE LINK (D323): one budget, because one org's quota.
				config.TargetSpec{Ref: "fs-mcp", Kind: mcp.Kind, Tenant: "eu1", Residency: "eu",
					BaseURL: srv.URL, CredentialRef: "env://SEKIZUI_MCP_TOK", Limits: &config.TargetLimits{Budget: "fs-eu1"}})
			if d.MCPSpecs == nil {
				d.MCPSpecs = map[string]config.MCPSpec{}
			}
			// A READ BRINGS IN ONLY WHAT ITS CLOSED DATA SCHEMA ALLOWS (D279), so
			// each read tool declares a text result of its own type.
			text := func(tool config.MCPToolSpec, outputType string) config.MCPToolSpec {
				tool.Result, tool.OutputType = "text", outputType
				tool.DataSchema = []byte(`{"type":"object","properties":{"text":{"type":"string"}}}`)
				return tool
			}
			d.MCPSpecs["fs-mcp"] = config.MCPSpec{Server: "fullstory", Host: "127.0.0.1", Tools: []config.MCPToolSpec{
				text(config.MCPToolSpec{Name: "get_session_events", Description: "A session's events.",
					InputSchema: objectSchema("session_id"), Native: []string{fullstory.ActionSessionEvents}}, "fleet.events_text.v1"),
				{Name: "create_event", Description: "Record a server-side event.", Mutating: true, Idempotency: "natural",
					InputSchema: objectSchema("name"), Native: []string{fullstory.ActionCreateEvent}},
				text(config.MCPToolSpec{Name: "ask_about_data", Description: "Ask a question of the org's data.",
					InputSchema: objectSchema("question"), Native: []string{config.NativeOpaque}}, "fleet.answer_text.v1"),
				text(config.MCPToolSpec{Name: "list_notes", Description: "The server's own notes.",
					InputSchema: objectSchema("query"), Native: []string{config.NativeNone}}, "fleet.notes_text.v1"),
			}}
			d.Grants = append(d.Grants, grants...)
		},
		fullstoryClient: fx.client,
		mcpClient:       srv.Client(),
	})
	return &fleet{run: r, dc: fx, up: up}
}

// enforce drives one command through the enforcement path as `who`.
func (f *fleet) enforce(t *testing.T, who, action, target string) *sekizuiv1.CommandResult {
	t.Helper()
	args := map[string]any{"name": "x"}
	switch {
	case strings.HasPrefix(action, "kata."):
		args = map[string]any{"project": "PROJ", "title": "fleet"}
	case action == mcpGetEvents:
		args = map[string]any{"session_id": "s"}
	case action == mcpAskAbout:
		args = map[string]any{"question": "q"}
	case action == mcpListNotes:
		args = map[string]any{"query": "q"}
	}
	res, err := f.srv.Enforce(context.Background(), assertedIdentity(who), &sekizuiv1.Command{
		Action: action, TargetRef: target, Args: mustArgs(t, args),
		IdempotencyKey: fmt.Sprintf("fleet-%s-%d", who, time.Now().UnixNano())})
	if err != nil {
		t.Fatalf("%s %s on %s: a transport error, where every deliberate refusal is a result (D135): %v",
			who, action, target, err)
	}
	return res
}

func (f *fleet) mcpCalls() int {
	f.up.mu.Lock()
	defer f.up.mu.Unlock()
	return len(f.up.calls)
}

// --- step 11: the tenancy property, with Fullstory and MCP in the mix ------

// door is one (action, target) pair the property drives.
type door struct{ action, target string }

// propertyDoors is the population: every class, both DCs, the MCP server.
var propertyDoors = []door{ //nolint:gochecknoglobals // immutable population
	{"kata.create_issue", "kata:alpha"}, {"kata.create_issue", "kata:beta"}, {"kata.create_issue", "kata:tokyo"},
	{fullstory.ActionCreateEvent, "fs:eu1"}, {fullstory.ActionCreateEvent, "fs:na1"},
	{mcpCreateEvent, "fs-mcp"}, {mcpAskAbout, "fs-mcp"}, {mcpListNotes, "fs-mcp"},
}

var fleetClass = map[string]string{ //nolint:gochecknoglobals // the fleet's declared classes
	"kata:alpha": "us", "kata:beta": "eu", "kata:tokyo": "jp", "fs:eu1": "eu", "fs:na1": "us", "fs-mcp": "eu",
}

// propertyGrants draws each principal's capabilities from the seed: each door
// granted or not, and each granted one naming its class, a wrong class, or
// none — plus, sometimes, the whole native surface of fs:eu1, the only grant
// that satisfies the opaque tool.
func propertyGrants(rng *rand.Rand, principals []string) []config.GrantSpec {
	var out []config.GrantSpec
	classes := []string{"eu", "us", "jp"}
	for _, p := range principals {
		g := config.GrantSpec{Principal: p}
		for _, d := range propertyDoors {
			if rng.Float64() < 0.5 {
				continue
			}
			// THE CLASS NAMED, NAMED AMONG OTHERS, OR NOT NAMED. A capability
			// naming only a WRONG class never fires, and boot refuses it — so it
			// is not a runtime case and the population does not draw it.
			c := config.CapabilitySpec{Action: d.action, TargetRef: d.target}
			switch rng.Intn(3) {
			case 0:
				c.Where = map[string]any{config.TargetResidencyFacet: []any{fleetClass[d.target]}}
			case 1:
				c.Where = map[string]any{config.TargetResidencyFacet: []any{classes[rng.Intn(3)], fleetClass[d.target]}}
			}
			g.Allow = append(g.Allow, c)
		}
		if rng.Float64() < 0.5 {
			g.Allow = append(g.Allow, config.CapabilitySpec{Action: "fullstory.*", TargetRef: "fs:eu1",
				Where: map[string]any{config.TargetResidencyFacet: []any{"eu"}}})
		}
		if len(g.Allow) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// admits is the property's ORACLE, written from D29, D136 and D323 rather than
// from the engine: the ceiling serves the target's class, a capability names
// the action on the target and covers its class, and an MCP tool's declared
// relation is held on the linked target. Deliberately literal — the grants it
// reads contain one pattern, `fullstory.*`, and it knows only that one.
func admits(grants []config.GrantSpec, ceiling []string, who string, d door) bool {
	served := func(target string) bool {
		for _, c := range ceiling {
			if c == fleetClass[target] {
				return true
			}
		}
		return false
	}
	holds := func(action, target string) bool {
		for _, g := range grants {
			if g.Principal != who {
				continue
			}
			for _, c := range g.Allow {
				covers := c.Action == action || (c.Action == "fullstory.*" && strings.HasPrefix(action, "fullstory."))
				if c.TargetRef != target || !covers {
					continue
				}
				want, named := c.Where[config.TargetResidencyFacet]
				if !named {
					if len(ceiling) == 1 {
						return true
					}
					continue
				}
				for _, class := range want.([]any) {
					if class == fleetClass[target] {
						return true
					}
				}
			}
		}
		return false
	}
	if !served(d.target) || !holds(d.action, d.target) {
		return false
	}
	switch d.action {
	case mcpCreateEvent:
		return holds(fullstory.ActionCreateEvent, "fs:eu1")
	case mcpAskAbout: // opaque: the whole surface, which only the pattern holds
		for _, spec := range fullstory.New().Actions() {
			if !holds(spec.Name, "fs:eu1") {
				return false
			}
		}
	}
	return true
}

// propertySeed is fixed so every run, and every mutation, sees the same
// population; SEKIZUI_PROPERTY_SEED explores another, and a failure prints the
// seed to replay it.
//
// **CHOSEN FOR COVERAGE, AND SAID SO.** The first fixed seed, 20260927, never
// drew fs:na1 granted with its class, so the property was vacuous about that
// door there; ten other seeds covered every door and agreed with the oracle
// on every command. 20260928 is the next that covers all eight both ways.
func propertySeed(t *testing.T) int64 {
	if s := os.Getenv("SEKIZUI_PROPERTY_SEED"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("SEKIZUI_PROPERTY_SEED=%q is not an integer", s)
		}
		return n
	}
	return 20260928
}

// p4Step11 — P1's tenancy property holds with Fullstory in the mix: no command
// reaches a target its principal's grants and the residency ceiling do not
// both admit — and every command they do admit is served.
func p4Step11(t *testing.T) {
	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		t.Skip("the property draws its own grants and ceilings; a running instance has its own")
	}
	seed := propertySeed(t)
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // reproducible generation, not security
	principals := []string{"prop:0", "prop:1", "prop:2", "prop:3", "prop:4", "prop:5"}
	total, refused := 0, 0
	admitted, denied := map[door]int{}, map[door]int{}
	// THREE CEILINGS, so every class is both outside and inside one: a
	// population in which jp is never served proves the ceiling only refusing.
	for _, ceiling := range [][]string{{"eu"}, {"eu", "us"}, {"eu", "jp", "us"}} {
		grants := propertyGrants(rng, principals)
		f := newFleet(t, ceiling, grants...)
		for range 200 {
			who := principals[rng.Intn(len(principals))]
			d := propertyDoors[rng.Intn(len(propertyDoors))]
			want := admits(grants, ceiling, who, d)
			beforeMCP, beforeEU, beforeNA := f.mcpCalls(), f.dc.eu1.writes(), f.dc.na1.writes()
			res := f.enforce(t, who, d.action, d.target)
			reached := f.mcpCalls() > beforeMCP || f.dc.eu1.writes() > beforeEU || f.dc.na1.writes() > beforeNA
			ok := res.GetStatus() == sekizuiv1.Status_STATUS_OK
			total++
			if !ok {
				refused++
				denied[d]++
			} else {
				admitted[d]++
			}
			switch {
			case !want && (ok || reached):
				t.Fatalf("step 11 (seed %d, ceiling %v): %s %s on %s was %v and reached=%v; neither its grants "+
					"and the ceiling nor the declared union admit it", seed, ceiling, who, d.action, d.target,
					res.GetStatus(), reached)
			case want && !ok:
				t.Fatalf("step 11 (seed %d, ceiling %v): %s %s on %s was refused (%s: %s), and its grants, "+
					"the ceiling and the union all admit it", seed, ceiling, who, d.action, d.target,
					res.GetKind(), res.GetReason())
			case want && !strings.HasPrefix(d.action, "kata.") && !reached:
				t.Fatalf("step 11 (seed %d): %s %s on %s was OK and no upstream saw it", seed, who, d.action, d.target)
			}
		}
	}
	// EVERY DOOR SEEN BOTH WAYS, or the property is vacuous about that door: a
	// population in which the opaque tool is never admitted proves nothing
	// about the union letting through what it should.
	//
	// A FAILURE ON THE FIXED SEED, A REPORT ON AN EXPLORED ONE: coverage is a
	// property of the population a seed draws, not of the system, and the
	// fixed seed is what CI and every mutation run.
	report := t.Errorf
	if os.Getenv("SEKIZUI_PROPERTY_SEED") != "" {
		report = t.Logf
	}
	for _, d := range propertyDoors {
		if admitted[d] == 0 || denied[d] == 0 {
			report("step 11 (seed %d): %s on %s was admitted %d and refused %d times; the population must "+
				"see every door both ways", seed, d.action, d.target, admitted[d], denied[d])
		}
	}
	t.Logf("step 11: seed %d — %d commands over three ceilings, %d refused, every outcome as the oracle said", seed, total, refused)
}

// --- step 12: D52's union, by test -----------------------------------------

// p4Step12 — a capability denied on the native driver cannot be obtained
// through the MCP target; Describe reports the doors together.
func p4Step12(t *testing.T) {
	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		p4Step12Live(t)
		return
	}
	mcpOnly := config.GrantSpec{Principal: "agent:union", Allow: []config.CapabilitySpec{
		{Action: "mcp.fullstory.*", TargetRef: "fs-mcp"}}}
	both := config.GrantSpec{Principal: "agent:union-native", Allow: []config.CapabilitySpec{
		{Action: "mcp.fullstory.*", TargetRef: "fs-mcp"},
		{Action: fullstory.ActionSessionEvents, TargetRef: "fs:eu1"}}}
	f := newFleet(t, []string{"eu"}, mcpOnly, both) // the fleet's MCP is the eu1 org's
	f.narrate(t, "a capability denied on the native driver cannot be obtained through the MCP target")
	if f.localOnly(t, "the fleet's MCP server and DCs are fixtures this process serves") {
		return
	}

	// 12a — THE NATIVE READ IS DENIED, SO ITS MIRROR IS: refused by policy, the
	// record naming the native action and door, and the MCP server never asked.
	before := f.mcpCalls()
	res := f.enforce(t, "agent:union", mcpGetEvents, "fs-mcp")
	rec := recordOf(t, f.path, res.GetDecisionId())
	if res.GetKind() != "denied" || rec.GetMatchedRule() != "union:fullstory.session_events@fs:eu1" {
		t.Errorf("step 12a: %s by agent:union (no native read): kind %q, rule %q (%s); want denied by the union",
			mcpGetEvents, res.GetKind(), rec.GetMatchedRule(), res.GetReason())
	}
	if f.mcpCalls() != before {
		t.Errorf("step 12a: the MCP server received the refused call")
	}

	// 12b — THROUGH ANY MCP TOOL: every tool agent:union's wildcard reaches
	// that could carry the data is refused; only the [none] tool is served.
	for _, action := range []string{mcpGetEvents, mcpCreateEvent, mcpAskAbout} {
		if got := f.enforce(t, "agent:union", action, "fs-mcp"); got.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Errorf("step 12b: %s was served to a principal holding none of what it mirrors", action)
		}
	}
	if got := f.enforce(t, "agent:union", mcpListNotes, "fs-mcp"); got.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("step 12b: the [none] tool was refused (%s); non-vacuity needs one tool served", got.GetReason())
	}

	// 12c — NON-VACUITY: granted the native read, the mirror is served.
	if got := f.enforce(t, "agent:union-native", mcpGetEvents, "fs-mcp"); got.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("step 12c: with the native read granted, %s was refused: %s", mcpGetEvents, got.GetReason())
	}

	// 12d — GRANT REVIEW READS ONE ANSWER: Describe pairs each tool with what it
	// mirrors, and lists for each principal only what the union admits.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	describe := func(who string) map[string][]string {
		resp, err := f.as(t, who).Describe(ctx, &sekizuiv1.DescribeRequest{})
		if err != nil {
			t.Fatalf("step 12d: Describe as %s: %v", who, err)
		}
		out := map[string][]string{}
		for _, c := range resp.GetCapabilities() {
			out[c.GetAction()+"@"+c.GetTargetRef()] = c.GetNative()
		}
		return out
	}
	only, native := describe("agent:union"), describe("agent:union-native")
	if _, listed := only[mcpGetEvents+"@fs-mcp"]; listed {
		t.Errorf("step 12d: agent:union was advertised %s, which the union refuses it", mcpGetEvents)
	}
	if got := only[mcpListNotes+"@fs-mcp"]; strings.Join(got, ",") != config.NativeNone {
		t.Errorf("step 12d: agent:union's %s carries native %v; want [none]", mcpListNotes, got)
	}
	if got := native[mcpGetEvents+"@fs-mcp"]; strings.Join(got, ",") != fullstory.ActionSessionEvents {
		t.Errorf("step 12d: agent:union-native's %s carries native %v; want it paired with %s",
			mcpGetEvents, got, fullstory.ActionSessionEvents)
	}
	if _, listed := native[fullstory.ActionSessionEvents+"@fs:eu1"]; !listed {
		t.Errorf("step 12d: agent:union-native's native door is not listed beside its mirror")
	}
	// 12e — THE LIVE DEMO CANNOT ROT (D315's rule for demo.d, applied to
	// live.d): rendered as `make run-live` renders it, it loads and validates
	// on every run — the union's link, relations and ceiling included.
	rendered := t.TempDir()
	files, err := filepath.Glob(filepath.Join("live.d", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("step 12e: no live.d files: %v", err)
	}
	for _, file := range files {
		raw, rerr := os.ReadFile(file)
		if rerr != nil {
			t.Fatal(rerr)
		}
		out := strings.ReplaceAll(string(raw), "@SEKIZUI_ROOT@", mustRoot(t))
		if werr := os.WriteFile(filepath.Join(rendered, filepath.Base(file)), []byte(out), 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	live, err := config.NewFileSource(rendered).Load(context.Background())
	if err != nil {
		t.Fatalf("step 12e: the live demo deployment does not load: %v", err)
	}
	if err := live.Validate(); err != nil {
		t.Fatalf("step 12e: the live demo deployment does not validate: %v", err)
	}
	if len(live.NativeRelations()["fullstory-mcp"]) == 0 {
		t.Errorf("step 12e: the live demo's MCP target is linked to no native target; the union arm would prove nothing")
	}

	keys := make([]string, 0, len(native))
	for k := range native {
		if strings.Contains(k, "fs") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	f.detail(t, "agent:union (MCP only) was refused %s by the union and never reached the server; the [none] "+
		"tool served. agent:union-native (both doors) was served, and Describe listed %v, each MCP tool paired "+
		"with what it mirrors", mcpGetEvents, keys)
}

// p4Step12Live — the union on the LIVE demo instance, against Fullstory's real
// MCP (D324): `make run-live` in one terminal, `make demo-live` in another.
func p4Step12Live(t *testing.T) {
	if os.Getenv("SEKIZUI_DEMO_LIVE") == "" {
		t.Skip("the union needs Fullstory's MCP beside its native target, on the org dev/fullstory-live.yaml names (NA1, us) — its own " +
			"instance, since it reaches the real MCP: `make run-live`, then `make demo-live` (D324)")
	}
	r := newRun(t)
	r.narrate(t, "a capability denied on the native driver cannot be obtained through Fullstory's real MCP")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const tool = "mcp.fullstory.discover_org_context"
	call := func(who string) *sekizuiv1.CommandResult {
		resp, err := r.as(t, who).Execute(ctx, &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
			Action: tool, TargetRef: "fullstory-mcp", Args: mustArgs(t, map[string]any{"queries": []any{"checkout"}})}})
		if err != nil {
			t.Fatalf("step 12 live: %s as %s: a transport error (D135): %v", tool, who, err)
		}
		return resp.GetResult()
	}

	// 12a LIVE — REFUSED BY THE UNION, BEFORE ANY CALL OUT: every tool is
	// [opaque], and agent:union holds no native door.
	refused := call("agent:union")
	if refused.GetKind() != "denied" || !strings.Contains(refused.GetReason(), "D323") {
		t.Errorf("step 12 live: agent:union's %s: kind %q (%s); want denied by the union", tool, refused.GetKind(), refused.GetReason())
	}
	// 12c LIVE — SERVED THROUGH THE REAL MCP to the principal holding both doors.
	served := call("agent:union-native")
	if served.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 12 live: agent:union-native's %s: %v %s: %s", tool, served.GetStatus(), served.GetKind(), served.GetReason())
	}
	// 12d LIVE — DESCRIBE CARRIES THE RELATION.
	desc, err := r.as(t, "agent:union-native").Describe(ctx, &sekizuiv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("step 12 live: Describe: %v", err)
	}
	var relation []string
	for _, c := range desc.GetCapabilities() {
		if c.GetAction() == tool && c.GetTargetRef() == "fullstory-mcp" {
			relation = c.GetNative()
		}
	}
	if strings.Join(relation, ",") != config.NativeOpaque {
		t.Errorf("step 12 live: Describe shows %s with native %v; want [opaque]", tool, relation)
	}
	r.detail(t, "on the maintainers' test org through Fullstory's real MCP: agent:union was refused %s by the union (%s) before "+
		"any call out; agent:union-native, holding both doors, was served it; Describe shows it %v",
		tool, refused.GetKind(), relation)
}

// --- step 13: one upstream limiter key per org ------------------------------

// p4Step13 — the native driver and the MCP target share one upstream limiter
// key per org: a 429 through one drains the bucket the other draws on, and the
// other org's does not move.
func p4Step13(t *testing.T) {
	grant := config.GrantSpec{Principal: "agent:quota", Allow: []config.CapabilitySpec{
		{Action: fullstory.ActionCreateEvent, TargetRef: "fs:eu1"},
		{Action: fullstory.ActionCreateEvent, TargetRef: "fs:na1"},
		{Action: mcpCreateEvent, TargetRef: "fs-mcp"}}}
	f := newFleet(t, []string{"eu", "us"}, withClasses(grant))
	f.narrate(t, "the native driver and the MCP target share one upstream limiter key per org")
	if f.localOnly(t, "the fleet's upstreams are fixtures this process serves") {
		return
	}

	// NON-VACUITY FIRST: both doors on eu1 serve before the upstream objects.
	if got := f.enforce(t, "agent:quota", mcpCreateEvent, "fs-mcp"); got.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 13: the MCP door was refused before any 429: %s", got.GetReason())
	}

	// 13a — THE UPSTREAM SAYS NO THROUGH THE NATIVE DOOR.
	f.dc.eu1.setThrottle(true)
	first := f.enforce(t, "agent:quota", fullstory.ActionCreateEvent, "fs:eu1")
	if first.GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 13a: eu1 answered 429 and the native call was OK")
	}
	f.dc.eu1.setThrottle(false)

	// 13b — THE OTHER DOOR SEES THE DRAINED BUCKET: refused by the limiter, the
	// MCP server never asked, though the fixture itself would now accept.
	before := f.mcpCalls()
	second := f.enforce(t, "agent:quota", mcpCreateEvent, "fs-mcp")
	if second.GetStatus() != sekizuiv1.Status_STATUS_RATE_LIMITED || f.mcpCalls() != before {
		t.Errorf("step 13b: after eu1's 429 through the native door, the MCP door was %v (%s: %s) and the "+
			"server saw %d new call(s); want rate_limited before any call — one org, one bucket",
			second.GetStatus(), second.GetKind(), second.GetReason(), f.mcpCalls()-before)
	}

	// 13c — PER ORG: na1's budget is its own.
	if got := f.enforce(t, "agent:quota", fullstory.ActionCreateEvent, "fs:na1"); got.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("step 13c: na1 was refused after eu1's 429 (%s: %s); another org's quota must not move",
			got.GetKind(), got.GetReason())
	}
	f.detail(t, "eu1 answered 429 to the native door (%s); the MCP door on the same org was then %s before "+
		"reaching its server; na1 still served", first.GetKind(), second.GetKind())
}

// withClasses names each capability's target class, as a multi-class
// deployment requires (D136).
func withClasses(g config.GrantSpec) config.GrantSpec {
	for i := range g.Allow {
		g.Allow[i].Where = map[string]any{config.TargetResidencyFacet: []any{fleetClass[g.Allow[i].TargetRef]}}
	}
	return g
}
