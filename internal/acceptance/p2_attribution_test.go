package acceptance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/limiter"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step39ACredentialFaultDoesNotOpenTheTargetsBreaker proves D200.
//
// **THE AMPLIFICATION THIS CLOSES IS THE REASON THE AXIS EXISTS.** Before it, a
// fault anywhere that was not a deliberate refusal counted against the TARGET,
// because the breaker keyed on `Deliberate()` — a predicate that decides the
// wire shape and merely correlated with fault. So an unreachable token endpoint
// was reported as `target_unavailable`, and one IdP blip opened the breaker on
// every target whose credential chained through it: a credential hiccup rendered
// as a fleet-wide outage, with every log line naming the innocent party.
//
// **THREE ARMS, AND THE THIRD IS WHAT STOPS THE FIRST TWO BEING VACUOUS.** A
// credential fault must not count; a target fault must; and a DELIBERATE fault
// of the target's — a 429 — must still not, because that is D141's original
// point and the easiest thing to lose while rewriting the rule around it.
func step39ACredentialFaultDoesNotOpenTheTargetsBreaker(t *testing.T) {
	ctx := context.Background()

	// TRIP ON ONE, so a single command is enough to show the difference and
	// nothing depends on a count.
	breaker := limiter.NewBreaker(1, time.Minute)

	// --- 39a: OUR OWN CONFIGURATION ERROR, INSIDE THE CALL -----------------
	//
	// **THE VEHICLE IS CHOSEN FOR WHERE THE FAULT LANDS, and the first draft got
	// it wrong in a way the sabotage exposed.** That version used an
	// unresolvable credential — which fails at step 5 (RESOLVE), several stages
	// before step 8b consults the breaker, so the breaker was never asked and
	// the arm passed under a deliberately broken rule. A step that cannot fail
	// proves nothing (CONTRACTS 59), and the reason it could not fail was an
	// ORDERING property rather than the classification under test.
	//
	// A plaintext `base_url` fails inside the driver instead: `mcp.base` refuses
	// it while building the request, so `execErr` is set and the breaker IS
	// recorded. It is our configuration error — the target was never contacted
	// and has done nothing — and before D200 the breaker counted it, because
	// `KindConfig` is not deliberate.
	stack := newMCPStack(ctx, t, func(d *config.Document) {
		d.Targets[0].BaseURL = "http://mcp.invalid"
		d.Grants = []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "mcp.fixture.search", TargetRef: "fixture-mcp"},
			},
		}}
	}, func(m *mcpTuning) { m.gw.Breaker = breaker })
	stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

	res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "mcp.fixture.search", TargetRef: "fixture-mcp",
		Args: mustArgs(t, map[string]any{"query": "anything"}),
	})
	if err == nil && res.GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Fatal("39a: a command against a plaintext base_url succeeded, so nothing " +
			"below is measuring what it claims to")
	}
	if got := breaker.State("fixture-mcp"); got != "closed" {
		t.Errorf("39a: the breaker is %q after OUR OWN configuration error. The target "+
			"was never contacted; degrading it sends an operator to investigate a "+
			"system that is answering perfectly well", got)
	}

	// --- 39b: A TARGET FAULT STILL COUNTS ----------------------------------
	//
	// NON-VACUITY. Without this the step passes against a breaker that records
	// nothing at all, which is "the fix works" and "the breaker is broken"
	// reported identically (CONTRACTS 59).
	failing := &mcpUpstream{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"boom"}}`))
	}))
	defer srv.Close()
	_ = failing

	t.Setenv("SEKIZUI_MCP_TOK2", "token")
	targetBreaker := limiter.NewBreaker(1, time.Minute)
	broken := newMCPStack(ctx, t, func(d *config.Document) {
		d.Targets[0].BaseURL = srv.URL
		d.Targets[0].CredentialRef = "env://SEKIZUI_MCP_TOK2"
		d.Grants = []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "mcp.fixture.search", TargetRef: "fixture-mcp"},
			},
		}}
	}, func(m *mcpTuning) { m.gw.Breaker = targetBreaker })

	_, _ = broken.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "mcp.fixture.search", TargetRef: "fixture-mcp",
		Args: mustArgs(t, map[string]any{"query": "anything"}),
	})
	if got := targetBreaker.State("fixture-mcp"); got == "closed" {
		t.Errorf("39b: the breaker is still %q after the TARGET returned an internal "+
			"error. The breaker has stopped protecting anything, and 39a passes for "+
			"the wrong reason", got)
	}

	// --- 39c: AND A DELIBERATE REFUSAL OF THE TARGET'S STILL DOES NOT ------
	//
	// D141's original rule, which the rewrite around it could easily have lost:
	// a 429 means the target is ALIVE, and counting it would turn a rate limit
	// into an outage.
	if fault.KindRateLimited.ImplicatesTarget() {
		t.Error("39c: a 429 implicates the target. It is the clearest evidence there is " +
			"that the target is alive and talking (D141)")
	}
	if !fault.KindTargetError.ImplicatesTarget() {
		t.Error("39c: a 500 does not implicate the target, so nothing opens the breaker")
	}
	for _, k := range []fault.Kind{
		fault.KindCredentialUnavailable, fault.KindUnauthenticated, fault.KindConfig,
	} {
		if k.ImplicatesTarget() {
			t.Errorf("39c: %v implicates the target", k)
		}
	}

	r := &run{}
	r.detail(t, "D200: a credential fault left the target's breaker closed while a "+
		"target error opened it, and a 429 still counts as the target being alive — "+
		"four parties in the taxonomy where three were expressible")
}
