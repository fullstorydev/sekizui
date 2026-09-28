package acceptance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step38AMalformedCredentialIsALocalRefusalNotAnOutage proves D199.
//
// **THE DEFECT IS A DIAGNOSIS, NOT A BREACH, AND THAT IS WHY IT NEEDED A STEP.**
// A credential file written with `echo` ends in a newline. Go's `net/http`
// refuses to send a request whose header value contains one — verified against
// the standard library rather than assumed, which also settles the injection
// question: CRLF never reaches the wire, so this is not an attack surface. What
// it IS, before this decision, is a one-character local mistake that arrives as
// `target_unavailable`: *"the server could not be reached"*. That kind is
// RETRYABLE, so the retry loop runs it again, and each failure counts against
// the target's circuit breaker.
//
// **SO A HEALTHY VENDOR GETS AN OPEN BREAKER AND EVERY SIGNAL POINTS AT THEM.**
// The operator reads an outage, checks the vendor's status page, finds nothing,
// and the truth is in a file on our side. D48 separates an availability
// condition from a governance one for the same reason; this is the third
// party — a CONFIGURATION condition — being reported as the first.
//
// **THE ARM WITH TEETH IS THE BREAKER, and it is the reason a package test in
// `pkg/connector` is not enough.** That test proves the helper refuses. Only a
// command through the real stack proves the refusal is WIRED, arrives with a
// kind the enforcement path treats as deliberate, and therefore does no damage
// to a target that has done nothing wrong — the habit being "grep for a CALLER,
// not an implementation".
func step38AMalformedCredentialIsALocalRefusalNotAnOutage(t *testing.T) {
	ctx := context.Background()

	stack := newMCPStack(ctx, t, func(d *config.Document) {
		d.Grants = []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "mcp.fixture.search", TargetRef: "fixture-mcp"},
			},
		}}
	})
	stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

	// A CREDENTIAL WRITTEN THE WAY A HUMAN WRITES ONE. `echo` appends the
	// newline; `printf %s` does not, and knowing that is not a reasonable
	// prerequisite for deploying a policy enforcement point.
	//
	// SET AFTER THE STACK IS BUILT, and the first draft set it before — where
	// the rig's own `t.Setenv` overwrote it and the step passed against a clean
	// credential, reporting that a malformed one had succeeded. Harmless here
	// because the arm was written to fail; worth the comment because it depends
	// on a real property: the resolver reads the environment at RESOLVE time,
	// which is the first command, not at wiring time.
	t.Setenv("SEKIZUI_MCP_TOK", "mcp-token\n")

	res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "mcp.fixture.search", TargetRef: "fixture-mcp",
		Args: mustArgs(t, map[string]any{"query": "anything"}),
	})
	if err != nil {
		t.Fatalf("38: the refusal arrived as a transport error rather than a result: %v", err)
	}

	// --- 38a: IT IS REFUSED, AND THE KIND IS BREAKER-SAFE ------------------
	//
	// **THE OBVIOUS KIND WAS THE WRONG ONE AND THIS ARM IS WHAT FOUND IT.** The
	// first version asserted `config`, which reads correctly — it IS a
	// configuration fault — and would have been worse than the bug: the breaker
	// records `err == nil || Kind.Deliberate()` as a success, and `config` is
	// NOT deliberate, so refusing with it opens the breaker on the healthy
	// target this decision exists to protect. Reasoning did not catch that; the
	// arm did, by failing on `Deliberate()`.
	if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Fatal("38a: a credential that cannot be sent as a header produced a successful " +
			"command")
	}
	if got := res.GetKind(); got != fault.KindUnauthenticated.String() {
		t.Errorf("38a: kind is %q, want %q", got, fault.KindUnauthenticated)
	}

	// --- 38b: THE MESSAGE NAMES THE FIX, NOT JUST THE FAULT ----------------
	//
	// D97's lesson: an operator learns what to SAY instead, rather than only
	// that what they said was wrong.
	reason := res.GetReason()
	for _, want := range []string{"newline", "printf", "fixture-mcp"} {
		if !strings.Contains(reason, want) {
			t.Errorf("38b: the refusal does not mention %q: %q", want, reason)
		}
	}

	// --- 38c: AND THE MATERIAL IS NOWHERE IN THE RECORD --------------------
	//
	// Checked against the actual bytes rather than named fields (P1 step 19's
	// shape), because a field added later with a plausible name is the only way
	// this could be lost. D119: material itself is never a field.
	if strings.Contains(reason, "mcp-token") {
		t.Errorf("38c: the refusal contains the credential: %q", reason)
	}

	// --- 38d: THE TARGET IS NOT BLAMED — no request, no breaker damage -----
	//
	// **THE POINT OF THE WHOLE DECISION.** A configuration fault must leave the
	// vendor's reputation with this instance untouched: nothing was sent, so
	// nothing can have failed at the far side.
	if called := stack.up.called(); len(called) != 0 {
		t.Errorf("38d: the server received %v. A credential that cannot be placed must "+
			"be refused before the call, not discovered by making it", called)
	}
	// DELIBERATE, so the breaker records it as a success — the target was never
	// contacted and has done nothing wrong. NOT RETRYABLE, so the retry loop
	// does not run a request that cannot succeed until a human edits a file.
	if !fault.KindUnauthenticated.Deliberate() {
		t.Error("38d: the refusal is not deliberate, so the breaker counts it against a " +
			"target that was never contacted (D125, D141)")
	}
	if fault.KindUnauthenticated.Retryable() {
		t.Error("38d: the refusal is retryable")
	}
	// **THE CONTRAST THE WHOLE STEP RESTS ON**, asserted rather than assumed:
	// the kind this replaces is retryable AND not deliberate, which is what
	// opened the breaker.
	if !fault.KindTargetUnavailable.Retryable() || fault.KindTargetUnavailable.Deliberate() {
		t.Error("38d: target_unavailable is no longer retryable-and-not-deliberate, so " +
			"the contrast this step rests on does not exist and the arms above prove " +
			"nothing")
	}

	r := &run{}
	r.detail(t, "D199: a credential ending in a newline is refused as %s — deliberate, "+
		"not retryable, no request sent and no breaker damage — with the fix named and "+
		"the material absent; unrefused it reaches net/http and comes back as %s, which "+
		"retries and opens the breaker on a healthy target",
		fault.KindUnauthenticated, fault.KindTargetUnavailable)
}

// _ keeps the connector import honest if the arms above ever stop using it.
var _ = connector.SetAuthorization
