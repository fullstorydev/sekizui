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

// statefulSpec turns the shared MCP fixture's target into a 2025-06-18 one.
//
// ONE EDIT, so every arm below differs from the drift steps in exactly the
// declared revision and nothing else. An arm that also changed the tool list or
// the grants would be comparing two configurations rather than two protocols.
func statefulSpec(d *config.Document) {
	spec := d.MCPSpecs["fixture-mcp"]
	spec.Revision = statefulRevision
	d.MCPSpecs["fixture-mcp"] = spec
	d.Grants = []config.GrantSpec{{
		Principal: "agent:dev",
		Allow: []config.CapabilitySpec{
			{Action: "mcp.fixture.search", TargetRef: "fixture-mcp"},
		},
	}}
}

// statefulRevision is the one stateful revision this build implements.
const statefulRevision = "2025-06-18"

// sessionHeaderName is the header the arms below assert a refusal names.
//
// WRITTEN OUT HERE rather than reaching for the driver's unexported constant:
// this is the wire name an operator greps for, and a test that read it from the
// code under test would pass if both were renamed together.
const sessionHeaderName = "Mcp-Session-Id"

// assertSessionRefusal checks a refusal arrived as a RESULT with the right kind,
// and returns the reason so an arm can assert on what it says.
//
// **A RESULT RATHER THAN AN ERROR IS ITSELF THE ASSERTION (D135).** Every kind
// this step produces is deliberate, so a refusal that arrived as a transport
// error would mean the caller got a coarse gRPC code with no `kind` to branch on
// and no decision id naming the row it caused — which is the shape D201 spent an
// entry fixing one layer over.
func assertSessionRefusal(t *testing.T, arm string, res *sekizuiv1.CommandResult,
	err error, want fault.Kind) string {

	t.Helper()
	if err != nil {
		t.Fatalf("%s: the refusal arrived as a transport error rather than a result "+
			"(D135), so it carries no kind and no decision id: %v", arm, err)
	}
	if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Fatalf("%s: the call succeeded, so nothing below is being tested", arm)
	}
	if got := res.GetKind(); got != want.String() {
		t.Errorf("%s: kind %q, want %q", arm, got, want)
	}
	return res.GetReason()
}

// step36AStatefulMCPRevisionIsSpokenInFullOrRefused is criterion 16 (D198,
// D213).
//
// **D192a REFUSED THE STATEFUL REVISIONS AND THE REAL SERVER IS ON ONE.** That
// refusal was right while it cost nothing: no server anybody needed spoke one,
// so "an incompatibility an operator must act on" named an action somebody could
// actually take. Fullstory's MCP server speaks 2025-06-18, so the choice became
// *speak it properly or do not reach the vendor at all*, and the maintainer ruled for
// speaking it.
//
// **THE FAILURE THAT MATTERS IS A PARTIAL ONE, WHICH IS WHY THE WHOLE LIFECYCLE
// IS DRIVEN RATHER THAN SAMPLED.** Half-supporting a session is precisely the
// shape §4.7.10 keeps naming: the operator watches the guarantee appear to work.
// A driver that sent `initialize` and dropped the session id would pass a test
// that only checked the handshake happened; one that carried the session and
// never terminated it would pass a test that only checked calls succeed; one
// that proceeded sessionless against a server that minted nothing would pass
// both. So the arms are: the handshake happens ONCE per pool entry, the session
// is on every subsequent request, 2026-07-28's request metadata is GONE, a
// server that mints no session is REFUSED, a server that answers a different
// revision is REFUSED, the session is TERMINATED on close, and an EXPIRED
// session re-establishes through D204's loop rather than through a second code
// path.
func step36AStatefulMCPRevisionIsSpokenInFullOrRefused(t *testing.T) {
	ctx := context.Background()

	// --- 36a: THE HANDSHAKE HAPPENS, ONCE, AND THE SESSION IS CARRIED -------
	//
	// **ONCE PER POOL ENTRY IS THE ASSERTION, NOT ONCE PER RUN.** A driver that
	// re-initialized per command would work — every call would succeed and every
	// other arm here would pass — while opening and abandoning a server-side
	// session on every request. That is a leak the vendor sees and we do not,
	// and the only thing that distinguishes it is the count.
	t.Run("the session is established once and carried on every request", func(t *testing.T) {
		stack := newMCPStack(ctx, t, statefulSpec)
		stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

		for i := 0; i < 3; i++ {
			if _, err := stack.call(ctx, t, "mcp.fixture.search"); err != nil {
				t.Fatalf("36a: call %d: %v", i+1, err)
			}
		}

		minted, initialized, _, carried := stack.up.stats()
		if minted != 1 {
			t.Errorf("36a: the server minted %d sessions for 3 calls, want 1. A "+
				"handshake per command leaves an abandoned session at the vendor for "+
				"every request, which looks like success from here", minted)
		}
		if initialized != 1 {
			t.Errorf("36a: `notifications/initialized` arrived %d times, want 1. A "+
				"server is entitled to answer nothing but pings until it receives it, "+
				"so skipping it produces a target that appears configured and serves "+
				"nothing", initialized)
		}
		if len(carried) == 0 {
			t.Fatal("36a: no request reached the server after the handshake")
		}
		for i, sid := range carried {
			if sid == "" {
				t.Errorf("36a: request %d carried no %s. The specification makes it a "+
					"client MUST once the server has assigned one, and a server that "+
					"requires it answers 400 — so this is a target that works until the "+
					"vendor tightens", i, "Mcp-Session-Id")
			}
		}
	})

	// --- 36b: A SERVER THAT MINTS NO SESSION IS REFUSED --------------------
	//
	// **THIS IS SEKIZUI BEING STRICTER THAN THE PROTOCOL, DELIBERATELY.** The
	// specification says a server "MAY assign a session ID at initialization
	// time", so the fixture here is CONFORMANT and is refused anyway. The reason
	// is that `Mcp-Session-Id` is a RESPONSE HEADER: an intermediary that drops
	// one silently converts a stateful deployment into a sessionless one, every
	// call still succeeds, and nothing anywhere records that the shape changed.
	// That is the same downgrade D193 refuses for revision negotiation, arriving
	// through a door D193 did not think to close.
	t.Run("a server that mints no session on a stateful revision is refused", func(t *testing.T) {
		stack := newMCPStack(ctx, t, statefulSpec)
		stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})
		stack.up.withholdSession = true

		res, err := stack.call(ctx, t, "mcp.fixture.search")
		reason := assertSessionRefusal(t, "36b", res, err, fault.KindSpecDrift)

		// **THE MESSAGE IS PINNED, NOT JUST THE KIND, AND SABOTAGE IS WHY.**
		// Disabling the absence check above did NOT fail this arm in its first
		// version: `visibleASCII("")` is false, so the NEXT check refused with
		// the same kind and the arm passed against the wrong refusal — while
		// telling an operator the server "minted a session id containing
		// characters the specification forbids" about a server that minted
		// nothing. Two refusals sharing a kind is fine; an arm that cannot tell
		// them apart is what makes a reordering invisible, and the message is
		// the only thing that distinguishes them.
		if !strings.Contains(reason, sessionHeaderName) {
			t.Errorf("36b: the refusal does not name %s, so an operator cannot tell a "+
				"server that minted NO session from one that minted a malformed "+
				"id — and those have different causes and different fixes: %q",
				sessionHeaderName, reason)
		}
		if !strings.Contains(reason, "sessionless") {
			t.Errorf("36b: the refusal does not say that continuing sessionless is "+
				"what is being refused. That is the whole reason this is stricter "+
				"than the specification, and an operator who cannot see the reason "+
				"reads it as a bug in us: %q", reason)
		}

		// AND IT DID NOT PROCEED SESSIONLESS, which is the half a kind check
		// cannot see: a driver that refused AND called would fail nothing above.
		if calls := stack.up.called(); len(calls) != 0 {
			t.Errorf("36b: the tool was called %v despite the refusal. Refusing after "+
				"the side effect is not refusing", calls)
		}
	})

	// --- 36g: AND A MALFORMED SESSION ID IS THE OTHER REFUSAL --------------
	//
	// **THE NON-VACUITY HALF OF 36b, and it exists because sabotaging 36b
	// produced this refusal instead.** The two share a kind, so pinning 36b's
	// message only helps if something also proves THIS message is reachable and
	// says its own thing — otherwise the pin could be satisfied by deleting the
	// second check entirely.
	//
	// **THE FIXTURE MINTS A TAB, WHICH IS THE INTERESTING CHARACTER RATHER THAN
	// THE OBVIOUS ONE, and running this is what showed why.** The tempting
	// justification for this check is that Go refuses to send a malformed header
	// — true of a NEWLINE, and false of a tab, which is legal in an HTTP field
	// value and transmits fine. So an implementation that only refused what it
	// could not send would pass a tab straight through, and the arm would pass
	// with it. Sabotaging the check confirmed exactly that: with the range check
	// removed, the call SUCCEEDS. What is being enforced is the specification's
	// range, not Go's tolerance.
	t.Run("a session id the specification forbids is refused before it is sent", func(t *testing.T) {
		stack := newMCPStack(ctx, t, statefulSpec)
		stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})
		stack.up.mintMalformedSession = true

		res, err := stack.call(ctx, t, "mcp.fixture.search")
		reason := assertSessionRefusal(t, "36g", res, err, fault.KindSpecDrift)

		if !strings.Contains(reason, "visible ASCII") {
			t.Errorf("36g: the refusal does not say what is wrong with the id, so it "+
				"is indistinguishable from the missing-session refusal above: %q", reason)
		}
		if calls := stack.up.called(); len(calls) != 0 {
			t.Errorf("36g: the tool was called %v with an unsendable session id. "+
				"Refused at the request would have read as an unreachable target and "+
				"opened the breaker on a healthy vendor (D199)", calls)
		}
	})

	// --- 36c: NOR IS A DIFFERENT REVISION NEGOTIATED -----------------------
	//
	// The specification's own flow has a server that does not support the
	// requested version "respond with another protocol version it supports", and
	// a client that does not support the answer "SHOULD disconnect". Sekizui
	// supports no answer but the declared one — not because it could not, but
	// because accepting one hands the far side the choice of how it is talked
	// to (D193).
	t.Run("a server answering a different revision is refused, not negotiated with", func(t *testing.T) {
		stack := newMCPStack(ctx, t, statefulSpec)
		stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})
		stack.up.answerRevision = "2025-03-26"

		res, err := stack.call(ctx, t, "mcp.fixture.search")
		reason := assertSessionRefusal(t, "36c", res, err, fault.KindSpecDrift)

		if !strings.Contains(reason, "2025-03-26") {
			t.Errorf("36c: the refusal does not name the revision the server offered, "+
				"so an operator cannot tell an upgraded server from a misconfigured "+
				"target: %q", reason)
		}
	})

	// --- 36d: THE SESSION IS TERMINATED ON CLOSE ---------------------------
	//
	// **THIS IS THE HALF THAT MAKES BREAK-GLASS MEAN ANYTHING HERE.** Revoking a
	// credential evicts the pooled client; without the DELETE the server still
	// holds an authorised session, and "the credential is withdrawn" would be
	// true of our side only. `pool.finalise` closes the client BEFORE wiping the
	// credential and its comment has said why since P0 — "an MCP session close
	// is itself an authenticated call" — which stopped being hypothetical here.
	t.Run("revoking the credential terminates the session at the server", func(t *testing.T) {
		stack := newMCPStack(ctx, t, statefulSpec)
		stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

		if _, err := stack.call(ctx, t, "mcp.fixture.search"); err != nil {
			t.Fatalf("36d: establishing the session: %v", err)
		}
		if _, _, deleted, _ := stack.up.stats(); len(deleted) != 0 {
			t.Fatalf("36d: the session was terminated before anything asked for it: %v", deleted)
		}

		if _, err := stack.pool.Revoke(ctx, "fixture-mcp", "step36"); err != nil {
			t.Fatalf("36d: revoking: %v", err)
		}

		_, _, deleted, _ := stack.up.stats()
		if len(deleted) != 1 {
			t.Fatalf("36d: the server saw %d session terminations after a revocation, "+
				"want 1. The credential is withdrawn on our side and the server still "+
				"holds an authorised session", len(deleted))
		}
		if deleted[0] == "" {
			t.Error("36d: the DELETE carried no session id, so the server cannot know " +
				"which session to drop and the termination is a no-op that reads as success")
		}
	})

	// --- 36e: AN EXPIRED SESSION RE-ESTABLISHES THROUGH THE ONE PATH -------
	//
	// **THE SPECIFICATION MAKES THIS A CLIENT MUST** — "when a client receives
	// HTTP 404 in response to a request containing an Mcp-Session-Id, it MUST
	// start a new session by sending a new InitializeRequest" — and the
	// interesting question is not whether we obey it but WHERE.
	//
	// **THE CHEAP ANSWER WOULD HAVE BEEN A SECOND ENFORCEMENT PATH, AND D155 IS
	// WHAT THAT COSTS.** Re-initializing inside the driver and retrying there
	// would be the smallest diff: the caller sees a success and nothing looks
	// wrong. But the retried call would never re-cross policy, the runtime
	// suspension, the withdrawal check, the limiter or the breaker — which is
	// exactly how `Query` grew into a second, weaker copy of `Enforce` one
	// omission at a time. So the marker travels out to D204's loop, the whole
	// path is traversed again, and the call that lands is authorised at the
	// moment it lands.
	t.Run("an expired session is re-established by re-traversing the whole path", func(t *testing.T) {
		stack := newMCPStack(ctx, t, statefulSpec)
		stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

		if _, err := stack.call(ctx, t, "mcp.fixture.search"); err != nil {
			t.Fatalf("36e: establishing the first session: %v", err)
		}

		// THE SERVER FORGETS. `forgetSessions` clears on the next handshake, so
		// the re-established session works — which is what makes this an expiry
		// rather than an outage.
		stack.up.expireOnce()

		res, err := stack.call(ctx, t, "mcp.fixture.search")
		if err != nil {
			t.Fatalf("36e: the call after the expiry failed rather than "+
				"re-establishing: %v", err)
		}
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("36e: status %v, want OK. The MUST was not met: an expired "+
				"session left the target unusable until something else intervened",
				res.GetStatus())
		}

		minted, initialized, _, _ := stack.up.stats()
		if minted != 2 {
			t.Errorf("36e: the server minted %d sessions, want 2 — one before the "+
				"expiry and one after. Anything else means the second call did not "+
				"actually re-handshake", minted)
		}
		if initialized != 2 {
			t.Errorf("36e: `notifications/initialized` arrived %d times, want 2. The "+
				"re-established session skipped the last step of the handshake, so it "+
				"is a session the server need not fully serve", initialized)
		}

		// --- AND THE CREDENTIAL WAS NOT TOUCHED, WHICH IS THE POINT OF THE
		// TYPED MARKER (D213) ------------------------------------------------
		//
		// A bool marker would have run the CREDENTIAL remedy: a forced mint
		// against the secret manager, plus a `credential_churn` tick that an
		// anzen rule quarantines on. The target's credential was never in
		// question, so both would be wrong — and the churn one is the dangerous
		// half, because it turns a routine server-side expiry into a governance
		// event.
		if got := stack.scrape(t); strings.Contains(got, "credential_churn_total") {
			t.Errorf("36e: the scrape carries credential_churn_total after a SESSION "+
				"expiry. Re-establishing a session is one extra round trip to a server "+
				"we were already talking to; counting it as credential churn makes a "+
				"rule watching that signal quarantine targets for behaving "+
				"normally:\n%s", got)
		}
	})

	// --- 36f: A STATEFUL TARGET WITH NO POOL IS REFUSED --------------------
	//
	// **THE SESSION LIVES IN THE POOL — §4.7.4 class 3, which `pool.Closer`'s
	// own comment has said since P0.** The unpooled driver path exists so the
	// driver is testable without one; a session has nowhere to live on it, so a
	// call would open one per command and abandon each. Refusing is what stops
	// that being a silent leak, and `KindConfig` is right because it is OUR
	// wiring rather than the target's fault (D200).
	t.Run("a stateful target on an unpooled driver is refused as a config fault", func(t *testing.T) {
		rig := newMCPRig(ctx, t, statefulSpec)
		// NO `WithPool`, which is the whole condition.
		driver := mcp.New(rig.doc.MCPSpecs, mcp.WithHTTPClient(rig.srv.Client()))

		// A REAL TENANT CONTEXT, so this arm cannot pass on §6 mechanism 3's
		// refusal instead of the one it is about — which is how its first
		// version failed, reading `kind internal, want config`.
		_, err := driver.Execute(connector.WithTenant(ctx, "acme"), rig.target,
			"mcp.fixture.search", map[string]any{"query": "x"},
			connector.Idempotency{Class: connector.IdempotencyNatural})
		if err == nil {
			t.Fatal("36f: an unpooled stateful target executed, so a session was " +
				"opened and abandoned with nothing to close it")
		}
		if got := fault.KindOf(err); got != fault.KindConfig {
			t.Errorf("36f: kind %v, want %v. Attributed to the target this would count "+
				"against its breaker for a mistake in our own wiring (D200)",
				got, fault.KindConfig)
		}
	})
}
