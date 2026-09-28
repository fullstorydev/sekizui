// The stateful MCP revision: `initialize`, the session, and its termination
// (D198, D213).
//
// **THIS FILE EXISTS BECAUSE A REAL VENDOR SERVES A REVISION D192a REFUSED.**
// That decision framed the choice as "an incompatibility an operator must act
// on, not worked around silently", which was the right call while the refusal
// cost nothing — no server anybody needed spoke a stateful revision. Fullstory's
// does. So the choice became *speak 2025-06-18 properly, or do not reach the
// vendor at all*, and the maintainer ruled for speaking it.
//
// **WHAT DID NOT CHANGE IS THE PART WORTH GUARDING.** The revision is still
// DECLARED in a reviewed commit and never negotiated (D193): two implemented
// revisions is not a negotiation, because which one a target speaks is fixed
// before any request goes out and the far side gets no say. What D213 adds is a
// second declarable answer, not a fallback.
//
// **THE SESSION IS §4.7.4 CLASS 3 STATE AND THEREFORE LIVES IN THE POOL**, which
// `pool.Closer`'s own comment has said since P0 — "an MCP session leaves
// server-side state and possibly a live authorised session". Putting it in the
// driver instead would put per-tenant state on a value shared by every tenant,
// and would leave revocation unable to reach it: the pool is what makes
// break-glass tear down a live authorised session rather than merely stop
// issuing new ones.
//
// **THE P7 COST IS STATED RATHER THAN HIDDEN.** A session is per-process, so a
// second replica does not hold it — the same limit CONTRACTS 41 already records
// for break-glass, arrived at from the other direction. It is bounded: a replica
// that holds no session establishes one on its first call, so the failure is a
// duplicated handshake rather than a wrong answer.
//
// DESIGN.md references: §4.7.4, §4.9a.4, §4.9a.7, D4, D190, D192a, D193, D198,
// D204, D213.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// revisionFor is the revision a target's vetted spec declares.
//
// **FROM THE SPEC, NOT FROM THE TARGET AND NOT FROM THE WIRE.** The spec is the
// artefact a human reviewed (D46), and the revision sits in it beside the tool
// list for the same reason the tool list is there: both are claims about what
// this server is, and both must be reviewable in one place at one commit.
//
// An absent declaration means the sessionless default, which is the safe shape
// — D193's rule that the weaker shape is the deliberate act.
func (d *Driver) revisionFor(t connector.Target) string {
	if spec, ok := d.specs[t.Ref()]; ok && spec.Revision != "" {
		return spec.Revision
	}
	return ProtocolVersion
}

// stateful reports whether a target's revision has a protocol-level session.
func (d *Driver) stateful(t connector.Target) bool {
	return !config.MCPRevisionStateless(d.revisionFor(t))
}

// session is the pooled client for a stateful revision.
//
// **IT HOLDS AN ID AND A WAY TO GIVE IT BACK, AND NOTHING ELSE.** Specifically
// it does NOT hold credential material: the token is a per-request header placed
// by the broker (D199), so even on the revision that has connection state the
// credential stays §4.7.4 class 1. That keeps rotation cheap — a rotated
// credential changes the PoolKey and builds a new session, which is correct, and
// it is the only reason a rotation costs a handshake rather than a leak.
type session struct {
	// id is the server's `Mcp-Session-Id`, carried on every subsequent request.
	id string

	// revision is what was declared when this session was established. Held so
	// Close can name it in a log line without re-reading the spec, and so a
	// session cannot outlive a config change to its own revision unnoticed.
	revision string

	// endpoint is the resolved base URL, captured at build time.
	//
	// CAPTURED RATHER THAN RE-DERIVED, because `Close` has no Target to derive
	// it from in the ordinary case and the address a session was opened against
	// is the only address that can close it.
	endpoint string

	// target is retained ONLY so the DELETE can be authenticated. See Close.
	target connector.Target

	http *http.Client

	// terminated guards Close against the pool calling it twice. The pool's
	// `once` already does, but `Closer` is a public contract and an
	// implementation that double-DELETEs on a second caller would produce a
	// second 404 in a vendor's logs during every teardown.
	terminated sync.Once
	closeErr   error
}

// String makes a pool dump legible without exposing the session id.
//
// **THE ID IS OMITTED DELIBERATELY.** A session id is a bearer credential for
// the duration of the session — the specification says it SHOULD be
// "cryptographically secure (e.g. a securely generated UUID, a JWT, or a
// cryptographic hash)" — so it is exactly the class of value §4.3.3 makes
// self-redacting by type. Printing it in a pool dump or a panic would put a
// live authorisation into a log that is not treated as one.
func (s *session) String() string {
	return fmt.Sprintf("MCP session for %s (revision %s; §4.7.4 class 3)",
		s.target.Ref(), s.revision)
}

// BuildClient satisfies connector.ClientBuilder (D190, D213).
//
// **IT RETURNS A MARKER FOR THE SESSIONLESS REVISION RATHER THAN DECLINING THE
// INTERFACE**, because the interface is per-DRIVER and the answer is per-TARGET.
// `2026-07-28` is class 1 — a credential-free client, nothing to cache — and
// `2025-06-18` is class 3, and one driver serves both. So the marker is
// constructed here through the published constructor rather than by the
// registry's fallback, and it is the same value the registry would have supplied.
//
// **CALLED LAZILY, ON THE FIRST CALL FOR A POOLKEY**, which is what makes the
// handshake cost one round trip per (target, credential version) rather than one
// per command — and what makes a rotated credential re-handshake, correctly,
// because the new session must be opened with the credential that will be used
// on it.
func (d *Driver) BuildClient(ctx context.Context, t connector.Target) (any, error) {
	const op = "mcp.BuildClient"

	if !d.stateful(t) {
		return connector.CredentialFreeClient(Kind), nil
	}
	return d.initialize(ctx, op, t)
}

// initialize performs the handshake and returns the established session.
//
// The sequence the specification fixes, in order: POST `initialize`, read the
// negotiated version and the minted `Mcp-Session-Id` off the response, then POST
// the `notifications/initialized` notification. A server "SHOULD NOT send
// requests other than pings and logging before receiving the initialized
// notification", so skipping the third step leaves a server that is technically
// within its rights to answer nothing useful.
func (d *Driver) initialize(ctx context.Context, op string, t connector.Target) (*session, error) {
	revision := d.revisionFor(t)

	base, err := d.base(op, t)
	if err != nil {
		return nil, err
	}

	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}

	// **NO SESSION ON THIS ONE, WHICH IS THE ONLY REQUEST THAT MAY SAY SO.**
	header, err := d.post(ctx, op, t, nil, "initialize", map[string]any{
		"protocolVersion": revision,
		// EMPTY AND PRESENT, for `requestMeta`'s reason one revision over:
		// Sekizui relays a governed action and cannot satisfy sampling,
		// elicitation or roots, so claiming any of them would invite a server to
		// ask — and `callTool` refuses an elicitation as `KindEscalated`
		// precisely because there is nobody here to ask.
		"capabilities": map[string]any{},
		"clientInfo":   map[string]any{"name": "sekizui", "version": "0.x"},
	}, nil, &result)
	if err != nil {
		return nil, err
	}

	// **THE SERVER ANSWERING A DIFFERENT REVISION IS A REFUSAL, NOT A
	// NEGOTIATION (D193).** The specification's own flow is that a server which
	// does not support the requested version "MUST respond with another protocol
	// version it supports", and that a client which does not support the
	// server's answer "SHOULD disconnect". Sekizui does not support ANY answer
	// other than the declared one — not because it could not, but because
	// accepting one hands the far side the choice of how it is talked to, which
	// is the attacker-triggerable downgrade D193 exists to close.
	if result.ProtocolVersion != revision {
		return nil, fault.New(fault.KindSpecDrift, op, fmt.Sprintf(
			"target %q is configured for MCP revision %s and the server answered "+
				"`initialize` with %q. Sekizui does not negotiate a revision — a client "+
				"that accepts whatever the far side offers lets the far side choose the "+
				"protocol, which is a downgrade an attacker can trigger (D193). Either "+
				"the server was upgraded and the vetted spec has not been reviewed, or "+
				"this target points at the wrong endpoint",
			t.Ref(), revision, result.ProtocolVersion))
	}

	// **A SERVER THAT MINTS NO SESSION ON A STATEFUL REVISION IS REFUSED, AND
	// THIS IS SEKIZUI BEING STRICTER THAN THE PROTOCOL ON PURPOSE.** The
	// specification makes it a server MAY — "a server ... MAY assign a session
	// ID at initialization time" — so a stateless 2025-06-18 server is perfectly
	// conformant and this refuses it anyway. The reason is that `Mcp-Session-Id`
	// is a RESPONSE HEADER, and a response header is the easiest thing in the
	// stack for an intermediary to drop. Accepting its absence means an attacker
	// who can strip one header silently converts a stateful deployment into a
	// sessionless one, with every call still succeeding and nothing in any log
	// saying the shape changed — which is the same downgrade the revision check
	// above refuses, arriving through the door D193 did not think to close.
	//
	// **SO THE DECLARATION IS THE AUTHORITY AND THE SERVER IS NOT.** A human
	// wrote `revision: 2025-06-18` meaning "this server is stateful"; a server
	// that is not has either changed or is not the server that was vetted, and
	// both are things an operator must see. The cost is stated rather than
	// hidden: an operator whose 2025-06-18 server genuinely runs stateless
	// cannot declare that today, and the honest answer is that the vocabulary
	// would need a third entry rather than that this check should soften.
	sid := header.Get(sessionHeader)
	if sid == "" {
		return nil, fault.New(fault.KindSpecDrift, op, fmt.Sprintf(
			"target %q declares MCP revision %s, whose sessions are the reason it is "+
				"declared at all, and the server answered `initialize` with no %s "+
				"header. Sekizui refuses rather than continuing sessionless: that "+
				"header is one an intermediary can strip, so treating its absence as "+
				"permission to proceed turns dropping a header into a silent protocol "+
				"downgrade. If this server really is sessionless, it is not the server "+
				"this spec was vetted against",
			t.Ref(), revision, sessionHeader))
	}

	// **THE ID MUST BE VISIBLE ASCII, AND THE SPECIFICATION SAYS SO** — "the
	// session ID MUST only contain visible ASCII characters (ranging from 0x21
	// to 0x7E)". Checked rather than trusted, because this value is about to be
	// written into a header on every subsequent request.
	//
	// **THE RANGE IS CHECKED WHOLE RATHER THAN CHECKING FOR THE DANGEROUS BYTES,
	// and measuring it is what settled that.** The bytes outside 0x21-0x7E do
	// not behave alike: a newline makes `net/http` refuse to send the request at
	// all, which is D199's exact misdiagnosis — a local fault arriving as an
	// unreachable target, opening the breaker on a healthy vendor — while a TAB
	// is perfectly legal in an HTTP field value and Go transmits it without
	// complaint. So a check aimed at "what would fail to send" would pass a tab
	// through, and the target would work until some intermediary normalised it.
	// The specification's range is the line that covers both, and it is the one
	// a human can check against the document.
	if !visibleASCII(sid) {
		return nil, fault.New(fault.KindSpecDrift, op, fmt.Sprintf(
			"target %q minted a session id containing characters the specification "+
				"forbids (visible ASCII 0x21-0x7E only). Refused here rather than at "+
				"the first request that tried to send it, where it would have looked "+
				"like the target was unreachable (D199)", t.Ref()))
	}

	sess := &session{
		id: sid, revision: revision, endpoint: base, target: t, http: d.http,
	}

	// **THE THIRD STEP, AND IT IS NOT OPTIONAL.** A server "SHOULD NOT send
	// requests other than pings and logging before receiving the initialized
	// notification", so a client that skips it has a session the server will not
	// fully serve — the half-supported shape §4.7.10 keeps naming.
	if err := d.notifyInitialized(ctx, op, t, sess); err != nil {
		// **TORN DOWN BEFORE THE ERROR IS RETURNED.** The server minted a session
		// and we are about to abandon it; leaving it open leaks server-side state
		// for every failed boot, and this is the one place where the client that
		// holds it is not yet in the pool and so will never be closed by it.
		//
		// **`WithoutCancel` RATHER THAN `ctx` OR `Background`, and the two
		// rejected options fail in opposite directions.** Passing `ctx` means a
		// handshake that failed BECAUSE the caller's deadline expired cannot
		// clean up after itself — the DELETE inherits the dead deadline and
		// returns instantly, leaking exactly the session this branch exists to
		// reclaim. `context.Background()` cleans up and throws away the trace
		// ids and request-scoped values the surrounding call is carrying, so the
		// termination appears in the logs unattached to the boot that caused it.
		// `WithoutCancel` keeps the values and drops only the cancellation,
		// which is precisely the difference wanted (GO-PRIMER §15ai).
		_ = sess.terminate(context.WithoutCancel(ctx))
		return nil, err
	}

	return sess, nil
}

// notifyInitialized sends the `notifications/initialized` JSON-RPC notification.
//
// **A NOTIFICATION IS NOT A REQUEST AND `post` CANNOT CARRY IT**, which is the
// one place this file duplicates transport rather than sharing it. A
// notification has NO `id`, and the specification says the server "MUST return
// HTTP status code 202 Accepted with no body" — so `post`'s final three checks,
// each of which exists to catch a server answering a request with nothing
// useful, would reject a correct 202 as "neither a result nor an error".
//
// The duplication is bounded to what differs and is stated here so a later
// reader does not "fix" it by routing this through `post`: same endpoint, same
// credential placement, same revision header, same session header, no id, and a
// 202 rather than a body.
func (d *Driver) notifyInitialized(ctx context.Context, op string, t connector.Target,
	sess *session) error {

	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "method": "notifications/initialized",
	})
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "encoding the initialized notification", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sess.endpoint,
		strings.NewReader(string(payload)))
	if err != nil {
		return fault.Wrap(fault.KindInvalidArgument, op, "building the notification", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", sess.revision)
	req.Header.Set(sessionHeader, sess.id)

	if err := connector.SetAuthorization(req.Header, t, "Bearer"); err != nil {
		return fault.Wrap(fault.KindUnauthenticated, op,
			"the target's credential could not be borrowed", err)
	}

	resp, err := d.http.Do(req)
	if err != nil {
		return transportFault(op, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// **ANY 2xx, NOT 202 EXACTLY.** The specification says 202 and a server
	// answering 200 has still accepted it; refusing that would fail a boot over
	// a distinction with no consequence. Anything else is a real refusal of the
	// handshake's last step and must not be swallowed, because the session that
	// results is one the server will not fully serve.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fault.New(fault.KindTargetError, op, fmt.Sprintf(
			"target %q refused the `notifications/initialized` notification with HTTP "+
				"%d. The session was minted and cannot be used: a server is entitled to "+
				"answer nothing but pings until it receives this, so proceeding would "+
				"produce a target that appears configured and serves nothing",
			t.Ref(), resp.StatusCode))
	}
	return nil
}

// Close terminates the session (pool.Closer).
//
// **THIS IS THE HALF THAT MAKES BREAK-GLASS MEAN ANYTHING ON A STATEFUL
// REVISION.** Revoking a credential evicts the pooled client; without this the
// server would still hold an authorised session, and "the credential is
// withdrawn" would be true of our side only. `pool.finalise` closes the client
// BEFORE wiping the credential, and its comment has said why since P0 — "an MCP
// session close is itself an authenticated call" — which stopped being
// hypothetical here.
//
// **IT BUILDS ITS OWN CONTEXT, AND THAT IS THE INTERFACE'S DOING RATHER THAN A
// SHORTCUT.** `Closer` is `Close() error` with no context, because it is called
// from teardown paths whose own context is frequently already cancelled — a
// revocation, a drain, a superseded entry — and inheriting one would mean the
// DELETE is skipped in exactly the cases where terminating the session matters
// most. So the deadline is short, fixed, and its own.
//
// **A FAILED DELETE IS LOGGED, NEVER FATAL.** The specification lets a server
// answer 405 to say it does not allow clients to terminate sessions, and a
// server that has already expired the session answers 404 — both mean the
// session is gone, which is the outcome wanted. `pool.finalise` logs whatever
// comes back and proceeds to the wipe regardless, which is right: a teardown
// failure must not strand a credential.
func (s *session) Close() error { return s.terminate(context.Background()) }

// terminate is Close with the context made explicit, for the one caller that
// has a live one: `initialize` tearing down a session whose handshake failed.
//
// Bounded here rather than at each caller, so no path can send an unbounded
// DELETE on a teardown a human is waiting for.
func (s *session) terminate(parent context.Context) error {
	s.terminated.Do(func() {
		ctx, cancel := context.WithTimeout(parent, sessionCloseTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.endpoint, nil)
		if err != nil {
			s.closeErr = fault.Wrap(fault.KindInternal, "mcp.session.Close",
				"building the session termination request", err)
			return
		}
		req.Header.Set("MCP-Protocol-Version", s.revision)
		req.Header.Set(sessionHeader, s.id)

		// **AUTHENTICATED, AND IT CAN LEGITIMATELY FAIL TO BE.** If break-glass
		// wiped the credential before this ran, the borrow refuses — which is the
		// ordering `pool.finalise` is built to prevent, and reporting it is how
		// anyone would learn that ordering had regressed.
		if err := connector.SetAuthorization(req.Header, s.target, "Bearer"); err != nil {
			s.closeErr = fault.Wrap(fault.KindUnauthenticated, "mcp.session.Close",
				"the credential could not be borrowed to terminate the session, so the "+
					"server may still hold it open", err)
			return
		}

		resp, err := s.http.Do(req)
		if err != nil {
			s.closeErr = transportFault("mcp.session.Close", err)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		// 405 and 404 both mean "not holding it any more": the first that the
		// server declines to be told, the second that it had already forgotten.
		switch {
		case resp.StatusCode == http.StatusMethodNotAllowed,
			resp.StatusCode == http.StatusNotFound,
			resp.StatusCode < 300:
			return
		default:
			s.closeErr = fault.New(fault.KindTargetError, "mcp.session.Close", fmt.Sprintf(
				"terminating the MCP session at %s answered HTTP %d, so the server may "+
					"still hold an authorised session for a credential we are about to "+
					"wipe", s.target.Ref(), resp.StatusCode))
		}
	})
	return s.closeErr
}

// sessionCloseTimeout bounds the DELETE.
//
// SHORT ON PURPOSE. This runs on teardown paths a human is waiting on — a
// revocation blocks until every entry has drained — so a vendor that stops
// answering must not extend break-glass by the length of an HTTP timeout.
const sessionCloseTimeout = 5 * time.Second

// visibleASCII reports whether every byte is in the specification's permitted
// range for a session id, 0x21 to 0x7E.
//
// **AN EMPTY STRING IS NOT VISIBLE ASCII**, which the loop gives for free and
// which matters: the caller checks for absence separately with a much better
// message, and this returning true for "" would make that ordering load-bearing.
func visibleASCII(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7E {
			return false
		}
	}
	return true
}
