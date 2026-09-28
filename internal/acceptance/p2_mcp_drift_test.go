package acceptance

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/catalog"
	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/grantcheck"
	"github.com/fullstorydev/sekizui/internal/metrics"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/provider/file"
	"github.com/fullstorydev/sekizui/pkg/provider/oauth"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// --- the fixture the drift steps share --------------------------------------

// mcpUpstream is an MCP server that answers `tools/list` and `tools/call`.
//
// **IT VALIDATES THE PROTOCOL RATHER THAN MERELY ANSWERING, and that is not
// decoration.** `MCP-Protocol-Version` is REQUIRED on every POST and MUST match
// `_meta.io.modelcontextprotocol/protocolVersion` in the body, and `Mcp-Method`
// must name the method — a conforming server rejects a mismatch with `-32020`.
// A fake that ignored those would let the driver stop sending them and every
// step below would still pass, which is the shape of a test that agrees with
// whatever the code does (D159's habit, applied to a fixture rather than to a
// comparison).
//
// **`internal/driver/mcp` HAS NO PACKAGE TESTS**, so these steps are also the
// first thing that has ever driven its transport. That is recorded rather than
// quietly relied on: the drift severities are covered here, and the status/error
// mapping still is not.
//
// **AND IT SPEAKS EITHER REVISION, WHICH IS WHY D213 EXTENDED IT RATHER THAN
// WRITING A SECOND ONE.** The two revisions differ in what a request must NOT
// carry as much as in what it must: `2025-06-18` defines no `Mcp-Method`, no
// `Mcp-Name` and none of the `io.modelcontextprotocol/` `_meta` keys, and those
// key names are RESERVED by the specification. A separate stateful fixture
// could only have asserted the stateful rules; one fixture that switches
// asserts the NEGATIVE half of each — that the driver stops sending
// 2026-07-28's metadata when it is talking to a server that never defined it —
// which is the half a second fixture would have quietly skipped.
type mcpUpstream struct {
	mu sync.Mutex

	// tools is what `tools/list` currently advertises. Mutable, because every
	// drift case below is "the server changed and the spec did not".
	tools []mcp.LiveTool

	// calls records the tool names `tools/call` received, so "not callable" can
	// be asserted at the far side rather than by reading our own refusal (D159).
	calls []string

	// lists counts `tools/list` requests, so a refused drift comparison can be
	// asserted never to have reached the server (P4 step 32d, D311).
	lists int

	// results is what `tools/call` answers, per tool — absent means the fixed
	// `"ok"` text every step before D289 relied on. argsSeen records the
	// arguments each call carried, so a pinned `org_id` can be asserted at the
	// far side (P3 step 25).
	results  map[string]map[string]any
	argsSeen map[string][]map[string]any

	// --- the stateful half (D213) -------------------------------------------

	// revision is what this server speaks. Empty means the sessionless default,
	// so every step written before D213 is unchanged.
	revision string

	// live is the set of session ids this server currently recognises.
	live map[string]bool

	// minted counts `initialize` calls that produced a session, which is how an
	// arm proves the handshake happened ONCE per pool entry rather than per
	// call.
	minted int

	// initialized counts `notifications/initialized`.
	initialized int

	// deleted records session ids terminated via HTTP DELETE.
	deleted []string

	// carried records the session id on every non-initialize request, including
	// the empty string. An arm asserts on this rather than on our own code
	// having intended to send one.
	carried []string

	// withholdSession makes `initialize` mint no `Mcp-Session-Id`, which the
	// specification permits and Sekizui refuses (D213).
	withholdSession bool

	// answerRevision overrides the `protocolVersion` in the initialize result,
	// so the no-negotiation rule can be driven from the server side.
	answerRevision string

	// mintMalformedSession mints an id outside the specification's visible-ASCII
	// range, which `net/http` would then refuse to put in a header.
	mintMalformedSession bool

	// --- the token endpoint (D131, step 37) ---------------------------------

	// minted tokens, one per exchange, so a step can prove a REFRESH happened
	// rather than assuming one.
	tokens int

	// tokenTTL is `expires_in`. Short values make the cache re-resolve within a
	// test rather than on a real clock.
	tokenTTL int

	// bearers records the Authorization header of every MCP request, so what
	// reached the vendor is asserted at the far side rather than from our own
	// intent (D159).
	bearers []string
}

// stateless reports whether this upstream speaks the sessionless revision.
func (u *mcpUpstream) stateless() bool {
	return u.revision == "" || u.revision == mcp.ProtocolVersion
}

// serve starts the upstream over TLS.
//
// **TLS, BECAUSE THE DRIVER REFUSES PLAINTEXT AND IS RIGHT TO.** The credential
// is a Bearer token on every request (§4.7.4 class 1), so an http:// base_url
// would put it on the wire in clear — `mcp.base` refuses one, which means
// `httptest.NewServer` cannot be used here however convenient it is.
func (u *mcpUpstream) serve(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// **SESSION TERMINATION, WHICH CARRIES NO BODY.** Handled before the
		// JSON-RPC decode, because a DELETE has nothing to decode.
		// **THE TOKEN ENDPOINT, ON THE SAME SERVER AS THE VENDOR.** One TLS
		// server rather than two, because `oauth.endpointOf` forces https and
		// `httptest` gives exactly one trusted client — so a second server would
		// need its CA threading through the provider as well as the driver, to
		// model a separation no assertion here depends on. What IS modelled is
		// the part that matters: a real chained resolution over a real
		// transport, with the client secret exchanged for a token that a
		// different handler then has to accept.
		if r.URL.Path == "/token" {
			u.mu.Lock()
			defer u.mu.Unlock()
			u.tokens++
			ttl := u.tokenTTL
			if ttl == 0 {
				ttl = 3600
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok-" + strconv.Itoa(u.tokens),
				"token_type":   "Bearer",
				"expires_in":   ttl,
			})
			return
		}

		if r.Method == http.MethodDelete {
			u.mu.Lock()
			defer u.mu.Unlock()
			sid := r.Header.Get("Mcp-Session-Id")
			u.deleted = append(u.deleted, sid)
			delete(u.live, sid)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		u.mu.Lock()
		u.bearers = append(u.bearers, r.Header.Get("Authorization"))
		u.mu.Unlock()

		var req struct {
			ID     int64          `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "not JSON-RPC", http.StatusBadRequest)
			return
		}

		meta, _ := req.Params["_meta"].(map[string]any)
		bodyVersion, _ := meta["io.modelcontextprotocol/protocolVersion"].(string)

		if u.stateless() {
			// THE REQUIRED METADATA, CHECKED THE WAY A CONFORMING SERVER CHECKS
			// IT.
			switch {
			case r.Header.Get("MCP-Protocol-Version") != mcp.ProtocolVersion,
				r.Header.Get("MCP-Protocol-Version") != bodyVersion,
				r.Header.Get("Mcp-Method") != req.Method:
				writeRPC(w, req.ID, nil, &struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				}{Code: -32020, Message: "header/body mismatch"})
				return
			}
		} else if !u.statefulPreflight(w, r, req.ID, req.Method, meta) {
			return
		}

		u.mu.Lock()
		defer u.mu.Unlock()

		switch req.Method {
		case "initialize":
			u.minted++
			answer := u.answerRevision
			if answer == "" {
				answer = u.revision
			}
			if !u.withholdSession {
				sid := "sess-" + strconv.Itoa(u.minted)
				if u.mintMalformedSession {
					// A TAB, which is outside 0x21-0x7E and is the classic
					// header-smuggling character. `Header().Set` stores it
					// happily; it is the WRITE that would fail, one layer and one
					// misdiagnosis later.
					sid += "\tbad"
				}
				u.live[sid] = true
				w.Header().Set("Mcp-Session-Id", sid)
			}
			writeRPC(w, req.ID, map[string]any{
				"protocolVersion": answer,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "fixture", "version": "1"},
			}, nil)
		case "notifications/initialized":
			u.initialized++
			// 202 WITH NO BODY, which is what the specification requires for a
			// notification and what `post` could not have parsed.
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			u.lists++
			writeRPC(w, req.ID, map[string]any{"tools": u.tools}, nil)
		case "tools/call":
			name, _ := req.Params["name"].(string)
			u.calls = append(u.calls, name)
			if args, ok := req.Params["arguments"].(map[string]any); ok {
				if u.argsSeen == nil {
					u.argsSeen = map[string][]map[string]any{}
				}
				u.argsSeen[name] = append(u.argsSeen[name], args)
			}
			if res, ok := u.results[name]; ok {
				writeRPC(w, req.ID, res, nil)
				break
			}
			writeRPC(w, req.ID, map[string]any{
				"resultType": "complete",
				"content":    []map[string]any{{"type": "text", "text": "ok"}},
			}, nil)
		default:
			writeRPC(w, req.ID, nil, &struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}{Code: -32601, Message: "method not found"})
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// statefulPreflight enforces the 2025-06-18 request rules, and the NEGATIVE
// ones are the reason it exists (D213).
//
// A conforming 2025-06-18 server sees no `Mcp-Method`, no `Mcp-Name` and no
// `io.modelcontextprotocol/` `_meta` keys, because that revision defines none of
// them and reserves the namespace. Rejecting them here is what stops the driver
// keeping 2026-07-28's request metadata on a revision that never had it and
// every step below still passing.
//
// Returns false when it has already written a response.
func (u *mcpUpstream) statefulPreflight(w http.ResponseWriter, r *http.Request,
	id int64, method string, meta map[string]any) bool {

	rpcErr := func(code int, msg string) bool {
		writeRPC(w, id, nil, &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{Code: code, Message: msg})
		return false
	}

	if got := r.Header.Get("MCP-Protocol-Version"); got != u.revision {
		return rpcErr(-32600, "MCP-Protocol-Version is "+got+", want "+u.revision)
	}
	if r.Header.Get("Mcp-Method") != "" || r.Header.Get("Mcp-Name") != "" {
		return rpcErr(-32600,
			"Mcp-Method/Mcp-Name are 2026-07-28 request metadata and this revision "+
				"does not define them")
	}
	for k := range meta {
		if strings.HasPrefix(k, "io.modelcontextprotocol/") {
			return rpcErr(-32600, "_meta key "+k+" is reserved and undefined in "+u.revision)
		}
	}

	if method == "initialize" {
		// The one request that must NOT carry a session.
		if r.Header.Get("Mcp-Session-Id") != "" {
			return rpcErr(-32600, "initialize carried a session id")
		}
		return true
	}

	sid := r.Header.Get("Mcp-Session-Id")

	u.mu.Lock()
	u.carried = append(u.carried, sid)
	known := u.live[sid]
	u.mu.Unlock()

	// **404, WHICH THE SPECIFICATION MAKES THE SIGNAL TO RE-ESTABLISH.** "The
	// server MAY terminate the session at any time, after which it MUST respond
	// to requests containing that session ID with HTTP 404 Not Found."
	if !known {
		if sid == "" {
			// A server that REQUIRES a session answers 400 to a request without
			// one, which is a different failure and must not be confused with an
			// expiry.
			http.Error(w, "no Mcp-Session-Id", http.StatusBadRequest)
			return false
		}
		http.Error(w, "unknown session", http.StatusNotFound)
		return false
	}
	return true
}

// exchanges reports how many tokens the endpoint minted, and every
// Authorization header the vendor side saw.
func (u *mcpUpstream) exchanges() (minted int, bearers []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.tokens, append([]string(nil), u.bearers...)
}

// stats reports the handshake bookkeeping.
func (u *mcpUpstream) stats() (minted, initialized int, deleted, carried []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.minted, u.initialized,
		append([]string(nil), u.deleted...), append([]string(nil), u.carried...)
}

// expireOnce makes the server forget the sessions it currently holds, WITHOUT
// refusing the ones it mints afterwards.
//
// **THAT DISTINCTION IS WHAT MAKES THE ARM AN EXPIRY RATHER THAN AN OUTAGE.** A
// server that 404s forever would prove only that re-establishment is bounded —
// which step 42 already proves for a credential. What must be shown here is that
// the SECOND session works, so the caller sees a success and the MUST is
// actually met.
func (u *mcpUpstream) expireOnce() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.live = map[string]bool{}
}

// offer replaces what the server advertises, so a step can make the live
// surface diverge from the vetted spec mid-run.
func (u *mcpUpstream) offer(tools ...mcp.LiveTool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.tools = tools
}

// listCalls reports how many `tools/list` requests arrived.
func (u *mcpUpstream) listCalls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lists
}

// called reports the tool names `tools/call` received.
func (u *mcpUpstream) called() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.calls...)
}

func writeRPC(w http.ResponseWriter, id int64, result map[string]any, rpcErr any) {
	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		body["error"] = rpcErr
	} else {
		body["result"] = result
	}
	_ = json.NewEncoder(w).Encode(body)
}

// objectSchema is the trivial valid input schema. `inputSchema` is mandatory in
// MCP, so every tool on both sides needs one.
func objectSchema(props ...string) json.RawMessage {
	if len(props) == 0 {
		return json.RawMessage(`{"type":"object"}`)
	}
	fields := map[string]any{}
	for _, p := range props {
		fields[p] = map[string]any{"type": "string"}
	}
	raw, _ := json.Marshal(map[string]any{"type": "object", "properties": fields})
	return raw
}

// mcpRig is a driver and a resolved target pointed at one upstream.
type mcpRig struct {
	up     *mcpUpstream
	srv    *httptest.Server
	driver *mcp.Driver
	target connector.Target
	doc    *config.Document

	// providers is the set both the rig and the stack build a resolver from.
	//
	// **THE SET IS SHARED AND THE RESOLVER IS NOT, WHICH IS A DISTINCTION STEP 38
	// ENFORCES.** Sharing the resolver shares its credential CACHE, and the rig
	// resolves once eagerly at wiring time — so a step that changes a credential
	// after the stack is built would find the clean value already cached. Step
	// 38 does exactly that (`t.Setenv` with a trailing newline, deliberately
	// after construction, because the rig's own `t.Setenv` would overwrite it
	// before), and it failed the moment these were shared. Its comment already
	// stated the property it depends on — "the resolver reads the environment at
	// RESOLVE time, which is the first command, not at wiring time" — which
	// sharing quietly falsified.
	providers []config.Provider
}

// unreachable stops the upstream mid-step, so ONE target is reachable and then
// is not. Two targets would compare two configurations; this compares two
// conditions on one. `httptest.Server.Close` is guarded against a second call,
// so the `t.Cleanup` registered by `serve` stays correct.
func (r *mcpRig) unreachable() { r.srv.Close() }

// newMCPRig wires a document, a driver and a resolved target against a live
// upstream.
//
// **THE TARGET COMES FROM THE RESOLVER**, not from a struct literal — §6
// mechanism 1 makes `connector.Target` unconstructable outside it, and a rig
// that reached around that would be proving something about a shape the running
// system never produces.
func newMCPRig(ctx context.Context, t *testing.T, edit func(*config.Document)) *mcpRig {
	t.Helper()

	up := &mcpUpstream{live: map[string]bool{}}
	srv := up.serve(t)

	t.Setenv("SEKIZUI_MCP_TOK", "mcp-token")
	doc := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "fixture-mcp", Kind: mcp.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: srv.URL, CredentialRef: "env://SEKIZUI_MCP_TOK",
		}},
		MCPSpecs: map[string]config.MCPSpec{
			"fixture-mcp": {
				Server: "fixture", Host: "127.0.0.1",
				Tools: []config.MCPToolSpec{{
					Name:        "search",
					Description: "Search the repository.",
					InputSchema: objectSchema("query"),
				}},
			},
		},
	}
	if edit != nil {
		edit(doc)
	}

	// **THE SERVER SPEAKS WHAT THE SPEC DECLARES, DERIVED RATHER THAN PASSED
	// (D213).** The handler reads this at REQUEST time, so setting it after the
	// document is edited is in time for every call — and deriving it means an
	// arm cannot point a 2025-06-18 target at a fixture still speaking
	// 2026-07-28 and mistake the resulting mismatch for a driver bug. The other
	// upstream knobs are set by an arm on `rig.up` afterwards, which is equally
	// in time because the handshake is lazy: it happens on the first pool
	// borrow, not at construction.
	up.mu.Lock()
	up.revision = doc.MCPSpecs["fixture-mcp"].Revision
	up.mu.Unlock()

	driver := mcp.New(doc.MCPSpecs, mcp.WithHTTPClient(srv.Client()))

	// **EVERY PROVIDER THE BINARY WIRES, NOT JUST THE ONE THIS DOCUMENT USES.**
	// The default target is `env://` and stays so, which leaves steps 7-13 and 36
	// untouched; step 37 points the same target at `oauth-cc://` chaining to
	// `file://` and needs no fixture of its own. Wiring the set rather than the
	// one in play also matches `cmd/sekizui`, where a target's scheme is a
	// configuration choice rather than a wiring choice — and D97's boot check
	// DERIVES the available schemes from exactly this slice, so a rig carrying a
	// narrower set would be modelling a deployment nobody runs.
	providers := []config.Provider{
		config.EnvProvider{},
		file.New(file.Roots(os.TempDir())),
		oauth.New(oauth.WithHTTPClient(srv.Client())),
	}
	res := resolver.New(doc, runtime.Profile{}, nil, providers...)
	target, err := res.Resolve(ctx, "fixture-mcp")
	if err != nil {
		t.Fatalf("resolving the MCP target: %v", err)
	}
	return &mcpRig{up: up, srv: srv, driver: driver, target: target, doc: doc,
		providers: providers}
}

// step7ActionsDerivesFromTheCommittedSpec proves D45 and D46.
//
// **THE STRUCTURAL REASON DRIFT IS DETECTABLE AT ALL.** A driver that asked the
// server what it could do would have nothing to compare against, and would adopt
// an attacker's answer as its own capability set — the supply-chain failure
// §4.9a.3 exists to make impossible. So `Actions()` is generated from the vetted
// spec in `config.Document` and the live `tools/list` cannot move it.
//
// **ASSERTED BY DIVERGENCE IN BOTH DIRECTIONS, because they fail differently.**
// A server that ADDS a tool must not widen the capability set (that is the
// attack); a server that REMOVES one must not narrow it either, because
// narrowing here would silently discard a vetted capability instead of raising
// `withheld`, and the operator would never learn the server had changed.
func step7ActionsDerivesFromTheCommittedSpec(t *testing.T) {
	ctx := context.Background()
	rig := newMCPRig(ctx, t, nil)

	vetted := []string{"mcp.fixture.search"}

	// --- 7a: NON-VACUITY — the server really does offer something else -----
	//
	// Without this the step passes against a server that never diverged, which
	// is "the check works" and "there was nothing to check" reported alike.
	rig.up.offer(
		mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")},
		mcp.LiveTool{Name: "exfiltrate", InputSchema: objectSchema("path")},
	)
	live, err := rig.driver.ListTools(connector.WithTenant(ctx, rig.target.Tenant()), rig.target)
	if err != nil {
		t.Fatalf("7a: listing the live tools: %v", err)
	}
	if len(live) != 2 {
		t.Fatalf("7a: the server advertises %d tools, want 2. Nothing below proves "+
			"anything if the live surface never diverged from the spec", len(live))
	}

	// --- 7b: AND `Actions()` IS UNMOVED -------------------------------------
	if got := actionNames(rig.driver); !equalStrings(got, vetted) {
		t.Errorf("7b: Actions() is %v, want %v. The live tool list moved the capability "+
			"set, so a vendor — or anyone who can answer for one — chooses what Sekizui "+
			"may call", got, vetted)
	}

	// --- 7c: NOR DOES A SERVER THAT WITHDRAWS A TOOL -----------------------
	//
	// The other direction, and the one that looks harmless. If `Actions()`
	// shrank with the server, a withdrawn tool would vanish from the catalog
	// with no finding and no record — D48's `withheld` severity exists precisely
	// because that must be a REPORTED condition rather than a silent narrowing.
	rig.up.offer()
	if _, err := rig.driver.ListTools(connector.WithTenant(ctx, rig.target.Tenant()), rig.target); err != nil {
		t.Fatalf("7c: listing the live tools: %v", err)
	}
	if got := actionNames(rig.driver); !equalStrings(got, vetted) {
		t.Errorf("7c: after the server withdrew every tool, Actions() is %v, want %v. "+
			"A capability set that follows the wire cannot report a withdrawal, because "+
			"the thing that would have been reported is already gone", got, vetted)
	}

	// --- 7d: AND IT ASKS NOBODY ---------------------------------------------
	//
	// **THE ONLY WAY TO ASSERT AN ABSENCE OF I/O** is to make the I/O fail the
	// test (P1 step 15's pattern). `Actions()` takes no context and no target, so
	// today it structurally cannot call out; this arm is what stops a later
	// version quietly acquiring a client and doing it anyway — which would look
	// like a performance improvement in review.
	mute := mcp.New(rig.doc.MCPSpecs, mcp.WithHTTPClient(&http.Client{
		Transport: refuseTransport{t: t},
	}))
	if got := actionNames(mute); !equalStrings(got, vetted) {
		t.Errorf("7d: Actions() over a transport that cannot be used is %v, want %v",
			got, vetted)
	}

	r := &run{}
	r.detail(t, "D45/D46: the server offered a tool the vetted spec does not carry and "+
		"then withdrew every tool; Actions() stayed %v through both, and made no call "+
		"to reach that answer", vetted)
}

// refuseTransport fails the test if it is used at all.
type refuseTransport struct{ t *testing.T }

func (r refuseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.t.Errorf("Actions() made an HTTP request to %s. The vetted spec is the capability "+
		"set (D46); a driver that asks the server what it can do has nothing left to "+
		"compare a live list against", req.URL)
	return nil, http.ErrUseLastResponse
}

func actionNames(d *mcp.Driver) []string {
	out := make([]string, 0, len(d.Actions()))
	for _, a := range d.Actions() {
		out = append(out, a.Name)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// step10OutputSchemaAbsenceIsNeverDrift proves D51.
//
// **MUCH OF THE MCP ECOSYSTEM PUBLISHES NO OUTPUT SCHEMA**, so absence must read
// as *the system does not describe its output* rather than as divergence. A
// check that fired on the common case would be switched off within a week, and
// §4.9a.3a's state matrix is what stops that happening while keeping the case
// that matters.
//
// **THE SECOND ARM IS THE ONE WITH TEETH: a `local`-provenance schema is never
// compared.** We authored it from observed responses; the vendor never claimed
// it, so there is nothing to diverge FROM — and comparing it would make D168's
// authoring tool a manufacturer of false incidents, each one indistinguishable
// from a real vendor change.
//
// Every arm holds `inputSchema` IDENTICAL on both sides, so the only variable is
// the output schema. An arm that let both move would report `refused` and prove
// nothing about D51.
func step10OutputSchemaAbsenceIsNeverDrift(t *testing.T) {
	ctx := context.Background()

	// noFindings asserts silence across the WHOLE vocabulary rather than at the
	// severity somebody expects (§15q). A severity added next year is covered by
	// this shape and invisible to an assertion naming members.
	noFindings := func(t *testing.T, fs drift.Findings, why string) {
		t.Helper()
		for _, s := range drift.Severities() {
			if got := fs.Of(s); len(got) > 0 {
				t.Errorf("%s: reported %d %s finding(s): %v", why, len(got), s, got)
			}
		}
	}

	// --- 10a: ABSENT ON BOTH SIDES IS THE COMMON CASE, AND IS NOT DRIFT -----
	t.Run("neither side publishes an output schema", func(t *testing.T) {
		rig := newMCPRig(ctx, t, nil)
		rig.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

		fs, err := rig.driver.Drift(connector.WithTenant(ctx, rig.target.Tenant()), rig.target)
		if err != nil {
			t.Fatalf("10a: %v", err)
		}
		noFindings(t, fs, "10a: a tool neither side gives an output schema for")
	})

	// --- 10b: A `local` SCHEMA IS NEVER COMPARED ----------------------------
	//
	// NON-VACUITY IS THE SAME DIVERGENCE UNDER `vendor`, which must be reported.
	// Without that arm this passes against a comparison that is broken outright,
	// and "we correctly ignore local schemas" reads identically to "we compare
	// nothing".
	t.Run("a local-provenance schema is not compared; a vendor one is", func(t *testing.T) {
		for _, tc := range []struct {
			origin string
			quiet  bool
		}{
			{origin: "local", quiet: true},
			{origin: "vendor", quiet: false},
		} {
			t.Run(tc.origin, func(t *testing.T) {
				rig := newMCPRig(ctx, t, func(d *config.Document) {
					spec := d.MCPSpecs["fixture-mcp"]
					spec.Tools[0].OutputSchema = objectSchema("hits")
					spec.Tools[0].OutputSchemaOrigin = tc.origin
					d.MCPSpecs["fixture-mcp"] = spec
				})
				// THE SERVER PUBLISHES SOMETHING DIFFERENT.
				rig.up.offer(mcp.LiveTool{
					Name:         "search",
					InputSchema:  objectSchema("query"),
					OutputSchema: objectSchema("results"),
				})

				fs, err := rig.driver.Drift(connector.WithTenant(ctx, rig.target.Tenant()), rig.target)
				if err != nil {
					t.Fatalf("10b/%s: %v", tc.origin, err)
				}
				if tc.quiet {
					noFindings(t, fs, "10b: a `local` schema we authored ourselves")
					return
				}
				if len(fs.Of(drift.SeverityInformational)) != 1 {
					t.Errorf("10b: a diverged `vendor` schema produced %v, want one "+
						"informational finding. With no finding here, the `local` arm "+
						"above passes against a comparison that never runs", fs)
				}
				if fs.RefusesTarget() {
					t.Errorf("10b: an output-schema divergence refused the target: %v. "+
						"Only `inputSchema` refuses — args validated against a pinned "+
						"schema reaching a server that expects another shape is a "+
						"different kind of problem from a result we may parse loosely", fs)
				}
			})
		}
	})

	// --- 10c: A WITHDRAWN VENDOR SCHEMA IS LOGGED, NOT REFUSED --------------
	//
	// D46 says our spec is truth, so a withdrawn advertisement does not un-vet
	// what was vetted: validation continues against the pinned copy. Dropping it
	// would silently stop checking output at all — the failure that looks like
	// nothing happening.
	t.Run("the vendor withdraws a schema the spec pins", func(t *testing.T) {
		rig := newMCPRig(ctx, t, func(d *config.Document) {
			spec := d.MCPSpecs["fixture-mcp"]
			spec.Tools[0].OutputSchema = objectSchema("hits")
			spec.Tools[0].OutputSchemaOrigin = "vendor"
			d.MCPSpecs["fixture-mcp"] = spec
		})
		rig.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

		fs, err := rig.driver.Drift(connector.WithTenant(ctx, rig.target.Tenant()), rig.target)
		if err != nil {
			t.Fatalf("10c: %v", err)
		}
		if fs.RefusesTarget() || len(fs.Of(drift.SeverityInformational)) != 1 {
			t.Errorf("10c: a withdrawn vendor schema produced %v, want exactly one "+
				"informational finding and no refusal", fs)
		}
	})

	r := &run{}
	r.detail(t, "D51: absence is not divergence on either side, a `local` schema is "+
		"never compared against the server while the same divergence under `vendor` is "+
		"reported, and no output-schema state refuses the target")
}

// step13AnUnreachableServerIsNotDrift proves D48's other half.
//
// **CONFLATING THEM TURNS A NETWORK BLIP INTO WHAT READS AS A SECURITY
// INCIDENT** — and it now matters more than when D48 was written, because D167
// puts a rule behind `spec_drift`: one that quarantines on drift must not fire
// because a server was briefly down.
//
// **ASSERTED ON THE CLASSIFICATION, NEVER ON THE LOG TEXT.** The two conditions
// differ on both axes a caller acts on: `spec_drift` is DELIBERATE and NOT
// retryable — a human must change something — while `target_unavailable` is a
// FAILURE and is retryable. A step comparing message strings would pass on a
// system that had the retryability backwards, which is the half that changes
// behaviour.
//
// **ONE TARGET, TWO CONDITIONS.** The upstream is diverged first and then
// stopped, so nothing differs between the arms except reachability. Two targets
// would compare two configurations.
func step13AnUnreachableServerIsNotDrift(t *testing.T) {
	ctx := context.Background()
	rig := newMCPRig(ctx, t, nil)

	// --- 13a: REACHABLE AND DIVERGED IS A GOVERNANCE EVENT ------------------
	//
	// NON-VACUITY, and the asymmetry the whole step rests on: the same code path
	// must be able to produce `spec_drift`, or "an unreachable server is not
	// drift" is satisfied by a driver that never reports drift at all.
	rig.up.offer(mcp.LiveTool{
		Name: "search", InputSchema: objectSchema("query", "unexpected_field"),
	})
	err := rig.driver.Health(connector.WithTenant(ctx, rig.target.Tenant()), rig.target)
	if err == nil {
		t.Fatal("13a: a server whose inputSchema diverges from the vetted one passed " +
			"health. Nothing below distinguishes anything if drift is never reported")
	}
	if got := fault.KindOf(err); got != fault.KindSpecDrift {
		t.Fatalf("13a: a diverged server reports kind %v, want %v", got, fault.KindSpecDrift)
	}

	// --- 13b: UNREACHABLE PRODUCES NO FINDINGS AT ALL -----------------------
	//
	// Not "no refusing findings" — NONE. A partial comparison alongside an error
	// would let a caller draw drift conclusions from a tool list that was never
	// read, and the conclusion it would draw is that every vetted tool was
	// withdrawn at once.
	rig.unreachable()

	findings, err := rig.driver.Drift(connector.WithTenant(ctx, rig.target.Tenant()), rig.target)
	if err == nil {
		t.Fatal("13b: Drift against a stopped server returned no error")
	}
	if len(findings) != 0 {
		t.Errorf("13b: Drift returned %d finding(s) alongside the error: %v. A server "+
			"that could not be read has not diverged; reporting both would say every "+
			"vetted tool had been withdrawn", len(findings), findings)
	}

	// --- 13c: AND IT IS CLASSIFIED AS AN AVAILABILITY CONDITION ------------
	err = rig.driver.Health(connector.WithTenant(ctx, rig.target.Tenant()), rig.target)
	if err == nil {
		t.Fatal("13c: Health against a stopped server reported healthy")
	}
	kind := fault.KindOf(err)
	switch {
	case kind == fault.KindSpecDrift:
		t.Error("13c: an unreachable server is reported as spec_drift. A rule that " +
			"quarantines a target on drift would then fire because a vendor had a " +
			"bad minute, which is the failure D48 separates the severities to prevent")
	case kind != fault.KindTargetUnavailable:
		t.Errorf("13c: an unreachable server reports kind %v, want %v",
			kind, fault.KindTargetUnavailable)
	}

	// --- 13d: THE TWO DIFFER WHERE A CALLER ACTS ---------------------------
	//
	// The properties rather than the words: a blip is a FAILURE and is worth
	// retrying, a divergence is a DELIBERATE refusal that a retry cannot fix.
	// Getting either backwards is what a message-matching assertion misses.
	if !kind.Retryable() {
		t.Errorf("13d: %v is not retryable. A server that was briefly down is the "+
			"case retrying exists for", kind)
	}
	if fault.KindSpecDrift.Retryable() {
		t.Error("13d: spec_drift is retryable. A driver retrying a divergence burns " +
			"quota against a wall until a human edits the vetted spec")
	}
	if kind.Deliberate() {
		t.Errorf("13d: %v is classified as a deliberate refusal, so an outage at a "+
			"vendor would be recorded as a governance decision Sekizui made", kind)
	}
	if !fault.KindSpecDrift.Deliberate() {
		t.Error("13d: spec_drift is not deliberate, so a real divergence would be " +
			"logged as a failure rather than as the refusal it is (D125)")
	}

	// **THE RESIDUAL, NAMED RATHER THAN IMPLIED.** `spec_drift` as an anzen
	// SIGNAL is raised by nothing yet — step 26 (D167) brings the raiser and the
	// watching rule. What is proven here is that both of the inputs such a raiser
	// can key on are absent for an unreachable server: no findings, and a fault
	// kind that is not `spec_drift`. Step 26 owes the negative case through the
	// dispatcher, and its declaration says so.
	r := &run{}
	r.detail(t, "D48: one target, diverged then stopped — the divergence is "+
		"spec_drift (deliberate, not retryable), the outage is target_unavailable "+
		"(a failure, retryable) with no findings at all, and neither input a "+
		"spec_drift raiser could key on is present for the outage")
}

// mcpStack is the rig with a real gateway and catalog around it, so a refusal
// can be observed where an AGENT would meet it rather than at the driver seam.
type mcpStack struct {
	*mcpRig
	gw      *gateway.Server
	catalog *catalog.Catalog

	// pool and metrics are held so a step can drive break-glass and read the
	// scrape (D213). Exposed on the fixture rather than rebuilt by an arm,
	// because the pool the gateway enforces through must be the SAME one an arm
	// revokes from — two pools would make a revocation truthfully report
	// cancelling nothing, which is the defect CONTRACTS 35 records.
	pool    *pool.Pool
	metrics *metrics.Registry

	// logPath is the stack's audit log, so a step can read what was RECORDED
	// as distinct from what was returned (P3 step 25).
	logPath string
}

// call runs one command through the whole enforcement path.
//
// TAKES THE CALLER'S CONTEXT rather than making one, which `contextcheck`
// insisted on and was right about: an arm's ctx is what carries a deadline and
// a cancellation, and a fixture that quietly substitutes `Background` makes
// every arm below unkillable.
//
// **ONE VALID VALUE PER ARGUMENT THE VETTED SCHEMA DECLARES.** This sent
// `{"query":"x"}` to every tool, which was harmless while arguments were
// validated against nothing; since D289 checks them against the vetted
// input_schema, closed, a tool declaring only `name` refuses `query` — correctly.
func (s *mcpStack) call(ctx context.Context, t *testing.T, action string) (*sekizuiv1.CommandResult, error) {
	t.Helper()
	args := map[string]any{"query": "x"}
	spec := s.doc.MCPSpecs["fixture-mcp"]
	for _, tool := range spec.Tools {
		if "mcp."+spec.Server+"."+tool.Name != action {
			continue
		}
		var in struct {
			Properties map[string]any `json:"properties"`
		}
		_ = json.Unmarshal(tool.InputSchema, &in)
		args = map[string]any{}
		for name := range in.Properties {
			args[name] = "x"
		}
	}
	return s.gw.Enforce(ctx, assertedIdentity("agent:dev"),
		&sekizuiv1.Command{Action: action, TargetRef: "fixture-mcp", Args: mustArgs(t, args)})
}

// scrape renders the metrics exposition, so an arm can pin a WHOLE LINE rather
// than a substring (D204's finding: a containment check over a namespaced name
// cannot tell `present` from `present with a prefix glued on`).
func (s *mcpStack) scrape(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if _, err := s.metrics.WriteTo(&b); err != nil {
		t.Fatalf("scraping: %v", err)
	}
	return b.String()
}

// newMCPStack wires the enforcement path the binary wires (D107), around one
// MCP target.
// tune adjusts the gateway config before it is built, for a step that needs a
// component the default rig does not wire — a breaker, say. A variadic option
// rather than a setter on `gateway.Server`, because a test-only export is a
// published symbol whose only caller is a test (archcheck), and this keeps the
// wiring in the fixture where the rest of it lives.
type tune func(*mcpTuning)

// mcpTuning is what a step may adjust about the stack.
//
// **A STRUCT RATHER THAN `func(*gateway.Config)`, because the second knob could
// not be a gateway field.** Step 37 needs the credential cache's TTL — the
// resolver is built from it, so it cannot be reached by editing a config the
// resolver is already inside. Two knobs with two lifetimes is what a struct is
// for, and the alternative was a second variadic, which Go does not allow.
type mcpTuning struct {
	// gw is the gateway config, before `gateway.New` consumes it.
	gw *gateway.Config

	// credOpts configure the credential cache the stack's resolver is built on.
	//
	// **`WithTTL(0)` IS THE ONE THAT MATTERS TODAY**: it makes every command
	// re-resolve, which is how step 37 drives a token refresh without a sleep
	// and without reaching into the cache to fake one.
	credOpts []credential.Option

	// residency is the stack's deployment ceiling (D320), read by the grant
	// engine and the resolver alike; nil is unconstrained, as before. P4 step 8
	// sets it, to prove the MCP target refuses a crossing as the native driver
	// does.
	residency []string
}

func newMCPStack(ctx context.Context, t *testing.T, edit func(*config.Document),
	tunes ...tune) *mcpStack {
	t.Helper()

	rig := newMCPRig(ctx, t, edit)
	doc := rig.doc

	logPath := auditPath(t)
	sink := auditwal.NewJSONLSink(logPath)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Stop(context.WithoutCancel(ctx)) })

	registry := connector.NewRegistry()
	clientPool := pool.New(registry.Build, slog.New(slog.NewTextHandler(io.Discard, nil)))
	driver := mcp.New(doc.MCPSpecs,
		mcp.WithHTTPClient(rig.srv.Client()), mcp.WithPool(clientPool))
	if err := registry.Register(driver); err != nil {
		t.Fatalf("registering the MCP driver: %v", err)
	}
	// **THE NATIVE DRIVER TOO, UNCONDITIONALLY, WHICH IS WHAT THE BINARY DOES.**
	// Step 14 needs one system behind two targets (D52), and a registry carrying
	// only the driver a given step happens to use would model a deployment that
	// does not exist. Registering it changes nothing for a document with no
	// `fullstory` target — a driver with no target is inert.
	if err := registry.Register(fullstory.New(fullstory.WithPool(clientPool))); err != nil {
		t.Fatalf("registering the Fullstory driver: %v", err)
	}
	drivers := registry.Drivers()

	guards := anzen.New(doc.Anzen)

	// **THE PAYLOAD REGISTRY THE BINARY BUILDS (D279, D289).** Absent, every
	// result was withheld — which no MCP step before P3 step 25 asserted on, and
	// which would have hidden whether a vetted data_schema shapes anything.
	payloads, err := schemareg.ForDeployment(doc, drivers)
	if err != nil {
		t.Fatalf("the MCP stack's payload registry: %v", err)
	}

	reg := metrics.New()
	cfg := gateway.Config{
		// THE DOCUMENT'S LENSES, as the binary builds them (D290) — so a step can
		// impose one on an MCP result.
		Lenses:   shin.New(doc.Shin),
		Payloads: payloads,
		Doc:      doc,
		Pool:     clientPool,
		Drivers:  drivers,
		Guards:   guards,
		Metrics:  reg,
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc)),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	tuning := &mcpTuning{gw: &cfg}
	for _, tn := range tunes {
		tn(tuning)
	}

	// **ITS OWN RESOLVER OVER THE RIG'S PROVIDERS, BUILT AFTER THE TUNES.** See
	// `mcpRig.providers` for why the cache must NOT be shared with the rig: the
	// rig resolves eagerly at wiring time, and step 38 depends on the gateway
	// resolving at first command. Built last because `credOpts` shapes the cache
	// the resolver is constructed from, so a tune has to have run first.
	//
	// THE GRANT ENGINE AND CATALOG AFTER THE TUNES TOO, for the same reason:
	// the ceiling a tune sets must be the one value both layers read (D136).
	eng := policy.NewGrantEngine(doc, tuning.residency)
	cat := catalog.New(catalog.Config{Doc: doc, Drivers: drivers, Policy: eng, Guards: guards})
	cfg.Policy, cfg.Catalog = eng, cat
	cfg.Resolver = resolver.NewWithCache(doc, runtime.Profile{}, tuning.residency,
		credential.New(rig.providers, tuning.credOpts...))
	gw := gateway.New(cfg)
	rig.driver = driver
	return &mcpStack{mcpRig: rig, gw: gw, catalog: cat, pool: clientPool, metrics: reg, logPath: logPath}
}

// step8AnUnvettedToolIsNotCallableAndIsReportedAsUnvetted is criterion 7.
//
// **THREE LAYERS, AND EACH ONE IS THE OTHERS' BACKSTOP.** A tool the vendor
// added and no human vetted is (1) refused a grant of its own at BOOT, (2)
// absent from what the catalog advertises under a wildcard grant that does cover
// it lexically, and (3) refused BY THE DRIVER if a call reaches there anyway.
// The third is not redundant: a wildcard grant makes the first two silent — the
// document is legal and the catalog is correct — so the only thing standing
// between an agent naming the tool and the server running it is the driver's own
// refusal.
//
// **AND THE REFUSAL SAYS `unvetted`, NOT `no such action` (D48).** An agent told
// "no such action" about a tool that plainly exists on the server it is talking
// to learns the wrong thing: it will retry, or report the server as broken. The
// truth is that the tool exists and nobody has vetted it, which is a review
// queue item rather than a bug — and it is the supply-chain win made visible.
func step8AnUnvettedToolIsNotCallableAndIsReportedAsUnvetted(t *testing.T) {
	ctx := context.Background()

	// A WILDCARD GRANT, deliberately: `mcp.fixture.*` LEXICALLY covers the
	// unvetted tool, so policy cannot be what refuses it. Anything weaker would
	// prove the grant table works rather than that vetting does.
	stack := newMCPStack(ctx, t, func(d *config.Document) {
		d.Grants = []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "mcp.fixture.*", TargetRef: "fixture-mcp"},
			},
		}}
	})
	stack.up.offer(
		mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")},
		mcp.LiveTool{Name: "exfiltrate", InputSchema: objectSchema("path")},
	)

	// --- 8a: THE CATALOG ADVERTISES THE VETTED TOOL AND ONLY IT (D195) -----
	//
	// The pattern is expanded against what the drivers implement, so an agent is
	// told `mcp.fixture.search` rather than `mcp.fixture.*` — and the tool the
	// vendor added is simply not there. Before D195 this advertised the raw
	// pattern, which tells a model to discover the boundary by hitting refusals.
	resp, err := stack.catalog.Describe(ctx, assertedIdentity("agent:dev"), "")
	if err != nil {
		t.Fatalf("8a: Describe: %v", err)
	}
	var advertised []string
	for _, c := range resp.GetCapabilities() {
		advertised = append(advertised, c.GetAction())
	}
	if !equalStrings(advertised, []string{"mcp.fixture.search"}) {
		t.Errorf("8a: the catalog advertises %v, want exactly [mcp.fixture.search]. A "+
			"wildcard reaching an agent verbatim is a boundary it must discover by "+
			"being refused; an unvetted tool reaching it is worse", advertised)
	}

	// --- 8b: THE CALL IS REFUSED, AND NOTHING REACHES THE SERVER -----------
	//
	// ASSERTED AT THE FAR SIDE, because our own refusal is not evidence that no
	// request was sent (D159). A governance layer that refuses the RESPONSE after
	// making the call has already let the vendor run the tool.
	res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "mcp.fixture.exfiltrate", TargetRef: "fixture-mcp",
		Args: mustArgs(t, map[string]any{"path": "/etc/passwd"}),
	})
	if err != nil {
		t.Fatalf("8b: the refusal arrived as a transport error rather than a result; "+
			"D135 makes every deliberate refusal a CommandResult: %v", err)
	}
	if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Fatal("8b: an UNVETTED tool was called. The vetted spec is the capability " +
			"set (D46), and a vendor adding a tool must not add a capability")
	}
	if called := stack.up.called(); len(called) != 0 {
		t.Errorf("8b: the server received tools/call for %v. The refusal must happen "+
			"before the call, or the tool has already run and Sekizui is refusing the "+
			"answer", called)
	}

	// --- 8c: AND IT IS REPORTED AS UNVETTED, NOT AS MISSING ----------------
	reason := res.GetReason()
	for _, want := range []string{"UNVETTED", "exfiltrate", "fixture"} {
		if !strings.Contains(reason, want) {
			t.Errorf("8c: the refusal does not contain %q: %q", want, reason)
		}
	}
	for _, wrong := range []string{"no such action", "unknown action"} {
		if strings.Contains(strings.ToLower(reason), wrong) {
			t.Errorf("8c: the refusal says %q about a tool the server plainly offers. An "+
				"agent believes the server is broken, or retries; the truth is that a "+
				"human has not vetted it: %q", wrong, reason)
		}
	}
	// THE KIND, not just the prose. A caller acting on `kind` must be told this
	// is a governance refusal rather than a missing route, and the two differ in
	// retryability.
	if got := res.GetKind(); got != fault.KindSpecDrift.String() {
		t.Errorf("8c: the refusal carries kind %q, want %q", got, fault.KindSpecDrift)
	}

	// --- 8d: AND A GRANT OF ITS OWN DOES NOT LOAD (D195) -------------------
	//
	// The layer a wildcard hides. An operator who saw the tool on the server and
	// wrote a grant for it by name gets a boot refusal rather than a capability
	// that is advertised, attempted and refused.
	unvetted := newMCPRig(ctx, t, func(d *config.Document) {
		d.Grants = []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "mcp.fixture.exfiltrate", TargetRef: "fixture-mcp"},
			},
		}}
	})
	err = grantcheck.Validate(unvetted.doc,
		map[string]connector.Driver{mcp.Kind: unvetted.driver})
	if err == nil {
		t.Error("8d: a grant naming an unvetted tool loaded cleanly. The catalog then " +
			"advertises a capability nothing implements, which is the defect D195 " +
			"closed and the reason it was found by probing Describe rather than by " +
			"reading the code")
	} else if !strings.Contains(err.Error(), "mcp.fixture.exfiltrate") {
		t.Errorf("8d: the refusal does not name the action: %v", err)
	}

	r := &run{}
	r.detail(t, "D48/D195: a tool the server offers and no human vetted is absent from "+
		"the catalog under a wildcard that covers it, is refused before any request "+
		"reaches the server, is reported as UNVETTED with kind %s rather than as a "+
		"missing action, and cannot be granted by name at all",
		fault.KindSpecDrift)
}

// answer sets what tools/call returns for one tool (P3 step 25).
func (u *mcpUpstream) answer(tool string, result map[string]any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.results == nil {
		u.results = map[string]map[string]any{}
	}
	u.results[tool] = result
}

// argsFor returns the arguments each call to tool carried, in order.
func (u *mcpUpstream) argsFor(tool string) []map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]map[string]any(nil), u.argsSeen[tool]...)
}
