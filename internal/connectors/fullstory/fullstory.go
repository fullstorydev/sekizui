// Package fullstory is the Fullstory server-side driver — P2's first real
// connector (D189).
//
// **TWO FUNCTIONS, DELIBERATELY.** Server-side events and server-side user
// updates, single-org and single-DC. The multi-org / multi-DC / residency work
// is P4's, which has a phase to itself, and pulling it forward here would defeat
// the point of a cheap first connector (§12 P2). D27 chose Atlassian first
// "because it's 193 lines, not because it's most important" — the criterion was
// CHEAPNESS, to derisk the abstraction early — and Fullstory scoped to two
// functions is comparably cheap while buying two things Atlassian cannot: it
// proves D52's MCP/native coexistence, and it has a real downstream consumer.
//
// **THE SHAPES ARE INHERITED, NOT GUESSED.** `POST /v2/events` and
// `POST /v2/users` are taken from Lexicon's own connector (`lexicon/Fullstory.js`
// `createEvent` and `createUser`), which is the provenance D163 already cites
// for their idempotency classes.
//
// **`Authorization: Basic`, NOT `Bearer`, and the difference matters.** DESIGN
// §12 P2 records `Authorization: Bearer` — correctly, for the MCP endpoint at
// `https://api.fullstory.com/mcp/fullstory`. The SERVER API takes
// `Basic <token>`. Two endpoints on one vendor with two auth schemes is exactly
// the detail a driver written from a summary gets wrong, and D52 puts both paths
// in this phase, so both are written down.
//
// **§4.7.4 CLASS 1: THE CLIENT IS CREDENTIAL-FREE.** One `http.Client`, shared,
// holding nothing; the credential becomes a per-request header inside
// `Target.Use`, which is the cheapest binding and the one `Target.Use` exists
// for. That is what makes one driver instance safe across tenants (D4), and it
// is the claim P2 step 2 exists to falsify rather than confirm.
//
// **THE DATA CENTRE IS CONFIGURATION, NEVER INFERENCE.** Fullstory's API host is
// per-DC — `api.fullstory.com` for NA1, `api.eu1.fullstory.com` for EU1 — and
// this driver reads `Target.BaseURL()` rather than mapping a DC name itself. A
// driver that derived the host would hold deployment topology as driver state,
// which breaks D4, and it would put the EU/US decision somewhere the residency
// ceiling cannot see (§7.1 item 2). An empty base URL is REFUSED.
//
// DESIGN.md references: §4.3.4, §4.7.4, §7.1, §12 P2, D4, D27, D52, D163, D186.
package fullstory

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Kind is the driver kind a target names to reach Fullstory's server API.
//
// `fullstory` rather than `fullstory-api`, even though D52 puts an MCP target in
// front of the same org: the MCP path is a DIFFERENT kind (`mcp`) pointed at a
// Fullstory server, not a variant of this. Naming this one for the vendor and
// that one for the protocol is what keeps the union-aware grant review (§4.9a.8)
// legible — a reviewer sees `fullstory` and `mcp` and knows to check both.
const Kind = "fullstory"

// The two actions, named `<kind>.<verb>` like every other action in the system.
const (
	ActionCreateEvent = "fullstory.create_event"
	ActionUpsertUser  = "fullstory.upsert_user"
)

// Driver is the Fullstory server-side client.
//
// **HOLDS NO CREDENTIALS AND NO PER-TARGET STATE (D4).** The only fields are a
// shared HTTP client and an optional pool, neither of which is per-tenant. That
// is not a coincidence to be preserved by review: P2's stated INVALIDATION
// SIGNAL is a Fullstory that needs per-instance state the `Driver` cannot hold,
// and step 2 is the step that can falsify D4 rather than confirm it.
type Driver struct {
	http *http.Client

	// pool is optional and exists for BREAK-GLASS rather than for performance.
	// CONTRACTS item 35: a driver that pools privately is invisible to
	// revocation — `revoke_credential` evicts the pool, truthfully reports
	// cancelling zero calls, and leaves this driver's connections running on a
	// compromised credential. Going through the pool is what puts in-flight
	// cancellation on the path (D128).
	pool connector.ClientPool

	// testHosts are hosts admitted beyond Fullstory's own (WithHosts) — a test
	// server's, never set by the binary (P3 step 24).
	testHosts map[string]bool
}

// Option configures the driver.
type Option func(*Driver)

// WithHTTPClient substitutes the transport.
//
// THE SEAM THAT MAKES THIS DRIVER TESTABLE WITHOUT AN ACCOUNT, and the reason it
// is an option rather than a parameter: production wiring never sets it, so the
// serving path carries no flag for a test's benefit. Every arm of this driver
// except "the real Fullstory accepts our request" is provable against an
// `httptest.Server` speaking the documented shapes — which is most of what can
// go wrong, and all of what a review cannot catch.
func WithHTTPClient(c *http.Client) Option { return func(d *Driver) { d.http = c } }

// WithHosts admits hosts beyond Fullstory's own — a TEST server's, and nothing
// else; the binary never passes it (P3 step 24). `host:port` admits exactly
// that; a bare hostname admits it on any port, which is what the published
// conformance suite needs, since its servers start after the driver is built.
func WithHosts(hosts ...string) Option {
	return func(d *Driver) {
		if d.testHosts == nil {
			d.testHosts = map[string]bool{}
		}
		for _, h := range hosts {
			d.testHosts[h] = true
		}
	}
}

// WithPool routes calls through the shared client pool, so break-glass can
// cancel them (CONTRACTS 35, D128).
func WithPool(p connector.ClientPool) Option { return func(d *Driver) { d.pool = p } }

// New returns the driver.
func New(opts ...Option) *Driver {
	d := &Driver{}
	for _, o := range opts {
		o(d)
	}
	if d.http == nil {
		// **A DEADLINE ON EVERY OUTBOUND CALL, from the client rather than from
		// hope** (CONTRACTS §5: there is no unbounded wait). The per-command
		// context deadline is the real bound; this is defence in depth for a
		// caller that arrives without one, and it is deliberately generous
		// because the retry policy — not this — is what decides how long a
		// command may take in total.
		d.http = &http.Client{Timeout: 30 * time.Second}
	}
	return d
}

// Compile-time assertion at the DECLARATION rather than in a test, so a
// signature drift shows up here.
var _ connector.Driver = (*Driver)(nil)

func (d *Driver) Kind() string { return Kind }

// Actions returns every action this driver implements: the four P2 built by
// hand and one per documented operation, derived from its contract (D314).
//
// The connector definition-of-done forbids an advertised-but-absent action, and
// this driver's own test calls every one of them.
func (d *Driver) Actions() []connector.ActionSpec {
	out := handActions()
	derived, err := apiActions()
	if err != nil {
		// A contract that does not derive is a build defect the package's
		// tests fail on; the four hand-built actions still serve.
		return out
	}
	for _, a := range derived {
		out = append(out, a.spec)
	}
	return out
}

// handActions are the four actions P2 built by hand, whose shapes grants,
// lenses and signed steps name.
func handActions() []connector.ActionSpec {
	return []connector.ActionSpec{
		{
			Name:       ActionCreateEvent,
			Mutating:   true,
			OutputType: WriteResultType,
			// **CLASS `none`, AND THIS IS THE ACTION P2's HEADLINE WRITE FALLS
			// INTO.** `POST /v2/events` documents `name`, `timestamp`,
			// `properties`, `user.uid` and `session.id` and offers no dedupe of
			// any kind — no idempotency header, no client-supplied event id. So a
			// retried timeout would duplicate the event, and the retry is REFUSED
			// with its reason rather than risked (D163, D182).
			Idempotency: connector.IdempotencyNone,
			InputSchema: "sekizui://schema/fullstory/create_event.v1",
			Description: "Record a server-side custom event against a user or session. " +
				"The upstream cannot deduplicate, so a timed-out call is never retried.",
		},
		{
			Name:       ActionUpsertUser,
			Mutating:   true,
			OutputType: WriteResultType,
			// **CLASS `natural`: create-or-update keyed on `uid`.** Replaying it
			// converges on the same state, so it needs no key at all — and it is
			// what makes D163's classification demonstrably do WORK rather than
			// refuse everything. Two actions, one vendor, opposite answers, which
			// is why the classification is per ACTION and a per-driver field
			// would have been wrong on its first connector.
			Idempotency: connector.IdempotencyNatural,
			InputSchema: "sekizui://schema/fullstory/upsert_user.v1",
			Description: "Create or update a user by `uid`. Repeat-safe by construction.",
		},
		{
			// THE READ-BACK (D270): a POST that reads, so non-mutating and
			// served by Query. One row per event, with its properties, so a
			// governed write's run stamp can be found again.
			Name:     ActionSessionEvents,
			Mutating: false,
			// UP TO 200 EVENTS, the caller choosing fewer through event_limit
			// (D283): the gateway prices the read before it is sent.
			Bound: &connector.ResultBound{MaxRows: maxSessionEvents, Arg: "event_limit",
				Default: defaultSessionEvents},
			InputSchema: "sekizui://schema/fullstory/session_events.v1",
			OutputType:  SessionEventType,
			Description: "Read a session's most recent events (POST /v2/sessions/{id}/context), " +
				"server-side custom events included.",
		},
		{
			// THE AFFERENT HALF (D265): an advertised action, not a governed
			// verb, so a grant names it like any other and the catalog says
			// which targets are pollable — kata.poll's reasoning.
			Name:        ActionPoll,
			Mutating:    false,
			InputSchema: "sekizui://schema/fullstory/poll.v1",
			OutputType:  SessionType,
			// THE OTHER SHAPE THIS POLL CAN YIELD (D276): a target with `poll:
			// events` emits session events. Declared, so boot requires its
			// schema and the runner refuses anything else.
			OutputTypes: []string{SessionEventType},
			Description: "Poll one user's sessions (GET /sessions/v2) — or, on a target with " +
				"`poll: events`, their events as fullstory.session_event.v1 (Generate Context by " +
				"TIMESTAMP window). The afferent path; not routed through Query.",
		},
	}
}

// endpoints maps an action to its path under the API version.
//
// ONE TABLE RATHER THAN A SWITCH IN Execute, so `Actions` and the paths cannot
// disagree about which actions exist — `TestEveryActionHasAnEndpoint` ranges the
// specs and fails on a gap (§15q).
//
//nolint:gochecknoglobals // immutable lookup table, fixed at compile time
var endpoints = map[string]endpoint{
	ActionCreateEvent: epCreateEvent,
	ActionUpsertUser:  epUpsertUser,
}

// Execute performs one of the two mutating actions.
func (d *Driver) Execute(ctx context.Context, t connector.Target, action string,
	args map[string]any, idem connector.Idempotency) (connector.Result, error) {

	const op = "fullstory.Execute"
	started := time.Now()

	spec, err := d.spec(op, action)
	if err != nil {
		return connector.Result{}, err
	}
	// A DERIVED ACTION (D314): a write goes through the generic path; a read is
	// refused here so the read and write planes stay distinguishable.
	if a, derived := apiActionFor(action); derived {
		if !a.spec.Mutating {
			return connector.Result{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"%q is a read; call it through Query", action))
		}
		data, err := d.callAPI(ctx, op, t, a, args)
		if err != nil {
			return connector.Result{}, err
		}
		return connector.Result{Data: data}, nil
	}
	// A POLL IS SERVED BY Poll, NEVER BY Execute (D265). It is advertised so a
	// grant can name it and the catalog can say what polling yields; without
	// this refusal, Execute would find it in Actions, miss it in the endpoint
	// table, and POST to the API root — which TestEveryActionHasAnEndpoint
	// exists to make impossible.
	if _, executable := endpoints[spec.Name]; !executable {
		return connector.Result{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"%q is not executable: it is a read, served by Poll (a job or a schedule) or by "+
				"Query, never by Execute", action))
	}

	// PLACE THE KEY AND VERIFY IT SURVIVED (D163, D186). Both classes here need
	// no placement — `none` has nowhere to put a key and `natural` needs none —
	// so this is a no-op today and is called anyway: the driver must not be the
	// place where a future `header`-class action silently skips its own
	// guarantee, and D186 moved both operations into pkg/connector precisely so
	// every driver inherits them rather than remembering them.
	body, headers, err := idem.PlaceIn(op, spec.Mutating, args)
	if err != nil {
		return connector.Result{}, err
	}
	if err := idem.Verify(op, body, headers); err != nil {
		return connector.Result{}, err
	}

	// §6 MECHANISM 3: assert the request's tenant against the target's,
	// immediately before the outbound call. Nanoseconds, and it is the only thing
	// that catches a pooled client belonging to the wrong tenant — a substitution
	// the constructor cannot see, because it happens in the pool after
	// construction.
	if err := connector.AssertTenant(ctx, t); err != nil {
		return connector.Result{}, err
	}

	var res connector.Result
	work := func(ctx context.Context, _ any) error {
		var callErr error
		res, callErr = d.post(ctx, op, t, endpoints[action], body, headers)
		return callErr
	}

	if d.pool == nil {
		// No pool wired: still correct, still governed, and NOT reachable by
		// break-glass. Explicit rather than silent, because "the driver worked"
		// and "the driver was reachable by revocation" must not look the same
		// (CONTRACTS 35).
		if err := work(ctx, nil); err != nil {
			return connector.Result{}, err
		}
	} else if err := d.pool.Do(ctx, t, work); err != nil {
		return connector.Result{}, err
	}

	res.Latency = time.Since(started)
	return res, nil
}

// Query REFUSES, because this driver has no read action.
//
// **D53's RULE: RUN OR REFUSE, NEVER SILENTLY SUCCEED AT NOTHING.** Returning an
// empty `Rows` would be the recurring defect in its purest form — an agent
// reasoning over zero rows reaches confident wrong conclusions, and the
// truncation flag exists to prevent exactly that hazard arriving through a
// different door. P2's scope is two MUTATING functions; a read lands with the
// phase that needs one.
func (d *Driver) Query(ctx context.Context, t connector.Target, action string,
	args map[string]any) (connector.Rows, error) {

	if action == ActionSessionEvents {
		return d.sessionEvents(ctx, t, args)
	}
	// A DERIVED READ (D314): the response object is the one row.
	if a, derived := apiActionFor(action); derived {
		if a.spec.Mutating {
			return connector.Rows{}, fault.New(fault.KindInvalidArgument, "fullstory.Query", fmt.Sprintf(
				"%q writes; call it through Execute", action))
		}
		data, err := d.callAPI(ctx, "fullstory.Query", t, a, args)
		if err != nil {
			return connector.Rows{}, err
		}
		if data == nil {
			return connector.Rows{}, nil
		}
		return connector.Rows{Rows: []map[string]any{data}}, nil
	}
	// THE ONE READ IS session_events (D270); the poll is served by Poll.
	// Anything else is refused rather than answered empty, which would let an
	// agent conclude the account is empty.
	return connector.Rows{}, fault.New(fault.KindNotFound, "fullstory.Query", fmt.Sprintf(
		"%q is not a read this driver implements; its one query is %s", action, ActionSessionEvents))
}

// Health reports whether the target is reachable.
//
// **IT DOES NOT GUESS.** Fullstory documents no health endpoint, and the two
// dishonest options are both available: return nil and claim health nobody
// checked, or probe a real endpoint and spend the customer's quota on
// bookkeeping. Neither is acceptable, so this validates what it CAN — that the
// target is configured well enough for a call to be attempted — and says
// plainly that it is not a reachability check.
//
// The distinction is D48's, one layer down: "unreachable" and "misconfigured"
// must never collapse into one signal, because one is an availability event and
// the other needs a human to edit something.
func (d *Driver) Health(_ context.Context, t connector.Target) error {
	const op = "fullstory.Health"

	if _, err := d.base(op, t); err != nil {
		return err
	}
	// A CONFIGURATION CHECK REPORTED AS SUCCESS, and the doc comment above is
	// where that is disclosed. When the panel's target-health view lands (§4.8)
	// it will want a real probe, and the honest place to decide what to spend on
	// one is when somebody is looking at it.
	return nil
}

// post makes the one outbound call.
func (d *Driver) post(ctx context.Context, op string, t connector.Target,
	ep endpoint, body, headers map[string]any) (connector.Result, error) {

	base, err := d.base(op, t)
	if err != nil {
		return connector.Result{}, err
	}

	payload, err := json.Marshal(body)
	if err != nil {
		// A payload protobuf could carry and JSON cannot is a caller problem, not
		// an upstream one — and it must be classified, or it surfaces as
		// `unknown` and the metric loses the distinction (fault.KindOf).
		return connector.Result{}, fault.Wrap(fault.KindInvalidArgument, op,
			"the arguments cannot be encoded as JSON", err)
	}

	req, err := http.NewRequestWithContext(ctx, ep.method,
		base+ep.path(), bytes.NewReader(payload))
	if err != nil {
		return connector.Result{}, fault.Wrap(fault.KindInvalidArgument, op,
			"building the request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		if s, ok := value.(string); ok {
			req.Header.Set(name, s)
		}
	}

	// **THE CREDENTIAL IS LENT FOR THE DURATION OF THE HEADER BUILD, NOT HELD
	// (D127), AND THE PLACEMENT IS THE BROKER'S RATHER THAN THIS DRIVER'S
	// (D199).** `Use` holds the credential's read lock across the callback, so a
	// concurrent revocation waits rather than zeroing memory somebody is reading
	// — the data race that can produce a partially-valid credential (§4.7.10).
	// This driver used to write that closure itself, as did two others; one
	// helper means the lending discipline cannot drift between them, and it is
	// where material that cannot BE a header value is refused as a
	// configuration fault rather than surfacing as an unreachable target.
	if err := connector.SetAuthorization(req.Header, t, "Basic"); err != nil {
		return connector.Result{}, fault.Wrap(fault.KindUnauthenticated, op,
			"the target's credential could not be borrowed", err)
	}

	resp, err := d.http.Do(req)
	if err != nil {
		return connector.Result{}, transportFault(op, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// BOUNDED READ. An upstream response is attacker-influenceable in the same
	// sense a driver result is (D178): it reaches the audit detail, the WAL and
	// an fsync, so an unbounded read here is a write amplifier aimed at
	// Sekizui's own disk. safestruct bounds the object later; this bounds the
	// bytes before they exist.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return connector.Result{}, fault.Wrap(fault.KindTargetUnavailable, op,
			"reading the response body", err)
	}

	if resp.StatusCode >= 300 {
		return connector.Result{}, upstreamFault(op, resp, raw)
	}

	// 204 NO CONTENT IS A SUCCESS WITH NOTHING TO SAY, which Fullstory returns
	// for some writes. An empty Data map is correct here and is not the D53 case
	// the Query refusal is about: the call happened and the upstream reported it.
	data := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &data); err != nil {
			// THE FAR SIDE WAS REACHED AND ANSWERED SOMETHING WE CANNOT READ,
			// which is KindTargetError rather than KindTargetUnavailable — D48's
			// distinction: we learned something specific, and it was bad.
			return connector.Result{}, fault.Wrap(fault.KindTargetError, op, fmt.Sprintf(
				"the upstream returned %d with a body that is not JSON", resp.StatusCode), err)
		}
	}

	return connector.Result{
		ExternalRef: externalRef(data),
		StatusCode:  resp.StatusCode,
		Data:        data,
	}, nil
}

// maxResponseBytes bounds one upstream response.
//
// 1 MiB, which is orders of magnitude above any documented response from these
// two endpoints and still far below what would matter to the audit WAL. A
// truncated body surfaces as a JSON parse failure classified `target_error`,
// which is the honest reading: we were answered and could not understand it.
const maxResponseBytes = 1 << 20

// base returns the target's API host, refusing rather than guessing.
func (d *Driver) base(op string, t connector.Target) (string, error) {
	raw := strings.TrimRight(t.BaseURL(), "/")
	if raw == "" {
		return "", fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q declares no base_url. Fullstory's API host is PER DATA CENTRE — "+
				"https://api.fullstory.com for NA1, https://api.eu1.fullstory.com for EU1 — "+
				"and this driver will not infer it: deriving the host would hold deployment "+
				"topology as driver state (D4) and put the EU/US choice where the residency "+
				"ceiling cannot see it (§7.1 item 2)", t.Ref()))
	}
	if err := d.AdmitBaseURL(t.Ref(), raw); err != nil {
		return "", err
	}
	return raw, nil
}

// apiHosts are Fullstory's documented API hosts, one per data centre. The
// P3 slice takes these and nothing else (P3 step 24, D239).
var apiHosts = map[string]bool{"api.fullstory.com": true, "api.eu1.fullstory.com": true} //nolint:gochecknoglobals // immutable

var _ connector.HostBound = (*Driver)(nil)

// AdmitBaseURL refuses a base_url that is not https to one of Fullstory's own
// API hosts (connector.HostBound, P3 step 24).
//
// **THE CREDENTIAL GOES WHERE THIS POINTS**, as the Authorization header of
// every call — so a target naming any other host sent the org's key there, on
// a poll's cadence (CONTRACTS 117). Checked at boot and on every call. Exact
// host match on the PARSED URL, so `https://api.fullstory.com@elsewhere` — whose
// host is `elsewhere` — is refused, and a non-default port is refused too.
//
// **ONE TARGET IS ONE ORG IN ONE DATA CENTRE**, by construction: one host, one
// credential. Multi-org and multi-DC tenancy are P4's question (D239), and
// nothing here half-serves them.
func (d *Driver) AdmitBaseURL(targetRef, raw string) error {
	const op = "fullstory.AdmitBaseURL"
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q has base_url %q, which is not an https URL with a host. Plaintext "+
				"would put the credential on the wire in clear", targetRef, raw))
	}
	if parsed.User != nil {
		// NOT WHAT IT LOOKS LIKE, OR MATERIAL IN CONFIGURATION. `a@b` names host
		// b — refused by the host rule anyway — and `user:secret@<real host>`
		// puts a credential in the config file, which §4.7 forbids.
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q has a base_url carrying userinfo; configuration carries references, "+
				"never material (§4.7), and the host it names is %q", targetRef, parsed.Host))
	}
	if (apiHosts[parsed.Host] && parsed.Port() == "") || d.testHosts[parsed.Host] ||
		d.testHosts[parsed.Hostname()] {
		return nil
	}
	return fault.New(fault.KindConfig, op, fmt.Sprintf(
		"target %q has base_url %q; a Fullstory target must name one of Fullstory's API hosts "+
			"(https://api.fullstory.com for NA1, https://api.eu1.fullstory.com for EU1). Its "+
			"credential is sent to this host on every call, so any other host would receive "+
			"the org's key (P3 step 24, CONTRACTS 117)", targetRef, raw))
}

// spec returns the ActionSpec for a declared action, or refuses.
func (d *Driver) spec(op, action string) (connector.ActionSpec, error) {
	for _, s := range d.Actions() {
		if s.Name == action {
			return s, nil
		}
	}
	return connector.ActionSpec{}, fault.New(fault.KindNotFound, op, fmt.Sprintf(
		"this driver does not implement %q; it implements every operation its reference "+
			"revision %s documents that no decision excluded", action, referenceRevision))
}

// WriteResultType is what a Fullstory write returns into Sekizui (D283): the
// identifiers an audit row joins on, and nothing else the vendor echoes.
const WriteResultType = "fullstory.write_result.v1"

// externalRef pulls the upstream's own identifier out of a response, so the
// audit trail joins to Fullstory's record of the same action (§5.4).
//
// **BEST EFFORT, AND EMPTY WHEN THERE IS NOTHING TO TAKE.** Inventing a
// reference would be worse than having none: the audit row would carry an
// identifier that resolves nowhere, and a human reconciling an indeterminate
// outcome (D182) would spend the search believing we knew something. The keys
// are tried in the order Fullstory's two endpoints use them.
func externalRef(data map[string]any) string {
	for _, key := range []string{"id", "uid", "event_id", "user_id"} {
		if s, ok := data[key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// transportFault classifies a failure that never got an HTTP response.
//
// THE TIMEOUT CASE IS THE ONE THAT MATTERS, because D182 makes it indeterminate:
// a `none`-class write that times out may or may not have landed, and reporting
// it as merely unavailable would tell a caller the write did not happen.
func transportFault(op string, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return fault.Wrap(fault.KindTimeout, op,
			"the call to Fullstory did not answer before its deadline", err)
	default:
		// Connection refused, DNS failure, TLS failure. We learned nothing about
		// the target except that it is not answering (KindTargetUnavailable's own
		// contract), which D182 treats as indeterminate for a write.
		return fault.Wrap(fault.KindTargetUnavailable, op,
			"Fullstory could not be reached", err)
	}
}

// upstreamFault maps an HTTP status onto the shared taxonomy.
//
// **THE CONNECTOR DEFINITION-OF-DONE REQUIRES THIS, and it is the item most
// easily skipped**: a driver that returns `fmt.Errorf("fullstory: %d", status)`
// works, passes review, and destroys every downstream decision. `Retryable`,
// `Deliberate`, `Indeterminate`, the gRPC code, the wire status and the metric
// label are all derived from the KIND, so an unclassified upstream failure is
// `unknown` — which the breaker counts as a failure, the retry policy refuses to
// retry, and the operator cannot act on.
//
// TOTAL OVER STATUS CLASSES rather than over the codes Fullstory happens to
// document today, because a vendor adding a status must not fall through to
// something silently wrong.
func upstreamFault(op string, resp *http.Response, raw []byte) error {
	msg := upstreamMessage(resp, raw)

	kind := fault.KindTargetError
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		// OUR REQUEST WAS WRONG. Deliberate, so D135 carries it to the caller as
		// a result it can act on rather than as a transport error.
		kind = fault.KindInvalidArgument
	case http.StatusUnauthorized:
		// THE CREDENTIAL, not the grant. Distinct from Denied because the remedy
		// is completely different — rotate a key versus review a capability —
		// and §7.1's argument is that an operator should not have to infer which.
		//
		// **AND THE REMEDY IS ONE SEKIZUI CAN APPLY ITSELF (D203).** The far side
		// read a credential we sent and rejected it, so a fresh mint may fix it —
		// the one producer of `unauthenticated` where that is true. The borrow
		// failure above returns the same kind and deliberately does not set this:
		// re-minting a credential that cannot be PLACED returns the same bad
		// bytes (D199), and re-minting after break-glass fetches material an
		// operator just wiped.
		//
		// The second attempt is a whole re-traversal of the enforcement path
		// (D204), so this cannot outrun a revocation, a budget or a breaker.
		return fault.CredentialRejected(op, msg)
	case http.StatusForbidden:
		kind = fault.KindDenied
	case http.StatusNotFound:
		kind = fault.KindNotFound
	case http.StatusConflict:
		kind = fault.KindConflict
	case http.StatusTooManyRequests:
		// THE UPSTREAM'S OWN NUMBER GOES BACK TO THE LIMITER (D14, §5.2.1). Being
		// told 429 means the local model was optimistic, and a limiter that only
		// predicts stays wrong for the rest of the window.
		return &fault.Error{
			Kind: fault.KindRateLimited, Op: op, Msg: msg,
			RetryAfter: retryAfter(resp.Header.Get("Retry-After")),
		}
	default:
		switch {
		case resp.StatusCode >= 500:
			// Reached and broke. Retryable AND indeterminate (D182): it may have
			// applied the write before failing.
			kind = fault.KindTargetError
		case resp.StatusCode >= 400:
			kind = fault.KindInvalidArgument
		}
	}
	return fault.New(kind, op, msg)
}

// upstreamMessage prefers the vendor's own explanation over its status text.
//
// BOUNDED, because the message reaches the audit record and a hostile upstream
// should not choose how much of Sekizui's disk it uses (D178).
func upstreamMessage(resp *http.Response, raw []byte) string {
	var body struct {
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	_ = json.Unmarshal(raw, &body)

	said := body.Message
	if said == "" {
		said = body.Detail
	}
	if said == "" {
		said = resp.Status
	}
	if len(said) > maxMessageBytes {
		said = said[:maxMessageBytes] + "… (truncated)"
	}
	return fmt.Sprintf("Fullstory returned %d: %s", resp.StatusCode, said)
}

// maxMessageBytes bounds the vendor text carried into a decision record.
const maxMessageBytes = 512

// retryAfter parses the header, tolerating both forms the RFC allows.
//
// **CAPPED BY THE RETRY POLICY, NOT HERE** (§4.3.4): a `Retry-After: 3600` from
// a misconfigured proxy must not park a command for an hour, and the cap is the
// operator's statement about how long a single wait may be. Honouring it exactly
// would let an upstream set Sekizui's latency budget — so this reports what was
// said and `retry.backoff` decides what to do about it.
func retryAfter(header string) time.Duration {
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(header); err == nil {
		if d := time.Until(at); d > 0 {
			return d
		}
	}
	return 0
}

// schemasYAML is this connector's data schemas (D279), shipped with the code
// that emits the data so the two cannot be deployed apart.
//
//go:embed schemas.yaml
var schemasYAML []byte

// Schemas returns the schema of every type this connector's actions declare
// (D279). The connector owns what may enter; the deployment lenses it.
func (d *Driver) Schemas() ([]connector.Schema, error) {
	hand, err := connector.ParseSchemas(schemasYAML)
	if err != nil {
		return nil, err
	}
	derived, err := apiSchemas()
	if err != nil {
		return nil, err
	}
	return append(hand, derived...), nil
}

// reflexesYAML is this connector's refines rules (D299), shipped beside the
// schemas their seiren type lives in. AVAILABLE, not imposed: nothing here reaches
// a caller until a deployment's `refinements:` names a rule.
//
//go:embed reflexes.yaml
var reflexesYAML []byte

// Reflexes makes the driver a connector.Refiner (D317).
func (d *Driver) Reflexes() []byte { return reflexesYAML }

// Meter declares Fullstory's meter (D284): CALLS, one per request.
//
// **NO DEFAULT OF ITS OWN, AND THAT IS THE HONEST ANSWER.** Fullstory's
// published limits page says per-second and burst limits exist and that a 429
// carries `Retry-After`, and gives no number; the one figure in circulation is
// from a community thread. A default is vendor knowledge (D67), and a number
// nobody published is not knowledge — so a Fullstory target without
// `rate_per_hr` takes the deployment's universal calls default. Whoever finds
// a documented figure sets DefaultPerHour here, citing it.
//
// A poll is priced by what the target makes it do: one list for sessions, one
// list plus one context read per session for events.
func (d *Driver) Meter() connector.Meter {
	return connector.Meter{Unit: connector.UnitCalls, PollCost: pollCost}
}
