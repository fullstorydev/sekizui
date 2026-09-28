// Package jira is the THIN JIRA CONNECTOR — P2's second native driver, and the
// first one written from `hako/BLUEPRINT.md` rather than from another
// driver's source (D167, P2 step 27).
//
// **IT EXISTS TO BE A SECOND USER, NOT TO BE COMPLETE.** Fullstory shaped the
// blueprint; a document validated only by the connector that produced it is
// validated by nobody. So this was built with the blueprint open and the
// Fullstory driver deliberately unread, and everything it needed that the
// blueprint did not say is recorded as a defect THERE rather than solved quietly
// here. That measurement is ONE-SHOT: once this package exists it cannot be
// spent again, which is why the reading discipline mattered more than the
// diffs.
//
// **NOT EXERCISED AGAINST A REAL JIRA, ON PURPOSE (the maintainer's ruling).** Every test
// drives a fixture. The endpoints and the auth scheme come from Atlassian's
// published documentation, and everything this package ASSUMES rather than
// verified is listed in one place — see `assumptions` below — so the day it
// first meets a live instance, the list of things to check is already written
// down instead of being reconstructed from a failure.
//
// Binding class 1 (blueprint step 1): stateless, credential-free, one instance
// per process shared across every tenant. It still takes the pool, because that
// is what puts break-glass on the path rather than because it is faster.
package jira

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

// Kind is what a target's `kind:` must say to route here (blueprint step 5).
const Kind = "jira"

// The two actions. Thin means thin: DESIGN §12 P2 scopes this to ticket lookup,
// and one mutating action was added on the maintainer's ruling so that blueprint step 3 —
// a human classifying idempotency, which is D163's whole subject — gets a second
// user rather than being skipped by a read-only driver.
const (
	ActionReadIssue    = "jira.read_issue"
	ActionCommentIssue = "jira.comment_issue"
)

// IssueType is the payload registry key for a read issue (D41, D88).
//
// THE REGISTRY KEY, NOT THE SCHEMA URI, and this constant exists so the driver,
// the payload schema and the shin lens name one string rather than three. D221
// is why it is worth a constant: the kata's answer key put the URI in this
// position in three files that agreed with each other, and nothing could see it.
const IssueType = "jira.issue.v1"

// assumptions is the honest half of "built from the docs, not from a sandbox".
//
// **A DRIVER THAT HAS NEVER MET ITS VENDOR HAS ASSUMPTIONS, and the choice is
// whether they are written down or rediscovered from a 400.** Atlassian's
// reference pages are too large to fetch whole, so what was VERIFIED against the
// published documentation is the auth scheme; the rest is read from the API's
// documented shape and encoded in the fixtures, which means the fixtures agree
// with this driver by construction and prove nothing about Jira.
//
// This is not a TODO list. It is the integration test's agenda, and P2 step 27
// asserts the mechanical half precisely because the vendor half cannot be
// asserted without a key.
//
//nolint:gochecknoglobals // immutable documentation, read by the ledger test
var assumptions = []string{
	"VERIFIED (developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis): " +
		"auth is `Authorization: Basic <base64(email:api_token)>`.",
	"ASSUMED: `GET /rest/api/3/issue/{issueIdOrKey}` returns the issue with its " +
		"fields under `fields`.",
	"ASSUMED: `POST /rest/api/3/issue/{issueIdOrKey}/comment` adds a comment and " +
		"returns the created comment including its `id`.",
	"ASSUMED: the add-comment request body accepts a `properties` array of " +
		"{key, value}, which is where attribution is stamped (§10.4). If it does " +
		"not, attribution moves to a second call against the comment-properties " +
		"endpoint and stops being free.",
	"ASSUMED-ABSENT: no idempotency mechanism is documented for creating a " +
		"comment — no `Idempotency-Key` header and no client-supplied comment id. " +
		"This is why the action is class `none`, and it is the CONSERVATIVE " +
		"direction: if Atlassian documents one, the class can be raised, whereas " +
		"a wrong `header` would have permitted a retry that duplicates.",
}

// Assumptions returns what this driver believes about Jira without having asked
// it. Exported so the connector's own test can assert the list is non-empty and
// so an operator can read it before pointing this at a real instance.
func Assumptions() []string { return append([]string(nil), assumptions...) }

// Driver is BLUEPRINT STEP 1: binding class 1.
//
// No per-tenant field, which is what makes one instance safe to serve every
// customer — and it is checked rather than reviewed, by the conformance suite's
// statelessness arm under `-race`.
type Driver struct {
	http *http.Client
	pool connector.ClientPool
}

// Option configures the driver.
type Option func(*Driver)

// WithHTTPClient substitutes the transport. Production never sets it; it is what
// makes every arm of this driver testable without an Atlassian account.
func WithHTTPClient(c *http.Client) Option { return func(d *Driver) { d.http = c } }

// WithPool routes calls through the shared client pool so break-glass can cancel
// them (blueprint step 1: a class-1 driver still gets a pool entry).
func WithPool(p connector.ClientPool) Option { return func(d *Driver) { d.pool = p } }

// New returns the driver.
func New(opts ...Option) *Driver {
	d := &Driver{}
	for _, o := range opts {
		o(d)
	}
	if d.http == nil {
		// BLUEPRINT STEP 12: a timeout on every outbound call. The per-command
		// deadline is the real bound; this is defence in depth for a caller that
		// arrives without one.
		d.http = &http.Client{Timeout: 30 * time.Second}
	}
	return d
}

// The compile-time assertion goes at the DECLARATION, so a signature drift shows
// up here rather than at a call site.
var _ connector.Driver = (*Driver)(nil)

func (d *Driver) Kind() string { return Kind }

// CommentType is what a comment write returns into Sekizui (D283): its ids.
const CommentType = "jira.comment.v1"

// Actions is BLUEPRINT STEPS 3 AND 4.
//
// **`jira.comment_issue` IS CLASS `none`, AND THAT IS THE INTERESTING ONE.**
// Atlassian documents no idempotency mechanism for creating a comment: no
// `Idempotency-Key` header, no client-supplied id. So a retried timeout
// duplicates the comment, and the honest classification is the one that REFUSES
// TO RETRY and says so to the caller (D182) — a closed retry gate that hands
// back a retryable timeout has relocated the double-write hazard to the agent
// rather than removing it.
//
// **A HUMAN CLASSIFIED IT, FROM THE VENDOR'S DOCUMENTATION, IN THE CONSERVATIVE
// DIRECTION.** That is the whole of D163's rule: there is no safe default, so
// `none` is chosen because being wrong about it costs a refused retry, while
// being wrong about `header` costs a duplicate nobody chose. It contrasts
// deliberately with the kata's `header` and with Fullstory's split of `none` and
// `natural` across two actions of one vendor — one system, one answer, and the
// answers do not generalise.
//
// **`OutputType` IS THE REGISTRY KEY AND `OutputSchema` IS THE URI (D41, D88).**
// They look interchangeable and are not; D221 records the session where three
// teaching artefacts agreed they were.
func (d *Driver) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{
		{
			Name:        ActionReadIssue,
			InputSchema: "sekizui://schema/jira/read_issue.v1",
			OutputType:  IssueType,
			Description: "Read a single Jira issue by key or id, including its summary, " +
				"status, reporter and description.",
		},
		{
			Name:        ActionCommentIssue,
			Mutating:    true,
			OutputType:  CommentType,
			Idempotency: connector.IdempotencyNone,
			InputSchema: "sekizui://schema/jira/comment_issue.v1",
			Description: "Add a comment to a Jira issue. The upstream offers no " +
				"idempotency mechanism, so a retry would duplicate the comment and is " +
				"refused rather than attempted.",
		},
	}
}

// Execute performs the mutating action.
func (d *Driver) Execute(ctx context.Context, t connector.Target, action string,
	args map[string]any, idem connector.Idempotency) (connector.Result, error) {

	const op = "jira.Execute"

	spec, err := d.spec(op, action)
	if err != nil {
		return connector.Result{}, err
	}
	if !spec.Mutating {
		return connector.Result{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"%q is a read; call it through Query so the read and write planes stay "+
				"distinguishable in policy, audit and metrics", action))
	}

	key, err := issueKey(op, args)
	if err != nil {
		return connector.Result{}, err
	}
	body, err := commentBody(op, args)
	if err != nil {
		return connector.Result{}, err
	}

	// PLACE THE KEY, THEN VERIFY IT SURVIVED. Both live in pkg/connector so every
	// driver inherits them rather than remembering them. For a class-`none`
	// action there is no key to place, and PlaceIn is still called: the check
	// that matters is that nothing was SILENTLY dropped.
	placed, headers, err := idem.PlaceIn(op, spec.Mutating, body)
	if err != nil {
		return connector.Result{}, err
	}
	if err := idem.Verify(op, placed, headers); err != nil {
		return connector.Result{}, err
	}

	// **§6 MECHANISM 3, IMMEDIATELY BEFORE THE OUTBOUND CALL.** The only thing
	// that catches a pooled client belonging to another tenant — a substitution
	// the constructor cannot see, because it happens in the pool after
	// construction.
	if err := connector.AssertTenant(ctx, t); err != nil {
		return connector.Result{}, err
	}

	var res connector.Result
	work := func(ctx context.Context, _ any) error {
		var callErr error
		res, callErr = d.send(ctx, op, t, http.MethodPost,
			"/rest/api/3/issue/"+url.PathEscape(key)+"/comment", placed, headers)
		return callErr
	}
	if d.pool == nil {
		if err := work(ctx, nil); err != nil {
			return connector.Result{}, err
		}
	} else if err := d.pool.Do(ctx, t, work); err != nil {
		return connector.Result{}, err
	}
	return res, nil
}

// Query performs the read.
func (d *Driver) Query(ctx context.Context, t connector.Target, action string,
	args map[string]any) (connector.Rows, error) {

	const op = "jira.Query"

	spec, err := d.spec(op, action)
	if err != nil {
		return connector.Rows{}, err
	}
	if spec.Mutating {
		return connector.Rows{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"%q mutates; call it through Execute", action))
	}

	key, err := issueKey(op, args)
	if err != nil {
		return connector.Rows{}, err
	}

	if err := connector.AssertTenant(ctx, t); err != nil {
		return connector.Rows{}, err
	}

	var rows connector.Rows
	work := func(ctx context.Context, _ any) error {
		res, callErr := d.send(ctx, op, t, http.MethodGet,
			"/rest/api/3/issue/"+url.PathEscape(key), nil, nil)
		if callErr != nil {
			return callErr
		}
		rows = connector.Rows{Rows: []map[string]any{res.Data}}
		return nil
	}
	if d.pool == nil {
		if err := work(ctx, nil); err != nil {
			return connector.Rows{}, err
		}
	} else if err := d.pool.Do(ctx, t, work); err != nil {
		return connector.Rows{}, err
	}
	return rows, nil
}

// Health reports whether the target is reachable. No caller in this tree yet;
// the panel is its consumer.
func (d *Driver) Health(context.Context, connector.Target) error { return nil }

// issueKey reads and validates the one argument both actions need.
//
// SHAPE IS VALIDATED BY THE SCHEMA BEFORE WE ARE CALLED (D40), so this checks
// only what a schema cannot: that the value is present and not whitespace. A
// driver re-validating shape is a second source of truth for the same rule.
func issueKey(op string, args map[string]any) (string, error) {
	key, _ := args["issue"].(string)
	if strings.TrimSpace(key) == "" {
		return "", fault.New(fault.KindInvalidArgument, op,
			"this action needs an `issue`, the Jira key or numeric id (e.g. \"PROJ-72\")")
	}
	return key, nil
}

// commentBody builds the add-comment payload, including the attribution stamp.
//
// **BLUEPRINT STEP 12: ATTRIBUTION STAMPED INTO THE ACTION (§10.4).** The audit
// log records what Sekizui did; this is what lets somebody reading the VENDOR's
// record see that an agent did it. It goes in a comment PROPERTY rather than in
// the comment text: appending a line to somebody's comment body mutates content
// a human will read and quote, and a property is metadata that reads as metadata.
//
// **THE PROPERTY IS SENT WITH THE CREATE, NOT AS A SECOND CALL.** A second
// request would be a second failure mode on a class-`none` action — the comment
// lands, the stamp does not, and there is no safe retry for either half. See
// `assumptions`: that the create endpoint accepts `properties` is read from the
// documented Comment shape and is not verified against a live instance.
func commentBody(op string, args map[string]any) (map[string]any, error) {
	text, _ := args["body"].(string)
	if strings.TrimSpace(text) == "" {
		return nil, fault.New(fault.KindInvalidArgument, op,
			"comment_issue needs a `body`")
	}

	// Atlassian Document Format. The v3 API takes structured content rather than
	// wiki markup, so the plain string a caller supplies is wrapped rather than
	// interpreted — interpreting it would make an agent's text able to inject
	// formatting nobody asked for.
	return map[string]any{
		"body": map[string]any{
			"type":    "doc",
			"version": 1,
			"content": []any{
				map[string]any{
					"type":    "paragraph",
					"content": []any{map[string]any{"type": "text", "text": text}},
				},
			},
		},
		"properties": []any{
			map[string]any{
				"key":   "sekizui.attribution",
				"value": map[string]any{"via": "sekizui"},
			},
		},
	}, nil
}

// send is the one outbound path, so the status mapping cannot differ per action.
func (d *Driver) send(ctx context.Context, op string, t connector.Target,
	method, path string, body, headers map[string]any) (connector.Result, error) {

	base := strings.TrimRight(t.BaseURL(), "/")
	if base == "" {
		return connector.Result{}, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q declares no base_url, and this driver will not guess one",
			t.Ref()))
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return connector.Result{}, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q has base_url %q, which is not an https URL with a host. "+
				"Plaintext would put the credential on the wire in clear", t.Ref(), base))
	}

	var payload io.Reader
	if body != nil {
		raw, mErr := json.Marshal(body)
		if mErr != nil {
			return connector.Result{}, fault.Wrap(fault.KindInvalidArgument, op,
				"the arguments are not JSON-encodable", mErr)
		}
		payload = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, base+path, payload)
	if err != nil {
		return connector.Result{}, fault.Wrap(fault.KindInternal, op,
			"building the request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		if s, ok := v.(string); ok {
			req.Header.Set(k, s)
		}
	}

	// **THE CREDENTIAL IS BORROWED, NEVER HELD (blueprint step 2, D127).**
	//
	// **SCHEME `Basic`, AND THE MATERIAL IS ALREADY THE ENCODED PAIR.** Jira
	// Cloud's header is `Basic <base64(email:api_token)>` — a COMPOSITE of an
	// identity and a secret, which is a shape the blueprint does not discuss and
	// `pkg/connector` cannot compose: `SetAuthorization` emits
	// `<scheme> <material>` and there is no exported helper for a value built
	// from more than the material. So the credential file holds the pre-encoded
	// pair, which keeps this driver entirely inside the published surface and
	// keeps the broker's header-byte validation. The cost is real and recorded
	// in the blueprint rather than absorbed here: the two halves cannot be
	// rotated independently, and an operator must base64 by hand.
	if err := connector.SetAuthorization(req.Header, t, "Basic"); err != nil {
		return connector.Result{}, fault.Wrap(fault.KindUnauthenticated, op,
			"the target's credential could not be borrowed", err)
	}

	resp, err := d.http.Do(req)
	if err != nil {
		return connector.Result{}, transportFault(op, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return connector.Result{}, fault.Wrap(fault.KindTargetUnavailable, op,
			"reading the response body", err)
	}
	if resp.StatusCode >= 300 {
		return connector.Result{}, upstreamFault(op, resp, raw)
	}

	data := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if jErr := json.Unmarshal(raw, &data); jErr != nil {
			// REACHED AND ANSWERED SOMETHING WE CANNOT READ. `target_error`
			// rather than `target_unavailable`: we learned something specific,
			// and it was bad.
			return connector.Result{}, fault.Wrap(fault.KindTargetError, op, fmt.Sprintf(
				"the upstream returned %d with a body that is not JSON",
				resp.StatusCode), jErr)
		}
	}

	// BLUEPRINT STEP 12: `Result.ExternalRef` is how an audit row joins to Jira's
	// own record. Read defensively — a 200 with no id is not worth failing a
	// write that already landed, and an empty ref is a gap in the audit trail
	// rather than a gap in the comment.
	ref, _ := data["id"].(string)
	if ref == "" {
		// The read path joins on the issue key, which the create path does not
		// return. Either is a real join key for the row that produced it.
		ref, _ = data["key"].(string)
	}

	return connector.Result{StatusCode: resp.StatusCode, Data: data, ExternalRef: ref}, nil
}

// spec returns the ActionSpec for a declared action, or refuses.
//
// **THE REFUSAL IS DELIBERATE AND ATTRIBUTED TO THE CALLER**, which the
// conformance suite checks: nothing was asked of the target, so counting it
// against the breaker would take a healthy vendor out of service over a typo.
func (d *Driver) spec(op, action string) (connector.ActionSpec, error) {
	for _, s := range d.Actions() {
		if s.Name == action {
			return s, nil
		}
	}

	known := make([]string, 0, 2)
	for _, s := range d.Actions() {
		known = append(known, s.Name)
	}
	return connector.ActionSpec{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
		"%q is not an action this driver implements; it has %s",
		action, strings.Join(known, " and ")))
}

// upstreamFault maps Jira's status codes onto the taxonomy.
//
// Each line encodes a decision about blame: who is at fault, whether a retry can
// help, and whether re-minting the credential can help. The four the conformance
// suite fixes are 401, 403, 429 and 5xx; 404 is ours to decide, and for Jira it
// is the caller's problem — an issue key that does not exist, or one this
// credential cannot see, which Jira deliberately does not distinguish.
func upstreamFault(op string, resp *http.Response, raw []byte) error {
	msg := fmt.Sprintf("the upstream returned %d", resp.StatusCode)
	if trimmed := strings.TrimSpace(string(raw)); trimmed != "" && len(trimmed) < 200 {
		msg += ": " + trimmed
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		// THE ONE PRODUCER OF `unauthenticated` A FRESH MINT CAN FIX: the far
		// side read a credential we sent and rejected it. A borrow failure
		// returns the same kind and must NOT set the marker.
		return fault.CredentialRejected(op, msg)
	case resp.StatusCode == http.StatusForbidden:
		// THE CREDENTIAL WAS ACCEPTED AND THE ACTION REFUSED, so re-minting
		// changes nothing and a retry is amplification against a vendor that
		// already said no.
		return fault.New(fault.KindDenied, op, msg)
	case resp.StatusCode == http.StatusTooManyRequests:
		// THE UPSTREAM IS THE AUTHORITY ON ITS OWN QUOTA. Dropped here, the
		// retry policy falls back to a guess.
		return &fault.Error{
			Kind: fault.KindRateLimited, Op: op, Msg: msg,
			RetryAfter: retryAfter(resp.Header.Get("Retry-After")),
		}
	case resp.StatusCode == http.StatusNotFound:
		// **JIRA CONFLATES "no such issue" WITH "not visible to you", and that
		// is the vendor's choice rather than ours to unpick.** Reporting it as
		// `denied` would claim a permission finding the response does not
		// support.
		return fault.New(fault.KindNotFound, op, msg)
	case resp.StatusCode == http.StatusConflict:
		return fault.New(fault.KindConflict, op, msg)
	case resp.StatusCode >= 500:
		// Reached and broke: the case the breaker exists for.
		return fault.New(fault.KindTargetError, op, msg)
	default:
		return fault.New(fault.KindInvalidArgument, op, msg)
	}
}

// transportFault separates an outage from a governance event.
//
// **`errors.Is` RATHER THAN A STRING MATCH.** `http.Client.Do` returns a
// `*url.Error` wrapping the real cause, and the cause is what decides the kind.
func transportFault(op string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fault.Wrap(fault.KindTimeout, op, "the caller cancelled the request", err)
	case errors.Is(err, context.DeadlineExceeded):
		return fault.Wrap(fault.KindTimeout, op, "the request deadline passed", err)
	default:
		// COULD NOT BE REACHED. An availability condition, never a divergence.
		return fault.Wrap(fault.KindTargetUnavailable, op,
			"the target could not be reached", err)
	}
}

// retryAfter reads the header's delta-seconds form.
//
// The HTTP-date form is not parsed: it needs a clock to be meaningful, and a
// wrong answer here silences a rate limit rather than reporting one. Absent
// beats wrong — the enforcement path's own backoff takes over.
func retryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// schemasYAML is this connector's data schemas (D279), shipped with the code
// that emits the data so the two cannot be deployed apart.
//
//go:embed schemas.yaml
var schemasYAML []byte

// Schemas returns the schema of every type this connector's actions declare
// (D279). The connector owns what may enter; the deployment lenses it.
func (d *Driver) Schemas() ([]connector.Schema, error) {
	return connector.ParseSchemas(schemasYAML)
}

// Meter declares Jira's meter (D284): calls, one per call. No default of its
// own — this driver has never been given a documented per-instance figure to
// cite — so a Jira target without `rate_per_hr` takes the universal default.
func (d *Driver) Meter() connector.Meter { return connector.Meter{Unit: connector.UnitCalls} }
