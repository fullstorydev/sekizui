// Package notes is the WORKED SOLUTION of the connector kata — a complete,
// governed connector for a small fictional service, written to be READ.
//
// **WHY A FICTIONAL VENDOR AND NOT `internal/connectors/kata` (D218).** That driver
// is the acceptance suite's in-memory fixture and it is a fine example of the
// MECHANICAL half. It cannot teach the governance half, and the reason is
// specific: it has no vendor payload, so there is nothing sensitive for a shin
// lens to withhold, and step 7 of the blueprint — the step most likely to be
// skipped and most expensive to skip — would have no worked example at all.
// Notes has an author's email address in every response, which is exactly the
// shape a real connector has to make a decision about.
//
// **READ IT BESIDE `hako/BLUEPRINT.md`.** Every section below names the
// blueprint step it satisfies, and `notes.yaml` carries the configuration half.
// The exercise next door is this with the governance removed.
//
// Everything here uses `pkg/` only. That is not tidiness: `internal/` is
// unreachable from outside this module, so a third-party driver author (D35) can
// write exactly this and no more.
package notes

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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Kind is what a target's `kind:` must say to route here (blueprint step 5).
const Kind = "notes"

// The two actions, named `<kind>.<verb>` like every action in the system.
const (
	ActionCreateNote = "notes.create_note"
	ActionReadNote   = "notes.read_note"
)

// Driver is BLUEPRINT STEP 1: binding class 1, stateless.
//
// The only fields are a shared HTTP client and the optional pool. Neither is
// per-tenant, which is what makes one instance safe to serve every customer —
// and it is checked rather than reviewed: `conformance.Run`'s statelessness arm
// drives four tenants at once and asks the far side whose credential arrived.
//
// **A CLASS 1 DRIVER STILL TAKES THE POOL, and it is not an optimisation.** The
// pool is how `revoke_credential` cancels calls already in flight. A driver that
// skipped it would be invisible to break-glass, which would evict nothing and
// truthfully report cancelling nothing while the compromised credential kept
// working.
type Driver struct {
	http *http.Client
	pool connector.ClientPool
}

// Option configures the driver.
type Option func(*Driver)

// WithHTTPClient substitutes the transport. Production never sets it; it is what
// makes every arm of this driver testable without an account.
func WithHTTPClient(c *http.Client) Option { return func(d *Driver) { d.http = c } }

// WithPool routes calls through the shared client pool so break-glass can cancel
// them.
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

// Actions is BLUEPRINT STEPS 3 AND 4.
//
// **THE IDEMPOTENCY CLASS IS PER ACTION AND A HUMAN CHOSE IT.** `create_note`
// POSTs and the vendor honours an `Idempotency-Key` header, so it is class
// `header` and the placement names the header. `read_note` is not mutating and
// needs no class at all.
//
// **`OutputType` IS NOT OPTIONAL ON THE QUERY ACTION.** Without it the result is
// lensable only by the type-less jurisdiction rules — which is to say the lens in
// `notes.yaml` could not name a field, and the author's email would travel.
//
// **AND `OutputType` IS THE REGISTRY KEY, NEVER THE SCHEMA URI (D41, D88).** They
// are two fields because they are two things: `OutputSchema` is a URI naming
// where the document lives, `OutputType` is the key `payload_schemas` is keyed on
// and the key a shin lens's `type:` is matched against. **This file had the URI
// in both, and nothing caught it** — `notes.yaml`'s lens carried the same URI and
// `config_test.go` asserted that exact string, so all three agreed and the answer
// key taught the one conflation D88 split the fields to prevent. A learner
// following it and registering `notes.note.v1` — the documented convention, and
// what `internal/connectors/kata` does — would have been refused at boot by
// `schemareg` naming their own action. The guard that now catches it is the real
// boot check rather than a fourth hand-written string.
func (d *Driver) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{
		{
			Name:                 ActionCreateNote,
			Mutating:             true,
			OutputType:           "notes.write_result.v1",
			Idempotency:          connector.IdempotencyHeader,
			IdempotencyPlacement: "Idempotency-Key",
			InputSchema:          "sekizui://schema/notes/create_note.v1",
			Description: "Create a note against a workspace. The upstream honours " +
				"Idempotency-Key, so a retried timeout produces one note.",
		},
		{
			Name:        ActionReadNote,
			InputSchema: "sekizui://schema/notes/read_note.v1",
			// Locally authored: there is no vendor publishing one, and the
			// pairing with OutputSchema is enforced at load rather than call time.
			OutputType:  "notes.note.v1",
			Description: "Read a single note by id, including its author and body.",
		},
		{
			// The afferent capability. A grant naming an action no driver
			// implements cannot load (D196), so a source that does not
			// advertise its poll is a source nobody can be granted.
			Name:        "notes.poll",
			Mutating:    false,
			InputSchema: "sekizui://schema/notes/poll.v1",
			// A polled note IS a note, so the type it emits is the one
			// `read_note` returns and the one the lens below names. Declaring
			// it is what lets shin narrow polled envelopes as well as query
			// rows — the same field, two planes.
			OutputType:  "notes.note.v1",
			Description: "Poll for notes changed after a cursor.",
		},
	}
}

// Execute performs the mutating action.
func (d *Driver) Execute(ctx context.Context, t connector.Target, action string,
	args map[string]any, idem connector.Idempotency) (connector.Result, error) {

	const op = "notes.Execute"

	spec, err := d.spec(op, action)
	if err != nil {
		return connector.Result{}, err
	}
	if !spec.Mutating {
		return connector.Result{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"%q is a read; call it through Query so the read and write planes stay "+
				"distinguishable in policy, audit and metrics", action))
	}

	// PLACE THE KEY, THEN VERIFY IT SURVIVED. Both operations live in
	// pkg/connector so every driver inherits them rather than remembering them —
	// sending a class `header` call without its key produces the double write the
	// classification exists to prevent, while every log line reports success.
	body, headers, err := idem.PlaceIn(op, spec.Mutating, args)
	if err != nil {
		return connector.Result{}, err
	}
	if err := idem.Verify(op, body, headers); err != nil {
		return connector.Result{}, err
	}

	// **§6 MECHANISM 3, IMMEDIATELY BEFORE THE OUTBOUND CALL.** Nanoseconds, and
	// it is the only thing that catches a pooled client belonging to another
	// tenant — a substitution the constructor cannot see, because it happens in
	// the pool after construction. `conformance.Run` proves it fires BEFORE the
	// call by counting what reached the far side, not by reading the error.
	if err := connector.AssertTenant(ctx, t); err != nil {
		return connector.Result{}, err
	}

	var res connector.Result
	work := func(ctx context.Context, _ any) error {
		var callErr error
		res, callErr = d.send(ctx, op, t, http.MethodPost, "/v1/notes", body, headers)
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

	const op = "notes.Query"

	spec, err := d.spec(op, action)
	if err != nil {
		return connector.Rows{}, err
	}
	if spec.Mutating {
		return connector.Rows{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"%q mutates; call it through Execute", action))
	}

	id, _ := args["id"].(string)
	if strings.TrimSpace(id) == "" {
		return connector.Rows{}, fault.New(fault.KindInvalidArgument, op,
			"read_note needs an `id`")
	}

	if err := connector.AssertTenant(ctx, t); err != nil {
		return connector.Rows{}, err
	}

	var rows connector.Rows
	work := func(ctx context.Context, _ any) error {
		res, callErr := d.send(ctx, op, t, http.MethodGet,
			"/v1/notes/"+url.PathEscape(id), nil, nil)
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

// Health reports whether the target is reachable. It has no caller in this tree
// yet; the panel is its consumer.
func (d *Driver) Health(context.Context, connector.Target) error { return nil }

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
	for k, v := range headers {
		if s, ok := v.(string); ok {
			req.Header.Set(k, s)
		}
	}

	// **THE CREDENTIAL IS BORROWED, NEVER HELD (blueprint step 2).** This helper
	// leases the material for the duration of a callback and refuses material
	// that cannot BE a header value — as a CONFIGURATION fault, so an operator
	// is not sent looking for an unreachable target.
	if err := connector.SetAuthorization(req.Header, t, "Bearer"); err != nil {
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

	ref, _ := data["id"].(string)
	return connector.Result{ExternalRef: ref, StatusCode: resp.StatusCode, Data: data}, nil
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
	names := make([]string, 0, 2)
	for _, s := range d.Actions() {
		names = append(names, s.Name)
	}
	return connector.ActionSpec{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
		"this driver does not implement %q. It implements: %s",
		action, strings.Join(names, ", ")))
}

// upstreamFault maps a status to the shared taxonomy.
//
// **THE MAPPING IS THE PART A CONFORMANCE SUITE CAN CHECK AND A REVIEW CANNOT**,
// because each line encodes a decision about blame: who is at fault, whether a
// retry could help, and whether the target's breaker should move. Getting 401
// wrong takes a healthy vendor out of service over a credential problem.
func upstreamFault(op string, resp *http.Response, raw []byte) error {
	msg := fmt.Sprintf("the upstream returned %d", resp.StatusCode)
	if trimmed := strings.TrimSpace(string(raw)); trimmed != "" && len(trimmed) < 200 {
		msg += ": " + trimmed
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		// THE ONE PRODUCER OF `unauthenticated` A FRESH MINT CAN FIX: the far
		// side read a credential we sent and rejected it. A borrow failure
		// returns the same kind and must NOT set the marker — re-minting returns
		// the same bad bytes.
		return fault.CredentialRejected(op, msg)
	case resp.StatusCode == http.StatusForbidden:
		// THE CREDENTIAL WAS ACCEPTED AND THE ACTION REFUSED, so re-minting
		// changes nothing and a retry is pure amplification against a vendor
		// that already said no.
		return fault.New(fault.KindDenied, op, msg)
	case resp.StatusCode == http.StatusTooManyRequests:
		// THE UPSTREAM IS THE AUTHORITY ON ITS OWN QUOTA. Dropped here, the
		// retry policy falls back to a guess.
		return &fault.Error{
			Kind: fault.KindRateLimited, Op: op, Msg: msg,
			RetryAfter: retryAfter(resp.Header.Get("Retry-After")),
		}
	case resp.StatusCode == http.StatusNotFound:
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
// `*url.Error` wrapping the real cause, and the cause is what decides the kind —
// matching on the message would break the first time Go rewords it.
func transportFault(op string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fault.Wrap(fault.KindTimeout, op, "the caller cancelled the request", err)
	case errors.Is(err, context.DeadlineExceeded):
		return fault.Wrap(fault.KindTimeout, op, "the request deadline passed", err)
	default:
		// COULD NOT BE REACHED. An availability condition, never a divergence:
		// conflating them makes a vendor's bad afternoon read as a supply-chain
		// incident, and fires every anzen rule watching for drift.
		return fault.Wrap(fault.KindTargetUnavailable, op,
			"the target could not be reached", err)
	}
}

// retryAfter reads the header's delta-seconds form.
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

// Meter declares what the upstream meters and what a call costs (D284).
//
// Calls, one per call, and a poll priced at its WORST CASE — every
// upstream request it can make, whether or not it makes them. This connector's
// poll is one read, so one. Get this wrong low and the spine under-counts every
// poll; that is why a Source must say.
func (d *Driver) Meter() connector.Meter {
	return connector.Meter{
		Unit:     connector.UnitCalls,
		PollCost: func(connector.Configured) uint64 { return 1 },
		// BLUEPRINT STEP "REPORT DRIFT" (D311): a Drifter declares a SYSTEM budget
		// of its own — its comparisons are Sekizui's safety traffic, never billed
		// to the consumers' budget — and prices one comparison before it is sent.
		// Twelve an hour is the drift watcher's cadence; one comparison is one GET.
		SystemPerHour: 12,
		DriftCost:     func(connector.Configured) uint64 { return 1 },
	}
}

// Drift compares what this connector VETTED — its actions — with what the notes
// vendor offers NOW, read from `GET /v1/capabilities` (D311). It is the
// reference connector's form of connector.Drifter, and it takes exactly the
// path Execute takes: assert the tenant, borrow through the pool, one send.
//
// A vetted action the vendor no longer offers is WITHHELD (the catalog stops
// advertising it); an operation nobody vetted is UNVETTED (harmless: it has no
// action to call). An unreachable vendor is an ERROR, never a finding — an
// outage is not drift.
func (d *Driver) Drift(ctx context.Context, t connector.Target) (connector.DriftFindings, error) {
	const op = "notes.Drift"
	if err := connector.AssertTenant(ctx, t); err != nil {
		return nil, err
	}
	var res connector.Result
	work := func(ctx context.Context, _ any) error {
		var callErr error
		res, callErr = d.send(ctx, op, t, http.MethodGet, "/v1/capabilities", nil, nil)
		return callErr
	}
	if d.pool == nil {
		if err := work(ctx, nil); err != nil {
			return nil, err
		}
	} else if err := d.pool.Do(ctx, t, work); err != nil {
		return nil, err
	}

	ops, ok := res.Data["operations"].([]any)
	if !ok {
		return nil, fault.New(fault.KindTargetError, op,
			"the capabilities response carries no `operations` list, so nothing can be compared")
	}
	live := map[string]bool{}
	for _, o := range ops {
		if name, _ := o.(string); name != "" {
			live[name] = true
		}
	}
	var out connector.DriftFindings
	for _, a := range d.Actions() {
		tool := strings.TrimPrefix(a.Name, Kind+".")
		if live[tool] {
			delete(live, tool)
			continue
		}
		out = append(out, connector.DriftFinding{Severity: connector.DriftWithheld, Tool: tool,
			Action: a.Name, Detail: "vetted, and the vendor no longer offers it"})
	}
	extra := make([]string, 0, len(live))
	for name := range live {
		extra = append(extra, name)
	}
	sort.Strings(extra)
	for _, name := range extra {
		out = append(out, connector.DriftFinding{Severity: connector.DriftUnvetted, Tool: name,
			Detail: "offered by the vendor, and nobody has vetted it"})
	}
	return out, nil
}
