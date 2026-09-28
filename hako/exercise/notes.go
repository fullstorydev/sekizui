// Package notes is the connector kata's EXERCISE — the solution next door with
// its governance half removed.
//
// **WORK IT WITH `hako/BLUEPRINT.md` OPEN.** Every gap is marked
// `HAKO STEP <n>` and names the blueprint step that closes it. Run
// `make hako` to see what is still missing; when it passes, compare with
// `hako/solution` and read the reasoning you did not have to write.
//
// **IT IS MEANT TO FAIL, and that is why its tests carry a build tag.** A
// teaching artefact that must fail cannot be guarded by a runner that requires
// green, so the pair is this and the solution, which runs in CI under the full
// conformance suite. What IS guarded here is that every `HAKO STEP` marker names
// a real blueprint step (P2 step 46), so a step added to the blueprint cannot
// leave the exercise silently no longer covering it.
//
// The mechanical half is deliberately INTACT. The compiler and the conformance
// suite already teach that; what nothing makes anybody confront is the lens, the
// ceiling and the narrow grant, so those are the gaps.
package notes

import (
	"bytes"
	"context"
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
func (d *Driver) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{
		{
			Name:     ActionCreateNote,
			Mutating: true,
			// HAKO STEP 3: this action mutates and declares no idempotency
			// class. The vendor honours an `Idempotency-Key` header. Which
			// class is that, and where does the key go? A human decides this —
			// never a vendor hint — and an absent classification on a mutating
			// action fails the load.
			InputSchema: "sekizui://schema/notes/create_note.v1",
			Description: "Create a note against a workspace. The upstream honours " +
				"Idempotency-Key, so a retried timeout produces one note.",
		},
		{
			Name:        ActionReadNote,
			InputSchema: "sekizui://schema/notes/read_note.v1",
			// HAKO STEP 4: a query action with no OutputType is lensable only by
			// the type-less jurisdiction rules — so the lens you write in step 7
			// cannot name a field, and this vendor's author email travels.
			// Declare the type and register its payload schema.
			Description: "Read a single note by id, including its author and body.",
		},
		{
			// The afferent capability. A grant naming an action no driver
			// implements cannot load (D196), so a source that does not
			// advertise its poll is a source nobody can be granted.
			// HAKO STEP 4: this poll declares no OutputType, so nothing knows
			// the SHAPE of the envelopes it produces — and the lens in step 7
			// has no type to name. A poll is non-mutating and is NOT a query;
			// it is the one action whose output reaches the bus rather than a
			// caller, which makes the missing type easier to overlook and no
			// less disabling.
			Name:        "notes.poll",
			Mutating:    false,
			InputSchema: "sekizui://schema/notes/poll.v1",
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

	// HAKO STEP 12: `Result.ExternalRef` is how an audit row joins to the
	// vendor's own record. Left empty, a governed action and the thing it did
	// are two facts nobody can connect. The vendor returns the note's id.
	return connector.Result{StatusCode: resp.StatusCode, Data: data}, nil
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

// Schemas returns this connector's data schemas (D279).
//
// HAKO STEP 4: none. Every type an action declares needs its schema shipped
// here, beside the code that emits it — and this connector declares no type,
// so nothing it polls can be lensed, detected or even admitted.
func (d *Driver) Schemas() ([]connector.Schema, error) { return nil, nil }

// Meter declares what the upstream meters and what a call costs (D284).
//
// HAKO STEP 4 again: the zero value — calls, one per call — and NO PollCost.
// This connector is a Source, so the spine cannot price a poll before sending
// it, and the published suite refuses the meter for exactly that.
func (d *Driver) Meter() connector.Meter { return connector.Meter{} }
