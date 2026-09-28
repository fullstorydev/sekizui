// Package kata (型, "form") is the REFERENCE FORM a connector fills in — a
// connector.Driver with no external dependencies, exercising every seam a real
// driver must.
//
// **NAMED FOR THE ROLE IT HAS, NOT THE ONE IT STARTED WITH (D176).** It was
// `fake`, which is exact in the test-double taxonomy — a working implementation
// with shortcuts, unsuitable for production — and exact about the wrong thing.
// A kata is the prescribed form you practise until it is structural, which is
// what this package is FOR: the shape a connector author fills in, run against
// the real enforcement path so the form is executable rather than described.
// `dummy` was considered and rejected: in the same taxonomy it means an object
// passed but never used, which is the weakest term available and the opposite of
// a package that does real work on every path.
//
// **THIS DOC COMMENT USED TO DISCLAIM THAT ROLE, AND WAS WRONG TWICE OVER.** It
// read: "Atlassian (P2) is the first real driver and the reference pattern; this
// one is deliberately not that." Atlassian is no longer in P2 at all — §12 P2
// amends D27 on its own reasoning and leads with Fullstory — and in the
// meantime this package became the only implementation that exercises §4.7.4's
// three credential-binding classes, D128's pool call-through, §6 mechanism 3's
// egress tenant assertion, and D163's idempotency classes. It IS the reference
// pattern, and it had been for some time while its own documentation denied it.
// The recurring class, in the one place a reader goes to learn what a package is
// for.
//
// **SO IT IS THE EXECUTABLE HALF OF THE CONNECTOR BLUEPRINT (D167).** The
// blueprint is three artefacts that must agree: a document describing the form,
// a conformance suite enforcing it, and an implementation demonstrating it. A
// document alone drifts from the code; a suite alone shows what is forbidden and
// never what is idiomatic.
//
// # Two surfaces, and copying the wrong one is the hazard
//
// EXEMPLARY — copy these, they are what a real connector must do: statelessness
// (D4), borrowing clients through ClientPool so break-glass can reach them
// (D128), asserting the context tenant against the target's immediately before
// every outbound call (§6), declaring an idempotency class per action and
// placing the key or refusing (D163), and mapping every failure into pkg/fault
// rather than a vendor string.
//
// TEST-DOUBLE ONLY — never copy these, they exist because there is no upstream:
// FailKey, LatencyKey and RetryAfterKey. A real driver has an upstream that
// fails on its own and must not accept an argument asking it to. They are marked
// individually where they are declared.
//
// STATELESS, like a real driver (D4). It records nothing and mutates nothing
// after construction, so it is safe to share across tenants and goroutines. That
// matters more than it looks for a test double: one that accumulated call
// history would be shared mutable state, which is exactly what §6 item 4 bans,
// and it would make it behave differently from the thing it stands in for.
//
// Behaviour is therefore driven by ARGUMENTS rather than by injected state — see
// FailKey. A caller asks for a failure; the driver does not remember one.
//
// PRIVATE (D35), and that is a limit worth stating: a self-hoster writing a
// driver reads this package rather than importing it. The part they can import
// is the conformance suite.
//
// **THIS IS THE DRIVER, AND `hako/` IS THE CONNECTOR (D244).** One word used to
// answer for both. The line is D175's: a driver is the Go type — what this
// package is — and a connector is the deliverable an operator installs, which
// is the driver plus its target, limits, grant, lens, guard and schemas. An
// author writing Go reads here; an author bringing a system under governance
// reads `hako/`, which is the box this package sits inside.
//
// DESIGN.md references: §4.3, §12 P0, §12 P2, §12 P3, D4, D27, D35, D128,
// D163, D167, D175, D176, D243, D244.
package kata

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Kind is the driver kind, matching TargetSpec.Kind in configuration.
const Kind = "kata"

// FailKey is a reserved argument that makes the driver return a classified
// error.
//
// **TEST-DOUBLE ONLY — DO NOT COPY THIS INTO A REAL CONNECTOR.** A real driver
// has an upstream that fails on its own, and an action argument that induces a
// failure would be a caller-controlled fault injector on a governed path. It
// exists here because there is no upstream to break.
//
// Failure injection through an ARGUMENT, not through driver state. State would
// be shared across concurrent callers, so one test could steer another's
// failure — and it would make the kata stateful where real drivers are not.
// The value is a fault.Kind name: "target_unavailable", "rate_limited", …
const FailKey = "_fail"

// LatencyKey is a reserved argument making the driver sleep, for exercising
// deadlines and timeouts. Value is a Go duration string.
const LatencyKey = "_latency"

// RetryAfterKey makes an injected failure carry the upstream's own backoff, as
// a real 429 does. Value is a Go duration string; ignored without FailKey.
//
// EXISTS BECAUSE THE INTERESTING HALF OF 429 HANDLING IS THE HEADER. Any double
// can return an error; what the retry policy has to get right is preferring the
// upstream's stated wait to its own model, and capping it so a misconfigured
// proxy cannot park a command for an hour (D14, §5.2.1). Without this the kata
// could only produce a bare rate limit, and step 20 would assert against
// Sekizui's guess rather than against the behaviour that matters.
const RetryAfterKey = "_retry_after"

// StripKeyPlacement makes the driver DROP its idempotency key after placing it,
// simulating something between placement and the wire that removes it.
//
// **THERE IS NO OTHER WAY TO REACH THE CASE (D186).** A real HTTP middleware
// stripping a header, a proxy rewriting one, a marshalling layer dropping an
// unknown body field — all produce an unkeyed request that every log line
// reports as keyed, and none of them can be provoked from outside the driver.
// Same shape as FailKey: a caller asks for the condition, the driver does not
// remember one.
//
// The value is ignored; presence is what counts.
const StripKeyPlacement = "_strip_key"

// BindingKey is the target SETTING selecting which §4.7.4 credential-binding
// class this target models: "class1" (default), "class2", "class3".
//
// A SETTING RATHER THAN THREE DRIVERS, because the class is a property of how a
// particular system authenticates, not of the driver's code — Fullstory REST and
// Fullstory MCP are the same vendor at different classes. Modelling it per
// target is also what lets one acceptance run exercise all three through the
// real enforcement path instead of through three hand-built pools.
const BindingKey = "binding"

// IdempotencyHeaderName and IdempotencyFieldPath are where this driver places a
// caller's idempotency key, for the two classes that need a placement.
//
// EXPORTED SO A TEST CAN ASSERT THE WIRE rather than asking the driver what it
// did — D159's rule, since a guard whose two inputs share an origin is not a
// guard. A step reads the recorded outbound call and looks for THIS name.
const (
	IdempotencyHeaderName = "Idempotency-Key"
	IdempotencyFieldPath  = "_idempotency_key"
)

// Binding classes, matching §4.7.4's table.
const (
	Class1 = "class1" // stateless, per-request auth: a credential-FREE client
	Class2 = "class2" // client constructed WITH the credential; no per-call seam
	Class3 = "class3" // session-oriented: needs explicit teardown
)

// Driver implements connector.Driver against nothing at all.
type Driver struct {
	// pool is where clients live so that eviction, teardown and REVOCATION can
	// reach them (D106, D128). Optional: without one the driver still works and
	// break-glass has nothing to cancel, which is the state CONTRACTS §4 item 35
	// described before this was wired.
	pool connector.ClientPool
}

// Option configures the driver.
//
// The original comment here read "No options: anything configurable would be
// state." That was right about STATE and wrong as a rule: a pool is a
// collaborator, shared and concurrency-safe, not per-call state the driver
// mutates. The distinction worth keeping is that nothing here may vary per
// caller.
type Option func(*Driver)

// WithPool makes this driver borrow its clients from Sekizui's pool.
//
// WITHOUT IT, BREAK-GLASS CANNOT REACH THIS DRIVER. A driver holding private
// clients is invisible to revocation: `revoke_credential` evicts the pool,
// reports what it cancelled, and leaves this driver's connections running on a
// compromised credential.
func WithPool(p connector.ClientPool) Option { return func(d *Driver) { d.pool = p } }

// New returns the driver.
func New(opts ...Option) *Driver {
	d := &Driver{}
	for _, o := range opts {
		o(d)
	}
	return d
}

// client is what classes 1 and 2 pool.
//
// IT HAS NO Close METHOD, AND THAT IS THE DESIGN. `pool.Closer` is an optional
// interface discovered by type assertion (GO-PRIMER §2.2), so a client needing
// no teardown says nothing — and §4.7.4 is explicit that class 3 "is the only
// class that needs it". Putting Close on one shared type made every class
// report a teardown, which made `Revocation.torn_down` a synonym for `evicted`
// and erased the distinction the field exists to record. Caught by step 52's
// non-vacuity check rather than by review.
type client struct {
	class string

	// bound is non-nil for class 2 only: the credential COPIED AT CONSTRUCTION,
	// the way an SDK client takes credentials in its constructor and offers no
	// per-call seam. This is the copy no wipe of ours can reclaim — exactly what
	// D106 means by class 2 being "entirely unaffected" by wiping cached
	// material, and why revocation for it is eviction plus teardown rather than
	// a memory write.
	bound []byte
}

// sessionClient is class 3: a client plus server-side state that must be told
// it is going away.
//
// Dropping a pooled BigQuery client costs nothing; dropping an MCP session
// leaves server-side state and possibly a live authorised session. This is the
// only type here that implements Close, so it is the only one the pool tears
// down.
type sessionClient struct {
	client

	mu     sync.Mutex
	closed bool
}

func (c *sessionClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	// A real class 3 close is an AUTHENTICATED call, which is why the pool
	// closes before it wipes.
	c.bound = nil
	return nil
}

func (c *sessionClient) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// BuildClient satisfies connector.ClientBuilder (D190).
//
// **A METHOD RATHER THAN A PACKAGE FUNCTION, and the second driver is why.**
// `pool.New` takes ONE build for the whole pool, and the wiring passed
// `kata.BuildClient` — correct while there was one driver, and untenable with
// two: the build has to dispatch on `t.Kind()`. A `map[string]Build` beside the
// existing `map[string]Driver` would be two maps keyed identically and kept in
// step by hand. As a method the build TRAVELS WITH THE DRIVER, so registering a
// driver without its build is not expressible.
//
// The split it preserves is the point of `connector.ClientPool`: the pool
// decides WHEN a client dies, the driver decides WHAT one is.
//
// The kata implements it because it models all three §4.7.4 binding classes;
// the Fullstory driver deliberately does NOT, because a class 1 client is
// credential-free and there is nothing per-target to build — which is what makes
// the interface optional rather than part of `Driver`.
func (d *Driver) BuildClient(_ context.Context, t connector.Target) (any, error) {
	class := t.Setting(BindingKey)
	if class == "" {
		class = Class1
	}

	c := client{class: class}

	if class == Class2 {
		// CLASS 2 TAKES THE CREDENTIAL AT CONSTRUCTION and keeps its own copy —
		// `bigquery.NewClient` and most cloud SDKs. UseRaw rather than AppendTo
		// because an SDK wants the material itself, and this is one of the two
		// cases that hole exists for (D127).
		if err := t.UseRaw(func(material []byte) error {
			c.bound = append([]byte(nil), material...)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if class == Class3 {
		// The ONLY branch returning something with a Close method.
		return &sessionClient{client: c}, nil
	}
	return &c, nil
}

// Compile-time proof that the interface is satisfied, per GO-PRIMER §2. Without
// it, a signature drift shows up at the wiring site rather than here.
var (
	_ connector.Driver = (*Driver)(nil)
	// AND THE OPTIONAL ONE, asserted here rather than left to be discovered:
	// the kata models all three §4.7.4 binding classes, so a refactor that
	// dropped BuildClient would silently demote every kata target to a
	// credential-free marker and stop exercising classes 2 and 3 (D190).
	_ connector.ClientBuilder = (*Driver)(nil)
)

func (d *Driver) Kind() string { return Kind }

// WriteResultType is what every kata write returns: a fixture ECHO of the call
// (D283) — what was sent and where the key went — which the steps assert
// against. kata is a test fixture that shows what was sent, not a source of data,
const WriteResultType = "kata.write_result.v1"

// Actions returns every action this driver implements, EXACTLY.
//
// The connector definition-of-done requires no advertised-but-absent action, and
// TestActionsMatchImplementation enforces it by calling every one of them.
func (d *Driver) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{
		{
			Name:       "kata.create_issue",
			Mutating:   true,
			OutputType: WriteResultType,
			// HEADER CLASS, and the kata carries the classes Fullstory does not
			// (D163). P2's real connector exercises `natural` and `none` only, so
			// without this the vocabulary would be built and two-fifths proven —
			// the same argument kata.BindingKey makes for §4.7.4's three credential
			// classes, which one acceptance run drives through the real enforcement
			// path rather than three hand-built pools.
			Idempotency:          connector.IdempotencyHeader,
			IdempotencyPlacement: IdempotencyHeaderName,
			InputSchema:          "sekizui://schema/kata/create_issue.v1",
			Description:          "Create an issue. Returns a synthetic external reference.",
		},
		{
			Name:       "kata.comment",
			Mutating:   true,
			OutputType: WriteResultType,
			// FIELD CLASS: the key rides in the request body rather than a header,
			// which is how BigQuery's streaming `insertId` works.
			Idempotency:          connector.IdempotencyField,
			IdempotencyPlacement: IdempotencyFieldPath,
			InputSchema:          "sekizui://schema/kata/comment.v1",
			Description:          "Comment on an issue.",
		},
		{
			// NATURAL: an upsert keyed on the caller's own identifier, which is
			// what Fullstory's create-or-update user is. Needs no key at all, and
			// exists so a step can prove the classification does WORK rather than
			// refusing everything — a driver that refused every retry would pass
			// the `none` step and be useless.
			Name:        "kata.upsert_record",
			Mutating:    true,
			OutputType:  WriteResultType,
			Idempotency: connector.IdempotencyNatural,
			InputSchema: "sekizui://schema/kata/create_issue.v1",
			Description: "Create or replace a record by id. Repeat-safe by construction.",
		},
		{
			// NONE: the upstream offers nothing, so a retry is refused rather than
			// risked. Fullstory's create-event is this, and it is the class P2's
			// headline write actually falls into.
			Name:        "kata.append_event",
			Mutating:    true,
			OutputType:  WriteResultType,
			Idempotency: connector.IdempotencyNone,
			InputSchema: "sekizui://schema/kata/create_issue.v1",
			Description: "Append an event. The upstream cannot deduplicate; a retry would double-write.",
		},
		{
			// Exists so that a denial has something to deny. P0 exit criterion 2
			// needs an action a narrow principal is NOT granted, and inventing
			// one only in test fixtures would leave the real catalog unable to
			// demonstrate it.
			Name:       "kata.delete_project",
			Mutating:   true,
			OutputType: WriteResultType,
			// NONE, and deliberately: a delete that half-happened must not be
			// retried on a guess. The destructive action is the one where the
			// honest answer costs the least to state.
			Idempotency: connector.IdempotencyNone,
			InputSchema: "sekizui://schema/kata/delete_project.v1",
			Description: "Delete a project. Destructive; expected to be denied or escalated.",
		},
		{
			Name:        "kata.read",
			Mutating:    false,
			InputSchema: "sekizui://schema/kata/read.v1",
			// The REGISTRY KEY, distinct from the URI above (D88). Without it a
			// query result cannot be lensed by type.
			OutputType: "kata.read_result.v1",
			// Locally authored: there is no vendor to publish one (D51).
			Description: "Read rows. Non-mutating; routed through Query.",
		},
		{
			// **THE AFFERENT CAPABILITY, ADVERTISED LIKE ANY OTHER.** A poll is
			// served through this driver, so it is not a governed verb
			// (`internal/verb` is for what Sekizui serves ITSELF); and a grant
			// naming an action no driver implements cannot load (D196). So the
			// only place it can live is here, which also means the catalog
			// tells an operator which targets are pollable and who may.
			//
			// The principal is `source:<target ref>` (D246), so a grant reads
			// "source:kata:alpha may kata.poll kata:alpha".
			Name:        "kata.poll",
			Mutating:    false,
			InputSchema: "sekizui://schema/kata/poll.v1",
			// **A POLL HAS AN OUTPUT TYPE AND IT IS NOT DECORATION.** Every
			// event it emits carries this as `Envelope.type`, which is the key
			// a shin lens names (§4.12, D41, D88) and the key
			// `payload_schemas` is keyed on — so declaring it here is what
			// lets a deployment lens polled data, and what makes the catalog
			// able to say what polling this target yields.
			OutputType:  "kata.row.v1",
			Description: "Poll for events after a cursor. The afferent path; not routed through Query.",
		},
	}
}

// placeKey delegates to connector.Idempotency.PlaceIn.
//
// **THE LOGIC MOVED TO pkg/connector (D186), AND THE MOVE FOUND A DEFECT.** This
// function used to own placement, and it wrote the key over whatever sat at the
// configured body path — so a caller supplying a field of that name had its
// value silently REPLACED, and the upstream acted on a request the agent did not
// make. A driver-local copy is also how the second driver gets it subtly
// different, which is CONTRACTS 63's shape: the key reaching the predicate and
// the record and not the wire, because no single place owned carrying it.
//
// Kept as a name rather than inlined, because the call site reads better with it
// and because `spec` is what this driver has while `PlaceIn` takes the one bit
// of it that matters.
func placeKey(op string, spec connector.ActionSpec, idem connector.Idempotency,
	args map[string]any) (map[string]any, map[string]any, error) {

	return idem.PlaceIn(op, spec.Mutating, args)
}

// Execute performs a mutating action.
func (d *Driver) Execute(ctx context.Context, t connector.Target, action string,
	args map[string]any, idem connector.Idempotency) (connector.Result, error) {

	const op = "kata.Execute"
	started := time.Now()

	spec, err := d.lookup(op, action, false)
	if err != nil {
		return connector.Result{}, err
	}
	// A WRITE THAT HOLDS ITS SLOT (P5 step 8): `_misbehave_block` blocks a write
	// as it blocks a poll, until the caller's context is cancelled — so "how many
	// are in flight at once" is answerable by looking rather than by racing it.
	if t.Setting(MisbehaveBlock) == "true" {
		<-ctx.Done()
		return connector.Result{}, fault.Wrap(fault.KindUnavailable, op,
			"blocked until the caller's context was cancelled", ctx.Err())
	}

	// PLACE THE KEY WHERE THE CLASS SAYS, OR REFUSE (D163).
	//
	// A real driver puts it in a header or a body field on the way out. This one
	// has no wire, so it records the placement into the outbound call the same way
	// it records everything else — which is what lets a step assert on WHERE the
	// key went rather than on Sekizui's report that it went somewhere (D159).
	//
	// The refusal is the half that matters. Sending the call without the key would
	// produce exactly the double-write the classification exists to prevent, while
	// every log line reports a successful idempotent write.
	outbound, headers, err := placeKey(op, spec, idem, args)
	if err != nil {
		return connector.Result{}, err
	}
	args = outbound

	// **THE STRIPPING TRANSPORT, which exists so Verify has something to catch.**
	// A real driver never does this; a real middleware does it to a real driver,
	// and the point of the seam is that the case is otherwise unreachable.
	if _, strip := args[StripKeyPlacement]; strip {
		delete(headers, idem.Placement)
		delete(args, idem.Placement)
	}

	// **VERIFY THE KEY SURVIVED, IMMEDIATELY BEFORE THE SEND (D186).** Placing it
	// is not the same as it being there when the request leaves. Fail-closed: an
	// unkeyed request reported as idempotent is exactly the condition D163 exists
	// to prevent, dressed as success.
	if err := idem.Verify(op, args, headers); err != nil {
		return connector.Result{}, err
	}

	// §6 MECHANISM 3, and a connector definition-of-done item: assert the
	// request's tenant against the target's, immediately before the outbound
	// call. Nanoseconds, and it is the only thing that catches a pooled client
	// belonging to the wrong tenant — a bug the constructor cannot see because
	// the substitution happens in the pool, after construction.
	if err := connector.AssertTenant(ctx, t); err != nil {
		return connector.Result{}, err
	}

	// THE BORROW, and this is what puts the pool in the enforcement path.
	//
	// Everything a revocation needs was built before this line existed and
	// reached nothing: `revoke_credential` evicted an empty pool and truthfully
	// reported cancelling zero calls (CONTRACTS §4 item 35). A driver that pools
	// privately is invisible to break-glass.
	//
	// The ctx handed to the callback is the one revocation CANCELS. Passing the
	// outer ctx to the work below instead would make revocation silently cancel
	// nothing while still reporting success — which is why D128 made this a
	// call-through rather than a checkout.
	work := func(ctx context.Context, client any) error {
		return d.call(ctx, op, client, t, args)
	}
	if d.pool == nil {
		// No pool wired: still correct, still governed, but nothing to revoke
		// through. Explicit rather than silent, because "the driver worked" and
		// "the driver was reachable by break-glass" must not look the same.
		if err := work(ctx, nil); err != nil {
			return connector.Result{}, err
		}
	} else if err := d.pool.Do(ctx, t, work); err != nil {
		return connector.Result{}, err
	}

	// EXTERNAL REF IS DERIVED, NOT COUNTED. A counter would be driver state; a
	// hash of (target, action, args) is deterministic, reproducible across runs,
	// and still unique per distinct call — which is what the audit trail needs
	// to join against (§5.4).
	return connector.Result{
		ExternalRef: externalRef(t, action, args),
		StatusCode:  201,
		Latency:     time.Since(started),
		Data: map[string]any{
			"action": spec.Name,
			"target": t.Ref(),
			"tenant": t.Tenant(),
			// WHEN kata recorded it — the time path a refines rule needs (D317).
			"at":        time.Now().UTC().Format(time.RFC3339Nano),
			"echo_args": args,
			// THE OUTBOUND HEADERS, so a step can assert WHERE the key went rather
			// than asking Sekizui what it did — a guard whose two inputs share an
			// origin is not a guard (D159).
			//
			// **map[string]any, NOT map[string]string, AND THE DIFFERENCE COST AN
			// HOUR.** structpb.NewStruct accepts a fixed set of Go types and
			// map[string]string is not among them, so one unconvertible value made
			// the WHOLE Data map fail to convert — and the gateway discards that
			// error (CONTRACTS 73). The result payload silently became empty, and
			// the symptom was P1 step 24 reporting "TENANT BLEED through the pool
			// — 32 of 32 commands reached the wrong tenant", because the tenant it
			// reads had gone with everything else.
			"echo_headers": headers,
		},
	}, nil
}

// Query performs a read.
//
// Separate from Execute so the read and write planes stay distinguishable in
// policy, audit, and metrics (§4.1.1) — not because the kata needs the
// distinction, but because a driver that blurred it would let a consumer of this
// kata write code that breaks against a real one.
func (d *Driver) Query(ctx context.Context, t connector.Target, action string,
	args map[string]any) (connector.Rows, error) {

	const op = "kata.Query"

	if _, err := d.lookup(op, action, true); err != nil {
		return connector.Rows{}, err
	}
	// Reads leak just as effectively as writes (§4.1.1 governs both).
	if err := connector.AssertTenant(ctx, t); err != nil {
		return connector.Rows{}, err
	}
	if err := d.simulate(ctx, op, args); err != nil {
		return connector.Rows{}, err
	}

	// A ROW RICH ENOUGH TO BE WORTH LENSING, including a nested personal field.
	// A kata that returns three flat scalars cannot demonstrate withholding, and
	// real reads return exactly this shape — an identifier, some context, and
	// personal data that not every consumer should receive (D83).
	return connector.Rows{
		Rows: []map[string]any{{
			"id":     externalRef(t, action, args),
			"tenant": t.Tenant(),
			"target": t.Ref(),
			"at":     time.Now().UTC().Format(time.RFC3339Nano),
			"user": map[string]any{
				"id":    "u-4417",
				"email": "someone@example.invalid",
			},
		}},
		Truncated: false,
	}, nil
}

// reflexesYAML is kata's refines rules (D299, D317): the reference driver
// teaches every contract a driver can implement, the Refiner's included —
// and its write rule is what exercises a seiren beside `CommandResult.result`
// (CONTRACTS 145), since no other in-tree write result carries a time.
//
//go:embed reflexes.yaml
var reflexesYAML []byte

// Reflexes makes kata a connector.Refiner.
func (d *Driver) Reflexes() []byte { return reflexesYAML }

// presetsYAML is kata's suggested presets (D327) — embedded so boot can compare
// a deployment's copy with it, never so a grant can expand from it.
//
//go:embed presets.yaml
var presetsYAML []byte

// SuggestedPresets makes kata a connector.Presetter: the reference driver
// teaches every contract (D317's reason for making it a Refiner).
func (d *Driver) SuggestedPresets() []byte { return presetsYAML }

// kataLevels are kata's FICTIONAL vendor levels, least privileged first — here
// to teach connector.Leveled, as the binding classes are here to teach §4.7.4.
//
//nolint:gochecknoglobals // immutable vocabulary
var kataLevels = []string{"viewer", "contributor", "owner"}

// actionLevels is the level each action needs. EVERY action has one: a
// connector that grades must grade everything it serves, or a `mirrors:` claim
// over an ungraded action cannot be checked and is refused.
//
//nolint:gochecknoglobals // immutable, fixed at compile time
var actionLevels = map[string]string{
	"kata.read": "viewer", "kata.poll": "viewer",
	"kata.create_issue": "contributor", "kata.comment": "contributor",
	"kata.upsert_record": "contributor", "kata.append_event": "contributor",
	"kata.delete_project": "owner",
}

// VendorLevels makes kata a connector.Leveled.
func (d *Driver) VendorLevels() []string { return append([]string(nil), kataLevels...) }

// ActionLevel is the level kata requires for action.
func (d *Driver) ActionLevel(action string) (string, bool) {
	l, ok := actionLevels[action]
	return l, ok
}

// Health reports whether the driver can reach the target.
//
// Always healthy: there is nothing to reach. Returning an error would be a lie,
// and always-nil is the honest answer for a driver with no far side.
func (d *Driver) Health(ctx context.Context, t connector.Target) error {
	if err := ctx.Err(); err != nil {
		return fault.Wrap(fault.KindTimeout, "kata.Health", "context done", err)
	}
	if !t.Resolved() {
		return fault.New(fault.KindInternal, "kata.Health",
			"unresolved target; it did not come from a resolver")
	}
	return nil
}

// lookup finds an action and checks it is being invoked through the right plane.
func (d *Driver) lookup(op, action string, wantRead bool) (connector.ActionSpec, error) {
	for _, s := range d.Actions() {
		if s.Name != action {
			continue
		}
		// A mutating action reached through Query would be a write that policy
		// and audit both recorded as a read.
		if wantRead && s.Mutating {
			return connector.ActionSpec{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"action %q is mutating and must go through Execute, not Query", action))
		}
		if !wantRead && !s.Mutating {
			return connector.ActionSpec{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"action %q is non-mutating and must go through Query, not Execute", action))
		}
		return s, nil
	}
	return connector.ActionSpec{}, fault.New(fault.KindNotFound, op,
		fmt.Sprintf("unknown action %q", action))
}

// simulate honours cancellation, injected latency, and injected failure.
func (d *Driver) simulate(ctx context.Context, op string, args map[string]any) error {
	// Every method honours cancellation and deadlines (connector DoD).
	if err := ctx.Err(); err != nil {
		return fault.Wrap(fault.KindTimeout, op, "context done before work started", err)
	}

	if raw, ok := args[LatencyKey].(string); ok {
		delay, err := time.ParseDuration(raw)
		if err != nil {
			return fault.Wrap(fault.KindInvalidArgument, op,
				fmt.Sprintf("%s=%q is not a duration", LatencyKey, raw), err)
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			// The deadline won. This is the path a real driver takes on a slow
			// upstream, and it must be a timeout rather than a target error.
			return fault.Wrap(fault.KindTimeout, op, "deadline exceeded during call", ctx.Err())
		}
	}

	if raw, ok := args[FailKey].(string); ok {
		kind, ok := fault.ParseKind(raw)
		if !ok {
			return fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"%s=%q is not a known fault kind", FailKey, raw))
		}
		// &Error{} rather than fault.New, which deliberately returns `error` and
		// gives no way to set RetryAfter — see its doc comment.
		e := &fault.Error{Kind: kind, Op: op, Msg: fmt.Sprintf("injected failure: %s", kind)}
		if after, present := args[RetryAfterKey].(string); present {
			d, perr := time.ParseDuration(after)
			if perr != nil {
				return fault.Wrap(fault.KindInvalidArgument, op,
					fmt.Sprintf("%s=%q is not a duration", RetryAfterKey, after), perr)
			}
			e.RetryAfter = d
		}
		return e
	}
	return nil
}

// externalRef derives a stable identifier from the call.
func externalRef(t connector.Target, action string, args map[string]any) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|", t.Ref(), t.Tenant(), action)

	// Map iteration order is randomised (GO-PRIMER §15), so args are folded in
	// order-independently: XOR of per-key digests. Without this the "same call
	// gives the same ref" property would hold only by luck.
	var acc [sha256.Size]byte
	for k, v := range args {
		if k == FailKey || k == LatencyKey || k == RetryAfterKey {
			continue // control arguments are not part of the call's identity
		}
		d := sha256.Sum256([]byte(fmt.Sprintf("%s=%v", k, v)))
		for i := range acc {
			acc[i] ^= d[i]
		}
	}
	h.Write(acc[:])
	return "KATA-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// call is the work done while holding a pooled client — the stand-in for an
// outbound request.
//
// AUTHENTICATION HAPPENS HERE, per class (§4.7.4). Class 1 borrows the
// credential for each call; classes 2 and 3 do not, because their client was
// constructed with it and has no per-call seam. That asymmetry is the whole of
// D101, and modelling it is what makes acceptance steps 50-52 mean anything.
func (d *Driver) call(ctx context.Context, op string, client any, t connector.Target,
	args map[string]any) error {

	if sc, ok := client.(*sessionClient); ok && sc.isClosed() {
		// DEFENCE IN DEPTH, the same shape as AssertTenant below. The pool
		// guarantees a torn-down client is never handed out again; asserting it
		// here means a bug in that guarantee surfaces as a refusal rather than
		// as a call against a session the server already considers gone.
		return fault.New(fault.KindDenied, op,
			"this pooled client was torn down; the session it held is no longer valid")
	}

	if classOf(client) != Class1 {
		// Classes 2 and 3: the credential was bound at construction. Nothing to
		// stamp, and deliberately no borrow — a class 2 driver that re-read the
		// credential per call would BE a class 1 driver, and the step asserting
		// it needs eviction would pass for the wrong reason.
		return d.simulate(ctx, op, args)
	}

	header := make([]byte, 0, 8+64)
	header = append(header, "Bearer "...)
	if err := t.Use(func(m connector.Material) error {
		// A class 1 driver stamps `Authorization: Bearer <material>` onto its
		// outbound request. Appending into a buffer this driver owns means
		// Sekizui's slice never leaves the callback (D127) — and it costs
		// nothing, because building the header copies the material either way.
		//
		// The LOAD-BEARING part is the refusal: `Use` errors for a credential
		// wiped by eviction or revocation, and that error propagates out of
		// Execute and fails the command.
		var err error
		header, err = m.AppendTo(header)
		return err
	}); err != nil {
		return err
	}
	clear(header) // the driver's own copy, gone as soon as the request is built

	return d.simulate(ctx, op, args)
}

// classOf reports the binding class of a pooled client, tolerating a nil client
// (the no-pool path) by treating it as class 1 — which is what an unpooled
// driver behaves like: it borrows per call and holds nothing.
func classOf(c any) string {
	switch v := c.(type) {
	case *sessionClient:
		return v.class
	case *client:
		return v.class
	default:
		return Class1
	}
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

// Meter declares kata's meter (D284): calls, one per call, and ONE per poll —
// a kata poll derives its rows and reads nothing upstream. No default of its
// own, so an unlimited-looking fixture still spends the universal budget like
// every other target; the reference driver is the worst place to be exempt.
func (d *Driver) Meter() connector.Meter {
	return connector.Meter{
		Unit:     connector.UnitCalls,
		PollCost: func(connector.Configured) uint64 { return 1 },
		// THE DRIFTER'S TWO DECLARATIONS (D311), in the form a real connector
		// fills in: a SYSTEM budget of its own — twelve comparisons an hour, the
		// drift watcher's cadence — so consumers never pay for Sekizui's safety
		// checks, and the worst-case price of one comparison, before it is sent.
		// kata's comparison reads a setting; a real one reads the network, and
		// is priced as the call it is.
		SystemPerHour: 12,
		DriftCost:     func(connector.Configured) uint64 { return 1 },
	}
}

// SurfaceKey is the target setting that SIMULATES the vendor's live surface for
// drift (D311): the vendor's own names for what it offers today, comma-separated
// — `create_issue,comment` — where kata's vetted actions are `kata.<name>`.
// Absent means the vendor offers exactly what was vetted. kata simulates its
// vendor through settings throughout (`kata_rows`, `_misbehave_*`); this is the
// same idiom for the one thing a real connector reads from the network.
const SurfaceKey = "kata_surface"

// Drift is the worked form of connector.Drifter (D311): compare what a human
// VETTED — the action set in code — with what the vendor offers NOW, and grade
// every difference in the published vocabulary.
//
// THE THREE THINGS EVERY DRIFTER DOES, in order:
//  1. ASSERT THE TENANT before anything that would be egress (§6 mechanism 3).
//     A comparison carries the target's credential in a real connector.
//  2. ONLY READ. A comparison that changed anything would make the safety
//     check a side effect; RunDrift asserts two comparisons in a row agree.
//  3. GRADE IN THE VOCABULARY, never invent a severity: a vetted action the
//     vendor dropped is WITHHELD (the catalog stops advertising it), something
//     nobody vetted is UNVETTED (harmless — it has no action to call).
func (d *Driver) Drift(ctx context.Context, t connector.Target) (connector.DriftFindings, error) {
	if err := connector.AssertTenant(ctx, t); err != nil {
		return nil, err
	}
	raw := t.Setting(SurfaceKey)
	if raw == "" {
		return nil, nil
	}
	live := map[string]bool{}
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
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
