// Package connector defines the extension surface for reaching external systems.
//
// This is PUBLIC API (D35). Sekizui ships open source and self-hosters add their
// own systems, so a third party implementing Driver must never need to fork.
//
// DESIGN.md references: §4.3, §6, D4, D35.
package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Driver is a stateless, credential-free client for one KIND of system.
//
// One Driver instance per process, shared across all tenants and all
// concurrent requests. It holds no credentials and no per-instance state —
// that is what makes it safe to share (D4).
//
// This is the break from Lexicon, where each connector was a module-level
// singleton with its auth header computed once in the constructor
// (lexicon/Atlassian.js:25) and therefore bound to exactly one
// Jira instance for the process lifetime.
//
// Implementations MUST be safe for concurrent use by multiple goroutines with
// different Targets. This is verified by the mixed-tenant property test, not by
// inspection (§6 item 5).
type Driver interface {
	// Kind returns the system kind this driver serves: "jira", "bigquery",
	// "fullstory". Matches Target.Kind and the prefix of action names.
	Kind() string

	// Actions returns every action this driver implements, with its input schema
	// reference. The capability catalog (§4.9) and the boot-time reflex
	// validation (§4.11.4b) are both generated from this — so a driver cannot
	// advertise an action it does not implement, and a rule cannot reference an
	// action nobody implements.
	Actions() []ActionSpec

	// Schemas returns the schema of every payload type this driver's actions
	// declare (D279). REQUIRED, and not optional per type: a declared type
	// without a schema fails the boot and the published suite, naming the
	// connector. The schemas ship in the driver package — `go:embed` beside
	// the code that emits the data — and are parsed with ParseSchemas.
	Schemas() ([]Schema, error)

	// Meter declares what this connector's upstream meters and what each call
	// and poll costs in it (D171, D284). REQUIRED, like Schemas: the spine
	// prices every call with it before sending, and a connector whose meter is
	// unsound (CheckMeter) is quarantined. The zero value is sound for a
	// calls-metered driver that is not a Source.
	Meter() Meter

	// Execute performs a mutating action.
	//
	// The Target arrives per call and is already resolved and authorised. The
	// driver MUST NOT re-derive credentials, consult configuration, or cache
	// anything keyed on anything other than Target.PoolKey().
	//
	// idem carries the action's declared idempotency class, where the key goes,
	// and the key itself (D163). A driver MUST place the key where the class says
	// and MUST REFUSE rather than send the call without it — sending it unkeyed
	// produces the double-write the classification exists to prevent while every
	// log line reports a successful idempotent write, which is the failure §4.7.10
	// keeps naming: the operator watches the guarantee appear to work.
	//
	// ADDED IN P2, BREAKING THE SIGNATURE ON PURPOSE (D163). The key previously
	// reached the decision record and the retry gate and nothing else, so it
	// authorised a retry it did not make safe (CONTRACTS 63) — invisible while the
	// only driver had no external side effect. Taken now, while pkg/ has no
	// external implementers and three drivers do not yet exist.
	Execute(ctx context.Context, t Target, action string, args map[string]any,
		idem Idempotency) (Result, error)

	// Query performs a read. Separate from Execute so the read and write planes
	// stay distinguishable in policy, audit, and metrics (§4.1.1).
	Query(ctx context.Context, t Target, action string, args map[string]any) (Rows, error)

	// Health reports whether this driver can currently reach the target.
	// Feeds the panel's target health view (§4.8) and readiness.
	Health(ctx context.Context, t Target) error
}

// HostBound is an OPTIONAL Driver method: whether a target's base_url is a host
// this connector's vendor actually serves (P3 step 24, CONTRACTS 117).
//
// **A CREDENTIAL GOES WHERE base_url POINTS.** Nothing spine-side bounds the
// host a driver dials, so a target naming any host sent that vendor's
// credential there on every call — the road D286's credential theft rode. A
// driver that knows its vendor's hosts says so here; boot refuses a target
// outside them, and the driver refuses again on every call. Optional and
// type-asserted: a generic driver (MCP, Jira Cloud's per-customer sites)
// cannot know a fixed host list.
type HostBound interface {
	AdmitBaseURL(targetRef, baseURL string) error
}

// ClientPool is how a driver obtains a client that Sekizui can evict, tear down
// and REVOKE (§4.7.4, D106, D128).
//
// PUBLIC BECAUSE REVOCATION HAS TO REACH THIRD-PARTY DRIVERS. A driver that
// pools its own clients privately is invisible to break-glass: `revoke_credential`
// would evict Sekizui's pool, report what it cancelled, and leave that driver's
// connections running with the compromised credential. Since self-hosters write
// drivers (D35), the borrowing seam has to be part of the published surface or
// the guarantee only holds for drivers we happen to have written.
//
// SATISFIED STRUCTURALLY BY `internal/pool.Pool` — this package declares the
// method set it needs and never imports the implementation, which is what keeps
// pkg/ free of a dependency on internal/ (GO-PRIMER §2.1).
//
// The call-through shape is D128: fn cannot be given a context other than the
// cancellable one, and the borrow cannot be left un-released, because both are
// the pool's to manage rather than the driver's to remember.
type ClientPool interface {
	// Do borrows a client for the Target and runs fn against it.
	//
	// The ctx passed to fn is CANCELLED when the credential is revoked. A driver
	// must pass that context to its outbound call — passing its own instead
	// makes revocation silently cancel nothing.
	Do(ctx context.Context, t Target, fn func(ctx context.Context, client any) error) error
}

// Source is implemented by drivers that can be polled for events (the afferent
// path). Optional — a driver may be write-only, like a Slack or Kafka sink.
//
// STATELESS BY SIGNATURE, which is the property everything else here rests on.
// The cursor is handed IN and the next one is handed OUT, so the SPINE holds the
// state and a source holds none. That is what lets a source be re-run, shared
// across tenants, and — the part D174 turns on — asked to recover without ever
// being told anything about Sekizui's own records.
type Source interface {
	// Poll returns events after the given cursor, plus the cursor to use next.
	//
	// A source is NOT required to be resumable, and MUST NOT be written as
	// though the spine assumes it is (D174). Say what is true in Recovery
	// below; the spine handles each answer, including "I cannot".
	Poll(ctx context.Context, t Target, cursor string, limit int) (events []RawEvent, next string, err error)

	// Recovery declares what this source can do when a poll did not commit.
	//
	// **DECLARED, NEVER DETECTED (D174).** The spine knows that the last poll
	// did not commit — it holds the cursor — and the connector knows what
	// re-querying costs and whether it is safe. A connector that DETECTED an
	// unclosed window would need to read the audit log, and that is an attack
	// surface in a component explicitly designed to be third-party-written
	// (D35). So the spine decides WHEN to recover, runs the recovery through
	// the governed path, and records what happened; this method only says what
	// is possible.
	//
	// REQUIRED RATHER THAN OPTIONAL, which is a departure from the
	// type-asserted optional interfaces elsewhere here (GO-PRIMER §2.2) and is
	// affordable for exactly one reason: nothing implements Source yet, so a
	// required method breaks no out-of-tree driver today and is a compile error
	// for the first one that arrives. That is the NewRecorder shape from D149 —
	// a required parameter cannot be forgotten — and the alternative, an
	// optional interface, would make the commonest failure a SILENT default.
	//
	// **IT TAKES A TARGET, AND THAT IS NOT SYMMETRY WITH Poll.** Recovery is
	// often a property of the SYSTEM rather than of the driver: a BigQuery
	// table that is append-only with a monotonic watermark can be re-queried
	// and one whose rows are updated in place cannot, and no amount of vendor
	// knowledge tells a driver which it is looking at. Without the target a
	// driver must answer for the worst system it might ever serve, so every
	// crash writes a gap marker even where recovery was possible — D153's
	// lesson exactly, an over-general derivation quietly degrading more than
	// the special case it replaced.
	//
	// The layering is D171's, unchanged: the TARGET declares the facts in
	// configuration (`Setting`), the CONNECTOR interprets them because it is
	// the only party that knows what makes this vendor's window re-readable,
	// and the SPINE knows neither and only acts on the answer.
	Recovery(t Target) RecoveryPolicy
}

// RecoveryMode is what a source can do about a window that was polled and never
// committed.
//
// **THE ZERO VALUE IS THE HONEST ONE.** A RecoveryPolicy nobody filled in reads
// as RecoveryUnable, so the spine records a gap rather than assuming rows can be
// fetched again. "Not declared is not available" is D117's rule and this is the
// case where the other direction loses data silently: an unfilled struct
// claiming recoverability produces a poller that quietly drops a window and
// reports nothing.
//
// The ordering of the constants below is LOAD-BEARING and looks arbitrary, which
// is why GO-PRIMER §15aj exists: reverse them and a driver author who forgets to
// fill the struct claims their source is re-queryable, with no compiler warning
// and no lint to say so.
type RecoveryMode int

const (
	// RecoveryUnable — the window cannot be fetched again, so an interrupted
	// poll loses rows and the spine writes a GAP MARKER naming what was lost
	// (D174). A legitimate answer, not a failure: a source that cannot be
	// re-queried is a fact about the upstream, and the design's contribution is
	// making the loss VISIBLE rather than pretending it did not happen.
	RecoveryUnable RecoveryMode = iota

	// RecoveryRequery — handing back the previous cursor yields the same
	// window. The spine re-polls from it and the rows arrive exactly once,
	// because the dedupe record is Sekizui's own (D170).
	RecoveryRequery
)

// RecoveryPolicy is a source's answer to "what can you do about an uncommitted
// window".
//
// **D174 NAMES THREE ANSWERS AND THIS CARRIES TWO, DELIBERATELY.** The third —
// replay from a checkpoint — is not represented because the spine's ACTION
// under it is identical to RecoveryRequery: hand back the previous position and
// expect the same rows. A mode that changes nothing the spine does is a
// vocabulary entry that promises something and delivers nothing, which is
// exactly CONTRACTS 65's shape — an anzen rule may watch a signal nothing
// raises, and boot says nothing. It lands when a source needs it to mean
// something different, and not before.
type RecoveryPolicy struct {
	// Mode is what the source can do. Zero value is RecoveryUnable.
	Mode RecoveryMode

	// MaxLookback bounds how far back RecoveryRequery reaches, where the
	// upstream has a retention window. Zero means the source states NO bound,
	// and the spine does not invent one — a lookback nobody declared is not a
	// lookback of zero, which would make every recovery a no-op that looked
	// like a success.
	MaxLookback time.Duration

	// Why is the operator-facing reason, and it is REQUIRED for
	// RecoveryUnable: it lands in the gap marker, which exists so somebody can
	// act on the loss. "Recovery impossible" names a state; "the export API
	// only serves the current window" names the thing to change.
	Why string
}

// ActionSpec describes one action a driver implements.
type ActionSpec struct {
	// Name, e.g. "jira.create_issue". Prefix must equal Driver.Kind().
	//
	// MCP actions are namespaced by server: "mcp.github.search" (D49). Names
	// must be globally unique because Actions() takes no Target, so one mcp
	// driver returns one flat list spanning every configured server.
	Name string

	// True for actions with side effects. Mutating actions require an
	// idempotency key and are audited as external effects (D23).
	//
	// For MCP this is NEVER inferred from the vendor's readOnlyHint /
	// destructiveHint, which are hints rather than contract. A human
	// classifies it in the vetted spec and a missing classification fails the
	// load (§4.9a.1).
	Mutating bool

	// URI of the registered JSON Schema for args (D40). Args are validated
	// against it before the driver is called, so drivers need not re-validate
	// shape — only semantics.
	//
	// No origin field: input schemas are uniform
	// per driver rather than per action. Every MCP tool has a vendor-supplied
	// one because the protocol requires it. A native driver's is hand-written —
	// or, since D314, DERIVED from its vendor's published contract, as the
	// Fullstory driver's are from its reference revision's operations, which
	// also checks the arguments closed by default against it.
	InputSchema string

	// OutputType is the payload TYPE this action's results carry, including
	// version — "kata.read_result.v1" (D41, D88).
	//
	// THE REGISTRY KEY, and since D279 the only link to the shape: the schema
	// itself is what the driver's Schemas() returns for this type. An
	// `OutputSchema` URI stood beside this field "naming where to fetch the
	// schema document", and nothing ever fetched it — removed by D279 rather
	// than left reading as a second, decorative statement of the same fact.
	//
	// REQUIRED FOR A READ, optional for a write (D279). A read brings data in,
	// so its results are shaped to this type's schema — which the driver ships —
	// before any lens (§4.12); an untyped read would pass whatever the far side
	// returned, and ValidateActions refuses it. A write with no result type
	// brings nothing in to shape.
	OutputType string

	// NoResult declares that this action returns NO DATA (D283) — the one
	// alternative to an OutputType. Every action says one or the other, so no
	// result can enter Sekizui undeclared: data returned by a NoResult action
	// is withheld, loudly, and never recorded or passed on.
	NoResult bool

	// Bound is how many results a READ may return, and optionally the argument
	// through which a caller asks for fewer (D283). ABSENT MEANS ONE OBJECT —
	// every Execute result and every single-object read — so only a read that
	// returns many rows declares one. The gateway turns it into a declared cost
	// (rows × the per-object budget) and checks it against the authorising
	// capability's max_bytes BEFORE the call, for every verb.
	Bound *ResultBound

	// Handle is this action's part in a stateful handle's lifecycle (D291), or
	// nil. A connector whose tool allocates something the vendor must be told
	// to release — a review session, a sandbox, a transaction — declares the
	// opener, the closer and the users here, and the spine records each handle
	// and closes it when it goes idle or the process drains, as its opener.
	Handle *HandleRole

	// OutputTypes are the OTHER payload types this action may emit (D276) —
	// a poll whose target chooses between shapes, a vendor with several
	// schemas behind one call. The action's declared set is OutputType plus
	// these; boot refuses any of them without a schema the connector ships
	// (D279), and the runner refuses, per event, a type outside the set.
	OutputTypes []string

	// Idempotency says HOW a repeat of this action is made safe (D163).
	//
	// REQUIRED WHEN Mutating IS TRUE, and boot refuses a mutating action that
	// leaves it empty. Ignored for reads, which are repeatable by definition.
	//
	// The failure direction is deliberate: a default would be silent, and there
	// is no safe one. Defaulting to `none` would quietly forbid retries a
	// connector could support; defaulting to anything else would permit a
	// double-write nobody chose. So the load fails and a human writes it down —
	// the same rule §4.9a.1 gives Mutating for MCP tools.
	Idempotency IdempotencyClass

	// IdempotencyPlacement names WHERE the key goes: a header name for
	// IdempotencyHeader, a dotted body path for IdempotencyField.
	//
	// Required exactly when Idempotency.NeedsPlacement(), and refused otherwise —
	// a paired-field invariant, enforced at load rather than at call time.
	IdempotencyPlacement string

	// Human/LLM-readable, and REQUIRED (D196).
	//
	// The catalog inlines granted constraints into this (§4.9 property 2), and
	// the consumer is a model deciding what to attempt. An action with no
	// description left the catalog nothing to say, so it SYNTHESISED one from the
	// identifier — "kata.create_issue on kata:alpha." — which fills a field
	// whose whole purpose is to say what the action DOES with a restatement of
	// what it is CALLED. Nothing here is synthesised: the load fails instead,
	// naming the action, because a description nobody wrote is a claim nobody
	// made.
	Description string
}

// SchemaOrigin records the provenance of an output schema (D51).
//
// This exists because a schema we wrote and a schema the vendor published are
// different kinds of claim, and treating them alike would either make absence
// look like drift or let a local guess masquerade as a vendor guarantee.
//
// A defined string type rather than a plain string: the compiler then rejects
// an arbitrary literal at the call site, while the value still marshals to
// readable YAML in the vetted spec.
type SchemaOrigin string

const (
	// SchemaFromVendor — copied from the system's own advertisement, e.g. an
	// MCP server's tools/list, then vetted by a human. There is a live claim
	// to compare against, so this IS drift-checked (§4.9a.3a).
	SchemaFromVendor SchemaOrigin = "vendor"

	// SchemaFromLocal — authored by a maintainer from observed responses. The
	// vendor asserts nothing, so there is nothing to diverge from and this is
	// NEVER drift-checked.
	//
	// It exists so reflexes still work against servers that publish no output
	// schema: D42 needs a registered schema to validate field paths, and the
	// vetted spec is allowed to be richer than what the vendor advertises.
	// The cost is honest — a local schema is an unverified assertion about
	// someone else's API, and when it starts failing, "they changed" and "we
	// guessed wrong" are indistinguishable.
	SchemaFromLocal SchemaOrigin = "local"
)

// IdempotencyClass says HOW an action can safely be repeated (D163).
//
// **CLASSIFIED BY A HUMAN, NEVER INFERRED**, and an absent classification on a
// mutating action fails the load. That is the same rule §4.9a.1 gives
// ActionSpec.Mutating, and for the same reason: a default would be silent, and
// the wrong default permits a double-write nobody chose.
//
// **PER ACTION, NOT PER DRIVER**, which Fullstory proves rather than motivates.
// `POST /v2/users` is a create-or-update keyed on `uid` and is therefore
// `natural`; `POST /v2/events` documents no dedupe of any kind and is `none`.
// Two actions, one vendor, opposite answers — a per-driver field would have been
// wrong on its first connector.
//
// **THE VOCABULARY IS OPEN IN SPIRIT AND CLOSED IN CODE**, and the distinction
// matters. Sekizui cannot know every way an upstream meters or dedupes, so the
// classes describe MECHANISMS rather than vendors, and a new mechanism is a new
// member here rather than a special case in a driver. What is deliberately NOT
// modelled is the vendor's own semantics: this type says where a key goes, not
// what the far side does with it.
//
// A defined string type rather than a plain string, following SchemaOrigin: the
// compiler then rejects an arbitrary literal at the call site while the value
// still reads as ordinary YAML in a vetted spec.
type IdempotencyClass string

const (
	// IdempotencyHeader — the upstream honours a key in a named request header.
	// Stripe's `Idempotency-Key`, PayPal's `PayPal-Request-Id`.
	IdempotencyHeader IdempotencyClass = "header"

	// IdempotencyField — the key goes in the request body at a named path.
	// BigQuery streaming inserts do this with `insertId`.
	IdempotencyField IdempotencyClass = "field"

	// IdempotencyNatural — the action is repeat-safe by construction and needs
	// no key at all: an upsert, or a PUT with a client-chosen identifier.
	// Fullstory's create-or-update user is this.
	IdempotencyNatural IdempotencyClass = "natural"

	// IdempotencyConditional — the retry must carry a precondition, so a repeat
	// FAILS rather than duplicating. ETag / If-Match.
	//
	// DECLARED AND NOT IMPLEMENTED IN THIS BUILD — see Implemented. It threads a
	// value from a prior response rather than a key from the request, which is a
	// different data flow, and no connector needs it yet.
	IdempotencyConditional IdempotencyClass = "conditional"

	// IdempotencyNone — the upstream offers no mechanism. A repeat duplicates,
	// so a retry is REFUSED (D113, D163). Fullstory's create-event, Jira's
	// create-issue.
	//
	// NOT A FAILURE TO CLASSIFY. It is a positive statement that the upstream
	// cannot help, and it is the honest answer for a great many APIs — which is
	// why it must be written down rather than left blank, since blank means
	// "nobody thought about it" and this means "somebody did".
	IdempotencyNone IdempotencyClass = "none"
)

// idempotencyClasses is the one source (§15q). The predicate and the enumerator
// below are what everything else calls, so adding a class is one edit here
// rather than four scattered ones.
//
//nolint:gochecknoglobals // immutable vocabulary, fixed at compile time
var idempotencyClasses = map[IdempotencyClass]struct {
	// needsPlacement: the class names WHERE the key goes, so a placement is
	// required and a missing one fails the load.
	needsPlacement bool

	// needsKey: a caller-supplied key is required for a repeat to be safe.
	// `natural` needs none; `none` cannot use one.
	needsKey bool

	// allowsRetry: whether a repeat can be made safe at all.
	allowsRetry bool

	// implemented: whether THIS BUILD can honour the class. A declared class
	// that is not implemented refuses at boot rather than degrading silently —
	// D53's rule (run or refuse, never silently succeed at nothing) applied to a
	// taxonomy, because the blueprint's value is showing a connector author the
	// whole shape and its cost is a member nobody wired.
	implemented bool

	why string
}{
	IdempotencyHeader:      {needsPlacement: true, needsKey: true, allowsRetry: true, implemented: true, why: "key in a named request header"},
	IdempotencyField:       {needsPlacement: true, needsKey: true, allowsRetry: true, implemented: true, why: "key at a named path in the request body"},
	IdempotencyNatural:     {allowsRetry: true, implemented: true, why: "repeat-safe by construction; an upsert or a client-keyed PUT"},
	IdempotencyConditional: {needsKey: true, allowsRetry: true, implemented: false, why: "a precondition carried from a prior response; ETag / If-Match"},
	IdempotencyNone:        {implemented: true, why: "the upstream offers no mechanism, so a retry is refused"},
}

// Known reports whether c is in the vocabulary. An unknown class is a typo or a
// driver written against a newer Sekizui, and both must fail the load rather
// than fall through to a default.
func (c IdempotencyClass) Known() bool { _, ok := idempotencyClasses[c]; return ok }

// NeedsPlacement reports whether c requires ActionSpec.IdempotencyPlacement.
func (c IdempotencyClass) NeedsPlacement() bool { return idempotencyClasses[c].needsPlacement }

// NeedsKey reports whether a caller-supplied idempotency key is required.
func (c IdempotencyClass) NeedsKey() bool { return idempotencyClasses[c].needsKey }

// AllowsRetry reports whether a repeat of this action can be made safe.
//
// THE PREDICATE THE RETRY GATE ASKS, replacing "is the key string non-empty",
// which was the bug: a key authorised a retry it did not make safe, because
// nothing carried it to the upstream (CONTRACTS 63).
func (c IdempotencyClass) AllowsRetry() bool { return idempotencyClasses[c].allowsRetry }

// Implemented reports whether this build can honour c.
func (c IdempotencyClass) Implemented() bool { return idempotencyClasses[c].implemented }

// Explain returns the one-line rationale, for boot errors and the catalog.
func (c IdempotencyClass) Explain() string { return idempotencyClasses[c].why }

// IdempotencyClasses enumerates the vocabulary, sorted.
//
// FOR TESTS AND FOR BOOT REPORTING, and it is the part worth copying: an
// assertion that ranges over the whole set covers the class somebody adds next
// year, where one naming a member passes forever and checks nothing (§15q).
func IdempotencyClasses() []IdempotencyClass {
	out := make([]IdempotencyClass, 0, len(idempotencyClasses))
	for c := range idempotencyClasses {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Idempotency is everything a driver needs to make one call repeat-safely: the
// class its ActionSpec declared, where the key goes, and the key itself.
//
// ONE PARAMETER RATHER THAN THREE, because Driver.Execute is public API (D35)
// and a struct grows without a signature change, where a fourth positional
// argument would break every implementer again.
//
// THE PLACEMENT IS PASSED RATHER THAN LOOKED UP, even though the driver declared
// it. The spine read the ActionSpec at boot and validated it; a driver
// re-deriving the placement at call time is a second source of truth, and D155's
// lesson is that the second one drifts silently.
type Idempotency struct {
	Class     IdempotencyClass
	Placement string
	Key       string
}

// UnimplementedClasses returns the classes this build declares and cannot
// honour, sorted.
//
// **SO A BOOT CAN DISCLOSE THE GAP RATHER THAN LEAVING IT TO BE DISCOVERED
// (D186).** D163 builds the vocabulary WHOLE even where a member is not fleshed
// out, so the blueprint can show a connector author the full shape — and the
// hazard that creates is a class sitting declared and inert, which is this
// codebase's recurring defect wearing a taxonomy. The load refuses such a class
// (ValidateActions), which serves the connector author at the moment they need
// it; this serves the OPERATOR, who otherwise has no way to know the vocabulary
// their configuration is validated against is not fully honoured.
//
// DERIVED FROM THE ONE SET, so a class implemented later disappears from the
// boot report without anybody editing it, and a class added unimplemented
// appears without anybody remembering to (§15q).
func UnimplementedClasses() []IdempotencyClass {
	var out []IdempotencyClass
	for _, c := range IdempotencyClasses() {
		if !c.Implemented() {
			out = append(out, c)
		}
	}
	return out
}

// PlaceIn writes the idempotency key where the class declares, returning the
// outbound body and headers — or REFUSES.
//
// **MOVED OUT OF THE DRIVER (D186), and CONTRACTS 63 is why.** Placement is
// governance rather than transport: D175 draws the line as "a driver is the
// code; a connector is the driver plus the governance that makes it safe to
// run", and the key reaching the wire is the safety property D163 exists for.
// It lived in the kata, where the second driver would have copied it — and the
// original defect was precisely that the key reached the predicate and the
// audit record and nothing else, because no single place owned carrying it.
// Three drivers each placing keys their own way is how one of them stops.
//
// **EVERY FAILURE HERE IS A REFUSAL, NEVER A DEGRADED SEND.** Sending the call
// without its key, or with the caller's own field overwritten, produces exactly
// the condition D163 exists to prevent while every log line reports a successful
// idempotent write — the shape §4.7.10 keeps warning about, where the operator
// watches the guarantee appear to work.
//
// `mutating` is passed rather than read from a spec, because the caller has the
// spec and this needs one bit of it; taking the whole ActionSpec would make the
// signature imply it validates more than it does.
func (i Idempotency) PlaceIn(op string, mutating bool, args map[string]any) (
	body, headers map[string]any, err error) {

	headers = map[string]any{}
	if !mutating {
		return args, headers, nil
	}

	if !i.Class.Known() {
		return nil, nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"idempotency class %q is not in the vocabulary. Known: %v",
			i.Class, IdempotencyClasses()))
	}
	if !i.Class.Implemented() {
		// NAMES WHAT TO DO, not just what is wrong. An author who picked a class
		// from the blueprint needs to know the member is real and this build
		// cannot honour it — otherwise "not implemented" reads as "you made it
		// up".
		return nil, nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"idempotency class %q is declared in the vocabulary and NOT implemented in "+
				"this build (%s). It is a real class and this is not a typo: pick one of "+
				"%v, or implement it — a class that cannot be honoured refuses rather "+
				"than sending the call without its guarantee (D53, D163)",
			i.Class, i.Class.Explain(), implementedClasses()))
	}

	// `natural` needs nothing placed and `none` has nowhere to put a key. The
	// retry gate is what enforces `none`, not this function.
	if !i.Class.NeedsPlacement() {
		return args, headers, nil
	}

	if i.Key == "" {
		return nil, nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"action is idempotency class %q and no key was supplied, so the call cannot "+
				"be made repeat-safe. Refusing rather than sending it unkeyed", i.Class))
	}
	if i.Placement == "" {
		return nil, nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"idempotency class %q requires a placement and none was declared", i.Class))
	}

	if i.Class == IdempotencyHeader {
		headers[i.Placement] = i.Key
		return args, headers, nil
	}

	// **A COLLISION IS A REFUSAL, and finding this is why placement moved here.**
	// The driver-local version wrote the key over whatever was at that path, so a
	// caller supplying a field named the same as the configured placement had its
	// value silently REPLACED — the upstream then acts on a request that differs
	// from the one the agent asked for, and the audit record echoes ours rather
	// than theirs. That is "a class whose configuration names a field the payload
	// has no room for", and overwriting is the one resolution that lies about it.
	if _, taken := args[i.Placement]; taken {
		return nil, nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"idempotency class %q places its key at body path %q and the caller already "+
				"supplied that field. Refusing rather than overwriting it: the upstream "+
				"would act on a request the caller did not make, and the record would "+
				"show ours rather than theirs",
			i.Class, i.Placement))
	}

	// COPY RATHER THAN MUTATE THE CALLER'S MAP. A map is a reference (§15i), and
	// writing into the caller's args leaks an internal detail into the audit
	// record's echo of what the agent asked for.
	out := make(map[string]any, len(args)+1)
	for k, v := range args {
		out[k] = v
	}
	out[i.Placement] = i.Key
	return out, headers, nil
}

// Verify reports whether the key actually survived to the outbound call.
//
// **CALLED IMMEDIATELY BEFORE THE SEND, on the REAL headers and body (D186).**
// PlaceIn putting the key somewhere is not the same as the key being there when
// the request leaves: an HTTP middleware can strip a header, a proxy can rewrite
// one, a body can be re-marshalled by a layer that drops unknown fields. Each of
// those produces an unkeyed request that every log line reports as a keyed one.
//
// FAIL-CLOSED, and the positive form of the placement test cannot express it.
// D163's guarantee is not "we tried to place a key"; it is that the upstream
// receives one, and the only honest thing a driver can do when it cannot confirm
// that is refuse.
//
// A CHEAP CHECK ON PURPOSE. Two map lookups on the write path, which is the
// right price for the one property that makes an idempotent retry meaningful.
func (i Idempotency) Verify(op string, body, headers map[string]any) error {
	if !i.Class.NeedsPlacement() {
		return nil
	}

	var got any
	var where string
	switch i.Class {
	case IdempotencyHeader:
		got, where = headers[i.Placement], "header"
	default:
		got, where = body[i.Placement], "body path"
	}

	if s, ok := got.(string); ok && s == i.Key {
		return nil
	}
	return fault.New(fault.KindConfig, op, fmt.Sprintf(
		"idempotency class %q requires the key at %s %q and it is not there on the "+
			"outbound call — something between placement and the wire removed or "+
			"rewrote it. REFUSING rather than sending an unkeyed request that every "+
			"log line would report as idempotent (D163, D186)",
		i.Class, where, i.Placement))
}

// implementedClasses is what an author can actually choose today.
func implementedClasses() []IdempotencyClass {
	var out []IdempotencyClass
	for _, c := range IdempotencyClasses() {
		if c.Implemented() {
			out = append(out, c)
		}
	}
	return out
}

// Target is one specific external instance, with credentials resolved and a
// tenant bound.
//
// CONSTRUCTION IS DELIBERATELY CONSTRAINED (§6 item 1). Fields are unexported and
// the only constructor validates. Driver methods require a Target, so a driver
// method cannot be called without one — which is what makes "forgot the tenant" a
// compile-time impossibility rather than a review item.
//
// Note on the §12.1 spike: perfect sealing across package boundaries is not
// achievable in Go without contortions (an unexported interface method confines
// implementation to the defining package). Validated-single-constructor is
// achievable and delivers the property we actually want. If the spike finds
// otherwise, revisit — but do not weaken this to a plain struct with exported
// fields, because then every call site becomes a place to get it wrong.
type Target struct {
	ref       string
	kind      string
	tenant    string
	residency string
	baseURL   string
	credVer   string
	settings  map[string]string

	// cred is a POINTER because a Target is copied freely — through the pool,
	// into a driver call — and every copy must share one wipeable, lockable
	// credential. A value here would mean a revocation zeroed one copy while
	// the others carried on (D127).
	cred *Credential
}

func (t Target) Ref() string       { return t.ref }
func (t Target) Kind() string      { return t.kind }
func (t Target) Tenant() string    { return t.tenant }
func (t Target) Residency() string { return t.residency }
func (t Target) BaseURL() string   { return t.baseURL }

// Use LENDS the credential to fn for the duration of the call (D127).
//
// REPLACES A `Credential() Secret` GETTER, and the change is the point. A getter
// hands out a slice with no scope: the driver may keep it, and a revocation then
// has to choose between zeroing memory somebody is reading (a data race that can
// produce a partially-valid credential, §4.7.10) and waiting for a caller that
// may never return (a window an attacker can hold open). Lending removes the
// choice — see the Credential type comment.
//
// fn receives a Material rather than a slice, so Sekizui's bytes never escape:
// a class 1 driver appends the credential into its own header buffer, which it
// was going to allocate anyway. Classes 2 and 3 need the raw slice to construct
// an SDK client or open a session, and use UseRaw.
func (t Target) Use(fn func(Material) error) error {
	if t.cred == nil {
		return fault.New(fault.KindConfig, "connector.Target.Use",
			"target "+t.ref+" has no credential; it was not built by a resolver")
	}
	return t.cred.Use(fn)
}

// UseRaw lends the raw slice, for §4.7.4 class 2 and class 3 only. Named so
// every exposure of credential bytes in the tree can be found with one grep.
func (t Target) UseRaw(fn func(material []byte) error) error {
	if t.cred == nil {
		return fault.New(fault.KindConfig, "connector.Target.UseRaw",
			"target "+t.ref+" has no credential; it was not built by a resolver")
	}
	return t.cred.UseRaw(fn)
}

// WipeCredential zeroes the material and makes every later Use refuse.
//
// Called by the pool when an entry is finalised — invariant 4 of §4.7.5. Safe
// while other Targets share this credential: they share the same *Credential,
// so they refuse rather than reading zeroed bytes.
func (t Target) WipeCredential() {
	if t.cred != nil {
		t.cred.Wipe()
	}
}

// CredentialWiped reports whether the material has been zeroed, for tests and
// for the staleness report (D109).
func (t Target) CredentialWiped() bool {
	return t.cred != nil && t.cred.Wiped()
}

// Setting returns a per-target configuration value, e.g. Fullstory "dc".
func (t Target) Setting(k string) string { return t.settings[k] }

// PoolKey is the ONLY legitimate key for caching anything derived from this
// Target — clients, connections, sessions.
//
// Derived from the type, never hand-assembled at a call site (§6 item 2). Every
// cross-tenant leak is a cache key missing a dimension; deriving it here means
// adding a field to Target forces the key to change, whereas a hand-built key at
// a call site silently drifts.
//
// credVer is included so credential rotation invalidates pooled clients
// (§4.3.2). It carries a generation rather than a hash of the material (D123),
// so nothing derived from a secret reaches this value.
//
// A TYPE RATHER THAN A STRING, and self-redacting (D112). `String`, `GoString`,
// and `LogValue` all yield only `kind:ref`; `credVer` is unexported and
// unreachable outside this package. The struct is comparable, so it works
// directly as a map key and the pool never needs a string form — which removes
// the last reason anyone would reach for one.
//
// Its justification narrowed once D123 removed the content hash: this no longer
// prevents a confirmation oracle, it keeps secret-manager PATHS out of logs.
// That is a smaller reason and still a real one — a reference names a project
// and a secret, which is infrastructure layout nobody needs in a metric label.
func (t Target) PoolKey() PoolKey {
	return PoolKey{kind: t.kind, ref: t.ref, credVer: t.credVer}
}

// PoolKey identifies a pooled client. See Target.PoolKey.
type PoolKey struct {
	kind, ref string

	// credVer is unexported deliberately: it is the whole point of the type.
	credVer string
}

// String yields only the safe half.
func (k PoolKey) String() string { return k.kind + ":" + k.ref }

// GoString covers %#v, which would otherwise print unexported fields.
func (k PoolKey) GoString() string { return "connector.PoolKey(" + k.String() + ")" }

// LogValue makes this self-redacting by type under slog, the same mechanism
// Secret uses (§4.3.3). A reviewer can forget; a %v in a 3am error path will.
func (k PoolKey) LogValue() slog.Value { return slog.StringValue(k.String()) }

// Secret is credential material.
//
// []byte rather than string so it can be zeroed. Go cannot reliably zero a
// string — immutable, and the GC may have copied it — so zeroing []byte is a
// mitigation rather than a guarantee, but it is strictly better than nothing.
//
// LogValue makes this SELF-REDACTING BY TYPE, which is structurally safer than
// Lexicon's regex-on-field-name approach
// (lexicon/loggerFramework.js:216), which silently failed on any field
// name its list did not anticipate — and there were two divergent lists.
type Secret []byte

// Redacted is what a Secret renders as, everywhere.
const Redacted = "[REDACTED]"

// LogValue implements slog.LogValuer, so slog renders this as [REDACTED]
// wherever it appears — as a value, inside a group, or nested in a struct.
//
// THIS IS THE MECHANISM §4.3.3 RELIES ON. Type-based rather than name-based: it
// cannot be defeated by calling the field something the redaction list did not
// anticipate, because there is no list. Every handler resolves LogValuer before
// formatting, so this holds even for slog's stock JSON and text handlers, with
// no Sekizui-specific handler required.
//
// Value receiver, deliberately: a pointer receiver would leave Secret (as
// opposed to *Secret) NOT implementing slog.LogValuer, so the common case of
// logging a Secret by value would silently print the bytes. That is the failure
// this method exists to prevent, so it must not depend on how the caller holds
// it.
func (s Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String covers the fmt verbs — %s, %v, and anything calling String().
//
// slog is not the only way bytes reach a log line. fmt.Sprintf("%v", target) or
// a stray %s in an error message would otherwise print credential material, and
// those paths do not consult LogValuer at all.
//
// Converting explicitly with []byte(s) still yields the real bytes, which is
// correct: a driver signing a request needs them, and the explicit conversion is
// the visible seam where that intent is stated.
func (s Secret) String() string { return Redacted }

// GoString covers %#v, which debugging code reaches for constantly and which
// ignores String entirely.
func (s Secret) GoString() string { return Redacted }

// Wipe overwrites the credential material in place.
//
// §4.3.3's justification for []byte over string is precisely that this is
// possible — "credentials should be []byte you can wipe". That claim went
// unimplemented until now, which made the type choice rationale rather than
// mechanism.
//
// WHAT THIS DOES AND DOES NOT BUY. It is a mitigation, not a guarantee, and the
// doc comment on Secret already says so: the garbage collector may have copied
// the slice during a heap move, and nothing can reach those copies. What it does
// buy is shrinking the window in which a credential sits readable in a
// long-lived process — a core dump, a debugger, or a heap profile taken after
// the wipe finds zeroes at this address rather than a working token.
//
// Value receiver despite mutating: a slice header is copied but the BACKING
// ARRAY is shared, so the zeroing is visible to every holder of the same slice.
// That is the intent — wiping one copy must invalidate all of them, or the wipe
// is theatre. This is the one place where Go's usual "value receiver means no
// mutation" reading is wrong, and it is worth knowing it is deliberate.
func (s Secret) Wipe() {
	clear(s)
}

// MarshalJSON closes the encoding/json door, which consults neither
// slog.LogValuer nor fmt.Stringer and would otherwise emit the credential as
// base64.
//
// The objection to doing this was that redacting on marshal corrupts a
// round-trip: marshal yields "[REDACTED]", unmarshal reads that back as literal
// bytes, and you hold a credential that silently is not one — surfacing as
// confusing 401s rather than as anything obvious. In a credential broker that is
// arguably worse than the leak.
//
// UnmarshalJSON below dissolves that objection by making the round-trip fail
// loudly instead of silently, which is why both exist and neither is safe alone.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + Redacted + `"`), nil
}

// UnmarshalJSON always fails, deliberately.
//
// Not a compromise to make MarshalJSON safe — it follows from §4.7. Configuration
// carries credential REFERENCES, never material, and config.Provider.Resolve
// hands back raw []byte rather than a Secret. So nothing legitimate parses a
// Secret out of JSON, and code attempting it has misunderstood where credentials
// come from. Better to say so at the point of the mistake.
//
// Pointer receiver because unmarshalling must be able to modify the target;
// json only looks for MarshalJSON on the value and UnmarshalJSON on the pointer.
func (s *Secret) UnmarshalJSON([]byte) error {
	return errors.New("connector: Secret cannot be unmarshalled from JSON; " +
		"credentials come from a SecretProvider, and configuration carries " +
		"references rather than material (§4.7)")
}

// TargetSpec WAS DECLARED HERE AND IS NOT. It said "the declarative form from
// configuration" and carried the same seven fields as `config.TargetSpec`,
// which is the type configuration actually decodes into — and nothing in the
// tree ever named this one.
//
// A DUPLICATE IS WORSE THAN DEAD CODE, and worse here than in `internal/`. This
// is public API (D35): a third-party driver author reaching for the
// connector-shaped spec would get a struct nothing populates, and would find
// out at runtime rather than at compile time. `config.TargetSpec` carries the
// JSON tags that make it decodable, so the two were never interchangeable —
// they merely looked it.
//
// Left as a note rather than silently removed because the recurring failure in
// this codebase is a declared contract nobody wires, and the correction is only
// useful if the next reader can see it was deliberate. See CONTRACTS §4.

// Resolver turns a target reference into a resolved Target.
//
// The sole constructor of Target. Implementations must:
//   - refuse refs the principal has no capability for
//   - refuse a residency conflict with the instance region (D29 item 2)
//   - resolve the credential via SecretProvider, cache it with the version in the
//     key and JITTERED expiry (§4.3.2)
type Resolver interface {
	Resolve(ctx context.Context, ref string) (Target, error)
}

// Result is the outcome of a mutating action.
type Result struct {
	// Identifier created or affected, e.g. "PROJ-123". Recorded in the audit
	// Effect so the trail joins to the target system's own records.
	ExternalRef string

	Data       map[string]any
	StatusCode int
	Latency    time.Duration
}

// Rows is the outcome of a read.
type Rows struct {
	Rows []map[string]any

	NextPageToken string

	// True when a limit cut the results short rather than exhausting them.
	// Surfaced to the caller, because an agent reasoning over a silently
	// truncated set reaches confident wrong conclusions.
	Truncated bool
}

// RawEvent is a source event before translation. Data is whatever the vendor
// returned; the translator maps it onto a registered schema (D40).
type RawEvent struct {
	ID   string
	Type string

	// Subject is the ENTITY this event is about — a session id, an issue key, a
	// user id — and becomes CloudEvents' `subject` on the envelope.
	//
	// **IT IS NOT A ROUTING KEY, AND NOTHING ROUTES ON IT (D258).** The bus
	// subject is derived from the envelope's stage and type (D60,
	// `bus.SubjectOf`). This field had no documentation, the in-process bus
	// matched subscriptions against it, and the reference driver set it to the
	// constant "kata.row" so that a subscription would match — so a driver
	// written by copying the reference put a routing string where the entity
	// belongs. Empty is legitimate for an event about no single entity.
	Subject string

	At   time.Time
	Data map[string]any
}

// ValidateActions reports every way a driver's action declarations are
// ill-formed, as human-readable problems.
//
// **ONE IMPLEMENTATION, TWO CALLERS, AND THAT IS THE POINT** (D155, D160). The
// boot check runs it over every wired driver so a bad declaration fails the
// load; the published conformance suite runs it so a self-hoster's driver is held
// to the same contract before it ever reaches a deployment. Two copies of "what
// makes an ActionSpec valid" would drift, and the drift would be silent — the
// deployment would accept what the suite rejected, or the reverse.
//
// PUBLIC FOR THE SAME REASON `Driver` IS (D35). A contract a third party cannot
// check they have met is a contract they will discover in production.
//
// COLLECTS RATHER THAN RETURNING THE FIRST, matching config.Document.Validate: a
// boot that reports one problem per restart makes fixing five a five-restart
// job, and an operator learns to stop reading.
func ValidateActions(kind string, specs []ActionSpec) []string {
	var problems []string

	// **UNIQUENESS AND THE RESTATEMENT RULE MOVED HERE FROM THE CONFORMANCE
	// SUITE (D218), because the two were a SECOND STATEMENT of this contract and
	// they disagreed.** `conformance.runActions` checked uniqueness and a
	// description that merely restates the action's own identifier; this
	// function checked the name prefix, the placement pairing, the implemented
	// set and the not-mutating-must-not-declare rule. Neither had the other's,
	// so an out-of-tree driver author (D35) running the published suite got four
	// checks their deployment would later refuse them on — the inversion the
	// suite exists to prevent, and CONTRACTS 93's condition one layer down.
	//
	// Found by WORKING THE KATA rather than by reading either one.
	seen := map[string]bool{}
	for _, spec := range specs {
		// EVERY ACTION DECLARES ITS RESULT (D283): an output type, or NoResult —
		// exactly one — so nothing it returns can enter undeclared.
		switch hasType := len(spec.DeclaredOutputs()) > 0; {
		case hasType && spec.NoResult:
			problems = append(problems, fmt.Sprintf("driver %q action %q declares an output type AND "+
				"NoResult; it returns data or it does not (D283)", kind, spec.Name))
		case !hasType && !spec.NoResult:
			problems = append(problems, fmt.Sprintf("driver %q action %q declares neither an output type "+
				"nor NoResult, so what it returns would enter Sekizui undeclared — declare the type of its "+
				"result and ship its schema, or NoResult if it returns nothing (D283)", kind, spec.Name))
		}
		if b := spec.Bound; b != nil {
			switch {
			case spec.Mutating:
				problems = append(problems, fmt.Sprintf("driver %q action %q is a write and declares a "+
					"Bound; a write's result is one object, and Bound is a read's row count (D283)", kind, spec.Name))
			case b.MaxRows < 1:
				problems = append(problems, fmt.Sprintf("driver %q action %q: Bound.MaxRows is %d; a read "+
					"returns at least one row (D283)", kind, spec.Name, b.MaxRows))
			case b.Arg == "" && b.Default != 0:
				problems = append(problems, fmt.Sprintf("driver %q action %q: Bound.Default without Arg "+
					"could never be consulted (D283)", kind, spec.Name))
			case b.Default > b.MaxRows:
				problems = append(problems, fmt.Sprintf("driver %q action %q: Bound.Default %d exceeds "+
					"MaxRows %d (D283)", kind, spec.Name, b.Default, b.MaxRows))
			}
		}
		if seen[spec.Name] {
			problems = append(problems, fmt.Sprintf(
				"driver %q declares action %q twice, so which spec applies depends on "+
					"iteration order", kind, spec.Name))
		}
		seen[spec.Name] = true
	}

	for _, spec := range specs {
		if strings.TrimSpace(spec.Name) == "" {
			problems = append(problems, fmt.Sprintf(
				"driver %q declares an action with an empty name, which nothing can "+
					"route to and the catalog cannot render", kind))
			continue
		}
		// THE PREFIX RULE WAS DOCUMENTED AND UNENFORCED. ActionSpec.Name says
		// "Prefix must equal Driver.Kind()", and the only thing checking it was
		// the kata driver's own test — which a third-party driver does not
		// inherit. D49 makes it load-bearing for MCP, where an action name embeds
		// the server segment and can contradict its target ref.
		if !strings.HasPrefix(spec.Name, kind+".") {
			problems = append(problems, fmt.Sprintf(
				"driver %q action %q: name must be prefixed %q, or the catalog and the "+
					"router disagree about which driver owns it", kind, spec.Name, kind+"."))
		}

		// **A DESCRIPTION IS REQUIRED, AND IS NOT SYNTHESISABLE (D196).** §4.9
		// property 2 makes the catalog an LLM's map of what it may attempt, so
		// that "the agent then doesn't discover the boundary by hitting 403s".
		// An action with no description gives the catalog nothing to render, and
		// the only thing it can invent is the action's own name — which reads as
		// a description, is not one, and cannot be told apart from a real one by
		// the consumer it misleads.
		if strings.TrimSpace(spec.Description) == "" {
			problems = append(problems, fmt.Sprintf(
				"driver %q action %q has no description. The catalog advertises this to a "+
					"model as what it may attempt (§4.9 property 2), and an empty one leaves "+
					"nothing to say but the action's own name — a restatement dressed as a "+
					"description. Write one sentence saying what the action does",
				kind, spec.Name))
		} else if strings.HasPrefix(strings.TrimSpace(spec.Description), spec.Name) {
			// **A RESTATEMENT IS NOT A DESCRIPTION, and it is worse than an empty
			// one** — an empty description is visibly absent, while
			// "notes.create_note creates a note" reads as prose and tells a model
			// nothing it did not already have from the identifier.
			problems = append(problems, fmt.Sprintf(
				"driver %q action %q describes itself as %q, which is its own "+
					"identifier restated. D196: dressing a restatement as a description "+
					"misleads the only consumer it has",
				kind, spec.Name, spec.Description))
		}

		if !spec.Mutating {
			// A PAIRED INVARIANT: a field that cannot mean anything must be
			// refused rather than ignored, or somebody reads it as in force.
			if spec.Idempotency != "" {
				problems = append(problems, fmt.Sprintf(
					"driver %q action %q is not mutating and declares idempotency %q. "+
						"A read is repeatable by definition, so the classification would "+
						"never be consulted and reading it as a guarantee would be wrong",
					kind, spec.Name, spec.Idempotency))
			}
			// A READ BRINGS DATA IN, SO IT DECLARES WHAT (D279). Its rows are
			// shaped to the schema of its output type before any lens; an
			// untyped read would pass whatever the far side returned.
			if len(spec.DeclaredOutputs()) == 0 {
				problems = append(problems, fmt.Sprintf(
					"driver %q action %q is a read and declares no output type, so its results "+
						"would enter with no schema to shape them to. Declare OutputType and ship "+
						"its schema (D279)", kind, spec.Name))
			}
			continue
		}

		// **THE LOAD FAILS ON AN UNCLASSIFIED MUTATING ACTION (D163).** There is
		// no safe default: `none` would quietly forbid retries a connector could
		// support, and anything else permits a double-write nobody chose. The
		// same rule §4.9a.1 gives Mutating for MCP tools, and the same failure
		// direction.
		if spec.Idempotency == "" {
			problems = append(problems, fmt.Sprintf(
				"driver %q action %q is mutating and declares no idempotency class. "+
					"A human must classify it — there is no safe default, since one would "+
					"either forbid retries the upstream supports or permit a double-write "+
					"nobody chose. Choose from %v",
				kind, spec.Name, IdempotencyClasses()))
			continue
		}
		if !spec.Idempotency.Known() {
			problems = append(problems, fmt.Sprintf(
				"driver %q action %q declares idempotency class %q, which is not in the "+
					"vocabulary. Known: %v", kind, spec.Name, spec.Idempotency, IdempotencyClasses()))
			continue
		}

		// **DECLARED BUT NOT IMPLEMENTED REFUSES AT LOAD, RATHER THAN DEGRADING.**
		// The vocabulary is built whole so the blueprint can show a connector
		// author the full shape (D163, D167); the cost of that is a member nobody
		// wired, and D53's rule is that a skeleton must run or refuse and never
		// silently succeed at nothing.
		if !spec.Idempotency.Implemented() {
			problems = append(problems, fmt.Sprintf(
				"driver %q action %q declares idempotency class %q, which is declared and "+
					"NOT IMPLEMENTED in this build (%s). It is in the vocabulary so the shape "+
					"is visible, and it is a real class rather than a typo; using it must fail "+
					"loudly rather than fall back to sending the call without its guarantee. "+
					"Pick one of %v, or implement it",
				kind, spec.Name, spec.Idempotency, spec.Idempotency.Explain(),
				implementedClasses()))
			continue
		}

		switch {
		case spec.Idempotency.NeedsPlacement() && spec.IdempotencyPlacement == "":
			problems = append(problems, fmt.Sprintf(
				"driver %q action %q is idempotency class %q, which needs a placement — "+
					"the header name or body path the key goes in — and declares none",
				kind, spec.Name, spec.Idempotency))
		case !spec.Idempotency.NeedsPlacement() && spec.IdempotencyPlacement != "":
			problems = append(problems, fmt.Sprintf(
				"driver %q action %q is idempotency class %q, which places no key, and "+
					"declares placement %q. A field that cannot be consulted must not be "+
					"set, or a reviewer reads it as in force",
				kind, spec.Name, spec.Idempotency, spec.IdempotencyPlacement))
		}
	}

	return problems
}

// DeclaredOutputs is the action's declared output set: OutputType, if any,
// then OutputTypes (D276). One definition for boot, the runner and the suite.
func (a ActionSpec) DeclaredOutputs() []string {
	var out []string
	if a.OutputType != "" {
		out = append(out, a.OutputType)
	}
	return append(out, a.OutputTypes...)
}

// HandleRole is one action's part in a handle lifecycle (D291); exactly one
// field is set.
type HandleRole struct {
	// Opens names the RESULT field carrying the handle the action allocates.
	Opens string
	// Closes names the ARGUMENT carrying the handle the action releases.
	Closes string
	// Uses names the argument carrying a handle the action works on.
	Uses string
}

// ResultBound is a read's declared result size (D283).
//
// UNIVERSAL BECAUSE EVERY RESULT IS ROWS OF BOUNDED OBJECTS: each object is
// capped by the same per-object budget whichever connector produced it, so a
// call's worst case is always rows × that budget, and the only fact a
// connector must supply is how many rows. MaxRows is a CEILING the driver
// never exceeds — the gateway truncates, and says so, if it does.
type ResultBound struct {
	// MaxRows is the most rows one call can return. At least 1.
	MaxRows int

	// Arg names the argument through which a caller asks for fewer rows — a
	// page size, an event limit. Optional: a read without one always costs
	// MaxRows.
	Arg string

	// Default is the rows asked for when Arg is absent from the call; 0 means
	// MaxRows. Meaningful only with Arg.
	Default int
}

// Rows is the row count a call with these args asks for, and whether the
// caller chose it. Absent, not a positive number, or over MaxRows: the default
// (explicit=false) — except over MaxRows, which is reported so the gateway can
// refuse it rather than silently lower what the caller asked.
func (b *ResultBound) Rows(args map[string]any) (rows int, explicit bool, over bool) {
	if b == nil {
		return 1, false, false
	}
	def := b.Default
	if def <= 0 {
		def = b.MaxRows
	}
	if b.Arg == "" {
		return b.MaxRows, false, false
	}
	n, ok := args[b.Arg].(float64)
	if !ok || n < 1 {
		return def, false, false
	}
	if int(n) > b.MaxRows {
		return int(n), true, true
	}
	return int(n), true, false
}
