package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"

	"github.com/fullstorydev/sekizui/internal/jsonref"
)

// **AND `drift.Reporter`, WHICH IS WHY THE VOCABULARY LIVES OUTSIDE THIS
// PACKAGE (D206, GO-PRIMER §15ag).** The watcher asks every driver whether it
// can compare a live surface to a vetted spec, and it must be able to ask
// without importing a driver — so the seam is declared in `internal/drift` and
// satisfied here structurally. Asserted at compile time because an optional
// interface is discovered by type assertion: without this line, a signature
// change turns the capability into SILENCE rather than a build failure, and the
// watcher would simply stop finding anything to compare.
var _ drift.Reporter = (*Driver)(nil)

// Kind is the driver kind an MCP target names (D49).
//
// **ONE KIND FOR EVERY SERVER, which is what forced namespaced action names.**
// `Actions() []ActionSpec` takes no `Target`, so one generic driver returns one
// flat list spanning every configured server — requiring globally unique names.
// A `Kind` per server was the alternative and makes `Kind` a property of the
// instance rather than of the type; `Actions(t Target)` churns public API for
// every driver to serve one (§4.9a.4, D35).
const Kind = "mcp"

// SpecTool is one vetted tool, flattened out of config so this package does not
// hand `config.MCPToolSpec` to its own comparison logic.
//
// A SEPARATE TYPE RATHER THAN THE CONFIG ONE, because `CompareToSpec` is a pure
// function over two lists and taking the configuration type would tie the
// severity judgements to a YAML shape. The mapping is one function, below.
type SpecTool struct {
	Name                 string
	Mutating             bool
	Idempotency          string
	IdempotencyPlacement string
	InputSchema          json.RawMessage
	OutputSchema         json.RawMessage
	OutputSchemaOrigin   string
	OutputType           string
	Description          string

	// Result, Extract and Pin are D289's: a text contract, the fields featured
	// out of it, and the arguments bound to the target's own settings.
	Result      string
	Extract     []config.ExtractSpec
	Pin         []string
	Combine     string
	UserContent bool

	// RefUnroll is the spec's `ref_unroll`, resolved to its default (D309).
	RefUnroll int
}

// LiveTool is one tool as the server currently advertises it.
type LiveTool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`

	// Annotations are carried and DELIBERATELY NOT TRUSTED.
	//
	// The specification's own words: "clients MUST consider tool annotations to
	// be untrusted unless they come from trusted servers." That is D46's whole
	// argument in the protocol's voice — `mutating` is a human's judgement in the
	// vetted spec, never `readOnlyHint` or `destructiveHint` off the wire. Kept so
	// the authoring tool can SHOW them to a reviewer (D168), which is the only
	// legitimate use.
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// Driver is the generic MCP client.
//
// HOLDS NO CREDENTIALS AND NO PER-TARGET STATE (D4). The spec map is
// configuration, read-only after wiring; `nextID` is a JSON-RPC request counter,
// which is per-process bookkeeping rather than per-tenant state.
type Driver struct {
	// specs are the vetted manifests, keyed by target ref (D46, D192).
	specs map[string]config.MCPSpec

	http *http.Client
	pool connector.ClientPool

	// nextID numbers JSON-RPC requests. Atomic because one driver instance
	// serves every tenant concurrently, and two calls sharing an id would let a
	// server's response be matched to the wrong request.
	nextID atomic.Int64

	// nonconforming is the per-target tally of results that ADDED fields to
	// their output contract (D289) — raised as `tool_nonconforming`. A type
	// break or a missing required field is refused instead, not tallied.
	ncMu          sync.Mutex
	nonconforming map[string]string
}

// Nonconforming reports, per target, the latest tool whose result added fields
// its output_schema does not declare (D289). A level: it does not fall, for
// the runner's reason — a later conforming result does not say the vendor
// reverted.
func (d *Driver) Nonconforming() map[string]string {
	d.ncMu.Lock()
	defer d.ncMu.Unlock()
	out := make(map[string]string, len(d.nonconforming))
	for k, v := range d.nonconforming {
		out[k] = v
	}
	return out
}

func (d *Driver) tallyNonconforming(targetRef, why string) {
	d.ncMu.Lock()
	defer d.ncMu.Unlock()
	if d.nonconforming == nil {
		d.nonconforming = map[string]string{}
	}
	d.nonconforming[targetRef] = why
}

// Option configures the driver.
type Option func(*Driver)

// WithHTTPClient substitutes the transport, so every arm of this driver except
// "a real MCP server agrees" is provable against an httptest server.
func WithHTTPClient(c *http.Client) Option { return func(d *Driver) { d.http = c } }

// WithPool routes calls through the shared pool, so break-glass can cancel them
// (CONTRACTS 35, D128).
func WithPool(p connector.ClientPool) Option { return func(d *Driver) { d.pool = p } }

// New returns the driver over a set of vetted specs.
//
// THE SPECS ARE A CONSTRUCTOR PARAMETER RATHER THAN AN OPTION, because a driver
// without them has no action set at all — `Actions()` is generated from them
// (D46). An option a wiring site forgets would produce a driver that loads
// cleanly and can do nothing, which is the failure D192's boot check exists to
// prevent one layer up.
func New(specs map[string]config.MCPSpec, opts ...Option) *Driver {
	d := &Driver{specs: specs}
	for _, o := range opts {
		o(d)
	}
	if d.http == nil {
		d.http = &http.Client{Timeout: 30 * time.Second}
	}
	return d
}

var (
	_ connector.Driver = (*Driver)(nil)

	// **AND THE OPTIONAL ONE SINCE D213, WHICH REVERSES D190'S NOTE HERE.** That
	// note said an MCP client is credential-free and there is nothing per-target
	// to build, which was true while every implemented revision was sessionless.
	// `2025-06-18` has a protocol-level session, and a session is §4.7.4 class 3
	// — so this driver is now BOTH classes depending on the target's declared
	// revision, and `BuildClient` answers per target rather than per driver.
	//
	// The credential is still a per-request header on both, which is worth
	// keeping straight: the class changed because of CONNECTION state, not
	// because the credential moved.
	_ connector.ClientBuilder = (*Driver)(nil)
)

func (d *Driver) Kind() string { return Kind }

// Actions returns every vetted tool across every configured server (D46).
//
// **DERIVED FROM THE COMMITTED SPEC, NEVER FROM A LIVE `tools/list`** — which is
// the structural reason drift is detectable at all. A driver that asked the
// server what it could do would have nothing to compare against, and would adopt
// an attacker's answer as its own capability set.
//
// SORTED, so the catalog and `Describe` are stable across restarts. Map
// iteration order would make an agent's tool list reshuffle for no reason.
func (d *Driver) Actions() []connector.ActionSpec {
	var out []connector.ActionSpec

	for _, ref := range sortedRefs(d.specs) {
		spec := d.specs[ref]
		for _, tool := range spec.Tools {
			out = append(out, connector.ActionSpec{
				Name:     ActionName(spec.Server, tool.Name),
				Mutating: tool.Mutating,
				// THE CLASS COMES FROM THE VETTED SPEC, where a human set it
				// (D163, D192). Never from `readOnlyHint`.
				Idempotency:          connector.IdempotencyClass(tool.Idempotency),
				IdempotencyPlacement: tool.IdempotencyPlacement,
				InputSchema:          schemaURI(spec.Server, tool.Name, "input"),
				OutputType:           tool.OutputType,
				// A TOOL WITH NO output_type RETURNS NOTHING INTO SEKIZUI (D283):
				// its result is withheld, because nobody declared its shape.
				NoResult:    tool.OutputType == "",
				Description: tool.Description,
				Handle:      handleRole(tool.Handle),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SpecFor returns the vetted tools for one target, in this package's own shape.
func (d *Driver) SpecFor(ref string) (server string, tools []SpecTool, ok bool) {
	spec, ok := d.specs[ref]
	if !ok {
		return "", nil, false
	}
	unroll := jsonref.DefaultUnroll
	if spec.RefUnroll != nil {
		unroll = *spec.RefUnroll
	}
	for _, t := range spec.Tools {
		tools = append(tools, SpecTool{
			Name: t.Name, Mutating: t.Mutating,
			Idempotency: t.Idempotency, IdempotencyPlacement: t.IdempotencyPlacement,
			InputSchema: t.InputSchema, OutputSchema: t.OutputSchema,
			OutputSchemaOrigin: t.OutputSchemaOrigin, OutputType: t.OutputType,
			Description: t.Description,
			Result:      t.Result, Extract: t.Extract, Pin: t.Pin,
			Combine: t.Combine, UserContent: t.UserContent,
			RefUnroll: unroll,
		})
	}
	return spec.Server, tools, true
}

// ListTools calls `tools/list`, FOLLOWING PAGINATION.
//
// **A CLIENT THAT IGNORES `nextCursor` SEES A PARTIAL TOOL LIST, and for drift
// detection that is worse than useless.** An unvetted tool on page two is
// invisible — so the supply-chain check silently stops working — and every
// vetted tool that happens to sit there is reported as WITHDRAWN, which
// withholds working capabilities from the catalog. Both failures look like the
// server changed.
//
// BOUNDED, because a server that returns a cursor pointing at itself would
// otherwise spin forever inside a governed call.
func (d *Driver) ListTools(ctx context.Context, t connector.Target) ([]LiveTool, error) {
	const op = "mcp.ListTools"

	// **A STATEFUL TARGET LISTS TOOLS THROUGH THE POOL AND A SESSIONLESS ONE
	// DOES NOT, AND THE ASYMMETRY IS FORCED (D213).** `tools/list` on
	// 2025-06-18 is a "subsequent request" and a server that requires a session
	// answers one without `Mcp-Session-Id` with HTTP 400 — so there is no
	// version of this that reaches a stateful server without borrowing the
	// pooled session. A sessionless target is left on the direct path it has
	// always used, because routing it through the pool would change what a
	// drift check does to a withdrawn target for no gain.
	//
	// The consequence IS worth naming: on a stateful target a drift check is now
	// refused while the target is withdrawn, so the drift report says
	// "unavailable" rather than "undiverged" for a quarantined target. That is
	// the honest answer — we genuinely cannot ask — and it is D48's rule
	// unchanged, since an unreachable server produces no findings either way.
	//
	// **THE TENANT IS ASSERTED FIRST (§6 mechanism 3, D311).** `tools/list` is an
	// outbound call carrying the target's credential, and until D311 only
	// Execute asserted the tenant — the drift path did not. RunDrift's tenant
	// arm is what found it.
	if err := connector.AssertTenant(ctx, t); err != nil {
		return nil, err
	}
	if !d.stateful(t) {
		return d.listTools(ctx, op, t, nil)
	}
	if d.pool == nil {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q declares MCP revision %s, whose session lives in the client "+
				"pool, and this driver was built without one. A stateful revision "+
				"cannot be spoken from an unpooled driver: there would be nowhere for "+
				"the session to live between calls, and every request would open one "+
				"and abandon it", t.Ref(), d.revisionFor(t)))
	}

	var out []LiveTool
	err := d.pool.Do(ctx, t, func(ctx context.Context, client any) error {
		var listErr error
		out, listErr = d.listTools(ctx, op, t, sessionOf(client))
		return listErr
	})
	return out, err
}

// sessionOf extracts the session from a pooled client, or nil.
//
// **NIL IS A LEGITIMATE ANSWER, NOT A FAILURE**, so this is a type assertion
// rather than a checked one: a sessionless target's pool entry is the
// credential-free marker, and `post` correctly sends no session header for it.
// Returning an error here would make every class 1 call fail on a driver that
// serves both classes.
func sessionOf(client any) *session {
	s, _ := client.(*session)
	return s
}

// listTools is the paging loop, once a session (or nil) is in hand.
func (d *Driver) listTools(ctx context.Context, op string, t connector.Target,
	sess *session) ([]LiveTool, error) {

	var out []LiveTool
	var cursor string

	// THE DECLARED BOUND, NOT THE HARD ONE (D311): the comparison was priced
	// at `list_pages` before it was sent, so reading past it would spend calls
	// nobody priced. A server still paginating there fails the comparison.
	bound := d.listPages(t.Ref())
	for page := 0; page < bound; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}

		var result struct {
			Tools      []LiveTool `json:"tools"`
			NextCursor string     `json:"nextCursor"`
		}
		if err := d.rpc(ctx, op, t, sess, "tools/list", params, nil, &result); err != nil {
			return nil, err
		}
		out = append(out, result.Tools...)

		if result.NextCursor == "" {
			return out, nil
		}
		if result.NextCursor == cursor {
			// A CURSOR POINTING AT ITSELF. Refused rather than looped, and named
			// as a protocol fault rather than as drift — the server is broken,
			// not diverged (D48).
			return nil, fault.New(fault.KindTargetError, op, fmt.Sprintf(
				"the server returned the same tools/list cursor twice (%q), which would "+
					"page forever", cursor))
		}
		cursor = result.NextCursor
	}
	return nil, fault.New(fault.KindTargetError, op, fmt.Sprintf(
		"tools/list did not terminate within the %d page(s) this target's spec declares "+
			"(list_pages, D311). Refusing rather than trusting a partial list: a missing page "+
			"reads as withdrawn tools and hides unvetted ones. Raise list_pages (at most %d) if "+
			"the server now paginates further", bound, maxToolPages))
}

// maxToolPages bounds `tools/list` pagination — config's constant, so the
// validation of `list_pages` and the loop agree (D311).
const maxToolPages = config.MaxMCPListPages

// listPages is how many pages a drift comparison of this target may read: the
// spec's `list_pages`, default 1 (D311). It is also the comparison's price.
func (d *Driver) listPages(ref string) int {
	if spec, ok := d.specs[ref]; ok && spec.ListPages != nil {
		return *spec.ListPages
	}
	return 1
}

// Drift compares the live surface against the vetted spec (D48).
//
// **THE LIVE HALF OF D50, and it never blocks start** — it gates readiness PER
// TARGET. A live comparison that blocked boot would make one unreachable MCP
// server prevent the whole instance from serving, including every target with
// nothing to do with it, so an outage at a vendor becomes a deploy outage here
// (§4.9a.7).
//
// **AN UNREACHABLE SERVER IS AN AVAILABILITY CONDITION, NEVER A DIVERGENCE**
// (D48). The error is returned unchanged and NO findings are produced, because
// conflating them turns a network blip into what reads as a security incident —
// and that matters more now that something acts on `spec_drift`: a rule that
// quarantines on drift must not fire because a server was briefly down.
func (d *Driver) Drift(ctx context.Context, t connector.Target) (drift.Findings, error) {
	const op = "mcp.Drift"

	server, spec, ok := d.SpecFor(t.Ref())
	if !ok {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q has no vetted spec, so there is nothing to compare the server "+
				"against. Boot refuses this configuration (D192)", t.Ref()))
	}

	live, err := d.ListTools(ctx, t)
	if err != nil {
		// NO FINDINGS ALONGSIDE THE ERROR. Returning a partial comparison here
		// would let a caller act on drift conclusions drawn from a list that was
		// never fully read.
		return nil, err
	}
	return CompareToSpec(server, spec, live), nil
}

// Execute calls one vetted tool.
func (d *Driver) Execute(ctx context.Context, t connector.Target, action string,
	args map[string]any, idem connector.Idempotency) (connector.Result, error) {

	const op = "mcp.Execute"
	started := time.Now()

	tool, err := d.toolFor(op, t, action)
	if err != nil {
		return connector.Result{}, err
	}

	// **A STATEFUL TARGET CANNOT RUN UNPOOLED, AND IT IS REFUSED HERE RATHER THAN
	// AT THE BORROW (D213).** The unpooled path exists so the driver is testable
	// without a pool; a session has nowhere to live on it, so a call would open
	// one per command and abandon each — a server-side leak that looks like
	// success from this side.
	//
	// **THE PLACEMENT IS DELIBERATE AND THE FIRST DRAFT HAD IT WRONG.** It sat
	// below the idempotency placement and `AssertTenant`, so this refusal was
	// masked by a `KindInternal` from §6 mechanism 3 — the acceptance arm caught
	// it, reading `kind internal, want config`. Above them is right on the
	// merits too: those two ask whether THIS REQUEST is well-formed, and this
	// asks whether the target can be called at all. Still BELOW `toolFor`,
	// because a caller naming a tool that does not exist should hear about their
	// own mistake rather than about our wiring (D200's attribution axis, applied
	// to an ordering).
	if d.pool == nil && d.stateful(t) {
		return connector.Result{}, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q declares MCP revision %s, whose session lives in the client "+
				"pool, and this driver was built without one. Every call would open a "+
				"session and abandon it", t.Ref(), d.revisionFor(t)))
	}

	// THE ARGUMENTS, AGAINST THE VETTED input_schema (D289). This was claimed
	// by ActionSpec.InputSchema's doc comment and done by nothing: any argument
	// reached the server, so the vetted input shape constrained nothing and a
	// call could name another org by `org_id`. Before the key is placed and
	// before anything is sent.
	args, err = admitArgs(op, t, tool, args)
	if err != nil {
		return connector.Result{}, err
	}

	// PLACE THE KEY AND VERIFY IT SURVIVED (D163, D186). MCP has no idempotency
	// header of its own, so a `header`-class tool means the SERVER honours one —
	// which is exactly the case the vetted spec records and the placement names.
	body, headers, err := idem.PlaceIn(op, tool.Mutating, args)
	if err != nil {
		return connector.Result{}, err
	}
	if err := idem.Verify(op, body, headers); err != nil {
		return connector.Result{}, err
	}

	// §6 MECHANISM 3, immediately before the outbound call.
	if err := connector.AssertTenant(ctx, t); err != nil {
		return connector.Result{}, err
	}

	var res connector.Result
	work := func(ctx context.Context, client any) error {
		var callErr error
		res, callErr = d.callTool(ctx, op, t, sessionOf(client), tool, body, headers)
		return callErr
	}

	if d.pool == nil {
		if err := work(ctx, nil); err != nil {
			return connector.Result{}, err
		}
	} else if err := d.pool.Do(ctx, t, work); err != nil {
		return connector.Result{}, err
	}

	res.Latency = time.Since(started)
	return res, nil
}

// Query REFUSES.
//
// **MCP HAS NO READ/WRITE SPLIT ON THE WIRE — `tools/call` is the only verb —
// and Sekizui's split is not the vendor's to make.** §4.1.1 governs both planes
// and the distinction is drawn by `ActionSpec.Mutating`, which a human sets in
// the vetted spec. Routing a non-mutating tool through Query would mean deciding
// that "not mutating" and "is a read" are the same claim; they are not, and
// which MCP tools are genuinely reads is a question the spec cannot answer.
//
// So every tool goes through Execute and D53's rule applies here: refuse rather
// than return an empty result set an agent would read as an empty account.
func (d *Driver) Query(_ context.Context, _ connector.Target, action string,
	_ map[string]any) (connector.Rows, error) {

	return connector.Rows{}, fault.New(fault.KindNotFound, "mcp.Query", fmt.Sprintf(
		"MCP exposes one verb, `tools/call`, so %q is reached through Execute rather "+
			"than Query. `Mutating` in the vetted spec is what separates the planes for "+
			"policy and audit (§4.1.1); it is not a claim that a tool is a READ, and "+
			"returning an empty row set instead would let an agent conclude there is "+
			"nothing there", action))
}

// Health reports whether the target's server is reachable AND undiverged.
//
// **BOTH, AND THE CALLER CAN TELL WHICH** — that is D48's requirement, not a
// convenience. Unreachable is an availability event; diverged is a governance
// event, and collapsing them means a network blip reads as a security incident
// while a schema change reads as a blip.
func (d *Driver) Health(ctx context.Context, t connector.Target) error {
	const op = "mcp.Health"

	findings, err := d.Drift(ctx, t)
	if err != nil {
		// Returned UNCHANGED, so its kind stays an availability kind.
		return err
	}
	if findings.RefusesTarget() {
		return fault.New(fault.KindSpecDrift, op, fmt.Sprintf(
			"target %q diverges from its vetted spec: %s", t.Ref(),
			strings.Join(details(findings.Of(drift.SeverityRefused)), "; ")))
	}
	return nil
}

func details(fs drift.Findings) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.String())
	}
	return out
}

// toolFor resolves an action name to its vetted tool, refusing an unvetted one.
//
// **THE REFUSAL SAYS `unvetted`, NOT `no such action` (D48).** An agent told
// "no such action" about a tool that plainly exists on the server it is talking
// to learns the wrong thing — it will retry, or report the server as broken. The
// truth is that the tool exists and nobody has vetted it, which is a review
// queue item rather than a bug.
func (d *Driver) toolFor(op string, t connector.Target, action string) (SpecTool, error) {
	server, tools, ok := d.SpecFor(t.Ref())
	if !ok {
		return SpecTool{}, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q has no vetted spec (D192)", t.Ref()))
	}

	want, found := strings.CutPrefix(action, mcpPrefix+server+".")
	if !found {
		return SpecTool{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"action %q does not name a tool on server %q (target %q). MCP actions are "+
				"`mcp.<server>.<tool>` (D49)", action, server, t.Ref()))
	}
	for _, tool := range tools {
		if tool.Name == want {
			return tool, nil
		}
	}

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)

	return SpecTool{}, fault.New(fault.KindSpecDrift, op, fmt.Sprintf(
		"tool %q on server %q is UNVETTED: it is not in the committed spec, so it is "+
			"not callable however the server advertises it (D46, D48). This is a review "+
			"queue item rather than a missing tool — vetted tools are %v",
		want, server, names))
}

// schemaURI is the registry key for a tool's input schema.
//
// Derived rather than configured, so a tool added to the vetted spec is
// registerable without a second edit somewhere else.
func schemaURI(server, tool, which string) string {
	return "sekizui://schema/mcp/" + server + "/" + tool + "." + which + ".v1"
}

func sortedRefs(m map[string]config.MCPSpec) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- the JSON-RPC transport ------------------------------------------------

// ProtocolVersion is the SESSIONLESS revision this driver speaks, and the one a
// target gets when its vetted spec declares none.
//
// **IT STOPPED BEING "THE" REVISION AT D213 AND THE NAME WAS KEPT.** A second
// revision is implemented now (`2025-06-18`, stateful), so what a given request
// carries comes from `Driver.revisionFor` — the vetted spec's declaration, which
// a human wrote and a reviewer read. This constant is what an absent declaration
// means, and `config.DefaultMCPRevision` is the same value on the configuration
// side; `TestTheDefaultRevisionAgreesWithConfig` pins them together, because two
// defaults that can disagree is how a target ends up speaking a shape nobody
// chose.
//
// **PINNED, AND SENT ON EVERY REQUEST.** `MCP-Protocol-Version` is REQUIRED on
// every POST and MUST match `_meta.io.modelcontextprotocol/protocolVersion` in
// the body, or the server rejects with 400 and `-32020 HeaderMismatch`. A driver
// that omitted it would be rejected by every conforming server — which is what
// the first draft of this file did, and why the specification was read rather
// than recalled.
//
// **A CONSTANT RATHER THAN A NEGOTIATION, deliberately (D192a), AND THAT IS
// UNCHANGED BY THERE BEING TWO OF THEM.** Two declared revisions is not
// negotiation: which one a target speaks is fixed in a reviewed commit before
// any request goes out, and the far side gets no say. Version
// negotiation means trying a request, reading an `UnsupportedProtocolVersionError`
// and retrying against whatever the server advertises — which makes the shape of
// a governed call depend on a vendor's deployment schedule. Sekizui states what
// it speaks; a server that cannot is reported as an incompatibility an operator
// must act on, not worked around silently.
const ProtocolVersion = "2026-07-28"

// **SESSIONS ARE SUPPORTED FOR EXACTLY ONE REVISION, AND REFUSED EVERYWHERE ELSE
// (D192a, amended by D213).**
//
// Revision 2026-07-28 REMOVED protocol-level sessions: no `Mcp-Session-Id`, no
// GET stream endpoint, no `Last-Event-ID` resumability. The specification is
// explicit that "MCP has no protocol-level session, so a server cannot rely on
// implicit per-connection state", and that "credentials are per-request input,
// not connection state" — which is §4.7.4 class 1 in the protocol's own words.
//
// **SO A PROBLEM SEKIZUI HAD ALREADY DESIGNED AROUND HAS RETIRED ITSELF.** A
// session would be class 3 state — `pool.Closer`'s own comment names it, "an MCP
// session leaves server-side state and possibly a live authorised session" — and
// P7's horizontal-scale question would then have to answer what happens when a
// command routes to a replica that does not hold it. D4 and the protocol now
// agree.
//
// Sessions existed in revisions 2025-03-26 through 2025-11-25. **`2025-06-18` is
// spoken in full as of D213** — established at `BuildClient`, carried here on
// every request, terminated on close — because Fullstory's server serves it and
// "an incompatibility an operator must act on" had no action behind it. The
// other two remain declarable and unimplemented: the reasoning that refuses them
// is unchanged, and what changed is that one of them acquired a vendor.
//
// **ON A SESSIONLESS REVISION A MINTED SESSION IS STILL REFUSED**, and that arm
// is untouched: a server answering `2026-07-28` with an `Mcp-Session-Id` is a
// server expecting continuity from a client that provides none, and
// "unpredictable" is the one thing a governed path must not be.
const sessionHeader = "Mcp-Session-Id"

// rpcRequest is one JSON-RPC 2.0 call.
type rpcRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int64          `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// requestMeta is the `_meta` block a `2026-07-28` request MUST carry.
//
// The field names are the specification's reverse-DNS keys verbatim; they are
// not ours to shorten.
//
// **SENT ONLY ON THE SESSIONLESS REVISION, and this is one of the three places
// D213 had to split by revision rather than add to.** `2025-06-18` defines none
// of these keys, and `_meta` names prefixed `io.modelcontextprotocol/` are
// RESERVED by the specification — so sending them to a server that predates them
// is not harmless padding, it is claiming a reserved namespace with a meaning
// that revision never assigned. The revision is a PARAMETER rather than the
// constant it reads like, so a future third revision cannot inherit
// `2026-07-28`'s value by being forgotten here.
func requestMeta(revision string) map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion": revision,
		"io.modelcontextprotocol/clientInfo": map[string]any{
			"name": "sekizui", "version": "0.x",
		},
		// EMPTY AND PRESENT, NOT ABSENT. Sekizui declares no client capabilities
		// because it relays a governed action: it cannot satisfy sampling,
		// elicitation or roots, and claiming otherwise would invite a server to
		// ask (see the input_required refusal in callTool).
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}
}

// rpcError is a PROTOCOL error: the request itself was wrong.
//
// Distinct from a tool-execution error (`result.isError`), which the
// specification separates deliberately — a protocol error means unknown tool,
// malformed request, or server error, and models are "less likely to be able to
// fix" it. **BOTH ARE DETERMINATE**: the server received and answered, so
// neither belongs in D182's indeterminate class however the call failed.
type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// JSON-RPC and MCP error codes this driver maps by name rather than by number.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603

	// codeHeaderMismatch is MCP's own: the headers do not match the body, or a
	// required one is missing. **ALWAYS OUR BUG** — it means this driver built a
	// malformed request, so it is KindInternal rather than a target fault.
	codeHeaderMismatch = -32020
)

// rpc makes one call and decodes `result` into out.
//
// `extra` carries outbound headers a vetted spec asked for — an idempotency key
// in a named header. One parameter rather than two entry points, because two
// would let a caller send an idempotency key on `tools/list`, which has no
// business carrying one.
func (d *Driver) rpc(ctx context.Context, op string, t connector.Target, sess *session,
	method string, params map[string]any, extra map[string]any, out any) error {

	_, err := d.post(ctx, op, t, sess, method, params, extra, out)
	return err
}

// post is the transport, and it is separate from `rpc` for exactly one reason:
// the `initialize` call needs the RESPONSE HEADERS and every other call does not
// (D213).
//
// **RETURNING THE HEADERS FROM THE SHARED FUNCTION RATHER THAN GIVING
// `initialize` A TRANSPORT OF ITS OWN.** A second POST path would be a second
// place to forget the bounded read (D178), the credential placement (D199), the
// status mapping the conformance suite pins (D167), and the 404-means-the-session-
// died rule below — which is D18's "no second code path" applied at the scale of
// one driver, and D155 is what that looks like when it is ignored.
func (d *Driver) post(ctx context.Context, op string, t connector.Target, sess *session,
	method string, params map[string]any, extra map[string]any, out any) (http.Header, error) {

	base, err := d.base(op, t)
	if err != nil {
		return nil, err
	}

	revision := d.revisionFor(t)
	stateless := config.MCPRevisionStateless(revision)

	if params == nil {
		params = map[string]any{}
	}
	if stateless {
		params["_meta"] = requestMeta(revision)
	}

	payload, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0", ID: d.nextID.Add(1), Method: method, Params: params,
	})
	if err != nil {
		return nil, fault.Wrap(fault.KindInternal, op, "encoding the request", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, bytes.NewReader(payload))
	if err != nil {
		return nil, fault.Wrap(fault.KindInvalidArgument, op, "building the request", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// BOTH, AND THE CLIENT MUST SUPPORT BOTH. A server chooses per request
	// whether to answer with a single JSON object or an SSE stream.
	req.Header.Set("Accept", "application/json, text/event-stream")

	// **`MCP-Protocol-Version` GOES ON EVERY REQUEST OF EVERY REVISION, INCLUDING
	// `initialize`, AND OMITTING IT IS A SILENT DOWNGRADE.** 2025-06-18 words it
	// as a client MUST "on all subsequent requests", which reads as though the
	// handshake is exempt — and the same section says that a server receiving no
	// header "SHOULD assume protocol version 2025-03-26". That is a revision this
	// build refuses, arrived at by omission, with nothing in any log to say it
	// happened. Sending it everywhere costs one header and removes the guess.
	req.Header.Set("MCP-Protocol-Version", revision)

	// **THE REQUEST-METADATA HEADERS ARE `2026-07-28`'S AND NOBODY ELSE'S.**
	// `Mcp-Method` and `Mcp-Name` must agree with the body or a validating server
	// rejects with `-32020`; they exist so intermediaries can route without
	// parsing it. `2025-06-18` does not define them, so sending them there is
	// asserting a routing contract that revision never made.
	if stateless {
		req.Header.Set("Mcp-Method", method)

		// `Mcp-Name` is required for tools/call, carrying params.name.
		if name, ok := params["name"].(string); ok {
			req.Header.Set("Mcp-Name", headerValue(name))
		}
	}

	// **THE SESSION, ON EVERY REQUEST AFTER THE HANDSHAKE THAT MINTED IT.** Nil
	// on a sessionless revision and nil for `initialize` itself, which is the
	// one request that may not carry one.
	if sess != nil {
		req.Header.Set(sessionHeader, sess.id)
	}

	for name, value := range extra {
		if s, ok := value.(string); ok {
			req.Header.Set(name, s)
		}
	}

	// **API-KEY AUTH AS A PER-REQUEST HEADER (§4.7.4 class 1), which the
	// specification now assumes**: "credentials are per-request input, not
	// connection state". `Bearer` here, unlike the Fullstory SERVER API's
	// `Basic` — two endpoints on one vendor with two schemes (D189).
	//
	// PLACED BY THE BROKER, NOT BY THIS DRIVER (D199): one helper owns the
	// borrow, the buffer and the refusal of material that cannot be a header
	// value.
	if err := connector.SetAuthorization(req.Header, t, "Bearer"); err != nil {
		return nil, fault.Wrap(fault.KindUnauthenticated, op,
			"the target's credential could not be borrowed", err)
	}

	resp, err := d.http.Do(req)
	if err != nil {
		return nil, transportFault(op, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// **A SERVER THAT MINTS A SESSION IS TALKING AN OLDER REVISION**, and this
	// driver neither echoes nor stores it (D192a). Reported rather than ignored
	// silently: a server expecting session continuity will behave unpredictably
	// under a client that provides none, and "unpredictable" is the one thing a
	// governed path must not be.
	if sid := resp.Header.Get(sessionHeader); sid != "" && stateless {
		return nil, fault.New(fault.KindSpecDrift, op, fmt.Sprintf(
			"the server at %q assigned an %s, which protocol revision %s removed. "+
				"Sekizui is stateless by design (D4) and will not carry a session: a "+
				"session is per-process state that a second replica does not hold (P7), "+
				"and half-supporting one produces a server that appears to work. Point "+
				"this target at an endpoint speaking %s, or wait for the server to be "+
				"upgraded", t.Ref(), sessionHeader, revision, revision))
	}

	// **A 404 ON A REQUEST THAT CARRIED A SESSION MEANS THE SERVER FORGOT US, and
	// the specification makes re-establishing it a client MUST** — "when a client
	// receives HTTP 404 in response to a request containing an Mcp-Session-Id, it
	// MUST start a new session by sending a new InitializeRequest".
	//
	// **CHECKED BEFORE THE BODY IS EVEN READ, and before `httpFault`, because the
	// same status means something completely different one line down.** MCP reads
	// a BARE 404 as "this might be a legacy HTTP+SSE endpoint" — a configuration
	// question about a URL. The presence of a session id is the entire difference
	// between that and a routine expiry, and it is a fact about the REQUEST WE
	// SENT rather than anything in the response, which is why no amount of
	// inspecting the body could recover it.
	if resp.StatusCode == http.StatusNotFound && sess != nil {
		return nil, fault.SessionRejected(op, fmt.Sprintf(
			"the server at %q no longer recognises our session, so the request was "+
				"rejected before %q ran. The session is discarded and the next call "+
				"establishes a new one (%s requires exactly that); no credential was "+
				"re-minted, because the credential was never in question",
			t.Ref(), method, revision))
	}

	// BOUNDED (D178): an MCP response reaches the audit detail, the WAL and an
	// fsync, so an unbounded read is a write amplifier aimed at our own disk.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fault.Wrap(fault.KindTargetUnavailable, op, "reading the response", err)
	}

	// **AN HTTP STATUS AND A JSON-RPC ERROR ARE DIFFERENT LAYERS, and the
	// specification makes the body authoritative where both are present.** A
	// modern server answers an unknown method with HTTP 404 AND `-32601`, and a
	// version mismatch with HTTP 400 AND a named error — so the body is read
	// first and the status is the fallback.
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	decoded := json.Unmarshal(raw, &envelope) == nil

	if decoded && envelope.Error != nil {
		return nil, protocolFault(op, t, method, envelope.Error)
	}
	if resp.StatusCode >= 300 {
		return nil, httpFault(op, resp, raw)
	}
	if !decoded {
		return nil, fault.New(fault.KindTargetError, op, fmt.Sprintf(
			"the server answered %s with a body that is not JSON-RPC", method))
	}
	if len(envelope.Result) == 0 {
		return nil, fault.New(fault.KindTargetError, op, fmt.Sprintf(
			"the server answered %s with neither a result nor an error", method))
	}
	if err := json.Unmarshal(envelope.Result, out); err != nil {
		return nil, fault.Wrap(fault.KindTargetError, op,
			"the server's result does not match the shape "+method+" defines", err)
	}
	return resp.Header, nil
}

// headerValue encodes a value for an MCP metadata header.
//
// **THE BASE64 SENTINEL IS NOT OPTIONAL.** HTTP field values are visible ASCII
// only, and a tool name outside that set — or one that merely LOOKS like the
// sentinel — must be encoded as `=?base64?…?=` or the server's header/body
// comparison fails with `-32020`. Tool names are only SHOULD-constrained to safe
// characters, so a conforming client cannot assume they are safe.
func headerValue(v string) string {
	safe := v != "" &&
		!strings.HasPrefix(v, "=?base64?") &&
		v == strings.TrimSpace(v)
	if safe {
		for i := 0; i < len(v); i++ {
			if v[i] < 0x21 || v[i] > 0x7E {
				safe = false
				break
			}
		}
	}
	if safe {
		return v
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(v)) + "?="
}

// transportFault classifies a failure that never got an HTTP response.
//
// The timeout case is the one that matters, because D182 makes it
// INDETERMINATE: a `none`-class tool call that times out may or may not have
// run, and reporting it as merely unavailable would tell a caller the call did
// not happen.
func transportFault(op string, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return fault.Wrap(fault.KindTimeout, op,
			"the MCP server did not answer before its deadline", err)
	default:
		return fault.Wrap(fault.KindTargetUnavailable, op,
			"the MCP server could not be reached", err)
	}
}

// httpFault maps a transport-level status with no usable JSON-RPC body.
//
// **A 401 FROM A GATEWAY IN FRONT OF AN MCP SERVER IS AN AUTH PROBLEM, NOT A
// PROTOCOL ONE**, and mapping it as a protocol error would lose that — sending
// an operator to read a tool spec when the answer is to rotate a key.
func httpFault(op string, resp *http.Response, raw []byte) error {
	kind := fault.KindTargetError
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		// **RE-ESTABLISHABLE, AND THIS IS ONE OF ONLY TWO PLACES THAT MAY SAY SO
		// (D203).** The far side looked at a credential we sent and rejected it,
		// which is the one producer of `unauthenticated` that a fresh mint can
		// fix. The other four — D199's placement refusal, D152's downgrade guard,
		// a borrow on a wiped credential, and an IdP that would not issue —
		// return the same kind and must NOT set this, because re-minting returns
		// the same bytes for one of them and is the attacker's goal for another.
		//
		// The marker is set HERE, where a real HTTP status was read, rather than
		// derived from the kind anywhere upstream. That is the whole reason it is
		// a field on the error and not a method on Kind.
		//
		// The gateway invalidates the cached credential and traverses the
		// enforcement path once more (D204) — every ceiling included, so a
		// revocation landing in between still stops the second call.
		return fault.CredentialRejected(op,
			fmt.Sprintf("the MCP server returned 401: %s", snippet(raw)))
	case http.StatusForbidden:
		kind = fault.KindDenied
	case http.StatusTooManyRequests:
		return &fault.Error{
			Kind: fault.KindRateLimited, Op: op,
			Msg:        fmt.Sprintf("the MCP server returned 429: %s", snippet(raw)),
			RetryAfter: retryAfter(resp.Header.Get("Retry-After")),
		}
	case http.StatusNotFound:
		// **AMBIGUOUS BY DESIGN, AND THE SPECIFICATION SAYS SO.** A modern server
		// answers an unknown METHOD with 404 plus `-32601`; a legacy HTTP+SSE
		// server returns a bare 404 because it hosts no MCP endpoint at all. We
		// reach here only when the body carried no JSON-RPC error, which is the
		// second case.
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"the endpoint returned 404 with no JSON-RPC error body, which is how a "+
				"legacy HTTP+SSE server (protocol 2024-11-05) answers a Streamable HTTP "+
				"POST. That transport is deprecated and this driver does not implement "+
				"it; the target's base_url is probably not an MCP endpoint"))
	case http.StatusMethodNotAllowed:
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"the endpoint returned 405 to a POST, so it is not an MCP endpoint that "+
				"accepts Streamable HTTP: %s", snippet(raw)))
	default:
		if resp.StatusCode >= 500 {
			kind = fault.KindTargetError
		} else if resp.StatusCode >= 400 {
			kind = fault.KindInvalidArgument
		}
	}
	return fault.New(kind, op, fmt.Sprintf("the MCP server returned %d: %s",
		resp.StatusCode, snippet(raw)))
}

// protocolFault maps a JSON-RPC error onto the shared taxonomy.
//
// **BY NAMED CODE RATHER THAN BY RANGE, because three of these mean something
// specific and one of them is OURS.** `-32020 HeaderMismatch` means this driver
// built a request whose headers and body disagree — a Sekizui bug, not a target
// fault, and classifying it as `target_error` would send an operator to
// investigate a vendor.
func protocolFault(op string, t connector.Target, method string, e *rpcError) error {
	msg := fmt.Sprintf("the MCP server rejected %s with JSON-RPC error %d: %s",
		method, e.Code, e.Message)

	switch e.Code {
	case codeHeaderMismatch:
		return fault.New(fault.KindInternal, op, msg+
			". Code -32020 means the request's headers and body disagree, or a required "+
			"header is missing — which this driver builds, so it is OUR defect rather "+
			"than the server's")

	case codeMethodNotFound:
		// The server does not implement the method. For `tools/list` that means
		// it is not a tools server at all, which is a configuration problem
		// rather than an availability one.
		return fault.New(fault.KindConfig, op, msg+fmt.Sprintf(
			". Target %q may not be an MCP tools server, or speaks a revision that "+
				"does not define %s", t.Ref(), method))

	case codeInvalidParams:
		// **THE ONE A CALLER CAN ACT ON.** Deliberate, so D135 carries it back as
		// a result with a kind rather than as a transport error.
		return fault.New(fault.KindInvalidArgument, op, msg)

	case codeParseError, codeInvalidRequest:
		return fault.New(fault.KindInternal, op, msg+
			". A malformed request is this driver's fault, not the server's")

	case codeInternalError:
		return fault.New(fault.KindTargetError, op, msg)
	}

	// **AN UNSUPPORTED PROTOCOL VERSION ARRIVES AS A NAMED ERROR RATHER THAN A
	// CODE**, so it is matched on the message. Reported as a configuration
	// incompatibility an operator must resolve — this driver does not negotiate
	// down, because that would make the shape of a governed call depend on a
	// vendor's deployment schedule (D192a).
	if strings.Contains(e.Message, "UnsupportedProtocolVersion") ||
		strings.Contains(e.Message, "protocol version") {
		return fault.New(fault.KindConfig, op, msg+fmt.Sprintf(
			". Sekizui speaks %s and does not negotiate down: an older revision means "+
				"sessions, a GET stream and resumable SSE, none of which a stateless "+
				"governed relay implements (D192a)", ProtocolVersion))
	}

	// UNKNOWN CODE, and the direction is deliberate: `target_error` is retryable
	// and non-deliberate, so an unclassified protocol error is loud rather than
	// silently treated as a caller mistake.
	return fault.New(fault.KindTargetError, op, msg)
}

// retryAfter parses the header, tolerating both forms the RFC allows. Capped by
// the retry policy rather than here (§4.3.4).
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

// snippet bounds vendor text carried into a decision record (D178).
func snippet(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > maxTextBytes {
		return s[:maxTextBytes] + "… (truncated)"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}

// base returns the target's MCP endpoint, refusing rather than guessing.
func (d *Driver) base(op string, t connector.Target) (string, error) {
	raw := strings.TrimRight(t.BaseURL(), "/")
	if raw == "" {
		return "", fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q declares no base_url, and an MCP endpoint cannot be inferred: "+
				"there is no convention, only whatever the operator was given", t.Ref()))
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q has base_url %q, which is not an https URL with a host. The "+
				"credential is a Bearer token on every request, and plaintext would put "+
				"it on the wire in clear", t.Ref(), raw))
	}
	// THE VETTED HOST, ON EVERY REQUEST (D289) — initialize, tools/list and
	// tools/call alike, because each carries the credential.
	if err := d.AdmitBaseURL(t.Ref(), raw); err != nil {
		return "", err
	}
	return raw, nil
}

var _ connector.HostBound = (*Driver)(nil)

// AdmitBaseURL refuses a base_url whose host is not the one the target's
// vetted spec was reviewed against (connector.HostBound, D289). What a human
// vetted is THIS server's tools; pointing them — and the target's credential —
// at another host is sending both to a server nobody reviewed. CONTRACTS 117,
// closed for MCP generically: the host list is the vetted spec's, not the
// driver's.
func (d *Driver) AdmitBaseURL(targetRef, raw string) error {
	const op = "mcp.AdmitBaseURL"
	spec, ok := d.specs[targetRef]
	if !ok {
		return nil // no vetted spec is refused elsewhere, by name (D192)
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.User != nil || spec.Host == "" || u.Hostname() != spec.Host {
		host := ""
		if err == nil {
			host = u.Hostname()
		}
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q is vetted against host %q and its base_url names %q; its credential "+
				"would go to a server nobody reviewed (D289, CONTRACTS 117)",
			targetRef, spec.Host, host))
	}
	return nil
}

// maxResponseBytes bounds one MCP response (D178).
const maxResponseBytes = 1 << 20

// maxTextBytes bounds vendor text carried into a decision record (D178).
const maxTextBytes = 4096

// toolResult is `tools/call`'s result envelope.
type toolResult struct {
	// ResultType is `complete` or `input_required` (multi round-trip).
	ResultType string `json:"resultType"`

	Content           []json.RawMessage `json:"content"`
	StructuredContent json.RawMessage   `json:"structuredContent,omitempty"`
	IsError           bool              `json:"isError"`
}

// callTool performs `tools/call`.
func (d *Driver) callTool(ctx context.Context, op string, t connector.Target,
	sess *session, spec SpecTool, args, headers map[string]any) (connector.Result, error) {

	tool := spec.Name
	var result toolResult
	if err := d.rpc(ctx, op, t, sess, "tools/call", map[string]any{
		"name": tool, "arguments": args,
	}, headers, &result); err != nil {
		return connector.Result{}, err
	}

	// **AN ELICITATION REQUEST IS REFUSED, NOT SATISFIED.** The specification
	// lets a server answer `tools/call` with `resultType: "input_required"`,
	// asking the CLIENT to gather more input and retry with `inputResponses`. A
	// governed relay has nobody to ask: there is no human on the efferent path,
	// and answering on the caller's behalf would make Sekizui's decision look
	// like theirs in the audit record.
	//
	// **KindEscalated IS THE RIGHT KIND and it is not a stretch** — it means the
	// request is well-formed and permitted in principle, with a precondition
	// (human input) unmet, which is exactly this. It is also why
	// `clientCapabilities` is declared EMPTY: claiming sampling or elicitation
	// support would invite the server to ask.
	if result.ResultType == "input_required" {
		return connector.Result{}, fault.New(fault.KindEscalated, op, fmt.Sprintf(
			"tool %q asked for additional input before it would run "+
				"(`resultType: input_required`). Sekizui relays a governed action and has "+
				"nobody to ask — answering on the caller's behalf would record our "+
				"decision as theirs. The call needs to supply everything up front, or "+
				"this tool needs a client that is not a policy enforcement point", tool))
	}

	// **`isError: true` MEANS THE TOOL RAN AND FAILED**, which the specification
	// separates from a protocol error precisely because a model can act on it.
	// DETERMINATE, because the server received the call — so D182's indeterminate
	// class does not apply however the tool failed, and a `none`-class retry
	// refusal would be the wrong answer here.
	if result.IsError {
		return connector.Result{}, fault.New(fault.KindTargetError, op, fmt.Sprintf(
			"tool %q reported an execution error: %s. The call was RECEIVED and the "+
				"tool ran, so the outcome is known rather than indeterminate (D182)",
			tool, textOf(result.Content)))
	}

	// **ONE PAYLOAD RULE, SO THE DRIVER DELIVERS WHAT sekizui-mcpspec DRAFTS
	// (D289).** A declared result is built by payloadOf; this older shape —
	// structuredContent nested under `structured`, text as one truncated string
	// — stays for a tool that declares no result, whose data D283 withholds
	// anyway. It was the ONLY shape until D289, and a drafted data_schema could
	// never match it: every field shaped away.
	if spec.Result == "text" || spec.OutputType != "" {
		data, err := payloadOf(op, spec, result)
		if err != nil {
			return connector.Result{}, err
		}
		// THE CONTRACT, AT RUN TIME (D289, CONTRACTS 137). A result that
		// breaks its output_schema's TYPES or drops a required field is
		// refused; one that only ADDS fields is tallied as a signal — its
		// data_schema already strips them, and refusing would take the tool
		// down whenever the vendor ships a feature.
		if added, err := conforms(op, spec, data); err != nil {
			return connector.Result{}, err
		} else if len(added) > 0 {
			d.tallyNonconforming(t.Ref(), fmt.Sprintf("tool %q returned fields its output_schema "+
				"does not declare: %v", spec.Name, added))
		}
		return connector.Result{StatusCode: http.StatusOK, Data: data}, nil
	}

	data := map[string]any{}
	if len(result.StructuredContent) > 0 {
		// **STRUCTURED CONTENT IS ANY JSON VALUE, not necessarily an object**, so
		// it is nested under a key rather than merged — merging would fail for an
		// array or a scalar and silently lose the result.
		var structured any
		if err := json.Unmarshal(result.StructuredContent, &structured); err != nil {
			return connector.Result{}, fault.Wrap(fault.KindTargetError, op,
				"structuredContent is not valid JSON", err)
		}
		data["structured"] = structured
	}
	if text := textOf(result.Content); text != "" {
		data["text"] = text
	}

	return connector.Result{StatusCode: http.StatusOK, Data: data}, nil
}

// textOf concatenates the text blocks of a content array.
//
// **TEXT ONLY, ON PURPOSE.** The array can carry images, audio, resource links
// and embedded resources; none of those belongs in an audit detail, and base64
// image data reaching the WAL is D178's write amplifier wearing a content type.
func textOf(content []json.RawMessage) string {
	var parts []string
	for _, block := range content {
		var b struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(block, &b); err != nil {
			continue
		}
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	joined := strings.Join(parts, "\n")
	if len(joined) > maxTextBytes {
		return joined[:maxTextBytes] + "… (truncated)"
	}
	return joined
}

// Schemas returns the data schema of every vetted tool that declares an
// OutputType (D279), from the vetted spec — the one place a data schema lives
// in configuration, because for MCP the spec IS the connector's declaration.
// A tool with an OutputType and no data_schema is not returned, and the boot
// refuses its type for having no schema, naming it.
//
// ONE TYPE, ONE SCHEMA: two targets of one server legitimately share a tool's
// type, and are returned once; the same type with DIFFERENT data schemas is
// refused, because what the type means would depend on which target served it.
func (d *Driver) Schemas() ([]connector.Schema, error) {
	var out []connector.Schema
	seen := map[string]json.RawMessage{}
	for _, ref := range sortedRefs(d.specs) {
		for _, tool := range d.specs[ref].Tools {
			if tool.OutputType == "" || len(tool.DataSchema) == 0 {
				continue
			}
			if prev, dup := seen[tool.OutputType]; dup {
				if !sameSchema(prev, tool.DataSchema) {
					return nil, fmt.Errorf("output type %q has two different data schemas across "+
						"vetted specs (target %q among them); one type, one schema (D279)", tool.OutputType, ref)
				}
				continue
			}
			seen[tool.OutputType] = tool.DataSchema
			out = append(out, connector.Schema{Type: tool.OutputType, Body: tool.DataSchema})
		}
	}
	return out, nil
}

// Meter declares an MCP server's meter (D284): calls, one `tools/call` each.
// A generic MCP driver knows no vendor, so it declares no default and a target
// without `rate_per_hr` takes the universal one.
func (d *Driver) Meter() connector.Meter {
	return connector.Meter{
		Unit: connector.UnitCalls,
		// THE SYSTEM BUDGET (D311): twelve comparisons an hour — the drift
		// watcher's five-minute cadence — at the HARD page bound, so any
		// `list_pages` a spec may declare fits. A separate bucket, so the
		// generosity costs consumers nothing; the vendor's quota is still one
		// (D52).
		SystemPerHour: 12 * maxToolPages,
		// ONE CALL PER PAGE, AT THE DECLARED BOUND, before it is sent (D284).
		DriftCost: func(t connector.Configured) uint64 { return uint64(d.listPages(t.Ref())) },
	}
}

// handleRole carries a vetted tool's handle declaration to its ActionSpec (D291).
func handleRole(h *config.HandleSpec) *connector.HandleRole {
	if h == nil {
		return nil
	}
	return &connector.HandleRole{Opens: h.Opens, Closes: h.Closes, Uses: h.Uses}
}
