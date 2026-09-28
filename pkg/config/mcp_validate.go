package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/jsonref"
)

// mcpActionPrefix is the namespace every MCP action name sits under (D49).
//
// `mcp.<server>.<tool>`, with `Kind()` staying `"mcp"`. The real constraint that
// forced namespacing is that `Actions() []ActionSpec` takes no Target, so one
// generic driver must return one flat list spanning every configured server —
// which requires globally unique names, or a signature change churning public
// API for every driver to serve one (§4.9a.4).
const mcpActionPrefix = "mcp."

// mcpKind is the driver kind an MCP target names.
const mcpKind = "mcp"

// outputSchemaOrigins is the closed vocabulary for D51's provenance.
//
// **ONLY `vendor` IS DRIFT-CHECKED**, which is the whole reason provenance is
// pinned rather than inferred: the vendor never claimed a `local` schema, so
// there is nothing for it to diverge from, and comparing one would manufacture
// incidents out of our own guesses (D51, D168).
//
//nolint:gochecknoglobals // immutable vocabulary, fixed at compile time
var outputSchemaOrigins = map[string]string{
	"vendor": "copied from the server's own tools/list and vetted; drift-checked",
	"local":  "authored by a maintainer from observed responses; NEVER drift-checked",
}

// OutputSchemaOrigins returns the vocabulary, sorted, for error messages.
//
// An enumerator beside the set, so a message offering the choices cannot fall
// behind the set that validates them (§15q).
func OutputSchemaOrigins() []string {
	out := make([]string, 0, len(outputSchemaOrigins))
	for o := range outputSchemaOrigins {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// mcpRevisions is the closed set of protocol revisions a spec may declare (D193).
//
// **EACH ENTRY STATES WHAT IT COSTS, because that is the point of declaring one
// rather than negotiating it.** An operator choosing an older revision is
// choosing sessions and an `initialize` handshake, and the vocabulary is where
// they can see that before the commit rather than after an incident.
//
//nolint:gochecknoglobals // immutable vocabulary, fixed at compile time
var mcpRevisions = map[string]struct {
	// stateless: no protocol-level session, no initialize handshake.
	stateless bool

	// implemented: whether THIS BUILD can speak it. D53's rule applied to a
	// protocol vocabulary — the set is declared whole so an operator can see
	// which revisions exist, and selecting an unimplemented one REFUSES rather
	// than degrading silently.
	implemented bool

	why string
}{
	"2026-07-28": {stateless: true, implemented: true,
		why: "sessions, the GET stream and resumable SSE are REMOVED; credentials are " +
			"per-request input rather than connection state, which is §4.7.4 class 1 in " +
			"the protocol's own words"},
	"2025-11-25": {
		why: "protocol-level sessions via Mcp-Session-Id, a standalone GET stream, " +
			"resumable SSE, and an initialize handshake — every one of which is " +
			"per-process state a second replica does not hold (D4, P7)"},
	// **IMPLEMENTED AS OF D213, AND IT IS THE ONLY STATEFUL ONE THAT IS.** The
	// difference between this entry and its two neighbours is not technical
	// merit — it is that a real vendor serves this revision and none serves
	// them, so D192a's "an incompatibility an operator must act on" had no
	// action behind it. `implemented` is what separates a revision we CAN speak
	// from one we merely know the name of, and the boot refusal reads
	// differently for each.
	"2025-06-18": {stateless: false, implemented: true,
		why: "protocol-level sessions via Mcp-Session-Id and an initialize " +
			"handshake, which are per-process state a second replica does not hold " +
			"(D4, P7). Sekizui speaks it in full — the session is established at " +
			"BuildClient, carried on every request, and terminated on close — and a " +
			"target declaring it is therefore §4.7.4 CLASS 3 rather than class 1"},
	"2025-03-26": {
		// **SELF-CONTAINED, and the first draft was not.** It read "as 2025-11-25",
		// which made the boot refusal for THIS revision tell an operator to go and
		// read a different entry — a message that defers is a message somebody has
		// to chase. Caught by the test asserting the refusal explains the cost.
		why: "protocol-level sessions via Mcp-Session-Id, a standalone GET stream, " +
			"resumable SSE, and an initialize handshake — and it predates the " +
			"request-metadata headers, so it is the revision that introduced Streamable " +
			"HTTP in its original stateful shape (D4, P7)"},
}

// MCPRevisions returns the vocabulary, sorted (§15q).
func MCPRevisions() []string {
	out := make([]string, 0, len(mcpRevisions))
	for r := range mcpRevisions {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// MCPRevisionImplemented reports whether this build can speak a revision.
func MCPRevisionImplemented(rev string) bool { return mcpRevisions[rev].implemented }

// MCPRevisionExplain returns what choosing a revision costs.
func MCPRevisionExplain(rev string) string { return mcpRevisions[rev].why }

// MCPRevisionStateless reports whether a revision has no protocol-level session.
//
// **THE DEFAULT ANSWER FOR AN UNKNOWN REVISION IS `false`, WHICH IS THE
// EXPENSIVE DIRECTION AND THE SAFE ONE.** A caller asking about a revision this
// table does not carry has already been refused at boot, so the only way to
// reach it is a hand-made Document in a test — and answering "stateless" there
// would build a driver that skips the handshake for a revision nobody described.
// Treating unknown as stateful means such a target attempts `initialize` and
// fails loudly against a server that does not want one, rather than silently
// speaking a shape the table never sanctioned.
//
// D75's *cannot confirm* against *refuted*, in the place a protocol vocabulary
// meets a zero value.
func MCPRevisionStateless(rev string) bool { return mcpRevisions[rev].stateless }

// DefaultMCPRevision is what an absent declaration means.
//
// **THE MODERN, SESSIONLESS ONE — so the SAFE shape is the default and the
// weaker shape is the deliberate act.** The inverse would make an unreviewed
// spec inherit sessions.
const DefaultMCPRevision = "2026-07-28"

// mcpHeaderAnnotation is the extension property that mirrors an argument value
// into an HTTP header (D194).
const mcpHeaderAnnotation = "x-mcp-header"

// validateMCP is the OFFLINE half of D50, and it BLOCKS THE LOAD.
//
// **THE SPLIT D50 DRAWS, AND GETTING IT BACKWARDS FAILS IN BOTH DIRECTIONS.** An
// offline error that only warned would let a contradictory configuration serve;
// a live comparison that blocked start would make one unreachable MCP server
// prevent the whole instance from booting, including every target that has
// nothing to do with it — so an outage at a vendor becomes a deploy outage here
// (§4.9a.7). Everything in this file is answerable from the document alone,
// which is precisely why it belongs in the blocking half.
func (d *Document) validateMCP(p *problems, targets map[string]bool) {
	servers := d.validateMCPSpecs(p, targets)
	d.validateMCPGrants(p, servers)
	d.validateMCPTargetsHaveSpecs(p)
	d.validateNativeRelations(p)
}

// The two `native:` relations that are not action names (D323).
//
// NativeNone: reviewed, and it reaches nothing the native connector does.
//
// NativeOpaque: the reviewer CANNOT bound what it reaches — an LLM-backed tool,
// an agentic composite, an undocumented one. Nothing guarantees a vendor's MCP
// tools are thin deterministic wrappers over its API, so the worst case is a
// declared answer rather than a guess: an opaque tool is taken to reach the
// WHOLE surface of every linked native target, and its caller must hold every
// action of it. An opaque door is as wide as the widest door.
const (
	NativeNone   = "none"
	NativeOpaque = "opaque"
)

// NativePeers are the native targets an MCP target is LINKED to: those sharing
// its `limits.budget`, the declaration that they consume one upstream's quota
// and so front one upstream (D52, D208, D323). Shared by boot validation and
// the grant engine, so the two cannot disagree about which doors overlap.
func (d *Document) NativePeers(mcpRef string) []TargetSpec {
	var budget string
	for _, t := range d.Targets {
		if t.Ref == mcpRef && t.Kind == mcpKind && t.Limits != nil {
			budget = t.Limits.Budget
		}
	}
	if budget == "" {
		return nil
	}
	var out []TargetSpec
	for _, t := range d.Targets {
		if t.Kind != mcpKind && t.Limits != nil && t.Limits.Budget == budget {
			out = append(out, t)
		}
	}
	return out
}

// NativeRelations is every declared relation in force: MCP target ref -> MCP
// action -> the tool's `native:` list, for targets LINKED to native ones
// (NativePeers). The one reading the grant engine enforces and the catalog
// reports, so the two cannot disagree about what a tool reaches (D323). An
// unlinked target's relations are absent: nothing is there to hold them to.
func (d *Document) NativeRelations() map[string]map[string][]string {
	out := map[string]map[string][]string{}
	for ref, spec := range d.MCPSpecs {
		if len(d.NativePeers(ref)) == 0 {
			continue
		}
		byAction := map[string][]string{}
		for _, tool := range spec.Tools {
			if len(tool.Native) > 0 {
				byAction[mcpActionPrefix+spec.Server+"."+tool.Name] = tool.Native
			}
		}
		out[ref] = byAction
	}
	return out
}

// validateNativeRelations checks each tool's `native:` relation against the
// native targets its MCP target is linked to (D323). The actions themselves
// are checked against the linked connectors by grantcheck, which knows the
// drivers.
//
// **THE RELATION IS WHAT MAKES THE LINK FAIL CLOSED.** A budget name typo'd or
// renamed would unlink two doors in silence; a tool declaring `fullstory.*`
// actions on a target linked to no Fullstory target refuses the boot instead.
func (d *Document) validateNativeRelations(p *problems) {
	byRef := make(map[string]TargetSpec, len(d.Targets))
	for _, t := range d.Targets {
		byRef[t.Ref] = t
	}
	for _, ref := range sortedKeys(d.MCPSpecs) {
		peers := d.NativePeers(ref)
		kinds := map[string]bool{}
		for _, peer := range peers {
			kinds[peer.Kind] = true
			if peer.Residency != byRef[ref].Residency {
				p.addf("targets[%q] (residency %q) shares budget %q with %q (residency %q). Two doors "+
					"onto one upstream cannot sit in two classes — D52's third obligation (D323)",
					ref, byRef[ref].Residency, byRef[ref].Limits.Budget, peer.Ref, peer.Residency)
			}
		}
		// AN MCP SERVER NAMED AFTER A NATIVE KIND HERE, UNLINKED, MUST SAY SO
		// (D324): `mcp.fullstory` beside a `kind: fullstory` target overlaps it
		// by name. Leaving it unlinked is legitimate — a hybrid connector's MCP
		// may touch a different surface than its APIs — but only as a stated
		// choice: every tool declared [none]. A blank relation there is what a
		// forgotten link looks like, and it catches a native connector added
		// after the MCP server was vetted.
		server := d.MCPSpecs[ref].Server
		if len(peers) == 0 {
			var named []string
			for _, t := range d.Targets {
				if t.Kind == server && t.Kind != mcpKind {
					named = append(named, t.Ref)
				}
			}
			for _, tool := range d.MCPSpecs[ref].Tools {
				saysNone := len(tool.Native) == 1 && tool.Native[0] == NativeNone
				if len(named) > 0 && !saysNone {
					p.addf("mcp_specs[%q].tools[%q].native: %v, and the server `mcp.%s` sits beside %s "+
						"target(s) %v without sharing a budget. Link them with one `limits.budget`, or declare "+
						"[%s] to state this tool touches a different surface (D323, D324)",
						ref, tool.Name, tool.Native, server, server, named, NativeNone)
				}
			}
			// OTHERWISE AN UNLINKED TARGET'S RELATIONS ARE INERT (D324): a hybrid
			// connector ships them once in its vetted spec, and a deployment
			// running no native target of that kind has nothing to hold them to.
			continue
		}
		for _, tool := range d.MCPSpecs[ref].Tools {
			where := fmt.Sprintf("mcp_specs[%q].tools[%q].native", ref, tool.Name)
			if len(peers) > 0 && len(tool.Native) == 0 {
				p.addf("%s: missing. Target %q shares an upstream budget with native targets, so every vetted "+
					"tool states its native relation — the actions it mirrors, [%s], or [%s] — or the union "+
					"review has a gap nobody chose (D323)", where, ref, NativeNone, NativeOpaque)
				continue
			}
			seen := map[string]bool{}
			for _, a := range tool.Native {
				kind, _, _ := strings.Cut(a, ".")
				switch {
				case (a == NativeNone || a == NativeOpaque) && len(tool.Native) > 1:
					p.addf("%s: [%s] stands alone — it is the whole relation, not one of several (D323)", where, a)
				case a == NativeNone || a == NativeOpaque:
				case kind == mcpKind:
					p.addf("%s: %q is an MCP action; the relation names native connectors' actions (D323)", where, a)
				case !kinds[kind]:
					p.addf("%s: %q mirrors a %s action, and target %q shares a budget with no %s target. "+
						"Link them with one `limits.budget`, or the relation restricts nothing (D323)",
						where, a, kind, ref, kind)
				case seen[a]:
					p.addf("%s: %q listed twice", where, a)
				}
				seen[a] = true
			}
		}
	}
}

// validateMCPSpecs checks each vetted spec on its own terms.
func (d *Document) validateMCPSpecs(p *problems, targets map[string]bool) map[string]string {
	// server segment -> the target ref that claims it.
	servers := map[string]string{}

	for _, ref := range sortedKeys(d.MCPSpecs) {
		spec := d.MCPSpecs[ref]

		// A SPEC FOR A TARGET NOBODY DECLARED is a spec nothing can use, and it
		// is far more likely to be a typo'd ref than a deliberate spare.
		if !targets[ref] {
			p.addf("mcp_specs[%q]: no target with that ref. A vetted spec keyed to "+
				"nothing is either a typo or a spec somebody believes is in force", ref)
		}

		if spec.Server == "" {
			p.addf("mcp_specs[%q]: missing server segment. Action names are "+
				"`mcp.<server>.<tool>` (D49), so without it no action can be named", ref)
		} else if other, taken := servers[spec.Server]; taken {
			// **TWO TARGETS CLAIMING ONE SEGMENT MAKES EVERY GRANT AMBIGUOUS.**
			// `mcp.github.search` would name a tool on two servers, and the
			// enforcement path would have to pick — which is not a decision code
			// should make silently.
			p.addf("mcp_specs[%q] and mcp_specs[%q] both use server segment %q. Every "+
				"`mcp.%s.*` grant would then name tools on two servers, and nothing "+
				"could say which was meant", ref, other, spec.Server, spec.Server)
		} else {
			servers[spec.Server] = ref
		}

		// **THE DECLARED REVISION (D193).** Absent means the modern sessionless
		// one, so the safe shape is the default and the weaker shape is a
		// deliberate, reviewable act.
		if spec.Revision != "" {
			switch {
			case mcpRevisions[spec.Revision].why == "":
				p.addf("mcp_specs[%q]: revision %q is not a known MCP protocol revision. "+
					"Known: %v. Sekizui does not NEGOTIATE a revision — the far side "+
					"answering `UnsupportedProtocolVersion` and getting a weaker protocol "+
					"is an attacker-triggerable downgrade, so a human declares it (D193)",
					ref, spec.Revision, MCPRevisions())
			case !MCPRevisionImplemented(spec.Revision):
				p.addf("mcp_specs[%q]: revision %q is a real MCP revision and is NOT "+
					"implemented in this build. It requires %s. Refusing rather than "+
					"speaking it partially: a server that appears to work is the failure "+
					"§4.7.10 keeps naming (D53, D193). Implemented: %v",
					ref, spec.Revision, MCPRevisionExplain(spec.Revision),
					implementedRevisions())
			}
		}

		// **THE COMPARISON'S PAGE BOUND (D311)**, which is also its price.
		if spec.ListPages != nil && (*spec.ListPages < 1 || *spec.ListPages > MaxMCPListPages) {
			p.addf("mcp_specs[%q]: list_pages %d is outside 1..%d — it prices a drift comparison "+
				"at worst case before it is sent (D284, D311)", ref, *spec.ListPages, MaxMCPListPages)
		}

		// **THE UNROLL DEPTH (D309)**, bounded by the resolver's own constant.
		if spec.RefUnroll != nil && (*spec.RefUnroll < 0 || *spec.RefUnroll > jsonref.MaxUnroll) {
			p.addf("mcp_specs[%q]: ref_unroll %d is outside 0..%d — each level multiplies what a "+
				"recursive schema expands to (D306, D309)", ref, *spec.RefUnroll, jsonref.MaxUnroll)
		}

		// **THE VETTED HOST (D289).** What a human reviewed is this server's
		// tools, and the target's credential goes to its base_url on every call
		// — so the two must name the same host, or the vetted spec is being
		// pointed at a server nobody reviewed (CONTRACTS 117, closed for MCP).
		var baseURL string
		for _, t := range d.Targets {
			if t.Ref == ref {
				baseURL = t.BaseURL
			}
		}
		switch u, err := url.Parse(baseURL); {
		case spec.Host == "":
			p.addf("mcp_specs[%q]: no host. A vetted spec names the server host its tools "+
				"were reviewed against, so a target cannot point them at another (D289)", ref)
		case err == nil && baseURL != "" && (u.Hostname() != spec.Host || u.User != nil):
			p.addf("mcp_specs[%q]: vetted against host %q, and target %q's base_url names %q. "+
				"Its credential would go to a server nobody reviewed (D289, CONTRACTS 117)",
				ref, spec.Host, ref, u.Host)
		}

		if len(spec.Tools) == 0 {
			// D53's rule on a configuration surface: a spec with no tools is a
			// target that can serve nothing, declared as though it could.
			p.addf("mcp_specs[%q]: no tools. The vetted spec IS the capability set "+
				"(D46), so an empty one advertises a server that can do nothing", ref)
		}

		seen := map[string]bool{}
		for i, tool := range spec.Tools {
			d.validateMCPTool(p, ref, i, tool, seen)
		}
		d.validateMCPHandles(p, ref, spec)
	}
	return servers
}

// validateMCPTool checks one vetted tool.
func (d *Document) validateMCPTool(p *problems, ref string, i int, tool MCPToolSpec,
	seen map[string]bool) {

	where := fmt.Sprintf("mcp_specs[%q].tools[%d]", ref, i)

	if tool.Name == "" {
		p.addf("%s: missing name", where)
		return
	}
	where = fmt.Sprintf("mcp_specs[%q].tools[%q]", ref, tool.Name)

	if seen[tool.Name] {
		p.addf("%s: declared twice. Two entries for one tool means the effective "+
			"one depends on iteration order", where)
	}
	seen[tool.Name] = true

	// **A VETTED TOOL OWES A DESCRIPTION (D196), AND THE VENDOR MAY NOT HAVE
	// SUPPLIED ONE.** `description` is optional in MCP, so a server is free to
	// publish a tool with none — and the catalog then has nothing to tell a model
	// but the tool's own name. That is the case D196 refuses: a human is already
	// vetting this tool, and writing the sentence is the same act as deciding it
	// is safe to expose. The same permission D51 gives an output schema — we may
	// author what the vendor did not — with the same obligation attached.
	if strings.TrimSpace(tool.Description) == "" {
		p.addf("%s: no description. It is advertised to a model as something it may "+
			"attempt (§4.9 property 2), and MCP makes the vendor's description optional "+
			"— so the reviewer who vetted this tool writes one rather than letting the "+
			"catalog restate the tool's name back (D196)", where)
	}

	// **`inputSchema` IS MANDATORY IN MCP**, so a vetted spec missing one cannot
	// be compared against the live surface — and §4.9a.3 makes that comparison
	// the most dangerous divergence there is, because args validated against a
	// pinned schema are then sent to a server expecting a different shape.
	if len(tool.InputSchema) == 0 {
		p.addf("%s: no input_schema. It is mandatory in MCP, so its absence means "+
			"either the spec was hand-written without one or the tool does not exist "+
			"— and without it there is nothing to drift-check against (§4.9a.3)", where)
	} else if !json.Valid(tool.InputSchema) {
		p.addf("%s: input_schema is not valid JSON", where)
	}

	// **PROVENANCE IS REQUIRED EXACTLY WHEN THERE IS A SCHEMA, AND REFUSED
	// OTHERWISE** (D51). An origin with no schema describes nothing; a schema
	// with no origin is the case D51 exists to prevent — a locally-authored guess
	// that cannot be told apart from a vendor guarantee, so that when it starts
	// failing "they changed" and "we guessed wrong" are indistinguishable.
	switch {
	case len(tool.OutputSchema) > 0 && tool.OutputSchemaOrigin == "":
		p.addf("%s: has an output_schema and no output_schema_origin. Without it a "+
			"schema we wrote cannot be told from one the vendor published, and the "+
			"drift check would compare our own guess against the server (D51). "+
			"Set one of %v", where, OutputSchemaOrigins())
	case len(tool.OutputSchema) == 0 && tool.OutputSchemaOrigin != "":
		p.addf("%s: declares output_schema_origin %q with no output_schema. An origin "+
			"with nothing to describe reads as output typing that is in force and is "+
			"not", where, tool.OutputSchemaOrigin)
	case tool.OutputSchemaOrigin != "":
		if _, known := outputSchemaOrigins[tool.OutputSchemaOrigin]; !known {
			p.addf("%s: output_schema_origin %q is not in the vocabulary. Known: %v",
				where, tool.OutputSchemaOrigin, OutputSchemaOrigins())
		}
		if !json.Valid(tool.OutputSchema) {
			p.addf("%s: output_schema is not valid JSON", where)
		}
	}

	// **`x-mcp-header` MIRRORS A CALLER'S ARGUMENT INTO A NETWORK-VISIBLE HEADER,
	// AND THE SERVER CHOOSES WHICH ONE (D194).** The specification makes
	// mirroring a client MUST, so a conforming client copies whatever the schema
	// designates into `Mcp-Param-*` — where every load balancer, proxy, WAF and
	// logging tier on the path can read it, and where headers are routinely
	// logged in full while bodies are not. It tells SERVERS they "SHOULD NOT mark
	// sensitive parameters", which is advice to the honest party.
	//
	// For a policy enforcement point that is a data-egress decision rather than a
	// transport detail, so a tool that does it is REFUSED unless a human has read
	// which parameters travel and said so.
	if names := headerMirroredProperties(tool.InputSchema); len(names) > 0 &&
		!tool.HeaderMirroringReviewed {
		p.addf("%s: its input_schema mirrors %v into HTTP headers via `%s`, and nobody "+
			"has reviewed that. A mirrored argument leaves the request BODY and enters "+
			"network-visible metadata — proxies, load balancers and logging tiers all "+
			"see it, and the audit record does not say so. Set "+
			"`header_mirroring_reviewed: true` once you have read which parameters "+
			"travel, or drop the tool (D194)", where, names, mcpHeaderAnnotation)
	}

	// **A MUTATING TOOL MUST DECLARE ITS IDEMPOTENCY CLASS (D163), and the reason
	// is the same one ActionSpec has.** There is no safe default: `none` would
	// forbid retries the upstream supports, and anything else permits a
	// double-write nobody chose. This is the second field a human must set, and
	// the second reason the spec is *vetted* rather than cached.
	//
	// The CLASS ITSELF is validated by pkg/connector, which owns the vocabulary —
	// this checks only that a mutating tool made a statement, because `pkg/config`
	// importing `pkg/connector` would invert the dependency (a driver-facing type
	// reading configuration).
	if tool.Mutating && tool.Idempotency == "" {
		p.addf("%s: is mutating and declares no idempotency class. A human classifies "+
			"it and nobody infers it from a vendor hint (D163) — MCP's own "+
			"readOnlyHint and destructiveHint are the vendor's opinion, and this "+
			"field drives the retry gate", where)
	}
	if !tool.Mutating && tool.Idempotency != "" {
		p.addf("%s: is not mutating and declares idempotency class %q, which nothing "+
			"would ever consult — leaving it accepted lets a reviewer read it as in "+
			"force", where, tool.Idempotency)
	}
	d.validateMCPResult(p, ref, where, tool)
}

// validateMCPResult checks a tool's result declaration, extractions and pins
// (D289). Every refusal names what would otherwise have been silently wrong.
func (d *Document) validateMCPResult(p *problems, ref, where string, tool MCPToolSpec) {
	switch tool.Result {
	case "", "text":
	default:
		p.addf("%s: result %q is not a result kind; a tool returns JSON (omit `result`) or "+
			"`text`", where, tool.Result)
	}
	if len(tool.Extract) > 0 && tool.Result != "text" {
		p.addf("%s: declares extract without `result: text`; a JSON result's fields are its "+
			"own, and extraction is for featuring fields out of PROSE (D289)", where)
	}
	var dataProps map[string]any
	if len(tool.DataSchema) > 0 {
		var ds struct {
			Properties map[string]any `json:"properties"`
		}
		_ = json.Unmarshal(tool.DataSchema, &ds)
		dataProps = ds.Properties
	}
	fields := map[string]bool{}
	for j, e := range tool.Extract {
		at := fmt.Sprintf("%s.extract[%d]", where, j)
		re, err := regexp.Compile(e.Pattern)
		switch {
		case e.Field == "" || e.Field == "text":
			p.addf("%s: field %q — every extraction names a field, and `text` is the whole "+
				"result", at, e.Field)
		case fields[e.Field]:
			p.addf("%s: field %q is extracted twice; one field, one pattern", at, e.Field)
		case err != nil:
			p.addf("%s: pattern %q is not RE2: %v", at, e.Pattern, err)
		case re.NumSubexp() != 1:
			p.addf("%s: pattern %q has %d capture groups; exactly one says which part is the "+
				"field", at, e.Pattern, re.NumSubexp())
		case tool.OutputType != "" && dataProps[e.Field] == nil:
			p.addf("%s: extracts %q and the data_schema does not declare it — it would be "+
				"extracted and then stripped by shaping, which is a field that only appears "+
				"to exist (D279)", at, e.Field)
		}
		fields[e.Field] = true
	}
	switch tool.Combine {
	case "":
	case "items":
		if tool.Result == "text" {
			p.addf("%s: combine applies to JSON results; a text result is already one string", where)
		}
	default:
		p.addf("%s: combine %q is not a combination; `items` is the one there is", where, tool.Combine)
	}
	if tool.UserContent && tool.Result != "text" {
		p.addf("%s: user_content applies to a text result, whose fields are extracted from prose", where)
	}
	for j, e := range tool.Extract {
		if tool.UserContent && e.Line < 1 {
			p.addf("%s.extract[%d]: the tool's text carries end-user content, so an extraction "+
				"must name the vendor-authored LINE it reads — matched anywhere, a line a user "+
				"typed could supply the field (D289)", where, j)
		}
		if e.Line < 0 {
			p.addf("%s.extract[%d]: line %d; lines count from 1", where, j, e.Line)
		}
	}
	if tool.Result == "text" && tool.OutputType != "" && dataProps["text"] == nil {
		p.addf("%s: is `result: text` and its data_schema does not declare `text`; the whole "+
			"result would be stripped, admitting only what was extracted — declare it, and "+
			"withhold it with a lens if a consumer must not see it (D289)", where)
	}
	if len(tool.Pin) > 0 {
		var in struct {
			Properties map[string]any `json:"properties"`
		}
		_ = json.Unmarshal(tool.InputSchema, &in)
		var settings map[string]string
		for _, t := range d.Targets {
			if t.Ref == ref {
				settings = t.Settings
			}
		}
		for _, name := range tool.Pin {
			switch {
			case in.Properties[name] == nil:
				p.addf("%s: pins %q, which its input_schema does not declare; a pin constrains "+
					"an argument the tool actually takes (D289)", where, name)
			case settings[name] == "":
				p.addf("%s: pins %q to the target's own setting, and target %q declares no "+
					"%q — say which value this target is bound to (D289)", where, name, ref, name)
			}
		}
	}
}

// validateMCPGrants is CONTRACTS item 10 and D49's stated cost.
//
// **THE SERVER SEGMENT DUPLICATES THE TARGET REF, SO THEY CAN DISAGREE.**
// `{action: "mcp.github.*", target_ref: "gitlab-mcp"}` names one server in the
// action and another in the ref, and it must be rejected AT LOAD rather than
// discovered at call time — a grant that cannot mean anything is a grant
// somebody believes they have (§4.9a.4).
func (d *Document) validateMCPGrants(p *problems, servers map[string]string) {
	for _, g := range d.Grants {
		for _, c := range g.Allow {
			d.checkMCPCapability(p, g.Principal, "allow", c, servers)
		}
		for _, c := range g.Escalate {
			d.checkMCPCapability(p, g.Principal, "escalate", c, servers)
		}
	}
}

func (d *Document) checkMCPCapability(p *problems, principal, list string,
	c CapabilitySpec, servers map[string]string) {

	segment, ok := mcpServerSegment(c.Action)
	if !ok {
		return
	}

	claimed, known := servers[segment]
	if !known {
		p.addf("grants[%q].%s: action %q names MCP server segment %q, which no vetted "+
			"spec declares. Known segments: %v. A grant naming a server nobody "+
			"configured cannot authorise anything",
			principal, list, c.Action, segment, sortedKeys(servers))
		return
	}
	if c.TargetRef != "" && c.TargetRef != claimed {
		p.addf("grants[%q].%s: action %q names MCP server %q, which belongs to target "+
			"%q — but the grant targets %q. One of the two is wrong, and discovering "+
			"which at call time means an operator believes they granted something they "+
			"did not (D49, CONTRACTS item 10)",
			principal, list, c.Action, segment, claimed, c.TargetRef)
	}
}

// validateMCPTargetsHaveSpecs closes the other direction.
//
// **AN MCP TARGET WITH NO VETTED SPEC HAS NO CAPABILITY SET AT ALL**, because
// `Actions()` is generated from the spec and never from the wire (D46). Left
// unchecked, such a target loads cleanly, serves nothing, and refuses every
// command that names it — which is the same late failure D190 closed for an
// unimplemented driver kind, one layer in.
func (d *Document) validateMCPTargetsHaveSpecs(p *problems) {
	for _, t := range d.Targets {
		if t.Kind != mcpKind {
			continue
		}
		if _, ok := d.MCPSpecs[t.Ref]; !ok {
			p.addf("targets[%q]: kind %q with no entry in mcp_specs. The vetted spec IS "+
				"the capability set (D46), so this target would load cleanly, advertise "+
				"nothing, and refuse every command naming it", t.Ref, mcpKind)
		}
	}
}

// mcpServerSegment extracts the server from an MCP action name.
//
// Returns false for a non-MCP action, so every caller can hand it any action
// name rather than pre-filtering — which is what stops a new call site
// forgetting the prefix check.
func mcpServerSegment(action string) (string, bool) {
	rest, ok := strings.CutPrefix(action, mcpActionPrefix)
	if !ok {
		return "", false
	}
	segment, _, found := strings.Cut(rest, ".")
	if !found || segment == "" {
		return "", false
	}
	return segment, true
}

// implementedRevisions is what an operator can actually choose today.
func implementedRevisions() []string {
	var out []string
	for _, r := range MCPRevisions() {
		if MCPRevisionImplemented(r) {
			out = append(out, r)
		}
	}
	return out
}

// headerMirroredProperties returns the property paths an inputSchema mirrors
// into HTTP headers (D194).
//
// **WALKS `properties` CHAINS ONLY, which is exactly where the specification says
// a valid annotation can live**: statically reachable from the root through
// `properties` keys, never through `items`, `oneOf`/`anyOf`/`allOf`/`not`,
// `if`/`then`/`else`, or `$ref`. An annotation anywhere else makes the tool
// definition invalid, and a client MUST reject such a definition — so finding
// one outside a properties chain is itself worth reporting rather than ignoring.
//
// A DEPTH BOUND, because a `$ref` cycle in a hostile schema would otherwise
// recurse until the stack gave out during config validation — a denial of
// service against boot rather than against the serving path.
func headerMirroredProperties(schema json.RawMessage) []string {
	if len(schema) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(schema, &decoded); err != nil {
		return nil
	}
	var found []string
	walkSchemaProperties(decoded, "", 0, &found)
	sort.Strings(found)
	return found
}

const maxSchemaDepth = 32

func walkSchemaProperties(node any, path string, depth int, found *[]string) {
	if depth > maxSchemaDepth {
		return
	}
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}

	// THE ANNOTATION SITS DIRECTLY IN THE PROPERTY'S OWN SCHEMA.
	if name, present := obj[mcpHeaderAnnotation]; present && path != "" {
		*found = append(*found, fmt.Sprintf("%s -> Mcp-Param-%v", path, name))
	}

	props, ok := obj["properties"].(map[string]any)
	if !ok {
		return
	}
	for _, key := range sortedKeys(props) {
		child := path + "." + key
		if path == "" {
			child = key
		}
		walkSchemaProperties(props[key], child, depth+1, found)
	}
}

// validateMCPHandles checks one spec's handle lifecycle (D291): at most one
// opener, which needs a closer; the opener mutating and the closer repeat-safe;
// and every principal granted the opener also granted the closer — because
// Sekizui closes an idle handle AS its opener, and a principal that may open
// but not close would make every automatic close a refusal.
func (d *Document) validateMCPHandles(p *problems, ref string, spec MCPSpec) {
	var opener, closer *MCPToolSpec
	for i := range spec.Tools {
		tool := &spec.Tools[i]
		h := tool.Handle
		if h == nil {
			continue
		}
		set := 0
		for _, v := range []string{h.Opens, h.Closes, h.Uses} {
			if v != "" {
				set++
			}
		}
		if set != 1 {
			p.addf("mcp_specs[%q] tool %q: a handle declares exactly one of opens, closes, uses (D291)", ref, tool.Name)
			continue
		}
		switch {
		case h.Opens != "":
			if opener != nil {
				p.addf("mcp_specs[%q]: tools %q and %q both open a handle; one opener per spec (D291)",
					ref, opener.Name, tool.Name)
			}
			opener = tool
			if !tool.Mutating {
				p.addf("mcp_specs[%q] tool %q opens a handle and is not mutating; allocating a "+
					"vendor's slot is an effect, and a retried open leaks one (D291)", ref, tool.Name)
			}
		case h.Closes != "":
			if closer != nil {
				p.addf("mcp_specs[%q]: tools %q and %q both close a handle; one closer per spec (D291)",
					ref, closer.Name, tool.Name)
			}
			closer = tool
			if tool.Idempotency == "none" {
				p.addf("mcp_specs[%q] tool %q closes a handle and is class none; a close Sekizui "+
					"makes on its own must be safe to repeat (D291)", ref, tool.Name)
			}
		}
	}
	switch {
	case opener == nil && closer != nil:
		p.addf("mcp_specs[%q]: tool %q closes a handle nothing opens (D291)", ref, closer.Name)
	case opener != nil && closer == nil:
		p.addf("mcp_specs[%q]: tool %q opens a handle and no tool closes it; Sekizui could never "+
			"release an idle one (D291)", ref, opener.Name)
	case opener != nil:
		openAction := "mcp." + spec.Server + "." + opener.Name
		closeAction := "mcp." + spec.Server + "." + closer.Name
		for _, g := range d.Grants {
			var opens, closes bool
			for _, c := range g.Allow {
				if c.TargetRef != ref && c.TargetRef != "*" {
					continue
				}
				opens = opens || actionCovers(c.Action, openAction)
				closes = closes || actionCovers(c.Action, closeAction)
			}
			if opens && !closes {
				p.addf("principal %q may %s on %q and may not %s; Sekizui closes an idle handle AS "+
					"its opener, so the grant must cover both (D291)", g.Principal, openAction, ref, closeAction)
			}
		}
	}
}

// actionCovers reports whether a granted action pattern covers an action — an
// exact name, or a trailing `*` prefix.
func actionCovers(pattern, action string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(action, prefix)
	}
	return pattern == action
}
