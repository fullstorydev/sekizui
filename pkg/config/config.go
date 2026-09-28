// Package config defines the configuration and secret seams.
//
// PUBLIC API (D35). A self-hoster on Vault, or with an internal KMS, implements
// SecretProvider rather than forking.
//
// DESIGN.md references: §4.7, §4.10, D29, D34, D40.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Source supplies declarative configuration: targets, grants, reflexes, payload
// schemas.
//
// Implementations: local file or directory (D278); GCS/S3/Azure Blob, K8s
// ConfigMap and git are DESIGN's list and not built. NOT hot-reloadable: a
// change arrives by redeploy, and the urgent ones as governed verbs (D144,
// D146). This comment claimed otherwise until D278.
//
// CONFIGURATION CONTAINS NO SECRETS — only credential REFERENCES resolved through
// Provider. That is what allows config to live in version control, which is what
// makes the governance layer's own governance reviewable (§4.8).
type Source interface {
	// Load returns the current configuration document set.
	Load(ctx context.Context) (*Document, error)

	// Watch delivers a new Document on change. Nil channel if unsupported, in
	// which case the caller polls.
	//
	// A REJECTED RELOAD MUST NOT REPLACE RUNNING CONFIG. Validation failures
	// (D42's missing field paths, D21's stage violations, unresolvable grants)
	// leave the previous document in force and log loudly. A hot reload that
	// half-applies is worse than one that refuses.
	Watch(ctx context.Context) (<-chan *Document, error)
}

// Document is one complete, self-consistent configuration snapshot.
//
// Validated as a WHOLE before being applied, because the invariants are
// cross-cutting: a reflex references a grant, a grant references a target, a
// reflex predicate references a payload schema field path.
//
// JSON TAGS ARE THE YAML CONTRACT. Config is loaded via sigs.k8s.io/yaml, which
// converts YAML to JSON and delegates to encoding/json — so these `json:` tags
// are what an operator's YAML keys must match, and there is only ONE set of tags
// to keep correct. They are written out explicitly rather than relying on
// encoding/json's case-insensitive fallback, because that fallback matches
// baseUrl but NOT base_url, and snake_case is what §4.7 documents.
type Document struct {
	// Demo marks a DEMONSTRATION deployment (D315): the binary refuses to boot
	// it unless started with `-demo`, which `make run` passes and no production
	// manifest would. It carries a showcase principal with a wildcard grant, and
	// that must never be one misplaced config directory away from production —
	// the environment is assumed compromised, so "nobody would deploy the demo"
	// is not a control. Set in at most one file of a composed deployment.
	Demo bool `json:"demo,omitempty"`

	// Ordered pipeline stages (D43). Order defines monotonicity; the set is
	// extensible without code changes.
	Stages []string `json:"stages,omitempty"`

	// LLMStages names the stages that carry agent output (D64).
	//
	// Configured rather than hardcoded for the same reason Stages is: the stage
	// set is extensible, so "judged" is a convention rather than a keyword. A
	// deployment that adds a second agent-output stage must be able to say so.
	LLMStages []string `json:"llm_stages,omitempty"`

	Targets  []TargetSpec `json:"targets,omitempty"`
	Grants   []GrantSpec  `json:"grants,omitempty"`
	Reflexes []ReflexSpec `json:"reflexes,omitempty"`

	// Issuers are the identity brokers whose signed subject tokens this
	// deployment accepts (§4.4.2 tier two, D303, D318). None means tier one
	// only: the subject is ASSERTED and checked against `may_speak_for`.
	Issuers []IssuerSpec `json:"issuers,omitempty"`

	// Refinements IMPOSE connector-shipped `refines:` rules on a target for an
	// audience (D297 ruling 2, D299): a driver's rules are available by name and
	// reach nobody until listed here, so upgrading a driver never silently
	// changes what an agent receives.
	Refinements []RefinementSpec `json:"refinements,omitempty"`

	// Jobs holds settings for caller-triggered jobs (D267, D268).
	Jobs JobsSpec `json:"jobs,omitempty"`

	// Sources are the SCHEDULED trigger: targets polled on a timer with nobody
	// asking (D249, D266). Run only by `-mode=ingest`; a gateway serving the
	// same document schedules none of them.
	Sources []SourceSpec `json:"sources,omitempty"`

	// ReflexBudgets are firing budgets SHARED by the rules that name them (D334,
	// P5 criterion 7): a storm spread across rules is still one storm.
	ReflexBudgets []ReflexBudgetSpec `json:"reflex_budgets,omitempty"`

	// Presets are named sets of actions a grant may name instead of listing them
	// (D327). Usually a connector's suggested `presets.yaml`, dropped into the
	// config directory; expanded into ordinary capabilities at load.
	Presets []PresetSpec `json:"presets,omitempty"`

	// Anzen (安全, "safety") rules — the defensive class (D65).
	//
	// A SEPARATE LIST, not a flag on ReflexSpec, because they are a different
	// KIND of thing rather than a variety of reflex. A reflex acts on the world;
	// an anzen rule acts on Sekizui. Keeping them apart means the distinction
	// survives review: you can read every rule that can reach a customer system
	// without also reading the ones that cannot.
	Anzen []AnzenSpec `json:"anzen,omitempty"`

	// Shin (真, "truth") lenses — what a given consumer actually receives (D83).
	//
	// A SEPARATE LIST for the same reason Anzen is: a lens is a different KIND of
	// thing from a grant. A grant answers "may you", a lens answers "in what
	// shape" — and conflating them would make it impossible to review the
	// permission model without also reading every projection.
	Shin []ShinSpec `json:"shin,omitempty"`

	// Payload schemas, type -> JSON Schema (D40) — for the types THIS
	// DEPLOYMENT PRODUCES, such as a reflex's enrichment (D279).
	//
	// NOT FOR A CONNECTOR'S TYPES. A connector ships the schema of everything
	// it emits, beside its code, and a schema here for one of its types is
	// refused at boot: one type, one owner. The deployment narrows what its
	// consumers see with shin, and reacts with anzen.
	//
	// json.RawMessage, NOT []byte: encoding/json treats a []byte as a
	// base64-encoded string, so a schema written inline as YAML would fail to
	// parse and one written out would be unreadable. RawMessage is the stdlib
	// type for "hold this JSON verbatim", which is exactly what a registry of
	// schemas needs.
	PayloadSchemas map[string]json.RawMessage `json:"payload_schemas,omitempty"`

	// Rego policy modules, module name -> source.
	//
	// string, NOT []byte, for the same base64 reason. Rego is source text and an
	// operator writes it inline in the config file.
	Policies map[string]string `json:"policies,omitempty"`

	// CredentialPolicy is the bar every credential source must clear (D111).
	//
	// A POINTER, so "absent" and "require nothing" are distinguishable. Absent
	// means the deployment takes the default for its execution model; an explicit
	// empty `require: []` means it has decided to require nothing, which is a
	// different statement and one an operator may legitimately want to make.
	CredentialPolicy *CredentialPolicySpec `json:"credential_policy,omitempty"`

	// MCPSpecs are the VETTED tool manifests, keyed by target ref (D46).
	//
	// **THE VENDOR'S LIVE `tools/list` IS AN INPUT; THIS IS THE TRUTH.** The naive
	// implementation calls `tools/list` at connect time and exposes whatever comes
	// back, which hands the vendor unilateral authority to widen what an agent
	// fleet can do: a tool appears in a vendor release and is immediately
	// callable, having been vetted by nobody. For a system whose whole thesis is
	// *policy enforcement point* that is the wrong default (§4.9a.1).
	//
	// **CONFIGURATION RATHER THAN Go, and D40's argument carries directly.** A Go
	// tool manifest would mean a recompile to add an MCP server and a FORK for any
	// self-hoster adding their own — straight through D35. This sits next to
	// PayloadSchemas because it is the same kind of thing: data a reviewer diffs.
	//
	// KEYED BY TARGET REF rather than by server segment, because the ref is what
	// the rest of the system already keys on — the resolver, the pool, the
	// limiter, every grant. Keying on the segment would create a second identity
	// for one thing, and D49's contradiction check exists precisely because the
	// segment and the ref CAN disagree.
	MCPSpecs map[string]MCPSpec `json:"mcp_specs,omitempty"`

	// Version/etag of this snapshot, for logging which config is in force.
	// Usually set by the Source rather than written by hand.
	Version string `json:"version,omitempty"`

	// files are what FileSource composed this from (D278). Unexported, so it
	// is provenance rather than configuration and Identity() does not hash it.
	// Identity() DOES hash entry ORDER, which follows file order — so moving an
	// entry to a different file can change the identity with the policy
	// unchanged. The direction is the safe one: a new hash for the same policy,
	// never the same hash for a different one.
	files []string
}

// MCPSpec is one MCP server's vetted surface (D46, CONTRACTS item 9).
type MCPSpec struct {
	// Server is the segment that appears in action names: `mcp.<server>.<tool>`
	// (D49).
	//
	// **EXPLICIT RATHER THAN DERIVED FROM THE TARGET REF**, and the duplication is
	// deliberate. A ref is an operator's name for an endpoint (`github-mcp`,
	// `github-enterprise`); the server segment is what appears in every grant and
	// every audit row, so it must be stable across a ref rename. §4.9a.4 names the
	// cost — they can disagree — and boot validation refuses
	// `{action: "mcp.github.*", target_ref: "gitlab-mcp"}` rather than discovering
	// it at call time (D49, CONTRACTS item 10).
	Server string `json:"server"`

	// Revision is the MCP protocol revision this server speaks (D193).
	//
	// **DECLARED, NEVER NEGOTIATED, and that is a security property rather than
	// a preference.** The specification's backward-compatibility flow has a
	// client try a modern request and fall back on a `400` carrying
	// `UnsupportedProtocolVersionError`. **That fallback is an
	// attacker-triggerable DOWNGRADE**: a compromised or hostile server answers
	// with that error and a negotiating client obligingly drops to an older
	// shape — sessions, a GET stream, resumable SSE, and in the legacy era an
	// `initialize` handshake. Nothing about a governed relay should let the far
	// side choose how it is talked to.
	//
	// So a human writes down which revision this server speaks, and it becomes
	// part of the reviewed commit — the same argument D46 makes about the tool
	// list. Absent means the modern, sessionless revision.
	//
	// **AN OLDER SERVER IS SUPPORTED BY DECLARATION AND REFUSED BY DEFAULT**,
	// which is D53's rule rather than a limitation: a server that quietly gets a
	// weaker protocol is one nobody reviewed, and a client that silently spans
	// four revisions cannot say which guarantees are in force for which target.
	Revision string `json:"revision,omitempty"`

	// Host is the server host these tools were VETTED against (D289), e.g.
	// `api.fullstory.com`. REQUIRED: what a human reviewed is THIS server's
	// tools, and the target's credential goes to its base_url on every call —
	// so boot refuses a target whose base_url names another host, and the
	// driver refuses again on every call (CONTRACTS 117, closed for MCP).
	Host string `json:"host,omitempty"`

	// RefUnroll is how many times a recursive `$ref` in this server's output
	// schemas is expanded when its results are checked (D306, D309). ABSENT
	// MEANS jsonref.DefaultUnroll (1); a pointer so 0 — never follow a
	// recursion — is expressible. It should match the `-unroll` the data
	// schemas were drafted with; a mismatch fails safe either way (deeper data
	// is stripped by the data schema, or reported by conformance).
	RefUnroll *int `json:"ref_unroll,omitempty"`

	// ListPages is how many `tools/list` pages a drift comparison may read
	// (D311). ABSENT MEANS 1. It PRICES the comparison at worst case before it
	// is sent (D284), so a server that paginates past it fails the comparison
	// rather than spending calls nobody priced. At most MaxMCPListPages.
	ListPages *int `json:"list_pages,omitempty"`

	// Tools is the vetted tool list. `Actions()` is generated from THIS, never
	// from the wire.
	Tools []MCPToolSpec `json:"tools,omitempty"`
}

// MCPToolSpec is one vetted tool.
type MCPToolSpec struct {
	Name string `json:"name"`

	// Mutating is set BY A HUMAN and is never a vendor hint (§4.9a.1).
	//
	// **THE ONE JUDGEMENT A PERSON IS HERE TO MAKE.** MCP's `readOnlyHint` and
	// `destructiveHint` are vendor-SUPPLIED, and this field drives the idempotency
	// class, the retry gate and audit-as-external-effect (D23, D163). A generator
	// that reset it from a hint would destroy the review; §4.9a.1 makes preserving
	// it a requirement of the authoring tool, which is why this is a *vetted*
	// spec rather than a cached one.
	Mutating bool `json:"mutating"`

	// Idempotency is how a repeat of this tool is made safe (D163).
	//
	// REQUIRED ON A MUTATING TOOL, for the reason D163 gives about ActionSpec:
	// there is no safe default, since `none` would forbid retries an upstream
	// supports and anything else permits a double-write nobody chose. This is the
	// second field a human must set, and the second reason the spec is vetted.
	Idempotency string `json:"idempotency,omitempty"`

	// IdempotencyPlacement names where the key goes, when the class needs one.
	IdempotencyPlacement string `json:"idempotency_placement,omitempty"`

	// InputSchema is MANDATORY in MCP, so it is always available to compare and
	// always drift-checked (§4.9a.3). Args are validated against THIS and then
	// sent to the server; a divergence means the shape a human approved is no
	// longer the shape the server acts on, which is why that case refuses the
	// target rather than logging.
	InputSchema json.RawMessage `json:"input_schema,omitempty"`

	// OutputSchema is OPTIONAL in the ecosystem (D51), which is why its
	// provenance is pinned beside it.
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`

	// OutputSchemaOrigin is `vendor`, `local`, or empty (D51).
	//
	// **ONLY `vendor` IS DRIFT-CHECKED.** Much of the ecosystem publishes no
	// output schema, so treating absence as drift would make the check useless
	// against most real servers; and a locally-authored schema must never
	// masquerade as a vendor claim, because when it starts failing "they changed"
	// and "we guessed wrong" become indistinguishable. Required exactly when
	// OutputSchema is present, and refused otherwise — an origin with no schema
	// describes nothing.
	OutputSchemaOrigin string `json:"output_schema_origin,omitempty"`

	// OutputType is the registry key a reflex's ExpectsType matches (D88),
	// distinct from the schema itself.
	OutputType string `json:"output_type,omitempty"`

	// DataSchema is SEKIZUI'S schema for what this tool returns (D279) —
	// required whenever OutputType is set, and NOT the vendor's optional
	// OutputSchema above. For MCP the vetted spec IS the connector's
	// declaration (D46): the generic driver cannot know a server's tools, so
	// the reviewed spec — drafted by sekizui-mcpspec — carries the allowlist of
	// what each tool's results may bring in. Closed by default, like every
	// data schema.
	DataSchema json.RawMessage `json:"data_schema,omitempty"`

	// Native is this tool's relation to the native targets its target shares a
	// `limits.budget` with — the same upstream reached by another door (D323):
	// the native actions it reaches the same capability as — one, or several
	// for a composite, every one of which the caller must hold —
	// `[none]`, a reviewed statement that only this door reaches it, or
	// `[opaque]`, a reviewed statement that nobody can bound what it reaches,
	// taken as the whole surface of every linked native target.
	//
	// **SET BY A HUMAN, LIKE `mutating`, AND MANDATORY ON A LINKED TARGET.**
	// APIs and MCP servers do not line up one-to-one, and no machine can judge
	// where they do (§4.9a.8), so the reviewer states it; with no silent third
	// state, union review is complete by construction. It only ever narrows:
	// a declaration grants nothing.
	Native []string `json:"native,omitempty"`

	Description string `json:"description,omitempty"`

	// HeaderMirroringReviewed accepts a tool whose `inputSchema` mirrors argument
	// values into HTTP headers via `x-mcp-header` (D194).
	//
	// **THE SERVER CONTROLS `inputSchema`, AND THE SPECIFICATION MAKES MIRRORING
	// A CLIENT `MUST`.** So a server can designate any argument to be copied into
	// an `Mcp-Param-*` header, where every intermediary on the path — load
	// balancer, proxy, WAF, logging tier — can read it. Headers are routinely
	// logged in full where bodies are not. The spec tells SERVERS they "SHOULD
	// NOT mark sensitive parameters", which is advice to the honest party and no
	// protection at all from a dishonest one.
	//
	// For a policy enforcement point that is a data-egress decision, not a
	// transport detail: the caller's argument leaves the request body and enters
	// network-visible metadata, with nothing in the audit record saying so. So a
	// tool that does it is REFUSED at vet time unless a human has looked at which
	// parameters travel and written this down.
	//
	// **THE REASSURING PART, which falls out of the existing design for free:**
	// `x-mcp-header` lives INSIDE `inputSchema`, and D48 already refuses a target
	// whose live `inputSchema` diverges from the vetted one. So the annotation
	// cannot be ADDED to a vetted tool without producing a `refused` drift
	// finding — a vendor cannot switch mirroring on behind our back.
	HeaderMirroringReviewed bool `json:"header_mirroring_reviewed,omitempty"`

	// Result is "text" when the tool's CONTRACT is prose rather than JSON (D289)
	// — Fullstory's accessibility tree, its diff, its screenshot receipt. The
	// payload is then `{text}` plus the Extract fields, and data_schema must
	// declare `text` and each of them. Empty means a JSON result: the payload
	// is structuredContent when it is an object, else JSON parsed from the
	// tool's text, else the call is refused as not its declared shape.
	Result string `json:"result,omitempty"`

	// Extract features FIELDS out of a text result (D289), each by an RE2
	// pattern with exactly one capture group, matched per line; the first match
	// wins. Drafted by `sekizui-mcpspec -text -feature …`, chosen by a human.
	// RE2 cannot backtrack catastrophically, so a vendor string cannot hang the
	// gateway through one.
	Extract []ExtractSpec `json:"extract,omitempty"`

	// Pin names arguments whose value is the TARGET's own setting of the same
	// name (D289) — Fullstory's `org_id`, which otherwise lets a call reach
	// another org by argument. The driver injects the value when the caller
	// omits it and refuses the call when the caller names another. The target
	// must declare the setting, and input_schema must declare the argument.
	Pin []string `json:"pin,omitempty"`

	// Combine is how several JSON text blocks become one payload (D289):
	// `items` makes it `{items: [...]}`, one element per block. Empty REFUSES a
	// multi-block JSON result, in the driver and in sekizui-mcpspec alike —
	// silently joining blocks (unparseable) or treating them as samples of one
	// shape (a union nobody declared) were the two halves disagreeing.
	Combine string `json:"combine,omitempty"`

	// UserContent says a text result carries END-USER content (D289) —
	// Fullstory's accessibility tree holds what a user typed. Then every
	// extraction must declare a Line, because a pattern matched anywhere could
	// match a line a user wrote, and attacker text would arrive as a trusted
	// field.
	UserContent bool `json:"user_content,omitempty"`

	// Handle declares a STATEFUL handle's lifecycle (D291) — Fullstory's
	// session_open allocates a concurrent-session slot and returns `client_id`;
	// session_close releases it. Sekizui records each handle an opener returns
	// and closes it itself when it goes idle or the process drains, as the
	// principal who opened it. One opener per spec, and it needs a closer.
	Handle *HandleSpec `json:"handle,omitempty"`

	// VendorHash is a hash of the vendor's original advertisement, for cheap
	// drift comparison (§4.9a.1).
	//
	// CHEAP rather than authoritative: the schemas above are what a divergence is
	// judged on. This exists so the common case — nothing changed — costs one
	// string comparison instead of two schema walks per tool per connect.
	VendorHash string `json:"vendor_hash,omitempty"`
}

// HandleSpec is one tool's part in a handle lifecycle (D291). Exactly one of
// the three is set.
type HandleSpec struct {
	// Opens names the RESULT field carrying the handle this tool allocates.
	Opens string `json:"opens,omitempty"`
	// Closes names the ARGUMENT carrying the handle this tool releases.
	Closes string `json:"closes,omitempty"`
	// Uses names the argument carrying a handle this tool works on — a call
	// keeps the handle alive (it is not idle).
	Uses string `json:"uses,omitempty"`
}

// ExtractSpec is one field featured out of a text result (D289).
type ExtractSpec struct {
	Field   string `json:"field"`
	Pattern string `json:"pattern"`

	// Line anchors the match to one line (1-based) of the tool's text — a
	// vendor-authored position. Required when the tool's UserContent is set.
	Line int `json:"line,omitempty"`
}

// Provider resolves credential references to material.
//
// Reference format: "provider://path/version", e.g.
//
//	env://JIRA_ACME_TOKEN
//	gcp-sm://projects/p/secrets/jira-acme/versions/7
//	vault://secret/data/jira/acme?version=3
//
// THE VERSION IS PART OF THE REFERENCE, and part of Target.PoolKey — which is
// what makes credential rotation actually invalidate pooled clients rather than
// leaving a revoked credential working until TTL expiry (§4.3.2).
type Provider interface {
	Scheme() string

	// Resolve fetches credential material.
	//
	// Callers cache with the version in the key and JITTERED expiry. Without
	// jitter, N replicas with synchronised TTLs stampede the secret manager on
	// every rotation, and secret managers have per-project read quotas.
	Resolve(ctx context.Context, ref string) (Resolution, error)
}

// Rotation is what can happen to a credential's bytes without a redeploy
// (D104).
type Rotation string

const (
	// RotationLive is a volume the platform updates in place.
	RotationLive Rotation = "live"

	// RotationOnChange is a source an edit reaches at the next resolution.
	RotationOnChange Rotation = "on-change"

	// RotationNone is a source that cannot change in place. **The dangerous
	// one**: rotation looks configured and never happens, so it is REPORTED
	// rather than documented.
	RotationNone Rotation = "NONE"
)

// Posture is the set of facts about a credential that boot reports and D104
// stamps on a decision.
//
// IN pkg/config BESIDE Provider, because D111 makes posture part of the provider
// contract — a provider declares facts, configuration declares the bar, and boot
// checks the intersection. The `require:` set that does the checking is P1 steps
// 36-37; the facts are needed NOW for D104's boot report, and defining them here
// is what stops the report inventing a second vocabulary the requirement set
// would then have to translate.
// WHO FILLS WHAT, because the struct has two authors and confusing them would
// put a provider in charge of a fact it cannot know:
//
//   - Rotation, Why, AtRest and AuditedReads are the PROVIDER's. They describe
//     the source and are the same for every resolution through it.
//   - Scheme and Version are the RESOLUTION's, filled by the cache. A provider
//     does not know which scheme string routed to it, and the version is what
//     that particular resolution produced — under a tracking reference it
//     changes while everything else stays put.
type Posture struct {
	Rotation Rotation

	// Why is the operator-readable reason INCLUDING the remedy. Carried rather
	// than derived at the call site: the reason a mount cannot rotate is the
	// only part anybody can act on, and a report that says "NONE" without it
	// tells an operator they have a problem and not what to do.
	Why string

	// AtRest says WHERE THE BYTES LIVE — secret-manager, k8s-secret,
	// static-file, platform. This is the column that kills the SOPS
	// misconception without anyone needing to know it in advance (D103).
	//
	// **NOT NAMED `Material`, ON D119'S EXPLICIT RULING**, and this field carried
	// that name until the record it feeds was written. D119: "Material itself is
	// never a field, and never becomes one. The record carries metadata ABOUT a
	// credential; `at_rest` names where the bytes live, never the bytes. An
	// earlier draft called that field `material`, which read as though the
	// material might be in there — renamed, because a field name is the only
	// documentation most readers get."
	//
	// D104 and §4.7.9 predate that ruling and still show `material=` in their
	// example output. One concept must not have two names across a log line and
	// a decision record, so the rename is applied everywhere and the older text
	// is annotated rather than left to be copied.
	AtRest string

	// Scheme is where material came from: "file", "env", "ambient", "gcp-sm".
	// Filled by the cache, which is what dispatched on it.
	Scheme string

	// Version is what the provider reported RESOLVING TO (D130) — not what
	// configuration asked for. Under a tracking reference config says
	// `versions/latest` forever while this moves, and it is what keeps "what was
	// in use at 14:03" answerable from Sekizui's own records.
	//
	// Empty where the provider cannot say, which for a content-addressed source
	// is the honest answer rather than a gap.
	Version string

	// Versioning is whether this REFERENCE names an identity for the material —
	// a version number in the path, or content that is itself the identity.
	//
	// **THE PROPERTY THAT ACTUALLY DERIVES D97** (D153). §4.7.2's table records
	// `env://` as versioned "no" and `file://` as "by content", and D97's first
	// argument is the absence of a version: "An environment variable has no
	// version, so rotation needs a new revision." Requiring this off a developer
	// machine refuses `env://` and permits every `file://`, including a `subPath`
	// mount — whose content is still an identity even though it will never
	// change, which is what keeps D104's warn-not-refuse intact.
	//
	// Per REFERENCE, not per provider: `gcp-sm://…/versions/7` names a version
	// and `…/versions/latest` does not, and D99 makes both legitimate.
	Versioning Versioning

	// AuditedReads is whether the SOURCE records who read this credential and
	// when — the property a secret manager has and a mounted file does not.
	//
	// A PROVIDER FACT, which is why it lives here rather than being inferred
	// from the scheme at the call site. D111 turns facts like this into a
	// requirement set a deployment can state a bar against (`require:
	// [audited_reads]`), and inferring it from a scheme name would put the rule
	// in the reader instead of in the provider — where a third-party provider
	// (D35) could not participate at all.
	AuditedReads bool
}

// Versioning is a THREE-STATE answer, and the third state is why (D75, D153).
//
// A bool would conflate "this source has no version" with "versions do not apply
// here", and those want opposite treatment. §4.7.2's table records `env://` as
// versioned **"no"** and `ambient://` as **"n/a; the platform rotates"** — so a
// bool requiring `versioned` off a developer machine would refuse `ambient://`,
// which is the configuration §4.7.8 recommends ABOVE every other. Getting the
// strongest posture refused by the rule meant to enforce good posture is the
// kind of inversion an over-general derivation produces, which is D153's whole
// subject.
//
// It is the same distinction D75 draws between *refuted* and *cannot confirm*,
// and D102's tiers draw for ambient validation. The third state appears here and
// not on AuditedReads or RotatableLive because it does not arise for those: every
// source either records its reads or does not, and either rotates in place or
// does not.
type Versioning uint8

const (
	// Unversioned means the source offers no identity for its material. An
	// environment variable: rotation requires a new revision and nothing can
	// tell you whether what you hold is current.
	Unversioned Versioning = iota

	// VersionedByReference means the reference names an identity — a version in
	// the path, or content that IS the identity (§4.7.2's "by content").
	VersionedByReference

	// VersioningNotApplicable means the platform mints credentials per use, so
	// there is no version to pin and nothing staleness could mean. Workload
	// identity. SATISFIES a `versioned` requirement rather than failing it,
	// because the concern the requirement encodes — being handed material you
	// cannot identify or check — does not arise.
	VersioningNotApplicable
)

func (v Versioning) String() string {
	switch v {
	case VersionedByReference:
		return "versioned"
	case VersioningNotApplicable:
		return "n/a"
	default:
		return "unversioned"
	}
}

// RotatableLive reports whether rotation takes effect with no redeploy.
//
// DERIVED, NOT STORED. §4.7.12 sketched it as a field beside the others; two
// fields answering one question eventually disagree, and D104's three-way answer
// is strictly richer than a bool — `on-change` and `NONE` are both "not live"
// and want different things said about them (D153).
func (p Posture) RotatableLive() bool { return p.Rotation == RotationLive }

// CredentialProperty is one thing a deployment may require of a credential
// source (D111).
//
// A NAMED VOCABULARY RATHER THAN FREE TEXT, because a requirement nobody
// implements must be refused at boot and not silently satisfied. A typo in
// `require: [audited_read]` that parsed and did nothing would be this codebase's
// most persistent defect, in the one place where the consequence is a
// compliance bar an operator believes is in force.
type CredentialProperty string

const (
	// PropertyVersioned — the reference names an identity for the material.
	PropertyVersioned CredentialProperty = "versioned"

	// PropertyAuditedReads — the source records who read it and when.
	PropertyAuditedReads CredentialProperty = "audited_reads"

	// PropertyRotatableLive — rotation takes effect with no redeploy.
	//
	// AVAILABLE AND NOT DEFAULT (D153). A regulated deployment may reasonably
	// require it; making it the default off-bare would refuse every static file,
	// which D104 rules must only warn.
	PropertyRotatableLive CredentialProperty = "rotatable_live"
)

// CredentialProperties is the closed set, in one place so boot validation and
// the requirement check cannot disagree about what exists.
//
//nolint:gochecknoglobals // immutable table, read once
var CredentialProperties = []CredentialProperty{
	PropertyVersioned, PropertyAuditedReads, PropertyRotatableLive,
}

// Offers reports whether this posture provides a property.
//
// ONE MAPPING FROM NAME TO PREDICATE, so a property cannot mean one thing in the
// boot check and another in a report. An UNKNOWN property returns false, which
// is the fail-safe direction D111 asks for — but boot refuses an unknown name
// outright, so nothing should ever reach this with one.
func (p Posture) Offers(prop CredentialProperty) bool {
	switch prop {
	case PropertyVersioned:
		// NOT APPLICABLE SATISFIES IT. See Versioning: the requirement exists to
		// stop material nobody can identify, and a platform that mints per use
		// has removed the concern rather than failed to meet it.
		return p.Versioning != Unversioned
	case PropertyAuditedReads:
		return p.AuditedReads
	case PropertyRotatableLive:
		return p.RotatableLive()
	default:
		return false
	}
}

// CredentialPolicySpec is the deployment's bar (D111).
//
// AN EXPLICIT POLICY REPLACES THE DEFAULT ENTIRELY rather than adding to it.
// That is what makes the mechanism demonstrably general: stating `require: []`
// permits what the default refused, which is how acceptance step 37 proves the
// specific behaviour is driven by the rule rather than sitting beside it.
type CredentialPolicySpec struct {
	Require []string `json:"require,omitempty"`
}

// Postured is the OPTIONAL interface a provider implements when it can describe
// its own security posture (D104, D111).
//
// OPTIONAL AND TYPE-ASSERTED, following ChainedProvider's precedent
// (GO-PRIMER §2.2), for the reason D35 makes unavoidable: `Provider` is a
// published interface, and adding a required method breaks every out-of-tree
// implementation for people who do not read our commit log. A provider that
// cannot answer is reported as unknown, which is honest, rather than being
// assumed to rotate.
type Postured interface {
	Posture(ref string) (Posture, error)
}

// ChainedProvider is the OPTIONAL interface a provider implements when its
// reference embeds other references (D131).
//
// `oauth-cc://token.vendor.com/oauth/token?client_secret=gcp-sm://…` needs the
// inner `gcp-sm://` resolved before it can do anything. The obvious way to
// arrange that is to hand every provider a resolver — and that is the wrong
// way, because a provider that can resolve references can resolve ANY
// reference. Providers are third-party-implementable (D35), so that interface
// would hand every self-hoster's connector a capability to read every secret
// the broker can reach. It would also move the read below Sekizui's seam, where
// nothing audits it and caching, jitter, singleflight and rotation detection all
// have to be reimplemented per provider.
//
// So the CACHE resolves inner references first and passes the results in. A
// provider receives material it was handed and cannot reach for more, which is
// the difference between Sekizui mediating credential access and Sekizui being
// a library that providers call.
//
// DISCOVERED BY TYPE ASSERTION rather than declared, per GO-PRIMER §2.2 — a
// provider with no nested references says nothing and is unaffected. A reference
// that HAS nested references whose provider does NOT implement this is refused
// rather than resolved with the inner ref left as a literal string, which would
// send `gcp-sm://…` to a token endpoint as a password.
type ChainedProvider interface {
	Provider

	// Inner names the query parameters whose values are themselves references,
	// so the cache knows what to resolve without guessing. Returning nothing
	// means this reference has no chaining, which is normal.
	//
	// STATICALLY DECLARED, and that limit is deliberate (D131). A provider
	// cannot choose its inner reference based on a response: chaining is
	// resolved before the provider runs, so a dynamic chain is impossible by
	// construction rather than by rule. Reopening that would restore exactly
	// the arbitrary-resolution capability this design removes.
	Inner(ref string) ([]string, error)

	// ResolveChained is Resolve with the inner references already resolved,
	// keyed by the parameter names Inner returned.
	ResolveChained(ctx context.Context, ref string, inner map[string]Resolution) (Resolution, error)
}

// Confined is an OPTIONAL Provider method: whether a reference may be read AT
// ALL in this deployment, answered before anything is read (D286).
//
// **A CREDENTIAL REFERENCE IS A READ OF WHATEVER IT NAMES, SENT OFF-HOST.**
// `file://` read any path, and the material became the Authorization header of
// every call to the target's base_url — so one configuration line pointed at
// the audit log, another tenant's secret or `/proc/self/environ` exfiltrated it
// on every poll. A provider that reads something local says here which
// references it refuses; boot asks for every target's reference and every
// reference chained inside it, and the provider asks again on every Resolve,
// because a symlink can change after boot.
//
// Optional and type-asserted (GO-PRIMER §2.2): a provider that reads nothing
// local — a secret manager, the platform's identity — has nothing to confine.
type Confined interface {
	Confine(ref string) error
}

// Resolution is what a Provider returns (D130).
//
// A STRUCT RATHER THAN THREE RETURN VALUES, because this seam keeps growing.
// It began as (material, expiry, error); D111 added Posture to the interface
// beside it; D130 needed Version. Providers are implementable by third parties
// (D35), so every signature change is a breaking change for people who do not
// read our commit log — a struct means the next field is additive.
type Resolution struct {
	// Material is the credential bytes.
	Material []byte

	// Expiry is when the material stops being valid, or the ZERO TIME when it
	// has no intrinsic expiry.
	//
	// HONOURED, NOT ADVISORY, and saying so here because it was not. The cache
	// discarded this and applied its own TTL, which is harmless for a static key
	// and wrong for anything minted: a sixty-second access token cached for five
	// minutes spends four of them failing, and an hour-long one gets re-minted
	// twelve times more often than it needs to be, against an endpoint that may
	// meter issuance. Zero means "you decide"; non-zero means "not after this".
	Expiry time.Time

	// Version is the IDENTITY of the credential resolved — not a digest of the
	// bytes, and not necessarily unique per resolution.
	//
	// THE DISTINCTION IS THE WHOLE POINT (D130). It answers "is this the same
	// credential as last time", which is what invalidates a pooled client, and
	// it must NOT change merely because the bytes did. An OAuth provider
	// refreshing an access token returns new material under the SAME version,
	// because the credential — the client secret behind it — did not rotate.
	// Reporting the token would tear down every pooled client, and for a
	// session-oriented target (§4.7.4 class 3) re-initialise an MCP session, on
	// a timer, for nothing.
	//
	// Empty is allowed and means "I cannot tell you". The cache then falls back
	// to digesting the material, which is D123's original mechanism — correct
	// for a static secret, and the reason this field exists is that it is wrong
	// for a refreshable one.
	//
	// For a tracking reference this is where `versions/latest` reports the
	// version it ACTUALLY resolved to, which a reference string cannot say.
	Version string
}

// TargetSpec is the declarative form of one external instance.
type TargetSpec struct {
	Ref     string `json:"ref"`
	Kind    string `json:"kind"`
	BaseURL string `json:"base_url,omitempty"`

	// Tagged "credential" to match §4.7's documented YAML. The Go field is named
	// CredentialRef because the REF is the whole point — configuration never
	// carries material — and the name should say so at every call site.
	CredentialRef string `json:"credential,omitempty"`

	// "eu", "us". Enforced at resolve time against the instance region — a
	// conflict REFUSES rather than warns (D29 item 2).
	Residency string `json:"residency,omitempty"`

	// Limits are this target's operational bounds — quota, retry, breaker.
	//
	// ON THE TARGET, NOT ON A FLAG, and that is the point (D142). These are the
	// knobs an operator reaches for during an incident: an upstream is angry and
	// the backoff needs lengthening, or a target is flapping and its breaker
	// should trip sooner. A flag means a redeploy to change them, which is the
	// same objection §4.7.10 raises about break-glass — a control you can only
	// use by shipping is not a control you can use when it matters.
	//
	// Jira's tolerance is not BigQuery's, so the knob belongs beside the target
	// rather than beside the process. The DEPLOYMENT still sets a ceiling a
	// target may only narrow (D108's shape), because "how hard may anything here
	// retry" is written once by whoever is accountable for the blast radius and
	// "how hard should THIS target be retried" is written per target by whoever
	// needs it — D71's asymmetry, on a third knob.
	Limits *TargetLimits `json:"limits,omitempty"`

	Tenant   string            `json:"tenant,omitempty"`
	Settings map[string]string `json:"settings,omitempty"`
}

// GrantSpec is what one principal may do.
type GrantSpec struct {
	Principal string `json:"principal"`

	Allow    []CapabilitySpec `json:"allow,omitempty"`
	Escalate []CapabilitySpec `json:"escalate,omitempty"`

	// Subject patterns this principal may CONSUME from the bus (D92).
	//
	// A SEPARATE LIST FROM allow/escalate, because a subscription is not an
	// action on a target. `allow` is action × target × constraints; a
	// subscription is a standing read of a subject pattern, with no target and
	// no arguments. Forcing it into CapabilitySpec would mean overloading
	// `target` to hold a bus subject, and target_ref means something specific —
	// a resolvable external system (CONTRACTS §3.1).
	//
	// DENY BY DEFAULT like everything else: a principal with no `subscribe` may
	// consume nothing. NATS-style patterns, matching what JetStream will
	// interpret at P7 — "sekizui.enriched.>" matches one or more trailing
	// tokens, "*" exactly one.
	//
	// **EACH ENTRY IS A SUBJECT AND A TARGET (D259)**, as each `allow` entry is
	// an action and a target. Until D259 a grant was a subject pattern alone,
	// and D60 keeps the target out of the subject, so the bus could not express
	// "only customer X's events" while the command plane had always required
	// exactly that. `allow` is action × target; `subscribe` is subject × target.
	Subscribe []SubscriptionSpec `json:"subscribe,omitempty"`

	// Principals this one may act on behalf of (§4.4.1).
	//
	// MUST BE ENUMERATED, NOT WILDCARDED. "agent:*" recreates the confused-deputy
	// problem the delegation model exists to solve: anything reaching Sekizui as
	// the mesh could then claim to be any agent. Document.Validate rejects a
	// wildcard rather than warning about it.
	MaySpeakFor []string `json:"may_speak_for,omitempty"`
}

// Predicate is a reflex's `where`: conditions ANDed together (D263).
type Predicate []Condition

// Condition is one test on one payload field.
//
// `path` is dotted into nested objects, the same syntax `carry` and D42's
// field-path check use. `op` is one of PredicateOps. `value`'s shape depends on
// the op, and boot refuses a mismatch rather than letting it evaluate to false
// at runtime — a rule that silently stops matching is D42's named failure.
type Condition struct {
	Path  string `json:"path"`
	Op    string `json:"op"`
	Value any    `json:"value,omitempty"`
}

// MaxMCPListPages is the hard bound on `tools/list` pagination — the MCP
// driver's, read from HERE so config validation and the driver cannot disagree
// (D311). A server whose list does not end within it is refused, not trusted.
const MaxMCPListPages = 50

// The operators a Condition may use. A CLOSED SET, and the set is the language
// (D263): adding one is a code change and a review, never a config trick.
const (
	OpEq     = "eq"
	OpIn     = "in"
	OpExists = "exists"
	OpGt     = "gt"
	OpGte    = "gte"
	OpLt     = "lt"
	OpLte    = "lte"

	// OpPrefix holds when a string field starts with the value (D300) — a
	// page's URL under `/checkout`, a mobile screen name under `CarGo1.`.
	// SHARED, so a bus rule has it too. No regex and no negation: a prefix is
	// the most a closed vocabulary needs to say "which page" (D263).
	OpPrefix = "prefix"
)

// PredicateOps lists the operators, for boot messages and the evaluator.
func PredicateOps() []string {
	return []string{OpEq, OpIn, OpExists, OpGt, OpGte, OpLt, OpLte, OpPrefix}
}

// UnmarshalJSON refuses the pre-D263 form by name: a Rego string, which parsed
// and did nothing for two phases (D262).
func (p *Predicate) UnmarshalJSON(raw []byte) error {
	var rego string
	if json.Unmarshal(raw, &rego) == nil {
		return fmt.Errorf("where %q is a Rego string; since D263 Sekizui takes no Rego and "+
			"`where` is a list of {path, op, value} conditions, all of which must hold — "+
			"e.g. [{path: clicks, op: gt, value: 5}]. Operators: %v", rego, PredicateOps())
	}
	type plain []Condition // no methods, so no recursion (GO-PRIMER §15al)
	var c plain
	if err := strictJSON(raw, &c); err != nil { // strict past this boundary too (D278)
		return err
	}
	*p = Predicate(c)
	return nil
}

// JobsSpec is the deployment's settings for caller-triggered jobs.
type JobsSpec struct {
	// ResultsTTLSec is how long a finished job's results wait for their caller
	// before they are dropped (D267, D268). Zero means the default, ten
	// minutes; the ceiling is MaxResultsTTLSec.
	//
	// The maintainer: "10 minutes may be too short for some." A deployment setting, not a
	// per-job request, so the memory it commits is decided in reviewed
	// configuration rather than by whoever calls StartJob.
	ResultsTTLSec uint32 `json:"results_ttl_s,omitempty"`
}

// DefaultResultsTTLSec is ten minutes (D267).
const DefaultResultsTTLSec = 600

// MaxResultsTTLSec is one day (D268). A result held longer than that is
// STORAGE, and the maintainer's line on the plane is that Sekizui "shouldn't just become
// yet another data repository" (D247) — the memory committed is the TTL times
// the job rate times each job's max_bytes, so the ceiling is what keeps a typo
// from becoming an outage.
const MaxResultsTTLSec = 86400

// ResultsTTL is the configured value, or the default.
func (j JobsSpec) ResultsTTL() time.Duration {
	if j.ResultsTTLSec == 0 {
		return DefaultResultsTTLSec * time.Second
	}
	return time.Duration(j.ResultsTTLSec) * time.Second
}

// SourceSpec is one scheduled poll: a target, how often, and how much (D249,
// D266).
//
// **A RECURRING JOB, NOT A SECOND SUBSYSTEM (D249).** It becomes a
// `kyuushin.Job` with `Every` set, admitted on every tick through the same gate
// a caller's `StartJob` takes. Its caller is CONFIGURATION, so it runs as the
// principal `source:<target>` (D250) — which therefore needs a grant for
// `<kind>.poll` on the target like any other principal, and can be suspended
// with `revoke_grant` like any other principal.
//
// UNIT-SUFFIXED INTEGERS, as `limits` writes them (`max_lifetime_s`), rather
// than a duration string: a decoded `time.Duration` is nanoseconds, and
// `every: 30` meaning thirty nanoseconds is a poll loop nobody asked for.
type SourceSpec struct {
	TargetRef string `json:"target"`
	EverySec  uint32 `json:"every_s"`

	// Limit is how many events one poll may ask for — the memory budget of a
	// poll rather than a hint (D243).
	Limit uint32 `json:"limit"`
}

// Principal is the identity a schedule runs as (D250). One definition, so the
// grant boot validation looks for and the identity the gate admits cannot
// spell it differently.
func (s SourceSpec) Principal() string { return SourcePrincipal(s.TargetRef) }

// SourcePrincipal names the principal a scheduled poll of ref runs as.
func SourcePrincipal(ref string) string { return "source:" + ref }

// SubscriptionSpec is one standing read: a subject pattern, from one target
// (D92, D259).
//
// **THE TARGET IS MATCHED EXACTLY, AND THERE IS NO WILDCARD**, because
// `CapabilitySpec.TargetRef` has none: the command plane matches a target by
// equality (`policy.GrantEngine.matches`), and a bus broader than the command
// plane can express is the mismatch this type exists to remove. A consumer of
// fifty orgs writes fifty entries, as `allow` already makes it.
//
// Checked per envelope against `Envelope.source` — the target ref that produced
// it — and decided once, at establishment (D93). An envelope from a target the
// grant does not name is withheld from that consumer, never delivered.
type SubscriptionSpec struct {
	Subject   string `json:"subject"`
	TargetRef string `json:"target"`
}

// UnmarshalJSON refuses the pre-D259 form by name.
//
// A bare string used to be a whole grant. Left to the decoder it fails as
// "cannot unmarshal string into Go struct field", which names the Go type and
// not the fix — so an operator upgrading is told what the entry must now say.
func (s *SubscriptionSpec) UnmarshalJSON(raw []byte) error {
	var bare string
	if json.Unmarshal(raw, &bare) == nil {
		return fmt.Errorf("subscribe entry %q is a bare subject; since D259 every entry names "+
			"a subject AND a target, as an allow entry names an action and a target — "+
			"write {subject: %q, target: <ref>}, one entry per target the principal may "+
			"consume from", bare, bare)
	}
	type plain SubscriptionSpec // no methods, so no recursion
	var p plain
	if err := strictJSON(raw, &p); err != nil { // strict past this boundary too (D278)
		return err
	}
	*s = SubscriptionSpec(p)
	return nil
}

// TargetResidencyFacet is the reserved `where:` key naming the residency of the
// TARGET a capability acts on (D136).
//
// DEFINED HERE BECAUSE IT IS CONFIG-FILE VOCABULARY. The enforcement rule lives
// in internal/policy, but the word an operator types lives in this document, and
// two packages spelling the same key independently is how a boot check ends up
// validating a constraint the engine never reads. Validation and evaluation
// share this constant.
//
// TWO AXES, TWO WORDS. `residency:` on a shin lens is the DATA's class (D84);
// `target_residency:` in a grant's `where:` is the TARGET's. They coincide while
// data drawn from a target carries that target's class, and P2's data classes
// are exactly where they stop coinciding — so the vocabulary keeps them apart
// now rather than after something depends on the conflation.
const TargetResidencyFacet = "target_residency"

// reservedWhereKeys is the closed set of `where:` keys Sekizui answers itself.
//
//nolint:gochecknoglobals // immutable table, read once
var reservedWhereKeys = map[string]bool{
	TargetResidencyFacet: true,
}

// IsReservedWhereKey reports whether a `where:` key is answered from
// configuration rather than from the caller's arguments.
//
// THE PREDICATE EVERY CONSUMER USES, so that adding a facet is one edit. Three
// places have to agree about this set — the engine skips reserved keys when
// matching arguments, boot validation checks them against the target instead of
// the request, and the catalog must not advertise them as arguments an agent can
// send. A fourth will exist eventually. Each deciding for itself with its own
// `== "target_residency"` is how the catalog ends up advertising a facet the
// engine ignores, which is the defect this set was extracted to prevent.
func IsReservedWhereKey(key string) bool { return reservedWhereKeys[key] }

// ReservedWhereKeys returns the set, for tests that must assert a property holds
// for EVERY reserved key rather than for the one somebody remembered.
//
// A hand-written list in a test rots the moment a facet is added, and it rots
// silently — the test still passes, having checked nothing about the new key.
func ReservedWhereKeys() []string {
	out := make([]string, 0, len(reservedWhereKeys))
	for k := range reservedWhereKeys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ConstraintSatisfied is the `where:` matching rule: a list means membership, a
// scalar means equality.
//
// ONE IMPLEMENTATION, SHARED BY VALIDATION AND EVALUATION. Boot validation
// refuses a residency constraint that can never match (D136), and the engine
// decides at runtime whether one does — two questions whose answers must agree
// exactly. Written twice they would drift, and the drift would be silent in the
// worst direction: a constraint boot calls unsatisfiable while the engine
// satisfies it, or the reverse.
//
// COMPARED AS STRINGS because config arrives through JSON, where every number is
// a float64 — so a YAML `1` and a wire `1` would otherwise fail to compare equal
// despite being the same value.
func ConstraintSatisfied(want, got any) bool {
	if list, ok := want.([]any); ok {
		for _, item := range list {
			if fmt.Sprint(item) == fmt.Sprint(got) {
				return true
			}
		}
		return false
	}
	return fmt.Sprint(want) == fmt.Sprint(got)
}

// TargetLimits bounds one target's outbound behaviour.
//
// PLAIN INTEGERS WITH UNIT-SUFFIXED NAMES, matching CapabilitySpec's existing
// `rate_per_hr` and the divergence already recorded in CONTRACTS §4 item 12.
// §4.7 writes `rate: 10/hr` and there is no parser for it yet; inventing one
// here would make this the only block in the file with human-friendly units.
//
// A POINTER ON TargetSpec, so "absent" and "all zeroes" are distinguishable. A
// zero value means "use the deployment default", and a target that genuinely
// wants no retries says `retry_attempts: 1` rather than being unable to say it.
type TargetLimits struct {
	// RatePerHr is the SHARED quota for this target, across every principal.
	// Zero means unlimited — §4.3.4 keys the shared budget on the target
	// because Jira Cloud meters per instance, not per caller.
	RatePerHr uint32 `json:"rate_per_hr,omitempty"`

	// Burst is how much of that rate may be spent at once. Zero derives a
	// modest burst from the rate rather than disabling bursting, because a
	// bucket with no burst admits one call per refill interval and makes any
	// concurrency look like a rate-limit failure.
	Burst uint32 `json:"burst,omitempty"`

	// Budget names the SHARED quota this target draws on (D208).
	//
	// **THE HINGE OF THE WHOLE MECHANISM, AND IT IS A NAME RATHER THAN A TARGET
	// REF ON PURPOSE.** §4.3.4 keys the shared budget on the target because a
	// vendor meters per instance — which is right until two targets front ONE
	// instance, and D52 makes that permanent: Fullstory's MCP surface and its
	// native API are two targets and, as far as anyone can tell, one quota. Keyed
	// on target ref, each carries an independent bucket while consuming one
	// upstream allowance, so Sekizui under-counts by construction and discovers
	// the real limit as 429s.
	//
	// **A NAME IS ALSO WHAT P7 CAN AGREE ABOUT.** A shared budget is a thing
	// several TARGETS draw on; a fleet-shared budget is a thing several REPLICAS
	// draw on, and cross-instance agreement needs something to agree about. A
	// target ref cannot serve — it names one target in one process. So the name
	// is the unit here and stays the unit there, which is what makes the
	// one-instance case the degenerate form of the many-instance one rather than
	// a different mechanism (D209).
	//
	// **ABSENT MEANS AN IMPLICIT BUDGET NAMED AFTER THIS TARGET**, so every
	// deployment written before D208 keeps exactly the behaviour it had and
	// nothing migrates.
	//
	// **SHARING IS THE DEFAULT FOR TARGETS FRONTING ONE UPSTREAM, and the two
	// mistakes are not symmetric (D208).** We do not know whether a vendor meters
	// its API and its MCP surface against one quota or two. Assuming SEPARATE
	// when they are shared exceeds a limit we were told, on the vendor's terms,
	// with 429s arriving for everyone; assuming SHARED when they are separate
	// leaves headroom unused. One is an incident, the other is a number in a
	// config file — so an operator claiming two surfaces are metered separately
	// says so HERE, where it is reviewed, rather than on a flag (D142's rule).
	Budget string `json:"budget,omitempty"`

	// Share is this target's explicit portion of its budget, in percent (D210).
	//
	// **ZERO MEANS EQUAL PARTS, which is an ENTITLEMENT UNDER CONTENTION rather
	// than a cap.** The maintainer's ruling — *"equal parts, so if MCP and API is enabled
	// that is 50% of budget for each unless defined explicitly"* — read as a hard
	// cap would contradict D143, which rejects fixed equal shares because "a
	// control that throttles an idle fleet is a control an operator switches
	// off": a hard 50% on the API while the MCP surface is idle throttles against
	// nothing. So the split is what is ENFORCED below the reserve, and above it
	// anyone proceeds.
	Share uint32 `json:"share,omitempty"`

	// RetryAttempts includes the first call, so 1 disables retrying. Zero means
	// "use the deployment default" — which is why a target that genuinely wants
	// no retries must say 1 and cannot say 0.
	RetryAttempts uint32 `json:"retry_attempts,omitempty"`

	// RetryCapMs bounds a SINGLE backoff wait, including one derived from an
	// upstream `Retry-After` (D140). Zero means the deployment default.
	RetryCapMs uint32 `json:"retry_cap_ms,omitempty"`

	// ReestablishAttempts includes the first call, so 1 disables re-establishing
	// (D203). Zero means "use the deployment default".
	//
	// **THE NEIGHBOUR IS THE SPECIFICATION.** This copies RetryAttempts' escape
	// from the zero-means-unlimited trap deliberately rather than by resemblance:
	// a target that genuinely wants no re-establishment must be able to SAY so,
	// and with zero meaning "off" it could not also mean "inherit". Saying 1
	// switches the whole mechanism off for this target, which is the block an
	// operator asked for and the reason no separate boolean exists.
	//
	// **THERE IS NO LEGITIMATE VALUE ABOVE 2.** If a freshly minted credential is
	// also rejected, minting a third returns the same thing — so a higher number
	// buys nothing and costs a call on somebody's system plus a mint against the
	// secret manager. Refused at boot rather than clamped, for Exceeded's reason.
	ReestablishAttempts uint32 `json:"reestablish_attempts,omitempty"`

	// BreakerTrip is the consecutive-failure count that withdraws from this
	// target. Zero means the deployment default.
	BreakerTrip uint32 `json:"breaker_trip,omitempty"`

	// MaxLifetimeS bounds how long a pooled client may live, whatever else
	// happens (D108). Zero means the deployment default.
	//
	// **A DIFFERENT KIND OF GUARANTEE FROM THE REST OF §6.** Most of this design
	// makes a failure impossible by construction; this one makes a failure
	// BOUNDED IN TIME regardless of construction. Content-addressing (D99)
	// creates a new pool entry on rotation and does not remove the old one, and
	// explicit invalidation closes that — but explicit invalidation is code we
	// wrote and could get wrong. A lifetime is the bound that does not depend on
	// our own correctness.
	//
	// SHORTER IS NARROWER, so this is an ordinary ceiling: a target may only
	// LOWER it. Unlike breaker_cooldown_s, there is no inversion here — a
	// shorter lifetime holds a credential for less time, which is unambiguously
	// gentler on the blast radius.
	MaxLifetimeS uint32 `json:"max_lifetime_s,omitempty"`

	// BreakerCooldownS is how long the breaker stays open before admitting one
	// probe. Zero means the deployment default.
	//
	// THE ONE FIELD WHOSE BOUND IS A FLOOR RATHER THAN A CEILING — see
	// OperationalBounds.
	BreakerCooldownS uint32 `json:"breaker_cooldown_s,omitempty"`

	// HandleIdleS is how long a stateful handle (D291) may go unused before
	// Sekizui closes it. Zero means the deployment's `-handle-idle`; a target
	// may only LOWER it — a shorter idle releases a vendor's slot sooner.
	HandleIdleS uint32 `json:"handle_idle_s,omitempty"`
}

// OperationalBounds is how hard ANYTHING in this deployment may push an
// upstream, set by flags and narrowable per target (D142, D108's shape).
//
// D71'S ASYMMETRY ON A THIRD KNOB. How hard anything here may retry is written
// once by whoever is accountable for the blast radius; how hard THIS target
// should be retried is written per target by whoever needs it. Jira's tolerance
// is not BigQuery's, so the value belongs beside the target — and a control an
// operator can only use by shipping a new binary is not a control they can use
// while an upstream is angry, which is §4.7.10's objection to break-glass
// applied to the knobs beside it.
//
// **"NARROW" MEANS LESS LOAD ON THE UPSTREAM, NOT A SMALLER NUMBER**, and that
// is the whole subtlety of this type. Three of the four fields narrow DOWNWARD
// and one narrows UPWARD:
//
//   - MaxLifetime — a shorter lifetime holds a credential for less time. Only
//     LOWER.
//   - RetryAttempts — fewer attempts is gentler. A target may only LOWER it.
//   - ReestablishAttempts — one fewer forced mint is gentler on the secret
//     manager AND on the target. A target may only LOWER it.
//   - RetryCap — a shorter maximum wait holds less in flight. Only LOWER.
//   - BreakerTrip — tripping after fewer failures withdraws sooner. Only LOWER.
//   - BreakerCooldown — a LONGER cooldown probes a dead target less often, so
//     it is gentler. A target may only RAISE it. **This bound is a FLOOR.**
//
// Getting that inversion wrong is silent in exactly the direction that matters:
// a target permitted to shorten its cooldown probes a dead upstream harder than
// the deployment allows, and every individual check still reads as "within the
// limit". So the rule is stated as one sentence — a target may only be LESS
// aggressive than the deployment permits — and each field derives from it.
type OperationalBounds struct {
	// MaxLifetime bounds how long any pooled client in this deployment may live
	// (D108). A target may only narrow it.
	MaxLifetime time.Duration

	RetryAttempts int
	RetryCap      time.Duration
	BreakerTrip   int

	// ReestablishAttempts is the deployment ceiling on D203's second attempt.
	//
	// **ITS OWN CEILING IS 2 AND THAT IS NOT CONFIGURABLE**, which is why
	// Exceeded checks this field against a constant as well as against the
	// deployment. Everything else here is a judgement about blast radius that an
	// operator is entitled to make; "a third mint returns what the second one
	// did" is a fact about credential managers, and a flag that let somebody
	// disagree with it would only ever be used by mistake.
	ReestablishAttempts int

	BreakerCooldown time.Duration

	// BudgetFloorPct is the fraction of a configured budget an instance falls
	// back to once its capacity allocator has been unreachable for k refreshes
	// (D210).
	//
	// **A SECURITY DIAL RATHER THAN AN AVAILABILITY CONVENIENCE, and it is on
	// the DEPLOYMENT rather than the target for D142's reason inverted.**
	// Operational limits belong on the target with the flag as a ceiling,
	// because a target knows its own vendor. This is not about a vendor: it is
	// about what this fleet does when it cannot be told how large it is, which
	// is a property of the deployment's topology and therefore belongs in the
	// manifest an operator reviews.
	//
	// Fleet GROWTH during an outage is the exposure — shrinkage is safe, since
	// every share ends up too small — so the floor is what bounds
	// `partition + autoscale`, and the same number bounds the phantom-instance
	// dilution attack where unauthenticated claimants shrink every real share.
	BudgetFloorPct int64

	// HandleIdle is the deployment's ceiling on how long a stateful handle may
	// go unused before Sekizui closes it (D291, `-handle-idle`). A target may
	// only lower it.
	HandleIdle time.Duration

	// MeterCeilings is the most any target may budget per hour, keyed by the
	// connector's meter UNIT (D284, `-meter-ceiling unit=N`). Keyed by unit
	// rather than by connector because the vocabulary is open (D171): the
	// deployment layer stays arithmetic in whatever unit a connector names. A
	// target asking for more is refused at boot; a DEFAULT above it is lowered.
	// A unit with no entry has no ceiling.
	MeterCeilings map[string]uint32

	// MeterDefaultCalls is the universal default budget, in CALLS per hour, for
	// a target whose connector declares no default and which declares none
	// itself (D284, `-meter-default-calls`). Calls only: a universal number
	// means something in exactly one unit.
	MeterDefaultCalls uint32
}

// MaxReestablishAttempts is the hard ceiling on D203's second attempt.
//
// TWO: the original call, plus one more after re-minting. See
// OperationalBounds.ReestablishAttempts for why this is a constant rather than a
// flag.
const MaxReestablishAttempts = 2

// Exceeded names the ways one target's limits are MORE aggressive than the
// deployment permits, in operator-readable form. Empty means it conforms.
//
// REFUSED AT BOOT RATHER THAN CLAMPED, which is D108's ruling on max_lifetime
// and the house answer everywhere else: a target quietly given less than it
// asked for is a target whose operator believes something false, and the belief
// survives until an incident tests it. Absent limits conform trivially.
func (b OperationalBounds) Exceeded(l *TargetLimits) []string {
	if l == nil {
		return nil
	}

	var out []string
	if b.RetryAttempts > 0 && l.RetryAttempts > uint32(b.RetryAttempts) {
		out = append(out, fmt.Sprintf(
			"retry_attempts %d exceeds the deployment ceiling of %d (-retry-attempts)",
			l.RetryAttempts, b.RetryAttempts))
	}
	if l.ReestablishAttempts > MaxReestablishAttempts {
		out = append(out, fmt.Sprintf(
			"reestablish_attempts %d exceeds the hard ceiling of %d: the second attempt "+
				"exists because a cached credential can go stale, and if a FRESHLY minted "+
				"one is also rejected then minting a third returns the same bytes — so a "+
				"higher number buys nothing and spends a call on the target plus a mint "+
				"against the secret manager. Use 1 to switch re-establishment off (D203)",
			l.ReestablishAttempts, MaxReestablishAttempts))
	}
	if b.ReestablishAttempts > 0 && l.ReestablishAttempts > uint32(b.ReestablishAttempts) {
		out = append(out, fmt.Sprintf(
			"reestablish_attempts %d exceeds the deployment ceiling of %d "+
				"(-reestablish-attempts)",
			l.ReestablishAttempts, b.ReestablishAttempts))
	}
	if b.RetryCap > 0 && time.Duration(l.RetryCapMs)*time.Millisecond > b.RetryCap {
		out = append(out, fmt.Sprintf(
			"retry_cap_ms %d exceeds the deployment ceiling of %d (-retry-cap)",
			l.RetryCapMs, b.RetryCap.Milliseconds()))
	}
	if b.BreakerTrip > 0 && l.BreakerTrip > uint32(b.BreakerTrip) {
		out = append(out, fmt.Sprintf(
			"breaker_trip %d exceeds the deployment ceiling of %d (-breaker-trip): "+
				"a higher trip tolerates more failures before withdrawing, which is "+
				"MORE load on a target that is already failing",
			l.BreakerTrip, b.BreakerTrip))
	}
	if b.MaxLifetime > 0 && time.Duration(l.MaxLifetimeS)*time.Second > b.MaxLifetime {
		out = append(out, fmt.Sprintf(
			"max_lifetime_s %d exceeds the deployment ceiling of %d (-pool-max-lifetime): "+
				"a longer lifetime holds a credential — and for a session-oriented target "+
				"a live authorised session — for longer after it should have gone",
			l.MaxLifetimeS, int(b.MaxLifetime.Seconds())))
	}
	if b.HandleIdle > 0 && time.Duration(l.HandleIdleS)*time.Second > b.HandleIdle {
		out = append(out, fmt.Sprintf(
			"handle_idle_s %d exceeds the deployment ceiling of %d (-handle-idle): a longer idle "+
				"holds a vendor's session slot longer after its caller stopped using it (D291)",
			l.HandleIdleS, int(b.HandleIdle.Seconds())))
	}
	// THE INVERTED ONE. Lower is more aggressive here, so the bound is a floor.
	if b.BreakerCooldown > 0 && l.BreakerCooldownS > 0 &&
		time.Duration(l.BreakerCooldownS)*time.Second < b.BreakerCooldown {
		out = append(out, fmt.Sprintf(
			"breaker_cooldown_s %d is BELOW the deployment floor of %d "+
				"(-breaker-cooldown): a shorter cooldown probes a dead target more "+
				"often, so this is the one bound a target raises rather than lowers",
			l.BreakerCooldownS, int(b.BreakerCooldown.Seconds())))
	}
	return out
}

// ExceedingTargets names every target refusing the deployment's bounds, keyed by
// ref, for one boot error naming all of them.
//
// SEPARATE FROM Document.Validate FOR D136'S REASON: Validate cannot see the
// deployment's flags, and a check that silently skipped when it could not see
// them would be worse than one that lives elsewhere and is called explicitly.
func ExceedingTargets(d *Document, b OperationalBounds) map[string][]string {
	var out map[string][]string
	for _, t := range d.Targets {
		if bad := b.Exceeded(t.Limits); len(bad) > 0 {
			if out == nil {
				out = map[string][]string{}
			}
			out[t.Ref] = bad
		}
	}
	return out
}

type CapabilitySpec struct {
	Action string `json:"action,omitempty"`

	// Preset names a `presets:` entry instead of an action (D327). The loader
	// expands it into one capability per action and clears it, so nothing past
	// the loader ever sees a preset.
	Preset string `json:"preset,omitempty"`

	// Origin is set on the capabilities of a list that held a preset: the
	// position as written, and the preset expanded. Not serialised.
	Origin *CapabilityOrigin `json:"-"`

	// Tagged "target" to match §4.7's YAML.
	TargetRef string `json:"target,omitempty"`

	// Where narrows a capability. Keys are matched against the command's
	// ARGUMENTS, with one reserved exception: TargetResidencyFacet is answered
	// from the target's declared class and never from the request, which is what
	// stops a command satisfying its own residency constraint.
	Where map[string]any `json:"where,omitempty"`

	// PLAIN INTEGERS, not the human-friendly forms §4.7 shows.
	//
	// That section writes `rate: 10/hr` and `max_bytes: 1GB`, which need a
	// parser these fields do not have yet. Limits are not enforced until P1, so
	// P0 accepts `rate_per_hr: 10` and `max_bytes: 1073741824` instead.
	// Recorded in CONTRACTS §4 rather than left as a silent divergence between
	// the documented format and the parsed one.
	RatePerHr uint32 `json:"rate_per_hr,omitempty"`
	MaxBytes  uint64 `json:"max_bytes,omitempty"`
}

// ReflexSpec is one deterministic event->action rule (§4.11).
type ReflexSpec struct {
	Name string `json:"name"`

	// The principal this reflex acts as. A reflex is a principal, not a bypass
	// (D18) — it needs its own grant, and its command traverses the identical
	// enforcement path.
	Principal string `json:"principal"`

	Enabled bool `json:"enabled"`

	// "shadow" evaluates and records WOULD_HAVE_FIRED without acting.
	// "enforce" acts. Every reflex should run shadow first (§4.11.4 item 3).
	Mode string `json:"mode,omitempty"`

	// Subject pattern consumed, e.g. "sekizui.raw.fullstory.>".
	Consumes string `json:"consumes,omitempty"`

	// Expected payload type INCLUDING VERSION, e.g. "fullstory.rage_click.v1".
	//
	// Boot validation checks the schema is registered AND that every field path
	// the predicate references exists in it (D42). Without this, a schema change
	// makes the rule silently stop matching — no error, nothing in the logs, and
	// the first symptom is a business process that stopped weeks ago.
	ExpectsType string `json:"expects_type,omitempty"`

	// Where narrows which matching envelopes fire the rule: conditions over the
	// PAYLOAD, all of which must hold, evaluated after the structural pre-filter
	// on (stage, type) has already narrowed the candidates (§4.5.2, D58).
	//
	// **DECLARATIVE, NOT A LANGUAGE (D263).** This was a Rego string that
	// nothing evaluated (D262). It is a closed set of operators whose paths are
	// checked against the registered payload schema at boot, so it REQUIRES
	// `expects_type` — a predicate over a shape nobody declared cannot be checked.
	Where Predicate `json:"where,omitempty"`

	// Debounce: of the envelopes whose payload shares one DebounceKey value,
	// only the first in each DebounceWindowSec fires the rule (D264). Both or
	// neither; the key is a payload path checked against the schema (D42).
	//
	// **SECONDS, AND THE FIELD WAS RENAMED FOR IT.** It was `debounce_window`,
	// a `time.Duration` — so `debounce_window: 60` meant sixty NANOSECONDS, a
	// debounce that suppresses nothing. Nothing had ever read it (D262), so the
	// rename broke nobody; `every_s` and `limits` already write units this way.
	DebounceKey       string `json:"debounce_key,omitempty"`
	DebounceWindowSec uint32 `json:"debounce_window_s,omitempty"`

	// Hard stop plus alert, distinct from rate limiting: rate limiting smooths,
	// a budget says "if this fires 50 times in an hour something is wrong"
	// (§4.11.4 item 4). Counted over the trailing hour, PER REPLICA (D264).
	//
	// **REQUIRED TO ARM A RULE (D264).** `mode: enforce` without it refuses the
	// boot — two deliberate acts, as anzen's reactive form (D157). The firing
	// past it is refused, recorded as VERDICT_BUDGET_EXCEEDED, and raises the
	// `budget_exceeded` signal.
	MaxFiringsPerHour uint32 `json:"max_firings_per_hour,omitempty"`

	// Budget names a `reflex_budgets:` entry this rule ALSO spends (D334). A
	// firing needs room in both its own budget and the shared one.
	Budget string `json:"budget,omitempty"`

	// Exactly ONE action (D31). Multiple actions are multiple rules — avoiding
	// partial-failure semantics inside one rule, where there is no good answer
	// for what the rule's outcome was.
	Action    string         `json:"action,omitempty"`
	TargetRef string         `json:"target,omitempty"`
	With      map[string]any `json:"with,omitempty"`

	// Projects makes this a PROJECTION rule (D248, D269): it shapes a compact
	// view of an envelope — `carry` and `with`, narrowed by `where` — into
	// `Envelope.projection` for a consumer that asked, at delivery, AFTER shin.
	//
	// **IT ACTS AS NOBODY.** No principal, no action, no target, no publish_to,
	// no mode, budget or debounce: it dispatches nothing and publishes nothing,
	// which is exactly what makes it the half of the engine that may run on the
	// synchronous path (D248 — enrichment may, actuation may not). Boot refuses
	// any of those fields on it, and the engine's dispatching half never sees it.
	Projects bool `json:"projects,omitempty"`

	// Set instead of Action/TargetRef for a bus->bus enrichment reflex (§4.11.6).
	// Must name a strictly later stage than Consumes (D21).
	PublishTo string `json:"publish_to,omitempty"`

	// PublishesType is the payload type this rule EMITS, including version —
	// "fullstory.friction_detected.v1" (D41, D88).
	//
	// REQUIRED WITH publish_to, and it was originally DERIVED from the bus
	// subject's last segment. That derivation produced "friction_detected": no
	// version, no registered schema, and therefore outside both D41 and D42 —
	// while the comment above the code that did it claimed "Type is versioned per
	// D41". A published type nobody declared is a payload shape that entered the
	// system without review, which is the hole D46 closes for MCP tools.
	//
	// Stating it explicitly also lets boot check the harder property: that every
	// field the rule CARRIES exists in the output schema as well as the input
	// one. A carried field the output schema does not declare is a field every
	// downstream lens and rule will silently fail to find.
	PublishesType string `json:"publishes_type,omitempty"`

	// Carry names the source payload fields this rule propagates (D63).
	//
	// EXPLICIT, NOT MERGE. Copying the whole source payload forward is
	// ergonomic and wrong at scale: the payload grows every hop with nothing
	// bounding it (§4.6.2 exists BECAUSE token budget matters), provenance
	// blurs because you cannot tell which fields came from where, and the
	// enriched schema stays coupled to the source's so a change ripples through
	// every descendant (D42).
	//
	// Naming the fields fixes all three at once, and the declaration IS the
	// provenance record — no separate change log to maintain or read.
	//
	// ["*"] carries everything, for the case where an author genuinely wants
	// that. It is a CHOICE rather than a default, which is the whole point.
	//
	// EMPTY CARRIES NOTHING. A rule that forgets it emits only its `with`
	// fields, which consumers notice immediately — loud and safe, where a
	// silent full copy is quiet and unbounded.
	Carry []string `json:"carry,omitempty"`

	// AcknowledgesLLMInput is required when Consumes names a stage carrying
	// agent output (D64).
	//
	// Not a safety mechanism — it changes no behaviour. It exists because
	// NOTHING currently distinguishes a reflex fed by a vendor webhook from one
	// fed by an LLM, and the second can be steered by a prompt injection into
	// pulling a trigger the reflex's grant permits. Admins write these rules
	// deliberately; they deserve to be told which ones sit downstream of a model.
	AcknowledgesLLMInput bool `json:"acknowledges_llm_input,omitempty"`
}

// AnzenSpec is one defensive rule — 安全, "safety" (D65).
//
// THE DISTINCTION FROM A REFLEX IS THE ACTION VOCABULARY, and it is structural
// rather than conventional. A reflex may call a driver and therefore reach a
// customer system. An anzen rule may only act on SEKIZUI ITSELF: quarantine a
// target, disable a reflex, revoke a grant, raise an alert. There is no anzen
// action that performs an external side effect, which is what makes the class
// safe to trigger from signals a reflex could not be trusted with.
//
// WHY THE CLASS EXISTS. P0 surfaced that nothing distinguishes a reflex fed by a
// vendor webhook from one fed by an LLM's output, and the second can be steered
// by a prompt injection into pulling whatever trigger its grant permits. The
// answer is not to forbid the risky reflex — operators legitimately want agent
// output to drive follow-up — but to have a layer watching for it misbehaving.
// A body does not stop reacting because a reaction might be wrong; it has an
// immune response for when one is.
type AnzenSpec struct {
	Name string `json:"name"`

	Enabled bool `json:"enabled"`

	// Mode is shadow|enforce, as for reflexes. Shadow is the default, because a
	// defensive rule that fires wrongly disables working automation.
	Mode string `json:"mode,omitempty"`

	// Watches names the internal signal: "budget_exceeded", "spec_drift",
	// "tenant_mismatch", "denial_storm", "audit_unavailable", "source_*" (D280)
	// — the closed set is validate.go's anzenSignals.
	//
	// SEKIZUI'S OWN SIGNALS, not bus subjects. An anzen rule does not consume
	// business events — that is a reflex. It watches the governance layer's
	// health, which is exactly the data nothing else is positioned to act on.
	//
	// NOT NAMED `on`. YAML 1.1 — which sigs.k8s.io/yaml speaks via yaml.v2 —
	// treats `on`, `off`, `yes`, and `no` as BOOLEANS, including as map KEYS. So
	// `on: spec_drift` parses to the key `true` with the value `true`, binds to
	// nothing, and the field silently stays empty. Worse, `on` and `yes` both
	// become `true`, so they overwrite each other without a word. See
	// CONTRACTS §4 item 16.
	Watches string `json:"watches,omitempty"`

	// Where narrows the signal, e.g. {"target": "fullstory:o-EXAMPLE"}.
	Where map[string]any `json:"where,omitempty"`

	// Do is the protective action: "quarantine_target", "disable_reflex",
	// "revoke_grant", "alert".
	//
	// A CLOSED VOCABULARY, validated at boot. Anzen rules are the one place in
	// Sekizui where an open action set would be actively dangerous: the class is
	// trusted precisely because its reach is bounded by construction, and an
	// arbitrary action would dissolve that in one config line.
	Do string `json:"do,omitempty"`

	// Subject is what Do applies to — a target ref, a reflex name, a principal.
	Subject string `json:"subject,omitempty"`

	// --- preventive form (D71) ------------------------------------------------
	//
	// An anzen rule is EITHER reactive (watches + do) or preventive (forbids /
	// max_concurrent), never both — the same one-thing-per-rule shape as D31.
	//
	// The two are complementary, and an immune system has both: barriers that
	// stop things happening, and responses to things that did. The reactive form
	// answers "a reflex has started misbehaving"; the preventive form answers
	// "no reflex should ever be able to do this in the first place".

	// Forbids is a CEILING that grants cannot exceed.
	//
	// Checked BEFORE policy, so a forbidden action is refused even where a grant
	// permits it. That ordering is the whole point: grants are written per
	// principal by whoever needs the capability, and a blocklist is written once
	// by whoever is accountable for the blast radius. If policy ran first, a
	// broad grant would win and the guard would be advisory.
	//
	// Supports the same trailing-star prefix as grants: "kata.delete_*".
	Forbids []string `json:"forbids,omitempty"`

	// MaxConcurrent caps simultaneous in-flight actions for the principals this
	// guard applies to.
	//
	// Distinct from a rate limit (§4.3.4), which smooths throughput over time.
	// This bounds BLAST RADIUS AT AN INSTANT: a reflex that suddenly matches a
	// thousand events should not have a thousand commands in flight, whatever
	// its hourly quota allows.
	MaxConcurrent uint32 `json:"max_concurrent,omitempty"`

	// AppliesTo names the principals a preventive guard covers. Empty means
	// EVERY principal — which is the right default for a blocklist, since a
	// destructive action nobody should perform is not a per-principal question.
	//
	// Supports the trailing-star prefix, so "reflex:*" covers every reflex —
	// the case §4.11.7 cares about, where a rule downstream of a model needs a
	// tighter ceiling than a human-driven agent.
	AppliesTo []string `json:"applies_to,omitempty"`

	// TargetResidency scopes a PREVENTIVE rule to the classes of the targets it
	// governs — the second axis beside AppliesTo, which scopes by principal
	// (D137).
	//
	// WHY IT EXISTS. A deployment serving `de,fr,jp` may be subject to a control
	// in one jurisdiction that does not apply in another, and today the only way
	// to express that is three deployments. That is the textbook answer and it is
	// unavailable to the case this was asked for: one instance, several classes.
	//
	// STRICTLY ADDITIVE, AND THIS IS THE LOAD-BEARING RULE. An EMPTY value means
	// the rule applies to every target, INCLUDING unclassified ones. A non-empty
	// value means the rule applies to those classes IN ADDITION to whatever the
	// unscoped rules already forbid — it can only ever add refusals, never remove
	// one. Composition is therefore monotone: adding a scoped rule cannot widen
	// anything, so no rule can be routed around by choosing a target in another
	// class.
	//
	// The asymmetry with AppliesTo is what forced that. A principal axis has no
	// equivalent of "unclassified": every request has a principal, so a scoped
	// rule always has a well-defined subject. A target may declare NO residency,
	// and if a scoped rule could be the only rule, an undeclared target would
	// escape the safety control entirely — fail-open, the opposite direction from
	// everything else here.
	//
	// PREVENTIVE ONLY. A reactive rule (`watches`/`do`/`subject`) already names
	// ONE target, so its residency is fixed by that target and a constraint here
	// could only agree or contradict. Boot refuses it rather than accepting a
	// field that can never mean anything.
	//
	// `target_residency`, not `residency`: this is the TARGET's class. A shin
	// lens's `residency:` is the DATA's (D84). See TargetResidencyFacet.
	TargetResidency []string `json:"target_residency,omitempty"`
}

// ShinSpec is one lens: what a consumer receives, as distinct from what it may
// do (D83).
//
// STRICTLY REDUCING. A lens may remove fields and cap size. It may never add a
// field, rename one, compute one, or reorder anything — reflexes do the compute
// (D63), and keeping the two apart is what makes a lens safe to apply
// automatically. Because every lens operation only ever removes, no lens change
// can cause a consumer to receive something it was not already receiving. That
// property is why anzen may tighten a lens as a defensive action (D85) without
// widening anzen's reach beyond "cannot touch a customer system".
//
// TWO MODES, COMPOSING BY INTERSECTION (D84). An `imposed` lens is a ceiling an
// operator sets and a consumer cannot opt out of. A `requestable` lens is one a
// consumer may select for itself. The effective lens is the intersection, so a
// request can only ever narrow further — the same shape as anzen over grants
// (D71) and caller ∩ subject (D59).
type ShinSpec struct {
	Name string `json:"name"`

	Enabled bool `json:"enabled"`

	// Mode is imposed|requestable.
	//
	// EMPTY MEANS IMPOSED, which inverts the default used everywhere else in this
	// file. Elsewhere the safe default is the passive one (shadow, disabled);
	// here the safe default is the RESTRICTIVE one, because a lens that silently
	// became optional would widen what a consumer receives — and widening is the
	// one thing a lens must never do.
	Mode string `json:"mode,omitempty"`

	// AppliesTo names the consuming principals. Supports the trailing-star
	// prefix, so "agent:*" covers every agent.
	//
	// EMPTY MEANS EVERY PRINCIPAL for an imposed lens, matching AnzenSpec.
	// AppliesTo — a ceiling nobody should exceed is not a per-principal question.
	// A requestable lens with no AppliesTo is refused at boot: "anyone may select
	// this" is almost never what someone meant to write.
	AppliesTo []string `json:"applies_to,omitempty"`

	// Type is the payload type this lens applies to, INCLUDING VERSION —
	// "fullstory.rage_click.v1" (D41).
	//
	// Empty means every type, which is only meaningful together with Withholds:
	// "this consumer never receives user.email, whatever the payload" is a
	// coherent jurisdiction rule, while "this consumer receives only session_id,
	// whatever the payload" is not.
	Type string `json:"type,omitempty"`

	// Fields is an ALLOW-LIST of dotted field paths — "session_id", "user.id".
	// Empty means every field survives, subject to Withholds.
	//
	// Every path is checked against the registered schema at boot (D42). A lens
	// naming a field no schema has is the identical silent failure as a reflex
	// predicate referencing one: no error, nothing in the logs, and a consumer
	// quietly receiving less than someone believes it does.
	Fields []string `json:"fields,omitempty"`

	// Withholds is a DENY-LIST, applied after Fields and winning over it.
	//
	// Both exist because they answer different questions. Fields is "what does
	// this consumer need" — an ergonomics judgement that changes as a consumer
	// evolves. Withholds is "what must this consumer never receive" — a
	// compliance judgement that must survive somebody widening Fields. A single
	// list would make the second a special case of the first, and the first is
	// edited far more often.
	Withholds []string `json:"withholds,omitempty"`

	// MaxBytes caps the serialised payload. Zero means uncapped.
	//
	// SHAPE, NOT RATE. This bounds what one message contains; how MANY arrive is
	// a rate limit (§4.3.4). Blurring them produces a control that does neither
	// job well.
	MaxBytes int `json:"max_bytes,omitempty"`

	// Residency restricts this lens to consumers in a given classification,
	// which is how a jurisdiction lens is expressed.
	//
	// Residency already decides whether a target RESOLVES (§7.1 item 2). This
	// applies the same axis one layer further out, to what crosses the boundary
	// rather than what may be reached — data in motion rather than data at rest.
	Residency string `json:"residency,omitempty"`

	// Because is the rationale, and it is REQUIRED.
	//
	// Same rule as anzen: a lens that silently drops a field is indistinguishable
	// from a bug six months later, and "why does analytics never see user.email"
	// must be answerable from the config rather than from whoever wrote it.
	Because string `json:"because,omitempty"`
}

// GetGrants returns the grants, tolerating a nil Document.
//
// Named for the protobuf getter convention the rest of the codebase reads
// against, and present for the same reason those exist: wiring code holds a
// document that may not have loaded yet, and `for range doc.Grants` on a nil
// pointer panics where `doc.GetGrants()` yields nothing.
func (d *Document) GetGrants() []GrantSpec {
	if d == nil {
		return nil
	}
	return d.Grants
}

// GetTargets returns the target specs, tolerating a nil Document.
func (d *Document) GetTargets() []TargetSpec {
	if d == nil {
		return nil
	}
	return d.Targets
}

// IssuerSpec pins one identity broker (D303, D318). Sekizui never handles a
// login or a redirect: the caller obtains a token from this broker and
// presents it in metadata (`sekizui-subject-token`), beside the mTLS
// certificate that still proves the caller.
type IssuerSpec struct {
	// Issuer is the token's exact `iss`.
	Issuer string `json:"issuer"`

	// Audience is what `aud` must name — THIS Sekizui — so a token minted for
	// another service cannot be replayed here.
	Audience string `json:"audience"`

	// Keys is the broker's JWKS, through the `file://` provider under its
	// credential root (D286): a mounted Secret, no fetch on the request path.
	Keys string `json:"keys"`

	// Algorithms is the allowlist: a subset of RS256, ES256, EdDSA.
	Algorithms []string `json:"algorithms"`

	// Callers are the mTLS principals that may present this issuer's tokens —
	// ENUMERATED, no wildcards, may_speak_for's rule (§4.4.1).
	Callers []string `json:"callers"`

	// RoleClaim names the claim carrying the role; default "role". The role
	// `architect` selects the grants of principal `role:architect`.
	RoleClaim string `json:"role_claim,omitempty"`

	// RequireBound, default true: a token must be bound to the connection's
	// certificate (RFC 8705). False is a visible relaxation, and every record
	// it admits says `unbound`.
	RequireBound *bool `json:"require_bound,omitempty"`

	// LeewaySec absorbs clock skew on `exp` and `nbf`; default 60, at most 300.
	LeewaySec uint32 `json:"leeway_s,omitempty"`
}

// RolePrefix names the principal a token's role selects (D318).
const RolePrefix = "role:"

// DefaultIssuerLeewaySec and MaxIssuerLeewaySec bound clock skew (D318).
const (
	DefaultIssuerLeewaySec = 60
	MaxIssuerLeewaySec     = 300
)

// Bound reports whether the issuer requires certificate binding (default yes).
func (i IssuerSpec) Bound() bool { return i.RequireBound == nil || *i.RequireBound }

// Leeway is the configured clock skew, or the default.
func (i IssuerSpec) Leeway() time.Duration {
	if i.LeewaySec == 0 {
		return DefaultIssuerLeewaySec * time.Second
	}
	return time.Duration(i.LeewaySec) * time.Second
}

// ReflexBudgetSpec is one firing budget several reflex rules share (D334).
//
// ON THE WALL CLOCK AND PER REPLICA, D264's terms: it bounds real actions per
// real hour on this instance, and the fleet-wide bound is P7's.
type ReflexBudgetSpec struct {
	Name              string `json:"name"`
	MaxFiringsPerHour uint32 `json:"max_firings_per_hour"`
}
