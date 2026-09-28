# Sekizui (脊髄)

**The spinal cord for your agentic infrastructure.** One governed pathway between every AI agent
and every system it acts on — so agents never hold credentials, every action is decided and
recorded, and deterministic automation runs without a model in the loop.

**Status: v1.** All six phases through P5 are complete and signed off; P4 and P5 together are **v1**
(D294, D339). See [Status and roadmap](#status-and-roadmap). Licensed under the [MIT License](LICENSE).

---

## Why Sekizui exists

Connecting agents to systems is an **N × M** problem. Ten agents that need five systems means fifty
integrations, each with its own credentials, its own audit gap, its own rate limits and its own
subtly different error handling. Sekizui makes it **N + M**: agents talk to Sekizui, and Sekizui
talks to systems.

That collapse is worth having, but it is not the reason to build this. Three problems are:

1. **A credential in an agent's context is a credential in an attacker's reach.** An agent holding
   a Jira token is one prompt injection away from being an attacker holding a Jira token. With
   Sekizui, agents hold *capability references* and Sekizui holds the secrets. A compromised agent
   can do exactly what it was granted — a set you write, review and revoke — and nothing more.
2. **"What did this agent do to production this week?" is usually unanswerable.** Sekizui answers it
   from one hash-chained audit log that records *decisions*, not just actions: refusals, the rule
   that matched, who asked on whose behalf, and what it cost.
3. **Governance, not capability, is what blocks agent deployment.** Deny-by-default grants,
   ceilings no grant can exceed, per-target budgets and a provable kill switch make an agent
   deployment something a reviewer can approve.

The honest cost, stated up front: centralising credentials makes Sekizui the highest-value target
in the system. The trade is that one small, hardened surface is more defensible than secrets spread
across a fleet of prompt-injectable agents.

**Sekizui brings governance and trust back to the front, in an age that has been moving them to the
back.** Agents are being given real systems to act on faster than anyone is deciding what they may
do there, and "we will add controls later" is how every serious incident starts. Sekizui is the
opposite bet: that a deployment can be ambitious *because* every action is decided, bounded,
recorded and revocable. A better future can be built with Sekizui — by any industry, and by anyone.

---

## What it is

A **policy enforcement point and credential broker** between an agent fleet and the systems it acts
on, built as a **platform**: a vendor-neutral core that enforces, records and bounds, and connectors —
one folder each — that teach it a system. Agents, meshes, reflexes and people are all *principals*;
none is a bypass, and there is exactly one path an action can take.

What it does, in short:

- **Enforces every action on one path.** Identity (mutual TLS, SPIFFE identities) → ceilings →
  policy → budget → target resolution → driver → audit. There is exactly one enforcement path,
  and Sekizui's own automation takes it too.
- **Brokers credentials.** Secrets come from a mounted file under a declared root (how secret
  managers and Kubernetes deliver them), from the platform's workload identity, or from OAuth — and
  Sekizui refuses to start rather than hold a production credential it cannot rotate or audit.
- **Closes the door on data, not only on actions.** Every connector declares, field by field, what
  it may return; anything undeclared is removed before a consumer, a rule or the audit log sees it.
  A connector whose declaration is unsound is quarantined at startup, not run.
- **Prices every call before it is sent.** Each connector declares a meter in its own unit; every
  call and every scheduled poll is priced at its worst case against the target's budget and the
  deployment's ceiling.
- **Puts MCP servers behind a vetted contract.** A vendor's tool list is pinned under version
  control and compared with what the server actually serves. Unvetted tools are unreachable,
  arguments nobody vetted are refused, results that break their declared shape are refused, and
  sensitive values — a signed screenshot URL, say — reach only the caller who asked.
- **Brings events in, durably.** Pollers on a schedule turn what external systems return into
  versioned envelopes on a governed stream. The cursor survives `kill -9`: a restart re-delivers at
  most one event, and a source that cannot be re-read records a possible loss by name.
- **Runs reflexes.** Deterministic event-to-action rules, with a declarative `where` checked
  against the schema at boot, firing budgets, and shadow mode as the default — no model in the
  loop, nothing to prompt-inject.
- **Watches itself (anzen).** Defensive rules whose vocabulary can only touch Sekizui itself:
  quarantine an integration, disable a misfiring rule, revoke a grant, raise an alarm.
- **Shapes output per consumer (shin).** Lenses that can only ever remove: *"analytics never
  receives email addresses"* is one line, enforced on the way out and checked before delivery.
  A lens never narrows the audit log.
- **Stops a compromised credential mid-flight.** Break-glass refuses new work, cancels calls already
  in flight, tears down pooled clients, and records how many calls it killed.

---

## How it works

```
  agents, meshes, people                                external systems
  (hold certificates,                                   (Fullstory, Jira, MCP servers, …)
   never secrets)                                              ▲          │
        │ mTLS gRPC                                    commands │          │ polls
        ▼                                                       │          ▼
  ENSHIN — the command plane                                    │   KYUUSHIN — the event plane
  identity → anzen → policy → meter → resolver → driver ────────┘   source → cursor → shape →
        ▲                                                           translate → bus → shin →
        │                                                           consumers
        └──── reflexes: deterministic rules on the bus, ◄───────────────┘
              taking the same enforcement path an agent does

  every decision, on either plane → a two-phase, hash-chained audit record
```

A spinal cord carries signals outward and inward, and executes *reflexes* without consulting the
brain. The names map onto the architecture: **enshin** (遠心, centrifugal) is the outbound command
path, **kyuushin** (求心, centripetal) the inbound event path, and a **reflex** is a rule that fires
with no model in the loop (D66).

### The words you will hit

Sekizui uses unusual vocabulary where English has no single word for the idea, so it carries its
own remedy: `sekizui -glossary` prints this table, a running instance serves it at
`/debugz/glossary`, and the table below is rendered from the same Go value (D220).

<!-- BEGIN:derived-glossary -->
| Term | Meaning |
|---|---|
| **Sekizui** (脊髄) | The spinal cord. The governed pathway every agent action travels |
| **Enshin** (遠心) | Centrifugal — outward. The command plane: caller → policy → driver → external system, and Sekizui's primary path |
| **Kyuushin** (求心) | Centripetal — inward. The event plane: sources → translate → bus → consumers. Built in P3: pollers, durable cursors, translation |
| **Anzen** (安全) | Safety. The ceilings no grant can exceed, plus the rules that watch Sekizui's own health. Policy answers "may you"; anzen answers "should anyone, ever" |
| **Shin** (真) | Truth. The lens deciding what a given consumer actually receives — not whether it may, but in what shape |
| **Konbini** (コンビニ) | Convenience store. Vendor knowledge and helpers stocked once, so every consumer inherits them rather than reimplementing them |
| **Kata** (型) | The reference DRIVER a connector author fills in: no upstream, and every seam a real one must exercise. The Go half of the connector blueprint, and what you find inside `hako` (D244) |
| **Hako** (箱) | The reference CONNECTOR: the blueprint, a complete governed skeleton, and the exercise that makes you build one. What most people should look at first |
| **Seiren** (精錬) | Refining ore into metal. The third tier: silver refined by a `refines:` rule, carried beside a result's rows as one typed message with the window it covers and what it could not build (D317) |
| **Reflex** | A deterministic event-to-action rule that fires without a model in the loop. It is a principal, enforced identically to an agent |
| **Principal** | Anything that can act: an agent, a mesh, a reflex, a person. All are bounded by grants; none is a bypass |
| **Grant** | What one principal may do: action x target x constraints. Deny by default, and a decision record names the grant that matched |
| **Target** | One specific external instance, with a tenant bound and a credential resolved. Named by callers, constructed only by the resolver |
| **Driver** | The Go type implementing connector.Driver: stateless, credential-free, one instance per process, shared across every tenant. The CODE half of a connector |
| **Connector** | The driver plus the governance that makes it safe to run: target specs and limits, grants, the shin lens, the anzen ceiling and the payload schemas. The deliverable an operator installs |
| **Stage** | Where an event sits in the pipeline: raw, enriched, triaged, judged. A rule may only publish to a later stage than it consumes |
| **Causation** | What triggered this — root, parent, depth, and producer. Distinct from the identity chain, which records who authorised it |
| **Shadow** | A rule that evaluates and records what it WOULD have done, without doing it. It is the default, so the dangerous option is never the easy one |
<!-- END:derived-glossary -->

Where English is already precise — *reflex*, *grant*, *driver*, *policy*, *audit* — English stays.
The Japanese is written without macrons, so it types on any keyboard and greps without surprises.

---

## Features

Every row names what proves it — acceptance steps you can run and decisions you can read. The table is
checked by P5 step 14: a row citing a step that does not exist or is not built fails the build, so this
list cannot claim what the tree does not do.

<!-- BEGIN:derived-features -->
| Feature | What it means | Proven by |
|---|---|---|
| **One enforcement path** | Identity, ceilings, policy, budget, resolution, driver, audit — for writes and reads alike, and Sekizui's own automation takes it too | P1 step 68 · D18 |
| **Credentials lent, never held** | Agents hold capability references; material is lent to a driver for one call and goes inert after | P1 step 53 · D127 |
| **Break-glass mid-flight** | Revoking a credential refuses new work, cancels calls in flight and records how many it killed | P1 step 9 · D106 |
| **Residency across data centres** | A deployment ceiling plus a grant layer; a cross-region resolve is refused before any credential moves | P4 steps 6–8 · D136 |
| **Closed data, per connector** | Every connector declares what it may return, field by field; anything undeclared never reaches a consumer, a rule or the log | P3 step 23 · D279 |
| **Priced before sent** | Every call and poll is priced at its worst case against the target's budget before it leaves | P3 steps 19–20 · D284 |
| **MCP behind a vetted contract** | Unvetted tools are unreachable, arguments and results are held to the vetted spec, and drift is recorded | P2 step 8 · P4 step 31 · D289 |
| **One capability, two doors** | A capability denied on a native connector cannot be obtained through its MCP server | P4 step 12 · D323 |
| **Durable inbound events** | Scheduled polls survive `kill -9` and re-deliver at most one event; an unrecoverable window is named | P3 steps 1–2 · D275 |
| **Reflexes, proven by replay** | Deterministic rules with no model in the loop; enforce fires exactly what shadow predicted over recorded traffic | P5 steps 1–2 · D298 |
| **Bounded automation** | Firing budgets, shared budgets, event-time debounce, serialised rules and a principal-wide cap | P5 steps 6–8 · D333 |
| **Anzen, the ceilings no grant exceeds** | Defensive rules that act only on Sekizui itself; an action a firing path does not implement is refused, never guessed | P4 step 33 · P5 step 5 · D331 |
| **Denial storms name their cause** | When one principal drains a shared budget, the signal names it — never the agents it crowded out | P5 step 9 · D143 |
| **Shin, lenses that only remove** | Per-consumer shaping: "analytics never receives email addresses" is one line, enforced on the way out | P0 step 15 · D84 |
| **Seiren, refined context** | Connector-shipped rules refine a result into a typed summary served beside the rows, per audience | P4 steps 18–20 · D317 |
| **Signed subjects** | A pinned issuer's token names the subject, bound to the caller's certificate, and may only narrow its role | P4 steps 26–30 · D318 |
| **An audit log you can hand over** | Two-phase, hash-chained decision records, shipped asynchronously and routed by residency | P4 steps 9–10 · D322 |
| **Presets that never widen** | Vendor-suggested roles a deployment reviews into its own config, held to the vendor's own levels | P5 steps 10–12 · D327 |
| **A contributor surface that cannot rot** | Every connector contract has a worked form in kata, hako and the demo, or a written exemption | P5 step 13 · D337 |
<!-- END:derived-features -->

---

## A platform first

Sekizui's core knows no vendor. It enforces, prices, records and bounds; everything it knows about a
particular system arrives through a **connector**, and every contract a connector implements is
published in `pkg/` with a conformance suite an out-of-tree author can run (D35). The reference driver,
`kata`, implements every optional contract; the reference connector, `hako`, packages it with the
governance that makes it safe to run; the generic MCP driver serves any vetted MCP server without a
line of vendor code. A new system is a new folder, not a fork.

That is the point of building it this way round. The value is not an integration with one product —
it is that **any** system, in any industry, can be put behind the same decided, recorded, revocable
path, by whoever operates it.

## Why Fullstory ships as a connector

Because a platform is only as convincing as what is built on it. Fullstory is the connector v1 ships
to **demonstrate how powerful a connector on Sekizui can be**, not because the platform is Fullstory's:

- **every documented Fullstory Server API operation**, derived from the vendor's own published
  contracts and checked against them on every live run;
- **Fullstory's MCP server, vetted in full** and held to what each tool mirrors on the native side;
- **two data centres**, with residency enforced before a credential moves;
- **seiren** that turns a session's raw events into the context an agent actually needs;
- **presets** that mirror Fullstory's own permission levels, checked against the snapshot.

It is the proof, and the pattern: the same shape serves the next system, whoever writes it.

---

## Getting started

### Prerequisites

- **Go 1.25** (see `go.mod`). The Makefile uses the `go` on your `PATH` (it asks `go env GOROOT`);
  set `GOROOT` explicitly to use another toolchain.
- Nothing else is installed globally. Every Go cache and tool binary lands inside the repository
  (`./.gocache`, `./bin`), and `make tools` installs the pinned `buf`, `golangci-lint` and protobuf
  plugins there.
- **No cloud account.** Everything below runs on a laptop.

### Build

```sh
make tools        # once: pinned codegen and lint tools into ./bin
make build        # go build ./...
make verify       # lint, vet, build, and every unit test under -race
```

The binaries are `cmd/sekizui` (the service), `cmd/sekizui-mcpspec` (drafts an MCP tool's schemas
from output your agent pipes to it — it never dials a server itself), `cmd/sekizui-tap` (a
development tap on the event stream), `cmd/sekizui-refsnap` (takes a connector's vendor API reference
snapshot — every documented operation and its contract, from the vendor's docs site) and
`cmd/sekizui-devcert` (local certificates).

### Run it

```sh
make dev-certs    # a local CA and mTLS identities in ./dev/certs
make run          # the gateway: mTLS gRPC on :8443, probes on :8080, the DEMO config (internal/acceptance/demo.d)
make demo         # in a second terminal: the full acceptance run, driven over the network
```

`make demo` drives the running instance exactly as an external agent would: every command crosses
a real TLS 1.3 handshake, client-certificate verification, policy, anzen, the resolver, a driver
and the audit log. `make demo-refusals` starts the real binary itself and watches it refuse — at
boot and on a request — as it should.

The binary has two modes: `-mode gateway` serves the command plane, and `-mode ingest` also polls
the configured `sources:`. `sekizui -h` lists every flag; the ones you meet first are `-config`,
`-wal` (the directory for the audit log and cursors), `-residency`, and the three `-tls-*` flags.

### Configure

A deployment is one YAML document, or a directory of them. A slice, with real field names:

```yaml
targets:
  - {ref: fs:main, kind: fullstory, tenant: acme, residency: eu,
     base_url: https://api.eu1.fullstory.com, credential: file:///run/secrets/fullstory,
     limits: {rate_per_hr: 600, burst: 10}}
  - {ref: jira:main, kind: jira, tenant: acme, residency: eu,
     base_url: https://acme.atlassian.net, credential: file:///run/secrets/jira}

grants:
  - principal: agent:triage
    allow:
      - {action: fullstory.session_events, target: fs:main}
  - principal: reflex:friction           # a reflex is a principal like any other
    subscribe:
      - {subject: "sekizui.raw.fullstory.>", target: fs:main}
    allow:
      - {action: jira.comment_issue, target: jira:main}
  - principal: source:fs:main            # the schedule polls as its own principal
    allow:
      - {action: fullstory.poll, target: fs:main}

shin:
  - name: triage-sees-no-email
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    type: fullstory.session_event.v1
    withholds: [event_properties.email]
    because: triage needs what happened, not who it happened to

sources:
  - {target: fs:main, every_s: 60, limit: 10}

reflexes:
  - name: note-navigations
    principal: reflex:friction
    enabled: true              # shadow by default: it records what it WOULD have done
    max_firings_per_hour: 100  # arming a rule requires a budget
    consumes: sekizui.raw.fullstory.>
    expects_type: fullstory.session_event.v1
    where:
      - {path: event_type, op: eq, value: navigate}
    action: jira.comment_issue
    target: jira:main
    with: {issue: OPS-42, body: "a watched session navigated"}
```

Every path in a lens or a `where` is checked against the connector's declared schema when the
service starts, and a configuration that would be unsafe is refused at boot rather than tolerated
at runtime. [`hako/reference/kata.yaml`](hako/reference/kata.yaml) is a complete, validated,
commented example; `internal/acceptance/acceptance.yaml` is the full one the acceptance run uses.

---

## How we know it works

Four commands, four questions — and there are four because three of them once passed while a
guarantee was broken.

| Command | The question | What it runs |
|---|---|---|
| `make verify` | **Does it work?** | buf lint, `go vet`, golangci-lint, build, `go test -race` |
| `make acceptance` | **Does each phase's commitment hold?** | Every phase's graduation run, cumulatively — runs never retire (D107) |
| `make demo` / `make demo-refusals` | **Can a human watch it happen?** | A running instance over real mTLS; the real binary refusing at boot and on a request |
| `make mutate` | **Would we notice if a guarantee broke?** | Breaks one real guarantee in the product at a time and checks that a step catches it |

`make ci` runs all of them.

**The acceptance run writes its own evidence.** `./out/acceptance.md` lists every step of every
phase and cites the audit-log lines each one produced, so a claim and the records behind it are
joined by the artefact, not by narration; a mis-cited or self-contradicting log fails the run even
when every assertion passed (D227). Nothing reaches a real vendor account unless someone types
`make acceptance-live` — possessing a key is a capability, not authorisation (D229).

**Mutation testing is the part most projects skip.** A guarantee that no test notices breaking is a
guarantee nothing proves, so every security guarantee ships with a mutation that breaks it, and
each mutation runs only the acceptance steps expected to catch it (D281). An unapplied mutation
fails rather than skips, so a guard refactored away cannot take its coverage claim with it.

---

## Status and roadmap

<!-- BEGIN:derived-status -->
- **P0 — Contracts and walking skeleton** — complete, signed off
- **P1 — Tenancy and credentials** — complete, signed off, 68 of 68 acceptance steps built
- **P2 — First connectors: Fullstory (MCP + API) and thin Jira** — complete, signed off, 46 of 46 acceptance steps built
- **P3 — Kyuushin, the inbound plane** — complete, signed off, 42 of 42 acceptance steps built
- **P4 — Fullstory, in full** — complete, signed off, 34 of 34 acceptance steps built
- **P5 — Reflexes** — complete, signed off, 14 of 14 acceptance steps built
- **P6 — Remaining connectors, catalog, panel** — in flight, 2 of 12 acceptance steps built
- `make mutate`: 206 mutations, 1 of them a recorded equivalent mutant. **How many are currently caught is a RUN RESULT, not a fact about the tree**, so it is not written down here — run `make ci` and read it
<!-- END:derived-status -->

Each phase answers one question, graduates on an acceptance run, and records an **invalidation
signal** — the observation that would mean its premise was wrong.

<!-- BEGIN:derived-phases -->
| Phase | Question it answers | Release |
|---|---|---|
| **P0** Contracts + skeleton | Does the enforcement path work end to end? | — |
| **P1** Tenancy hardening | Can tenants leak into each other? | — |
| **P2** First connectors (Fullstory MCP + API, thin Jira) | Does the abstraction survive a real API, and does D52 coexistence hold? | **Prototype** |
| **P3** Kyuushin — the inbound plane | Does the schema/bus/translation layer hold? | — |
| **P4** Fullstory, in full | Does multi-org / multi-DC / residency work? | — |
| **P5** Reflexes | Does deterministic automation work safely? | **v1** (with P4 — D294) |
| **P6** Remaining connectors + panel + catalog | Is it operable? | **v1.1** |
| **P7** Horizontal scale (any `Bus` driver — D180) | Does it scale horizontally? | **v1.2** |
| **P8** Egress sinks + ingest split | Does it integrate with the heavyweights? | **v2** |
<!-- END:derived-phases -->

**v1 is P4 and P5 together (D294, D339).** P4 brought every *documented* Fullstory Server API
operation, multi-org and multi-data-centre residency, and connector-shipped rules that refine session
context into a **seiren** (精錬) beside the rows; P5 finished the reflex engine, proved by replay that
`enforce` does exactly what shadow predicted, and made the contributor surface complete. **Next is
v1.1 (P6):** the remaining connectors, the catalog and the operator panel.

**What to know before depending on it today:**

- **One replica, and at-most-once delivery to subscribers** (D24, D30). The inbound side is
  durable; the stream to consumers is not yet — at-least-once delivery and horizontal scale arrive
  with a `Bus` driver in P7.
- **Residency is a deployment ceiling plus a grant layer** (D136): one instance can serve more than
  one class, and a crossing is refused before any credential moves.
- **Connectors today:** Fullstory (native API, and MCP session review), a thin Jira driver, a
  generic MCP driver behind vetted specs, and `kata`, the reference driver. More arrive in P6.
- **Using the Fullstory connector needs your own Fullstory API key** — see
  [Trying the Fullstory connector](#trying-the-fullstory-connector) below.

---

## Contributing

Sekizui is built to be extended by people who were not in the room when it was designed, and the
repository enforces as tests most of what a contributing guide usually asks for.

### Bringing a new system under governance

Start at **[hako/](hako/README.md)** — the reference connector — and
**[hako/BLUEPRINT.md](hako/BLUEPRINT.md)**, the step-by-step guide. The reference driver in the box,
`internal/connectors/kata`, implements every optional contract, and P5 step 13 keeps it that way: a new
contract fails the build until kata, hako and the demo carry it, and the few that deliberately are not
carried are listed with their reasons in `internal/acceptance/p5_complete_test.go`. A connector is done when it:

- declares an idempotency class and a meter for every action, and a closed data schema for
  everything it returns;
- maps its errors into the shared taxonomy in `pkg/fault`, and carries a span per outbound call;
- names the hosts it may dial, if it knows its vendor's;
- passes the mandatory `pkg/connector/conformance` suite;
- ships the governance that makes it safe to run: target limits, grants, lenses, ceilings.

`make hako` runs the exercise — a connector with its governance removed for you to rebuild — and
every failure names the blueprint step it belongs to.

### Working on the core

- **Decide in writing.** A design choice comes with the reasoning that forced it and the
  alternatives discarded — in the pull request and in the code's comments. Documentation changes
  in the same change as the code. (Labels such as `D344` in comments refer to the maintainers'
  design record.)
- **Declare the proof before the code.** A phase's acceptance steps are written first, each skipping
  loudly with the assertion it will make until it is built (D114).
- **Ship the mutation with the guarantee.** A new security guarantee comes with the entry in
  `scripts/mutate.py` that breaks it, scoped to the steps that should notice.
- **Break a new guard once, by hand, before trusting it.** Copy the file aside — never rely on
  `git checkout` in a tree with uncommitted work — break exactly what the guard claims to catch,
  watch it fail, read the message, and restore.
- **Run `make verify` and `make acceptance` before you push, and `make ci` when a guarantee
  changed.**

Obligations the build enforces rather than asks for:

| Obligation | Enforced by |
|---|---|
| Every exit criterion of a phase has an acceptance step | `TestP3CoversItsExitCriteria`, one per phase |
| A phase cannot be marked complete with an unbuilt step | `TestP3CompletionIsHonest` |
| Every driver runs the published conformance suite | `TestEveryDriverRunsTheConformanceSuite` |
| Every in-tree connector is one complete folder — README, schemas, suites, registration, fragments that load | `TestEveryConnectorFolderIsComplete`, P4 step 34 |
| Every credential provider runs its conformance suite | `TestEveryProviderRunsTheConformanceSuite` |
| A refusal is built by one constructor, so status and kind cannot disagree | `TestEveryRefusalUsesTheConstructor` |
| A durable write goes through one audited helper | `TestNoAdHocAtomicWrites` |
| An unused public export is registered with a reason, and the entry expires when it gains a caller | `TestNoUnregisteredOrphansInPublicAPI` |
| Every mutation's anchor still matches its code exactly once, and no mutation is left applied | `scripts/mutate.py --check-clean`, first thing in `make verify` |
| Design documents are read through one parser that fails rather than returning empty | `TestNoAdHocDocumentReads` |
| Readiness is withdrawn before the drain, not after | `TestReadinessIsWithdrawnBeforeTheDrain` |

---

## Repository layout

```
proto/sekizui/v1/     wire contracts: core, envelope, command, decision, service
pkg/                  public seams — what a third party implements
  connector/            Driver, Target, ActionSpec, Meter, and the conformance suite
  fault/                the shared error taxonomy
  config/ audit/ bus/   configuration, audit sinks, transport
  provider/             credential providers and their conformance suite
internal/             implementations — compiler-enforced private
  gateway/              THE enforcement path; there is exactly one (D18)
  policy/ anzen/        grants, and the ceilings no grant can exceed
  resolver/ pool/       target resolution, pooled clients, residency refusal
  auditwal/             two-phase decision records with a persisted hash chain
  shin/ catalog/        per-consumer lenses, and the capability catalog
  connectors/           one folder per connector: kata (reference), fullstory, jira (D316)
  driver/mcp/           the one MCP driver every MCP-only connector folder is served by
  kyuushin/ cursor/     the inbound plane: schedules, polls, recovery; durable cursors
  translate/ schemareg/ rows to envelopes; the connector-owned schema registry
  reflex/ predicate/    deterministic rules and their declarative `where`
  meter/ limiter/       connector-declared prices and the budgets they draw on
  mcpspec/              drafting MCP tool schemas from advertised or observed output
  acceptance/           the graduation runs, one per phase, and their evidence report
  archcheck/ docref/    structural guards, and the one parser they read documents through
hako/                 the reference CONNECTOR — blueprint, skeleton, exercise (D244)
cmd/                  sekizui, sekizui-mcpspec, sekizui-refsnap, sekizui-tap, sekizui-devcert
scripts/mutate.py     the mutation harness
```

`pkg/` is interfaces and `internal/` is implementations (D35). The Go module path is
`github.com/fullstorydev/sekizui`.

---

## Trying the Fullstory connector

The whole suite — `make verify`, `make acceptance`, `make demo` — runs offline, against fixtures and
in-process fakes, with no vendor account. To point the Fullstory connector at a real org you need
**your own Fullstory API key**:

1. In Fullstory, an admin creates an API key (see Fullstory's developer documentation at
   https://developer.fullstory.com/ for API keys and their permission levels). Give it the lowest
   level that covers the actions you grant.
2. Save it as a file outside version control — for example `dev/secrets/fullstory.key`, which is
   gitignored — and reference it from a target, with the directory declared as a credential root:

   ```yaml
   targets:
     - {ref: "fullstory:myorg", type: fullstory,
        base_url: https://api.fullstory.com, credential: file:///path/to/dev/secrets/fullstory.key}
   ```

   and run with `-file-credential-root /path/to/dev/secrets`. Sekizui refuses a `file://`
   credential outside a declared root.

**The live arms and the live demo reach an org you name.** `make live-config` writes
`dev/fullstory-live.yaml` (gitignored) — the key file, a user, one of that user's sessions as the API
names it, and the same session's browser address, each field saying where its value comes from; each
can be overridden by an environment variable (`SEKIZUI_LIVE_KEY`, `_UID`, `_SESSION`,
`_SESSION_URL`). Then:

- `make acceptance-live` runs the suite PLUS the arms that write to that org — an event appended to
  that session (append-only: it cannot be deleted) and a property upserted on that user. Nothing is
  discovered: the writes go only where the file points. **Asked for and not configured, it fails**,
  naming what is missing, rather than passing having reached nothing.
- `make run-live` and `make demo-live` (two terminals) show the native/MCP union against that org's
  real Fullstory MCP.

NA1 orgs only today: the acceptance deployment serves the `us` class. `make acceptance` never reaches
a vendor, with or without the file.

---

## Documentation

1. **[hako/BLUEPRINT.md](hako/BLUEPRINT.md)** — how to bring a new system under governance.
2. **[hako/README.md](hako/README.md)** — the reference connector, and the exercise.
3. Each connector's own README under `internal/connectors/`.

---

## License

[MIT](LICENSE) © 2026 Engineering at Fullstory.
