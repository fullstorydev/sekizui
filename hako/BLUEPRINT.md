# Connector blueprint

**How to bring a new system under governance, in the order you actually do it.**

This is the half of "done" that a connector checklist does not carry. Ours had thirty
checkboxes and **not one is about configuration** — so a driver can be stateless, tenant-asserting,
idempotency-classified and attribution-stamped, tick every box, and ship with no shin lens, no anzen
ceiling and grants nobody reviewed. The mechanism half is specified to the letter and the governance
half is left to whoever remembers. That is the recurring defect of this repository one level up:
present, correct, and reaching nobody.

**THIS IS A BUILD ORDER, NOT A CHECKLIST (D167).** A checklist is read once at the end by somebody
who has already made the decisions it asks about. The steps below are in dependency order, and each
says what it is FOR — because a connector author who understands why the lens comes before the grant
writes a different lens than one who is ticking a box.

**Validated by its SECOND user.** Fullstory shaped this document; the thin Jira driver is the first
connector built FROM it. **Anything Jira needs that this document did not say is a defect HERE**,
recorded as such rather than fixed silently in the driver — which is the only honest test of a
reusable artefact, and the reason P2 is the phase to write it in: it is the one phase with three
connectors to run it against.

**AND THERE IS A WORKED FORM OF IT: [`hako/`](README.md), the box this document sits in.** The solution is a complete,
governed connector written to be read; the exercise is the same with its governance removed, one gap
per step, and `make hako` runs it. Read this document alongside that one — a reference answers "what
does `target_residency` mean", and a kata answers "what do I do first".

---

## What is enforced, and what is advice

Be clear which is which before you start, because the two fail differently.

| | Enforced by | Failure looks like |
|---|---|---|
| The mechanical contract | `pkg/connector/conformance`, invoked from your package (step 25 makes it mandatory) | a failing build |
| The catalog is honest | `internal/actionset` at boot (D195, D196) | a refused boot naming your action |
| Schemas resolve | `internal/schemareg`'s boot check | a refused boot naming the path |
| Idempotency is classified | the loader (D163) | a refused load naming the action |
| **The lens, the guard, the limits, the grant** | **nothing** | **a connector that works and governs nothing** |

### What the conformance suite asserts

**GENERATED FROM `conformance.Arms()` — do not edit by hand (D218).** Step 46 regenerates it and
prints what to paste. CONTRACTS 93 is why: this contract used to be stated in three places and no
two agreed, and the sentence that overclaimed was in a DECISION, where nothing could check it.

<!-- BEGIN:derived-conformance-arms -->

| Arm | Selected by | What your driver must do |
|---|---|---|
| `runKind` | `Run` | your Kind is non-empty, so a target's `kind:` can route to you at all |
| `runActions` | `Run` | every action has a unique name, a real description (not its own identifier restated), and — if it mutates — a declared idempotency class |
| `runSchemasDeclared` | `Run` | you ship the schema of every type your actions declare, and of nothing else — closed by default, the same check the boot makes (D279) |
| `runMeterSound` | `Run` | your meter can price every call and every poll before it is sent — a Source declares its poll's worst case, and a unit other than calls declares its own default and action cost; the same check the boot makes (D284) |
| `runUnknownAction` | `Run` | an action you do not implement is refused DELIBERATELY, is not retryable, and does not touch the target's breaker |
| `runStateless` | `Run` | one instance serves every tenant at once and the far side sees each call's OWN credential — under `-race`, which the arm requires |
| `runTenantAsserted` | `Run` | a request whose tenant does not match the target's never REACHES the far side, and the refusal is not attributed to the target |
| `runUnauthorized` | `RunHTTP` | a 401 is `unauthenticated`, does not implicate the target, and asks for the CREDENTIAL to be re-established |
| `runForbidden` | `RunHTTP` | a 403 is deliberate and is NOT re-establishable — the credential was accepted and the action refused |
| `runRateLimited` | `RunHTTP` | a 429 is `rate_limited`, does not implicate the target, and its `Retry-After` survives classification |
| `runServerError` | `RunHTTP` | a 5xx implicates the target, is retryable, and is not re-establishable |
| `runUnreachable` | `RunHTTP` | an unreachable server implicates the target and is never reported as drift |
| `runCancelled` | `RunHTTP` | an already-cancelled context stops you doing work the caller abandoned |
| `runSourceIsAdvertised` | `RunSource` | your poll appears in Actions() as `<kind>.poll` and is not mutating, because a grant cannot name an action no driver implements |
| `runSourceTypesDeclared` | `RunSource` | your poll declares the types it yields, and every event it returns carries one of them — an undeclared type is refused, never published |
| `runSourceConformsToItsSchema` | `RunSource` | what your poll returns conforms to your own schema once shaped — no declared field of the wrong type, no kind your own family refuses |
| `runSourceResponse` | `RunSource` | one poll's response conforms — within the limit, no repeated or missing ids, every event typed and dated, and the cursor not handed straight back |
| `runSourceTenantAsserted` | `RunSource` | a poll carrying a tenant the target is not bound to is REFUSED — a read is not exempt from the egress assertion |
| `runSourceProgress` | `RunSource` | a second poll from the cursor you returned yields DIFFERENT rows, so a cursor that changes while the window does not is caught |
| `runSourceRecoveryIsTrue` | `RunSource` | your declared recovery policy is true: `requery` really returns the same window twice, and `unable` says what an operator should change |
| `runSourceCancelled` | `RunSource` | a cancelled context stops the poll and returns no events, because the spine's per-poll deadline arrives as exactly that |
| `runSourceBorrows` | `RunSource` | your poll borrows its client from the pool, because a source that dials privately cannot be stopped by `revoke_credential` — and a poll repeats on a timer |
| `runNoCredentialInTheError` | `RunHTTP` | the credential you send appears nowhere in the error you return |
| `runDriftPriced` | `RunDrift` | if you report drift, you declare a system budget and price a comparison before it is sent — comparisons are Sekizui's safety traffic and never billed to consumers (D311) |
| `runDriftClean` | `RunDrift` | a live surface that matches what was vetted reports nothing |
| `runDriftGraded` | `RunDrift` | every difference is graded in the published vocabulary, names what diverged, and withholds only actions you actually advertise |
| `runDriftReadOnly` | `RunDrift` | a comparison only reads — two in a row of an unchanged target agree |
| `runDriftTenantAsserted` | `RunDrift` | a comparison asserts the tenant before any egress, and refuses with none bound |
| `runRefinerParses` | `RunRefiner` | if you ship `refines:` rules, your reflexes.yaml loads in the closed vocabulary and every rule is named under your kind (D300, D317) |
| `runRefinerOwnsItsTypes` | `RunRefiner` | every rule refines a type your actions return and writes a seiren type your schemas declare — one type, one owner (D279, D299) |
| `runPresetterParses` | `RunPresetter` | if you suggest presets, your presets.yaml is a fragment a deployment can drop in as it stands, every preset named under your kind (D327) |
| `runPresetterHoldsItsClaims` | `RunPresetter` | every preset names only your actions, and every `mirrors:` claim holds against your own connector.Leveled grading — the rule boot applies (D327) |

<!-- END:derived-conformance-arms -->

The last row of the table above is what this document exists for. There is no guard that can write your lens, because
what is sensitive in your vendor's payload is a judgement about somebody else's API. What CAN be
mechanised is already mechanised; the rest is here, in the order that makes it likely to happen.

---

## 1. Decide the binding class before you write any code

§4.7.4's three classes, and the choice constrains everything after it:

1. **Stateless** — the client holds no credential. Fullstory is class 1: it builds an
   `Authorization` header per call from lent material, so one driver instance serves every tenant.
2. **Credential-bound** — the client is constructed with the credential and must be rebuilt when it
   rotates. Implement `connector.ClientBuilder`; the pool keys on `Target.PoolKey()`, which carries
   the credential version (D132), so rotation produces a new entry rather than a stale one.
3. **Session-oriented** — the far side mints a session that must be established, carried and torn
   down. The MCP driver on revision `2025-06-18` is class 3. **Implement teardown**, or eviction
   drops the session instead of closing it, and the far side holds an authorised session nobody
   is using.

**A class-1 driver still gets a pool entry, and this is not an optimisation (D190).** The pool is
what puts break-glass on the path: `revoke_credential` cancels in-flight calls by evicting the pool,
so a driver the pool skipped is invisible to revocation — it would evict nothing and truthfully
report cancelling nothing while calls continue on a credential just declared compromised.

## 2. Write the driver against the conformance suite from the first commit

```go
func TestConformance(t *testing.T) {
    conformance.Run(t, myDriver, conformance.Case{
        UnknownAction: "mine.no_such_action",
        Refuse:        func(ctx context.Context) error { /* real target, real call */ },

        // REQUIRED, not optional — see "What `Run` asserts" below.
        Tenants:    []string{"alpha", "beta"},
        Concurrent: func(ctx context.Context, tenant string) (observed string, err error) { ... },
        Command:    func(ctx context.Context, baseURL, ctxTenant string) error { ... },
    })
}

func TestHTTPConformance(t *testing.T) {   // only if you speak HTTP yourself
    conformance.RunHTTP(t, conformance.HTTPCase{
        Tenant:          "alpha",
        SecretOnTheWire: "the credential as a packet capture would show it",
    }, func(ctx context.Context, baseURL, tenant string) error { ... })
}
```

**BOTH SNIPPETS USED TO BE WRONG, AND THE SECOND DID NOT COMPILE (D222).** `RunHTTP` takes an
`HTTPCase` before the invoker, and the invoker takes the TENANT it must thread rather than
deriving one. The first omitted `Tenants`, `Concurrent` and `Command` — which the prose two
paragraphs down calls required — so a reader who started from the snippet got a suite that
`t.Fatal`s on its own configuration. Found by the thin Jira driver, which is what a second user
is for.

**Not at the end.** D160 built the same thing for `config.Provider` and it found two of four
providers violating the contract on its first run — including one written after reading a comment
predicting that exact violation. Your own tests assert what you believe; the suite asserts what the
system requires.

**What `Run` asserts**, beyond the action set: that your driver is STATELESS across tenants (four
tenants, eight calls each, every one in flight, and the far side is asked who called — a crossing
shows up as another tenant's credential, not as a crash), and that your tenant assertion fires
**before** the outbound call. That second one is counted at the far side rather than read off the
error, because a driver that calls the vendor and then declines to return the answer has already
acted for the wrong tenant. Both need a seam from you — `Case.Concurrent` and `Case.Command` — and
both may be declined only with `Case.WhyNoFarSide`, for a driver with genuinely nothing a caller can
observe. `kata` is the one in this tree.

`RunHTTP` additionally checks that **your credential does not appear in an error**. The suite owns
the server, so it confirms the secret genuinely arrived before failing the call — an arm satisfied
by the absence of the thing it checks is the trap this repository has walked into most often. It
covers the ERROR and not `Effect.detail`: a Result exists only on the success path, where no generic
body is plausible to every driver, so that half stays yours to test.

`RunHTTP` is **selected explicitly and never folded into `Run`**: a driver on a vendor SDK has no
HTTP statuses to classify, and a universal suite would either fail it for the wrong reason or skip
the half that matters while reporting coverage. It covers 401, 403, 429 and 5xx — the statuses whose
meaning the taxonomy FIXES. **404 and most of 4xx are yours to test**, because they have no single
right answer: MCP reads a bare 404 as a legacy endpoint and therefore a configuration fault, while
another API's 404 is an absent record and the caller's problem.

**Two things §5 still says that are no longer true**, corrected here and in CONTRACTS (items 91 and
92) rather than left for you to discover:

- **`Target.Credential()` does not exist.** D127 replaced it with `Target.Use(fn)` — material is
  LENT for the duration of a callback and goes inert when it returns. There is no accessor that
  hands you bytes to keep.
- **You do not call the limiter, the breaker or the retry policy.** §5's Resilience section reads as
  though a driver drives them; D140–D143 put all three in the ENFORCEMENT PATH, deliberately, so
  that they cannot be forgotten by a driver or implemented differently by each. **What a driver owes
  is to REPORT accurately**: surface the upstream's `Retry-After` on the fault (the enforcement path
  caps it — a proxy must not set our latency budget), classify the failure so D200's attribution
  axis can tell a credential fault from a target fault, and put a timeout on every outbound call.

### If your connector is POLLED, select the source suite too

A `connector.Source` is optional — most connectors are write-only, which is why `RunSource` is
chosen rather than folded into `Run` (the same reasoning as `RunHTTP`, D160's vacuous-`Run`
lesson).

**READ `hako/solution/conformance_test.go`'s `TestSourceConformance` — it is four lines and it
compiles.** No snippet is reproduced here on purpose: D222 is the record of what happens to this
document's Go examples, and one of them did not even compile. A pointer cannot rot into something
that looks right and is not.

**FOUR THINGS A SOURCE OWES, and the third is the one authors get wrong:**

- **`Poll` is a PURE FUNCTION of (target, cursor, limit).** Hold no offset, remember no page.
  Derive the window from the cursor you were handed, and re-querying works by construction instead
  of by luck. This is D4's statelessness, and it is the same property D174 calls re-queryability.
- **A cursor you mint is one you must accept**, and one you did NOT mint you must REFUSE. Starting
  over on an unrecognised cursor is the failure that looks like success: the whole source is
  re-ingested while every log line reports a healthy poll.
- **`Recovery(t)` is a DECLARATION THE SUITE CHECKS, not a hint.** Say `requery` and the arm makes
  you return the same window twice; say `unable` and you owe a `Why` that names what an operator
  should change, because it lands verbatim in the gap marker they read. It takes a TARGET because
  re-queryability is usually a property of the system rather than of your code — an append-only
  table and a mutable one are the same driver.
- **A cancelled context stops you.** The spine's per-poll deadline arrives as exactly that, so a
  source that ignores one cannot be bounded by the thing that exists to bound it.

**AND WHAT THE SPINE DOES ANYWAY, whether or not you run this suite (D243).** It truncates at
`limit`, cancels at its own deadline, recovers your panic, and stops polling a source that keeps
handing back the cursor it was given. Those are not configurable away, because a badly written
connector must not be able to melt the system in a deployment that never wrote an anzen rule. What
the suite buys you is finding out BEFORE a deploy rather than after — and everything it checks is
`connector.ValidatePoll`, the same function the poller runs on every tick, so there is exactly one
definition of conforming.

### If your connector can DRIFT, implement `connector.Drifter` and select the drift suite

A connector whose actions are pinned against something its vendor controls — a tool list, an API
reference, an SDK version — can find the vendor has moved. `connector.Drifter` is how it says so,
and it is optional for the same reason `Source` is: a connector with nothing to diverge from is not
asked (D311).

**READ `hako/solution/notes.go`'s `Drift` and `TestDriftConformance` beside it.** `kata` has the
same form with its vendor simulated by a setting, and the MCP driver has it against a live
`tools/list`. Three implementations, one suite.

**FOUR THINGS A DRIFTER OWES:**

- **Take the path your actions take.** Assert the tenant, borrow through the pool, send. A
  comparison carries the target's credential, so it is egress like any other call — the MCP driver's
  comparison did NOT assert the tenant until `RunDrift`'s tenant arm found it.
- **Only read.** A safety check with a side effect cannot be run on a timer; the suite asserts two
  comparisons in a row agree.
- **Grade in the published vocabulary** — `withheld` for a vetted action the vendor dropped (the
  catalog stops advertising it), `unvetted` for something nobody vetted (harmless: it has no action),
  `refused` for an input shape that changed under a vetted action, `informational` for output.
  Never a severity of your own: the store refuses one.
- **Declare what it costs, in your meter.** `SystemPerHour` is YOUR system budget — comparisons are
  Sekizui's safety traffic and are charged there, never to the consumers' budget — and `DriftCost`
  prices one comparison at worst case before it is sent. The boot quarantines a Drifter that
  declares neither, and a non-Drifter that declares either.

**A HYBRID CONNECTOR DRIFTS PER HALF.** Fullstory is two drivers against one system (D52): its MCP
half is a Drifter comparing the server's own `tools/list` at run time; its API half is not, because
no API describes what it serves — its reference revision is compared with the published
documentation at release (D299, D311). Choose per half what can actually be read live, and grade
both in the one vocabulary.

**WHAT THE SPINE DOES WITH IT.** Every comparison is admitted like a poll (every ceiling, the
withdrawal check, your system budget), recorded as a decision — clean, diverged or refused — as the
built-in `sekizui:drift-watcher`, and its state survives a restart: a withheld action stays withheld
until a comparison says the vendor offers it again.

### If your vendor has roles, suggest presets: ship `presets.yaml`, implement `connector.Presetter`

A preset is a named set of your actions that a deployment grants by name —
`{preset: <kind>.<name>, target: …}` — with an `explain:` saying what it is for (D327). Ship them as
`presets.yaml` in your folder: a config FRAGMENT a deployment drops into its own directory, exactly
like `anzen.yaml`. **Grants expand from the deployment's copy, never from your file**, so nothing you
release can widen a grant; embed the same file and return it from `SuggestedPresets()`, and boot
tells an operator when their copy has fallen behind yours. If your vendor grades operations by level
(Fullstory's Standard, Architect, Admin), implement `connector.Leveled` and a preset may say
`mirrors: <level>` — boot refuses one holding anything above it. **Select `conformance.RunPresetter`**:
it runs the checks boot makes, so a preset that passes here is not refused at somebody's deploy.

**READ `internal/connectors/kata/presets.yaml`** (the reference: two presets over fictional levels,
and no `owner` preset, on purpose — a connector need not package its most dangerous level), then
**`hako/reference/`**, where the same file is dropped in beside `kata.yaml` and a grant names
`kata.viewer`: the deployment side. `internal/connectors/fullstory/presets.yaml` is the same shape
over a real vendor's levels.

### If your connector can REFINE its results, implement `connector.Refiner` and select the refiner suite

A connector that knows how to turn its own results into something an agent can use directly — the
milestones inside a session's events, the path a user took — ships that knowledge as `refines:`
rules in a `reflexes.yaml` embedded beside `schemas.yaml`, returned from `Reflexes()` (D299, D317).
Optional, like `Source` and `Drifter`: a connector with nothing to refine is not asked.

**READ `internal/connectors/fullstory/reflexes.yaml`**, the worked form: three org-independent rules
and one template.

**WHAT A REFINER OWES, AND WHAT IT DOES NOT CONTROL:**

- **Rules in Sekizui's vocabulary, which your file cannot extend.** `where` over the shared
  operators, one `preceded_by` and one `followed_by`, and exactly one of `list`, `count` or `first`
  (D300). Name every rule under your kind: `<kind>.<rule>`.
- **Your own types, both ends.** A rule refines a type your actions return and writes one key of a
  seiren type declared in YOUR `schemas.yaml`. The input type declares exactly one top-level
  `format: date-time` field, because every rule sorts by time (D317).
- **A template refuses to be imposed bare.** A parameter your rule cannot know — which page is this
  customer's sign-in — is declared `required`, and the boot refuses an imposition that leaves it out.
- **Nothing you ship reaches anybody by itself.** The deployment imposes a rule with `refinements:`,
  `for:` an audience, so a release that adds a rule changes nothing an agent receives. There is no
  `mode:` — a rule that never actuates is staged by audience, not shadow (D298).

`RunRefiner` holds the first two with the boot's own parser and registry; the boot holds the rest
when a deployment imposes a rule.

## 3. Declare an idempotency class per action, and mean it

`header`, `field`, `natural`, `conditional`, `none` (D163). **A human classifies it. Never infer it
from a vendor hint.** An absent classification on a mutating action fails the load.

The classification is per ACTION, not per driver, and Fullstory is the proof that this had to be:
`create_event` is `none` — `POST /v2/events` offers no idempotency header and no client-supplied
event id, so a retried timeout duplicates the event — while `upsert_user` is `natural`, keyed on
`uid`, converging on the same state however often it replays. One vendor, two actions, opposite
answers.

**A `none`-class action REFUSES to retry and the refusal reaches the caller (D182).** A closed retry
gate that hands back a retryable timeout has relocated the double-write hazard to the agent rather
than removing it.

## 4. Register an input schema for every action, and an `OutputType` for every query action

`ActionSpec.InputSchema` is a registered URI (`sekizui://schema/<kind>/<action>.v1`).

**`OutputSchema` AND `OutputType` ARE TWO FIELDS BECAUSE THEY ARE TWO THINGS, and this
is the step's sharpest edge (D41, D88).** `OutputSchema` is a URI naming where the
document lives. `OutputType` is the REGISTRY KEY — dotted and versioned, the key
`payload_schemas:` is keyed on and the key step 7's lens `type:` is matched against.
They were one field once, and merging them meant inventing a slash-to-dot convention:
a guess dressed as a rule.

```go
OutputSchema:       "sekizui://schema/jira/issue.v1",   // where the document lives
OutputSchemaOrigin: connector.SchemaFromLocal,          // required when OutputSchema is set
OutputType:         "jira.issue.v1",                    // the registry key
```

```yaml
payload_schemas:
  jira.issue.v1:            # same key the action declares and the lens names
    type: object
    properties: {...}
```

**Put the URI in `OutputType` and one of two things happens, neither of them loud at the
right moment**: register your schema under the dotted key and `schemareg` refuses the
boot naming your action; register it under the URI and you boot carrying a type
namespace `internal/connectors/kata` and `acceptance.yaml` both contradict. This paragraph
exists because the kata's answer key did exactly that in three mutually-agreeing files,
and its own guard asserted the wrong string rather than catching it.

**`OutputType` IS NOT OPTIONAL FOR A QUERY ACTION**, upgraded from guidance by the maintainer's ruling: bus
subjects are per-connector and a consumer learns a shape by asking the connector, so a driver that
omits `OutputType` is lensable only by the type-less jurisdiction rules. Omitting it is a LEDGERED
EXCEPTION with a reason — not a silent degradation. Register the payload schema alongside it, or
`internal/schemareg`'s boot check refuses the boot naming the path.

This is what makes step 4 (the lens) possible at all: a lens that withholds `properties.email` needs
something that says `properties.email` exists.

### If your vendor has fixed hosts, say so: implement `connector.HostBound`

**A CREDENTIAL GOES WHERE `base_url` POINTS.** Nothing on Sekizui's side bounds the host a driver
dials, so a target naming any host would send your vendor's credential there on every call — the road
D286's credential theft rode. A driver that knows its vendor's hosts implements `AdmitBaseURL(targetRef,
baseURL) error`: boot refuses a target outside them, and the driver refuses again on every call (D288).
Require `https`, refuse userinfo in the URL (a credential in config), and name the hosts in the
refusal so an operator can fix it.

Optional, and type-asserted: a generic driver (the MCP driver, Jira Cloud's per-customer sites) cannot
know a fixed list and says nothing. **kata does not implement it, on purpose** — it is in memory and
dials nothing, so a host list would bound nothing (P5 step 13's exemption). **READ
`internal/connectors/fullstory/fullstory.go`'s `AdmitBaseURL`:** two data centres, one host per
target, each refusal naming both.

### If your vendor publishes its API contract, derive from it

A vendor whose reference is generated from OpenAPI publishes more than a list of endpoints: each
operation's parameters, request body and responses. The Fullstory connector takes that as its
reference revision (`sekizui-refsnap`, D313) and derives an action per documented operation from it
(D314) — input checked closed against the documented parameters and body, data schema the closed
subset of the documented response. What is NOT derived is what only a human can say: whether a
write is repeat-safe, and a name where the vendor's operation id is ambiguous. Keep both in reviewed
tables, and refuse any write that has no ruling rather than defaulting it.

## 5. Write the target spec, and put the operational limits ON THE TARGET

```yaml
targets:
  - ref: jira:acme
    kind: jira
    tenant: acme
    residency: eu
    base_url: https://acme.atlassian.net
    credential: file:///etc/sekizui/jira-acme          # NOT env:// — see below
    limits:
      rate_per_hr: 500
      budget: atlassian                                # share one bucket across targets
      max_lifetime_s: 3600
      breaker_trip: 5
      retry_attempts: 3
```

**D142: operational limits belong on the TARGET in config, with the flag as a CEILING a target may
only narrow.** The flag is the deployment's bound and the target may lower it, never raise it —
which is D108's shape, and the reason is the maintainer's: changing a rate limit must not need a redeploy.

**`env://` is refused off bare metal (D111, D153).** The default credential policy requires a
credential be `versioned`, and an environment variable declares no version — so the refusal is
general rather than a hardcoded special case. Everything Helm and SOPS produce terminates as a
`file://` mount (D103, D151), which is the path to plan for. A `file://` credential is versioned BY
CONTENT and `credver.Ordinal` exempts it from the monotonic check, because a content digest has no
older or newer and inventing an order would refuse legitimate edits about half the time.

**IF YOUR VENDOR'S CREDENTIAL IS A COMPOSITE, THE FILE HOLDS THE COMPOSED VALUE — and this is a
real limitation rather than a convention (D222).** Jira Cloud authenticates with
`Authorization: Basic <base64(email:api_token)>`: an identity and a secret, joined. Sekizui has no
way to express that. `connector.SetAuthorization` emits `<scheme> <material>` and there is no
exported helper for a header value built from anything but the material, so a composite vendor has
exactly two options:

- **Pre-compose the credential.** The `file://` credential holds `base64(email:api_token)` and the
  driver calls `SetAuthorization(h, t, "Basic")`. Stays entirely inside the published surface and
  keeps the broker's header-byte validation. **Cost: the two halves cannot be rotated
  independently**, and an operator base64s by hand.
- **Carry the identity in `Settings` and compose inside `Target.Use`.** More natural operationally
  — the secret stays the secret — but the driver then hand-rolls the `Authorization` value and
  loses `refuseUnsafeHeaderBytes`, which is unexported. A trailing newline from `echo` becomes a
  confusing transport error instead of a named configuration fault.

The thin Jira driver takes the first, because a second user's job is to test the published surface
rather than to route around it. **Neither is good**, and which one is right may depend on how often
your vendor rotates. It is written down here so the next author chooses rather than discovers.

**Declare `residency` unless you genuinely cannot.** In a deployment serving more than one class, an
unclassified target REFUSES THE BOOT (D136) — the grant layer switches on only where more than one
class is served, and letting something silently cross a border is how privacy incidents happen.

## 6. Write a NARROW grant, and review it as a union if two paths reach one system

```yaml
grants:
  - principal: agent:triage
    allow:
      - {action: jira.create_issue, target: jira:acme}
      - {action: jira.read_issue,   target: jira:acme, where: {target_residency: [eu]}}
```

- **Name the target.** A capability with no `target:` is a capability against every target of that
  kind, which is rarely what anybody meant and is invisible in review.
- **`target_residency` is a RESERVED `where:` key** — answered from the compiled Document, never
  from `Args`, or a command could satisfy its own compliance constraint.
- **A wildcard action expands into the concrete actions it covers (D195)** rather than reaching an
  agent verbatim, and a granted action that no driver implements FAILS THE BOOT. You cannot grant
  something into existence.
- **IF YOUR SYSTEM IS ALSO REACHABLE BY MCP, THE GRANT REVIEW IS A UNION (D52, §4.9a.8).** The
  namespaces do not collide — `jira.create_issue` and `mcp.atlassian.createIssue` are different
  actions and neither glob reaches the other — and that is precisely the hazard: denying one leaves
  the other open, and **no machine can adjudicate whether an MCP tool and a native action are
  equivalent**, because that is a semantic judgement about somebody else's API. The mitigation that
  CAN be built is built: one `Describe` shows both doors onto one system, so the review has
  something to review. The review itself is a human obligation and this document is where it is
  written down.

## 7. Suggest an imposed lens, naming what your vendor's payload carries

```yaml
shin:
  - name: jira-detail-withheld
    enabled: true
    mode: imposed              # empty means imposed; this is the one restrictive default
    type: jira.issue.v1        # the PAYLOAD TYPE from step 4, never the schema URI
    withholds: [reporter.email_address, description]
    because: "issue bodies carry customer PII pasted by support agents"
```

**`type:` IS THE PAYLOAD TYPE, AND THIS EXAMPLE USED TO GET IT WRONG.** It read
`sekizui://schema/jira/issue.v1` — the schema URI — which is step 4's distinction
collapsed at the point a reader is most likely to copy it. The kata's answer key made
the same substitution in three files that agreed with each other, so nothing caught it
until the kata was worked. Follow the URI version and register your schema under the
documented key and `schemareg` refuses the boot naming your own action; register it
under the URI instead and you boot with a type namespace the rest of the tree
contradicts.

**`mode:` empty means IMPOSED, which inverts the default used everywhere else in this file.**
Elsewhere the safe default is passive (shadow, disabled); here the safe default is restrictive,
because a lens that silently becomes optional discloses.

**`because:` is not decoration.** A lens whose reason is unrecorded is one nobody dares remove and
nobody can justify, so it survives long past the concern that produced it.

The lens is a SUGGESTION in this document and a REQUIREMENT of the deployment: what your connector
owes is a proposed default that a reviewer can accept or narrow, written by the person who has
actually read the vendor's response payloads. Nobody else is in a position to write it.

## 8. Suggest a preventive guard naming your IRREVERSIBLE actions

```yaml
anzen:
  - name: no-jira-deletion
    enabled: true
    mode: enforce
    forbids: ["jira.delete_*"]
```

**A ceiling, not an opinion (D71).** It is checked BEFORE policy, so a forbidden action is refused
even where a grant permits it — and that ordering is the whole point: grants are written per
principal by whoever needs the capability, and a blocklist is written once by whoever is accountable
for the blast radius.

`applies_to` empty means EVERY principal, which is the right default for a blocklist: a destructive
action nobody should perform is not a per-principal question. Scope by `target_residency` only where
a control genuinely differs by jurisdiction (D137) — scoped rules are strictly ADDITIVE and never
cover an unclassified target.

**Name the irreversible actions specifically.** "Irreversible" is the criterion, not "dangerous": a
call that can be undone by a subsequent call is a policy question, and a call that cannot is a
ceiling question.

## 9. Say which closed signals your connector can raise

The vocabulary is CLOSED and validated at boot — `budget_exceeded`, `spec_drift`,
`tenant_mismatch`, `denial_storm`, `audit_unavailable`, `credential_stale`. These are Sekizui's own
governance signals, not bus subjects: an anzen rule that consumed business events would be a reflex
wearing a different name.

**Declaring one you cannot raise is worse than declaring none**, and the reason is CONTRACTS 65:
five of the six have had no producer anywhere in the tree while `acceptance.yaml` already WATCHED
`spec_drift`, so boot validated a rule that could never fire and told the operator nothing. If your
connector can detect a condition in the vocabulary, RAISE it; if it cannot, say so here and let the
init ledger carry the expiry (CONTRACTS 48) so the gap rots loudly instead of quietly.

## 10. Register the driver, or it does not exist

```go
for _, dr := range []connector.Driver{
    // ...
    jira.New(jira.WithPool(clientPool)),
} {
    if err := registry.Register(dr); err != nil { return nil, err }
}
```

**THIS STEP WAS MISSING AND THE DOCUMENT DID NOT NOTICE (D222).** Every other step here is about
making a driver correct; none of them made it REACHABLE. `Register` reads the kind off the driver
rather than taking a key, so the two cannot disagree (D190), and a driver that is never registered
compiles, tests green, passes the whole conformance suite, and is routed to by nothing.

**AND IT FAILS SILENTLY IN THE MOST CONVINCING WAY**, which is why it earns a step of its own:
your driver's `Execute`, `Query`, `Kind` and `Actions` all LOOK reached, because they satisfy
`connector.Driver` and the gateway calls that interface. `New` having no caller is the only symbol
whose silence says the driver is inert — which is exactly how `TestNoOrphanedExportsInInternal`
caught the Jira driver, and how D213 caught the MCP driver before it. If you are writing a driver
outside this tree you have no such guard, so the question to ask is simply: **what constructs it?**

**IN THIS TREE, A CONNECTOR IS ONE FOLDER AND REGISTRATION IS CHECKED BOTH WAYS (D316).**
`internal/connectors/<name>/` holds the driver, `schemas.yaml`, the conformance tests and a README,
plus `mcp.yaml`, `anzen.yaml`, `reflexes.yaml`, `presets.yaml` and `reference/` where the connector has them; an
MCP-only connector is a folder with an `mcp.yaml` and no code. The one list of drivers is
`internal/builtin`, and `internal/connectorcheck` fails the build for a folder with code that list
does not construct — and for a registered driver that lives anywhere but its folder.

## 11. Enter the driver into the mixed-tenant property test

Add your targets to `internal/acceptance/acceptance.yaml` under distinct tenants in one residency.
Step 14 then runs 48 concurrent commands across four tenants against them under `-race`.

**Give each tenant a DISTINCT credential.** A shared one makes the test able to catch only an EMPTY
header; distinct ones catch a SWAPPED one, which is the failure that actually happens — tenant B's
credential on tenant A's request, which succeeds, is audited as successful, and writes A's data into
B's org.

**If your target needs a `base_url` that is not known until a test server starts, you cannot use the
shared fixture** — `acceptance.yaml` is loaded once before any step runs, and a fixed local port
makes the whole suite fail as a port conflict. Build your own document, gateway and pool in the
step, the way step 2 does, and preserve what the property needs: the real enforcement path, distinct
tenants in one residency, every command in flight at once.

## 12. What nothing checks, and you must

**THESE CAME FROM CONTRACTS §5, which D218 superseded** — the residue after its checkboxes were
classified. Each is real, none is machine-checkable today, and each says why.

- **`Result.ExternalRef`, populated.** It is how an audit row joins to the target's own record —
  the Jira key, the vendor's event id — and without it a governed action and the thing it did are
  two facts nobody can connect. The MCP driver populates none today; that is a gap rather than a
  design.
- **A timeout on every outbound call.** The per-command context deadline is the real bound; a
  client timeout is defence in depth for a caller that arrives without one. Nothing checks that you
  set one, because a driver with no unbounded path and a driver whose unbounded path was not
  exercised look identical.
- **Cache nothing keyed on anything but `Target.PoolKey()`.** The key carries the credential
  version (D132), so anything you key differently survives a rotation it should not have survived.
  A private cache is also invisible to break-glass, which is the same argument as step 1's.
- **Attribution stamped into the ACTION where the system allows it** — a Jira label, a BigQuery job
  label, Slack metadata (§10.4). The audit log records what Sekizui did; this is what lets somebody
  looking at the VENDOR's record see that an agent did it. Only you know whether your vendor has
  somewhere to put it.
- **`connector.Source` if your system is pollable.** The afferent path lands at P3 and the Jira
  poller is its first implementer; a connector that will feed the bus should be shaped for it now.
- **An OTel span per outbound call, with the delegation chain in attributes.** Not yet possible:
  nothing in the tree emits one, and `obs:otel` is an init-ledger entry landing at P2 step 29. Held
  here so it is not forgotten, and it will be enforced when it exists.

**And the tests §5 asked for, minus the one that was wrong.** Unit tests against a fake transport;
one integration test against a real sandbox, skipped without credentials; and an
idempotency-under-retry test — the same key twice, one side effect. **§5 also asked for a
credential-rotation test and that one is not yours**: the POOL invalidates on a version change
(D99, D132) and your driver holds no cache to invalidate.

**If your system is also reachable by MCP**, the generic driver carries its own obligations —
`Actions()` from the committed spec and never a live `tools/list` (D46), drift severities
distinguished (D48), `outputSchema` absence never read as drift (D51), `mutating` never inferred
from a vendor hint, offline validation blocking the load while live comparison gates readiness per
target (D50), an unreachable server reported as availability and never as divergence, and a shared
upstream budget declared where a native driver fronts the same system (D52, §4.3.4). Those are
proven by P2 steps 7 to 15 rather than by the conformance suite, because they are claims about one
driver rather than about every driver.

---

## The limit of this document, stated rather than pretended away

**Whether a connector FOLLOWED this blueprint is not machine-checkable.** Steps 1, 2, 3, 4, 10 and 11
have guards behind them and will fail a build. Steps 5 through 9 produce configuration, and
configuration that is absent is indistinguishable from configuration a reviewer decided against.

What is checkable is that the QUESTION was asked, and the mechanism for that is the same one D167
used for the signals: an omission is LEDGERED with a reason rather than left silent. A connector
shipping with no lens because its payload carries nothing sensitive is fine. A connector shipping
with no lens because nobody looked is the failure, and the two are identical in the tree unless one
of them wrote down which it was.
