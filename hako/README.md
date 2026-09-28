# hako — the reference connector

**箱, a box.** A driver is the Go type; a **connector** is the deliverable an operator installs —
the driver plus its target, its limits, its grant, its lens, its guard and its schemas (D175).
That list is a packing list, and this is the box.

**START HERE IF YOU ARE BRINGING A SYSTEM UNDER GOVERNANCE.** Three things, in the order you want
them:

| | what it is | how it is kept honest |
|---|---|---|
| **[`BLUEPRINT.md`](BLUEPRINT.md)** | the reasoning no artefact can carry — why a grant is narrow, what `target_residency` means, and the prohibitions an exemplary connector is silent about because it does not do them | its conformance table is GENERATED from `conformance.Arms()`; step 46 fails until it is regenerated |
| **[`reference/`](reference/)** | the **skeleton**: a complete, governed connector, as configuration, wrapping `internal/connectors/kata` | four tests, including the real boot check and a cross-check that every granted action exists on the driver |
| **[`exercise/`](exercise/)** + [`solution/`](solution/) | the **form you work**: a connector for a fictional notes service with its governance removed, and the answer key | the exercise fails on purpose; the solution runs green in CI under the full published suite |

**AND WHAT IS IN THE BOX IS `kata`.** Dig into `reference/kata.yaml` and the thing being governed
is `internal/connectors/kata` — 型, the reference DRIVER, the Go half a connector author fills in
(D176). The two words divide exactly where D175 divides driver from connector, and that is the
whole reason there are two (D244).

**BOTH ARE WALKING SKELETONS AND ARE MEANT TO GROW.** §12.0 principle 4 makes that the house form
for a subsystem; applying it here buys something the phase plan cannot. A pull request touching
`reference/` is a pull request changing what every future connector author owes — and the
governance half has never had a review signal, because no compiler checks that a grant is narrow
(D167). The mechanical half has had one since D218.

---

## The exercise and its answer key

## The two halves of the pair

| | What it is | Does it pass? |
|---|---|---|
| **`exercise/`** | The solution with its governance removed. Every gap is marked `HAKO STEP <n>` and names the [blueprint](BLUEPRINT.md) step that closes it. | **No, on purpose.** Run `make hako`. |
| **`solution/`** | A complete, governed connector for a small fictional service, written to be read. | **Yes, in CI**, under the full published conformance suite. |

**The pair is the design, not a convenience.** An exercise cannot be guarded by a runner that
requires green — so the solution is what keeps the kata honest: if the conformance suite gains an
arm, the answer key breaks in CI rather than a release later. And the exercise's markers are checked
against the blueprint's step headings (P2 step 46), so a step that moves cannot leave a learner
pointed at the wrong section.

## Working it

```sh
make hako          # the exercise; every failure names a blueprint step
```

Read [`BLUEPRINT.md`](BLUEPRINT.md) alongside. Close the gaps in
`exercise/notes.go` and `exercise/notes.yaml` until it passes, then read `solution/` for the
reasoning you did not have to write.

## The source half

A connector that is POLLED implements `connector.Source` and selects `conformance.RunSource` as
well. `solution/source.go` is the worked form; the exercise's copy has two gaps, and they fail
differently on purpose — one is caught by checking the RESPONSE (a page bigger than the limit
asked for), the other only by CALLING (a poll carrying the wrong tenant, which a read is not
exempt from).

**The second gap found a hole in the published suite rather than in the learner's code.** There
was no tenant arm for `Poll` at all — `runTenantAsserted` covers `Execute` and nothing covered the
read path, so a source skipping §6 mechanism 3 passed cleanly. That is D155's defect class on the
afferent plane, and the exercise is what exposed it (D243).

**Every gap has a failure behind it, except one.** Step 9 — saying which of the closed signal
vocabulary this connector can raise, or that it raises none and why — is prose, and nothing can
check prose. It is marked anyway, because the step is real; it is named here so the absence of a
failure is not read as coverage.

**Steps 5 to 9 are the ones worth your time.** The others fail loudly whatever you do; those five
are the ones nothing in the system will ever tell you are missing.

## Why a fictional vendor

`internal/connectors/kata` is this tree's in-memory fixture and a good example of the mechanical half.
It cannot teach the governance half, and the reason is specific: it has no vendor payload, so there
is nothing for a lens to withhold, and **step 7 — the step most likely to be skipped and most
expensive to skip — would have no worked example at all.**

The Notes service returns an author's name and email address on every read. That is a decision
somebody has to make, which is the whole point.

## What the solution proves besides itself

Every line of it uses `pkg/` only, including `connector.NewTarget`. `internal/` is unreachable from
outside this module, so that is the entire surface a third-party driver author has — and if the
published contract could not be satisfied from it, the conformance suite would be unrunnable by the
population it exists for.
