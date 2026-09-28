# fullstory — the Fullstory connector (`kind: fullstory`, and its MCP half)

**A HYBRID CONNECTOR (D311).** Two halves, one folder (D316):

| file | what it is |
|---|---|
| `*.go` | the native **Server API driver**: every documented operation implemented or excluded by a named decision — 61 derived from the reference contracts with their arguments checked closed, 4 by hand (D312-D314) — and a **Source** polling sessions and session events through Generate Context (P3) |
| `schemas.yaml` | every type the driver emits, closed by default and embedded (D279) |
| `reference/2026-09/` | the API reference snapshot the driver is held to: `manifest.yaml`, each operation's `contracts/`, and the Lexicon audit (D304, D313). Refreshed with `sekizui-refsnap`; drift against the live docs fails `acceptance-live` only (D299) |
| `mcp.yaml` | the **vetted Fullstory MCP spec** — all 33 tools it serves but the deprecated `session_view` (D308) — served by the generic driver in `internal/driver/mcp`. The MCP half drifts at RUN time; the API half at RELEASE (D311) |
| `anzen.yaml` | a **suggested ceiling**: the 3 irreversible and 9 recording-configuration writes forbidden (D314). Suggested, never imposed — a deployment drops it into its config directory, as `internal/acceptance/demo.d` does |
| `reflexes.yaml` | four `refines:` rules — frustration, page path, errors, and a login TEMPLATE — offered by name, imposed only by a deployment's `refinements:` (D299). **A worked EXAMPLE of the Refiner contract, not a product** (the maintainer, D317); proven on one real web session, not on mobile |
| `presets.yaml` | four **suggested presets** (D327): `fullstory.session_review` (nine read-only actions — the one most agents want) and `fullstory.standard` / `.architect` / `.admin`, each mirroring Fullstory's own permission level and holding nothing above it, checked against the snapshot. A deployment drops the file in and grants name a preset — `{preset: fullstory.session_review, target: …}`; grants expand from the deployment's COPY, so a release that changes this file widens nothing, and boot says when the copy has fallen behind |
| `testdata/` | one live read kept verbatim, no secret in it (D265); and `seiren/web.json`, one real EXAMPLE web session captured THROUGH THE REAL BINARY as shaped rows (`make run-capture` + `make capture-seiren`, D317), which P4 step 18 replays |

**A connector ships everything and Sekizui decides exposure** (D308): grants, lenses and anzen
choose what a deployment serves, never what this folder left out. The native driver dials only
`api.fullstory.com` and `api.eu1.fullstory.com` (D288). `internal/connectorcheck` holds this folder
to the shape above (D316).
