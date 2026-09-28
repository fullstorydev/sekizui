# jira — the thin Jira connector (`kind: jira`)

**THE BLUEPRINT'S SECOND USER (D222)** — built from the vendor's documentation with the blueprint
open and the Fullstory driver deliberately unread, which cost the blueprint three defects. Its value
is as evidence: P2's two-systems criterion rests on it, so it STAYS, and it takes no new work before
P6 (D274).

| file | what it is |
|---|---|
| `jira.go` | the driver, with `Assumptions()` — what it believes about Jira that no fixture can confirm |
| `schemas.yaml` | `jira.issue.v1`, closed and embedded (D279) |
| `jira.yaml` | the **governance half** (blueprint steps 5-9): target, limits, grants, lens, anzen — shipped beside the driver as a fragment a deployment installs with its own `base_url` and credential (D175) |

`internal/connectorcheck` holds this folder to the connector shape (D316).
