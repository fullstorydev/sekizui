# sekizui-mcpspec: from an MCP server's output to a vetted connector fragment

**MOVED HERE FROM `specs/mcp/README.md` BY D316**, when in-tree connectors moved to one folder each.
A vetted MCP spec is a config FRAGMENT we ship as the connector's authors, and it now lives in its
connector's folder as `internal/connectors/<name>/mcp.yaml` — the Fullstory MCP's 33 tools are
`internal/connectors/fullstory/mcp.yaml` (D308). A deployment drops that file into its config
DIRECTORY (D278); P3 step 25 loads it itself. An MCP-only connector is a folder with an `mcp.yaml`
and no code, served by the one generic driver in `internal/driver/mcp` (D316).

**A DRAFT IS NOT A CONNECTOR FILE.** What the tool writes is headed `DRAFT — NOT VETTED, NOT LOADED`,
for a human to read and correct; only a reviewed draft becomes a connector's `mcp.yaml`. One fragment
per target, because D278 refuses a second — D305's 27 drafts were vetted into one file (D308).

**THE FLOW SINCE D287:** the user's AGENT calls the MCP and pipes the raw result to `sekizui-mcpspec`;
the CLI never talks to a server. `-text` for a tool that returns prose, `-feature` to extract fields
from it, `-caller-only` for a field the record must never hold (D289).

**THE DIFF IS THE REVIEW.** That is the whole reason drafts are committed: D46 makes the vetted spec
reviewed configuration, and a pull request is where a person actually looks at it. A draft kept in a
gitignored scratch directory would be a draft nobody reviewed.

## The flow

```sh
# 1. Observe. PIPE — do not save. See below.
<something that calls the tool> | sekizui-mcpspec \
    -tool discover_org_context -type fullstory.org_context.v1 \
    > internal/connectors/fullstory/draft-discover_org_context.yaml

# 2. Read the warnings on stderr. Every one names a place where the observations
#    were too thin to support the schema that was written.

# 3. Review the diff, correct what is wrong, and add the two fields the tool
#    REFUSES to guess: `mutating`, and `idempotency` if it is mutating.

# 4. Merge the vetted tool into the connector's `mcp.yaml`, delete the draft, and
#    let the completeness guard (D316) load the result.
```

**TWO OR MORE OBSERVATIONS, ALWAYS, IF YOU CAN GET THEM.** One response cannot tell a field that is
always present from one that happened to be, so an object observed once carries no `required`, and
the draft names each such object (D289 corrected a warning that said "anywhere"). It also cannot tell an object used as a MAP from one used as a record — the first real draft
against Fullstory's `discover_org_context` put the caller's own search terms in as schema properties
(D233), and a second response with different keys is what settles it.

## PIPE, DO NOT SAVE

**A response big enough to be interesting is customer data.** A session-events result is tens of
kilobytes of session ids, user emails, page URLs and click text. A schema needs SHAPE, not somebody's
session, so the observation should never have to land on disk — and `-at /events/0` narrows the draft
to the subtree carrying the type a reflex actually reads, which is the ELEMENT rather than the page.

If you must save one: keep it under `dev/`, which is gitignored in full. **Do not put observations in
a connector folder.** An earlier version of this note proposed exactly that, and it was wrong for the
reason above: a folder for observations is a folder that accumulates customer data.

The tool warns above 16 KB, naming both consequences.

## A directory source, since D278

This section once explained why a vetted spec was PASTED into one config file rather than loaded from
a directory (D233's deferral). D278 made configuration a composable directory — boot-only, because
D144 ruled out hot reload, and hashed after composition so D149's identity stays whole — so a
connector's `mcp.yaml` is dropped in beside the rest of a deployment's fragments as it is.
