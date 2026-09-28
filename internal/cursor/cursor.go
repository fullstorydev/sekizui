// Package cursor is the durable poll state the afferent path rests on.
//
// **NOT AN EMBEDDED DATABASE (D173, D240).** One small value per source,
// written once per poll, through `internal/atomicfile` — the same
// temp-file-fsync-rename-fsync sequence `auditwal.FileTailStore` and the
// withdrawal store use. Bolt would be this tree's first storage dependency,
// arriving to answer questions nobody here is asking.
//
// # The state machine, and why it has three parts rather than one
//
// A poll tick is: read the cursor, poll the source from it, publish what comes
// back, commit the next cursor. **Everything interesting lives in the window
// between publishing and committing**, because that is the only place a
// `kill -9` can land and leave the two out of step.
//
//	Cursor  — the committed position. The source's own string; opaque here.
//	Pending — an attempt that was started and never committed. Its PRESENCE
//	          after a restart is how the spine knows the last poll did not
//	          commit, which is the fact D174 requires it to know and forbids
//	          the connector from discovering for itself.
//	IDs     — the event ids that attempt was about to publish.
//
// # Why the ids are written BEFORE publishing, which looks backwards
//
// Writing them afterwards would record what was published, which is the
// question nobody can answer after a crash. Writing them BEFORE records what
// was AT RISK, and that turns out to be the more useful fact: on restart the
// spine knows the exact set of events that may or may not have reached a
// consumer.
//
// **So the gap marker D174 requires can NAME THE EVENTS rather than describe a
// window.** "Rows between 09:14:02 and 09:14:31 may have been lost" is
// something an operator can do very little with; a list of seven ids is
// something they can go and check.
//
// # The dedupe set is bounded by ONE BATCH, and that is a correction
//
// D240 named the trigger for an eventual embedded store as "D170's dedupe
// record outgrowing a whole-file rewrite", reading D170's phrase "a durable
// record of what we have already ingested" at its widest. **Building it shows
// that set never needs to be wide.** A cursor that only moves forward means
// rows behind it are never returned again, so the only ids worth remembering
// are the ones inside the uncommitted window — bounded by the poll's `limit`,
// not by how much has ever been ingested.
//
// **What could still grow is a LOOKBACK**: a source with late-arriving rows
// re-reads a span it has already passed, and deduplicating that span means
// remembering it. That is the honest trigger, it is per-source rather than
// global, and it is NOT built here (§0 — stated rather than half-built). See
// D243.
//
// # Failure directions (D150)
//
// Cannot WRITE, so a poll cannot record its attempt: **the poll fails.** A
// cursor that evaporates makes the next tick re-read the world, and an attempt
// nobody recorded is a crash whose losses cannot be named.
//
// Cannot LOAD at start: **the boot fails.** An absent cursor is not a degraded
// start — it is every source replayed from its beginning, which for a
// watermark poller is the whole table.
//
// DESIGN.md references: §4.2.1, §5.2.2, §12 P3, D53, D145, D150, D170, D173,
// D174, D240, D243.
package cursor

import (
	"context"
	"time"
)

// State is everything remembered about one source.
//
// The zero value is a source that has never been polled: no cursor, no
// attempt. That is deliberately indistinguishable from "polled and returned
// nothing at position zero", because both mean the same thing to the next
// tick — start from the source's own beginning.
type State struct {
	// Cursor is the last COMMITTED position, in whatever encoding the source
	// uses. Opaque here on purpose: a watermark timestamp, a changelog token
	// and a row id are all strings, and the moment the spine parses one it has
	// acquired vendor knowledge that belongs in the connector (D171).
	Cursor string `json:"cursor,omitempty"`

	// Pending is an attempt started and not committed. Non-nil after a restart
	// means the last poll did not finish, which is the ONLY way the spine can
	// know that (D174) — and it must know it without the connector reading
	// anything, because a connector with read access to Sekizui's records is an
	// attack surface in a component designed to be third-party-written (D35).
	Pending *Attempt `json:"pending,omitempty"`

	// LastPoll is when the schedule last STARTED a poll of this source,
	// productive or not (CONTRACTS 134). The runner's first poll after a start
	// is due one interval after it — so a restart neither delays the cadence
	// nor adds a poll, and a source whose interval is longer than the deploy
	// cadence still polls.
	//
	// **omitzero**, so a source that was never polled writes no field at all
	// rather than year one (GO-PRIMER §15at).
	LastPoll time.Time `json:"last_poll,omitzero"`
}

// Attempt is a poll that was recorded and has not yet been committed.
type Attempt struct {
	// From is the cursor the attempt started at, so a recovery re-polls the
	// same window rather than guessing.
	From string `json:"from"`

	// To is the cursor the source returned, which becomes Cursor on commit.
	To string `json:"to"`

	// IDs are the event ids this attempt was about to publish.
	//
	// AT RISK, not published — see the package comment. On restart these are
	// the events that may or may not have reached a consumer, and the two
	// things the spine does with them are both worth having: skip them, so a
	// re-poll cannot duplicate; and name them in the gap marker, so the loss is
	// enumerated rather than described.
	IDs []string `json:"ids,omitempty"`

	// Published is how many of IDs, in order, have been published — written
	// durably AFTER each one (D275). On restart it splits the at-risk set in
	// two: IDs[:Published] reached the bus, IDs[Published:] did not, except
	// that the one envelope in flight at the crash may have been published and
	// not yet marked. So recovery can publish EXACTLY the rest for a source
	// that can re-read its window — at most that one envelope twice, never one
	// lost — and a gap marker can name exactly what was lost for one that
	// cannot. Before D275 the runner skipped every at-risk id and recorded
	// nothing, while its own comment claimed the opposite.
	Published int `json:"published,omitempty"`

	// At is when the attempt was recorded. Present so an operator reading a
	// stale pending entry can tell a crash thirty seconds ago from one last
	// Tuesday; nothing branches on it.
	At time.Time `json:"at"`
}

// Store is durable poll state, one entry per source.
//
// **SINGLE-WRITER, AND THAT LIMIT IS INHERITED RATHER THAN INTRODUCED.** A
// file-backed cursor is single-writer exactly like the withdrawal store, so it
// carries CONTRACTS 41's limitation by construction — and §5.2.3 already says a
// poller at N replicas fights itself and needs leader election or sharding,
// which is P8's. Choosing a local file does not create that limit; it keeps it
// visible in the same place as the others, rather than behind a library that
// looks like it solved something.
type Store interface {
	// Load returns the state for a source. A source never polled returns the
	// zero State and no error; an unreadable one returns an error, and the
	// caller is boot.
	Load(ctx context.Context, source string) (State, error)

	// Begin records an attempt, durably, BEFORE its events are published.
	//
	// Returning an error must fail the poll. An attempt nobody recorded is one
	// whose losses cannot be named afterwards, which is the whole mechanism.
	Begin(ctx context.Context, source string, a Attempt) error

	// Commit advances the cursor and clears the pending attempt, in one atomic
	// replacement — never two writes, or a crash between them invents a state
	// the machine has no meaning for.
	Commit(ctx context.Context, source string, cursor string) error

	// Progress records that the pending attempt's first n ids are published
	// (D275). Durable before it returns: it is the mark recovery trusts.
	Progress(ctx context.Context, source string, published int) error

	// Polled records that a scheduled poll of source started at `at`
	// (CONTRACTS 134). Called on EVERY tick, empty or not — recorded only on a
	// productive poll, a quiet source's time would go stale and a restart
	// would poll at once, which is the bug this exists to remove, with extra
	// steps. It preserves the cursor and any pending attempt.
	Polled(ctx context.Context, source string, at time.Time) error
}
