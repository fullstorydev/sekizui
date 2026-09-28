package kata

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// This file is `kata`'s afferent half: the FORM a source connector fills in
// (D176, D243).
//
// **THE SHAPE IS THE DELIVERABLE HERE, more than the behaviour.** The maintainer's
// ruling at D243: connectors are not this project's bread and butter, somebody
// will write a broken one and deploy it, and what decides whether that melts
// the system is how well the spine is designed — not how good our connectors
// are. So this file is written to be COPIED, and the things a real driver must
// never copy are marked where they are declared, as `FailKey` already is.
//
// # EXEMPLARY — copy these
//
// A Source is a PURE FUNCTION of (target, cursor, limit). No table is held
// here, no offset is remembered, nothing accumulates: rows are DERIVED from
// the cursor, so re-polling the same cursor returns the same rows by
// construction rather than by luck. That is what makes the driver stateless
// under D4 and shareable across tenants, and it is also — for free — the
// property D174 calls re-queryability.
//
// `Recovery` reads the TARGET rather than answering for the driver, which is
// D171's layering: the deployment declares the facts about this particular
// system, the connector interprets them, the spine acts on the answer.
//
// # TEST-DOUBLE ONLY — never copy these
//
// Every `_misbehave_*` setting below. A real source has an upstream that
// misbehaves on its own and must not accept configuration asking it to. They
// exist because D243's right-hand column — the runtime bounds that make the
// spine formidable against a driver nobody vetted — can only be proven against
// a source that actually does those things, and P3 exit criterion 6 needs a
// source "deliberately made hostile".

// Reserved TARGET SETTINGS that make this source misbehave.
//
// **TEST-DOUBLE ONLY — DO NOT COPY THESE INTO A REAL CONNECTOR.** Same
// demarcation as FailKey and for the same reason (D176): without it, the first
// thing a connector author copies is the failure injector.
//
// They are settings rather than arguments because `Poll` takes no argument map
// — the principle they preserve is the one the package comment states, that
// behaviour comes from INPUTS and never from state the driver accumulates.
const (
	// SettingRows is the size of the synthetic table. Not a misbehaviour: an
	// ordinary source has a size, and without one this source is simply idle.
	SettingRows = "kata_rows"

	// SettingRecovery declares what re-querying can do here: "unable" or
	// "requery". Absent means requery, because a derived table genuinely is
	// re-queryable — see Recovery for why the DEFAULT differs from the zero
	// value of the type.
	SettingRecovery = "kata_recovery"

	// MisbehaveStallCursor returns rows while handing back the cursor it was
	// given. **THE MELT (D243)**: a poller that believes it re-ingests the same
	// window every tick, for ever, writing an audit record each time.
	MisbehaveStallCursor = "_misbehave_stall_cursor"

	// MisbehaveOverLimit returns more events than `limit` asked for.
	MisbehaveOverLimit = "_misbehave_over_limit"

	// MisbehaveDuplicateIDs repeats an id within one batch.
	MisbehaveDuplicateIDs = "_misbehave_duplicate_ids"

	// MisbehaveEmptyID returns an event with no id at all, which is the one
	// field the spine needs to name a loss or skip a re-delivery.
	MisbehaveEmptyID = "_misbehave_empty_id"

	// MisbehaveBlock blocks until the context is done, for proving the
	// per-poll deadline is the spine's and not the driver's good manners.
	MisbehaveBlock = "_misbehave_block"

	// MisbehavePanic panics. A real driver that does this takes the process
	// with it unless the spine is built not to let it.
	MisbehavePanic = "_misbehave_panic"
)

// COMPILE-TIME ASSERTION, not a comment claiming conformance. Without it the
// driver could drift out of `Source` — by a signature change on either side —
// and nothing would say so until a poller failed to find it at runtime, which
// is the type-assertion failure that looks like "this driver is write-only".
var _ connector.Source = (*Driver)(nil)

// epoch is the synthetic table's first row time.
//
// FIXED, NOT time.Now(). Event times reach the envelope and the audit record,
// and a source whose output changes every run cannot be asserted against and
// cannot be re-polled to the same answer — the determinism argument D178 makes
// about truncation, arriving at the other end of the pipe.
var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) //nolint:gochecknoglobals // immutable

// Poll returns rows after cursor, derived rather than stored.
//
// The cursor is the decimal ordinal of the last row returned; empty means the
// beginning. That encoding is the DRIVER's business and the spine never parses
// it (D171) — it is a string to everybody else.
func (d *Driver) Poll(ctx context.Context, t connector.Target, cursor string, limit int) (
	[]connector.RawEvent, string, error,
) {
	const op = "kata.Poll"

	if t.Setting(MisbehavePanic) == "true" {
		panic("kata: deliberate driver panic (" + MisbehavePanic + ")")
	}
	if err := ctx.Err(); err != nil {
		return nil, cursor, fault.Wrap(fault.KindUnavailable, op, "context done before polling", err)
	}
	// THE TENANT ASSERTION IS NOT SKIPPED BECAUSE THIS IS A READ (§6 mechanism
	// 3). D155's whole lesson is that a read path which skips a check becomes a
	// second enforcement path one omission at a time, and the reference driver
	// is the worst possible place to demonstrate the omission.
	if err := connector.AssertTenant(ctx, t); err != nil {
		return nil, cursor, err
	}

	from, err := parseCursor(op, cursor)
	if err != nil {
		return nil, cursor, err
	}
	total := settingInt(t, SettingRows)

	n := limit
	if over := settingInt(t, MisbehaveOverLimit); over > 0 {
		n += over
	}

	// **THE POLL BORROWS ITS CLIENT FROM THE POOL, EXACTLY AS Execute DOES
	// (D128), AND IT DID NOT UNTIL P3 STEP 33.**
	//
	// `internal/kyuushin`'s package documentation states this as a property of
	// the afferent design, in as many words: *"it borrows its client from the
	// pool rather than holding one: a poller with a private client is
	// invisible to revocation, and `revoke_credential` would evict the pool,
	// report what it cancelled, and leave an in-flight poll running on a
	// compromised credential."* **`Execute` below has borrowed since item 35;
	// this did not**, so the sentence was true of the efferent plane and false
	// of the one it was written about — and `hako/solution`, the reference
	// CONNECTOR, borrows correctly, so the worked form was right and the
	// reference DRIVER was the copy everybody reads.
	//
	// **WHAT IT COSTS TO OMIT IS NOT A TIDINESS POINT.** `revoke_credential`
	// cancels the contexts the pool is holding; a poll that never borrowed is
	// not holding one, so break-glass evicts an empty set for this target and
	// truthfully reports cancelling nothing while the poll keeps running on
	// the credential an operator has just declared compromised. That is
	// CONTRACTS item 35's defect, on the plane that repeats on a timer.
	//
	// THE CALLBACK'S ctx IS THE ONE REVOCATION CANCELS, so the rows are
	// generated inside it rather than after it — passing the outer ctx to the
	// work would make revocation cancel nothing while still reporting success,
	// which is why D128 made this a call-through rather than a checkout.
	var events []connector.RawEvent
	work := func(ctx context.Context, _ any) error {
		// **BLOCKING HAPPENS INSIDE THE BORROW, and it used to happen before
		// it.** A real source blocks on the network call, which is the moment
		// the client is held — so a fixture that blocked before borrowing
		// modelled the one state that cannot occur, and P3 step 33's whole
		// claim is about what happens to a poll that is holding one.
		if t.Setting(MisbehaveBlock) == "true" {
			<-ctx.Done()
			return fault.Wrap(fault.KindUnavailable, op,
				"blocked until the borrowed context was cancelled", ctx.Err())
		}
		for i := from; i < from+n && i < total; i++ {
			if err := ctx.Err(); err != nil {
				return fault.Wrap(fault.KindUnavailable, op,
					"the borrowed context was cancelled mid-poll", err)
			}
			events = append(events, d.row(t, i))
		}
		return nil
	}
	if d.pool == nil {
		// No pool wired: still correct, still governed, but nothing to revoke
		// through. Explicit rather than silent, for Execute's reason — "the
		// driver worked" and "the driver was reachable by break-glass" must
		// not look the same.
		if err := work(ctx, nil); err != nil {
			return nil, cursor, err
		}
	} else if err := d.pool.Do(ctx, t, work); err != nil {
		return nil, cursor, err
	}

	if len(events) == 0 {
		return nil, cursor, nil
	}

	if t.Setting(MisbehaveDuplicateIDs) == "true" {
		events[len(events)-1].ID = events[0].ID
	}
	if t.Setting(MisbehaveEmptyID) == "true" {
		events[0].ID = ""
	}

	next := strconv.Itoa(from + len(events))
	if t.Setting(MisbehaveStallCursor) == "true" {
		next = cursor
	}
	return events, next, nil
}

// Recovery declares what a re-query can do for THIS target.
//
// **THE DEFAULT IS `RecoveryRequery` AND THE ZERO VALUE IS `RecoveryUnable`,
// which is not a contradiction.** D241 orders the constants so that a struct
// nobody filled in reads as "I cannot recover" — that protects the forgetful.
// This driver is not forgetful: it KNOWS its rows are derived from the cursor,
// so a window re-polled returns the same rows, and saying otherwise would make
// every kata crash write a gap marker for data that was never at risk. A
// driver that can answer should answer.
func (d *Driver) Recovery(t connector.Target) connector.RecoveryPolicy {
	if t.Setting(SettingRecovery) == "unable" {
		return connector.RecoveryPolicy{
			Mode: connector.RecoveryUnable,
			// NAMES THE THING TO CHANGE, not the state. It lands in the gap
			// marker, which exists so somebody can act on the loss (D241).
			Why: "this target is configured to model a source whose window cannot be " +
				"re-read — set " + SettingRecovery + " to `requery` if it can",
		}
	}
	return connector.RecoveryPolicy{
		Mode: connector.RecoveryRequery,
		// Zero MaxLookback: no retention bound, and "no bound" rather than
		// "a bound of zero" (D241). A derived table does not forget.
		Why: "rows are derived from the cursor, so the same window always returns the same rows",
	}
}

// row builds one synthetic event. Deterministic in (target, ordinal).
func (d *Driver) row(t connector.Target, i int) connector.RawEvent {
	return connector.RawEvent{
		// THE REF IS IN THE ID so two targets served by one driver cannot
		// produce colliding ids — the same mistake the cursor store's filename
		// escaping avoids, one layer up.
		ID:   fmt.Sprintf("%s#%d", t.Ref(), i),
		Type: "kata.row.v1",
		// THE ENTITY, NOT A ROUTING KEY (D258). This was the constant
		// "kata.row", written so a subscription to `kata.>` would match on the
		// field the bus wrongly routed on — and this is the driver people copy.
		Subject: fmt.Sprintf("row/%d", i),
		At:      epoch.Add(time.Duration(i) * time.Second),
		Data: map[string]any{
			"ordinal": i,
			"ref":     t.Ref(),
		},
	}
}

func parseCursor(op, cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(cursor)
	if err != nil || n < 0 {
		// A DRIVER REFUSES A CURSOR IT DID NOT MINT rather than starting over.
		// Starting over is the failure mode that looks like success: the whole
		// table is re-ingested and every log line reports a healthy poll.
		return 0, fault.New(fault.KindConfig, op,
			fmt.Sprintf("cursor %q was not minted by this driver; refusing rather than "+
				"restarting from the beginning", cursor))
	}
	return n, nil
}

func settingInt(t connector.Target, key string) int {
	n, err := strconv.Atoi(t.Setting(key))
	if err != nil || n < 0 {
		return 0
	}
	return n
}
