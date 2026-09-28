package notes

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// The afferent half of the reference connector (D243, D244).
//
// **A SOURCE IS OPTIONAL AND MOST CONNECTORS ARE NOT ONE.** A Slack sink, a
// ticket actuator, anything write-only: none of these implements this, and the
// conformance suite is selected separately (`RunSource`) so they are not failed
// for a shape they never claimed.
//
// **THE WHOLE CONTRACT IN ONE SENTENCE: `Poll` is a pure function of (target,
// cursor, limit).** Everything below follows from it. No offset is held, no page
// is remembered, nothing accumulates — which is what keeps the driver stateless
// under D4, and which gives re-queryability (D174) for free rather than as a
// second feature.

// SettingAppendOnly is the TARGET's declaration that its notes are never
// edited in place, so a window re-read returns the same rows.
//
// **DECLARED IN CONFIGURATION, NOT DISCOVERED.** This driver cannot tell an
// append-only deployment of the notes service from one where notes are edited,
// and guessing would be a guarantee invented on the vendor's behalf. D171's
// layering: the TARGET declares the facts, the CONNECTOR interprets them, the
// SPINE acts on the answer and knows neither.
const SettingAppendOnly = "append_only"

var _ connector.Source = (*Driver)(nil)

// Poll returns notes changed after cursor, with the cursor to use next.
//
// The cursor is this driver's own encoding — an RFC3339 timestamp — and NOTHING
// outside this file parses it. The spine treats it as an opaque string and
// compares it only for equality (D243), which is what lets the encoding change
// here without changing anything else.
func (d *Driver) Poll(ctx context.Context, t connector.Target, cursor string, limit int) (
	[]connector.RawEvent, string, error,
) {
	const op = "notes.Poll"

	// HAKO STEP 2: nothing here asserts the tenant, and this is a READ.
	// §6 mechanism 3 is the last check before the wire; D155 is the reminder
	// that a read path skipping a check is how a second enforcement path
	// arrives — one omission at a time, each invisible because the shorter
	// path reads like a shorter version rather than a weaker one.

	since, err := parseCursor(op, cursor)
	if err != nil {
		return nil, cursor, err
	}

	q := url.Values{}
	if !since.IsZero() {
		q.Set("since", since.Format(time.RFC3339Nano))
	}
	q.Set("limit", strconv.Itoa(limit))

	var events []connector.RawEvent
	work := func(ctx context.Context, _ any) error {
		res, callErr := d.send(ctx, op, t, http.MethodGet, "/v1/notes?"+q.Encode(), nil, nil)
		if callErr != nil {
			return callErr
		}
		events, err = notesToEvents(op, t, res.Data)
		return err
	}
	if d.pool == nil {
		if err := work(ctx, nil); err != nil {
			return nil, cursor, err
		}
	} else if err := d.pool.Do(ctx, t, work); err != nil {
		return nil, cursor, err
	}

	// HAKO STEP 2: this driver asks the vendor for `limit` notes and returns
	// whatever it gets. A vendor that ignores the parameter, or a newer API
	// version that changes its default page size, then hands an unbounded page
	// straight through to a caller whose memory budget `limit` WAS.
	//
	// The spine bounds it too, and that is not a reason to leave it — a driver
	// declining to be the reason somebody else's guard has to fire is the
	// difference between a connector that works and one that is safe to run.
	if len(events) == 0 {
		// NO EVENTS, NO MOVEMENT. Returning a "now" cursor for an empty window
		// would skip a note written a millisecond ago and never seen.
		return nil, cursor, nil
	}

	// The next cursor is the LAST event's time, not `now`: anything the server
	// had not committed when it answered must still be reachable.
	return events, events[len(events)-1].At.UTC().Format(time.RFC3339Nano), nil
}

// Recovery says what re-querying can do FOR THIS TARGET.
//
// **THE SUITE CHECKS THIS AGAINST THE BEHAVIOUR** (`runSourceRecoveryIsTrue`),
// so it is a declaration rather than a hint: claim `requery` and you owe the
// same window twice, claim `unable` and you owe an operator the sentence they
// will read in the gap marker.
func (d *Driver) Recovery(t connector.Target) connector.RecoveryPolicy {
	if t.Setting(SettingAppendOnly) != "true" {
		return connector.RecoveryPolicy{
			Mode: connector.RecoveryUnable,
			Why: "this target has not declared `" + SettingAppendOnly + ": \"true\"`, so a note " +
				"edited after we passed its timestamp would be missed on a re-read. Declare it " +
				"if the deployment never edits notes in place",
		}
	}
	return connector.RecoveryPolicy{
		Mode: connector.RecoveryRequery,
		// A REAL RETENTION BOUND, unlike a derived table's. The notes service
		// keeps thirty days; past that a re-query silently returns less than it
		// should, and a bound nobody declared would be discovered as data loss.
		MaxLookback: 30 * 24 * time.Hour,
		Why:         "notes are append-only on this target, and the service serves 30 days of history",
	}
}

func notesToEvents(op string, t connector.Target, data map[string]any) ([]connector.RawEvent, error) {
	raw, _ := data["notes"].([]any)
	out := make([]connector.RawEvent, 0, len(raw))
	for i, item := range raw {
		n, ok := item.(map[string]any)
		if !ok {
			return nil, fault.New(fault.KindTargetError, op, fmt.Sprintf(
				"note at index %d is not an object", i))
		}
		id, _ := n["id"].(string)
		at, _ := n["updated_at"].(string)
		when, err := time.Parse(time.RFC3339Nano, at)
		if err != nil || strings.TrimSpace(id) == "" {
			// REFUSE THE BATCH, NOT THE EVENT, and say which one. An event with
			// no id cannot be named in a gap marker or kept from being
			// re-delivered, and silently dropping it is the selective,
			// invisible loss D177 refuses.
			return nil, fault.New(fault.KindTargetError, op, fmt.Sprintf(
				"note at index %d has an empty id or an unparseable updated_at %q", i, at))
		}
		out = append(out, connector.RawEvent{
			// THE TARGET REF IS IN THE ID. One driver serves many targets, and
			// two notes services both numbering from 1 would otherwise collide
			// in the dedupe record that decides what gets re-delivered.
			ID:      t.Ref() + "#" + id,
			Type:    "notes.note.v1",
			Subject: "notes.note",
			At:      when,
			Data:    n,
		})
	}
	return out, nil
}

func parseCursor(op, cursor string) (time.Time, error) {
	if cursor == "" {
		return time.Time{}, nil
	}
	at, err := time.Parse(time.RFC3339Nano, cursor)
	if err != nil {
		// A CURSOR THIS DRIVER DID NOT MINT IS REFUSED, never treated as the
		// beginning. Starting over is the failure that looks like success: the
		// whole source is re-ingested while every log line reports a healthy poll.
		return time.Time{}, fault.Wrap(fault.KindConfig, op, fmt.Sprintf(
			"cursor %q was not minted by this driver; refusing rather than restarting "+
				"from the beginning", cursor), err)
	}
	return at, nil
}
