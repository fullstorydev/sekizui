package fullstory

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// SettingPoll chooses what a target's `fullstory.poll` yields (D276): absent,
// the uid's sessions (fullstory.session.v1); "events", their events
// (fullstory.session_event.v1). One poll action per kind is the runner's
// contract, so the TARGET — a fact reviewed in configuration — says which.
const SettingPoll = "poll"

// SettingSessionsPerPoll is how many of the uid's newest sessions one events
// poll reads (D284). Events land in OLD sessions too — P2's server-side events
// were appended to a session created days earlier — so the poll re-reads recent
// sessions from the cursor time rather than only following new ones.
//
// **EVERY SESSION READ IS ONE UPSTREAM CALL**, because Generate Context reads
// one session per request. So this number IS the poll's price, and it is a
// target setting — reviewed beside the budget it spends — rather than a
// constant nobody sees: an operator trades how far back events are noticed
// against how many calls each poll costs, and `PollCost` prices exactly this.
const SettingSessionsPerPoll = "sessions_per_poll"

// maxSessionsPerPoll is the default and the ceiling of SettingSessionsPerPoll.
//
// **A CEILING AT TODAY'S VALUE, NOT A GUESS ABOVE IT.** Twenty is the value
// confirmed live against the sessions endpoint; its own maximum `limit` is not
// documented. A target may narrow it; raising it is a decision that needs a
// live check, not a larger number in a config file.
const maxSessionsPerPoll = 20

// sessionsPerPoll is the target's SettingSessionsPerPoll, or the default.
func sessionsPerPoll(op string, t connector.Configured) (int, error) {
	raw := t.Setting(SettingSessionsPerPoll)
	if raw == "" {
		return maxSessionsPerPoll, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxSessionsPerPoll {
		return 0, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q sets %s=%q; it is a whole number of sessions from 1 to %d, and each one "+
				"is an upstream call on every poll", t.Ref(), SettingSessionsPerPoll, raw, maxSessionsPerPoll))
	}
	return n, nil
}

// pollCost is the Meter's PollCost (D284): the worst case of one poll, in
// calls. The sessions poll is one list. The events poll is that list plus ONE
// context read per session — exactly one, since a read asks for the whole
// bound at once rather than growing a slice. A setting that does not parse is
// priced at the ceiling: the poll itself refuses it, and pricing a refusal at
// its worst case can only over-charge.
func pollCost(t connector.Configured) uint64 {
	if t.Setting(SettingPoll) != "events" {
		return 1
	}
	n, err := sessionsPerPoll("fullstory.PollCost", t)
	if err != nil {
		n = maxSessionsPerPoll
	}
	return 1 + uint64(n)
}

// pollEvents is the second Fullstory source (P3 step 18, D274, D276):
// Generate Context read per session by TIMESTAMP window from the cursor.
//
// **DIFFERENTLY SHAPED FROM THE SESSIONS POLL, WHICH IS ITS POINT.** An event
// stream rather than a list; RFC 3339 times with nanoseconds rather than epoch
// strings; NO vendor event id, so the id is DERIVED — session, time and kind,
// plus an ordinal among identical keys — and because a closed window re-reads
// byte-identical (confirmed live, D274) the same event always gets the same
// id. The cursor is `<event_time>|<ids at that time>`, the sessions poll's
// boundary rule in another unit.
//
// **TIMES ARE COMPARED AS TIMES, NEVER AS STRINGS.** RFC 3339 with nanoseconds
// trims trailing zeros, so `…:05Z` sorts AFTER `…:05.1Z` byte-wise (`Z` > `.`)
// while being earlier — and an offset other than `Z` breaks it the same way.
// The first version compared the strings, which would have dropped or
// re-delivered events at exactly the boundary. The cursor is written in
// `cursorTime`'s fixed width so it cannot be misread either.
func (d *Driver) pollEvents(ctx context.Context, t connector.Target, cursor string, limit int) (
	[]connector.RawEvent, string, error) {

	const op = "fullstory.Poll"
	uid := t.Setting(SettingSessionsUID)
	if uid == "" {
		return nil, cursor, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q polls events and declares no %s, so there is no user whose sessions to read",
			t.Ref(), SettingSessionsUID))
	}
	afterRaw, seenAt, _ := strings.Cut(cursor, "|")
	var after time.Time
	if afterRaw != "" {
		var perr error
		if after, perr = time.Parse(time.RFC3339Nano, afterRaw); perr != nil {
			return nil, cursor, fault.Wrap(fault.KindInvalidArgument, op, fmt.Sprintf(
				"cursor %q is not one this source produced", cursor), perr)
		}
	}
	seen := map[string]bool{}
	for _, id := range strings.Split(seenAt, ",") {
		if id != "" {
			seen[id] = true
		}
	}

	type row struct {
		at time.Time
		ev connector.RawEvent
	}
	var rows []row
	// horizon is the earliest instant past which some session may hold events
	// this poll did not read. Zero means every session was read to its end.
	var horizon time.Time
	types, allowed, terr := fetchedTypes(op, t)
	if terr != nil {
		return nil, cursor, terr
	}
	perPoll, serr := sessionsPerPoll(op, t)
	if serr != nil {
		return nil, cursor, serr
	}
	work := func(ctx context.Context, _ any) error {
		var sessions sessionsResponse
		if err := d.getSessions(ctx, op, t, uid, perPoll, &sessions); err != nil {
			return err
		}
		// **KEPT, NOT TRUSTED (D284).** The poll is priced at one context read
		// per session asked for; a vendor — or anything between — returning
		// more than `limit` would otherwise make it spend calls nobody priced.
		// The endpoint lists newest first, so the first perPoll are the ones
		// asked for.
		if len(sessions.Sessions) > perPoll {
			sessions.Sessions = sessions.Sessions[:perPoll]
		}
		for _, s := range sessions.Sessions {
			session := s.UserID + ":" + s.SessionID
			fresh, last, full, err := d.readSessionAfter(ctx, op, t, session, after, seen, types, allowed)
			if err != nil {
				return err
			}
			for _, e := range fresh {
				rows = append(rows, row{at: e.At, ev: e})
			}
			if full && (horizon.IsZero() || last.Before(horizon)) {
				horizon = last
			}
		}
		return nil
	}
	var err error
	if d.pool == nil {
		err = work(ctx, nil)
	} else {
		err = d.pool.Do(ctx, t, work)
	}
	if err != nil {
		return nil, cursor, err
	}
	// **NOTHING PAST THE HORIZON (the loss the boundary test found).** Each
	// session is read to at most a slice. One whose slice came back FULL may
	// hold more events after its last — so delivering another session's later
	// event would move the cursor past them, and they would never be read.
	if !horizon.IsZero() {
		kept := rows[:0]
		for _, r := range rows {
			if !r.at.After(horizon) {
				kept = append(kept, r)
			}
		}
		rows = kept
	}
	if len(rows) == 0 {
		return nil, cursor, nil
	}
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].at.Equal(rows[j].at) {
			return rows[i].at.Before(rows[j].at)
		}
		return rows[i].ev.ID < rows[j].ev.ID
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	events := make([]connector.RawEvent, len(rows))
	newest := rows[len(rows)-1].at
	var atNewest []string
	if newest.Equal(after) {
		for id := range seen {
			atNewest = append(atNewest, id)
		}
	}
	for i, r := range rows {
		events[i] = r.ev
		if r.at.Equal(newest) {
			atNewest = append(atNewest, r.ev.ID)
		}
	}
	sort.Strings(atNewest)
	return events, newest.UTC().Format(cursorTime) + "|" + strings.Join(atNewest, ","), nil
}

// cursorTime is RFC 3339 at a FIXED width — UTC, nine fraction digits — so a
// cursor this source writes has exactly one spelling per instant.
const cursorTime = "2006-01-02T15:04:05.000000000Z07:00"

// readSessionAfter reads one session's events after the cursor: those not yet
// delivered (`fresh`), the instant of the last event the slice held, and
// whether the slice came back FULL — in which case there may be more.
//
// **ONE CALL, THE WHOLE BOUND, EVERY TIME (D284, the maintainer's fix).** This used to
// start at `limit + already-seen` and DOUBLE whenever a full slice held only
// events already delivered — a sound answer to a stall that cost up to nine
// calls per session (1, 2, 4 … 128, 200), so a twenty-session poll could make
// 181 while the meter was about to price it at 21. Asking for the driver's
// ceiling in the payload at once gives the same events with one call: a
// response may be larger, but the meter is calls, the body read is bounded
// (D178), and what the POLL returns is still capped by its limit.
//
// **A FULL SLICE OF ALREADY-DELIVERED EVENTS STILL FAILS BY NAME.** The slice
// starts at (just before) the cursor, so it re-reads the siblings the last
// poll delivered at that instant. Were they to fill the whole bound, this
// session would contribute nothing and — through the horizon — hold every
// other session back on every poll, so the poll fails rather than stalling in
// silence (D257's bound, and D150's direction).
func (d *Driver) readSessionAfter(ctx context.Context, op string, t connector.Target, session string,
	after time.Time, seen map[string]bool, types []string, allowed map[string]bool) (
	fresh []connector.RawEvent, last time.Time, full bool, err error) {

	n := maxSessionEvents
	slice := map[string]any{"mode": "FIRST", "event_limit": n}
	if !after.IsZero() {
		// **ASKED FROM JUST BEFORE THE CURSOR, AND FILTERED HERE.** Whether
		// `start_timestamp` is inclusive is not documented and not yet
		// confirmed. If it were exclusive, siblings sharing the cursor's
		// instant that the last poll's limit cut off would never be read
		// again — a silent loss. Starting a millisecond early makes the
		// answer not matter; the filter below drops what was already seen.
		slice = map[string]any{"mode": "TIMESTAMP",
			"start_timestamp": after.Add(-time.Millisecond).Format(cursorTime), "event_limit": n}
	}
	resp, rerr := d.readContext(ctx, op, t, session, slice, types)
	if rerr != nil {
		return nil, time.Time{}, false, rerr
	}
	fresh, last = nil, time.Time{}
	held := 0
	dup := map[string]int{}
	for _, p := range resp.ContextData.Pages {
		for _, e := range p.Events {
			at, perr := time.Parse(time.RFC3339Nano, e.Timestamp)
			if perr != nil {
				return nil, time.Time{}, false, fault.Wrap(fault.KindTargetError, op, fmt.Sprintf(
					"an event in session %s has timestamp %q, which is not RFC 3339", session,
					e.Timestamp), perr)
			}
			// ASKED FOR THESE TYPES ONLY; anything else is dropped, not
			// trusted — and before it is counted, so the slice's fullness
			// and the ids' ordinals are over the same filtered stream the
			// vendor's event_limit counted.
			if !allowed[e.Type] {
				continue
			}
			held++
			if at.After(last) {
				last = at
			}
			key := session + "@" + e.Timestamp + "@" + e.Type
			id := fmt.Sprintf("%s#%d", key, dup[key])
			dup[key]++
			if at.Before(after) || (at.Equal(after) && seen[id]) {
				continue
			}
			fresh = append(fresh, connector.RawEvent{
				ID: id, Type: SessionEventType, Subject: session, At: at.UTC(),
				Data: sessionEvent(session, p.URL, e.Type, e.Description, e.Timestamp, e.Properties),
			})
		}
	}
	full = held >= n
	if !full || len(fresh) > 0 {
		return fresh, last, full, nil
	}
	return nil, time.Time{}, false, fault.New(fault.KindTargetError, op, fmt.Sprintf(
		"session %s has at least %d events at or just before %s, all already delivered, so "+
			"this poll cannot advance past them within one read's bound", session,
		maxSessionEvents, after.Format(cursorTime)))
}
