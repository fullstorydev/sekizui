package fullstory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// This file is the driver's afferent half: `GET /sessions/v2` for one user,
// as P3's headline poll (D265).
//
// **BUILT AGAINST A LIVE RESPONSE, NOT A GUESS.** The vendor's page does not
// render the response schema; `lexicon/Fullstory.js` documents it, and one
// read against EXAMPLE on 2026-09-23 confirmed it verbatim. That response is
// `testdata/sessions_v2.json`, and it is what the ordinary run's fixture
// serves. Four facts from it are load-bearing below, each marked where it bites.

// ActionPoll is the poll this driver advertises (D196): a grant reads
// "agent:jobs may fullstory.poll fs:sessions" like every other grant.
const ActionPoll = "fullstory.poll"

// SessionType is the payload type every polled session carries (D41, D88).
const SessionType = "fullstory.session.v1"

// SettingSessionsUID names the user whose sessions a target polls.
//
// A TARGET SETTING, NOT A POLL ARGUMENT, because `Poll` takes no argument map
// and the question "whose sessions does this target yield" is a fact about
// the deployment, reviewed in configuration — the same layering kata's
// `kata_rows` follows.
const SettingSessionsUID = "sessions_uid"

var _ connector.Source = (*Driver)(nil)

// sessionsResponse is the documented and confirmed shape.
//
// **EVERY FIELD IS A STRING, AND TWO OF THEM MUST STAY ONE.** `userId` and
// `sessionId` hold integers above 2^53 (6606828898126528473): decoded into a
// float64, as `encoding/json` does for a bare number, they would be silently
// rounded to a different session. They arrive as strings and are carried as
// strings end to end.
type sessionsResponse struct {
	Sessions []struct {
		UserID      string `json:"userId"`
		SessionID   string `json:"sessionId"`
		CreatedTime string `json:"createdTime"`
		FSURL       string `json:"fsUrl"`
	} `json:"sessions"`
}

// Poll returns the user's sessions newer than the cursor, oldest first.
//
// **THE CURSOR IS `<createdTime>|<id>,<id>…`** — the newest second seen and the
// session ids already returned AT that second. The endpoint has no `since`
// parameter; it returns the newest `limit` sessions every time, so the source
// filters, and a bare timestamp would drop the second of two sessions created
// in the same second once the first had been seen. The encoding is the
// driver's business (D171); the spine never parses it.
func (d *Driver) Poll(ctx context.Context, t connector.Target, cursor string, limit int) (
	[]connector.RawEvent, string, error) {

	const op = "fullstory.Poll"

	if err := ctx.Err(); err != nil {
		return nil, cursor, fault.Wrap(fault.KindUnavailable, op, "context done before polling", err)
	}
	// THE TENANT IS ASSERTED ON A READ TOO (§6 mechanism 3, D155).
	if err := connector.AssertTenant(ctx, t); err != nil {
		return nil, cursor, err
	}
	// WHAT THIS TARGET YIELDS IS ITS OWN DECLARATION (D276).
	switch t.Setting(SettingPoll) {
	case "":
	case "events":
		return d.pollEvents(ctx, t, cursor, limit)
	default:
		return nil, cursor, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q sets %s=%q; a Fullstory target polls its sessions (unset) or their "+
				"`events`", t.Ref(), SettingPoll, t.Setting(SettingPoll)))
	}
	uid := t.Setting(SettingSessionsUID)
	if uid == "" {
		return nil, cursor, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"target %q declares no %s, so there is no user whose sessions it yields",
			t.Ref(), SettingSessionsUID))
	}
	after, seen, err := parseSessionCursor(op, cursor)
	if err != nil {
		return nil, cursor, err
	}

	var resp sessionsResponse
	work := func(ctx context.Context, _ any) error {
		return d.getSessions(ctx, op, t, uid, limit, &resp)
	}
	// BORROWED FROM THE POOL, AS Execute DOES (D128, D255): a poll that dials
	// privately is invisible to `revoke_credential`, and a poll repeats.
	if d.pool == nil {
		err = work(ctx, nil)
	} else {
		err = d.pool.Do(ctx, t, work)
	}
	if err != nil {
		return nil, cursor, err
	}

	type row struct {
		at int64
		ev connector.RawEvent
	}
	var rows []row
	for _, s := range resp.Sessions {
		// **`createdTime` IS A STRING OF EPOCH SECONDS**, confirmed live. A value
		// that does not parse is the vendor breaking its contract, and it fails
		// the poll by name rather than becoming time zero — a session placed in
		// 1970 sorts before every cursor and would never be delivered.
		at, perr := strconv.ParseInt(s.CreatedTime, 10, 64)
		if perr != nil {
			return nil, cursor, fault.Wrap(fault.KindTargetError, op, fmt.Sprintf(
				"session %q has createdTime %q, which is not epoch seconds", s.SessionID,
				s.CreatedTime), perr)
		}
		if at < after || (at == after && seen[s.SessionID]) {
			continue
		}
		rows = append(rows, row{at: at, ev: connector.RawEvent{
			ID:   s.SessionID,
			Type: SessionType,
			// THE ENTITY (D258): the session, in the `user:session` form the
			// vendor's own URLs use.
			Subject: s.UserID + ":" + s.SessionID,
			At:      time.Unix(at, 0).UTC(),
			Data: map[string]any{
				"session_id":   s.SessionID,
				"user_id":      s.UserID,
				"created_time": s.CreatedTime,
				"fs_url":       s.FSURL,
				// **THE uid WE ASKED FOR, because the response does not say.**
				// `userId` is Fullstory's internal id; without this a consumer
				// could not join a session back to the identity it was polled for.
				"uid": uid,
			},
		}})
	}
	if len(rows) == 0 {
		return nil, cursor, nil
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].at != rows[j].at {
			return rows[i].at < rows[j].at
		}
		return rows[i].ev.ID < rows[j].ev.ID
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}

	events := make([]connector.RawEvent, len(rows))
	newest := rows[len(rows)-1].at
	var atNewest []string
	if newest == after {
		for id := range seen {
			atNewest = append(atNewest, id)
		}
	}
	for i, r := range rows {
		events[i] = r.ev
		if r.at == newest {
			atNewest = append(atNewest, r.ev.ID)
		}
	}
	sort.Strings(atNewest)
	return events, strconv.FormatInt(newest, 10) + "|" + strings.Join(atNewest, ","), nil
}

// getSessions performs the GET, inside the borrowed context.
func (d *Driver) getSessions(ctx context.Context, op string, t connector.Target, uid string,
	limit int, out *sessionsResponse) error {

	q := url.Values{"uid": {uid}, "limit": {strconv.Itoa(limit)}}
	raw, err := d.send(ctx, op, t, epListSessions, nil, "?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fault.Wrap(fault.KindTargetError, op, "the sessions response is not the documented shape", err)
	}
	return nil
}

// send performs one READ request, inside the borrowed context: the credential
// lent for the header build (D127, D199), a bounded body read (D178), and the
// upstream's status mapped into pkg/fault. Shared by the two reads so the
// lending discipline cannot drift between them; `post` keeps its own because a
// write also places an idempotency key and treats 204 as success.
//
// IT TAKES AN ENDPOINT, NEVER A PATH (D299): the method and path come only from
// a declared entry of `surface`, filled with the caller's already-escaped path
// parameters and followed by an optional query string.
func (d *Driver) send(ctx context.Context, op string, t connector.Target, ep endpoint,
	params []string, query string, body []byte) ([]byte, error) {

	base, err := d.base(op, t)
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, ep.method, base+ep.path(params...)+query, rdr)
	if err != nil {
		return nil, fault.Wrap(fault.KindInvalidArgument, op, "building the request", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := connector.SetAuthorization(req.Header, t, "Basic"); err != nil {
		return nil, fault.Wrap(fault.KindUnauthenticated, op, "the target's credential could not be borrowed", err)
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, transportFault(op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fault.Wrap(fault.KindTargetUnavailable, op, "reading the response body", err)
	}
	if resp.StatusCode >= 300 {
		return nil, upstreamFault(op, resp, raw)
	}
	return raw, nil
}

// parseSessionCursor reads `<createdTime>|<id>,…`. Empty is the beginning.
func parseSessionCursor(op, cursor string) (int64, map[string]bool, error) {
	seen := map[string]bool{}
	if cursor == "" {
		return 0, seen, nil
	}
	ts, ids, _ := strings.Cut(cursor, "|")
	after, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return 0, nil, fault.Wrap(fault.KindInvalidArgument, op, fmt.Sprintf(
			"cursor %q is not one this source produced", cursor), err)
	}
	for _, id := range strings.Split(ids, ",") {
		if id != "" {
			seen[id] = true
		}
	}
	return after, seen, nil
}

// Recovery declares what a re-query can do: nothing reliable (D174, D241).
//
// **UNABLE, AND SAYING SO IS THE POINT.** `GET /sessions/v2` returns the newest
// `limit` sessions with no paging and no `since`. A window re-polled returns
// whatever is newest NOW, so a burst larger than `limit` between polls pushes
// the oldest of it out of reach, and no re-query brings it back. Claiming
// `requery` would have the spine trust a recovery this endpoint cannot perform.
func (d *Driver) Recovery(t connector.Target) connector.RecoveryPolicy {
	// THE EVENTS POLL CAN RE-READ ITS WINDOW, and that was confirmed by
	// looking (D274): the same closed TIMESTAMP window read twice returned
	// byte-identical events. The sessions poll cannot.
	if t.Setting(SettingPoll) == "events" {
		return connector.RecoveryPolicy{
			Mode: connector.RecoveryRequery,
			Why: "Generate Context re-reads a closed TIMESTAMP window byte-identically " +
				"(confirmed live 2026-09-23), so an interrupted window is re-read rather than lost",
		}
	}
	return connector.RecoveryPolicy{
		Mode: connector.RecoveryUnable,
		Why: "GET /sessions/v2 returns only the newest `limit` sessions, with no paging and no " +
			"since parameter, so a window cannot be re-read — raise the poll's limit or shorten " +
			"its interval if sessions arrive faster than one poll can see",
	}
}
