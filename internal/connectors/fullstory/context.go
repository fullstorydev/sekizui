package fullstory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// ActionSessionEvents reads the most recent events of one session (D270).
//
// **THE READ-BACK P2 NEVER HAD.** `POST /v2/events` answers `200 {}` with no
// identifier and `GET /v2/events` is 405 (D224), so a governed write could be
// confirmed only by a human in the UI. Generate Context — `POST
// /v2/sessions/{session_id}/context`, confirmed live on 2026-09-23 — returns a
// session's events INCLUDING server-side custom ones, with their properties,
// so a write's run stamp can be found again. A POST that reads: non-mutating,
// served by Query, retryable (D113).
const ActionSessionEvents = "fullstory.session_events"

// SessionEventType is the row type the read yields (D41, D88).
const SessionEventType = "fullstory.session_event.v1"

// maxSessionEvents bounds one read. The endpoint takes an event_limit, and a
// caller-chosen number with no ceiling is `review five million` again (D257).
const maxSessionEvents = 200

// defaultSessionEvents is the read's size when the caller names none — one
// statement, shared by the driver and its declared Bound (D283).
const defaultSessionEvents = 50

// SettingCustomEvents names the org's CUSTOM events a target fetches (D279):
// comma-separated, exactly as the org named them ("Added to Cart,Video Watched").
//
// **AN ALLOWLIST, SENT TO THE VENDOR.** Generate Context takes `include_types`,
// and every other event type is never returned — confirmed live 2026-09-23 for
// standard and custom names alike. So a custom event not listed here never
// leaves Fullstory; an org with hundreds of them fetches the few it asked for.
// `exclude_types` exists too and is deliberately unused: it would admit every
// custom event an org adds tomorrow, which is plugging in and hoping.
//
// THIS IS GENERATE CONTEXT'S BEHAVIOUR, and this driver's alone. The spine
// knows only that the session_event family admits other kinds open; which
// other kinds exist to be admitted is decided here, per target.
const SettingCustomEvents = "custom_events"

// excludedContext is every context group Generate Context can omit. None is
// read by anything this driver returns, and the user group carries the
// person's name and email, so none is FETCHED: the vendor never sends it
// (confirmed live 2026-09-23, `context.exclude`).
var excludedContext = []string{"user", "org", "location", "device"} //nolint:gochecknoglobals // immutable request constant

// builtinKinds are the standard event kinds this connector's schema declares —
// read from the embedded schema, so the kinds fetched and the kinds declared
// are one list.
var builtinKinds = sync.OnceValues(func() ([]string, error) { //nolint:gochecknoglobals // parsed once from the embedded file
	schemas, err := connector.ParseSchemas(schemasYAML)
	if err != nil {
		return nil, err
	}
	for _, s := range schemas {
		if s.Type == SessionEventType && s.Family != nil {
			kinds := make([]string, 0, len(s.Family.Kinds))
			for k := range s.Family.Kinds {
				kinds = append(kinds, k)
			}
			sort.Strings(kinds)
			return kinds, nil
		}
	}
	return nil, fmt.Errorf("the embedded schemas declare no %s family", SessionEventType)
})

// fetchedTypes is what a target's context reads ask for: the declared standard
// kinds and the custom events the target lists.
func fetchedTypes(op string, t connector.Target) ([]string, map[string]bool, error) {
	kinds, err := builtinKinds()
	if err != nil {
		return nil, nil, fault.Wrap(fault.KindInternal, op, "reading this connector's own schemas", err)
	}
	types := append([]string(nil), kinds...)
	for _, c := range strings.Split(t.Setting(SettingCustomEvents), ",") {
		if c = strings.TrimSpace(c); c != "" {
			types = append(types, c)
		}
	}
	allowed := make(map[string]bool, len(types))
	for _, k := range types {
		allowed[k] = true
	}
	return types, allowed, nil
}

// contextResponse is the part of the confirmed response this action uses.
//
// **ONLY THE EVENTS.** The response also carries org, user, location and
// device context — the user's name and email among them — and none of it is
// what a read-back asks. Not decoding it keeps it out of the rows, out of the
// audit detail, and out of every lens's problem.
type contextResponse struct {
	ContextData struct {
		Context struct {
			SessionID string `json:"session_id"`
		} `json:"context"`
		Pages []struct {
			URL    string `json:"url"`
			Events []struct {
				Type        string         `json:"type"`
				Description string         `json:"description"`
				Timestamp   string         `json:"timestamp"`
				Properties  map[string]any `json:"properties"`
			} `json:"events"`
		} `json:"pages"`
	} `json:"context_data"`
}

// sessionEvents performs the read, borrowed from the pool like every call.
func (d *Driver) sessionEvents(ctx context.Context, t connector.Target, args map[string]any) (
	connector.Rows, error) {

	const op = "fullstory.Query"

	session, _ := args["session_id"].(string)
	if session == "" {
		return connector.Rows{}, fault.New(fault.KindInvalidArgument, op,
			"fullstory.session_events needs a session_id in the `user:session` form")
	}
	limit := defaultSessionEvents
	if n, ok := args["event_limit"].(float64); ok {
		limit = int(n)
	}
	if limit < 1 || limit > maxSessionEvents {
		return connector.Rows{}, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"event_limit %d is outside 1..%d", limit, maxSessionEvents))
	}
	if err := connector.AssertTenant(ctx, t); err != nil {
		return connector.Rows{}, err
	}

	types, allowed, err := fetchedTypes(op, t)
	if err != nil {
		return connector.Rows{}, err
	}
	var resp contextResponse
	work := func(ctx context.Context, _ any) error {
		var err error
		resp, err = d.readContext(ctx, op, t, session, map[string]any{"mode": "LAST", "event_limit": limit}, types)
		return err
	}
	if d.pool == nil {
		err = work(ctx, nil)
	} else {
		err = d.pool.Do(ctx, t, work)
	}
	if err != nil {
		return connector.Rows{}, err
	}

	var rows []map[string]any
	returned := 0
	for _, p := range resp.ContextData.Pages {
		returned += len(p.Events)
		for _, e := range p.Events {
			// DEFENCE IN DEPTH: the vendor was asked for these types only, and
			// anything else it returns is dropped here rather than trusted.
			if !allowed[e.Type] {
				continue
			}
			rows = append(rows, sessionEvent(session, p.URL, e.Type, e.Description, e.Timestamp, e.Properties))
		}
	}
	// **A LAST READ THAT FILLED ITS LIMIT MAY NOT BE THE SESSION (D300).**
	// Generate Context returns the session's LAST `event_limit` events, so a
	// full slice means earlier events may exist; a short one is the whole
	// session. Said on the result, so a seiren's window can say it too — "no
	// login in these 200 events" must not read as "no login in this session".
	return connector.Rows{Rows: rows, Truncated: returned >= limit}, nil
}

// sessionEvent is fullstory.session_event.v1 — ONE type for every event kind,
// shaped the way Fullstory's own event-centric export shapes an event (the maintainer,
// D276): `event_type` says what kind it is and `event_properties` carries its
// data, so a new kind is a new value rather than a new schema. The ids are
// the `device:session` pair split apart and kept as STRINGS: the export calls
// them int64, and above 2^53 a JSON number would round them (D265).
func sessionEvent(session, pageURL, kind, description, at string, props map[string]any) map[string]any {
	device, sess, _ := strings.Cut(session, ":")
	return map[string]any{
		"device_id":        device,
		"session_id":       sess,
		"event_time":       at,
		"event_type":       kind,
		"event_properties": props,
		"description":      description,
		"page_url":         pageURL,
	}
}

// readContext is ONE Generate Context call, inside a borrowed context — shared
// by the session_events read and the events poll, so the session id's %3A and
// the response's decoding live in one place.
//
// THE ID MUST CARRY %3A FOR ITS COLON, which the vendor states and
// url.PathEscape does not do: a colon is legal in a path segment.
//
// **WHAT IS NOT ASKED FOR IS NOT SENT (D279).** `events.include_types` is the
// target's allowlist and `context.exclude` drops every context group — so the
// user's name and email, and every custom event the target did not list, stay
// at the vendor. Note the slice's `event_limit` counts AFTER the type filter
// (confirmed live), which is what makes a filtered poll's limit mean what it
// says.
func (d *Driver) readContext(ctx context.Context, op string, t connector.Target, session string,
	slice map[string]any, types []string) (contextResponse, error) {

	body, _ := json.Marshal(map[string]any{
		"slice":   slice,
		"events":  map[string]any{"include_types": types},
		"context": map[string]any{"exclude": excludedContext},
	})
	raw, err := d.send(ctx, op, t, epSessionContext,
		[]string{strings.ReplaceAll(url.PathEscape(session), ":", "%3A")}, "", body)
	if err != nil {
		return contextResponse{}, err
	}
	var resp contextResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return contextResponse{}, fault.Wrap(fault.KindTargetError, op,
			"the context response is not the documented shape", err)
	}
	return resp, nil
}
