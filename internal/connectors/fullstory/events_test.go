package fullstory

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
)

// fixtureEvent is one event the events fixture holds for a session.
type fixtureEvent struct{ Type, Timestamp string }

// eventsFixture serves `GET /sessions/v2` (the given sessions, all for uid
// 1509793) and Generate Context for each, honouring the slice the way the
// poll depends on: FIRST or TIMESTAMP, then the EARLIEST `event_limit` events.
//
// **`start_timestamp` IS MODELLED AS EXCLUSIVE — the worse case**, because the
// vendor does not say and the poll must be right either way. The timestamps
// are served exactly as given, so a test can mix precisions the vendor emits.
//
// **AND IT FILTERS AS THE VENDOR DOES (D279):** only `events.include_types` are
// returned, with `event_limit` counted after the filter, and a request that
// does not exclude the user context is refused — so a driver that stopped
// asking for less would fail here, not in production.
func eventsFixture(t *testing.T, sessions map[string][]fixtureEvent) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/sessions/v2" {
			if r.URL.Query().Get("uid") != "1509793" {
				http.Error(w, "wrong uid", http.StatusBadRequest)
				return
			}
			var list []map[string]string
			for id := range sessions {
				user, sess, _ := strings.Cut(id, ":")
				list = append(list, map[string]string{"userId": user, "sessionId": sess,
					"createdTime": "1789032077", "fsUrl": "u"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sessions": list})
			return
		}
		id, ok := strings.CutPrefix(r.URL.EscapedPath(), "/v2/sessions/")
		id, ok2 := strings.CutSuffix(id, "/context")
		id = strings.Replace(id, "%3A", ":", 1)
		evs, known := sessions[id]
		if r.Method != http.MethodPost || !ok || !ok2 || !known {
			http.Error(w, "not a known session's context", http.StatusNotFound)
			return
		}
		var body struct {
			Slice struct {
				Mode       string `json:"mode"`
				Start      string `json:"start_timestamp"`
				EventLimit int    `json:"event_limit"`
			} `json:"slice"`
			Events struct {
				IncludeTypes []string `json:"include_types"`
			} `json:"events"`
			Context struct {
				Exclude []string `json:"exclude"`
			} `json:"context"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if !slices.Contains(body.Context.Exclude, "user") {
			http.Error(w, "the user context was not excluded", http.StatusBadRequest)
			return
		}
		ordered := slices.Clone(evs)
		sort.SliceStable(ordered, func(i, j int) bool {
			return mustTime(t, ordered[i].Timestamp).Before(mustTime(t, ordered[j].Timestamp))
		})
		var out []map[string]any
		for _, e := range ordered {
			if !slices.Contains(body.Events.IncludeTypes, e.Type) {
				continue
			}
			switch body.Slice.Mode {
			case "FIRST":
			case "TIMESTAMP":
				if !mustTime(t, e.Timestamp).After(mustTime(t, body.Slice.Start)) {
					continue
				}
			default:
				http.Error(w, "want FIRST or TIMESTAMP, got "+body.Slice.Mode, http.StatusBadRequest)
				return
			}
			if len(out) == body.Slice.EventLimit {
				break
			}
			out = append(out, map[string]any{"type": e.Type, "timestamp": e.Timestamp, "properties": map[string]any{}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"context_data": map[string]any{
			"pages": []any{map[string]any{"url": "https://x", "events": out}}}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("fixture timestamp %q: %v", s, err)
	}
	return at
}

// eventsTarget is an events-polling target listing `custom` as the custom
// events it fetches (D279).
func eventsTarget(t *testing.T, base string, custom ...string) connector.Target {
	t.Helper()
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "fs:events", Kind: Kind, Tenant: "alpha", Residency: "eu", BaseURL: base,
		CredentialVersion: "v1", Credential: connector.Secret("fixture-token"),
		Settings: map[string]string{SettingSessionsUID: "1509793", SettingPoll: "events",
			SettingCustomEvents: strings.Join(custom, ",")},
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tgt
}

// boundarySessions is the case the first version got wrong: `…:05Z` and
// `…:05.5Z` sort the WRONG way as strings, two identical events share an
// instant and a limit of two splits them, and a second session interleaves.
var boundarySessions = map[string][]fixtureEvent{
	"1:2": {
		{"navigate", "2026-09-23T09:00:04.9Z"},
		{"click", "2026-09-23T09:00:05Z"},
		{"click", "2026-09-23T09:00:05Z"},
		{"click", "2026-09-23T09:00:05Z"},
		{"rage-click", "2026-09-23T09:00:05.5Z"},
	},
	"1:3": {
		{"navigate", "2026-09-23T09:00:05.25+00:00"},
		{"click", "2026-09-23T11:00:06+02:00"},
	},
}

// drain polls from the zero cursor until a poll returns nothing, and returns
// every id in delivery order.
func drain(t *testing.T, d *Driver, tgt connector.Target, limit int) []string {
	t.Helper()
	var ids []string
	cursor := ""
	for i := 0; i < 20; i++ {
		events, next, err := d.Poll(tenantCtx("alpha"), tgt, cursor, limit)
		if err != nil {
			t.Fatalf("Poll from %q: %v", cursor, err)
		}
		if len(events) == 0 {
			return ids
		}
		for _, e := range events {
			ids = append(ids, e.ID)
		}
		cursor = next
	}
	t.Fatal("twenty polls did not reach the end of seven events; the cursor is not advancing")
	return nil
}

// TestEventsArriveExactlyOnceAcrossEveryBoundary is the events poll's
// continuity: at every limit, each event arrives once, in time order — across
// mixed precisions, offsets, siblings at one instant split by the limit, and
// two sessions interleaved. Against a fixture whose start_timestamp is
// EXCLUSIVE, which is what the poll's one-millisecond lead is for.
func TestEventsArriveExactlyOnceAcrossEveryBoundary(t *testing.T) {
	fx := eventsFixture(t, boundarySessions)
	d := New(WithHTTPClient(fx.Client()), withServer(fx))
	tgt := eventsTarget(t, fx.URL)
	want := []string{
		"1:2@2026-09-23T09:00:04.9Z@navigate#0",
		"1:2@2026-09-23T09:00:05Z@click#0",
		"1:2@2026-09-23T09:00:05Z@click#1",
		"1:2@2026-09-23T09:00:05Z@click#2",
		"1:3@2026-09-23T09:00:05.25+00:00@navigate#0",
		"1:2@2026-09-23T09:00:05.5Z@rage-click#0",
		"1:3@2026-09-23T11:00:06+02:00@click#0",
	}
	for _, limit := range []int{1, 2, 3, 7, 50} {
		if got := drain(t, d, tgt, limit); !slices.Equal(got, want) {
			t.Errorf("limit %d delivered\n  %v\nwant each event once, in time order\n  %v", limit, got, want)
		}
	}
}

// TestAReReadYieldsTheSameIDs is what `requery` promises (D275): the spine
// re-polls an interrupted window from its starting cursor and skips the ids
// its mark says were published — which is only sound if the same window
// yields the same ids, in the same order. The id is DERIVED (there is no
// vendor id), so this is the derivation being deterministic.
func TestAReReadYieldsTheSameIDs(t *testing.T) {
	fx := eventsFixture(t, boundarySessions)
	d := New(WithHTTPClient(fx.Client()), withServer(fx))
	tgt := eventsTarget(t, fx.URL)
	first, cursor, err := d.Poll(tenantCtx("alpha"), tgt, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, from := range []string{"", cursor} {
		a, na, err := d.Poll(tenantCtx("alpha"), tgt, from, 3)
		if err != nil {
			t.Fatal(err)
		}
		b, nb, err := d.Poll(tenantCtx("alpha"), tgt, from, 3)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.EqualFunc(a, b, func(x, y connector.RawEvent) bool { return x.ID == y.ID }) || na != nb {
			t.Errorf("two reads from cursor %q differ: %v / %v", from, ids(a), ids(b))
		}
	}
	if len(first) != 2 {
		t.Fatalf("%d events for a limit of 2", len(first))
	}
}

func ids(evs []connector.RawEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.ID
	}
	return out
}

// TestAForeignCursorIsRefused: a cursor this source did not write is refused
// by name rather than read as the beginning, which would re-deliver everything.
func TestAForeignCursorIsRefused(t *testing.T) {
	fx := eventsFixture(t, boundarySessions)
	if _, _, err := New(WithHTTPClient(fx.Client()), withServer(fx)).Poll(tenantCtx("alpha"),
		eventsTarget(t, fx.URL), "1789032077|x", 2); err == nil {
		t.Error("a sessions-poll cursor was accepted by the events poll")
	}
}

// TestEventsSourceConformance runs the published source suite against the
// events poll — including `runSourceRecoveryIsTrue`, which holds the `requery`
// it declares to account.
func TestEventsSourceConformance(t *testing.T) {
	fx := eventsFixture(t, boundarySessions)
	spy := conformance.NewPoolSpy()
	conformance.RunSource(t, New(WithHTTPClient(fx.Client()), withServer(fx), WithPool(spy)),
		conformance.SourceCase{Target: eventsTarget(t, fx.URL), Limit: 2, Tenant: "alpha", Pool: spy})
}

// TestLeadInEventsCannotStallThePoll: the slice starts a millisecond before
// the cursor, so events delivered by EARLIER polls can fill it. Then the
// session must be re-read larger, or it contributes nothing and the horizon
// holds it back on every poll — a stall that returns no error, for ever.
func TestLeadInEventsCannotStallThePoll(t *testing.T) {
	sessions := map[string][]fixtureEvent{"1:2": {
		{"a1", "2026-09-23T09:00:04.9994Z"}, {"a2", "2026-09-23T09:00:04.9994Z"},
		{"a3", "2026-09-23T09:00:04.9994Z"}, {"a4", "2026-09-23T09:00:04.9994Z"},
		{"a5", "2026-09-23T09:00:04.9997Z"},
		{"b", "2026-09-23T09:00:05Z"},
		{"c", "2026-09-23T09:00:06Z"},
	}}
	fx := eventsFixture(t, sessions)
	got := drain(t, New(WithHTTPClient(fx.Client()), withServer(fx)), eventsTarget(t, fx.URL, "a1", "a2", "a3", "a4", "a5", "b", "c"), 5)
	if len(got) != 7 || !strings.Contains(got[6], "@c#0") {
		t.Errorf("delivered %v; want all seven, ending with c", got)
	}
}

// TestAnUnadvanceableInstantFailsLoudly: more already-delivered events inside
// the lead-in than one read may hold. The poll cannot advance, and it says so
// rather than returning nothing — a source that reports "no new events" while
// it is stuck is the silent stall D150 rules out.
func TestAnUnadvanceableInstantFailsLoudly(t *testing.T) {
	var evs []fixtureEvent
	customs := []string{"after"}
	for i := 0; i < maxSessionEvents; i++ {
		evs = append(evs, fixtureEvent{fmt.Sprintf("burst%03d", i), "2026-09-23T09:00:04.9995Z"})
		customs = append(customs, fmt.Sprintf("burst%03d", i))
	}
	evs = append(evs, fixtureEvent{"after", "2026-09-23T09:00:06Z"})
	fx := eventsFixture(t, map[string][]fixtureEvent{"1:2": evs})
	d, tgt := New(WithHTTPClient(fx.Client()), withServer(fx)), eventsTarget(t, fx.URL, customs...)
	_, cursor, err := d.Poll(tenantCtx("alpha"), tgt, "", maxSessionEvents)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Poll(tenantCtx("alpha"), tgt, cursor, maxSessionEvents); err == nil ||
		!strings.Contains(err.Error(), "cannot advance") {
		t.Errorf("err = %v; want the poll to fail by name rather than stall", err)
	}
}

// TestAnotherSessionCannotCarryTheCursorPastUnreadEvents is the horizon. Here
// session 1:2's slice fills with the lead-in and one fresh event while it still
// holds a2 at :07 unread; session 1:3's b at :08 is fresh. Delivering b would
// move the cursor to :08 and a2 would never be read.
func TestAnotherSessionCannotCarryTheCursorPastUnreadEvents(t *testing.T) {
	fx := eventsFixture(t, map[string][]fixtureEvent{
		"1:2": {{"x", "2026-09-23T09:00:04.9995Z"}, {"y", "2026-09-23T09:00:05Z"},
			{"a", "2026-09-23T09:00:06Z"}, {"a2", "2026-09-23T09:00:07Z"}},
		"1:3": {{"b", "2026-09-23T09:00:08Z"}},
	})
	got := drain(t, New(WithHTTPClient(fx.Client()), withServer(fx)), eventsTarget(t, fx.URL, "x", "y", "a", "a2", "b"), 2)
	if len(got) != 5 || !strings.Contains(strings.Join(got, " "), "@a2#0") {
		t.Errorf("delivered %v; want all five, a2 included", got)
	}
}

// TestTheLeadInIsFilteredByTimeNotSpelling: an event delivered earlier and
// spelled `…:05Z` falls inside the lead-in of a cursor at `…:05.0005Z`. As
// strings it sorts AFTER the cursor (`Z` > `.`) and would be delivered again.
func TestTheLeadInIsFilteredByTimeNotSpelling(t *testing.T) {
	fx := eventsFixture(t, map[string][]fixtureEvent{"1:2": {
		{"e1", "2026-09-23T09:00:05Z"}, {"e2", "2026-09-23T09:00:05.0005Z"}, {"e3", "2026-09-23T09:00:06Z"},
	}})
	got := drain(t, New(WithHTTPClient(fx.Client()), withServer(fx)), eventsTarget(t, fx.URL, "e1", "e2", "e3"), 1)
	if len(got) != 3 {
		t.Errorf("delivered %v; want e1, e2, e3 once each", got)
	}
}

// TestOnlyWhatTheTargetListsIsFetched is D279 at the driver: the standard
// kinds this connector declares and the custom events the target names are
// ASKED FOR, and nothing else comes back — a custom event the target did not
// list never leaves the vendor, and the user context is never requested (the
// fixture refuses a request that does not exclude it).
func TestOnlyWhatTheTargetListsIsFetched(t *testing.T) {
	fx := eventsFixture(t, map[string][]fixtureEvent{"1:2": {
		{"click", "2026-09-23T09:00:01Z"}, {"Added to Cart", "2026-09-23T09:00:02Z"},
		{"User Login", "2026-09-23T09:00:03Z"},
	}})
	events, _, err := New(WithHTTPClient(fx.Client()), withServer(fx)).Poll(tenantCtx("alpha"),
		eventsTarget(t, fx.URL, "Added to Cart"), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range events {
		got = append(got, e.Data["event_type"].(string))
	}
	if !slices.Equal(got, []string{"click", "Added to Cart"}) {
		t.Errorf("fetched %v; want the standard click and the listed custom event, and not User Login", got)
	}
}

// TestAVendorIgnoringTheFilterIsNotTrusted: were Fullstory to return a type it
// was not asked for, the driver drops it — the request's allowlist is not the
// only thing standing between an unlisted custom event and the bus.
func TestAVendorIgnoringTheFilterIsNotTrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/v2" {
			_, _ = w.Write([]byte(`{"sessions":[{"userId":"1","sessionId":"2","createdTime":"1789032077","fsUrl":"u"}]}`))
			return
		}
		// EVERYTHING, whatever include_types said.
		_, _ = w.Write([]byte(`{"context_data":{"pages":[{"url":"u","events":[` +
			`{"type":"click","timestamp":"2026-09-23T09:00:01Z","properties":{}},` +
			`{"type":"User Login","timestamp":"2026-09-23T09:00:02Z","properties":{"email":"a@b.c"}}]}]}}`))
	}))
	defer srv.Close()
	events, _, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Poll(tenantCtx("alpha"), eventsTarget(t, srv.URL), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Data["event_type"] == "User Login" {
			t.Error("an unlisted custom event the vendor returned anyway was passed on")
		}
	}
	if len(events) != 1 {
		t.Errorf("%d events; want the one click", len(events))
	}
}

// TestEventsPollSpendsWhatItIsPriced — the price the Meter declares is what the
// poll does (D284): one sessions call plus exactly ONE context read per session,
// each asking for the whole bound at once, and never more sessions than the
// target's `sessions_per_poll` — even when the far side returns more.
func TestEventsPollSpendsWhatItIsPriced(t *testing.T) {
	sessions := map[string][]fixtureEvent{}
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("6606828898126528473:%d", 100+i)
		sessions[id] = []fixtureEvent{{"navigate", "2026-09-10T12:00:05Z"}}
	}
	for _, tc := range []struct {
		setting string
		reads   int // context reads the poll may make
	}{
		{"", 5},  // default 20, but only 5 sessions exist
		{"3", 3}, // the fixture returns all 5 regardless; the driver keeps 3
	} {
		t.Run("sessions_per_poll="+tc.setting, func(t *testing.T) {
			srv := eventsFixture(t, sessions)
			var calls, contextReads int
			var limits []int
			inner := srv.Config.Handler
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if strings.HasSuffix(r.URL.Path, "/context") {
					contextReads++
					var body struct {
						Slice struct {
							EventLimit int `json:"event_limit"`
						} `json:"slice"`
					}
					raw, _ := io.ReadAll(r.Body)
					_ = json.Unmarshal(raw, &body)
					limits = append(limits, body.Slice.EventLimit)
					r.Body = io.NopCloser(strings.NewReader(string(raw)))
				}
				inner.ServeHTTP(w, r)
			})
			d := New(WithHTTPClient(srv.Client()), withServer(srv))
			base := eventsTarget(t, srv.URL)
			settings := map[string]string{SettingSessionsUID: "1509793", SettingPoll: "events"}
			if tc.setting != "" {
				settings[SettingSessionsPerPoll] = tc.setting
			}
			tgt, err := connector.NewTarget(connector.TargetParams{
				Ref: base.Ref(), Kind: Kind, Tenant: "alpha", Residency: "eu", BaseURL: srv.URL,
				CredentialVersion: "v1", Credential: connector.Secret("fixture-token"), Settings: settings,
			})
			if err != nil {
				t.Fatalf("NewTarget: %v", err)
			}
			if _, _, err := d.Poll(tenantCtx("alpha"), tgt, "", 1); err != nil {
				t.Fatalf("Poll: %v", err)
			}
			if contextReads != tc.reads || calls != 1+tc.reads {
				t.Errorf("the poll made %d calls (%d context reads); want 1 + %d. A read per session "+
					"is the price — more is a poll spending what nobody priced", calls, contextReads, tc.reads)
			}
			for _, n := range limits {
				if n != maxSessionEvents {
					t.Errorf("a context read asked event_limit=%d; it asks the whole bound (%d) once, "+
						"or a full slice of seen events costs another call", n, maxSessionEvents)
				}
			}
			price, err := d.Meter().Poll(tgt)
			if err != nil || price < uint64(calls) {
				t.Errorf("the Meter prices this poll at %d (%v) and it made %d calls; a price below "+
					"the spend is the under-count D284 closed", price, err, calls)
			}
		})
	}
}

// TestSessionsPerPollIsBounded — the setting is the price, so a value outside
// 1..maxSessionsPerPoll is refused by name rather than read as something else.
func TestSessionsPerPollIsBounded(t *testing.T) {
	for _, bad := range []string{"0", "-1", "21", "twenty", "3.5"} {
		cfg := connector.Configuration("fs:events", map[string]string{SettingSessionsPerPoll: bad, SettingPoll: "events"})
		if _, err := sessionsPerPoll("test", cfg); err == nil {
			t.Errorf("sessions_per_poll=%q was accepted; it is 1..%d", bad, maxSessionsPerPoll)
		}
		if got := pollCost(cfg); got != 1+maxSessionsPerPoll {
			t.Errorf("an unparseable setting %q priced the poll at %d; price a refusal at its "+
				"worst case, %d", bad, got, 1+maxSessionsPerPoll)
		}
	}
	if got := pollCost(connector.Configuration("fs:sessions", nil)); got != 1 {
		t.Errorf("a sessions poll is one list call; priced at %d", got)
	}
}
