package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/internal/translate"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// THE REPLAY PROOF (D298), P5 steps 1-2: reflexes are deterministic, so "enforce
// does what shadow predicted" is proven EXACTLY by running one recording
// through both — not by a calendar week of live traffic.
//
// THE RECORDING IS P4 STEP 18's CAPTURE (the maintainer, 2026-09-27): 148 real session
// events from the maintainers' test org, fetched through the real binary, rows of
// fullstory.session_event.v1 — the type the poller publishes. Each row is
// wrapped here as the poller wraps it: the poller's id scheme, the target the
// suite polls, and Sekizui's own translate.

// replayRule is the actuating bus→driver rule the recording runs through: one
// ticket per rage-click, undebounced, so every rage-click is a firing.
const replayRule = "rage-to-ticket"

// replayEnvelopes wraps the recording's rows into the envelopes the fs:events
// poller would publish.
func replayEnvelopes(t *testing.T, firstStage string) []*sekizuiv1.Envelope {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(mustRoot(t), "internal", "connectors", "fullstory", "testdata", "seiren", "web.json"))
	if err != nil {
		t.Fatalf("the recording (P4 step 18's capture): %v", err)
	}
	var capture struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(raw, &capture); err != nil || len(capture.Rows) == 0 {
		t.Fatalf("the recording has no rows: %v", err)
	}
	target, err := connector.NewTarget(connector.TargetParams{
		Ref: "fs:events", Kind: fullstory.Kind, Tenant: "events", Residency: "us",
		BaseURL: "https://api.fullstory.com", Credential: connector.Secret([]byte("replay")),
	})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := translate.New(firstStage, safestruct.DefaultBudget)
	if err != nil {
		t.Fatal(err)
	}
	var out []*sekizuiv1.Envelope
	dup := map[string]int{}
	for i, row := range capture.Rows {
		session := fmt.Sprint(row["device_id"]) + ":" + fmt.Sprint(row["session_id"])
		stamp, kind := fmt.Sprint(row["event_time"]), fmt.Sprint(row["event_type"])
		at, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			t.Fatalf("row %d: event_time %q: %v", i, stamp, err)
		}
		// THE POLLER'S ID SCHEME (fullstory/events.go): session@time@type#n.
		key := session + "@" + stamp + "@" + kind
		ev := connector.RawEvent{
			ID: fmt.Sprintf("%s#%d", key, dup[key]), Type: fullstory.SessionEventType,
			Subject: session, At: at.UTC(), Data: row,
		}
		dup[key]++
		env, _, err := tr.Translate(ev, target, fmt.Sprintf("01J0REPLAY%04d", i), fmt.Sprintf("%016x", i+1), "")
		if err != nil {
			t.Fatalf("row %d does not translate: %v", i, err)
		}
		out = append(out, env)
	}
	return out
}

// firing is one would-be or actual firing, keyed by its causing envelope.
type firing struct{ cause, action, target string }

// replay runs the recording through replayRule in mode, and returns the rule's
// firings with the run and each outcome's status. A firing the engine REFUSED
// (its budget, say) is an error, not a firing — collected rather than fatal, so
// step 2's comparison names a divergence instead of the first symptom of one.
func replay(t *testing.T, mode string) (*run, []firing, map[string]sekizuiv1.Status) {
	t.Helper()
	r := newRunWith(t, runOpts{patch: func(d *config.Document) {
		d.Reflexes = append(d.Reflexes, config.ReflexSpec{
			Name: replayRule, Principal: "reflex:friction", Enabled: true, Mode: mode,
			MaxFiringsPerHour: 100,
			Consumes:          "sekizui.raw.fullstory.>", ExpectsType: fullstory.SessionEventType,
			Where:  config.Predicate{{Path: "event_type", Op: "eq", Value: "rage-click"}},
			Action: "kata.create_issue", TargetRef: "kata:alpha", With: map[string]any{"project": "PROJ"},
		})
	}})
	if r.localOnly(t, "the reflex engine is this instance's; no governed verb publishes onto its bus (D246)") {
		return nil, nil, nil
	}
	envs := replayEnvelopes(t, r.doc.Stages[0])
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var out []firing
	status := map[string]sekizuiv1.Status{}
	for _, env := range envs {
		for _, o := range r.engine.Dispatch(ctx, env) {
			if o.Rule != replayRule {
				continue
			}
			if o.Err != nil || o.Result == nil {
				t.Errorf("%s (%s) on %s did not fire: %v", replayRule, mode, env.GetId(), o.Err)
				continue
			}
			out = append(out, firing{cause: env.GetId(), action: "kata.create_issue", target: "kata:alpha"})
			status[env.GetId()] = o.Result.GetStatus()
		}
	}
	return r, out, status
}

// rageClicks counts the recording's rage-clicks — the oracle, from the data.
func rageClicks(t *testing.T) int {
	t.Helper()
	n := 0
	for _, env := range replayEnvelopes(t, "raw") {
		if env.GetData().GetFields()["event_type"].GetStringValue() == "rage-click" {
			n++
		}
	}
	return n
}

// p5Step1 — an actuating rule's shadow run over a recorded capture lists the
// firings it would make (D298).
func p5Step1(t *testing.T) {
	r, fired, status := replay(t, "shadow")
	if r == nil {
		return
	}
	r.narrate(t, "an actuating rule's shadow run over a recorded capture lists the firings it would make")
	want := rageClicks(t)
	if want == 0 {
		t.Fatal("step 1: the recording holds no rage-click; the replay would prove nothing")
	}
	if len(fired) != want {
		t.Errorf("step 1: shadow listed %d firing(s); the recording holds %d rage-clicks", len(fired), want)
	}
	for cause, s := range status {
		if s != sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED {
			t.Errorf("step 1: the firing caused by %s came back %v; shadow must not act", cause, s)
		}
	}
	// EVERY RECORD IS WOULD_HAVE_FIRED, NAMES THE RULE AND ITS CAUSE, and none is
	// an ALLOW — nothing reached the driver.
	recorded := map[string]bool{}
	for _, d := range readLog(t, r.path) {
		if d.GetReflexName() != replayRule {
			continue
		}
		if d.GetVerdict() != sekizuiv1.Verdict_VERDICT_WOULD_HAVE_FIRED {
			t.Errorf("step 1: a %s record has verdict %v; a shadow rule acts on nothing", replayRule, d.GetVerdict())
		}
		recorded[d.GetCausation().GetParentId()] = true
	}
	for _, f := range fired {
		if !recorded[f.cause] {
			t.Errorf("step 1: the firing caused by %s has no record naming that cause", f.cause)
		}
	}
	// FOR A REVIEWER: rule, cause, action, target — and nothing else.
	var lines []string
	for i, f := range fired {
		if i == 3 {
			lines = append(lines, fmt.Sprintf("... and %d more", len(fired)-3))
			break
		}
		lines = append(lines, fmt.Sprintf("%s ← %s → %s on %s", replayRule, f.cause, f.action, f.target))
	}
	r.detail(t, "148 recorded events replayed in shadow: %d would-be firings, one per rage-click, every one "+
		"recorded WOULD_HAVE_FIRED with its cause, none acted: %s", len(fired), strings.Join(lines, "; "))
}

// p5Step2 — enforce over the same recording fires exactly what shadow predicted.
func p5Step2(t *testing.T) {
	shadowRun, predicted, _ := replay(t, "shadow")
	if shadowRun == nil {
		return
	}
	r, fired, status := replay(t, "enforce")
	r.narrate(t, "enforce over the same recording fires exactly what shadow predicted")
	key := func(fs []firing) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.cause+" "+f.action+" "+f.target)
		}
		sort.Strings(out)
		return out
	}
	want, got := key(predicted), key(fired)
	onlyShadow, onlyEnforce := diffStrings(want, got), diffStrings(got, want)
	if len(onlyShadow) > 0 || len(onlyEnforce) > 0 {
		t.Errorf("step 2: enforce did not fire what shadow predicted.\n  predicted, not fired: %v\n  fired, not predicted: %v\n"+
			"The engine is deterministic, so any difference is a defect, not traffic (D298)", onlyShadow, onlyEnforce)
	}
	if len(got) == 0 {
		t.Fatal("step 2: nothing fired; agreement over an empty set proves nothing")
	}
	for cause, s := range status {
		if s != sekizuiv1.Status_STATUS_OK {
			t.Errorf("step 2: the enforced firing caused by %s came back %v", cause, s)
		}
	}
	r.detail(t, "the same 148 events in enforce: %d firings, identical to shadow's prediction envelope by envelope, "+
		"every one executed", len(got))
}

// diffStrings is what a holds that b lacks.
func diffStrings(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	return out
}

// p5Step6 — a rage-click burst files one ticket per debounce key per window
// (D30, D333). The recording's burst is 19 rage-clicks inside 1.65 seconds of
// one session. The window is on EVENT time (D333), so the answer is the same
// however fast the burst is delivered or replayed.
func p5Step6(t *testing.T) {
	const rule = "rage-burst-ticket"
	r := newRunWith(t, runOpts{patch: func(d *config.Document) {
		d.Reflexes = append(d.Reflexes, config.ReflexSpec{
			Name: rule, Principal: "reflex:friction", Enabled: true, MaxFiringsPerHour: 100,
			Consumes: "sekizui.raw.fullstory.>", ExpectsType: fullstory.SessionEventType,
			Where:       config.Predicate{{Path: "event_type", Op: "eq", Value: "rage-click"}},
			DebounceKey: "session_id", DebounceWindowSec: 60,
			Action: "kata.create_issue", TargetRef: "kata:alpha", With: map[string]any{"project": "PROJ"},
		})
	}})
	if r.localOnly(t, "the reflex engine is this instance's; no governed verb publishes onto its bus (D246)") {
		return
	}
	r.narrate(t, "a rage-click burst files one ticket per debounce key per window")
	ctx := context.Background()
	count := func(envs []*sekizuiv1.Envelope) (fired, suppressed int) {
		for _, env := range envs {
			for _, o := range r.engine.Dispatch(ctx, env) {
				switch {
				case o.Rule != rule:
				case o.Debounced:
					suppressed++
				case o.Err == nil && o.Result != nil:
					fired++
				default:
					t.Errorf("step 6: %s on %s: %v", rule, env.GetId(), o.Err)
				}
			}
		}
		return fired, suppressed
	}
	envs := replayEnvelopes(t, r.doc.Stages[0])
	clicks := rageClicks(t)

	// 6a — THE RECORDED BURST: one ticket, and every other rage-click counted
	// as suppressed rather than vanishing.
	fired, suppressed := count(envs)
	if fired != 1 || suppressed != clicks-1 {
		t.Fatalf("step 6a: the burst of %d rage-clicks fired %d and suppressed %d; want 1 and %d",
			clicks, fired, suppressed, clicks-1)
	}

	// 6b — A SECOND WINDOW: the same rage-clicks, re-timed 61 seconds later with
	// new ids. DERIVED from the recording, and said so — it holds one burst.
	var later []*sekizuiv1.Envelope
	for i, env := range envs {
		if env.GetData().GetFields()["event_type"].GetStringValue() != "rage-click" {
			continue
		}
		e := proto.Clone(env).(*sekizuiv1.Envelope)
		e.Id = fmt.Sprintf("01J0REPLAYB%04d", i)
		e.Time = timestamppb.New(env.GetTime().AsTime().Add(61 * time.Second))
		later = append(later, e)
	}
	fired2, suppressed2 := count(later)
	if fired2 != 1 || suppressed2 != clicks-1 {
		t.Errorf("step 6b: the burst re-timed past the window fired %d and suppressed %d; want 1 and %d",
			fired2, suppressed2, clicks-1)
	}

	// 6c — DELIVERY SPEED IS NOT AN INPUT: the first burst again, as though the
	// poller delivered it late, is inside its own window and fires nothing.
	if again, _ := count(envs[:1+len(envs)/2]); again != 0 {
		t.Errorf("step 6c: re-delivering the recorded burst fired %d ticket(s); its window is its event time", again)
	}
	r.detail(t, "%d recorded rage-clicks in 1.65s of one session: 1 ticket, %d suppressed and counted; the same "+
		"burst re-timed 61s later (derived): 1 more; re-delivered late: none — the window is event time (D333)",
		clicks, suppressed)
}
