package translate_test

import (
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/internal/translate"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

func target(t *testing.T) connector.Target {
	t.Helper()
	tg, err := connector.NewTarget(connector.TargetParams{
		Ref: "kata:alpha", Kind: "kata", Tenant: "alpha", Residency: "eu",
		BaseURL: "https://alpha.invalid", CredentialVersion: "v1",
		Credential: connector.Secret("tok"),
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tg
}

func raw() connector.RawEvent {
	return connector.RawEvent{
		ID: "kata:alpha#1", Type: "kata.row.v1", Subject: "kata.row",
		At:   time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
		Data: map[string]any{"ordinal": 1.0, "ref": "kata:alpha"},
	}
}

// THE ROOT IS ITS OWN ID, AND THIS IS THE ARM THAT MATTERS. Copying enrichment's
// causation block leaves root_id EMPTY on every ingested event, and every chain
// built on one is then unattributable to its origin — a field populated with
// nothing rather than with something wrong, which is D232's invisible shape.
func TestTheFirstEnvelopeIsItsOwnCausationRoot(t *testing.T) {
	t.Parallel()
	tr, err := translate.New("raw", 4096)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	env, _, err := tr.Translate(raw(), target(t), "env-1", "trace-9", "")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	c := env.GetCausation()
	if c.GetRootId() != "env-1" {
		t.Errorf("root_id is %q, want the envelope's own id — nothing preceded it", c.GetRootId())
	}
	if c.GetParentId() != "" {
		t.Errorf("parent_id is %q; there is no predecessor to name", c.GetParentId())
	}
	if c.GetDepth() != 0 {
		t.Errorf("depth is %d, want 0", c.GetDepth())
	}
	if c.GetProducedBy() != "translator:kata" {
		t.Errorf("produced_by is %q, want translator:<kind>", c.GetProducedBy())
	}
}

// EVERY FIELD THE SPINE OWES, asserted together. A census over Envelope would
// catch these; none exists (D164 is scoped to Decision), so this stands in.
func TestTheSpineStampsWhatOnlyItKnows(t *testing.T) {
	t.Parallel()
	tr, _ := translate.New("raw", 4096)
	env, _, err := tr.Translate(raw(), target(t), "env-1", "trace-9", "")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	for what, got := range map[string]string{
		"source":       env.GetSource(),
		"spec_version": env.GetSpecVersion(),
		"stage":        env.GetStage(),
		"residency":    env.GetResidency(),
		"trace_id":     env.GetTraceId(),
	} {
		if got == "" {
			t.Errorf("%s is empty; absent reads as never-set rather than as wrong", what)
		}
	}
	if env.GetResidency() != "eu" {
		t.Errorf("residency is %q, not the target's — it travels WITH the data (D29)",
			env.GetResidency())
	}
	if env.GetObservedTime() == nil {
		t.Error("observed_time is nil, so the ingest lag cannot be computed")
	}
}

// `time` IS THE SOURCE'S AND `observed_time` IS OURS. Defaulting a missing event
// time to now reports every late arrival as punctual.
func TestTheEventTimeAndTheObservedTimeAreNotConflated(t *testing.T) {
	t.Parallel()
	tr, _ := translate.New("raw", 4096)

	env, _, err := tr.Translate(raw(), target(t), "env-1", "", "")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if env.GetTime().AsTime().Equal(env.GetObservedTime().AsTime()) {
		t.Error("the event time equals the observed time; the gap between them is the ingest lag")
	}

	undated := raw()
	undated.At = time.Time{}
	env, _, err = tr.Translate(undated, target(t), "env-2", "", "")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if env.GetTime() != nil {
		t.Errorf("an event with no time got one (%v). Absence is not a timestamp",
			env.GetTime().AsTime())
	}
}

// D177: an unrepresentable value must SUBSTITUTE, never erase the object.
func TestAnUnrepresentableValueDoesNotEraseTheEnvelope(t *testing.T) {
	t.Parallel()
	tr, _ := translate.New("raw", 4096)

	ev := raw()
	ev.Data = map[string]any{"ok": "kept", "bad": make(chan int)}

	env, report, err := tr.Translate(ev, target(t), "env-1", "", "")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if env.GetData().GetFields()["ok"].GetStringValue() != "kept" {
		t.Error("a representable field was lost because a sibling was not — " +
			"structpb's all-or-nothing failure is exactly what D177 closed")
	}
	if len(report.Substituted) == 0 {
		t.Error("nothing was reported as substituted, so the loss is invisible")
	}
	if _, named := env.GetData().GetFields()[safestruct.UnrepresentableKey]; !named {
		t.Errorf("the substituted paths are not named under %q in the payload itself",
			safestruct.UnrepresentableKey)
	}
}

func TestABudgetIsSpentWhileBuilding(t *testing.T) {
	t.Parallel()
	tr, _ := translate.New("raw", 64)

	ev := raw()
	ev.Data = map[string]any{}
	for i := range 200 {
		ev.Data[string(rune('a'+i%26))+strings.Repeat("x", 40)+string(rune('0'+i%10))] = "value"
	}

	_, report, err := tr.Translate(ev, target(t), "env-1", "", "")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !report.Truncated {
		t.Error("a payload far over budget was not truncated; an event becomes an " +
			"envelope, a record and an fsync, so this is disk amplification (D178)")
	}
}

func TestRefusals(t *testing.T) {
	t.Parallel()

	if _, err := translate.New("", 4096); err == nil {
		t.Error("an empty first stage was accepted; every envelope would land in a " +
			"stage D21's monotonicity check has never heard of")
	}
	if _, err := translate.New("raw", 0); err == nil {
		t.Error("a zero budget was accepted, which makes every envelope empty")
	}

	tr, _ := translate.New("raw", 4096)
	for name, mutate := range map[string]func(*connector.RawEvent){
		"no event id": func(e *connector.RawEvent) { e.ID = "" },
		"no type":     func(e *connector.RawEvent) { e.Type = "" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ev := raw()
			mutate(&ev)
			if _, _, err := tr.Translate(ev, target(t), "env-1", "", ""); err == nil {
				t.Error("accepted")
			}
		})
	}

	ev := raw()
	if _, _, err := tr.Translate(ev, target(t), "", "", ""); err == nil {
		t.Error("an empty envelope id was accepted; it cannot be its own causation root")
	}
}

// A JOB'S RESULTS SHARE ONE CAUSATION ROOT — the job's id — so a caller can
// subscribe on it. A polled event has no such origin and remains its own root,
// which is why no `job_id` field was added to the envelope (D247).
func TestAJobsResultsShareItsIdAsTheirRoot(t *testing.T) {
	t.Parallel()
	tr, _ := translate.New("raw", 4096)

	own, _, err := tr.Translate(raw(), target(t), "env-1", "", "")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if own.GetCausation().GetRootId() != "env-1" {
		t.Errorf("a polled event must be its own root, got %q", own.GetCausation().GetRootId())
	}

	fromJob, _, err := tr.Translate(raw(), target(t), "env-2", "", "job-9")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got := fromJob.GetCausation().GetRootId(); got != "job-9" {
		t.Errorf("a job's result must carry the JOB as its root, got %q — a caller "+
			"subscribing on the root would receive nothing", got)
	}
	if fromJob.GetId() != "env-2" {
		t.Errorf("the envelope lost its own id: %q", fromJob.GetId())
	}
}
