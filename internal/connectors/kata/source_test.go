package kata

import (
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/connector"
)

// sourceTarget is `target` plus settings, which is what the afferent half
// varies. Kept beside the source tests rather than folded into `target`: every
// existing caller passes no settings, and widening a helper used by two dozen
// tests to serve four is how a helper becomes a configuration language.
func sourceTarget(t *testing.T, settings map[string]string) connector.Target {
	t.Helper()
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "kata:alpha", Kind: Kind, Tenant: "alpha", Residency: "eu",
		BaseURL:           "https://alpha.invalid",
		CredentialVersion: "v1", Credential: connector.Secret("fake-token"),
		Settings: settings,
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tgt
}

// merge returns base plus one key. Base is not mutated — the subtests run in
// parallel and share it.
func merge(base map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(base)+1)
	for bk, bv := range base {
		out[bk] = bv
	}
	out[k] = v
	return out
}

// A SOURCE IS A PURE FUNCTION OF (target, cursor, limit), and that is the
// property everything else rests on: it is what makes the driver stateless
// under D4 and what makes re-querying work at all (D174).
func TestPollIsAPureFunctionOfItsInputs(t *testing.T) {
	t.Parallel()
	d := New()
	tgt := sourceTarget(t, map[string]string{SettingRows: "10"})

	first, next1, err := d.Poll(tenantCtx("alpha"), tgt, "", 4)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	second, next2, err := d.Poll(tenantCtx("alpha"), tgt, "", 4)
	if err != nil {
		t.Fatalf("re-poll: %v", err)
	}
	if next1 != next2 || len(first) != len(second) {
		t.Fatalf("the same cursor returned different windows: %d/%q vs %d/%q",
			len(first), next1, len(second), next2)
	}
	for i := range first {
		if first[i].ID != second[i].ID || !first[i].At.Equal(second[i].At) {
			t.Errorf("row %d differs between polls: %+v vs %+v", i, first[i], second[i])
		}
	}
}

func TestPollHonoursTheLimitAndAdvances(t *testing.T) {
	t.Parallel()
	d := New()
	tgt := sourceTarget(t, map[string]string{SettingRows: "10"})

	events, next, err := d.Poll(tenantCtx("alpha"), tgt, "", 4)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("want 4 events, got %d", len(events))
	}
	if next == "" {
		t.Fatal("the cursor did not advance")
	}

	rest, _, err := d.Poll(tenantCtx("alpha"), tgt, next, 100)
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if len(rest) != 6 {
		t.Errorf("want the remaining 6 rows, got %d", len(rest))
	}
	seen := map[string]bool{}
	for _, e := range append(events, rest...) {
		if seen[e.ID] {
			t.Errorf("id %q delivered twice across a well-behaved poll", e.ID)
		}
		seen[e.ID] = true
	}
}

// A DRIVER REFUSES A CURSOR IT DID NOT MINT. Restarting from the beginning is
// the failure that looks like success — the whole table is re-ingested while
// every log line reports a healthy poll.
func TestAnUnmintedCursorIsRefusedRatherThanRestarted(t *testing.T) {
	t.Parallel()
	d := New()
	tgt := sourceTarget(t, map[string]string{SettingRows: "10"})

	events, _, err := d.Poll(tenantCtx("alpha"), tgt, "not-a-cursor", 4)
	if err == nil {
		t.Fatalf("an unmintable cursor was accepted and returned %d events", len(events))
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("the message must say what it refused to do, got %q", err)
	}
}

// RECOVERY IS A PROPERTY OF THE TARGET, not of the driver (D171, D243).
func TestRecoveryIsDeclaredPerTarget(t *testing.T) {
	t.Parallel()
	d := New()

	ok := d.Recovery(sourceTarget(t, nil))
	if ok.Mode != connector.RecoveryRequery {
		t.Errorf("a derived table is re-queryable; got mode %v", ok.Mode)
	}

	unable := d.Recovery(sourceTarget(t, map[string]string{SettingRecovery: "unable"}))
	if unable.Mode != connector.RecoveryUnable {
		t.Fatalf("the target declared `unable` and the driver said %v", unable.Mode)
	}
	if !strings.Contains(unable.Why, SettingRecovery) {
		t.Errorf("Why lands in the gap marker and must name the thing to change, got %q", unable.Why)
	}
}

// THE HOSTILE SETTINGS MUST ACTUALLY MISBEHAVE, or the spine's bounds are
// proven against a source that was never difficult (D243, P3 criterion 6).
func TestTheMisbehavingSettingsMisbehave(t *testing.T) {
	t.Parallel()
	ctx := tenantCtx("alpha")
	d := New()
	rows := map[string]string{SettingRows: "10"}

	t.Run("the cursor stalls while rows keep coming — the melt", func(t *testing.T) {
		t.Parallel()
		tgt := sourceTarget(t, merge(rows, MisbehaveStallCursor, "true"))
		events, next, err := d.Poll(ctx, tgt, "", 4)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if len(events) == 0 {
			t.Fatal("the melt needs rows AND no progress; got no rows")
		}
		if next != "" {
			t.Errorf("want the cursor handed straight back, got %q", next)
		}
	})

	t.Run("more events than the limit asked for", func(t *testing.T) {
		t.Parallel()
		tgt := sourceTarget(t, merge(rows, MisbehaveOverLimit, "3"))
		events, _, err := d.Poll(ctx, tgt, "", 2)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if len(events) <= 2 {
			t.Errorf("want more than the limit of 2, got %d", len(events))
		}
	})

	t.Run("a duplicate id inside one batch", func(t *testing.T) {
		t.Parallel()
		tgt := sourceTarget(t, merge(rows, MisbehaveDuplicateIDs, "true"))
		events, _, err := d.Poll(ctx, tgt, "", 4)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if events[0].ID != events[len(events)-1].ID {
			t.Error("want a repeated id in the batch")
		}
	})

	t.Run("an event with no id at all", func(t *testing.T) {
		t.Parallel()
		tgt := sourceTarget(t, merge(rows, MisbehaveEmptyID, "true"))
		events, _, err := d.Poll(ctx, tgt, "", 4)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if events[0].ID != "" {
			t.Errorf("want an empty id, got %q", events[0].ID)
		}
	})
}

// THE HOSTILE FIXTURE AND THE DETECTOR MUST AGREE, and nothing else in the tree
// checks that they do.
//
// `ValidatePoll` is tested against hand-built responses and the `_misbehave_*`
// settings are tested for misbehaving; each half can be right while the pair is
// useless, if the fixture produces a shape the detector does not look for. This
// is the join, and it is what makes the hostile source a usable instrument for
// the poller's bounds (D243, P3 criterion 6) rather than two things that were
// each tested alone.
func TestTheHostileSettingsTripTheDetector(t *testing.T) {
	t.Parallel()
	ctx := tenantCtx("alpha")
	d := New()
	rows := map[string]string{SettingRows: "10"}

	for name, tc := range map[string]struct {
		setting, value string
		want           connector.PollViolationKind
	}{
		"a stalled cursor is detected":    {MisbehaveStallCursor, "true", connector.PollCursorStalled},
		"an over-limit batch is detected": {MisbehaveOverLimit, "3", connector.PollOverLimit},
		"a duplicated id is detected":     {MisbehaveDuplicateIDs, "true", connector.PollDuplicateID},
		"an empty id is detected":         {MisbehaveEmptyID, "true", connector.PollEmptyID},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tgt := sourceTarget(t, merge(rows, tc.setting, tc.value))

			const limit = 4
			events, next, err := d.Poll(ctx, tgt, "", limit)
			if err != nil {
				t.Fatalf("poll: %v", err)
			}

			for _, v := range connector.ValidatePoll("", limit, events, next) {
				if v.Kind == tc.want {
					return
				}
			}
			t.Errorf("%s=%s produced a response ValidatePoll is happy with; the fixture "+
				"and the detector disagree, so the poller's bound would be proven against "+
				"a source that was never difficult", tc.setting, tc.value)
		})
	}
}
