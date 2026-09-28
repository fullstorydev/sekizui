package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/fullstorydev/sekizui/internal/reflex"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step16 — one projection, generated as a stateless enrichment rule shape
// (P3 criteria 1 and 2, D248, D269).
//
// **THE MACHINERY IS D269's; THIS IS ITS PURITY.** Step 36 proves a projection
// reaches a caller who asked and that the synchronous path cannot actuate.
// What it does not prove is the property the deliverable was named for: that a
// projection is a FUNCTION of the envelope — the same envelope gives the same
// view, whoever asks, however often, in whatever order — so it can be computed
// at delivery on every replica without any of them keeping anything.
func p3Step16(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "one projection, generated as a stateless enrichment rule shape")

	projector, err := reflex.NewProjector(loadAcceptanceDoc(t).Reflexes)
	if err != nil {
		t.Fatalf("step 16: %v", err)
	}
	row := func(ordinal int) *sekizuiv1.Envelope {
		return envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": ordinal, "ref": "kata:alpha"})
	}

	// 16a — SAME ENVELOPE, SAME OUTPUT, REPEATEDLY AND INTERLEAVED. If Project
	// kept anything between calls — a counter, a cache keyed wrongly, a merge
	// map reused — an interleaved second call would differ from the first.
	a, b := row(0), row(1)
	// THE SNAPSHOT IS TAKEN BEFORE ANY PROJECTION, and the first version of
	// this step took it after 16a's calls: a projector writing the same value
	// into its input every time had already written it, so 16b compared the
	// mutated envelope with itself and passed. Sabotage found it.
	pristine := proto.Clone(a)
	first, _, err := projector.Project(a)
	if err != nil || first == nil {
		t.Fatalf("step 16a: row 0 did not project: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := projector.Project(b); err != nil {
			t.Fatalf("step 16a: %v", err)
		}
		again, _, err := projector.Project(a)
		if err != nil || !proto.Equal(first, again) {
			t.Fatalf("step 16a: projecting the same envelope gave %v then %v; a projection must "+
				"be a function of the envelope and nothing else", first.AsMap(), again.AsMap())
		}
	}

	// 16b — AND THE INPUT IS UNTOUCHED: projecting must not write into an
	// envelope other consumers are also receiving.
	if !proto.Equal(pristine, a) {
		t.Error("step 16b: Project mutated its input envelope")
	}

	// 16c — NO REACHABLE STATE: the Projector's fields are its rules, and the
	// rules are values. A map or pointer field would be somewhere to keep things.
	pt := reflect.TypeOf(reflex.Projector{})
	for i := 0; i < pt.NumField(); i++ {
		if k := pt.Field(i).Type.Kind(); k == reflect.Map || k == reflect.Pointer || k == reflect.Chan {
			t.Errorf("step 16c: reflex.Projector has a %s field %q — somewhere to keep state "+
				"between projections", k, pt.Field(i).Name)
		}
	}
	r.detail(t, "row-summary's projection of one envelope was identical across interleaved calls, "+
		"left its input untouched, and the Projector holds only its rules")
}

// p3Step10 — boot refuses a deliberately cyclic subject config, and names the
// cycle (P3 criterion 5, D21).
//
// **THE MESSAGE IS HALF THE ARM.** D21 refuses any rule publishing to a stage
// not strictly later than the one it consumes — cycles impossible by
// construction. But a refusal naming only the backward edge leaves the
// operator to find the rest of the loop; since this step, when other rules
// already lead back, the refusal names them, because they are what tells the
// operator which rule is the mistake.
func p3Step10(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "boot refuses a deliberately cyclic subject config, and names the cycle")

	base, err := os.ReadFile("acceptance.yaml")
	if err != nil {
		t.Fatalf("step 10: %v", err)
	}
	const anchor = "reflexes:\n"
	if !strings.Contains(string(base), anchor) {
		t.Fatalf("step 10: acceptance.yaml has no %q", anchor)
	}
	withRule := func(consumes, publishTo string) error {
		t.Helper()
		rule := "  - name: rebound\n    principal: reflex:friction\n    enabled: true\n" +
			"    consumes: " + consumes + "\n    expects_type: fullstory.friction_detected.v1\n" +
			"    publish_to: " + publishTo + "\n    publishes_type: fullstory.rage_click.v1\n" +
			"    carry: [session_id]\n"
		path := filepath.Join(t.TempDir(), "acceptance.yaml")
		if err := os.WriteFile(path, []byte(strings.Replace(string(base), anchor, anchor+rule, 1)), 0o600); err != nil {
			t.Fatalf("step 10: %v", err)
		}
		doc, err := config.NewFileSource(path).Load(context.Background())
		if err != nil {
			return err
		}
		return doc.Validate()
	}

	// 10a — THE CYCLE. correlate-friction already takes raw to enriched;
	// `rebound` takes enriched back to raw.
	err = withRule("sekizui.enriched.>", "sekizui.raw.rebound")
	if err == nil {
		t.Fatal("step 10a: a rule publishing from enriched back to raw booted — a cycle (D21)")
	}
	for _, want := range []string{`reflex "rebound"`, "an earlier stage", "correlate-friction (raw -> enriched)",
		`then this rule back to "raw"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("step 10a: the refusal does not say %q, so the operator is not shown the loop:\n%v",
				want, err)
		}
	}

	// 10b — NON-VACUITY: the same rule, publishing FORWARD, loads. A checker
	// refusing every publishing rule would pass 10a and break every deployment.
	if err := withRule("sekizui.enriched.>", "sekizui.triaged.rebound"); err != nil {
		t.Errorf("step 10b: the same rule publishing forward (enriched -> triaged) was refused: %v", err)
	}
	r.detail(t, "rebound (enriched -> raw) was refused naming correlate-friction (raw -> enriched) as "+
		"the rest of the loop; the same rule publishing forward loaded")
}
