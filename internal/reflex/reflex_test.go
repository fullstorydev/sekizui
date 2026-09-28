package reflex

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fullstorydev/sekizui/internal/bus"
	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// These are the FIRST tests in the project to construct an Envelope. Until now
// the wire contract existed, compiled, and had never been built by any code —
// which is exactly how a wrongly-shaped message survives to P4.

func envelope(t *testing.T, stage, source, typ string, data map[string]any) *sekizuiv1.Envelope {
	t.Helper()
	d, err := structpb.NewStruct(data)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	return &sekizuiv1.Envelope{
		Id:           "01J000000000000000000ROOT",
		Source:       source,
		SpecVersion:  "1.0",
		Type:         typ,
		Subject:      "session:abc123",
		Time:         timestamppb.New(time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)),
		Data:         d,
		Stage:        stage,
		Residency:    "eu",
		TraceId:      "4bf92f3577b34da6",
		ObservedTime: timestamppb.New(time.Date(2026, 8, 24, 12, 0, 1, 0, time.UTC)),
	}
}

func rageClick(t *testing.T) *sekizuiv1.Envelope {
	t.Helper()
	return envelope(t, "raw", "fullstory:o-EXAMPLE", "fullstory.rage_click.v1",
		map[string]any{"session_id": "abc123", "url": "/checkout", "clicks": 7})
}

// TestMatchIsTheStructuralPreFilter — D26's first stage, over (stage, source,
// type). A rule eliminated here costs no policy evaluation at all, which is the
// whole point at event volume.
func TestMatchIsTheStructuralPreFilter(t *testing.T) {
	env := rageClick(t)

	for name, tc := range map[string]struct {
		consumes string
		want     bool
	}{
		// D60: sekizui.<stage>.<type>, and the type is source-prefixed.
		"exact subject":              {"sekizui.raw.fullstory.rage_click.v1", true},
		"trailing wildcard":          {"sekizui.raw.fullstory.>", true},
		"trailing wildcard at stage": {"sekizui.raw.>", true},
		// Every version of one event — what D41's dual-publish migration needs.
		"version wildcard": {"sekizui.raw.fullstory.rage_click.*", true},
		"wrong version":    {"sekizui.raw.fullstory.rage_click.v2", false},
		"wrong stage":      {"sekizui.enriched.>", false},
		"wrong source":     {"sekizui.raw.jira.>", false},
		"empty pattern":    {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Match(env, config.ReflexSpec{
				Name: "r", Enabled: true, Consumes: tc.consumes,
			})
			if err != nil {
				t.Fatalf("Match: %v", err)
			}
			if got != tc.want {
				t.Errorf("Match(%q) = %v, want %v (subject is %q)",
					tc.consumes, got, tc.want, pkgbus.SubjectOf(env))
			}

			// **A SUBSCRIBER WITH THE SAME PATTERN SEES THE SAME ENVELOPE (D258).**
			// The rule engine and the bus each had their own reading of "the
			// subject", and the bus's was the CloudEvents entity — so every row
			// above passed while a subscription on the identical pattern
			// received nothing from a real connector. This arm is a claim about
			// the RELATIONSHIP between two paths, the kind no single-path test
			// can make (D155). An empty pattern is skipped because the two
			// DELIBERATELY differ there: a rule with no pattern matches nothing,
			// a filter with none is "everything authorised".
			if tc.consumes == "" {
				return
			}
			b := bus.New(slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
			sub, err := b.Subscribe(context.Background(), pkgbus.Filter{Unscoped: true, Subjects: []string{tc.consumes}})
			if err != nil {
				t.Fatalf("Subscribe: %v", err)
			}
			if err := b.Publish(context.Background(), env); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			_ = b.Close(context.Background())
			delivered := false
			for range sub.Events() {
				delivered = true
			}
			if delivered != got {
				t.Errorf("pattern %q: the rule engine says match=%v and the bus delivered=%v "+
					"— the two planes disagree about what an envelope's subject is (D60, D258)",
					tc.consumes, got, delivered)
			}
		})
	}
}

// TestDisabledRuleNeverMatches. A config with history accumulates disabled
// rules, so this is the most common rejection and the cheapest.
func TestDisabledRuleNeverMatches(t *testing.T) {
	got, err := Match(rageClick(t), config.ReflexSpec{
		Name: "r", Enabled: false, Consumes: "sekizui.raw.>",
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if got {
		t.Error("a disabled rule matched")
	}
}

// TestExpectsTypeIsCheckedAtMatchTime is the second half of D42.
//
// Boot validation checks the schema is REGISTERED. This checks the envelope in
// hand actually carries the expected type — a different question, answerable
// only here, and the one that stops a rule firing on a payload it cannot read.
func TestExpectsTypeIsCheckedAtMatchTime(t *testing.T) {
	env := rageClick(t)
	rule := config.ReflexSpec{Name: "r", Enabled: true, Consumes: "sekizui.raw.>"}

	rule.ExpectsType = "fullstory.rage_click.v1"
	if got, _ := Match(env, rule); !got {
		t.Error("the declared type matches the envelope but the rule did not fire")
	}

	rule.ExpectsType = "fullstory.rage_click.v2"
	if got, _ := Match(env, rule); got {
		t.Error("a rule expecting v2 fired on a v1 envelope; D41's dual-publish " +
			"migration depends on these staying distinct")
	}
}

// TestDepthCapStopsRunaways is §4.11.4 item 2 — the BACKSTOP behind stage
// monotonicity, catching what a boot-time check cannot: a bug in the checker, or
// agent-produced events re-entering from outside the stage model.
func TestDepthCapStopsRunaways(t *testing.T) {
	env := rageClick(t)
	env.Causation = &sekizuiv1.Causation{RootId: "root", ParentId: "parent", Depth: MaxDepth}

	_, err := Match(env, config.ReflexSpec{Name: "r", Enabled: true, Consumes: "sekizui.raw.>"})
	if err == nil {
		t.Fatal("a rule matched an envelope at the depth cap")
	}
	if !errors.Is(err, fault.KindBudgetExceeded) {
		t.Errorf("kind = %v, want KindBudgetExceeded", fault.KindOf(err))
	}
	// The error must say this is a bug rather than normal operation — hitting
	// the backstop means the primary guarantee failed.
	if got := err.Error(); !strings.Contains(got, "bug") {
		t.Errorf("error does not flag this as a guarantee failure: %v", got)
	}
}

// TestEnrichIsTheBusToBusPath — §4.11.6, "the higher-impact half".
func TestEnrichIsTheBusToBusPath(t *testing.T) {
	src := rageClick(t)
	rule := config.ReflexSpec{
		Name: "correlate-friction", Enabled: true,
		Consumes:  "sekizui.raw.fullstory.>",
		PublishTo: "sekizui.enriched.friction_detected",
		Carry:     []string{"session_id", "url"},
		With:      map[string]any{"severity": "high", "correlated": true},
	}

	out, err := Enrich(src, rule, "01J000000000000000000NEXT")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if out.GetStage() != "enriched" {
		t.Errorf("stage = %q, want enriched", out.GetStage())
	}
	if out.GetType() != "friction_detected" {
		t.Errorf("type = %q; the enriched form must be a distinct type so a consumer "+
			"can subscribe to one and not the other (D41)", out.GetType())
	}

	// The enrichment is merged OVER the original payload, so a rule adding one
	// field does not have to restate the rest.
	data := out.GetData().AsMap()
	if data["severity"] != "high" || data["correlated"] != true {
		t.Errorf("enrichment did not land: %v", data)
	}
	if data["session_id"] != "abc123" || data["url"] != "/checkout" {
		t.Errorf("the original payload was lost: %v", data)
	}

	// Residency travels with the data (D29). Losing it here would make the
	// enriched copy exportable to a region the original was not.
	if out.GetResidency() != "eu" {
		t.Errorf("residency = %q, want eu — the copy must not escape the original's region",
			out.GetResidency())
	}
	if out.GetTraceId() != src.GetTraceId() {
		t.Error("trace correlation was lost across the hop")
	}
}

// TestEnrichDoesNotMutateTheSource. The input envelope has already been
// delivered to other subscribers; editing it changes what they see after they
// have seen it.
func TestEnrichDoesNotMutateTheSource(t *testing.T) {
	src := rageClick(t)
	before := src.GetData().AsMap()

	_, err := Enrich(src, config.ReflexSpec{
		Name: "r", PublishTo: "sekizui.enriched.x",
		Carry: []string{CarryAll},
		With:  map[string]any{"added": "value"},
	}, "new-id")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if _, leaked := src.GetData().AsMap()["added"]; leaked {
		t.Error("Enrich wrote into the source payload")
	}
	if len(src.GetData().AsMap()) != len(before) {
		t.Error("the source payload changed size")
	}
	if src.GetStage() != "raw" {
		t.Errorf("the source stage changed to %q", src.GetStage())
	}
}

// TestCausationChainIsBuiltCorrectly is D19, "required from v1… the one field
// that must not be deferred".
func TestCausationChainIsBuiltCorrectly(t *testing.T) {
	root := rageClick(t)
	rule := config.ReflexSpec{Name: "step-one", PublishTo: "sekizui.enriched.x"}

	first, err := Enrich(root, rule, "id-1")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	// A root envelope with no causation becomes the root of the chain.
	if got := first.GetCausation(); got.GetRootId() != root.GetId() {
		t.Errorf("root_id = %q, want the originating envelope %q", got.GetRootId(), root.GetId())
	}
	if got := first.GetCausation(); got.GetParentId() != root.GetId() {
		t.Errorf("parent_id = %q, want %q", got.GetParentId(), root.GetId())
	}
	if got := first.GetCausation().GetDepth(); got != 1 {
		t.Errorf("depth = %d, want 1", got)
	}
	if got := first.GetCausation().GetProducedBy(); got != "reflex:step-one" {
		t.Errorf("produced_by = %q; the chain must name WHAT emitted this", got)
	}

	// A second hop: root is PRESERVED, parent advances, depth increments.
	second, err := Enrich(first, config.ReflexSpec{
		Name: "step-two", PublishTo: "sekizui.triaged.x",
	}, "id-2")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if got := second.GetCausation().GetRootId(); got != root.GetId() {
		t.Errorf("root_id = %q after two hops, want the original root %q — rewriting "+
			"it would make a chain untraceable to its origin", got, root.GetId())
	}
	if got := second.GetCausation().GetParentId(); got != first.GetId() {
		t.Errorf("parent_id = %q, want the immediate predecessor %q", got, first.GetId())
	}
	if got := second.GetCausation().GetDepth(); got != 2 {
		t.Errorf("depth = %d, want 2", got)
	}
}

// TestBuildCommandGoesThroughEnforcement is D18: a reflex is a principal, not a
// bypass.
func TestBuildCommandGoesThroughEnforcement(t *testing.T) {
	env := rageClick(t)
	rule := config.ReflexSpec{
		Name: "friction-to-ticket", Enabled: true, Mode: "enforce",
		Principal: "reflex:friction",
		Consumes:  "sekizui.enriched.>",
		Action:    "kata.create_issue", TargetRef: "kata:alpha",
		With: map[string]any{"project": "PROJ", "title": "Checkout friction"},
	}

	cmd, err := BuildCommand(env, rule)
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}

	if cmd.GetAction() != "kata.create_issue" || cmd.GetTargetRef() != "kata:alpha" {
		t.Errorf("command = %s on %s", cmd.GetAction(), cmd.GetTargetRef())
	}
	if got := cmd.GetArgs().AsMap()["project"]; got != "PROJ" {
		t.Errorf("args did not carry through: %v", cmd.GetArgs().AsMap())
	}
	// Causation is what lets the Decision record WHAT TRIGGERED this, as
	// distinct from who authorised it (§4.11.1).
	if cmd.GetCausation().GetProducedBy() != "reflex:friction-to-ticket" {
		t.Errorf("produced_by = %q", cmd.GetCausation().GetProducedBy())
	}
}

// TestIdempotencyKeyIsDerivedNotRandom. A redelivery of the same event must
// produce the same key and therefore ONE side effect — a random key would defeat
// the idempotency the connector DoD requires.
func TestIdempotencyKeyIsDerivedNotRandom(t *testing.T) {
	env := rageClick(t)
	rule := config.ReflexSpec{
		Name: "r", Action: "kata.create_issue", TargetRef: "kata:alpha",
	}

	a, _ := BuildCommand(env, rule)
	b, _ := BuildCommand(env, rule)

	if a.GetIdempotencyKey() != b.GetIdempotencyKey() {
		t.Errorf("the same event produced two keys: %q and %q — a redelivery would "+
			"create two tickets", a.GetIdempotencyKey(), b.GetIdempotencyKey())
	}
	if a.GetIdempotencyKey() == "" {
		t.Error("no idempotency key; the DoD requires one for every mutating action")
	}

	// A different event must produce a different key, or two distinct events
	// would collapse into one action.
	other := rageClick(t)
	other.Id = "01J000000000000000000OTHR"
	c, _ := BuildCommand(other, rule)
	if c.GetIdempotencyKey() == a.GetIdempotencyKey() {
		t.Error("two different events share an idempotency key")
	}
}

// TestShadowIsTheDefault is §4.11.4 item 3: "every reflex should run shadow
// first". The safe mode must be what you get by not choosing.
func TestShadowIsTheDefault(t *testing.T) {
	env := rageClick(t)
	base := config.ReflexSpec{Name: "r", Action: "kata.create_issue", TargetRef: "kata:alpha"}

	shadow, _ := BuildCommand(env, base) // Mode unset
	if !shadow.GetDryRun() {
		t.Error("an unset mode produced a live command; shadow must be the default " +
			"or the dangerous option is the easy one")
	}

	base.Mode = "shadow"
	explicit, _ := BuildCommand(env, base)
	if !explicit.GetDryRun() {
		t.Error("mode=shadow produced a live command")
	}

	base.Mode = "enforce"
	live, _ := BuildCommand(env, base)
	if live.GetDryRun() {
		t.Error("mode=enforce produced a dry run")
	}
}

// TestWrongRuleShapeIsRefused — D31's one-rule-one-action, enforced at use as
// well as at config load.
func TestWrongRuleShapeIsRefused(t *testing.T) {
	env := rageClick(t)

	if _, err := Enrich(env, config.ReflexSpec{Name: "r", Action: "x", TargetRef: "y"}, "id"); err == nil {
		t.Error("Enrich accepted a bus->driver rule")
	}
	if _, err := BuildCommand(env, config.ReflexSpec{Name: "r", PublishTo: "sekizui.enriched.x"}); err == nil {
		t.Error("BuildCommand accepted a bus->bus rule")
	}
}

// TestCarryIsExplicit is D63. Merge was ergonomic and unbounded; naming the
// fields costs one config line and fixes payload growth, provenance blur, and
// schema coupling at once.
func TestCarryIsExplicit(t *testing.T) {
	src := envelope(t, "raw", "fullstory:o-1", "fullstory.rage_click.v1",
		map[string]any{"session_id": "abc", "url": "/checkout", "clicks": 7, "noise": "drop me"})

	out, err := Enrich(src, config.ReflexSpec{
		Name: "r", PublishTo: "sekizui.enriched.friction",
		Carry: []string{"session_id", "url"},
		With:  map[string]any{"severity": "high"},
	}, "id")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	data := out.GetData().AsMap()
	if data["session_id"] != "abc" || data["url"] != "/checkout" {
		t.Errorf("carried fields missing: %v", data)
	}
	if data["severity"] != "high" {
		t.Errorf("the rule's own addition missing: %v", data)
	}
	// THE POINT: uncarried fields do not travel. Under merge these rode along
	// forever, growing the payload every hop with nothing bounding it.
	if _, rode := data["noise"]; rode {
		t.Error("an uncarried field propagated; carry is not bounding the payload")
	}
	if _, rode := data["clicks"]; rode {
		t.Error("an uncarried field propagated")
	}
	if len(data) != 3 {
		t.Errorf("payload has %d fields, want exactly the 2 carried + 1 added: %v", len(data), data)
	}
}

// TestEmptyCarryCarriesNothing. A rule that forgets carry emits only its own
// fields — which a consumer notices immediately. Silent full propagation is the
// alternative, and it is quiet and unbounded.
func TestEmptyCarryCarriesNothing(t *testing.T) {
	src := envelope(t, "raw", "fullstory:o-1", "fullstory.rage_click.v1",
		map[string]any{"session_id": "abc", "url": "/checkout"})

	out, err := Enrich(src, config.ReflexSpec{
		Name: "r", PublishTo: "sekizui.enriched.x",
		With: map[string]any{"severity": "high"},
	}, "id")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := out.GetData().AsMap(); len(got) != 1 || got["severity"] != "high" {
		t.Errorf("payload = %v, want only the rule's own field", got)
	}
}

// TestCarryAllIsAvailableButExplicit — the merge behaviour is preserved as a
// CHOICE, so it appears in a diff where a reviewer sees it.
func TestCarryAllIsAvailableButExplicit(t *testing.T) {
	src := envelope(t, "raw", "fullstory:o-1", "fullstory.rage_click.v1",
		map[string]any{"a": 1, "b": 2, "c": 3})

	out, err := Enrich(src, config.ReflexSpec{
		Name: "r", PublishTo: "sekizui.enriched.x",
		Carry: []string{CarryAll},
		With:  map[string]any{"d": 4},
	}, "id")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := len(out.GetData().AsMap()); got != 4 {
		t.Errorf("carry-all produced %d fields, want 4", got)
	}
}

// TestCarryingAMissingFieldIsAnError. The rule states a dependency on the
// source's shape. If the source changed and the field is gone, the rule is
// broken — emitting a quietly smaller payload is D42's silent-stop failure
// arriving through a different door.
func TestCarryingAMissingFieldIsAnError(t *testing.T) {
	src := envelope(t, "raw", "fullstory:o-1", "fullstory.rage_click.v1",
		map[string]any{"session_id": "abc"})

	_, err := Enrich(src, config.ReflexSpec{
		Name: "r", PublishTo: "sekizui.enriched.x",
		Carry: []string{"session_id", "url", "referrer"},
	}, "id")

	if err == nil {
		t.Fatal("a rule carrying fields the source lacks succeeded quietly")
	}
	if !errors.Is(err, fault.KindInvalidArgument) {
		t.Errorf("kind = %v, want KindInvalidArgument", fault.KindOf(err))
	}
	// Both missing fields named, sorted — map iteration is randomised and the
	// error must not be.
	for _, want := range []string{"referrer", "url"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits %q: %v", want, err)
		}
	}
}

// TestWithCollidingWithCarryIsRefused is D61, now expressed against carry: a
// rule intending to ADD a field must not silently destroy one it chose to carry.
func TestWithCollidingWithCarryIsRefused(t *testing.T) {
	src := envelope(t, "raw", "fullstory:o-1", "fullstory.rage_click.v1",
		map[string]any{"session_id": "abc", "severity": "low"})

	_, err := Enrich(src, config.ReflexSpec{
		Name: "r", PublishTo: "sekizui.enriched.x",
		Carry: []string{"session_id", "severity"},
		With:  map[string]any{"severity": "high"},
	}, "id")

	if err == nil {
		t.Fatal("a rule silently overwrote a field it carried")
	}
	if !errors.Is(err, fault.KindConfig) {
		t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
	}
}
