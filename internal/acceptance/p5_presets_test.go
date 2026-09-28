package acceptance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/builtin"
	"github.com/fullstorydev/sekizui/internal/connectorcheck"
	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/grantcheck"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// CONNECTOR PRESETS (D327), P5 steps 10-12: a vendor recommends and explains
// named sets of its actions, a sysadmin owns the copy deployed, and nothing a
// connector release does can widen a grant.

// suggestedPresetsFile is the Fullstory connector's presets.yaml — the file the
// steps load, so what ships is what is tested (P4 step 33's rule).
// deleteUser is a DERIVED action (D314), so it has no constant: an Architect
// write the connector's suggested ceiling forbids as irreversible.
const deleteUser = "fullstory.delete_user"

func suggestedPresetsFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(mustRoot(t), "internal", "connectors", "fullstory", "presets.yaml")
}

func loadSuggestedPresets(t *testing.T) []config.PresetSpec {
	t.Helper()
	raw, err := os.ReadFile(suggestedPresetsFile(t))
	if err != nil {
		t.Fatalf("the suggested presets fragment: %v", err)
	}
	presets, err := config.ParsePresets(raw)
	if err != nil {
		t.Fatalf("the suggested presets fragment does not load: %v", err)
	}
	return presets
}

func presetNamed(t *testing.T, presets []config.PresetSpec, name string) config.PresetSpec {
	t.Helper()
	for _, p := range presets {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("the connector suggests no preset %q", name)
	return config.PresetSpec{}
}

// presetRun is a run in which agent:triage holds `preset` on fs:fixture, the
// document carrying `presets` as the deployment's copy, and fs:fixture pointed
// at a server that counts what reaches it. extra patches after, before the
// expansion a loader would have done.
func presetRun(t *testing.T, presets []config.PresetSpec, preset string, extra func(*config.Document)) (*run, *atomic.Int32, int) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	written := -1
	r := newRunWith(t, runOpts{patch: func(doc *config.Document) {
		doc.Presets = append(doc.Presets, presets...)
		for i := range doc.Targets {
			if doc.Targets[i].Ref == "fs:fixture" {
				doc.Targets[i].BaseURL = srv.URL
			}
		}
		for i := range doc.Grants {
			if doc.Grants[i].Principal == "agent:triage" {
				written = len(doc.Grants[i].Allow)
				doc.Grants[i].Allow = append(doc.Grants[i].Allow,
					config.CapabilitySpec{Preset: preset, TargetRef: "fs:fixture"})
			}
		}
		if extra != nil {
			extra(doc)
		}
		// THE LOADER EXPANDS; a patch lands after it, so it expands here — the
		// same function, and Validate refuses a document that skipped it.
		if err := doc.ExpandPresets(); err != nil {
			t.Fatalf("expanding the patched presets: %v", err)
		}
	}})
	return r, &hits, written
}

// dryRun executes action on fs:fixture as a dry run: policy decides and the
// record says so, and nothing is dialled.
func dryRun(ctx context.Context, t *testing.T, c sekizuiv1.GatewayServiceClient, action string) *sekizuiv1.CommandResult {
	t.Helper()
	req := execute(action, "fs:fixture", map[string]any{})
	req.Command.DryRun = true
	resp, err := c.Execute(ctx, req)
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return resp.GetResult()
}

func recordFor(t *testing.T, r *run, id string) *sekizuiv1.Decision {
	t.Helper()
	for _, d := range readLog(t, r.path) {
		if d.GetId() == id {
			return d
		}
	}
	t.Fatalf("no decision record %s", id)
	return nil
}

// p5Step10 — the Fullstory connector's presets ship as a suggested fragment, and
// a preset grant expands at boot to a fixed action list (D327).
func p5Step10(t *testing.T) {
	presets := loadSuggestedPresets(t)
	standard := presetNamed(t, presets, "fullstory.standard")

	// 10a — DROPPED IN, AS A DEPLOYMENT WOULD: acceptance.yaml, the connector's
	// file symlinked beside it, and a grant naming a preset. Composed by the
	// loader, expanded, and passed by both halves of boot validation.
	dir := t.TempDir()
	for name, target := range map[string]string{
		"acceptance.yaml": filepath.Join(mustRoot(t), "internal", "acceptance", "acceptance.yaml"),
		"presets.yaml":    suggestedPresetsFile(t),
	} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "reviewer.yaml"), []byte(`
grants:
  - principal: agent:preset-reader
    allow:
      - {preset: fullstory.session_review, target: fs:live}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := config.NewFileSource(dir).Load(context.Background())
	if err != nil {
		t.Fatalf("step 10a: the deployment with the fragment dropped in does not load: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("step 10a: it does not validate: %v", err)
	}
	if err := grantcheck.Validate(doc, builtin.ByKind(doc, nil)); err != nil {
		t.Fatalf("step 10a: grantcheck refuses it: %v", err)
	}
	review := presetNamed(t, presets, "fullstory.session_review")
	var got []string
	for _, g := range doc.Grants {
		if g.Principal == "agent:preset-reader" {
			for _, c := range g.Allow {
				got = append(got, c.Action)
			}
		}
	}
	if !slices.Equal(got, review.Actions) {
		t.Errorf("step 10a: the grant expanded to %v; want the preset's fixed list %v", got, review.Actions)
	}

	// 10b — AN UNKNOWN PRESET, AND A PRESET NAMING AN ACTION THE CONNECTOR LACKS,
	// REFUSE THE BOOT.
	bad := &config.Document{Grants: []config.GrantSpec{{Principal: "agent:x",
		Allow: []config.CapabilitySpec{{Preset: "fullstory.nope", TargetRef: "fs:live"}}}}}
	if err := bad.ExpandPresets(); err == nil || !strings.Contains(err.Error(), "fullstory.nope") {
		t.Errorf("step 10b: an unknown preset expanded, or the refusal does not name it: %v", err)
	}
	typo := []config.PresetSpec{{Name: "fullstory.typo", Explain: "x", Actions: []string{"fullstory.list_segmentz"}}}
	if misses := grantcheck.PresetMisses(typo, builtin.ByKind(doc, nil), nil); len(misses) != 1 ||
		!strings.Contains(misses[0], "fullstory.list_segmentz") {
		t.Errorf("step 10b: a preset naming an action the connector lacks: %v; want one refusal naming it", misses)
	}

	// THE REMOTE PATH: `make demo` drives the running demo instance, whose
	// deployment drops the same file in and grants agent:showcase a preset.
	if os.Getenv("SEKIZUI_ACCEPTANCE_TARGET") != "" {
		p5Step10Remote(t, review)
		return
	}

	// 10c — AT RUN TIME: a preset action passes policy with the preset on the
	// record, and a write the preset does not hold is refused by policy.
	r, hits, written := presetRun(t, presets, "fullstory.standard", nil)
	if r.localOnly(t, "the patched deployment is this instance's") {
		return
	}
	r.narrate(t, "the Fullstory connector's presets ship as a suggested fragment and a preset grant expands at boot")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := r.as(t, "agent:triage")

	in := dryRun(ctx, t, c, "fullstory.create_annotation") // Standard, a write, in the preset
	if in.GetStatus() == sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("step 10c: create_annotation, which fullstory.standard holds, was refused: %s", in.GetReason())
	}
	wantRule := "agent:triage#allow[" + strconv.Itoa(written) + "]/preset:fullstory.standard"
	if rule := recordFor(t, r, in.GetDecisionId()).GetMatchedRule(); rule != wantRule {
		t.Errorf("step 10c: matched_rule %q; want %q — the line as written, and the preset", rule, wantRule)
	}
	out := dryRun(ctx, t, c, "fullstory.create_extraction_rule") // Architect, not in the preset
	if out.GetStatus() != sekizuiv1.Status_STATUS_DENIED || out.GetKind() != "denied" {
		t.Errorf("step 10c: create_extraction_rule, which fullstory.standard does not hold, came back %v "+
			"kind %q; want refused by policy", out.GetStatus(), out.GetKind())
	}
	if hits.Load() != 0 {
		t.Errorf("step 10c: the fixture received %d request(s) from dry runs", hits.Load())
	}

	// 10d — DESCRIBE LISTS THE EXPANSION: every action of the preset on fs:fixture.
	desc, err := c.Describe(ctx, &sekizuiv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("step 10d: %v", err)
	}
	listed := map[string]bool{}
	for _, cap := range desc.GetCapabilities() {
		if cap.GetTargetRef() == "fs:fixture" {
			listed[cap.GetAction()] = true
		}
	}
	for _, w := range desc.GetWithheld() {
		if w.GetTargetRef() == "fs:fixture" {
			listed[w.GetAction()] = true // withheld by the ceiling, still named
		}
	}
	var missing []string
	for _, a := range standard.Actions {
		if !listed[a] {
			missing = append(missing, a)
		}
	}
	if len(missing) > 0 {
		t.Errorf("step 10d: Describe does not list %v of fullstory.standard on fs:fixture", missing)
	}
	r.detail(t, "the connector's presets.yaml dropped into a deployment loads and validates; "+
		"fullstory.session_review expanded to its %d actions; fullstory.standard (%d actions) authorised "+
		"create_annotation as %s and refused create_extraction_rule by policy; Describe lists all %d",
		len(review.Actions), len(standard.Actions), wantRule, len(standard.Actions))
}

// p5Step10Remote is step 10 against the running demo instance (D327): demo.d
// symlinks the connector's presets.yaml and grants agent:showcase
// `fullstory.session_review` on fs:live. Describe on the real binary lists
// exactly the preset's actions there, and a read outside it is refused by
// policy — nothing reaches Fullstory, because policy refuses before resolve.
func p5Step10Remote(t *testing.T, review config.PresetSpec) {
	r := newRun(t)
	r.narrate(t, "a preset grant on the running instance expands to exactly the preset's actions")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := r.as(t, "agent:showcase")
	desc, err := c.Describe(ctx, &sekizuiv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("step 10 (remote): %v", err)
	}
	var onLive []string
	for _, cap := range desc.GetCapabilities() {
		if cap.GetTargetRef() == "fs:live" {
			onLive = append(onLive, cap.GetAction())
		}
	}
	want := slices.Clone(review.Actions)
	slices.Sort(want)
	slices.Sort(onLive)
	if !slices.Equal(onLive, want) {
		t.Errorf("step 10 (remote): Describe lists %v on fs:live; want exactly fullstory.session_review's %v",
			onLive, want)
	}
	refused, err := c.Query(ctx, &sekizuiv1.QueryRequest{Action: "fullstory.get_user", TargetRef: "fs:live",
		Args: mustArgs(t, map[string]any{"id": "u-1"})})
	if err != nil {
		t.Fatalf("step 10 (remote): %v", err)
	}
	if refused.GetStatus() != sekizuiv1.Status_STATUS_DENIED || refused.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_POLICY {
		t.Errorf("step 10 (remote): get_user, outside the preset, came back %v by %v; want refused by policy",
			refused.GetStatus(), refused.GetRefusedBy())
	}
	r.detail(t, "agent:showcase holds fullstory.session_review on fs:live: Describe lists its %d actions and no "+
		"others; get_user, outside it, refused by policy: %s", len(want), refused.GetReason())
}

// p5Step11 — a vendor preset that grew is a finding and widens no grant (D327).
func p5Step11(t *testing.T) {
	presets := loadSuggestedPresets(t)
	review := presetNamed(t, presets, "fullstory.session_review")

	// THE DEPLOYMENT'S COPY IS ONE ACTION BEHIND: exactly the state a connector
	// release adding `get_segment` to the preset leaves every deployment in.
	const grown = "fullstory.get_segment"
	behind := review
	behind.Actions = slices.DeleteFunc(slices.Clone(review.Actions), func(a string) bool { return a == grown })
	if len(behind.Actions) != len(review.Actions)-1 {
		t.Fatalf("the suggested session_review has no %s to hold back", grown)
	}
	copyOf := []config.PresetSpec{behind}

	// 11a — THE FINDING names the preset and the action, and says grants follow
	// the deployment's copy.
	findings := grantcheck.PresetFindings(copyOf, map[string]connector.Driver{fullstory.Kind: fullstory.New()})
	if len(findings) != 1 || !strings.Contains(findings[0], "fullstory.session_review") ||
		!strings.Contains(findings[0], grown) || !strings.Contains(findings[0], "grants follow the deployment's copy") {
		t.Fatalf("step 11a: findings %q; want one naming the preset, %s, and whose copy grants follow", findings, grown)
	}
	// NON-VACUITY: a copy identical to the suggestion is no finding.
	if same := grantcheck.PresetFindings([]config.PresetSpec{review},
		map[string]connector.Driver{fullstory.Kind: fullstory.New()}); len(same) != 0 {
		t.Errorf("step 11a: an unchanged copy produced findings %q", same)
	}

	// 11b — AND THE GRANT DID NOT WIDEN: the new action is refused, its neighbour
	// is not. Reads, so as Query — refused by policy before anything is dialled.
	r, hits, _ := presetRun(t, copyOf, "fullstory.session_review", nil)
	if r.localOnly(t, "the patched deployment is this instance's") {
		return
	}
	r.narrate(t, "a vendor preset that grew is a finding and widens no grant")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := r.as(t, "agent:triage")
	refused, err := c.Query(ctx, &sekizuiv1.QueryRequest{Action: grown, TargetRef: "fs:fixture",
		Args: mustArgs(t, map[string]any{"id": "seg-1"})})
	if err != nil {
		t.Fatalf("step 11b: %v", err)
	}
	if refused.GetStatus() != sekizuiv1.Status_STATUS_DENIED || refused.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_POLICY {
		t.Errorf("step 11b: %s, which the connector now suggests and the copy lacks, came back %v by %v; "+
			"want refused by policy — a vendor release must not widen a grant", grown, refused.GetStatus(), refused.GetRefusedBy())
	}
	// THE RECORD NAMES THE STAGE TOO — this arm found Query recording a policy
	// refusal with none, while Enforce and the job gate named it (D327).
	if rec := recordFor(t, r, refused.GetDecisionId()); rec.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_POLICY {
		t.Errorf("step 11b: the refused read was recorded refused_by %v; want policy", rec.GetRefusedBy())
	}
	if hits.Load() != 0 {
		t.Errorf("step 11b: the fixture received %d request(s) for a refused read", hits.Load())
	}
	r.detail(t, "the copy one action behind the suggestion: finding %q; %s refused by policy, nothing dialled",
		findings[0], grown)
}

// p5Step12 — a preset's vendor level is checked against the snapshot, and the
// anzen ceiling holds after expansion (D304, D327).
func p5Step12(t *testing.T) {
	presets := loadSuggestedPresets(t)
	fs := fullstory.New()
	drivers := map[string]connector.Driver{fullstory.Kind: fs}

	// 12a — EVERY SHIPPED CLAIM HOLDS, by the check the connector folder gets:
	// connectorcheck over the real tree reports nothing for the fullstory folder.
	report := connectorcheck.Check(mustRoot(t), builtin.Drivers(&config.Document{}, nil))
	for _, f := range report.Findings {
		if strings.Contains(f.Where, "fullstory") {
			t.Errorf("step 12a: the connector-folder check refuses the shipped fullstory folder: %s", f)
		}
	}
	if ships := report.Folders[connectorcheck.Root+"/fullstory"]; !strings.Contains(ships, "presets") {
		t.Errorf("step 12a: the folder check did not examine presets.yaml (it reports %q)", ships)
	}

	// 12b — A FALSE CLAIM IS REFUSED, naming the action and its level: get_user
	// is Architect in the snapshot, so a Standard preset may not hold it.
	lie := []config.PresetSpec{{Name: "fullstory.lie", Mirrors: "Standard", Explain: "x",
		Actions: []string{"fullstory.list_sessions", "fullstory.get_user"}}}
	misses := grantcheck.PresetMisses(lie, drivers, nil)
	if len(misses) != 1 || !strings.Contains(misses[0], "fullstory.get_user") || !strings.Contains(misses[0], "Architect") {
		t.Errorf("step 12b: a Standard preset holding get_user: %q; want one refusal naming the action and "+
			"Architect", misses)
	}
	if l, ok := fs.ActionLevel("fullstory.get_user"); !ok || l != "Architect" {
		t.Errorf("step 12b: the connector grades get_user %q (%v); the snapshot says Architect", l, ok)
	}

	// 12c — THE CEILING HOLDS AFTER EXPANSION: fullstory.architect holds
	// delete_user, and the connector's suggested ceiling still refuses it.
	rules := loadSuggestedAnzen(t)
	architect := presetNamed(t, presets, "fullstory.architect")
	if !slices.Contains(architect.Actions, deleteUser) {
		t.Fatalf("step 12c: fullstory.architect does not hold %s; the arm needs an action the ceiling forbids",
			deleteUser)
	}
	r, hits, _ := presetRun(t, presets, "fullstory.architect", func(doc *config.Document) {
		kept := doc.Anzen[:0]
		for _, rule := range doc.Anzen {
			if rule.Name != "no-destructive-actions" { // P4 step 33's reason: prove the connector's rule
				kept = append(kept, rule)
			}
		}
		doc.Anzen = append(kept, rules...)
	})
	if r.localOnly(t, "the patched deployment is this instance's") {
		return
	}
	r.narrate(t, "a preset's vendor level is checked against the snapshot, and the anzen ceiling holds after expansion")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := r.as(t, "agent:triage")
	res, err := c.Execute(ctx, execute(deleteUser, "fs:fixture", map[string]any{"id": "u-1"}))
	if err != nil {
		t.Fatalf("step 12c: %v", err)
	}
	if res.GetResult().GetStatus() != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("step 12c: delete_user under fullstory.architect came back %v; the ceiling must hold after expansion",
			res.GetResult().GetStatus())
	}
	rec := recordFor(t, r, res.GetResult().GetDecisionId())
	if rec.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_ANZEN || rec.GetMatchedRule() != "anzen:fullstory-irreversible" {
		t.Errorf("step 12c: recorded refused_by %v rule %q; want anzen, anzen:fullstory-irreversible",
			rec.GetRefusedBy(), rec.GetMatchedRule())
	}
	desc, err := c.Describe(ctx, &sekizuiv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("step 12c: %v", err)
	}
	var guard string
	for _, w := range desc.GetWithheld() {
		if w.GetTargetRef() == "fs:fixture" && w.GetAction() == deleteUser {
			guard = w.GetGuard()
		}
	}
	if guard != "fullstory-irreversible" {
		t.Errorf("step 12c: Describe reports delete_user withheld by %q; want fullstory-irreversible", guard)
	}
	if hits.Load() != 0 {
		t.Errorf("step 12c: the fixture received %d request(s) for a forbidden action", hits.Load())
	}
	r.detail(t, "all four shipped presets' mirrors claims hold under the folder check; a Standard preset holding "+
		"get_user refused naming Architect; delete_user under fullstory.architect refused by "+
		"anzen:fullstory-irreversible and withheld in Describe")
}
