package config

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func load(t *testing.T, path string) *Document {
	t.Helper()
	doc, err := NewFileSource(path).Load(context.Background())
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}
	return doc
}

// TestLoadsDocumentedYAMLFormat is the test that matters most here.
//
// DESIGN §4.7 shows operators a snake_case YAML format. Go field names are
// CamelCase, and encoding/json's case-insensitive fallback matches baseUrl but
// NOT base_url — so without explicit tags this file would parse "successfully"
// into a Document with empty fields. Silent, and exactly the class of bug where
// documentation and code drift apart.
func TestLoadsDocumentedYAMLFormat(t *testing.T) {
	doc := load(t, filepath.Join("testdata", "valid.yaml"))

	if len(doc.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(doc.Targets))
	}
	alpha := doc.Targets[0]

	// Each of these binds through a snake_case or renamed tag. A missing tag
	// shows up as a zero value rather than an error.
	if alpha.Ref != "kata:alpha" {
		t.Errorf("ref = %q", alpha.Ref)
	}
	if alpha.BaseURL != "https://alpha.invalid" {
		t.Errorf(`base_url did not bind to BaseURL: %q`, alpha.BaseURL)
	}
	if alpha.CredentialRef != "env://SEKIZUI_FAKE_ALPHA_TOKEN" {
		t.Errorf(`credential did not bind to CredentialRef: %q`, alpha.CredentialRef)
	}
	if alpha.Residency != "eu" {
		t.Errorf("residency = %q", alpha.Residency)
	}

	if got := doc.Stages; len(got) != 4 || got[0] != "raw" || got[3] != "judged" {
		t.Errorf("stages = %v", got)
	}

	var mesh *GrantSpec
	for i := range doc.Grants {
		if doc.Grants[i].Principal == "mesh:primary" {
			mesh = &doc.Grants[i]
		}
	}
	if mesh == nil {
		t.Fatal("mesh:primary grant not parsed")
	}
	if len(mesh.MaySpeakFor) != 2 {
		t.Errorf(`may_speak_for did not bind to MaySpeakFor: %v`, mesh.MaySpeakFor)
	}

	triage := doc.Grants[0]
	if len(triage.Allow) != 1 || triage.Allow[0].TargetRef != "kata:alpha" {
		t.Errorf(`target did not bind to TargetRef: %+v`, triage.Allow)
	}
	if triage.Allow[0].RatePerHr != 10 {
		t.Errorf("rate_per_hr = %d, want 10", triage.Allow[0].RatePerHr)
	}
	if len(triage.Escalate) != 1 {
		t.Errorf("escalate = %+v", triage.Escalate)
	}
	// `where: {project: [PROJ]}` lands as map[string]any holding a slice.
	if _, ok := triage.Allow[0].Where["project"]; !ok {
		t.Errorf("where did not parse: %+v", triage.Allow[0].Where)
	}
}

// TestVersionDefaultsFromTheFile. Document.Version names which configuration
// authorised a decision (§4.9a.2), so it must never be empty just because
// nobody wrote one by hand.
func TestVersionDefaultsFromTheFile(t *testing.T) {
	doc := load(t, filepath.Join("testdata", "valid.yaml"))

	if doc.Version == "" {
		t.Fatal("Version empty; an audit row could not name the config in force")
	}
	if !strings.HasPrefix(doc.Version, "valid.yaml@") {
		t.Errorf("Version = %q, want valid.yaml@<mtime>", doc.Version)
	}
}

func TestValidDocumentPasses(t *testing.T) {
	if err := load(t, filepath.Join("testdata", "valid.yaml")).Validate(); err != nil {
		t.Fatalf("the reference config was rejected: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want string
	}{
		"credential material instead of a reference": {
			yaml: `
targets: [{ref: t, kind: kata, credential: "hunter2-actual-secret"}]`,
			want: "not a reference",
		},
		"wildcarded may_speak_for": {
			yaml: `
targets: [{ref: t, kind: kata}]
grants: [{principal: mesh, may_speak_for: ["agent:*"]}]`,
			want: "wildcarded",
		},
		"grant referencing an unknown target": {
			yaml: `
targets: [{ref: t, kind: kata}]
grants: [{principal: a, allow: [{action: kata.do, target: nope}]}]`,
			want: "unknown target",
		},
		"duplicate principal": {
			yaml: `
targets: [{ref: t, kind: kata}]
grants:
  - {principal: a, allow: [{action: x, target: t}]}
  - {principal: a, allow: [{action: y, target: t}]}`,
			want: "declared twice",
		},
		"duplicate target": {
			yaml: `
targets:
  - {ref: t, kind: kata}
  - {ref: t, kind: kata}`,
			want: "declared twice",
		},
		"target missing kind": {
			yaml: `
targets: [{ref: t}]`,
			want: "missing kind",
		},
		"capability with no action": {
			yaml: `
targets: [{ref: t, kind: kata}]
grants: [{principal: a, allow: [{target: t}]}]`,
			want: "no action",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var doc Document
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatalf("fixture did not parse: %v", err)
			}

			err := doc.Validate()
			if err == nil {
				t.Fatalf("accepted: %s", tc.yaml)
			}
			if !errors.Is(err, fault.KindConfig) {
				t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestValidateReportsEveryProblem — an operator fixing config wants the whole
// list, not one error per restart.
func TestValidateReportsEveryProblem(t *testing.T) {
	var doc Document
	err := yaml.Unmarshal([]byte(`
targets: [{ref: t}]
grants: [{principal: a, allow: [{action: x, target: nope}], may_speak_for: ["*"]}]`), &doc)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	verr := doc.Validate()
	if verr == nil {
		t.Fatal("accepted a document with three problems")
	}
	for _, want := range []string{"missing kind", "unknown target", "wildcarded"} {
		if !strings.Contains(verr.Error(), want) {
			t.Errorf("error omits %q: %v", want, verr)
		}
	}
}

// TestSecretCannotBeParsedFromYAML proves the claim that motivated choosing
// sigs.k8s.io/yaml over gopkg.in/yaml.v3.
//
// That library converts YAML to JSON and delegates to encoding/json, so
// connector.Secret's UnmarshalJSON — which refuses outright — applies. A
// yaml.v3-style library uses its own reflection, would never consult
// UnmarshalJSON, and would happily populate a credential from a config file.
//
// This is an ASSERTION ABOUT A DEPENDENCY, which is exactly the kind of thing
// that silently changes under an upgrade. Hence a test rather than a comment.
func TestSecretCannotBeParsedFromYAML(t *testing.T) {
	var holder struct {
		Cred connector.Secret `json:"cred"`
	}

	err := yaml.Unmarshal([]byte(`cred: "a-real-looking-token"`), &holder)
	if err == nil {
		t.Fatal("YAML populated a Secret; credential material can now enter through " +
			"a config file, defeating §4.7. Has the YAML library stopped routing " +
			"through encoding/json?")
	}
	if !strings.Contains(err.Error(), "SecretProvider") {
		t.Errorf("refusal did not come from Secret.UnmarshalJSON: %v", err)
	}
}

func TestFileSourceErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := NewFileSource(filepath.Join("testdata", "nope.yaml")).Load(context.Background())
		if err == nil {
			t.Fatal("missing file accepted")
		}
		if !errors.Is(err, fault.KindConfig) {
			t.Errorf("kind = %v, want KindConfig — a missing config file is an "+
				"operator problem, not a Sekizui bug", fault.KindOf(err))
		}
		if !strings.Contains(err.Error(), "nope.yaml") {
			t.Errorf("error does not name the file: %v", err)
		}
	})

	t.Run("malformed yaml", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(p, []byte("targets: [{{{"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := NewFileSource(p).Load(context.Background())
		if err == nil {
			t.Fatal("malformed YAML accepted")
		}
		if !errors.Is(err, fault.KindConfig) {
			t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := NewFileSource(filepath.Join("testdata", "valid.yaml")).Load(ctx)
		if err == nil {
			t.Fatal("read proceeded on a cancelled context")
		}
	})
}

// TestWatchReportsUnsupported. The Source contract says "nil channel if
// unsupported", and returning nil is how a source says so — as opposed to a
// channel that never delivers, which looks like a working watcher.
func TestWatchReportsUnsupported(t *testing.T) {
	ch, err := NewFileSource("irrelevant").Watch(context.Background())
	if err != nil {
		t.Fatalf("Watch returned an error rather than reporting unsupported: %v", err)
	}
	if ch != nil {
		t.Error("Watch returned a non-nil channel; FileSource cannot watch, and a " +
			"channel that never delivers is indistinguishable from one with no changes")
	}
}

func TestEnvProvider(t *testing.T) {
	p := EnvProvider{}

	if p.Scheme() != "env" {
		t.Errorf("Scheme = %q", p.Scheme())
	}

	t.Setenv("SEKIZUI_TEST_TOKEN", "shhh")
	res, err := p.Resolve(context.Background(), "env://SEKIZUI_TEST_TOKEN")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := string(res.Material); got != "shhh" {
		t.Errorf("Resolve = %q", got)
	}

	// Unset must be distinguishable from empty: an empty variable is nearly
	// always a misconfigured deployment, and returning nothing silently
	// produces a 401 far from the cause.
	if _, err := p.Resolve(context.Background(), "env://SEKIZUI_DEFINITELY_UNSET"); err == nil {
		t.Error("unset variable resolved successfully")
	}

	t.Setenv("SEKIZUI_EMPTY", "")
	if _, err := p.Resolve(context.Background(), "env://SEKIZUI_EMPTY"); err != nil {
		t.Errorf("an explicitly-empty variable should resolve: %v", err)
	}

	if _, err := p.Resolve(context.Background(), "gcp-sm://projects/p/secrets/s/versions/1"); err == nil {
		t.Error("EnvProvider resolved a ref belonging to another scheme")
	}
}

// --- Loader lifecycle -------------------------------------------------------

// spine's interfaces, restated locally.
//
// pkg/ must not import internal/, so this is how the structural satisfaction
// gets asserted where it is caused. Go has no "implements" clause: Loader
// satisfies spine.Component by having the right methods, and would stop
// satisfying it silently if a signature changed — the failure would otherwise
// surface at the wiring site in cmd/sekizui with no clue where it came from.
type (
	component interface {
		Name() string
		Start(context.Context) error
		Stop(context.Context) error
	}
	validator      interface{ Validate(context.Context) error }
	healthReporter interface{ Health(context.Context) error }
)

func TestLoaderSatisfiesSpineInterfaces(t *testing.T) {
	var l any = NewLoader(NewFileSource("x"), quiet())

	if _, ok := l.(component); !ok {
		t.Error("Loader no longer satisfies spine.Component")
	}
	if _, ok := l.(validator); !ok {
		t.Error("Loader no longer satisfies spine.Validator; config would not be " +
			"rejected at boot")
	}
	if _, ok := l.(healthReporter); !ok {
		t.Error("Loader no longer satisfies spine.HealthReporter; P0 exit criterion 5 " +
			"requires readiness to fail when config is unloaded")
	}
}

func TestLoaderLifecycle(t *testing.T) {
	ctx := context.Background()
	l := NewLoader(NewFileSource(filepath.Join("testdata", "valid.yaml")), quiet())

	// P0 exit criterion 5: readiness fails when config is unloaded.
	if err := l.Health(ctx); err == nil {
		t.Error("healthy before any config was loaded")
	}
	if l.Document() != nil {
		t.Error("Document non-nil before Validate")
	}

	// Start before Validate must fail loudly rather than serving a nil document.
	if err := l.Start(ctx); err == nil {
		t.Error("Start succeeded without Validate; every consumer would get nil")
	}

	if err := l.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := l.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := l.Health(ctx); err != nil {
		t.Errorf("unhealthy after a successful load: %v", err)
	}
	if doc := l.Document(); doc == nil || len(doc.Targets) != 2 {
		t.Errorf("Document not available after Start: %+v", doc)
	}

	// After Stop, readiness must fail again — Started and Healthy are
	// different questions, which is why Loader implements HealthReporter.
	if err := l.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := l.Health(ctx); err == nil {
		t.Error("still healthy after Stop")
	}
	// Idempotent, per the Component contract.
	if err := l.Stop(ctx); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestLoaderValidateRejectsBadConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(p, []byte("grants: [{principal: a, may_speak_for: [\"*\"]}]"), 0o600)

	l := NewLoader(NewFileSource(p), quiet())
	if err := l.Validate(context.Background()); err == nil {
		t.Fatal("Validate accepted a wildcarded may_speak_for")
	}
	// A rejected load must leave nothing in force.
	if l.Document() != nil {
		t.Error("a rejected document was retained")
	}
}
