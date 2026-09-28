package config

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func loadPath(t *testing.T, path string) (*Document, error) {
	t.Helper()
	return NewFileSource(path).Load(context.Background())
}

func mustFail(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v; want one mentioning %q", err, want)
	}
}

// TestTheParseIsStrict is D278's strict half: each of these parsed
// "successfully" under the lax loader and changed what the deployment meant.
func TestTheParseIsStrict(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct{ body, want string }{
		// A typo in a governance field disabled it in silence.
		"unknown field": {"shin:\n  - name: s\n    withhold: [user.email]\n", `unknown field "withhold"`},
		// The second key replaced the first: acceptance.local.yaml's defect.
		"duplicate key": {"targets: []\ngrants: []\ntargets: []\n", `"targets" already set`},
		// Strictness stopped at a custom UnmarshalJSON until it carried it on.
		"typo past a custom decoder": {"grants:\n  - principal: a\n    subscribe:\n      - {subject: x, targetz: [y]}\n",
			`unknown field "targetz"`},
		"typo in a predicate": {"reflexes:\n  - name: r\n    where: [{path: a, opp: eq, value: 1}]\n", `unknown field "opp"`},
	} {
		_, err := loadPath(t, write(t, dir, strings.ReplaceAll(name, " ", "_")+".yaml", c.body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v; want %q", name, err, c.want)
		}
	}
}

// TestADirectoryComposesWithNoOverride is D278's composable half: a
// connector's declaration pack beside the deployment, merged; and every way a
// later file could replace an earlier one, refused naming both files.
func TestADirectoryComposesWithNoOverride(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "deployment.yaml", "stages: [raw, enriched]\ntargets:\n  - {ref: a:1, kind: kata}\n")
	write(t, dir, "connectors/fullstory.yaml",
		"payload_schemas:\n  x.v1: {type: object}\ntargets:\n  - {ref: b:1, kind: kata}\n")
	write(t, dir, ".swap.yaml", "stages: [bogus]\n")       // hidden: not configuration
	write(t, dir, ".git/config.yaml", "stages: [bogus]\n") // hidden directory
	write(t, dir, "README.md", "not yaml\n")
	doc, err := loadPath(t, dir)
	if err != nil {
		t.Fatalf("composing: %v", err)
	}
	if len(doc.Targets) != 2 || doc.Targets[0].Ref != "b:1" || doc.Targets[1].Ref != "a:1" ||
		!reflect.DeepEqual(doc.Stages, []string{"raw", "enriched"}) || doc.PayloadSchemas["x.v1"] == nil {
		t.Errorf("composed wrongly: targets %v stages %v schemas %v", doc.Targets, doc.Stages, doc.PayloadSchemas)
	}
	if f := doc.Files(); len(f) != 2 || !strings.HasSuffix(f[0], "connectors/fullstory.yaml") {
		t.Errorf("files = %v; want the two visible files in path order", f)
	}

	for name, c := range map[string]struct{ a, b, want string }{
		"a key declared twice": {"payload_schemas:\n  x.v1: {type: object}\n",
			"payload_schemas:\n  x.v1: {type: string}\n", `payload_schemas "x.v1" is declared in`},
		"a whole value set twice": {"stages: [raw]\n", "stages: [raw, enriched]\n", "stages is set in"},
	} {
		d := t.TempDir()
		write(t, d, "a.yaml", c.a)
		write(t, d, "zz.yaml", c.b)
		_, err := loadPath(t, d)
		mustFail(t, err, c.want)
		if err != nil && (!strings.Contains(err.Error(), "a.yaml") || !strings.Contains(err.Error(), "zz.yaml")) {
			t.Errorf("%s: the refusal does not name both files: %v", name, err)
		}
	}

	// AN ENTRY DECLARED IN TWO FILES is Validate's "declared twice", as it is
	// within one file.
	d := t.TempDir()
	write(t, d, "a.yaml", "targets:\n  - {ref: a:1, kind: kata}\n")
	write(t, d, "b.yaml", "targets:\n  - {ref: a:1, kind: kata}\n")
	doc, err = loadPath(t, d)
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, doc.Validate(), `target "a:1": declared twice`)

	_, err = loadPath(t, t.TempDir())
	mustFail(t, err, "no .yaml or .yml files")
}

// TestEveryDocumentFieldHasAMergeClass: a new Document field must say how it
// composes before a directory can carry it.
func TestEveryDocumentFieldHasAMergeClass(t *testing.T) {
	typ := reflect.TypeOf(Document{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		c, ok := mergeClasses[f.Name]
		switch {
		case !ok:
			t.Errorf("Document.%s has no merge class; add it to mergeClasses (D278)", f.Name)
		case c == keyed && f.Type.Kind() != reflect.Map:
			t.Errorf("Document.%s is keyed but is a %s", f.Name, f.Type.Kind())
		case c == entries && f.Type.Kind() != reflect.Slice:
			t.Errorf("Document.%s is entries but is a %s", f.Name, f.Type.Kind())
		}
	}
	for name := range mergeClasses {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("mergeClasses names %q, which Document does not have", name)
		}
	}
}

// TestEveryConfigDocumentInTheTreeLoads: a document nothing loads rots in
// silence — the gitignored acceptance.local.yaml, a hand-copied overlay, did not
// load for three phases and under the lax parser had REPLACED every target with
// its one. Each committed document is loaded strictly and validated as a boot
// would. (A local overlay is now a directory: the shared file plus one more.)
func TestEveryConfigDocumentInTheTreeLoads(t *testing.T) {
	for _, p := range []string{
		"testdata/valid.yaml",
		"../../internal/acceptance/acceptance.yaml",
		"../../internal/connectors/jira/jira.yaml",
		// A DIRECTORY since D327: kata.yaml grants a preset declared in the
		// kata fragment dropped in beside it, so the file alone does not load —
		// exactly as a deployment's grants file alone would not.
		"../../hako/reference",
		"../../hako/solution/notes.yaml",
		"../../hako/exercise/notes.yaml",
	} {
		doc, err := loadPath(t, p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if err := doc.Validate(); err != nil {
			t.Errorf("%s does not validate: %v", p, err)
		}
	}
}
