package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// presetBase is a valid document declaring one preset, so each test below
// changes exactly one thing (D327).
const presetBase = `
stages: [raw, enriched, triaged, judged]
targets:
  - {ref: kata:alpha, kind: kata, tenant: a, credential: env://TOK}
presets:
  - name: kata.basic
    mirrors: Standard
    explain: read rows and file issues; nothing destructive
    actions: [kata.read, kata.create_issue]
`

func expanded(t *testing.T, src string) *Document {
	t.Helper()
	d := docFromYAML(t, src)
	if err := d.ExpandPresets(); err != nil {
		t.Fatalf("expansion refused a valid document: %v", err)
	}
	return d
}

// TestAPresetExpandsIntoOrdinaryCapabilitiesAtTheirWrittenPosition — every
// consumer downstream sees plain actions, and matched_rule still points at the
// line as written.
func TestAPresetExpandsIntoOrdinaryCapabilitiesAtTheirWrittenPosition(t *testing.T) {
	d := expanded(t, presetBase+`
grants:
  - principal: agent:triage
    allow:
      - {preset: kata.basic, target: kata:alpha, max_bytes: 4096}
      - {action: kata.delete_project, target: kata:alpha}
`)
	allow := d.Grants[0].Allow
	var got []string
	for _, c := range allow {
		got = append(got, c.Action)
		if c.Preset != "" {
			t.Errorf("capability %q still names preset %q after expansion", c.Action, c.Preset)
		}
		if c.TargetRef != "kata:alpha" {
			t.Errorf("capability %q lost its target: %q", c.Action, c.TargetRef)
		}
	}
	if strings.Join(got, ",") != "kata.read,kata.create_issue,kata.delete_project" {
		t.Fatalf("expanded to %v; want the preset's two actions in order, then the written one", got)
	}
	if allow[0].MaxBytes != 4096 || allow[1].MaxBytes != 4096 {
		t.Errorf("max_bytes did not travel with the preset: %d, %d", allow[0].MaxBytes, allow[1].MaxBytes)
	}
	// THE LINE AS WRITTEN: the preset was allow[0], the action allow[1].
	for i, want := range []struct {
		index  int
		suffix string
	}{{0, "/preset:kata.basic"}, {0, "/preset:kata.basic"}, {1, ""}} {
		o := allow[i].Origin
		if o == nil || o.Index != want.index || o.RuleSuffix() != want.suffix {
			t.Errorf("capability %d (%s): origin %+v; want index %d, suffix %q",
				i, allow[i].Action, o, want.index, want.suffix)
		}
	}
	accepts(t, d)

	// IDEMPOTENT: nothing left to expand, nothing changes.
	if err := d.ExpandPresets(); err != nil || len(d.Grants[0].Allow) != 3 {
		t.Errorf("a second expansion changed the document: %v, %d capabilities", err, len(d.Grants[0].Allow))
	}
}

// TestAListWithoutAPresetIsLeftAsWritten — no Origin, so a document that uses no
// preset records exactly what it recorded before D327.
func TestAListWithoutAPresetIsLeftAsWritten(t *testing.T) {
	d := expanded(t, presetBase+`
grants:
  - principal: agent:triage
    allow:
      - {action: kata.read, target: kata:alpha}
`)
	if o := d.Grants[0].Allow[0].Origin; o != nil {
		t.Errorf("a list with no preset gained an origin %+v", o)
	}
}

func TestExpansionRefusesWhatWouldMisleadAReader(t *testing.T) {
	for _, c := range []struct{ name, capability, want string }{
		{"unknown preset", `{preset: kata.nope, target: kata:alpha}`, "not declared in `presets:`"},
		{"action and preset", `{action: kata.read, preset: kata.basic, target: kata:alpha}`, "an action OR a preset"},
		{"rate per action", `{preset: kata.basic, target: kata:alpha, rate_per_hr: 10}`, "PER ACTION"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := docFromYAML(t, presetBase+`
grants:
  - principal: agent:triage
    allow:
      - `+c.capability+"\n")
			err := d.ExpandPresets()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v; want a refusal mentioning %q", err, c.want)
			}
		})
	}
}

// TestAnUnexpandedPresetIsRefusedByValidate — a document built without its
// loader grants nothing it appears to, and says so rather than booting.
func TestAnUnexpandedPresetIsRefusedByValidate(t *testing.T) {
	refuses(t, docFromYAML(t, presetBase+`
grants:
  - principal: agent:triage
    allow:
      - {preset: kata.basic, target: kata:alpha}
`), "never expanded")
}

func TestAPresetIsHeldToItsShape(t *testing.T) {
	for _, c := range []struct{ name, preset, want string }{
		{"undotted name", "{name: basic, explain: x, actions: [kata.read]}", "dotted"},
		{"no explain", "{name: kata.quiet, actions: [kata.read]}", "no `explain`"},
		{"no actions", "{name: kata.empty, explain: x, actions: []}", "no actions"},
		{"pattern", "{name: kata.wide, explain: x, actions: [kata.*]}", "FIXED list"},
		{"duplicate action", "{name: kata.twice, explain: x, actions: [kata.read, kata.read]}", "listed twice"},
		{"declared twice", "{name: kata.basic, explain: again, actions: [kata.read]}", "declared twice"},
	} {
		t.Run(c.name, func(t *testing.T) {
			refuses(t, docFromYAML(t, presetBase+"  - "+c.preset+"\n"), c.want)
		})
	}
}

// TestTheLoaderExpandsAcrossFiles — the connector's fragment and the grant
// naming its preset are different files, which is the normal case (D278).
func TestTheLoaderExpandsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a-deployment.yaml", `
stages: [raw, enriched, triaged, judged]
targets:
  - {ref: kata:alpha, kind: kata, tenant: a, credential: env://TOK}
grants:
  - principal: agent:triage
    allow:
      - {preset: kata.basic, target: kata:alpha}
`)
	write("z-presets.yaml", `
presets:
  - {name: kata.basic, explain: read only, actions: [kata.read]}
`)
	d, err := NewFileSource(dir).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a := d.Grants[0].Allow; len(a) != 1 || a[0].Action != "kata.read" {
		t.Fatalf("loaded %+v; want the preset's one action", a)
	}
	accepts(t, d)
}
