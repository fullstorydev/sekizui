package schemareg

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// The payloads below are the SHAPES read from a real (synthetic) session on
// 2026-09-23: a custom `User Login` whose description is its properties
// re-serialised, a built-in `click` carrying an `email`, and page URLs that
// carry account ids.

const eventBody = `{"type":"object","properties":{
	"device_id":{"type":"string"},"session_id":{"type":"string"},
	"event_time":{"type":"string"},"event_type":{"type":"string"},
	"event_properties":{"type":"object"},"description":{"type":"string"},
	"page_url":{"type":"string"},"withheld":{"type":"boolean"}}}`

func liveFamily() *connector.Family {
	return &connector.Family{
		Discriminator: "event_type", Properties: "event_properties",
		FreeText: []string{"description", "page_url"},
		Kinds: map[string]connector.Kind{
			"click": {Schema: json.RawMessage(`{"type":"object","properties":{"fs-element":{"type":"string"}}}`)},
			"step1": {Schema: json.RawMessage(`{"type":"object","properties":{"run":{"type":"string"}}}`),
				KeepFreeText: []string{"description"}},
			"navigate": {Schema: json.RawMessage(`{"type":"object"}`), KeepFreeText: []string{"page_url"}},
		},
	}
}

// connectorReg registers schemas as the connector "fs" would ship them.
func connectorReg(t *testing.T, schemas ...connector.Schema) *Registry {
	t.Helper()
	r := reg(t, map[string]string{})
	for _, sc := range schemas {
		if problems := r.addConnectorSchema("fs", sc); len(problems) > 0 {
			t.Fatalf("addConnectorSchema: %v", problems)
		}
	}
	return r
}

func family(t *testing.T, other *connector.OtherKinds) *Registry {
	t.Helper()
	f := liveFamily()
	f.Other = other
	return connectorReg(t, connector.Schema{Type: "x.event.v1", Body: json.RawMessage(eventBody), Family: f})
}

func event(kind string, props map[string]any, description string) map[string]any {
	return map[string]any{"device_id": "1", "session_id": "2", "event_time": "2026-09-10T09:21:17.227Z",
		"event_type": kind, "event_properties": props, "description": description,
		"page_url": "https://x/account/1509793"}
}

var skeleton = &connector.OtherKinds{Skeleton: &connector.Skeleton{
	Keep: []string{"device_id", "session_id", "event_time", "event_type"}, Mark: "withheld"}}

var open = &connector.OtherKinds{Open: &connector.Kind{
	Schema: json.RawMessage(`{"type":"object","additionalProperties":true}`), KeepFreeText: []string{"description"}}}

// TestAnUndeclaredKindBecomesItsSkeleton: what survives is which kind, when,
// about what — and the mark. The email in the properties and the SAME email in
// the description do not.
func TestAnUndeclaredKindBecomesItsSkeleton(t *testing.T) {
	r := family(t, skeleton)
	in := event("User Login", map[string]any{"email": "benjamin.clark@example.com", "is_host": false},
		"email=benjamin.clark@example.com,is_host=false,")
	out, shaped := r.Shape("x.event.v1", in)
	if !shaped.Undeclared || !shaped.Withheld || shaped.Refused() {
		t.Fatalf("shaped = %+v; want an undeclared kind, withheld", shaped)
	}
	enc, _ := json.Marshal(out)
	if strings.Contains(string(enc), "BenjaminClark") || strings.Contains(string(enc), "1509793") {
		t.Errorf("the skeleton carries content: %s", enc)
	}
	if out["withheld"] != true || out["event_type"] != "User Login" {
		t.Errorf("the skeleton lost what it keeps: %s", enc)
	}
	if err := r.Validate("x.event.v1", out); err != nil {
		t.Errorf("a shaped skeleton does not validate: %v", err)
	}
	if in["event_properties"].(map[string]any)["email"] == nil {
		t.Error("Shape modified its input")
	}
}

// TestAnOpenOtherKindIsAdmittedWhole (D279): the connector declared other
// kinds open — for Fullstory, the custom events a target asked for — so their
// properties enter as they came and the deployment lenses them. Free text
// survives only as the open kind names it.
func TestAnOpenOtherKindIsAdmittedWhole(t *testing.T) {
	r := family(t, open)
	out, shaped := r.Shape("x.event.v1", event("User Login", map[string]any{"email": "a@b.c", "nested": map[string]any{"x": 1.0}}, "email=a@b.c,"))
	if !shaped.Open || shaped.Refused() || len(shaped.Stripped) != 0 {
		t.Fatalf("shaped = %+v; want admitted open with nothing stripped", shaped)
	}
	if props := out["event_properties"].(map[string]any); props["email"] != "a@b.c" || props["nested"] == nil {
		t.Errorf("an open kind lost properties: %v", props)
	}
	if out["description"] == nil || out["page_url"] != nil {
		t.Errorf("the open kind keeps description and not page_url: %v", out)
	}
	if err := r.Validate("x.event.v1", out); err != nil {
		t.Errorf("a shaped open kind does not validate: %v", err)
	}
}

// TestADeclaredKindKeepsOnlyWhatItDeclares: a `click` carrying `email` keeps
// its declared property, loses the undeclared one, and loses its description
// and URL because click keeps no free text.
func TestADeclaredKindKeepsOnlyWhatItDeclares(t *testing.T) {
	r := family(t, nil)
	out, shaped := r.Shape("x.event.v1", event("click",
		map[string]any{"fs-element": "input", "email": "a@b.c"}, `element (Email) with text "a@b.c"`))
	props := out["event_properties"].(map[string]any)
	if props["fs-element"] != "input" || props["email"] != nil {
		t.Errorf("properties = %v; want fs-element only", props)
	}
	if _, kept := out["description"]; kept || !shaped.FreeText {
		t.Errorf("the description survived a kind that keeps no free text: %v", out)
	}
	if _, kept := out["page_url"]; kept {
		t.Errorf("click kept page_url, which carries an account id: %v", out)
	}
	if !slices.Equal(shaped.Stripped, []string{"event_properties.email"}) {
		t.Errorf("stripped = %v, want [event_properties.email]", shaped.Stripped)
	}
	if err := r.Validate("x.event.v1", out); err != nil {
		t.Errorf("a shaped click does not validate: %v", err)
	}
	kept, _ := r.Shape("x.event.v1", event("step1", map[string]any{"run": "r"}, "run=r,"))
	if kept["description"] != "run=r," || kept["page_url"] != nil {
		t.Errorf("step1 keeps description only: %v", kept)
	}
	nav, _ := r.Shape("x.event.v1", event("navigate", map[string]any{}, "HomePage"))
	if nav["page_url"] == nil || nav["description"] != nil {
		t.Errorf("navigate keeps page_url only: %v", nav)
	}
}

// TestEveryTypeIsClosedByDefault is D279's generalisation: a type with NO kinds
// — a kata row, a Jira issue — keeps only what its schema names, at every
// depth and inside arrays, unless an object says additionalProperties: true.
func TestEveryTypeIsClosedByDefault(t *testing.T) {
	r := connectorReg(t, connector.Schema{Type: "jira.issue.v1", Body: json.RawMessage(`{"type":"object",
		"properties":{"key":{"type":"string"},
		  "fields":{"type":"object","properties":{"summary":{"type":"string"},
		    "labels":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"}}}},
		    "custom":{"type":"object","additionalProperties":true}}}}}`)})
	in := map[string]any{"key": "PROJ-1", "secret": "x",
		"fields": map[string]any{"summary": "s", "reporter": map[string]any{"emailAddress": "a@b.c"},
			"labels": []any{map[string]any{"name": "l", "owner": "a@b.c"}},
			"custom": map[string]any{"anything": "goes"}}}
	out, shaped := r.Shape("jira.issue.v1", in)
	enc, _ := json.Marshal(out)
	if strings.Contains(string(enc), "a@b.c") || strings.Contains(string(enc), "secret") {
		t.Errorf("an undeclared field survived: %s", enc)
	}
	if !strings.Contains(string(enc), `"anything":"goes"`) || !strings.Contains(string(enc), `"summary":"s"`) {
		t.Errorf("a declared or explicitly open field was lost: %s", enc)
	}
	want := []string{"fields.labels[0].owner", "fields.reporter", "secret"}
	if !slices.Equal(shaped.Stripped, want) {
		t.Errorf("stripped = %v, want %v", shaped.Stripped, want)
	}
	if err := r.Validate("jira.issue.v1", out); err != nil {
		t.Errorf("a shaped issue does not validate: %v", err)
	}
	if err := r.Validate("jira.issue.v1", in); err == nil {
		t.Error("an unshaped issue validated; shaped ⇔ valid")
	}
}

// TestWithoutOtherAnUndeclaredKindIsRefused: a family that says nothing about
// other kinds admits none.
func TestWithoutOtherAnUndeclaredKindIsRefused(t *testing.T) {
	r := family(t, nil)
	out, shaped := r.Shape("x.event.v1", event("User Login", map[string]any{}, ""))
	if !shaped.Refused() {
		t.Errorf("shaped = %+v; want refused", shaped)
	}
	if err := r.Validate("x.event.v1", out); err == nil {
		t.Error("an undeclared kind validated with no `other` declared")
	}
}

// TestAFamilyThatAdmitsContentIsRefusedAtLoad: every way to write a family
// whose "withholding" publishes what it withholds.
func TestAFamilyThatAdmitsContentIsRefusedAtLoad(t *testing.T) {
	cases := map[string]func(*connector.Family){
		"skeleton keeps the properties": func(f *connector.Family) {
			f.Other = &connector.OtherKinds{Skeleton: &connector.Skeleton{Keep: []string{"event_type", "event_properties"}, Mark: "withheld"}}
		},
		"skeleton keeps free text": func(f *connector.Family) {
			f.Other = &connector.OtherKinds{Skeleton: &connector.Skeleton{Keep: []string{"event_type", "description"}, Mark: "withheld"}}
		},
		"skeleton omits the kind": func(f *connector.Family) {
			f.Other = &connector.OtherKinds{Skeleton: &connector.Skeleton{Keep: []string{"event_time"}, Mark: "withheld"}}
		},
		"marks with a string": func(f *connector.Family) {
			f.Other = &connector.OtherKinds{Skeleton: &connector.Skeleton{Keep: []string{"event_type"}, Mark: "page_url"}}
		},
		"both skeleton and open": func(f *connector.Family) {
			f.Other = &connector.OtherKinds{Skeleton: skeleton.Skeleton, Open: open.Open}
		},
		"a kind with no schema":   func(f *connector.Family) { f.Kinds["bare"] = connector.Kind{} },
		"a nested free-text path": func(f *connector.Family) { f.FreeText = []string{"event_properties.x"} },
		"keeps a field that is not free text": func(f *connector.Family) {
			f.Kinds["navigate"] = connector.Kind{Schema: json.RawMessage(`{"type":"object"}`), KeepFreeText: []string{"page_ur"}}
		},
	}
	for name, mutate := range cases {
		f := liveFamily()
		mutate(f)
		r := reg(t, map[string]string{})
		if p := r.addConnectorSchema("fs", connector.Schema{Type: "x.event.v1", Body: json.RawMessage(eventBody), Family: f}); len(p) == 0 {
			t.Errorf("%s: loaded", name)
		}
	}
}

// TestOneTypeOneOwner is D279's ownership with D282's consequence: a
// connector's defect QUARANTINES THAT CONNECTOR, naming why, while a healthy
// connector beside it registers and serves; two connectors claiming one type
// are both quarantined; a rule naming a quarantined type is inert, not fatal;
// and a DOCUMENT declaring a connector's type still refuses the boot.
func TestOneTypeOneOwner(t *testing.T) {
	body := json.RawMessage(`{"type":"object"}`)
	driver := func(kind, typ string, schemas ...connector.Schema) stubDriver {
		return stubDriver{kind: kind, schemas: schemas, actions: []connector.ActionSpec{{
			Name: kind + ".poll", Description: "Poll it.", OutputType: typ}}}
	}
	healthy := driver("ok", "ok.event.v1", connector.Schema{Type: "ok.event.v1", Body: body})
	for name, c := range map[string]struct {
		bad  stubDriver
		want string
	}{
		"no schema shipped": {driver("fs", "fs.event.v1"),
			`declares output type "fs.event.v1" (action "fs.poll") and ships NO SCHEMA`},
		"a schema for nothing declared": {driver("fs", "fs.event.v1",
			connector.Schema{Type: "fs.event.v1", Body: body}, connector.Schema{Type: "fs.other.v1", Body: body}),
			`ships a schema for "fs.other.v1", which none of its actions declares`},
		"a schema that does not load": {driver("fs", "fs.event.v1",
			connector.Schema{Type: "fs.event.v1", Body: json.RawMessage(`{"type":"string","enum":["a"]}`)}),
			`enum`},
	} {
		reg, err := ForDeployment(&config.Document{}, map[string]connector.Driver{"fs": c.bad, "ok": healthy})
		if err != nil {
			t.Fatalf("%s: the whole registry was refused for one connector: %v", name, err)
		}
		if why := reg.Quarantined()["fs"]; !strings.Contains(why, c.want) {
			t.Errorf("%s: quarantine reason %q; want it to say %q", name, why, c.want)
		}
		if _, q := reg.Quarantined()["ok"]; q || !reg.Has("ok.event.v1") {
			t.Errorf("%s: the healthy connector was affected", name)
		}
		if reg.Has("fs.event.v1") {
			t.Errorf("%s: a quarantined connector's type was registered", name)
		}
		if kind, q := reg.QuarantinedBy("fs.event.v1"); !q || kind != "fs" {
			t.Errorf("%s: QuarantinedBy(fs.event.v1) = %q, %v", name, kind, q)
		}
	}

	// TWO CLAIMANTS, BOTH QUARANTINED: neither is more right, and path order
	// must not decide what a type means.
	reg, err := ForDeployment(&config.Document{}, map[string]connector.Driver{
		"a": driver("a", "shared.v1", connector.Schema{Type: "shared.v1", Body: body}),
		"b": driver("b", "shared.v1", connector.Schema{Type: "shared.v1", Body: body})})
	if err != nil {
		t.Fatal(err)
	}
	if q := reg.Quarantined(); q["a"] == "" || q["b"] == "" || reg.Has("shared.v1") {
		t.Errorf("two claimants: quarantined %v, registered %v; want both quarantined, type unregistered",
			q, reg.Has("shared.v1"))
	}

	// A DOCUMENT FAULT still refuses: the operator's configuration is wrong.
	if _, err := ForDeployment(&config.Document{PayloadSchemas: map[string]json.RawMessage{"ok.event.v1": body}},
		map[string]connector.Driver{"ok": healthy}); err == nil ||
		!strings.Contains(err.Error(), `the document declares payload schema "ok.event.v1", which connector "ok" owns`) {
		t.Errorf("a document declaring a connector's type: err = %v", err)
	}
}

// TestARuleNamingAQuarantinedTypeIsInertNotFatal: the boot's schema check does
// not fail because a rule expects the type of a quarantined connector — that
// would take the deployment down through the rules that mention it (D282).
func TestARuleNamingAQuarantinedTypeIsInertNotFatal(t *testing.T) {
	bad := stubDriver{kind: "fs", actions: []connector.ActionSpec{{Name: "fs.poll", Description: "Poll it.",
		OutputType: "fs.event.v1"}}}
	if err := check(t, `
reflexes:
  - name: r
    principal: reflex:x
    enabled: true
    expects_type: fs.event.v1
    action: kata.create_issue
    target: kata:alpha
shin:
  - name: l
    enabled: true
    mode: imposed
    applies_to: ["agent:x"]
    type: fs.event.v1
    withholds: [anything]
    because: the connector is quarantined
`, bad); err != nil {
		t.Errorf("a rule and a lens naming a quarantined type failed the boot: %v", err)
	}
}

// TestAKeywordThatIsNotEnforcedIsRefused (D278): `enum` would read as a
// constraint the checker never applies, and a typo'd `additonalProperties`
// would silently leave the schema open. Annotations describe and pass.
func TestAKeywordThatIsNotEnforcedIsRefused(t *testing.T) {
	for _, body := range []string{
		`{"type":"string","enum":["a","b"]}`,
		`{"type":"object","additonalProperties":false}`,
		`{"type":"object","properties":{"x":{"type":"string","pattern":"^a"}}}`,
	} {
		if _, err := New(map[string]json.RawMessage{"x.v1": json.RawMessage(body)}); err == nil {
			t.Errorf("%s: loaded; its keyword would read as enforced", body)
		}
	}
	if _, err := New(map[string]json.RawMessage{"x.v1": json.RawMessage(
		`{"type":"object","title":"t","description":"d","$comment":"c","examples":[{}]}`)}); err != nil {
		t.Errorf("annotations were refused: %v", err)
	}
}

// TestALensPathResolvesThroughTheFamily (D292): a property a declared kind
// carries is DECLARED; one no declared kind carries is PLAUSIBLE under an open
// kind and an error without one; a misspelled carrier is an error either way.
func TestALensPathResolvesThroughTheFamily(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		other      *connector.OtherKinds
		plausible  bool
		refused    bool
	}{
		{"a declared kind's property", "event_properties.fs-element", nil, false, false},
		{"the same, in an open family", "event_properties.fs-element", open, false, false},
		{"a top-level field", "session_id", nil, false, false},
		{"under an open kind", "event_properties.is_host", open, true, false},
		{"under a skeleton", "event_properties.is_host", skeleton, false, true},
		{"with no other kinds", "event_properties.is_host", nil, false, true},
		{"a misspelled carrier, open", "event_propertes.is_host", open, false, true},
		{"a declared property's child", "event_properties.fs-element.x", nil, false, true},
	} {
		plausible, err := family(t, tc.other).LensPath("x.event.v1", tc.path)
		if (err != nil) != tc.refused || plausible != tc.plausible {
			t.Errorf("%s: LensPath(%q) = (plausible %v, %v); want plausible %v, refused %v",
				tc.name, tc.path, plausible, err, tc.plausible, tc.refused)
		}
	}
}
