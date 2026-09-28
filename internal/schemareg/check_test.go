package schemareg

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// D42 promises that boot validates every field path a rule references. It was
// implemented and called by NOTHING — the package had zero callers outside its
// own tests, because the check needs the schema registry and `pkg/config` cannot
// import `internal/` (D88).
//
// These tests exercise the Checker through its Validate method, which is the
// thing spine actually calls, rather than through the helpers underneath it.

func check(t *testing.T, docYAML string, drivers ...connector.Driver) error {
	t.Helper()

	var doc config.Document
	if err := yaml.Unmarshal([]byte(docYAML), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	byKind := map[string]connector.Driver{}
	for _, d := range drivers {
		byKind[d.Kind()] = d
	}
	return NewChecker(func() *config.Document { return &doc }, func(*config.Document) map[string]connector.Driver { return byKind },
		slog.New(slog.NewTextHandler(io.Discard, nil))).Validate(context.Background())
}

func mustRefuse(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("validation passed; expected a refusal mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("refusal does not mention %q:\n%v", want, err)
	}
}

const schemas = `
payload_schemas:
  fullstory.rage_click.v1:
    type: object
    properties:
      session_id: {type: string}
      url: {type: string}
      clicks: {type: integer}
  fullstory.friction.v1:
    type: object
    properties:
      session_id: {type: string}
      severity: {type: string}
`

// TestACarriedFieldMissingFromTheOUTPUTSchemaIsRefused is the check that did not
// exist before D88, and the one with teeth.
//
// The rule carries `url`, its INPUT schema declares it, and its OUTPUT schema
// does not. Everything downstream — every lens, every rule consuming the
// enriched type — looks for a field that never arrives, and nothing says so.
func TestACarriedFieldMissingFromTheOUTPUTSchemaIsRefused(t *testing.T) {
	err := check(t, schemas+`
reflexes:
  - name: enrich
    principal: reflex:x
    enabled: true
    consumes: sekizui.raw.>
    expects_type: fullstory.rage_click.v1
    publish_to: sekizui.enriched.friction
    publishes_type: fullstory.friction.v1
    carry: [session_id, url]
`)
	mustRefuse(t, err, `carries "url" into "fullstory.friction.v1"`)
}

// TestACarriedFieldMissingFromTheINPUTSchemaIsRefused — D42's original promise.
func TestACarriedFieldMissingFromTheINPUTSchemaIsRefused(t *testing.T) {
	err := check(t, schemas+`
reflexes:
  - name: enrich
    principal: reflex:x
    enabled: true
    expects_type: fullstory.rage_click.v1
    publish_to: sekizui.enriched.friction
    publishes_type: fullstory.friction.v1
    carry: [session_id, nonexistent]
`)
	mustRefuse(t, err, `carries "nonexistent"`)
}

// TestPublishingWithoutDeclaringATypeIsRefused (D88). The type used to be
// derived from the bus subject, producing something unversioned and
// unregistered while a comment claimed it was versioned per D41.
func TestPublishingWithoutDeclaringATypeIsRefused(t *testing.T) {
	err := check(t, schemas+`
reflexes:
  - name: enrich
    principal: reflex:x
    enabled: true
    expects_type: fullstory.rage_click.v1
    publish_to: sekizui.enriched.friction_detected
    carry: [session_id]
`)
	mustRefuse(t, err, "declares no publishes_type")
}

// TestAnUnversionedPublishedTypeIsRefused — D41's dual-publish migration depends
// on v1 and v2 being distinct types.
func TestAnUnversionedPublishedTypeIsRefused(t *testing.T) {
	err := check(t, schemas+`
reflexes:
  - name: enrich
    principal: reflex:x
    enabled: true
    expects_type: fullstory.rage_click.v1
    publish_to: sekizui.enriched.friction
    publishes_type: friction_detected
    carry: [session_id]
`)
	mustRefuse(t, err, "no version suffix")
}

// TestAnAddedFieldMissingFromTheOutputSchemaIsRefused — `with:` invents fields
// too, and one the schema does not declare is as invisible as a missing carry.
func TestAnAddedFieldMissingFromTheOutputSchemaIsRefused(t *testing.T) {
	err := check(t, schemas+`
reflexes:
  - name: enrich
    principal: reflex:x
    enabled: true
    expects_type: fullstory.rage_click.v1
    publish_to: sekizui.enriched.friction
    publishes_type: fullstory.friction.v1
    carry: [session_id]
    with: {undeclared_key: value}
`)
	mustRefuse(t, err, `adds "undeclared_key"`)
}

// TestADebounceKeyThatDoesNotExistIsRefused. A debounce key naming an absent
// field collapses every event into one bucket, so the rule fires once and looks
// like it is working.
func TestADebounceKeyThatDoesNotExistIsRefused(t *testing.T) {
	err := check(t, schemas+`
reflexes:
  - name: r
    principal: reflex:x
    enabled: true
    expects_type: fullstory.rage_click.v1
    debounce_key: sesion_id
    action: kata.create_issue
    target: kata:alpha
`)
	mustRefuse(t, err, "collapses every event into one bucket")
}

// TestAPredicateFieldPathIsChecked — every path a `where` names is checked
// against the payload schema (D42, D263). This was best-effort regexp
// extraction of `input.x` from a Rego string; a structured predicate names its
// paths, so none go unchecked.
func TestAPredicateFieldPathIsChecked(t *testing.T) {
	err := check(t, schemas+`
reflexes:
  - name: r
    principal: reflex:x
    enabled: true
    expects_type: fullstory.rage_click.v1
    where: [{path: clicsk, op: gt, value: 5}]
    action: kata.create_issue
    target: kata:alpha
`)
	mustRefuse(t, err, `where[0] references "clicsk"`)
}

// TestAValidRuleIsAccepted, so the tests above prove something.
func TestAValidRuleIsAccepted(t *testing.T) {
	if err := check(t, schemas+`
reflexes:
  - name: enrich
    principal: reflex:x
    enabled: true
    expects_type: fullstory.rage_click.v1
    where: [{path: clicks, op: gt, value: 5}]
    debounce_key: session_id
    publish_to: sekizui.enriched.friction
    publishes_type: fullstory.friction.v1
    carry: [session_id]
    with: {severity: high}
`); err != nil {
		t.Fatalf("a valid rule was refused: %v", err)
	}
}

// TestADisabledRuleIsNotChecked — a parked rule is not going to silently stop
// matching, and refusing boot over one would make disabling a broken rule
// impossible.
func TestADisabledRuleIsNotChecked(t *testing.T) {
	if err := check(t, schemas+`
reflexes:
  - name: parked
    principal: reflex:x
    enabled: false
    expects_type: fullstory.rage_click.v1
    carry: [nonexistent]
`); err != nil {
		t.Fatalf("a disabled rule was validated: %v", err)
	}
}

// --- driver output types (D88) ----------------------------------------------

type stubDriver struct {
	kind    string
	actions []connector.ActionSpec
	schemas []connector.Schema
}

func (d stubDriver) Kind() string                         { return d.kind }
func (d stubDriver) Actions() []connector.ActionSpec      { return d.actions }
func (d stubDriver) Schemas() ([]connector.Schema, error) { return d.schemas, nil }
func (d stubDriver) Meter() connector.Meter               { return connector.Meter{} }
func (d stubDriver) Health(context.Context, connector.Target) error {
	return nil
}

func (d stubDriver) Execute(context.Context, connector.Target, string, map[string]any,
	connector.Idempotency) (connector.Result, error) {
	return connector.Result{}, nil
}

func (d stubDriver) Query(context.Context, connector.Target, string, map[string]any) (connector.Rows, error) {
	return connector.Rows{}, nil
}

// TestADefectiveConnectorIsQuarantinedNotTheBoot is D282: a connector
// declaring a type it ships no schema for, or an unversioned type, is
// QUARANTINED — named, with the reason — and the boot's schema check passes,
// because every other connector must go on serving.
func TestADefectiveConnectorIsQuarantinedNotTheBoot(t *testing.T) {
	for name, c := range map[string]struct {
		output, want string
	}{
		"no schema":   {"stub.result.v1", `declares output type "stub.result.v1"`},
		"unversioned": {"stub_result", "no version suffix"},
	} {
		d := stubDriver{kind: "stub", actions: []connector.ActionSpec{
			{Name: "stub.read", Description: "Read rows.", OutputType: c.output}}}
		if err := check(t, schemas, d); err != nil {
			t.Errorf("%s: the boot was refused for one connector's defect: %v", name, err)
		}
		reg, err := ForDeployment(&config.Document{}, map[string]connector.Driver{"stub": d})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if why := reg.Quarantined()["stub"]; !strings.Contains(why, c.want) {
			t.Errorf("%s: quarantine reason %q does not say %q", name, why, c.want)
		}
	}
}

// TestADriverWithNoOutputTypeIsFine — declaring one is optional. Such a driver
// is still governed; its results are simply only lensable by the type-less
// rules, which is the jurisdiction case.
func TestADriverWithNoOutputTypeIsFine(t *testing.T) {
	// A WRITE-ONLY driver declares no type and ships no schema: nothing it
	// does brings data in.
	if err := check(t, schemas, stubDriver{kind: "stub", actions: []connector.ActionSpec{
		{Name: "stub.create", Description: "Create a row.", Mutating: true, Idempotency: connector.IdempotencyNone,
			NoResult: true},
	}}); err != nil {
		t.Fatalf("a write-only driver declaring no output type was refused: %v", err)
	}
	// A READ does bring data in, so since D279 it must say what (the published
	// action contract, which the boot runs).
	mustRefuse(t, check(t, schemas, stubDriver{kind: "stub", actions: []connector.ActionSpec{
		{Name: "stub.read", Description: "Read rows."},
	}}), `"stub.read" is a read and declares no output type`)
}

// --- shin field paths (§4.12) -----------------------------------------------

// TestALensKeepingAFieldTheSchemaLacksIsRefused. A lens naming an absent field
// silently delivers less than someone believes it does.
func TestALensKeepingAFieldTheSchemaLacksIsRefused(t *testing.T) {
	err := check(t, schemas+`
shin:
  - name: typo
    enabled: true
    mode: imposed
    applies_to: ["agent:x"]
    type: fullstory.rage_click.v1
    fields: [session_id, ulr]
    because: the url is misspelt
`)
	mustRefuse(t, err, `keeps "ulr"`)
}

// TestAWithheldPathNeedNotExist — a jurisdiction rule saying "never send
// user.email" must hold for every payload, including those that happen not to
// carry one. Refusing boot because the field is absent would make the safe rule
// the hard one to write.
// TestAWithheldPathNeedNotExist — for a TYPELESS jurisdiction rule. "Never
// send user.email" holds across every payload, including those that carry no
// user, and refusing the boot for an absent field would make the safe rule the
// hard one to write (D292 keeps this).
func TestAWithheldPathNeedNotExist(t *testing.T) {
	if err := check(t, schemas+`
shin:
  - name: jurisdiction
    enabled: true
    mode: imposed
    applies_to: ["agent:x"]
    withholds: [user.email]
    because: this payload has no user, and the rule should still hold
`); err != nil {
		t.Fatalf("a typeless withhold naming an absent field was refused: %v", err)
	}
}

// TestATypedLensMustWithholdAFieldItsTypeCanCarry — D292. Scoped to one type, a
// withheld path no kind of that type could carry is a TYPO, and a typo here
// withholds nothing, silently: the leaking direction, which used to be the
// unchecked one while a typo in `fields` refused the boot.
func TestATypedLensMustWithholdAFieldItsTypeCanCarry(t *testing.T) {
	err := check(t, schemas+`
shin:
  - name: typo
    enabled: true
    mode: imposed
    applies_to: ["agent:x"]
    type: fullstory.rage_click.v1
    withholds: [user.emial]
    because: a typo that would withhold nothing
`)
	if err == nil || !strings.Contains(err.Error(), "withholds nothing") {
		t.Fatalf("a typed lens withholding a field its type cannot carry loaded: %v", err)
	}
}

// TestAllProblemsAreReportedTogether — an operator fixing configuration wants
// the whole list, not one error per restart.
func TestAllProblemsAreReportedTogether(t *testing.T) {
	err := check(t, schemas+`
reflexes:
  - name: a
    principal: reflex:x
    enabled: true
    expects_type: fullstory.rage_click.v1
    carry: [missing_one]
  - name: b
    principal: reflex:x
    enabled: true
    expects_type: fullstory.rage_click.v1
    carry: [missing_two]
`)
	if err == nil {
		t.Fatal("validation passed")
	}
	if !strings.Contains(err.Error(), "missing_one") || !strings.Contains(err.Error(), "missing_two") {
		t.Errorf("only some problems were reported:\n%v", err)
	}
	if !strings.Contains(err.Error(), "2 schema problem(s)") {
		t.Errorf("the count is wrong:\n%v", err)
	}
}

// TestAWhereOnAnUndeclaredKindIsRefused is D276 at boot: a rule matching a kind
// that can never arrive — every undeclared kind is refused at publish — would
// be enabled and permanently inert. And a declared kind boots.
func TestAWhereOnAnUndeclaredKindIsRefused(t *testing.T) {
	doc := `
reflexes:
  - name: r
    principal: reflex:x
    enabled: true
    expects_type: x.event.v1
    where: [{path: event_type, op: eq, value: %s}]
    action: kata.create_issue
    target: kata:alpha
`
	// THE FAMILY IS THE CONNECTOR'S (D279), shipped by a driver.
	family := func(other *connector.OtherKinds) connector.Driver {
		return stubDriver{kind: "x", actions: []connector.ActionSpec{{Name: "x.poll", Description: "Poll it.",
			OutputType: "x.event.v1"}}, schemas: []connector.Schema{{Type: "x.event.v1",
			Body: json.RawMessage(`{"type":"object","properties":{"event_type":{"type":"string"},"event_properties":{"type":"object"}}}`),
			Family: &connector.Family{Discriminator: "event_type", Properties: "event_properties",
				Kinds: map[string]connector.Kind{"click": {Schema: json.RawMessage(`{"type":"object"}`)}},
				Other: other}}}}
	}
	mustRefuse(t, check(t, strings.Replace(doc, "%s", "rage-click", 1), family(nil)),
		`"rage-click", which is not a declared kind`)
	if err := check(t, strings.Replace(doc, "%s", "click", 1), family(nil)); err != nil {
		t.Fatalf("a where naming a declared kind was refused: %v", err)
	}
	// A FAMILY THAT ADMITS OTHER KINDS can deliver an undeclared one, so a rule
	// naming it is not waiting for the impossible.
	openOther := &connector.OtherKinds{Open: &connector.Kind{Schema: json.RawMessage(`{"type":"object","additionalProperties":true}`)}}
	if err := check(t, strings.Replace(doc, "%s", "rage-click", 1), family(openOther)); err != nil {
		t.Fatalf("a where on a kind an open family admits was refused: %v", err)
	}
}

// TestAnUnregisteredTypeIsRefusedWhereverItIsNamed: a reflex's expects_type and
// a lens's type must name a registered type — MOVED HERE from config's own
// validation by D279, because most types are now a connector's, and only this
// checker sees the connectors' schemas as well as the document's.
func TestAnUnregisteredTypeIsRefusedWhereverItIsNamed(t *testing.T) {
	mustRefuse(t, check(t, `
reflexes:
  - name: r
    principal: reflex:friction
    enabled: true
    consumes: sekizui.enriched.x
    expects_type: fullstory.rage_click.v1
    action: kata.create_issue
    target: kata:alpha
`), `expects_type "fullstory.rage_click.v1" has no registered schema`)
	mustRefuse(t, check(t, `
shin:
  - name: typo
    enabled: true
    mode: imposed
    applies_to: ["agent:triage"]
    type: fullstory.rage_click
    fields: [session_id]
    because: the version suffix is missing
`), `fullstory.rage_click`)
}

// meteredStub is stubDriver with a chosen meter.
type meteredStub struct {
	stubDriver
	m connector.Meter
}

func (d meteredStub) Meter() connector.Meter { return d.m }

// TestAnUnsoundMeterQuarantinesTheWholeConnector is D284's one verdict: a
// connector whose calls cannot be priced is dropped WHOLE — its types are not
// registered, exactly as for a schema fault — and QuarantineOf reports each
// half to the arm that owns it.
func TestAnUnsoundMeterQuarantinesTheWholeConnector(t *testing.T) {
	body := []byte(`{"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}}}`)
	d := meteredStub{
		stubDriver: stubDriver{kind: "stub",
			actions: []connector.ActionSpec{{Name: "stub.read", Description: "Read rows.", OutputType: "stub.row.v1"}},
			schemas: []connector.Schema{{Type: "stub.row.v1", Body: body}}},
		m: connector.Meter{Unit: "records"}, // no default, no action cost
	}
	reg, err := ForDeployment(&config.Document{}, map[string]connector.Driver{"stub": d})
	if err != nil {
		t.Fatal(err)
	}
	if reg.Has("stub.row.v1") {
		t.Error("a connector quarantined for its meter still has its type registered; the gateway " +
			"refuses its targets while the registry admits what it emits")
	}
	if kind, q := reg.QuarantinedBy("stub.row.v1"); !q || kind != "stub" {
		t.Errorf("QuarantinedBy(stub.row.v1) = %q, %v; configuration naming it must read as inert", kind, q)
	}
	schemaFaults, meterFaults := reg.QuarantineOf("stub")
	if schemaFaults != "" || len(meterFaults) != 2 {
		t.Errorf("QuarantineOf split %q / %v; want no schema fault and two meter faults", schemaFaults, meterFaults)
	}
	if !strings.Contains(reg.Quarantined()["stub"], "its meter is not sound") {
		t.Errorf("the joined reason does not name the meter: %q", reg.Quarantined()["stub"])
	}

	// And a schema fault alone reports no meter half.
	d.m = connector.Meter{}
	d.schemas = nil
	reg, _ = ForDeployment(&config.Document{}, map[string]connector.Driver{"stub": d})
	if s, m := reg.QuarantineOf("stub"); s == "" || m != nil {
		t.Errorf("a schema-only fault split as %q / %v", s, m)
	}
}
