package config

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/jsonref"
)

// THIS FILE EXISTS BECAUSE ONE BUG SHAPE HAS NOW APPEARED THREE TIMES.
//
//	1. connector.Secret documented a LogValue method that was never written, so
//	   credentials would have printed. Go's implicit interfaces meant deleting it
//	   broke no build.
//	2. Document's structs had no `json:` tags, so §4.7's documented `base_url`
//	   parsed "successfully" into an empty field.
//	3. AnzenSpec.On was named `on`, which YAML 1.1 reads as the boolean `true`
//	   even as a map KEY, so the field silently never bound.
//
// The shape is always the same: A DECLARED CONTRACT THAT SILENTLY DOES NOTHING.
// The code compiles, the config parses, no error appears, and the property is
// simply absent. Reviews do not catch it because the declaration is right there
// in the file, looking correct.
//
// The tests below attack the CLASS rather than the three instances, and they
// keep working for fields nobody has written yet:
//
//	TestEveryFieldHasAnExplicitTag     — instance 2, generalised
//	TestNoTagCollidesWithYAMLKeyword   — instance 3, generalised
//	TestFixtureIsComplete              — forces new fields into the fixture
//	TestEveryFieldSurvivesYAML         — proves the tags actually bind
//
// Instance 1 lives in pkg/connector/secret_test.go, where the equivalent guard
// is an explicit interface assertion.

// yamlBooleanKeywords are the YAML 1.1 tokens that become booleans, INCLUDING
// as map keys. sigs.k8s.io/yaml delegates to yaml.v2, which is YAML 1.1.
//
// Verified, not assumed:
//
//	on: x   -> key `true`,  value `true`
//	off: x  -> key `false`
//	yes: x  -> key `true`   (silently overwrites `on`)
//	no: x   -> key `false`  (silently overwrites `off`)
//
// A key named for any of these binds to nothing, and two of them collide with
// each other without a word. `no_retry` and `on_failure` are the obvious next
// victims, which is why this checks PREFIXES too when the whole key matches.
var yamlBooleanKeywords = map[string]bool{
	"y": true, "yes": true, "n": true, "no": true,
	"true": true, "false": true, "on": true, "off": true,
}

// documentFixture is a Document with EVERY field set to a distinctive non-zero
// value. TestFixtureIsComplete fails if a field is added and not set here, so
// the fixture cannot rot silently.
func documentFixture() *Document {
	return &Document{
		// D315: set, so the completeness guard sees the field.
		Demo:      true,
		Stages:    []string{"raw", "enriched", "triaged", "judged"},
		LLMStages: []string{"judged"},
		// D111's requirement set. Non-zero here so the fixture guard is
		// satisfied, and stating BOTH properties rather than one because a
		// single-element list would not catch an implementation that only ever
		// read the first.
		CredentialPolicy: &CredentialPolicySpec{
			Require: []string{"versioned", "audited_reads"},
		},
		Targets: []TargetSpec{{
			Ref: "kata:alpha", Kind: "kata", BaseURL: "https://alpha.invalid",
			CredentialRef: "env://TOK", Residency: "eu", Tenant: "alpha",
			Settings: map[string]string{"dc": "na1"},
			Limits:   &TargetLimits{RatePerHr: 3600, Burst: 100, Budget: "alpha-upstream"},
		}, {
			// AN MCP TARGET, so the vetted spec below has something to be keyed to
			// and `validateMCPTargetsHaveSpecs` is exercised in its passing
			// direction (D192).
			Ref: "fixture-mcp", Kind: "mcp", BaseURL: "https://mcp.invalid",
			CredentialRef: "env://TOK", Residency: "eu", Tenant: "alpha",
			// The value the fixture tool's `repo` argument is pinned to (D289).
			Settings: map[string]string{"repo": "acme/api"},
			// SHARING kata:alpha's BUDGET, so the two are linked (D323) and every
			// tool below states its native relation — the passing direction.
			Limits: &TargetLimits{Budget: "alpha-upstream"},
		}},
		// THE VETTED SPEC (D46, D192). Non-zero here so the fixture guard is
		// satisfied, and carrying BOTH a mutating and a read tool because the
		// interesting validations are per-tool and asymmetric: a mutating tool owes
		// an idempotency class, a read must not declare one, and only a
		// `vendor`-provenance output schema is ever drift-checked (D51, D163).
		MCPSpecs: map[string]MCPSpec{
			"fixture-mcp": {
				Host:   "mcp.invalid",
				Server: "fixture",
				// DECLARED EXPLICITLY even though it is the default, so the
				// completeness guard is satisfied and a reader sees the field exists
				// (D193).
				Revision: DefaultMCPRevision,
				// Likewise the unroll depth (D309): the default, declared.
				RefUnroll: func() *int { n := jsonref.DefaultUnroll; return &n }(),
				// And the comparison's page bound (D311), at its default.
				ListPages: func() *int { n := 1; return &n }(),
				// **THE MUTATING TOOL IS FIRST, and that ordering is forced by two
				// guards pulling opposite ways.** TestFixtureIsComplete walks the
				// FIRST element of a slice and requires every field non-zero, so
				// whichever tool leads must set `Mutating`, `Idempotency` AND
				// `IdempotencyPlacement` — while validateMCPTool refuses a
				// non-mutating tool that declares a class, because nothing would
				// ever consult it. Only a mutating tool can satisfy both, which is
				// worth stating rather than leaving as an accident somebody
				// reorders.
				Tools: []MCPToolSpec{{
					Name: "create_issue", Mutating: true,
					Native:               []string{"kata.create_issue"},
					Idempotency:          "header",
					IdempotencyPlacement: "Idempotency-Key",
					// **A MIRRORED PARAMETER, REVIEWED (D194).** The fixture carries
					// one so the completeness guard is satisfied AND the accepted path
					// is exercised: without `header_mirroring_reviewed` this tool is
					// refused, which is the whole point of the flag.
					InputSchema: json.RawMessage(
						`{"type":"object","properties":{"repo":{"type":"string",` +
							`"x-mcp-header":"Repo"}}}`),
					HeaderMirroringReviewed: true,
					OutputSchema:            json.RawMessage(`{"type":"object"}`),
					OutputSchemaOrigin:      "vendor",
					// A TEXT RESULT with one featured field and a pinned argument
					// (D289), so the completeness guard sees all three set and valid.
					DataSchema: json.RawMessage(`{"type":"object","properties":{` +
						`"text":{"type":"string"},"number":{"type":"string"}}}`),
					Result:      "text",
					Extract:     []ExtractSpec{{Field: "number", Pattern: `^#(\d+)$`, Line: 1}},
					UserContent: true,
					Pin:         []string{"repo"},
					// A HANDLE LIFECYCLE (D291): this tool opens, `search` closes.
					Handle:      &HandleSpec{Opens: "number"},
					OutputType:  "github.issue.v1",
					Description: "Open an issue.",
					VendorHash:  "sha256:cafebabe",
				}, {
					// A READ, so the asymmetric half is present too: no idempotency
					// class, and no output typing at all — which is the common case
					// in the MCP ecosystem and the reason D51 pins provenance rather
					// than treating absence as drift.
					Name: "search", Mutating: false,
					Native:      []string{NativeNone},
					InputSchema: json.RawMessage(`{"type":"object"}`),
					// SEVERAL JSON BLOCKS, combined as items (D289) — the field a
					// text tool cannot carry, so it lives on this one.
					Combine:     "items",
					Handle:      &HandleSpec{Closes: "query"},
					Description: "Search code.",
					VendorHash:  "sha256:deadbeef",
				}},
			},
		},
		Grants: []GrantSpec{{
			Principal: "agent:triage",
			Allow: []CapabilitySpec{{
				Action: "kata.create_issue", TargetRef: "kata:alpha",
				Where: map[string]any{"project": "PROJ"}, RatePerHr: 10, MaxBytes: 1024,
			}, {
				// D327: a preset names what an action would; exclusive with it.
				// Origin is set only by expansion and never serialised.
				Preset: "kata.basic", TargetRef: "kata:alpha",
				Origin: &CapabilityOrigin{Index: 1, Preset: "kata.basic"},
			}},
			Escalate: []CapabilitySpec{{
				Action: "kata.delete_project", TargetRef: "kata:alpha",
				Where: map[string]any{"confirm": true}, RatePerHr: 1, MaxBytes: 1,
			}, {
				Preset: "kata.basic", TargetRef: "kata:alpha",
				Origin: &CapabilityOrigin{Index: 1, Preset: "kata.basic"},
			}},
			Subscribe:   []SubscriptionSpec{{Subject: "sekizui.enriched.>", TargetRef: "kata:alpha"}},
			MaySpeakFor: []string{"agent:architect"},
		}},
		Sources: []SourceSpec{{TargetRef: "kata:alpha", EverySec: 30, Limit: 50}},
		Jobs:    JobsSpec{ResultsTTLSec: 900},
		Reflexes: []ReflexSpec{{
			// Projects is set although no valid rule both projects and acts:
			// this fixture proves every field DECODES, and validity is the
			// validator's question (D269).
			Name: "r", Principal: "reflex:friction", Enabled: true, Mode: "shadow", Projects: true,
			Budget:   "tickets", // D334
			Consumes: "sekizui.raw.fullstory.>", ExpectsType: "fullstory.rage_click.v1",
			Where: Predicate{{Path: "clicks", Op: OpGt, Value: float64(5)}}, DebounceKey: "session_id",
			DebounceWindowSec: 60, MaxFiringsPerHour: 50,
			Action: "kata.create_issue", TargetRef: "kata:alpha",
			With:      map[string]any{"project": "PROJ"},
			PublishTo: "sekizui.enriched.friction",
			// Declared, never derived from the subject (D88).
			PublishesType: "fullstory.friction.v1",
			Carry:         []string{"session_id"}, AcknowledgesLLMInput: true,
		}},
		// D318: every field set.
		Issuers: []IssuerSpec{{
			Issuer: "https://broker.test", Audience: "sekizui:test", Keys: "file:///etc/sekizui/broker.jwks",
			Algorithms: []string{"RS256"}, Callers: []string{"agent:triage"}, RoleClaim: "role",
			RequireBound: func() *bool { b := false; return &b }(), LeewaySec: 30,
		}},
		// D317: every field set, so a new one cannot escape the checks here.
		Refinements: []RefinementSpec{{
			Rule: "kata.summary", Target: "kata:alpha", For: []string{"agent:triage"},
			Params: map[string]any{"prefix": "/login"},
		}},
		ReflexBudgets: []ReflexBudgetSpec{{Name: "tickets", MaxFiringsPerHour: 20}},
		Presets: []PresetSpec{{
			Name: "kata.basic", Mirrors: "Standard", Explain: "read and file issues",
			Actions: []string{"kata.read", "kata.create_issue"},
		}},
		Anzen: []AnzenSpec{{
			Name: "a", Enabled: true, Mode: "enforce", Watches: "spec_drift",
			Where: map[string]any{"target": "kata:alpha"},
			Do:    "quarantine_target", Subject: "kata:alpha",
			// Preventive fields too — the fixture covers every field, not every
			// valid COMBINATION. Validation rejects reactive+preventive in one
			// rule; this exists to prove the tags bind.
			Forbids: []string{"kata.delete_*"}, MaxConcurrent: 3,
			AppliesTo: []string{"reflex:*"}, TargetResidency: []string{"eu"},
		}},
		Shin: []ShinSpec{{
			Name: "s", Enabled: true, Mode: "requestable",
			AppliesTo: []string{"agent:triage"}, Type: "fullstory.rage_click.v1",
			Fields: []string{"session_id"}, Withholds: []string{"user.email"},
			MaxBytes: 4096, Residency: "eu",
			Because: "the fixture covers every field, so a new one cannot escape the net",
		}},
		PayloadSchemas: map[string]json.RawMessage{
			"fullstory.rage_click.v1": json.RawMessage(`{"type":"object"}`),
		},
		Policies: map[string]string{"authz": "package sekizui.authz"},
		Version:  "fixture@1",
	}
}

// TestEveryFieldHasAnExplicitTag is instance 2, generalised.
//
// encoding/json falls back to CASE-INSENSITIVE field-name matching when a tag is
// absent, so `baseUrl` binds to BaseURL but `base_url` does NOT. A missing tag
// therefore produces a field that looks configurable, is documented as
// snake_case, and silently stays empty.
//
// Requiring an explicit tag on every exported field removes the fallback from
// the equation entirely.
func TestEveryFieldHasAnExplicitTag(t *testing.T) {
	for _, typ := range configTypes() {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := range typ.NumField() {
				f := typ.Field(i)
				if !f.IsExported() {
					continue
				}
				tag, ok := f.Tag.Lookup("json")
				if !ok {
					t.Errorf("%s.%s has no json tag; encoding/json would fall back to "+
						"case-insensitive matching, which binds camelCase but NOT the "+
						"snake_case §4.7 documents", typ.Name(), f.Name)
					continue
				}
				if name := strings.Split(tag, ",")[0]; name == "" {
					t.Errorf("%s.%s has an empty json name", typ.Name(), f.Name)
				}
			}
		})
	}
}

// TestNoTagCollidesWithYAMLKeyword is instance 3, generalised.
func TestNoTagCollidesWithYAMLKeyword(t *testing.T) {
	for _, typ := range configTypes() {
		for i := range typ.NumField() {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if yamlBooleanKeywords[strings.ToLower(name)] {
				t.Errorf("%s.%s is tagged %q, which YAML 1.1 parses as a BOOLEAN even as a "+
					"map key — the field would silently never bind. Rename it (e.g. `on` -> "+
					"`watches`); see CONTRACTS §4 item 13",
					typ.Name(), f.Name, name)
			}
		}
	}
}

// TestFixtureIsComplete walks the fixture and fails on any zero-valued field.
//
// THIS IS WHAT KEEPS THE OTHER TESTS HONEST AS THE CONFIG GROWS. A new field
// added to any spec is zero here, so this fails, so whoever added it must
// populate the fixture — which then flows through TestEveryFieldSurvivesYAML and
// proves their tag actually works. Without it, the round-trip test would quietly
// stop covering new fields the moment they were added.
func TestFixtureIsComplete(t *testing.T) {
	var zeroes []string
	walkForZeroes(reflect.ValueOf(documentFixture()).Elem(), "Document", &zeroes)

	for _, path := range zeroes {
		t.Errorf("%s is zero in documentFixture(); set it, or a new field escapes "+
			"every check in this file", path)
	}
}

// TestEveryFieldSurvivesYAML proves the tags bind, rather than merely existing.
//
// Marshals the fixture, unmarshals it back, and re-marshals — then compares the
// two YAML documents. A field whose tag does not bind is present in the first
// and absent from the second, so the diff is the bug.
func TestEveryFieldSurvivesYAML(t *testing.T) {
	original := documentFixture()

	first, err := yaml.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back Document
	if err := yaml.Unmarshal(first, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	second, err := yaml.Marshal(&back)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}

	if string(first) != string(second) {
		t.Errorf("a field did not survive the round trip.\n--- written ---\n%s\n--- read back ---\n%s",
			first, second)
	}

	// Belt and braces: spot-check the two fields whose bugs prompted this file.
	if len(back.Targets) == 0 || back.Targets[0].BaseURL != "https://alpha.invalid" {
		t.Error("base_url did not survive — the instance-2 bug is back")
	}
	if len(back.Anzen) == 0 || back.Anzen[0].Watches != "spec_drift" {
		t.Error("watches did not survive — the instance-3 bug is back")
	}
}

// TestOperatorYAMLBindsToTheDocumentedKeys reads the format an OPERATOR writes,
// not the one Go emits.
//
// The distinction matters and is why the round-trip test alone is insufficient:
// Go marshals BaseURL to `baseURL` when untagged and reads it straight back, so
// a round trip through Go's own output stays green while §4.7's documented
// `base_url` binds to nothing. Only reading hand-written YAML catches that.
func TestOperatorYAMLBindsToTheDocumentedKeys(t *testing.T) {
	const operatorWrote = `
stages: [raw, enriched]
llm_stages: [judged]
targets:
  - ref: kata:alpha
    kind: kata
    base_url: https://alpha.invalid
    credential: env://TOK
    residency: eu
    tenant: alpha
grants:
  - principal: agent:triage
    may_speak_for: [agent:architect]
    allow:
      - action: kata.create_issue
        target: kata:alpha
        rate_per_hr: 10
        max_bytes: 1024
sources:
  - {target: kata:alpha, every_s: 30, limit: 50}
jobs: {results_ttl_s: 900}
reflexes:
  - name: r
    principal: reflex:friction
    enabled: true
    consumes: sekizui.raw.fullstory.>
    expects_type: fullstory.rage_click.v1
    publish_to: sekizui.enriched.friction
    carry: [session_id]
    acknowledges_llm_input: true
anzen:
  - name: a
    enabled: true
    watches: spec_drift
    do: quarantine_target
    subject: kata:alpha
`
	var d Document
	if err := yaml.Unmarshal([]byte(operatorWrote), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Each of these is a snake_case or renamed key. A missing tag shows up as a
	// zero value, never as an error.
	checks := map[string]bool{
		"llm_stages":                         len(d.LLMStages) == 1 && d.LLMStages[0] == "judged",
		"targets[0].base_url":                len(d.Targets) == 1 && d.Targets[0].BaseURL == "https://alpha.invalid",
		"targets[0].credential":              len(d.Targets) == 1 && d.Targets[0].CredentialRef == "env://TOK",
		"grants[0].may_speak_for":            len(d.Grants) == 1 && len(d.Grants[0].MaySpeakFor) == 1,
		"allow[0].target":                    len(d.Grants) == 1 && d.Grants[0].Allow[0].TargetRef == "kata:alpha",
		"allow[0].rate_per_hr":               len(d.Grants) == 1 && d.Grants[0].Allow[0].RatePerHr == 10,
		"allow[0].max_bytes":                 len(d.Grants) == 1 && d.Grants[0].Allow[0].MaxBytes == 1024,
		"jobs.results_ttl_s":                 d.Jobs.ResultsTTLSec == 900,
		"sources[0].target":                  len(d.Sources) == 1 && d.Sources[0].TargetRef == "kata:alpha",
		"sources[0].every_s":                 len(d.Sources) == 1 && d.Sources[0].EverySec == 30,
		"sources[0].limit":                   len(d.Sources) == 1 && d.Sources[0].Limit == 50,
		"reflexes[0].expects_type":           len(d.Reflexes) == 1 && d.Reflexes[0].ExpectsType == "fullstory.rage_click.v1",
		"reflexes[0].publish_to":             len(d.Reflexes) == 1 && d.Reflexes[0].PublishTo == "sekizui.enriched.friction",
		"reflexes[0].carry":                  len(d.Reflexes) == 1 && len(d.Reflexes[0].Carry) == 1,
		"reflexes[0].acknowledges_llm_input": len(d.Reflexes) == 1 && d.Reflexes[0].AcknowledgesLLMInput,
		"anzen[0].watches":                   len(d.Anzen) == 1 && d.Anzen[0].Watches == "spec_drift",
		"anzen[0].do":                        len(d.Anzen) == 1 && d.Anzen[0].Do == "quarantine_target",
		"anzen[0].subject":                   len(d.Anzen) == 1 && d.Anzen[0].Subject == "kata:alpha",
	}
	for key, bound := range checks {
		if !bound {
			t.Errorf("%s did not bind from operator-written YAML", key)
		}
	}
}

// configTypes is every struct an operator writes.
func configTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(Document{}),
		reflect.TypeOf(TargetSpec{}),
		reflect.TypeOf(GrantSpec{}),
		reflect.TypeOf(CapabilitySpec{}),
		reflect.TypeOf(ReflexSpec{}),
		reflect.TypeOf(AnzenSpec{}),
	}
}

// walkForZeroes records the path of every zero-valued exported field.
func walkForZeroes(v reflect.Value, path string, out *[]string) {
	var set []string
	walkFixture(v, path, out, &set)
}

// walkFixture records every ZERO leaf and every SET leaf under v.
//
// **A SLICE'S FIELD IS ZERO ONLY IF NO ELEMENT SETS IT.** This walked element
// [0] alone, on the premise "one element is enough to reach every nested field"
// — false once fields became mutually exclusive (D289: a `result: text` tool
// cannot also `combine` JSON blocks), so the fixture spreads them across
// elements. The first rewrite reported a path only if it was zero in EVERY
// element, and UNDER-reported: a path one element does not reach at all (an
// empty `extract`) never counted as zero there. So the rule is "zero somewhere,
// set nowhere" — a zero path is excused only by an element setting that path or
// something beneath it.
func walkFixture(v reflect.Value, path string, zeros, set *[]string) {
	switch v.Kind() {
	case reflect.Struct:
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			walkFixture(v.Field(i), path+"."+f.Name, zeros, set)
		}
	case reflect.Slice, reflect.Map:
		if v.Len() == 0 {
			*zeros = append(*zeros, path+" (empty)")
			return
		}
		if v.Kind() == reflect.Slice {
			var zs, ss []string
			for i := 0; i < v.Len(); i++ {
				walkFixture(v.Index(i), path+"[0]", &zs, &ss)
			}
			*set = append(*set, ss...)
			seen := map[string]bool{}
			for _, z := range zs {
				base := strings.TrimSuffix(strings.TrimSuffix(z, " (empty)"), " (nil)")
				excused := false
				for _, st := range ss {
					if st == base || strings.HasPrefix(st, base+".") || strings.HasPrefix(st, base+"[") {
						excused = true
						break
					}
				}
				if !excused && !seen[z] {
					seen[z] = true
					*zeros = append(*zeros, z)
				}
			}
			sort.Strings(*zeros)
			return
		}
		for _, k := range v.MapKeys() {
			walkFixture(v.MapIndex(k), path+"["+k.String()+"]", zeros, set)
			return
		}
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			*zeros = append(*zeros, path+" (nil)")
		} else {
			*set = append(*set, path)
		}
	default:
		if v.IsZero() {
			*zeros = append(*zeros, path)
		} else {
			*set = append(*set, path)
		}
	}
}
