package config

import (
	"errors"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Reflex EXECUTION is P5; reflex VALIDATION is P0 (§12.0 principle 4). These
// tests are three later-phase exit criteria, made executable now:
//
//	P3 exit 5 — a cyclic subject config is rejected at boot
//	P5 exit 3 — a cyclic rule is rejected at boot, "not detected at runtime"
//	P5 exit 4 — a rule granted an action its principal lacks is rejected at boot
//
// Each is pure configuration analysis, so none of them needs the bus, the
// matcher, or anything else P3 and P5 will bring. They assert the CONTRACT, so
// they survive the engine landing rather than being replaced by it.

func docFromYAML(t *testing.T, src string) *Document {
	t.Helper()
	var d Document
	if err := yaml.Unmarshal([]byte(src), &d); err != nil {
		t.Fatalf("fixture did not parse: %v", err)
	}
	return &d
}

// base is a valid document with stages, a target, and a granted reflex
// principal — so each test below changes exactly one thing.
const base = `
stages: [raw, enriched, triaged, judged]
targets:
  - {ref: kata:alpha, kind: kata, credential: env://TOK}
grants:
  - principal: reflex:friction
    allow:
      - {action: kata.create_issue, target: kata:alpha}
    # A reflex subscribes as its principal (D261), so the fixture's rules need
    # this to consume anything at all. Broad on purpose: these tests vary ONE
    # thing each, and the grant is not it.
    subscribe:
      - {subject: "sekizui.>", target: kata:alpha}
`

func TestValidReflexPasses(t *testing.T) {
	d := docFromYAML(t, base+`
reflexes:
  - name: friction-to-ticket
    principal: reflex:friction
    enabled: true
    mode: shadow
    consumes: sekizui.enriched.friction_detected
    action: kata.create_issue
    target: kata:alpha
`)
	if err := d.Validate(); err != nil {
		t.Fatalf("a well-formed reflex was rejected: %v", err)
	}
}

func TestValidBusToBusReflexPasses(t *testing.T) {
	d := docFromYAML(t, base+`
reflexes:
  - name: enrich-friction
    principal: reflex:friction
    consumes: sekizui.raw.fullstory.rage_click
    publish_to: sekizui.enriched.friction_detected
`)
	if err := d.Validate(); err != nil {
		t.Fatalf("a valid bus->bus reflex was rejected: %v", err)
	}
}

func TestReflexValidationRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		reflex string
		want   string
	}{
		// P5 exit 4. The rule looks enabled and does nothing but generate
		// denials — the worst kind of broken, because it appears configured.
		"principal not granted the action": {
			reflex: `
  - name: r
    principal: reflex:friction
    consumes: sekizui.enriched.x
    action: kata.delete_project
    target: kata:alpha`,
			want: "not granted action",
		},
		"principal granted the action but not on that target": {
			reflex: `
  - name: r
    principal: reflex:friction
    consumes: sekizui.enriched.x
    action: kata.create_issue
    target: kata:beta`,
			want: "unknown target",
		},
		// D18: a reflex is a principal, not a bypass.
		"no principal at all": {
			reflex: `
  - name: r
    consumes: sekizui.enriched.x
    action: kata.create_issue
    target: kata:alpha`,
			want: "not a bypass",
		},
		"principal with no grant": {
			reflex: `
  - name: r
    principal: reflex:unknown
    consumes: sekizui.enriched.x
    action: kata.create_issue
    target: kata:alpha`,
			want: "has no grant",
		},
		// D31: one rule, one action.
		"both an action and publish_to": {
			reflex: `
  - name: r
    principal: reflex:friction
    consumes: sekizui.raw.x
    action: kata.create_issue
    target: kata:alpha
    publish_to: sekizui.enriched.x`,
			want: "does exactly one thing",
		},
		"neither an action nor publish_to": {
			reflex: `
  - name: r
    principal: reflex:friction
    consumes: sekizui.raw.x`,
			want: "can never do anything",
		},
		"missing consumes": {
			reflex: `
  - name: r
    principal: reflex:friction
    action: kata.create_issue
    target: kata:alpha`,
			want: "missing consumes",
		},
		"unknown mode": {
			reflex: `
  - name: r
    principal: reflex:friction
    mode: yolo
    consumes: sekizui.enriched.x
    action: kata.create_issue
    target: kata:alpha`,
			want: "neither shadow nor enforce",
		},
		"duplicate name": {
			reflex: `
  - name: r
    principal: reflex:friction
    consumes: sekizui.enriched.x
    action: kata.create_issue
    target: kata:alpha
  - name: r
    principal: reflex:friction
    consumes: sekizui.enriched.y
    action: kata.create_issue
    target: kata:alpha`,
			want: "declared twice",
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := docFromYAML(t, base+"reflexes:"+tc.reflex+"\n")

			err := d.Validate()
			if err == nil {
				t.Fatalf("accepted:%s", tc.reflex)
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

// TestStageMonotonicity is P3 exit criterion 5 and P5 exit criterion 3.
//
// §4.11.6: PREVENTION BY TOPOLOGY, NOT DETECTION BY DEPTH. Requiring a strictly
// later stage makes a cycle impossible by construction — there is no ordering of
// stages in which a loop can close — where a runtime depth cap only notices one
// after it has already been running.
func TestStageMonotonicity(t *testing.T) {
	for name, tc := range map[string]struct {
		consumes, publishTo string
		wantErr             string
	}{
		"forward one stage": {
			consumes: "sekizui.raw.x", publishTo: "sekizui.enriched.x",
		},
		"forward two stages": {
			consumes: "sekizui.raw.x", publishTo: "sekizui.triaged.x",
		},
		// The direct cycle: a rule consuming and publishing on the same stage
		// feeds itself forever.
		"same stage": {
			consumes: "sekizui.enriched.x", publishTo: "sekizui.enriched.y",
			wantErr: "the same stage as",
		},
		"backwards": {
			consumes: "sekizui.triaged.x", publishTo: "sekizui.raw.x",
			wantErr: "an earlier stage than",
		},
		"consumes names no configured stage": {
			consumes: "sekizui.nonsense.x", publishTo: "sekizui.enriched.x",
			wantErr: "names no configured stage",
		},
		"publishes to no configured stage": {
			consumes: "sekizui.raw.x", publishTo: "sekizui.nonsense.x",
			wantErr: "names no configured stage",
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := docFromYAML(t, base+`
reflexes:
  - name: r
    principal: reflex:friction
    consumes: `+tc.consumes+`
    publish_to: `+tc.publishTo+`
`)
			err := d.Validate()

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid monotonic reflex rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %s -> %s", tc.consumes, tc.publishTo)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestStageMatchingIsByTokenNotSubstring. A source named "rawlogs" must not be
// read as the "raw" stage — substring matching would silently mis-order the
// pipeline and let a genuine cycle through.
func TestStageMatchingIsByTokenNotSubstring(t *testing.T) {
	d := docFromYAML(t, base+`
reflexes:
  - name: r
    principal: reflex:friction
    consumes: sekizui.rawlogs.x
    publish_to: sekizui.enriched.x
`)
	err := d.Validate()
	if err == nil {
		t.Fatal(`"rawlogs" was accepted as the "raw" stage; substring matching would ` +
			`silently mis-order the pipeline`)
	}
	if !strings.Contains(err.Error(), "names no configured stage") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestBusToBusWithoutStagesIsRefused. With no configured stage list there is no
// ordering to check against, so monotonicity cannot be enforced — and an
// unchecked bus→bus reflex is exactly the cycle risk D43 exists to remove.
func TestBusToBusWithoutStagesIsRefused(t *testing.T) {
	d := docFromYAML(t, `
targets:
  - {ref: kata:alpha, kind: kata}
grants:
  - {principal: reflex:friction, allow: [{action: kata.create_issue, target: kata:alpha}]}
reflexes:
  - name: r
    principal: reflex:friction
    consumes: raw.x
    publish_to: enriched.x
`)
	err := d.Validate()
	if err == nil {
		t.Fatal("a bus->bus reflex was accepted with no stages configured")
	}
	if !strings.Contains(err.Error(), "no stages are configured") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestEmptyModeMeansShadow. §4.11.4 item 3 says every reflex should run shadow
// first, so the SAFE value must be the default — an unset mode that meant
// "enforce" would make the dangerous option the easy one.
func TestEmptyModeMeansShadow(t *testing.T) {
	d := docFromYAML(t, base+`
reflexes:
  - name: r
    principal: reflex:friction
    consumes: sekizui.enriched.x
    action: kata.create_issue
    target: kata:alpha
`)
	if err := d.Validate(); err != nil {
		t.Fatalf("a reflex with no mode was rejected: %v", err)
	}
	if got := d.Reflexes[0].Mode; got != "" {
		t.Errorf("mode = %q; the zero value must remain the safe one", got)
	}
}

// TestReflexProblemsAreAllReported — same reason as everywhere else: an operator
// fixing config wants the whole list.
func TestReflexProblemsAreAllReported(t *testing.T) {
	// One problem per reflex, deliberately distinct. Note that "a" cannot ALSO
	// report an ungranted action: with no principal there is nothing to check
	// the grant against, and emitting `principal "" is not granted ...` would be
	// noise pointing at a problem already reported. Hence a separate reflex for
	// that case.
	d := docFromYAML(t, base+`
reflexes:
  - name: a
    consumes: sekizui.enriched.x
    action: kata.create_issue
    target: kata:alpha
  - name: b
    principal: reflex:friction
    consumes: sekizui.enriched.x
    action: kata.delete_project
    target: kata:alpha
  - name: c
    principal: reflex:friction
    mode: yolo
    consumes: sekizui.triaged.x
    publish_to: sekizui.raw.x
`)
	err := d.Validate()
	if err == nil {
		t.Fatal("accepted a document with several broken reflexes")
	}
	for _, want := range []string{
		"not a bypass",          // a: no principal
		"not granted action",    // b: ungranted action
		"neither shadow nor",    // c: bad mode
		"an earlier stage than", // c: backwards publish
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits %q:\n%v", want, err)
		}
	}
}

// TestNoCascadingErrorsFromAMissingPrincipal pins the behaviour the test above
// discovered: one root cause produces ONE message, not a cascade.
//
// A reflex with no principal reports exactly that. It does not additionally
// report `principal "" is not granted ...`, which would point at a symptom and
// bury the cause in noise — the failure mode that makes operators skim
// validation output instead of reading it.
func TestNoCascadingErrorsFromAMissingPrincipal(t *testing.T) {
	d := docFromYAML(t, base+`
reflexes:
  - name: a
    consumes: sekizui.enriched.x
    action: kata.create_issue
    target: kata:alpha
`)
	err := d.Validate()
	if err == nil {
		t.Fatal("accepted a reflex with no principal")
	}
	if n := strings.Count(err.Error(), "\n  - "); n != 1 {
		t.Errorf("one root cause produced %d messages:\n%v", n, err)
	}
}

// TestAReflexCoveredByAWildcardGrantIsGranted — the boot check answers by the
// enforcer's rule (D330). It looked the action up LITERALLY, so a rule the
// wildcard below covers was refused as "not granted" while every firing would
// have been allowed; and the target still has to match.
func TestAReflexCoveredByAWildcardGrantIsGranted(t *testing.T) {
	wild := strings.Replace(base, "      - {action: kata.create_issue, target: kata:alpha}",
		"      - {action: \"kata.*\", target: kata:alpha}", 1)
	rule := func(target string) string {
		return `
reflexes:
  - name: friction-to-comment
    principal: reflex:friction
    enabled: true
    consumes: sekizui.enriched.friction_detected
    action: kata.comment
    target: ` + target + "\n"
	}
	accepts(t, docFromYAML(t, wild+rule("kata:alpha")))
	refuses(t, docFromYAML(t, strings.Replace(wild+rule("kata:beta"), "targets:\n",
		"targets:\n  - {ref: kata:beta, kind: kata, credential: env://TOK}\n", 1)),
		`granted "kata.comment" but not on target "kata:beta"`)
}

// TestASharedReflexBudgetIsNamedDeclaredAndUsed — D334: an unnamed budget bounds
// nothing and reads as a bound; a rule naming a missing one fires unbounded by
// the budget its author meant.
func TestASharedReflexBudgetIsNamedDeclaredAndUsed(t *testing.T) {
	rule := func(budget string) string {
		return `
reflexes:
  - name: friction-to-ticket
    principal: reflex:friction
    enabled: true
    consumes: sekizui.enriched.friction_detected
    action: kata.create_issue
    target: kata:alpha
    budget: ` + budget + "\n"
	}
	budgets := func(rate string) string {
		return "reflex_budgets:\n  - {name: tickets, max_firings_per_hour: " + rate + "}\n"
	}
	accepts(t, docFromYAML(t, base+budgets("3")+rule("tickets")))
	refuses(t, docFromYAML(t, base+budgets("3")+rule("tikcets")), `spends budget "tikcets"`)
	refuses(t, docFromYAML(t, base+budgets("0")+rule("tickets")), "max_firings_per_hour is 0")
	refuses(t, docFromYAML(t, base+budgets("3")+strings.Replace(rule("x"), "    budget: x\n", "", 1)),
		"no rule spends it")
}
