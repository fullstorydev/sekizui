package policy

import (
	"context"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

func engine(t *testing.T, grantsYAML string) *GrantEngine {
	t.Helper()
	var doc config.Document
	if err := yaml.Unmarshal([]byte(grantsYAML), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return NewGrantEngine(&doc, nil)
}

func ident(caller, subject string) *sekizuiv1.Identity {
	chain := []string{caller}
	if caller != subject {
		chain = append(chain, subject)
	}
	return &sekizuiv1.Identity{
		Caller:  &sekizuiv1.Caller{Principal: caller},
		Subject: &sekizuiv1.Subject{Principal: subject},
		Chain:   chain,
	}
}

func ask(t *testing.T, e *GrantEngine, caller, subject, action, target string, args map[string]any) Decision {
	t.Helper()
	d, err := e.Authorise(context.Background(), Request{
		Identity: ident(caller, subject), Action: action, TargetRef: target, Args: args,
	})
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	return d
}

// TestDenyByDefault is §4.5, "non-negotiable here specifically because agents
// are non-deterministic: you cannot enumerate what they will try, so a blocklist
// is structurally wrong".
func TestDenyByDefault(t *testing.T) {
	e := engine(t, `
grants:
  - principal: agent:triage
    allow: [{action: kata.create_issue, target: kata:alpha}]
`)

	for name, tc := range map[string]struct{ principal, action, target string }{
		"unknown principal":            {"agent:ghost", "kata.create_issue", "kata:alpha"},
		"ungranted action":             {"agent:triage", "kata.delete_project", "kata:alpha"},
		"granted action, wrong target": {"agent:triage", "kata.create_issue", "kata:beta"},
	} {
		t.Run(name, func(t *testing.T) {
			d := ask(t, e, tc.principal, tc.principal, tc.action, tc.target, nil)

			if d.Verdict != sekizuiv1.Verdict_VERDICT_DENY {
				t.Errorf("verdict = %v, want DENY", d.Verdict)
			}
			// A denial with no explanation is unactionable.
			if d.Reason == "" {
				t.Error("denial carried no reason")
			}
			if d.Rule == "" {
				t.Error("denial carried no rule; §5.4 requires knowing WHAT decided")
			}
		})
	}
}

func TestAllowNamesTheGrantThatMatched(t *testing.T) {
	e := engine(t, `
grants:
  - principal: agent:triage
    allow:
      - {action: kata.comment, target: kata:alpha}
      - {action: kata.create_issue, target: kata:alpha}
`)

	d := ask(t, e, "agent:triage", "agent:triage", "kata.create_issue", "kata:alpha", nil)

	if d.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
		t.Fatalf("verdict = %v (%s), want ALLOW", d.Verdict, d.Reason)
	}
	// The INDEX matters: an operator with five similar grants needs to know
	// which one fired, not merely that one did.
	if d.Rule != "agent:triage#allow[1]" {
		t.Errorf("rule = %q, want agent:triage#allow[1]", d.Rule)
	}
}

// TestIntersectionNarrows is P0 exit criterion 3: "effective permission is the
// caller∩subject intersection — proven by a test where the mesh holds less than
// the agent".
func TestIntersectionNarrows(t *testing.T) {
	// The agent may do two things; the mesh may only do one of them.
	e := engine(t, `
grants:
  - principal: agent:architect
    allow:
      - {action: kata.create_issue, target: kata:alpha}
      - {action: kata.delete_project, target: kata:alpha}
  - principal: mesh:primary
    allow:
      - {action: kata.create_issue, target: kata:alpha}
    may_speak_for: [agent:architect]
`)

	t.Run("both permit", func(t *testing.T) {
		d := ask(t, e, "mesh:primary", "agent:architect", "kata.create_issue", "kata:alpha", nil)
		if d.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
			t.Errorf("verdict = %v (%s), want ALLOW", d.Verdict, d.Reason)
		}
		// BOTH grants are named: the audit row should show two had to agree.
		if !strings.Contains(d.Rule, "mesh:primary") || !strings.Contains(d.Rule, "agent:architect") {
			t.Errorf("rule = %q, want both principals' grants named", d.Rule)
		}
	})

	t.Run("subject permits but caller does not", func(t *testing.T) {
		// THE CASE THAT MATTERS. The agent may delete the project. The mesh may
		// not. Delegation can only NARROW, so the answer is deny — otherwise
		// the mesh gains everything its subjects can do, which is the
		// confused-deputy collapse arriving through the policy layer.
		d := ask(t, e, "mesh:primary", "agent:architect", "kata.delete_project", "kata:alpha", nil)

		if d.Verdict != sekizuiv1.Verdict_VERDICT_DENY {
			t.Fatalf("verdict = %v, want DENY — the mesh holds less than the agent "+
				"and the intersection must reduce to the mesh", d.Verdict)
		}
		// The reason must say WHICH principal lacked it, or an operator has two
		// grants to go read.
		if !strings.Contains(d.Reason, "mesh:primary") {
			t.Errorf("reason does not name the principal that lacked the permission: %q", d.Reason)
		}
	})

	t.Run("caller permits but subject does not", func(t *testing.T) {
		// The mirror case: the mesh may create issues, but a subject that
		// cannot must not gain it by being spoken for.
		d := ask(t, e, "mesh:primary", "agent:nobody", "kata.create_issue", "kata:alpha", nil)
		if d.Verdict != sekizuiv1.Verdict_VERDICT_DENY {
			t.Errorf("verdict = %v, want DENY", d.Verdict)
		}
	})
}

// TestStandaloneIsOneEvaluation — D6's chain-of-one, and it must not require a
// principal to be granted may_speak_for over itself.
func TestStandaloneIsOneEvaluation(t *testing.T) {
	e := engine(t, `
grants:
  - principal: agent:triage
    allow: [{action: kata.create_issue, target: kata:alpha}]
`)

	d := ask(t, e, "agent:triage", "agent:triage", "kata.create_issue", "kata:alpha", nil)

	if d.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
		t.Fatalf("verdict = %v (%s)", d.Verdict, d.Reason)
	}
	// Exactly one rule, not a self-intersection: "agent:triage#allow[0]", not
	// that string twice.
	if strings.Contains(d.Rule, "+") {
		t.Errorf("rule = %q; a standalone caller should not intersect with itself", d.Rule)
	}
}

// TestEscalateBeatsAllow. A capability in both blocks means the operator asked
// for human approval; scanning allow first would silently discard that.
func TestEscalateBeatsAllow(t *testing.T) {
	e := engine(t, `
grants:
  - principal: agent:architect
    allow:    [{action: kata.transition, target: kata:alpha}]
    escalate: [{action: kata.transition, target: kata:alpha}]
`)

	d := ask(t, e, "agent:architect", "agent:architect", "kata.transition", "kata:alpha", nil)

	if d.Verdict != sekizuiv1.Verdict_VERDICT_ESCALATE {
		t.Errorf("verdict = %v, want ESCALATE — an operator asked for approval and "+
			"ordering must not discard that", d.Verdict)
	}
}

func TestDenyBeatsEscalate(t *testing.T) {
	e := engine(t, `
grants:
  - principal: agent:architect
    escalate: [{action: kata.transition, target: kata:alpha}]
  - principal: mesh:primary
    allow: []
`)

	d := ask(t, e, "mesh:primary", "agent:architect", "kata.transition", "kata:alpha", nil)

	if d.Verdict != sekizuiv1.Verdict_VERDICT_DENY {
		t.Errorf("verdict = %v, want DENY — a caller that cannot do it at all "+
			"outranks a subject awaiting approval", d.Verdict)
	}
}

// TestWhereConstraints covers §4.5's `where: {project: [PROJ]}`.
func TestWhereConstraints(t *testing.T) {
	e := engine(t, `
grants:
  - principal: agent:triage
    allow:
      - action: kata.create_issue
        target: kata:alpha
        where:
          project: [PROJ, PLAT]
          urgent: true
`)

	allow := func(args map[string]any) bool {
		return ask(t, e, "agent:triage", "agent:triage",
			"kata.create_issue", "kata:alpha", args).Verdict == sekizuiv1.Verdict_VERDICT_ALLOW
	}

	if !allow(map[string]any{"project": "PROJ", "urgent": true}) {
		t.Error("a request satisfying every constraint was denied")
	}
	if !allow(map[string]any{"project": "PLAT", "urgent": true}) {
		t.Error("membership against the second list entry failed")
	}
	if allow(map[string]any{"project": "SECRET", "urgent": true}) {
		t.Error("a project outside the allowed list was permitted")
	}
	if allow(map[string]any{"project": "PROJ", "urgent": false}) {
		t.Error("a scalar constraint was not enforced")
	}

	// THE ATTACK THIS BLOCKS: drop the constrained argument entirely. Treating
	// absence as a pass would make every `where` optional from the caller's side.
	if allow(map[string]any{"urgent": true}) {
		t.Error("omitting a constrained argument escaped the constraint")
	}
	if allow(nil) {
		t.Error("sending no arguments escaped every constraint")
	}
}

// TestNumericConstraintsSurviveJSON. Config arrives through JSON, where every
// number is a float64 — a YAML `1` and a wire `1` must still compare equal.
func TestNumericConstraintsSurviveJSON(t *testing.T) {
	e := engine(t, `
grants:
  - principal: agent:triage
    allow:
      - {action: kata.create_issue, target: kata:alpha, where: {priority: 1}}
`)

	for _, v := range []any{1, int64(1), float64(1), "1"} {
		d := ask(t, e, "agent:triage", "agent:triage", "kata.create_issue", "kata:alpha",
			map[string]any{"priority": v})
		if d.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
			t.Errorf("priority=%v (%T) was denied; numeric types must not decide authorisation", v, v)
		}
	}
}

func TestActionGlob(t *testing.T) {
	e := engine(t, `
grants:
  - principal: agent:architect
    allow: [{action: "mcp.fixture.*", target: fixture-mcp}]
  - principal: agent:super
    allow: [{action: "*", target: fixture-mcp}]
`)

	permits := func(principal, action string) bool {
		return ask(t, e, principal, principal, action, "fixture-mcp", nil).Verdict ==
			sekizuiv1.Verdict_VERDICT_ALLOW
	}

	if !permits("agent:architect", "mcp.fixture.search") {
		t.Error("prefix glob did not match")
	}
	if permits("agent:architect", "mcp.gitlab.search") {
		t.Error("prefix glob matched a different server")
	}
	if !permits("agent:super", "anything.at.all") {
		t.Error(`"*" did not match everything`)
	}
}

// TestAuthoriseWithoutIdentityIsInternal — being asked to decide with no
// established identity is a bug in the caller, not a refusal of the request, and
// must not be recorded as a policy denial.
func TestAuthoriseWithoutIdentityIsInternal(t *testing.T) {
	e := engine(t, `grants: []`)

	_, err := e.Authorise(context.Background(), Request{
		Identity: &sekizuiv1.Identity{}, Action: "kata.read", TargetRef: "kata:alpha",
	})
	if err == nil {
		t.Fatal("policy decided a request with no identity")
	}
}
