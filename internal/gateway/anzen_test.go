package gateway

import (
	"context"
	"sync"
	"testing"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// withGuards rebuilds the harness with anzen guards installed.
func withGuards(t *testing.T, specs ...config.AnzenSpec) *harness {
	t.Helper()
	h := newHarness(t)
	h.srv.guards = anzen.New(specs)
	return h
}

// TestGuardIsACeilingGrantsCannotExceed is the whole point of D71.
//
// agent:triage IS GRANTED kata.create_issue on kata:alpha. The guard refuses it
// anyway. Grants are written per principal by whoever needs the capability; a
// guard is written once by whoever is accountable for the damage — and the
// second must not be overridable by the first.
func TestGuardIsACeilingGrantsCannotExceed(t *testing.T) {
	h := withGuards(t, config.AnzenSpec{
		Name: "no-issue-creation", Enabled: true, Mode: "enforce",
		Forbids: []string{"kata.create_issue"},
	})

	// Sanity: this exact command succeeds without the guard.
	clean := newHarness(t)
	ok, _ := clean.srv.Execute(callerCtx(t, "agent:triage"),
		cmd("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"}))
	if ok.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatal("precondition: the grant should permit this")
	}

	resp, err := h.srv.Execute(callerCtx(t, "agent:triage"),
		cmd("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"}))
	if err != nil {
		t.Fatalf("a guard refusal should be a Result, not an error: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("status = %v, want DENIED — a granted action was permitted despite a guard", got)
	}

	// Recorded, and the record says ANZEN refused it — not "policy denied",
	// which would send an operator to read the wrong file.
	records := h.sink.all()
	if len(records) != 1 {
		t.Fatalf("%d records, want 1", len(records))
	}
	// NAMES THE GUARD, not merely the class. A bare "anzen" told a reviewer that
	// some guard refused and left them parsing the reason to learn which — the
	// same gap D96 closed for reflexes, where several rules share a principal.
	if got := records[0].GetMatchedRule(); got != "anzen:no-issue-creation" {
		t.Errorf("matched_rule = %q, want anzen:no-issue-creation — the record must say "+
			"WHICH guard refused, since several can cover one principal", got)
	}
}

// TestDestructiveBlocklistAcrossSekizui — the motivating case: forbid a class of
// action for everyone, with no per-principal enumeration.
func TestDestructiveBlocklistAcrossSekizui(t *testing.T) {
	h := withGuards(t, config.AnzenSpec{
		Name: "no-destructive-actions", Enabled: true, Mode: "enforce",
		Forbids: []string{"*.delete_*"},
		// AppliesTo empty == every principal. A destructive action nobody
		// should perform is not a per-principal question, and enumerating
		// principals means a new one silently escapes.
	})

	// agent:triage has delete_project as ESCALATE — the guard outranks that too.
	resp, err := h.srv.Execute(callerCtx(t, "agent:triage"),
		cmd("kata.delete_project", "kata:alpha", nil))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Errorf("status = %v, want DENIED — a blocklist outranks an escalation too", got)
	}

	// Non-destructive actions are unaffected.
	ok, _ := h.srv.Execute(callerCtx(t, "agent:triage"),
		cmd("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"}))
	if ok.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Error("the blocklist refused an unrelated action")
	}
}

// TestGuardScopedToReflexes — §4.11.7's case: a rule downstream of a model needs
// a tighter ceiling than a human-driven agent.
func TestGuardScopedToReflexes(t *testing.T) {
	h := withGuards(t, config.AnzenSpec{
		Name: "reflexes-may-not-delete", Enabled: true, Mode: "enforce",
		Forbids: []string{"kata.delete_project"}, AppliesTo: []string{"reflex:*"},
	})

	// An agent is untouched by a reflex-scoped guard.
	resp, _ := h.srv.Execute(callerCtx(t, "agent:triage"),
		cmd("kata.delete_project", "kata:alpha", nil))
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_ESCALATED {
		t.Errorf("agent status = %v, want ESCALATED — the guard scopes to reflexes only", got)
	}
}

// TestMaxConcurrentBoundsBlastRadiusAtAnInstant.
//
// Distinct from a rate limit, which smooths over time. A reflex that suddenly
// matches a thousand events should not put a thousand commands in flight,
// whatever its hourly quota permits.
func TestMaxConcurrentBoundsBlastRadiusAtAnInstant(t *testing.T) {
	h := withGuards(t, config.AnzenSpec{
		Name: "burst-cap", Enabled: true, Mode: "enforce",
		MaxConcurrent: 3, AppliesTo: []string{"agent:triage"},
	})

	// The kata driver sleeps, so calls genuinely overlap.
	slow := func() *sekizuiv1.ExecuteRequest {
		return cmd("kata.create_issue", "kata:alpha",
			map[string]any{"project": "PROJ", "_latency": "60ms"})
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
		refused int
	)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := h.srv.Execute(callerCtx(t, "agent:triage"), slow())
			mu.Lock()
			defer mu.Unlock()
			// TWO KINDS OF REFUSAL REACH THIS TEST, and D135 treats them
			// differently on purpose.
			//
			// ADMISSION CONTROL runs before identity is even verified, so there
			// is no principal, no decision record and nothing to audit. It is
			// transport backpressure rather than governance, and it stays a
			// gRPC error — a result with no decision id would be a worse lie
			// than an error.
			//
			// THE ANZEN CAP is governance: a named rule refusing a named
			// principal, recorded. It is a result. And its status is
			// RATE_LIMITED rather than DENIED, which this test used to require:
			// every anzen refusal reported DENIED regardless of which rule
			// fired, conflating "you may never do this" with "not right now".
			// They differ in retryability, so DENIED told a caller to stop
			// trying when retrying is the correct response to a cap.
			switch {
			case err != nil:
				refused++
			case resp.GetResult().GetStatus() == sekizuiv1.Status_STATUS_RATE_LIMITED:
				refused++
			case resp.GetResult().GetStatus() == sekizuiv1.Status_STATUS_OK:
				allowed++
			default:
				t.Errorf("a concurrency cap refused with status %v, want RATE_LIMITED",
					resp.GetResult().GetStatus())
			}
		}()
	}
	wg.Wait()

	if allowed > 3 {
		t.Errorf("%d commands ran concurrently, cap is 3", allowed)
	}
	if refused == 0 {
		t.Error("nothing was refused; the cap did not bind")
	}
	// Slots are returned: after the burst, the next command succeeds.
	after, err := h.srv.Execute(callerCtx(t, "agent:triage"),
		cmd("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"}))
	if err != nil || after.GetResult().GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Errorf("the cap leaked slots; a later command was refused: %v", err)
	}
}

// TestShadowGuardWarnsButPermits — §4.11.4 item 3. A defensive rule that fires
// wrongly disables working automation, so it observes first.
func TestShadowGuardWarnsButPermits(t *testing.T) {
	h := withGuards(t, config.AnzenSpec{
		Name: "proposed-blocklist", Enabled: true, // Mode unset == shadow
		Forbids: []string{"kata.create_issue"},
	})

	resp, err := h.srv.Execute(callerCtx(t, "agent:triage"),
		cmd("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"}))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Errorf("status = %v — a shadow guard must not refuse", got)
	}

	// And it must be REPORTED, or the observation week teaches nothing.
	if names := h.srv.guards.WouldRefuse("agent:triage", "kata.create_issue", ""); len(names) != 1 {
		t.Errorf("WouldRefuse = %v, want the guard named", names)
	}
}

// TestDisabledGuardDoesNothing.
func TestDisabledGuardDoesNothing(t *testing.T) {
	h := withGuards(t, config.AnzenSpec{
		Name: "off", Enabled: false, Mode: "enforce",
		Forbids: []string{"kata.create_issue"},
	})

	resp, err := h.srv.Execute(context.Background(), cmd("kata.create_issue", "kata:alpha", nil))
	_ = resp
	// No certificate, so it fails on identity — which proves the guard did not
	// short-circuit ahead of it.
	if err == nil {
		t.Error("expected an identity failure, not a guard refusal")
	}
}
