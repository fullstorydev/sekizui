package anzen

import (
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
)

// TestGlobMatch pins the pattern language, including the cases a blocklist
// author actually writes.
func TestGlobMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"kata.create_issue", "kata.create_issue", true},
		{"kata.create_issue", "kata.create_other", false},

		// Trailing — the grant-style prefix still works.
		{"reflex:*", "reflex:friction", true},
		{"reflex:*", "agent:triage", false},
		{"kata.delete_*", "kata.delete_project", true},

		// Leading and middle — what a destructive-action blocklist needs, and
		// what the grant-style matcher could not express.
		{"*.delete_*", "kata.delete_project", true},
		{"*.delete_*", "jira.delete_issue", true},
		{"*.delete_*", "kata.create_issue", false},
		{"*_project", "kata.delete_project", true},
		{"*", "anything.at.all", true},

		// A pattern must not match a superstring by accident.
		{"kata.read", "kata.read_all", false},
	} {
		if got := globMatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

// TestEmptyScopeCoversEveryone. A destructive action nobody should perform is
// not a per-principal question, and requiring enumeration means a principal
// added later silently escapes the guard.
func TestEmptyScopeCoversEveryone(t *testing.T) {
	if !covers(nil, "anyone:at:all") {
		t.Error("an unscoped guard did not cover an arbitrary principal")
	}
	if covers([]string{"reflex:*"}, "agent:triage") {
		t.Error("a reflex-scoped guard covered an agent")
	}
}

// The guard behaviour is exercised end to end in internal/gateway, but the
// package's own coverage was 24% — so the concurrency and shadow-mode paths, the
// ones hardest to reason about from a call site, had no direct test.

func specs(s ...config.AnzenSpec) *Guards { return New(s) }

func TestForbidRefusesOnlyWhenEnforcing(t *testing.T) {
	enforcing := specs(config.AnzenSpec{
		Name: "g", Enabled: true, Mode: "enforce", Forbids: []string{"x.delete"},
	})
	if _, _, err := enforcing.Check("agent:a", "x.delete", ""); err == nil {
		t.Error("an enforcing guard permitted a forbidden action")
	}
	if _, release, err := enforcing.Check("agent:a", "x.read", ""); err != nil {
		t.Errorf("an unrelated action was refused: %v", err)
	} else {
		release()
	}

	shadow := specs(config.AnzenSpec{
		Name: "g", Enabled: true, Forbids: []string{"x.delete"}, // Mode unset
	})
	_, release, err := shadow.Check("agent:a", "x.delete", "")
	if err != nil {
		t.Errorf("a shadow guard refused: %v", err)
	} else {
		release()
	}
	if names := shadow.WouldRefuse("agent:a", "x.delete", ""); len(names) != 1 || names[0] != "g" {
		t.Errorf("WouldRefuse = %v; a shadow week that reports nothing teaches nothing", names)
	}

	disabled := specs(config.AnzenSpec{
		Name: "g", Enabled: false, Mode: "enforce", Forbids: []string{"x.delete"},
	})
	if _, _, err := disabled.Check("agent:a", "x.delete", ""); err != nil {
		t.Errorf("a disabled guard refused: %v", err)
	}
}

// TestConcurrencyCapReleasesSlots. A leaked slot is worse than no cap: the
// guard silently tightens over time until nothing gets through, and nothing in
// the logs explains why.
func TestConcurrencyCapReleasesSlots(t *testing.T) {
	g := specs(config.AnzenSpec{
		Name: "cap", Enabled: true, Mode: "enforce", MaxConcurrent: 2,
	})

	_, r1, err := g.Check("agent:a", "x.do", "")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	_, r2, err := g.Check("agent:a", "x.do", "")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if _, _, err := g.Check("agent:a", "x.do", ""); err == nil {
		t.Fatal("a third concurrent action was admitted past a cap of 2")
	}
	// A DIFFERENT principal is unaffected — the cap is per principal.
	if _, r3, err := g.Check("agent:b", "x.do", ""); err != nil {
		t.Errorf("another principal was blocked by the first one's cap: %v", err)
	} else {
		r3()
	}

	r1()
	r2()
	if g.InFlight()["agent:a"] != 0 {
		t.Errorf("slots leaked: %v", g.InFlight())
	}
	// And the cap admits again.
	if _, r, err := g.Check("agent:a", "x.do", ""); err != nil {
		t.Errorf("the cap did not recover after release: %v", err)
	} else {
		r()
	}
}

// TestReleaseIsIdempotent — a double release would free a slot twice and let
// concurrency drift ABOVE the cap, which is worse than leaking one.
func TestReleaseIsIdempotent(t *testing.T) {
	g := specs(config.AnzenSpec{
		Name: "cap", Enabled: true, Mode: "enforce", MaxConcurrent: 1,
	})
	_, release, err := g.Check("agent:a", "x.do", "")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	release()
	release()
	release()

	if got := g.InFlight()["agent:a"]; got != 0 {
		t.Errorf("InFlight = %d after repeated release, want 0", got)
	}
	// One slot, so exactly one admission.
	_, r1, err := g.Check("agent:a", "x.do", "")
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	defer r1()
	if _, _, err := g.Check("agent:a", "x.do", ""); err == nil {
		t.Error("repeated release inflated the cap above its configured value")
	}
}

// TestConcurrentCheckIsSafe — one Guards is consulted by every request at once.
func TestConcurrentCheckIsSafe(t *testing.T) {
	g := specs(config.AnzenSpec{
		Name: "cap", Enabled: true, Mode: "enforce", MaxConcurrent: 4,
	})
	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 50 {
				if _, release, err := g.Check("agent:a", "x.do", ""); err == nil {
					release()
				}
			}
		}()
	}
	for range 8 {
		<-done
	}
	if got := g.InFlight(); len(got) != 0 {
		t.Errorf("slots outstanding after every caller released: %v", got)
	}
}
