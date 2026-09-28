package main

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// The flag parsers are the CLI CONTRACT — the boundary between what an operator
// types and what the process believes. They are pure functions with error paths,
// which makes them cheap to test and easy to leave untested.
//
// Note what is NOT tested here: that slog suppresses INFO at WARN level. That is
// stdlib behaviour, not ours. What IS ours is the string -> Level mapping below
// and, in internal/obs, that the redacting wrapper delegates Enabled rather than
// swallowing the decision.

func TestParseLevel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		// "warning" is an accepted alias. Undiscoverable without reading the
		// source, which is exactly why it needs a test to stop it being
		// "tidied away" by someone who never knew it was deliberate.
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		// Case-insensitive: operators type INFO as often as info.
		{"INFO", slog.LevelInfo},
		{"Warn", slog.LevelWarn},
	} {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseLevel(tc.in)
			if err != nil {
				t.Fatalf("parseLevel(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseLevel(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseLevelRejectsUnknown(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "verbose", "trace", "fatal", "9"} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			_, err := parseLevel(in)
			if err == nil {
				t.Fatalf("parseLevel(%q) accepted an unknown level", in)
			}
			if !errors.Is(err, fault.KindConfig) {
				t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
			}
			// A rejection that does not say what IS valid makes the operator
			// go read the source.
			if !containsAll(err.Error(), "debug", "info", "warn", "error") {
				t.Errorf("error does not list the valid levels: %v", err)
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	t.Parallel()

	gateway, err := parseMode("gateway")
	if err != nil || gateway != runtime.ModeGateway {
		t.Errorf("parseMode(gateway) = %v, %v", gateway, err)
	}
	ingest, err := parseMode("ingest")
	if err != nil || ingest != runtime.ModeIngest {
		t.Errorf("parseMode(ingest) = %v, %v", ingest, err)
	}

	// Unlike parseLevel, mode is deliberately case-SENSITIVE: it names a
	// deployment topology that appears verbatim in manifests, and accepting
	// "Ingest" would invite two spellings of one thing.
	if _, err := parseMode("Gateway"); err == nil {
		t.Error("parseMode accepted mixed case; modes appear verbatim in deployment manifests")
	}
	if _, err := parseMode("worker"); err == nil {
		t.Error("parseMode accepted an unknown mode")
	} else if !errors.Is(err, fault.KindConfig) {
		t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
	}
}

func TestParseAudit(t *testing.T) {
	t.Parallel()

	wal, err := parseAudit("wal")
	if err != nil || wal != runtime.AuditWAL {
		t.Errorf("parseAudit(wal) = %v, %v", wal, err)
	}
	sync, err := parseAudit("sync")
	if err != nil || sync != runtime.AuditSync {
		t.Errorf("parseAudit(sync) = %v, %v", sync, err)
	}
	if _, err := parseAudit("async"); err == nil {
		t.Error("parseAudit accepted 'async'; §5.2.2 rejects fully-async audit outright, " +
			"so the word must not be quietly aliased to something else")
	}
}

// TestParseOverridesTriState is the reason these flags are strings rather than
// flag.Bool: unset and false must stay distinguishable, because
// runtime.Override uses *bool precisely to tell them apart.
func TestParseOverridesTriState(t *testing.T) {
	t.Parallel()

	unset, err := parseOverrides("", "")
	if err != nil {
		t.Fatalf("parseOverrides: %v", err)
	}
	if unset.BackgroundWork != nil || unset.LeaderElection != nil {
		t.Error("empty flags produced non-nil overrides; unset must stay unset")
	}

	on, err := parseOverrides("true", "true")
	if err != nil {
		t.Fatalf("parseOverrides: %v", err)
	}
	if on.BackgroundWork == nil || !*on.BackgroundWork {
		t.Error(`-background-work=true did not set the override`)
	}

	off, err := parseOverrides("false", "false")
	if err != nil {
		t.Fatalf("parseOverrides: %v", err)
	}
	if off.BackgroundWork == nil {
		t.Fatal(`-background-work=false read as unset; the whole point of *bool is lost`)
	}
	if *off.BackgroundWork {
		t.Error(`-background-work=false set the override to true`)
	}
}

func TestParseOverridesRejectsJunk(t *testing.T) {
	t.Parallel()

	// "1"/"yes"/"on" are NOT accepted. Being liberal here would mean a typo
	// like -background-work=ture reads as false and silently disables a
	// capability the operator was trying to enable.
	for _, in := range []string{"1", "0", "yes", "no", "on", "off", "ture"} {
		if _, err := parseOverrides(in, ""); err == nil {
			t.Errorf("parseOverrides accepted %q; a typo must not silently mean false", in)
		}
	}
}

// TestListenAddr pins the precedence: an explicit flag beats $PORT, and $PORT
// beats the default. Cloud Run and App Service both inject PORT and expect it
// obeyed, so getting this backwards means the service binds somewhere the
// platform is not listening.
func TestListenAddr(t *testing.T) {
	// Not parallel: t.Setenv is incompatible with t.Parallel, since process
	// environment is global (see GO-PRIMER §15a).
	t.Setenv("PORT", "9090")

	if got := listenAddr(":1234"); got != ":1234" {
		t.Errorf("explicit flag = %q, want :1234 — the flag must beat $PORT", got)
	}
	if got := listenAddr(""); got != ":9090" {
		t.Errorf("with $PORT set = %q, want :9090", got)
	}

	t.Setenv("PORT", "")
	if got := listenAddr(""); got != ":8080" {
		t.Errorf("with no flag and no $PORT = %q, want :8080", got)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
