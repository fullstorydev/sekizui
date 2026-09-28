package obs

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/connector"
)

const canary = "super-secret-value-9d21"

func capture(t *testing.T, f func(*slog.Logger)) string {
	t.Helper()
	var buf bytes.Buffer
	f(NewLogger(&buf, Options{Level: slog.LevelDebug, JSON: true}))
	return buf.String()
}

// TestRedactsByName is layer 2: a plain string under a sensitive key.
//
// These values are NOT self-redacting types, so nothing but the handler stands
// between them and the log line.
func TestRedactsByName(t *testing.T) {
	keys := []string{
		"password", "passwd", "passphrase",
		"token", "access_token", "refreshToken", "BEARER_TOKEN",
		"secret", "client_secret", "clientSecret",
		"credential", "credentials",
		"api_key", "apiKey", "APIKEY",
		"authorization", "Authorization",
		"cookie", "private_key",
	}

	for _, k := range keys {
		t.Run(k, func(t *testing.T) {
			out := capture(t, func(l *slog.Logger) { l.Info("msg", k, canary) })

			if strings.Contains(out, canary) {
				t.Errorf("key %q leaked its value: %s", k, out)
			}
			if !strings.Contains(out, Redacted) {
				t.Errorf("key %q not redacted: %s", k, out)
			}
		})
	}
}

// TestDoesNotOverRedact is the counterweight, and it matters as much as the
// test above.
//
// Over-redaction destroys the debuggability logs exist for, and a log full of
// [REDACTED] trains people to stop reading it. Every key here contains a
// fragment a careless list WOULD have matched — "key" in poolKey, "auth" in
// auth_method — which is exactly why bare "key" and bare "auth" are absent from
// sensitiveFragments.
func TestDoesNotOverRedact(t *testing.T) {
	keys := []string{
		"pool_key", "poolKey", "cache_key", "idempotency_key",
		"auth_method", "authMethod",
		"key_count", "keyspace",
		"target_ref", "principal", "action", "tenant", "residency",
		"decision_id", "trace_id", "causation_id",
	}

	for _, k := range keys {
		t.Run(k, func(t *testing.T) {
			out := capture(t, func(l *slog.Logger) { l.Info("msg", k, "visible-value") })

			if !strings.Contains(out, "visible-value") {
				t.Errorf("key %q was redacted but is not a secret; "+
					"over-redaction destroys the debuggability logs exist for: %s", k, out)
			}
		})
	}
}

// TestRedactsInsideGroups — a secret nested three levels down is still a secret.
func TestRedactsInsideGroups(t *testing.T) {
	out := capture(t, func(l *slog.Logger) {
		l.Info("resolved",
			slog.Group("target",
				slog.String("ref", "jira:acme"),
				slog.Group("auth",
					slog.String("token", canary),
				),
			),
		)
	})

	if strings.Contains(out, canary) {
		t.Errorf("nested secret leaked: %s", out)
	}
	if !strings.Contains(out, "jira:acme") {
		t.Errorf("non-secret sibling was lost: %s", out)
	}
}

// TestRedactsAttrsBoundWithWith. A secret bound once via logger.With() would
// otherwise leak on every subsequent record rather than just one.
func TestRedactsAttrsBoundWithWith(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, Options{Level: slog.LevelDebug, JSON: true}).
		With("api_key", canary)

	l.Info("first")
	l.Info("second")

	if strings.Contains(buf.String(), canary) {
		t.Errorf("With-bound secret leaked: %s", buf.String())
	}
	if n := strings.Count(buf.String(), Redacted); n != 2 {
		t.Errorf("expected redaction on both records, got %d", n)
	}
}

// TestTypeBasedRedactionSurvivesTheHandler is the layer-1/layer-2 interaction.
//
// connector.Secret is already [REDACTED] by the time the name check runs,
// because redact() resolves LogValuer first. The key here ("blob") is
// deliberately NOT sensitive-looking — proving the type defends itself with no
// help from the list, which is the whole argument of §4.3.3.
func TestTypeBasedRedactionSurvivesTheHandler(t *testing.T) {
	out := capture(t, func(l *slog.Logger) {
		l.Info("resolved", "blob", connector.Secret(canary))
	})

	if strings.Contains(out, canary) {
		t.Errorf("Secret leaked under a non-sensitive key: %s", out)
	}
	if !strings.Contains(out, Redacted) {
		t.Errorf("expected redaction: %s", out)
	}
}

// TestRedactionIsUnconditional is the Lexicon upgrade, asserted.
//
// There, redaction was opt-in: infoSensitive() sanitised only if the caller
// remembered (loggerFramework.js:360). Here an ordinary Info call on an ordinary
// logger is already protected — there is no second method to forget.
func TestRedactionIsUnconditional(t *testing.T) {
	out := capture(t, func(l *slog.Logger) {
		l.Info("ordinary call, no special method", "password", canary)
	})

	if strings.Contains(out, canary) {
		t.Error("redaction required an opt-in call; it must apply to every record")
	}
}

// TestLevelIsHonoured confirms Enabled delegates rather than being swallowed by
// the wrapper.
func TestLevelIsHonoured(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, Options{Level: slog.LevelWarn, JSON: true})

	l.Info("should not appear")
	if buf.Len() != 0 {
		t.Errorf("INFO emitted at WARN level: %s", buf.String())
	}

	l.Warn("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("WARN suppressed: %s", buf.String())
	}
}

// TestBothHandlerFormatsRedact closes a gap in every test above: they all pass
// JSON:true, so the text branch of NewLogger was unexercised.
//
// The wrapper sits OUTSIDE the format handler, so redaction cannot depend on
// which one is chosen — but "cannot" is a claim about code I wrote, and the
// text path is what a developer sees locally, which makes it the likelier place
// to notice a leaked credential and the worse place to have one.
func TestBothHandlerFormatsRedact(t *testing.T) {
	for name, asJSON := range map[string]bool{"json": true, "text": false} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			l := NewLogger(&buf, Options{Level: slog.LevelDebug, JSON: asJSON})

			l.Info("msg",
				"api_key", canary,
				"blob", connector.Secret(canary),
				"tenant", "acme",
			)

			out := buf.String()
			if strings.Contains(out, canary) {
				t.Errorf("%s handler leaked: %s", name, out)
			}
			if strings.Count(out, Redacted) != 2 {
				t.Errorf("%s handler: want both values redacted, got: %s", name, out)
			}
			if !strings.Contains(out, "acme") {
				t.Errorf("%s handler dropped a non-secret attribute: %s", name, out)
			}
		})
	}
}

// TestFormatSelection confirms the Options.JSON branch actually selects a
// different encoder, rather than both paths quietly producing the same thing.
func TestFormatSelection(t *testing.T) {
	var j, txt bytes.Buffer
	NewLogger(&j, Options{Level: slog.LevelInfo, JSON: true}).Info("hello", "k", "v")
	NewLogger(&txt, Options{Level: slog.LevelInfo, JSON: false}).Info("hello", "k", "v")

	if !strings.HasPrefix(j.String(), "{") {
		t.Errorf("JSON:true did not produce JSON: %s", j.String())
	}
	if strings.HasPrefix(txt.String(), "{") {
		t.Errorf("JSON:false produced JSON: %s", txt.String())
	}
	if !strings.Contains(txt.String(), "k=v") {
		t.Errorf("text handler output unexpected: %s", txt.String())
	}
}

func TestIsSensitive(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"token", true},
		{"TOKEN", true},
		{"refresh-token", true},
		{"refresh.token", true},
		{"client_secret", true},
		{"key", false},
		{"pool_key", false},
		{"auth_method", false},
		{"", false},
	} {
		if got := IsSensitive(tc.key); got != tc.want {
			t.Errorf("IsSensitive(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}
