package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// The literal a leak would print. Every test below asserts it never appears.
const canary = "super-secret-jira-token-8f3a"

// TestSecretImplementsLogValuer guards the interface satisfaction itself.
//
// Worth an explicit test because Go's implicit satisfaction means DELETING
// LogValue does not break the build — Secret simply stops being a LogValuer and
// starts printing its bytes. That is exactly how this shipped documented but
// unimplemented: the doc comment described a method that did not exist and
// nothing failed.
func TestSecretImplementsLogValuer(t *testing.T) {
	var _ slog.LogValuer = Secret(nil) // value receiver: the common case
	var _ fmt.Stringer = Secret(nil)   // %s and %v
	var _ fmt.GoStringer = Secret(nil) // %#v
}

// logTo captures one JSON log record.
func logTo(t *testing.T, f func(*slog.Logger)) string {
	t.Helper()
	var buf bytes.Buffer
	f(slog.New(slog.NewJSONHandler(&buf, nil)))
	return buf.String()
}

func TestSecretRedactedByStockHandlers(t *testing.T) {
	s := Secret(canary)

	cases := map[string]func(*slog.Logger){
		"as a direct value": func(l *slog.Logger) {
			l.Info("resolved", "credential", s)
		},
		"inside a group": func(l *slog.Logger) {
			l.Info("resolved", slog.Group("target", slog.Any("credential", s)))
		},
		"via slog.Any": func(l *slog.Logger) {
			l.Info("resolved", slog.Any("cred", s))
		},
		"attached with With": func(l *slog.Logger) {
			l.With("credential", s).Info("resolved")
		},
	}

	for name, emit := range cases {
		t.Run(name, func(t *testing.T) {
			out := logTo(t, emit)
			if strings.Contains(out, canary) {
				t.Errorf("credential leaked: %s", out)
			}
			if !strings.Contains(out, Redacted) {
				t.Errorf("expected %s in output, got: %s", Redacted, out)
			}
		})
	}
}

// TestSecretRedactedInsideATarget is the case that matters operationally:
// nobody logs a bare Secret, they log the Target that holds one.
func TestSecretRedactedInsideATarget(t *testing.T) {
	tgt := Target{
		ref:    "jira:acme",
		kind:   "jira",
		tenant: "acme",
		cred:   NewCredential(Secret(canary)),
	}

	// Every route a Target could plausibly reach a log or a debugger.
	//
	// %s is deliberately absent: go vet rejects %s on a struct with no String
	// method ("wrong type"), so that route cannot reach production without
	// failing `make lint` first. One fewer thing to test, because the toolchain
	// already forbids it.
	for name, got := range map[string]string{
		"%v":  fmt.Sprintf("%v", tgt),
		"%+v": fmt.Sprintf("%+v", tgt),
		"%#v": fmt.Sprintf("%#v", tgt),
		"slog": logTo(t, func(l *slog.Logger) {
			l.Info("resolved target", "target", fmt.Sprintf("%+v", tgt))
		}),
	} {
		if strings.Contains(got, canary) {
			t.Errorf("credential leaked via %s: %s", name, got)
		}
	}
}

// TestExplicitConversionStillYieldsBytes. Redaction must not break the
// legitimate use — a driver signing a request needs the real material, and the
// explicit []byte conversion is the visible seam where that intent is stated.
func TestExplicitConversionStillYieldsBytes(t *testing.T) {
	s := Secret(canary)

	if got := string([]byte(s)); got != canary {
		t.Errorf("explicit conversion = %q, want the real secret", got)
	}
	if len(s) != len(canary) {
		t.Errorf("len = %d, want %d", len(s), len(canary))
	}
}

func TestSecretRedactedByEncodingJSON(t *testing.T) {
	b, err := json.Marshal(Secret(canary))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), canary) {
		t.Errorf("credential leaked through encoding/json: %s", b)
	}
	if got, want := string(b), `"`+Redacted+`"`; got != want {
		t.Errorf("marshal = %s, want %s", got, want)
	}
}

// TestSecretRedactedInsideAMarshalledStruct covers the realistic route: nobody
// marshals a bare Secret, they marshal something holding one.
func TestSecretRedactedInsideAMarshalledStruct(t *testing.T) {
	payload := struct {
		Ref   string `json:"ref"`
		Cred  Secret `json:"cred"`
		Extra string `json:"extra"`
	}{Ref: "jira:acme", Cred: Secret(canary), Extra: "visible"}

	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), canary) {
		t.Errorf("credential leaked: %s", b)
	}
	// The rest of the struct must survive — redaction that eats neighbouring
	// fields is its own bug.
	if !strings.Contains(string(b), "visible") || !strings.Contains(string(b), "jira:acme") {
		t.Errorf("non-secret fields lost: %s", b)
	}
}

// TestSecretRefusesUnmarshal is what makes MarshalJSON safe.
//
// Without it the round-trip corrupts silently: "[REDACTED]" unmarshals back as
// literal bytes and you hold a credential that is not one, surfacing as
// confusing 401s. Failing loudly is strictly better — and refusing outright
// follows from §4.7, since configuration carries references rather than
// material and nothing legitimate parses a Secret out of JSON.
func TestSecretRefusesUnmarshal(t *testing.T) {
	var s Secret
	err := json.Unmarshal([]byte(`"anything at all"`), &s)
	if err == nil {
		t.Fatal("Secret unmarshalled from JSON; the redacted round-trip would " +
			"silently yield a credential that is not a credential")
	}
	if !strings.Contains(err.Error(), "SecretProvider") {
		t.Errorf("error should point at where credentials actually come from: %v", err)
	}
	if len(s) != 0 {
		t.Errorf("Secret was partially populated despite the error: %q", s)
	}
}

// TestTargetMarshalsEmpty records why the exposure was narrower than it looked.
//
// Target's fields are all unexported for §6's tenancy reasons, and encoding/json
// skips unexported fields — so the most plausible leak route, dumping a Target
// into a debug endpoint, was already closed by sealing done for an unrelated
// purpose. Worth pinning: if someone exports a field later, this fails and the
// credential question gets asked again.
func TestTargetMarshalsEmpty(t *testing.T) {
	tgt := Target{ref: "jira:acme", tenant: "acme", cred: NewCredential(Secret(canary))}

	// staticcheck SA9005 flags marshalling a struct with no exported fields as
	// pointless. That is exactly the property being asserted — and the linter
	// independently confirming it is reassuring rather than annoying.
	//nolint:staticcheck // SA9005 is the assertion, not a warning.
	b, err := json.Marshal(tgt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "{}" {
		t.Errorf("Target marshalled to %s, want {} — a field was exported, so "+
			"re-check whether credential material can now escape", b)
	}
}

func TestWipeZeroesTheMaterial(t *testing.T) {
	s := Secret(canary)

	s.Wipe()

	if strings.Contains(string([]byte(s)), canary) {
		t.Error("Wipe left the credential readable")
	}
	for i, b := range s {
		if b != 0 {
			t.Errorf("byte %d = %d after Wipe, want 0", i, b)
		}
	}
	// Length is unchanged: Wipe zeroes, it does not truncate or reallocate.
	// A reallocating Wipe would leave the ORIGINAL array untouched and
	// readable, which is the bug this test exists to prevent.
	if len(s) != len(canary) {
		t.Errorf("len = %d after Wipe, want %d — reallocating would leave the "+
			"original bytes intact somewhere", len(s), len(canary))
	}
}

// TestWipeIsVisibleThroughEveryCopy is the reason Wipe uses a value receiver.
//
// A slice header copies, but the backing array is shared. Wiping one holder must
// invalidate all of them — otherwise a Target that handed its credential to a
// driver still holds a live copy after the wipe, and the mitigation is theatre.
func TestWipeIsVisibleThroughEveryCopy(t *testing.T) {
	original := Secret(canary)
	handedToDriver := original
	insideAStruct := struct{ Cred Secret }{Cred: original}

	handedToDriver.Wipe()

	if strings.Contains(string([]byte(original)), canary) {
		t.Error("wiping a copy left the original readable")
	}
	if strings.Contains(string([]byte(insideAStruct.Cred)), canary) {
		t.Error("wiping a copy left a struct-held reference readable")
	}
}

func TestWipeOnEmptyAndNilIsSafe(t *testing.T) {
	// Both are realistic: an unresolved Target, or a deferred Wipe on an error
	// path that never populated the field. Neither may panic.
	Secret(nil).Wipe()
	Secret{}.Wipe()
}

// TestSecretIsNotRedactedByYAMLStyleReflection documents the REMAINING gap, in
// the same style as the JSON one it replaces.
//
// Type-based redaction only defends paths that ASK THE TYPE what it wants to
// look like. Each serialiser needs its own method: encoding/json wants
// MarshalJSON, YAML wants MarshalYAML and gets nothing from String, protobuf
// uses its own machinery entirely. A serialiser reaching the bytes by
// reflection — which is what a YAML encoder does absent MarshalYAML — sees
// straight through all of it.
//
// No YAML dependency exists yet, so this simulates the shape rather than
// importing one. It is a placeholder for a real case: configuration is written
// in YAML (§4.7), and a config-dumping debug endpoint is a plausible future.
//
// The honest claim for Secret is therefore "every path that asks the type what
// it wants to look like", NOT "every path". string(secret) and writing the bytes
// to an io.Writer bypass everything by design, because drivers need the material.
func TestSecretIsNotRedactedByYAMLStyleReflection(t *testing.T) {
	// What a reflection-based encoder sees: a []byte, with no method consulted.
	viaReflection := string([]byte(Secret(canary)))

	if !strings.Contains(viaReflection, canary) {
		t.Skip("reflection no longer reaches the bytes — re-examine this gap")
	}
	t.Logf("known gap: a reflection-based serialiser (YAML without MarshalYAML) "+
		"sees %d raw bytes; add MarshalYAML when a YAML dependency lands", len(viaReflection))
}
