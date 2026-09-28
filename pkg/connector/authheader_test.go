package connector

import (
	"net/http"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// headerTarget builds a target holding the given credential material.
func headerTarget(t *testing.T, material string) Target {
	t.Helper()
	tgt, err := NewTarget(TargetParams{
		Ref: "vendor:one", Kind: "kata", Tenant: "acme", Residency: "eu",
		BaseURL: "https://vendor.invalid", CredentialVersion: "1",
		Credential: Secret(material),
	})
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}
	return tgt
}

// TestSetAuthorizationRefusesWhatHTTPCannotCarry is D199.
//
// **THE CASES ARE THE REASON THE CHECK IS HERE AND NOT IN A PROVIDER.** A
// trailing newline is how a secret gets written, not what it is; Go then refuses
// the request and the failure reads as the TARGET being unreachable, which
// retries and opens the breaker on a server that is fine.
func TestSetAuthorizationRefusesWhatHTTPCannotCarry(t *testing.T) {
	for _, tc := range []struct {
		name, material string
		ok             bool
		says           string
	}{
		{name: "an ordinary token", material: "abc123", ok: true},
		{name: "base64 padding and dots", material: "eyJ.aGVsbG8=.x_y-z", ok: true},

		// **A TRAILING SPACE IS ACCEPTED, and that is not an oversight.** HTTP
		// itself trims leading and trailing whitespace from a field value
		// (RFC 9110 §5.5), so it reaches the server identically — verified
		// against net/http rather than assumed. Refusing it would refuse a
		// credential that works.
		{name: "a trailing space", material: "abc123 ", ok: true},

		{name: "a trailing newline", material: "abc123\n", says: "ends with a newline"},
		{name: "a trailing CRLF", material: "abc123\r\n", says: "ends with a newline"},
		{name: "an interior newline", material: "abc\ndef", says: "not permitted"},
		{name: "a CRLF injection attempt", material: "abc\r\nX-Injected: yes", says: "not permitted"},
		{name: "a NUL", material: "abc\x00def", says: "not permitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			err := SetAuthorization(h, headerTarget(t, tc.material), "Bearer")

			if tc.ok {
				if err != nil {
					t.Fatalf("a usable credential was refused: %v", err)
				}
				if got := h.Get("Authorization"); got != "Bearer "+tc.material {
					t.Errorf("header is %q, want %q", got, "Bearer "+tc.material)
				}
				return
			}

			if err == nil {
				t.Fatal("accepted. Go then refuses to send the request and the failure " +
					"reads as the target being unreachable — retried, and the breaker " +
					"opens on a healthy server")
			}
			// **THE KIND IS THE POINT, not merely that it failed**, and the
			// reading that looks right is wrong: `KindConfig` is NOT deliberate,
			// and the breaker records a non-deliberate failure against the
			// target. `KindUnauthenticated` is deliberate and not retryable, so
			// the healthy vendor is left alone.
			if got := fault.KindOf(err); got != fault.KindUnauthenticated {
				t.Errorf("kind is %v, want %v", got, fault.KindUnauthenticated)
			}
			if !fault.KindOf(err).Deliberate() {
				t.Error("the refusal is not deliberate, so the breaker records it as a " +
					"failure of a target that was never contacted")
			}
			if fault.KindOf(err).Retryable() {
				t.Error("the refusal is retryable, so the retry loop runs a request that " +
					"cannot succeed until a human edits a file")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the refusal does not say %q: %v", tc.says, err)
			}
			// **NOTHING IS STAMPED ON THE WAY OUT.** A refusal that had already
			// written the header would leave the caller free to send it.
			if got := h.Get("Authorization"); got != "" {
				t.Errorf("the header was set despite the refusal: %q", got)
			}
		})
	}
}

// TestSetAuthorizationNeverShowsTheMaterial — D119: material itself is never a
// field, and never becomes one. A refusal that quoted the credential to explain
// what was wrong with it would put it in every log that captures the error.
func TestSetAuthorizationNeverShowsTheMaterial(t *testing.T) {
	const secret = "super-secret-value"

	err := SetAuthorization(http.Header{}, headerTarget(t, secret+"\n"), "Bearer")
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the refusal contains the credential: %v", err)
	}
	// It must still be diagnosable: the target and what to do.
	for _, want := range []string{"vendor:one", "printf"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so it names the problem and not "+
				"the fix: %v", want, err)
		}
	}
}

// TestSetAuthorizationHonoursAnExpiredLease — the borrow discipline is the
// helper's now, so the refusal D127 relies on must survive being centralised.
func TestSetAuthorizationHonoursAnExpiredLease(t *testing.T) {
	tgt := headerTarget(t, "abc123")
	tgt.WipeCredential()

	if err := SetAuthorization(http.Header{}, tgt, "Bearer"); err == nil {
		t.Fatal("a wiped credential was stamped onto a header. `Use` refusing after " +
			"eviction or revocation is what makes a command fail rather than proceed " +
			"with material that is no longer authorised (D127)")
	}
}
