package connector

import (
	"fmt"
	"net/http"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// SetAuthorization borrows the target's credential and stamps it onto an HTTP
// header as `<scheme> <material>` (D199).
//
// **PLACEMENT IS GOVERNANCE, NOT TRANSPORT — D186's rule, applied to the
// credential rather than to the idempotency key.** Three drivers hand-rolled
// this: the same `t.Use` closure, the same buffer, the same `append(buf,
// "Bearer "...)`, each free to get the lending discipline subtly different from
// the next. That is CONTRACTS 63's shape, and it is how a fourth driver comes to
// stash a `Material` because it copied the one that did.
//
// **AND IT REFUSES MATERIAL THAT CANNOT BE A HEADER VALUE, which is the half
// with teeth.** A credential file written with `echo` ends in a newline, and Go
// then refuses to send the request at all:
//
//	net/http: invalid header field value for "Authorization"
//
// That is a good outcome badly reported. The error surfaces through
// `transportFault` as `target_unavailable` — *"the server could not be
// reached"* — which is RETRYABLE, so the retry loop runs and the breaker opens
// **on a target that is perfectly healthy, with every signal pointing at the
// vendor.** A local, one-character configuration mistake is diagnosed as somebody
// else's outage.
//
// **THE REFUSAL IS `KindUnauthenticated`, AND THE OBVIOUS CHOICE WAS WRONG IN A
// WAY ONLY THE STEP CAUGHT.** `KindConfig` reads better — it IS a configuration
// fault — and it would have made things worse on the exact axis this exists for:
// the breaker records `err == nil || Kind.Deliberate()` as a success, and
// `KindConfig` is NOT deliberate, so refusing with it opens the breaker on the
// healthy target. `KindUnauthenticated` is deliberate and not retryable: no
// retry, no breaker damage, and it points at the credential rather than at the
// caller's arguments or at the vendor. The DIAGNOSIS lives in the message, which
// is where an operator reads it.
//
// The residual, stated: `unauthenticated` says the credential is unusable, where
// the truth is narrower — it was never sent. Whether a command-time
// configuration fault should be deliberate at all is a live question about
// `Kind.Deliberate` rather than about this function, and changing a whole kind's
// wire shape to improve one message is D153's over-general derivation.
//
// **SCOPED TO HEADER USE, DELIBERATELY.** The constraint is not "credential
// material may not contain a newline" — a `file://` credential is legitimately a
// PEM client key, and those are full of them. It is "material placed into a
// header value must be one", which is a property of the PLACEMENT and is
// therefore checked where the placement happens. `UseRaw` and the SDK paths are
// untouched.
//
// **NOT AN INJECTION DEFENCE, and saying so matters.** Go's own header
// validation already blocks CRLF before the wire, verified rather than assumed;
// anyone who can write a newline into the secret can write a whole different
// credential, so this buys no confidentiality. What it buys is that the failure
// is attributed to the thing that is actually wrong — and that a driver outside
// this repository (D35), placing material somewhere with no such validation,
// meets a broker that checked rather than one that passed the bytes through.
func SetAuthorization(h http.Header, t Target, scheme string) error {
	const op = "connector.SetAuthorization"

	return t.Use(func(m Material) error {
		// THE BUFFER IS OURS AND THE MATERIAL NEVER LEAVES THE CALLBACK, which
		// is the whole point of the lease (D127). The header value that escapes
		// is a copy the request must hold either way.
		buf := make([]byte, 0, len(scheme)+1+64)
		buf = append(buf, scheme...)
		buf = append(buf, ' ')

		buf, err := m.AppendTo(buf)
		if err != nil {
			return err
		}
		if err := refuseUnsafeHeaderBytes(op, t.Ref(), scheme, buf); err != nil {
			return err
		}

		h.Set("Authorization", string(buf))
		return nil
	})
}

// refuseUnsafeHeaderBytes rejects a value HTTP cannot carry.
//
// **THE MESSAGE NEVER CONTAINS THE MATERIAL.** It names the OFFENDING BYTE and
// where it sits — "ends with a newline", "at byte 12 of 40" — which is
// everything an operator needs and nothing an audit log must not hold (D119:
// material itself is never a field, and never becomes one).
//
// RFC 9110 §5.5: a field value is visible ASCII, space and horizontal tab.
// Anything else is refused, and the two overwhelmingly likely cases — a trailing
// newline from `echo` or an editor — get their own sentence, because "invalid
// byte 0x0a" sends somebody to a hex table to be told they pressed Enter.
func refuseUnsafeHeaderBytes(op, ref, scheme string, value []byte) error {
	// The prefix is ours and known-safe; only the material can be at fault, so
	// positions are reported within it.
	start := len(scheme) + 1
	material := value[start:]

	for i, b := range material {
		if b == '\t' || (b >= 0x20 && b <= 0x7E) {
			continue
		}

		// **NEITHER REFUSAL BELOW MAY USE `fault.CredentialRejected` (D203).** Both
		// are `KindUnauthenticated` and both are about the credential, so the
		// marker looks apt — and it is exactly wrong. Re-minting returns the SAME
		// BYTES: the material is unusable as a header value, which is a property
		// of what was stored rather than of how old it is. A marked refusal here
		// would spend a mint against the secret manager and then refuse again, on
		// every command, for as long as the operator's `echo` newline is in the
		// file. `archcheck.TestOnlyADriverReportsAFarSideRejection` enforces it.
		switch {
		// CRLF is TWO bytes and the CR is hit first, so the trailing case has to
		// look ahead rather than only back. The first draft looked back, which
		// reported a `\r\n` ending as a generic invalid byte — the right refusal
		// with the wrong sentence, and the sentence is the whole reason this
		// branch exists.
		case (b == '\n' || b == '\r') && i == len(material)-1,
			b == '\r' && i == len(material)-2 && material[len(material)-1] == '\n':
			return fault.New(fault.KindUnauthenticated, op, fmt.Sprintf(
				"the credential for target %q ends with a newline, so it cannot be sent as "+
					"an %s Authorization header. This is almost always how the secret was "+
					"written rather than what it is: `echo` appends one and `printf %%s` does "+
					"not. Refused here rather than at the transport, because Go rejects the "+
					"request and the failure then reads as the target being unreachable — "+
					"which retries, opens the breaker, and blames a server that is fine",
				ref, scheme))

		default:
			return fault.New(fault.KindUnauthenticated, op, fmt.Sprintf(
				"the credential for target %q contains byte %#02x at position %d of %d, "+
					"which is not permitted in an HTTP header value (RFC 9110 §5.5: visible "+
					"ASCII, space and tab). The material is not shown. If this credential is "+
					"genuinely binary or multi-line — a PEM key, for instance — it is not an "+
					"%s header credential and the target is configured for the wrong "+
					"binding class (§4.7.4)",
				ref, b, i+1, len(material), scheme))
		}
	}
	return nil
}
