package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Identity is a content hash of the COMPILED document — what this instance will
// actually enforce, independent of where it came from or how it was written
// (D149).
//
// DISTINCT FROM Version, WHICH IS PROVENANCE. `Version` is whatever the source
// supplies, defaulting to `<file>@<mtime>`, and it answers "which snapshot was I
// handed". That cannot answer the question §4.9a.2 asks of an audit row —
// "which configuration authorised this call" — and it fails in BOTH directions:
// the same configuration deployed to two replicas has two mtimes, so identical
// policy looks divergent; and `touch -r` gives two different configurations one
// mtime, so divergent policy looks identical. The second direction is the
// dangerous one, because it is silent. Both fields are kept: the boot log
// carries them together, so a hash on a decision row joins back to a file.
//
// **Version is EXCLUDED from the hash**, which is the load-bearing detail. Feed
// it in and the identity inherits the mtime sensitivity it exists to remove, and
// two replicas serving byte-identical policy would attest as divergent forever.
//
// SEMANTIC, NOT TEXTUAL, and the boundary is drawn where it can be defended:
//
//   - Comments, key order, indentation and file layout are gone before this runs
//     — the document is already parsed. An operator reformatting YAML has
//     changed nothing an agent can observe, and a hash that disagrees is one
//     people learn to ignore.
//   - Whitespace INSIDE a payload schema is normalised, because a schema is data
//     the registry parses rather than text anybody reads here.
//   - Rego policy source is hashed VERBATIM. It is code, and reformatting code is
//     a change worth seeing.
//   - SLICE ORDER IS SIGNIFICANT and is deliberately not normalised. Grant order
//     is observable in the audit record — `Decision.matched_rule` reads
//     `agent:triage#allow[0]`, an INDEX — so two documents differing only in the
//     order of a principal's grants do not explain their records identically,
//     and calling them the same configuration would be false.
//
// NOT FOR THE HOT PATH. This marshals and hashes the whole document; compute it
// once when wiring and carry the string. The gateway does exactly that.
func (d *Document) Identity() (string, error) {
	const op = "config.Document.Identity"

	// A shallow copy is enough to drop Version: the field is a string, and
	// nothing else below is mutated in place.
	c := *d
	c.Version = ""

	if len(d.PayloadSchemas) > 0 {
		c.PayloadSchemas = make(map[string]json.RawMessage, len(d.PayloadSchemas))
		for name, raw := range d.PayloadSchemas {
			var buf bytes.Buffer
			if err := json.Compact(&buf, raw); err != nil {
				return "", fault.Wrap(fault.KindConfig, op,
					"normalising payload schema "+name, err)
			}
			c.PayloadSchemas[name] = buf.Bytes()
		}
	}

	// encoding/json is deterministic for this shape: struct fields marshal in
	// declaration order and MAP KEYS ARE SORTED, which is a documented guarantee
	// rather than an implementation detail. Without it PayloadSchemas and
	// Policies would hash differently on every run of the same binary.
	b, err := json.Marshal(&c)
	if err != nil {
		return "", fault.Wrap(fault.KindConfig, op, "marshalling document", err)
	}

	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ValidIdentity reports whether s is well-formed as a document identity.
//
// SEPARATE FROM COMPARING IT, because "you configured the guard wrong" and "this
// is not the configuration you shipped" are different problems with different
// remedies, and D138's argument applies: a mismatch is a deployment to
// investigate, a malformed value is a flag to correct, and §7.1's whole point is
// that an operator should not have to infer which. A truncated hash pasted from
// a terminal would otherwise read as a compromised deployment.
func ValidIdentity(s string) error {
	const op = "config.ValidIdentity"

	if len(s) != sha256.Size*2 {
		return fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"a document identity is %d hex characters; got %d",
			sha256.Size*2, len(s)))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fault.Wrap(fault.KindInvalidArgument, op, "not hexadecimal", err)
	}
	return nil
}

// CheckExpectedIdentity compares the identity a deployment SHIPPED against the
// one this process LOADED (D150).
//
// IN pkg/config RATHER THAN IN cmd, so the acceptance step exercises the
// function the binary runs instead of a reimplementation beside it — this
// codebase has already paid once for two internally-consistent implementations
// of one convention (auditwal.TailPathFor).
//
// THE TWO FAILURES RETURN DIFFERENT KINDS ON PURPOSE. A malformed expectation is
// a flag to correct; a mismatch is a deployment to investigate. §7.1's argument
// is that an operator should not have to infer which, and D138 made the same
// split between INVALID_ARGUMENT and DENIED for the same reason — a hash
// truncated by a copy-paste would otherwise read as a compromised deployment,
// which is the more alarming of the two and the wrong one.
//
// AN EMPTY EXPECTATION PASSES. The check is opt-in, and the default has to be
// the direction that cannot cause an outage (D150): a guard that refuses when it
// has not been configured turns an unset flag into a fleet-wide failure.
func CheckExpectedIdentity(expected, actual string) error {
	const op = "config.CheckExpectedIdentity"

	if expected == "" {
		return nil
	}
	if err := ValidIdentity(expected); err != nil {
		return fault.Wrap(fault.KindInvalidArgument, op,
			"-expect-config is not a usable identity; run `sekizui -config <file> "+
				"-config-hash` to print one", err)
	}

	// Case-insensitive: hex is hex, and an operator who upper-cased a hash
	// copying it out of a terminal has not changed which configuration they
	// named. Refusing that would be a guard failing on presentation.
	if !strings.EqualFold(expected, actual) {
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"this configuration is not the one the deployment expected.\n"+
				"  expected: %s\n  loaded:   %s\n\n"+
				"The file on disk is not what was shipped. Refusing to serve rather than "+
				"enforcing a policy nobody reviewed — the replicas already running are "+
				"unaffected. Run `sekizui -config <file> -config-hash` to see what this "+
				"file actually is.", expected, actual))
	}
	return nil
}
