// Package credver is the monotonic high-water mark for credential versions
// (D152).
//
// WHAT IT DEFENDS AGAINST, and why it is not a measurement. A TRACKING reference
// like `gcp-sm://…/versions/latest` asks the platform which version is current.
// Google's documentation states only that a version may be "a version number as
// a string (e.g. '5') or an alias (e.g. 'latest')" and says nothing whatever
// about what `latest` does when the newest version is DISABLED — which is
// exactly the break-glass action §4.7.10 depends on.
//
// So the behaviour is unspecified, and an unspecified behaviour is not a
// contract. If `latest` fails, disabling the newest version IS break-glass. If it
// falls back to the newest *enabled* version, then disabling a compromised
// version silently reverts every caller to the PREVIOUS credential — which may be
// the one compromised first, and is certainly not the one anybody chose — while
// every log line reports a successful resolution. The operator watches
// break-glass appear to work.
//
// **A CHARACTERISATION TEST WOULD NOT SETTLE IT.** It would report what one
// project, in one region, against one API version, did on one day. Sekizui's
// break-glass guarantee would then rest on an accident that may differ elsewhere
// and may change without notice. D105 originally scheduled exactly that test;
// D152 supersedes it for this question, on the maintainer's ruling: build the security
// property instead of measuring the platform.
//
// THE RULE REMOVES THE DEPENDENCY RATHER THAN RESOLVING IT. A tracking reference
// may only move FORWARD. Sekizui records the highest version it has resolved for
// a reference and refuses a resolution that comes back lower. Under the first
// behaviour it fails closed; under the second it refuses because 6 < 7. Correct
// either way, and correct on a platform nobody has characterised.
//
// It is also a rollback guard in its own right: a credential version going
// backwards is a downgrade whether a platform or a person arranged it.
//
// A LEGITIMATE ROLLBACK STAYS POSSIBLE and becomes explicit, which is the shape
// D133 gives restoration. An operator who shipped a broken rotation PINS the
// older version in configuration — a reviewed change with a name against it —
// rather than a tracking reference quietly going backwards.
//
// PUBLIC (D35) for `withdrawal.Store`'s reason: the local implementation makes a
// mark survive a RESTART, and making it survive across REPLICAS needs a shared
// one. See CONTRACTS item 41.
//
// DESIGN.md references: §4.7.3, §4.7.10, §6, D99, D105, D123, D130, D133, D145,
// D152.
package credver

import (
	"context"
	"regexp"
	"strconv"
	"time"
)

// Mark is the highest version seen for one credential reference.
type Mark struct {
	// Ref is the credential reference as configured, tracking alias and all —
	// `gcp-sm://projects/p/secrets/s/versions/latest`. The MARK is keyed on what
	// configuration says, because that is the thing whose meaning can change
	// underneath it; keyed on the resolved version it would be a set of
	// versions, which answers a different question.
	Ref string

	// Version is what the provider reported resolving to (D130), kept verbatim
	// so an operator reading the file sees the platform's own answer.
	Version string

	// Ordinal is Version's comparable form. STORED rather than re-derived,
	// because the extraction rule may improve and a mark written by an older
	// build must keep meaning what it meant.
	Ordinal int64

	At time.Time
}

// Store persists high-water marks.
//
// THE FAILURE DIRECTIONS ARE THE CONTRACT, as they are for withdrawal.Store, and
// they differ in one instructive way. A store that cannot RECORD must NOT fail
// the resolution: the mark is a guard against a future downgrade, and refusing
// to serve a credential that is currently correct would turn a defence into an
// outage — the D150 lesson, that fail-closed is the attack when the threat is to
// availability. It logs loudly instead.
//
// A store that cannot LOAD at boot MUST fail the boot, for withdrawal.Store's
// reason exactly: starting with no marks silently permits every downgrade the
// marks existed to refuse, and an empty set is not a degraded start.
type Store interface {
	// Load returns every mark. Called once at boot.
	//
	// SAME BOOT-ONLY SHAPE AS withdrawal.Store, AND THE SAME LIMITATION
	// (CONTRACTS item 43): a shared BACKEND does not make marks cross replicas,
	// because each replica loads at its own boot. A shared implementation needs
	// a propagation method, and this interface will need the same one.
	Load(ctx context.Context) ([]Mark, error)

	// Put records a new high-water mark. Only ever called with a HIGHER ordinal
	// than the one in force.
	Put(ctx context.Context, m Mark) error
}

// trailingInt matches the last run of digits in a version string, which is where
// every manager that numbers versions puts it: `…/versions/7`, `7`, `v7`.
var trailingInt = regexp.MustCompile(`(\d+)\D*$`)

// Ordinal extracts a comparable ordering from a version string.
//
// RETURNS false WHEN THERE IS NO ORDER, AND THAT IS THE IMPORTANT HALF. A
// content digest — which is what `file://` versions are (§4.7.2's "versioned by
// content") — has no older or newer, so there is nothing to compare and the
// guard must not run. Inventing an order over digests would refuse a legitimate
// edit roughly half the time, and a guard that fires on correct configurations
// is a guard somebody switches off.
//
// The rule is deliberately narrow: a run of digits at the end. `versions/7`
// gives 7, `7` gives 7, `v12` gives 12, and a UUID or a hex digest gives
// nothing. Narrow because a wrong ORDER is worse than no order — it would refuse
// a real rotation while claiming a downgrade, which is the most alarming message
// this system can produce and would be false.
func Ordinal(version string) (int64, bool) {
	m := trailingInt.FindStringSubmatch(version)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		// Overflow on an absurdly long digit run. No order rather than a wrong
		// one, per the note above.
		return 0, false
	}
	return n, true
}
