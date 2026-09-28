package archcheck_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnlyAFarSideRejectionMarksReestablish is D203's structural half, in two
// parts: nobody sets the field, and only a driver calls the constructor that
// does.
//
// **THE MARKER IS PER-ERROR PRECISELY BECAUSE THE KIND IS NOT ENOUGH**, and a
// per-error marker is only as good as the discipline about who sets it.
// `KindUnauthenticated` has five producers with three different correct
// remedies:
//
//	a 401 from the far side          re-mint and retry — the case this exists for
//	D199's header-placement refusal  re-minting returns the same bad bytes
//	D152's downgrade guard           re-resolving re-triggers it — RETRYING IS
//	                                 WHAT THE ATTACKER WANTS
//	a borrow on a wiped credential   break-glass just happened; retrying is wrong
//	an IdP that would not issue      the credential chain is broken, not stale
//
// So the marker is useless-to-harmful the moment somebody sets it from a place
// that has not read a real far-side status. The dangerous case is not
// hypothetical and is not a slippery slope: D152's guard refuses a credential
// version that moved BACKWARDS, which is what a disabled compromised version
// looks like when a platform falls back — and a re-resolve is exactly what an
// attacker forcing that rollback wants us to do.
//
// **THIS GUARD FOUND ITS FIRST OFFENDER BEFORE IT HAD ONE.** Written when two
// drivers each hand-built the marked error, it immediately flagged the
// acceptance suite's fake far side — which is a legitimate marker-setter, being
// a driver. Rather than exempt it, the marking became one constructor
// (`fault.CredentialRejected`) that all three call, which is D173's and D199's
// answer to the same shape and is why the rule below can be absolute.
func TestOnlyAFarSideRejectionMarksReestablish(t *testing.T) {
	root := repoRootFor(t)

	// ONLY THE DECLARATION AND THIS GUARD. Absolute, because there is now a
	// constructor: any code that needs the marker calls it, and any code that
	// sets the field literally is bypassing the one place the rule is written.
	exempt := []string{"pkg/fault/", "internal/archcheck"}

	offenders := filesContaining(t, root, exempt, "Reestablish: true")
	if len(offenders) > 0 {
		t.Errorf("%d file(s) set fault.Error.Reestablish directly: %v\n\n"+
			"Use `fault.CredentialRejected`, which is the one place that says what the "+
			"marker MEANS — a far side read the credential we sent and rejected it "+
			"(D203). Setting the field by hand is how the second driver's copy drifts "+
			"from the first's, and this is the field where a drift is a security "+
			"property: four of `unauthenticated`'s five producers must NOT be marked, "+
			"and one of them is D152's downgrade guard, where retrying is the "+
			"attacker's goal.", len(offenders), offenders)
	}
}

// TestOnlyADriverReportsAFarSideRejection bounds who may CALL the constructor.
//
// The guard above stops the field being set by hand; this one stops the
// constructor being called from a stage that inferred an auth problem rather
// than reading one. Those stages exist and are named: `internal/credential`
// holds D152's downgrade guard, `pkg/connector` holds D199's placement refusal,
// and `pkg/provider/oauth` refuses when an IdP will not issue. All three
// produce `KindUnauthenticated` and all three must stay unmarked.
//
// **A FILE ALLOWLIST RATHER THAN A TYPE**, because there is no type that
// distinguishes "I read a 401 off the wire" from "I decided this is an auth
// problem". What distinguishes them is WHERE the code sits, so that is what the
// guard keys on. A new driver is one line here, and that line is a reviewer
// asking whether it really did read a status from the far side.
func TestOnlyADriverReportsAFarSideRejection(t *testing.T) {
	root := repoRootFor(t)

	permitted := []string{
		"pkg/fault/",           // declares it
		"internal/driver/",     // read a real status from a real far side
		"internal/connectors/", // the same, since D316 moved the connectors' drivers here
		"internal/acceptance/p2_reestablish_test.go", // the fake far side, which is a driver
		"internal/archcheck",                         // this guard

		// **THE KATA IS A DRIVER, and the guard was right to ask (D218).** It
		// fired the minute `hako/solution` landed, because "a driver" was
		// spelled as a path under `internal/driver/` and the kata deliberately
		// sits at the repo root where the audience it is written for will find
		// it. The review question this guard exists to force has an answer: the
		// kata's 401 branch reads `resp.StatusCode` off a real response, which
		// is the one producer of `unauthenticated` a fresh mint can fix — and
		// its borrow failure a few lines above returns the same kind and
		// deliberately does NOT mark it.
		//
		// The EXERCISE is listed too, and on purpose: its gaps are in the
		// governance half, so a learner must not be handed a driver whose error
		// taxonomy is subtly wrong on top of everything else.
		"hako/solution/", "hako/exercise/",
	}

	offenders := filesContaining(t, root, permitted, "fault.CredentialRejected(")
	if len(offenders) > 0 {
		t.Errorf("%d file(s) outside a driver report a far-side credential rejection: "+
			"%v\n\nOnly a status read from the far side may ask for a re-mint (D203). "+
			"The stages that infer an auth problem must NOT: re-minting returns the same "+
			"bad bytes for D199's placement refusal, fetches material an operator just "+
			"wiped after break-glass, and RE-TRIGGERS D152's downgrade guard. If a new "+
			"driver belongs here, add it and say in review how it knows the far side "+
			"rejected the credential rather than inferring it.", len(offenders), offenders)
	}
}

// filesContaining walks the tree for a literal, skipping an allowlist.
//
// TESTS ARE IN SCOPE, for TestNoAdHocAuthorizationHeaders' reason: a test that
// marks its own fixture asserts against a marking the product does not perform,
// which is how a guard becomes true of the tests and false of the code.
func filesContaining(t *testing.T, root string, exempt []string, literal string) []string {
	t.Helper()

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "bin", "out", ".gocache", "dev":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		for _, ex := range exempt {
			if strings.HasPrefix(slash, ex) {
				return nil
			}
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(b), literal) {
			offenders = append(offenders, slash)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	return offenders
}

// TestReestablishHasOneInvalidationCaller keeps the forced mint reachable from
// one place (D204).
//
// A FORCED RE-RESOLVE IS AN AMPLIFICATION PRIMITIVE aimed at the secret manager
// or the IdP, and it is reachable by a hostile target returning 401 deliberately.
// It is bounded per command, bounded again by the target's rate limit, and
// switchable off — and all of that is worth nothing if a second caller appears
// that does not go through the loop those bounds live in.
//
// TWO LINKS, ONE CALLER EACH: the gateway calls `resolver.Invalidate`, the
// resolver calls `credential.Cache.Invalidate`, and nothing else calls either.
func TestReestablishHasOneInvalidationCaller(t *testing.T) {
	root := repoRootFor(t)

	// THE TWO DECLARATIONS AND THE ONE CALLER, by exact file rather than by
	// package — a package-wide exemption would let a second production caller
	// appear inside `internal/credential` and pass, which is most of what this
	// guard is for.
	permitted := []string{
		"internal/credential/cache.go",    // declares Cache.Invalidate
		"internal/resolver/resolver.go",   // declares Resolver.Invalidate, calls the cache's
		"internal/gateway/reestablish.go", // the loop, and the only caller of the resolver's
		"internal/archcheck",              // this guard
	}

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "bin", "out", ".gocache", "dev":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		for _, ex := range permitted {
			if strings.HasPrefix(slash, ex) {
				return nil
			}
		}
		// **TESTS ARE OUT OF SCOPE HERE, AND IN SCOPE FOR THE MARKER GUARD ABOVE.**
		// The two differ because the hazards differ. A test that stamps an
		// Authorization header, or marks its own error re-establishable, asserts
		// against behaviour the product does not perform — so the guard must see
		// it. A test that calls Invalidate is exercising the unit, and forbidding
		// that would only push the test into a shape that proves less.
		//
		// What this guard protects is PRODUCTION REACHABILITY: the bounds on a
		// forced mint live in the loop, and a test calling it directly is not a
		// path a hostile target can reach.
		if strings.HasSuffix(slash, "_test.go") {
			return nil
		}

		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(b), ".Invalidate(") {
			offenders = append(offenders, slash)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("%d file(s) force a credential re-resolve outside the re-establishment "+
			"loop: %v\n\n"+
			"A forced mint is an amplification primitive a hostile target can trigger by "+
			"returning 401 (D204). It is bounded per command by `reestablish_attempts`, "+
			"per hour by `rate_per_hr`, and quarantined by `credential_churn` — and every "+
			"one of those bounds lives in `gateway.Enforce`'s loop. A caller outside it "+
			"has none of them.", len(offenders), offenders)
	}
}
