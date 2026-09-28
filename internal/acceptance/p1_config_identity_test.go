package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step65ConfigIdentityIsOnEveryRecord proves D149.
//
// The step exists because §4.9a.2 and pkg/config/file.go both stated that
// "Document.Version is recorded on decisions, so an audit row names the spec
// version that authorised the call" — and nothing recorded it anywhere. It was
// logged once at boot and never reached a record. That is the codebase's
// recurring class in the shape CONTRACTS item 23 says is still unguarded: a
// proto field nobody populates, where the log looks complete because the field
// is simply absent rather than wrong.
//
// It also proves the field that replaced it is the right one. Version could not
// have kept the promise: it defaults to `<file>@<mtime>`, so the same config
// deployed twice differs and `touch -r` makes two different configs agree.
func step65ConfigIdentityIsOnEveryRecord(t *testing.T) {
	base := loadAcceptanceDoc(t)

	baseID, err := base.Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if baseID == "" {
		t.Fatal("identity is empty; a hash nobody computed cannot name a configuration")
	}

	// --- 65a: PROVENANCE DOES NOT MOVE IT ---------------------------------
	//
	// The direction that makes attestation possible at all (D148): two replicas
	// serving byte-identical policy must agree. Version differs on every replica
	// because mtime does, so feeding it into the hash would report permanent
	// divergence between instances enforcing exactly the same thing.
	moved := *base
	moved.Version = "somewhere-else.yaml@1799999999"
	movedID, err := moved.Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if movedID != baseID {
		t.Errorf("identity changed with Version alone:\n  %s\n  %s\n"+
			"Version is provenance — the same document from a second file, or the same "+
			"file with a fresh mtime, is the same configuration. An identity that "+
			"disagrees would make two replicas serving identical policy attest as "+
			"divergent forever", baseID, movedID)
	}

	// --- 65b: THE TEXT DOES NOT MOVE IT -----------------------------------
	//
	// Reformatting YAML changes nothing an agent can observe. An identity that
	// flags it is one operators learn to ignore, and an ignored integrity signal
	// is D77's crying-wolf failure with a different trigger.
	//
	// The two documents below differ in comments, indentation, key order, quoting
	// and file NAME — every textual axis at once — and agree on every field the
	// engine compiles.
	plain := docFromYAML(t, "plain.yaml", `
stages: [observed, judged]
grants:
  - principal: agent:triage
    allow:
      - action: kata.create_issue
        target: kata:alpha
        rate_per_hr: 60
`)
	fussy := docFromYAML(t, "fussy-but-identical.yaml", `
# Reviewed 2026-08-30. The comment below is the kind of thing that must not
# change what an audit row says authorised a call.
grants:
    -   allow:
            -   rate_per_hr: 60
                target: "kata:alpha"
                action: "kata.create_issue"
        principal: "agent:triage"
stages:
    - "observed"
    - "judged"
`)

	if plain.Version == fussy.Version {
		t.Fatal("the two documents share a Version, so 65b would pass without " +
			"proving the identity ignores provenance")
	}
	if got, want := mustIdentity(t, fussy), mustIdentity(t, plain); got != want {
		t.Errorf("identity changed under reformatting alone:\n  %s\n  %s\n"+
			"comments, key order, quoting and indentation are gone before the hash "+
			"runs — the document is already parsed. Hashing file bytes would have "+
			"made every whitespace edit look like a policy change", want, got)
	}

	// --- 65c: SUBSTANCE DOES MOVE IT --------------------------------------
	//
	// Non-vacuity. Everything above is satisfied by a constant.
	if len(base.Grants) == 0 {
		t.Fatal("the acceptance document has no grants, so 65c cannot prove the " +
			"identity responds to substance at all")
	}
	changed := *base
	changed.Grants = append([]config.GrantSpec(nil), base.Grants...)
	changed.Grants[0].Principal = changed.Grants[0].Principal + "-someone-else"
	changedID, err := changed.Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if changedID == baseID {
		t.Error("identity did not change when a grant's PRINCIPAL changed. An identity " +
			"insensitive to who may act is not an identity of the policy")
	}

	// --- 65d: ORDER MOVES IT, DELIBERATELY --------------------------------
	//
	// The one normalisation deliberately NOT applied. Reordering a principal's
	// grants looks cosmetic and is not: `Decision.matched_rule` reads
	// `agent:triage#allow[0]`, an INDEX, so two documents differing only in
	// order do not explain their own audit records identically. Calling them
	// the same configuration would be false in the one place it matters.
	if len(base.Grants) > 1 {
		reordered := *base
		reordered.Grants = append([]config.GrantSpec(nil), base.Grants...)
		reordered.Grants[0], reordered.Grants[1] = reordered.Grants[1], reordered.Grants[0]
		reorderedID, err := reordered.Identity()
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		if reorderedID == baseID {
			t.Error("identity survived a grant REORDER. Order is observable in " +
				"matched_rule's index, so this must be a different identity — the " +
				"normalisation stops where the audit record starts caring")
		}
	}

	// --- 65e: IT REACHES A RECORD -----------------------------------------
	//
	// The promise §4.9a.2 made and nothing kept. Everything above is a property
	// of a function no production path called until this arm passes.
	//
	// Asserted against the DOCUMENT's identity, not merely against "non-empty":
	// a non-empty check is satisfied by any placeholder a wiring site happens to
	// pass, which is the same shape as the `!= STATUS_OK` assertion D138 found
	// being satisfied by the absence of an answer.
	srv, sink, path := multiResidencyInstance(t, acceptanceResidency)
	ctx := context.Background()

	for _, who := range []string{"agent:triage", "agent:global"} {
		args, err := structpb.NewStruct(map[string]any{"project": "PROJ"})
		if err != nil {
			t.Fatalf("args: %v", err)
		}
		// Both an allowed and a refused command, so the assertion covers the
		// terminal-refusal row as well as the intent/outcome pair. A refusal is
		// §5.4's highest-value record and the one an incident reads first.
		res, err := srv.Enforce(ctx, assertedIdentity(who), &sekizuiv1.Command{
			Action: "kata.create_issue", TargetRef: "kata:alpha", Args: args,
			IdempotencyKey: "acc-65-" + who,
		})
		if err != nil {
			t.Fatalf("%s: refused as a transport error: %v", who, err)
		}
		// ASSERTED, because it went vacuous once without failing: under D326's
		// flip this instance kept an `eu` ceiling, both commands were refused
		// by residency, and the step still passed (found by comparing records).
		requireAllowedThenRefused(t, "65e", who, res)
	}

	if err := sink.Stop(ctx); err != nil {
		t.Fatalf("stopping sink: %v", err)
	}
	records := readLog(t, path)
	if len(records) == 0 {
		t.Fatal("no decision records were written, so 65e proves nothing")
	}

	// THE WHOLE LOG, not only this step's rows. Under `make acceptance` the sink
	// is shared and cumulative (D107), so this arm asserts the property across
	// every step's records — an unstamped exit path anywhere in the run is
	// caught here rather than only where step 65 happens to look.
	var missing int
	for _, rec := range records {
		if rec.GetConfigIdentity() == "" {
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("%d of %d decision records carry no config_identity. This is exactly "+
			"the state §4.9a.2 described as already working: the field is ABSENT "+
			"rather than wrong, so the log reads as complete", missing, len(records))
	}

	// THIS STEP'S OWN ROWS, identified by the idempotency keys it issued. The
	// value must be the document's real identity and not merely non-empty: a
	// non-empty check is satisfied by any placeholder a wiring site passes,
	// which is the assertion shape D138 caught being satisfied by the absence
	// of an answer. It caught one here too — the acceptance run stamped
	// "test-config" on 117 records, so the graduation evidence named a
	// configuration that does not exist.
	var mine, wrong int
	for _, rec := range records {
		if !strings.HasPrefix(rec.GetIdempotencyKey(), "acc-65-") {
			continue
		}
		mine++
		if rec.GetConfigIdentity() != baseID {
			wrong++
		}
	}
	if mine == 0 {
		t.Fatal("none of this step's own commands are in the log, so the arm that " +
			"checks the VALUE rather than its presence did not run")
	}
	if wrong > 0 {
		t.Errorf("%d of %d records from this step name a configuration the instance is "+
			"not enforcing (want %s)", wrong, mine, baseID)
	}

	assertOneIdentityAcrossRecords(t, records)
}

// assertOneIdentityAcrossRecords is the property that makes the field usable.
//
// A per-row value that varied within one process would mean the field named
// something other than the configuration in force — and a reader correlating an
// incident to a policy would draw the wrong conclusion from a log that looked
// fine.
func assertOneIdentityAcrossRecords(t *testing.T, records []*sekizuiv1.Decision) {
	t.Helper()

	seen := map[string]int{}
	for _, rec := range records {
		seen[rec.GetConfigIdentity()]++
	}
	if len(seen) > 1 {
		got := make([]string, 0, len(seen))
		for id := range seen {
			got = append(got, id)
		}
		sort.Strings(got)
		t.Errorf("records carry %d different config identities in one run: %v.\n"+
			"Every acceptance instance compiles the SAME acceptance.yaml, so they must "+
			"agree. More than one value means either a Decision is being built with the "+
			"field set outside the recorder's funnel, or an instance was wired with a "+
			"PLACEHOLDER identity — which is how 117 records in the graduation evidence "+
			"came to name a configuration that does not exist", len(seen), strings.Join(got, ", "))
	}
}

// mustIdentity computes a document's identity or fails the test.
//
// Used by the instance builders so an acceptance run stamps the REAL identity of
// the document it is enforcing rather than a placeholder. A placeholder would
// let step 65e pass while proving only that a string reaches a field — which is
// the shape of the assertion D138 caught being satisfied by an absent answer.
func mustIdentity(t *testing.T, doc *config.Document) string {
	t.Helper()
	id, err := doc.Identity()
	if err != nil {
		t.Fatalf("config identity: %v", err)
	}
	return id
}

// docFromYAML writes src to a temp file and loads it the way a deployment would.
//
// THROUGH FileSource rather than yaml.Unmarshal directly, so the Version default
// (`<file>@<mtime>`) is populated exactly as it is in production — which is the
// field 65a and 65b need to differ while the identity does not.
func docFromYAML(t *testing.T, name, src string) *config.Document {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	doc, err := config.NewFileSource(path).Load(context.Background())
	if err != nil {
		t.Fatalf("loading %s: %v", name, err)
	}
	return doc
}

// step66BootRefusesAConfigurationTheDeploymentDidNotShip proves D150.
//
// D148's first form had a replica compare its identity against what its PEERS
// reported and withdraw itself on divergence. The maintainer asked whether an attacker
// could forge that and take the fleet down; the answer was yes, and the flaw was
// that self-adjudication moved the AUTHORITY inside the replica while leaving
// the EVIDENCE outside it. Forge a peer majority and every honest replica
// removes itself — the outage refusing peer enforcement was meant to prevent.
//
// The authority is the DEPLOYER. The pipeline that shipped a configuration knows
// what it shipped, and an attacker who can set the flag already owns the
// deployment — outside the trust boundary in the same way the credential-source
// killswitch is (§4.7.10). No peer is consulted for this at all.
func step66BootRefusesAConfigurationTheDeploymentDidNotShip(t *testing.T) {
	doc := loadAcceptanceDoc(t)
	shipped := mustIdentity(t, doc)

	// --- 66a: THE MATCH, AND THE DEFAULT THAT CANNOT CAUSE AN OUTAGE -------
	t.Run("the configuration the deployment shipped is accepted", func(t *testing.T) {
		if err := config.CheckExpectedIdentity(shipped, shipped); err != nil {
			t.Errorf("the shipped configuration was refused: %v. If a match is refused "+
				"the flag is a fleet-wide outage rather than a guard", err)
		}
	})

	t.Run("hex case is not a mismatch", func(t *testing.T) {
		if err := config.CheckExpectedIdentity(strings.ToUpper(shipped), shipped); err != nil {
			t.Errorf("an upper-cased hash was refused: %v. An operator who copied a hash "+
				"out of a terminal has not named a different configuration, and a guard "+
				"that fails on presentation is one that gets switched off", err)
		}
	})

	t.Run("an unset expectation does not refuse", func(t *testing.T) {
		// THE LOAD-BEARING DEFAULT (D150). The check is opt-in because the
		// direction that cannot cause an outage has to be the one you get by
		// doing nothing — a guard refusing when nobody configured it turns an
		// unset flag into a fleet-wide failure, which is the shape of attack
		// this whole decision exists to avoid.
		if err := config.CheckExpectedIdentity("", shipped); err != nil {
			t.Errorf("an empty -expect-config refused the boot: %v", err)
		}
	})

	// --- 66b: THE MISMATCH, NAMING BOTH SIDES ------------------------------
	t.Run("a configuration the deployment did not ship is refused", func(t *testing.T) {
		other := strings.Repeat("0", len(shipped))

		err := config.CheckExpectedIdentity(other, shipped)
		if err == nil {
			t.Fatal("a configuration that is not the one shipped was accepted; the guard " +
				"is inert and the deployment enforces a policy nobody reviewed")
		}
		if got := fault.KindOf(err); got != fault.KindConfig {
			t.Errorf("kind = %v, want %v — a mismatch is a deployment to investigate",
				got, fault.KindConfig)
		}
		// BOTH SIDES NAMED. An operator holding one hash and told only that it
		// is wrong cannot tell a stale deploy from a tampered file, which are
		// the two cases and want opposite responses.
		if !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), shipped) {
			t.Errorf("the refusal does not name both the expected and the loaded "+
				"identity: %v", err)
		}
	})

	// --- 66c: A BROKEN FLAG IS A DIFFERENT PROBLEM -------------------------
	//
	// The distinction D138 drew between INVALID_ARGUMENT and DENIED. A hash
	// truncated by a copy-paste must not read as a compromised deployment —
	// that is the more alarming of the two answers and the wrong one, and an
	// operator acting on it wastes an incident looking for an attacker.
	for _, bad := range []string{"nonsense", shipped[:16], shipped + "aa", "z" + shipped[1:]} {
		t.Run("a malformed expectation is a flag to correct: "+bad[:min(12, len(bad))], func(t *testing.T) {
			err := config.CheckExpectedIdentity(bad, shipped)
			if err == nil {
				t.Fatalf("a malformed expectation %q was accepted", bad)
			}
			if got := fault.KindOf(err); got != fault.KindInvalidArgument {
				t.Errorf("kind = %v, want %v — %q is a flag to correct, not evidence "+
					"of a deployment that was tampered with", got, fault.KindInvalidArgument, bad)
			}
		})
	}

	// --- 66d: NON-VACUITY OF THE WHOLE MECHANISM ---------------------------
	//
	// Everything above is satisfied by a checker that answers from the string
	// alone. This is the arm that ties it to the document: a REAL edit to the
	// policy must make a previously-good expectation fail.
	t.Run("editing the policy makes the shipped hash stop matching", func(t *testing.T) {
		if len(doc.Grants) == 0 {
			t.Fatal("the acceptance document has no grants, so 66d cannot make a real edit")
		}
		edited := *doc
		edited.Grants = append([]config.GrantSpec(nil), doc.Grants...)
		edited.Grants[0].Principal += "-tampered"

		if err := config.CheckExpectedIdentity(shipped, mustIdentity(t, &edited)); err == nil {
			t.Error("a document with a rewritten grant principal still matched the hash " +
				"the deployment shipped. That is the whole attack this guard exists for: " +
				"a policy edited after review, enforced as though it had been reviewed")
		}
	})
}

// requireAllowedThenRefused holds the "both an allowed and a refused command"
// that steps 42b and 65e claim: agent:triage's kata.create_issue on kata:alpha
// is ALLOWED, and agent:global's is refused by POLICY, the grant it lacks.
//
// Both steps once ran on an instance whose ceiling refused both commands, and
// passed: their assertions are about every record, so they held of two
// refusals just as well. A refusal by the wrong stage fails here (D326).
func requireAllowedThenRefused(t *testing.T, step, who string, res *sekizuiv1.CommandResult) {
	t.Helper()
	switch who {
	case "agent:triage":
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Errorf("step %s: agent:triage's command was %v (%s); the step needs it ALLOWED "+
				"so its assertion covers an intent/outcome pair", step, res.GetStatus(), res.GetReason())
		}
	case "agent:global":
		// kind "denied" is policy's (D138); the ceiling's is "residency".
		if res.GetStatus() != sekizuiv1.Status_STATUS_DENIED || res.GetKind() != "denied" {
			t.Errorf("step %s: agent:global's command was %v, kind %q (%s); the step needs it "+
				"refused by POLICY (kind denied) — kind residency means the instance serves the wrong class",
				step, res.GetStatus(), res.GetKind(), res.GetReason())
		}
	}
}
