package acceptance

import (
	"context"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// step30ADeclaredButUnimplementedClassRefuses proves D163 and D186.
//
// **THE STEP AS DECLARED ASKED FOR AN INIT-LEDGER ENTRY, AND IT IS THE WRONG
// INSTRUMENT.** Recording the amendment rather than quietly substituting a
// mechanism, which is what P1 step 34 did when its declaration turned out to
// duplicate step 21 — the declaration is a commitment to a PROPERTY, and D154's
// failure is a step rewritten to pass rather than to prove.
//
// The property is right: a class declared and not implemented must be REPORTED
// so the gap rots loudly rather than quietly (CONTRACTS 48). The ledger cannot
// carry it, for two reasons that only appear once you try:
//
//   - **A ledger entry must name the phase that retires it**, and `conditional`
//     has no phase, because no connector needs ETag/If-Match. An entry claiming
//     one would use the exact hole
//     TestLedgerEntriesInLivePhasesNameTheirSteps documents in its own comment
//     ("an entry could dodge the check by claiming a later phase").
//   - **The ledger's expiry keys on STEPS BUILT, not on the thing existing.**
//     `ProvenBy: [30]` would make building THIS STEP retire the entry — and
//     building a step that proves the class refuses does not implement the
//     class. The guard would demand deletion of an entry that is still true.
//
// So the disclosure is a boot WARNING (D186), and the expiry already exists and
// is stronger than a ledger entry: step 6 ranges the vocabulary and FAILS the
// moment an implemented class has no driven case. `conditional` becoming real
// therefore breaks the run until it is exercised, which is what a ledger entry
// was being asked to approximate.
//
// Also: a ledger entry would make /readyz report DEGRADED because a taxonomy
// member is unfleshed, and the service is fully able to serve. That is D77's
// crying-wolf failure aimed at the readiness signal.
func step30ADeclaredButUnimplementedClassRefuses(t *testing.T) {
	unimplemented := connector.UnimplementedClasses()
	if len(unimplemented) == 0 {
		t.Skip("every class in the vocabulary is implemented, so there is no gap to " +
			"disclose. Skipping LOUDLY rather than passing: if a class is added " +
			"unimplemented later, this starts asserting again")
	}

	// --- 30a: THE LOAD REFUSES, AND SAYS WHAT TO DO ------------------------
	//
	// Step 5e already proves the refusal HAPPENS, ranging the vocabulary. What
	// it does not check is the message, and the message is the whole difference
	// between a refusal an author can act on and one that reads as a typo. An
	// author who picked a class out of the blueprint needs to be told the member
	// is REAL and this build cannot honour it.
	for _, class := range unimplemented {
		t.Run("load refusal names "+string(class), func(t *testing.T) {
			spec := connector.ActionSpec{Name: "probe.act", Mutating: true, Idempotency: class}
			if class.NeedsPlacement() {
				spec.IdempotencyPlacement = "Idempotency-Key"
			}

			problems := strings.Join(connector.ValidateActions("probe", []connector.ActionSpec{spec}), "\n")
			if problems == "" {
				t.Fatalf("class %q is not implemented and loaded cleanly", class)
			}

			// CASE-INSENSITIVE, because the message SHOUTS "NOT IMPLEMENTED" and
			// an assertion pinned to casing is a test about prose style. What
			// matters is that the words are there.
			lower := strings.ToLower(problems)
			for what, want := range map[string]string{
				"the class":                  strings.ToLower(string(class)),
				"why it exists":              strings.ToLower(class.Explain()),
				"that it is not implemented": "not implemented",
			} {
				if !strings.Contains(lower, want) {
					t.Errorf("the refusal does not name %s (%q):\n%s", what, want, problems)
				}
			}

			// AND WHAT TO DO INSTEAD. An author told only "not implemented" has to
			// go reading source to find out what IS available; told the
			// implemented set, they fix it in one edit. Derived from the
			// vocabulary, so a class becoming implemented appears here without
			// anybody editing a message (§15q).
			for _, usable := range connector.IdempotencyClasses() {
				if !usable.Implemented() {
					continue
				}
				if !strings.Contains(lower, strings.ToLower(string(usable))) {
					t.Errorf("the refusal does not offer %q, which IS implemented. A "+
						"refusal naming no alternative sends an author to the source",
						usable)
				}
			}
		})
	}

	// --- 30b: A DRIVER SELECTING IT REFUSES THE CALL TOO -------------------
	//
	// DEFENCE IN DEPTH, and not redundant: the load refusal protects a
	// configuration reviewed at boot, and D46's vetted MCP spec will let a class
	// arrive from CONFIGURATION rather than from a driver's compiled ActionSpec.
	// A path that reaches Execute with an unimplemented class must refuse there
	// rather than treat it as "no placement needed", which is what the class
	// predicates would say if nobody asked.
	for _, class := range unimplemented {
		idem := connector.Idempotency{Class: class, Placement: "Idempotency-Key", Key: "k-30"}
		_, _, err := idem.PlaceIn("probe", true, map[string]any{"project": "PROJ"})
		if err == nil {
			t.Errorf("class %q placed a key at call time despite not being implemented. "+
				"A class that cannot be honoured must refuse rather than sending the "+
				"call without its guarantee (D53)", class)
			continue
		}
		if got := fault.KindOf(err); got != fault.KindConfig {
			t.Errorf("class %q refused with kind %v, want config — it is a declaration "+
				"the deployment cannot honour, not a bad request from the caller", class, got)
		}
	}

	// --- 30c: AND THE REFERENCE DRIVER CANNOT DECLARE ONE ------------------
	//
	// The arm that stops the vocabulary and the blueprint's own example drifting
	// apart. The kata declares four classes deliberately, so that the ones
	// Fullstory does not exercise are still driven through the real enforcement
	// path — and it must never declare the one that refuses, or step 6's
	// coverage map and this step would contradict each other.
	notImplemented := map[connector.IdempotencyClass]bool{}
	for _, c := range unimplemented {
		notImplemented[c] = true
	}
	for _, spec := range kata.New().Actions() {
		if notImplemented[spec.Idempotency] {
			t.Errorf("the reference driver's %q declares class %q, which this build "+
				"cannot honour — so the blueprint's own example would refuse at load",
				spec.Name, spec.Idempotency)
		}
	}

	t.Logf("D186: %v declared and not implemented; refused at load, refused at call, "+
		"absent from the reference driver, and disclosed at boot", unimplemented)
}

// step31APlacementThatCannotBeSatisfiedRefusesTheCall proves D163 and D186.
//
// **FAIL-CLOSED, AND THE POSITIVE FORM OF STEP 6 CANNOT EXPRESS IT.** Step 6
// proves the key lands where the class declares, which is the guarantee working.
// This is the guarantee being unable to work: if the key cannot be placed, or
// does not survive to the wire, the call must be REFUSED rather than sent
// unkeyed. Sending it produces exactly the condition D163 exists to prevent
// while every log line reports a successful idempotent write — the shape
// §4.7.10 keeps warning about, where the operator watches the guarantee appear
// to work.
//
// **WRITING IT MOVED PLACEMENT OUT OF THE DRIVER AND FOUND A DEFECT (D186).**
// `kata.placeKey` owned placement and wrote the key OVER whatever sat at the
// configured body path, so a caller supplying a field of that name had its value
// silently replaced: the upstream acted on a request the agent did not make, and
// the audit record echoed ours rather than theirs. A driver-local copy is also
// how the second driver gets it subtly different, which is CONTRACTS 63's shape.
func step31APlacementThatCannotBeSatisfiedRefusesTheCall(t *testing.T) {
	ctx := connector.WithTenant(context.Background(), "alpha")
	tgt := katatarget(t)

	specs := map[string]connector.ActionSpec{}
	for _, spec := range kata.New().Actions() {
		specs[spec.Name] = spec
	}
	idemFor := func(action, key string) connector.Idempotency {
		spec := specs[action]
		return connector.Idempotency{
			Class: spec.Idempotency, Placement: spec.IdempotencyPlacement, Key: key,
		}
	}

	// --- 31a: A STRIPPED HEADER REFUSES ------------------------------------
	//
	// The case that needs a seam to exist at all: an HTTP middleware removing a
	// header, a proxy rewriting one, a marshaller dropping an unknown body field.
	// None can be provoked from outside a driver, and all three produce an
	// unkeyed request reported as keyed.
	t.Run("a key that does not survive to the wire refuses the call", func(t *testing.T) {
		_, err := kata.New().Execute(ctx, tgt, "kata.create_issue",
			map[string]any{"project": "PROJ", kata.StripKeyPlacement: "yes"},
			idemFor("kata.create_issue", "ik-31"))

		if err == nil {
			t.Fatal("the call was SENT with its idempotency key removed. Every log line " +
				"would report an idempotent write, and a retry would double-write — the " +
				"exact condition D163 exists to prevent, dressed as success")
		}
		if !strings.Contains(err.Error(), "outbound call") {
			t.Errorf("the refusal does not say the key was missing FROM THE OUTBOUND "+
				"CALL: %v. An operator told only 'idempotency error' cannot tell a "+
				"misconfiguration from a middleware eating a header", err)
		}
	})

	// --- 31b: A COLLIDING BODY PATH REFUSES --------------------------------
	//
	// "A class whose configuration names a field the payload has no room for",
	// and the arm that found the overwrite. Overwriting is the one resolution
	// that lies: the request differs from the one the caller made, and nothing
	// says so.
	t.Run("a body placement colliding with a caller's field refuses", func(t *testing.T) {
		const action = "kata.comment"
		placement := specs[action].IdempotencyPlacement
		if placement == "" {
			t.Fatalf("%s declares no placement, so this arm has nothing to collide with", action)
		}

		_, err := kata.New().Execute(ctx, tgt, action,
			map[string]any{"project": "PROJ", placement: "the caller's own value"},
			idemFor(action, "ik-31b"))

		if err == nil {
			t.Fatalf("a caller's %q was silently OVERWRITTEN by the idempotency key. The "+
				"upstream then acts on a request the agent did not make, and the record "+
				"echoes ours rather than theirs", placement)
		}
		if got := fault.KindOf(err); got != fault.KindInvalidArgument {
			t.Errorf("the collision refused with kind %v, want invalid_argument — the "+
				"caller can fix this by renaming a field, which is a request to correct "+
				"rather than a deployment problem", got)
		}
	})

	// --- 31c: NON-VACUITY — THE SAME CALLS SUCCEED WITHOUT THE OBSTRUCTION -
	//
	// Without this the step passes against a driver that refuses every mutating
	// call, and fail-closed would be indistinguishable from broken. Both arms
	// above are re-run with only the obstruction removed.
	t.Run("the same calls succeed once the obstruction is gone", func(t *testing.T) {
		res, err := kata.New().Execute(ctx, tgt, "kata.create_issue",
			map[string]any{"project": "PROJ"}, idemFor("kata.create_issue", "ik-31"))
		if err != nil {
			t.Fatalf("a `header` class call with nothing stripped was refused: %v", err)
		}
		headers, _ := res.Data["echo_headers"].(map[string]any)
		if got, _ := headers[specs["kata.create_issue"].IdempotencyPlacement].(string); got != "ik-31" {
			t.Errorf("header %q = %q, want ik-31 — 31a proves nothing if the key never "+
				"lands in the unobstructed case",
				specs["kata.create_issue"].IdempotencyPlacement, got)
		}

		if _, err := kata.New().Execute(ctx, tgt, "kata.comment",
			map[string]any{"project": "PROJ"}, idemFor("kata.comment", "ik-31b")); err != nil {
			t.Fatalf("a `field` class call with no collision was refused: %v", err)
		}
	})

	// --- 31d: AND A CLASS NEEDING NO PLACEMENT IS UNAFFECTED ---------------
	//
	// The guard must not become a blanket. `natural` places nothing and `none`
	// has nowhere to place anything, so Verify has nothing to check — and a
	// fail-closed check that refused them would break the two classes P2's real
	// connector actually uses.
	t.Run("a class needing no placement is not caught by the check", func(t *testing.T) {
		for _, action := range []string{"kata.upsert_record", "kata.append_event"} {
			if _, err := kata.New().Execute(ctx, tgt, action,
				map[string]any{"project": "PROJ", kata.StripKeyPlacement: "yes"},
				idemFor(action, "ik-31d")); err != nil {
				t.Errorf("%s (class %q) was refused by the placement check: %v. It places "+
					"no key, so there is nothing for a stripping transport to remove",
					action, specs[action].Idempotency, err)
			}
		}
	})
}
