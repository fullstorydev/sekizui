package acceptance

import (
	"context"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// step6EveryIdempotencyClassHasADrivenCase proves D163 on the wire.
//
// **INVERTED FROM THE FIRST DRAFT, at the maintainer's suggestion, and the inversion is
// the whole value.** The draft drove ONE class and looked for its header. That
// proves one case and goes stale the moment a sixth class exists, which is the
// shape of assertion §15q warns about: a test naming a member passes forever and
// checks nothing about the member somebody adds next year.
//
// This RANGES OVER `connector.IdempotencyClasses()` and FAILS when a declared
// class has no driven case. A new class then arrives with its proof rather than
// with somebody remembering to extend a test — the same structural obligation
// `TestEveryProviderRunsTheConformanceSuite` places on a provider.
//
// **ASSERTED ON THE OUTBOUND CALL, NOT ON SEKIZUI'S REPORT OF IT.** Asking the
// gateway which key it used would compare a value with itself, and D159 is the
// standing reminder that a guard whose two inputs share an origin is not a
// guard. The kata echoes its outbound body and headers separately for exactly
// this.
func step6EveryIdempotencyClassHasADrivenCase(t *testing.T) {
	// THE TENANT MUST BE ON THE CONTEXT, and the first version of this step
	// forgot — §6 mechanism 3 refused all four cases with "no tenant on the
	// request; refusing rather than assuming". Worth keeping: the egress
	// assertion fired against a test that had no business reaching a driver, in
	// exactly the position it exists to guard, and it named what was wrong.
	ctx := connector.WithTenant(context.Background(), "alpha")

	// THE DRIVEN CASES, keyed by class. A class absent from this map fails the
	// step rather than being skipped — that is the inversion.
	//
	// Each names a kata action that DECLARES the class, so the mapping is checked
	// against the driver rather than asserted here: if an action's class changes,
	// the lookup below stops matching and this step says so.
	cases := map[connector.IdempotencyClass]string{
		connector.IdempotencyHeader:  "kata.create_issue",
		connector.IdempotencyField:   "kata.comment",
		connector.IdempotencyNatural: "kata.upsert_record",
		connector.IdempotencyNone:    "kata.append_event",
	}

	specs := map[string]connector.ActionSpec{}
	for _, spec := range kata.New().Actions() {
		specs[spec.Name] = spec
	}

	for _, class := range connector.IdempotencyClasses() {
		t.Run(string(class), func(t *testing.T) {
			// --- 6a: EVERY DECLARED CLASS IS EITHER DRIVEN OR UNIMPLEMENTED ---
			action, driven := cases[class]
			if !driven {
				if !class.Implemented() {
					t.Skipf("class %q is declared and not implemented in this build, "+
						"so it has no driven case by design (D163). Step 5 asserts it "+
						"REFUSES at load, which is the guarantee for an unimplemented "+
						"member; this step covers the implemented ones", class)
				}
				t.Fatalf("class %q is implemented and has NO driven case. A class in the "+
					"vocabulary that nothing exercises is a declared contract doing "+
					"nothing — add a kata action declaring it and a case here", class)
			}

			spec, known := specs[action]
			if !known {
				t.Fatalf("case names kata action %q, which the driver does not advertise", action)
			}
			// THE MAPPING IS CHECKED, NOT ASSUMED. If an action's declared class
			// changes, this fires rather than silently testing the wrong class.
			if spec.Idempotency != class {
				t.Fatalf("case for class %q names action %q, which declares %q. The map "+
					"has drifted from the driver", class, action, spec.Idempotency)
			}

			d := kata.New()
			tgt := katatarget(t)
			const key = "ik-step-6"

			res, err := d.Execute(ctx, tgt, action, map[string]any{"project": "PROJ"},
				connector.Idempotency{
					Class: spec.Idempotency, Placement: spec.IdempotencyPlacement, Key: key,
				})
			if err != nil {
				t.Fatalf("executing a %q-class action: %v", class, err)
			}

			body, _ := res.Data["echo_args"].(map[string]any)
			headers, _ := res.Data["echo_headers"].(map[string]any)

			// --- 6b: THE KEY LANDS WHERE THE CLASS DECLARES -------------------
			switch class {
			case connector.IdempotencyHeader:
				if got, _ := headers[spec.IdempotencyPlacement].(string); got != key {
					t.Errorf("header %q = %q, want %q. A `header` class must put the key "+
						"in the named HEADER; putting it in the body would be a different "+
						"request to the upstream and would not deduplicate",
						spec.IdempotencyPlacement, got, key)
				}
				if _, leaked := body[spec.IdempotencyPlacement]; leaked {
					t.Errorf("the key also appears in the BODY at %q. Placement is one "+
						"place, not a best effort", spec.IdempotencyPlacement)
				}

			case connector.IdempotencyField:
				if got, _ := body[spec.IdempotencyPlacement].(string); got != key {
					t.Errorf("body[%q] = %q, want %q. A `field` class carries the key in "+
						"the request payload", spec.IdempotencyPlacement, got, key)
				}
				if len(headers) != 0 {
					t.Errorf("a `field` class set headers %v; the key belongs in the body", headers)
				}

			case connector.IdempotencyNatural:
				// NEEDS NO KEY AT ALL, and must not invent a placement for one.
				// The upsert is repeat-safe by construction, and a key smuggled
				// into the payload would change the request the upstream sees.
				if len(headers) != 0 {
					t.Errorf("a `natural` class set headers %v; it needs no key", headers)
				}
				if _, found := body["ik-step-6"]; found {
					t.Error("a `natural` class wrote a key into the body")
				}

			case connector.IdempotencyNone:
				// The call still SUCCEEDS — `none` is about retrying, not about
				// refusing the first attempt. Step 3 covers the retry refusal.
				if len(headers) != 0 {
					t.Errorf("a `none` class set headers %v; there is nowhere to put a "+
						"key, which is what the class means", headers)
				}
			}
		})
	}
}

// katatarget builds a resolved target for a direct driver call.
func katatarget(t *testing.T) connector.Target {
	t.Helper()
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "kata:alpha", Kind: kata.Kind, Tenant: "alpha", Residency: "eu",
		BaseURL: "https://alpha.invalid", CredentialVersion: "v1",
		Credential: connector.Secret("kata-token"),
	})
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}
	return tgt
}
