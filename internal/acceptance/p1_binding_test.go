package acceptance

import (
	"context"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// P1 steps 50-52: the three credential-binding classes (§4.7.4, D101).
//
// ASSERTED BEHAVIOURALLY, through the real driver and the real pool, rather
// than by inspecting a client. The three classes differ in ONE observable way —
// what happens to an in-flight-capable driver when its credential is wiped —
// and that difference is exactly why revocation is cancel-plus-teardown rather
// than a memory write. An accessor like `HoldsCredential()` would have made the
// same point with a method no production code calls, which is the defect this
// project keeps finding.

// bindingDriver returns a driver borrowing from its own pool, plus a target of
// the requested class.

// idemFor builds the idempotency a kata action declares, for the few steps that
// call a Driver DIRECTLY rather than through the gateway (D163).
//
// DERIVED FROM Actions(), not written out here, for the reason the driver's own
// test helper is: a class change on an action must not need every call site
// edited, and a fixture asserting a placement the driver no longer uses is
// exactly the silent drift D155 describes.
func idemFor(action string) connector.Idempotency {
	for _, spec := range kata.New().Actions() {
		if spec.Name == action {
			return connector.Idempotency{
				Class:     spec.Idempotency,
				Placement: spec.IdempotencyPlacement,
				Key:       "ik-acceptance",
			}
		}
	}
	return connector.Idempotency{}
}

func bindingDriver(t *testing.T, class, ref, tenant string) (*kata.Driver, connector.Target, context.Context) {
	t.Helper()

	settings := map[string]string{}
	if class != "" {
		settings[kata.BindingKey] = class
	}
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: ref, Kind: "kata", Tenant: tenant, Residency: "eu",
		CredentialVersion: "v#1",
		Credential:        connector.Secret([]byte("binding-token")),
		Settings:          settings,
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	d := kata.New(kata.WithPool(pool.New(kataBuild(), quietLogger())))
	return d, tgt, connector.WithTenant(context.Background(), tenant)
}

func mustExecute(t *testing.T, d *kata.Driver, ctx context.Context, tgt connector.Target) error {
	t.Helper()
	_, err := d.Execute(ctx, tgt, "kata.create_issue", map[string]any{"project": "PROJ"}, idemFor("kata.create_issue"))
	return err
}

// step50Class1IsCredentialFree — the pooled client never held the credential,
// so auth must ride on every request.
//
// §4.7.1 claimed rotation is "instant, because the connection never held the
// token". §4.7.4 corrected that for classes 2 and 3. D132 extends the
// correction to class 1 itself: the CLIENT is genuinely credential-free, and
// Sekizui rebuilds it on rotation ANYWAY, because `PoolKey` carries `credVer`
// for every class without exception — §6 opens by saying every cross-tenant
// leak is a cache key missing a dimension, and a key that drops one for a
// single class is a rule with an exception.
//
// So the property asserted is the one that is actually true and actually
// matters: no credential is bound to the client, which is precisely why
// revocation for class 1 has to CANCEL rather than tear the client down.
func step50Class1IsCredentialFree(t *testing.T) {
	d, tgt, ctx := bindingDriver(t, "", "kata:alpha", "alpha")

	if err := mustExecute(t, d, ctx, tgt); err != nil {
		t.Fatalf("class 1 call: %v", err)
	}

	// Wipe. The client is untouched — but every subsequent call borrows, and
	// the borrow is refused.
	tgt.WipeCredential()

	err := mustExecute(t, d, ctx, tgt)
	if err == nil {
		t.Fatal("a class 1 call SUCCEEDED after its credential was wiped. Auth is " +
			"supposed to ride on each request, so a wiped credential must stop the " +
			"next one — if it does not, the driver cached the material somewhere and " +
			"is not class 1 at all")
	}
	if !fault.KindOf(err).Deliberate() {
		t.Errorf("the refusal was kind %v, classified as a FAILURE. A wiped credential "+
			"is Sekizui refusing on purpose, not a target being down (D125)",
			fault.KindOf(err))
	}
}

// step51Class2NeedsEviction — the client was CONSTRUCTED with the credential,
// so wiping ours does not stop it.
//
// THIS IS THE ASSERTION THAT JUSTIFIES D106. That decision rejects memory-
// wiping as a revocation mechanism partly because "its blast radius is
// selective by accident... a class 2 driver whose SDK client was constructed
// WITH the credential is entirely unaffected. A nuclear option that silently
// spares the BigQuery client is not one." This is that claim, executed: the
// wipe lands, and the class 2 driver carries on regardless.
func step51Class2NeedsEviction(t *testing.T) {
	d, tgt, ctx := bindingDriver(t, kata.Class2, "kata:sdk", "sdk")

	if err := mustExecute(t, d, ctx, tgt); err != nil {
		t.Fatalf("class 2 call: %v", err)
	}

	tgt.WipeCredential()

	if err := mustExecute(t, d, ctx, tgt); err != nil {
		t.Errorf("a class 2 call FAILED after the credential was wiped: %v. That would "+
			"make memory-wiping a working revocation for this class — and D106's "+
			"central argument, that it silently spares the SDK client, would be "+
			"wrong. It is not wrong; the SDK holds its own copy", err)
	}

	// Which is why eviction is the mechanism. A rotated credential produces a
	// new PoolKey, the old entry is superseded, and the client holding the old
	// material is torn down rather than left to serve.
	rotated, err := connector.NewTarget(connector.TargetParams{
		Ref: "kata:sdk", Kind: "kata", Tenant: "sdk", Residency: "eu",
		CredentialVersion: "v#2",
		Credential:        connector.Secret([]byte("rotated-token")),
		Settings:          map[string]string{kata.BindingKey: kata.Class2},
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	if err := mustExecute(t, d, ctx, rotated); err != nil {
		t.Fatalf("class 2 call after rotation: %v", err)
	}
}

// step52Class3IsTornDown — a session is CLOSED, not dropped, and it is proven
// by observing the close through the real enforcement path.
func step52Class3IsTornDown(t *testing.T) {
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	if r.localOnly(t, "it observes the pooled session belonging to this process") {
		return
	}

	// A REAL COMMAND over mTLS, so the pooled session is one production put
	// there rather than one this test constructed.
	resp, err := r.as(t, "agent:binding").Execute(context.Background(),
		execute("kata.create_issue", "kata:session", map[string]any{"project": "PROJ"}))
	if err != nil {
		t.Fatalf("class 3 command: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("class 3 command: status %v: %s", got, resp.GetResult().GetReason())
	}

	if r.pool.Len() == 0 {
		t.Fatal("no pooled entry after a command against a class 3 target. The driver " +
			"is not borrowing from the pool, so break-glass cannot reach it and every " +
			"assertion below would be vacuous")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, _ := r.pool.Revoke(ctx, "kata:session", "test")

	if w.Evicted != 1 {
		t.Errorf("evicted = %d, want 1", w.Evicted)
	}
	if w.TornDown != 1 {
		t.Errorf("torn_down = %d, want 1. Dropping a pooled BigQuery client costs "+
			"nothing; dropping an MCP session leaves server-side state and possibly a "+
			"live authorised session (§4.7.4 class 3), so teardown is an explicit "+
			"close rather than garbage collection", w.TornDown)
	}

	// Non-vacuity: a class 1 target in the same pool must NOT report a teardown,
	// or "torn_down" is just a synonym for "evicted".
	if _, err := r.as(t, "agent:binding").Execute(context.Background(),
		execute("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"})); err != nil {
		t.Fatalf("class 1 command: %v", err)
	}
	w1, _ := r.pool.Revoke(ctx, "kata:alpha", "test")
	if w1.Evicted != 1 {
		t.Fatalf("class 1 evicted = %d, want 1", w1.Evicted)
	}
	if w1.TornDown != 0 {
		t.Errorf("a class 1 client reported torn_down = %d. Only class 3 implements "+
			"Close; if every class reports a teardown then the field says nothing and "+
			"the distinction §4.7.4 draws is invisible in the audit log", w1.TornDown)
	}

	// **AND NOW THE AUDIT LOG, WHICH THIS STEP TALKED ABOUT AND NEVER READ.**
	//
	// Every assertion above is on `pool.Revoke`'s RETURN VALUE, and the sentence
	// they end on is about the audit log — so the claim that §4.7.4's
	// distinction is visible to a reviewer was made at the wrong altitude.
	// **The population census (D164) found it: `revocation.torn_down` is
	// populated by `gateway.withdraw` and no record in the corpus carried it**,
	// because this step reaches the pool directly and no step revoked a
	// session-oriented target through the governed verb.
	//
	// A FRESH RUN, because the revocations above have already withdrawn both
	// targets and a withdrawn target refuses the command that would re-pool it
	// (D133) — which is the mechanism working, not an obstacle to route around.
	t.Run("the teardown count reaches an audit record, not only the pool", func(t *testing.T) {
		r := newRun(t)
		if r.sink != nil {
			defer r.sink.Close(context.Background())
		}
		if r.localOnly(t, "it reads this process's audit log") {
			return
		}
		ctx := context.Background()

		// POOL A CLASS 3 CLIENT, the way production does.
		if _, err := r.as(t, "agent:binding").Execute(ctx,
			execute("kata.create_issue", "kata:session",
				map[string]any{"project": "PROJ"})); err != nil {
			t.Fatalf("class 3 command: %v", err)
		}

		// REVOKE IT THROUGH THE GOVERNED VERB, over mTLS, as an operator.
		resp, err := r.as(t, "operator:oncall").Execute(ctx,
			execute(verb.RevokeCredential, "kata:session", nil))
		if err != nil {
			t.Fatalf("revoke_credential over the wire: %v", err)
		}
		id := resp.GetResult().GetDecisionId()

		var rec *sekizuiv1.Decision
		for _, d := range readLog(t, r.path) {
			if d.GetId() == id {
				rec = d
			}
		}
		if rec == nil {
			t.Fatalf("no audit record for decision %q", id)
		}
		if got := rec.GetRevocation().GetTornDown(); got != 1 {
			t.Errorf("the record reports torn_down = %d, want 1. A reviewer asking whether "+
				"a session was CLOSED or merely dropped can only read the row, and until "+
				"this arm existed no row in the corpus carried the answer", got)
		}
	})
}
