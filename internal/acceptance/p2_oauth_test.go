package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/provider/oauth"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// clientCredentialed points the shared MCP target at an `oauth-cc://` reference
// whose client secret chains to a real `file://` on disk.
//
// **THE SECRET IS A FILE RATHER THAN AN ENVIRONMENT VARIABLE, and that is
// D151/D153 rather than convenience.** `env://` declares no version, so the
// default credential policy refuses it off bare metal — and the version is
// exactly what this step is about, since it is what reaches the pool key.
// `file://` is versioned BY CONTENT, which is what lets a token refresh leave
// the version alone.
func clientCredentialed(t *testing.T) func(*config.Document) {
	t.Helper()

	secret := filepath.Join(t.TempDir(), "client-secret")
	// **`printf`, NOT `echo`** — written as `[]byte` with no trailing newline for
	// the reason step 38 exists: `pkg/provider/file` reads the bytes verbatim,
	// and a newline lands inside the header and produces a refusal that looks
	// exactly like a bad key (D199).
	if err := os.WriteFile(secret, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatalf("writing the client secret: %v", err)
	}

	return func(d *config.Document) {
		// **THE HOST COMES OFF THE DOCUMENT, NOT FROM THE CALLER.** The first
		// draft closed over a variable the test assigned from `stack.srv.URL` —
		// which is set AFTER `newMCPStack` returns, while `edit` runs INSIDE it,
		// so the reference was built against an empty host. `BaseURL` already
		// holds the listening address by the time this runs, and one server
		// serves both the vendor and the token endpoint, so this is the same
		// address by construction rather than by coincidence.
		tgt := d.Targets[0]
		tgt.CredentialRef = "oauth-cc://" +
			strings.TrimPrefix(tgt.BaseURL, "https://") + "/token" +
			"?client_id=sekizui&client_secret=file://" + secret
		d.Targets[0] = tgt

		spec := d.MCPSpecs["fixture-mcp"]
		spec.Revision = statefulRevision
		d.MCPSpecs["fixture-mcp"] = spec

		d.Grants = []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "mcp.fixture.search", TargetRef: "fixture-mcp"},
			},
		}}
	}
}

// step37AClientCredentialsTokenReachesAnMCPCall is criterion 17 (D198, D130,
// D131).
//
// **GROUNDWORK SCOPED TO A PROOF — the maintainer: "skeleton it and show we can hit it;
// the API key is the focus."** `pkg/provider/oauth` was built in P1 and is in
// the binary's provider slice already, so almost nothing is added here. What is
// added is evidence, and the evidence is worth more than the machinery: the
// guarantee this step pins has been TRUE BY CONSTRUCTION since P1 and had
// nothing driving it.
//
// **THE ARM WITH TEETH IS 37b AND IT IS ONLY MEASURABLE NOW.** `Version` must
// report the INNER secret's version and never the token's, so a refresh must
// leave the pool key alone. Before step 36 the consequence of getting that
// backwards was "pooled clients are evicted more often than necessary" — real,
// and hard to see. On a stateful revision the consequence is that `initialize`
// re-runs on the token's expiry timer, destroying server-side state for a
// credential that never rotated. That is now COUNTABLE, at the far side, as the
// number of sessions the server minted.
func step37AClientCredentialsTokenReachesAnMCPCall(t *testing.T) {
	ctx := context.Background()

	// --- 37a: THE MINTED TOKEN IS WHAT REACHES THE VENDOR ------------------
	//
	// **ASSERTED AT THE FAR SIDE, and the negative half is the one that matters
	// (D159).** That a Bearer header arrived proves little; what must be true is
	// that it carries the TOKEN and that the CLIENT SECRET never left the
	// process. A chained provider that passed the secret through — which is what
	// `oauth.Resolve` exists to refuse — would still produce a working-looking
	// header on a server that does not check it.
	t.Run("the token minted by the grant is what reaches the vendor", func(t *testing.T) {
		stack := newMCPStack(ctx, t, clientCredentialed(t))
		stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

		res, err := stack.call(ctx, t, "mcp.fixture.search")
		if err != nil {
			t.Fatalf("37a: %v", err)
		}
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("37a: status %v (%s): %s", res.GetStatus(), res.GetKind(), res.GetReason())
		}

		minted, bearers := stack.up.exchanges()
		if minted == 0 {
			t.Fatal("37a: the token endpoint was never called, so whatever reached the " +
				"vendor did not come from the client-credentials grant")
		}
		if len(bearers) == 0 {
			t.Fatal("37a: the vendor side saw no request")
		}
		for i, got := range bearers {
			if !strings.HasPrefix(got, "Bearer tok-") {
				t.Errorf("37a: request %d carried %q, want a minted `tok-` bearer", i, got)
			}
			// **THE CLIENT SECRET MUST NOT BE ANYWHERE IN IT.** Checked against
			// the actual bytes rather than against a field name, which is the
			// only form that survives somebody adding a plausible-looking header
			// later (P1 step 19's habit).
			if strings.Contains(got, "s3cr3t") {
				t.Errorf("37a: request %d carried the CLIENT SECRET to the vendor. The "+
					"grant exists so the long-lived secret stays between us and the "+
					"token endpoint; sending it on is worse than not using the grant, "+
					"because it reaches a party that never needed it", i)
			}
		}
	})

	// --- 37b: A REFRESH DOES NOT EVICT THE POOL ----------------------------
	//
	// **`Version` IS THE INNER SECRET'S, SO THE POOL KEY DOES NOT MOVE (D130).**
	// The cache digests `Resolution.Version` when there is one and the MATERIAL
	// only when there is not, so a provider reporting the token would put a
	// freshly-minted secret into `credVer` on every refresh. Everything derived
	// from the pool key would then churn on the token's clock.
	//
	// **DRIVEN BY A REAL EXPIRY, not by reaching into the cache.** `expires_in:
	// 1` with the cache's own clock is what makes the second command re-resolve,
	// so what is measured is the path a deployment takes at 3am rather than a
	// state a test constructed.
	t.Run("a token refresh does not change the pool key or re-run initialize", func(t *testing.T) {
		// **`WithTTL(0)` MAKES EVERY COMMAND RE-RESOLVE, which is how the refresh
		// is driven without a sleep.** The first draft set `expires_in: -1` on
		// the token endpoint instead, reasoning that an already-expired token
		// would force a re-mint. It does the opposite: `ResolveChained` only
		// sets `Expiry` when `expires_in > 0`, so a non-positive value means NO
		// expiry and the token is cached forever. Five requests then carried one
		// bearer and the arm caught its own premise.
		stack := newMCPStack(ctx, t, clientCredentialed(t),
			func(m *mcpTuning) { m.credOpts = append(m.credOpts, credential.WithTTL(0)) })
		stack.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

		for i := 0; i < 3; i++ {
			res, err := stack.call(ctx, t, "mcp.fixture.search")
			if err != nil {
				t.Fatalf("37b: call %d: %v", i+1, err)
			}
			if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
				t.Fatalf("37b: call %d: status %v (%s): %s",
					i+1, res.GetStatus(), res.GetKind(), res.GetReason())
			}
		}

		minted, bearers := stack.up.exchanges()

		// --- NON-VACUITY FIRST: a refresh really did happen ----------------
		//
		// Without this the arm below passes against a deployment that never
		// refreshed, which is "the pool survived a refresh" and "there was no
		// refresh" reported alike — the failure mode this repository keeps
		// finding in its own tests.
		if minted < 2 {
			t.Fatalf("37b: the token endpoint minted %d token(s) across three calls, so "+
				"no refresh occurred and nothing below is being tested", minted)
		}
		if !distinctBearers(bearers) {
			t.Fatalf("37b: every request carried the same bearer (%v), so the refresh "+
				"did not reach the vendor and the arm below is vacuous", bearers)
		}

		// --- AND THE SESSION SURVIVED IT -----------------------------------
		sessions, initialized, _, _ := stack.up.stats()
		if sessions != 1 {
			t.Errorf("37b: the server minted %d SESSIONS while the token refreshed %d "+
				"times, want 1. The token's version reached the pool key, so every "+
				"refresh evicted the pooled client and re-ran `initialize` — server-side "+
				"state destroyed on a timer, for a credential that never rotated. This "+
				"is the failure §4.7.1's table was drawn to prevent, and before step 36 "+
				"it had no way to show itself", sessions, minted)
		}
		if initialized != 1 {
			t.Errorf("37b: `notifications/initialized` arrived %d times, want 1 — the "+
				"same finding as above, seen through the handshake's last step", initialized)
		}
	})

	// --- 37c: THE SECRET IS RESOLVED INNER-FIRST, BY THE CACHE (D131) ------
	//
	// **THE PROVIDER NEVER HOLDS A RESOLVER, which is the property and not an
	// implementation detail.** A chained provider handed one could point it at
	// any secret in the deployment — so the cache resolves the inner reference
	// and passes the RESULT in. `oauth.Resolve` exists solely to refuse the
	// unchained path, and reaching it means a caller did not check for
	// `config.ChainedProvider`.
	//
	// Asserted by driving the refusal directly, because the success path cannot
	// distinguish "chained correctly" from "chained by luck".
	t.Run("the unchained resolve path refuses rather than sending the reference", func(t *testing.T) {
		// DRIVEN DIRECTLY, because the success path cannot distinguish "chained
		// correctly" from "chained by luck" — 37a would pass either way.
		_, err := oauth.New().Resolve(ctx,
			"oauth-cc://idp.example/token?client_id=x&client_secret=file:///tmp/s")
		if err == nil {
			t.Fatal("37c: the unchained resolve path SUCCEEDED. Reaching it means a " +
				"caller did not check for config.ChainedProvider, and succeeding there " +
				"means the literal string `file:///tmp/s` was posted to a token endpoint " +
				"as a password")
		}
		if got := fault.KindOf(err); got != fault.KindInternal {
			t.Errorf("37c: kind %v, want %v — this is OUR dispatch being wrong, not the "+
				"operator's configuration and not the IdP's fault", got, fault.KindInternal)
		}

		// AND THE REFERENCE'S QUERY IS NOT IN THE MESSAGE (D112). It embeds a
		// secret-manager path and a tenant-identifying client_id, and errors
		// travel further than anyone expects.
		// **THE PATH AND THE CLIENT ID, NOT THE WORD.** The first version matched
		// on "client_secret" and failed against a message whose PROSE explains
		// the chaining — "with its client_secret already resolved (D131)" — which
		// is the phrase an operator needs, not a leak. What must not appear is
		// the reference's query STRING: the secret-manager path it points at and
		// the tenant-identifying client_id (D112).
		for _, leak := range []string{"/tmp/s", "client_id=x"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("37c: the refusal echoes %q from the reference's query string, "+
					"which carries a secret-manager path and a tenant identifier into "+
					"every log that sees it: %v", leak, err)
			}
		}

		// --- AND THE CHAINED PATH DOES WORK, which is what stops the arm above
		// passing against a provider that refuses everything ----------------
		rig := newMCPRig(ctx, t, clientCredentialed(t))
		if rig.target.Ref() == "" {
			t.Fatal("37c: the chained resolution produced no target")
		}
		if minted, _ := rig.up.exchanges(); minted == 0 {
			t.Error("37c: the chained path resolved without calling the token endpoint, " +
				"so whatever it produced did not come from the grant")
		}
	})
}

// distinctBearers reports whether more than one distinct Authorization value
// reached the vendor.
func distinctBearers(bearers []string) bool {
	seen := map[string]bool{}
	for _, b := range bearers {
		seen[b] = true
	}
	return len(seen) > 1
}
