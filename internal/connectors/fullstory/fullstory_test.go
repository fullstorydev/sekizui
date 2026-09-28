package fullstory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// WHAT THESE TESTS CAN AND CANNOT PROVE, stated once so nobody reads more into a
// green run than is there.
//
// They prove the driver's SHAPE against Fullstory's documented shapes: the auth
// header, the paths, the status-to-taxonomy mapping, the idempotency
// classifications, statelessness under concurrent multi-tenant load, and every
// refusal. They cannot prove that the real Fullstory accepts the request, which
// is P2 acceptance step 1's job and needs an org and a key.
//
// That split is deliberate rather than a limitation to apologise for: most of
// what goes wrong in a connector is the part a review cannot catch and a fake
// transport can — a mis-mapped status, a credential that leaks into a log, a
// header on the wrong request. What only a live call proves is whether the
// vendor agrees with its own documentation.

const token = "fs-test-token"

// target builds a resolved target pointed at a test server.
func target(t *testing.T, ref, tenant, base string) connector.Target {
	t.Helper()
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: ref, Kind: Kind, Tenant: tenant, Residency: "eu",
		BaseURL: base, CredentialVersion: "v1",
		Credential: connector.Secret(token),
	})
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}
	return tgt
}

func tenantCtx(name string) context.Context {
	return connector.WithTenant(context.Background(), name)
}

// idemFor returns what the spine would pass for an action.
func idemFor(t *testing.T, action string) connector.Idempotency {
	t.Helper()
	for _, s := range New().Actions() {
		if s.Name == action {
			return connector.Idempotency{
				Class: s.Idempotency, Placement: s.IdempotencyPlacement,
			}
		}
	}
	t.Fatalf("no spec for %q", action)
	return connector.Idempotency{}
}

// recorder is a fake Fullstory that records what it was sent.
type recorder struct {
	mu       sync.Mutex
	paths    []string
	auths    []string
	bodies   []map[string]any
	status   int
	response string
	headers  map[string]string
}

// serve returns a TLS server, and the driver is why.
//
// **`httptest.NewServer` IS PLAINTEXT AND THE DRIVER REFUSES IT**, correctly: an
// http:// base_url puts the credential on the wire in clear, so `base()` rejects
// any scheme but https. The first draft of these tests used the plaintext
// helper and every call was refused — the security control working, and the test
// wrong. `NewTLSServer` plus `srv.Client()` (which trusts the server's generated
// certificate) exercises the real path including the handshake, which is
// strictly better than what was intended.
func (r *recorder) serve() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)

		r.mu.Lock()
		r.paths = append(r.paths, req.URL.Path)
		r.auths = append(r.auths, req.Header.Get("Authorization"))
		r.bodies = append(r.bodies, body)
		status, response, headers := r.status, r.response, r.headers
		r.mu.Unlock()

		for k, v := range headers {
			w.Header().Set(k, v)
		}
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if response != "" {
			_, _ = w.Write([]byte(response))
		}
	}))
}

func (r *recorder) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.paths)
}

// --- the definition-of-done items -----------------------------------------

// TestActionsMatchImplementation forbids an advertised-but-absent action.
//
// The connector definition-of-done's first item, and the cheapest defect to ship
// without it: a spec somebody added to the catalog and never wired, which an
// agent discovers by being refused something `Describe` promised.
func TestActionsMatchImplementation(t *testing.T) {
	rec := &recorder{status: http.StatusOK, response: `{"id":"x"}`}
	srv := rec.serve()
	defer srv.Close()

	d := New(WithHTTPClient(srv.Client()), withServer(srv))
	specs := d.Actions()
	if len(specs) == 0 {
		t.Fatal("the driver advertises no actions")
	}

	for _, spec := range specs {
		t.Run(spec.Name, func(t *testing.T) {
			// THE POLL IS CALLED THROUGH ITS REAL ENTRY POINT, Poll (D265) —
			// "callable" means callable the way the spine calls it.
			if spec.Name == ActionSessionEvents {
				fx := contextFixture(t, "stamp-x")
				if _, err := New(WithHTTPClient(fx.Client()), withServer(fx)).Query(tenantCtx("alpha"),
					readBackTarget(t, fx.URL), spec.Name,
					map[string]any{"session_id": "1:2"}); err != nil {
					t.Errorf("advertised action %q is not callable through Query: %v", spec.Name, err)
				}
				return
			}
			if spec.Name == ActionPoll {
				fx := sessionsFixture(t)
				tgt := sessionsTarget(t, fx.URL)
				if _, _, err := New(WithHTTPClient(fx.Client()), withServer(fx)).Poll(tenantCtx("alpha"), tgt, "", 5); err != nil {
					t.Errorf("advertised action %q is not callable through Poll: %v", spec.Name, err)
				}
				return
			}
			// A DERIVED ACTION (D314) is called the way its CONTRACT says: every
			// path parameter filled, through Query for a read and Execute for a
			// write — and what reaches the server is the documented path with
			// its parameters in it, never the template.
			if a, derived := apiActionFor(spec.Name); derived {
				args := map[string]any{}
				for _, p := range a.params {
					if p.required {
						args[p.name] = "p-" + p.name
					}
				}
				tgt := target(t, "fs:alpha", "alpha", srv.URL)
				var err error
				if spec.Mutating {
					_, err = d.Execute(tenantCtx("alpha"), tgt, spec.Name, args, idemFor(t, spec.Name))
				} else {
					_, err = d.Query(tenantCtx("alpha"), tgt, spec.Name, args)
				}
				if err != nil {
					t.Fatalf("advertised action %q is not callable as its contract says: %v", spec.Name, err)
				}
				rec.mu.Lock()
				got := rec.paths[len(rec.paths)-1]
				rec.mu.Unlock()
				if strings.Contains(got, "{") {
					t.Errorf("%s reached %s — a path parameter was not filled", spec.Name, got)
				}
				return
			}
			if _, err := d.Execute(tenantCtx("alpha"),
				target(t, "fs:alpha", "alpha", srv.URL), spec.Name,
				map[string]any{"name": "checkout_started"}, idemFor(t, spec.Name)); err != nil {
				t.Errorf("advertised action %q is not callable: %v", spec.Name, err)
			}
		})
	}
}

// TestEveryActionHasAnEndpoint ranges the specs rather than naming them, so an
// action added later is covered by existing (§15q).
func TestEveryActionHasAnEndpoint(t *testing.T) {
	for _, spec := range New().Actions() {
		// THE POLL IS THE ONE EXCEPTION, AND IT MUST BE REFUSED RATHER THAN
		// SENT (D265): it is served by Poll, and Execute reaching it would POST
		// to the API root — the failure this test is named for.
		// EVERY READ IS REFUSED BY Execute RATHER THAN SENT (D265, D270): the
		// poll is served by Poll and session_events by Query, and Execute
		// reaching either would POST to the API root.
		if !spec.Mutating {
			if _, err := New().Execute(context.Background(), target(t, "fs:x", "x", "https://api.invalid"), spec.Name, nil,
				connector.Idempotency{}); err == nil {
				t.Errorf("Execute accepted the read %s; with no endpoint it would POST to the API root", spec.Name)
			}
			continue
		}
		// A DERIVED WRITE CARRIES ITS OWN ENDPOINT, BUILT FROM ITS CONTRACT
		// (D314): it must be a real documented path, never empty.
		if a, derived := apiActionFor(spec.Name); derived {
			if a.ep.method == "" || !strings.HasPrefix(a.ep.template, "/") {
				t.Errorf("derived action %q has no endpoint: %+v", spec.Name, a.ep)
			}
			continue
		}
		if _, ok := endpoints[spec.Name]; !ok {
			t.Errorf("action %q is advertised and has no endpoint, so Execute would POST "+
				"to the API root. A table lookup that misses must be impossible rather "+
				"than merely unlikely", spec.Name)
		}
	}
	for action := range endpoints {
		var advertised bool
		for _, spec := range New().Actions() {
			if spec.Name == action {
				advertised = true
			}
		}
		if !advertised {
			t.Errorf("endpoint table names %q, which the driver does not advertise — a "+
				"path nothing can reach", action)
		}
	}
}

// TestActionsPassTheSharedContract is the check every driver owes.
//
// It is what catches a missing idempotency class, a placement declared for a
// class that needs none, or a mutating action nobody classified — before the
// first retry rather than after it (D163).
func TestActionsPassTheSharedContract(t *testing.T) {
	d := New()
	if problems := connector.ValidateActions(d.Kind(), d.Actions()); len(problems) > 0 {
		t.Errorf("the driver fails the contract every driver must meet:\n  - %s",
			strings.Join(problems, "\n  - "))
	}
}

// TestTheTwoActionsCarryOppositeIdempotencyClasses pins D163's central claim.
//
// **THE CLASSIFICATION IS PER ACTION, AND FULLSTORY IS THE PROOF RATHER THAN THE
// MOTIVATION.** `POST /v2/users` is create-or-update keyed on `uid` and is
// therefore `natural`; `POST /v2/events` documents no dedupe of any kind and is
// `none`. Two actions, one vendor, opposite answers — a per-driver field would
// have been wrong on its first connector, and this is the test that says so.
func TestTheTwoActionsCarryOppositeIdempotencyClasses(t *testing.T) {
	want := map[string]connector.IdempotencyClass{
		ActionCreateEvent: connector.IdempotencyNone,
		ActionUpsertUser:  connector.IdempotencyNatural,
	}
	seen := map[connector.IdempotencyClass]bool{}

	for _, spec := range New().Actions() {
		// A READ CARRIES NO CLASS (D163 classifies what a retry could DUPLICATE),
		// and declaring one on the poll would be decoration. Reviewed here, as
		// the rule below demands, rather than inherited.
		if spec.Name == ActionPoll || spec.Name == ActionSessionEvents {
			if spec.Mutating || spec.Idempotency != "" {
				t.Errorf("%s is a read and must be non-mutating with no class; got mutating=%v "+
					"class=%q", spec.Name, spec.Mutating, spec.Idempotency)
			}
			continue
		}
		// A DERIVED ACTION'S CLASS IS THE MAINTAINER'S RULING (D314), recorded in
		// writeClasses — deriveAction refuses any non-GET operation without one,
		// so "reviewed, not inherited" holds by construction. Here it is held to
		// exactly that ruling: a GET carries no class and does not write.
		if a, derived := apiActionFor(spec.Name); derived {
			ruled, has := writeClasses[a.op.Key()]
			switch {
			case a.op.Method == http.MethodGet && (spec.Mutating || spec.Idempotency != ""):
				t.Errorf("%s is a GET and must be a read with no class", spec.Name)
			case a.op.Method != http.MethodGet && !has:
				t.Errorf("%s has no ruling in writeClasses", spec.Name)
			case has && (spec.Mutating != ruled.mutating || spec.Idempotency != ruled.idempotency):
				t.Errorf("%s declares mutating=%v class=%q; ruled mutating=%v class=%q", spec.Name,
					spec.Mutating, spec.Idempotency, ruled.mutating, ruled.idempotency)
			}
			if spec.Idempotency != "" {
				seen[spec.Idempotency] = true
			}
			continue
		}
		expected, known := want[spec.Name]
		if !known {
			t.Errorf("action %q has no expected idempotency class here. A new action "+
				"must have its classification reviewed, not inherited", spec.Name)
			continue
		}
		if spec.Idempotency != expected {
			t.Errorf("%s declares class %q, want %q", spec.Name, spec.Idempotency, expected)
		}
		seen[spec.Idempotency] = true
	}

	// THE ARM THAT MAKES IT ABOUT D163 RATHER THAN ABOUT TWO CONSTANTS. If both
	// actions ever carried the same class, this driver would stop demonstrating
	// that the classification is per-action — and the phase's whole argument for
	// choosing Fullstory first would quietly stop holding.
	if len(seen) < 2 {
		t.Error("both actions now carry the same idempotency class, so this driver no " +
			"longer demonstrates that the classification is PER ACTION. That is the " +
			"reason §12 P2 gives for Fullstory being the first connector")
	}
}

// --- the credential ------------------------------------------------------

// TestTheCredentialTravelsAsBasicAuthAndNowhereElse.
//
// **`Basic`, NOT `Bearer`.** DESIGN §12 P2 records Bearer, correctly, for the MCP
// endpoint; the server API takes Basic. Two endpoints on one vendor with two
// schemes is the detail a driver written from a summary gets wrong, and D52 puts
// both in this phase.
func TestTheCredentialTravelsAsBasicAuthAndNowhereElse(t *testing.T) {
	rec := &recorder{status: http.StatusOK, response: `{"id":"e-1"}`}
	srv := rec.serve()
	defer srv.Close()

	if _, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Execute(tenantCtx("alpha"),
		target(t, "fs:alpha", "alpha", srv.URL), ActionCreateEvent,
		map[string]any{"name": "checkout_started"}, idemFor(t, ActionCreateEvent)); err != nil {
		t.Fatalf("executing: %v", err)
	}

	rec.mu.Lock()
	auth, body := rec.auths[0], rec.bodies[0]
	rec.mu.Unlock()

	if want := "Basic " + token; auth != want {
		t.Errorf("Authorization = %q, want %q. Bearer is the MCP endpoint's scheme; the "+
			"server API takes Basic, and getting it wrong fails as 401 — which reads as "+
			"a revoked key rather than as a wrong header", auth, want)
	}

	// AND NOT IN THE BODY. A credential that reaches the request payload also
	// reaches the audit record's echo of what was sent, where `Secret`'s
	// self-redaction cannot help because it is no longer a Secret.
	encoded, _ := json.Marshal(body)
	if strings.Contains(string(encoded), token) {
		t.Errorf("the credential appears in the request BODY: %s", encoded)
	}
}

// --- the base URL --------------------------------------------------------

// TestTheBaseURLIsConfigurationAndNeverInference.
//
// Fullstory's host is per data centre, and a driver that mapped a DC name to a
// host would hold deployment topology as driver state (D4) and put the EU/US
// choice where the residency ceiling cannot see it (§7.1 item 2).
func TestTheBaseURLIsConfigurationAndNeverInference(t *testing.T) {
	d := New()

	t.Run("an empty base_url is refused", func(t *testing.T) {
		_, err := d.Execute(tenantCtx("alpha"), target(t, "fs:alpha", "alpha", ""),
			ActionCreateEvent, map[string]any{"name": "x"}, idemFor(t, ActionCreateEvent))
		if err == nil {
			t.Fatal("a target with no base_url was accepted. The driver would then have " +
				"to guess a data centre, which is the topology decision it must not make")
		}
		if got := fault.KindOf(err); got != fault.KindConfig {
			t.Errorf("kind = %v, want config — it is a deployment problem, not a bad "+
				"request from the caller", got)
		}
		if !strings.Contains(err.Error(), "PER DATA CENTRE") {
			t.Errorf("the refusal does not explain WHY it will not guess: %v", err)
		}
	})

	t.Run("plaintext is refused", func(t *testing.T) {
		_, err := d.Execute(tenantCtx("alpha"),
			target(t, "fs:alpha", "alpha", "http://api.fullstory.com"),
			ActionCreateEvent, map[string]any{"name": "x"}, idemFor(t, ActionCreateEvent))
		if err == nil {
			t.Fatal("an http:// base_url was accepted, which puts the credential on the " +
				"wire in clear")
		}
	})

	t.Run("a trailing slash does not double up the path", func(t *testing.T) {
		rec := &recorder{status: http.StatusOK, response: "{}"}
		srv := rec.serve()
		defer srv.Close()

		if _, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Execute(tenantCtx("alpha"),
			target(t, "fs:alpha", "alpha", srv.URL+"/"), ActionCreateEvent,
			map[string]any{"name": "x"}, idemFor(t, ActionCreateEvent)); err != nil {
			t.Fatalf("a base_url with a trailing slash was refused: %v", err)
		}
		rec.mu.Lock()
		path := rec.paths[0]
		rec.mu.Unlock()

		if path != "/v2/events" {
			t.Errorf("the upstream saw path %q, want /v2/events. An untrimmed trailing "+
				"slash produces `//v2/events`, which some gateways route and others "+
				"404 — a difference nobody wants to debug in production", path)
		}
	})
}

// --- the error taxonomy --------------------------------------------------

// TestUpstreamStatusesMapOntoTheTaxonomy is the definition-of-done item most
// easily skipped.
//
// A driver returning `fmt.Errorf("fullstory: %d", status)` works, passes review,
// and destroys every downstream decision: `Retryable`, `Deliberate`,
// `Indeterminate`, the gRPC code, the wire status and the metric label are all
// derived from the KIND. An unclassified failure is `unknown`, which the breaker
// counts against the target, the retry policy refuses to retry, and the operator
// cannot act on.
func TestUpstreamStatusesMapOntoTheTaxonomy(t *testing.T) {
	for _, c := range []struct {
		status int
		want   fault.Kind
		why    string
	}{
		{http.StatusBadRequest, fault.KindInvalidArgument, "our request was malformed"},
		{http.StatusUnauthorized, fault.KindUnauthenticated, "the KEY is wrong — rotate it"},
		{http.StatusForbidden, fault.KindDenied, "the key is fine and lacks the capability"},
		{http.StatusNotFound, fault.KindNotFound, "no such user or session"},
		{http.StatusConflict, fault.KindConflict, "a state collision"},
		{http.StatusUnprocessableEntity, fault.KindInvalidArgument, "semantically invalid"},
		{http.StatusTooManyRequests, fault.KindRateLimited, "quota; clears itself"},
		{http.StatusInternalServerError, fault.KindTargetError, "reached and broke"},
		{http.StatusBadGateway, fault.KindTargetError, "reached and broke"},
		{http.StatusServiceUnavailable, fault.KindTargetError, "reached and broke"},
	} {
		t.Run(fmt.Sprintf("%d_is_%v", c.status, c.want), func(t *testing.T) {
			rec := &recorder{status: c.status, response: `{"message":"upstream said so"}`}
			srv := rec.serve()
			defer srv.Close()

			_, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Execute(tenantCtx("alpha"),
				target(t, "fs:alpha", "alpha", srv.URL), ActionCreateEvent,
				map[string]any{"name": "x"}, idemFor(t, ActionCreateEvent))
			if err == nil {
				t.Fatalf("status %d produced no error", c.status)
			}
			if got := fault.KindOf(err); got != c.want {
				t.Errorf("status %d mapped to %v, want %v (%s)", c.status, got, c.want, c.why)
			}
			// THE VENDOR'S OWN EXPLANATION SURVIVES. An operator reading
			// "Fullstory returned 400" learns less than one reading what
			// Fullstory said about it.
			if !strings.Contains(err.Error(), "upstream said so") {
				t.Errorf("the vendor's message was dropped: %v", err)
			}
		})
	}
}

// TestARateLimitCarriesTheUpstreamsOwnBackoff.
//
// The upstream knows its quota window and we are guessing at it (D14, §5.2.1);
// this is what makes the local limiter viable without a distributed coordinator.
func TestARateLimitCarriesTheUpstreamsOwnBackoff(t *testing.T) {
	rec := &recorder{
		status:   http.StatusTooManyRequests,
		response: `{"message":"slow down"}`,
		headers:  map[string]string{"Retry-After": "20"},
	}
	srv := rec.serve()
	defer srv.Close()

	_, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Execute(tenantCtx("alpha"),
		target(t, "fs:alpha", "alpha", srv.URL), ActionCreateEvent,
		map[string]any{"name": "x"}, idemFor(t, ActionCreateEvent))
	if err == nil {
		t.Fatal("a 429 produced no error")
	}
	if got := fault.RetryAfterOf(err); got != 20*time.Second {
		t.Errorf("RetryAfter = %v, want 20s. Dropping it makes the retry policy fall "+
			"back to its own guess, which stays wrong for the rest of the window", got)
	}
}

func TestRetryAfterAcceptsBothFormsTheRFCAllows(t *testing.T) {
	if got := retryAfter("7"); got != 7*time.Second {
		t.Errorf("seconds form = %v, want 7s", got)
	}
	if got := retryAfter(time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)); got <= 0 {
		t.Errorf("HTTP-date form = %v, want a positive duration", got)
	}
	// A DATE IN THE PAST MEANS "NOW", not a negative wait that would be applied
	// as an immediate retry or, worse, as a negative timer.
	if got := retryAfter(time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)); got != 0 {
		t.Errorf("a past date gave %v, want 0", got)
	}
	if got := retryAfter("not-a-duration"); got != 0 {
		t.Errorf("garbage gave %v, want 0 — an unparseable header is no guidance, not a "+
			"reason to invent one", got)
	}
}

// --- the response --------------------------------------------------------

func TestTwoOhFourIsASuccessWithNothingToSay(t *testing.T) {
	rec := &recorder{status: http.StatusNoContent}
	srv := rec.serve()
	defer srv.Close()

	res, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Execute(tenantCtx("alpha"),
		target(t, "fs:alpha", "alpha", srv.URL), ActionUpsertUser,
		map[string]any{"uid": "u-1"}, idemFor(t, ActionUpsertUser))
	if err != nil {
		t.Fatalf("204 was treated as a failure: %v", err)
	}
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("StatusCode = %d, want 204 — the record should say what the upstream "+
			"actually answered", res.StatusCode)
	}
}

func TestANonJSONBodyIsATargetErrorRatherThanAnUnknownOne(t *testing.T) {
	rec := &recorder{status: http.StatusOK, response: "<html>a proxy interfered</html>"}
	srv := rec.serve()
	defer srv.Close()

	_, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Execute(tenantCtx("alpha"),
		target(t, "fs:alpha", "alpha", srv.URL), ActionCreateEvent,
		map[string]any{"name": "x"}, idemFor(t, ActionCreateEvent))
	if err == nil {
		t.Fatal("an unparseable 200 body was reported as success. The call may have " +
			"landed and we cannot tell, which must not read as a clean write")
	}
	// KindTargetError, not TargetUnavailable: we were REACHED and answered
	// something we cannot read, which is D48's distinction — we learned something
	// specific, and it was bad.
	if got := fault.KindOf(err); got != fault.KindTargetError {
		t.Errorf("kind = %v, want target_error", got)
	}
}

func TestTheExternalRefIsTakenAndNeverInvented(t *testing.T) {
	for _, c := range []struct{ body, want string }{
		{`{"id":"e-99"}`, "e-99"},
		{`{"uid":"u-7"}`, "u-7"},
		{`{"nothing":"useful"}`, ""},
		{`{}`, ""},
	} {
		rec := &recorder{status: http.StatusOK, response: c.body}
		srv := rec.serve()

		res, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Execute(tenantCtx("alpha"),
			target(t, "fs:alpha", "alpha", srv.URL), ActionUpsertUser,
			map[string]any{"uid": "u-1"}, idemFor(t, ActionUpsertUser))
		srv.Close()
		if err != nil {
			t.Fatalf("executing against %s: %v", c.body, err)
		}
		if res.ExternalRef != c.want {
			// INVENTING ONE WOULD BE WORSE THAN HAVING NONE: the audit row would
			// carry an identifier that resolves nowhere, and a human reconciling
			// an indeterminate outcome (D182) would spend the search believing we
			// knew something.
			t.Errorf("response %s gave ExternalRef %q, want %q", c.body, res.ExternalRef, c.want)
		}
	}
}

// --- the refusals --------------------------------------------------------

// TestQueryRefusesRatherThanReturningNothing is D53 on the read plane.
func TestQueryRefusesRatherThanReturningNothing(t *testing.T) {
	rows, err := New().Query(context.Background(),
		target(t, "fs:alpha", "alpha", "https://api.fullstory.com"), "fullstory.read", nil)
	if err == nil {
		t.Fatal("Query returned no error. An empty result set would let an agent " +
			"conclude the account is empty, which is the recurring defect in its " +
			"purest form (D53)")
	}
	if len(rows.Rows) != 0 {
		t.Error("Query returned rows alongside its refusal")
	}
}

func TestAnUndeclaredActionIsRefused(t *testing.T) {
	_, err := New().Execute(tenantCtx("alpha"),
		target(t, "fs:alpha", "alpha", "https://api.fullstory.com"),
		"fullstory.delete_everything", nil, connector.Idempotency{})
	if err == nil {
		t.Fatal("an action the driver does not implement was accepted")
	}
	if got := fault.KindOf(err); got != fault.KindNotFound {
		t.Errorf("kind = %v, want not_found", got)
	}
}

// TestTheTenantIsAssertedBeforeTheCall is §6 mechanism 3.
//
// The assertion catches a pooled client belonging to the wrong tenant — a
// substitution the constructor cannot see, because it happens after
// construction. **NO REQUEST MAY REACH FULLSTORY**, which is the arm worth
// having: an egress check that fires after the call has leaked the thing it
// exists to protect.
func TestTheTenantIsAssertedBeforeTheCall(t *testing.T) {
	rec := &recorder{status: http.StatusOK, response: "{}"}
	srv := rec.serve()
	defer srv.Close()

	_, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Execute(tenantCtx("beta"),
		target(t, "fs:alpha", "alpha", srv.URL), ActionCreateEvent,
		map[string]any{"name": "x"}, idemFor(t, ActionCreateEvent))
	if err == nil {
		t.Fatal("a request whose context tenant is `beta` reached a target bound to " +
			"`alpha`")
	}
	if rec.calls() != 0 {
		t.Errorf("%d request(s) reached the upstream despite the tenant mismatch. An "+
			"egress assertion that fires after the call has already leaked", rec.calls())
	}
}

func TestATenantlessRequestIsRefusedRatherThanAssumed(t *testing.T) {
	rec := &recorder{status: http.StatusOK, response: "{}"}
	srv := rec.serve()
	defer srv.Close()

	if _, err := New(WithHTTPClient(srv.Client()), withServer(srv)).Execute(context.Background(),
		target(t, "fs:alpha", "alpha", srv.URL), ActionCreateEvent,
		map[string]any{"name": "x"}, idemFor(t, ActionCreateEvent)); err == nil {
		t.Fatal("a request with no tenant on the context was served. Assuming one is " +
			"how a multi-tenant leak becomes possible")
	}
	if rec.calls() != 0 {
		t.Errorf("%d request(s) went out for a tenantless command", rec.calls())
	}
}

// --- D4, which this driver can falsify -----------------------------------

// TestTheDriverIsStatelessAcrossConcurrentTenants.
//
// **THE TEST THAT CAN FALSIFY A DECISION RATHER THAN CONFIRM ONE.** D4's claim is
// that a driver holds no credentials and no per-instance state, which is what
// makes ONE instance safe to share across tenants — and P2's stated
// INVALIDATION SIGNAL is a Fullstory that needs per-instance state the `Driver`
// cannot hold. Cheap to check here at two functions; expensive to discover at P4.
//
// The assertion is not "it did not crash". Each request carries its tenant in
// the body, so a target substituted under concurrency shows up as a MISMATCH
// rather than as a panic. Run under `-race`, which is where the interesting
// version of this failure lives (§15g).
func TestTheDriverIsStatelessAcrossConcurrentTenants(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // event name -> Authorization it arrived with

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)
		name, _ := body["name"].(string)

		mu.Lock()
		seen[name] = req.Header.Get("Authorization")
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"e"}`))
	}))
	defer srv.Close()

	// ONE DRIVER, four tenants, every call in flight at once — the realistic
	// shape of a shared mesh serving several customers, and the only shape in
	// which tenant bleed is possible at all.
	d := New(WithHTTPClient(srv.Client()), withServer(srv))
	tenants := []string{"alpha", "beta", "gamma", "delta"}

	var wg sync.WaitGroup
	for _, name := range tenants {
		for i := range 12 {
			wg.Add(1)
			go func(tenant string, n int) {
				defer wg.Done()
				event := fmt.Sprintf("%s-%d", tenant, n)
				if _, err := d.Execute(tenantCtx(tenant),
					target(t, "fs:"+tenant, tenant, srv.URL), ActionCreateEvent,
					map[string]any{"name": event}, idemFor(t, ActionCreateEvent)); err != nil {
					t.Errorf("tenant %s call %d: %v", tenant, n, err)
				}
			}(name, i)
		}
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(tenants)*12 {
		t.Errorf("the upstream saw %d distinct events, want %d — calls were lost or "+
			"collided", len(seen), len(tenants)*12)
	}
	// EVERY REQUEST CARRIED A CREDENTIAL, and the same one, because every target
	// here holds the same secret. What would break under per-instance state is a
	// request arriving with an EMPTY header — the borrow having been clobbered by
	// a concurrent one.
	for event, auth := range seen {
		if auth != "Basic "+token {
			t.Errorf("event %q arrived with Authorization %q. A credential that changes "+
				"under concurrency means the driver is holding one (D4)", event, auth)
		}
	}
}
