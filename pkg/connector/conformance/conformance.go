// Package conformance is the contract a `connector.Driver` must satisfy, and —
// separately selected — the contract an HTTP-transported one must satisfy
// (D167, D156).
//
// **WHY A PUBLISHED SUITE, AND WHY IT IS NOT THE DRIVER'S OWN TESTS.** D160
// built the same thing for `config.Provider` and it earned its keep on the first
// run: `file` and `ambient` — both written here — ignored a cancelled context,
// while `EnvProvider` honoured it and carried a comment predicting exactly that.
// Neither provider's own tests caught it, in D160's words, because *"they were
// written by whoever wrote the provider and asserted what that person
// believed"*. A driver is the same shape of extension point (D35), with more
// surface and a taxonomy to get right.
//
// **`RunHTTP` IS EXPLICITLY SELECTED AND NOT FOLDED INTO `Run`.** D160 learned
// this the hard way too: `Run` passes VACUOUSLY against `oauth-cc://`, because
// every refusal assertion holds for a provider that refuses everything. Here the
// hazard is the mirror image — a driver built on a vendor SDK has no HTTP status
// codes to classify, so a universal suite would either fail it for not being
// HTTP or quietly skip the half that matters and report coverage it does not
// have. A suite that cannot fail for the shape it is aimed at is decoration.
//
// **WHAT `RunHTTP` COVERS IS THE STATUSES WHOSE MEANING THE TAXONOMY FIXES, NOT
// EVERY STATUS.** 401, 403, 429 and 5xx have one correct classification for any
// driver, because D200's attribution axis and D203's re-establishment marker are
// statements about what happened rather than about a particular API. 404, 405
// and most of 4xx do NOT: MCP reads a bare 404 as a legacy HTTP+SSE endpoint and
// therefore a configuration fault, while another API's 404 is an absent record
// and a caller's problem. Demanding one answer there would force MCP's reading
// onto every driver, so those are the driver's own tests to write, and this
// suite says so rather than pretending the enumeration is complete.
//
// Usage, from a driver's own package:
//
//	func TestConformance(t *testing.T) {
//	    conformance.Run(t, myDriver, conformance.Case{...})
//	}
//
//	func TestHTTPConformance(t *testing.T) {
//	    conformance.RunHTTP(t, func(ctx context.Context, baseURL string) error {
//	        return callOnceThrough(myDriver, baseURL)
//	    })
//	}
//
// DESIGN.md references: §4.3.4, §4.9a, D35, D135, D141, D156, D160, D167, D182,
// D200, D203, D204.
package conformance

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Case describes the driver under test.
type Case struct {
	// UnknownAction is an action name the driver does NOT implement. The suite
	// checks it is genuinely absent from Actions(), so the refusal below cannot
	// pass for the wrong reason.
	UnknownAction string

	// Tenants are distinct tenants Concurrent understands, and what `observed`
	// must equal for each. At least two are required: one tenant cannot cross
	// into another.
	Tenants []string

	// WhyNoFarSide is required when Concurrent is nil, and permits exactly one
	// case: a driver with NOTHING A CALLER CAN OBSERVE.
	//
	// **THIS FIELD EXISTS BECAUSE `kata` FALSIFIED THE FIRST DESIGN OF THIS ARM,
	// which required Concurrent of everybody.** `kata` is in-memory: it builds
	// its outbound header, `clear()`s it inside the driver, and returns a Data
	// map assembled FROM THE TARGET IT WAS GIVEN — so the only observation
	// available compares a value with itself, which is D159's failure and worse
	// than no arm. The obvious fix, echoing the credential back so the suite can
	// see it, is forbidden by the other arm added here in the same hour.
	//
	// So the arm is required where a far side exists and LEDGERED where one does
	// not, which is D153's lesson again: an over-general requirement is worse
	// than the narrow case it replaces, because it refuses a correct shape as a
	// consequence of a rule everybody approved.
	WhyNoFarSide string

	// Concurrent invokes the driver once for `tenant` and returns WHAT THE FAR
	// SIDE SAW for that call — the credential it arrived with, an echoed tenant
	// header, whatever distinguishes one tenant from another at the far side.
	//
	// **RETURN AN ERROR ONLY IF THE CALL COULD NOT BE MADE.** If the far side
	// answered something the driver rejects — a fixture that records the request
	// and replies with anything — swallow that and return the observation: the
	// subject here is who the far side thought was calling, not whether the
	// exchange completed. A non-nil error FAILS the arm, because a failure that
	// appears under concurrency and not alone is per-instance state contending
	// with itself.
	//
	// **THE ASSERTION IS NOT "IT DID NOT CRASH" (D4, D218).** Under per-instance
	// state the failure is not a panic: it is tenant B's credential on tenant
	// A's request, which SUCCEEDS, is audited as a success, and writes A's data
	// into B's org. A test that only checked for errors would pass on exactly
	// the catastrophe D4 exists to make impossible, so the far side has to be
	// asked who it thinks called (D159).
	//
	// Required, not optional, and in `Run` rather than `RunHTTP`: statelessness
	// is universal where HTTP status mapping is not, and an optional
	// conformance check is one nobody runs — D160's argument for the suite
	// existing at all, applied to its own arms.
	Concurrent func(ctx context.Context, tenant string) (observed string, err error)

	// Command invokes a TENANT-SCOPED operation — Execute or Query — against a
	// target whose tenant is Tenants[0], with `ctxTenant` on the context.
	//
	// **IT IS SEPARATE FROM THE HTTP INVOKER, AND `mcp` IS WHY (D218).** This
	// arm first lived in `RunHTTP`, reusing the transport invoker, and the MCP
	// driver failed it — correctly. Its HTTP invoker drives `Drift`, which is
	// the driver's one unconditional round trip and is deliberately NOT
	// tenant-scoped: drift comparison runs off the command path for a watcher
	// that acts for nobody, so there is no request tenant to assert against and
	// `AssertTenant` there would refuse every comparison in production.
	//
	// **The assertion is a property of the COMMAND PATH, so the arm has to
	// drive a command.** Putting it in `RunHTTP` was reasoning from where the
	// suite happened to own a server rather than from what the check is about —
	// and the suite can own a server anywhere.
	Command func(ctx context.Context, baseURL, ctxTenant string) error

	// Refuse invokes the driver with UnknownAction against a REAL target and
	// returns the error.
	//
	// **THE CALLER SUPPLIES THE INVOCATION, and the first version of this suite
	// did not — which made the check pass for the wrong reason on the first
	// driver it met.** It called `Execute` with a zero `connector.Target`,
	// because a Target is unconstructable outside the resolver (§6 mechanism 1).
	// For a driver with a compile-time action set that is harmless; for one
	// whose action set comes from CONFIGURATION (D46) a zero target has no
	// vetted spec, so the driver refused for THAT reason and the unknown-action
	// path was never reached. Required rather than defaulted: a silent fallback
	// to the zero target is how a suite comes to report coverage it does not
	// have.
	Refuse func(ctx context.Context) error
}

// Run asserts the contract every driver must satisfy, transport or not.
func Run(t *testing.T, d connector.Driver, c Case) {
	t.Helper()

	runKind(t, d)
	runActions(t, d)
	runSchemasDeclared(t, d)
	runMeterSound(t, d)
	runUnknownAction(t, d, c)
	runStateless(t, c)
	runTenantAsserted(t, c)
}

// runStateless drives every tenant at once and asks the far side who called.
//
// **THE ONE ARM THAT CAN FALSIFY A DECISION RATHER THAN CONFIRM ONE.** D4's
// claim is that a driver holds no credentials and no per-instance state, which
// is what makes ONE instance safe to share across tenants. P2's stated
// invalidation signal is a vendor that needs per-instance state the `Driver`
// interface cannot hold, and this is where an out-of-tree driver's version of
// that shows up.
//
// **IT WAS PROVEN FOR OUR DRIVERS AND NOT BY THIS SUITE, WHICH IS BACKWARDS
// (CONTRACTS 93).** P2 step 2 drives 48 concurrent commands across four tenants
// at the Fullstory driver, and each in-tree driver's own tests do something
// similar. So the population with no check was the one D35 invites and the one
// a PUBLISHED suite exists for.
func runStateless(t *testing.T, c Case) {
	t.Helper()

	if c.Concurrent == nil {
		if strings.TrimSpace(c.WhyNoFarSide) == "" {
			t.Fatal("Case.Concurrent is nil and WhyNoFarSide does not say why, so the " +
				"statelessness contract is unchecked. A driver with a far side must " +
				"supply one; a driver with NOTHING a caller can observe must say so, " +
				"and the two are indistinguishable in a nil")
		}
		t.Logf("statelessness arm not run: %s", c.WhyNoFarSide)
		return
	}
	if len(c.Tenants) < 2 {
		t.Fatal("Case.Tenants needs at least two entries. Two is the minimum that can " +
			"show a crossing: with one, a driver holding a credential returns the " +
			"right answer every time")
	}

	// **REFUSED, NOT SKIPPED, WITHOUT THE DETECTOR.** See race.go: a driver that
	// races on an unsynchronised field answers correctly on a quiet machine and
	// wrongly under load, and that half is the detector's to find.
	if !raceEnabled {
		t.Fatal("the statelessness arm requires the race detector. Run:" +
			"\n\n    go test -race ./...\n\n" +
			"Half of what this arm proves is the detector's — a driver may answer every " +
			"call correctly here and still race on a field that only tears under load. " +
			"It fails rather than skipping because a skipped arm in a mandatory suite " +
			"is one nobody notices missing")
	}

	const perTenant = 8

	type answer struct {
		tenant, observed string
		err              error
	}
	results := make(chan answer, len(c.Tenants)*perTenant)

	var wg sync.WaitGroup
	for _, tenant := range c.Tenants {
		for range perTenant {
			wg.Add(1)
			go func(tenant string) {
				defer wg.Done()
				observed, err := c.Concurrent(context.Background(), tenant)
				results <- answer{tenant: tenant, observed: observed, err: err}
			}(tenant)
		}
	}
	wg.Wait()
	close(results)

	seen := 0
	for a := range results {
		seen++
		if a.err != nil {
			t.Errorf("a concurrent call for tenant %q failed: %v. Every call here is "+
				"one the driver should serve; a failure under concurrency that does not "+
				"occur alone is per-instance state contending with itself",
				a.tenant, a.err)
			continue
		}
		if a.observed != a.tenant {
			t.Errorf("a call for tenant %q was seen by the far side as %q. **THIS IS D4 "+
				"FALSIFIED**: the driver is HOLDING per-instance state, so under "+
				"concurrency one tenant's credential rides another tenant's request — "+
				"which succeeds, is audited as a success, and writes one customer's data "+
				"into another's system (§6 item 5)", a.tenant, a.observed)
		}
	}
	if want := len(c.Tenants) * perTenant; seen != want {
		t.Errorf("%d of %d concurrent calls came back. Calls were lost or the driver "+
			"serialised them into each other", seen, want)
	}
}

// runKind checks the routing key.
//
// A driver's Kind is what a target's `kind:` matches and what the registry keys
// on, so an empty or whitespace one makes a driver unroutable in a way that
// shows up as "no driver implements this kind" pointing at a driver that is
// registered.
func runKind(t *testing.T, d connector.Driver) {
	t.Helper()

	kind := d.Kind()
	if strings.TrimSpace(kind) == "" {
		t.Error("Kind() is empty, so no target can name this driver and the registry has " +
			"nothing to key on")
	}
	if kind != strings.TrimSpace(kind) {
		t.Errorf("Kind() = %q has surrounding whitespace, which will not match a config "+
			"value nobody thought to pad", kind)
	}
}

// runActions asserts the action set is usable and self-describing.
//
// **EVERY ACTION CARRIES A DESCRIPTION, AND NOTHING IS SYNTHESISED (D196).** The
// catalog renders these into the sentence an agent reads to decide what to
// attempt, and it has no fallback: an action whose description is empty, or is a
// restatement of its own identifier, is the defect D196 was written for after a
// grant naming `mcp.github.exfiltrate` was advertised with a description
// synthesised from the name.
func runActions(t *testing.T, d connector.Driver) {
	t.Helper()

	actions := d.Actions()
	if len(actions) == 0 {
		// NOT AN ERROR. An MCP driver built with no vetted spec legitimately
		// implements nothing, and a suite that demanded actions would fail a
		// correct driver for its configuration.
		t.Log("Actions() is empty; the rest of the action contract is not applicable")
		return
	}

	// **ONE STATEMENT OF THE CONTRACT, CALLED RATHER THAN RESTATED (D218).**
	// This arm used to make its own checks — uniqueness, empty name, the
	// description rules, the idempotency class — while `connector.ValidateActions`
	// made a DIFFERENT set that boot runs through `internal/schemareg`. Neither
	// had the other's, so an out-of-tree author (D35) passed this suite and would
	// then be refused at deploy for the name prefix, the placement pairing, an
	// unimplemented class, or a read that declared one.
	//
	// **That is CONTRACTS 93's condition one layer down, and it was found by
	// working the kata rather than by reading either function.** Calling it means
	// every check boot makes, the suite makes too — including checks added after
	// this line was written.
	if problems := connector.ValidateActions(d.Kind(), actions); len(problems) > 0 {
		for _, p := range problems {
			t.Error(p)
		}
	}
}

// runUnknownAction checks the driver refuses what it does not implement.
//
// **WHAT IS UNIVERSAL HERE IS THE SHAPE OF THE REFUSAL, NOT ITS ATTRIBUTION —
// and the first version of this suite got that wrong.** It demanded
// `AttributionCaller`, on the reasoning that an unknown action is a caller's
// typo. The MCP driver failed it, and the driver was right: an action set that
// comes from configuration (D46) has THREE honest refusals for an action it does
// not implement, and they are attributed differently on purpose —
// `invalid_argument` (the name is not `mcp.<server>.<tool>`, so the CALLER is
// wrong), `config` (this target has no vetted spec, so WE are), and `spec_drift`
// (the tool exists on the server and nobody vetted it, which is a fact about the
// TARGET's surface and the supply-chain win D48 exists to make visible).
// Demanding one answer would have forced a compile-time driver's reading onto a
// configured one — the same over-reach this package's comment warns about for
// 404, committed in the suite that warns about it.
//
// So what is asserted is what all three share, and what a driver getting this
// wrong would breach: the refusal is DECIDED rather than transported (D135), it
// is not retryable, and it does not touch the target's breaker (D141) — because
// nothing was asked of the target.
func runUnknownAction(t *testing.T, d connector.Driver, c Case) {
	t.Helper()

	if c.UnknownAction == "" {
		t.Fatal("Case.UnknownAction is empty, so the refusal contract is unchecked. Name " +
			"an action this driver does not implement — a driver that attempts anything " +
			"it is handed has no action set worth advertising")
	}
	if c.Refuse == nil {
		t.Fatal("Case.Refuse is nil, so nothing invokes the driver. See the field's own " +
			"comment: the suite cannot build a `connector.Target` (§6 mechanism 1), and " +
			"invoking with a zero one exercises a different refusal than the one under test")
	}

	for _, a := range d.Actions() {
		if a.Name == c.UnknownAction {
			t.Fatalf("Case.UnknownAction is %q, which this driver DOES implement, so the "+
				"check would pass for the wrong reason", c.UnknownAction)
		}
	}

	err := c.Refuse(context.Background())
	if err == nil {
		t.Fatalf("the driver accepted unknown action %q", c.UnknownAction)
	}

	kind := fault.KindOf(err)
	if kind.ImplicatesTarget() {
		t.Errorf("an unknown action was classified %q, which implicates the TARGET: a "+
			"caller's typo would count against a vendor's breaker and could take a "+
			"healthy target out of service over a request that never left this process "+
			"(D141, D200)", kind)
	}
	// **THIS ASSERTION WAS WRITTEN, WITHDRAWN, AND RESTORED WHEN THE TAXONOMY
	// CAUGHT UP (CONTRACTS 84, D211) — and the middle step is the interesting
	// one.** It was asserted in the first version on D135's rule: a decided
	// refusal travels as a result and only genuine failures stay transport
	// errors, and nothing failed when a driver declined to attempt an action it
	// does not implement. Two drivers failed it by returning
	// `fault.KindNotFound`, and both were using that kind exactly as
	// documented — "an unknown target ref, action, or tool" — which the taxonomy
	// then declared NOT deliberate.
	//
	// So the suite WITHDREW the assertion rather than weakening the drivers to
	// suit it, and recorded the question: the kind conflated a caller naming
	// something that does not exist (a decision) with our own configuration
	// pointing at nothing (a failure), which is D200's shape and a wire change
	// at nine call sites. **A conformance suite must not settle a taxonomy
	// question by asserting one side of it.** D211 settled it — the config sites
	// moved to `KindConfig` and `not_found` became a caller-attributed
	// deliberate refusal — and the assertion came back.
	if !kind.Deliberate() {
		t.Errorf("an unknown action was classified %q, which is not DELIBERATE. The "+
			"driver decided — nothing was attempted and no far side was contacted — so "+
			"it must reach the caller as a result carrying a kind and a decision id "+
			"rather than as a transport failure (D135)", kind)
	}
	if kind.Retryable() {
		t.Errorf("an unknown action was classified %q, which is RETRYABLE — so a typo "+
			"would be retried against a vendor that can never satisfy it", kind)
	}
}

// Invoker performs ONE transport round trip against baseURL and returns the
// driver's classified error.
//
// **THE CALLER SUPPLIES THIS RATHER THAN A DRIVER, because a `connector.Target`
// is unconstructable outside the resolver (§6 mechanism 1).** A suite that built
// its own target would be proving something about a shape the running system
// never produces, so the driver's own test — which can build a document and a
// resolver — closes over whatever it needs and exposes one function.
//
// It must return the error UNWRAPPED far enough for `fault.KindOf` to classify
// it, which every driver already does because the enforcement path depends on
// it.
//
// **THE CALLER ALSO SUPPLIES WHATEVER THE ENFORCEMENT PATH NORMALLY WOULD, and
// discovering which is part of what this suite is for.** A driver asserts the
// request's tenant against its target's (§6 mechanism 3), so an Invoker whose
// context carries none gets `internal: no tenant on the request` — and every
// status arm then classifies THAT rather than anything the server returned.
// The suite cannot supply it: deriving the context's tenant from the target
// would be D159's guard-with-one-origin reproduced in a fixture. So the driver's
// own test calls `connector.WithTenant`, which is one line and is the line that
// says out loud what the driver requires.
// **AND IT TAKES THE TENANT FROM THE SUITE RATHER THAN FROM THE TARGET
// (D218).** It used to derive it — `connector.WithTenant(ctx, target.Tenant())`
// — and the suite's own comment said the tenant assertion was therefore
// unprovable here, because deriving the context's tenant from the target
// reproduces the check inside the fixture. **That reasoning was right about the
// mechanism it examined and wrong that the mechanism was the only one.** The
// suite does not have to derive a tenant; it only has to be able to pass a
// WRONG one and watch nothing leave. So the invoker threads what it is given,
// and one function serves both calls.
type Invoker func(ctx context.Context, baseURL, tenant string) error

// HTTPCase describes the HTTP-transported driver under test.
type HTTPCase struct {
	// Tenant is the tenant the Invoker's TARGET carries. The suite calls with
	// this one and expects the request to reach the server, and with another
	// and expects it not to.
	Tenant string

	// SecretOnTheWire is the credential value as it appears IN THE REQUEST — the
	// bearer token, the basic-auth blob, whatever a packet capture would show.
	//
	// **NOT "the credential": the two differ, and the difference is the whole
	// reason this field can be empty.** A driver that HMAC-signs its request, or
	// exchanges a long-lived secret for a short-lived token before its first
	// call, never puts the configured secret on the wire — and the arrival check
	// below would then fail a CORRECT driver. So an empty value is permitted and
	// WhyNoSecret is required with it, which makes the omission a ledgered
	// decision rather than a silently skipped arm.
	SecretOnTheWire string

	// WhyNoSecret is required when SecretOnTheWire is empty.
	WhyNoSecret string
}

// RunHTTP asserts the transport contract for a driver that speaks HTTP.
//
// **A FINITE ENUMERATION, WHICH IS WHY THIS IS PROVABLE AT ALL (D156's rule).**
// A test that measured what one vendor returns would be evidence about that
// vendor on that day; enumerating what a conforming server MAY return and
// proving our classification under each is evidence about us. The set below is
// the statuses whose meaning the taxonomy fixes — see the package comment for
// why 404 and most of 4xx are deliberately not here.
func RunHTTP(t *testing.T, c HTTPCase, invoke Invoker) {
	t.Helper()

	if strings.TrimSpace(c.Tenant) == "" {
		t.Fatal("HTTPCase.Tenant is empty. Every arm here needs the tenant the target " +
			"carries — without it a driver refuses before building a request and every " +
			"status arm classifies THAT refusal instead of anything the server returned")
	}

	runUnauthorized(t, c, invoke)
	runForbidden(t, c, invoke)
	runRateLimited(t, c, invoke)
	runServerError(t, c, invoke)
	runUnreachable(t, c, invoke)
	runCancelled(t, c, invoke)
	runNoCredentialInTheError(t, c, invoke)
}

// serveCounting is `serve` with a request counter, for the arms whose assertion
// is about what did NOT arrive.
func serveCounting(t *testing.T, status int, body string) (url string, arrived func() int) {
	t.Helper()

	var (
		mu sync.Mutex
		n  int
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return srv.URL, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// runTenantAsserted proves the tenant check happens BEFORE the outbound call.
//
// **THE ARM WITH TEETH IS THE FAR-SIDE COUNT, not the error (D159, D218).** A
// driver that calls the vendor and then declines to return the answer has
// already acted for the wrong tenant: the request is in the vendor's logs, the
// write is done, and the refusal describes something that already happened.
// §6 mechanism 3 is a PRE-condition, and the only way to tell a precondition
// from a postcondition is to count what reached the server.
//
// **ONE INVOKER, TWO CALLS, ONE VARIABLE — and the first design was vacuous for
// want of that.** It took a second, author-supplied `Mismatch` invoker, and a
// `Mismatch` that returned an error without calling the driver at all would
// pass perfectly, because zero requests reaching the server is exactly what it
// produces. A far-side count proves nothing about a call that was never made.
// Threading the tenant through the SAME function means an author can only
// defeat this by ignoring the parameter — and then the matching call would have
// to keep arriving while the mismatched one stopped, through identical code.
func runTenantAsserted(t *testing.T, c Case) {
	t.Helper()

	if c.Command == nil {
		if strings.TrimSpace(c.WhyNoFarSide) == "" {
			t.Fatal("Case.Command is nil and WhyNoFarSide does not say why, so §6 " +
				"mechanism 3 — the last check between a pooled client and the wrong " +
				"customer's data — is unchecked")
		}
		t.Logf("tenant-assertion arm not run: %s", c.WhyNoFarSide)
		return
	}
	if len(c.Tenants) < 2 {
		t.Fatal("Case.Tenants needs at least two entries: the arm calls with the " +
			"target's own tenant and then with another")
	}
	own, other := c.Tenants[0], c.Tenants[1]

	// 500 rather than 200: the arm cares that a request ARRIVED, and no success
	// body is plausible to every driver. A driver that failed to parse a success
	// would fail this arm for the wrong reason.
	url, arrived := serveCounting(t, http.StatusInternalServerError, `boom`)

	// --- the target's own tenant reaches the far side (non-vacuity) --------
	_ = c.Command(context.Background(), url, own)
	if got := arrived(); got != 1 {
		t.Fatalf("a command carrying the target's own tenant %q reached the server %d "+
			"times, want 1. The mismatch arm below cannot mean anything until this one "+
			"does — zero requests is what a broken fixture produces too", own, got)
	}

	// --- and another tenant does not ---------------------------------------
	err := c.Command(context.Background(), url, other)
	if err == nil {
		t.Fatalf("a command whose request tenant (%q) does not match the target's (%q) "+
			"SUCCEEDED. §6 mechanism 3 is the last check between a pooled client and "+
			"the wrong customer's data", other, own)
	}
	if got := arrived(); got != 1 {
		t.Errorf("the mismatched command reached the server: %d requests total, want 1. "+
			"The assertion fired AFTER the outbound call, so the action was performed "+
			"for the wrong tenant and then reported as refused — a refusal that "+
			"describes something which already happened", got)
	}

	// A tenant mismatch is OURS, not the target's. Counted against the target it
	// would open a breaker on a healthy vendor over a bug in here (D200).
	if kind := fault.KindOf(err); kind.ImplicatesTarget() {
		t.Errorf("a tenant mismatch was classified %q, which implicates the TARGET. The "+
			"vendor did nothing wrong and was not even asked; attributing this to it "+
			"opens a breaker on a healthy target over a fault of ours (D200)", kind)
	}
}

// runNoCredentialInTheError proves the credential does not leak into an error.
//
// **NON-VACUOUS BECAUSE THE SUITE OWNS THE SERVER**: the handler confirms the
// secret genuinely ARRIVED before the call is failed, so a driver that never
// sent it cannot pass by omission. That trap — an arm satisfied by the absence
// of the thing it is checking — is the one this repository has walked into most
// often.
//
// **THE LIMIT, AND IT IS REAL: this covers the ERROR, not `Effect.detail`.**
// The detail is built from `connector.Result`, and a Result exists only on the
// SUCCESS path, where no generic body is plausible to every driver — an MCP
// envelope and a Fullstory event response have nothing in common. So the
// success half stays each driver's own to test, as P1 step 19 does for the
// posture record, and D218's "or a result" is narrowed here rather than
// silently dropped.
func runNoCredentialInTheError(t *testing.T, c HTTPCase, invoke Invoker) {
	t.Helper()

	if c.SecretOnTheWire == "" {
		if strings.TrimSpace(c.WhyNoSecret) == "" {
			t.Fatal("HTTPCase.SecretOnTheWire is empty and WhyNoSecret does not say why. " +
				"A driver that signs its requests or exchanges the secret for a token " +
				"legitimately puts nothing verbatim on the wire — but an unexplained " +
				"empty value is indistinguishable from an author skipping the arm")
		}
		t.Logf("credential-leak arm not run: %s", c.WhyNoSecret)
		return
	}

	var (
		mu   sync.Mutex
		sent []string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		for _, vs := range r.Header {
			sent = append(sent, vs...)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`boom`))
	}))
	t.Cleanup(srv.Close)

	err := invoke(context.Background(), srv.URL, c.Tenant)
	if err == nil {
		t.Fatal("a 500 produced no error, so there is no error to check for a leak")
	}

	mu.Lock()
	carried := false
	for _, v := range sent {
		if strings.Contains(v, c.SecretOnTheWire) {
			carried = true
			break
		}
	}
	mu.Unlock()

	if !carried {
		t.Fatalf("SecretOnTheWire (%d bytes) did not appear in any request header, so "+
			"this arm would pass on a driver that leaks. Either the value is not what "+
			"the driver actually sends, or the driver transforms it — in which case "+
			"leave it empty and say so in WhyNoSecret", len(c.SecretOnTheWire))
	}

	if strings.Contains(err.Error(), c.SecretOnTheWire) {
		t.Errorf("the credential appears in the error this driver returned. An error " +
			"reaches the log, the audit Effect detail and — through a fault kind the " +
			"gateway maps to a result — the CALLER, so a credential in one is a " +
			"credential disclosed to the party the credential is used against")
	}
}

// serve runs a TLS server that answers everything with one status and body.
//
// TLS BECAUSE A CREDENTIAL RIDES ON EVERY REQUEST. A driver that accepted an
// http:// base_url would put a bearer token on the wire in clear, so drivers
// refuse one — which means `httptest.NewServer` cannot be used here however
// convenient it is, and a suite built on it would only ever test drivers that
// have the bug.
func serve(t *testing.T, status int, body string, header http.Header) string {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k, vs := range header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// InsecureClient is an HTTP client that trusts the suite's test servers.
//
// **NEEDED BECAUSE THE SUITE'S SERVERS ARE TLS WITH SELF-SIGNED CERTIFICATES**,
// and a driver under test builds its own client. Named for what it is: nothing
// in this package is reachable from a production build, and a driver that used
// it outside a test would be disabling certificate verification on a credential
// path.
func InsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// MinVersion 1.3 (D344): the suite's servers are httptest, which speaks
			// 1.3, so nothing is lost — and a helper that turns verification off
			// should not also accept every protocol version while it is at it.
			//nolint:gosec // a self-signed httptest certificate, in a test-only helper
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		},
		Timeout: 5 * time.Second,
	}
}

// runUnauthorized is the sharpest case in the suite.
func runUnauthorized(t *testing.T, c HTTPCase, invoke Invoker) {
	t.Helper()

	err := invoke(context.Background(), serve(t, http.StatusUnauthorized, `{"error":"nope"}`, nil), c.Tenant)
	if err == nil {
		t.Fatal("a 401 produced no error")
	}

	kind := fault.KindOf(err)
	if kind != fault.KindUnauthenticated {
		t.Errorf("a 401 was classified %q, want %q", kind, fault.KindUnauthenticated)
	}
	if kind.ImplicatesTarget() {
		t.Errorf("a 401 implicates the TARGET (%q). The vendor answered correctly — it "+
			"rejected OUR credential — so counting it against the breaker would take a "+
			"healthy target out of service over a credential problem (D200)", kind)
	}

	// **THE RE-ESTABLISHMENT MARKER, AND ONLY THE FAR SIDE MAY SET IT (D203).**
	// A 401 read off a real response is the ONE producer of `unauthenticated`
	// that a fresh mint can fix. The others — a placement refusal, a downgrade
	// guard, a borrow on a wiped credential, an IdP that would not issue —
	// return the same kind and must NOT set it, because re-minting returns the
	// same bytes for one and is the attacker's goal for another.
	// **AND IT MUST ASK FOR THE CREDENTIAL SPECIFICALLY (D213).** The marker
	// stopped being a bool when a second kind of far-side state appeared, and a
	// non-zero check here would pass a driver that asked for its SESSION to be
	// re-established after a 401 — a second traversal that discards a pooled
	// client, leaves the rejected credential cached, and fails identically.
	if got := fault.ReestablishOf(err); got != fault.ReestablishCredential {
		t.Errorf("a 401 from the far side asks to re-establish %q rather than the "+
			"credential, so a credential "+
			"the vendor rejected will never be re-minted and every call fails until an "+
			"operator notices (D203, D204, D213)", got)
	}
}

func runForbidden(t *testing.T, c HTTPCase, invoke Invoker) {
	t.Helper()

	err := invoke(context.Background(), serve(t, http.StatusForbidden, `{"error":"denied"}`, nil), c.Tenant)
	if err == nil {
		t.Fatal("a 403 produced no error")
	}

	kind := fault.KindOf(err)
	if !kind.Deliberate() {
		t.Errorf("a 403 was classified %q, which is not DELIBERATE. The vendor decided; "+
			"a decision must reach the caller as a result with a kind rather than as a "+
			"transport failure (D135), and a non-deliberate classification also counts "+
			"it against the breaker (D141)", kind)
	}
	if fault.ReestablishOf(err) != fault.ReestablishNone {
		t.Error("a 403 is marked re-establishable. The credential was accepted and the " +
			"ACTION was refused, so re-minting changes nothing and the retry is pure " +
			"amplification against a vendor that already said no (D203)")
	}
}

func runRateLimited(t *testing.T, c HTTPCase, invoke Invoker) {
	t.Helper()

	const after = 7
	hdr := http.Header{"Retry-After": []string{"7"}}
	err := invoke(context.Background(), serve(t, http.StatusTooManyRequests, `slow down`, hdr), c.Tenant)
	if err == nil {
		t.Fatal("a 429 produced no error")
	}

	kind := fault.KindOf(err)
	if kind != fault.KindRateLimited {
		t.Errorf("a 429 was classified %q, want %q", kind, fault.KindRateLimited)
	}

	// **A 429 MEANS THE TARGET IS ALIVE, so it must not open the breaker
	// (D141).** Counting a rate limit as a failure turns a working rate limit
	// into an outage, which is the failure mode that gets a breaker disabled.
	if kind.ImplicatesTarget() {
		t.Errorf("a 429 implicates the TARGET (%q), so a rate limit would trip the "+
			"breaker and turn throttling into an outage (D141)", kind)
	}

	// **THE UPSTREAM IS THE AUTHORITY ON ITS OWN QUOTA**, and `Retry-After` is
	// better information than any local model — so it has to survive
	// classification. Dropped here, the retry falls back to a guess and the
	// limiter never learns what the vendor said (§4.3.4, pkg/limiter's own
	// comment).
	if got := fault.RetryAfterOf(err); got != after*time.Second {
		t.Errorf("Retry-After: 7 arrived as %v, want %v. The vendor's own number must "+
			"reach the retry policy, or the local model overrides the only authority on "+
			"the quota", got, after*time.Second)
	}
}

func runServerError(t *testing.T, c HTTPCase, invoke Invoker) {
	t.Helper()

	err := invoke(context.Background(), serve(t, http.StatusInternalServerError, `boom`, nil), c.Tenant)
	if err == nil {
		t.Fatal("a 500 produced no error")
	}

	kind := fault.KindOf(err)
	if !kind.ImplicatesTarget() {
		t.Errorf("a 500 was classified %q, which does NOT implicate the target. A vendor "+
			"failing is the case the breaker exists for; classified otherwise, a target "+
			"can fail every call forever without the breaker ever opening (D141, D200)",
			kind)
	}
	if !kind.Retryable() {
		t.Errorf("a 500 was classified %q, which is not retryable. A server error is the "+
			"canonical transient failure", kind)
	}
	if fault.ReestablishOf(err) != fault.ReestablishNone {
		t.Error("a 500 is marked re-establishable, so a vendor outage would burn " +
			"credential mints against the secret manager (D204's churn)")
	}
}

// runUnreachable is the case that separates an outage from a governance event.
func runUnreachable(t *testing.T, c HTTPCase, invoke Invoker) {
	t.Helper()

	// A server that is started and immediately closed gives a port nothing is
	// listening on — a connection refused rather than a timeout, which is fast
	// and deterministic.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	err := invoke(context.Background(), url, c.Tenant)
	if err == nil {
		t.Fatal("an unreachable server produced no error")
	}

	kind := fault.KindOf(err)
	if !kind.ImplicatesTarget() {
		t.Errorf("an unreachable server was classified %q, which does not implicate the "+
			"target — so the breaker never opens on a target that cannot be reached at "+
			"all (D141)", kind)
	}
	if kind == fault.KindSpecDrift {
		t.Error("an unreachable server was classified as spec_drift. An outage is an " +
			"availability event and a divergence is a governance one; conflating them " +
			"makes a vendor's bad afternoon read as a supply-chain incident and fires " +
			"every anzen rule watching for drift (D48, P2 step 13)")
	}
}

// runCancelled is the case D160 found every in-house provider failing.
func runCancelled(t *testing.T, c HTTPCase, invoke Invoker) {
	t.Helper()

	// A server that never answers, so the only way out is the context.
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	// **CLOSE THE CHANNEL BEFORE THE SERVER**, or `srv.Close` waits for the
	// handler and the handler waits for the channel (GO-PRIMER §15t).
	t.Cleanup(func() { close(block); srv.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := invoke(ctx, srv.URL, c.Tenant)
	if err == nil {
		t.Fatal("an already-cancelled context produced no error, so this driver performs " +
			"work a caller has already abandoned. D160 found `file` and `ambient` doing " +
			"exactly this while the provider that honoured cancellation carried a comment " +
			"predicting it")
	}
	if !errors.Is(err, context.Canceled) && fault.KindOf(err) != fault.KindTimeout {
		t.Errorf("a cancelled context produced %q (kind %q), want a wrapped "+
			"context.Canceled or a timeout kind. A caller that gave up needs the "+
			"cancellation reflected, not a vendor error it cannot act on",
			err, fault.KindOf(err))
	}
}
