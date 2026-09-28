package fault

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// allKinds is every declared Kind. Maintained by hand deliberately: Go has no
// enum reflection, so a generated list would just be this list with extra
// steps. TestAllKindsAreListed catches the case where someone adds a Kind and
// forgets to extend this.
var allKinds = []Kind{
	KindUnknown,
	KindInvalidArgument,
	KindUnauthenticated,
	KindDenied,
	KindEscalated,
	KindNotFound,
	KindConflict,
	KindRateLimited,
	KindBudgetExceeded,
	KindResidency,
	KindSpecDrift,
	KindTargetUnavailable,
	KindTargetError,
	KindTimeout,
	KindConfig,
	KindUnavailable,
	KindInternal,
	KindIndeterminate,
	KindCredentialUnavailable,
	KindSessionExpired,
}

// highestKind is DERIVED from allKinds rather than naming whichever constant is
// currently last.
//
// The earlier version wrote `KindInternal` in three places on the reasoning that
// it was declared last. That stopped being true the moment KindRevoked was added
// — and the failure was silent in the worst direction: TestEveryKindIsClassified
// looped `k <= KindInternal`, so the newest kind, the one nobody had classified
// yet, was the single kind the totality check skipped. A guard keyed on a
// hardcoded last element covers everything except the thing it was added for.
func highestKind() Kind {
	var max Kind
	for _, k := range allKinds {
		if k > max {
			max = k
		}
	}
	return max
}

// TestAllKindsAreListed fails when a Kind is added without extending allKinds,
// which would silently hollow out every totality test below.
func TestAllKindsAreListed(t *testing.T) {
	if got, want := len(allKinds), len(kindNames); got != want {
		t.Fatalf("allKinds has %d entries, kindNames has %d — a Kind was added without updating both", got, want)
	}
	// Kinds are numbered contiguously from zero, so the highest value plus one
	// is how many there must be. Catches a gap as well as a missing entry.
	if got, want := int(highestKind())+1, len(allKinds); got != want {
		t.Errorf("highest Kind is %d so there should be %d kinds, allKinds has %d",
			highestKind(), got, want)
	}
}

// TestKindNumbersAreStable pins every numeric value.
//
// The values are assigned explicitly rather than by iota so that inserting a
// kind cannot silently renumber the ones after it. This test is the second half
// of that guarantee: a DELIBERATE renumber now has to be deliberate twice, once
// in the constant block and once here.
//
// Why it matters beyond tidiness: audit rows outlive the code that wrote them.
// A stored "9" changing from residency to something else, years later, with
// nothing to detect it, is a silent corruption of the record this whole system
// exists to produce. (Persist String(), not the number — but defence in depth.)
func TestKindNumbersAreStable(t *testing.T) {
	for k, want := range map[Kind]uint8{
		KindUnknown: 0, KindInvalidArgument: 1, KindUnauthenticated: 2,
		KindDenied: 3, KindEscalated: 4, KindNotFound: 5, KindConflict: 6,
		KindRateLimited: 7, KindBudgetExceeded: 8, KindResidency: 9,
		KindSpecDrift: 10, KindTargetUnavailable: 11, KindTargetError: 12,
		KindTimeout: 13, KindConfig: 14, KindUnavailable: 15, KindInternal: 16,
		KindIndeterminate: 17,
		// 18 WAS MISSING UNTIL D213 ADDED 19 BESIDE IT. The table is the second
		// half of the stability guarantee and it had silently stopped covering
		// the newest kind — an allowlist-shaped test that only protects what
		// somebody remembered to add, which is the shape `TestAllKindsAreListed`
		// exists to catch and does not, because it counts `allKinds` against
		// `kindNames` and never looks here.
		KindCredentialUnavailable: 18, KindSessionExpired: 19,
	} {
		if uint8(k) != want {
			t.Errorf("Kind %v = %d, want %d — renumbering changes the meaning of "+
				"already-persisted values", k, uint8(k), want)
		}
	}
}

// TestParseKindRoundTrips: String is the persistence format, so it must read back.
func TestParseKindRoundTrips(t *testing.T) {
	for _, k := range allKinds {
		got, ok := ParseKind(k.String())
		if !ok {
			t.Errorf("ParseKind(%q) failed; a persisted audit row could not be read back", k)
			continue
		}
		if got != k {
			t.Errorf("ParseKind(%q) = %v, want %v", k.String(), got, k)
		}
	}
}

// TestParseKindRejectsUnknown. A name retired by a later version is a real case
// when reading old rows; ParseKind must say so rather than guess.
func TestParseKindRejectsUnknown(t *testing.T) {
	for _, s := range []string{"", "nonsense", "DENIED", "kind(3)"} {
		if k, ok := ParseKind(s); ok {
			t.Errorf("ParseKind(%q) = %v, true; want failure", s, k)
		}
	}
}

// TestEveryKindHasAStableName guards the metrics-label contract: the fallback
// formatting would silently produce "kind(12)" as a dashboard label.
func TestEveryKindHasAStableName(t *testing.T) {
	seen := map[string]Kind{}
	for _, k := range allKinds {
		name := k.String()
		if name == "" {
			t.Errorf("Kind %d has an empty name", k)
		}
		if name == fmt.Sprintf("kind(%d)", uint8(k)) {
			t.Errorf("Kind %d fell through to the numeric fallback — missing from kindNames", k)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("Kinds %d and %d share the name %q", prev, k, name)
		}
		seen[name] = k
	}
}

// TestKindIsUsableAsSentinel is the core ergonomic promise of the package.
func TestKindIsUsableAsSentinel(t *testing.T) {
	err := New(KindDenied, "policy.Evaluate", "project not permitted")

	if !errors.Is(err, KindDenied) {
		t.Error("errors.Is(err, KindDenied) = false, want true")
	}
	if errors.Is(err, KindTargetError) {
		t.Error("errors.Is matched the wrong Kind")
	}
}

// TestSentinelSurvivesWrapping is what an exception hierarchy would give for
// free and Go must be shown to give explicitly — classification must survive
// being wrapped by intermediate layers.
func TestSentinelSurvivesWrapping(t *testing.T) {
	root := New(KindRateLimited, "jira.create_issue", "429 from upstream")
	wrapped := fmt.Errorf("driver call failed: %w", root)
	twice := fmt.Errorf("enforcement path: %w", wrapped)

	if !errors.Is(twice, KindRateLimited) {
		t.Error("classification lost after two layers of wrapping")
	}
	if got := KindOf(twice); got != KindRateLimited {
		t.Errorf("KindOf(twice) = %v, want %v", got, KindRateLimited)
	}
}

func TestWrapPreservesCause(t *testing.T) {
	cause := errors.New("connection refused")
	err := Wrap(KindTargetUnavailable, "jira.health", "dialing", cause)

	if !errors.Is(err, cause) {
		t.Error("wrapped cause not reachable via errors.Is")
	}
	if !errors.Is(err, KindTargetUnavailable) {
		t.Error("Kind not matchable after Wrap")
	}
}

// TestWrapNilReturnsNil lets callers write `return fault.Wrap(...)` without a
// preceding nil check, matching the standard library's wrapping helpers.
func TestWrapNilReturnsNil(t *testing.T) {
	if err := Wrap(KindInternal, "op", "msg", nil); err != nil {
		t.Errorf("Wrap(..., nil) = %v, want nil", err)
	}
}

// TestWrapNilIsNilThroughInterface is the regression guard for Go's typed-nil
// trap, which this package shipped with for one commit.
//
// The test above is NOT sufficient: when Wrap returned *Error, that comparison
// still passed, because comparing a nil *Error against nil is true. The bug only
// appears once the value crosses into an error interface — which is what every
// real caller does. Hence the deliberate round-trip through a function typed to
// return error.
func TestWrapNilIsNilThroughInterface(t *testing.T) {
	// Exactly what an ordinary caller writes.
	doWork := func(cause error) error {
		return Wrap(KindInternal, "doWork", "something", cause)
	}

	if err := doWork(nil); err != nil {
		t.Fatalf("doWork(nil) = non-nil (%v, type %T); Wrap must return the error "+
			"interface, never *Error, or success takes the failure branch", err, err)
	}
	if err := doWork(errors.New("real failure")); err == nil {
		t.Fatal("doWork(cause) = nil; a real cause must survive")
	}
}

// TestKindOfUnclassifiedIsUnknown pins the deliberate choice not to default
// unclassified errors to KindInternal — the gap should be visible in metrics,
// not disguised as a known category.
func TestKindOfUnclassifiedIsUnknown(t *testing.T) {
	if got := KindOf(errors.New("some raw vendor string")); got != KindUnknown {
		t.Errorf("KindOf(unclassified) = %v, want KindUnknown", got)
	}
	if got := KindOf(nil); got != KindUnknown {
		t.Errorf("KindOf(nil) = %v, want KindUnknown", got)
	}
}

// TestGRPCCodeIsTotal ensures no Kind falls through to the default arm by
// accident. KindUnknown and the genuinely-internal kinds are expected to be
// Internal; everything else must have been considered explicitly.
func TestGRPCCodeIsTotal(t *testing.T) {
	expectInternal := map[Kind]bool{
		KindUnknown:     true,
		KindConfig:      true,
		KindInternal:    true,
		KindTargetError: true,
	}
	for _, k := range allKinds {
		got := k.GRPCCode()
		if got == codes.Internal && !expectInternal[k] {
			t.Errorf("Kind %v maps to codes.Internal — likely fell through the default arm", k)
		}
		if got == codes.OK {
			t.Errorf("Kind %v maps to codes.OK, which would report a failure as success", k)
		}
	}
}

// TestUnreachableAndDriftAreDistinguishable is the D50 guard.
//
// §4.9a.7 requires that "server unreachable" and "spec diverged" never collapse
// into one signal: one is an availability event, the other a governance event.
// This test exists so a future simplification that merges them fails loudly
// rather than quietly re-teaching operators to ignore a real alarm.
func TestUnreachableAndDriftAreDistinguishable(t *testing.T) {
	if KindSpecDrift == KindTargetUnavailable {
		t.Fatal("kinds collapsed")
	}
	if KindSpecDrift.GRPCCode() == KindTargetUnavailable.GRPCCode() {
		t.Errorf("drift and unreachable share gRPC code %v — callers cannot tell a governance failure from an availability one",
			KindSpecDrift.GRPCCode())
	}
	if KindSpecDrift.Retryable() {
		t.Error("KindSpecDrift is retryable — a caller would retry a vetting violation forever")
	}
	if !KindTargetUnavailable.Retryable() {
		t.Error("KindTargetUnavailable should be retryable")
	}
}

// TestNonRetryableKinds pins the counter-intuitive answers. Each of these needs
// a human to change something before a retry could possibly succeed.
func TestNonRetryableKinds(t *testing.T) {
	for _, k := range []Kind{
		KindDenied, KindUnauthenticated, KindResidency, KindSpecDrift,
		KindInvalidArgument, KindNotFound, KindConflict, KindBudgetExceeded,
		KindEscalated, KindConfig,
		// THE SHARPEST OF THEM (D182). This kind is handed to a caller BECAUSE
		// the effect may already have landed; a taxonomy that called it
		// retryable would tell an agent to produce the duplicate the refusal
		// exists to prevent.
		KindIndeterminate,
	} {
		if k.Retryable() {
			t.Errorf("Kind %v reported retryable; retrying cannot succeed without external change", k)
		}
	}
}

// TestEveryDeliberateKindHasAVerdict is the guard on the audit record's coarse
// axis, and it is DERIVED rather than written out.
//
// **THE LITERAL VERSION OF THIS TEST CEMENTED A DEFECT FOR MONTHS.** It carried
// a five-entry map — denied, unauthenticated, residency, escalated,
// budget_exceeded — and asserted `Verdict()` matched it exactly. Every kind
// added afterwards joined `Deliberate()` and none joined the map, so the test
// went on passing while `gateway.refuse` recorded refusals of the other seven
// kinds with no verdict, or worse, left an earlier stage's ALLOW standing on a
// command that never ran. The test was named for the direction that was never in
// danger — *"guards against inventing a verdict for a kind that never
// represented a policy decision"* — and it enforced the hole in the other
// direction as though it were the specification. D221's lesson, one package
// over: a guard that restates the code as a literal cannot notice the code is
// wrong, and it makes the wrongness look decided.
//
// The claim now: EVERY deliberate kind has a verdict, because every deliberate
// kind can reach the funnel that records one; no non-deliberate kind has one,
// because a timeout is not a decision and inventing a verdict for it would put a
// fiction in the audit log. One exception, stated in the code and asserted
// below.
func TestEveryDeliberateKindHasAVerdict(t *testing.T) {
	// THE SPECIFIC MAPPINGS, which are the only part that is not derivable: a
	// kind whose verdict is finer than DENY. Absence from this map means DENY
	// rather than meaning nothing, which is the inversion that matters.
	finer := map[Kind]sekizuiv1.Verdict{
		KindEscalated:      sekizuiv1.Verdict_VERDICT_ESCALATE,
		KindBudgetExceeded: sekizuiv1.Verdict_VERDICT_BUDGET_EXCEEDED,
	}

	for _, k := range allKinds {
		got, ok := k.Verdict()

		// KindIndeterminate: DELIBERATE, AND DELIBERATELY WITHOUT A VERDICT.
		// The command was permitted and attempted; what is unknown is whether
		// the effect landed (D182). A verdict of DENY on that row would read as
		// "this did not happen", which is the one thing nobody knows.
		if k == KindIndeterminate {
			if ok {
				t.Errorf("Kind %v has a verdict; an indeterminate OUTCOME is not a "+
					"decision, and stamping one would tell a reader the effect did not "+
					"land when that is precisely what is unknown", k)
			}
			continue
		}

		if k.Deliberate() != ok {
			t.Errorf("Kind %v: Deliberate() = %v but Verdict() ok = %v. A deliberate kind "+
				"reaches gateway.refuse, which records a verdict from this method — so a "+
				"deliberate kind without one is a refusal row that says nothing, or worse "+
				"keeps whatever an earlier stage had set",
				k, k.Deliberate(), ok)
			continue
		}
		if !ok {
			if got != sekizuiv1.Verdict_VERDICT_UNSPECIFIED {
				t.Errorf("Kind %v: Verdict() returned %v with ok=false; must be UNSPECIFIED", k, got)
			}
			continue
		}
		want, isFiner := finer[k]
		if !isFiner {
			want = sekizuiv1.Verdict_VERDICT_DENY
		}
		if got != want {
			t.Errorf("Kind %v: Verdict() = %v, want %v", k, got, want)
		}
	}
}

// TestDeniedAndUnauthenticatedDifferOnTheWire.
//
// Both deny the request and both audit as VERDICT_DENY, but they must remain
// separable to the caller: "we do not know who you are" is fixable by
// presenting a certificate, "we know and the answer is no" is not.
func TestDeniedAndUnauthenticatedDifferOnTheWire(t *testing.T) {
	if KindDenied.GRPCCode() == KindUnauthenticated.GRPCCode() {
		t.Error("denied and unauthenticated share a gRPC code; the confused-deputy defence becomes unauditable")
	}
}

func TestRetryAfterRoundTrips(t *testing.T) {
	err := &Error{Kind: KindRateLimited, Op: "jira.create", RetryAfter: 30 * time.Second}
	wrapped := fmt.Errorf("outer: %w", err)

	if got := RetryAfterOf(wrapped); got != 30*time.Second {
		t.Errorf("RetryAfterOf = %v, want 30s", got)
	}
	// Zero means "no guidance", not "retry immediately".
	if got := RetryAfterOf(New(KindRateLimited, "op", "no header")); got != 0 {
		t.Errorf("RetryAfterOf with no header = %v, want 0", got)
	}
}

func TestErrorMessageIncludesOpAndCause(t *testing.T) {
	err := Wrap(KindTargetError, "jira.create_issue", "unexpected status", errors.New("500"))

	want := "jira.create_issue: target_error: unexpected status: 500"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestDeliberateSeparatesRefusalsFromFailures.
//
// The two are indistinguishable at a call site — both are a non-nil error — so
// code branching on `err != nil` treats a residency refusal like a target being
// down. That shipped: the enforcement path logged both at WARN, which pages an
// operator for the guarantee working correctly.
func TestDeliberateSeparatesRefusalsFromFailures(t *testing.T) {
	classified := map[Kind]bool{
		KindDenied:            true,  // policy said no
		KindResidency:         true,  // §7.1 item 2, refusing on purpose
		KindRateLimited:       true,  // shedding load is the design (§7.1)
		KindBudgetExceeded:    true,  // a cap doing its job
		KindEscalated:         true,  // a human must approve
		KindUnauthenticated:   true,  // no proven caller
		KindInvalidArgument:   true,  // validation working
		KindSpecDrift:         true,  // D48 refuses a diverged surface on purpose
		KindIndeterminate:     true,  // D182: Sekizui declined to repeat the call
		KindTargetUnavailable: false, // the target is down
		KindTargetError:       false,
		KindTimeout:           false,
		KindInternal:          false,
		KindUnavailable:       false,
		// **DELIBERATE SINCE D211.** A driver declining an action it does not
		// implement has DECIDED — nothing was attempted and no far side was
		// contacted — so D135 carries it as a result. Found by the driver
		// conformance suite, which had a caller's typo arriving as a transport
		// failure attributed to Sekizui.
		KindNotFound: true,
		KindConflict: false,
		KindUnknown:  false,

		// **A REFUSAL SINCE D201.** Sekizui decided not to call, so the caller
		// gets a result it can branch on rather than an opaque error — and a
		// decision id naming the row it caused.
		KindConfig: true,

		// Nothing DECIDED this — the credential source is down — so it is a
		// failure and stays a transport error. What keeps it off the target's
		// breaker is its ATTRIBUTION, not its deliberateness (D200).
		KindCredentialUnavailable: false,

		// **A REFUSAL, AND THIS ARM IS LOAD-BEARING RATHER THAN COSMETIC
		// (D213).** The server consulted its own state and rejected the request;
		// it is alive and correct, exactly as a 429 is. `ImplicatesTarget` is
		// `AttributionTarget && !Deliberate()`, so flipping this to false counts
		// every session expiry as a failure against a healthy vendor and opens
		// the breaker on a target doing nothing wrong.
		KindSessionExpired: true,
	}

	for kind, want := range classified {
		if got := kind.Deliberate(); got != want {
			t.Errorf("%v.Deliberate() = %v, want %v", kind, got, want)
		}
	}

	// TOTALITY, asserted rather than assumed. Without this the table is a
	// sample: a kind left out of it is simply not checked, and Deliberate's
	// default arm silently classifies it as a failure — which is safe for a
	// failure and wrong for a refusal. The whole point of the default being
	// FAILURE is that the mistake is loud, and it is only loud if something
	// notices the kind is missing.
	for _, k := range allKinds {
		if _, ok := classified[k]; !ok {
			t.Errorf("Kind %v is not classified above, so Deliberate() is untested for it "+
				"and falls through to the default FAILURE arm", k)
		}
	}
}

// TestEveryKindIsClassified — a kind added without a classification defaults to
// FAILURE, which is the noisy direction. This asserts the default is never
// silently relied upon: every kind that exists is named explicitly above.
//
// Bounded by highestKind() rather than by KindInternal. The hardcoded bound
// excluded the newest kind, which is precisely the one whose classification
// nobody had thought about yet.
func TestEveryKindIsClassified(t *testing.T) {
	for k := KindUnknown; k <= highestKind(); k++ {
		// Deliberate must not panic or fall through for any real kind; the
		// switch above enumerates all of them, so an added kind that nobody
		// classified will fail TestDeliberateSeparatesRefusalsFromFailures
		// rather than pass here by accident.
		_ = k.Deliberate()

		// Naming is NOT re-checked here. TestEveryKindHasAStableName already
		// walks allKinds for an empty name, for the numeric fallback, and for
		// two kinds sharing a name — which is strictly more than this loop was
		// doing. A second assertion of the same property is not defence in
		// depth; it is one more place to update and one more chance for two
		// checks to disagree about which is authoritative.
	}
}

// TestIndeterminateIsNotRetryable is the one-line reason the kind exists, pinned
// so no later tidy-up of Retryable's switch can fold it into a default that
// happens to agree today.
//
// Kept SEPARATE from TestNonRetryableKinds, which lists the counter-intuitive
// answers as a set. This one asserts the pair of properties together — refused
// on purpose AND never retryable — because either alone is satisfiable by an
// accident and the hazard needs both.
func TestIndeterminateIsNotRetryable(t *testing.T) {
	if KindIndeterminate.Retryable() {
		t.Error("KindIndeterminate.Retryable() = true. The kind is handed to a caller " +
			"precisely because the write may already have landed and Sekizui declined " +
			"to repeat it; a retryable classification relocates the double-write " +
			"hazard to the caller, which is the failure D182 exists to close")
	}
	if !KindIndeterminate.Deliberate() {
		// **THE PARENTHETICAL HERE USED TO SAY the in-process reflex path "never
		// sees an error" and "would lose it entirely". Checked under D201: it is
		// not true.** `reflex.fire` returns `Outcome{Err: err}`, so a reflex does
		// see the error. What every caller loses on the error path is narrower
		// and still worth this assertion: the status, the `kind` to branch on,
		// and the decision id naming the audit row it caused.
		t.Error("KindIndeterminate.Deliberate() = false, so D135 would carry it to the " +
			"caller as a transport error — with no kind to branch on and no decision " +
			"id, which for this kind is the whole actionable payload")
	}
	// AND NOT A VERDICT. Sekizui refused to RETRY; policy allowed the command.
	// Inventing a DENY here would put a fiction in the audit log, which is the
	// case Kind.Verdict's contract names.
	if _, ok := KindIndeterminate.Verdict(); ok {
		t.Error("KindIndeterminate claims an audit verdict. Policy ALLOWED this " +
			"command — the refusal is about repeating it — so a verdict here would " +
			"record a policy decision nobody made")
	}
}

// TestIndeterminateIsClassifiedForEveryKind is the totality guard, in the shape
// TestDeliberateSeparatesRefusalsFromFailures established.
//
// It matters more here than for Deliberate, because this default is TRUE. A kind
// added and left unclassified therefore reports an unknown outcome, which sends
// an operator to reconcile against a far side that was never called — noisy in
// the right direction, and still worth being told about.
func TestIndeterminateIsClassifiedForEveryKind(t *testing.T) {
	classified := map[Kind]bool{
		// The call went out and we do not know what it did.
		KindTimeout:           true,
		KindTargetError:       true,
		KindTargetUnavailable: true,
		KindUnknown:           true, // unclassified is not determinate

		// Refused before the call, or answered definitively by the far side.
		KindRateLimited:     false,
		KindDenied:          false,
		KindUnauthenticated: false,
		KindEscalated:       false,
		KindInvalidArgument: false,
		KindNotFound:        false,
		KindConflict:        false,
		KindBudgetExceeded:  false,
		KindResidency:       false,
		KindSpecDrift:       false,
		KindConfig:          false,
		KindUnavailable:     false,
		KindInternal:        false,

		// The answer, not an input to the question.
		KindIndeterminate: false,

		// **THE REQUEST WAS NEVER BUILT.** The credential could not be obtained,
		// so nothing reached the far side and nothing is unknown. The default
		// would say TRUE, which is fail-safe in general and expensive here: a
		// `none`-class action would be abandoned and reconciled by hand when the
		// honest answer is "retry once the source is back".
		KindCredentialUnavailable: false,

		// **THE REQUEST WAS REJECTED BEFORE THE TOOL RAN.** An MCP 404 on a
		// request carrying a session id is the server declining to route it at
		// all, so the outcome is known and a `none`-class action can be retried
		// once the session is re-established. The default would say TRUE and
		// send an operator to reconcile against a far side where nothing
		// happened.
		KindSessionExpired: false,
	}

	for kind, want := range classified {
		if got := kind.Indeterminate(); got != want {
			t.Errorf("%v.Indeterminate() = %v, want %v", kind, got, want)
		}
	}

	for _, k := range allKinds {
		if _, ok := classified[k]; !ok {
			t.Errorf("Kind %v is not classified above, so Indeterminate() is untested "+
				"for it and falls through to the default TRUE arm — every failure of "+
				"that kind will report an unknown outcome", k)
		}
	}
}

// TestIndeterminateAndRetryableAreDifferentQuestions.
//
// THE MISTAKE THE FIRST DRAFT OF D182 MADE, pinned so it cannot come back. The
// gateway's condition was `retry.Retryable(err)`, which reads plausibly and is
// wrong on the most common retryable kind there is: a 429 is retryable AND
// determinate, because the upstream said it declined to act. Had that shipped,
// every rate-limited `none`-class command would have been reported as an unknown
// outcome and had its RetryAfter suppressed.
//
// Asserted as a DISAGREEMENT rather than per-kind, so the test says what it is
// for: if the two predicates ever partition the taxonomy identically, one of
// them is redundant and this is the place that notices.
func TestIndeterminateAndRetryableAreDifferentQuestions(t *testing.T) {
	if !KindRateLimited.Retryable() || KindRateLimited.Indeterminate() {
		t.Errorf("KindRateLimited: retryable = %v, indeterminate = %v; want true, false. "+
			"A 429 is the case that separates the two questions — the far side told us "+
			"it did not act, so coming back later is safe and there is nothing to "+
			"reconcile", KindRateLimited.Retryable(), KindRateLimited.Indeterminate())
	}
	if !KindTimeout.Retryable() || !KindTimeout.Indeterminate() {
		t.Errorf("KindTimeout: retryable = %v, indeterminate = %v; want true, true. "+
			"A deadline says the answer did not arrive, never that the request did "+
			"not — which is D113's founding sentence",
			KindTimeout.Retryable(), KindTimeout.Indeterminate())
	}

	var differ bool
	for _, k := range allKinds {
		if k.Retryable() != k.Indeterminate() {
			differ = true
			break
		}
	}
	if !differ {
		t.Error("Retryable and Indeterminate agree on every kind, so one of them is " +
			"answering a question nobody asked. They are different questions: " +
			"'could a repeat succeed' and 'do we know whether the first one did'")
	}
}

// TestAttributionIsClassifiedForEveryKind is D200's totality guard, in the shape
// the other three axes already use.
//
// **THE DEFAULT IS `unknown`, WHICH IS THE SAFE DIRECTION AND A USELESS ONE.** A
// kind nobody attributed never implicates the target, so it cannot manufacture a
// false outage — and it also tells an operator nothing about where to look. That
// is exactly the trade the other totality tests exist to stop being made
// silently.
func TestAttributionIsClassifiedForEveryKind(t *testing.T) {
	classified := map[Kind]Attribution{
		// The caller's request, or a decision about it.
		KindInvalidArgument: AttributionCaller,
		KindDenied:          AttributionCaller,
		KindEscalated:       AttributionCaller,
		KindBudgetExceeded:  AttributionCaller,
		KindResidency:       AttributionCaller,
		KindIndeterminate:   AttributionCaller,

		// This deployment, or this process.
		KindConfig:      AttributionSekizui,
		KindInternal:    AttributionSekizui,
		KindUnavailable: AttributionSekizui,
		// CALLER SINCE D211: the sites that meant "our configuration points at
		// nothing" moved to KindConfig, so what is left is a caller naming
		// something that does not exist.
		KindNotFound: AttributionCaller,

		// The credential, or where it comes from.
		KindUnauthenticated:       AttributionCredential,
		KindCredentialUnavailable: AttributionCredential,

		// The external system.
		KindTargetUnavailable: AttributionTarget,
		KindTargetError:       AttributionTarget,
		KindTimeout:           AttributionTarget,
		KindConflict:          AttributionTarget,
		KindRateLimited:       AttributionTarget,
		KindSpecDrift:         AttributionTarget,
		// THE TARGET'S STATE, not ours and not the credential's (D213). It is
		// the far side that forgot the session; attributing it to the credential
		// — the tempting alternative, since `unauthenticated` is where a
		// rejected bearer lands — would make `needsAHuman` log a routine expiry
		// loudly and would count it as credential churn.
		KindSessionExpired: AttributionTarget,

		KindUnknown: AttributionUnknown,
	}

	for kind, want := range classified {
		if got := kind.Attribution(); got != want {
			t.Errorf("%v.Attribution() = %v, want %v", kind, got, want)
		}
	}

	for _, k := range allKinds {
		if _, ok := classified[k]; !ok {
			t.Errorf("Kind %v is not classified above, so Attribution() is untested for "+
				"it and falls through to `unknown` — which never implicates the target, "+
				"and never tells an operator which system to go and look at", k)
		}
	}
}

// TestOnlyTheTargetImplicatesTheTarget is the property the breaker depends on,
// and the one whose absence was the defect (D200).
//
// **TWO CONDITIONS, AND BOTH ARE LOAD-BEARING.** A fault must be attributed to
// the target AND not be a deliberate refusal before it counts. Dropping the
// first lets a broken local configuration or an unreachable token endpoint open
// the breaker on a healthy system; dropping the second turns a rate limit into
// an outage, which is D141's original point.
func TestOnlyTheTargetImplicatesTheTarget(t *testing.T) {
	for _, k := range allKinds {
		implicates := k.ImplicatesTarget()

		if implicates && k.Attribution() != AttributionTarget {
			t.Errorf("%v implicates the target while attributed to %v, so a fault "+
				"somewhere else opens the target's breaker", k, k.Attribution())
		}
		if implicates && k.Deliberate() {
			t.Errorf("%v implicates the target and is a deliberate refusal. A 429 or an "+
				"upstream denial means the target is ALIVE; counting it would turn a "+
				"rate limit into an outage (D141)", k)
		}
	}

	// NON-VACUITY: something must implicate the target, or the guard above is
	// satisfied by a predicate that always returns false.
	if !KindTargetError.ImplicatesTarget() {
		t.Error("a 500 from the target does not implicate the target, so the breaker " +
			"has nothing left to open and every arm above passes for the wrong reason")
	}
	// AND THE THREE THAT MUST NOT.
	for _, k := range []Kind{KindCredentialUnavailable, KindConfig, KindUnauthenticated} {
		if k.ImplicatesTarget() {
			t.Errorf("%v implicates the target. A credential or configuration fault "+
				"must not degrade a system that is answering perfectly well", k)
		}
	}
	// A 429 IS THE TARGET'S AND IS STILL NOT A FAILURE.
	if KindRateLimited.ImplicatesTarget() {
		t.Error("a 429 implicates the target: it means the target is alive and talking")
	}
}
