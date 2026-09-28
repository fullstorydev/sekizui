// Package fault is the shared error taxonomy.
//
// PUBLIC API (D35), and necessarily so. The connector definition-of-done
// (CONTRACTS §5) requires every driver to map its errors "to the shared
// taxonomy, not raw vendor strings" — and third parties write drivers. Go's
// internal/ is compiler-enforced, not a convention, so a taxonomy in
// internal/obs would be literally unimportable by the people obliged to use it.
// DESIGN §11 lists it under internal/obs/; that placement is wrong and this
// package supersedes it.
//
// The predecessor is Lexicon's ERROR_TYPES (lexicon/loggerFramework.js:16),
// a flat map of eight strings: VALIDATION, DATABASE, NETWORK, API, CONFIG, AUTH,
// PERMISSION, INTERNAL. It was string-typed, so a typo produced a new category
// silently, and it carried no mapping to anything — each call site decided for
// itself what an ApiError meant to a caller.
//
// DESIGN.md references: §4.1.1, §4.3.4, §4.9a.7, §5.4, D23, D29, D48, D50.
package fault

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Kind is one category in the taxonomy.
//
// Kind ITSELF IMPLEMENTS error, which is why there are no separate sentinel
// values to keep in sync with it. errors.Is(err, fault.KindDenied) works
// because *Error.Is compares kinds. This mirrors how the standard library
// treats syscall.Errno — a comparable scalar that is also an error.
//
// Coming from Java or C#, the reflex would be an exception hierarchy with
// DeniedException extending SekizuiException. Go has no exception types and no
// inheritance; the equivalent expressiveness comes from a comparable value plus
// errors.Is, which additionally survives wrapping across package boundaries in
// a way that catch-by-type does not.
type Kind uint8

// NUMERIC VALUES ARE ASSIGNED EXPLICITLY, NOT BY iota.
//
// With iota, inserting a kind in the middle silently renumbers every kind after
// it. That is harmless while the values live only in memory, and dangerous the
// moment one is written down — an audit warehouse holds decision records for
// years, and a row saying "kind 9" would change meaning under a later insertion
// with nothing to detect it.
//
// Explicit values make an accidental renumber impossible, and
// TestKindNumbersAreStable pins them so a deliberate one has to be deliberate.
//
// Even so: PERSIST Kind.String(), NEVER THE NUMBER. The string is the stable
// external identifier (kindNames), the number is an implementation detail.
// ParseKind reads it back.
const (
	// KindUnknown is the zero value and always a bug: something produced an
	// Error without classifying it. Mapped to Internal deliberately, so an
	// unclassified failure is loud rather than quietly benign.
	KindUnknown Kind = 0

	// --- caller's fault -----------------------------------------------------

	// KindInvalidArgument covers malformed requests and payloads failing their
	// registered JSON Schema (D40). Lexicon's VALIDATION.
	KindInvalidArgument Kind = 1

	// KindUnauthenticated means identity could not be established: no client
	// certificate, an unverifiable one, or a subject asserted by a caller with
	// no may_speak_for grant covering it (§4.4.1). Lexicon's AUTH.
	//
	// Distinct from KindDenied: this is "we do not know who you are", not "we
	// know exactly who you are and the answer is no". Conflating them makes the
	// confused-deputy defence unauditable.
	KindUnauthenticated Kind = 2

	// KindDenied means policy evaluated and refused. Lexicon's PERMISSION.
	//
	// These rows are the highest-value records in the audit log (§5.4): "agent X
	// tried to delete a project and was refused" is the sentence that justifies
	// this service existing.
	KindDenied Kind = 3

	// KindEscalated means policy returned ESCALATE — not refused, awaiting a
	// human. Not an error in the moral sense, but it terminates the request, so
	// it travels the error path rather than being a second return value that
	// every call site would have to remember to check.
	KindEscalated Kind = 4

	// KindNotFound is an unknown target ref, action, or tool.
	KindNotFound Kind = 5

	// KindConflict is an idempotency collision: the same key seen again with
	// different arguments. Distinct from a benign replay, which is a success.
	KindConflict Kind = 6

	// --- limits -------------------------------------------------------------

	// KindRateLimited is a local limiter refusal or an upstream 429 (§4.3.4).
	// Carries RetryAfter when the upstream supplied one.
	KindRateLimited Kind = 7

	// KindBudgetExceeded is a reflex firing budget being exhausted — a hard stop
	// plus alert, deliberately distinct from rate limiting, which merely smooths
	// (§4.11.4). Maps to VERDICT_BUDGET_EXCEEDED so a tripped guard is recorded
	// even for bus->bus reflexes that otherwise skip decision records (D23).
	KindBudgetExceeded Kind = 8

	// --- governance ---------------------------------------------------------

	// KindResidency is a residency conflict between a target and the instance
	// region. Refuses rather than warns (D29 item 2).
	//
	// Separate from KindDenied even though both refuse, because the remedy is
	// completely different: a denial is a grant to review, a residency conflict
	// is a deployment topology problem, and an operator reading the audit log
	// should not have to infer which.
	KindResidency Kind = 9

	// KindSpecDrift means a target's live surface diverged from its vetted spec
	// — an MCP server whose inputSchema no longer matches what was reviewed
	// (D48).
	//
	// THE WHOLE POINT OF THIS KIND is to stay distinguishable from
	// KindTargetUnavailable. Both end in "this target cannot be used", and D50
	// requires that they never collapse into one signal: unreachable is an
	// availability event, drift is a governance event. Two kinds is the
	// mechanism that keeps that distinction real instead of aspirational.
	KindSpecDrift Kind = 10

	// --- the far side -------------------------------------------------------

	// KindTargetUnavailable means the external system could not be reached:
	// connection refused, DNS failure, TLS failure, 503. Lexicon's NETWORK.
	// We learned nothing about the target except that it is not answering.
	KindTargetUnavailable Kind = 11

	// KindTargetError means the external system was reached and failed:
	// a 500, or a semantically invalid response. Lexicon's API. We learned
	// something specific, and it was bad.
	KindTargetError Kind = 12

	// KindTimeout is a deadline or context cancellation. Every outbound call has
	// one; there is no unbounded wait (CONTRACTS §5).
	KindTimeout Kind = 13

	// --- ours ---------------------------------------------------------------

	// KindConfig is malformed or incoherent configuration, including a
	// RuntimeProfile whose assertions do not hold (§4.10.2). Lexicon's CONFIG.
	// Almost always fatal at boot rather than returned to a caller.
	KindConfig Kind = 14

	// KindUnavailable means Sekizui itself is not ready to serve — config not
	// yet loaded, still initialising. The clean 503 that §4.10.3 wants instead
	// of a crash or a hang.
	KindUnavailable Kind = 15

	// KindInternal is our bug. Lexicon's INTERNAL.
	KindInternal Kind = 16

	// --- ours, about somebody else's state ----------------------------------

	// KindIndeterminate means the call went out, the outcome is UNKNOWN, and
	// Sekizui will not find out by repeating it (D182, D163).
	//
	// THE CALLER'S SITUATION, NOT SEKIZUI'S DECISION, and the name says so
	// deliberately. `not_retryable` would have named our internal answer; what a
	// caller has to act on is that a write may or may not have landed and nobody
	// can tell from here. The remedy is a human reconciling against the far side,
	// which is different work from every other kind in this taxonomy.
	//
	// **WHY THE TAXONOMY NEEDED AN EIGHTEENTH MEMBER.** A `none`-class action
	// (D163) that times out is refused a retry, correctly — and every existing
	// kind that could carry that refusal to the caller either invites the retry
	// or misdescribes what happened. KindTimeout is Retryable, so a well-behaved
	// caller consulting the taxonomy retries and produces the duplicate the
	// refusal existed to prevent: the hazard is not removed, it is relocated one
	// hop out, to an agent that has no idempotency-class table. KindConflict
	// means a key collided. KindDenied means policy said no, which is a lie about
	// a command policy allowed.
	//
	// DELIBERATE (see Deliberate), because Sekizui refused on purpose, so D135
	// makes it a RESULT rather than an error. NOT Retryable, which is the entire
	// reason it exists. And NOT Indeterminate's own producer: the CAUSE is
	// wrapped, so errors.Is still finds the timeout underneath and the audit row
	// carries both facts.
	KindIndeterminate Kind = 17

	// KindCredentialUnavailable — the credential could not be OBTAINED from its
	// source (D200).
	//
	// **DELIBERATELY WIDER THAN "UNREACHABLE".** It covers a token endpoint that
	// cannot be reached, one that answers with something yielding no credential,
	// and a secret that cannot be resolved. The distinction the taxonomy needs
	// here is not how the source failed but WHOSE failure it is — splitting it
	// into an unavailable/error pair the way the target has would add a kind to
	// carry a difference nothing acts on.
	//
	// **A TOKEN ENDPOINT OR A SECRET MANAGER BEING DOWN IS NOT THE TARGET BEING
	// DOWN, AND THE TAXONOMY COULD NOT SAY SO.** `pkg/provider/oauth` mapped an
	// unreachable token endpoint to KindTargetUnavailable, which is not
	// deliberate — so the breaker recorded a FAILURE against a target that was
	// healthy and never contacted. One IdP blip therefore opened the breaker on
	// every target whose credential chained through it, turning a credential
	// hiccup into a fleet-wide outage with every log line naming the innocent
	// party.
	//
	// RETRYABLE, because a source that is down usually comes back, and NOT
	// deliberate, because nothing decided this — it is a genuine failure, just
	// not the target's. Its attribution is what keeps it off the breaker.
	KindCredentialUnavailable Kind = 18

	// KindSessionExpired — the far side discarded the CONNECTION STATE we
	// established with it, and says so (D213).
	//
	// **ADDED ONLY AFTER D200'S TEST WAS APPLIED TO IT, because D200's own
	// finding was that the gap it was asked about turned out to be a conflated
	// PREDICATE rather than a missing kind.** The three predicates were checked
	// first and none of them needed changing: this is deliberate (the server
	// answered), attributed to the target, and therefore already off the
	// breaker — the same {deliberate, target} pair `rate_limited` and
	// `spec_drift` occupy. So the case for a new kind rests entirely on the
	// NAME, and D138 is the precedent that a name can be worth it: `kind`
	// exists beside `status` precisely so a reflex engine can separate
	// conditions the coarse answer merges.
	//
	// **AND HERE THE MERGE WOULD BE ACTIVELY WRONG.** The nearest existing kind
	// with the right predicates is `spec_drift`, and routing a session expiry
	// through it would fire every anzen rule watching for drift — quarantining
	// a target because a server did what servers routinely do. `unauthenticated`
	// is the other temptation and is worse in a quieter way: it is attributed
	// to the CREDENTIAL, so `needsAHuman` logs it loudly, `credential_churn`
	// counts it, and a rule watching that signal quarantines a target whose
	// credential was never in question. The remediations differ too — re-mint a
	// secret against re-run a handshake — and D204's loop has to tell them
	// apart to do either.
	//
	// NOT INDETERMINATE: an MCP 404 on a request carrying a session id is a
	// rejection before the tool runs, so the outcome is known. NOT RETRYABLE on
	// its own, for `unauthenticated`'s reason — repeating the same request with
	// the same dead session reproduces the same answer. It becomes viable only
	// after re-establishment, which is a different mechanism and is bounded by
	// `reestablish_attempts` rather than by the retry policy.
	KindSessionExpired Kind = 19
)

// Attribution says WHOSE fault a Kind describes.
//
// **THE AXIS THE TAXONOMY WAS MISSING, and its absence was a live defect rather
// than an untidiness (D200).** Every Kind says WHAT happened; the breaker and
// the log level need to know ABOUT WHOM, and both were deriving it from
// `Deliberate()` — a predicate that answers a different question (D135's wire
// shape) and happened to agree often enough to look right.
//
// **FOUR PARTIES, AND ONLY THREE WERE EXPRESSIBLE.** A caller sends a bad
// request; Sekizui is misconfigured or broken; the target fails; and the
// CREDENTIAL SOURCE — a token endpoint, a secret manager — fails. The fourth
// collapsed into the third, which is how an IdP outage came to open a healthy
// target's breaker.
type Attribution uint8

const (
	// AttributionUnknown — nothing classified it. Treated as NOT implicating the
	// target, which is the direction that cannot manufacture a false outage.
	AttributionUnknown Attribution = iota

	// AttributionCaller — the request was wrong. A denial, a bad argument, a
	// budget the caller has exhausted.
	AttributionCaller

	// AttributionSekizui — this deployment is misconfigured or this process is
	// broken. Nothing the caller or the target can do about it, and always worth
	// waking somebody: these are the faults that persist until a human acts.
	AttributionSekizui

	// AttributionTarget — the external system failed, refused or timed out.
	// **THE ONLY ONE THE BREAKER MAY COUNT.**
	AttributionTarget

	// AttributionCredential — the credential or its source is the problem: an
	// unreachable token endpoint, a secret that cannot be resolved, material
	// that cannot be placed. Deliberately NOT the target, and deliberately not
	// merely "Sekizui" either — the distinction is the one an operator needs to
	// know which system to go and look at.
	AttributionCredential
)

//nolint:gochecknoglobals // immutable vocabulary, fixed at compile time
var attributionNames = map[Attribution]string{
	AttributionUnknown:    "unknown",
	AttributionCaller:     "caller",
	AttributionSekizui:    "sekizui",
	AttributionTarget:     "target",
	AttributionCredential: "credential",
}

func (a Attribution) String() string {
	if s, ok := attributionNames[a]; ok {
		return s
	}
	return fmt.Sprintf("attribution(%d)", uint8(a))
}

// Attribution reports whose fault this kind describes.
//
// **STATIC PER KIND, WHICH IS A DELIBERATE LIMIT.** An error could carry an
// override — `RetryAfter` already sets that precedent — and one is NOT provided
// until a case needs it, because an optional field is a field somebody forgets
// and the default would then be silently wrong. Where a kind is genuinely
// ambiguous, the default is the one that CANNOT manufacture a false outage: not
// the target.
func (k Kind) Attribution() Attribution {
	switch k {
	case KindInvalidArgument, KindDenied, KindEscalated, KindBudgetExceeded,
		KindResidency, KindIndeterminate, KindNotFound:
		// The caller's request, or a decision about it. Indeterminate belongs
		// here because the CALLER is who must act on it — reconcile, do not
		// repeat — and the target did nothing wrong.
		//
		// **KindNotFound MOVED HERE WHEN ITS SITES WERE DISAMBIGUATED (D211).**
		// It used to sit under Sekizui with a comment calling it "the ambiguous
		// one", placed there on the safe-direction rule because it covered an
		// unknown ACTION (the caller's fault) and an unknown TARGET REF (this
		// deployment's) and the target must not wear either. That default was
		// the right call while one kind meant two things; the fix was to stop it
		// meaning two things. The sites that mean "our configuration points at
		// nothing" — the resolver's missing target, the withdrawal path's
		// unconfigured one — return KindConfig now, and what is left is a caller
		// naming something that does not exist.
		return AttributionCaller

	case KindConfig, KindInternal, KindUnavailable:
		return AttributionSekizui

	case KindUnauthenticated, KindCredentialUnavailable:
		// **A 401 MEANS THE TARGET IS ALIVE AND ANSWERING**, and it means the
		// credential is wrong. Attributing it to the credential rather than to
		// the target is right in both directions this arises from: the far side
		// rejecting what we sent, and D199's refusal to send material that
		// cannot be a header value.
		return AttributionCredential

	case KindTargetUnavailable, KindTargetError, KindTimeout, KindConflict,
		KindRateLimited, KindSpecDrift, KindSessionExpired:
		// **RATE-LIMITED AND SPEC-DRIFT ARE THE TARGET'S, AND THEY ARE NOT
		// FAILURES.** Attribution says whose, not how bad; the breaker still
		// declines to count a deliberate refusal, because a 429 means the target
		// is alive. Keeping the two questions apart is the whole point.
		return AttributionTarget

	default:
		return AttributionUnknown
	}
}

// ImplicatesTarget reports whether this kind is evidence that the TARGET is
// unhealthy.
//
// **THE BREAKER'S QUESTION, AND IT USED TO ASK A DIFFERENT ONE.** It keyed on
// `Deliberate()`, which decides the wire shape — so anything not deliberate
// counted against the target, including a broken local configuration and an
// unreachable token endpoint. Both open a breaker on a system that is fine.
//
// A DELIBERATE REFUSAL IS STILL NOT A FAILURE (D141): a 429 or an upstream
// denial means the target is alive and talking, and counting those would turn a
// rate limit into an outage. So the breaker records a failure only when the
// fault is BOTH attributed to the target and not a deliberate refusal.
func (k Kind) ImplicatesTarget() bool {
	return k.Attribution() == AttributionTarget && !k.Deliberate()
}

// kindNames are stable identifiers. Deliberately not derived from the constant
// names: these appear in metrics labels and audit rows, so renaming a Go
// constant must not silently repartition a dashboard or break a saved query.
//
// §6 item 4 bans package-level MUTABLE state; the hazard it names is state
// shared across tenants and across tests. This is an immutable lookup table,
// written once at compile time and never assigned to. Rebuilding it inside
// String() would allocate an 18-entry map on every log line and every metric
// increment — a real cost to satisfy a rule aimed at a different problem.
//
//nolint:gochecknoglobals // immutable lookup table; see above
var kindNames = map[Kind]string{
	KindUnknown:           "unknown",
	KindInvalidArgument:   "invalid_argument",
	KindUnauthenticated:   "unauthenticated",
	KindDenied:            "denied",
	KindEscalated:         "escalated",
	KindNotFound:          "not_found",
	KindConflict:          "conflict",
	KindRateLimited:       "rate_limited",
	KindBudgetExceeded:    "budget_exceeded",
	KindResidency:         "residency",
	KindSpecDrift:         "spec_drift",
	KindTargetUnavailable: "target_unavailable",
	KindTargetError:       "target_error",
	KindTimeout:           "timeout",
	KindConfig:            "config",
	KindUnavailable:       "unavailable",
	KindInternal:          "internal",
	KindIndeterminate:     "indeterminate",

	KindCredentialUnavailable: "credential_unavailable",
	KindSessionExpired:        "session_expired",
}

// String returns the stable identifier used in metrics and audit records.
//
// THIS, NOT THE NUMBER, IS WHAT GETS WRITTEN DOWN. Audit rows outlive the code
// that produced them by years; a persisted integer would silently change meaning
// under any renumbering, while a persisted name cannot.
func (k Kind) String() string {
	if n, ok := kindNames[k]; ok {
		return n
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// kindsByName is the reverse of kindNames, built once at init.
//
// Derived rather than written out twice: two hand-maintained maps are two
// chances to disagree, which is precisely the Lexicon failure this package
// exists to avoid (two divergent lists, loggerFramework.js:216 and
// initialization.js:218).
//
// Immutable, derived once from kindNames at init. Same reasoning as kindNames
// above: the ban targets mutable shared state, not compile-time lookup tables.
//
//nolint:gochecknoglobals // immutable lookup table; see above
var kindsByName = func() map[string]Kind {
	m := make(map[string]Kind, len(kindNames))
	for k, n := range kindNames {
		m[n] = k
	}
	return m
}()

// ParseKind reads back a Kind persisted as its String form.
//
// Returns KindUnknown and false for anything unrecognised — including a name
// retired by a later version, which is a real case when reading old audit rows.
// The caller decides whether that is tolerable; this function does not guess.
func ParseKind(s string) (Kind, bool) {
	k, ok := kindsByName[s]
	return k, ok
}

// Error lets a Kind be used directly as a sentinel: errors.Is(err, KindDenied).
func (k Kind) Error() string { return k.String() }

// GRPCCode maps to the transport. Defined here rather than at the transport
// boundary so there is exactly one mapping: a per-call-site translation is how
// two callers end up disagreeing about what a rate limit looks like on the wire.
//
// The cost is that this package imports grpc/codes, so a third-party driver
// pulls in gRPC. Acceptable — it is already a module dependency, and the
// serving surface is gRPC by decision (CONTRACTS §2).
func (k Kind) GRPCCode() codes.Code {
	switch k {
	case KindInvalidArgument:
		return codes.InvalidArgument
	case KindUnauthenticated:
		return codes.Unauthenticated
	case KindDenied, KindResidency:
		// Revocation is PermissionDenied rather than Aborted or Canceled, both
		// of which invite a retry. By the time this reaches a caller the
		// permission really is gone: the material is evicted and the next
		// resolution fails closed, so retrying can only produce this again.
		return codes.PermissionDenied
	case KindEscalated:
		// Not an error condition — the request is well-formed and permitted in
		// principle, but a precondition (human approval) is unmet.
		return codes.FailedPrecondition
	case KindNotFound:
		return codes.NotFound
	case KindConflict:
		return codes.Aborted
	case KindRateLimited, KindBudgetExceeded:
		return codes.ResourceExhausted
	case KindSpecDrift:
		// Deliberately NOT Unavailable. A caller retrying drift will retry
		// forever; the condition needs a human to review a diff.
		return codes.FailedPrecondition
	case KindSessionExpired:
		// **THE SAME CODE FOR A DIFFERENT REASON, AND THE REASON MATTERS.** A
		// caller only ever SEES this kind when re-establishment did not fix it —
		// it was switched off, or it had already been spent — so by the time this
		// crosses the wire, retrying really does need something else to change
		// first. Unavailable would be read by a stock gRPC client as "come back
		// shortly", which is how a dead session becomes a retry loop against a
		// server that is answering every one of them correctly.
		return codes.FailedPrecondition
	case KindIndeterminate:
		// THE SAME REASONING AS DRIFT, and the same code. DeadlineExceeded — the
		// code the underlying timeout would have carried — is one gRPC clients
		// retry by default, which would drive the duplicate write this kind
		// exists to prevent straight through a stock interceptor. Aborted is the
		// other candidate and is worse: gRPC documents it as retryable at a
		// higher level, so it says the opposite of what is meant. The condition
		// needs a human to reconcile against the far side, which is what
		// FailedPrecondition's "do not retry until the state is explicitly
		// fixed" already means.
		return codes.FailedPrecondition
	case KindTargetUnavailable, KindUnavailable, KindCredentialUnavailable:
		return codes.Unavailable
	case KindTargetError:
		return codes.Internal
	case KindTimeout:
		return codes.DeadlineExceeded
	case KindConfig, KindInternal, KindUnknown:
		return codes.Internal
	default:
		return codes.Internal
	}
}

// Status maps to the command-result wire enum (command.proto).
//
// The wire enum is deliberately coarser than the taxonomy: a caller needs to
// know "denied" versus "the far side broke", while an operator reading audit
// rows needs to know which of six ways it broke. Collapsing happens here, once.
func (k Kind) Status() sekizuiv1.Status {
	switch k {
	case KindDenied, KindUnauthenticated, KindResidency:
		return sekizuiv1.Status_STATUS_DENIED
	case KindInvalidArgument, KindNotFound:
		// Deliberate, so D135 makes it a RESULT — and until D138 it fell to the
		// default and reached callers as STATUS_UNSPECIFIED, which is the zero
		// value meaning "nobody set this". Two live paths produced it: restoring
		// a target nobody withdrew (D133) and firing something that is not an
		// anzen rule (D134). Both are refusals a client must be able to act on.
		//
		// **KindNotFound SHARES IT RATHER THAN GETTING ITS OWN (D211), and this
		// enum's own comment is the argument.** STATUS_INVALID_ARGUMENT is for a
		// request "well-formed enough to reach the enforcement path and wrong
		// enough to refuse", and is "a request to correct" rather than "a grant
		// to review" — which is exactly a caller naming an action, a lens or a
		// rule that does not exist. It even lists `fire_anzen` naming something
		// that is not a rule, one of the sites this kind serves. D138 argues
		// against mirroring the taxonomy into this enum, and a NOT_FOUND member
		// would be that: the coarse answer a caller branches on is identical.
		return sekizuiv1.Status_STATUS_INVALID_ARGUMENT
	case KindEscalated:
		return sekizuiv1.Status_STATUS_ESCALATED
	case KindConfig:
		// D201. Deliberate, so D135 makes it a RESULT — and with no case here it
		// would reach callers as STATUS_UNSPECIFIED, which is D138's exact bug
		// arriving through a kind that had just changed shape.
		return sekizuiv1.Status_STATUS_MISCONFIGURED
	case KindRateLimited, KindBudgetExceeded:
		return sekizuiv1.Status_STATUS_RATE_LIMITED
	case KindTargetUnavailable, KindTargetError, KindTimeout, KindSpecDrift,
		KindIndeterminate, KindSessionExpired:
		// INDETERMINATE COLLAPSES INTO TARGET_ERROR, and the collapse is a
		// deliberate trade rather than an oversight. The coarse answer a caller
		// branches on is "this command did not report success", which is true; the
		// actionable half — do not repeat this, and go and look — is carried by
		// `kind`, which is the field D138 added because Status is deliberately
		// coarser than the taxonomy. A new Status member would create a second
		// vocabulary to keep in step with fault.Kind, which is exactly what
		// CommandResult.kind's own contract argues against.
		//
		// The residual cost, stated: a caller reading only `status` may infer
		// "the far side failed, so nothing happened". That inference is already
		// available to it for a plain timeout, which is equally indeterminate —
		// so this does not make the coarse view less honest than it was, and the
		// finer view is now strictly better.
		return sekizuiv1.Status_STATUS_TARGET_ERROR
	default:
		return sekizuiv1.Status_STATUS_UNSPECIFIED
	}
}

// Verdict maps to the audit enum, for the kinds that represent a policy
// outcome. The bool is false for kinds that are not policy decisions at all —
// a timeout has no verdict, and inventing one would put a fiction in the
// audit log.
//
// **THE VERDICT AXIS IS COARSE ON PURPOSE, AND THAT IS WHY MOST OF THESE
// COLLAPSE INTO DENY.** It already collapses a policy denial, an unauthenticated
// caller and a residency ceiling into one word, and D138's argument applies
// unchanged: the fine answer belongs in `kind`, which shares a vocabulary with
// the metric label and the wire result, and a second enum member per kind would
// be a second taxonomy to keep in step with this one.
//
// **KindIndeterminate IS DELIBERATELY ABSENT, AND ITS ABSENCE IS LOAD-BEARING.**
// An indeterminate outcome is not a refusal to permit — the command WAS
// permitted, the call was made, and what is unknown is whether the effect
// landed (D182). Mapping it here would stamp DENY on a row for a write that may
// well have happened, which is the worst available lie for an audit log to tell:
// it reads as "this did not occur". It reaches the caller through
// `refusalResult` on the OUTCOME path, where the intent row's ALLOW is correct
// and the Effect carries the truth. If it ever arrives at the pre-call funnel
// that consumes this method, the floor there is DENY and this comment is the
// reason that is a bug rather than a default.
func (k Kind) Verdict() (sekizuiv1.Verdict, bool) {
	switch k {
	case KindEscalated:
		return sekizuiv1.Verdict_VERDICT_ESCALATE, true
	case KindBudgetExceeded:
		return sekizuiv1.Verdict_VERDICT_BUDGET_EXCEEDED, true
	case KindIndeterminate:
		// THE ONE STATED EXCEPTION, for the reason above. It is deliberate and
		// it has no verdict, because it is an OUTCOME rather than a decision.
		return sekizuiv1.Verdict_VERDICT_UNSPECIFIED, false
	}

	// **DERIVED FROM Deliberate(), NOT ENUMERATED — AND THE ENUMERATION IS WHAT
	// WAS BROKEN.** The list used to read `KindDenied, KindUnauthenticated,
	// KindResidency`, which left SEVEN of the deliberate kinds answering "no
	// verdict": invalid_argument, not_found, rate_limited, spec_drift, config,
	// session_expired and indeterminate. `gateway.refuse` consults this method
	// and nothing else, so for those kinds it left the field exactly as the
	// earlier stages had set it — nothing before policy, and ALLOW after it. One
	// acceptance run produced three rows reading `VERDICT_ALLOW` with
	// `refused_by` set and a `matched_rule` naming the grant that "authorised"
	// commands that never ran, plus one row with no verdict at all.
	//
	// A list of kinds and a predicate over kinds are the same question asked
	// twice, and the list is the copy that rots: every kind added since this
	// method was written joined `Deliberate()` and none of them joined here.
	// Derived, a kind added at P5 is covered by the decision that makes it
	// deliberate, which is the decision that means it can arrive here at all.
	//
	// D138 found the identical hole in `Kind.Status()` and added
	// STATUS_INVALID_ARGUMENT for it. The audit record was the third view, and
	// nobody counted it.
	if k.Deliberate() {
		return sekizuiv1.Verdict_VERDICT_DENY, true
	}
	return sekizuiv1.Verdict_VERDICT_UNSPECIFIED, false
}

// Indeterminate reports whether a failure of this kind leaves the caller unable
// to tell whether the effect happened (D182).
//
// CENTRALISED HERE FOR THE REASON Retryable IS: it is a property of the FAILURE,
// and three drivers answering it independently is how they come to disagree.
// It is a different question from Retryable and the two must not be conflated —
// which is the mistake the first draft of D182 made.
//
// **A 429 IS RETRYABLE AND NOT INDETERMINATE.** The upstream told us it declined
// to act, so the effect is KNOWN not to have happened and a later attempt is
// safe. **A TIMEOUT IS BOTH.** We learned nothing about which side of the write
// it died on, which is D113's founding sentence. Treating the two alike in
// either direction is a defect: call a 429 indeterminate and Sekizui reports an
// unknown outcome for a command that demonstrably did not run, sending an
// operator to reconcile nothing; call a timeout determinate and a caller is told
// the write did not land when it may well have.
//
// THE DEFAULT IS TRUE, and it is the only predicate in this file whose default
// is. An unclassified driver error is one we know nothing about, and "we know
// nothing" IS the indeterminate answer — so the default is the honest reading
// rather than a cautious one. The cost is a spurious "go and check" on a kind
// nobody classified, which is the noisy direction; the alternative is telling a
// caller the write did not happen on no evidence at all.
func (k Kind) Indeterminate() bool {
	switch k {
	case KindTimeout:
		// THE CANONICAL CASE. A deadline says the answer did not arrive, never
		// that the request did not.
		return true
	case KindTargetError:
		// A 500 means the upstream was REACHED and broke. It may have applied
		// the write and failed afterwards, and a partially-applied write is the
		// worst version of this: the audit row would say the command failed while
		// the far side holds the effect.
		return true
	case KindTargetUnavailable:
		// The kind's own contract is "we learned nothing about the target except
		// that it is not answering", and learning nothing is indeterminate. It
		// spans a connection refused before any bytes moved — determinate, and
		// benignly misreported here — and a 503 from a proxy that had already
		// forwarded the request, which is not.
		return true
	case KindRateLimited:
		// AN EXPLICIT REFUSAL FROM THE FAR SIDE. The quota was consulted and the
		// request was not served. Nothing happened, and RetryAfter says when to
		// come back.
		return false
	case KindUnknown:
		// Reached via the default in practice; named here so the totality test
		// covers it and so the reasoning is written down. An unclassified error
		// is not a determinate one.
		return true
	case KindInvalidArgument, KindUnauthenticated, KindDenied, KindEscalated,
		KindNotFound, KindConflict, KindBudgetExceeded, KindResidency,
		KindSpecDrift, KindConfig, KindUnavailable, KindInternal,
		KindIndeterminate, KindCredentialUnavailable, KindSessionExpired:
		// **`KindCredentialUnavailable` BELONGS HERE AND THE DEFAULT WOULD HAVE
		// SAID OTHERWISE.** The credential could not be obtained, so the request
		// was never built and nothing can have happened at the far side. The
		// default is TRUE for the fail-safe reason, and here it would be a lie in
		// the expensive direction — a `none`-class action abandoned and
		// reconciled by hand when the honest answer is "retry once the secret
		// manager is back".
		//
		// EVERY ONE OF THESE IS A REFUSAL BEFORE THE CALL WENT OUT, or a
		// definitive answer from the far side. Nothing was attempted, so nothing
		// is unknown. KindIndeterminate itself is false: it is the ANSWER to this
		// question and not an input to it, and returning true would let a wrap of
		// a wrap read as a fresh unknown outcome.
		return false
	default:
		return true
	}
}

// Deliberate reports whether this kind is the system REFUSING something on
// purpose, as opposed to something having gone wrong.
//
// THE DISTINCTION MATTERS BECAUSE THEY LOOK IDENTICAL AT A CALL SITE. Both
// arrive as a non-nil error, so code that branches on `err != nil` treats a
// residency refusal — §7.1 item 2, the guarantee working exactly as designed —
// the same as a target being down. That was live: the enforcement path logged
// both at WARN, so an operator alerting on WARN would page on normal
// governance, and alert fatigue is how a real page gets ignored.
//
// A deliberate refusal is a DECISION. It belongs in the audit log, it is worth
// an INFO line, and it is never a symptom. The rest are failures.
//
// KindEscalated is deliberate: it means a human must approve, which is the
// system working. KindInvalidArgument is deliberate: a malformed request was
// rejected, which is validation doing its job. KindSpecDrift is deliberate — D48
// refuses a diverged MCP surface on purpose.
//
// A WITHDRAWAL is the most deliberate of all: an operator or an anzen rule
// revoked a credential on purpose, and it is the one refusal somebody definitely
// wants to read about (D106). It carries KindDenied rather than a kind of its
// own — pool.withdrawnErr makes that choice explicitly, because what the caller
// must do is identical to any other denial (stop, and tell a human) and the
// severity that ran is a field on the decision record. Three comments here used
// to name a `KindRevoked` that was never declared, which is the recurring defect
// inverted: prose describing a symbol rather than a symbol with no caller.
func (k Kind) Deliberate() bool {
	switch k {
	case KindInvalidArgument, KindUnauthenticated, KindDenied, KindEscalated,
		KindRateLimited, KindBudgetExceeded, KindResidency, KindSpecDrift,
		KindIndeterminate, KindSessionExpired:
		// **`KindSessionExpired` IS DELIBERATE, AND IT IS THE ARM THAT KEEPS IT
		// OFF THE BREAKER (D213).** A server answering 404 to a request carrying
		// a session id has consulted its own state and decided — it is alive and
		// correct, exactly as a 429 is. `ImplicatesTarget` is
		// `AttributionTarget && !Deliberate()`, so putting it here is not a
		// presentational choice: get it wrong and every session expiry counts as
		// a failure against a healthy vendor, which is precisely the
		// hiccup-becomes-outage shape D200 wrote `KindCredentialUnavailable` to
		// stop one layer over.
		return true
	case KindConfig:
		// **DELIBERATE SINCE D201, AND THE WIRE SHAPE IS WHY.** A command-time
		// configuration fault is Sekizui deciding not to call — the base_url is
		// unusable, the vetted spec is absent — and as a transport error the
		// caller got a coarse gRPC code, no `kind` to branch on, and no decision
		// id to name the audit row it just caused. D182 made the same call for a
		// refusal-to-retry over an upstream timeout: what the caller must DO
		// about it is what decides the shape.
		//
		// Safe to change only because D200 landed first. While the log severity
		// keyed on this predicate, making config deliberate would have silenced a
		// broken deployment to INFO; `needsAHuman` now reads the attribution
		// instead, so it stays loud.
		return true

	case KindNotFound:
		// **DELIBERATE SINCE D211, and nothing failed to make it so.** A driver
		// declining to attempt an action it does not implement, or shin
		// declining a lens nobody offers, has DECIDED — no request was built and
		// no far side was contacted — so D135's rule applies: a decided refusal
		// travels as a result carrying a kind and a decision id, and only a
		// genuine failure stays a transport error.
		//
		// **FOUND BY THE DRIVER CONFORMANCE SUITE ON ITS FIRST RUN (D167).** A
		// caller naming a nonexistent action got a transport error attributed to
		// Sekizui, reachable today through `fullstory.Query`, which returns this
		// kind for every action — so an agent using the READ verb on a write
		// action produced a failure that read as our problem and could page.
		//
		// Safe in the same sequence D201 needed: D200 moved log severity off
		// this predicate onto attribution, so making a kind deliberate no longer
		// changes how loudly it is logged.
		return true

	case KindUnknown, KindConflict, KindTargetUnavailable,
		KindTargetError, KindTimeout, KindUnavailable, KindInternal,
		KindCredentialUnavailable:
		return false
	default:
		// A kind added without being classified is treated as a FAILURE, which
		// is the noisy direction rather than the silent one. A new refusal that
		// pages someone gets fixed; a new failure that logs at debug does not.
		return false
	}
}

// Retryable reports whether retrying the same request could plausibly succeed
// without anything else changing.
//
// Centralised because it is a judgement every driver would otherwise make
// independently, and because three of the answers are counter-intuitive:
// KindSpecDrift, KindResidency, and a WITHDRAWAL (KindDenied, see Deliberate)
// are NOT retryable — each needs a human to change something first, and a driver
// that retries them burns quota against a wall. The withdrawal is the sharpest
// of the three, because the natural reading of a cancelled call IS "try again":
// the credential was withdrawn, so the retry re-resolves, fails closed, and the
// only thing achieved is noise in the secret manager's access log during an
// incident.
func (k Kind) Retryable() bool {
	switch k {
	case KindRateLimited, KindTargetUnavailable, KindTimeout, KindUnavailable,
		KindCredentialUnavailable:
		// A source that is down usually comes back, and nothing was sent — so
		// there is no double-write hazard in trying again.
		return true
	case KindTargetError:
		// A 500 may be transient. Retryable, but the caller still owes bounded
		// backoff with jitter (CONTRACTS §5) rather than an immediate retry.
		return true
	case KindIndeterminate:
		// STATED RATHER THAN LEFT TO THE DEFAULT. The default arm below already
		// returns false, so this case changes no behaviour — and a safety
		// property resting on a zero value is what D138 and D149 object to, and
		// what silently inverted D140's mutating default for the length of one
		// refactor. This kind exists BECAUSE the caller must not retry; that is
		// worth one line naming it.
		return false
	default:
		return false
	}
}

// Error is a classified error with an optional wrapped cause.
//
// A pointer type because it is always constructed via New/Wrap and compared by
// identity through errors.As, never copied around as a value.
type Error struct {
	Kind Kind

	// Op is the operation that failed: "resolver.Resolve", "jira.create_issue".
	// Optional, and worth setting — it is what turns a stack-trace-free error
	// chain into something diagnosable.
	Op string

	Msg string

	// Err is the wrapped cause, or nil.
	Err error

	// RetryAfter is the upstream's stated backoff, when it supplied one. Zero
	// means "no guidance", NOT "retry immediately" — honouring an upstream
	// Retry-After is a definition-of-done item (CONTRACTS §5).
	RetryAfter time.Duration

	// DecisionID names the audit row that explains this failure (D202).
	//
	// **A FAILURE USED TO BE UNNAMEABLE BY THE CALLER.** Every refusal reaches
	// the caller as a `CommandResult` carrying its decision id (D135), and every
	// FAILURE reached it as a transport error carrying none — while
	// `gateway.recordFailure` minted an id, wrote the row, and discarded the id
	// with `_`. So the row existed and the only party who needed to find it had
	// no key. At one replica an operator finds it by timestamp; across replicas
	// under concurrent load the id is the join key and there is no substitute.
	//
	// SET AT THE ONE FUNNEL that records failures, never at the ~40 sites that
	// construct errors — D149's reasoning for `config_identity`, and the reason
	// this is a field rather than a constructor parameter: an error built deep in
	// a driver cannot know the id of a row that does not exist yet.
	DecisionID string

	// Reestablish says this failure may clear if some state we established with
	// the far side is established AGAIN and the call made once more (D203,
	// widened by D213).
	//
	// **IT WAS A BOOL UNTIL A SECOND KIND OF STATE APPEARED, and widening it was
	// cheaper than the alternative precisely because D204 put the loop above the
	// whole enforcement path.** A bool answered "re-establish?" when the loop
	// also has to know WHAT to re-establish: a rejected credential is fixed by
	// invalidating the resolver's cache entry and forcing a mint, an expired MCP
	// session by discarding the pooled client so the next borrow runs
	// `initialize` again. Doing either in place of the other is a no-op that
	// costs a second traversal and then fails identically — and doing the
	// credential one for a session expiry ALSO raises `credential_churn`, which
	// is a signal an anzen rule quarantines on.
	//
	// **A FIELD, NOT A METHOD ON Kind, AND THE EVIDENCE IS WHAT SETTLES IT.**
	// `KindUnauthenticated` has five producers with three different correct
	// remedies:
	//
	//	a 401 from the far side          re-mint and retry — the case this exists for
	//	D199's header-placement refusal  re-minting returns the same bad bytes
	//	D152's downgrade guard           re-resolving re-triggers it — RETRYING IS
	//	                                 WHAT THE ATTACKER WANTS
	//	a borrow on a wiped credential   break-glass just happened; retrying is wrong
	//
	// So a static `Kind.Reestablish()` would be wrong for four of the five and
	// actively harmful for two. This is the per-error override §D200 declined to
	// add "until a case needs it", with four cases now proving both that it is
	// needed and that the static form would be dangerous.
	//
	// **SET BY THE PRODUCER THAT KNOWS**, which is a driver looking at a real
	// far-side status — never by a stage that merely observes the kind. The
	// default is `ReestablishNone`, and that is the safe direction: a marker
	// nobody sets means nothing is re-established, which is the behaviour that
	// predates it.
	Reestablish Reestablishment
}

// Reestablishment names WHAT a producer is asking to be established again.
//
// **A CLOSED SET WITH A ZERO VALUE MEANING "NOTHING", so the safe answer is the
// one a producer gets by saying nothing** — the same shape `Versioning` takes in
// `pkg/config` and for the same reason (D153).
type Reestablishment uint8

const (
	// ReestablishNone is the zero value: this failure is not re-establishable.
	ReestablishNone Reestablishment = 0

	// ReestablishCredential — the far side rejected the credential we sent, so
	// the cached entry is invalidated and a fresh one minted (D203).
	ReestablishCredential Reestablishment = 1

	// ReestablishSession — the far side discarded the CONNECTION STATE we
	// established, so the pooled client is discarded and the next borrow builds
	// a new one (D213). The credential is untouched, which is the whole
	// distinction: re-minting a secret that was never rejected spends the secret
	// manager's quota and raises a churn signal about a target that is fine.
	ReestablishSession Reestablishment = 2
)

// reestablishmentNames are stable identifiers, for the same reason kindNames are
// (these reach log lines an operator greps during an incident).
//
//nolint:gochecknoglobals // immutable lookup table
var reestablishmentNames = map[Reestablishment]string{
	ReestablishNone:       "none",
	ReestablishCredential: "credential",
	ReestablishSession:    "session",
}

func (r Reestablishment) String() string {
	if n, ok := reestablishmentNames[r]; ok {
		return n
	}
	return fmt.Sprintf("reestablishment(%d)", uint8(r))
}

func (e *Error) Error() string {
	var b []byte
	if e.Op != "" {
		b = append(b, e.Op...)
		b = append(b, ": "...)
	}
	b = append(b, e.Kind.String()...)
	if e.Msg != "" {
		b = append(b, ": "...)
		b = append(b, e.Msg...)
	}
	if e.Err != nil {
		b = append(b, ": "...)
		b = append(b, e.Err.Error()...)
	}
	return string(b)
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.Err }

// Is makes errors.Is(err, KindDenied) match on category.
//
// Without this, errors.Is would compare pointers and never match, because
// nothing holds a shared *Error instance to compare against.
func (e *Error) Is(target error) bool {
	k, ok := target.(Kind)
	return ok && k == e.Kind
}

// New constructs a classified error with no cause.
//
// RETURNS error, NOT *Error — see Wrap. Construct &Error{...} directly when you
// need to set RetryAfter or otherwise touch fields.
func New(kind Kind, op, msg string) error {
	return &Error{Kind: kind, Op: op, Msg: msg}
}

// Wrap classifies an existing error, preserving it for errors.Is/As.
//
// Returns nil when err is nil, so a caller can write
//
//	return fault.Wrap(fault.KindTargetError, "jira.create", "", err)
//
// without first checking whether err was nil.
//
// THE RETURN TYPE IS error AND MUST STAY error. Returning *Error would make the
// nil case a trap: assigning a nil *Error into an error interface produces a
// value that is NOT nil, because the interface carries a type alongside its
// (nil) pointer. Every caller doing the ordinary thing —
//
//	if err := doWork(); err != nil {
//
// would take the error branch on success, and the error would print as "<nil>".
// This package shipped with that bug for exactly one commit; TestWrapNilIsNilThroughInterface
// is what catches it coming back. os.NewSyscallError has the same shape for the
// same reason.
func Wrap(kind Kind, op, msg string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Kind: kind, Op: op, Msg: msg, Err: err}
}

// KindOf extracts the taxonomy category from any error.
//
// Returns KindUnknown for errors that never passed through this package, which
// is the honest answer: an unclassified error is not "internal", it is
// unclassified, and the metrics should show that so the gap gets closed.
func KindOf(err error) Kind {
	if err == nil {
		return KindUnknown
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindUnknown
}

// RetryAfterOf returns the upstream-supplied backoff, or zero if none.
// DecisionIDOf returns the audit row this error was recorded as, or "".
//
// SAME SHAPE AS RetryAfterOf, deliberately: it reads through a wrap, because the
// id is attached where the failure is RECORDED and a caller may receive it
// several wraps out.
func DecisionIDOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.DecisionID
	}
	return ""
}

// WithDecisionID returns err carrying the id of the row that recorded it.
//
// **IT DOES NOT MUTATE.** The error may already have been returned to another
// goroutine — the retry path holds one across attempts — and a shared `*Error`
// gaining a field under a reader is a data race for the sake of a convenience.
// A copy is cheap and the alternative is unprovable.
//
// A non-fault error is WRAPPED rather than dropped, because a failure whose id
// is lost because it came from a driver that did not use this package is exactly
// the caller this exists for.
func WithDecisionID(err error, id string) error {
	if err == nil || id == "" {
		return err
	}
	var e *Error
	if errors.As(err, &e) {
		copied := *e
		copied.DecisionID = id
		return &copied
	}
	return &Error{Kind: KindOf(err), Msg: err.Error(), Err: err, DecisionID: id}
}

func RetryAfterOf(err error) time.Duration {
	var e *Error
	if errors.As(err, &e) {
		return e.RetryAfter
	}
	return 0
}

// CredentialRejected is a FAR SIDE saying the credential we sent is no good, and
// it is the only constructor that sets the re-establishment marker (D203).
//
// **ONE CONSTRUCTOR BECAUSE TWO DRIVERS ALREADY HAD THE SAME FOUR LINES**, which
// is D173's shape and D199's — three copies of an atomic write, none of them
// syncing; three drivers hand-rolling an auth header, none of them checking the
// bytes. The fourth driver would have copied whichever it found, and the marker
// is the one field where a copy that drifts is a security property that drifts:
// setting it from a stage that merely inferred an auth problem re-triggers
// D152's downgrade guard, which is what an attacker rolling a credential back is
// trying to make us do.
//
// **WHO MAY CALL IT IS GUARDED, NOT DOCUMENTED**, by
// `archcheck.TestOnlyADriverReportsAFarSideRejection`: a driver that read a real
// status off the wire, and nothing else. The four producers that must NOT are in
// `Error.Reestablish`'s own comment.
//
// Takes no cause: the far side's status IS the cause, and a driver with
// something to wrap has a message field to put it in.
func CredentialRejected(op, msg string) error {
	return &Error{Kind: KindUnauthenticated, Op: op, Msg: msg,
		Reestablish: ReestablishCredential}
}

// SessionRejected is a FAR SIDE saying the connection state we established with
// it is gone, and it is the only constructor that asks for a session to be
// re-established (D213).
//
// **A SIBLING OF `CredentialRejected` RATHER THAN A FLAG ON IT**, so that the
// one-constructor rule survives the second case instead of being the thing the
// second case works around. Both are guarded by
// `archcheck.TestOnlyADriverReportsAFarSideRejection`: a producer must be a
// driver that read a real status off the wire, because the marker's whole value
// is that it distinguishes what the FAR SIDE said from what a middle stage
// inferred.
//
// **THE SPECIFICATION MAKES THIS A CLIENT MUST**, which is unusual for something
// this codebase would otherwise be free to refuse: MCP 2025-06-18 says "when a
// client receives HTTP 404 in response to a request containing an
// Mcp-Session-Id, it MUST start a new session by sending a new
// InitializeRequest". D204's loop is how that MUST is met without a second
// enforcement path — the new session is established on the next borrow, and the
// call that uses it is authorised at the moment it actually goes out.
//
// Takes no cause, for `CredentialRejected`'s reason: the far side's status IS
// the cause.
func SessionRejected(op, msg string) error {
	return &Error{Kind: KindSessionExpired, Op: op, Msg: msg,
		Reestablish: ReestablishSession}
}

// ReestablishOf reports what this failure asked to have re-established (D203,
// D213).
//
// SAME SHAPE AS RetryAfterOf AND DecisionIDOf: it reads THROUGH a wrap, because
// the marker is set by a driver and read by the gateway several wraps out.
//
// **`ReestablishNone` FOR AN UNCLASSIFIED ERROR**, and that is the safe
// direction rather than an oversight — an error that never passed through this
// package cannot have been marked by a producer that knew, and re-minting on a
// guess is the amplification D204 bounds everywhere else.
func ReestablishOf(err error) Reestablishment {
	var e *Error
	if errors.As(err, &e) {
		return e.Reestablish
	}
	return ReestablishNone
}
