package gateway

import (
	"context"
	"errors"
	"fmt"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/catalog"
	"github.com/fullstorydev/sekizui/internal/grantcheck"
	"github.com/fullstorydev/sekizui/internal/identity"
	"github.com/fullstorydev/sekizui/internal/metrics"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/internal/reflex"
	"github.com/fullstorydev/sekizui/internal/retry"
	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/internal/tracing"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/audit"
	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/limiter"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Resolver is the seam onto internal/resolver, declared here so the gateway
// depends on a method set rather than a package (GO-PRIMER §2.1).
type Resolver interface {
	Resolve(ctx context.Context, ref string) (connector.Target, error)
	Kinds() map[string]string

	// ResidencyRefused answers the deployment ceiling without resolving, so it
	// can be checked ahead of policy (D136). See resolver.ResidencyRefused for
	// why a lookup rather than a resolve.
	ResidencyRefused(ref string) (class string, refused bool)

	// Invalidate drops this target's cached credential so the next Resolve mints
	// fresh material (D203, D204). Called from exactly one place, the
	// re-establishment loop in reestablish.go.
	Invalidate(ref string)
}

// ChurnRecorder is the slice of internal/churn the enforcement path needs,
// declared here so the gateway depends on a method set rather than a package
// (GO-PRIMER §2.1). The WINDOW and the THRESHOLD are the counter's business, not
// this package's.
type ChurnRecorder interface{ Record(targetRef string) }

// MistenantRecorder tallies refused egress tenant assertions, so
// `tenant_mismatch` can be published as a level (D226).
//
// A SEPARATE INTERFACE FROM ChurnRecorder despite the identical signature,
// because they are different conditions with different consumers and one
// deployment may wire either without the other. Collapsing them to a shared
// `Recorder` would make the wiring site say nothing about which signal it feeds.
type MistenantRecorder interface{ Record(targetRef string) }

// DenialRecorder tallies rate-limit refusals with who was over their share, so
// `denial_storm` can name the principal causing them (D143, D336) —
// denial.Tally in production.
type DenialRecorder interface {
	Record(budget, victim string, over []string)
}

// Server implements sekizuiv1.GatewayServiceServer.
//
// THE ENFORCEMENT PATH LIVES HERE, and there is exactly one of it. §4.11.1:
// "reflexes call the same internal path. There is no fast lane (D18)." When the
// reflex engine lands at P5 it calls execute() directly rather than getting a
// shortcut, which is the difference between a reflex being a principal and a
// reflex being a bypass.
type Server struct {
	// doc is the validated document, kept for Validate: the grant table has to
	// be checked against the drivers, and this is the only place holding both
	// (D195).
	doc *config.Document

	sekizuiv1.UnimplementedGatewayServiceServer

	verifier  *identity.Verifier
	churn     ChurnRecorder
	mistenant MistenantRecorder
	denials   DenialRecorder
	guards    *anzen.Guards
	policy    policy.Engine
	resolver  Resolver
	drivers   map[string]connector.Driver // by Kind
	catalog   *catalog.Catalog
	lenses    *shin.Lenses
	bus       pkgbus.Bus
	// subscribable is the compiled subscribe grant table: principal -> its
	// (subject, target) pairs (D259). Built once and never mutated, so it is
	// safe to share.
	subscribable map[string][]config.SubscriptionSpec

	// projector shapes Envelope.projection at delivery (D269). Nil means no
	// projection rules, and a consumer asking for one receives none.
	projector *reflex.Projector
	payloads  Payloads

	// refinements are the imposed `refines:` rules, compiled once at boot by
	// schemareg.Refinements — the same compilation the schema check reported
	// on, so what boot checked is what serves (D317). Nil means none.
	refinements []schemareg.Refinement

	// quarantined: connector kind -> why (D282). Read by driverFor.
	quarantined map[string]string
	recorder    audit.Recorder
	admission   *Admission
	metrics     *metrics.Registry
	tracer      Tracer
	log         *slog.Logger
	now         func() time.Time

	// handles are the stateful handles an opener returned and nothing closed
	// (D291); handleIdle is the deployment's idle ceiling.
	handles    *handleTable
	handleIdle time.Duration

	// pool is what break-glass withdraws from (§4.7.10). Optional: a Server
	// built without one refuses the verb rather than reporting a revocation
	// that withdrew nothing.
	pool *pool.Pool

	// retry bounds how hard one command may try (D113, D14). Never nil — New
	// installs the default policy — because a nil runner would mean "no
	// retries" silently, and that is a behaviour change nobody asked for
	// hiding in a wiring omission.
	retry *retry.Runner

	// breaker withdraws from unhealthy targets (§4.3.4). OPTIONAL, unlike
	// retry: a deployment may legitimately run without one, and a nil breaker
	// means every call is allowed rather than none.
	breaker limiter.Breaker

	// revocations suspends a principal's grants at runtime (D146). Optional;
	// nil means the verbs are unavailable rather than silently no-ops.
	revocations *policy.Revocations

	// rate shapes healthy traffic: the shared target budget and the
	// per-principal fairness within it (D143). Optional, and nil means
	// unlimited — the same reading a target with no configured rate gets.
	rate limiter.Limiter

	// jobs runs governed asynchronous jobs (D247). Optional, and nil means
	// `StartJob` refuses rather than accepting a job nothing will run.
	//
	// **NOT A Config FIELD, AND THE REASON IS A GENUINE CYCLE RATHER THAN
	// TASTE.** The runner must be governed BY this server — it admits every
	// poll through `s.ceilings` (D18, D155) — and this server must dispatch TO
	// the runner. Neither can be constructed first, so one edge is closed
	// after construction by `AttachJobRunner`, which refuses to be called
	// twice. The alternative considered was a `func() JobRunner` thunk on
	// Config, and it is worse: a closure over a variable assigned later is nil
	// for a window nothing marks, so the failure is a job accepted and dropped
	// during startup rather than a refusal at the wiring site.
	jobs JobRunner

	// reflexes is the running reflex engine's off switch, for `disable_reflex`
	// (D332). Attached after construction, as the job runner is: the engine
	// takes this server as its enforcer, so it cannot exist first.
	reflexes ReflexSwitch

	// specs is target ref -> its declared spec, captured at construction.
	//
	// EXISTS SO REVOCATION NEED NOT RESOLVE. The record must name the credential
	// reference, and the obvious way to get it is resolver.Resolve — which
	// fetches the credential through the cache, and would therefore make the
	// first act of revoking a credential be to go and fetch it. The spec carries
	// the reference and the residency without touching a provider.
	specs map[string]config.TargetSpec
}

// Config is what a Server needs. A struct rather than eight parameters, so
// adding a dependency is a compile error at the wiring site rather than a
// silently-reordered argument.
type Config struct {
	// Projector shapes projections at delivery (D269); optional.
	Projector *reflex.Projector

	// HandleIdle is the deployment's ceiling on how long a stateful handle may
	// go unused before Sekizui closes it (D291, `-handle-idle`). Zero never
	// closes on idleness; the drain still closes every handle.
	HandleIdle time.Duration

	// Quarantined names the connectors whose schemas are not sound, and why
	// (D282) — schemareg's verdict. Their targets are refused by every governed
	// call; every other connector serves.
	Quarantined map[string]string

	// Payloads shapes every Query result row to its connector's schema before
	// any lens sees it (D279) — the same allowlist the runner applies to
	// polled events. REQUIRED: a Query with no registry is refused rather than
	// returning what the connector happened to fetch.
	Payloads Payloads

	// Refinements are the imposed `refines:` rules, compiled by
	// schemareg.Refinements (D297, D317). A Query or Execute whose result an
	// imposed rule refines carries a Seiren beside its rows or result.
	Refinements []schemareg.Refinement

	Verifier *identity.Verifier
	Guards   *anzen.Guards
	Policy   policy.Engine
	Resolver Resolver
	Drivers  map[string]connector.Driver
	Catalog  *catalog.Catalog
	Lenses   *shin.Lenses
	Bus      pkgbus.Bus
	Doc      *config.Document
	Pool     *pool.Pool
	Retry    *retry.Runner
	Breaker  limiter.Breaker
	Rate     limiter.Limiter

	// Churn tallies forced credential re-establishments, so `credential_churn`
	// can be published as a level (D204). Nil disables the tally; the scraped
	// counter is unconditional, because a deployment that raises no signal should
	// still be visible to whatever is watching from outside.
	Churn ChurnRecorder

	// Mistenant tallies refused egress assertions, so `tenant_mismatch` can be
	// published as a level (D226, §6 mechanism 3). Nil disables the tally; the
	// assertion itself is unconditional and refuses the call either way.
	Mistenant MistenantRecorder

	// Denials tallies rate-limit refusals for `denial_storm` (D336). Nil: no
	// tally, and nothing can raise the signal.
	Denials DenialRecorder

	// Revocations backs sekizui.revoke_grant. Built by the caller so the panel
	// and the boot report read the same set the enforcement path consults.
	Revocations *policy.Revocations
	Recorder    audit.Recorder
	Admission   *Admission
	Metrics     *metrics.Registry

	// Tracer mints one span per outbound call (§10.4, D235). NIL IS SAFE and
	// means no spans are recorded — a `Provider` with no sink behaves the same
	// way, so the enforcement path never branches on observability being
	// configured. `Trace.span_id` is then empty, which is the honest value.
	Tracer Tracer

	Log *slog.Logger
	Now func() time.Time
}

// Tracer is what the gateway needs of a span provider.
//
// **AN INTERFACE HERE AND A CONCRETE TYPE IN `internal/tracing`**, so a nil
// Tracer is expressible and every existing caller of `gateway.New` keeps
// working. The alternative — taking `*tracing.Provider` — would make every test
// that builds a Server construct one, which is the churn D91's skeleton avoided
// for the bus.
type Tracer interface {
	Begin(traceID, parentSpanID string, sampled bool, name string,
		attrs map[string]string) *tracing.Live
}

func New(c Config) *Server {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Guards == nil {
		c.Guards = anzen.New(nil)
	}
	if c.Metrics == nil {
		c.Metrics = metrics.New()
	}
	if c.Retry == nil {
		c.Retry = retry.New(retry.DefaultPolicy())
	}
	if c.Lenses == nil {
		// No lenses configured means no projection, which is the correct empty
		// behaviour: absence of a lens is not a lens that removes everything.
		c.Lenses = shin.New(nil)
	}
	subscribable := map[string][]config.SubscriptionSpec{}
	for _, g := range c.Doc.GetGrants() {
		if len(g.Subscribe) > 0 {
			subscribable[g.Principal] = g.Subscribe
		}
	}

	specs := map[string]config.TargetSpec{}
	for _, t := range c.Doc.GetTargets() {
		specs[t.Ref] = t
	}

	return &Server{
		doc: c.Doc, subscribable: subscribable, bus: c.Bus, projector: c.Projector, payloads: c.Payloads, refinements: c.Refinements, quarantined: c.Quarantined,
		verifier: c.Verifier, guards: c.Guards, policy: c.Policy, resolver: c.Resolver,
		churn:     c.Churn,
		mistenant: c.Mistenant,
		denials:   c.Denials,
		drivers:   c.Drivers, catalog: c.Catalog, lenses: c.Lenses,
		recorder: c.Recorder, admission: c.Admission, pool: c.Pool, specs: specs,
		retry: c.Retry, breaker: c.Breaker, rate: c.Rate, revocations: c.Revocations,
		metrics: c.Metrics, tracer: c.Tracer, log: c.Log, now: c.Now,
		handles: &handleTable{open: map[string]*openHandle{}}, handleIdle: c.HandleIdle,
	}
}

// AttachJobRunner closes the wiring cycle between this server and the job
// runner it governs. See Server.jobs for why the cycle is real.
//
// **REFUSES A SECOND CALL RATHER THAN OVERWRITING.** A server serving one
// runner while a caller holds a handle to another is two enforcement paths
// wearing one address, which is the shape D155 exists to stop from recurring.
func (s *Server) AttachJobRunner(r JobRunner) error {
	const op = "gateway.AttachJobRunner"
	if r == nil {
		return fault.New(fault.KindConfig, op, "no job runner")
	}
	if s.jobs != nil {
		return fault.New(fault.KindConfig, op,
			"a job runner is already attached; replacing it would leave callers "+
				"holding a handle to a runner this server no longer dispatches to")
	}
	s.jobs = r
	return nil
}

// ReflexSwitch turns a running reflex rule off (D332) — reflex.Engine.Disable.
type ReflexSwitch interface {
	Disable(rule, by string) (already bool, err error)
}

// AttachReflexes gives `disable_reflex` the engine to act on. Once, for
// AttachJobRunner's reason.
func (s *Server) AttachReflexes(sw ReflexSwitch) error {
	const op = "gateway.AttachReflexes"
	if sw == nil {
		return fault.New(fault.KindConfig, op, "no reflex engine")
	}
	if s.reflexes != nil {
		return fault.New(fault.KindConfig, op, "a reflex engine is already attached; replacing it would "+
			"leave rules an anzen rule disabled running in the engine this server no longer reaches")
	}
	s.reflexes = sw
	return nil
}

// Execute is P0 exit criteria 1 and 2: a command traverses identity → policy →
// driver → audit, and a DENIED command produces a decision record too.
func (s *Server) Execute(ctx context.Context, req *sekizuiv1.ExecuteRequest) (*sekizuiv1.ExecuteResponse, error) {
	release, err := s.admission.Acquire(ctx, "Execute")
	if err != nil {
		return nil, toStatus(err)
	}
	defer release()

	cmd := req.GetCommand()
	if cmd.GetAction() == "" || cmd.GetTargetRef() == "" {
		return nil, toStatus(fault.New(fault.KindInvalidArgument, "gateway.Execute",
			"command needs both an action and a target_ref"))
	}

	// 1. WHO. From the verified mTLS peer; the subject is claimed and checked
	// against may_speak_for (§4.4.1). Never from a payload field.
	//
	// SEPARATED FROM Enforce DELIBERATELY (D69). Identity ESTABLISHMENT differs
	// by caller — a gRPC request proves itself with a certificate, an in-process
	// reflex cannot — while everything after it is identical. Keeping the mTLS
	// step here rather than inside the enforcement path is what makes D18's
	// "reflexes call the same internal path" implementable rather than
	// aspirational.
	id, err := s.verifier.Verify(ctx)
	if err != nil {
		// No decision record: identity failed, so there is no principal to
		// attribute one to. Writing "unknown denied something" would be an
		// audit row nobody can act on, and an unauthenticated flood would fill
		// the log with them.
		return nil, toStatus(err)
	}

	result, err := s.Enforce(ctx, id, cmd)
	if err != nil {
		return nil, toStatus(err)
	}
	return &sekizuiv1.ExecuteResponse{Result: result}, nil
}

// Validate refuses a configuration the enforcement path could not serve (D190).
//
// **A TARGET NAMING A DRIVER KIND NOBODY IMPLEMENTS WAS ALREADY REFUSED — AT
// CALL TIME, WHICH IS THE WRONG MOMENT.** `Enforce` looks up
// `s.drivers[target.Kind()]` and returns a config fault when it misses, and
// `connector.Registry.Build` refuses too. Both are correct and both are late:
// D50 draws the line at offline versus live, and a configuration that cannot
// mean anything belongs in the blocking half. The failure it prevents is
// specific — a typo'd `kind: fullstroy` passes every other boot check, serves
// happily, and refuses the first command that names it hours later, to an agent,
// as a runtime error.
//
// **THIS IS WHERE THE CHECK BELONGS BECAUSE IT IS THE ONLY PLACE THAT KNOWS BOTH
// HALVES.** The registry knows which kinds are implemented; the resolver knows
// which kinds the configuration names. The gateway holds both, and until now
// `Resolver.Kinds` was declared by this file's own interface and called by
// nothing — a published method with no consumer, which is the recurring defect
// wearing an interface.
//
// SORTED, so a refusal listing four targets reads the same on every run: a
// message whose order changes is one an operator cannot diff against the last.
func (s *Server) Validate() error {
	const op = "gateway.Validate"

	if s.resolver == nil {
		return fault.New(fault.KindInternal, op, "no resolver wired")
	}

	var unknown []string
	for ref, kind := range s.resolver.Kinds() {
		if _, implemented := s.drivers[kind]; !implemented {
			unknown = append(unknown, fmt.Sprintf("%s (kind %q)", ref, kind))
		}
	}
	if len(unknown) == 0 {
		// **THE GRANT TABLE, AGAINST WHAT THIS BUILD SERVES (D195), AND ONLY ONCE
		// THE KINDS ARE SOUND.** Checked here for this function's own stated
		// reason — the registry knows which actions are implemented, the document
		// knows which are granted, and the gateway is the only place holding both.
		//
		// **THE ORDER IS LOAD-BEARING AND THE SUITE CAUGHT IT, not reasoning.**
		// Run first, this check answers a typo'd driver KIND by blaming the
		// GRANT: a target declaring `kind: fullstroy` has no actions under that
		// prefix, so every grant naming it covers nothing, and the refusal sends
		// an operator to edit ten correct grants instead of one wrong letter. A
		// broken kind makes every question about coverage unanswerable, so the
		// question is not asked until the kinds are sound.
		if s.doc != nil {
			if err := grantcheck.Validate(s.doc, s.drivers); err != nil {
				return err
			}
			// AND NO REFLEX THE CEILING FORBIDS (P5 step 4): the guards and the
			// document meet here too.
			if dead := s.guards.ForbiddenReflexes(s.doc.Reflexes, s.configuredResidency); len(dead) > 0 {
				return fault.New(fault.KindConfig, op, fmt.Sprintf("%d reflex(es) can never act:\n  - %s",
					len(dead), strings.Join(dead, "\n  - ")))
			}
		}
		return nil
	}
	sort.Strings(unknown)

	registered := make([]string, 0, len(s.drivers))
	for kind := range s.drivers {
		registered = append(registered, kind)
	}
	sort.Strings(registered)

	return fault.New(fault.KindConfig, op, fmt.Sprintf(
		"%d target(s) name a driver kind no driver implements: %s. Registered kinds are "+
			"%v. Such a target cannot serve a single command, and refusing at boot is the "+
			"difference between an operator seeing it now and an agent discovering it later",
		len(unknown), strings.Join(unknown, ", "), registered))
}

// needsAHuman reports whether a fault should be logged loudly (D125, D200).
//
// **IT USED TO BE `!Deliberate()`, AND THAT MISSED A WHOLE CATEGORY.** A
// deliberate refusal is routine — policy said no, the upstream said 429 — and
// logging it at WARN is the crying-wolf failure D77 names. But some deliberate
// refusals are NOT routine: a credential that cannot be placed, or a target that
// is misconfigured, refuses every command until a human edits something, and at
// INFO it is a flood that hides its own cause.
//
// So the question is WHOSE fault rather than whether Sekizui decided: anything
// attributed to this deployment or to the credential needs somebody, however
// deliberately it was refused.
func needsAHuman(k fault.Kind) bool {
	switch k.Attribution() {
	case fault.AttributionSekizui, fault.AttributionCredential:
		return true
	default:
		return !k.Deliberate()
	}
}

// enforceOnce is ONE TRAVERSAL of the enforcement path, and there is exactly one
// of it.
//
// Takes an ALREADY-ESTABLISHED identity, so both callers share it:
//
//	Execute      — identity from the mTLS peer certificate
//	reflex.Engine — identity constructed for the rule's own principal
//
// D18 requires that a reflex "needs its own grant, and its command traverses the
// identical enforcement path". `Enforce` above is what both of them call, and it
// calls this — never a variant of it, so there is no second path to drift.
//
// **IT WAS `Enforce` UNTIL D204, AND THE RENAME IS THE DECISION.** D203 placed
// the re-establishment retry INSIDE this function, at step 5, re-running resolve
// plus the call. That would have made attempt 2 an ABBREVIATED traversal —
// skipping the runtime revocation check, policy, break-glass placement, the rate
// limiter, the breaker and the intent record — which is precisely the shape
// `ceilings` records `Query` growing, "one omission at a time, each invisible
// because Query reads like a shorter version of the same thing rather than a
// weaker one". So the second attempt is a whole second call to this function and
// the loop lives above it.
//
// `again` IS AN OUT-PARAMETER, WHICH IS NOT AN ACCIDENT AND NOT IDIOMATIC GO.
// The fact the loop needs — "the far side asked us to re-mint, and repeating
// this call is safe" — is known at ONE point near the end, and that point
// returns a RESULT rather than an error (D135), so the marker cannot ride out on
// the error the way `RetryAfter` and `DecisionID` do. The alternative is a third
// return value, which means writing `nil` on twenty-three exit paths that have
// nothing to do with re-establishment, in the one function where a wrong value
// on an exit path is most expensive. One writer, one reader, and the writer is
// six lines below the outcome record it depends on. See GO-PRIMER §15ad.
//
// Never nil: the loop always allocates it.
func (s *Server) enforceOnce(ctx context.Context, id *sekizuiv1.Identity,
	cmd *sekizuiv1.Command, again *reattempt) (result *sekizuiv1.CommandResult, err error) {

	const op = "gateway.Enforce"

	// ONE OBSERVATION POINT, on the way out, whichever way that is.
	//
	// The first version of this called Observe by hand at two of the eight exit
	// paths. The result was three defects at once: the two call sites emitted
	// DIFFERENT vocabularies while a comment claimed they matched, four paths
	// emitted nothing at all, and Query was unmetered entirely. That is the
	// cost of instrumenting by hand — a new branch is a metric nobody notices
	// is missing, and each site derives its own label.
	//
	// NAMED RETURN VALUES plus defer make it structural: the deferred closure
	// reads whatever is about to be returned, so a path added later is covered
	// by construction rather than by remembering.
	// refusedKind carries the TAXONOMY of a refusal to the deferred observation
	// point below, and it exists because D135 cost the metric a distinction.
	//
	// The label used to come from the error's kind, so a residency conflict was
	// metered as `residency` and a policy denial as `denied` — a separation §7.1
	// item 2 and D89 both rest on, since one is a grant to review and the other
	// is a deployment topology problem. Turning refusals into RESULTS removed
	// the error the label was read from, and `Status()` is deliberately coarser
	// than `Kind` (it collapses denied, unauthenticated and residency into one).
	// Without this the metric silently lost a dimension while every test still
	// passed except the one that checks every exit path is metered.
	var refusedKind fault.Kind

	// ONE PLACE SETS IT, for the same reason D76 gives about the observation
	// point itself: a refusal path added later is covered by construction rather
	// than by remembering to instrument it.
	refuse := func(d *sekizuiv1.Decision, by sekizuiv1.RefusedBy, e error) (*sekizuiv1.CommandResult, error) {
		refusedKind = fault.KindOf(e)
		return s.refuse(ctx, d, by, e)
	}

	started := s.now()
	defer func() {
		outcome := outcomeLabel(result, err, refusedKind)
		took := s.now().Sub(started)
		s.metrics.Observe(cmd.GetTargetRef(), cmd.GetAction(), outcome, took)
		s.report(id, cmd.GetAction(), cmd.GetTargetRef(), outcome, took,
			result.GetDecisionId(), result.GetReason(), err, refusedKind)
	}()

	if id.GetCaller().GetPrincipal() == "" {
		return nil, fault.New(fault.KindInternal, op,
			"enforcement requested with no established identity")
	}

	// **THE SECOND CALLER-CONTROLLED STRING THAT REACHES A FSYNCED RECORD
	// (D215).** `identity.Verify` bounds the trace id; this is the same hazard
	// through the message body rather than a header, and it lands on both the
	// intent and the outcome record. Checked BEFORE the intent record is written,
	// because a refusal that writes the very thing it is refusing has spent the
	// disk it was protecting.
	if err := refuseUnusableIdempotencyKey(op, cmd.GetIdempotencyKey()); err != nil {
		// **A RECORD IS WRITTEN, AND IT DOES NOT CARRY THE VALUE — the first
		// version of this got the trade backwards.** It refused without a record
		// at all, reasoning that writing one would spend the disk the bound was
		// protecting. That is wrong on the governance axis: a refusal with no
		// audit trail is the thing this system exists to prevent, and D135 makes
		// every deliberate refusal a result with a decision id. The amplification
		// is defeated by OMITTING the oversized field from the record, not by
		// omitting the record.
		//
		// `REFUSED_BY_REQUEST` rather than the zero value, which would be D201's
		// defect exactly: a stage that cannot say what refused it.
		return refuse(&sekizuiv1.Decision{
			Identity: id, Action: cmd.GetAction(), TargetRef: cmd.GetTargetRef(),
			// **IT SAYS WHAT DECIDED, AND IT DID NOT (§5.4).** This row carried
			// an empty `matched_rule`, so the log held a refusal that could not
			// explain itself — "an unexplainable outcome is a log line, not an
			// audit record". No grant was consulted, which is exactly why the
			// field needed a value rather than being left blank: nothing later
			// can reconstruct that the REQUEST was refused rather than the
			// principal. Same shape as policy's `default_deny`, and found the
			// same way D228 was, by reading the whole log rather than P0's slice
			// of it — `assertEveryRecordIsSelfContained` runs inside
			// TestP0Acceptance and this row is P2's.
			MatchedRule: "request_bounds",
		}, sekizuiv1.RefusedBy_REFUSED_BY_REQUEST, err)
	}

	args := cmd.GetArgs().AsMap()
	subject := id.GetSubject().GetPrincipal()

	// EVERY CEILING, SHARED WITH Query (D18, D155). Suspension, then the
	// residency ceiling, then the anzen guard — in that order, and the order is
	// itself a decision recorded in ceilings().
	_, releaseCeilings, ceilingRef := s.ceilings(ctx, id, subject,
		cmd.GetAction(), cmd.GetTargetRef(), cmd.GetIdempotencyKey(), cmd.GetCausation())
	defer releaseCeilings()
	if ceilingRef != nil {
		return refuse(ceilingRef.decision, ceilingRef.by, ceilingRef.err)
	}

	// 3. MAY THEY. Caller ∩ subject, strictest wins (D59).
	//
	// **UNLESS THE SUBJECT IS ANZEN'S OWN, whose authority is its closed
	// vocabulary rather than a grant (D122).** That is not a bypass and it is not
	// a second path: the command still travels this function, is still recorded
	// by the same recorder, and is still hash-chained. What differs is where the
	// authorisation comes from, and D122 says why it must: a grant naming an
	// `anzen:` principal is refused at boot, so there is no grant to consult and
	// an anzen action would otherwise be denied for having no permission it was
	// never allowed to be given.
	//
	// **NARROW TO ONE ACTION ON ONE TARGET.** An `anzen:<rule>` subject may fire
	// exactly that rule and nothing else. Anything wider would attach arbitrary
	// capability to something an audit log reads as anzen, which is precisely the
	// misstatement the reservation exists to prevent.
	dec, err := s.anzenAuthorise(subject, cmd)
	if err != nil {
		return nil, err
	}
	if dec == nil {
		authorised, aerr := s.policy.Authorise(ctx, policy.Request{
			Identity: id, Action: cmd.GetAction(), TargetRef: cmd.GetTargetRef(), Args: args,
		})
		if aerr != nil {
			return nil, aerr
		}
		dec = &authorised
	}

	base := &sekizuiv1.Decision{
		Identity: id,
		// **THE SPAN CONTEXT, FROM THE REQUEST RATHER THAN FROM THE IDENTITY
		// (D216).** A trace answers which conversation, which is request scope;
		// `Identity.trace_id` survives as a mirror for records already written.
		// The header is authoritative and `Command.trace` is the internal path
		// for a reflex-originated command, which has no header to read.
		Trace:     traceFor(ctx, cmd),
		Action:    cmd.GetAction(),
		TargetRef: cmd.GetTargetRef(),
		// WHICH RULE, not just which principal (D96). Several reflexes commonly
		// share one principal, and without this the log answers "a reflex did
		// it" when the question is "why did this ticket get created".
		ReflexName:     audit.ReflexNameFrom(ctx),
		Verdict:        dec.Verdict,
		MatchedRule:    dec.Rule,
		Reason:         dec.Reason,
		IdempotencyKey: cmd.GetIdempotencyKey(),
		Causation:      cmd.GetCausation(),
	}
	// THE RECORD'S RESIDENCY CLASS FROM THE CONFIGURED TARGET, BEFORE ANY STAGE
	// CAN REFUSE (D29 item 4, D319). It was stamped only once the target
	// resolved, so a command refused on residency — about a us target — was
	// recorded with NO class, and a shipper sent it to every destination, EU
	// included: the command regional, its audit row not. P4 step 9 found it.
	// The class is declared on the target, the same document the ceiling
	// checks, so it is known here; the resolved stamp below agrees with it.
	base.Residency = s.configuredResidency(cmd.GetTargetRef())

	// 4. REFUSALS ARE RECORDED. §5.4: denials and escalations are the
	// highest-value rows — "agent X tried to delete a project and was refused"
	// is the sentence that justifies this service. Returning early without a
	// record is the easily-dropped half, so it is not a separate code path.
	if dec.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
		refusedKind = policyKind(dec.Verdict)
		base.RefusedBy = sekizuiv1.RefusedBy_REFUSED_BY_POLICY
		decisionID, rerr := s.recorder.Terminal(ctx, base)
		if rerr != nil {
			return nil, rerr
		}
		return refusalResult(decisionID, refusedKind,
			fmt.Sprintf("%s (%s)", dec.Reason, dec.Rule)), nil
	}

	// 4b. BREAK-GLASS, which is governed rather than special (D129).
	//
	// AFTER POLICY AND BEFORE RESOLVE, and both halves of that are deliberate.
	// After policy, because a revocation is an authorised action like any other
	// and must be refusable, recorded, and hash-chained by the same path — D18
	// exists to stop a second enforcement path appearing, and break-glass is the
	// most tempting place to grow one. Before resolve, because resolving fetches
	// the credential through the cache: the first act of revoking a credential
	// would otherwise be to go and fetch it.
	if isWithdrawal(cmd.GetAction()) {
		return s.withdraw(ctx, base, cmd)
	}
	if isGrantVerb(cmd.GetAction()) {
		return s.grantVerb(ctx, base, cmd)
	}

	// 5. RESOLVE. The sole constructor of a Target (§6 mechanism 1), and where
	// residency is refused (§7.1 item 2).
	target, err := s.resolver.Resolve(ctx, cmd.GetTargetRef())
	if err != nil {
		// A DELIBERATE REFUSAL HERE IS A RESULT, not a failure (D135) — it is a
		// guarantee working. **WHICH GUARANTEE IS THE PART THIS USED TO GET
		// WRONG (D201).**
		//
		// It gated on `Deliberate()` and labelled everything
		// `REFUSED_BY_RESIDENCY`, using "did Sekizui decide" as a stand-in for
		// "is this residency". So D152's monotonic guard — refusing a credential
		// version that moved BACKWARDS, which is exactly what a disabled
		// compromised version looks like when a platform falls back — produced an
		// audit row naming DATA RESIDENCY as the reason. Proven with a throwaway
		// probe: `refused_by=REFUSED_BY_RESIDENCY` beside a reason about a
		// credential downgrade. The control fired correctly and the record
		// explained it wrongly, which is worse than either alone, because the row
		// is what somebody reviews six months later.
		//
		// **AND THE LABEL IT CHOSE IS THE ONE STAGE THAT CANNOT FIRE HERE.** The
		// residency CEILING is checked in `s.ceilings` before policy (D136);
		// `Resolve` re-checks it only as defence in depth, and both read the same
		// `ResidencyPermitted`. So a residency refusal at this point means the two
		// disagreed — kept, and now the only thing that gets the residency label.
		//
		// The stage cannot be derived from the kind alone: `KindDenied` arises at
		// policy AND at withdrawal, so a global mapping would have to lie about
		// one of them. It CAN be derived from D200's attribution, which is what
		// the axis is for.
		kind := fault.KindOf(err)
		switch {
		case kind == fault.KindResidency:
			return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_RESIDENCY, err)
		case kind.Attribution() == fault.AttributionCredential:
			return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_CREDENTIAL, err)
		case kind == fault.KindConfig:
			return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_CONFIGURATION, err)
		}
		// Anything else — an unknown target, a provider that could not be
		// reached — is a genuine failure and stays an error.
		return nil, s.recordFailure(ctx, base, err)
	}

	// A WITHDRAWN TARGET IS REFUSED HERE, alongside residency, and not inside
	// the driver (D135).
	//
	// The pool refuses it too, as defence in depth, and that is where it used to
	// be caught — after the intent record was written. Which produced a row
	// saying an action was about to happen followed by one saying it did not,
	// for a command Sekizui refused itself. A withdrawn target is not a call
	// that was attempted and failed; it is a call that never should have
	// started, which is exactly the shape of a residency conflict.
	if s.pool != nil {
		if sev, withdrawn := s.pool.Withdrawn(cmd.GetTargetRef()); withdrawn {
			return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL,
				pool.WithdrawnErr(op, cmd.GetTargetRef(), sev))
		}
	}

	// STAMP THE RECORD'S RESIDENCY (D89). Known only now, because it is a
	// property of the resolved target rather than of the request. The audit sink
	// refuses records it may not receive, and it can only do that if the record
	// says where the data came from — the field existed and nothing populated it.
	base.Residency = target.Residency()
	stampPosture(base, s.resolver, cmd.GetTargetRef())

	driver, derr := s.driverFor(op, target)
	if derr != nil {
		return nil, s.recordFailure(ctx, base, derr)
	}

	// PRICED BEFORE IT IS SENT (D283): an Execute result is one object, so a
	// capability whose max_bytes cannot hold one is refused here — the same
	// rule, by the same function, as a read and a job. Before the dry run, so
	// a rehearsal of an unaffordable call shows the refusal it would meet.
	if pspec, ok := s.specFor(driver, cmd.GetAction()); ok {
		if _, _, perr := priceResult(op, cmd.GetAction(), cmd.GetTargetRef(), pspec, args, dec.MaxBytes); perr != nil {
			base.MatchedRule = "capability_max_bytes"
			return refuse(base, sekizuiv1.RefusedBy_REFUSED_BY_REQUEST, perr)
		}
	}

	// 6. DRY RUN stops here, having produced a real audit row. §4.11.4 item 3's
	// shadow mode depends on this: a rule can be observed for a week and
	// produce exactly the records it would have produced, minus the effect.
	if cmd.GetDryRun() {
		base.Verdict = sekizuiv1.Verdict_VERDICT_WOULD_HAVE_FIRED
		decisionID, rerr := s.recorder.Terminal(ctx, base)
		if rerr != nil {
			return nil, rerr
		}
		return &sekizuiv1.CommandResult{
			DecisionId: decisionID,
			Status:     sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED,
		}, nil
	}

	// 7. INTENT BEFORE THE SIDE EFFECT (§5.2.2). If the process dies between
	// here and the driver returning, the record says an action was attempted
	// with no outcome — which is the truth, and far more useful than silence.
	decisionID, err := s.recorder.Intent(ctx, base)
	if err != nil {
		return nil, err
	}

	// 8. THE TENANT ON THE CONTEXT, for the egress assertion the driver makes
	// immediately before its outbound call (§6 mechanism 3). Bound here, once,
	// from the resolved target — so a pooled client belonging to another tenant
	// is caught by comparison rather than trusted.
	ctx = connector.WithTenant(ctx, target.Tenant())

	// 8a/8b. THE METER — §4.3.4's CONSUMING CONTROLS, SHARED WITH EVERY OTHER
	// VERB (D253).
	//
	// **AFTER THE INTENT RECORD, DELIBERATELY, AND THAT IS WHY IT IS NOT PART
	// OF `ceilings`.** A metered refusal is a call that was attempted and
	// stopped by Sekizui; §5.2.2's two-phase shape is what distinguishes it
	// from one that never started. The row already says what was about to
	// happen, and the outcome says it did not. Checking before intent would
	// lose the attempt entirely — and `ceilings` runs before policy, four
	// stages earlier still, where consuming a token would let a caller with no
	// grant drain the budget.
	cost, cerr := driver.Meter().Cost(cmd.GetAction(), args)
	if cerr != nil {
		return nil, s.recordFailure(ctx, base, fault.Wrap(fault.KindInvalidArgument, op,
			"the connector could not price this call before sending it (D284)", cerr))
	}
	meterRef, merr := s.meters(ctx, subject, cmd.GetAction(), cmd.GetTargetRef(), cmd.GetTargetRef(), cost)
	if merr != nil {
		return nil, s.recordFailure(ctx, base, merr)
	}
	if meterRef != nil {
		if oerr := s.recorder.Outcome(ctx, decisionID, &sekizuiv1.Effect{
			Success: false, Attempts: 0, Error: meterRef.err.Error(),
		}); oerr != nil {
			return nil, oerr
		}
		// **THE TWO CONTROLS LEAVE BY DIFFERENT DOORS, AND THE EXTRACTION DID
		// NOT INVENT THAT — IT EXPOSED IT (CONTRACTS 119).** A rate limit has
		// always returned a RESULT here and an open breaker a transport
		// ERROR, while `Query` returns a result for both. Preserved rather
		// than unified, because unifying changes what every caller of
		// `Execute` sees for an open breaker, and P2 step 42c asserts the
		// current shape deliberately.
		//
		// The cause is worth knowing before anybody "tidies" it:
		// `KindTargetUnavailable` is not `Deliberate()`, and it must not be —
		// `ImplicatesTarget` is `AttributionTarget && !Deliberate()`, so
		// making it deliberate would stop the breaker counting the failures
		// it exists to count. That is BREAKER ACCOUNTING deciding a WIRE
		// SHAPE, which is the double duty D138 already caught this predicate
		// doing once.
		if !meterRef.kind.Deliberate() {
			return nil, meterRef.err
		}
		refusedKind = meterRef.kind
		return refusalResult(decisionID, meterRef.kind, meterRef.err.Error()), nil
	}

	// 8c. THE CALL, UNDER THE RETRY POLICY.
	//
	// D113'S REFUSAL IS DECIDED HERE, BEFORE THE FIRST ATTEMPT, because it is a
	// property of the COMMAND rather than of the failure: a mutating action with
	// no idempotency key must not be retried however retryable the error turns
	// out to be. Deciding it inside the predicate keeps the two reasons a retry
	// is refused — "this failure is not retryable" and "this call is not safe to
	// repeat" — in one place the audit record can distinguish.
	//
	// **THE CLASS, NOT THE PRESENCE OF A KEY** (D163, CONTRACTS 63). The old form
	// asked whether the key string was non-empty, and the key reached this
	// predicate and the decision record and nothing else — so it opened the gate
	// on a retry it did not make safe. The spec is what says how a repeat becomes
	// safe, and it travels to the driver below so the driver cannot re-derive a
	// second answer (D155).
	spec, found := s.specFor(driver, cmd.GetAction())
	if !found {
		// **D140'S SAFETY DEFAULT, RESTATED EXPLICITLY — and it was silently lost
		// for the length of one refactor.** This call site used to read
		// `s.isMutating(driver, action)`, whose not-found branch returns TRUE.
		// Replacing it with `spec.Mutating` from a lookup that can miss handed
		// back a ZERO VALUE, so an action nobody declares became non-mutating and
		// freely retryable — the exact inversion D140 wrote the default against.
		//
		// P1 step 34 caught it within the minute, which is D107's argument for
		// old runs executing against the current stack rather than a frozen one.
		//
		// Set explicitly rather than relying on the zero IdempotencyClass also
		// refusing retries. It does, today; a safety property resting on a zero
		// value is D138's and D149's complaint, and the cost of saying it is one
		// line.
		spec = connector.ActionSpec{
			Mutating:    true,
			Idempotency: connector.IdempotencyNone,
		}
	}
	idem := connector.Idempotency{
		Class:     spec.Idempotency,
		Placement: spec.IdempotencyPlacement,
		Key:       cmd.GetIdempotencyKey(),
	}
	noRetryWhy, unsafe := retry.UnsafeToRetry(spec.Mutating, spec.Idempotency, cmd.GetIdempotencyKey())

	var res connector.Result
	callStarted := s.now()

	// **ONE SPAN PER OUTBOUND CALL, CARRYING THE DELEGATION CHAIN (§10.4, D235).**
	//
	// HERE AND NOT AT THE TOP OF Enforce, deliberately. A command refused at a
	// ceiling never reaches a driver, and a span covering the refusal would
	// report a call to a system nobody called — `Trace.span_id`'s emptiness on
	// those rows is the honest answer. This is the last point before the
	// outbound call and it wraps the RETRY, so a re-attempt (D204) is inside one
	// span rather than looking like two calls.
	//
	// THE CHAIN IS AN ATTRIBUTE, not a reconstruction: `mesh:primary →
	// agent:triage` is the question "who asked for this" and a span with only
	// the subject cannot answer it (D7, §4.4.1).
	// NIL-SAFE WITHOUT A BRANCH AT THE CALL SITE. `beginSpan` returns a nil
	// *tracing.Live when no tracer is configured, and `(*Live).End` tolerates
	// nil — so the enforcement path reads the same whether observability is
	// wired or not. A branch here would be a second shape for the hot path to
	// have, which is how one of them comes to be untested.
	span := s.beginSpan(
		base.GetTrace().GetTraceId(), base.GetTrace().GetParentSpanId(),
		base.GetTrace().GetSampled(),
		cmd.GetAction(),
		map[string]string{
			"sekizui.target":      cmd.GetTargetRef(),
			"sekizui.action":      cmd.GetAction(),
			"sekizui.caller":      id.GetCaller().GetPrincipal(),
			"sekizui.subject":     subject,
			"sekizui.chain":       strings.Join(id.GetChain(), " -> "),
			"sekizui.decision_id": decisionID,
		})
	defer span.End()
	// THE RECORD NAMES THE SPAN, so a trace and an audit row join in both
	// directions. Stamped on the base before the outcome row is written.
	if t := base.GetTrace(); t != nil && span != nil {
		t.SpanId = span.SpanID()
	}

	// PER TARGET (D142). Jira's tolerance is not BigQuery's, and the deployment
	// flag is the ceiling this may only narrow — enforced at boot, not here.
	attempts, execErr := s.retry.For(cmd.GetTargetRef()).Do(ctx,
		func(err error) bool { return !unsafe && retry.Retryable(err) },
		func(ctx context.Context) error {
			var callErr error
			res, callErr = driver.Execute(ctx, target, cmd.GetAction(), args, idem)
			return callErr
		})

	// THE CALL'S ANSWER GOES BACK TO BOTH CONTROLS, through the same helper
	// `Query` uses (D253). These two blocks were duplicated verbatim across the
	// verbs, and a drift between them would have been invisible until a read
	// and a write disagreed about whether a target was healthy.
	s.meterOutcome(ctx, subject, cmd.GetAction(), cmd.GetTargetRef(), execErr)

	// **THE EGRESS ASSERTION'S ESCALATION FROM ONE REFUSAL TO A CONDITION
	// (D226, §6 mechanism 3).** The assertion already refuses the call; what did
	// not exist is anything that turns that refusal into a level an anzen rule
	// can act on, which left `tenant_mismatch` a vocabulary entry a config could
	// watch and nothing could raise (CONTRACTS 65).
	//
	// **`errors.Is` ON A SENTINEL, NEVER THE KIND AND NEVER THE MESSAGE.** The
	// kind is `internal` and deliberately shared with an unresolved target and an
	// absent request tenant, so it cannot tell them apart; the message says
	// "TENANT MISMATCH" and matching that survives until somebody improves the
	// sentence.
	//
	// HERE, beside the breaker, because both are judgements about the same
	// classified error — and a mismatch is OURS, so the breaker above correctly
	// leaves a healthy vendor's circuit closed while this raises the condition
	// against us.
	if s.mistenant != nil && errors.Is(execErr, connector.ErrTenantMismatch) {
		s.mistenant.Record(cmd.GetTargetRef())
	}

	// 8d. THE REFUSAL SEKIZUI OWES THE CALLER (D182).
	//
	// **THE GATE ABOVE CLOSED AND NOBODY WAS TOLD.** `unsafe` stopped Sekizui
	// retrying, which is D163 working — and then the upstream's own error went
	// back to the caller unchanged. That error is a TIMEOUT, which the taxonomy
	// classifies as retryable and gRPC maps to DeadlineExceeded, so a
	// well-behaved agent consulting either one retries and produces exactly the
	// duplicate the gate refused to produce. The hazard was not removed; it was
	// relocated one hop out, to a caller with no idempotency-class table.
	//
	// **RETRYABILITY AND INDETERMINACY ARE DIFFERENT QUESTIONS**, and this
	// condition asks the second one. The first draft asked `retry.Retryable`,
	// which is wrong on the commonest retryable kind there is: a 429 means the
	// upstream declined to act, so the effect is KNOWN not to have happened and
	// reporting an unknown outcome would send an operator to reconcile nothing —
	// while suppressing the RetryAfter that says when to come back. A rate limit
	// therefore falls through to the Deliberate branch below and reaches the
	// caller as `rate_limited`, exactly as it does today.
	//
	// THE CAUSE IS WRAPPED RATHER THAN REPLACED, so the audit row and any
	// errors.Is still carry the timeout underneath. One consequence is
	// deliberate: fault.RetryAfterOf now finds this wrapper's zero rather than
	// the upstream's number, which is the correct answer — advertising a backoff
	// would contradict the refusal in the same response.
	outcomeErr := execErr
	if unsafe && fault.KindOf(execErr).Indeterminate() {
		// **THE FIRST SENTENCE CARRIES EVERYTHING AN OPERATOR NEEDS, because it
		// is the only one they see.** `firstLine` truncates a refusal at the
		// first ". " for log readability, with the full text in the audit record —
		// a deliberate trade, and it means sentence one is the whole demo (D115).
		// The first draft put the mechanism there and the INSTRUCTION second, so
		// the line a human watches said the outcome was unknown and never said
		// what to do about it. Found by running `make demo` rather than by
		// asserting it worked.
		//
		// Action, class, state, instruction, target — in that order, in one
		// sentence. The reasoning follows for whoever wants it.
		outcomeErr = fault.Wrap(fault.KindIndeterminate, op, fmt.Sprintf(
			"the call to %q is idempotency class %q and its outcome is UNKNOWN — "+
				"do NOT repeat it; reconcile against %s. The effect may already have "+
				"landed, and repeating it is the double-write this refusal exists to "+
				"prevent: %s",
			cmd.GetAction(), spec.Idempotency, cmd.GetTargetRef(), noRetryWhy), execErr)
	}

	// **SHAPED BEFORE IT IS RECORDED OR RETURNED (D283).** A write's result —
	// and every MCP tool's, since `tools/call` is MCP's only verb — was written
	// into the audit record exactly as the far side sent it, and handed to the
	// caller the same way. Now it is shaped to the action's declared output type
	// first, and a NoResult action's data is withheld: nothing reaches the WAL
	// that the connector did not declare.
	// A HANDLE LIFECYCLE (D291), from the driver's RAW result, before shaping.
	s.trackHandle(spec, driver, id, cmd, args, res.Data, decisionID)
	res.Data = s.shapeResult(cmd.GetAction(), cmd.GetTargetRef(), spec, res.Data)

	effect := &sekizuiv1.Effect{
		Success:   outcomeErr == nil,
		LatencyMs: s.now().Sub(callStarted).Milliseconds(),
		// REAL, AT LAST. This read a hardcoded 1 for as long as nothing retried
		// — and would have gone on reading 1 while retries happened underneath
		// it, which is CONTRACTS §4 item 22's shape: a declared field stating
		// something the system stopped doing.
		Attempts:    uint32(attempts), //nolint:gosec // bounded by Policy.MaxAttempts
		ExternalRef: res.ExternalRef,
		StatusCode:  int32(res.StatusCode),
	}
	// BOTH FACTS IN ONE STRING. The upstream's failure AND the refusal to repeat
	// it, because `attempts` reading 1 under a policy that permits three is
	// otherwise indistinguishable from the retry code being broken.
	if outcomeErr != nil {
		effect.Error = outcomeErr.Error()
	}
	// **ALWAYS SET, NEVER CONDITIONALLY (D177).** This used to read
	// `if detail, derr := structpb.NewStruct(...); derr == nil`, so a driver
	// returning one value protobuf could not represent made the effect detail
	// vanish while the record went on reporting a successful effect. Drivers are
	// third-party (D35) and legitimately echo upstream responses, which made that
	// an attacker-reachable way to render an effect unauditable.
	//
	// Never contains credentials: Secret is self-redacting by type, drivers are
	// told not to put material here (Effect.detail's contract), and safestruct's
	// marker names the TYPE of an unrepresentable value rather than its content.
	// THE RECORDED COPY, NOT THE RETURNED ONE (D289): caller-only fields left
	// as a trace and scrubbed from every other string, long strings cut. The
	// caller's copy at the end of this function is converted from res.Data.
	detail, rep := safestruct.Convert(s.forRecord(spec, res.Data), safestruct.DefaultBudget)
	effect.Detail = detail
	if rep.Truncated {
		// **BOUNDED BEFORE THE WAL, WHICH IS THE POINT (D178).** This detail is
		// about to be written and fsynced, so an unbounded driver result is a
		// write amplifier aimed at Sekizui's disk — and a full audit volume fails
		// CLOSED, turning a disk attack into a total outage.
		s.log.Warn("driver result exceeded the effect-detail budget and was truncated; "+
			"the record is short but says so",
			"action", cmd.GetAction(), "target", cmd.GetTargetRef(),
			"budget_bytes", safestruct.DefaultBudget)
	}
	if len(rep.Substituted) > 0 {
		// SURFACED AS WELL AS RECORDED. The audit row carries it durably; this
		// tells whoever is watching a terminal, because a driver producing
		// unrepresentable data is a defect worth fixing and — if it is coming from
		// upstream content rather than from driver code — a signal.
		s.log.Warn("driver returned values protobuf cannot represent; they were "+
			"substituted rather than dropped, and the effect detail is complete",
			"action", cmd.GetAction(), "target", cmd.GetTargetRef(),
			"fields", rep.Substituted)
	}

	// 9. OUTCOME. Written whether the call succeeded or failed — a failed
	// external call is exactly the case where the record matters.
	// THE SPAN THAT COVERED THE CALL, on the row that describes it (D235).
	//
	// NOT ON THE INTENT ROW: the span begins after the limiter, the breaker and
	// the resolver, so the intent is already durable — and a command refused
	// before any of that never reached a driver, where an id would name a span
	// that does not exist. `SpanID()` is empty for a nil span and `WithSpan`
	// ignores an empty id, so an untraced deployment writes the field as absent.
	if oerr := s.recorder.Outcome(ctx, decisionID, effect,
		audit.WithSpan(span.SpanID())); oerr != nil {
		return nil, oerr
	}

	// 9a. THE ONE PLACE THAT REPORTS "THIS COULD BE RE-ESTABLISHED" (D203, D204).
	//
	// AFTER THE OUTCOME ROW IS DURABLE, deliberately. The loop above will make a
	// second call on somebody's system; the row saying the first one happened
	// must exist before that, for §5.2.2's reason and because the second row's
	// causation names this one.
	//
	// **THE MARKER IS THE PRODUCER'S, NOT THE KIND'S (D203).** Read through
	// whatever wrapping the driver and D182 applied, because a static answer
	// would be wrong for four of `KindUnauthenticated`'s five producers — and for
	// D152's downgrade guard, retrying is the attacker's goal.
	//
	// **GATED BY D163'S CLASS, NOT BY A SECOND POLICY.** `unsafe` already says
	// this call must not be repeated: a 401 normally means the far side rejected
	// before executing, and "normally" is not a guarantee for every vendor, so a
	// `none`-class action is never silently repeated for a reason that looks
	// benign.
	if what := fault.ReestablishOf(outcomeErr); !unsafe && what != fault.ReestablishNone {
		*again = reattempt{decisionID: decisionID, what: what}
	}

	if outcomeErr != nil {
		// UNIFORM SHAPE (D135): a driver that refuses on purpose — spec drift
		// (D48), an upstream saying no — reaches the caller as a result like
		// every other refusal, so a client catches one category one way.
		//
		// D182 NEEDED NO NEW EXIT PATH, which is the argument for making
		// KindIndeterminate Deliberate rather than adding a branch: the wrap
		// above is the whole change, and this machinery — the refusal
		// constructor, the metric label, the report line — picks it up by
		// construction. A second return site would have been a second place to
		// forget the `kind` field (D138).
		//
		// `refused_by` is NOT set: this is an OUTCOME-phase fact and the row
		// carrying it was already written at intent. That is why the enum has no
		// REFUSED_BY_DRIVER member — a value nothing writes is the defect this
		// codebase keeps finding, and it lands with P2's drivers alongside a
		// writer.
		if kind := fault.KindOf(outcomeErr); kind.Deliberate() {
			refusedKind = kind
			return refusalResult(decisionID, kind, outcomeErr.Error()), nil
		}
		// **THE ID GOES ON THE FAILURE TOO, AND IT DID NOT UNTIL D211 (D202's
		// unmet half).** D202 fixed this for `recordFailure` — the funnel every
		// REFUSAL and every pre-call failure passes through — and this is the
		// sibling path: a command that was authorised, called, and failed at the
		// far side. The Intent and Outcome rows were both written naming
		// `decisionID`, which is in scope on this line, and the caller got the
		// driver's error with no way to name either of them.
		//
		// **IT IS THE COMMONEST FAILURE IN PRODUCTION**, which is what made the
		// gap worth finding: a vendor blowing up mid-command. Step 41 asserted
		// D202's claim and only ever drove the OTHER path, because its fixture
		// used an unknown target ref — refused before any driver was reached.
		// Rebuilding that fixture around a driver that genuinely fails is what
		// surfaced this.
		//
		// COPIES rather than mutates (D202's own rule): the retry path shares
		// one error across attempts, so writing into it would stamp the first
		// attempt's id onto the second.
		return nil, fault.WithDecisionID(outcomeErr, decisionID)
	}

	// **THE RETURNED COPY, LENSED (D290).** Shin was applied to Query rows, bus
	// deliveries and job results — and never to an Execute result, which is
	// how every MCP tool's output returns. So no lens could reach one: a
	// deployment could not keep an agent from receiving a tool's prose, the
	// carrier of any instructions planted in it (CONTRACTS 141). Imposed lenses
	// only — a command selects none. A lens that cannot deliver refuses the
	// DELIVERY, not the action, which already happened and is recorded, exactly
	// as Query does.
	//
	// THE RECORD AND THE CALLER NO LONGER AGREE, ON PURPOSE (D289, D290): the
	// record is forRecord's copy — caller-only fields as traces, long strings
	// cut — and unlensed, because the audit is the truth and a lens is what one
	// consumer receives. The conversion itself is still safestruct's (D177).
	returned := res.Data
	if res.Data != nil && s.lenses != nil {
		projected, _, lerr := s.lenses.Apply(shin.Request{
			Principal: id.GetSubject().GetPrincipal(),
			Type:      spec.OutputType,
			Residency: target.Residency(),
			Added:     id.GetSubject().GetTokenLenses(), // a signed subject's token may add (D303)
		}, res.Data)
		if lerr != nil {
			return nil, fault.WithDecisionID(lerr, decisionID)
		}
		returned = projected
	}
	// THE SEIREN BESIDE `result` (D300, D317): the same function a Query uses,
	// over the one object the action returned, after its lens. kata's write
	// rule exercises it (P4 step 20d, CONTRACTS 145).
	var seiren *sekizuiv1.Seiren
	if returned != nil {
		var serr error
		seiren, serr = s.seirenFor(cmd.GetTargetRef(), shin.Request{Principal: id.GetSubject().GetPrincipal(),
			Type: spec.OutputType, Residency: target.Residency(), Added: id.GetSubject().GetTokenLenses()},
			[]map[string]any{returned}, false, 0)
		if serr != nil {
			return nil, fault.WithDecisionID(serr, decisionID)
		}
	}
	out, _ := safestruct.Convert(returned, safestruct.DefaultBudget)
	return &sekizuiv1.CommandResult{
		DecisionId: decisionID,
		Status:     sekizuiv1.Status_STATUS_OK,
		Result:     out,
		Seiren:     seiren,
	}, nil
}

// THE GOVERNED VERBS LIVE IN `internal/verb` (D195).
//
// They were constants here, with their reasoning attached. The catalog needs
// each verb's DESCRIPTION to advertise it without synthesising one (D196) and
// the gateway imports the catalog, so the table had to move somewhere both could
// read — Go reporting the import cycle before the argument had to be made. Boot
// validation reads the same set to refuse a grant naming a verb this build does
// not serve, which is the third reader and the reason it is a package rather
// than a shared file.
//
// The two REF PREFIXES stay here: they are how this dispatch path tells a
// principal reference from a target ref, and nothing outside it parses them.
const (
	// principalRefPrefix namespaces a principal reference in `target_ref`, so a
	// grant cannot be mistaken for a target and boot can tell them apart.
	principalRefPrefix = "principal:"

	// anzenRefPrefix namespaces a rule reference so it cannot be mistaken for a
	// target ref, and so a grant reads unambiguously.
	anzenRefPrefix = "anzen:"
)

func isWithdrawal(action string) bool {
	spec, ok := verb.Lookup(action)
	return ok && spec.Withdrawal
}

// isGrantVerb reports whether an action suspends or reinstates a principal.
func isGrantVerb(action string) bool {
	spec, ok := verb.Lookup(action)
	return ok && spec.GrantVerb
}

// revocationDrainBudget bounds how long a revocation waits for in-flight calls
// to notice they were cancelled.
//
// Short, because it is not waiting for work to FINISH — it is waiting for
// already-cancelled calls to unwind. A driver that honours its context returns
// in microseconds; one that does not will not return in thirty seconds either,
// and an operator holding a break-glass call open during an incident is the
// worst possible thing to make wait. Exceeding it is reported as a straggler
// rather than escalated, because there is nothing safe left to escalate TO:
// D127 declines to wipe under a live reader.
const revocationDrainBudget = 2 * time.Second

// withdraw runs a break-glass verb and records what it did.
//
// TERMINAL, NOT INTENT/OUTCOME. The two-phase shape exists because a side
// effect at an external system may or may not have landed when the process dies
// (§5.2.2). A withdrawal touches nothing outside this process, so there is no
// such ambiguity — and a two-phase record would imply one.
func (s *Server) withdraw(ctx context.Context, base *sekizuiv1.Decision,
	cmd *sekizuiv1.Command) (*sekizuiv1.CommandResult, error) {

	const op = "gateway.withdraw"

	action, ref := cmd.GetAction(), cmd.GetTargetRef()

	// FIRING A RULE RESOLVES TO A VERB PLUS A SUBJECT, and everything after this
	// point is identical to an operator having typed them. One code path, so a
	// rule-driven withdrawal and an improvised one cannot drift in what they do
	// — only in what the record says decided them.
	var decidedBy string
	if action == verb.FireAnzen {
		rule, rerr := s.resolveRule(ref)
		if rerr != nil {
			// Anzen's vocabulary refusing: an undeclared rule, a shadow rule, or
			// a reference that is not a rule at all. Deliberate, so it is a
			// result like every other refusal (D135).
			if fault.KindOf(rerr).Deliberate() {
				return s.refuse(ctx, base, sekizuiv1.RefusedBy_REFUSED_BY_ANZEN, rerr)
			}
			return nil, s.recordFailure(ctx, base, rerr)
		}
		// THE TWO ACTIONS THAT WITHDRAW NOTHING leave here (D332), before the
		// subject is looked up as a target — which is the lookup that, reached
		// with an alert, used to REVOKE it (D331).
		switch rule.Do {
		case "alert":
			return s.anzenAlert(ctx, base, rule)
		case "disable_reflex":
			return s.anzenDisableReflex(ctx, base, rule)
		case "revoke_grant":
			return s.anzenRevokeGrant(ctx, base, rule)
		}
		action, ref, decidedBy = "sekizui."+rule.Do, rule.Subject, rule.Name
		base.TargetRef = ref
	}

	// The spec, NOT a resolve. Carries the credential reference the record must
	// name and the residency the audit sink routes on, without asking a provider
	// for material we are in the middle of revoking.
	spec, known := s.specs[ref]
	if !known {
		// KindConfig for the resolver's reason (D211): the grant that authorised
		// this withdrawal names a target boot checked against the target list, so
		// an unconfigured one here is our own inconsistency rather than a caller
		// naming something that does not exist.
		return nil, s.recordFailure(ctx, base, fault.New(fault.KindConfig, op,
			"no target "+ref+" is configured, so there is nothing to withdraw — and a "+
				"grant authorised it, which boot refuses when the target list disagrees"))
	}
	base.Residency = spec.Residency

	if s.pool == nil {
		// REFUSES RATHER THAN REPORTING A CLEAN NO-OP. A revocation that
		// withdraws nothing and returns OK is the worst outcome available here:
		// an operator reads success during an incident and stops looking.
		return nil, s.recordFailure(ctx, base, fault.New(fault.KindUnavailable, op,
			"this instance has no client pool, so "+cmd.GetAction()+" has nothing to "+
				"withdraw from and cannot honestly report success"))
	}

	// The trigger, which is NOT the identity. Identity says who authenticated;
	// trigger says what fired this, and for an anzen rule there is no human
	// behind it at all (§4.11).
	trigger := "operator:" + base.GetIdentity().GetSubject().GetPrincipal()
	if name := audit.ReflexNameFrom(ctx); name != "" {
		trigger = "anzen:" + name
	}

	if action == verb.RestoreTarget {
		return s.restore(ctx, base, ref, trigger)
	}

	// A WITHDRAWAL THAT CANNOT BE RECORDED DURABLY MUST FAIL (D145). Reporting a
	// successful revocation whose effect evaporates at the next restart is the
	// false reassurance §4.7.10 and D133 both refuse — worse than failing,
	// because an operator stops looking.
	var (
		w    pool.Withdrawal
		werr error
	)
	// D158's RULE, DERIVED FROM THE REGISTRY RATHER THAN WRITTEN HERE (D165).
	//
	// This branch and its twin in `grant_verb.go` were two hand-written copies
	// of one decision, each composing its own confirmation message, and only
	// THIS one handled escalation. `verb.Repeated` is now the single derivation
	// for all six verbs; what stays here is the pool's own vocabulary — which
	// severity a prior withdrawal holds, and whether this call raises it — plus
	// shaping the answer into a `CommandResult`, which is D155's "shared code,
	// not copied checks".
	// **ONLY THE TWO WITHDRAWALS REACH THE POOL, NAMED, AND ANYTHING ELSE IS
	// REFUSED (D331, CONTRACTS 157).** This read "not quarantine, so revoke", and
	// `fire_anzen` rewrites `action` to the rule's `do` — so a rule doing
	// `alert` ("changes no behaviour"), `disable_reflex` or `restrict_shin`,
	// fired by the dispatcher, REVOKED its subject's credential. Found by probe,
	// building P5 step 5. Boot now refuses an enforcing rule whose action is not
	// implemented; this is the backstop for any path that reaches here anyway.
	switch action {
	case verb.QuarantineTarget, verb.RevokeCredential:
	default:
		why := fmt.Sprintf("%s is not a withdrawal this build performs; only %s and %s withdraw a target, "+
			"and nothing else is guessed into one (D331)", action, verb.QuarantineTarget, verb.RevokeCredential)
		if decidedBy != "" {
			why = fmt.Sprintf("anzen rule %s does %s, which this build does not implement — refused rather "+
				"than acted on as a revocation of %s (D331)", decidedBy, strings.TrimPrefix(action, "sekizui."), ref)
		}
		return s.refuse(ctx, base, sekizuiv1.RefusedBy_REFUSED_BY_ANZEN, fault.New(fault.KindDenied, op, why))
	}
	prior, already := s.pool.PriorWithdrawal(ref)
	wanted := pool.SeverityRevoke
	if action == verb.QuarantineTarget {
		wanted = pool.SeverityQuarantine
	}
	// THE VERB LOOKED UP FROM THE ACTION AS REWRITTEN, which matters for
	// `fire_anzen`: `action` is the rule's `do` by this point, so a lever that
	// fires `revoke` behaves exactly like `revoke` — including escalating an
	// already-quarantined target. The registry's own test holds the withdrawal
	// verbs to one State and one Lifetime, so consulting either entry gives the
	// same answer and cannot drift into giving two.
	vspec, _ := verb.Lookup(action)
	if resp, decided := verb.Repeated(vspec, ref, verb.Prior{
		Present: already, At: prior.At, By: prior.Trigger, Detail: prior.Severity,
		Escalating: escalates(prior.Severity, wanted),
	}); decided && resp.Confirm {
		base.Revocation = &sekizuiv1.Revocation{
			Severity: prior.Severity, Trigger: prior.Trigger, DecidedBy: decidedBy,
			// ZEROES, TRUTHFULLY. Nothing was cancelled, evicted or torn down,
			// because there was nothing left to act on — and a record claiming
			// otherwise would make a repeat indistinguishable from work.
		}
		return s.confirmRepeat(ctx, base, resp)
	}

	switch action {
	case verb.QuarantineTarget:
		w, werr = s.pool.Quarantine(ctx, ref, trigger)
	case verb.RevokeCredential:
		drainCtx, cancel := context.WithTimeout(ctx, revocationDrainBudget)
		defer cancel()
		w, werr = s.pool.Revoke(drainCtx, ref, trigger)
	}
	if werr != nil {
		return nil, s.recordFailure(ctx, base, werr)
	}

	base.Revocation = &sekizuiv1.Revocation{
		Severity:          w.Severity.String(),
		Trigger:           trigger,
		CancelledInFlight: uint32(w.Cancelled),
		LeftRunning:       uint32(w.LeftRunning),
		Evicted:           uint32(w.Evicted),
		TornDown:          uint32(w.TornDown),
		Stragglers:        uint32(w.Stragglers),
		DecidedBy:         decidedBy,
	}

	decisionID, err := s.recorder.Terminal(ctx, base)
	if err != nil {
		return nil, err
	}

	s.log.Warn("break-glass withdrawal",
		"severity", w.Severity.String(), "target", ref, "trigger", trigger,
		"decided_by", decidedBy,
		"cancelled", w.Cancelled, "left_running", w.LeftRunning,
		"evicted", w.Evicted, "torn_down", w.TornDown, "stragglers", w.Stragglers,
		"decision_id", decisionID)

	if decidedBy == "" {
		// THE GAP, NAMED — AND THERE ARE TWO OF THEM (D134).
		//
		// An improvised withdrawal is legitimate; the unanticipated incident is
		// what break-glass is for. What must not read as health is its absence
		// from configuration. But "nobody has decided what to do about this
		// target" and "somebody has, and it was bypassed" are different
		// problems, and the second is the worse one: a reviewed decision existed
		// and the response was composed under pressure anyway. Reporting both
		// with one message hides that.
		if declared := s.guards.DeclaredFor(ref); len(declared) > 0 {
			s.log.Warn("this withdrawal BYPASSED an anzen rule that already covers it",
				"target", ref, "severity", w.Severity.String(),
				"available_rules", strings.Join(declared, ", "),
				"gap", "a reviewed decision exists for this target and was not used, so "+
					"the severity was chosen during the incident instead. Fire it with "+
					verb.FireAnzen+" unless it was deliberately wrong for this case — "+
					"in which case the rule is what needs changing")
		} else {
			s.log.Warn("this withdrawal had no anzen rule behind it",
				"target", ref, "severity", w.Severity.String(),
				"gap", "no rule declares what to do when this target is compromised, so "+
					"the subject and the severity were chosen during the incident rather "+
					"than reviewed before it. Declare an anzen rule and fire it with "+
					verb.FireAnzen)
		}
	}

	return &sekizuiv1.CommandResult{
		DecisionId: decisionID,
		Status:     sekizuiv1.Status_STATUS_OK,
	}, nil
}

// restore lifts a withdrawal (D133).
//
// REFUSES A NO-OP. Restoring a target nobody withdrew reports an error rather
// than success, because during an incident a mistyped reference that answers OK
// is worse than one that fails: the operator believes the target is back and
// stops looking.
func (s *Server) restore(ctx context.Context, base *sekizuiv1.Decision,
	ref, trigger string) (*sekizuiv1.CommandResult, error) {

	const op = "gateway.restore"

	from, was, rerr := s.pool.Restore(ctx, ref)
	if rerr != nil {
		// The lift could not be recorded. Reported as a failure rather than a
		// success, or the target comes back from the dead at the next restart.
		return nil, s.recordFailure(ctx, base, rerr)
	}
	// D158's REFUSING HALF, DERIVED (D165). The precondition is false: the
	// operator believes there is a withdrawal to lift and there is not.
	vspec, _ := verb.Lookup(verb.RestoreTarget)
	if resp, decided := verb.Repeated(vspec, ref, verb.Prior{Present: was}); decided && resp.Refuse {
		return s.refuse(ctx, base, sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL,
			fault.New(fault.KindInvalidArgument, op, resp.Reason))
	}

	base.Restoration = &sekizuiv1.Restoration{
		Trigger:      trigger,
		RestoredFrom: from.String(),
	}

	decisionID, err := s.recorder.Terminal(ctx, base)
	if err != nil {
		return nil, err
	}

	// WARN, not INFO. Lifting a revocation asserts that a credential believed
	// compromised is safe again — among the highest-value lines an operator can
	// see in real time, and the counterpart to the revocation's own WARN.
	s.log.Warn("withdrawal lifted",
		"target", ref, "restored_from", from.String(), "trigger", trigger,
		"decision_id", decisionID)

	return &sekizuiv1.CommandResult{
		DecisionId: decisionID,
		Status:     sekizuiv1.Status_STATUS_OK,
	}, nil
}

// confirmRepeat records D158's confirmation and returns it as STATUS_OK (D165).
//
// **THE FUNNEL FOR THE CONFIRMING HALF, and the reason it exists is that there
// were two of it.** The withdrawal family and the grant family each recorded
// their own confirmation and each built their own `CommandResult`, so a change
// to what a confirmation carries had two places to be made and was made in one.
// `verb.Repeated` composes the sentence; this records it and shapes the result.
// Each caller still sets its own record fields first — the withdrawal's truthful
// zeroes, the suspension's matched rule — which is the part that genuinely
// differs.
//
// **THE VERDICT IS ALLOW, AND IT IS SET HERE RATHER THAN LEFT.** A confirmation
// is not a refusal: the caller's goal is met, and the row says the command was
// permitted because it was. D228's floor governs the other direction and this is
// the one place a `refused_by`-free OK is written for a call that did no work.
func (s *Server) confirmRepeat(ctx context.Context, base *sekizuiv1.Decision,
	resp verb.Response) (*sekizuiv1.CommandResult, error) {

	base.Verdict = sekizuiv1.Verdict_VERDICT_ALLOW
	base.Reason = resp.Reason

	decisionID, rerr := s.recorder.Terminal(ctx, base)
	if rerr != nil {
		return nil, rerr
	}
	return &sekizuiv1.CommandResult{
		DecisionId: decisionID,
		Status:     sekizuiv1.Status_STATUS_OK,
		Reason:     resp.Reason,
	}, nil
}

// refuse records a deliberate refusal and returns it as a RESULT (D135).
//
// THE ONE PLACE THE SHAPE IS DECIDED. Every stage that says no on purpose comes
// through here, so a caller catches one category one way — and the decision id
// on the result is what lets D124's stdout line join to the record that
// explains it, which it could not do while refusals left as transport errors.
//
// The status is `Kind.Status()` rather than a hardcoded DENIED: that mapping
// already distinguishes escalation and rate limiting, and flattening them would
// discard distinctions §4.11.4 and D48 depend on.
func (s *Server) refuse(ctx context.Context, base *sekizuiv1.Decision,
	by sekizuiv1.RefusedBy, err error) (*sekizuiv1.CommandResult, error) {

	kind := fault.KindOf(err)
	base.RefusedBy = by

	// **A ROW THIS FUNCTION WRITES MUST NEVER READ AS PERMISSION.**
	//
	// It did, four times in one acceptance run, and the run was green. The base
	// Decision arrives carrying whatever the stages before it set: NOTHING when
	// the refusal is pre-policy (D215's idempotency-key bound, refused before the
	// intent record exists) and **ALLOW, with a matched_rule naming the grant,
	// when policy admitted the command and a later stage refused it** —
	// `restore_target` on a healthy target, `revoke_grant` with no reason. Both
	// were KindInvalidArgument, `Verdict()` returned ok=false for it, and so the
	// field was left exactly as it was found. A SIEM asking "what was allowed"
	// got three commands that never ran; a SIEM asking "what was denied" got
	// none of them.
	//
	// THE FLOOR IS SET FIRST AND REFINED, rather than being the mapping's `else`.
	// The invariant belongs to this funnel and not to the taxonomy: whatever some
	// later kind turns out to mean, a refusal recorded here is a command that did
	// not proceed. Leaving it to `Verdict()` is what failed, and it failed
	// SILENTLY and in the direction where the log looks complete — the class this
	// codebase keeps finding (CONTRACTS 23).
	//
	// D138 put `status` and `kind` behind one constructor for exactly this
	// reason, and its guard is named "both views". The audit record was the
	// third.
	base.Verdict = sekizuiv1.Verdict_VERDICT_DENY
	if v, ok := kind.Verdict(); ok {
		base.Verdict = v
	}
	if base.GetReason() == "" {
		base.Reason = err.Error()
	}

	decisionID, rerr := s.recorder.Terminal(ctx, base)
	if rerr != nil {
		return nil, rerr
	}
	return refusalResult(decisionID, kind, err.Error()), nil
}

// refusalResult builds the wire result for a deliberate refusal (D138).
//
// ONE CONSTRUCTOR, so `status` and `kind` are DERIVED FROM THE SAME fault.Kind
// and cannot disagree. Set separately at each exit path they eventually would:
// the coarse status says DENIED while the fine kind says rate_limited, and a
// caller that trusted either would be wrong about the other. There is no
// argument for the two to differ, so the code offers no way to make them.
//
// It is also the answer to "what stops `kind` joining the unpopulated-field
// list" (CONTRACTS item 23). A refusal path that forgets this constructor is a
// refusal path that also forgot to set a status, which is not a mistake that
// survives a test — and TestEveryRefusalUsesTheConstructor makes it a build
// failure rather than a hope.
func refusalResult(decisionID string, kind fault.Kind, reason string) *sekizuiv1.CommandResult {
	return &sekizuiv1.CommandResult{
		DecisionId: decisionID,
		Status:     kind.Status(),
		// THE STABLE TAXONOMY WORD, the same one the metric label and the audit
		// record carry (D125). A caller, a dashboard and a log line then use one
		// vocabulary rather than three.
		Kind:   kind.String(),
		Reason: reason,
	}
}

// policyKind maps a non-allow verdict back to the kind that labels it, so a
// policy refusal meters as `denied` or `escalated` rather than collapsing into
// whatever Status it shares with residency.
func policyKind(v sekizuiv1.Verdict) fault.Kind {
	switch v {
	case sekizuiv1.Verdict_VERDICT_ESCALATE:
		return fault.KindEscalated
	case sekizuiv1.Verdict_VERDICT_BUDGET_EXCEEDED:
		return fault.KindBudgetExceeded
	default:
		return fault.KindDenied
	}
}

// resolveRule turns an `anzen:<name>` reference into the decision it holds.
func (s *Server) resolveRule(ref string) (anzen.Reactive, error) {
	const op = "gateway.resolveRule"

	name, ok := strings.CutPrefix(ref, anzenRefPrefix)
	if !ok {
		return anzen.Reactive{}, fault.New(fault.KindInvalidArgument, op,
			verb.FireAnzen+" names an anzen RULE rather than a target; use "+
				anzenRefPrefix+"<rule-name>")
	}

	rule, found := s.guards.Rule(name)
	if !found {
		return anzen.Reactive{}, fault.New(fault.KindNotFound, op,
			"no enabled anzen rule named "+name+". A disabled rule is absent from "+
				"configuration's point of view, so this fails the same way a misspelled "+
				"name does — deliberately, because silently doing nothing during an "+
				"incident is the worst available outcome")
	}
	if !rule.Enforcing {
		return anzen.Reactive{}, fault.New(fault.KindDenied, op,
			"anzen rule "+name+" is in SHADOW mode and cannot be fired. §4.11.4 wants a "+
				"rule observed before it is trusted, and an observation somebody can "+
				"discharge on demand is not an observation. Move it to enforce, or use "+
				"the raw verb and accept that the record will show no rule decided it")
	}
	return rule, nil
}

// Query is the read plane. Governed identically to Execute (§4.1.1) — "an agent
// running an unbounded scan across BigQuery is a data-exfiltration path".
func (s *Server) Query(ctx context.Context, req *sekizuiv1.QueryRequest) (resp *sekizuiv1.QueryResponse, err error) {
	release, aerr := s.admission.Acquire(ctx, "Query")
	if aerr != nil {
		return nil, toStatus(aerr)
	}
	defer release()

	// Reads are metered exactly like writes. §4.1.1: "an agent running an
	// unbounded scan across BigQuery is a data-exfiltration path" — a read plane
	// nobody counts is one nobody notices being abused.
	// Declared before the defer so the closure can read whatever Verify sets.
	// The deferred report runs even when Verify itself fails, and then has no
	// identity to name — which is correct: an unauthenticated caller has no
	// principal, and inventing one would be the "unknown denied something" row
	// D39 rejected.
	var id *sekizuiv1.Identity

	qStarted := s.now()
	defer func() {
		outcome := queryOutcomeLabel(resp, err)
		took := s.now().Sub(qStarted)
		s.metrics.Observe(req.GetTargetRef(), req.GetAction(), outcome, took)
		// Query still returns its refusals as errors, so the kind is read from
		// the error and there is nothing to carry. When the read plane adopts
		// D135's shape this gains the same treatment as Execute.
		s.report(id, req.GetAction(), req.GetTargetRef(), outcome, took,
			resp.GetDecisionId(), resp.GetReason(), err, fault.KindUnknown)
	}()

	id, err = s.verifier.Verify(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	// EVERY CEILING, THE SAME ONES Execute APPLIES AND IN THE SAME ORDER
	// (D18, D155).
	//
	// This was absent, and its absence was a hole in break-glass rather than a
	// missing nicety: a read returned STATUS_OK with a row against a target whose
	// credential had just been revoked as compromised. A suspended principal
	// could still read, and an anzen `forbids` rule did not reach reads at all.
	//
	// §4.1.1 is the sentence this restores: the two planes are "distinguishable
	// in policy and audit, not differently governed".
	subject := id.GetSubject().GetPrincipal()
	_, releaseCeilings, ceilingRef := s.ceilings(ctx, id, subject,
		req.GetAction(), req.GetTargetRef(), "", nil)
	defer releaseCeilings()
	if ceilingRef != nil {
		decisionID, rerr := s.recorder.Terminal(ctx, ceilingRef.decision)
		if rerr != nil {
			return nil, toStatus(rerr)
		}
		// A CEILING REFUSAL IS A RESULT, NOT AN ERROR (D135), on this verb too —
		// the caller learns which stage refused rather than receiving a transport
		// failure that says nothing.
		return &sekizuiv1.QueryResponse{
			DecisionId: decisionID,
			Status:     fault.KindOf(ceilingRef.err).Status(),
			Reason:     ceilingRef.err.Error(),
			RefusedBy:  ceilingRef.by,
		}, nil
	}

	args := req.GetArgs().AsMap()
	dec, err := s.policy.Authorise(ctx, policy.Request{
		Identity: id, Action: req.GetAction(), TargetRef: req.GetTargetRef(), Args: args,
	})
	if err != nil {
		return nil, toStatus(err)
	}

	base := &sekizuiv1.Decision{
		Identity: id, Action: req.GetAction(), TargetRef: req.GetTargetRef(),
		Verdict: dec.Verdict, MatchedRule: dec.Rule, Reason: dec.Reason,
		// From the configured target, before any stage can refuse (D29 item 4,
		// D319) — see Enforce.
		Residency: s.configuredResidency(req.GetTargetRef()),
	}

	// A denied READ is recorded exactly as a denied write. §4.1.1 keeps the
	// planes distinguishable in policy and audit, not differently governed.
	//
	// **"EXACTLY" WAS FALSE UNTIL P5 STEP 11 (D327):** Enforce and the job gate
	// stamped REFUSED_BY_POLICY and this branch stamped nothing — the record
	// named no stage and the caller got no stage and no reason. P4 step 7 found
	// the same hole for residency one branch up; this is the branch it missed.
	if dec.Verdict != sekizuiv1.Verdict_VERDICT_ALLOW {
		base.RefusedBy = sekizuiv1.RefusedBy_REFUSED_BY_POLICY
		decisionID, rerr := s.recorder.Terminal(ctx, base)
		if rerr != nil {
			return nil, toStatus(rerr)
		}
		return &sekizuiv1.QueryResponse{
			DecisionId: decisionID,
			Status:     verdictStatus(dec.Verdict),
			Reason:     fmt.Sprintf("%s (%s)", dec.Reason, dec.Rule),
			RefusedBy:  sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
		}, nil
	}

	target, err := s.resolver.Resolve(ctx, req.GetTargetRef())
	if err != nil {
		return nil, toStatus(s.recordFailure(ctx, base, err))
	}
	base.Residency = target.Residency() // D89, as in Enforce
	stampPosture(base, s.resolver, req.GetTargetRef())

	// A WITHDRAWN TARGET IS REFUSED ON READS TOO (D133, D155).
	//
	// The probe that found this revoked a credential and then read from it:
	// STATUS_OK, one row. `revoke_credential` is an operator's statement that a
	// credential is COMPROMISED, and a read with a compromised credential is an
	// exfiltration path — §4.1.1's own words are that "an agent running an
	// unbounded scan across BigQuery is a data-exfiltration path".
	//
	// AFTER RESOLVE, matching Execute: a withdrawn target is not a call that was
	// attempted and failed, it is one that never should have started.
	if s.pool != nil {
		if sev, withdrawn := s.pool.Withdrawn(req.GetTargetRef()); withdrawn {
			werr := pool.WithdrawnErr("gateway.Query", req.GetTargetRef(), sev)
			base.RefusedBy = sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL
			base.Verdict = sekizuiv1.Verdict_VERDICT_DENY
			base.Reason = werr.Error()
			decisionID, rerr := s.recorder.Terminal(ctx, base)
			if rerr != nil {
				return nil, toStatus(rerr)
			}
			return &sekizuiv1.QueryResponse{
				DecisionId: decisionID,
				Status:     fault.KindOf(werr).Status(),
				Reason:     werr.Error(),
				RefusedBy:  sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL,
			}, nil
		}
	}
	driver, derr := s.driverFor("gateway.Query", target)
	if derr != nil {
		return nil, toStatus(s.recordFailure(ctx, base, derr))
	}

	// PRICED BEFORE IT IS SENT (D283, P3 step 19): rows × the per-object
	// budget against the capability that authorised the read. A caller who
	// asked for more than fits is refused, told how many would; a default that
	// does not fit is lowered to what does, through the action's own argument.
	qspec, _ := s.specFor(driver, req.GetAction())
	allowedRows, clamped, perr := priceResult("gateway.Query", req.GetAction(), req.GetTargetRef(), qspec, args, dec.MaxBytes)
	if perr != nil {
		base.MatchedRule = "capability_max_bytes"
		base.RefusedBy = sekizuiv1.RefusedBy_REFUSED_BY_REQUEST
		base.Verdict = sekizuiv1.Verdict_VERDICT_DENY
		base.Reason = perr.Error()
		decisionID, rerr := s.recorder.Terminal(ctx, base)
		if rerr != nil {
			return nil, toStatus(rerr)
		}
		return &sekizuiv1.QueryResponse{
			DecisionId: decisionID,
			Status:     fault.KindOf(perr).Status(),
			Reason:     perr.Error(),
			RefusedBy:  sekizuiv1.RefusedBy_REFUSED_BY_REQUEST,
		}, nil
	}
	if clamped {
		args[qspec.Bound.Arg] = float64(allowedRows)
	}

	decisionID, err := s.recorder.Intent(ctx, base)
	if err != nil {
		return nil, toStatus(err)
	}

	// §4.3.4'S THREE CONTROLS, ON READS TOO (D140, D141, D143, D155, D253).
	//
	// **THIS COMMENT WAS TRUE ABOUT TWO OF THE THREE FOR A PHASE.** D155 found
	// reads bypassing the breaker, the rate limiter and retry; the breaker and
	// the retry landed and **the limiter did not**, so `s.rate.Allow` existed
	// at exactly one site in the tree and reads never drew on the shared
	// budget. The sentence that described the defect — *a deployment
	// configured for 100/hr sent 100 writes plus unlimited reads at an
	// upstream that counts both* — stayed literally true, written here, in the
	// past tense. DESIGN §12 and CONTRACTS 54 said the same.
	//
	// It is a SHARED STAGE now rather than a block to keep in step by reading
	// (D253), which is the only form that survives the next verb: the job
	// binding was about to inherit the same hole.
	//
	// **REFUSED AS AN OUTCOME AGAINST THE INTENT, NOT AS A SECOND ROW.** The
	// breaker arm used to write a Terminal and shadow `decisionID`, leaving
	// the intent above with no outcome — which in the log is exactly what a
	// process dying mid-read looks like. §5.2.2's two phases say a metered
	// refusal is a call attempted and stopped, and Execute has always recorded
	// it that way.
	cost, cerr := driver.Meter().Cost(req.GetAction(), args)
	if cerr != nil {
		return nil, toStatus(s.recordFailure(ctx, base, fault.Wrap(fault.KindInvalidArgument,
			"gateway.Query", "the connector could not price this read before sending it (D284)", cerr)))
	}
	meterRef, merr := s.meters(ctx, subject, req.GetAction(), req.GetTargetRef(), req.GetTargetRef(), cost)
	if merr != nil {
		return nil, toStatus(s.recordFailure(ctx, base, merr))
	}
	if meterRef != nil {
		if oerr := s.recorder.Outcome(ctx, decisionID, &sekizuiv1.Effect{
			Success: false, Attempts: 0, Error: meterRef.err.Error(),
		}); oerr != nil {
			return nil, toStatus(oerr)
		}
		return &sekizuiv1.QueryResponse{
			DecisionId: decisionID,
			Status:     meterRef.kind.Status(),
			Reason:     meterRef.err.Error(),
			RefusedBy:  meterRef.stage(),
		}, nil
	}

	ctx = connector.WithTenant(ctx, target.Tenant())
	callStarted := s.now()

	// NO D113 REFUSAL HERE, AND THAT IS THE POINT OF THE ASYMMETRY. D113 refuses
	// to retry a MUTATING action with no idempotency key because the first call
	// may have landed and a 429 does not say which side of the write it died on.
	// A read has no such hazard, so it retries under the policy unconditionally —
	// which is what makes step 35 the other half of D113's conjunction.
	var rows connector.Rows
	attempts, qerr := s.retry.For(req.GetTargetRef()).Do(ctx,
		retry.Retryable,
		func(ctx context.Context) error {
			var callErr error
			rows, callErr = driver.Query(ctx, target, req.GetAction(), args)
			return callErr
		})

	s.meterOutcome(ctx, subject, req.GetAction(), req.GetTargetRef(), qerr)

	effect := &sekizuiv1.Effect{
		Success:   qerr == nil,
		LatencyMs: s.now().Sub(callStarted).Milliseconds(),
		// REAL ON READS TOO. This field read a hardcoded 1 on Execute until
		// retries existed; on Query it had no retries to count at all.
		Attempts: uint32(attempts), //nolint:gosec // bounded by Policy.MaxAttempts
	}
	if qerr != nil {
		effect.Error = qerr.Error()
	}
	if oerr := s.recorder.Outcome(ctx, decisionID, effect); oerr != nil {
		return nil, toStatus(oerr)
	}
	if qerr != nil {
		return nil, toStatus(qerr)
	}

	// 10. SHIN — WHAT THIS CONSUMER ACTUALLY RECEIVES (D83).
	//
	// APPLIED AFTER THE AUDIT RECORD IS WRITTEN, and that ordering is a
	// guarantee rather than an accident: a lens narrows what a CONSUMER sees and
	// must never narrow what the log records. The record above says what was
	// permitted and what the target returned; this decides how much of it is
	// appropriate to hand back. Reversing the two would make a lens an evasion
	// tool, which is the one thing this system exists to prevent.
	//
	// THE TYPE COMES FROM THE DRIVER'S DECLARED OUTPUT TYPE (D88), so a field
	// allow-list works on query results exactly as it does on an envelope. That
	// mapping used to be missing, which limited Query to type-less lenses — and
	// bridging it by string surgery on the schema URI would have been a guess
	// dressed as a rule. A driver that declares no output type still gets the
	// type-less lenses; it simply cannot be narrowed by field.
	lensReq := shin.Request{
		Principal: id.GetSubject().GetPrincipal(),
		Type:      s.outputTypeOf(driver, req.GetAction()),
		Residency: target.Residency(),
		Selected:  req.GetLens(),
		Added:     id.GetSubject().GetTokenLenses(), // a signed subject's token may add (D303)
	}

	// **SHAPED TO THE CONNECTOR'S SCHEMA BEFORE ANY LENS (D279).** A read is
	// ingest too: what the connector's schema does not declare is stripped
	// here, exactly as the runner strips a polled event, so a lens decides
	// what a consumer SEES of what was declared — never of everything the far
	// side returned. A row of a kind the connector refuses is dropped, and
	// said out loud.
	if s.payloads == nil {
		return nil, toStatus(fault.New(fault.KindInternal, "gateway.Query",
			"no payload registry: a query result cannot be shaped to its connector's schema, so it "+
				"is not returned (D279)"))
	}
	// THE DECLARATION IS KEPT, NOT TRUSTED (D283): a connector returning more
	// rows than its Bound allows is cut to the bound, flagged Truncated, and
	// named — the size the read was priced at is the size it delivers.
	if len(rows.Rows) > allowedRows {
		s.log.Warn("a connector returned more rows than its action declares; the excess was dropped",
			"action", req.GetAction(), "target", req.GetTargetRef(), "declared", allowedRows,
			"returned", len(rows.Rows))
		rows.Rows, rows.Truncated = rows.Rows[:allowedRows], true
	}
	var refused int
	shapedRows := rows.Rows[:0:0]
	// A ROW OF NO REGISTERED TYPE IS NOT RETURNED (D283): Shape would pass it
	// through untouched, and nothing validates a read's rows after this.
	registered := lensReq.Type != "" && s.payloads.Has(lensReq.Type)
	for _, row := range rows.Rows {
		shaped, report := s.payloads.Shape(lensReq.Type, row)
		if !registered || report.Refused() {
			refused++
			continue
		}
		shapedRows = append(shapedRows, shaped)
	}
	if refused > 0 {
		s.log.Warn("query rows of a kind the connector does not admit were not returned",
			"action", req.GetAction(), "target", req.GetTargetRef(), "rows", refused)
	}
	rows.Rows = shapedRows

	// **EVERY ROW LENSED FIRST, THEN THE SEIREN, THEN THE BUDGET (D297, D300,
	// D317).** The seiren is built only from what the caller's lens let through
	// — so a withheld field cannot reach it by any path — and over the WHOLE
	// result, before the response budget below can cut the rows short: a
	// seiren over a truncated page would pair a click on one side of the cut
	// with nothing on the other.
	lensed := make([]map[string]any, 0, len(rows.Rows))
	var applied []string
	for _, row := range rows.Rows {
		projected, names, lerr := s.lenses.Apply(lensReq, row)
		if lerr != nil {
			// A lens that could not deliver refuses the DELIVERY, not the action.
			// The action already happened and is already recorded; what failed is
			// the projection, and handing back an unlensed payload because the
			// lens broke is precisely the disclosure the assertion exists to stop.
			return nil, toStatus(lerr)
		}
		applied = names
		lensed = append(lensed, projected)
	}
	seiren, serr := s.seirenFor(req.GetTargetRef(), lensReq, lensed, rows.Truncated, refused)
	if serr != nil {
		return nil, toStatus(serr)
	}

	out := make([]*structpb.Struct, 0, len(lensed))
	var spent int
	var truncatedByBudget bool
	for _, projected := range lensed {
		// **THE ROW IS ALWAYS APPENDED (D177), and this was the worst of the
		// three.** It read `if v, err := ...; err == nil`, so a row carrying one
		// unrepresentable value was silently DROPPED from the result set — which
		// is selective row suppression by whoever controls the data, with no
		// Truncated flag and no error. An agent cannot notice a row that was never
		// mentioned.
		// **THE AGGREGATE BUDGET IS THE ONE THAT MATTERS FOR A QUERY (D178).** A
		// per-row bound does nothing against a million small rows, and
		// QueryResponse.rows is `repeated Struct` — memory-hungry by construction
		// (CONTRACTS 5). So the budget is spent ACROSS the response, and running
		// out sets the flag the wire already has for exactly this.
		if spent >= safestruct.DefaultBudget {
			truncatedByBudget = true
			break
		}
		v, rowRep := safestruct.Convert(projected, safestruct.DefaultBudget-spent)
		spent += safestruct.SizeOf(v)
		if len(rowRep.Substituted) > 0 {
			s.log.Warn("query row carried values protobuf cannot represent; they were "+
				"substituted rather than the row being dropped",
				"action", req.GetAction(), "target", req.GetTargetRef(),
				"fields", rowRep.Substituted)
		}
		out = append(out, v)
	}
	if len(applied) > 0 {
		s.log.Debug("shin applied to query results",
			"principal", lensReq.Principal, "lenses", applied, "rows", len(out))
	}
	return &sekizuiv1.QueryResponse{
		DecisionId: decisionID,
		Status:     sekizuiv1.Status_STATUS_OK,
		Rows:       out,
		// Surfaced rather than silent: "an agent reasoning over a silently
		// truncated set reaches confident wrong conclusions" (connector.Rows).
		// **EITHER THE DRIVER TRUNCATED OR WE DID (D178).** The driver sets this
		// when a limit cut its own results short; the budget sets it when the
		// response would have grown past what Sekizui will carry. A caller needs
		// the same answer to the same question — "is this set complete?" — and
		// which side shortened it is not their problem.
		Truncated:     rows.Truncated || truncatedByBudget,
		NextPageToken: rows.NextPageToken,
		AppliedLenses: applied,
		Seiren:        seiren,
	}, nil
}

// Describe answers "what can I do?" — §4.9's capability catalog.
//
// NOT AUDITED AS A DECISION, and that is a judgement worth stating. §5.2 records
// "every decision and every external effect"; Describe makes no decision and
// causes no effect — it reports the decisions that WOULD be made. Writing a
// decision record for it would put a row in the audit log for something that
// never touched a target, diluting the log whose value is that every row is an
// action. It is counted in metrics and logged, so a principal enumerating the
// fleet is still visible.
//
// The reconnaissance concern is handled by refusing to describe principals the
// caller may not speak for, not by auditing the attempt after the fact.
func (s *Server) Describe(ctx context.Context, req *sekizuiv1.DescribeRequest) (
	resp *sekizuiv1.DescribeResponse, err error) {

	release, aerr := s.admission.Acquire(ctx, "Describe")
	if aerr != nil {
		return nil, toStatus(aerr)
	}
	defer release()

	// Metered like every other RPC (D76): one vocabulary, one place, so a new
	// method cannot be added without appearing in RED. "describe" occupies the
	// action label because there is no per-action dimension to report.
	started := s.now()
	defer func() {
		s.metrics.Observe("", "describe", describeOutcomeLabel(err), s.now().Sub(started))
	}()

	if s.catalog == nil {
		// A Server built without a catalog is a wiring error, not a user error —
		// same class as the "no established identity" check in Enforce, and
		// reported the same way rather than as an empty capability list, which
		// would tell an agent it may do nothing.
		return nil, toStatus(fault.New(fault.KindInternal, "gateway.Describe",
			"server was built without a catalog; Describe cannot answer"))
	}

	id, err := s.verifier.Verify(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	resp, err = s.catalog.Describe(ctx, id, req.GetPrincipal())
	if err != nil {
		// **THE REFUSED ENUMERATION IS RECORDED TOO, AND IT IS THE MORE VALUABLE
		// OF THE TWO ROWS (D231).** §4.9's reconnaissance refusal — naming
		// another principal needs a may_speak_for grant, because a capability
		// listing is the map of what to try after compromising something else —
		// left NO durable trace at all: `toStatus` returns and the INFO line
		// below is never reached. So the one event most worth having in a
		// tamper-evident log, an agent asking what a principal it may not speak
		// for is allowed to do, was the one event that produced nothing.
		//
		// Recorded through the same funnel as every refusal (D135, D228), so it
		// carries a verdict, a stage and a decision id like the rest.
		if fault.KindOf(err).Deliberate() {
			if _, rerr := s.refuse(ctx, s.describeDecision(ctx, id, req.GetPrincipal(), nil),
				sekizuiv1.RefusedBy_REFUSED_BY_POLICY, err); rerr != nil {
				return nil, toStatus(rerr)
			}
		}
		return nil, toStatus(err)
	}

	// **THE DISCLOSURE ROW, IN THE HASH CHAIN (D166).** D79 refused to audit
	// Describe on a dilution argument that a distinct row shape answers, and its
	// volume premise ("a call agents make rarely") contradicted itself. What
	// decided it is tamper-evidence: the INFO line below was the ONLY
	// identity-carrying trace of enumeration, self-describe is DEBUG (D126), and
	// CONTRACTS 28 says that log loses records on rotation.
	//
	// DERIVED FROM `resp`, never recomputed. The row's whole value is that it
	// says what the caller was TOLD, and asking the catalog a second time could
	// answer differently — `stampPosture`'s lesson (D119) and D138's.
	base := s.describeDecision(ctx, id, resp.GetPrincipal(), resp)
	base.Verdict = sekizuiv1.Verdict_VERDICT_ALLOW
	if _, rerr := s.recorder.Terminal(ctx, base); rerr != nil {
		// A DISCLOSURE THAT CANNOT BE RECORDED FAILS. The same direction D145
		// chose for a withdrawal, and for the same reason: an enumeration whose
		// trace evaporates is exactly the outcome an attacker wants, and
		// returning the answer anyway would hand it over silently.
		return nil, toStatus(rerr)
	}

	// SELF-DESCRIBE IS DEBUG; DESCRIBING ANOTHER PRINCIPAL IS INFO.
	//
	// Not an inconsistency with D124's policy — the asymmetry is the point, and
	// it follows what the two cases actually reveal. An agent asking what IT can
	// do learns nothing it could not get by trying actions and collecting
	// refusals; that is the designed common path, once per process start.
	// Describing SOMEONE ELSE requires a may_speak_for grant and reveals
	// capabilities the caller could not otherwise discover — the reconnaissance
	// shape D79 wrote its refusal for.
	//
	// This line is also the ONLY identity-carrying trace of enumeration, because
	// Describe is deliberately unaudited (D79). The metric shows the rate at any
	// level; only this says WHO.
	attrs := []any{
		"caller", id.GetCaller().GetPrincipal(),
		"principal", resp.GetPrincipal(),
		"capabilities", len(resp.GetCapabilities()),
	}
	if resp.GetPrincipal() != id.GetSubject().GetPrincipal() {
		s.log.Info("described ANOTHER principal's capabilities", attrs...)
	} else {
		s.log.Debug("described capabilities", attrs...)
	}
	return resp, nil
}

// beginSpan starts a span, or returns nil when nothing is tracing.
func (s *Server) beginSpan(traceID, parentSpanID string, sampled bool,
	name string, attrs map[string]string) *tracing.Live {

	if s.tracer == nil {
		return nil
	}
	return s.tracer.Begin(traceID, parentSpanID, sampled, name, attrs)
}

// describeAction is the `action` a disclosure row carries.
//
// NOT IN `internal/verb`, deliberately: Describe is an RPC rather than a
// governed verb, so `verb.Is` must keep answering false for it — a grant naming
// `sekizui.describe` would be refused at boot, correctly, because Describe is
// authorised by `may_speak_for` and not by a capability (§4.9).
const describeAction = "sekizui.describe"

// describeDecision builds the row a Describe writes, from the response it is
// about.
//
// **`action` IS THE GOVERNED-VERB NAME SO THE ROW IS FILTERABLE.** D79's
// dilution objection is answered by a row shape a query can exclude — "every row
// is an action" survives as `action != "sekizui.describe"` — which is the same
// trade D138 made when it put `kind` beside a coarse status rather than adding
// enum members.
//
// `resp` is nil for a REFUSED describe, where there is no disclosure to record
// because nothing was disclosed. The row still names the principal that was
// ASKED ABOUT, which is the field an incident review greps for.
func (s *Server) describeDecision(ctx context.Context, id *sekizuiv1.Identity,
	principal string, resp *sekizuiv1.DescribeResponse) *sekizuiv1.Decision {

	matched := "self_describe"
	if principal != id.GetSubject().GetPrincipal() {
		// **WHAT AUTHORISED THE DISCLOSURE**, which for a Describe is not a
		// grant: it is the may_speak_for relation (§4.4.1, §4.9). Every record
		// must say what decided (§5.4), and the convention for a decision no
		// capability indexed is a bare token — policy writes `default_deny`,
		// the grant verbs write `revoked:<principal>`.
		matched = "may_speak_for:" + principal
	}
	base := &sekizuiv1.Decision{
		Identity:    id,
		Action:      describeAction,
		MatchedRule: matched,
		// **NO TARGET, AND THAT IS THE HONEST VALUE.** A Describe touches no
		// target: it reads the catalog. The census (step 24) must not learn to
		// expect one here.
		//
		// The trace comes off the ctx the way `Enforce`'s does — request-scoped,
		// so it cannot be stamped in the recorder funnel like `config_identity`
		// (D216, D149). There is no Command to fall back to, which is what the
		// nil says.
		Trace: traceFor(ctx, nil),
	}
	if resp == nil {
		base.Disclosure = &sekizuiv1.Disclosure{PrincipalDescribed: principal}
		return base
	}

	d := &sekizuiv1.Disclosure{
		PrincipalDescribed: resp.GetPrincipal(),
		//nolint:gosec // a capability count cannot plausibly exceed 2^32
		Capabilities: uint32(len(resp.GetCapabilities())),
	}
	for _, l := range resp.GetImposedLenses() {
		d.ImposedLenses = append(d.ImposedLenses, l.GetName())
	}
	for _, l := range resp.GetAvailableLenses() {
		d.AvailableLenses = append(d.AvailableLenses, l.GetName())
	}
	// **THE RULES, DEDUPLICATED.** One guard commonly withholds several
	// capabilities, and the question this row answers is "which rules shaped the
	// advertisement" rather than "how many times did each fire" — the second is
	// the per-capability dilution D79 refused.
	seen := map[string]bool{}
	for _, w := range resp.GetWithheld() {
		if seen[w.GetGuard()] {
			continue
		}
		seen[w.GetGuard()] = true
		d.WithheldBy = append(d.WithheldBy, w.GetGuard())
	}
	base.Disclosure = d
	return base
}

func describeOutcomeLabel(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}

// specFor finds one action's spec.
//
// REPLACED `isMutating`, which asked the same question for one field. Its
// safety default — an unknown action is treated as MUTATING — did not come with
// it and must be applied by the caller, which is stated at the one call site
// that needs it and is the first thing to check if a third caller appears.
//
// ONE LOOKUP FOR EVERY QUESTION ABOUT AN ACTION, because three helpers each
// walking Actions() for one field is how they come to disagree about which
// action they found — D138's lesson about a record field built at two exit
// paths, applied to a read. It also matters now that a single call needs the
// mutating flag, the idempotency class and the placement together: fetching them
// separately would let a driver whose Actions() changed mid-call answer two
// questions from two different specs.
func (s *Server) specFor(d connector.Driver, action string) (connector.ActionSpec, bool) {
	for _, spec := range d.Actions() {
		if spec.Name == action {
			return spec, true
		}
	}
	return connector.ActionSpec{}, false
}

// outputTypeOf reports the payload type an action's results carry.
//
// Empty when the driver declares none, which is legitimate: boot refuses a
// declared type that is not registered (D88), so an empty answer here means
// "this driver has not described its output", not "the description was wrong".
func (s *Server) outputTypeOf(d connector.Driver, action string) string {
	for _, spec := range d.Actions() {
		if spec.Name == action {
			return spec.OutputType
		}
	}
	return ""
}

// report logs the outcome of one governed call.
//
// SHARES THE DEFERRED OBSERVATION POINT WITH METRICS (D76), for the same reason
// that decision made: a new exit path is covered by construction rather than by
// remembering. Before this the enforcement path logged NOTHING — not an allowed
// command, not a denial, not an anzen refusal — so a running instance served 48
// concurrent commands and printed two lines, and an operator tailing logs during
// an incident would have seen nothing at all. The audit log had it; the thing
// people actually watch did not.
//
// LEVELS ARE CHOSEN BY VOLUME AND BY VALUE, not by severity:
//
//	refused  INFO   rare, and the point of the system (§5.4's highest-value rows)
//	failed   WARN   something broke after authorisation
//	allowed  DEBUG  can be thousands per second
//
// So the default level shows every refusal and every failure, and `-log-level
// debug` adds the successes. A demo watching stdout sees the governance
// happening; production is not drowned by it.
//
// NEVER THE ARGUMENTS. §4.3.3 keeps payloads out of logs above debug, and a
// command's args are the most likely place for customer data. The decision id is
// here instead, which is the join key to the record that does hold them.
func (s *Server) report(id *sekizuiv1.Identity, action, target, outcome string,
	took time.Duration, decisionID, reason string, err error, refused fault.Kind) {

	// A FAILURE'S DECISION ID RIDES ON THE ERROR, not the result (D203): a
	// failed call returns no result, so reading only the result logged
	// `decision=""` for every failure while the audit log held the record —
	// the join key missing exactly where an operator needs it. Seen live in
	// the step-18 capture (D317).
	if decisionID == "" && err != nil {
		decisionID = fault.DecisionIDOf(err)
	}
	attrs := []any{
		"principal", id.GetSubject().GetPrincipal(),
		"action", action, "target", target,
		"outcome", outcome, "took", took, "decision", decisionID,
	}
	// Only when it differs, so the common standalone case stays readable.
	if c := id.GetCaller().GetPrincipal(); c != id.GetSubject().GetPrincipal() {
		attrs = append(attrs, "caller", c)
	}

	switch {
	case err != nil && needsAHuman(fault.KindOf(err)):
		// Something broke. WARN, because someone may need to act.
		s.log.Warn("command failed", append(attrs, "err", err)...)

	case err != nil:
		// A refusal that arrives as an error — residency, rate limiting, a
		// budget. Classified by KIND rather than by "is there an error", because
		// the two are indistinguishable at this call site and only the taxonomy
		// knows which is which. Logging a residency refusal at WARN pages an
		// operator for the guarantee working (§7.1 item 2).
		s.log.Info("command REFUSED", append(attrs, "why", firstLine(err.Error()))...)

	case refused != fault.KindUnknown:
		// A refusal that arrives as a RESULT, which since D135 is most of them.
		//
		// CLASSIFIED BY THE TAXONOMY, NOT BY A LIST OF OUTCOME STRINGS. This
		// read `outcome == "denied" || outcome == "escalated"` — a hand-written
		// allowlist of labels, which is the shape this project keeps
		// rediscovering: correct when written, silently wrong the moment a new
		// label appears. D135 produced one immediately. A residency refusal
		// meters as `residency`, matched neither arm, fell through to the
		// default, and was logged as **"command allowed" at DEBUG** — the
		// §7.1 item 2 guarantee working, reported as a success and hidden at a
		// level nobody runs in production.
		//
		// D125 already said how to classify this: by kind. The kind is now
		// carried here rather than re-derived from a string.
		s.log.Info("command REFUSED", append(attrs, "why", firstLine(reason))...)

	case outcome == "would_have_fired":
		s.log.Info("command would have fired (dry run or shadow)", attrs...)

	default:
		s.log.Debug("command allowed", attrs...)
	}
}

// firstLine keeps a refusal readable on one log line. The reasons here are
// deliberately long — they explain the rule and the rationale — and the full
// text is in the audit record for anyone who wants it.
//
// SPLITS ON ". " RATHER THAN ".", and the first version did not: a fault message
// begins with its op, so `anzen.Check: denied: ...` truncated to "anzen." — a log
// line that names nothing and reads like a bug. Cutting on period-SPACE keeps
// `anzen.Check`, `versions/7`, and `v1.2` intact, which is the same reason the
// acceptance report's renderer does it.
func firstLine(reason string) string {
	reason = strings.TrimSpace(strings.ReplaceAll(reason, "\n", " "))
	if head, _, found := strings.Cut(reason, ". "); found {
		return head + "."
	}
	const limit = 160
	if len(reason) > limit {
		return reason[:limit] + "…"
	}
	return reason
}

// recordFailure writes a terminal record for a failure AFTER authorisation.
//
// The verdict was ALLOW — policy permitted it and something else went wrong —
// so the row records what was permitted and what then failed. Losing that would
// leave an approved action with no trace, which is the gap two-phase recording
// exists to close.
// ceilingRefusal is a ceiling's answer, in a form BOTH verbs can shape into
// their own response type (D155).
type ceilingRefusal struct {
	decision *sekizuiv1.Decision
	by       sekizuiv1.RefusedBy
	err      error
}

// **THE RECORD CARRIES THE STAGE AND THE REASON FROM HERE, NOT FROM ITS
// CONSUMER.** Execute stamped them in `refuse`; Query and the job gate write the
// decision straight to the recorder, so their residency refusals were recorded
// with no `refused_by` and no reason — a read refused as a crossing that an
// auditor could not tell from any other denial (§7.1 item 2). P4 step 7 found
// it, asserting on the record rather than the answer.
func ceilingRefusalOf(d *sekizuiv1.Decision, by sekizuiv1.RefusedBy, err error) *ceilingRefusal {
	d.RefusedBy = by
	if d.GetReason() == "" {
		d.Reason = err.Error()
	}
	return &ceilingRefusal{decision: d, by: by, err: err}
}

// noRelease is the release func for a path that acquired no concurrency slot.
//
// A NO-OP RATHER THAN A NIL, so no caller has to remember to check before
// deferring. A nil here would be a panic reachable only on a refusal, which is
// the path least likely to be exercised and most likely to matter.
func noRelease() {}

// ceilings runs every check that must precede policy, for BOTH Execute and Query
// (D18, D155).
//
// **THIS WAS INLINE IN Execute, AND Query DID NOT HAVE IT.** Query ran admission,
// identity and policy, and skipped the runtime grant suspension, the anzen guard,
// the withdrawal check and all three of §4.3.4's controls. A probe proved the
// worst of it: a read returned STATUS_OK with a row against a target whose
// credential had just been revoked as compromised.
//
// D18 is the decision that forbids it, in twelve words — "No second code path,
// no hole in the audit log." It was written about reflexes, and the principle is
// not about reflexes. The second path arrived from the other direction: not
// something added beside the enforcement path, but a verb that grew its own
// abbreviated copy one omission at a time, each invisible because Query reads
// like a shorter version of the same thing rather than a weaker one.
//
// SHARED CODE RATHER THAN COPIED CHECKS, because copying is how two paths drift
// again and the drift is silent — the same argument stampPosture already settled
// for one field at two exit paths.
//
// Returns the residency `class` because the anzen guard needs it (D137), a
// release func for the concurrency guard, and a refusal when any ceiling applied.
// **THE CALLER MUST `defer release()`**: it is returned rather than deferred here
// because a concurrency slot has to be held for the duration of the CALL, not of
// this function.
func (s *Server) ceilings(ctx context.Context, id *sekizuiv1.Identity,
	subject, action, targetRef, idempotencyKey string,
	causation *sekizuiv1.Causation) (class string, release func(), refusal *ceilingRefusal) {

	// 1b. A RUNTIME GRANT REVOCATION, BEFORE ANYTHING ABOUT THE REQUEST (D146).
	//
	// FIRST OF THE CEILINGS, ahead of residency, the anzen guard and policy —
	// because it answers a blunter question than any of them: not "may this
	// principal do this action on this target" but "may this principal do
	// ANYTHING at all right now". Once an operator has said no, evaluating what
	// was asked for is answering a question we have decided not to entertain,
	// and the caller would get told about a residency conflict when the actual
	// answer is that somebody suspended them twenty minutes ago.
	//
	// Found by the acceptance step rather than by reasoning: placed after the
	// residency ceiling, the suspension changed nothing observable for a
	// principal whose target was already out of region.
	//
	// NOT DURABLE, deliberately — "until config is redeployed" (see
	// policy.Revocations for why the asymmetry with D133 is defensible).
	if s.revocations != nil {
		if rev, revoked := s.revocations.Revoked(subject); revoked {
			suspended := &sekizuiv1.Decision{
				Identity: id, Action: action, TargetRef: targetRef,
				Residency: s.configuredResidency(targetRef), // D29 item 4, D319: a refusal is regional too
				Verdict:   sekizuiv1.Verdict_VERDICT_DENY,
				// NAMES THE RUNTIME REVOCATION, not "no grant". The two are
				// indistinguishable to a caller and completely different to an
				// operator: one is a config question and the other is somebody
				// having pulled a lever twenty minutes ago.
				MatchedRule:    "revoked:" + subject,
				ReflexName:     audit.ReflexNameFrom(ctx),
				IdempotencyKey: idempotencyKey, Causation: causation,
			}
			return class, noRelease, ceilingRefusalOf(suspended, sekizuiv1.RefusedBy_REFUSED_BY_POLICY,
				fault.New(fault.KindDenied, "gateway.ceilings", fmt.Sprintf(
					"the grants of %q were suspended at runtime by %q (%s) and stay "+
						"suspended until this instance is redeployed. Reason: %s",
					subject, rev.Trigger, rev.At.Format(time.RFC3339), rev.Reason)))
		}
	}

	// 1c. THE RESIDENCY CEILING, BEFORE EVERYTHING ELSE IT BOUNDS (D136).
	//
	// D71's rule is that a ceiling is evaluated before the grants it bounds, and
	// residency is the most absolute ceiling here: not "this principal may not"
	// but "this deployment may not, whoever is asking". It used to be checked
	// inside Resolve, four stages below policy, which produced the right refusal
	// for the wrong reason — when a grant ALSO denied, the caller was told
	// REFUSED_BY_POLICY and an operator went to read a grant about a target this
	// instance was never allowed to touch. §7.1 item 2 exists so that an operator
	// does not have to infer which of the two it was.
	//
	// STILL CHECKED IN Resolve TOO, as defence in depth. Resolve is the sole
	// constructor of a Target (§6 mechanism 1) and the guarantee belongs with the
	// construction, not with one caller's ordering — the same reason the pool
	// re-checks withdrawal.
	//
	// An unknown ref falls through: Resolve owns that refusal, and a second
	// not-found here would be a second answer to drift from the first.
	//
	// `class` OUTLIVES THE REFUSAL because the anzen guard below needs it too: a
	// preventive rule may be scoped to a residency class (D137), and that is the
	// second reason this lookup belongs ahead of the guard rather than inside it.
	class, ceilingRefused := s.resolver.ResidencyRefused(targetRef)
	if ceilingRefused {
		crossing := &sekizuiv1.Decision{
			Identity: id, Action: action, TargetRef: targetRef,
			Residency:      s.configuredResidency(targetRef), // D29 item 4, D319: a refusal is regional too
			Verdict:        sekizuiv1.Verdict_VERDICT_DENY,
			MatchedRule:    "residency:ceiling",
			ReflexName:     audit.ReflexNameFrom(ctx),
			IdempotencyKey: idempotencyKey, Causation: causation,
		}
		return class, noRelease, ceilingRefusalOf(crossing, sekizuiv1.RefusedBy_REFUSED_BY_RESIDENCY,
			fault.New(fault.KindResidency, "gateway.ceilings", fmt.Sprintf(
				"target %q is %s-resident and this deployment does not serve that class; "+
					"no grant can authorise the crossing, because the ceiling is set by the "+
					"deployment rather than by whoever wants the data (D71, D136)",
				targetRef, class)))
	}

	// 2. THE CEILING, BEFORE THE GRANT (D71). An anzen guard refuses regardless
	// of what policy would say — grants are written per principal by whoever
	// needs the capability, guards once by whoever is accountable for the blast
	// radius. Running policy first would let a broad grant win.
	guardName, releaseGuard, guardErr := s.guards.Check(subject, action, class)
	if guardErr != nil {
		blocked := &sekizuiv1.Decision{
			Identity: id, Action: action, TargetRef: targetRef,
			Residency: s.configuredResidency(targetRef), // D29 item 4, D319: a refusal is regional too
			Verdict:   sekizuiv1.Verdict_VERDICT_DENY,
			// WHICH guard, not merely that one refused. Several can cover the
			// same principal, and a reviewer should not have to parse prose to
			// learn which — the same gap D96 closed for reflexes.
			MatchedRule: "anzen:" + guardName, Reason: guardErr.Error(),
			ReflexName:     audit.ReflexNameFrom(ctx),
			IdempotencyKey: idempotencyKey, Causation: causation,
		}
		return class, noRelease, ceilingRefusalOf(blocked, sekizuiv1.RefusedBy_REFUSED_BY_ANZEN, guardErr)
	}

	// Shadow-mode guards report what they WOULD have refused. Silent shadow
	// mode teaches an operator nothing during the week it is meant to inform.
	for _, name := range s.guards.WouldRefuse(subject, action, class) {
		s.log.Warn("anzen guard would have refused this action",
			"guard", name, "principal", subject, "action", action,
			"mode", "shadow")
	}

	return class, releaseGuard, nil
}

// anzenAuthorise decides an action whose SUBJECT is anzen itself (D121, D122).
//
// Returns nil when the subject is not anzen's, so the ordinary grant path runs.
//
// **WHY THIS EXISTS AT ALL.** D122 rules that "anzen's authority comes from its
// closed vocabulary rather than from a grant", and reserves the `anzen:`
// namespace so a grant cannot name one — which leaves an anzen-dispatched action
// with no grant to consult and, until this, a denial for lacking a permission it
// was never permitted to hold. The decision declared an authorisation source and
// nothing implemented it.
//
// **WHY IT IS SAFE, in three parts that each have to hold.** The namespace is
// REFUSED AT BOOT to configuration, so no operator can mint one of these
// subjects. It is SYNTHESISED only by the reactive dispatcher, from the name of a
// rule that is already declared, already validated against the closed vocabulary,
// and already required to say `mode: enforce`. And it authorises EXACTLY ONE
// THING: firing the rule the subject names. An `anzen:credential-compromise`
// subject cannot execute against a target, cannot fire a different rule, and
// cannot restore anything.
//
// A SHADOW RULE IS STILL REFUSED HERE, by resolveRule, which is what keeps
// "observed for a week before trusted" from being discharged by a signal.
func (s *Server) anzenAuthorise(subject string, cmd *sekizuiv1.Command) (*policy.Decision, error) {
	if !strings.HasPrefix(subject, anzenRefPrefix) {
		return nil, nil
	}

	deny := func(why string) *policy.Decision {
		return &policy.Decision{
			Verdict: sekizuiv1.Verdict_VERDICT_DENY,
			Rule:    subject,
			Reason:  why,
		}
	}

	if cmd.GetAction() != verb.FireAnzen {
		return deny("an " + anzenRefPrefix + " subject may only fire the rule it names; " +
			"its authority is anzen's closed vocabulary rather than a grant (D122), and " +
			"that vocabulary contains exactly one thing it may do"), nil
	}
	if cmd.GetTargetRef() != subject {
		return deny("subject " + subject + " may fire only its own rule, not " +
			cmd.GetTargetRef()), nil
	}
	if _, err := s.resolveRule(cmd.GetTargetRef()); err != nil {
		// Undeclared, shadow, or not a rule at all. Anzen's own vocabulary
		// refusing, which is the check that makes the authority above bounded.
		return deny(err.Error()), nil
	}

	return &policy.Decision{
		Verdict: sekizuiv1.Verdict_VERDICT_ALLOW,
		// NAMES THE RULE, not "default_allow". §5.4: without this, "allowed" is
		// unexplainable — and an anzen action is the one most in need of an
		// explanation, because no human asked for it.
		Rule: subject,
	}, nil
}

// escalates reports whether a new withdrawal is STRONGER than the one in force
// (D158).
//
// THE ONLY DIRECTION THAT MAY ACT TWICE. §4.7.10 splits quarantine from
// revocation on whether in-flight calls are cancelled, so quarantine → revoke is
// an operator deciding the target is not merely misbehaving but compromised.
// Treating that as a repeat would leave calls running with a credential somebody
// has just declared unsafe.
//
// The reverse — revoke → quarantine — is NOT an escalation and is confirmed:
// downgrading a withdrawal in place would silently weaken it, and D133's rule is
// that a withdrawal is lifted only by an explicit governed verb.
func escalates(inForce string, wanted pool.Severity) bool {
	return inForce == pool.SeverityQuarantine.String() && wanted == pool.SeverityRevoke
}

// stampPosture puts the credential's security posture on the record (D100, D119).
//
// ONE HELPER FOR BOTH CALL SITES — Enforce and Query — because D138's lesson is
// that a record field built at two exit paths eventually disagrees at one of
// them, and this one exists so an auditor can compare rows. Residency (D89) is
// stamped twice in exactly this shape and is the reason to be careful: the field
// existed and nothing populated it until somebody noticed.
//
// D104's boot report states the posture once, to whoever is watching a terminal.
// An auditor asking "which targets were reachable with an unrotatable credential
// last quarter" cannot answer from a log line nobody kept — they need it per
// action, which is what §5.4 means by a record that stands alone. D118 makes the
// richer record safe: decisions provably reach no bus consumer, so the
// reconnaissance concern that argued for restraint does not apply.
//
// NIL WHEN NOTHING ESTABLISHED ONE, rather than a zero-valued message. An empty
// CredentialPosture on the wire reads as a credential that does not rotate and
// whose reads are unaudited — which is an assertion. Absence is not.
func stampPosture(base *sekizuiv1.Decision, r Resolver, ref string) {
	// OPTIONAL, discovered by type assertion (GO-PRIMER §2.2), for the reason
	// ChainedProvider and limiter.Contended are: a Resolver substituted by a
	// test or a later phase must not be forced to answer a question it has no
	// way to answer, and the honest result of not answering is an absent field.
	asked, can := r.(interface {
		PostureOf(ref string) (config.Posture, bool)
	})
	if !can {
		return
	}
	p, ok := asked.PostureOf(ref)
	if !ok || p.Scheme == "" {
		return
	}
	base.CredentialPosture = &sekizuiv1.CredentialPosture{
		Scheme:       p.Scheme,
		Version:      p.Version,
		Rotation:     string(p.Rotation),
		AuditedReads: p.AuditedReads,
		AtRest:       p.AtRest,
	}
}

// recordFailure writes the row that explains a failure and RETURNS THE ID ON THE
// ERROR (D202).
//
// **IT USED TO DISCARD IT.** `recorder.Terminal` returns the id of the row it
// just wrote and this function threw it away with `_`, so every failure reached
// its caller with no way to name the record that explains it — while every
// deliberate REFUSAL carried one (D135). The row existed and the only party who
// needed to find it had no key.
//
// The id is attached rather than logged, because the caller is frequently not a
// human reading our logs: a reflex holds `Outcome{Err}`, an agent gets a gRPC
// error, and across replicas under concurrent load the id is the join key with
// no substitute.
//
// **A RECORDING FAILURE STILL RETURNS THE ORIGINAL CAUSE.** If the recorder
// itself fails there is no id to attach, and substituting the recorder's error
// would replace the thing that went wrong with our inability to write about it.
func (s *Server) recordFailure(ctx context.Context, base *sekizuiv1.Decision, cause error) error {
	base.Reason = cause.Error()

	id, err := s.recorder.Terminal(ctx, base)
	if err != nil {
		s.log.Error("failed to record a failure", "err", err, "cause", cause)
		return cause
	}
	return fault.WithDecisionID(cause, id)
}

// DrainAdmission reports how many commands are still in flight, blocking until
// they finish or the context expires (D62).
//
// Exists because Admission.Drain's own comment names the sentence it produces —
// "drained with 3 commands still in flight" is what explains missing audit
// outcomes afterwards — and nothing called it. gRPC's GracefulStop waits for
// in-flight RPCs but reports nothing about them, so without this the count that
// explains a truncated audit log is computed and discarded.
func (s *Server) DrainAdmission(ctx context.Context, poll func()) (int, map[string]int) {
	remaining := s.admission.Drain(ctx, poll)

	// The PER-RPC breakdown, not just a total. Admission.InFlight exists for
	// exactly this — its comment calls it "D62's P0 contingency" because §7.1
	// names the ugly case, "a command mid-side-effect must still get its audit
	// outcome recorded" — and it had no caller at all, so the drain reported a
	// number without saying what was behind it.
	return remaining, s.admission.InFlight()
}

// BusDropped reports envelopes discarded for lagging subscribers, or 0 when the
// bus does not count them.
//
// Reached through an OPTIONAL INTERFACE (GO-PRIMER §2.2) rather than a concrete
// type, so a broker-backed bus at P7 either supplies the number or does not,
// without this needing to know which.
func (s *Server) BusDropped() uint64 {
	if d, ok := s.bus.(interface{ Dropped() uint64 }); ok {
		return d.Dropped()
	}
	return 0
}

// Metrics exposes the registry, so cmd can serve /metrics from the same counters
// the enforcement path writes.
func (s *Server) Metrics() *metrics.Registry { return s.metrics }

// outcomeLabel derives the RED outcome label from whatever is being returned.
//
// ONE RULE, ONE PLACE. The label space is deliberately the UNION of two
// vocabularies, because neither alone covers what an operator dashboards:
//
//	an ERROR   -> the fault.Kind name: target_unavailable, rate_limited, timeout
//	a REFUSAL  -> the verdict: denied, escalated, would_have_fired
//	success    -> ok
//
// A denial and an upstream outage are different facts requiring different
// responses, and collapsing them into one word would make the most useful
// dashboard query impossible. Both vocabularies are already stable identifiers
// used in the audit log, so a metric label and a decision record still read as
// the same word.
func outcomeLabel(result *sekizuiv1.CommandResult, err error, refused fault.Kind) string {
	if err != nil {
		return fault.KindOf(err).String()
	}
	// A REFUSAL IS LABELLED BY KIND, NOT BY STATUS (D135). Status is
	// deliberately coarser — denied, unauthenticated and residency all map to
	// STATUS_DENIED — and the metric needs the finer answer, because "review a
	// grant" and "fix the deployment topology" are different work.
	if refused != fault.KindUnknown {
		return refused.String()
	}
	if result == nil {
		return "unknown"
	}
	return statusLabel(result.GetStatus())
}

func queryOutcomeLabel(resp *sekizuiv1.QueryResponse, err error) string {
	if err != nil {
		return fault.KindOf(err).String()
	}
	if resp == nil {
		return "unknown"
	}
	return statusLabel(resp.GetStatus())
}

// statusLabel turns a wire status into a metric label.
//
// Derived from the enum name rather than a hand-written switch, so a status
// added to the proto appears in metrics without anyone remembering to extend a
// mapping — the same failure this whole refactor exists to remove.
func statusLabel(st sekizuiv1.Status) string {
	if st == sekizuiv1.Status_STATUS_OK {
		return "ok"
	}
	name := strings.TrimPrefix(st.String(), "STATUS_")
	if name == "" || name == "UNSPECIFIED" {
		return "unknown"
	}
	return strings.ToLower(name)
}

// verdictStatus maps a policy verdict onto the wire status.
func verdictStatus(v sekizuiv1.Verdict) sekizuiv1.Status {
	switch v {
	case sekizuiv1.Verdict_VERDICT_DENY:
		return sekizuiv1.Status_STATUS_DENIED
	case sekizuiv1.Verdict_VERDICT_ESCALATE:
		return sekizuiv1.Status_STATUS_ESCALATED
	case sekizuiv1.Verdict_VERDICT_WOULD_HAVE_FIRED:
		return sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED
	default:
		return sekizuiv1.Status_STATUS_UNSPECIFIED
	}
}

// statusError carries a gRPC status WITHOUT discarding the classified error
// underneath it.
//
// status.Error() returns a fresh error, so wrapping with it erases the
// fault.Kind and errors.Is stops working. That is invisible over the wire — a
// client only ever sees the code and message — and it matters a great deal
// IN-PROCESS, because the reflex engine (P5) calls the enforcement path
// directly and needs to distinguish a residency refusal from a rate limit.
//
// gRPC finds the status through the GRPCStatus method; errors.Is finds the kind
// through Unwrap. Both work, and neither knows about the other.
type statusError struct {
	err error
	st  *status.Status
}

func (e *statusError) Error() string              { return e.err.Error() }
func (e *statusError) Unwrap() error              { return e.err }
func (e *statusError) GRPCStatus() *status.Status { return e.st }

// toStatus converts a classified error into a gRPC status, preserving the
// classification for in-process callers.
//
// ONE MAPPING, from fault.Kind (§4.5.3). Translating per call site is how two
// handlers end up disagreeing about what a rate limit looks like on the wire.
func toStatus(err error) error {
	if err == nil {
		return nil
	}
	// **THE DECISION ID TRAVELS (D202).** A remote caller receives a gRPC error
	// and nothing else; without the id in the message it cannot name the audit
	// row explaining its own failure, which is the whole point of attaching one.
	// Appended rather than substituted so the cause still reads first, and only
	// when there is one — a bare `[decision ]` would be worse than its absence.
	msg := err.Error()
	if id := fault.DecisionIDOf(err); id != "" {
		msg += " [decision " + id + "]"
	}
	return &statusError{
		err: err,
		st:  status.New(fault.KindOf(err).GRPCCode(), msg),
	}
}

// MaxIdempotencyKeyBytes bounds a caller-supplied idempotency key (D215).
//
// **THE SAME AMPLIFICATION AS THE TRACE ID, THROUGH THE MESSAGE BODY.** The key
// reaches `Decision.idempotency_key` on the intent record and the outcome
// record, both fsynced. gRPC's default 4 MiB receive limit is the only thing
// bounding it today, which is a limit on the whole request rather than a
// judgement about this field.
//
// 512 BYTES because a key identifies one attempt: D163's classes are satisfied
// by a UUID, a request hash, or a vendor's own reference, and none of those is
// long. It is deliberately more generous than the trace id's ceiling, because a
// key may legitimately be a composite an operator built out of several
// identifiers.
const MaxIdempotencyKeyBytes = 512

// refuseUnusableIdempotencyKey rejects a key that cannot safely be recorded.
//
// **`KindInvalidArgument`, ATTRIBUTED TO THE CALLER (D200), AND REFUSED RATHER
// THAN TRUNCATED.** Truncation is worse here than for a driver result and worse
// than for a trace: a shortened key is a DIFFERENT key, so it would silently
// collide with every other request sharing the prefix — turning an
// over-long key into a false deduplication, which is the exact failure D163's
// classes exist to prevent.
func refuseUnusableIdempotencyKey(op, key string) error {
	if len(key) > MaxIdempotencyKeyBytes {
		return fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"the idempotency key is %d bytes and the ceiling is %d. It is recorded on "+
				"every decision this command produces, each fsynced to the audit log "+
				"(D178's reasoning, D215) — and truncating it is not an option, because a "+
				"shortened key would collide with every request sharing its prefix and "+
				"produce a false deduplication",
			len(key), MaxIdempotencyKeyBytes))
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; c < 0x20 || c == 0x7F {
			return fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"the idempotency key contains a control character at byte %d. It is an "+
					"identifier, it reaches operator-facing text, and it is placed into "+
					"outbound HTTP headers by D186's helper — where a newline is refused at "+
					"the wire and looks exactly like an unreachable target (D199)", i))
		}
	}
	return nil
}

// traceFor resolves the span context for one command (D216).
//
// **THE HEADER WINS AND THE BODY IS THE FALLBACK, which is the precedence the
// proto states.** For a wire caller `Command.trace` is ignored, so the body can
// never override the header — not because the trace is trusted (nothing
// authorises on it, CONTRACTS 89) but because two sources for one value with no
// stated precedence is how they come to disagree silently.
//
// **THE FALLBACK IS NOT DEAD CODE: it is the reflex path.** A command produced
// by a rule was never requested over the wire, so there is no `traceparent` to
// read — and without this the trace of the envelope that triggered it would be
// lost at exactly the hop worth following.
func traceFor(ctx context.Context, cmd *sekizuiv1.Command) *sekizuiv1.Trace {
	if t := identity.TraceFromContext(ctx); t != nil {
		return t
	}
	return cmd.GetTrace()
}

// Payloads is what a Query result is shaped against (D279) — in production the
// deployment's schemareg.Registry.
type Payloads interface {
	Shape(typ string, payload map[string]any) (map[string]any, schemareg.Shaped)
	// Has says whether a type is registered: a result of an UNREGISTERED type
	// is withheld, because Shape passes it through unchanged for a validator
	// to refuse, and results have no validator after them (D283).
	Has(typ string) bool
	// CallerOnly names a type's fields returned to the caller and never
	// recorded (D289) — forRecord withholds them from the audit copy.
	CallerOnly(typ string) []string
}

// configuredResidency is the residency class the document declares for a
// target, or "" for an unknown ref or none declared (D29 item 4, D319).
func (s *Server) configuredResidency(ref string) string {
	if s.doc == nil {
		return ""
	}
	for _, t := range s.doc.Targets {
		if t.Ref == ref {
			return t.Residency
		}
	}
	return ""
}

// driverFor is the one lookup a governed call makes for its target's driver.
//
// **A QUARANTINED CONNECTOR IS REFUSED HERE (D282)**, for every verb — a command,
// a read, a job — because its schemas are not sound and nothing it emits could
// be shaped. The refusal names the connector and why, and is recorded like any
// other: the caller learns it is the CONNECTOR, not their grant or the target,
// and an operator reading the log sees the same reason the boot logged.
func (s *Server) driverFor(op string, target connector.Target) (connector.Driver, error) {
	if why, q := s.quarantined[target.Kind()]; q {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"connector %q is quarantined — it is not sound: %s. Its targets are refused "+
				"until a fixed connector ships; every other connector serves (D282)", target.Kind(), why))
	}
	driver, ok := s.drivers[target.Kind()]
	if !ok {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf("no driver registered for kind %q", target.Kind()))
	}
	return driver, nil
}

// priceResult is a governed call's declared cost, checked before the call is
// sent (D283) — one function for commands, reads and (through jobSize) jobs.
//
// **UNIVERSAL BECAUSE EVERY RESULT IS ROWS OF BOUNDED OBJECTS.** Each object is
// capped at safestruct.DefaultBudget whichever connector produced it, so a
// call's worst case is rows × that budget, and the only connector-specific fact
// is how many rows — the action's Bound, or one object when it declares none.
//
// Returns the rows the call may return, and whether a DEFAULT was lowered to
// fit (the caller then passes the lower number through Bound.Arg). A caller's
// EXPLICIT request that does not fit is refused naming the number that would,
// because silently delivering less than was asked is the truncation an agent
// reasons wrongly over. Uncapped (max_bytes 0) prices nothing but the ceiling.
func priceResult(op, action, target string, spec connector.ActionSpec, args map[string]any,
	maxBytes uint64) (rows int, clamped bool, err error) {

	const perObject = uint64(safestruct.DefaultBudget)
	rows, explicit, over := spec.Bound.Rows(args)
	if over {
		return 0, false, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"%q asks for %d rows through %q; the action returns at most %d", action, rows,
			spec.Bound.Arg, spec.Bound.MaxRows))
	}
	if maxBytes == 0 {
		return rows, false, nil
	}
	affordable := int(maxBytes / perObject)
	if affordable < 1 {
		return 0, false, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"the capability authorising %q on %q allows %d bytes, and one result may occupy up to %d — "+
				"so this grant cannot pay for a single result. Raise max_bytes on the capability",
			action, target, maxBytes, perObject))
	}
	if rows <= affordable {
		return rows, false, nil
	}
	declared := uint64(rows) * perObject
	switch {
	case explicit:
		return 0, false, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"%q on %q asks for %d rows, a declared cost of %d bytes; the capability that authorised it "+
				"allows %d, which fits %d. Ask for %d or fewer", action, target, rows, declared, maxBytes,
			affordable, affordable))
	case spec.Bound != nil && spec.Bound.Arg != "":
		return affordable, true, nil
	default:
		return 0, false, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
			"%q on %q returns up to %d rows, a declared cost of %d bytes, and offers no argument to ask "+
				"for fewer; the capability that authorised it allows %d", action, target, rows, declared, maxBytes))
	}
}

// shapeResult is an Execute result shaped to its action's declared output type
// before it is recorded or returned (D283). A NoResult action's data, or data
// of a kind the connector's schema refuses, is WITHHELD — nil — and said.
func (s *Server) shapeResult(action, target string, spec connector.ActionSpec, data map[string]any) map[string]any {
	if len(data) == 0 {
		return data
	}
	if spec.NoResult || spec.OutputType == "" || s.payloads == nil || !s.payloads.Has(spec.OutputType) {
		s.log.Warn("an action returned data it does not declare; it was withheld, not recorded or returned",
			"action", action, "target", target, "fields", len(data))
		return nil
	}
	shaped, report := s.payloads.Shape(spec.OutputType, data)
	if report.Refused() {
		s.log.Warn("an action returned a result of a kind its connector refuses; it was withheld",
			"action", action, "target", target, "kind", report.Kind)
		return nil
	}
	return shaped
}

// anzenAlert is the `alert` action (D332): record and surface, change nothing.
// The record is the alert — terminal, allowed, naming the rule, the signal it
// watches and its subject — and the log line is its surface.
func (s *Server) anzenAlert(ctx context.Context, base *sekizuiv1.Decision,
	rule anzen.Reactive) (*sekizuiv1.CommandResult, error) {
	base.TargetRef = rule.Subject
	base.Reason = fmt.Sprintf("anzen alert: rule %s, watching %s, about %s — recorded; nothing was changed",
		rule.Name, rule.Watches, rule.Subject)
	decisionID, err := s.recorder.Terminal(ctx, base)
	if err != nil {
		return nil, err
	}
	s.log.Warn("ANZEN ALERT", "rule", rule.Name, "signal", rule.Watches, "subject", rule.Subject,
		"decision", decisionID)
	return &sekizuiv1.CommandResult{DecisionId: decisionID, Status: sekizuiv1.Status_STATUS_OK,
		Reason: base.Reason}, nil
}

// anzenDisableReflex is the `disable_reflex` action (D332): the named reflex
// rule stops, as though configuration had said `enabled: false`, until config
// is redeployed. A second firing confirms rather than fails, D158's rule.
func (s *Server) anzenDisableReflex(ctx context.Context, base *sekizuiv1.Decision,
	rule anzen.Reactive) (*sekizuiv1.CommandResult, error) {
	const op = "gateway.anzenDisableReflex"
	base.TargetRef = rule.Subject
	if s.reflexes == nil {
		return nil, s.recordFailure(ctx, base, fault.New(fault.KindUnavailable, op,
			"this instance runs no reflex engine, so there is no rule "+rule.Subject+" to disable"))
	}
	already, err := s.reflexes.Disable(rule.Subject, rule.Name)
	if err != nil {
		return nil, s.recordFailure(ctx, base, err)
	}
	base.Reason = fmt.Sprintf("anzen rule %s disabled reflex %s until config is redeployed", rule.Name, rule.Subject)
	if already {
		base.Reason = fmt.Sprintf("reflex %s was already disabled; confirmed, nothing changed (D158)", rule.Subject)
	}
	decisionID, err := s.recorder.Terminal(ctx, base)
	if err != nil {
		return nil, err
	}
	return &sekizuiv1.CommandResult{DecisionId: decisionID, Status: sekizuiv1.Status_STATUS_OK,
		Reason: base.Reason}, nil
}

// anzenRevokeGrant is `revoke_grant` fired from a rule (D340, a v1 hotfix): the
// rule's subject is a PRINCIPAL, bare — `agent:metered` — because that is how a
// signal names one (`denial_storm` keys its level by the monopoliser), and the
// dispatcher matches a rule's subject against those keys.
//
// **THE GOVERNED VERB AN OPERATOR WOULD ISSUE, NOT A COPY OF IT.** The rule
// becomes `sekizui.revoke_grant` on `principal:<subject>`, with a reason naming
// the rule and its signal, and goes through grantVerb: the suspension, D158's
// confirm-on-repeat, cancelling the principal's jobs already running (D256),
// the record — one path. Until config is redeployed, D146's asymmetry, and the
// trigger on the record is `anzen:<rule>`.
func (s *Server) anzenRevokeGrant(ctx context.Context, base *sekizuiv1.Decision,
	rule anzen.Reactive) (*sekizuiv1.CommandResult, error) {
	args, err := structpb.NewStruct(map[string]any{
		"reason": fmt.Sprintf("anzen rule %s fired on %s", rule.Name, rule.Watches),
	})
	if err != nil {
		return nil, err
	}
	base.TargetRef = principalRefPrefix + rule.Subject
	return s.grantVerb(audit.WithReflexName(ctx, rule.Name), base, &sekizuiv1.Command{
		Action: verb.RevokeGrant, TargetRef: base.TargetRef, Args: args,
	})
}
