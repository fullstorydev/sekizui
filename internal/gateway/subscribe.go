package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/fullstorydev/sekizui/internal/bus"
	"github.com/fullstorydev/sekizui/internal/metrics"
	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Subscribe streams envelopes to a consumer — the afferent plane's egress
// (D91).
//
// THREE THINGS HAPPEN HERE THAT DO NOT HAPPEN IN THE BUS, and separating them
// is the point of building this in P0 rather than with the real broker at P3:
//
//  1. AUTHORISATION. May this principal consume these subjects? Deny by default,
//     from `subscribe` grants (D92). The bus itself authorises nothing — putting
//     it there would create a second enforcement path, which D18 forbids.
//  2. AUDIT, ONCE. A subscription is one decision, recorded at establishment.
//  3. SHIN, PER ENVELOPE. Each delivery is lensed for this consumer (§4.12).
//
// The transport underneath is a skeleton — at-most-once, no replay, no queue
// groups. The governance is not.
func (s *Server) Subscribe(req *sekizuiv1.SubscribeRequest,
	stream sekizuiv1.GatewayService_SubscribeServer) error {

	const op = "gateway.Subscribe"

	ctx := stream.Context()

	release, err := s.admission.Acquire(ctx, "Subscribe")
	if err != nil {
		return toStatus(err)
	}
	defer release()

	if s.bus == nil {
		return toStatus(fault.New(fault.KindInternal, op,
			"server was built without a bus; Subscribe cannot answer"))
	}

	id, err := s.verifier.Verify(ctx)
	if err != nil {
		return toStatus(err)
	}
	consumer := id.GetSubject().GetPrincipal()

	// 1 + 2. MAY THEY, RECORDED ONCE, AND THE SCOPE COMPILED (D260). One
	// function, because the reflex engine consumes through it too, and two
	// copies of "authorise a subscription" is D155's second path.
	sub, decisionID, err := s.openScoped(ctx, id, pkgbus.Filter{
		Subjects:  req.GetSubjects(),
		Types:     req.GetTypes(),
		Residency: req.GetResidency(),
	})
	if err != nil {
		return toStatus(err)
	}
	defer sub.Close()

	s.log.Info("subscription opened",
		"consumer", consumer, "decision", decisionID)

	delivered, lensed := 0, 0
	defer func() {
		s.log.Info("subscription closed", "consumer", consumer,
			"delivered", delivered, "lensed", lensed,
			"out_of_scope", sub.outOfScope, "decision", decisionID)
	}()

	for {
		env, ok := sub.Next(ctx)
		if !ok {
			// The consumer went away, or the bus closed. Not an error: a dropped
			// connection loses the events sent during the gap, which IS
			// at-most-once rather than a pretence of something better
			// (CONTRACTS §2.1).
			return nil
		}

		// 3. SHIN, PER DELIVERY (§4.12) — through the one delivery step both
		// streams take (D267).
		projected, lenses, ok := s.shape("subscribe", consumer, env, req.GetLens(),
			req.GetIncludeProjection())
		if !ok {
			continue
		}
		if len(lenses) > 0 {
			lensed++
		}

		// THE DROPS SINCE THE LAST MESSAGE TRAVEL WITH THIS ONE (D24): a
		// consumer that fell behind is told how much it missed.
		if err := stream.Send(&sekizuiv1.SubscribeResponse{
			Envelope: projected, Dropped: sub.TakeDropped(),
		}); err != nil {
			return toStatus(fault.Wrap(fault.KindUnavailable, op, "sending to consumer", err))
		}
		delivered++
		s.metrics.Observe("", "subscribe", "delivered", 0)
	}
}

// openScoped is THE way anything in this process subscribes to the bus (D260).
//
// Four things, in this order, for every consumer — a remote agent over
// Subscribe and, from P3, the reflex engine as its rule's principal:
//
//  1. AUTHORISE the requested subjects against the principal's grant, deny by
//     default (D92), refusing rather than narrowing a pattern it does not cover.
//  2. RECORD the decision once (D93), allowed or denied, naming the targets.
//  3. COMPILE the grant into the filter's Scope with ScopeFor, so the TRANSPORT
//     applies authorisation — the consumer's own Subjects/Types/Residency may
//     only narrow what the grant already bounds.
//  4. WRAP the subscription so every envelope is ASSERTED in scope on receipt,
//     with the same matcher the bus used (D86's apply-then-assert).
//
// `internal/archcheck` fails the build if production code calls
// `Bus.Subscribe` from anywhere else.
func (s *Server) openScoped(ctx context.Context, id *sekizuiv1.Identity,
	narrow pkgbus.Filter) (*ScopedSubscription, string, error) {

	const op = "gateway.openScoped"

	if s.bus == nil {
		return nil, "", fault.New(fault.KindInternal, op,
			"server was built without a bus; nothing can subscribe")
	}
	consumer := id.GetSubject().GetPrincipal()

	// An empty subject list means "everything this principal is granted"
	// (SubscribeRequest.subjects), which is a narrowing convenience and never a
	// widening: the grant is still the ceiling.
	subjects, grants, err := s.authoriseSubjects(consumer, narrow.Subjects)
	if err != nil {
		// Recorded, because a refused subscription is a denial like any other and
		// §5.4 calls denials the highest-value rows.
		// THE ID IS ATTACHED, NOT DISCARDED (D202). A refused subscriber reaches
		// for the row explaining why, and a denial is the highest-value row in
		// the log (§5.4) — of no use to the party it was about if they cannot
		// name it.
		decisionID, rerr := s.recorder.Terminal(ctx, &sekizuiv1.Decision{
			Identity: id, Action: "sekizui.subscribe",
			TargetRef:   strings.Join(narrow.Subjects, ","),
			Verdict:     sekizuiv1.Verdict_VERDICT_DENY,
			MatchedRule: "default_deny", Reason: err.Error(),
		})
		if rerr != nil {
			s.log.Error("failed to record a subscription denial", "err", rerr)
		}
		return nil, decisionID, fault.WithDecisionID(err, decisionID)
	}

	// AUDITED ONCE, AT ESTABLISHMENT — not per envelope (D93).
	//
	// The DECISION being made is "may this principal consume these subjects",
	// and it is made exactly once. A record per delivery would write millions of
	// rows saying the same thing, drowning the log whose value is that every row
	// is a decision someone can review. What per-envelope volume needs is a
	// METRIC.
	decisionID, err := s.recorder.Terminal(ctx, &sekizuiv1.Decision{
		Identity: id, Action: "sekizui.subscribe",
		TargetRef:   strings.Join(subjects, ","),
		Verdict:     sekizuiv1.Verdict_VERDICT_ALLOW,
		MatchedRule: fmt.Sprintf("%s#subscribe", consumer),
		// THE TARGETS ARE IN THE RECORD because they are half of what was
		// decided (D259): a reviewer reading "opened over sekizui.raw.kata.>"
		// alone could not tell which customers' events this consumer can see.
		Reason: fmt.Sprintf("subscription opened over %d subject pattern(s), from target(s) %v",
			len(subjects), grantedTargets(grants)),
	})
	if err != nil {
		return nil, "", err
	}

	scope := ScopeFor(grants)
	f := narrow
	f.Subjects, f.Scope, f.Unscoped = subjects, scope, false
	sub, err := s.bus.Subscribe(bus.WithConsumer(ctx, consumer), f)
	if err != nil {
		return nil, decisionID, err
	}
	return &ScopedSubscription{
		sub: sub, scope: scope, consumer: consumer, decision: decisionID,
		log: s.log, metrics: s.metrics,
	}, decisionID, nil
}

// SubscribeAs opens a scoped subscription for an IN-PROCESS consumer — the
// reflex engine, subscribing as its rule's principal (D261).
//
// The same four steps a remote agent's Subscribe takes, by calling the same
// function: authorised against the principal's grant, recorded once, scope
// compiled, every envelope asserted on receipt. What differs is only where the
// identity came from — `reflex.IdentityFor`, ASSERTED rather than signed
// because the process making the claim is Sekizui (D57, D69) — and that is why
// this is not reachable over the wire: there is no RPC for it, and the
// verifier stays the only way a REMOTE caller gets an identity.
func (s *Server) SubscribeAs(ctx context.Context, id *sekizuiv1.Identity,
	subjects []string) (*ScopedSubscription, error) {

	sub, _, err := s.openScoped(ctx, id, pkgbus.Filter{Subjects: subjects})
	return sub, err
}

// ScopeFor compiles a principal's subscribe grant into the bus scope that
// authorises its deliveries (D259, D260). THE ONE CONSTRUCTOR: a Scope built
// from anything but configuration — a request, a header, a rule's own
// `consumes` — would let the consumer author its own authorisation.
func ScopeFor(grants []config.SubscriptionSpec) []pkgbus.Scope {
	out := make([]pkgbus.Scope, 0, len(grants))
	for _, g := range grants {
		out = append(out, pkgbus.Scope{Subject: g.Subject, Source: g.TargetRef})
	}
	return out
}

// ScopedSubscription is a bus subscription whose every envelope is asserted in
// scope on receipt (D260).
//
// **THE ASSERTION IS NOT A SECOND DECISION.** The bus decided, with
// `pkgbus.InScope`, from a scope compiled once at establishment; this checks
// with the SAME function that the decision held. What it guards is the
// transport — an out-of-tree bus driver that ignored `Filter.Scope` would
// otherwise deliver every tenant's events, quietly. An envelope failing it is
// DROPPED and logged at ERROR, never delivered: fail closed, and loudly,
// because the event it reports is a broken transport rather than a busy one.
type ScopedSubscription struct {
	sub      pkgbus.Subscription
	scope    []pkgbus.Scope
	consumer string
	decision string
	log      *slog.Logger
	metrics  *metrics.Registry

	// outOfScope counts envelopes the transport delivered and the assertion
	// refused. Anything but zero is a defect in the bus driver.
	outOfScope int

	// seenDropped is the transport's drop count when last read, and
	// pendingDropped the drops not yet reported to the consumer (P3 step 6).
	seenDropped, pendingDropped uint64
}

// accountDrops reads the transport's per-subscription drop count, if it keeps
// one, and turns what is new into the `bus_dropped` metric and a count owed to
// the consumer. **AT-MOST-ONCE MADE AUDITABLE, NOT RELIABLE (D24):** before this,
// `SubscribeResponse.dropped` was documented and set by nothing, and the scrape
// the bus's own comment promised did not exist — an operator learned of drops
// from one line at shutdown, and the consumer that lost them never did.
func (s *ScopedSubscription) accountDrops() {
	d, ok := s.sub.(interface{ Dropped() uint64 })
	if !ok {
		return
	}
	now := d.Dropped()
	if now > s.seenDropped {
		delta := now - s.seenDropped
		s.seenDropped = now
		s.pendingDropped += delta
		s.metrics.Add("bus_dropped", delta)
	}
}

// TakeDropped returns the drops not yet reported and resets the count — what
// SubscribeResponse.dropped means: "since the last message".
func (s *ScopedSubscription) TakeDropped() uint64 {
	s.accountDrops()
	n := s.pendingDropped
	s.pendingDropped = 0
	return n
}

// Next returns the next in-scope envelope, or false when the context ends or
// the subscription closes.
func (s *ScopedSubscription) Next(ctx context.Context) (*sekizuiv1.Envelope, bool) {
	for {
		select {
		case <-ctx.Done():
			return nil, false
		case env, ok := <-s.sub.Events():
			s.accountDrops()
			if !ok {
				return nil, false
			}
			if pkgbus.InScope(s.scope, env) {
				return env, true
			}
			s.outOfScope++
			s.metrics.Observe("", "subscribe", "out_of_scope", 0)
			s.log.Error("the bus delivered an envelope outside this subscription's scope; "+
				"dropped. The transport is not honouring Filter.Scope (D260)",
				"consumer", s.consumer, "envelope", env.GetId(),
				"source", env.GetSource(), "subject", pkgbus.SubjectOf(env),
				"decision", s.decision)
		}
	}
}

// Close ends the underlying subscription. The error is discarded on purpose:
// there is nothing a failing teardown could tell a consumer whose stream is
// already ending, matching spine.stopStarted.
func (s *ScopedSubscription) Close() { _ = s.sub.Close() }

// authoriseSubjects intersects requested subjects with granted ones, and
// returns the grant entries the delivery loop checks each envelope's target
// against (D259).
//
// DENY BY DEFAULT (§4.5). A principal with no `subscribe` grant consumes
// nothing, and a requested subject not covered by a grant is REFUSED rather than
// silently dropped from the filter — a consumer receiving no events because a
// pattern was quietly removed has no way to tell that from an idle bus.
//
// **THE SUBJECT IS DECIDED HERE AND THE TARGET PER ENVELOPE**, and the split is
// forced rather than chosen: a request names subjects and never targets, so
// "may this consumer have kata:acme's rows" has no answer until a row from
// kata:acme arrives. Both halves come from the same entries, so a subject
// granted for one target confers nothing from another.
func (s *Server) authoriseSubjects(consumer string, requested []string) (
	[]string, []config.SubscriptionSpec, error) {

	const op = "gateway.authoriseSubjects"

	grants := s.subscribable[consumer]
	if len(grants) == 0 {
		return nil, nil, fault.New(fault.KindDenied, op, fmt.Sprintf(
			"principal %q has no subscribe grant, so it may consume nothing. Bus subjects "+
				"are granted explicitly (D92), like every other capability", consumer))
	}
	granted := grantedSubjects(grants)

	// Empty request means everything granted — a convenience, never a widening.
	if len(requested) == 0 {
		return granted, grants, nil
	}

	var out []string
	for _, want := range requested {
		if !coveredByGrant(granted, want) {
			return nil, nil, fault.New(fault.KindDenied, op, fmt.Sprintf(
				"principal %q may not subscribe to %q; it is granted %v. Refused rather "+
					"than dropped from the filter, because a consumer receiving nothing "+
					"cannot tell a removed pattern from an idle bus", consumer, want, granted))
		}
		out = append(out, want)
	}
	return out, grants, nil
}

// grantedSubjects is the distinct subject patterns across a principal's entries,
// in declaration order.
func grantedSubjects(grants []config.SubscriptionSpec) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range grants {
		if !seen[g.Subject] {
			seen[g.Subject] = true
			out = append(out, g.Subject)
		}
	}
	return out
}

// grantedTargets is the distinct targets, sorted, for the establishment record.
func grantedTargets(grants []config.SubscriptionSpec) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range grants {
		if !seen[g.TargetRef] {
			seen[g.TargetRef] = true
			out = append(out, g.TargetRef)
		}
	}
	sort.Strings(out)
	return out
}

// coveredByGrant reports whether some granted pattern permits a requested one.
// A REQUEST MUST BE NO BROADER THAN ITS GRANT; `pkgbus.PatternCovers` is the
// rule, shared with boot validation of a reflex's `consumes` (D261).
func coveredByGrant(granted []string, want string) bool {
	for _, g := range granted {
		if pkgbus.PatternCovers(g, want) {
			return true
		}
	}
	return false
}

// PublishForTest exposes the bus so the acceptance run can drive the afferent
// path without a poller, which lands at P3.
//
// NAMED FOR WHAT IT IS. A neutral name like `Publish` would read as a supported
// ingress and get called from somewhere real; ingress is a Source polling a
// driver, not an RPC. When P3 lands, this goes.
func (s *Server) PublishForTest(env *sekizuiv1.Envelope) error {
	if s.bus == nil {
		return fault.New(fault.KindInternal, "gateway.PublishForTest", "no bus")
	}
	return s.bus.Publish(context.Background(), env)
}

// shape is THE DELIVERY STEP for anything leaving on a stream — a bus
// subscription and a job's results alike (D267) — so a result is lensed exactly
// as a delivery is, and what step 36 adds (the projection) lands in one place.
//
// False means the envelope must not be sent: a lens that could not produce
// what it promised must not fall back to the unlensed envelope — that is the
// disclosure the egress assertion exists to stop (D86). Refuse the DELIVERY,
// not the stream.
//
// `verb` labels the metric, so the `subscribe` series an operator already
// watches keeps its name and a job's results get their own.
//
// **THE PROJECTION IS SHAPED HERE, AFTER SHIN, FROM THE LENSED DATA (D248,
// D269)** — so it can only ever contain what this consumer's lens let through,
// by construction rather than by a second lensing surface. And only for a
// consumer who asked: `include_projection` was on the wire for three phases and
// read by nothing; it is honoured now, in both directions — a consumer who did
// not ask receives no projection, and shin has already stripped any that
// arrived. A projection that cannot be shaped is logged and the envelope is
// delivered WITHOUT one: the data is intact, and losing the event over a
// convenience view would be the wrong trade (the maintainer's ruling).
func (s *Server) shape(verb, consumer string, env *sekizuiv1.Envelope, lens string,
	includeProjection bool) (*sekizuiv1.Envelope, []string, bool) {

	shaped, lenses, err := s.lenses.Deliver(consumer, env, lens)
	if err != nil {
		s.log.Error("refusing to deliver an envelope its lens could not shape",
			"consumer", consumer, "envelope", env.GetId(), "err", err)
		s.metrics.Observe("", verb, "lens_refused", 0)
		return nil, nil, false
	}
	if !includeProjection || s.projector == nil {
		return shaped, lenses, true
	}
	projection, applied, perr := s.projector.Project(shaped)
	switch {
	case perr != nil:
		s.log.Warn("delivering without a projection: it could not be shaped from what this "+
			"consumer may see", "consumer", consumer, "envelope", env.GetId(), "err", perr)
		s.metrics.Observe("", verb, "projection_failed", 0)
	case projection != nil:
		if shaped == env {
			// shin returns its input untouched when no lens applied; never
			// write into an envelope other consumers are also receiving.
			shaped = proto.Clone(env).(*sekizuiv1.Envelope)
		}
		shaped.Projection = projection
		s.log.Debug("projection shaped", "consumer", consumer, "envelope", env.GetId(),
			"rules", applied)
	}
	return shaped, lenses, true
}
