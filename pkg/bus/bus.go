// Package bus defines the event transport seam.
//
// PUBLIC API (D35). A self-hoster who already runs Kafka should be able to back
// the bus with it rather than fork.
//
// DESIGN.md references: §4.6.3, §4.6.4, §4.11.6, D21, D24, D43.
package bus

import (
	"context"
	"strings"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Bus is the internal event transport.
//
// THE ABSTRACTION'S ACCEPTANCE TEST (§4.6.4 item 3): swapping the inproc driver
// for JetStream at P7 must change ZERO lines of reflex or consumer code. If a
// consumer ever needs to know which delivery semantics it is getting, this
// interface has leaked and it is wrong.
//
// Note this is NOT the same thing as an egress sink. A sink is a Driver that
// publishes into someone else's broker (§4.6.5), governed by policy and audit
// like any other external effect. Conflating the two is the mistake that makes
// "integrate with Kafka" look like transport work when it is connector work.
type Bus interface {
	// Publish sends one envelope.
	//
	// Implementations MUST NOT validate stage monotonicity or payload schemas —
	// that happens upstream, at config load and publish time respectively, so
	// that a misconfiguration fails at boot rather than at 3am (D21, D42).
	Publish(ctx context.Context, env *sekizuiv1.Envelope) error

	// Subscribe returns a Subscription for the given filter.
	//
	// Where the driver supports it, members of the same QueueGroup share
	// delivery rather than each receiving a copy. This matters enormously for
	// reflexes: N gateway replicas each subscribing independently would fire one
	// reflex N times, producing duplicate Jira tickets scaled by replica count —
	// and it looks completely fine at one replica (§4.11.2).
	Subscribe(ctx context.Context, f Filter) (Subscription, error)

	// Close drains and releases resources. Must respect the drain budget, which
	// must in turn fit inside RuntimeProfile.GracePeriod (§4.10.2).
	Close(ctx context.Context) error
}

// Filter selects which envelopes a subscription receives.
type Filter struct {
	// Scope is WHAT THIS CONSUMER IS AUTHORISED TO RECEIVE: (subject pattern,
	// source target) pairs compiled from its subscribe grant (D259, D260).
	//
	// **AUTHORISATION, NOT NARROWING, and the difference is who may set it.**
	// Subjects, Types and Residency below are the CONSUMER's choice and can only
	// narrow. Scope is the grant's, built by one constructor from configuration
	// and never from a request, so it is decided once — at establishment, D93 —
	// and applied by the transport's matcher rather than by code in each
	// consumer's loop. That is D260's answer to the objection D254 raised about
	// filtering inside the delivery path.
	//
	// **REQUIRED.** A Subscribe with no Scope is REFUSED unless Unscoped is set,
	// because an empty scope that delivered everything would make forgetting it
	// the widest grant there is, and one that delivered nothing would give a
	// consumer an idle stream it cannot tell from a quiet bus (D92's argument).
	Scope []Scope

	// Unscoped subscribes to every source, and exists for ONE production-shaped
	// purpose: proving that something never travels on the bus at all (P1 step
	// 42, D118), where the broadest subscription is the instrument. Test files
	// only, and ENFORCED rather than conventional: `internal/archcheck` fails
	// the build on a use in production code (`TestEveryBusSubscriptionIsScoped`).
	// Stricter than `UseRaw`, which is merely greppable — deliberately, since
	// that one leaks one credential and this one every tenant's events.
	Unscoped bool

	// Subject patterns, e.g. []string{"sekizui.enriched.>"}.
	//
	// Stage prefixes come from the configured ordered stage list, not a fixed
	// enum (D43), so inserting a stage does not require code changes here.
	Subjects []string

	// Optional payload type filter, e.g. "fullstory.rage_click.v1".
	Types []string

	// Optional residency filter, so a consumer can decline envelopes it must not
	// receive rather than receiving and then dropping them (D29).
	Residency string

	// Non-empty means competing consumption: exactly one member of the group
	// receives each envelope. REQUIRED for reflexes running on more than one
	// replica.
	QueueGroup string
}

// Subscription is a stream of envelopes.
type Subscription interface {
	// Events returns the delivery channel. Closed when the subscription ends.
	//
	// Bounded buffer. On overflow the driver's documented policy applies —
	// either block or drop with a counter — but never unbounded buffering, which
	// converts a slow consumer into an OOM (§7.1).
	Events() <-chan *sekizuiv1.Envelope

	// Err returns why the subscription ended, or nil for a clean close.
	Err() error

	// Ack acknowledges an envelope.
	//
	// A NO-OP under at-most-once (D24). It exists on the interface from v1 so
	// consumer code written today needs no change when JetStream arrives — which
	// is precisely the acceptance test above. Calling it is always correct.
	Ack(id string) error

	Close() error
}

// StageOrder resolves configured pipeline stages to an ordering, so that
// monotonicity can be checked (D21).
//
// Cycles are prevented STRUCTURALLY by this ordering, not detected after the
// fact by the causation depth cap. Depth is the backstop for bugs; this is the
// guarantee. Detection alone would mean discovering cycles in production.
type StageOrder interface {
	// Index returns the position of a stage, or false if unknown.
	Index(stage string) (int, bool)

	// Validate reports whether publishing to `to` while consuming from `from` is
	// permitted — i.e. whether `to` is strictly later.
	Validate(from, to string) error
}

// SubjectOf is the bus subject an envelope is routed on: `sekizui.<stage>.<type>`
// (D60), and nothing else.
//
// **DERIVED, NEVER READ FROM `Envelope.subject`, AND THAT FIELD IS WHY THIS
// FUNCTION EXISTS (D258).** `subject` is CloudEvents' primary ENTITY — a session
// id, an issue key — and for two phases the in-process bus matched subscription
// patterns against it while the reflex engine derived D60's form. A real
// connector's envelope therefore matched no subscription at all; the suite
// passed because P0 step 16 overwrote the entity with a subject-shaped string
// before publishing, and the reference driver wrote the constant "kata.row"
// where an entity belongs — which is what an out-of-tree author copying it
// would then have done too. One contract, stated in D60, kept by one of its two
// readers.
//
// PUBLIC because a bus driver outside this repository (D35) has to publish on
// the same subject the in-process one matches, and a second derivation there is
// the defect this replaces.
//
// THE SOURCE IS DELIBERATELY NOT A SEPARATE TOKEN, and the §12.1 spike is why.
// Types are source-prefixed by convention (D41: "fullstory.rage_click.v1"), so
// prepending the source kind produced a duplicate in EVERY raw subject —
// `sekizui.raw.fullstory.fullstory.rage_click.v1`. Running the shape across all
// five connectors' event types made that obvious in a way that one example did
// not, which is precisely what §12.1 schedules the spike for.
//
// Consequences worth knowing:
//   - The token count is the TYPE's, not the stage's. The spike's example had
//     post-raw subjects at 4 tokens (raw.fullstory.rage_click ->
//     enriched.friction_detected), and D88 since made every published type
//     declared and versioned — `fullstory.friction_detected.v1` — so an
//     enriched subject is 5 tokens like a raw one. Write patterns against the
//     declared types, not against a remembered length.
//   - The version is its own trailing token, so `...rage_click.*` matches every
//     version — which is exactly what D41's dual-publish migration needs.
//   - The target INSTANCE is absent. `fullstory:o-EXAMPLE` contributes nothing:
//     per-org subjects would explode cardinality and put a tenant dimension on
//     the wire, which D37 rules out. **Which org's events a consumer may
//     receive is AUTHORISATION, not a filter (D259)** — a subscribe grant is
//     subject × target, checked against `Envelope.source`, because a consumer
//     choosing its own filter is not a control. This bullet used to say
//     "filtering by org is a Filter concern", and that sentence is how the bus
//     came to have no way to say "only customer X".
//
// A missing stage or type is left out rather than rendered as an empty token,
// so the result stays a well-formed subject; Publish refuses such an envelope
// before it gets here.
func SubjectOf(env *sekizuiv1.Envelope) string {
	parts := []string{"sekizui"}
	if s := env.GetStage(); s != "" {
		parts = append(parts, s)
	}
	if t := env.GetType(); t != "" {
		parts = append(parts, t)
	}
	return strings.Join(parts, ".")
}

// Scope is one authorised (subject, source) pair (D259).
//
// Source is compared EXACTLY — a capability's target has no wildcard, so a
// subscription's cannot either (D259) — and Subject is a NATS-style pattern
// matched with SubjectMatches against SubjectOf(env).
type Scope struct {
	Subject string
	Source  string
}

// InScope reports whether some pair in scope admits this envelope.
//
// **THE ONE MATCHER, AND BOTH ITS CALLERS ARE THE POINT (D260).** A bus driver
// calls it to decide delivery; the gateway calls it AGAIN on receipt, to assert
// the driver did (D86's apply-then-assert, aimed at the transport). Two
// implementations of this function is how one would disagree with the other,
// which is D258's defect in a new place — so an out-of-tree driver is expected
// to call this rather than write its own.
//
// PAIRED: {raw.>, alpha} and {enriched.>, beta} admit alpha's raw rows and
// beta's enriched ones, and not beta's raw rows.
func InScope(scope []Scope, env *sekizuiv1.Envelope) bool {
	subject, source := SubjectOf(env), env.GetSource()
	for _, sc := range scope {
		if sc.Source == source && SubjectMatches(sc.Subject, subject) {
			return true
		}
	}
	return false
}

// SubjectMatches reports whether a subject matches a pattern.
//
// NATS-STYLE WILDCARDS, because that is what the subjects are written in and
// what JetStream will interpret at P7: `*` matches exactly one token, `>`
// matches one or more trailing tokens. Implementing a DIFFERENT dialect now
// would mean every subject in configuration changing meaning when the real
// broker lands — a migration nobody would see coming.
//
// PUBLIC and HERE rather than in internal/bus (D260): InScope needs it, an
// out-of-tree driver needs InScope, and the reflex engine and the gateway had
// each been reaching into internal/bus for it.
func SubjectMatches(pattern, subject string) bool {
	p := strings.Split(pattern, ".")
	s := strings.Split(subject, ".")

	for i, token := range p {
		if token == ">" {
			// `>` must match at least one remaining token, so `a.>` does not
			// match `a` itself.
			return len(s) > i
		}
		if i >= len(s) {
			return false
		}
		if token != "*" && token != s[i] {
			return false
		}
	}
	return len(p) == len(s)
}

// PatternCovers reports whether a GRANTED pattern permits everything a REQUESTED
// pattern could match — "may a consumer granted `grant` subscribe to `want`".
//
// **TOKEN BY TOKEN, BECAUSE BOTH SIDES ARE PATTERNS (D261).** This replaced
// `gateway.coveredByGrant`, which ran `SubjectMatches(grant, want)` and so read
// the request's wildcards as literal tokens: a grant of `sekizui.raw.*` —
// exactly one token — was held to cover a request for `sekizui.raw.>`, one OR
// MORE. Until D260 the request's subjects were the whole filter, so that
// consumer received deeper subjects than it was granted. D260's scope bounds
// delivery by the grant's own pattern and contained it; this makes the answer
// right as well, and the boot check on a reflex's `consumes` reuses it.
//
// The rules, per position:
//   - a granted `>` covers whatever remains, provided at least one token does;
//   - a granted `*` covers a literal or a `*`, and never a `>`;
//   - a granted literal covers only the same literal.
func PatternCovers(grant, want string) bool {
	g, w := strings.Split(grant, "."), strings.Split(want, ".")
	for i, tok := range g {
		if tok == ">" {
			return len(w) > i
		}
		if i >= len(w) {
			return false
		}
		switch {
		case tok == "*":
			if w[i] == ">" {
				return false
			}
		case tok != w[i]:
			return false
		}
	}
	return len(g) == len(w)
}
