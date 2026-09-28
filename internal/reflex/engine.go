package reflex

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/predicate"
	"github.com/fullstorydev/sekizui/pkg/audit"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Enforcer is the enforcement path, as the engine needs it.
//
// Declared here rather than imported from internal/gateway so the dependency
// runs one way — the engine is a CALLER of enforcement, not a peer of it — and
// so this package can be tested without standing up a gRPC server.
type Enforcer interface {
	Enforce(ctx context.Context, id *sekizuiv1.Identity, cmd *sekizuiv1.Command) (*sekizuiv1.CommandResult, error)
}

// Engine dispatches envelopes to matching rules.
//
// SKELETON, AND THE SKELETON IS THE POINT (§12.0 principle 4). What exists is
// the DISPATCH PATH: given an envelope, find matching rules, and drive each one
// through the same enforcement path an agent uses. What is absent is everything
// that needs the bus — subscribing, delivery, debounce state, firing budgets —
// which arrives with P3 and P5.
//
// Building it now caught a structural gap that would otherwise have surfaced at
// P5 (D69): the enforcement path began with mTLS verification, which an
// in-process reflex cannot satisfy, so D18's "reflexes call the same internal
// path" was unimplementable. Nothing revealed that until something tried to be
// the second caller.
type Engine struct {
	rules    []config.ReflexSpec
	enforcer Enforcer
	recorder audit.Recorder
	signal   SignalFunc
	log      *slog.Logger
	newID    IDFunc
	validate ValidateFunc
	now      func() time.Time

	// THE BOUNDS' STATE (D264), and it is PER REPLICA: two replicas each allow
	// a rule its whole budget. Stated on the decision and in CONTRACTS rather
	// than implied; the fleet-wide bound is P7's coordination node.
	mu        sync.Mutex
	firings   map[string][]time.Time            // rule -> firings in the trailing hour
	exhausted map[string]bool                   // rule -> budget currently exhausted
	lastFired map[string]map[string][]time.Time // rule -> debounce key -> the windows it fired in

	// disabled are rules an anzen rule switched off (D332): rule -> the anzen
	// rule that did. IN MEMORY UNTIL REDEPLOYED, D146's asymmetry: configuration
	// is the authority on whether a rule is enabled, so a restart re-reads it —
	// and Disable says so loudly, so nobody mistakes the switch for an edit.
	disabled map[string]string

	// shared are the `reflex_budgets` rules may name (D334): budget -> its
	// max firings per hour. Their firings share `firings` under "budget:<name>".
	shared map[string]uint32
}

// Option configures an Engine beyond what every engine needs.
type Option func(*Engine)

// WithSharedBudgets gives the engine the document's `reflex_budgets` (D334).
// `main` and the acceptance harness both pass it, from the same document.
func WithSharedBudgets(budgets []config.ReflexBudgetSpec) Option {
	return func(e *Engine) {
		e.shared = map[string]uint32{}
		for _, b := range budgets {
			e.shared[b.Name] = b.MaxFiringsPerHour
		}
	}
}

// SignalFunc raises an anzen signal for subjects (rule name -> detail). In
// production it is the anzen dispatcher's Observe.
type SignalFunc func(ctx context.Context, signal string, subjects map[string]string)

// IDFunc generates envelope IDs for enriched output. Injected so tests are
// deterministic, and so it can become a ULID (§4.6.1d) without touching this.
type IDFunc func() string

// ValidateFunc checks a payload against its registered schema — in production
// the document's `schemareg.Registry.Validate`.
type ValidateFunc func(typ string, payload map[string]any) error

// SignalNonconforming is raised when an enrichment's output does not match the
// schema of the type it publishes (CONTRACTS 128).
const SignalNonconforming = "enrichment_nonconforming"

// NewEngine builds a dispatcher over the configured rules.
//
// THE RECORDER AND THE SIGNAL ARE REQUIRED PARAMETERS, not options (D264): an
// engine built without them would refuse a firing past its budget and record
// nothing and tell nobody — a bound whose exhaustion is invisible, which is the
// form of this project's recurring defect most likely to be written by
// omission. `NewRecorder`'s required identity is the precedent.
//
// **THE VALIDATOR IS REQUIRED FOR THE SAME REASON (CONTRACTS 128).** Boot checks
// that a rule's `publishes_type` has a schema and that what it carries exists
// in it; only the VALUES can break it, and only at runtime. "Validated at
// publish time" held for polled envelopes alone until the engine checked its
// own — the runner's precedent, `kyuushin.Options.Validate`.
func NewEngine(rules []config.ReflexSpec, enforcer Enforcer, recorder audit.Recorder,
	signal SignalFunc, log *slog.Logger, newID IDFunc, validate ValidateFunc, opts ...Option) *Engine {
	if validate == nil {
		// A nil validator is a programming error in the wiring, not a
		// configuration a deployment can choose; failing every enrichment says
		// so on the first one rather than publishing it unchecked.
		validate = func(typ string, _ map[string]any) error {
			return fault.New(fault.KindInternal, "reflex.NewEngine",
				"the engine was built without a payload validator, so "+typ+" cannot be checked before publish")
		}
	}
	e := &Engine{
		// PROJECTIONS ARE REMOVED HERE, NOT BY THE CALLER (D269): the engine is
		// the dispatching half, and a projection it never holds is one it can
		// never subscribe or try to fire.
		rules: OnlyDispatching(rules), enforcer: enforcer, recorder: recorder, signal: signal,
		log: log, newID: newID, validate: validate, now: time.Now,
		firings:   map[string][]time.Time{},
		exhausted: map[string]bool{},
		lastFired: map[string]map[string][]time.Time{},
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Outcome is what one rule did with one envelope.
type Outcome struct {
	Rule string

	// Result is set for a bus->driver rule that reached enforcement. Note that
	// a DENIED command still yields a Result — a denial is a decision, not an
	// error (§5.4).
	Result *sekizuiv1.CommandResult

	// Publish is set for a bus->bus rule: the envelope to put back on the bus.
	// The engine does NOT publish it — that is the bus's job, and the bus does
	// not exist until P3.
	Publish *sekizuiv1.Envelope

	// Err is set when the rule matched but could not be carried out — including
	// a firing refused because the rule's budget was exhausted (D264).
	Err error

	// Debounced is set when the rule matched and an earlier envelope with the
	// same debounce key already fired it inside the window (D264). Not an
	// error and not recorded: suppression is the rule working.
	Debounced bool
}

// Dispatch runs every rule against one envelope.
//
// CONTINUES AFTER A FAILING RULE rather than aborting. Rules are independent by
// construction (D31: one rule, one action), so one rule's failure says nothing
// about the next one's — and stopping would make a single broken rule silently
// disable every rule declared after it, with the ordering in a config file
// deciding which.
func (e *Engine) Dispatch(ctx context.Context, env *sekizuiv1.Envelope) []Outcome {
	var out []Outcome
	for _, rule := range e.rules {
		if o, matched := e.dispatchOne(ctx, rule, env); matched {
			out = append(out, o)
		}
	}
	return out
}

// dispatchOne runs ONE rule against one envelope — what both Dispatch and the
// live loop in Run call, so the two cannot drift (D155). False means the rule
// did not match and did nothing.
func (e *Engine) dispatchOne(ctx context.Context, rule config.ReflexSpec,
	env *sekizuiv1.Envelope) (Outcome, bool) {
	// A RULE AN ANZEN RULE SWITCHED OFF DOES NOTHING, and records nothing, as
	// though configuration had said `enabled: false` (D332).
	if e.isDisabled(rule.Name) {
		return Outcome{}, false
	}

	matched, err := Match(env, rule)
	if err != nil {
		// **A DEPTH-CAP REFUSAL IS A GOVERNANCE OUTCOME AND GOES ON THE RECORD
		// (P3 step 8).** It was logged and nothing else — a runaway loop that
		// Sekizui stopped left no row saying it had. Recorded as
		// VERDICT_BUDGET_EXCEEDED, whose own definition names "causation depth
		// cap tripped" (D23), through the same helper the firing budget uses.
		if fault.KindOf(err) == fault.KindBudgetExceeded {
			e.recordRefused(ctx, rule, env, rule.Name+"#max_depth", err.Error())
		}
		return Outcome{Rule: rule.Name, Err: err}, true
	}
	if !matched {
		return Outcome{}, false
	}

	// THE BOUNDS, IN THIS ORDER (D264): a debounced envelope never reaches the
	// budget, so suppression does not spend what the budget is for.
	if e.debounced(rule, env) {
		e.log.Debug("reflex debounced", "rule", rule.Name, "envelope", env.GetId())
		return Outcome{Rule: rule.Name, Debounced: true}, true
	}
	if err := e.spend(ctx, rule, env); err != nil {
		return Outcome{Rule: rule.Name, Err: err}, true
	}

	switch {
	case rule.PublishTo != "":
		enriched, err := Enrich(env, rule, e.newID())
		if err != nil {
			return Outcome{Rule: rule.Name, Err: err}, true
		}
		// **CHECKED BEFORE IT CAN BE PUBLISHED (CONTRACTS 128).** A failure is
		// this rule's: not published, logged, and signalled against the rule,
		// so a deployment learns its enrichment drifted from its schema rather
		// than a consumer learning it from a payload it cannot read.
		if verr := e.validate(enriched.GetType(), enriched.GetData().AsMap()); verr != nil {
			e.log.Warn("refusing to publish a nonconforming enrichment", "rule", rule.Name,
				"type", enriched.GetType(), "error", verr)
			e.signal(ctx, SignalNonconforming, map[string]string{rule.Name: verr.Error()})
			return Outcome{Rule: rule.Name, Err: fault.Wrap(fault.KindInvalidArgument, "reflex.Dispatch",
				fmt.Sprintf("rule %q produced a %s that does not match its schema, so it was not published",
					rule.Name, enriched.GetType()), verr)}, true
		}
		return Outcome{Rule: rule.Name, Publish: enriched}, true

	case rule.Action != "":
		result, err := e.fire(ctx, env, rule)
		return Outcome{Rule: rule.Name, Result: result, Err: err}, true

	default:
		// Config validation rejects this shape at boot (D31), so reaching
		// it means validation was bypassed.
		return Outcome{Rule: rule.Name, Err: fault.New(fault.KindConfig,
			"reflex.Dispatch", "rule has neither an action nor publish_to")}, true
	}
}

// Stream is a scoped bus subscription as the engine needs it.
//
// DECLARED HERE, WHERE IT IS CONSUMED (GO-PRIMER §15ag), and deliberately
// narrower than `pkg/bus.Subscription`: no `Events()` channel, because reading
// the raw channel is exactly how a consumer would skip the gateway's receipt
// assertion (D260). `gateway.ScopedSubscription` satisfies it.
type Stream interface {
	Next(ctx context.Context) (*sekizuiv1.Envelope, bool)
	Close()
}

// SubscribeFunc opens a Stream as a principal. In production it is
// `gateway.Server.SubscribeAs` — the one scoped path (D260) — and a rule never
// reaches the bus any other way.
type SubscribeFunc func(ctx context.Context, id *sekizuiv1.Identity, subjects []string) (Stream, error)

// PublishFunc puts an enriched envelope back on the bus.
type PublishFunc func(ctx context.Context, env *sekizuiv1.Envelope) error

// Run consumes the bus for every enabled rule until ctx ends (D172, D261).
//
// **ONE SUBSCRIPTION PER RULE, AS THE RULE'S PRINCIPAL.** Not one engine-wide
// subscription fanned out to rules: rules may act as different principals,
// and a single subscription would have to be authorised as SOMEBODY — either
// the union of every rule's grant (a principal that exists nowhere in
// configuration) or an unscoped reader, which D260 refuses in production. Per
// rule, each one sees exactly what its principal's subscribe grant admits, and
// the establishment record names that principal.
//
// ALL OR NOTHING AT START: if any rule cannot subscribe, the ones already
// opened are closed and the error returned, so a deployment does not come up
// with some rules silently not listening. Boot validation (D261) makes that
// unreachable through a validated document; this is the defence behind it.
//
// SHADOW IS STILL THE DEFAULT, and it is `BuildCommand`'s to decide, not
// Run's: a rule with no mode dispatches a dry run (D172, P3 step 22).
//
// SUBSCRIBES SYNCHRONOUSLY AND LOOPS IN THE BACKGROUND: the error is the
// subscription's, returned before any loop starts, so the caller can fail its
// own start on it; `wait` blocks until ctx ends and every loop has returned.
func (e *Engine) Run(ctx context.Context, subscribe SubscribeFunc, publish PublishFunc) (
	wait func(), err error) {

	type live struct {
		rule   config.ReflexSpec
		stream Stream
	}
	var opened []live
	for _, rule := range e.rules {
		if !rule.Enabled || rule.Consumes == "" {
			continue
		}
		stream, err := subscribe(ctx, IdentityFor(rule), []string{rule.Consumes})
		if err != nil {
			for _, l := range opened {
				l.stream.Close()
			}
			return nil, fault.Wrap(fault.KindConfig, "reflex.Run",
				fmt.Sprintf("rule %q could not subscribe as %q", rule.Name, rule.Principal), err)
		}
		opened = append(opened, live{rule: rule, stream: stream})
	}

	var wg sync.WaitGroup
	for _, l := range opened {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer l.stream.Close()
			for {
				env, ok := l.stream.Next(ctx)
				if !ok {
					return
				}
				e.handle(ctx, l.rule, env, publish)
			}
		}()
	}
	return wg.Wait, nil
}

// handle carries out one rule's outcome for one envelope. Nothing here is
// returned to anybody — there is no caller waiting — so everything that goes
// wrong is LOGGED, and a command's own outcome is already in the audit log
// because it went through Enforce.
func (e *Engine) handle(ctx context.Context, rule config.ReflexSpec,
	env *sekizuiv1.Envelope, publish PublishFunc) {

	o, matched := e.dispatchOne(ctx, rule, env)
	if !matched {
		return
	}
	if o.Err != nil {
		e.log.Warn("reflex rule could not be carried out",
			"rule", rule.Name, "envelope", env.GetId(), "err", o.Err)
		return
	}
	if o.Publish != nil {
		if err := publish(ctx, o.Publish); err != nil {
			e.log.Error("reflex could not publish its enriched envelope",
				"rule", rule.Name, "envelope", env.GetId(), "err", err)
		}
	}
}

// fire drives one bus->driver rule through the enforcement path.
func (e *Engine) fire(ctx context.Context, env *sekizuiv1.Envelope,
	rule config.ReflexSpec) (*sekizuiv1.CommandResult, error) {

	cmd, err := BuildCommand(env, rule)
	if err != nil {
		return nil, err
	}

	result, err := e.enforcer.Enforce(audit.WithReflexName(ctx, rule.Name), IdentityFor(rule), cmd)
	if err != nil {
		return nil, err
	}

	// A denial is a normal outcome worth noticing: a rule that is denied on
	// every event is misconfigured, and boot validation cannot see it because
	// grants can change after boot.
	if result.GetStatus() == sekizuiv1.Status_STATUS_DENIED {
		e.log.Warn("reflex denied by policy",
			"rule", rule.Name, "principal", rule.Principal,
			"action", rule.Action, "target", rule.TargetRef,
			"reason", result.GetReason())
	}
	return result, nil
}

// IdentityFor constructs the identity a reflex acts under.
//
// CALLER AND SUBJECT ARE BOTH THE RULE'S PRINCIPAL — a chain of ONE, exactly as
// a standalone agent produces (D6). A reflex does not act on behalf of whoever
// produced the event: it acts as itself, under its own grant, which is what
// makes the grant the blast radius (§4.11.7) and why an anzen rule watching it
// is the mitigation rather than an intersection.
//
// The assertion is ASSERTED, not SIGNED. Nothing cryptographic happened; the
// claim is trusted because the process making it IS Sekizui. Recording SIGNED
// would put a false provenance statement in the audit trail (D57).
func IdentityFor(rule config.ReflexSpec) *sekizuiv1.Identity {
	return &sekizuiv1.Identity{
		Caller: &sekizuiv1.Caller{
			Principal: rule.Principal,
			// AUTH_METHOD_INTERNAL, not UNSPECIFIED. Both mean "no certificate
			// was verified", but UNSPECIFIED is the zero value meaning "nobody
			// set this" — so an audit row could not distinguish a deliberate
			// in-process action from a field somebody forgot to populate. Those
			// are different facts and a reviewer needs both.
			Method:       sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL,
			CredentialId: "reflex:" + rule.Name,
		},
		Subject: &sekizuiv1.Subject{
			Principal: rule.Principal,
			Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED,
		},
		Chain: []string{rule.Principal},
	}
}

// maxDebounceAnchors bounds the windows remembered per debounce key (D333).
const maxDebounceAnchors = 64

// debounced reports whether an earlier envelope with this one's debounce key
// fired the rule inside the window, and records this firing otherwise.
//
// AN ABSENT KEY IS NOT DEBOUNCED. Boot checks the path exists in the schema;
// an envelope that leaves an optional key out would otherwise share one bucket
// with every other such envelope and be suppressed as their duplicate.
func (e *Engine) debounced(rule config.ReflexSpec, env *sekizuiv1.Envelope) bool {
	if rule.DebounceKey == "" {
		return false
	}
	v, ok := predicate.Lookup(env.GetData().AsMap(), rule.DebounceKey)
	if !ok {
		return false
	}
	key := fmt.Sprint(v)
	window := time.Duration(rule.DebounceWindowSec) * time.Second

	// **ON THE EVENT'S OWN TIME, NOT THE CLOCK THAT PROCESSED IT (D333, the maintainer).**
	// A window on processing time made a debounced rule depend on how fast its
	// input arrived: a two-hour recording replayed in a second collapsed into one
	// window, so shadow over a replay did not predict enforce (D298's premise),
	// and live, the poller's 30-second batches decided what was a burst. The
	// FIRING BUDGET stays on the wall clock (spend): it bounds real actions per
	// real hour, so a forged vendor timestamp can evade de-duplication and never
	// the budget. No event time: the observed time, then now.
	at := e.now()
	if t := env.GetObservedTime(); t.IsValid() && !t.AsTime().IsZero() {
		at = t.AsTime()
	}
	if t := env.GetTime(); t.IsValid() && !t.AsTime().IsZero() {
		at = t.AsTime()
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	// EVERY WINDOW THE KEY HAS FIRED IN, NOT ONLY THE LATEST, and distance either
	// way: a late-delivered older burst belongs to the window it happened in. The
	// first version kept one anchor per key, so an old burst re-delivered after a
	// newer one fired a ticket per event — P5 step 6c caught it (D333). Bounded
	// to the most recent maxDebounceAnchors windows per key.
	anchors := e.lastFired[rule.Name][key]
	for _, fired := range anchors {
		if d := at.Sub(fired); d < window && d > -window {
			return true
		}
	}
	if e.lastFired[rule.Name] == nil {
		e.lastFired[rule.Name] = map[string][]time.Time{}
	}
	anchors = append(anchors, at)
	if len(anchors) > maxDebounceAnchors {
		anchors = anchors[len(anchors)-maxDebounceAnchors:]
	}
	e.lastFired[rule.Name][key] = anchors
	return false
}

// spend charges one firing against the rule's hourly budget, or refuses it.
//
// **A REFUSED FIRING IS RECORDED, NEVER SILENTLY SKIPPED** — VERDICT_BUDGET_
// EXCEEDED exists for exactly this, "audited even for bus->bus reflexes …
// because a tripped guard is a governance event" (D23). And the SIGNAL is
// raised on the TRANSITION into exhaustion, not on every refusal: a rule
// matching a thousand rows past its budget is one event for anzen, not a
// thousand.
func (e *Engine) spend(ctx context.Context, rule config.ReflexSpec, env *sekizuiv1.Envelope) error {
	// THE RULE'S OWN BUDGET (D264), AND THE SHARED ONE IT NAMES (D334). A
	// firing needs room in BOTH, and takes from both only when both have it —
	// checking one, spending it, and then being refused by the other would
	// charge a firing that never happened.
	type bucket struct {
		key, subject, matched, reason string
		limit                         uint32
	}
	var buckets []bucket
	if rule.MaxFiringsPerHour > 0 {
		buckets = append(buckets, bucket{key: rule.Name, subject: rule.Name,
			matched: rule.Name + "#max_firings_per_hour", limit: rule.MaxFiringsPerHour,
			reason: fmt.Sprintf("rule %q has fired %d time(s) in the trailing hour, its "+
				"max_firings_per_hour; this firing was refused. Per replica (D264)",
				rule.Name, rule.MaxFiringsPerHour)})
	}
	// A RULE NAMING A BUDGET THIS ENGINE WAS NOT GIVEN FIRES NOTHING (D334).
	// Boot checks the document; this is the wiring — an engine built without
	// WithSharedBudgets would otherwise run every such rule unbounded by the
	// budget its author wrote, which is the fail-open direction.
	if _, ok := e.shared[rule.Budget]; rule.Budget != "" && !ok {
		reason := fmt.Sprintf("rule %q spends budget %q, which this engine was not given; refused "+
			"rather than fired unbounded (D334)", rule.Name, rule.Budget)
		e.recordRefused(ctx, rule, env, "reflex_budgets:"+rule.Budget, reason)
		return fault.New(fault.KindInternal, "reflex.spend", reason)
	}
	if limit, ok := e.shared[rule.Budget]; ok && rule.Budget != "" {
		buckets = append(buckets, bucket{key: "budget:" + rule.Budget, subject: rule.Budget,
			matched: "reflex_budgets:" + rule.Budget, limit: limit,
			reason: fmt.Sprintf("the rules sharing budget %q have fired %d time(s) in the trailing hour, "+
				"its max_firings_per_hour; this firing of %q was refused. Per replica (D264, D334)",
				rule.Budget, limit, rule.Name)})
	}
	if len(buckets) == 0 {
		return nil
	}
	e.mu.Lock()
	now := e.now()
	var full *bucket
	for i := range buckets {
		b := &buckets[i]
		kept := e.firings[b.key][:0]
		for _, at := range e.firings[b.key] {
			if now.Sub(at) < time.Hour {
				kept = append(kept, at)
			}
		}
		e.firings[b.key] = kept
		if full == nil && uint32(len(kept)) >= b.limit {
			full = b
		}
	}
	if full == nil {
		for _, b := range buckets {
			e.firings[b.key] = append(e.firings[b.key], now)
			e.exhausted[b.key] = false
		}
		e.mu.Unlock()
		return nil
	}
	transition := !e.exhausted[full.key]
	e.exhausted[full.key] = true
	e.mu.Unlock()

	e.recordRefused(ctx, rule, env, full.matched, full.reason)
	if transition {
		e.signal(ctx, "budget_exceeded", map[string]string{full.subject: full.reason})
	}
	return fault.New(fault.KindBudgetExceeded, "reflex.spend", full.reason)
}

// causationFrom is the causation a firing of rule on env carries — the same
// one BuildCommand stamps on the command, so a refused firing and an allowed
// one name their origin identically.
func causationFrom(env *sekizuiv1.Envelope, rule config.ReflexSpec) *sekizuiv1.Causation {
	c := &sekizuiv1.Causation{
		RootId:     env.GetCausation().GetRootId(),
		ParentId:   env.GetId(),
		Depth:      env.GetCausation().GetDepth() + 1,
		ProducedBy: "reflex:" + rule.Name,
		// THE DECISION THAT PRODUCED THE TRIGGERING ENVELOPE, carried forward
		// (D272) — so a command a reflex fires on a polled row is joinable in
		// the log to the poll that fetched it: poll decision, envelope, command.
		DecisionId: env.GetCausation().GetDecisionId(),
	}
	if c.RootId == "" {
		c.RootId = env.GetId()
	}
	return c
}

// recordRefused writes the record for a firing a BOUND refused — the hourly
// budget (D264) or the causation depth cap (P3 step 8). One helper, so the two
// refusals name their rule, their causation and their verdict identically, and
// neither is ever a log line alone.
func (e *Engine) recordRefused(ctx context.Context, rule config.ReflexSpec,
	env *sekizuiv1.Envelope, matched, reason string) {

	action, target := rule.Action, rule.TargetRef
	if rule.PublishTo != "" {
		action, target = "sekizui.reflex.publish", rule.PublishTo
	}
	if _, err := e.recorder.Terminal(audit.WithReflexName(ctx, rule.Name), &sekizuiv1.Decision{
		Identity:    IdentityFor(rule),
		Action:      action,
		TargetRef:   target,
		Verdict:     sekizuiv1.Verdict_VERDICT_BUDGET_EXCEEDED,
		MatchedRule: matched,
		Reason:      reason,
		Causation:   causationFrom(env, rule),
		ReflexName:  rule.Name,
	}); err != nil {
		e.log.Error("could not record a refused reflex firing", "rule", rule.Name, "err", err)
	}
}

// Disable switches a running rule off, as though configuration had said
// `enabled: false` (D332) — the `disable_reflex` anzen action, reached through
// the gateway. by names the anzen rule that decided it. A second Disable of the
// same rule reports already=true and changes nothing; an unknown rule is an
// error naming the rules there are.
//
// UNTIL REDEPLOYED (D146's asymmetry), and logged as such: configuration is the
// authority on whether a rule is enabled, so the switch lives in memory and a
// restart re-reads the document. A budget-tripped rule stays bounded by its
// firing budget across that restart; this switch is the response, not the bound.
func (e *Engine) Disable(name, by string) (already bool, err error) {
	known := false
	for _, r := range e.rules {
		known = known || r.Name == name
	}
	if !known {
		names := make([]string, 0, len(e.rules))
		for _, r := range e.rules {
			names = append(names, r.Name)
		}
		return false, fault.New(fault.KindNotFound, "reflex.Disable",
			fmt.Sprintf("no reflex rule %q is running here; the rules are %v", name, names))
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.disabled == nil {
		e.disabled = map[string]string{}
	}
	if _, was := e.disabled[name]; was {
		return true, nil
	}
	e.disabled[name] = by
	e.log.Warn("reflex rule DISABLED by an anzen rule, until config is redeployed",
		"rule", name, "by", by,
		"note", "configuration still says enabled; edit it to make this permanent, or a restart re-enables the rule")
	return false, nil
}

func (e *Engine) isDisabled(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, off := e.disabled[name]
	return off
}
