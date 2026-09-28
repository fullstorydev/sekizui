// Package catalog answers "what can I do?" — §4.9's capability catalog.
//
// PRIVATE (D35). This is the part of MCP that survives (D3): Sekizui does not
// serve MCP, but the requirement it served is real — something must tell a
// caller what it may do.
//
// DERIVED BY ASKING THE ENFORCER, NOT BY READING GRANTS IN PARALLEL. §4.9
// property 1 requires the catalog to come from "the same grant data the enforcer
// reads", because "a separate static list drifts, and then agents are told about
// tools that deny — burning turns and confusing the model".
//
// The strongest form of that is not "read the same data" but "ask the same
// component": for each candidate capability, the catalog puts the question to
// policy.Engine exactly as the enforcement path would. Drift then is not
// unlikely, it is impossible — the two cannot disagree because there is only one
// answerer. It costs one policy evaluation per capability on a call an agent
// makes rarely.
//
// DESIGN.md references: §4.9, §4.4.1, D3, D7, D40, D59.
package catalog

import (
	"context"
	"fmt"
	"github.com/fullstorydev/sekizui/internal/refine"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/actionset"
	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/internal/identity"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Catalog builds per-principal capability descriptions.
type Catalog struct {
	grants map[string]config.GrantSpec

	// native is the declared relation of each MCP tool on a linked target
	// (D323) — the SAME reading the grant engine enforces, reported so grant
	// review sees the doors onto one upstream together.
	native  map[string]map[string][]string
	schemas map[string]string // payload type -> schema URI

	// refinements are the imposed `refines:` rules, the SAME compiled list the
	// gateway serves (D302) — handed to both by whoever wires them.
	refinements []schemareg.Refinement

	// actions is what this deployment serves and what each granted pattern
	// covers within it. SHARED WITH BOOT VALIDATION (D195) rather than rebuilt:
	// `grantcheck` refuses a pattern covering nothing, and if the two computed
	// coverage differently the disagreement would be silent — a grant accepted at
	// boot and advertised nowhere reads as a permission in force.
	actions *actionset.Set

	// residency is target ref -> declared class, for the guard's second scoping
	// axis (D137).
	residency map[string]string

	policy policy.Engine
	guards *anzen.Guards
	lenses *shin.Lenses

	// identity answers "may this caller act for that principal", and it is the
	// SAME Verifier the enforcement path uses (D18's no-second-path applied to
	// a predicate rather than a code path).
	//
	// The catalog used to answer it with a copy of its own, which differed:
	// the Verifier permits `caller == subject` outright and the copy did not,
	// so the two agreed only because the ONE call site checks `target !=
	// subject` before asking. A duplicated authorisation check whose divergence
	// is contained by the ordering at its only caller is one refactor away from
	// being a defect, and the type-resolved orphan guard is what surfaced it —
	// `Verifier.MaySpeakFor` had no caller at all, while its doc comment named
	// this file as one.
	identity *identity.Verifier

	// drift is the last known divergence per target, written by the drift
	// watcher and read here to WITHHOLD an action a vendor no longer offers
	// (D197). Nil is legitimate — see Config.Drift.
	drift *drift.Store

	types []string // registered payload types, sorted
}

// New builds a catalog over a validated document and the registered drivers.
//
// TAKES BOTH HALVES OF THE ENFORCEMENT PATH. Asking policy alone is not enough,
// and that was a real defect here rather than a hypothetical: anzen is checked
// BEFORE policy (D71), so a guard can forbid an action that a grant permits. A
// catalog consulting only policy advertised a destructive action that every call
// would refuse — sending agents at a wall, which is precisely the failure §4.9
// property 1 exists to prevent.
//
// The unit tests missed it because none configured a guard. The acceptance run
// caught it, because it uses the real document where step 4 refuses exactly that
// action.
// Config carries the catalog's collaborators.
//
// A STRUCT RATHER THAN A PARAMETER LIST, and the change was forced by adding
// one field. `New` had five positional parameters, three of them
// interface-or-nil, and the Verifier made six — so the shortest call site read
// `New(doc, drivers, eng, guards, nil, nil)`, two nils of different types whose
// meaning depends entirely on getting the order right. `gateway.New` already
// takes a `gateway.Config` for exactly this set of reasons and is the
// precedent.
//
// **AND THE NEXT FIELD IS ALREADY SCHEDULED.** P2 steps 9 and 12 give the
// catalog the per-target MCP drift state, so it can withhold a tool the server
// no longer offers (D197) — a seventh parameter on a list that already had two
// trailing nils. Widening a positional list one collaborator at a time is how a
// constructor becomes uncallable without counting commas.
type Config struct {
	// Doc is the validated document. Required.
	Doc *config.Document

	// Drivers are the registered drivers, for deriving what this deployment
	// actually serves (D195).
	Drivers map[string]connector.Driver

	// Policy is the grant engine. Required — see New's note on needing BOTH
	// halves of the enforcement path.
	Policy policy.Engine

	// Guards is the anzen rule set. Nil means no guards.
	Guards *anzen.Guards

	// Lenses is the shin lens set. Nil means no lenses.
	Lenses *shin.Lenses

	// Drift is the per-target spec-drift state. Nil means nothing is withheld,
	// which is the right default for a deployment with no MCP targets and for
	// every test that does not care.
	Drift *drift.Store

	// Identity answers may-speak-for. Nil builds one from Doc, which is safe
	// because a Verifier is a pure function of `doc.Grants` and so cannot
	// answer differently from the one the gateway holds — unlike Policy, where
	// a default would be a second engine with its own residency view.
	// `cmd/sekizui` passes its own instance, so a process has ONE.
	Identity *identity.Verifier

	// Refinements are the imposed `refines:` rules, compiled once by
	// schemareg.Refinements and handed to the gateway too, so Describe reports
	// exactly the seiren a principal receives (D302). Nil when none.
	Refinements []schemareg.Refinement
}

func New(cfg Config) *Catalog {
	doc, drivers, eng := cfg.Doc, cfg.Drivers, cfg.Policy

	guards := cfg.Guards
	if guards == nil {
		guards = anzen.New(nil)
	}
	lenses := cfg.Lenses
	if lenses == nil {
		lenses = shin.New(nil)
	}
	verifier := cfg.Identity
	if verifier == nil {
		verifier = identity.NewVerifier(doc)
	}
	c := &Catalog{
		grants:    make(map[string]config.GrantSpec, len(doc.Grants)),
		actions:   actionset.New(doc, drivers),
		schemas:   map[string]string{},
		native:    doc.NativeRelations(),
		residency: make(map[string]string, len(doc.Targets)),
		policy:    eng,
		guards:    guards,
		lenses:    lenses,
		identity:  verifier,
		drift:     cfg.Drift,

		refinements: cfg.Refinements,
	}
	// A guard may be scoped to a target's residency class (D137), so the catalog
	// needs the class to ask the same question the enforcement path asks.
	// Reading it from the same Document keeps the two from disagreeing.
	for _, t := range doc.Targets {
		c.residency[t.Ref] = t.Residency
	}
	for _, g := range doc.Grants {
		c.grants[g.Principal] = g
	}
	for typ := range doc.PayloadSchemas {
		// D40: a consumer can fetch the shape of what it will receive rather
		// than inferring it from examples.
		c.schemas[typ] = "sekizui://schema/" + typ
		c.types = append(c.types, typ)
	}
	sort.Strings(c.types)
	return c
}

// Describe returns what the named principal may do, as seen by this caller.
//
// An empty `principal` means the request's own effective identity — the common
// case, an agent asking what it can do.
func (c *Catalog) Describe(ctx context.Context, id *sekizuiv1.Identity,
	principal string) (*sekizuiv1.DescribeResponse, error) {

	const op = "catalog.Describe"

	subject := id.GetSubject().GetPrincipal()
	if subject == "" {
		return nil, fault.New(fault.KindInternal, op, "describe requested with no identity")
	}

	target := principal
	if target == "" {
		target = subject
	}

	// DESCRIBING SOMEONE ELSE NEEDS THE SAME PERMISSION AS ACTING AS THEM.
	//
	// The proto says "naming another principal requires a grant to do so;
	// otherwise an agent could enumerate the whole fleet's permissions". The
	// natural grant already exists: may_speak_for. If a caller may act as a
	// principal it may see what that principal can do, and if it may not, a
	// capability listing is a reconnaissance tool — the map of what to try after
	// compromising something else.
	if target != subject && !c.identity.MaySpeakFor(subject, target) {
		return nil, fault.New(fault.KindUnauthenticated, op, fmt.Sprintf(
			"%q may not describe %q; describing a principal requires the same "+
				"may_speak_for grant as acting as it, because a capability listing is a "+
				"map of what to try next (§4.4.1)", subject, target))
	}

	caps, withheld, err := c.capabilitiesFor(ctx, id, target)
	if err != nil {
		return nil, err
	}

	available, imposed := c.lensesFor(target)

	return &sekizuiv1.DescribeResponse{
		Principal:       target,
		Capabilities:    caps,
		MaySpeakFor:     append([]string(nil), c.grants[target].MaySpeakFor...),
		PayloadSchemas:  c.schemas,
		AvailableLenses: available,
		ImposedLenses:   imposed,
		Withheld:        withheld,

		ImposedRefinements: c.refinementsFor(target),
	}, nil
}

// refinementsFor is every refinement imposed on principal (D302), in
// configuration order — reported, not hidden, as imposed lenses are.
func (c *Catalog) refinementsFor(principal string) []*sekizuiv1.ImposedRefinement {
	var out []*sekizuiv1.ImposedRefinement
	for _, r := range c.refinements {
		if !refine.AudienceCovers(r.For, principal) {
			continue
		}
		out = append(out, &sekizuiv1.ImposedRefinement{
			Rule: r.Rule.Name, TargetRef: r.Target, SeirenType: r.Rule.Into,
			SchemaUri: "sekizui://schema/" + r.Rule.Into, Key: r.Rule.Key,
			Lookups: false, // P4 derives only (D317); P5's lookups will set it
		})
	}
	return out
}

// capabilitiesFor asks the enforcer about each candidate.
func (c *Catalog) capabilitiesFor(ctx context.Context, id *sekizuiv1.Identity,
	target string) ([]*sekizuiv1.Capability, []*sekizuiv1.WithheldCapability, error) {

	grant, ok := c.grants[target]
	if !ok {
		// Not an error: a principal with no grant can do nothing, and an empty
		// catalog is the accurate answer. Erroring would leak whether a
		// principal exists at all.
		return nil, nil, nil
	}

	// Describing SELF asks about the request's own identity, so the caller ∩
	// subject intersection applies (D59) — a mesh with narrower grants than the
	// agent it speaks for sees the narrower set, which is exactly what it can
	// actually do.
	//
	// Describing ANOTHER principal asks about that principal standing alone.
	probe := id
	if target != id.GetSubject().GetPrincipal() {
		probe = &sekizuiv1.Identity{
			Caller:  &sekizuiv1.Caller{Principal: target},
			Subject: &sekizuiv1.Subject{Principal: target},
			Chain:   []string{target},
		}
	}

	var (
		out      []*sekizuiv1.Capability
		withheld []*sekizuiv1.WithheldCapability
	)
	for _, spec := range append(append([]config.CapabilitySpec(nil), grant.Allow...), grant.Escalate...) {
		// **THE PATTERN IS RESOLVED INTO THE CONCRETE ACTIONS IT COVERS (D195).**
		// A grant may name `mcp.github.*`, and advertising that string tells a
		// model to guess at the boundary — the exact discovery-by-refusal §4.9
		// property 2 exists to prevent. It also cannot be asked of policy
		// honestly: authorising the pattern compares it with itself, which is a
		// guard whose two inputs share an origin (D159).
		//
		// A pattern covering nothing yields nothing here, and boot has already
		// refused that document (`grantcheck`), so this loop cannot silently drop
		// a capability in a running deployment.
		for _, action := range c.actions.Covers(spec) {
			if err := c.appendCapability(ctx, probe, target, action, spec,
				&out, &withheld); err != nil {
				return nil, nil, err
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].TargetRef < out[j].TargetRef
	})
	// SORTED FOR THE SAME REASON THE CAPABILITIES ARE: the audit row derived
	// from this lists the rules that withheld something, and D149 excluded
	// nothing from the config identity precisely so that two runs over one
	// document produce the same bytes. A map-ordered list of guard names would
	// make an otherwise identical disclosure record look different every time.
	sort.Slice(withheld, func(i, j int) bool {
		if withheld[i].Action != withheld[j].Action {
			return withheld[i].Action < withheld[j].Action
		}
		return withheld[i].TargetRef < withheld[j].TargetRef
	})
	return out, withheld, nil
}

// appendCapability asks the enforcement path about ONE concrete action and
// appends it if the answer is yes.
func (c *Catalog) appendCapability(ctx context.Context, probe *sekizuiv1.Identity,
	principal, action string, spec config.CapabilitySpec,
	out *[]*sekizuiv1.Capability, withheld *[]*sekizuiv1.WithheldCapability) error {

	{
		// THE CEILING FIRST, in the same order the enforcement path uses (D71).
		// A forbidden action is never advertised however broad the grant is,
		// because every call would be refused before policy was consulted.
		//
		// Forbids, not Check: Check would acquire an in-flight slot per cap rule,
		// so enumerating capabilities would consume the budget for the work about
		// to be done. Concurrency caps are also deliberately NOT consulted — an
		// action at its ceiling is still a capability, and a catalog that
		// flickered with load would be worse than one that ignores load.
		// BOTH SCOPING AXES, or the catalog and the enforcer disagree (D137). A
		// guard scoped to a residency class governs only targets in it, and a
		// catalog that ignored the second axis would hide a capability every
		// call would in fact allow — the §4.9 property 1 failure in its less
		// obvious direction.
		if guard, forbidden := c.guards.Forbids(principal, action,
			c.residency[spec.TargetRef]); forbidden {
			// **THE NAME IS KEPT NOW (D166, CONTRACTS 64).** This read
			// `if _, forbidden := ...` and dropped the one piece of information
			// that makes the absence answerable. A capability that is simply
			// missing is indistinguishable from one never granted, and the
			// consumer cannot tell which without reading configuration somebody
			// else wrote — so the catalog silently produced the mystery
			// `imposed_lenses` exists to prevent for shin.
			*withheld = append(*withheld, &sekizuiv1.WithheldCapability{
				Action: action, TargetRef: spec.TargetRef, Guard: guard,
			})
			return nil
		}

		dec, err := c.policy.Authorise(ctx, policy.Request{
			Identity: probe, Action: action, TargetRef: spec.TargetRef,
			// Constraints are satisfied by construction here: the question is
			// "may this principal ever do this", not "may it do this with these
			// arguments". A capability constrained to project PROJ is still a
			// capability, and the constraint is described rather than tested.
			Args: satisfyingArgs(spec.Where),
		})
		if err != nil {
			return err
		}
		// THE POINT OF ASKING: a grant the enforcer would refuse never appears.
		// An agent told about a tool that denies burns a turn discovering it.
		if dec.Verdict == sekizuiv1.Verdict_VERDICT_DENY {
			return nil
		}

		// **NOTHING HERE IS SYNTHESISED (D196).** A description comes from the
		// driver that implements the action or from the governed verb's own
		// entry; there is no third source, and the identifier is not one.
		// `grantcheck` refuses a document naming an action nothing implements and
		// `connector.ValidateActions` refuses an action with no description, so
		// the branch below is unreachable from a booted deployment — KEPT because
		// a Catalog can be built from a hand-made Document, which every test
		// does, and because an absent description reaching a model as its own
		// action name is precisely what D196 forbids.
		described, ok := c.actions.Describe(action)
		if !ok {
			return fault.New(fault.KindInternal, "catalog.capabilitiesFor", fmt.Sprintf(
				"action %q is granted to %q and nothing describes it: no registered driver "+
					"implements it and it is not a governed verb. Boot refuses this document "+
					"(D195); reaching here means the catalog was built without the "+
					"validation that precedes it", action, principal))
		}

		// **WITHHELD: THE VENDOR NO LONGER OFFERS IT (D197).**
		//
		// LAST, AFTER EVERY ENFORCEMENT-ORDER CHECK ABOVE, and the order is the
		// decision rather than an accident. §4.9 property 1 requires the catalog
		// and the enforcer to agree, so an action anzen forbids must be absent
		// for THAT reason — checking drift first would explain a forbidden
		// action as a withdrawn one, and the two have different remedies. The
		// undescribed-action error above runs first for the same reason: a
		// deployment built without its validation is a defect to surface, not
		// something to hide behind a withholding.
		//
		// **THE AGENT SEES ABSENCE; THE OPERATOR SEES THE FINDING NAMED.** A
		// capability list is not an explanation surface — there is no field on
		// `Capability` for "and here is one you cannot have" — and inventing one
		// would advertise the shape of what was withdrawn. So D197's "named
		// rather than silently absent" is discharged where a human is looking:
		// `/readyz` reports the target degraded, `/debugz/targets` names the
		// finding, and the `spec_drift` signal reaches anzen. The audit RECORD
		// naming it is D166's, which is P2 step 22.
		//
		// **NOT ALSO A CALL-TIME REFUSAL, deliberately.** D197 withholds from
		// the catalog and degrades the target; it does not refuse the call. This
		// state is up to one poll interval old, and refusing on it would deny a
		// tool the vendor may have restored — the availability half of the
		// same trade D152 makes about a cache window. A call to a withdrawn tool
		// reaches the vendor and fails honestly, which is the fail-closed
		// outcome anyway: the tool is gone, so nothing unreviewed can run.
		if c.drift != nil && c.drift.Withholds(spec.TargetRef, action) {
			return nil
		}

		where := constraints(spec.Where)
		*out = append(*out, &sekizuiv1.Capability{
			Action:    action,
			TargetRef: spec.TargetRef,
			Where:     where,
			// Rendered FROM `where`, not from spec.Where, so the prose an LLM
			// reads and the structured field a program reads cannot disagree.
			// Two renderings of the same source is how "only project PROJ" ends
			// up next to in: ["PLAT"].
			Description: renderDescription(described, spec, where),
			Disposition: disposition(dec.Verdict),
			Native:      c.native[spec.TargetRef][action],
			Limits: &sekizuiv1.Limits{
				RatePerHour: spec.RatePerHr,
				MaxBytes:    spec.MaxBytes,
				// MaxResults has no CapabilitySpec field to draw from — §4.7's
				// documented grant format does not carry one. Left zero, which
				// the proto reads as unset rather than "zero results allowed".
				// Tracked in CONTRACTS rather than filled with a guess.
			},
		})
	}
	return nil
}

// **`described` IS THE DRIVER'S OR THE VERB'S OWN SENTENCE, and there is no
// fallback (D196).** This function used to take the CapabilitySpec and reach for
// `spec.Action` when nothing described the action — rendering
// "mcp.github.exfiltrate on github-mcp." into the field a model reads to decide
// what to attempt. The maintainer's objection is the right one and it is the house rule
// stated elsewhere as absence-is-not-an-assertion (D119's nil posture, D75's
// cannot-confirm): a restatement of an identifier is not a description, and
// dressing one as the other misleads the only consumer it has.
func renderDescription(described string, spec config.CapabilitySpec,
	where map[string]*sekizuiv1.Constraint) string {

	var b strings.Builder

	// THE TARGET ATTACHES TO THE FIRST SENTENCE, not to the whole description.
	// A driver's ActionSpec often reads "Create an issue. Returns a synthetic
	// reference." — appending "on kata:alpha" to all of that produces "Returns a
	// synthetic reference on kata:alpha", which says something false. Splitting
	// keeps the target bound to the verb it belongs to.
	lead, rest := splitFirstSentence(described)

	// A GOVERNED VERB MAY NAME A PRINCIPAL OR A RULE RATHER THAN A TARGET
	// (D134, D146), and "Suspend a principal's grants on principal:agent:crawler"
	// reads as a target it is not. `for` carries both readings.
	preposition := "on"
	if strings.HasPrefix(spec.TargetRef, "principal:") ||
		strings.HasPrefix(spec.TargetRef, "anzen:") {
		preposition = "for"
	}
	fmt.Fprintf(&b, "%s %s %s.", lead, preposition, spec.TargetRef)
	if rest != "" {
		fmt.Fprintf(&b, " %s", rest)
	}

	fields := make([]string, 0, len(where))
	for f := range where {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, field := range fields {
		fmt.Fprintf(&b, " Only %s %s is permitted.", field,
			strings.Join(where[field].GetIn(), " or "))
	}
	if spec.RatePerHr > 0 {
		fmt.Fprintf(&b, " At most %d per hour.", spec.RatePerHr)
	}
	return b.String()
}

// splitFirstSentence returns the first sentence without its full stop, and
// whatever follows it.
//
// Splits on ". " rather than "." so "e.g." and "v1.2" stay intact — a naive
// split would cut "Query the v1.2 API" into nonsense.
func splitFirstSentence(s string) (lead, rest string) {
	s = strings.TrimSpace(s)
	if head, tail, found := strings.Cut(s, ". "); found {
		return head, strings.TrimSpace(tail)
	}
	return strings.TrimSuffix(s, "."), ""
}

// constraints converts config's two `where` forms into the wire message.
//
// Both become `in`. Constraint has no equality field, and a scalar constraint IS
// membership of a one-element set — policy.valueSatisfies treats them
// identically, so representing them identically keeps the catalog from implying
// a distinction the enforcer does not make.
//
// The richer forms (not_in, matches, gte/lte) exist on the wire message but have
// no config syntax yet: §4.7's grant format only spells `in` and equality. They
// stay unset rather than being synthesised, so a consumer reading the catalog
// sees exactly the constraint vocabulary P0 can actually enforce.
// constraints renders `where:` for the catalog — the structured field a program
// reads and the prose an LLM reads.
//
// A RESERVED FACET IS NOT AN ARGUMENT AND MUST NOT BE ADVERTISED AS ONE (D136).
// `target_residency` is answered from the target's configuration; a caller can
// neither send it nor influence it. Rendering it here would describe a
// constraint the agent must satisfy, and the predictable result is an LLM
// dutifully putting `target_residency: "us"` in its arguments — where it is
// ignored, because whereMatches skips reserved keys. A catalog that asks for
// something unsendable is worse than one that stays quiet: the caller cannot
// tell its request was fine and its permission was not.
//
// Nothing is lost by omitting it. A capability names exactly one target, and
// that target has exactly one residency, so the constraint tells a caller
// nothing it could act on.
func constraints(where map[string]any) map[string]*sekizuiv1.Constraint {
	if len(where) == 0 {
		return nil
	}
	out := make(map[string]*sekizuiv1.Constraint, len(where))
	for field, want := range where {
		if config.IsReservedWhereKey(field) {
			continue
		}
		var in []string
		if list, ok := want.([]any); ok {
			for _, item := range list {
				in = append(in, fmt.Sprint(item))
			}
			sort.Strings(in)
		} else {
			in = []string{fmt.Sprint(want)}
		}
		out[field] = &sekizuiv1.Constraint{In: in}
	}
	return out
}

// satisfyingArgs builds arguments that meet every constraint, so the probe asks
// "is this action reachable at all" rather than "does an empty request pass".
func satisfyingArgs(where map[string]any) map[string]any {
	if len(where) == 0 {
		return nil
	}
	args := make(map[string]any, len(where))
	for field, want := range where {
		// A reserved facet is answered from configuration, not from arguments
		// (D136). Synthesising one would be inert — the engine ignores it — and
		// would suggest to the next reader that a caller could supply it.
		if config.IsReservedWhereKey(field) {
			continue
		}
		if list, ok := want.([]any); ok && len(list) > 0 {
			args[field] = list[0]
			continue
		}
		args[field] = want
	}
	return args
}

func disposition(v sekizuiv1.Verdict) sekizuiv1.Disposition {
	if v == sekizuiv1.Verdict_VERDICT_ESCALATE {
		return sekizuiv1.Disposition_DISPOSITION_ESCALATE
	}
	return sekizuiv1.Disposition_DISPOSITION_ALLOW
}

// lensesFor reports the shin lenses a principal may select and the ceiling it
// cannot decline (D84).
//
// ASKED, NOT READ — the same rule the capabilities above follow (D79). The
// catalog puts the question to the lens engine exactly as the delivery path
// would, so a lens reported here is a lens that will actually apply.
//
// ACROSS EVERY REGISTERED TYPE, plus the type-less lenses. A consumer asking
// "what will I receive" needs the answer for every payload it might see, not
// only for one it happened to name.
func (c *Catalog) lensesFor(principal string) (available, imposed []*sekizuiv1.LensInfo) {
	seenAvail := map[string]bool{}
	seenImposed := map[string]bool{}

	// The empty type covers lenses that apply to every payload — the jurisdiction
	// case, and the only kind P0 applies to Query rows.
	for _, typ := range append([]string{""}, c.types...) {
		for _, lens := range c.lenses.Available(principal, typ, "") {
			if !seenAvail[lens.Name] {
				seenAvail[lens.Name] = true
				available = append(available, lensInfo(lens))
			}
		}
		for _, lens := range c.lenses.Imposed(principal, typ, "") {
			if !seenImposed[lens.Name] {
				seenImposed[lens.Name] = true
				imposed = append(imposed, lensInfo(lens))
			}
		}
	}

	sort.Slice(available, func(i, j int) bool { return available[i].Name < available[j].Name })
	sort.Slice(imposed, func(i, j int) bool { return imposed[i].Name < imposed[j].Name })
	return available, imposed
}

func lensInfo(l shin.Lens) *sekizuiv1.LensInfo {
	return &sekizuiv1.LensInfo{
		Name:      l.Name,
		Type:      l.Type,
		Fields:    l.Fields(),
		Withholds: l.Withholds(),
		MaxBytes:  uint32(l.MaxBytes), //nolint:gosec // config-bounded, not attacker-controlled
		Because:   l.Because,
	}
}
