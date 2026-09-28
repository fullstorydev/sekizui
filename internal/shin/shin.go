// Package shin (真, "truth") decides what a consumer actually receives (D83).
//
// PRIVATE (D35).
//
// THE THIRD QUESTION. Sekizui already answers two: policy answers *may you do
// this* and anzen answers *should anyone ever be able to*. Neither answers *in
// what shape* — and a consumer fully entitled to an event may still be the wrong
// recipient for all of it. The information a body sends to a hand is not the
// information it sends to an organ; sending either the other's would not be a
// permission failure, it would be a fitness failure.
//
// STRICTLY REDUCING, AND THAT IS THE LOAD-BEARING PROPERTY. A lens removes
// fields and caps size. It never adds, renames, computes, or reorders —
// reflexes do the compute (D63). Because every operation only removes, no lens
// change can cause a consumer to receive something it was not already receiving.
// Two things follow that would otherwise be unsafe:
//
//   - anzen may TIGHTEN a lens as a defensive action (D85) while still honouring
//     §4.11's rule that its vocabulary cannot touch a customer system. Narrowing
//     an output is inherently safe; almost no other control is.
//   - a misconfigured lens fails toward silence rather than toward disclosure.
//
// APPLY, THEN ASSERT. §6 mechanism 3 asserts the tenant at egress, immediately
// before the outbound call, because that is the only thing that catches a pooled
// client belonging to the wrong tenant. Withholding has the same shape: a lens
// that silently failed to apply is undetectable by inspection and, where the
// withholding is a compliance rule, is a disclosure rather than a badly-shaped
// payload. So Apply verifies its own output and refuses delivery on mismatch
// (D86).
//
// WHAT A LENS MUST NEVER DO is narrow the audit log. A lens governs what a
// CONSUMER sees; the record of what happened is not a consumer. Otherwise a lens
// becomes an evasion tool, which is the one thing this system exists to prevent.
//
// DESIGN.md references: §4.12, §6, §7.1, D63, D83, D84, D85, D86.
package shin

import (
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Mode distinguishes a ceiling from an offer.
type Mode string

const (
	// ModeImposed is a lens the consumer cannot opt out of.
	ModeImposed Mode = "imposed"

	// ModeRequestable is a lens the consumer may select for itself. It composes
	// UNDER the imposed ceiling and can only narrow further.
	ModeRequestable Mode = "requestable"
)

// Lens is one compiled projection.
type Lens struct {
	Name      string
	Mode      Mode
	Type      string // "" means every type
	Residency string // "" means every residency
	MaxBytes  int
	Because   string

	appliesTo []string
	fields    []string // allow-list; empty means "everything"
	withholds []string // deny-list; wins over fields
}

// Lenses is the compiled set in force.
type Lenses struct {
	all []Lens
}

// New compiles the lenses from a validated document.
func New(specs []config.ShinSpec) *Lenses {
	l := &Lenses{}
	for _, s := range specs {
		if !s.Enabled {
			continue
		}
		// EMPTY MODE MEANS IMPOSED — the restrictive default, inverting the
		// convention used for reflexes and anzen. See ShinSpec.Mode: a lens that
		// silently became optional would WIDEN what a consumer receives.
		mode := ModeImposed
		if s.Mode == string(ModeRequestable) {
			mode = ModeRequestable
		}
		l.all = append(l.all, Lens{
			Name: s.Name, Mode: mode, Type: s.Type, Residency: s.Residency,
			MaxBytes: s.MaxBytes, Because: s.Because,
			appliesTo: s.AppliesTo, fields: s.Fields, withholds: s.Withholds,
		})
	}
	return l
}

// Available returns the lenses a principal may SELECT — the requestable ones
// that apply to it. Feeds Describe (D79).
func (l *Lenses) Available(principal, payloadType, residency string) []Lens {
	var out []Lens
	for _, lens := range l.all {
		if lens.Mode == ModeRequestable && lens.covers(principal, payloadType, residency) {
			out = append(out, lens)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Imposed returns the ceiling in force for a principal — the lenses it cannot
// opt out of. Also surfaced by Describe, because a consumer that cannot see its
// own ceiling will keep asking why a field never arrives.
func (l *Lenses) Imposed(principal, payloadType, residency string) []Lens {
	var out []Lens
	for _, lens := range l.all {
		if lens.Mode == ModeImposed && lens.covers(principal, payloadType, residency) {
			out = append(out, lens)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Request is one delivery to lens.
type Request struct {
	Principal string
	Type      string
	Residency string

	// Selected names a requestable lens the consumer chose. Empty means none;
	// the imposed ceiling still applies.
	Selected string

	// Added names lenses a signed subject's token listed (D303): they join the
	// imposed ones for this request whatever their mode or audience, because a
	// lens can only REMOVE — a token may add restriction, never widen.
	Added []string
}

// Apply projects a payload for one consumer, then verifies its own work.
//
// Returns the projected payload and the names of every lens that contributed, so
// a caller can report WHICH lens removed something rather than leaving a
// consumer to guess.
func (l *Lenses) Apply(req Request, payload map[string]any) (map[string]any, []string, error) {
	const op = "shin.Apply"

	effective, err := l.effective(req)
	if err != nil {
		return nil, nil, err
	}
	if len(effective) == 0 {
		// No lens applies. The payload passes through whole, which is correct:
		// absence of a lens is not a lens that removes everything.
		return payload, nil, nil
	}

	out := payload
	names := make([]string, 0, len(effective))
	for _, lens := range effective {
		out = lens.project(out)
		names = append(names, lens.Name)
	}

	// APPLY, THEN ASSERT (D86). Everything above is ordinary code that could be
	// wrong; this is the check that makes a withheld field's absence a fact
	// rather than an expectation. Cheap, and it is the difference between a
	// compliance lens and a hopeful one.
	if err := assertWithheld(effective, out); err != nil {
		return nil, nil, fault.Wrap(fault.KindInternal, op, fmt.Sprintf(
			"refusing delivery to %q: the lens did not produce what it promised", req.Principal), err)
	}
	if err := assertSize(effective, out); err != nil {
		return nil, nil, err
	}

	sort.Strings(names)
	return out, names, nil
}

// Withholds reports whether the lenses in effect for req — imposed plus any
// selected, exactly as Apply composes them — withhold path, and names the lens.
//
// For a refines rule deciding whether it can run (D300: the unit is the RULE).
// CONSERVATIVE: a path at or under a withheld field is withheld, and so is one
// an allow-list does not reach — including a path an allow-list keeps only
// PART of, because a rule reading half an object reads a lie.
func (l *Lenses) Withholds(req Request, path string) (lens string, withheld bool, err error) {
	effective, err := l.effective(req)
	if err != nil {
		return "", false, err
	}
	for _, ln := range effective {
		if PathWithheld(ln.fields, ln.withholds, path) {
			return ln.Name, true, nil
		}
	}
	return "", false, nil
}

// PathWithheld is THE reading of whether a lens with this allow-list and
// deny-list withholds path — for Withholds at run time and for the boot check
// refusing a rule its audience's imposed lens would always block (D300).
// Conservative: at or under a withheld field is withheld, and so is a path an
// allow-list does not reach whole.
func PathWithheld(fields, withholds []string, path string) bool {
	for _, w := range withholds {
		if path == w || strings.HasPrefix(path, w+".") {
			return true
		}
	}
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if path == f || strings.HasPrefix(path, f+".") {
			return false
		}
	}
	return true
}

// effective is the lenses in force for req: imposed, the one selected, and any
// a signed subject's token added — ONE reading for Apply and Withholds.
func (l *Lenses) effective(req Request) ([]Lens, error) {
	out := l.Imposed(req.Principal, req.Type, req.Residency)
	if req.Selected != "" {
		chosen, err := l.selectable(req)
		if err != nil {
			return nil, err
		}
		out = append(out, chosen)
	}
	for _, name := range req.Added {
		found := false
		for _, lens := range l.all {
			if lens.Name == name {
				found = true
				if lens.Type == "" || lens.Type == req.Type {
					out = append(out, lens)
				}
			}
		}
		if !found {
			return nil, fault.New(fault.KindDenied, "shin.effective", fmt.Sprintf(
				"a token added lens %q, which is not declared; a restriction that cannot be applied refuses the "+
					"delivery rather than being skipped", name))
		}
	}
	return out, nil
}

// selectable resolves a requested lens name, refusing anything not on offer.
//
// REFUSED, NOT IGNORED. A consumer naming a lens it may not have is either
// misconfigured or probing; silently falling back to the imposed ceiling would
// hide both. This is D46's model for MCP tools applied to lenses: what is not
// declared is not selectable.
func (l *Lenses) selectable(req Request) (Lens, error) {
	const op = "shin.selectable"

	for _, lens := range l.all {
		if lens.Name != req.Selected {
			continue
		}
		if lens.Mode != ModeRequestable {
			return Lens{}, fault.New(fault.KindDenied, op, fmt.Sprintf(
				"lens %q is imposed, not requestable; an imposed lens is a ceiling an "+
					"operator set and a consumer cannot select or decline it", req.Selected))
		}
		if !lens.covers(req.Principal, req.Type, req.Residency) {
			// SAY WHAT THE LENS IS SCOPED TO, not only what was asked for.
			// "not offered for type X" leaves a consumer unable to tell a typo
			// from a scoping rule, and the answer is one field away.
			var why []string
			if lens.Type != "" && lens.Type != req.Type {
				why = append(why, fmt.Sprintf("it is scoped to type %q", lens.Type))
			}
			if lens.Residency != "" && lens.Residency != req.Residency {
				why = append(why, fmt.Sprintf("it is scoped to residency %q", lens.Residency))
			}
			if !lens.coversPrincipal(req.Principal) {
				why = append(why, "it is not offered to this principal")
			}
			return Lens{}, fault.New(fault.KindDenied, op, fmt.Sprintf(
				"lens %q does not apply to %q for type %q in residency %q: %s",
				req.Selected, req.Principal, req.Type, req.Residency, strings.Join(why, "; ")))
		}
		return lens, nil
	}

	// NAME EVERY LENS THIS PRINCIPAL COULD EVER SELECT, not only those matching
	// the current type. A consumer that asked for a real lens under the wrong
	// payload type would otherwise be told "available: []" — technically true and
	// actively misleading, since the lens plainly exists in the config they were
	// handed.
	here, elsewhere := []string{}, []string{}
	for _, lens := range l.all {
		if lens.Mode != ModeRequestable || !lens.coversPrincipal(req.Principal) {
			continue
		}
		if lens.covers(req.Principal, req.Type, req.Residency) {
			here = append(here, lens.Name)
			continue
		}
		elsewhere = append(elsewhere, fmt.Sprintf("%s (type %q)", lens.Name, lens.Type))
	}
	sort.Strings(here)
	sort.Strings(elsewhere)

	msg := fmt.Sprintf("no lens named %q; lenses are declared in configuration and "+
		"reviewed, not composed per request (D84). Available to %q for type %q: %v",
		req.Selected, req.Principal, req.Type, here)
	if len(elsewhere) > 0 {
		msg += fmt.Sprintf(". Offered to it for OTHER types: %v — a lens can be scoped "+
			"to one payload type, so check the type as well as the name", elsewhere)
	}
	return Lens{}, fault.New(fault.KindNotFound, op, msg)
}

// project applies one lens. Pure: it never mutates its input, because the same
// payload is delivered to several consumers with different lenses.
func (l Lens) project(in map[string]any) map[string]any {
	out := in

	if len(l.fields) > 0 {
		out = keepOnly(out, l.fields)
	}
	for _, path := range l.withholds {
		out = remove(out, strings.Split(path, "."))
	}
	return out
}

// covers reports whether this lens applies to a consumer.
func (l Lens) covers(principal, payloadType, residency string) bool {
	if l.Type != "" && l.Type != payloadType {
		return false
	}
	if l.Residency != "" && l.Residency != residency {
		return false
	}
	return l.coversPrincipal(principal)
}

// coversPrincipal is the principal half of covers, split out so an error can
// distinguish "not offered to you" from "not offered for this type".
func (l Lens) coversPrincipal(principal string) bool {
	if len(l.appliesTo) == 0 {
		// Every principal. Correct for an imposed ceiling; boot validation
		// refuses it for a requestable lens.
		return true
	}
	for _, pattern := range l.appliesTo {
		if pattern == principal {
			return true
		}
		if prefix, ok := strings.CutSuffix(pattern, "*"); ok && strings.HasPrefix(principal, prefix) {
			return true
		}
	}
	return false
}

// Fields returns the allow-list, for Describe and for tests.
func (l Lens) Fields() []string { return append([]string(nil), l.fields...) }

// Withholds returns the deny-list, for Describe and for tests.
func (l Lens) Withholds() []string { return append([]string(nil), l.withholds...) }

// assertWithheld verifies that nothing a lens promised to remove survived.
func assertWithheld(lenses []Lens, payload map[string]any) error {
	const op = "shin.assertWithheld"

	var leaked []string
	for _, lens := range lenses {
		for _, path := range lens.withholds {
			if present(payload, strings.Split(path, ".")) {
				leaked = append(leaked, fmt.Sprintf("%s (lens %q: %s)", path, lens.Name, lens.Because))
			}
		}
	}
	if len(leaked) > 0 {
		sort.Strings(leaked)
		return fault.New(fault.KindInternal, op, fmt.Sprintf(
			"%d withheld field(s) survived projection:\n  - %s",
			len(leaked), strings.Join(leaked, "\n  - ")))
	}
	return nil
}

// assertSize enforces the tightest MaxBytes among the applied lenses.
//
// KindBudgetExceeded rather than KindInternal: an oversized payload is a real
// event that is genuinely too large for this consumer, not a bug in the lens. An
// operator seeing this should widen the cap or narrow the fields, not read code.
func assertSize(lenses []Lens, payload map[string]any) error {
	const op = "shin.assertSize"

	limit := 0
	name := ""
	for _, lens := range lenses {
		if lens.MaxBytes > 0 && (limit == 0 || lens.MaxBytes < limit) {
			limit, name = lens.MaxBytes, lens.Name
		}
	}
	if limit == 0 {
		return nil
	}

	if size := approxSize(payload); size > limit {
		return fault.New(fault.KindBudgetExceeded, op, fmt.Sprintf(
			"projected payload is ~%d bytes; lens %q caps it at %d. Narrow the lens or "+
				"raise the cap — this bounds what ONE message carries, not how many arrive "+
				"(that is a rate limit, §4.3.4)", size, name, limit))
	}
	return nil
}

// approxSize estimates the serialised size without serialising.
//
// APPROXIMATE ON PURPOSE. An exact figure means marshalling every payload for
// every consumer on the delivery path, and the cap exists to stop a consumer
// drowning rather than to bill it. An estimate within a few percent refuses the
// same payloads.
func approxSize(v any) int {
	switch t := v.(type) {
	case map[string]any:
		n := 2 // {}
		for k, val := range t {
			n += len(k) + 4 + approxSize(val) // "k": v,
		}
		return n
	case []any:
		n := 2
		for _, item := range t {
			n += approxSize(item) + 1
		}
		return n
	case string:
		return len(t) + 2
	case nil:
		return 4
	case bool:
		return 5
	default:
		return 8 // numbers, near enough
	}
}

// keepOnly builds a payload containing only the named paths.
func keepOnly(in map[string]any, paths []string) map[string]any {
	out := map[string]any{}
	for _, path := range paths {
		copyPath(in, out, strings.Split(path, "."))
	}
	return out
}

func copyPath(from, to map[string]any, segments []string) {
	head := segments[0]
	v, ok := from[head]
	if !ok {
		// A path the payload does not carry. NOT an error here: boot validation
		// already refused paths no schema declares (D42), so an absence at
		// runtime means an optional field, which is normal.
		return
	}
	if len(segments) == 1 {
		to[head] = v
		return
	}
	sub, ok := v.(map[string]any)
	if !ok {
		return
	}
	nested, ok := to[head].(map[string]any)
	if !ok {
		nested = map[string]any{}
		to[head] = nested
	}
	copyPath(sub, nested, segments[1:])
}

// remove returns a copy without the given path.
//
// COPIES RATHER THAN DELETING IN PLACE. The same payload map is delivered to
// several consumers with different lenses; deleting from it would mean the first
// consumer's withholding silently applied to everyone — a bug that looks like
// correct behaviour until one consumer is missing a field nobody removed for it.
func remove(in map[string]any, segments []string) map[string]any {
	head := segments[0]
	if _, present := in[head]; !present {
		return in
	}

	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	if len(segments) == 1 {
		delete(out, head)
		return out
	}
	if sub, ok := out[head].(map[string]any); ok {
		out[head] = remove(sub, segments[1:])
	}
	return out
}

func present(in map[string]any, segments []string) bool {
	v, ok := in[segments[0]]
	if !ok {
		return false
	}
	if len(segments) == 1 {
		return true
	}
	sub, ok := v.(map[string]any)
	if !ok {
		return false
	}
	return present(sub, segments[1:])
}

// Deliver projects an envelope for one consumer.
//
// THE SECOND CALLER, and it exists now rather than at P3 for the reason D70
// records: a seam with one caller gets shaped to fit that caller. Query hands
// this package flat rows with no declared type; an envelope carries a versioned
// type and a residency. Two callers with genuinely different shapes is what
// forces the interface to be honest before the bus arrives and becomes the
// third.
//
// Returns a COPY. The same envelope is delivered to several consumers with
// different lenses, and projecting in place would mean the first consumer's
// lens silently applied to everyone — a bug that looks like correct behaviour
// until one consumer is missing a field nobody removed for it.
func (l *Lenses) Deliver(consumer string, env *sekizuiv1.Envelope, selected string) (
	*sekizuiv1.Envelope, []string, error) {

	const op = "shin.Deliver"

	if env == nil {
		return nil, nil, fault.New(fault.KindInvalidArgument, op, "no envelope to deliver")
	}

	// **AN INBOUND PROJECTION IS NEVER CARRIED THROUGH (D269).** A projection
	// is generated at delivery, AFTER this, from the lensed data — so one
	// arriving here was made from data this consumer may not see, and cloning it
	// through untouched is how a withheld field would leave in the one part of
	// the envelope no lens and no egress assertion looks at. Stripped first, on
	// every path out of this function.
	if env.GetProjection() != nil {
		env = proto.Clone(env).(*sekizuiv1.Envelope)
		env.Projection = nil
	}

	projected, names, err := l.Apply(Request{
		Principal: consumer,
		Type:      env.GetType(),
		Residency: env.GetResidency(),
		Selected:  selected,
	}, env.GetData().AsMap())
	if err != nil {
		return nil, nil, err
	}
	if len(names) == 0 {
		return env, nil, nil
	}

	data, err := structpb.NewStruct(projected)
	if err != nil {
		return nil, nil, fault.Wrap(fault.KindInternal, op, "re-encoding the projected payload", err)
	}

	// ENVELOPE METADATA IS NEVER LENSED — only `data` is.
	//
	// id, type, stage, causation, and trace_id are how a consumer correlates what
	// it received with what the audit log says happened. Removing them would make
	// a lensed delivery untraceable, which is the evasion this package must not
	// enable. A lens shapes the payload, never the provenance.
	out := proto.Clone(env).(*sekizuiv1.Envelope)
	out.Data = data
	return out, names, nil
}
