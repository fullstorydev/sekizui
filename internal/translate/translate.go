// Package translate turns a source's raw event into the FIRST envelope of a
// causation chain.
//
// **THE MIRROR OF `reflex.Enrich`, NOT A COPY OF IT.** Enrich derives one
// envelope from another and every causation field is inherited or incremented;
// this derives one from nothing that came before, and every causation field is
// therefore different:
//
//	                reflex.Enrich (bus -> bus)      translate (source -> bus)
//	root_id         inherited, never rewritten      ITS OWN id — it IS the root
//	parent_id       the consumed envelope           EMPTY — nothing preceded it
//	depth           +1                              0
//	produced_by     "reflex:<rule>"                 "translator:<kind>"
//	stage           the rule's publish_to           the FIRST configured stage
//
// Writing that table is what stopped this being a copy with four edits, which
// is how the two would have drifted (D155). The fields they DO share — source,
// residency, trace, spec version, observed time — are the ones a census over
// `Envelope` would catch either of them forgetting, and nothing does that yet
// (D164 is scoped to `Decision`).
//
// # Three things reused rather than reinvented
//
//  1. **`safestruct.Convert`, never `structpb.NewStruct`.** D177 exists because
//     `structpb` fails ALL-OR-NOTHING on a value protobuf cannot carry, so one
//     awkward field erased a whole object — including the fields Sekizui itself
//     wrote. A `RawEvent.Data` is a third-party driver echoing an upstream
//     (D35), so this is the same hole with a different entrance, and the
//     entrance is what makes it worth saying: D177 was found on the command
//     path and closed there.
//  2. **The budget is spent while the struct is BUILT** (D178). Measuring
//     afterwards has already performed the allocation being defended against,
//     and an event becomes an envelope, an audit record and an fsync — so an
//     unbounded payload is disk amplification at no cost to the sender.
//  3. **The id is INJECTED, not generated here.** `reflex.Enrich` takes one and
//     `auditwal.Recorder` takes `WithIDFunc`, both so the generator can become
//     a ULID (§4.6.1d) without touching a caller, and so a test is
//     deterministic.
//
// # What this deliberately does not do
//
// **It does not validate the payload against its schema.** `Envelope.data` is
// "validated against data_schema AT PUBLISH TIME" (D40, D42), and moving that
// here would be a second validation point for one contract. It also does not
// check the source's conformance — that is `connector.ValidatePoll` at the
// boundary, called by the poller on every tick (D243).
//
// DESIGN.md references: §4.6.1, §4.6.1d, §12 P3, D19, D21, D29, D35, D40, D41,
// D43, D155, D177, D178, D243.
package translate

import (
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// specVersion is the CloudEvents spec version every envelope carries.
const specVersion = "1.0"

// Translator holds what comes from CONFIGURATION, so the per-event call carries
// only what varies per event.
//
// A TYPE RATHER THAN SEVEN PARAMETERS, and the split is on lifetime: the first
// stage and the byte budget are properties of the deployment and are read once
// at boot; the event, the target, the id and the trace change every time. A
// function taking all of them would invite a call site that passes the budget
// from somewhere other than the document.
type Translator struct {
	stage  string
	budget int
}

// New returns a Translator.
//
// **THE FIRST STAGE IS PASSED IN RATHER THAN DERIVED HERE**, because the
// ordered stage list is configuration (D43) and this package must not acquire a
// second reading of it — `config` already has `stageOrder`, and two parsers over
// one document is the divergent-lists failure D234 found inside the package
// built to prevent it.
func New(firstStage string, budget int) (*Translator, error) {
	const op = "translate.New"
	if firstStage == "" {
		// REFUSES RATHER THAN DEFAULTING TO "raw". A deployment that configured
		// no stages has a subject namespace nobody designed, and inventing one
		// here would place every envelope in a stage the monotonicity checker
		// (D21) has never heard of — so a later rule could publish "backwards"
		// into it with nothing to notice.
		return nil, fault.New(fault.KindConfig, op,
			"no first stage: the ordered stage list is empty, and a translator that "+
				"invented one would put every envelope in a stage D21's monotonicity "+
				"check does not know about")
	}
	if budget <= 0 {
		return nil, fault.New(fault.KindConfig, op,
			"a payload budget of zero or less would make every envelope empty; D178's "+
				"bound is a ceiling, not a switch")
	}
	return &Translator{stage: firstStage, budget: budget}, nil
}

// Translate builds the first envelope of a chain.
//
// `id` is the envelope's own identifier and `traceID` correlates it with the
// poll that produced it — both supplied by the caller, which is the poller.
// `root` is the causation root every envelope in this chain shares. EMPTY
// means this envelope IS the root, which is the polled case: nothing preceded
// it. A JOB passes its own id, so every result it produces shares one root and
// a caller can subscribe on it — which is why no `job_id` field was added to
// the envelope (D247). One field, two honest readings.
// rootOr returns the chain's root: the job's, or this envelope's own.
func rootOr(root, own string) string {
	if root != "" {
		return root
	}
	return own
}

func (tr *Translator) Translate(ev connector.RawEvent, t connector.Target, id, traceID, root string) (
	*sekizuiv1.Envelope, safestruct.Report, error,
) {
	const op = "translate.Translate"

	// THE ID IS OURS AND MUST NOT BE EMPTY. Every other required field can be
	// argued about; without this one the envelope cannot be referenced, cannot
	// be a causation root, and cannot be named in a gap marker.
	if id == "" {
		return nil, safestruct.Report{}, fault.New(fault.KindInternal, op,
			"no envelope id supplied; the id is the caller's to mint and is what makes "+
				"this envelope the root of its own causation chain")
	}
	// THE EVENT'S ID IS THE SOURCE'S AND IS ALREADY CHECKED AT THE BOUNDARY
	// (ValidatePoll, D243). Checked again here because this package is
	// reachable from a caller that did not poll — and because an envelope whose
	// source event cannot be named is one no gap marker can describe.
	if ev.ID == "" {
		return nil, safestruct.Report{}, fault.New(fault.KindInvalidArgument, op,
			fmt.Sprintf("the raw event from %q has no id", t.Ref()))
	}
	if ev.Type == "" {
		return nil, safestruct.Report{}, fault.New(fault.KindInvalidArgument, op,
			fmt.Sprintf("the raw event %q from %q has no type, so nothing can route, "+
				"lens or schema-check it", ev.ID, t.Ref()))
	}

	data, report := safestruct.Convert(ev.Data, tr.budget)

	env := &sekizuiv1.Envelope{
		Id: id,
		// CloudEvents `source` is the TARGET REF that produced this, which is
		// also what makes two systems of one kind distinguishable downstream.
		Source:      t.Ref(),
		SpecVersion: specVersion,
		Type:        ev.Type,
		Subject:     ev.Subject,
		Data:        data,
		Stage:       tr.stage,
		// RESIDENCY TRAVELS WITH THE DATA (D29), taken from the target because
		// that is the only party that knows where the rows came from. Losing it
		// here would make the envelope exportable to a region its source never
		// was, and the audit sink would inherit the same freedom (§4.6.1).
		Residency:    t.Residency(),
		TraceId:      traceID,
		ObservedTime: timestamppb.Now(),
		Causation: &sekizuiv1.Causation{
			// **ITS OWN ID, AND THAT IS THE WHOLE DIFFERENCE FROM ENRICHMENT.**
			// This envelope has no predecessor, so it is the root of its chain;
			// `parent_id` stays empty and `depth` stays 0. Copying Enrich's
			// `RootId: env.GetCausation().GetRootId()` here would leave the
			// root EMPTY on every ingested event, and every chain built on one
			// would then be unattributable to its origin.
			RootId:     rootOr(root, id),
			Depth:      0,
			ProducedBy: "translator:" + t.Kind(),
		},
	}

	// `time` IS THE SOURCE'S AND `observed_time` IS OURS. The gap between them
	// is the ingest lag and is worth graphing; collapsing them by defaulting a
	// missing event time to now would report every late arrival as punctual.
	if !ev.At.IsZero() {
		env.Time = timestamppb.New(ev.At.UTC())
	}

	return env, report, nil
}
