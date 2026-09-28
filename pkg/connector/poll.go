package connector

import (
	"fmt"
	"strconv"
)

// ValidatePoll reports every way one Poll's RESPONSE breaks the Source
// contract.
//
// **ONE IMPLEMENTATION, TWO CALLERS, AND THAT IS THE POINT** — the same
// sentence `ValidateActions` carries, for the same reason and with the same
// evidence behind it (D155, D160, D243). The published conformance suite runs
// this so an author learns the contract before they deploy; the POLLER runs it
// on every tick so a driver that never ran the suite is bounded anyway. Two
// statements of "what conforming means" would drift, and CONTRACTS 93 is what
// that costs: the connector contract was stated in three places, no two agreed,
// and an out-of-tree author (D35) running the published suite got four checks
// their deployment would later refuse them on.
//
// # Why the suite alone is not enough, and the bound alone is not enough
//
// A suite has no power over an author who does not run it, and the maintainer's ruling at
// D243 is that somebody will write a broken connector and deploy it. A runtime
// bound with no arm is a surprise at deploy. **A conformance arm without a
// runtime bound is advice; a runtime bound without an arm is an ambush.**
//
// # What is checked here, and what cannot be
//
// This function sees a RESPONSE. It cannot see behaviour — a driver that panics
// or ignores its context is violating the contract in a way no return value
// records, so those are the POLLER's to detect and the suite's to exercise by
// calling. Split stated rather than left to be discovered.
//
// **CROSS-BATCH DUPLICATES ARE NOT CHECKED, and the reason is worth reading
// before somebody adds it.** Remembering every id ever ingested is the unbounded
// set D240 was corrected about; and the ids in an UNCOMMITTED window are
// legitimately returned again, because that is re-querying working exactly as
// D174 intends. There is no version of this check that is both bounded and
// correct, so it is absent and named rather than half-built.
//
// DESIGN.md references: §4.2.1, §12 P3, D35, D155, D160, D171, D174, D243.
func ValidatePoll(cursor string, limit int, events []RawEvent, next string) []PollViolation {
	var out []PollViolation

	if limit > 0 && len(events) > limit {
		out = append(out, PollViolation{
			Kind: PollOverLimit,
			Detail: "returned " + strconv.Itoa(len(events)) + " events for a limit of " +
				strconv.Itoa(limit) + "; the limit is the caller's memory budget, not a hint",
		})
	}

	// **THE MELT (D243).** Rows returned and no progress reported is a
	// contradiction on its face, and a poller that believes it re-ingests the
	// same window every tick, for ever, writing an audit record each time.
	//
	// EQUALITY, NEVER ORDER. A cursor is the source's own string and the moment
	// this function parses one to decide it moved forward it has acquired vendor
	// knowledge that belongs in the connector (D171) — and it would be wrong on
	// the first cursor that is a page token rather than a timestamp.
	if len(events) > 0 && next == cursor {
		out = append(out, PollViolation{
			Kind: PollCursorStalled,
			Detail: "returned " + strconv.Itoa(len(events)) + " events and handed back the " +
				"cursor it was given, which claims progress and reports none",
		})
	}

	// THE ONE ORDERING FACT THAT IS OURS RATHER THAN THE VENDOR'S: the empty
	// string is what the SPINE passes on a source's first ever poll, so its
	// meaning — the beginning — is defined by this protocol and not by the
	// vendor's encoding. A source resetting to it has asked for the world to be
	// re-read, which is the melt wearing a different coat.
	if cursor != "" && next == "" {
		out = append(out, PollViolation{
			Kind:   PollCursorReset,
			Detail: "reset the cursor to empty from " + strconv.Quote(cursor) + ", which asks for the whole source to be re-read",
		})
	}

	seen := make(map[string]bool, len(events))
	for i, e := range events {
		switch {
		case e.ID == "":
			out = append(out, PollViolation{
				Kind: PollEmptyID,
				Detail: "event at index " + strconv.Itoa(i) + " has no id, and the id is the " +
					"only thing that can name it in a gap marker or keep it from being re-delivered",
			})
		case seen[e.ID]:
			out = append(out, PollViolation{
				Kind:   PollDuplicateID,
				Detail: "id " + strconv.Quote(e.ID) + " appears more than once in one batch",
			})
		default:
			seen[e.ID] = true
		}

		if e.Type == "" {
			out = append(out, PollViolation{
				Kind:   PollUntypedEvent,
				Detail: "event " + strconv.Quote(e.ID) + " has no type, so nothing can route or lens it",
			})
		}
		if e.At.IsZero() {
			out = append(out, PollViolation{
				Kind: PollUndatedEvent,
				Detail: "event " + strconv.Quote(e.ID) + " has no time; a zero timestamp reaches " +
					"the envelope and the audit record as a date in year one",
			})
		}
	}
	return out
}

// PollViolationKind names one way a Source broke its contract.
//
// **THE ZERO VALUE IS `PollViolationUnknown` AND IT IS TREATED AS THE MOST
// SEVERE**, which is GO-PRIMER §15aj's rule and D113's shape — an unknown
// action is treated as mutating, because the safe reading of "I do not
// recognise this" is never "then it is fine". A violation arriving with no kind
// is a violation somebody forgot to classify, and classifying it as harmless by
// default is how a new failure mode ships switched off.
type PollViolationKind int

const (
	// PollViolationUnknown is the zero value: unclassified, handled as the
	// worst case.
	PollViolationUnknown PollViolationKind = iota

	// PollOverLimit — more events than the caller asked for.
	PollOverLimit

	// PollCursorStalled — events returned with no cursor progress. The melt.
	PollCursorStalled

	// PollCursorReset — the cursor was set back to the beginning.
	PollCursorReset

	// PollDuplicateID — one batch carries the same id twice.
	PollDuplicateID

	// PollEmptyID — an event with no id.
	PollEmptyID

	// PollUntypedEvent — an event nothing can route.
	PollUntypedEvent

	// PollUndatedEvent — an event with a zero timestamp.
	PollUndatedEvent

	// PollUndeclaredType — an event of a type its poll action does not declare
	// (D276). Appended, so every value above keeps its number.
	PollUndeclaredType

	// PollNonconformingPayload — an event whose payload fails its declared
	// schema, or names a kind nobody declared (D276).
	PollNonconformingPayload
)

// String names the kind for a log line, an audit detail and the signal.
func (k PollViolationKind) String() string {
	switch k {
	case PollOverLimit:
		return "over_limit"
	case PollCursorStalled:
		return "cursor_stalled"
	case PollCursorReset:
		return "cursor_reset"
	case PollDuplicateID:
		return "duplicate_id"
	case PollEmptyID:
		return "empty_id"
	case PollUntypedEvent:
		return "untyped_event"
	case PollUndatedEvent:
		return "undated_event"
	case PollUndeclaredType:
		return "undeclared_type"
	case PollNonconformingPayload:
		return "nonconforming_payload"
	case PollViolationUnknown:
		return "unclassified"
	default:
		return "unclassified"
	}
}

// PollViolation is one broken obligation, with enough detail to act on.
//
// **NOT A `[]string`, which is what `ValidateActions` returns and would have
// been the obvious symmetry.** The suite needs prose and the poller needs to
// DECIDE — truncate, or stop polling this source — and a string forces the
// second caller to parse the first caller's sentence. That is the divergent
// reading D234 found inside `internal/docref`, which is the package built to
// prevent it.
type PollViolation struct {
	Kind   PollViolationKind
	Detail string
}

func (v PollViolation) String() string { return fmt.Sprintf("%s: %s", v.Kind, v.Detail) }
