package connector_test

import (
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/connector"
)

func ev(id string) connector.RawEvent {
	return connector.RawEvent{ID: id, Type: "kata.row.v1", At: time.Unix(1, 0)}
}

// A CONFORMING RESPONSE MUST REPORT NOTHING. Without this the whole table below
// is satisfied by a function that returns every violation every time.
func TestAConformingPollReportsNothing(t *testing.T) {
	t.Parallel()
	got := connector.ValidatePoll("w-1", 4, []connector.RawEvent{ev("a"), ev("b")}, "w-2")
	if len(got) != 0 {
		t.Errorf("a conforming response reported %v", got)
	}
}

func TestEveryViolationIsDetected(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		cursor string
		limit  int
		events []connector.RawEvent
		next   string
		want   connector.PollViolationKind
	}{
		"more events than the limit": {
			cursor: "w-1", limit: 1,
			events: []connector.RawEvent{ev("a"), ev("b")}, next: "w-2",
			want: connector.PollOverLimit,
		},
		"rows returned and the cursor handed straight back": {
			cursor: "w-1", limit: 4,
			events: []connector.RawEvent{ev("a")}, next: "w-1",
			want: connector.PollCursorStalled,
		},
		"the cursor reset to the beginning": {
			cursor: "w-1", limit: 4,
			events: nil, next: "",
			want: connector.PollCursorReset,
		},
		"the same id twice in one batch": {
			cursor: "w-1", limit: 4,
			events: []connector.RawEvent{ev("a"), ev("a")}, next: "w-2",
			want: connector.PollDuplicateID,
		},
		"an event with no id": {
			cursor: "w-1", limit: 4,
			events: []connector.RawEvent{ev("")}, next: "w-2",
			want: connector.PollEmptyID,
		},
		"an event nothing can route": {
			cursor: "w-1", limit: 4,
			events: []connector.RawEvent{{ID: "a", At: time.Unix(1, 0)}}, next: "w-2",
			want: connector.PollUntypedEvent,
		},
		"an event with no time": {
			cursor: "w-1", limit: 4,
			events: []connector.RawEvent{{ID: "a", Type: "kata.row.v1"}}, next: "w-2",
			want: connector.PollUndatedEvent,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := connector.ValidatePoll(tc.cursor, tc.limit, tc.events, tc.next)
			for _, v := range got {
				if v.Kind == tc.want {
					if strings.TrimSpace(v.Detail) == "" {
						t.Errorf("%v has no detail, and the detail is what reaches the "+
							"signal an operator reads", v.Kind)
					}
					return
				}
			}
			t.Errorf("want a %v violation, got %v", tc.want, got)
		})
	}
}

// RE-POLLING AN UNCOMMITTED WINDOW IS NOT A VIOLATION. That is re-querying
// working exactly as D174 intends, and a check that flagged it would report the
// recovery path as a defect every time it ran.
func TestReturningTheSameWindowForTheSameCursorIsNotAViolation(t *testing.T) {
	t.Parallel()
	events := []connector.RawEvent{ev("a"), ev("b")}
	if got := connector.ValidatePoll("w-1", 4, events, "w-2"); len(got) != 0 {
		t.Errorf("first poll reported %v", got)
	}
	if got := connector.ValidatePoll("w-1", 4, events, "w-2"); len(got) != 0 {
		t.Errorf("re-polling the same cursor reported %v", got)
	}
}

// AN EMPTY WINDOW IS ORDINARY. A source with nothing new returns no events, and
// a watermark may legitimately advance across rows that did not match.
func TestAnEmptyWindowIsNotAViolation(t *testing.T) {
	t.Parallel()
	if got := connector.ValidatePoll("w-1", 4, nil, "w-1"); len(got) != 0 {
		t.Errorf("an idle source reported %v", got)
	}
	if got := connector.ValidatePoll("w-1", 4, nil, "w-9"); len(got) != 0 {
		t.Errorf("an advanced-but-empty window reported %v", got)
	}
}

// THE ZERO VALUE IS TREATED AS THE WORST CASE (GO-PRIMER §15aj, D113).
func TestAnUnclassifiedViolationIsNamedRatherThanBlank(t *testing.T) {
	t.Parallel()
	if got := connector.PollViolationKind(0).String(); got != "unclassified" {
		t.Errorf("the zero kind renders as %q; it reaches a log line and a signal", got)
	}
}
