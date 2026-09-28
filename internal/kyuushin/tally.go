package kyuushin

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/fullstorydev/sekizui/pkg/connector"
)

// Tally counts contract violations per source, so `source_nonconforming` can be
// published as a LEVEL an anzen rule watches (D243).
//
// **`internal/mistenant`'s SHAPE, NOT `internal/churn`'s, AND THE CHOICE IS THE
// ONE MISTENANT'S OWN COMMENT ARGUES.** Churn needs a window and a threshold
// because one forced re-establishment is routine and ten in a quarter hour is a
// condition. **Every predicate in `ValidatePoll` is a thing that is never
// legitimate** — a duplicate id in one batch, a page over the limit asked for,
// an event with no id — so there is no normal rate to be above, and a threshold
// would be a decision to ignore the first occurrence.
//
// **SLOW IS NOT IN HERE, deliberately.** A source taking forty seconds is the
// world; a source still running after we cancelled it is a violation. Putting
// the first in this signal is how the signal becomes one nobody reads (D77).
//
// **AND THE LEVEL DOES NOT FALL, inheriting mistenant's asymmetry for a reason
// that transposes exactly.** Nothing about a later clean poll says the
// connector was fixed — only that this window did not hit the bug. A fixed
// connector arrives by deploy, and the restart is the re-arm.
type Tally struct {
	mu   sync.Mutex
	seen map[string]map[string]int // source ref -> violation kind -> count
}

// NewTally returns an empty Tally.
func NewTally() *Tally { return &Tally{seen: map[string]map[string]int{}} }

// Record notes violations against a source.
//
// The COUNT is kept although one occurrence already raises the level, because
// the detail an operator reads should say whether this happened once or is
// happening every tick. It changes nothing about when a rule fires.
func (t *Tally) Record(ref string, vs []connector.PollViolation) {
	if ref == "" || len(vs) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen[ref] == nil {
		t.seen[ref] = map[string]int{}
	}
	for _, v := range vs {
		t.seen[ref][v.Kind.String()]++
	}
}

// Nonconforming returns the current level: subject -> why.
//
// The shape `anzen.Dispatcher.Observe` takes, which is the same shape the drift
// watcher and the mistenant tally publish — so the dispatcher meets one kind of
// thing from every producer.
func (t *Tally) Nonconforming() map[string]string {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make(map[string]string, len(t.seen))
	for ref, kinds := range t.seen {
		parts := make([]string, 0, len(kinds))
		for k, n := range kinds {
			parts = append(parts, fmt.Sprintf("%s x%d", k, n))
		}
		// SORTED, so two reads of an unchanged tally produce the same string.
		// This reaches a signal subject and a log line, and a set that
		// reordered itself would look like a new condition every scrape.
		sort.Strings(parts)
		out[ref] = fmt.Sprintf(
			"source %s broke the Source contract: %s. These are conditions that are "+
				"never legitimate, so one is enough — the connector is at fault and the "+
				"remedy is to stop polling it, not to work around it (D243)",
			ref, strings.Join(parts, ", "))
	}
	return out
}
