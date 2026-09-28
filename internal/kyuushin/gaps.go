package kyuushin

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/fullstorydev/sekizui/internal/schemareg"
)

// Gaps counts what sources emitted that their connector's schema does not
// declare (D277, D279): undeclared kinds, withheld or refused, and undeclared
// fields stripped, as dotted paths.
//
// **NOT THE TALLY, AND THE SEPARATION IS THE POINT.** The Tally's every entry
// means the connector broke its contract and "the remedy is to stop polling
// it". A Fullstory user firing a new custom event is the vendor working as
// designed; filing it there would teach an anzen rule to stop polling the
// first time anybody adds an event. The remedy here is the connector owner's:
// declare the kind or the field, or accept that it is withheld (D279).
//
// **NAMES ONLY, NEVER VALUES.** A kind or property NAME is a developer's
// identifier; the value is where content lives, and none is kept here.
type Gaps struct {
	mu   sync.Mutex
	seen map[string]map[string]int // source ref -> "what" -> count
}

// NewGaps returns an empty Gaps.
func NewGaps() *Gaps { return &Gaps{seen: map[string]map[string]int{}} }

// Record notes what one shaped event revealed about the declaration.
func (g *Gaps) Record(ref string, s schemareg.Shaped) {
	var whats []string
	// AN OPEN KIND IS NOT A GAP: the connector declared other kinds open and
	// the source was asked for this one (D279).
	switch {
	case s.Withheld:
		whats = append(whats, fmt.Sprintf("kind %q withheld", s.Kind))
	case s.Refused():
		whats = append(whats, fmt.Sprintf("kind %q refused", s.Kind))
	}
	for _, p := range s.Stripped {
		if s.Kind != "" {
			p = s.Kind + ":" + p
		}
		whats = append(whats, p+" stripped")
	}
	if len(whats) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen[ref] == nil {
		g.seen[ref] = map[string]int{}
	}
	for _, w := range whats {
		g.seen[ref][w]++
	}
}

// Undeclared returns the current level: source ref -> what, and the remedy.
func (g *Gaps) Undeclared() map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]string, len(g.seen))
	for ref, whats := range g.seen {
		parts := make([]string, 0, len(whats))
		for w, n := range whats {
			parts = append(parts, fmt.Sprintf("%s x%d", w, n))
		}
		sort.Strings(parts)
		out[ref] = fmt.Sprintf("source %s emitted what its connector's schema does not declare: %s. "+
			"The source is behaving and nothing undeclared was published; the remedy is the "+
			"CONNECTOR OWNER's — declare these in the connector's schema — never to stop polling "+
			"(D277, D279)", ref, strings.Join(parts, ", "))
	}
	return out
}
