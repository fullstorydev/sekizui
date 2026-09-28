package main

// The DRIFT PRESENTATION. The component itself is `internal/drift.Watcher` —
// unlike `staleWatcher` and `churnWatcher`, which live in this package and can
// therefore only be tested by re-implementing what they do. D206 moved the loop
// into `internal/` so P2 step 12 could start the real one; what stays here is
// what belongs here, namely how an operator surface renders the state.

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/internal/drift"
)

// driftSummary is the one line /readyz carries, or empty when there is nothing
// to say.
//
// **COUNTS, NOT NAMES, and empty rather than "all targets ok".** A probe body
// is read by a human who is already worried; a line that appears only when
// something is off is a line worth reading, and one that appears on every
// healthy probe is D77's crying wolf with a per-request cost attached.
func driftSummary(s *drift.Store) string {
	var refused, degraded, unverified, failing int
	for _, st := range s.States() {
		switch {
		case st.Refused():
			refused++
		case st.Degraded():
			degraded++
		}
		// **ORTHOGONAL TO THE ABOVE, not an else.** A target can be degraded by
		// a comparison that succeeded an hour ago AND be failing its attempts
		// now, and an operator needs both facts: the first says what is wrong,
		// the second says whether what we are reporting is current.
		if !st.Checked() {
			unverified++
		}
		if st.Err != nil {
			failing++
		}
	}

	var parts []string
	for _, p := range []struct {
		n    int
		word string
	}{
		{refused, "refused"},
		{degraded, "degraded"},
		{unverified, "unverified"},
		{failing, "not comparing"},
	} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.word))
		}
	}
	return strings.Join(parts, ", ")
}

// writeTargetDrift renders every tracked target's state.
//
// **EVERY TARGET, INCLUDING THE HEALTHY ONES, unlike the /readyz summary.** A
// human asking this endpoint wants the whole picture — "is `mcp:acme` fine or
// is it absent from this list because the watcher never saw it" is a question
// only a complete list answers, and an endpoint that showed problems alone
// cannot distinguish healthy from unwatched.
func writeTargetDrift(w io.Writer, s *drift.Store) {
	states := s.States()
	if len(states) == 0 {
		fmt.Fprintln(w, "no target reports spec drift: no configured target's driver "+
			"compares a live surface against a vetted spec (D206). A deployment with no "+
			"MCP targets is expected to read exactly this.")
		return
	}

	for _, st := range states {
		fmt.Fprintf(w, "%s\n", st.Ref)

		switch {
		case !st.Checked():
			// UNVERIFIED IS NOT CLEAN, and saying so is the whole reason the
			// store keeps two timestamps (D75's cannot-confirm versus refuted).
			fmt.Fprintln(w, "  UNVERIFIED: no comparison has completed yet")
		case st.Refused():
			fmt.Fprintln(w, "  REFUSED: the target is unusable until the spec is re-vetted")
		case st.Degraded():
			fmt.Fprintf(w, "  DEGRADED: serving less than its vetted spec describes; "+
				"%d action(s) withheld\n", len(st.Withheld()))
		default:
			fmt.Fprintln(w, "  ok: matches its vetted spec")
		}

		fmt.Fprintf(w, "  compared: %s\n", since(st.At))
		if st.AttemptedAt != st.At {
			fmt.Fprintf(w, "  attempted: %s\n", since(st.AttemptedAt))
		}
		if st.Err != nil {
			// THE ATTEMPT, NOT THE VERDICT. An unreachable server is an
			// availability event and the findings above are from before it —
			// step 13's distinction, carried through to the operator surface so
			// nobody reads a stale finding as a current one.
			fmt.Fprintf(w, "  not comparing: %v\n", st.Err)
		}

		for _, f := range st.Findings {
			fmt.Fprintf(w, "  - %s\n", f)
			fmt.Fprintf(w, "      why this severity: %s\n", f.Severity.Explain())
		}
	}
}

// since renders a timestamp as an age, or says it never happened.
func since(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return time.Since(t).Truncate(time.Second).String() + " ago"
}
