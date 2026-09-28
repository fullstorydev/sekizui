package drift

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/atomicfile"
)

// State is what the last completed check learned about one target.
type State struct {
	// Ref is the target this is about.
	Ref string

	// Findings is the last COMPLETED comparison. Empty means the target matched
	// its vetted spec; see Checked for the difference between that and "never
	// compared".
	Findings Findings

	// At is when that comparison completed. The zero value means no comparison
	// has ever completed for this target.
	At time.Time

	// AttemptedAt is when the watcher last TRIED, whether or not it succeeded.
	//
	// BOTH TIMESTAMPS, because one of them alone misleads in a way an operator
	// acts on. `At` alone cannot distinguish "the poll loop is dead" from "the
	// vendor has been unreachable for an hour" — both look like a stale
	// comparison. Together they say which: an advancing AttemptedAt with a
	// frozen At is a vendor problem, and both frozen is ours.
	AttemptedAt time.Time

	// Err is set when the most recent ATTEMPT failed — an unreachable server,
	// a protocol fault, a cancelled context.
	//
	// **AN OUTAGE IS NOT DRIFT, AND THE TWO ARE KEPT APART HERE BECAUSE STEP 13
	// DECIDED IT:** a divergence is `spec_drift` (deliberate, not retryable), an
	// outage is `target_unavailable` (a failure, retryable) with NO findings at
	// all. A store that turned a network blip into a governance finding would
	// make a vendor's bad afternoon look like a supply-chain event, and anzen
	// rules watching `spec_drift` would fire on it.
	Err error
}

// Checked reports whether any comparison has ever completed for this target.
//
// **"NOT YET CHECKED" IS NOT "CHECKED AND CLEAN", and conflating them is D75's
// refuted-versus-cannot-confirm in a third guise.** An empty `Findings` is
// ambiguous on its own: it is what a matching target looks like AND what a
// target looks like before the first poll, or after nothing but failures. The
// distinction is what lets readiness say UNVERIFIED rather than implying a
// clean bill of health nothing has established.
func (st State) Checked() bool { return !st.At.IsZero() }

// Withheld returns the actions to drop from the catalog for this target.
func (st State) Withheld() []string { return st.Findings.Withheld() }

// Degraded reports whether this target is serving less than its vetted spec
// describes.
//
// **NOT THE SAME WORD THE SPINE USES.** `spine.Status.Degraded()` means
// SUBSYSTEMS REMAIN UNBUILT (D53's init ledger) — a fact about this build.
// This means a vendor is offering less than a human vetted — a fact about a
// target, at runtime. Two audiences, two remedies: one is answered by shipping
// the next phase, the other by re-vetting a spec. They are reported separately
// for that reason, and neither is allowed to set the other's flag.
func (st State) Degraded() bool { return len(st.Findings.Withheld()) > 0 }

// Refused reports whether the divergence makes the whole target unusable.
func (st State) Refused() bool { return st.Findings.RefusesTarget() }

// Store holds the last known drift state per target.
//
// **THREE READERS, ONE WRITER, AND THAT IS WHY IT IS A PACKAGE RATHER THAN A
// FIELD ON SOMETHING.** The catalog reads it to withhold an action, readiness
// reads it to report a target degraded, and the anzen dispatcher takes the
// `spec_drift` signal derived from it. The writer is the drift watcher. None of
// the readers may block on a vendor's availability, which is the whole reason
// the comparison is a background poll rather than something `Describe` does:
// a Describe that reached out to every MCP server would make an agent's
// capability listing as slow and as failure-prone as the least reliable vendor
// in the deployment.
//
// **IT MUST NOT IMPLEMENT `spine.HealthReporter`, and that is asserted
// structurally rather than left to reading.** A component reporting unhealthy
// makes `Status.Ready` false, which takes the whole instance out of rotation —
// so a single withdrawn tool at one vendor would stop the process serving
// nineteen tools that work and every other target besides. That is the
// over-refusal failure D197 refuses in as many words, and P1 step 33 already
// established the shape of the guard (the pool must not implement it either).
type Store struct {
	mu       sync.RWMutex
	byTarget map[string]State

	// gen counts changes; each persisted snapshot carries the gen it was taken
	// at, so a slower writer can never overwrite a newer state with an older one.
	gen uint64

	// PERSISTENCE (D311). Empty path means in memory only, which is what the
	// unit-level fixtures want. fileMu serialises writes and is SEPARATE from
	// mu, because mu must never be held across a file write (GO-PRIMER §15u).
	path       string
	fileMu     sync.Mutex
	written    uint64
	persistErr error
}

// OpenStore returns a store PERSISTED at path, loaded from what is there (D311).
//
// **A DIVERGED TARGET STAYS DIVERGED ACROSS A RESTART** (the maintainer): the loaded state
// is in force — its withheld tools stay withheld — until a fresh comparison says
// otherwise. A restart must never be how a divergence goes away; that is the
// "never auto-restore trust" rule, and a store that forgot on every boot would
// hand anything able to restart the process a way to clear a finding.
//
// **FAILURE DIRECTIONS, D150's:** a file that exists and cannot be read or
// parsed FAILS THE LOAD, and so the boot — an empty store in its place would be
// every finding forgotten. A file that does not exist is a first boot, and an
// empty store is the truth; the boot-time comparison re-derives the state
// either way. (Deleting the file is therefore equivalent to a first boot — the
// same residual D145's withdrawal store carries, and the reason the comparison
// runs at once rather than after one interval.)
//
// **AN EMPTY PATH IS A STORE IN MEMORY ONLY**, for fixtures that test the
// comparison rather than its persistence. ONE CONSTRUCTOR, because a second one
// only tests called was exactly what TestNoOrphanedExportsInInternal refuses.
func OpenStore(path string) (*Store, error) {
	s := &Store{byTarget: map[string]State{}, path: path}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("drift.OpenStore: %w", err)
	}
	var p persisted
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("drift.OpenStore: %s is not a drift state file: %w", path, err)
	}
	if p.Version != persistedVersion {
		return nil, fmt.Errorf("drift.OpenStore: %s is version %d; this build reads %d",
			path, p.Version, persistedVersion)
	}
	for _, ps := range p.States {
		for _, f := range ps.Findings {
			if !f.Severity.Known() {
				return nil, fmt.Errorf("drift.OpenStore: %s records severity %q for %q, which is "+
					"not in the vocabulary %v", path, f.Severity, ps.Ref, Severities())
			}
		}
		st := State{Ref: ps.Ref, Findings: ps.Findings, At: ps.At, AttemptedAt: ps.AttemptedAt}
		if ps.Err != "" {
			st.Err = errors.New(ps.Err)
		}
		s.byTarget[ps.Ref] = st
	}
	return s, nil
}

// PersistErr is the most recent failure to write the state file, or nil. The
// in-memory state stays in force either way — the watcher reports it loudly
// and the comparison's decision record says the state was not persisted.
func (s *Store) PersistErr() error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.persistErr
}

const persistedVersion = 1

type persisted struct {
	Version int              `json:"version"`
	States  []persistedState `json:"states"`
}

type persistedState struct {
	Ref         string    `json:"ref"`
	Findings    Findings  `json:"findings,omitempty"`
	At          time.Time `json:"at"`
	AttemptedAt time.Time `json:"attempted_at"`
	Err         string    `json:"err,omitempty"`
}

// snapshotLocked captures the state for writing. Call with mu held.
func (s *Store) snapshotLocked() (uint64, []byte) {
	s.gen++
	p := persisted{Version: persistedVersion}
	for _, st := range s.byTarget {
		ps := persistedState{Ref: st.Ref, Findings: st.Findings, At: st.At, AttemptedAt: st.AttemptedAt}
		if st.Err != nil {
			ps.Err = st.Err.Error()
		}
		p.States = append(p.States, ps)
	}
	sort.Slice(p.States, func(i, j int) bool { return p.States[i].Ref < p.States[j].Ref })
	body, _ := json.MarshalIndent(p, "", "  ")
	return s.gen, body
}

// persist writes a snapshot taken at gen, unless a newer one is already down.
// Called WITHOUT mu held.
func (s *Store) persist(gen uint64, body []byte) {
	if s.path == "" {
		return
	}
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	if gen <= s.written {
		return
	}
	if err := atomicfile.Write(s.path, body, 0o600); err != nil {
		s.persistErr = fmt.Errorf("drift: persisting %s: %w", s.path, err)
		return
	}
	s.written, s.persistErr = gen, nil
}

// Record stores the result of a COMPLETED comparison.
//
// **AN UNKNOWN SEVERITY IS REFUSED, because the vocabulary's zero value is
// "harmless".** `severities` is a map, so a severity nobody registered answers
// false to both `RefusesTarget` and `WithholdsAction` — meaning a typo, or a
// severity a future driver invents, would be recorded and then quietly ignored
// while looking like a finding in every log and every operator surface. That is
// the fail-OPEN direction on a governance signal, so it fails loudly here
// instead. The check belongs at the boundary rather than in the vocabulary,
// because a `Severity` is a string and there is no constructor to hang it on.
func (s *Store) Record(ref string, fs Findings, at time.Time) error {
	for _, f := range fs {
		if !f.Severity.Known() {
			return fmt.Errorf("drift.Record: target %q reported severity %q, which is not "+
				"in the vocabulary %v — an unregistered severity answers false to both "+
				"RefusesTarget and WithholdsAction, so recording it would read as a finding "+
				"and act as nothing", ref, f.Severity, Severities())
		}
	}

	s.mu.Lock()
	s.byTarget[ref] = State{Ref: ref, Findings: fs, At: at, AttemptedAt: at}
	gen, body := s.snapshotLocked()
	s.mu.Unlock()
	s.persist(gen, body)
	return nil
}

// RecordFailure notes that the most recent ATTEMPT failed.
//
// **THE PREVIOUS FINDINGS ARE KEPT, deliberately, and this is the fail-closed
// direction.** If a vendor withdrew a tool and the server then became
// unreachable, clearing the findings would put that capability back in the
// catalog on the strength of a failed check — advertising something we have
// already learned is gone. The state carries `At`, so an operator can see the
// finding is from before the outage rather than being told it is current.
func (s *Store) RecordFailure(ref string, err error, at time.Time) {
	s.mu.Lock()

	st := s.byTarget[ref]
	st.Ref, st.Err, st.AttemptedAt = ref, err, at
	if !st.Checked() {
		// Never compared, so there is nothing to preserve and nothing to imply.
		st.Findings = nil
	}
	// `At` is deliberately NOT advanced: it dates the last COMPARISON, and a
	// failed attempt compared nothing. Advancing it would make a target that
	// has been unreachable for an hour read as freshly verified.
	s.byTarget[ref] = st
	gen, body := s.snapshotLocked()
	s.mu.Unlock()
	s.persist(gen, body)
}

// Of returns one target's state.
func (s *Store) Of(ref string) (State, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st, ok := s.byTarget[ref]
	return st, ok
}

// Withholds reports whether ONE action is withheld for a target.
//
// The per-action question the catalog actually asks, so the caller neither
// builds a set per capability nor has to know that `Withheld` is sorted.
//
// A BOOL AND NOT THE FINDING, because the only caller has nowhere to put one:
// the catalog drops the capability and D197's "named rather than silently
// absent" is discharged on the operator surfaces, which read `States`. Handing
// back a Finding the caller discards would be a signature written for a use
// nobody has.
func (s *Store) Withholds(ref, action string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, f := range s.byTarget[ref].Findings {
		if f.Action == action && f.Severity.WithholdsAction() {
			return true
		}
	}
	return false
}

// States returns every known target's state, sorted by ref.
//
// Sorted because it is rendered — an operator surface whose order changes
// between refreshes is one nobody can diff.
func (s *Store) States() []State {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]State, 0, len(s.byTarget))
	for _, st := range s.byTarget {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}
