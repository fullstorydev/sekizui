package credential

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/fullstorydev/sekizui/internal/atomicfile"
	"github.com/fullstorydev/sekizui/pkg/credver"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// MarkFileStore persists D152's high-water marks beside the audit log.
//
// THE SAME SHAPE AS THE CHAIN TAIL (D78) AND THE WITHDRAWAL STORE (D145), and
// for the same reason each time: a piece of state whose loss silently weakens a
// guarantee, small enough that a file is the honest answer rather than a
// dependency bigger than the problem. `<auditPath>.credver`, not a dotfile, so
// an operator archiving with `cp audit.jsonl*` takes it along.
//
// SINGLE-INSTANCE, AND THAT IS THE LIMIT — the third time this note appears in
// this codebase, which is itself the argument for CONTRACTS item 41 being a real
// piece of work rather than a footnote. Two pods keep two files, so a mark set on
// one does not bound the other, and a downgrade refused here would be served
// there. Closing it needs a shared credver.Store, which is why the seam is public.
type MarkFileStore struct {
	path string

	mu sync.Mutex
}

var _ credver.Store = (*MarkFileStore)(nil)

// NewMarkFileStore stores marks at path.
func NewMarkFileStore(path string) *MarkFileStore { return &MarkFileStore{path: path} }

// MarkPathFor derives the sidecar path for an audit log.
//
// ONE CONVENTION, DERIVED IN ONE PLACE — auditwal.TailPathFor's lesson, which
// this codebase paid for once when a helper produced `.audit.tail` while the
// binary wrote `audit.jsonl.tail` inline and nothing broke until somebody used
// the obvious helper.
func MarkPathFor(auditPath string) string { return auditPath + ".credver" }

// Load returns every mark.
func (s *MarkFileStore) Load(_ context.Context) ([]credver.Mark, error) {
	const op = "credential.MarkFileStore.Load"

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		// A FRESH DEPLOYMENT, not an error. Distinguished from a CORRUPT file
		// below, which is: an unreadable set of marks is not evidence that
		// nothing has been seen.
		return nil, nil
	}
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "reading "+s.path, err)
	}

	var marks []credver.Mark
	if err := json.Unmarshal(data, &marks); err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "parsing "+s.path, err)
	}
	return marks, nil
}

// Put records a mark, rewriting the whole set.
//
// TEMP-AND-RENAME, because a truncated file must not be readable as a shorter
// one — D145's reasoning, and here the shorter read is worse than a failed one:
// a missing mark permits the downgrade it was written to refuse.
func (s *MarkFileStore) Put(ctx context.Context, m credver.Mark) error {
	const op = "credential.MarkFileStore.Put"

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.loadLocked(ctx)
	if err != nil {
		return err
	}

	replaced := false
	for i := range existing {
		if existing[i].Ref == m.Ref {
			existing[i] = m
			replaced = true
			break
		}
	}
	if !replaced {
		existing = append(existing, m)
	}

	data, err := json.Marshal(existing)
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "encoding marks", err)
	}

	// SHARED HELPER (D173), and this file is the reason the guard exists rather
	// than an incidental beneficiary of it. The comment above already said this
	// was "THE SAME SHAPE AS THE CHAIN TAIL (D78) AND THE WITHDRAWAL STORE
	// (D145), and for the same reason each time" — the third instance was
	// NOTICED and copied anyway, which is exactly why recognising a repetition in
	// prose is not the same as removing it (D155).
	//
	// The sync it adds is the whole point here: an unsynced rename meant host
	// loss could drop the mark, and this comment's own words are that "a missing
	// mark permits the downgrade it was written to refuse" (D152).
	if err := atomicfile.Write(s.path, data, 0o600); err != nil {
		return fault.Wrap(fault.KindConfig, op, "saving credential version marks", err)
	}
	return nil
}

// loadLocked reads the set with s.mu already held.
func (s *MarkFileStore) loadLocked(_ context.Context) ([]credver.Mark, error) {
	const op = "credential.MarkFileStore.loadLocked"

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "reading "+s.path, err)
	}
	var marks []credver.Mark
	if err := json.Unmarshal(data, &marks); err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "parsing "+s.path, err)
	}
	return marks, nil
}
