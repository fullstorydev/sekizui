package pool

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/fullstorydev/sekizui/internal/atomicfile"
	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/withdrawal"
)

// FileStore persists withdrawals beside the audit log.
//
// THE SAME SHAPE AS THE CHAIN TAIL (D78), and for the same reason: a piece of
// state whose loss silently weakens a guarantee, small enough that a file is the
// honest answer and an external dependency would be a bigger promise than the
// problem needs. `<auditPath>.withdrawn` rather than a dotfile, so an operator
// archiving with `cp audit.jsonl*` takes it along — the tail store's own note,
// applied to the other thing that must travel with the log.
//
// SINGLE-INSTANCE, AND THAT IS THE LIMIT. This makes a withdrawal survive a
// RESTART, which is what D133 already promised. It does NOT make one survive
// across replicas: two pods each keep their own file, so a revocation on one
// leaves the other serving. That is a hole in break-glass rather than a
// performance characteristic (§5.1's "no shared mutable state" claim is what
// break-glass invalidated), and closing it needs a shared withdrawal.Store —
// which is why the seam is public.
type FileStore struct {
	path string
	mu   sync.Mutex
}

var _ withdrawal.Store = (*FileStore)(nil)

// NewFileStore stores withdrawals at path.
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

// WithdrawnPathFor derives the sidecar path for an audit log.
//
// ONE CONVENTION, declared here rather than built inline at the wiring site —
// the tail store learned that lesson the expensive way: two internally
// consistent conventions existed at once, and nothing broke until somebody used
// the helper to read a file the running binary had never written.
func WithdrawnPathFor(auditPath string) string { return auditPath + ".withdrawn" }

// Load returns every withdrawal in force.
//
// A MISSING FILE IS NOT AN ERROR — that is a first boot, or a deployment that
// has never revoked anything. A file that exists and cannot be PARSED is an
// error, and deliberately so: the alternative is starting with an empty
// withdrawal set, which silently restores every revoked credential. That is
// precisely the attack D133 refused, and it must not arrive through a corrupt
// file being treated as an absent one.
func (s *FileStore) Load(_ context.Context) ([]withdrawal.Record, error) {
	const op = "pool.FileStore.Load"

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "reading "+s.path, err)
	}

	var records []withdrawal.Record
	if uerr := json.Unmarshal(data, &records); uerr != nil {
		return nil, fault.Wrap(fault.KindConfig, op,
			"withdrawal store "+s.path+" is unreadable. Refusing to start rather than "+
				"treating it as empty: an empty set means every revoked credential is "+
				"live again, and a corrupt file is not evidence that nothing was "+
				"revoked", uerr)
	}
	return records, nil
}

// Put records a withdrawal durably.
func (s *FileStore) Put(ctx context.Context, r withdrawal.Record) error {
	return s.mutate(ctx, func(in []withdrawal.Record) []withdrawal.Record {
		for i := range in {
			if in[i].TargetRef == r.TargetRef {
				in[i] = r // re-withdrawing escalates severity; keep the latest
				return in
			}
		}
		return append(in, r)
	})
}

// Delete lifts one, and is reached only by `sekizui.restore_target` (D133).
func (s *FileStore) Delete(ctx context.Context, targetRef string) error {
	return s.mutate(ctx, func(in []withdrawal.Record) []withdrawal.Record {
		out := in[:0]
		for _, r := range in {
			if r.TargetRef != targetRef {
				out = append(out, r)
			}
		}
		return out
	})
}

// mutate is read-modify-write under the lock, then an atomic rename.
//
// WRITE TO A TEMPORARY FILE AND RENAME, as the chain tail does. A partial write
// here is worse than a partial write of the tail: a truncated JSON array fails
// to parse, and Load then refuses to boot — which is the safe direction, but it
// turns a revocation into an outage. Rename is atomic on one filesystem, so the
// file is either the old set or the new one.
func (s *FileStore) mutate(ctx context.Context, fn func([]withdrawal.Record) []withdrawal.Record) error {
	const op = "pool.FileStore.mutate"

	s.mu.Lock()
	defer s.mu.Unlock()

	var records []withdrawal.Record
	data, err := os.ReadFile(s.path)
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return fault.Wrap(fault.KindInternal, op, "reading "+s.path, err)
	default:
		if uerr := json.Unmarshal(data, &records); uerr != nil {
			return fault.Wrap(fault.KindConfig, op, "existing store is unreadable", uerr)
		}
	}

	out, merr := json.MarshalIndent(fn(records), "", "  ")
	if merr != nil {
		return fault.Wrap(fault.KindInternal, op, "encoding withdrawals", merr)
	}

	// 0600: not a secret, but it names targets and the principals who withdrew
	// them, beside decision records with the same sensitivity.
	//
	// SHARED HELPER (D173), and here the sync it adds is load-bearing rather than
	// tidy: D145 makes a withdrawal durable precisely so that inducing a restart
	// is not a way to clear it, and an unsynced rename left host loss as a way to
	// clear it — the same attack with a narrower trigger.
	if werr := atomicfile.Write(s.path, out, 0o600); werr != nil {
		return fault.Wrap(fault.KindInternal, op, "saving withdrawals", werr)
	}
	_ = ctx
	return nil
}
