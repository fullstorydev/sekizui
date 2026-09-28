package cursor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/internal/atomicfile"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// FileStore keeps one file per source in a directory.
//
// **ONE FILE PER SOURCE, NOT ONE FILE OF ALL SOURCES**, and the difference is
// not filing tidiness. A whole-file rewrite is what makes the atomic-file
// pattern cheap; put every source in one document and each poll rewrites every
// other source's state, so the write cost grows with the number of sources
// rather than staying flat. That is the quadratic shape D240 went looking for
// in the wrong place — it is a property of the LAYOUT, and choosing per-source
// files removes it rather than deferring it to a database.
type FileStore struct {
	dir string

	// mu serialises the read-modify-write in Commit.
	//
	// ONE MUTEX FOR THE WHOLE STORE, not one per source, and that is a
	// deliberate under-engineering: writes happen once per poll per source,
	// which is a rate measured in tens per minute. A per-source lock map would
	// be faster at a scale this component cannot reach before P8's leader
	// election changes the shape entirely (§5.2.3). GO-PRIMER §15u's rule still
	// holds and is what makes this safe — the lock is never held across the
	// poll, only across the file write.
	mu sync.Mutex
}

// NewFileStore returns a store rooted at dir. The directory is created on first
// write by atomicfile, so a fresh deployment needs no setup step.
func NewFileStore(dir string) *FileStore { return &FileStore{dir: dir} }

// Load reads one source's state.
//
// A MISSING FILE IS NOT AN ERROR and a corrupt one is, which is the asymmetry
// D150 asks for: never polled is an ordinary first boot, while unreadable means
// the cursor exists and cannot be trusted — and treating that as "start from
// the beginning" would silently re-ingest an entire table while reporting
// success.
func (s *FileStore) Load(ctx context.Context, source string) (State, error) {
	_ = ctx
	return s.read(source)
}

// read is the lock-free body of Load.
//
// **SEPARATE FROM `Load` BECAUSE `Begin` NEEDS IT UNDER THE LOCK**, and calling
// the exported method there would be GO-PRIMER §15af's deadlock waiting for
// somebody to add a lock to `Load` — which is a reasonable thing for a future
// reader to do, since every other method here takes one. It is safe today and
// safe by accident; this makes it safe by construction.
//
// Load itself takes NO lock, and that is correct rather than an oversight:
// atomicfile renames into place, so a concurrent reader sees the whole old file
// or the whole new one. A mutex would buy nothing and would suggest the file
// could be seen half-written.
func (s *FileStore) read(source string) (State, error) {
	const op = "cursor.FileStore.read"

	data, err := os.ReadFile(s.path(source))
	switch {
	case os.IsNotExist(err):
		return State{}, nil
	case err != nil:
		return State{}, fault.Wrap(fault.KindInternal, op, "reading cursor for "+source, err)
	}

	var st State
	if uerr := json.Unmarshal(data, &st); uerr != nil {
		// KindConfig, not KindInternal: the operator's remedy is to look at the
		// file, and the boot message should send them there rather than reading
		// as a bug in Sekizui.
		return State{}, fault.Wrap(fault.KindConfig, op,
			"cursor for "+source+" is unreadable — a source that cannot say where it "+
				"stopped must not be started, because an empty cursor re-reads the source "+
				"from its beginning", uerr)
	}
	return st, nil
}

// Begin records an attempt before its events are published.
//
// It REPLACES the whole state rather than appending, and a second Begin
// overwrites the first. That is correct and worth saying: two uncommitted
// attempts for one source cannot happen while the poller is single-writer per
// source, and if it ever does the newer attempt is the one whose ids are at
// risk.
func (s *FileStore) Begin(ctx context.Context, source string, a Attempt) error {
	const op = "cursor.FileStore.Begin"
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = ctx
	st, err := s.read(source)
	if err != nil {
		return err
	}
	st.Pending = &a
	return s.saveLocked(op, source, st)
}

// Progress records how many of the pending attempt's ids are published (D275).
// Refused without a pending attempt: progress on nothing is a caller bug that
// would otherwise be written down as a fact.
func (s *FileStore) Progress(ctx context.Context, source string, published int) error {
	const op = "cursor.FileStore.Progress"
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = ctx
	st, err := s.read(source)
	if err != nil {
		return err
	}
	if st.Pending == nil {
		return fault.New(fault.KindInternal, op, "progress recorded for "+source+
			" with no attempt pending")
	}
	st.Pending.Published = published
	return s.saveLocked(op, source, st)
}

// Commit advances the cursor and clears the pending attempt in ONE write.
//
// Two writes — advance, then clear — would leave a crash between them holding a
// state with both a new cursor and a stale attempt, which means "we finished
// and also did not", and nothing downstream could act on it. One replacement
// makes that state unrepresentable rather than merely unlikely.
func (s *FileStore) Commit(ctx context.Context, source string, cursor string) error {
	const op = "cursor.FileStore.Commit"
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = ctx
	// **THE POLL TIME SURVIVES THE COMMIT (CONTRACTS 134).** This wrote a fresh
	// `State{Cursor: cursor}`, which was exactly right while the state held
	// only a cursor and an attempt — and would have wiped LastPoll on every
	// productive poll the moment it was added.
	st, err := s.read(source)
	if err != nil {
		return err
	}
	return s.saveLocked(op, source, State{Cursor: cursor, LastPoll: st.LastPoll})
}

// Polled records when a scheduled poll of source started (CONTRACTS 134),
// keeping the cursor and any pending attempt exactly as they were.
func (s *FileStore) Polled(ctx context.Context, source string, at time.Time) error {
	const op = "cursor.FileStore.Polled"
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = ctx
	st, err := s.read(source)
	if err != nil {
		return err
	}
	st.LastPoll = at.UTC()
	return s.saveLocked(op, source, st)
}

func (s *FileStore) saveLocked(op, source string, st State) error {
	out, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "encoding cursor for "+source, err)
	}
	// 0600, matching the withdrawal store and the chain tail: not a secret, and
	// it names sources and sits beside decision records with that sensitivity.
	if werr := atomicfile.Write(s.path(source), out, 0o600); werr != nil {
		return fault.Wrap(fault.KindInternal, op, "saving cursor for "+source, werr)
	}
	return nil
}

// path maps a source ref to a filename.
//
// **REVERSIBLE ESCAPING, NOT A HASH AND NOT A SUBSTITUTION.** A source ref is
// `kata:alpha` — shaped like a target ref, and refs may carry characters a
// filesystem dislikes. The three obvious answers are all worse:
//
//   - a hash gives opaque filenames, so an operator diagnosing a stuck poller
//     cannot find the file for the source they are looking at;
//   - replacing `:` with `-` COLLIDES with any ref that already contains `-`,
//     and two sources sharing a cursor file is silent cross-contamination of
//     exactly the state that decides what gets re-read;
//   - refusing awkward refs moves a filesystem detail into the config
//     vocabulary.
//
// Percent-escaping every byte outside a safe set is reversible, collision-free
// because `%` is itself escaped, and leaves the common case readable —
// `kata%3Aalpha.json`.
func (s *FileStore) path(source string) string {
	var b strings.Builder
	for i := 0; i < len(source); i++ {
		c := source[i]
		safe := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
		if safe {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return filepath.Join(s.dir, b.String()+".json")
}
