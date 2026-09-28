package auditwal

import (
	"encoding/hex"
	"os"
	"strings"
	"sync"

	"github.com/fullstorydev/sekizui/internal/atomicfile"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// FileTailStore persists the chain tail beside the audit log.
//
// A SEPARATE FILE, not the last line of the log. Reading the tail from the log
// would mean parsing and re-hashing the final record at every boot — and would
// trust the very file whose integrity the tail exists to prove.
//
// Hex rather than raw bytes so an operator can compare it against a
// VerifyChain error by eye. The file is tiny and rewritten per record; that is
// affordable because the audit path already fsyncs a full record on the same
// write.
type FileTailStore struct {
	path string

	mu sync.Mutex
}

// NewFileTailStore stores the tail at path.
func NewFileTailStore(path string) *FileTailStore {
	return &FileTailStore{path: path}
}

// TailPathFor derives the sidecar path for an audit log.
//
// ONE CONVENTION, AND THIS IS IT. There were briefly two: this helper produced a
// hidden `.audit.tail` while cmd/sekizui built `audit.jsonl.tail` inline and
// never called the helper. Both were internally consistent, so nothing broke —
// until someone used the obvious helper and read a tail the running binary had
// never written.
//
// `<auditPath>.tail` rather than a dotfile, deliberately: the tail is what makes
// the chain tamper-evident across restarts, and an operator archiving the log
// with `cp audit.jsonl*` must not silently leave it behind. A hidden file is the
// wrong shape for something that has to travel with its log.
func TailPathFor(auditPath string) string {
	return auditPath + ".tail"
}

// Load returns the persisted tail, or nil when there is none.
func (f *FileTailStore) Load() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		return nil, nil // a fresh chain, not an error
	}
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, "auditwal.FileTailStore.Load",
			"reading chain tail "+f.path, err)
	}

	h, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, "auditwal.FileTailStore.Load",
			"chain tail "+f.path+" is not hex", err)
	}
	return h, nil
}

// Save writes the tail durably.
//
// WRITE TO A TEMPORARY FILE AND RENAME. A partial write of the tail would leave
// a hash that matches nothing, and every subsequent verification would report
// tampering on a file nobody touched. Rename is atomic on the same filesystem,
// so the tail is either the old value or the new one.
func (f *FileTailStore) Save(hash []byte) error {
	const op = "auditwal.FileTailStore.Save"

	f.mu.Lock()
	defer f.mu.Unlock()

	// 0600: the tail is not a secret, but it sits beside decision records that
	// carry principals, actions, and targets.
	//
	// SHARED HELPER, NOT A LOCAL WRITE-AND-RENAME (D173). This was one of the two
	// copies that motivated it, and neither synced — so the tail survived a
	// process crash and not a power failure, which is the case D78's
	// tamper-evidence argument actually cares about.
	if err := atomicfile.Write(f.path, []byte(hex.EncodeToString(hash)), 0o600); err != nil {
		return fault.Wrap(fault.KindInternal, op, "saving the chain tail", err)
	}
	return nil
}
