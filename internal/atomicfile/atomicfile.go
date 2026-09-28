// Package atomicfile replaces a file's contents durably, or not at all.
//
// **THIS EXISTS BECAUSE THE PATTERN WAS ALREADY HERE TWICE AND WRONG BOTH
// TIMES** (CONTRACTS 71, D173). `auditwal.FileTailStore.Save` and the pool's
// withdrawal store both wrote a temp file and renamed it into place, carrying
// near-identical rationale comments — and neither called `Sync`, so both were
// durable against a process crash and not against host loss. P3's cursor store
// would have been the third copy of the same near-miss.
//
// # What "durable" costs, and why os.WriteFile is not enough
//
// `os.WriteFile` returns once the kernel has the bytes, not once the disk does.
// `os.Rename` is ATOMIC — a reader sees the old contents or the new ones, never
// a half-written file — but atomicity is not durability, and the two are easy to
// conflate because the failure that distinguishes them is rare and total.
//
// The full sequence, and every step earns its place:
//
//  1. write the temp file
//  2. **fsync the temp file** — otherwise the rename can be on disk while the
//     contents it points at are not, and the file comes back EMPTY
//  3. rename into place
//  4. **fsync the directory** — the rename itself is metadata, and metadata is
//     buffered like anything else
//
// # Why this matters more than a file-handling detail
//
// D145 makes a withdrawal durable specifically so that inducing a restart is not
// a way to clear it, and D148 names the same hazard for grant suspensions:
// "anything that can induce a restart holds a REINSTATE-EVERYONE primitive
// dressed as remediation". Host loss is a narrower trigger than a restart and it
// is the same shape of attack, so a break-glass record that evaporates on power
// failure is a security property with a hole in it rather than a robustness
// nicety.
//
// # The honest limit
//
// fsync tells the kernel to flush; a lying disk controller with a volatile write
// cache can still acknowledge and lose the write. Go's `File.Sync` uses
// `F_FULLFSYNC` on darwin, which asks the drive to flush its own cache, and on
// Linux it is `fsync(2)` with the usual caveats. This is the strongest guarantee
// available from userspace and it is not an absolute one — the same shape of
// honesty `Secret.Wipe` states about the garbage collector.
//
// DESIGN.md references: §5.2.2, D53, D78, D145, D148, D155, D173, D344.
package atomicfile

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// dirPerm is the mode for a directory created on the way to the file.
//
// 0700 rather than 0755, taken from the stricter of the two call sites this
// replaced: these directories hold decision records, chain tails and
// withdrawals, which name principals, targets and the operators who withdrew
// them.
const dirPerm fs.FileMode = 0o700

// Write replaces path's contents with data, durably.
//
// The file is either fully replaced or untouched, and on return the replacement
// has reached the disk rather than the page cache.
//
// perm applies to the FINAL file, set exactly (not masked by umask) on the open
// handle before the rename. The temp file is born 0600, so the contents are
// never briefly world-readable — which they would be if the temp file took the
// default and the mode were fixed after the rename.
func Write(path string, data []byte, perm fs.FileMode) error {
	const op = "atomicfile.Write"

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fault.Wrap(fault.KindInternal, op, "creating "+dir, err)
	}

	// SAME DIRECTORY, deliberately. Rename is only atomic within one
	// filesystem, so a temp file in os.TempDir() would silently degrade to a
	// copy across a mount boundary — and the degradation is invisible until the
	// crash it was supposed to survive.
	//
	// **A FRESH NAME, CREATED EXCLUSIVELY (D344).** This was `path + ".tmp"`,
	// opened with O_CREATE|O_TRUNC — which FOLLOWS a symlink. Anyone able to
	// write into the directory could plant `<file>.tmp` pointing at any file
	// this process may write, and the next durable write truncated and
	// overwrote it: the audit chain tail, a withdrawal, a cursor. CreateTemp
	// opens O_EXCL under a random suffix, so there is no predictable name to
	// plant and an existing entry of any kind is never opened. Found by the scanner's
	// SAST scan (2026-09-28); the fix is the one assume-compromise asks for.
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "creating a temp file in "+dir, err)
	}
	tmp := f.Name()

	// CLEAN UP ON EVERY FAILURE PATH, or a crashed write leaves a stale temp
	// file behind — harmless to correctness now that every write takes a fresh
	// name, and exactly the kind of residue that makes a directory unreadable
	// during an incident.
	fail := func(what string, cause error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fault.Wrap(fault.KindInternal, op, what, cause)
	}

	// ON THE HANDLE, not the path: a path-based chmod would follow whatever the
	// name points at by the time it runs.
	if err := f.Chmod(perm); err != nil {
		return fail("setting the mode of "+tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		return fail("writing "+tmp, err)
	}
	// STEP 2. Without this the rename below can be durable while the bytes it
	// names are not, and the file comes back empty after a power loss.
	if err := f.Sync(); err != nil {
		return fail("syncing "+tmp, err)
	}
	if err := f.Close(); err != nil {
		return fail("closing "+tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fault.Wrap(fault.KindInternal, op, "renaming into place", err)
	}

	// STEP 4. The rename is a directory-metadata change, buffered like any
	// other. Skipping this leaves a window where the OLD file is on disk, the
	// new one is in the page cache, and a crash reverts a withdrawal somebody
	// was told had been recorded.
	//
	// A directory is opened read-only and synced; that is portable across the
	// platforms this ships on. The error is RETURNED rather than ignored,
	// because a silent partial guarantee is what this package exists to end.
	d, err := os.Open(dir)
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "opening "+dir+" to sync", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fault.Wrap(fault.KindInternal, op, "syncing "+dir, err)
	}
	return nil
}
