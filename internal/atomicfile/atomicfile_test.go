package atomicfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fullstorydev/sekizui/internal/atomicfile"
)

// TestWriteReplacesAndLeavesNoResidue covers the properties a caller relies on:
// the content lands, the mode is what was asked for, and nothing is left behind.
//
// The temp file matters more than it looks. A stale `.tmp` beside a chain tail
// or a withdrawal store is the sort of thing that makes somebody hesitate during
// an incident, and hesitation is the cost this package's callers cannot afford.
func TestWriteReplacesAndLeavesNoResidue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := atomicfile.Write(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := atomicfile.Write(path, []byte(`{"v":2}`), 0o600); err != nil {
		t.Fatalf("replacing: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if string(got) != `{"v":2}` {
		t.Errorf("content is %q; the replacement did not land", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode is %v, want 0600. The temp file carries the final mode "+
			"deliberately, so the contents are never briefly world-readable", perm)
	}

	if left := tempResidue(t, filepath.Dir(path)); len(left) > 0 {
		t.Errorf("temp file(s) survived a successful write: %v", left)
	}
}

// TestWriteCreatesMissingDirectories — a cursor store or a withdrawal store may
// be the first thing to touch its directory on a fresh deployment, and failing
// there would turn an empty disk into a boot failure.
func TestWriteCreatesMissingDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "state")
	if err := atomicfile.Write(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write into a missing directory tree: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

// TestWriteFailsCleanly. The failure path has to be exercised, not assumed —
// this package exists because two call sites had a silent partial guarantee, and
// a cleanup that only runs in the happy path is the same species of defect.
//
// **THE FIRST VERSION OF THIS TEST WAS WRONG IN A WAY WORTH KEEPING.** It made
// MkdirAll fail by putting a regular file where a directory belonged, then
// asserted no temp file remained — but nothing had been created that far, so it
// was asserting the absence of something that was never going to exist, and it
// FAILED anyway because stat through a non-directory returns ENOTDIR rather than
// ENOENT and `os.IsNotExist` is false for it. A test that cannot fail for the
// right reason and does fail for the wrong one.
//
// A failing RENAME is the reachable version: the temp file is written, synced and
// closed, and the rename then fails because the destination is a non-empty
// directory. That exercises the cleanup that actually matters.
func TestWriteFailsCleanly(t *testing.T) {
	dir := t.TempDir()

	// The destination is a NON-EMPTY DIRECTORY, so rename cannot replace it.
	dest := filepath.Join(dir, "state")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatalf("setting up: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatalf("setting up: %v", err)
	}

	if err := atomicfile.Write(dest, []byte("replacement"), 0o600); err == nil {
		t.Fatal("writing over a non-empty directory succeeded; it must refuse")
	}

	if left := tempResidue(t, dir); len(left) > 0 {
		t.Errorf("temp file(s) survived a failed write: %v. A stale temp file "+
			"beside a chain tail or a withdrawal store is what makes somebody "+
			"hesitate during an incident", left)
	}
}

// tempResidue lists the directory's temp files. Every write takes a FRESH name
// (D344), so absence is checked by pattern: a check for the old fixed `.tmp`
// name would pass forever while checking nothing.
func tempResidue(t *testing.T, dir string) []string {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(dir, "*.tmp-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return left
}

// TestWriteDoesNotFollowAPlantedTempName — D344. The temp file was `path+".tmp"`,
// opened O_CREATE|O_TRUNC, which follows a symlink: whoever could write the
// directory planted the link and the next durable write truncated its target.
// The plant here is the old name, pointing at a file that must survive.
func TestWriteDoesNotFollowAPlantedTempName(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("not yours"), 0o600); err != nil {
		t.Fatalf("setting up: %v", err)
	}
	path := filepath.Join(dir, "tail")
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatalf("planting: %v", err)
	}

	if err := atomicfile.Write(path, []byte("chain tail"), 0o600); err != nil {
		t.Fatalf("write beside a planted link: %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "not yours" {
		t.Fatalf("the planted link's target now reads %q — the write followed it", got)
	}
	if got, _ := os.ReadFile(path); string(got) != "chain tail" {
		t.Fatalf("the destination reads %q", got)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("the destination is not a regular file: %v %v", fi, err)
	}
}

// TestWriteSetsTheModeExactly — the mode is set on the handle, so a permissive
// umask cannot widen it and a restrictive one cannot narrow a 0640 caller.
func TestWriteSetsTheModeExactly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := atomicfile.Write(path, []byte("x"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode is %v, want 0640", perm)
	}
}

// TestRefusesWhenTheDirectoryCannotBeCreated is the other failure, split out
// because it stops EARLIER — no temp file is ever created, so there is nothing
// to assert about residue and pretending otherwise was the first version's bug.
func TestRefusesWhenTheDirectoryCannotBeCreated(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("in the way"), 0o600); err != nil {
		t.Fatalf("setting up: %v", err)
	}
	if err := atomicfile.Write(filepath.Join(blocker, "state"), []byte("x"), 0o600); err == nil {
		t.Fatal("writing under a regular file succeeded; it must refuse")
	}
}
