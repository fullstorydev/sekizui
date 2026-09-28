package cursor_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/cursor"
)

func TestASourceNeverPolledLoadsTheZeroState(t *testing.T) {
	t.Parallel()
	s := cursor.NewFileStore(t.TempDir())

	st, err := s.Load(context.Background(), "kata:alpha")
	if err != nil {
		t.Fatalf("a source never polled must not be an error: %v", err)
	}
	if st.Cursor != "" || st.Pending != nil {
		t.Errorf("want the zero State, got %+v", st)
	}
}

// A CORRUPT CURSOR MUST NOT READ AS A FRESH ONE. This is the arm with teeth:
// the safe-looking failure is to treat unreadable state as "never polled",
// which re-reads the source from its beginning while reporting success.
func TestACorruptCursorIsAnErrorRatherThanAFreshStart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := cursor.NewFileStore(dir)

	if err := s.Commit(context.Background(), "kata:alpha", "w-100"); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Find the file it wrote and truncate it into invalid JSON.
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("want exactly one cursor file, got %v (%v)", entries, err)
	}
	path := filepath.Join(dir, entries[0].Name())
	if werr := os.WriteFile(path, []byte("{not json"), 0o600); werr != nil {
		t.Fatalf("sabotage: %v", werr)
	}

	_, err = s.Load(context.Background(), "kata:alpha")
	if err == nil {
		t.Fatal("a corrupt cursor loaded cleanly — an empty cursor re-reads the whole source")
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("the message must send the operator to the file, got %q", err)
	}
}

func TestAnAttemptSurvivesAndCommitClearsIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	s := cursor.NewFileStore(dir)

	att := cursor.Attempt{
		From: "w-100", To: "w-200",
		IDs: []string{"e1", "e2", "e3"},
		At:  time.Now().UTC(),
	}
	if err := s.Begin(ctx, "kata:alpha", att); err != nil {
		t.Fatalf("begin: %v", err)
	}

	// A DIFFERENT STORE OVER THE SAME DIRECTORY, because the point is what
	// survives a process rather than what a struct remembers.
	reopened := cursor.NewFileStore(dir)
	st, err := reopened.Load(ctx, "kata:alpha")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if st.Pending == nil {
		t.Fatal("the attempt did not survive — the spine cannot know the last poll did not commit")
	}
	if got := st.Pending.IDs; len(got) != 3 || got[0] != "e1" {
		t.Errorf("the at-risk ids must survive verbatim, got %v", got)
	}
	if st.Pending.From != "w-100" {
		t.Errorf("recovery re-polls From, got %q", st.Pending.From)
	}

	if cerr := reopened.Commit(ctx, "kata:alpha", "w-200"); cerr != nil {
		t.Fatalf("commit: %v", cerr)
	}
	st, err = cursor.NewFileStore(dir).Load(ctx, "kata:alpha")
	if err != nil {
		t.Fatalf("load after commit: %v", err)
	}
	if st.Cursor != "w-200" {
		t.Errorf("cursor did not advance, got %q", st.Cursor)
	}
	if st.Pending != nil {
		t.Errorf("commit must clear the attempt in the same write, got %+v", st.Pending)
	}
}

// TWO SOURCES MUST NOT SHARE A FILE. A collision here is silent
// cross-contamination of the state that decides what gets re-read, which is
// why the escaping is reversible rather than a substitution.
func TestSourcesWithAwkwardRefsDoNotCollide(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	s := cursor.NewFileStore(dir)

	// `a:b` and `a-b` collide under the obvious "replace the colon" scheme.
	for ref, want := range map[string]string{"a:b": "one", "a-b": "two", "a%3Ab": "three"} {
		if err := s.Commit(ctx, ref, want); err != nil {
			t.Fatalf("commit %q: %v", ref, err)
		}
	}
	for ref, want := range map[string]string{"a:b": "one", "a-b": "two", "a%3Ab": "three"} {
		st, err := s.Load(ctx, ref)
		if err != nil {
			t.Fatalf("load %q: %v", ref, err)
		}
		if st.Cursor != want {
			t.Errorf("%q read back %q, want %q — two sources are sharing a cursor file", ref, st.Cursor, want)
		}
	}
}

// THE PERMISSION IS ASSERTED, not assumed. It sits beside decision records and
// names sources; the withdrawal store and the chain tail both use 0600.
func TestTheCursorFileIsNotWorldReadable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := cursor.NewFileStore(dir).Commit(context.Background(), "kata:alpha", "w-1"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("want one file, got %v (%v)", entries, err)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("cursor file is %v, want 0600", got)
	}
}
