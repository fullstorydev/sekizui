package archcheck_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoAdHocAtomicWrites stops the pattern being reimplemented a third time.
//
// **THE THIRD COPY IS THE ONE THIS PREVENTS, and two already existed** (CONTRACTS
// 71, D173). `auditwal.FileTailStore.Save` and the pool's withdrawal store each
// wrote a temp file and renamed it into place, with near-identical rationale
// comments — and NEITHER called Sync, so both were durable against a process
// crash and not against host loss. Two independent authors reached for the same
// shape and made the same omission, which is the argument for a guard rather
// than for a code review: the pattern LOOKS complete without the sync, and the
// case it fails is the one nobody tests.
//
// Deliberately crude, in the same spirit as the provider conformance guard: a
// file that mentions both `os.Rename` and a `.tmp` path is doing this by hand.
// Parsing the AST to decide whether the rename is really an atomic replace would
// be more precise and would not have been written.
//
// NOT A SECURITY GUARANTEE IN ITSELF, so it owes no mutation (D162) — but what
// it protects is one: D145 makes a withdrawal durable so that inducing a restart
// cannot clear it, and an unsynced rename leaves host loss as a way to clear it.
func TestNoAdHocAtomicWrites(t *testing.T) {
	root := repoRootFor(t)

	// Three exemptions, and all are the file DESCRIBING the rule rather than
	// breaking it: the implementation, this guard, whose error message has to
	// name the pattern it forbids — and P6 step 12 (D344), which PLANTS a link at
	// the old `.tmp` name and swaps directories by rename to prove that neither
	// works any more. Named as one file, not its package, so the rest of the
	// acceptance suite stays guarded.
	exempt := []string{"internal/atomicfile", "internal/archcheck", "internal/acceptance/p6_security_test.go"}

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "bin", "out", ".gocache", "dev":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		for _, ex := range exempt {
			if strings.HasPrefix(filepath.ToSlash(rel), ex) {
				return nil
			}
		}

		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		src := string(b)
		// Both shapes of a hand-rolled temp-and-rename: the fixed `.tmp` name,
		// and CreateTemp (atomicfile's own shape since D344, still missing the
		// two fsyncs when written by hand).
		if strings.Contains(src, "os.Rename(") &&
			(strings.Contains(src, `.tmp"`) || strings.Contains(src, "os.CreateTemp(")) {
			offenders = append(offenders, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("%d file(s) implement an atomic write by hand:\n  %s\n\n"+
			"Use internal/atomicfile.Write. The hand-rolled form is not durable — "+
			"os.WriteFile returns before the bytes reach the disk, and the rename is "+
			"buffered directory metadata — so a power failure can revert a withdrawal "+
			"somebody was told had been recorded (CONTRACTS 71, D145, D173).",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// repoRootFor returns the module root.
//
// A second name for repoRoot, twenty lines away in a sibling file (D185). The implementation is docref.Root.
func repoRootFor(t *testing.T) string {
	t.Helper()
	return mustRoot(t)
}
