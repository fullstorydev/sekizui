package file

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestTheReadIsConfinedNotOnlyTheCheck — D344, deterministically. The race it
// closes is a directory on the resolved path swapped for a symlink out of the
// root BETWEEN confined() and the read; a test cannot win that race on demand,
// so it takes the two halves apart: check, swap, then read what the check
// returned. The read must refuse — before D344 it re-walked the name and
// returned the secret outside the root.
//
// In-package because the gap is between two unexported steps. P6 step 12 shows
// the same property through the public Resolve, racing.
func TestTheReadIsConfinedNotOnlyTheCheck(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "token"), []byte("SECRET-OUTSIDE"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "svc")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := New(Roots(root))
	path, confinedRoot, err := p.confined(Scheme + "://" + filepath.Join(dir, "token"))
	if err != nil {
		t.Fatalf("the reference inside the root was refused: %v", err)
	}

	// THE SWAP: svc/ becomes a link out of the root, after the check passed.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}

	f, err := openConfined(confinedRoot, path)
	if err == nil {
		b, _ := io.ReadAll(f)
		_ = f.Close()
		t.Fatalf("the read followed a link out of the root and returned %q — the check and "+
			"the read are two different walks again", b)
	}
}

// TestKubernetesDataLinksStillResolve — the projected-volume layout D104 reads
// for its posture: `token -> ..data/token`, `..data -> ..2026_09_28/`, all
// inside the mount. os.Root follows links that stay inside, so this must pass.
func TestKubernetesDataLinksStillResolve(t *testing.T) {
	root := t.TempDir()
	stamp := filepath.Join(root, "..2026_09_28_10_00_00.000000001")
	if err := os.Mkdir(stamp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stamp, "token"), []byte("rotated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(stamp), filepath.Join(root, DataLink)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(DataLink, "token"), filepath.Join(root, "token")); err != nil {
		t.Fatal(err)
	}

	got, err := New(Roots(root)).Resolve(context.Background(), Scheme+"://"+filepath.Join(root, "token"))
	if err != nil {
		t.Fatalf("a projected-volume secret was refused: %v", err)
	}
	if string(got.Material) != "rotated" {
		t.Fatalf("material = %q", got.Material)
	}
}
