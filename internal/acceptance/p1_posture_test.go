package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
	filecred "github.com/fullstorydev/sekizui/pkg/provider/file"
)

// projectedVolume builds the structure the kubelet actually creates, not a mock.
//
// A REAL SYMLINK TREE, because the whole detection is one Lstat and a mock would
// assert that the code agrees with the mock. The shape is:
//
//	dir/..2026_08_31_10_00_00/token   the real bytes
//	dir/..data -> ..2026_08_31_10_00_00
//	dir/token  -> ..data/token
//
// The kubelet writes a new timestamped directory and re-points `..data` at it,
// which is what makes the swap atomic — a reader either sees the whole old
// version or the whole new one, never a half-written file.
func projectedVolume(t *testing.T, content string) (dir, secretPath string) {
	t.Helper()

	dir = t.TempDir()
	stamp := "..2026_08_31_10_00_00.123456789"
	if err := os.MkdirAll(filepath.Join(dir, stamp), 0o700); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, stamp, "token"), []byte(content), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.Symlink(stamp, filepath.Join(dir, filecred.DataLink)); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.Symlink(filepath.Join(filecred.DataLink, "token"), filepath.Join(dir, "token")); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return dir, filepath.Join(dir, "token")
}

// rotate re-points ..data at a new timestamped directory, the way the kubelet
// does when a Secret changes.
func rotate(t *testing.T, dir, content string) {
	t.Helper()

	stamp := "..2026_08_31_11_00_00.987654321"
	if err := os.MkdirAll(filepath.Join(dir, stamp), 0o700); err != nil {
		t.Fatalf("rotating: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, stamp, "token"), []byte(content), 0o600); err != nil {
		t.Fatalf("rotating: %v", err)
	}
	// Symlink then rename: os.Symlink refuses an existing name, and the kubelet's
	// swap is atomic for the same reason this one has to be — a reader must never
	// see the link missing.
	tmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink(stamp, tmp); err != nil {
		t.Fatalf("rotating: %v", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, filecred.DataLink)); err != nil {
		t.Fatalf("rotating: %v", err)
	}
}

// step17AProjectedVolumeReportsRotationLive proves D103 and D104's positive arm.
func step17AProjectedVolumeReportsRotationLive(t *testing.T) {
	ctx := context.Background()
	dir, path := projectedVolume(t, "first-token")
	_ = dir

	p := filecred.New(filecred.InKubernetes(true), filecred.Roots(os.TempDir()))
	ref := "file://" + path

	got, err := p.Posture(ref)
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	if got.Rotation != config.RotationLive {
		t.Errorf("rotation = %q, want %q. The ..data link is present, which is how the "+
			"kubelet swaps a Secret's contents — reporting anything else would tell an "+
			"operator their rotation does not work when it does",
			got.Rotation, config.RotationLive)
	}
	if got.AtRest != "k8s-secret" {
		t.Errorf("at_rest = %q, want k8s-secret. This is the column that answers the "+
			"SOPS misconception without anybody needing to know it in advance: helm-secrets "+
			"encrypts version control and leaves the runtime exactly where a plain Secret "+
			"leaves it", got.AtRest)
	}

	// THE CLAIM IS NOT JUST A LABEL. `rotation=live` asserts that a rotation is
	// actually picked up, so the step rotates the volume and reads again — the
	// posture and the behaviour have to agree, or the report is decoration.
	res, err := p.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if string(res.Material) != "first-token" {
		t.Fatalf("at_rest = %q, want first-token", res.Material)
	}

	rotate(t, dir, "second-token")

	res, err = p.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve after rotation: %v", err)
	}
	if string(res.Material) != "second-token" {
		t.Errorf("at_rest = %q after the kubelet re-pointed ..data, want second-token. "+
			"A posture that says `live` while the bytes are stale is worse than no "+
			"report at all", res.Material)
	}

	// AND THE VERSION IS DELIBERATELY EMPTY, which is what makes the rotation
	// invalidate a pooled client: the cache digests the material, so new bytes
	// are a new PoolKey (D99, D123, D130). A provider inventing a stable version
	// here would leave a rotated credential working until TTL expiry.
	if res.Version != "" {
		t.Errorf("Version = %q, want empty. D130 defines empty as \"I cannot tell you\", "+
			"and for a file that is the truth — the cache then digests the content, which "+
			"is what §4.7.2's table means by \"versioned by content\"", res.Version)
	}
}

// step18ASubPathMountReportsRotationNoneAndWarns proves D104's dangerous arm.
//
// THE SILENT FAILURE THIS WHOLE REPORT EXISTS FOR. Kubernetes states it plainly:
// "A container using a ConfigMap as a subPath volume mount will not receive
// updates when the ConfigMap changes", and the same holds for a Secret. So the
// operator rotates, the API server accepts it, every dashboard agrees, and the
// pod presents the old credential until something restarts it.
func step18ASubPathMountReportsRotationNoneAndWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("mounted-once-by-subpath"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	// A subPath mount is an ORDINARY FILE from the container's point of view —
	// no ..data link, no symlink, nothing to distinguish it structurally. Which
	// is exactly why the environment decides how to read the absence.
	inPod := filecred.New(filecred.InKubernetes(true), filecred.Roots(os.TempDir()))
	got, err := inPod.Posture("file://" + path)
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	if got.Rotation != config.RotationNone {
		t.Fatalf("rotation = %q, want %q. In a pod, no ..data link means subPath, and "+
			"Kubernetes does not update those — reporting `live` here is the failure "+
			"D104 was written for", got.Rotation, config.RotationNone)
	}
	// THE WARNING NAMES THE CONSEQUENCE AND THE FIX. "NONE" alone tells an
	// operator they have a problem, not what to do about it, and D104 warns
	// rather than refuses precisely because a static credential is legitimate —
	// what is illegitimate is believing it rotates.
	//
	// MATCHED CASE-INSENSITIVELY, because the assertion is about what the message
	// SAYS and not how it is styled. The first version of this checked for
	// "without subPath" and failed against "WITHOUT subPath" — a test that
	// fails when prose is emphasised differently is a test that gets weakened
	// rather than fixed the second time it happens.
	why := strings.ToLower(got.Why)
	for _, want := range []string{"subpath", "restarts", "without subpath"} {
		if !strings.Contains(why, want) {
			t.Errorf("the reason does not mention %q: %q", want, got.Why)
		}
	}

	// SAME FILE, NOT IN A POD, DIFFERENT AND CORRECT ANSWER. Without this arm
	// the step would pass against a provider that reported NONE for everything,
	// and every developer running locally would be warned that their perfectly
	// ordinary file does not rotate.
	onLaptop := filecred.New(filecred.Roots(os.TempDir()))
	got, err = onLaptop.Posture("file://" + path)
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	if got.Rotation != config.RotationOnChange {
		t.Errorf("rotation = %q on a developer machine, want %q. The absence of a ..data "+
			"link is not definitive on its own — only its PRESENCE is — so a report that "+
			"ignored the environment would cry wolf at every local run, and D77 is the "+
			"cost of that", got.Rotation, config.RotationOnChange)
	}
	if got.AtRest != "static-file" {
		t.Errorf("at_rest = %q, want static-file", got.AtRest)
	}
}
