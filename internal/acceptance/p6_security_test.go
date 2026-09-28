package acceptance

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/atomicfile"
	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
	"github.com/fullstorydev/sekizui/pkg/provider/file"
)

// p6Step12 — D343 and D344, THE SECURITY BEST-PRACTICES HOTFIX, filed as P6 step 12
// the way D340 was filed as step 9 (D341): landed on the unreleased v1 after the scanner's
// dependency and SAST scans, and here so it is not hidden and `make mutate` sees it.
//
// FOUR ARMS, EACH THE PROPERTY RATHER THAN THE PATCH. The probe endpoints'
// nosniff header (the fifth fix) lives in package main, which this package cannot
// import; `cmd/sekizui`'s TestProbesAreUnsniffablePlainText holds it, and the
// mutation harness cannot see a unit test (CONTRACTS 107) — said, not hidden.
//
// NO RUNNING INSTANCE: every arm is a property of the code and the tree, so the
// step runs the same in-process and against `make demo`, and narrates nothing a
// remote instance could show.
func p6Step12(t *testing.T) {
	t.Run("a_durable_write_does_not_follow_a_planted_temp_name", p6Step12PlantedName)
	t.Run("a_file_credential_is_read_through_its_root", p6Step12ConfinedRead)
	t.Run("the_insecure_test_client_refuses_below_tls_1_3", p6Step12TLSFloor)
	t.Run("the_dependency_floor_carries_the_cve_fixes", p6Step12DependencyFloor)
}

// p6Step12PlantedName — atomicfile wrote `path+".tmp"` O_CREATE|O_TRUNC, which
// follows a symlink: whoever could write the directory planted the link, and the
// next durable write (a chain tail, a withdrawal, a cursor) truncated its target.
func p6Step12PlantedName(t *testing.T) {
	dir, elsewhere := t.TempDir(), t.TempDir()
	victim := filepath.Join(elsewhere, "not-sekizuis")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	tail := filepath.Join(dir, "chain.tail")
	if err := os.Symlink(victim, tail+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Write(tail, []byte("deadbeef"), 0o600); err != nil {
		t.Fatalf("a durable write beside a planted link failed: %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Fatalf("the link planted at %s.tmp was followed: its target now reads %q (D344)", tail, got)
	}
	if got, _ := os.ReadFile(tail); string(got) != "deadbeef" {
		t.Fatalf("the chain tail reads %q", got)
	}
}

// p6Step12ConfinedRead — the confinement check resolved a NAME and the read
// re-walked it, so a directory swapped for a link out of the root between the
// two sent a file from outside every root off-host. This arm RACES that swap
// through the public Resolve; the deterministic proof, check and read taken
// apart, is pkg/provider/file's TestTheReadIsConfinedNotOnlyTheCheck.
//
// Every resolution may succeed (the directory was real) or be refused (it was a
// link); the one outcome that must never happen is the outside secret.
func p6Step12ConfinedRead(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "token"), []byte("SECRET-OUTSIDE-THE-ROOT"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := filepath.Join(root, "svc")
	real, link := filepath.Join(root, "svc.real"), filepath.Join(root, "svc.link")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "token"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	// svc starts as the real directory. The swapper moves the two entries in and
	// out of svc by rename, so svc is always one or the other, never absent.
	if err := os.Rename(real, svc); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = os.Rename(svc, real) // the directory out…
			_ = os.Rename(link, svc) // …the link in
			_ = os.Rename(svc, link) // the link out…
			_ = os.Rename(real, svc) // …the directory back
		}
	}()

	p := file.New(file.Roots(root))
	ref := file.Scheme + "://" + filepath.Join(svc, "token")
	var served, refused int
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		res, err := p.Resolve(context.Background(), ref)
		if err != nil {
			refused++
			continue
		}
		served++
		if strings.Contains(string(res.Material), "OUTSIDE") {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("after %d reads, Resolve returned the file OUTSIDE the root: the check and the "+
				"read walked the path separately, and a swap between them escaped (D344)", served+refused)
		}
	}
	stop.Store(true)
	wg.Wait()
	if served == 0 {
		t.Fatalf("no read was served in %d attempts — the race never exercised the read, so this "+
			"arm proved nothing", refused)
	}
	t.Logf("%d reads served from inside the root and %d refused while svc/ was swapped; none escaped",
		served, refused)
}

// p6Step12TLSFloor — the conformance suite's client turns verification off for
// httptest's self-signed certificates; it need not also accept every version.
func p6Step12TLSFloor(t *testing.T) {
	tr, ok := conformance.InsecureClient().Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatal("InsecureClient has no TLS configuration to inspect")
	}
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS13 {
		t.Fatalf("InsecureClient accepts TLS below 1.3 (MinVersion %#x) (D344)", tr.TLSClientConfig.MinVersion)
	}
}

// p6Step12DependencyFloor — D343, read from go.mod as it is committed: the
// fixed versions the scanner named are required, the language floor HELD at 1.25.0
// (the lowest fixed versions keep it; @latest would have raised it), and
// the toolchain line suggests the patched standard library. And the CI workflow
// is on the setup-go that installs that line.
func p6Step12DependencyFloor(t *testing.T) {
	mod := mustText(t, mustDoc(t, "go.mod"))
	for module, floor := range map[string]string{
		"google.golang.org/grpc": "v1.83.1", // three findings, fixed in 1.83.1
		"golang.org/x/net":       "v0.55.0", // the idna Punycode bypass and one more
		"golang.org/x/mod":       "v0.40.0", // two findings, test-only reach
	} {
		m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(module) + `\s+(v\S+)`).FindStringSubmatch(mod)
		if m == nil {
			t.Errorf("go.mod requires no %s", module)
			continue
		}
		if semverLess(m[1], floor) {
			t.Errorf("go.mod requires %s %s, below %s — the version carrying the CVE fix (D343)", module, m[1], floor)
		}
	}
	if !regexp.MustCompile(`(?m)^go 1\.25\.0$`).MatchString(mod) {
		t.Errorf("go.mod's language floor is no longer `go 1.25.0`. D343 held it deliberately; moving " +
			"it locks out every self-hoster and importer below the new floor, so it is a decision, not a tidy")
	}
	if !regexp.MustCompile(`(?m)^toolchain go1\.26\.\d+$`).MatchString(mod) {
		t.Errorf("go.mod suggests no patched toolchain: the standard library's vendored idna is " +
			"reachable only by a toolchain, and `toolchain go1.26.x` is how go.mod asks for one (D343)")
	}
	if wf := mustText(t, mustDoc(t, ".github/workflows/verify.yml")); !strings.Contains(wf, "actions/setup-go@v6") {
		t.Errorf("verify.yml is not on actions/setup-go@v6 — v5 ignores the toolchain line and builds CI " +
			"with go 1.25.0 exactly, the floor with none of its security releases (D343)")
	}
}

// semverLess compares vMAJOR.MINOR.PATCH. go.mod's own requirements only: no
// pre-release or build suffixes appear there for these modules.
func semverLess(a, b string) bool {
	parse := func(v string) [3]int {
		var out [3]int
		for i, part := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
			n, err := strconv.Atoi(strings.SplitN(part, "-", 2)[0])
			if err != nil {
				panic(fmt.Sprintf("unparseable version %q", v))
			}
			out[i] = n
		}
		return out
	}
	pa, pb := parse(a), parse(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}
