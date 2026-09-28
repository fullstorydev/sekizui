package acceptance

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/provider/file"
	"github.com/fullstorydev/sekizui/pkg/provider/oauth"
)

// p3Step42 — the afferent path cannot be turned into a read of the audit log
// (D286). The maintainer's question: "the poller cannot be used to access the audit log
// for nefarious means?"
//
// The poller's own code never touches it — but nothing ENFORCED that, and the
// credential a poll sends turned out to be a read of any file the process
// could open, shipped off-host on the poll's cadence. So two halves: the
// import graph, and what a credential reference may name.
func p3Step42(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the afferent path cannot be turned into a read of the audit log")

	// 42a — NOTHING ON THE AFFERENT PATH CAN REACH THE AUDIT LOG'S CODE,
	// transitively. A direct-import walk (P1 step 43's form) misses a package
	// that reaches auditwal through another; `go list -deps` does not. The
	// driver packages are FOUND, so a connector added tomorrow is covered.
	root := repoRoot(t)
	pkgs := []string{"./internal/kyuushin", "./internal/cursor", "./internal/translate",
		"./pkg/connector", "./pkg/provider/file", "./pkg/provider/oauth", "./pkg/provider/ambient"}
	// THE DRIVER PACKAGES COME FROM `driverPackageDirs` (D316), which fails if a
	// registered driver is not among them: rooted at `internal/driver` alone,
	// this arm kept passing after the connectors moved and checked none of them.
	for _, rel := range driverPackageDirs(t) {
		pkgs = append(pkgs, "./"+rel)
	}
	for _, parent := range []string{"hako"} {
		entries, err := os.ReadDir(filepath.Join(root, parent))
		if err != nil {
			t.Fatalf("step 42a: %v", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				pkgs = append(pkgs, "./"+parent+"/"+e.Name())
			}
		}
	}
	list := exec.Command(goTool(t), append([]string{"list", "-deps", "-f",
		"{{.ImportPath}}"}, pkgs...)...)
	list.Dir = root
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("step 42a: go list: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "/internal/auditwal") {
		t.Errorf("step 42a: a package on the afferent path reaches internal/auditwal. A poller, a "+
			"connector or a credential provider that can load the audit log's code can read it; "+
			"recovery was designed never to need to (D174). Packages checked: %v", pkgs)
	}
	r.detail(t, "%d afferent packages, none reaching internal/auditwal even transitively", len(pkgs))

	// The deployment's shape: secrets mounted under one root, the audit
	// directory beside it, and a root that CONTAINS the audit directory for 42c.
	// CANONICAL, so the arms test the link rule and not the platform: on macOS
	// the temp directory lives under /var, itself a link to /private/var, and a
	// non-canonical base made the "symlinks are not followed" mutation fail at
	// 42b for that reason instead of at 42d for the real one.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secrets := filepath.Join(base, "secrets")
	audit := filepath.Join(base, "wal")
	for _, d := range []string{secrets, audit} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	token := filepath.Join(secrets, "token")
	auditLog := filepath.Join(audit, "audit.jsonl")
	outside := filepath.Join(base, "elsewhere.txt")
	for _, f := range []string{token, auditLog, outside} {
		if err := os.WriteFile(f, []byte("material"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	provider := func(roots ...string) *file.Provider {
		return file.New(file.Roots(roots...), file.Deny(audit))
	}
	refuse := func(p *file.Provider, refs map[string]string) []string {
		doc := &config.Document{}
		for target, ref := range refs {
			doc.Targets = append(doc.Targets, config.TargetSpec{Ref: target, CredentialRef: ref})
		}
		return credential.RefuseUnconfined(doc, []config.Provider{p, oauth.New()})
	}

	// 42b — OUTSIDE EVERY ROOT: THE BOOT REFUSES, CHAINS INCLUDED. The second
	// reference hides the file inside an oauth-cc:// client secret — the cache
	// resolves that inner reference too, so the boot must walk it.
	chained := "oauth-cc://vendor.example/oauth/token?client_id=abc&client_secret=" +
		url.QueryEscape("file://"+outside)
	got := refuse(provider(secrets), map[string]string{
		"fs:plain": "file://" + outside, "fs:chained": chained, "fs:fine": "file://" + token})
	if joined := strings.Join(got, "\n"); len(got) != 2 || !strings.Contains(joined, `"fs:plain"`) ||
		!strings.Contains(joined, `"fs:chained"`) || strings.Contains(joined, `"fs:fine"`) {
		t.Fatalf("step 42b: want exactly fs:plain and fs:chained refused, fs:fine admitted; got %q", got)
	}

	// 42c — THE AUDIT DIRECTORY IS REFUSED EVEN INSIDE A ROOT.
	if got := refuse(provider(base), map[string]string{"fs:audit": "file://" + auditLog}); len(got) != 1 ||
		!strings.Contains(got[0], "no credential may be read from") {
		t.Fatalf("step 42c: a reference to the audit log under a root that contains it was not "+
			"refused: %q", got)
	}

	// 42d — A SYMLINK IS JUDGED BY WHERE IT LANDS, AT BOOT AND AT EVERY READ.
	link := filepath.Join(secrets, "linked")
	if err := os.Symlink(auditLog, link); err != nil {
		t.Fatal(err)
	}
	if got := refuse(provider(secrets), map[string]string{"fs:link": "file://" + link}); len(got) != 1 {
		t.Fatalf("step 42d: a link inside the root pointing at the audit log passed the boot: %q", got)
	}
	swapped := filepath.Join(secrets, "swapped")
	if err := os.Symlink(token, swapped); err != nil {
		t.Fatal(err)
	}
	p := provider(secrets)
	if got := refuse(p, map[string]string{"fs:swap": "file://" + swapped}); len(got) != 0 {
		t.Fatalf("step 42d: an honest link was refused at boot: %q", got)
	}
	// AFTER THE BOOT: somebody with write access inside the root re-points it.
	if err := os.Remove(swapped); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(auditLog, swapped); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Resolve(context.Background(), "file://"+swapped); err == nil {
		t.Fatal("step 42d: a link re-pointed at the audit log AFTER the boot was read. The boot " +
			"check alone is a check on the day it ran; the read must confine again")
	}

	// 42e — NO ROOT: REFUSED, UNLESS THIS IS A BARE DEVELOPER MACHINE. The
	// default of the published provider is the safe one; `main` opts out on
	// bare execution only.
	if got := refuse(file.New(), map[string]string{"fs:any": "file://" + token}); len(got) != 1 ||
		!strings.Contains(got[0], "-file-credential-root") {
		t.Fatalf("step 42e: a file credential with no root declared was admitted by default: %q", got)
	}
	if got := refuse(file.New(file.AllowUnrooted(true), file.Deny(audit)),
		map[string]string{"fs:any": "file://" + token}); len(got) != 0 {
		t.Fatalf("step 42e: the bare-machine opt-out refused an ordinary file: %q", got)
	}
	r.detail(t, "outside a root, chained or not: refused; the audit directory: refused inside a "+
		"root; a link re-pointed after boot: refused at read; no root by default: refused")
}
