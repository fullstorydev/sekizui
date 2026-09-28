package acceptance

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/ledger"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// TestBootDisclosuresAreVisible is the POSITIVE twin of
// TestBootRefusalsAreVisible (D188).
//
// **`demo-refusals` COVERS ONLY HALF OF BOOT.** It drives the real binary
// against deliberately broken configurations and watches each refusal, which is
// the whole shape D115 asks for — and it is structurally incapable of checking
// what a SUCCESSFUL boot says, because a refused boot never gets that far.
// Nothing read the output of a good boot at all.
//
// **THAT GAP WAS NAMED BEFORE IT WAS CLOSED, which is why it is worth closing
// here rather than later.** D186 moved a disclosure OUT of the init ledger and
// into a boot warning, and the residual cost recorded at the time was exactly
// this: the ledger is a place an operator can enumerate, a WARN line is not, and
// nothing checked the line existed. The maintainer's response — that boot output should be
// part of the dev cycle so everything is verified — is the general form of that
// complaint, and it applies to more than D186's line.
//
// **EVERY EXPECTATION IS DERIVED FROM ITS SOURCE OF TRUTH, never listed here.**
// That is the property that makes this worth having rather than a snapshot test:
// a new ledger entry, a newly unimplemented idempotency class, or a new
// non-rotating credential appears in the requirement by EXISTING, not by
// somebody remembering to extend this file (§15q). A hardcoded list of expected
// lines would pass forever while the boot report quietly stopped mentioning
// something.
//
// NOT A FIFTH ARTEFACT. D162 settled four questions and this answers `verify`'s
// — *does it work* — so it runs under `make test` like any other test, and
// `make demo-refusals` widened its pattern so a human can watch both halves of
// boot in one place.
func TestBootDisclosuresAreVisible(t *testing.T) {
	root := repoRoot(t)
	certs := filepath.Join(root, "dev", "certs")
	if _, err := os.Stat(filepath.Join(certs, "ca.crt")); err != nil {
		t.Skip("no development certificates; run `make dev-certs`. Skipping rather " +
			"than failing, for the reason the refusal suite gives: the certificates " +
			"are a developer convenience and this test's subject is what boot SAYS")
	}

	bin := filepath.Join(t.TempDir(), "sekizui")
	build := exec.Command(goTool(t), "build", "-o", bin, "./cmd/sekizui")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the binary: %v\n%s", err, out)
	}

	// **EPHEMERAL PORTS, so this cannot collide with a `make run` somebody has
	// open.** A test that fails with "address already in use" teaches nothing
	// about the boot report and reads like a Sekizui bug.
	cmd := exec.Command(bin,
		"-config", filepath.Join(root, "internal", "acceptance", "acceptance.yaml"),
		"-wal", t.TempDir(),
		"-residency", strings.Join(acceptanceResidency, ","),
		"-log-text", "-log-level", "debug",
		"-addr", "127.0.0.1:0",
		"-grpc-addr", "127.0.0.1:0",
		"-tls-cert", filepath.Join(certs, "server.crt"),
		"-tls-key", filepath.Join(certs, "server.key"),
		"-tls-client-ca", filepath.Join(certs, "ca.crt"),
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SEKIZUI_ACCEPT_TOK=boot-disclosure-token",
		"SEKIZUI_REGION=europe-west1")

	// **A PLAIN bytes.Buffer HERE IS A DATA RACE, and `-race` caught it on the
	// first CI run after this test passed cleanly without it.** exec.Cmd copies
	// the child's output on its own goroutine while the loop below polls for the
	// ready line, and bytes.Buffer is not safe for concurrent use. Exactly
	// §15g's argument, arriving in the test written to verify boot: the
	// unsynchronised version passed `go test` and failed `go test -race`.
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the binary: %v", err)
	}

	// WAITED ON A CHANNEL RATHER THAN POLLING cmd.ProcessState. That field is nil
	// until Wait returns, so the first draft's "did it exit?" check could never
	// fire — a binary that died during boot would have sat out the full timeout
	// and reported the wrong reason.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	// KILLED RATHER THAN DRAINED. The subject is what boot printed; a graceful
	// shutdown would add seconds per run and prove something else's guarantee.
	defer func() {
		_ = cmd.Process.Kill()
		<-exited
	}()

	// Wait for the line that means boot finished, rather than for a duration. A
	// sleep long enough to be reliable on a loaded machine is long enough to be
	// annoying on every other run.
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(out.String(), "msg=ready") {
		select {
		case err := <-exited:
			exited <- err // so the deferred drain does not block
			t.Fatalf("the binary exited during boot (%v). Output:\n%s", err, out.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the binary never reported ready within 30s. Output:\n%s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	report := out.String()

	// --- (a) EVERY INIT-LEDGER ENTRY IS PRINTED (D53) ----------------------
	//
	// The ledger's whole argument is that a skeleton reading as complete is the
	// danger, so every boot prints exactly how much is missing. Nothing verified
	// that the printing happens — and `logLedger` iterating an empty slice would
	// be silent and green.
	// **ASSERTED ON `step=<name>`, NOT ON THE BARE NAME, and the first draft got
	// this wrong in the way that matters.** It searched the whole report for each
	// entry's name — which is also in the readiness summary's
	// `missing="[audit:ship obs:otel …]"`. Suppressing every per-entry line left
	// the arm GREEN, because the names were still present somewhere else. An arm
	// satisfied by a different line than the one it means to check is a guard
	// that passes for the wrong reason, which is worse than not having it.
	for _, p := range ledger.Planned() {
		if want := "step=" + p.Name; !strings.Contains(report, want) {
			t.Errorf("boot prints no `%s` line for init-ledger entry %q (lands in %s). "+
				"D53's disclosure is the entire reason the ledger lives in code rather "+
				"than in a checklist", want, p.Name, p.LandsIn)
		}
		if want := "lands_in=" + p.LandsIn; !strings.Contains(report, want) {
			t.Errorf("boot never says entry %q lands in %s. The phase is what makes the "+
				"gap reviewable rather than permanent", p.Name, p.LandsIn)
		}
	}

	// --- (b) READINESS NAMES WHAT IS MISSING -------------------------------
	if !strings.Contains(report, "readiness DEGRADED") {
		t.Errorf("boot did not report readiness DEGRADED with %d planned entries "+
			"outstanding. A readiness signal that over-reports health is one an "+
			"operator stops consulting", len(ledger.Planned()))
	}

	// --- (c) EVERY UNIMPLEMENTED IDEMPOTENCY CLASS IS DISCLOSED (D186) -----
	//
	// **THE LINE D186 TRADED THE LEDGER FOR**, and until now nothing checked it
	// was emitted. `TestNoUnregisteredOrphansInPublicAPI` proves the FUNCTION has
	// a caller — delete the boot block and `connector.UnimplementedClasses`
	// orphans — which is a guard on the wiring rather than on the output. This is
	// the output.
	for _, class := range connector.UnimplementedClasses() {
		if !strings.Contains(report, string(class)) {
			t.Errorf("boot never discloses that idempotency class %q is declared and "+
				"not implemented. D186 moved this disclosure out of the init ledger "+
				"precisely so it would be reported; a disclosure nobody prints is the "+
				"defect the ledger exists to prevent, relocated", class)
		}
	}

	// --- (d) EVERY NON-ROTATING CREDENTIAL IS NAMED (D104) -----------------
	//
	// DERIVED FROM THE CONFIGURATION, so a target added later is covered by
	// existing. §4.7.8's two silent failures — a `subPath` mount that never
	// updates, and SOPS believed to protect the runtime — are only visible
	// because this line exists, and a paragraph in a design document accounts for
	// neither.
	doc, err := config.NewFileSource(
		filepath.Join(root, "internal", "acceptance", "acceptance.yaml")).Load(t.Context())
	if err != nil {
		t.Fatalf("loading the config to derive what boot should have said: %v", err)
	}
	var checked int
	for _, target := range doc.Targets {
		if !strings.HasPrefix(target.CredentialRef, "env://") {
			continue
		}
		checked++
		if !strings.Contains(report, target.Ref) {
			t.Errorf("boot never names target %q, whose credential is an environment "+
				"variable and therefore does not rotate (D104, §4.7.8)", target.Ref)
		}
	}
	if checked == 0 {
		t.Error("the fixture has no env:// target, so arm (d) checked nothing. It is " +
			"the arm that proves posture reporting reaches a REAL configuration rather " +
			"than a hand-built one")
	}

	if !t.Failed() {
		t.Logf("boot disclosed %d ledger entry/entries, %d unimplemented idempotency "+
			"class(es), and posture for %d non-rotating credential(s)",
			len(ledger.Planned()), len(connector.UnimplementedClasses()), checked)
	}
}

// syncBuffer is a bytes.Buffer that survives being written by one goroutine
// while another reads it.
//
// exec.Cmd's output copier and the poll loop above are different goroutines, and
// bytes.Buffer documents no synchronisation. The unguarded version of this test
// passed `go test` and failed `go test -race` (§15g), which is the whole reason
// -race is in `make verify` rather than being an occasional check.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
