package acceptance

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// TestRuntimeRefusalsAreVisible drives the REAL BINARY over mTLS and watches a
// REQUEST refusal happen (D115, D215, D235).
//
// **THE THIRD KIND OF REFUSAL, AND NOTHING COULD WATCH IT.** `make demo` points
// the suite at a running instance and shows the enforcement path; `demo-refusals`
// runs the binary against broken configurations and shows BOOT refusals. D215's
// refusals are neither: they are refusals of a REQUEST — a caller-controlled
// string that would otherwise be fsynced into the audit log — so they need a
// live instance AND a client willing to send something malformed, which neither
// target could express. HANDOFF has carried that as a known gap.
//
// **WHAT IT ADDS OVER STEP 44, which already proves D215 in-process:** that the
// bound is WIRED. The step asserts the function refuses; this asserts a real
// client, over a real TLS 1.3 handshake, holding a CA-signed certificate,
// against a separately-launched process, is told no — and is told something an
// operator can act on. That is the gap this codebase keeps finding: an
// implementation with no caller, or a caller in an order where it is
// unreachable.
//
// **D213's MCP REFUSALS STILL CANNOT BE SHOWN HERE, and the reason is worth
// recording rather than retrying.** They need the binary to reach an MCP server,
// and a fixture's certificate is not one the binary trusts: `mcp.WithHTTPClient`
// is a code-level seam, so an out-of-process instance cannot be told to trust a
// test CA without a new deployment flag. Adding "trust this CA" to the binary
// for the sake of a demo is a security-shaped decision, not a chore. The
// alternative is the real Fullstory MCP, which needs Sekizui's OWN credential
// (D234's grant) and a vetted spec (§4.9a) — more than a demo.
func TestRuntimeRefusalsAreVisible(t *testing.T) {
	root := mustRoot(t)
	certs := filepath.Join(root, "dev", "certs")
	if _, err := os.Stat(filepath.Join(certs, "ca.crt")); err != nil {
		t.Skip("no development certificates; run `make dev-certs`. Skipping rather than " +
			"failing: the certificates are a developer convenience and this test's subject " +
			"is the refusal behind them")
	}

	bin := filepath.Join(t.TempDir(), "sekizui")
	build := exec.Command(goTool(t), "build", "-o", bin, "./cmd/sekizui")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the binary: %v\n%s", err, out)
	}

	// FREE PORTS, NOT THE DEFAULTS. `make run` may be holding :8443 and :8080,
	// and a demo that fails because somebody is already watching the system is a
	// demo that teaches the wrong lesson.
	grpcAddr, probeAddr := freePort(t), freePort(t)

	wal := t.TempDir()
	cmd := exec.Command(bin,
		"-config", filepath.Join(root, "internal", "acceptance", "acceptance.yaml"),
		"-grpc-addr", grpcAddr, "-addr", probeAddr,
		"-wal", wal, "-residency", strings.Join(acceptanceResidency, ","), "-log-text", "-log-level", "info",
		"-tls-cert", filepath.Join(certs, "server.crt"),
		"-tls-key", filepath.Join(certs, "server.key"),
		"-tls-client-ca", filepath.Join(certs, "ca.crt"),
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SEKIZUI_ACCEPT_TOK=local-development-token",
		"SEKIZUI_REGION=europe-west1",
	)
	var logs strings.Builder
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the instance: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		// exec.Cmd.Wait, not os.Process.Wait: only the former waits for the
		// goroutine copying the child's output into `logs`, which is read just
		// below on failure (GO-PRIMER §15an).
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("the instance's own log:\n%s", logs.String())
		}
	})

	waitForReady(t, probeAddr, &logs)
	t.Logf("instance up: gRPC %s, probes %s", grpcAddr, probeAddr)

	// HOST AND PORT. A bare port reads as an integer IP — Go dialled
	// 0.0.239.202:443 and the failure looked like a refusal that did not happen.
	r := remoteRun(t, "127.0.0.1"+grpcAddr, certs)
	ctx := context.Background()
	triage := r.as(t, "agent:triage")

	// **THE REFUSAL A HUMAN SHOULD SEE (D215).** A caller-controlled string is
	// recorded on every decision the command produces, each fsynced — so an
	// unbounded one is an amplification the caller chooses and Sekizui pays for.
	// Truncating is not an option: a shortened key collides with every request
	// sharing its prefix and produces a false deduplication.
	oversized := strings.Repeat("k", 513)
	resp, err := triage.Execute(ctx, &sekizuiv1.ExecuteRequest{
		Command: &sekizuiv1.Command{
			Action:         "kata.create_issue",
			TargetRef:      "kata:alpha",
			IdempotencyKey: oversized,
		},
	})
	if err != nil {
		t.Fatalf("the oversized key arrived as a transport error (%v); a deliberate "+
			"refusal is a RESULT carrying a decision id (D135)", err)
	}

	got := resp.GetResult()
	t.Logf("REFUSED, as it should be:")
	t.Logf("  status:      %v", got.GetStatus())
	t.Logf("  kind:        %s", got.GetKind())
	t.Logf("  decision id: %s", got.GetDecisionId())
	t.Logf("  reason:      %s", firstSentence(got.GetReason()))

	if got.GetStatus() != sekizuiv1.Status_STATUS_INVALID_ARGUMENT {
		t.Errorf("status = %v, want INVALID_ARGUMENT", got.GetStatus())
	}
	// THE MESSAGE HAS TO TELL AN OPERATOR WHAT TO DO, which is the half a runner
	// cannot check and the whole reason this target is watched rather than
	// merely green.
	for _, want := range []string{"513", "512", "idempotency"} {
		if !strings.Contains(got.GetReason(), want) {
			t.Errorf("the refusal does not mention %q, so whoever hits it cannot tell what "+
				"the bound is or which field broke it:\n  %s", want, got.GetReason())
		}
	}
	if got.GetDecisionId() == "" {
		t.Error("the refusal names no decision id, so nothing joins it to the audit row " +
			"that explains it (D202, D211)")
	}

	// AND THE INSTANCE IS STILL SERVING. A request refusal must not take the
	// process with it — the caller made a mistake, not the deployment.
	ok, err := triage.Execute(ctx, execute("kata.create_issue", "kata:alpha",
		map[string]any{"project": "PROJ"}))
	if err != nil {
		t.Fatalf("the instance stopped serving after refusing one request: %v", err)
	}
	if s := ok.GetResult().GetStatus(); s != sekizuiv1.Status_STATUS_OK {
		t.Errorf("a well-formed command after the refusal returned %v, want OK: %s",
			s, ok.GetResult().GetReason())
	}
	t.Logf("and a well-formed command still succeeds: %v", ok.GetResult().GetStatus())
}

// freePort asks the kernel for one and hands back ":<port>".
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("splitting %q: %v", l.Addr(), err)
	}
	return ":" + port
}

// waitForReady polls /readyz until the instance says it is serving.
//
// **NOT A SLEEP.** A fixed wait is either too short on a cold build or wasted on
// a warm one, and when it is too short the failure looks like a refusal that did
// not happen rather than an instance that was not up.
func waitForReady(t *testing.T, probeAddr string, logs *strings.Builder) {
	t.Helper()
	url := "http://127.0.0.1" + probeAddr + "/readyz"
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:noctx,gosec // a local probe in a test
		if err == nil {
			body := resp.StatusCode
			_ = resp.Body.Close()
			if body == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the instance never became ready at %s within 30s. Its log:\n%s",
		url, logs.String())
}
