package acceptance

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBootRefusalsAreVisible drives the REAL BINARY against deliberately broken
// configurations and watches each refusal happen (D115).
//
// WHY THIS EXISTS AND `make demo` COULD NOT COVER IT. `make demo` points the
// acceptance suite at a running instance, which is the right shape for
// everything the enforcement path does — and structurally incapable of showing a
// boot refusal, because a refused boot leaves nothing to drive. P1 has since
// filled up with boot refusals: D97's env:// rule, D98's empty credential and
// cross-cloud claim, D142's operational ceilings, D150's config identity. Every
// one of them was proven in-process by its step and had no "watch it happen"
// path at all.
//
// THE BINARY, NOT A FUNCTION CALL. Each step already asserts its own refusal
// against the function that implements it. What this adds is the part no unit
// test can reach: that the refusal is WIRED — that boot actually calls it, in an
// order where it is reachable, and prints something an operator can act on. The
// gap it guards is the one this codebase keeps finding: an implementation with no
// caller.
//
// ORDERING NOTE, LEARNED THE HARD WAY. `gateway:serve` validates TLS material
// before it builds the enforcement stack, so every refusal below is reachable
// only once the certificates are right. That is defensible — an operator fixes
// one thing at a time — but it means a config error is invisible while the certs
// are wrong, and it is why these cases pass dev certs rather than omitting them.
func TestBootRefusalsAreVisible(t *testing.T) {
	root := repoRoot(t)
	certs := filepath.Join(root, "dev", "certs")
	if _, err := os.Stat(filepath.Join(certs, "ca.crt")); err != nil {
		t.Skip("no development certificates; run `make dev-certs`. Skipping rather " +
			"than failing: the certificates are a developer convenience and this " +
			"test's subject is the config refusals behind them")
	}

	bin := filepath.Join(t.TempDir(), "sekizui")
	build := exec.Command(goTool(t), "build", "-o", bin, "./cmd/sekizui")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the binary: %v\n%s", err, out)
	}

	base, err := os.ReadFile(filepath.Join(root, "internal", "acceptance", "acceptance.yaml"))
	if err != nil {
		t.Fatalf("reading the base config: %v", err)
	}

	cases := []struct {
		name string
		// edit mutates the good configuration into a broken one.
		edit func(string) string
		// env simulates a platform, using the REAL detection variables rather
		// than a test-only override — so the binary genuinely believes where it
		// is running (§4.10).
		env  []string
		args []string
		want []string
		// gone is the refusal a NEGATIVE case (no `want`) proves is lifted —
		// named per case, because an absence asserted against the wrong phrase
		// passes by default (D315 found the old check hard-coded to D97's).
		gone string
	}{
		{
			name: "D97: env:// on a managed platform",
			edit: func(s string) string { return s },
			// K_SERVICE is what Cloud Run sets, so runtime.Detect reports
			// ExecutionManaged — and every target in the base config uses
			// env://, which is exactly the posture D97 refuses.
			env: []string{"K_SERVICE=sekizui-demo"},
			// -audit=sync because a WAL needs BackgroundWork and Cloud Run
			// cannot be relied on to run one (§5.2.2, §4.10.2). Simulating the
			// platform means inheriting its real constraints, which is the point
			// of using the detection variables rather than a test override —
			// this case failed on exactly that before the flag was added, and
			// the profile check was right to fire first.
			args: []string{"-audit", "sync"},
			// THE MESSAGE CHANGED WHEN THE RULE BECAME DERIVED (D111, D153), and
			// this case is what noticed. It used to recite D97's blast-radius
			// argument; it now names the missing PROPERTY, which is the point of
			// generalising — an operator learns what to look for in an
			// alternative rather than that one scheme is disallowed. The remedy
			// is still named, because a general rule must not make specific
			// advice worse.
			want: []string{"versioned", "-allow-env-credentials", "no version"},
		},
		{
			name: "D97: the override makes it deployable, and visible in the manifest",
			edit: func(s string) string { return s },
			env:  []string{"K_SERVICE=sekizui-demo"},
			args: []string{"-allow-env-credentials", "-audit", "sync"},
			// Boots far enough to leave the credential check behind — and may boot
			// all the way, in which case the run's deadline stops it (D315: this
			// case used to rely on `make run` holding :8443 to terminate at all).
			// What matters is that the refusal ABOVE is gone.
			want: nil,
			gone: "-allow-env-credentials",
		},
		{
			// D315: the demo deployment grants `agent:showcase` a wildcard, and
			// on bare metal env:// is allowed — so the marker is what keeps it
			// from serving anywhere a human did not ask for it by flag.
			name: "D315: a demonstration deployment without -demo",
			edit: func(s string) string { return "demo: true\n" + s },
			want: []string{"DEMONSTRATION", "-demo", "never serve production"},
		},
		{
			name: "D315: -demo lets the demonstration boot, visibly in the command line",
			edit: func(s string) string { return "demo: true\n" + s },
			args: []string{"-demo"},
			want: nil,
			gone: "DEMONSTRATION",
		},
		{
			name: "D98: a target that declares no credential",
			edit: func(s string) string {
				return strings.Replace(s, ", credential: env://SEKIZUI_ACCEPT_TOK}", "}", 1)
			},
			want: []string{"declares no credential", "ambient://"},
		},
		{
			name: "item 47: a scheme this binary has no provider for",
			edit: func(s string) string {
				return strings.Replace(s, "credential: env://SEKIZUI_ACCEPT_TOK",
					"credential: gcp-sm://projects/p/secrets/s/versions/1", 1)
			},
			want: []string{"no provider for", "Available:"},
		},
		{
			name: "D98/D102 tier 1: a cross-cloud ambient claim, with no packet sent",
			edit: func(s string) string {
				return strings.Replace(s, "credential: env://SEKIZUI_ACCEPT_TOK",
					"credential: ambient://gcp", 1)
			},
			// Running on AWS Lambda as far as detection is concerned, so the
			// claim is REFUTED for free. If this ever starts taking seconds, the
			// tier-1 check has stopped being free and is probing instead.
			env:  []string{"AWS_LAMBDA_FUNCTION_NAME=sekizui-demo"},
			args: []string{"-audit", "sync", "-allow-env-credentials"},
			want: []string{"does not cross clouds", "federation"},
		},
		{
			name: "D142: a target more aggressive than the deployment permits",
			edit: func(s string) string {
				return strings.Replace(s, ", credential: env://SEKIZUI_ACCEPT_TOK}",
					", credential: env://SEKIZUI_ACCEPT_TOK, limits: {breaker_trip: 99}}", 1)
			},
			args: []string{"-breaker-trip", "5"},
			want: []string{"breaker_trip 99 exceeds", "LESS aggressive"},
		},
		{
			// P5 step 4 (D330). A reflex whose every firing the ceiling refuses:
			// granted, enabled, and able to do nothing — refused at boot, naming
			// the rule and the guard, where it used to boot and deny forever.
			name: "P5 step 4: a reflex the anzen ceiling forbids can never act",
			edit: func(s string) string {
				s = strings.Replace(s, "  - principal: reflex:friction\n    allow:\n      - {action: kata.create_issue, target: kata:alpha}\n",
					"  - principal: reflex:friction\n    allow:\n      - {action: kata.create_issue, target: kata:alpha}\n"+
						"      - {action: kata.delete_project, target: kata:alpha}\n", 1)
				return strings.Replace(s, "reflexes:\n", "reflexes:\n  - name: purge-on-friction\n"+
					"    principal: reflex:friction\n    enabled: true\n    consumes: sekizui.enriched.>\n"+
					"    action: kata.delete_project\n    target: kata:alpha\n", 1)
			},
			want: []string{"purge-on-friction", "no-destructive-actions", "can never act"},
		},
		{
			// P3 step 24. A Fullstory target naming a foreign host: its org's
			// key would be sent there on every call.
			name: "P3 step 24: a Fullstory target naming a host Fullstory does not serve",
			edit: func(s string) string {
				return strings.Replace(s, "ref: fs:live, kind: fullstory, tenant: live, residency: us, "+
					"base_url: https://api.fullstory.com", "ref: fs:live, kind: fullstory, tenant: live, "+
					"residency: us, base_url: https://collector.example.test", 1)
			},
			want: []string{"a host their connector does not serve", "fs:live", "api.fullstory.com"},
		},
		{
			// D324. Fullstory's MCP beside the native Fullstory targets, sharing
			// no budget, its tool left at the drafted [opaque]: a forgotten link.
			// The boot refuses and names both remedies — link, or declare [none].
			name: "D324: an MCP server named after a native connector, unlinked and silent",
			edit: func(s string) string {
				s = strings.Replace(s, "  - {ref: fs:live, ", "  - {ref: fullstory-mcp, kind: mcp, tenant: live, "+
					"residency: us, base_url: https://mcp.example.test, credential: env://SEKIZUI_ACCEPT_TOK}\n"+
					"  - {ref: fs:live, ", 1)
				return s + "\nmcp_specs:\n  fullstory-mcp:\n    server: fullstory\n    host: mcp.example.test\n" +
					"    tools:\n      - {name: create_note, description: Record a note., mutating: true, " +
					"idempotency: natural, input_schema: {type: object}, native: [opaque]}\n"
			},
			want: []string{"sits beside fullstory target(s)", "limits.budget", "different surface"},
		},
		{
			// D286. The process's environment — every env secret it was given —
			// named as a credential, which would be sent as the Authorization
			// header of every call. Refused even on a bare machine, where an
			// unrooted file credential is otherwise allowed.
			name: "D286: a credential naming /proc/self/environ",
			edit: func(s string) string {
				return strings.Replace(s, "credential: env://SEKIZUI_ACCEPT_TOK",
					"credential: file:///proc/self/environ", 1)
			},
			want: []string{"no credential may be read from", "/proc", "sent off-host"},
		},
		{
			// fs:live declares rate_per_hr 600 in the base configuration.
			name: "D284: a target budgeting past its unit's ceiling",
			edit: func(s string) string { return s },
			args: []string{"-meter-ceiling", "calls=500"},
			// No quotes in the phrases: the text log escapes them.
			want: []string{"fs:live", "asks for rate_per_hr 600 calls", "-meter-ceiling calls=500"},
		},
		{
			name: "D284: a universal default of zero would mean unlimited",
			edit: func(s string) string { return s },
			args: []string{"-meter-default-calls", "0"},
			want: []string{"-meter-default-calls must be a positive"},
		},
		{
			name: "D150: a configuration the deployment did not ship",
			edit: func(s string) string { return s },
			args: []string{"-expect-config", strings.Repeat("0", 64)},
			want: []string{"not the one the deployment expected", "expected:", "loaded:"},
		},
		{
			name: "D150: a malformed expectation is a flag to correct, not an alarm",
			edit: func(s string) string { return s },
			args: []string{"-expect-config", "truncated-by-a-copy-paste"},
			want: []string{"not a usable identity", "-config-hash"},
		},
		{
			// D49, D192. **CONTRACTS ITEM 10, WATCHED HAPPENING.** MCP action names
			// embed the server segment, so they can contradict the target ref —
			// `{action: "mcp.fixture.*", target_ref: "gitlab-mcp"}` names one server
			// in the action and another in the ref. Step 11 asserts the refusal
			// against `Document.Validate`; this is the part no unit test reaches:
			// that boot actually calls it, in an order where it is reachable, and
			// prints something an operator can act on.
			//
			// The config is EDITED to add an MCP target, its vetted spec and a
			// contradictory grant, because the shared fixture has no MCP target —
			// and giving it one would make every other step's boot depend on a
			// server nobody runs.
			//
			// **ALL THREE PARTS ARE NEEDED, which the first draft discovered by
			// omitting the target.** The validator then fired its OTHER check —
			// "a vetted spec keyed to nothing" — which is correct, and not the
			// property this case is about. A boot refusal suite is only as precise
			// as the configuration it feeds in.
			name: "D49: an MCP action contradicting its target ref",
			// **THREE PRECISE EDITS RATHER THAN AN APPEND, which the first two
			// drafts learned the hard way.** Appending a target at the end of the
			// file put it under `shin:`; adding a second `agent:triage` block
			// tripped the duplicate-principal check. Both are the validator
			// working, and neither is the property under test — a boot refusal
			// suite is only as precise as the configuration it feeds in.
			edit: func(s string) string {
				// 1. an MCP target, inside the targets list.
				s = strings.Replace(s, "targets:\n",
					"targets:\n  - {ref: fixture-mcp, kind: mcp, tenant: acme, residency: eu, "+
						"base_url: https://mcp.invalid, credential: env://SEKIZUI_ACCEPT_TOK}\n", 1)
				// 2. its vetted spec, so the target is not specless (D46).
				s = strings.Replace(s, "grants:\n", `mcp_specs:
  fixture-mcp:
    server: fixture
    host: mcp.invalid
    tools:
      - name: search
        input_schema: {type: object}

grants:
`, 1)
				// 3. THE CONTRADICTION, added to an EXISTING grant block so the
				// duplicate-principal check does not fire first.
				return strings.Replace(s,
					"      - {action: kata.read, target: kata:alpha}\n",
					"      - {action: kata.read, target: kata:alpha}\n"+
						"      - {action: mcp.fixture.search, target: kata:alpha}\n", 1)
			},
			want: []string{
				"names MCP server", "belongs to target", "fixture-mcp", "kata:alpha",
			},
		},
		{
			// D190. **A TYPO'D DRIVER KIND PASSED EVERY OTHER BOOT CHECK.** It was
			// refused at CALL time by the driver lookup in `Enforce` — correct and
			// late: the instance serves happily and refuses the first command that
			// names the target, hours later, to an agent, as a runtime error. D50
			// puts an offline check in the blocking half, because a configuration
			// that cannot mean anything is one somebody believes is in force.
			//
			// The refusal must name the REGISTERED kinds as well as the bad one,
			// because `fullstroy` versus `fullstory` is a diff nobody sees in
			// prose and everybody sees in a list.
			name: "D190: a target naming a driver kind nobody implements",
			edit: func(s string) string {
				return strings.Replace(s, "{ref: kata:beta,  kind: kata,",
					"{ref: kata:beta,  kind: fullstroy,", 1)
			},
			// MATCHED ON THE PARTS, not on the quoted phrase: slog's text handler
			// escapes the inner quotes of the `err=` field, so the literal in the
			// output is `kind \"fullstroy\"`. Asserting the rendered form would be
			// a test about the log handler's escaping rather than about the
			// refusal.
			want: []string{
				"name a driver kind no driver implements",
				"kata:beta", "fullstroy",
				"Registered kinds are",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := filepath.Join(t.TempDir(), "sekizui.yaml")
			edited := c.edit(string(base))
			if len(c.want) > 0 && edited == string(base) && c.edit != nil && len(c.args) == 0 && len(c.env) == 0 {
				t.Fatal("this case edits nothing and passes no flag or platform variable, " +
					"so it is asserting against the unmodified configuration")
			}
			if err := os.WriteFile(cfg, []byte(edited), 0o600); err != nil {
				t.Fatalf("writing config: %v", err)
			}

			args := append([]string{
				"-config", cfg,
				"-wal", t.TempDir(),
				"-residency", strings.Join(acceptanceResidency, ","),
				"-log-text",
				"-tls-cert", filepath.Join(certs, "server.crt"),
				"-tls-key", filepath.Join(certs, "server.key"),
				"-tls-client-ca", filepath.Join(certs, "ca.crt"),
				// PORT 0, so a case that gets past the refusals never fights
				// `make run` for :8443. It BINDS — port 0 always does — so such a
				// case boots and serves until the deadline below stops it (D315
				// corrected this comment, which claimed it "fails on binding").
				"-grpc-addr", "127.0.0.1:0",
				"-addr", "127.0.0.1:0",
			}, c.args...)

			// A DEADLINE ON EVERY CASE (D315). A refusal exits in well under a
			// second; a binary still running at the deadline booted past every
			// check, and is stopped — without it a clean boot serves forever.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Env = append(os.Environ(), c.env...)
			cmd.Env = append(cmd.Env, "SEKIZUI_ACCEPT_TOK=demo-token")
			out, err := cmd.CombinedOutput()
			text := string(out)
			booted := ctx.Err() != nil

			if len(c.want) == 0 {
				// The negative case: the NAMED refusal must be gone — asserted by
				// its absence, whether the binary then stopped for another reason
				// or booted and was stopped by the deadline.
				if c.gone == "" {
					t.Fatal("a negative case must name the refusal it proves is lifted")
				}
				if strings.Contains(text, c.gone) {
					t.Errorf("the refusal naming %q was not lifted:\n%s", c.gone, indent(text))
				}
				if booted {
					t.Logf("booted past every check and was stopped by the deadline")
				}
				return
			}
			if booted {
				t.Fatalf("the binary was still serving at the deadline — a configuration this "+
					"deployment must refuse was accepted:\n%s", indent(text))
			}

			if err == nil {
				t.Fatalf("the binary started. A configuration this deployment must refuse "+
					"was accepted, so the check exists and nothing calls it:\n%s", indent(text))
			}
			for _, want := range c.want {
				if !strings.Contains(text, want) {
					t.Errorf("the refusal does not mention %q — an operator cannot act on "+
						"what it does not say:\n%s", want, indent(text))
				}
			}
			// WATCH IT HAPPEN (D115). Under `-v` this is the point of the test.
			t.Logf("refused, as it should be:\n%s", indent(lastError(text)))
		})
	}
}

// goTool finds the Go the Makefile put on PATH.
func goTool(t *testing.T) string {
	t.Helper()

	p, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain found: %v", err)
	}
	return p
}

// lastError pulls the refusal out of the boot log, so the -v output is the
// message an operator would read rather than forty lines of init ledger.
func lastError(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "level=ERROR") || strings.Contains(lines[i], "err=") {
			return strings.Join(lines[i:], "\n")
		}
	}
	return s
}

func indent(s string) string {
	return "    " + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n    ")
}
