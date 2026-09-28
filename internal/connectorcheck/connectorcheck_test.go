package connectorcheck_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/builtin"
	"github.com/fullstorydev/sekizui/internal/connectorcheck"
	"github.com/fullstorydev/sekizui/internal/docref"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// TestEveryConnectorFolderIsComplete is D316's build guard: the fast half of
// "both". P4 step 34 runs the same Check for the evidence report.
func TestEveryConnectorFolderIsComplete(t *testing.T) {
	root, err := docref.Root()
	if err != nil {
		t.Fatal(err)
	}
	rep := connectorcheck.Check(root, builtin.Drivers(&config.Document{}, nil))

	// NON-VACUITY: a guard that walks a directory passes trivially once the
	// directory moves — which is how D316's own move found three guards checking
	// less than they claimed.
	if len(rep.Folders) == 0 {
		t.Fatalf("no connector folders under %s, so this guard is checking nothing", connectorcheck.Root)
	}
	for _, f := range rep.Findings {
		t.Errorf("%s", f)
	}
}

// plant writes files into a temp repository, keyed by path relative to it.
func plant(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// A vetted MCP fragment the checks accept: one read-only tool, closed output.
const goodMCP = `mcp_specs:
  zzmcp:
    server: zzmcp
    host: mcp.zz.invalid
    tools:
      - name: ping
        description: answers
        mutating: false
        input_schema: {type: object, additionalProperties: false}
        output_type: zzmcp.pong.v1
        output_schema: {type: object, properties: {ok: {type: boolean}}}
        data_schema: {type: object, additionalProperties: false, properties: {ok: {type: boolean}}}
        output_schema_origin: vendor
`

// TestTheGuardRejectsEachIncompleteShape is the guard's own sabotage: every
// requirement in the ruling, planted missing once, with a complete MCP-only
// folder beside them so the check is not merely rejecting everything.
func TestTheGuardRejectsEachIncompleteShape(t *testing.T) {
	c := connectorcheck.Root + "/"
	root := plant(t, map[string]string{
		// complete: an MCP-only connector
		c + "zzmcp/README.md": "x",
		c + "zzmcp/mcp.yaml":  goodMCP,

		// a driver folder missing everything a driver owes, and unregistered
		c + "zzcode/zzcode.go":      "package zzcode\n",
		c + "zzcode/zzcode_test.go": "package zzcode\n",

		// neither code nor mcp.yaml
		c + "zzempty/README.md": "x",

		// fragments present and broken
		c + "zzfrag/README.md":                          "x",
		c + "zzfrag/mcp.yaml":                           goodMCP,
		c + "zzfrag/anzen.yaml":                         "anzen:\n  - name: r\n    forbidz: [x]\n",
		c + "zzfrag/reflexes.yaml":                      "reflexes: []\n",
		c + "zzfrag/reference/2026-09/contracts/x.json": "{}",

		// an mcp.yaml that loads and fails the vetted-spec checks: a write
		// without idempotency (D113)
		c + "zzwrite/README.md": "x",
		c + "zzwrite/mcp.yaml":  strings.Replace(goodMCP, "mutating: false", "mutating: true", 1),
	})

	rep := connectorcheck.Check(root, nil)
	got := strings.Join(func() []string {
		var s []string
		for _, f := range rep.Findings {
			s = append(s, f.String())
		}
		return s
	}(), "\n")

	for _, want := range []string{
		"zzcode: has no README.md",
		"zzcode: has Go code and is not registered",
		"zzcode: has Go code and no schemas.yaml",
		"zzcode: does not run conformance.Run",
		"zzempty: has no Go code and no mcp.yaml",
		"zzfrag: anzen.yaml does not load",
		"zzfrag: reflexes.yaml does not load",
		"zzfrag: ships reflexes.yaml and its driver is not a connector.Refiner",
		"zzfrag: reference/2026-09 has no manifest.yaml",
		"zzwrite: mcp.yaml does not validate",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the guard did not report %q; it reported:\n%s", want, got)
		}
	}
	if strings.Contains(got, connectorcheck.Root+"/zzmcp:") {
		t.Errorf("the guard rejected the complete MCP-only folder:\n%s", got)
	}
	if len(rep.Folders) != 5 {
		t.Errorf("examined %d folders, want 5", len(rep.Folders))
	}
}

// stray is a driver declared outside any connector folder — in this test
// package — which is exactly a connector split across the tree.
type stray struct{ connector.Driver }

// TestARegisteredDriverOutsideAFolderIsRefused — registration → folder, the
// direction the folder walk cannot see. The shared MCP driver is accepted.
func TestARegisteredDriverOutsideAFolderIsRefused(t *testing.T) {
	root := plant(t, map[string]string{
		connectorcheck.Root + "/zz/README.md": "x",
		connectorcheck.Root + "/zz/mcp.yaml":  goodMCP,
	})
	rep := connectorcheck.Check(root, []connector.Driver{&stray{}, mcp.New(nil)})
	if len(rep.Findings) != 1 || !strings.Contains(rep.Findings[0].Problem, "is not a folder directly under") {
		t.Errorf("findings = %v, want exactly the stray driver refused and the MCP driver accepted", rep.Findings)
	}
}
