package acceptance

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/mcpspec"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// mcpspecBinary builds the real command, because stdin handling and the file
// refusal live in `package main`, which a test cannot call.
func mcpspecBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sekizui-mcpspec")
	build := exec.Command(goTool(t), "build", "-o", bin, "./cmd/sekizui-mcpspec")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building sekizui-mcpspec: %v\n%s", err, out)
	}
	return bin
}

func runMCPSpec(t *testing.T, bin, stdin string, args ...string) (stdout, stderr string, ok bool) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"-tool", "get_session", "-type", "fs.session.v1"}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.String(), errb.String(), err == nil
}

// A tools/call result carrying sentinel VALUES, and a tools/list entry.
const (
	resultWithSentinels = `{"content":[{"type":"text","text":"{\"session_id\":\"SENTINEL-SID-7731\",` +
		`\"user_email\":\"sentinel.person@example.test\",\"events\":[{\"type\":\"SENTINEL-KIND\",` +
		`\"url\":\"https://sentinel.example.test/p\",\"x\":424242}]}"}]}`
	advertisedEntry = `{"name":"get_session","inputSchema":{"type":"object"},"outputSchema":` +
		`{"type":"object","additionalProperties":true,"properties":{"session_id":{"type":"string",` +
		`"format":"uuid"},"tags":{"type":"array","items":{"type":"string"}}}}}`
)

// p3Step26 — the CLI never talks to an MCP server (D287).
func p3Step26(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "sekizui-mcpspec never talks to an MCP server: the user's agent does, and the CLI cannot dial")

	// 26a — IT CANNOT DIAL, BY ITS IMPORT GRAPH.
	list := exec.Command(goTool(t), "list", "-deps", "./cmd/sekizui-mcpspec")
	list.Dir = repoRoot(t)
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("step 26a: go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch {
		case dep == "net", dep == "net/http", dep == "crypto/tls",
			strings.HasSuffix(dep, "/internal/driver/mcp"), strings.HasSuffix(dep, "/pkg/connector"):
			t.Errorf("step 26a: sekizui-mcpspec reaches %s. A CLI that can dial can become an MCP "+
				"client again — holding the credential Sekizui governs; the user's agent calls "+
				"the MCP and pipes its output (D287)", dep)
		}
	}

	// 26b — IT READS THE AGENT'S RAW MCP JSON, AND REFUSES WHAT IS NOT.
	bin := mcpspecBinary(t)
	for _, c := range []struct{ name, in string }{
		{"a tools/call result", resultWithSentinels},
		{"a tools/list entry", advertisedEntry},
		{"a whole tools/list result", `{"tools":[` + advertisedEntry + `]}`},
	} {
		if stdout, stderr, ok := runMCPSpec(t, bin, c.in); !ok || !strings.Contains(stdout, "data_schema:") {
			t.Errorf("step 26b: %s was not drafted: %s", c.name, stderr)
		}
	}
	for _, c := range []struct{ name, in, says string }{
		{"prose", `{"content":[{"type":"text","text":"The session has three events."}]}`, "holds no JSON"},
		{"an error result", `{"isError":true,"content":[{"type":"text","text":"{\"error\":\"x\"}"}]}`, "isError"},
		{"a tool advertising no outputSchema", `{"name":"get_session","inputSchema":{"type":"object"}}`, "CALL the tool"},
		{"not MCP at all", `{"session_id":"s"}`, "neither a tools/list entry"},
	} {
		if _, stderr, ok := runMCPSpec(t, bin, c.in); ok || !strings.Contains(stderr, c.says) {
			t.Errorf("step 26b: %s was not refused saying %q (ok=%v): %s", c.name, c.says, ok, stderr)
		}
	}
	r.detail(t, "no network package in the import graph; three MCP shapes read, four non-shapes refused")
}

// p3Step27 — the observation never lands on disk, and no value is printed.
func p3Step27(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the observation never lands on disk, and no value from it is printed")
	bin := mcpspecBinary(t)

	// 27a — STDIN ONLY: a file is refused, so nothing has to be saved.
	if _, stderr, ok := runMCPSpec(t, bin, "", "saved-result.json"); ok || !strings.Contains(stderr, "stdin") {
		t.Errorf("step 27a: a file argument was not refused: %s", stderr)
	}

	// 27b — NEITHER PACKAGE WRITES A FILE.
	for _, dir := range []string{"internal/mcpspec", "cmd/sekizui-mcpspec"} {
		entries, err := os.ReadDir(filepath.Join(repoRoot(t), dir))
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(repoRoot(t), dir, e.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "os" {
						switch sel.Sel.Name {
						case "WriteFile", "Create", "OpenFile", "CreateTemp", "MkdirTemp", "Rename":
							t.Errorf("step 27b: %s/%s:%d calls os.%s. The observation is customer "+
								"data and must never land on disk (D233)", dir, e.Name(),
								fset.Position(sel.Pos()).Line, sel.Sel.Name)
						}
					}
				}
				return true
			})
		}
	}

	// 27c — TYPES, NEVER VALUES, in everything the command prints.
	stdout, stderr, ok := runMCPSpec(t, bin, resultWithSentinels)
	if !ok {
		t.Fatalf("step 27c: the seeded result was not drafted: %s", stderr)
	}
	for _, sentinel := range []string{"SENTINEL-SID-7731", "sentinel.person@example.test", "SENTINEL-KIND",
		"sentinel.example.test", "424242"} {
		if strings.Contains(stdout+stderr, sentinel) {
			t.Errorf("step 27c: the output carries %q, a VALUE from the result. The list and the "+
				"schemas are shape; a value is the customer's data (D233)", sentinel)
		}
	}
	if !strings.Contains(stdout, "user_email: string") {
		t.Errorf("step 27c: the list does not carry the field's type — the arm above would pass "+
			"for a command that printed nothing:\n%s", stdout)
	}
	r.detail(t, "stdin only; no file write in either package; five sentinel values drafted, none printed")
}

// p3Step28 — the list, the output schema and the data schema are renderings of
// one inference.
func p3Step28(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the list, the output schema and the data schema are renderings of one inference")

	// Both paths, from the library the command wires.
	obs, err := mcpspec.ReadObservation(strings.NewReader(resultWithSentinels), "get_session", "")
	if err != nil {
		t.Fatal(err)
	}
	local, err := mcpspec.Draft("get_session", "fs.session.v1", "", obs.Samples)
	if err != nil {
		t.Fatal(err)
	}
	adv, err := mcpspec.ReadObservation(strings.NewReader(advertisedEntry), "get_session", "")
	if err != nil {
		t.Fatal(err)
	}
	vendor, err := mcpspec.DraftAdvertised("get_session", "fs.session.v1", adv.Advertised)
	if err != nil {
		t.Fatal(err)
	}

	for name, f := range map[string]mcpspec.Fragment{"local": local, "vendor": vendor} {
		out, data := schemasOf(t, f.YAML)
		// 28a — THE DATA SCHEMA LOADS IN THE REAL REGISTRY. The CLI keeps its
		// own keyword list; this is what stops that copy drifting.
		if _, err := schemareg.New(map[string]json.RawMessage{"fs.session.v1": data}); err != nil {
			t.Errorf("step 28a: the %s draft's data_schema does not load in schemareg — pasted, it "+
				"would fail the boot: %v", name, err)
		}
		// 28b — THE LIST AND THE DATA SCHEMA NAME THE SAME PATHS.
		if got, want := listPaths(f.List), schemaPaths(t, data); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("step 28b: the %s list names %v and its data_schema %v; they are one inference "+
				"rendered twice and must not disagree", name, got, want)
		}
		_ = out
	}

	// 28c — THE VENDOR COPY IS THE VENDOR'S, AND THE LIVE CHECK HOLDS IT TO THAT.
	out, _ := schemasOf(t, vendor.YAML)
	if !strings.Contains(vendor.YAML, "output_schema_origin: "+string(connector.SchemaFromVendor)) ||
		!strings.Contains(local.YAML, "output_schema_origin: "+string(connector.SchemaFromLocal)) {
		t.Fatalf("step 28c: provenance does not follow the input — vendor for a copy, local for an "+
			"inference:\n%s\n%s", vendor.YAML, local.YAML)
	}
	var advertised struct {
		OutputSchema json.RawMessage `json:"outputSchema"`
	}
	_ = json.Unmarshal([]byte(advertisedEntry), &advertised)
	spec := []mcp.SpecTool{{Name: "get_session", InputSchema: json.RawMessage(`{"type":"object"}`),
		OutputSchema: out, OutputSchemaOrigin: string(connector.SchemaFromVendor)}}
	same := []mcp.LiveTool{{Name: "get_session", InputSchema: json.RawMessage(`{"type":"object"}`),
		OutputSchema: advertised.OutputSchema}}
	changed := []mcp.LiveTool{{Name: "get_session", InputSchema: json.RawMessage(`{"type":"object"}`),
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"session_id":{"type":"number"}}}`)}}
	if f := mcp.CompareToSpec("fs", spec, same); len(f) != 0 {
		t.Errorf("step 28c: the copied vendor schema drifts against the very server it was copied "+
			"from: %v", f)
	}
	if f := mcp.CompareToSpec("fs", spec, changed); len(f) == 0 {
		t.Error("step 28c: a vendor copy that no longer matches the server produced NO drift. That " +
			"live check is the whole reason a copy may say vendor (D287)")
	}
	// AND WHAT THE DATA SCHEMA COULD NOT CARRY IS SAID, not silently lost.
	if joined := strings.Join(vendor.Warnings, "\n"); !strings.Contains(joined, "format") ||
		!strings.Contains(joined, "drafted CLOSED") {
		t.Errorf("step 28c: the vendor schema's `format` and `additionalProperties: true` were "+
			"dropped from the data_schema without a warning:\n%s", joined)
	}
	r.detail(t, "both drafts' data_schemas load in schemareg; list and schema agree; the vendor copy "+
		"passes against its server and drifts against a changed one")
}

// schemasOf pulls output_schema and data_schema out of a drafted fragment.
func schemasOf(t *testing.T, yaml string) (out, data json.RawMessage) {
	t.Helper()
	grab := func(key string) json.RawMessage {
		i := strings.Index(yaml, "  "+key+": |\n")
		if i < 0 {
			t.Fatalf("the draft has no %s:\n%s", key, yaml)
		}
		var body []string
		for _, line := range strings.Split(yaml[i+len(key)+6:], "\n") {
			if !strings.HasPrefix(line, "    ") {
				break
			}
			body = append(body, strings.TrimPrefix(line, "    "))
		}
		return json.RawMessage(strings.Join(body, "\n"))
	}
	return grab("output_schema"), grab("data_schema")
}

func listPaths(list string) []string {
	var out []string
	for _, line := range strings.Split(list, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path, _, _ := strings.Cut(line, ": ")
		out = append(out, path)
	}
	return out
}

func schemaPaths(t *testing.T, data json.RawMessage) []string {
	t.Helper()
	var s map[string]any
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("data_schema is not JSON: %v", err)
	}
	var out []string
	var walk func(path string, s map[string]any)
	walk = func(path string, s map[string]any) {
		if path != "" {
			out = append(out, path)
		}
		if props, ok := s["properties"].(map[string]any); ok {
			for _, name := range sortedKeysAny(props) {
				child, _ := props[name].(map[string]any)
				p := name
				if path != "" {
					p = path + "." + name
				}
				walk(p, child)
			}
		}
		if items, ok := s["items"].(map[string]any); ok {
			walk(path+"[]", items)
		}
	}
	walk("", s)
	return out
}

func sortedKeysAny(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
