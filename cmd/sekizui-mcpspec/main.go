// Command sekizui-mcpspec drafts the vetted spec for one MCP tool — its
// output contract and the connector's data schema — from what the user's
// AGENT piped (D287).
//
// **THE AGENT CALLS THE MCP; THIS COMMAND NEVER DOES.** It holds no credential
// and cannot dial (P3 step 26): the user's agent already has the connection,
// the auth and a permission prompt per call, so the human chooses the tool
// there. Two inputs, and the input decides the provenance — no flag can:
//
//	# the server ADVERTISES an outputSchema: pipe its tools/list entry.
//	#   output_schema is COPIED, origin vendor, and drift-checked live (§4.9a.7)
//	<tools/list entry> | sekizui-mcpspec -tool get_session -type fs.session.v1
//
//	# it advertises none: have the agent CALL the tool and pipe the result.
//	#   output_schema is INFERRED, origin local
//	<tools/call result> | sekizui-mcpspec -tool get_session -type fs.session.v1
//
// Either way the output is the field list first — `path: type`, never a value
// (D233) — then the YAML: output_schema, and data_schema, the closed allowlist
// of what the connector may provide (D279).
//
// **STDIN ONLY.** A result big enough to be interesting is customer data; it
// should never have to be saved to a file to be drafted from.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fullstorydev/sekizui/internal/jsonref"
	"github.com/fullstorydev/sekizui/internal/mcpspec"
)

func main() {
	tool := flag.String("tool", "", "the MCP tool's name, as the server advertises it")
	outputType := flag.String("type", "", "the registry key a reflex's ExpectsType will match (D88)")
	at := flag.String("at", "", "JSON pointer to the subtree of a RESULT to describe, e.g. /events/0")
	text := flag.Bool("text", false, "the tool returns TEXT, not JSON: draft `result: text` and list candidate fields (D289)")
	feature := flag.String("feature", "", "with -text: comma-separated candidate fields to extract as fields")
	callerOnly := flag.String("caller-only", "", "with -text: featured fields returned to the caller and never recorded")
	userContent := flag.Bool("user-content", false, "with -text: the text carries END-USER content, so each extraction is anchored to its line (D289)")
	combine := flag.String("combine", "", "a result of several JSON text blocks: `items` drafts {items: [...]} (D289)")
	unroll := flag.Int("unroll", jsonref.DefaultUnroll, "how many times a recursive $ref is expanded in the data_schema; "+
		"match the spec's ref_unroll (D306, D309)")
	flag.Parse()

	if *text {
		if err := runText(*tool, *outputType, split(*feature), split(*callerOnly), *userContent, flag.Args()); err != nil {
			fmt.Fprintf(os.Stderr, "sekizui-mcpspec: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*tool, *outputType, *at, *combine, *unroll, flag.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "sekizui-mcpspec: %v\n", err)
		os.Exit(1)
	}
}

func run(tool, outputType, at, combine string, unroll int, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("files are not read: pipe the agent's MCP output on stdin, so a result " +
			"that is customer data never has to be saved to disk (D233)")
	}
	obs, err := mcpspec.ReadObservation(os.Stdin, tool, combine)
	if err != nil {
		return err
	}
	if caution := mcpspec.WarnOnSize([][]byte{obs.Raw}); caution != "" {
		fmt.Fprintf(os.Stderr, "sekizui-mcpspec: %s\n", caution)
	}
	var fragment mcpspec.Fragment
	if obs.Advertised != nil {
		fragment, err = mcpspec.DraftAdvertised(tool, outputType, obs.Advertised, jsonref.WithUnroll(unroll))
	} else {
		fragment, err = mcpspec.Draft(tool, outputType, at, obs.Samples)
	}
	if err != nil {
		return err
	}
	for _, w := range append(obs.Warnings, fragment.Warnings...) {
		fmt.Fprintf(os.Stderr, "sekizui-mcpspec: %s\n", w)
	}
	fmt.Fprintf(os.Stderr, "sekizui-mcpspec: %s\n", fragment.Obligations)
	fmt.Fprint(os.Stdout, fragment.List)
	fmt.Fprintln(os.Stdout)
	fmt.Fprint(os.Stdout, fragment.YAML)
	return nil
}

func split(csv string) []string {
	var out []string
	for _, f := range strings.Split(csv, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// runText drafts a text-returning tool (D289).
func runText(tool, outputType string, feature, callerOnly []string, userContent bool, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("files are not read: pipe the agent's MCP output on stdin (D233)")
	}
	text, raw, err := mcpspec.ReadTextResult(os.Stdin)
	if err != nil {
		return err
	}
	if caution := mcpspec.WarnOnSize([][]byte{raw}); caution != "" {
		fmt.Fprintf(os.Stderr, "sekizui-mcpspec: %s\n", caution)
	}
	fragment, err := mcpspec.DraftText(tool, outputType, text, feature, callerOnly, userContent)
	if err != nil {
		return err
	}
	for _, w := range fragment.Warnings {
		fmt.Fprintf(os.Stderr, "sekizui-mcpspec: %s\n", w)
	}
	fmt.Fprintf(os.Stderr, "sekizui-mcpspec: %s\n", fragment.Obligations)
	fmt.Fprint(os.Stdout, fragment.List)
	fmt.Fprintln(os.Stdout)
	fmt.Fprint(os.Stdout, fragment.YAML)
	return nil
}
