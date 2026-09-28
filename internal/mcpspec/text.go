package mcpspec

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// A TEXT RESULT (D289). Some tools return prose, not JSON — Fullstory's
// accessibility tree, its diff, its screenshot receipt. D287 refuses prose by
// default, because an agent PARAPHRASING a JSON result is the lossy path at its
// worst; `-text` is the admin saying "this tool returns text, and that is its
// contract". The data_schema is then one string field, admitted or withheld
// whole — plus whatever FIELDS the admin chooses to feature out of it, each
// extracted by a declared RE2 pattern. This tool proposes candidates; the admin
// decides (the maintainer: "this is why the mcpspec tool exists, so I can then decide if
// we feature the URL as a field or not").

// Candidate is a field this tool found in a text result, by NAME and PATTERN —
// never by value.
type Candidate struct {
	Name    string
	Pattern string
	Line    int // 1-based line the candidate was found on
}

// ReadTextResult reads a tools/call result whose content is text, JSON or not.
func ReadTextResult(r io.Reader) (text string, raw []byte, err error) {
	raw, err = io.ReadAll(r)
	if err != nil {
		return "", nil, fmt.Errorf("reading stdin: %w", err)
	}
	var v struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", nil, fmt.Errorf("stdin is not a tools/call result: %v. Pipe the MCP's raw JSON", err)
	}
	if v.IsError {
		return "", nil, fmt.Errorf("the piped result is an ERROR (isError: true); its text is the error's")
	}
	var parts []string
	for _, c := range v.Content {
		if c.Type == "text" {
			parts = append(parts, c.Text)
		}
	}
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("the result has no text content to draft from")
	}
	return strings.Join(parts, "\n"), raw, nil
}

var (
	keyValueLine = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9 _-]{0,48}?)(\s*\([^)]*\))?:\s+(\S.*)$`)
	bareURL      = regexp.MustCompile(`https?://\S+`)
	nonWord      = regexp.MustCompile(`[^a-z0-9]+`)
)

// Candidates proposes the fields a text result could feature: `Key: value`
// lines (a parenthetical after the key is allowed to vary — `URL (expires in
// 168h)` — so the pattern does not pin a duration), and bare URLs on other
// lines. Sorted by name; each pattern captures exactly one group.
func Candidates(text string) []Candidate {
	seen := map[string]Candidate{}
	urls := 0
	for n, line := range strings.Split(text, "\n") {
		if m := keyValueLine.FindStringSubmatch(line); m != nil {
			key := strings.TrimSpace(m[1])
			name := strings.Trim(nonWord.ReplaceAllString(strings.ToLower(key), "_"), "_")
			if name == "" || seen[name].Name != "" {
				continue
			}
			pattern := `^\s*` + regexp.QuoteMeta(key)
			if m[2] != "" {
				pattern += `(?:\s*\([^)]*\))?`
			}
			pattern += `:\s+(\S.*)$`
			seen[name] = Candidate{Name: name, Pattern: pattern, Line: n + 1}
			continue
		}
		if bareURL.MatchString(line) {
			urls++
			name := fmt.Sprintf("url_%d", urls)
			seen[name] = Candidate{Name: name, Pattern: `(https?://\S+)`, Line: n + 1}
		}
	}
	out := make([]Candidate, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DraftText renders the spec fragment for a text-returning tool: `result:
// text`, one `extract` entry per featured candidate, and a closed data_schema
// of `text` plus the featured fields — callerOnly where the admin said so.
//
// userContent says the text carries END-USER content (D289): each extraction is
// then anchored to the line it was found on, and the spec says so, because a
// pattern matched anywhere could match a line a user typed.
func DraftText(tool, outputType, text string, feature, callerOnly []string, userContent bool) (Fragment, error) {
	if tool == "" || outputType == "" {
		return Fragment{}, fmt.Errorf("both a tool name and an output type are required")
	}
	cands := Candidates(text)
	byName := map[string]Candidate{}
	for _, c := range cands {
		byName[c.Name] = c
	}
	var names []string
	for _, c := range cands {
		names = append(names, c.Name)
	}
	chosen := map[string]bool{}
	var extracts []Candidate
	for _, f := range feature {
		c, ok := byName[f]
		if !ok {
			return Fragment{}, fmt.Errorf("-feature %q is not a candidate in this result; candidates: %v", f, names)
		}
		chosen[f] = true
		extracts = append(extracts, c)
	}
	for _, f := range callerOnly {
		if !chosen[f] {
			return Fragment{}, fmt.Errorf("-caller-only %q is not a featured field; feature it first", f)
		}
	}
	if chosen["text"] {
		return Fragment{}, fmt.Errorf("a featured field may not be called `text`; that is the whole result")
	}

	props := map[string]any{"text": map[string]any{"type": "string",
		"description": "the tool's whole text result, admitted or withheld as one (D289)"}}
	only := map[string]bool{}
	for _, f := range callerOnly {
		only[f] = true
	}
	for _, c := range extracts {
		p := map[string]any{"type": "string"}
		if only[c.Name] {
			p["callerOnly"] = true
		}
		props[c.Name] = p
	}
	data := map[string]any{"type": "object", "properties": props,
		"$comment": "drafted from an agent-supplied TEXT result; unverified until vetted (D289)"}
	body, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return Fragment{}, err
	}

	var b strings.Builder
	b.WriteString("# Drafted by sekizui-mcpspec from a TEXT result an AGENT supplied — UNVERIFIED; VET BEFORE USE.\n")
	b.WriteString("# result: text — the tool's contract is prose, so there is no output_schema; the data_schema is\n")
	b.WriteString("# the whole text as one field, plus the fields featured out of it by an RE2 pattern each.\n")
	fmt.Fprintf(&b, "- name: %s\n", tool)
	fmt.Fprintf(&b, "  output_type: %s\n", outputType)
	b.WriteString("  result: text\n")
	// THE SAFE ANSWER, DRAFTED (D323): on a target sharing a budget with native
	// ones the relation is required, and a reviewer narrows it only where they
	// know what the tool reaches. On an unlinked target it changes nothing.
	b.WriteString("  native: [opaque]\n")
	if userContent {
		b.WriteString("  user_content: true\n")
	}
	if len(extracts) > 0 {
		b.WriteString("  extract:\n")
		for _, c := range extracts {
			q, _ := json.Marshal(c.Pattern)
			if userContent {
				fmt.Fprintf(&b, "    - {field: %s, pattern: %s, line: %d}\n", c.Name, q, c.Line)
			} else {
				fmt.Fprintf(&b, "    - {field: %s, pattern: %s}\n", c.Name, q)
			}
		}
	}
	b.WriteString("  data_schema: |\n")
	indent(&b, body)

	var list strings.Builder
	fmt.Fprintf(&list, "# %s → %s: a TEXT result an AGENT supplied — UNVERIFIED\n", tool, outputType)
	list.WriteString("# types only; no value from the result is ever printed (D233)\n")
	list.WriteString("text: string (the whole result)\n")
	for _, c := range extracts {
		mark := ""
		if only[c.Name] {
			// THE WHOLE TEXT CARRIES THE VALUE TOO. A caller-only URL beside an
			// admitted `text` that contains it would reach the audit log through
			// `text` — so the gateway scrubs a caller-only value from every other
			// string in the recorded copy (D289), and the list says so.
			mark = " — callerOnly: returned to the caller, never recorded; its value is " +
				"also scrubbed from `text` and every other recorded string"
		}
		fmt.Fprintf(&list, "%s: string (featured)%s\n", c.Name, mark)
	}
	var warnings []string
	if !userContent && len(extracts) > 0 {
		warnings = append(warnings, "the extractions match ANYWHERE in the text. If this tool's text "+
			"can carry end-user content (a form a user filled, a page they wrote), re-run with "+
			"-user-content: a line a user typed could otherwise supply a trusted field (D289)")
	}
	for _, c := range cands {
		if !chosen[c.Name] {
			warnings = append(warnings, fmt.Sprintf("candidate field %q (pattern %s) is NOT featured; "+
				"re-run with -feature %s to extract it", c.Name, c.Pattern, c.Name))
		}
	}
	return Fragment{
		List: list.String(), YAML: b.String(), Warnings: warnings,
		Obligations: "YOU MUST STILL SET `mutating`, and `idempotency` if it is mutating (§4.9a.1, D163). " +
			"`native` is drafted [opaque], the safe answer; narrow it only if you know (D323).",
	}, nil
}
