// Package apiref reads a vendor's API reference from the documentation site
// that publishes it (D312, D313): every operation, with its full contract.
//
// PRIVATE (D35). Used by `sekizui-refsnap`, which takes a connector's reference
// snapshot, and by P4 step 5's live arm, which compares the published
// reference with the committed one — ONE reader, so the snapshot and the drift
// check cannot parse the same site two ways.
//
// **WHAT IT READS IS THE SITE'S OWN BUILD, NOT ITS PROSE.** Fullstory's reference
// is generated from OpenAPI (docusaurus-openapi-docs), and every operation page
// ships as a JavaScript chunk whose page metadata, a `JSON.parse('…')` literal,
// carries the RESOLVED OpenAPI operation under `frontMatter.api`: operationId,
// parameters, request body, responses — no `$ref` left. The route of each page
// comes from the site's route registry, its chunk file from the runtime's two
// chunk maps, and the list of pages from `sitemap.xml`. No summarising model is
// involved at any step: a guard needs exact contracts (D304).
//
// **TWO THINGS THE FIRST READER GOT WRONG, KEPT HERE SO NOBODY RE-LEARNS THEM
// (D312):** the runtime's chunk-name map carries readable names beside content
// hashes, and the minifier writes chunk 5000 as `5e3` — a JavaScript exponent
// literal — so a digits-only, hex-only map pattern matches neither map.
package apiref

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Operation is one documented API operation and its contract.
type Operation struct {
	Tier        string          `json:"tier"`
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	OperationID string          `json:"operation_id,omitempty"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	Permission  string          `json:"permission,omitempty"`
	Deprecated  bool            `json:"deprecated,omitempty"`
	Servers     []string        `json:"servers,omitempty"`
	Docs        string          `json:"docs"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	RequestBody json.RawMessage `json:"request_body,omitempty"`
	Response    json.RawMessage `json:"response,omitempty"`
}

// Key is "METHOD /path", the join key between a snapshot and a reading.
func (o Operation) Key() string { return o.Method + " " + o.Path }

var (
	locRE      = regexp.MustCompile(`<loc>([^<]+)</loc>`)
	scriptRE   = regexp.MustCompile(`src="(/assets/js/(?:runtime~main|main)\.[0-9a-f]+\.js)"`)
	registryRE = regexp.MustCompile(`"(/[^"]+?)-[0-9a-f]{3}":\{"__comp":"[0-9a-f]+","content":"([0-9a-f]+)"\}`)
	chunkMapRE = regexp.MustCompile(`\{(?:[0-9]+(?:e[0-9]+)?:"[^"]+",?){20,}\}`)
	pairRE     = regexp.MustCompile(`([0-9]+(?:e[0-9]+)?):"([^"]+)"`)
)

// Read returns every operation published under the routes include admits,
// sorted by key. base is the site root, e.g. "https://developer.fullstory.com".
func Read(ctx context.Context, client *http.Client, base string,
	include func(route string) bool, tier func(route string) string) ([]Operation, error) {

	get := func(u string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	}

	sitemap, err := get(base + "/sitemap.xml")
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	var anyPage string
	for _, m := range locRE.FindAllSubmatch(sitemap, -1) {
		route := strings.TrimPrefix(string(m[1]), base)
		if include(route) {
			want[route] = true
			anyPage = route
		}
	}
	if anyPage == "" {
		return nil, fmt.Errorf("the sitemap lists no page this reader was asked for")
	}
	page, err := get(base + anyPage)
	if err != nil {
		return nil, err
	}
	var mainJS, runtimeJS []byte
	for _, m := range scriptRE.FindAllSubmatch(page, -1) {
		body, err := get(base + string(m[1]))
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(m[1]), "runtime~main") {
			runtimeJS = body
		} else {
			mainJS = body
		}
	}
	maps := chunkMapRE.FindAll(runtimeJS, -1)
	if len(maps) < 2 || mainJS == nil {
		return nil, fmt.Errorf("the site's build does not have the shape this reader knows " +
			"(runtime chunk maps or main bundle missing) — the reference must be re-taken by hand")
	}
	names, hashes := map[string]string{}, map[string]string{}
	for _, p := range pairRE.FindAllSubmatch(maps[0], -1) {
		names[string(p[2])] = chunkID(string(p[1]))
	}
	for _, p := range pairRE.FindAllSubmatch(maps[1], -1) {
		hashes[chunkID(string(p[1]))] = string(p[2])
	}

	var out []Operation
	for _, m := range registryRE.FindAllSubmatch(mainJS, -1) {
		route, key := string(m[1]), string(m[2])
		if !want[route] {
			continue
		}
		id, ok := names[key]
		if !ok {
			continue
		}
		chunk, err := get(fmt.Sprintf("%s/assets/js/%s.%s.js", base, key, hashes[id]))
		if err != nil {
			return nil, err
		}
		op, ok, err := operationOf(chunk)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", route, err)
		}
		if !ok {
			continue // a prose page
		}
		op.Tier, op.Docs = tier(route), base+route
		out = append(out, op)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no operation was read from the reference")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// chunkID normalises a minified chunk key — `5e3` is 5000 — so the maps agree.
func chunkID(k string) string {
	mant, exp, found := strings.Cut(k, "e")
	if !found {
		return k
	}
	n := 0
	for _, c := range exp {
		n = n*10 + int(c-'0')
	}
	return mant + strings.Repeat("0", n)
}

// operationOf extracts the resolved OpenAPI operation from a page chunk. A page
// with no operation is prose: (zero, false, nil).
func operationOf(chunk []byte) (Operation, bool, error) {
	s := string(chunk)
	const open = "JSON.parse('"
	i := strings.Index(s, open)
	if i < 0 {
		return Operation{}, false, nil
	}
	raw, err := jsString(s[i+len(open):])
	if err != nil {
		return Operation{}, false, err
	}
	var meta struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		FrontMatter struct {
			API *struct {
				OperationID string          `json:"operationId"`
				Method      string          `json:"method"`
				Path        string          `json:"path"`
				Deprecated  bool            `json:"deprecated"`
				Permission  string          `json:"x-fullstory-permission-level"`
				Parameters  json.RawMessage `json:"parameters"`
				RequestBody struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"requestBody"`
				Responses map[string]struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"responses"`
				Servers []struct {
					URL string `json:"url"`
				} `json:"servers"`
			} `json:"api"`
		} `json:"frontMatter"`
	}
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return Operation{}, false, fmt.Errorf("the page metadata is not JSON: %w", err)
	}
	api := meta.FrontMatter.API
	if api == nil || api.Method == "" {
		return Operation{}, false, nil
	}
	op := Operation{
		Method: strings.ToUpper(api.Method), Path: api.Path, OperationID: api.OperationID,
		Permission: api.Permission, Deprecated: api.Deprecated, Parameters: api.Parameters,
		Title: meta.Title, Description: meta.Description,
	}
	if c, ok := api.RequestBody.Content["application/json"]; ok {
		op.RequestBody = c.Schema
	}
	// THE SUCCESS RESPONSE: the lowest 2xx that carries JSON.
	codes := make([]string, 0, len(api.Responses))
	for code := range api.Responses {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		if strings.HasPrefix(code, "2") {
			if c, ok := api.Responses[code].Content["application/json"]; ok {
				op.Response = c.Schema
				break
			}
		}
	}
	for _, sv := range api.Servers {
		op.Servers = append(op.Servers, sv.URL)
	}
	return op, true, nil
}

// jsString decodes a JavaScript single-quoted string literal's body up to its
// closing quote: webpack escapes the embedded JSON's backslashes and quotes for
// JavaScript, so `\\` is one backslash and `\'` one quote; every other escape
// belongs to the JSON and is kept for the JSON decoder.
func jsString(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			if i+1 >= len(s) {
				return "", fmt.Errorf("an unterminated escape in the page metadata")
			}
			switch n := s[i+1]; n {
			case '\\':
				b.WriteByte('\\')
			case '\'':
				b.WriteByte('\'')
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			i++
		case '\'':
			return b.String(), nil
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("the page metadata string never closes")
}
