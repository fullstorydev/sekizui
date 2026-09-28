// Command sekizui-refsnap takes a connector's API reference snapshot (D299,
// D313): every operation its vendor documents, with its full contract, written
// as a dated revision a connector declares and a guard holds it to.
//
//	sekizui-refsnap -from 2026-09 -revision 2026-10 \
//	    -out internal/connectors/fullstory/reference
//
// It writes `<out>/<revision>/manifest.yaml` — the operations, as P4 steps 1-5
// read them — and `<out>/<revision>/contracts/<METHOD>_<path>.json`, one per
// operation: its parameters, request body and success response, RESOLVED, from
// the documentation site's own build (internal/apiref).
//
// **DECISIONS ARE CARRIED, NEVER SCRAPED.** An exclusion (D301, D305) and a
// vendor-confirmed host (D304) are rulings, not facts on a page, so they are
// read from the `-from` revision and written into the new one. An operation
// published OUTSIDE the reference sections that no decision covers refuses the
// snapshot: somebody must decide it before it is written down. The Lexicon
// audit is a human artefact and is not regenerated.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/apiref"
)

func main() {
	site := flag.String("site", "https://developer.fullstory.com", "the documentation site to read")
	out := flag.String("out", "internal/connectors/fullstory/reference", "the connector's reference directory")
	from := flag.String("from", "", "the revision whose decisions (exclusions, vendor-confirmed hosts) are carried")
	revision := flag.String("revision", "", "the revision to write, YYYY-MM")
	flag.Parse()
	if err := run(*site, *out, *from, *revision); err != nil {
		fmt.Fprintf(os.Stderr, "sekizui-refsnap: %v\n", err)
		os.Exit(1)
	}
}

// previous is the part of a prior manifest that is DECIDED rather than read.
type previous struct {
	VendorConfirmedHosts []map[string]any `json:"vendor_confirmed_hosts"`
	Endpoints            []struct {
		Method, Path, Excluded string
	} `json:"endpoints"`
	ExcludedOutside []struct {
		Section, Method, Path, Excluded string
	} `json:"excluded_outside_server"`
}

func run(site, out, from, revision string) error {
	if !regexp.MustCompile(`^\d{4}-\d{2}$`).MatchString(revision) || from == "" {
		return fmt.Errorf("-revision YYYY-MM and -from <revision> are both required")
	}
	raw, err := os.ReadFile(filepath.Join(out, from, "manifest.yaml"))
	if err != nil {
		return fmt.Errorf("the -from revision: %w", err)
	}
	var prev previous
	if err := yaml.Unmarshal(raw, &prev); err != nil {
		return fmt.Errorf("the -from manifest: %w", err)
	}
	excluded := map[string]string{}
	for _, e := range prev.Endpoints {
		if e.Excluded != "" {
			excluded[e.Method+" "+e.Path] = e.Excluded
		}
	}
	outside := map[string]string{}
	for _, e := range prev.ExcludedOutside {
		outside[e.Method+" "+e.Path] = e.Excluded
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ops, err := apiref.Read(ctx, &http.Client{Timeout: 30 * time.Second}, site,
		func(r string) bool {
			return strings.HasPrefix(r, "/server/") || strings.HasPrefix(r, "/anywhere/v1/webhooks/")
		}, tierOf)
	if err != nil {
		return err
	}

	dir := filepath.Join(out, revision)
	contracts := filepath.Join(dir, "contracts")
	if err := os.MkdirAll(contracts, 0o755); err != nil {
		return err
	}
	var server, undecided []string
	var outsideRows []string
	hosts := map[string]bool{}
	for _, op := range ops {
		body, err := json.MarshalIndent(op, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling %s %s: %w", op.Method, op.Path, err)
		}
		if err := os.WriteFile(filepath.Join(contracts, contractFile(op)), append(body, '\n'), 0o644); err != nil {
			return err
		}
		if op.Tier == "anywhere" {
			d, ok := outside[op.Key()]
			if !ok {
				undecided = append(undecided, op.Key())
				continue
			}
			outsideRows = append(outsideRows, fmt.Sprintf("  - {section: anywhere, method: %s, path: %q, excluded: %s,\n     docs: %q}",
				op.Method, op.Path, d, op.Docs))
			continue
		}
		extra := ""
		if op.Deprecated {
			extra += ", deprecated: true"
		}
		if d := excluded[op.Key()]; d != "" {
			extra += ", excluded: " + d
		}
		for _, s := range op.Servers {
			h := strings.TrimPrefix(s, "https://")
			hosts[h] = true
			if h != "api.fullstory.com" {
				extra += ", host: " + h
			}
		}
		server = append(server, fmt.Sprintf("  - {tier: %s, method: %s, path: %q, permission: %s%s,\n     docs: %q}",
			op.Tier, op.Method, op.Path, op.Permission, extra, op.Docs))
	}
	if len(undecided) > 0 {
		return fmt.Errorf("operation(s) published outside the reference sections that no decision covers — "+
			"decide them before they are written down: %v", undecided)
	}
	hostList := make([]string, 0, len(hosts))
	for h := range hosts {
		hostList = append(hostList, h)
	}
	sort.Strings(hostList)

	var b strings.Builder
	fmt.Fprintf(&b, `# Fullstory Server API reference — snapshot %s (D299), written by sekizui-refsnap (D313).
#
# THE DATE IS THE LABEL, THIS FILE IS THE EVIDENCE. Every operation Fullstory documents at
# developer.fullstory.com/server — v2, v1 and beta all count (D299) — read from the site's own build
# (internal/apiref), not its prose. The driver may call only what is listed here (P4 criterion 7) and
# must implement every entry not marked `+"`excluded`"+` (criterion 9). Each operation's full contract —
# parameters, request body, success response — is beside this file in contracts/.
#
# DECISIONS ARE CARRIED FROM REVISION %s, NEVER SCRAPED: the exclusions (D301, D305) and the
# vendor-confirmed hosts (D304). api.eu1.fullstory.com is Fullstory's dedicated EU1 data center,
# vendor-confirmed and used for EU residency (D288, D304).

revision: %s
fetched: %s
source: %s/sitemap.xml
documented_hosts: [%s]
`, revision, from, revision, time.Now().UTC().Format("2006-01-02"), site, strings.Join(hostList, ", "))
	b.WriteString("vendor_confirmed_hosts:\n")
	for _, h := range prev.VendorConfirmedHosts {
		fmt.Fprintf(&b, "  - {host: %v, dc: %v, decision: %v}\n", h["host"], h["dc"], h["decision"])
	}
	b.WriteString("endpoints:\n" + strings.Join(server, "\n") + "\n")
	b.WriteString("\n# SERVER-SIDE OPERATIONS DOCUMENTED OUTSIDE /server/, excluded by decision — listed so the drift\n" +
		"# arm still surfaces a change here (D305).\nexcluded_outside_server:\n" + strings.Join(outsideRows, "\n") + "\n")
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	fmt.Printf("revision %s: %d operations, %d contracts, written to %s\n", revision, len(ops), len(ops), dir)
	return nil
}

// tierOf reads a page's tier from its route: the reference's own sections.
func tierOf(route string) string {
	switch {
	case strings.HasPrefix(route, "/server/beta/"):
		return "beta"
	case strings.HasPrefix(route, "/server/v1/"):
		return "v1"
	case strings.HasPrefix(route, "/server/"):
		return "v2"
	default:
		return strings.SplitN(strings.TrimPrefix(route, "/"), "/", 2)[0]
	}
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]+`)

// contractFile names one operation's contract: METHOD_path, e.g.
// POST_v2_sessions_session_id_context.json.
func contractFile(op apiref.Operation) string {
	return op.Method + "_" + strings.Trim(nonAlnum.ReplaceAllString(op.Path, "_"), "_") + ".json"
}
