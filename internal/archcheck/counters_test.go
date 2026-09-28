package archcheck_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCounterNamesAreUnprefixed keeps `sekizui_` owned by one place.
//
// **THREE CALL SITES DOUBLED IT AND EVERY TEST PASSED.** `metrics.WriteTo` adds
// the namespace, the same way it does for the RED series — and
// `internal/credential` and the re-establishment loop each passed a name that
// already carried it, so the scrape read `sekizui_sekizui_credential_churn_total`
// for as long as those call sites existed.
//
// **WHAT LET IT THROUGH IS THE ASSERTION SHAPE, WHICH IS THE GENERAL LESSON.**
// The tests checked `strings.Contains(scrape, "sekizui_credential_churn_total")`
// — and the correct name is a SUBSTRING of the doubled one, so the assertion was
// true of the broken output. A containment check over a namespaced string cannot
// tell "present" from "present with a prefix glued on", which is why the
// acceptance arms now pin whole lines.
//
// Nothing else catches this: it is not a compile error, not a lint, and the
// metric still appears on the scrape under a name nobody will ever query.
func TestCounterNamesAreUnprefixed(t *testing.T) {
	root := repoRootFor(t)

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// A file that vanished mid-walk is not a violation: an acceptance
			// step plants and removes files (P1 step 28, P2 step 25) while test
			// packages run in parallel. See walkGo for the full reasoning.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "bin", "out", ".gocache", "dev":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		// The registry's own package names metrics in its exposition literals,
		// which is where the prefix is SUPPOSED to be written.
		if strings.HasPrefix(slash, "internal/metrics/") ||
			strings.HasPrefix(slash, "internal/archcheck") {
			return nil
		}

		// **A PARSE FAILURE IS RETURNED, NOT SWALLOWED.** The first draft ignored
		// it as "the build catches unparseable Go", and the linter was right to
		// object: this walk is how the guard SEES the tree, so a file it cannot
		// read is a file the guard silently stops covering. Failing loudly is the
		// same choice `Findings` and the ledger make — a check that quietly
		// examines less than it claims is the shape this codebase keeps finding.
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// `count` is internal/credential's own one-line wrapper, and the
			// name it forwards is written at ITS call sites. Named here rather
			// than skipped, because a wrapper is exactly how this mistake hides.
			switch sel.Sel.Name {
			case "Incr", "IncrFor", "count":
			default:
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if strings.HasPrefix(strings.Trim(lit.Value, `"`), "sekizui_") {
				offenders = append(offenders, slash+":"+
					fset.Position(lit.Pos()).String()[strings.LastIndex(
						fset.Position(lit.Pos()).String(), ":")+1:]+" "+lit.Value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("%d counter name(s) already carry the `sekizui_` namespace: %v\n\n"+
			"`metrics.WriteTo` adds it, so these emit `sekizui_sekizui_...` — a metric "+
			"under a name nobody will query, on a dashboard that will read zero and "+
			"look healthy. Drop the prefix from the call site.", len(offenders), offenders)
	}
}

// TestNoMetricCarriesATraceLabel keeps trace ids off the scrape surface (D216).
//
// **UNBOUNDED CARDINALITY, AND THE FAILURE IS THE WHOLE SCRAPE RATHER THAN ONE
// SERIES.** A trace id is one per conversation by construction, so a single
// label would multiply every RED series by the number of conversations the
// deployment has seen. Prometheus does not degrade gracefully at that
// cardinality: the scrape gets slower, then larger than the ingest limit, then
// stops — and what stops is ALL the metrics, including the ones an operator is
// using to watch the incident that made them look.
//
// **IT IS A LIKELY MISTAKE RATHER THAN AN UNTHINKABLE ONE**, which is why it is
// guarded rather than documented. D216 puts a span context on every decision;
// `metrics.IncrFor(name, target)` already takes a dimension, and "label it with
// the trace so we can find the slow one" is the obvious next thought for
// somebody debugging. RED metrics key on `(target, action, outcome)` and must
// continue to — a trace belongs in the audit record and in the span, both of
// which are per-event stores that expect high cardinality.
func TestNoMetricCarriesATraceLabel(t *testing.T) {
	root := repoRootFor(t)

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "bin", "out", ".gocache", "dev":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		// This guard's own error message has to name the pattern it forbids.
		if strings.HasPrefix(slash, "internal/archcheck") {
			return nil
		}

		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "IncrFor(") && !strings.Contains(line, ".Observe(") {
				continue
			}
			low := strings.ToLower(line)
			if strings.Contains(low, "traceid") || strings.Contains(low, "trace_id") ||
				strings.Contains(low, "gettrace()") {
				offenders = append(offenders, slash+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("%d metric call(s) carry a trace id as a dimension:\n  %s\n\n"+
			"A trace id is one per conversation, so this multiplies every series by the "+
			"number of conversations and takes the WHOLE scrape down — including the metrics "+
			"an operator is using to watch the incident that made them look. RED metrics key "+
			"on (target, action, outcome); a trace belongs in the decision record and in the "+
			"span (D216).",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}
