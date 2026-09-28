package gateway

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// nonRefusalStatuses are the only statuses a CommandResult may carry WITHOUT
// having been built by refusalResult.
//
// AN ALLOWLIST, AND THE DIRECTION IS THE SAFE ONE. A refusal status added to the
// proto and not listed here fails the guard below, which is a loud demand to
// think about it; a NON-refusal status added and not listed fails too, and the
// fix is one line. Both directions surface. The dangerous version would be an
// allowlist of REFUSAL statuses, where a new refusal nobody listed would pass
// silently — which is the mistake `report` made with outcome labels, described
// in CONTRACTS §4 item 37.
//
//nolint:gochecknoglobals // immutable table, read once
var nonRefusalStatuses = map[string]bool{
	"sekizuiv1.Status_STATUS_OK":               true,
	"sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED": true,
}

// TestEveryRefusalUsesTheConstructor.
//
// `status` and `kind` on a CommandResult are two views of one fault.Kind (D138),
// and refusalResult is the only thing that derives both from the same value.
// A refusal built by hand somewhere else sets a status and forgets the kind —
// which does not fail any behavioural test, because the status is still right
// and `kind` is merely empty. That is CONTRACTS §4 item 23 exactly: a declared
// proto field nothing populates, invisible to every check a reviewer would run.
//
// DERIVED FROM THE SOURCE, not from a list of known call sites. The list version
// of this idea is what let nine cited decisions go unchecked (see
// TestP1ProvesItsDecisions); a walk over the AST covers an exit path added next
// year without anyone remembering this test exists.
func TestEveryRefusalUsesTheConstructor(t *testing.T) {
	fset := token.NewFileSet()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	var checked int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}

		// The constructor itself is the one place allowed to build a refusal, so
		// its body is skipped rather than special-cased inside the walk.
		var inConstructor bool
		ast.Inspect(file, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				inConstructor = fn.Name.Name == "refusalResult"
				return true
			}
			if inConstructor {
				return true
			}

			lit, ok := n.(*ast.CompositeLit)
			if !ok || exprString(lit.Type) != "sekizuiv1.CommandResult" {
				return true
			}
			checked++

			status := "«unset»"
			for _, elt := range lit.Elts {
				kv, isKV := elt.(*ast.KeyValueExpr)
				if !isKV {
					continue
				}
				if key, isIdent := kv.Key.(*ast.Ident); isIdent && key.Name == "Status" {
					status = exprString(kv.Value)
				}
			}

			if !nonRefusalStatuses[status] {
				t.Errorf("%s:%d builds a CommandResult with Status %s by hand. "+
					"A refusal must go through refusalResult, which derives `status` and "+
					"`kind` from one fault.Kind — set separately they drift, and the "+
					"symptom is an empty `kind` that no behavioural test notices (D138)",
					name, fset.Position(lit.Pos()).Line, status)
			}
			return true
		})
	}

	// NON-VACUITY. A walk that found nothing would pass while proving nothing —
	// a renamed type or a moved file would silently disarm it.
	if checked == 0 {
		t.Error("no CommandResult literals found; the guard is not looking at anything")
	}
}

// TestEveryDeliberateKindHasAllThreeViews closes the guard from the taxonomy end.
//
// The AST walk above proves every refusal goes through the constructor. This
// proves the constructor produces something USEFUL for every kind it can be
// handed — a kind that is Deliberate but maps to no status would yield a result
// saying "refused" with nothing a caller can act on.
//
// **IT WAS CALLED "BOTH VIEWS" AND THERE ARE THREE.** `kind` and `status` are
// what a CALLER reads; the third is the VERDICT on the fsynced audit record,
// which is what a reviewer and a SIEM read, and it was checked by nothing. The
// omission was not theoretical — `KindInvalidArgument` mapped to no verdict, so
// `gateway.refuse` left the field as it found it, and one acceptance run
// produced three rows reading `VERDICT_ALLOW` with `refused_by` set for commands
// that never ran, plus one row with no verdict at all. The two views this test
// already had were both CORRECT on every one of those rows.
//
// The third arm drives the REAL FUNNEL rather than re-deriving the mapping,
// which is the difference between checking the invariant and restating the
// table. It seeds the base Decision with ALLOW and a matched_rule on purpose:
// that is the state a post-policy refusal actually arrives in, and it is the one
// a test written against a zero-valued Decision cannot see.
//
// DERIVED BY ITERATING fault.Kind, so a kind added at P2 is covered without
// anyone extending a list here.
func TestEveryDeliberateKindHasAllThreeViews(t *testing.T) {
	h := newHarness(t)
	var seen int
	for k := fault.Kind(0); k < fault.Kind(64); k++ {
		if k.String() == "" || strings.HasPrefix(k.String(), "Kind(") {
			continue // not a declared member
		}
		if !k.Deliberate() {
			continue
		}
		seen++

		res := refusalResult("d-1", k, "because")
		if res.GetKind() == "" {
			t.Errorf("kind %v produces an empty `kind` on the wire", k)
		}
		if res.GetKind() != k.String() {
			t.Errorf("kind %v produces `kind`=%q; it must be the same word the metric "+
				"label and the audit record use", k, res.GetKind())
		}
		if res.GetStatus() == sekizuiv1.Status_STATUS_UNSPECIFIED {
			t.Errorf("kind %v is Deliberate but maps to STATUS_UNSPECIFIED, so a caller "+
				"is told it was refused and given no usable status", k)
		}

		// THE THIRD VIEW: the row that outlives the call.
		base := &sekizuiv1.Decision{
			Identity:  &sekizuiv1.Identity{Caller: &sekizuiv1.Caller{Principal: "operator:oncall"}},
			Action:    "kata.create_issue",
			TargetRef: "kata:alpha",
			// AS A POST-POLICY REFUSAL ARRIVES: permitted by a named grant, and
			// then refused by a later stage.
			Verdict:     sekizuiv1.Verdict_VERDICT_ALLOW,
			MatchedRule: "operator:oncall#allow[0]",
		}
		if _, err := h.srv.refuse(context.Background(), base,
			sekizuiv1.RefusedBy_REFUSED_BY_POLICY, fault.New(k, "test.refuse", "because")); err != nil {
			t.Fatalf("kind %v: refuse: %v", k, err)
		}
		switch base.GetVerdict() {
		case sekizuiv1.Verdict_VERDICT_UNSPECIFIED:
			t.Errorf("kind %v is refused and recorded with no verdict at all — the row is "+
				"invisible to every query that filters on one", k)
		case sekizuiv1.Verdict_VERDICT_ALLOW:
			t.Errorf("kind %v is refused and recorded as VERDICT_ALLOW beside matched_rule "+
				"%q — the audit log says a command that never ran was permitted, and names "+
				"the grant that permitted it", k, base.GetMatchedRule())
		}
	}

	if seen < 5 {
		t.Errorf("only %d deliberate kinds found; the iteration is not reaching the "+
			"taxonomy and this test proves nothing", seen)
	}
}

// exprString renders a selector or identifier for comparison and messages.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	default:
		return ""
	}
}
