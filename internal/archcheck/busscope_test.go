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

// TestEveryBusSubscriptionIsScoped is D260's structural half.
//
// A subscription's authorisation is a Scope compiled from configuration by
// `gateway.ScopeFor`, applied by the transport and asserted on receipt — and all
// three happen only if the subscription is opened through `openScoped`. Two
// ways round that, and this guard closes both in PRODUCTION code:
//
//   - **a second call site for `Bus.Subscribe`.** It would choose its own scope
//     or none, and the reflex engine arriving in P3 is exactly the second
//     consumer that would be tempted to — D155's second path, aimed at the bus.
//   - **`Unscoped`, anywhere but a test.** It exists so P1 step 42 can prove
//     decisions never reach the bus with the broadest subscription there is.
//     In production it is every tenant's events for whoever sets it.
//
// SYNTACTIC, AND SAYS SO. It flags any two-argument `.Subscribe(` call and any
// `Unscoped` field set to something other than `false`, without type
// information — so a gRPC client stub's `Subscribe(ctx, req)` in production
// code would trip it too. None exists today, and one would earn an exemption
// here with its reason, rather than a type-checked walk nobody would write.
func TestEveryBusSubscriptionIsScoped(t *testing.T) {
	root := repoRootFor(t)

	// The one sanctioned call site, and the transport that implements the
	// method (whose own Subscribe is a declaration, not a call).
	//
	// And the published bus conformance suite, which is not a consumer at all:
	// it drives a TRANSPORT directly to check the transport honours Scope, and
	// going through openScoped would test the gateway instead of the driver.
	//
	// And the dev tap's capture (D273) — the gRPC-client false positive this
	// comment's header predicted: `client.Subscribe(ctx, req)` is a CLIENT of
	// the gateway, subscribing through openScoped from outside the process
	// like any agent, and it never holds a bus.
	allowedSubscribe := map[string]bool{
		"internal/gateway/subscribe.go":      true,
		"pkg/bus/conformance/conformance.go": true,
		"internal/tap/tap.go":                true,
	}

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
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			strings.HasSuffix(path, ".pb.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)

		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "Subscribe" && len(n.Args) == 2 && !allowedSubscribe[rel] {
					offenders = append(offenders, rel+": calls .Subscribe( outside openScoped")
				}
			case *ast.KeyValueExpr:
				if k, ok := n.Key.(*ast.Ident); ok && k.Name == "Unscoped" && !isFalse(n.Value) {
					offenders = append(offenders, rel+": sets Unscoped in a composite literal")
				}
			case *ast.AssignStmt:
				for i, lhs := range n.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Unscoped" {
						continue
					}
					if i < len(n.Rhs) && isFalse(n.Rhs[i]) {
						continue // clearing it is what openScoped does
					}
					offenders = append(offenders, rel+": assigns Unscoped")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("%d bus subscription(s) bypass the scope:\n  %s\n\n"+
			"Subscribe through gateway.openScoped, which authorises against the principal's "+
			"grant, records the decision once and compiles the Scope with ScopeFor (D259, "+
			"D260). A subscription opened any other way chooses its own authorisation, and "+
			"Unscoped in production code delivers every tenant's events.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

func isFalse(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "false"
}
