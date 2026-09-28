package archcheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadinessIsWithdrawnBeforeTheDrain guards a TWO-STATEMENT ORDERING that
// nothing else can see.
//
// **THE INVARIANT.** `spine.BeginStopping` must be called before
// `DrainAdmission`, so readiness is withdrawn before the process waits for
// in-flight work. Get it the other way around and the process spends its entire
// drain window — the longest part of a shutdown, with a grace period sized for
// it — still answering `/readyz` with "ready", so the load balancer keeps
// sending work while we wait for work to finish.
//
// **WHY A GUARD RATHER THAN A COMMENT.** That is exactly how it was written the
// first time: `spine.Stop` recorded STOPPING before stopping components and its
// doc comment promised "the load balancer must stop sending work before the
// process stops accepting it" — while the drain ran earlier, in another
// function, and made the promise false. The bug was in the ORDER of two
// statements, each correct, in a function no test can call (`run` builds a
// process). Nothing here is checkable at runtime either: both orderings shut
// down cleanly, and the difference shows up as requests arriving at a draining
// pod.
//
// **AN AST WALK, and P1 step 68's arm is the precedent** — it requires `Enforce`
// to reach the far side through `enforceOnce` rather than resolving and calling
// inline, which is the same shape of claim: not what a function computes, but
// what it does first.
func TestReadinessIsWithdrawnBeforeTheDrain(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	const (
		withdraw = "BeginStopping"
		drain    = "DrainAdmission"
	)

	var (
		foundWithdraw, foundDrain bool
		withdrawPos, drainPos     token.Pos
	)

	walkGo(t, filepath.Join(root, "cmd"), func(path string) {
		if strings.HasSuffix(path, "_test.go") {
			return
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case withdraw:
				// FIRST occurrence only: `spine.Stop` calls it again internally
				// and a later call must not be able to satisfy this.
				if !foundWithdraw {
					foundWithdraw, withdrawPos = true, call.Pos()
				}
			case drain:
				if !foundDrain {
					foundDrain, drainPos = true, call.Pos()
				}
			}
			return true
		})
	})

	// NON-VACUITY FIRST, because a guard for two calls passes trivially once
	// either call is renamed away — and the rename is the likely change.
	if !foundWithdraw {
		t.Fatalf("no call to %s in cmd/, so this guard is checking nothing. Readiness "+
			"must be withdrawn explicitly before the drain; if the mechanism was "+
			"renamed, rename it here", withdraw)
	}
	if !foundDrain {
		t.Fatalf("no call to %s in cmd/, so this guard is checking nothing", drain)
	}

	if withdrawPos > drainPos {
		t.Errorf("%s is called at %s, AFTER %s at %s.\n\nReadiness must be withdrawn "+
			"BEFORE the drain: otherwise the process waits for in-flight work while "+
			"still advertising itself ready, so the load balancer keeps sending work "+
			"to a pod that is shutting down. `spine.Stop` withdrawing readiness first "+
			"is not enough on its own — it runs after the drain.",
			withdraw, fset.Position(withdrawPos), drain, fset.Position(drainPos))
	}
}
