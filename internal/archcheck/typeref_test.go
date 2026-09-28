package archcheck

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// THE TYPE-RESOLVED ANSWER TO "WHAT DOES THIS TREE DECLARE, AND WHAT DOES IT
// REFERENCE" — and why a syntactic walk could not give it.
//
// The guards in this package used to answer both questions from the AST alone,
// and each was imprecise in a DIFFERENT direction:
//
//   - orphan_test.go's `calledNames` collected BARE identifiers, so the orphan
//     guard could not tell `obs.Handle` from any other `.Handle(` in the tree.
//     It erred toward false NEGATIVES — a missed orphan, which is the quiet
//     direction and was tolerable for the main guard. It also made the
//     `permitted` allowlist UNCHECKABLE in the other direction, which is what
//     let `internal/metrics:Incr` survive its own justification: registered as
//     "Observe covers every current call site" and made false by D204's churn
//     counter, with nothing to say so.
//   - public_test.go's `referencedNames` resolves a `pkg.Symbol` selector
//     through the FILE's imports, which is exact for package-qualified
//     references and blind to a method call on a value. It therefore excludes
//     METHODS entirely, and says so: "attributing it to a package needs
//     go/types, and the syntactic walk cannot" (CONTRACTS 33).
//
// AND THE DECLARED SIDE HAD THE SAME FLAW, WHICH NOBODY HAD WRITTEN DOWN.
// `exportedDecls` returned `map[symbol]where`, last-wins. Measured before this
// landed: 298 exported func and method declarations in `internal/`, 202
// distinct names, so **96 declarations across 38 colliding names were never
// asked about at all** — `New` 17 times, `Name` 7, `Validate` 6, `Close` and
// `WithClock` 5 each. That is worse than an imprecise answer: it is a question
// never posed for a third of the surface. It was hiding at least one real
// orphan (`internal/limiter:(*Breaker).State`, which passed only because
// `internal/identity` writes `tlsInfo.State.PeerCertificates` — a stdlib struct
// field in an unrelated package).
//
// THE INVERSION WAS WRITTEN AND WITHDRAWN ONCE ON THE SYNTACTIC VERSION
// (CONTRACTS 79): it reported five false positives, because `recorder.Intent`,
// `lenses.Deliver` and their like are reached through an interface-typed field
// and never appear with a package qualifier anywhere. The information is not in
// the syntax, so the fix is not a better pattern.
//
// WHY THIS IS WORTH A MODULE. `golang.org/x/tools` was ALREADY in the module
// graph at v0.43.0, required by `golang.org/x/text`, and v0.38.0 is already
// linked into the `golangci-lint` binary `make verify` runs — one of 202
// third-party modules in it. Pinned here at **v0.44.0 deliberately**: it is the
// newest release whose own requirements are `x/net` v0.53.0 and `x/sys`
// v0.43.0, the versions this module already pins, so adopting it moves NOTHING
// in the shipped binary. v0.49.0 would have raised `x/net` to v0.58.0 —
// grpc's HTTP/2 path — which is a production change arriving as a side effect of
// a test-only tool, and D58 does not take dependencies that way.
// TestTypeLoaderStaysInTests keeps it out of the binary entirely.

// symbols is the loaded tree's declaration and reference sets.
//
// KEYED `package:Symbol` FOR A FUNCTION AND `package:Receiver.Method` FOR A
// METHOD, on BOTH sides. This package's rule is that nothing is ever keyed by a
// bare identifier — learned three times over (see `permitted`'s comment and
// `referencedNames`') — and a receiver-qualified key is that rule finally
// applied within a package as well as across them: `internal/driver/mcp` holds
// both `(Findings).RefusesTarget` and `(Severity).RefusesTarget`, so a
// `pkg:Name` key would leave a smaller instance of the same hole we came here
// to close.
type symbols struct {
	// declared maps key -> "file:line", for exported funcs and methods declared
	// in non-test files under the requested directory.
	declared map[string]string

	// direct holds keys the tree references BY RESOLVED IDENTITY: a call, a
	// method value, or any other use whose object is that exact declaration.
	// A declaration's own name node is in TypesInfo.Defs rather than Uses, so
	// it is excluded structurally — which is the trap the orphan guard's first
	// attempt fell into (it accepted a reference from the declaring package,
	// which is true of every symbol ever written).
	direct map[string]bool

	// viaInterface holds keys reachable only through an interface: the receiver
	// satisfies an interface DECLARED IN THIS MODULE whose method of that name
	// the tree references somewhere.
	//
	// IN-MODULE INTERFACES ONLY, and that boundary is the load-bearing choice.
	// For a foreign interface the CALL SITE is code we cannot see — an in-tree
	// reference to `io.Closer.Close` says nothing about whether anything calls
	// OUR type's `Close` — so propagating through one would mark a method used
	// on the strength of evidence about somebody else's. Those cases keep
	// needing a `permitted` entry, which is already that table's first and
	// best-documented category ("implementations of interfaces defined OUTSIDE
	// this module"). For an in-module interface the opposite holds: we declare
	// it, we call through it, and the implementers are the intended targets.
	//
	// THE RESIDUAL, STATED RATHER THAN HIDDEN: a single-method in-module
	// interface (`pool.Closer`) marks every implementer's method of that name
	// reachable once any one of them is called through it. That errs toward a
	// missed orphan, the quiet direction, and it is why the inversion below
	// consults `direct` alone.
	viaInterface map[string]bool
}

// used answers the main guard's question: is this symbol referenced at all.
func (s *symbols) used(key string) bool {
	return s.direct[key] || s.viaInterface[key]
}

// loadSymbols type-checks the whole module and resolves every reference in it.
//
// NON-TEST FILES ONLY, VIA `Tests: false` RATHER THAN A FILENAME FILTER. Every
// one of the historical instances of this bug class had passing tests, and being
// exercised by a test is exactly what made them look implemented. Asking the
// loader for the non-test build is stronger than skipping `_test.go` paths
// afterwards: an in-package test file cannot be reached at all, so there is no
// filter to forget.
func loadSymbols(t *testing.T, root, dir string) *symbols {
	t.Helper()

	pkgs := loadModule(t, root)

	s := &symbols{
		declared:     map[string]string{},
		direct:       map[string]bool{},
		viaInterface: map[string]bool{},
	}

	// Every named type in the module, for the interface propagation below. Built
	// once: the check is O(interfaces x types) and both sets are small, but
	// rebuilding the type list per interface would not be.
	var named []*types.Named
	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			// UNEXPORTED TYPES INCLUDED, deliberately. `auditwal.restricted`
			// implements `audit.Sink`, and the methods it carries are EXPORTED
			// methods on an unexported type — which is exactly the shape whose
			// `Name` and `Residencies` were among the 96 collapsed declarations.
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			if n, ok := types.Unalias(tn.Type()).(*types.Named); ok {
				named = append(named, n)
			}
		}
	}

	want := filepath.ToSlash(dir) + "/"
	ifaceUses := map[*types.Interface]map[string]bool{}

	for _, pkg := range pkgs {
		rel, ok := moduleDir(pkg.PkgPath)
		if !ok {
			continue
		}

		// --- declarations, from the AST but IDENTIFIED by the type checker ----
		//
		// The AST supplies the set (an exported FuncDecl in a non-test file, the
		// same scope the syntactic version had, so this is a precision change
		// and not a scope change), and TypesInfo.Defs supplies the receiver,
		// which is the half the AST cannot give exactly.
		if strings.HasPrefix(rel+"/", want) {
			for _, file := range pkg.Syntax {
				for _, decl := range file.Decls {
					fd, isFunc := decl.(*ast.FuncDecl)
					if !isFunc {
						continue
					}
					name := fd.Name.Name
					if !ast.IsExported(name) || strings.HasPrefix(name, "Test") {
						continue
					}
					fn, isFn := pkg.TypesInfo.Defs[fd.Name].(*types.Func)
					if !isFn {
						continue
					}
					if key, okKey := symbolKey(fn); okKey {
						s.declared[key] = posOf(pkg.Fset, fd.Pos())
					}
				}
			}
		}

		// --- references, resolved --------------------------------------------
		for _, obj := range pkg.TypesInfo.Uses {
			fn, isFn := obj.(*types.Func)
			if !isFn {
				continue
			}
			// Origin() collapses an instantiated generic method back to the
			// declaration, so a reference through a type argument still names
			// the thing that was written.
			fn = fn.Origin()

			if iface, method, isIface := interfaceMethod(fn); isIface {
				if ifaceUses[iface] == nil {
					ifaceUses[iface] = map[string]bool{}
				}
				ifaceUses[iface][method] = true
				continue
			}
			if key, okKey := symbolKey(fn); okKey {
				s.direct[key] = true
			}
		}
	}

	// --- propagate through in-module interfaces -----------------------------
	for iface, methods := range ifaceUses {
		for _, n := range named {
			if !satisfies(n, iface) {
				continue
			}
			dir, okDir := moduleDir(n.Obj().Pkg().Path())
			if !okDir {
				continue
			}
			for method := range methods {
				s.viaInterface[dir+":"+n.Obj().Name()+"."+method] = true
			}
		}
	}

	// NON-VACUITY, and this package has paid for its absence twice: D185's
	// extractors return an error rather than an empty match, because "an
	// extractor that silently matches nothing turns its guard into a no-op that
	// PASSES". A type load that resolved nothing would pass every guard here.
	if len(s.declared) == 0 || len(s.direct) == 0 {
		t.Fatalf("the type load resolved %d declarations and %d references under %s — "+
			"one of them is zero, so every guard built on it would pass vacuously. "+
			"Something is wrong with the load rather than with the tree",
			len(s.declared), len(s.direct), dir)
	}
	return s
}

// loadModule type-checks every package in the module.
func loadModule(t *testing.T, root string) []*packages.Package {
	t.Helper()

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
		Dir: root,
		// TESTS EXCLUDED — see loadSymbols. This is the whole of the
		// "non-test files only" rule, expressed once.
		Tests: false,
		// `packages.Load` SHELLS OUT to `go list`, and the repo toolchain is
		// deliberately NOT on the ambient PATH (the Makefile header explains
		// why: this monorepo's direnv points GOPATH at another project). Under
		// `make` the PATH is already right; this makes a bare
		// `go test ./internal/archcheck/` work too, rather than failing with
		// `go` not found and blaming the guard.
		Env: append(os.Environ(),
			"PATH="+filepath.Join(build.Default.GOROOT, "bin")+string(os.PathListSeparator)+os.Getenv("PATH")),
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("type-checking the module: %v\n\nThis guard needs a real type load "+
			"rather than a syntax walk (CONTRACTS 79). Run it through `make verify`, "+
			"which puts the repo toolchain on PATH.", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("the type load returned no packages, so every guard built on it would " +
			"pass vacuously")
	}

	// A PACKAGE THAT FAILS TO TYPE-CHECK YIELDS AN EMPTY REFERENCE SET, NOT AN
	// ERROR, so a silent failure here would read as "nothing references this"
	// for every symbol in it — the guard would report the whole package as
	// orphaned, or worse, report nothing because `Uses` is empty on both sides.
	// Refused outright.
	var broken []string
	for _, pkg := range pkgs {
		for _, e := range pkg.Errors {
			broken = append(broken, pkg.PkgPath+": "+e.Error())
		}
		if pkg.Types == nil || pkg.TypesInfo == nil {
			broken = append(broken, pkg.PkgPath+": no type information")
		}
	}
	if len(broken) > 0 {
		sort.Strings(broken)
		t.Fatalf("%d package(s) did not type-check, so the reference set is incomplete "+
			"and no answer from it can be trusted:\n\n  %s",
			len(broken), strings.Join(broken, "\n  "))
	}
	return pkgs
}

// symbolKey renders a func or method as `package:Symbol` / `package:Recv.Method`.
//
// Reports false for anything outside this module, which is most of what a
// reference set contains.
func symbolKey(fn *types.Func) (string, bool) {
	if fn.Pkg() == nil {
		return "", false // a builtin or an error method on a foreign type
	}
	dir, ok := moduleDir(fn.Pkg().Path())
	if !ok {
		return "", false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return "", false
	}
	recv := sig.Recv()
	if recv == nil {
		return dir + ":" + fn.Name(), true
	}
	name := receiverName(recv.Type())
	if name == "" {
		return "", false
	}
	return dir + ":" + name + "." + fn.Name(), true
}

// interfaceMethod reports whether fn is a method declared ON AN INTERFACE, and
// returns the interface and the method name.
//
// The distinction is the receiver's UNDERLYING type: an interface method's
// receiver is the interface, a concrete method's is a struct, a basic type or a
// slice. Nothing else separates them, and getting it wrong in either direction
// breaks the propagation — a concrete method treated as an interface one would
// propagate to every sibling implementation.
//
// **AN ANONYMOUS INTERFACE COUNTS, AND LEAVING IT OUT COST TWO FALSE POSITIVES
// ON THE FIRST RUN.** GO-PRIMER §2.2's optional-interface idiom is written
// INLINE at its assertion site throughout this tree —
// `r.(interface{ PostureOf(ref string) (config.Posture, bool) })` in
// `stampPosture`, `s.bus.(interface{ Dropped() uint64 })` in `BusDropped` — so
// the receiver is an unnamed `*types.Interface` and the first version dropped
// the reference entirely, reporting `resolver.PostureOf` and `bus.Dropped` as
// orphans while the call sites sat in the same file it had just parsed. An
// anonymous interface needs no in-module test: it is written in the source
// being walked, so the call site is ours by construction.
func interfaceMethod(fn *types.Func) (*types.Interface, string, bool) {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil, "", false
	}

	switch recv := types.Unalias(sig.Recv().Type()).(type) {
	case *types.Interface:
		return recv, fn.Name(), true
	case *types.Named:
		iface, isIface := recv.Underlying().(*types.Interface)
		if !isIface {
			return nil, "", false
		}
		if recv.Obj().Pkg() == nil {
			return nil, "", false
		}
		if _, inModule := moduleDir(recv.Obj().Pkg().Path()); !inModule {
			return nil, "", false // see `viaInterface`: a foreign interface does not propagate
		}
		return iface, fn.Name(), true
	default:
		return nil, "", false
	}
}

// satisfies reports whether the type or its pointer implements the interface.
//
// BOTH FORMS, because a method set with pointer receivers belongs to the
// pointer: `*JSONLSink` implements `audit.Sink` and `JSONLSink` does not, and
// checking only the value would propagate to nothing at all.
func satisfies(n *types.Named, iface *types.Interface) bool {
	if iface.Empty() {
		// `any` is implemented by everything, so propagating through it would
		// mark every method in the tree reachable.
		return false
	}
	return types.Implements(n, iface) || types.Implements(types.NewPointer(n), iface)
}

// receiverName is the receiver's type name, with the pointer and any alias
// stripped.
func receiverName(t types.Type) string {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}

// moduleDir turns an import path into the repo-relative directory the guards key
// on, and reports whether the path is in this module at all.
func moduleDir(path string) (string, bool) {
	if !strings.HasPrefix(path, modulePath) {
		return "", false
	}
	return strings.TrimPrefix(path, modulePath), true
}

// TestTypeLoaderStaysInTests keeps the new dependency out of the binary.
//
// `golang.org/x/tools` is here to make ONE GUARD precise, and the argument for
// taking it (typeref_test.go's header) rests entirely on it never being linked
// into anything that ships: a test-only import cannot reach production code, so
// a compromise of it reaches a developer's machine and CI — which
// `./bin/golangci-lint` already exposes, since that binary links 202
// third-party modules including this one — and never a deployment.
//
// **THAT IS A CLAIM ABOUT THE IMPORT GRAPH, SO IT IS ASSERTED ON THE IMPORT
// GRAPH.** Nothing else would notice: `go build` succeeds either way, `go.mod`
// does not distinguish a test dependency from any other, and the module would
// simply appear in the binary's `go version -m` output where nobody looks.
//
// NON-VACUITY MATTERS MORE HERE THAN USUAL. A guard that forbids an import
// passes trivially once the import is gone for the wrong reason — somebody
// reverting the type load would leave this test green while the reason for
// having the dependency at all had disappeared. So the absence in production is
// asserted TOGETHER with the presence in tests.
func TestTypeLoaderStaysInTests(t *testing.T) {
	const dep = "golang.org/x/tools"

	root := repoRoot(t)
	fset := token.NewFileSet()

	var inProduction []string
	inTests := 0

	for _, dir := range []string{"cmd", "internal", "pkg"} {
		walkGo(t, filepath.Join(root, dir), func(path string) {
			parsed, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			for _, imp := range parsed.Imports {
				if !strings.HasPrefix(strings.Trim(imp.Path.Value, `"`), dep) {
					continue
				}
				if strings.HasSuffix(path, "_test.go") {
					inTests++
					continue
				}
				rel, _ := filepath.Rel(root, path)
				inProduction = append(inProduction, rel)
			}
		})
	}

	sort.Strings(inProduction)
	if len(inProduction) > 0 {
		t.Errorf("%s is imported by %d NON-TEST file(s):\n\n  %s\n\nThe whole case for "+
			"taking this dependency (D58 takes them deliberately) is that it is confined to "+
			"the guards and can never be linked into a deployment. A production import "+
			"falsifies that, and the module's own supply-chain argument with it: move the "+
			"code into a _test.go file, or make the case for shipping it.",
			dep, len(inProduction), strings.Join(inProduction, "\n  "))
	}
	if inTests == 0 {
		t.Errorf("%s is imported by NO test file either, so this guard is passing "+
			"vacuously.\n\nEither the type-resolved guard has been reverted — in which case "+
			"the dependency should come out of go.mod in the same change, and CONTRACTS 79 "+
			"reopens — or the import moved somewhere this walk does not reach.", dep)
	}
}
