package archcheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// aheadOfItsPhase registers exported symbols with no in-tree user, and names the
// phase each one lands in.
//
// WHY A REGISTRY RATHER THAN A CALLER REQUIREMENT. The sibling guard in
// orphan_test.go demands that everything exported from `internal/` has a
// non-test caller, and that is right because Go guarantees nobody outside this
// module can import it. `pkg/` is the opposite by decision: D35 makes it the
// published API, so a self-hoster implementing `Provider` or a third-party
// driver borrowing from `connector.ClientPool` is the intended user and this
// walk will never see them. "Must have a caller" would be wrong there.
//
// What is NOT acceptable is silence. CONTRACTS §4 item 33 states the actual
// problem: **nothing distinguishes "ahead of its phase" from "forgotten"**, and
// no boot, lint or test reported either. So the requirement is a DECLARATION —
// each unused export names the phase that brings its user.
//
// THE ENTRY EXPIRES, AND THAT IS THE POINT. See
// TestRegisteredSymbolsAreStillUnused: a symbol listed here that GAINS a caller
// fails the build until the line is deleted. Without that, this table becomes
// what every allowlist becomes — a place where the reason stopped being true
// years ago and nobody looked. It is the same lesson the `permitted` table in
// orphan_test.go learned when a bare-name key silently covered every package's
// `Stats`.
//
//nolint:gochecknoglobals // immutable table, read once
var aheadOfItsPhase = map[string]string{
	// P1 steps 21-24: the local limiter, 429/Retry-After handling, backoff and
	// the breaker. Declared in DESIGN's P1 deliverables as
	// "`Limiter` (local + 429/`Retry-App`/backoff/breaker)".
	// Breaker and RetryAfterOf were here and are not any more: step 22 built
	// internal/limiter.Breaker and step 20 built the backoff that reads
	// Retry-After, so TestRegisteredSymbolsAreStillUnused failed until these
	// lines went. That is the expiry working, one turn after it was written.
	// Limiter was here until step 23 implemented it; Breaker and RetryAfterOf
	// until steps 20 and 22 did. Each line went because
	// TestRegisteredSymbolsAreStillUnused failed the build, which is the expiry
	// doing exactly what it was written for.

	// P3 exit criterion 5: "Stage-monotonicity checker rejects a deliberately
	// cyclic subject config at boot (D21)". The interface exists now because
	// D21 makes cycles structurally impossible rather than detected after the
	// fact, and the shape has to be settled before subjects are published.
	// THE CONFORMANCE SUITE, whose callers are tests here and third parties
	// everywhere else — the cleanest instance of the case this registry exists
	// for. D35 makes `Provider` the extension point, so the implementations that
	// most need a contract check are the ones no walk in this tree will ever see.
	//
	// It is NOT unused: every provider package invokes it, and
	// TestEveryProviderRunsTheConformanceSuite fails the build if a new one does
	// not. That guard is what keeps this registration from being a place the
	// suite quietly stopped mattering.
	"pkg/connector/conformance:Run": "the published Driver contract (D167); called from every driver's tests and " +
		"by out-of-tree implementers (D35). Registered for the same reason as its Provider " +
		"sibling below: a suite's callers are TESTS by construction, and this walk counts " +
		"non-test files only",
	"pkg/connector/conformance:RunHTTP": "the transport half of the Driver contract, SELECTED rather than folded " +
		"into Run (D167) — a driver built on a vendor SDK has no HTTP statuses to classify, " +
		"so a universal suite would pass vacuously against it, which is the finding D160 " +
		"paid for with `oauth-cc://`",
	"pkg/connector/conformance:RunDrift": "the DRIFT half of the Driver contract (D311), selected by a " +
		"connector that implements connector.Drifter — called from kata's, hako's and the MCP driver's " +
		"tests, and from an out-of-tree Drifter's (D35)",
	"pkg/connector/conformance:RunRefiner": "the REFINER half of the Driver contract (D317), selected by a " +
		"connector that ships `refines:` rules; called from Fullstory's tests and by an out-of-tree connector " +
		"that ships its own (D35, D299)",
	"pkg/connector/conformance:RunPresetter": "the PRESET half of the Driver contract (D327), selected by a " +
		"connector that suggests presets; called from kata's and Fullstory's tests, and by an out-of-tree " +
		"connector that ships its own presets.yaml (D35) — which has this suite and not the in-tree folder check",
	"pkg/connector/conformance:RunSource": "the SOURCE half of the Driver contract, selected rather than folded into " +
		"Run for RunHTTP's reason: most drivers are write-only, and a universal suite would " +
		"either fail them for not being a source or skip the half that matters (D160, D167, " +
		"D243). Called from `kata`'s tests and by out-of-tree implementers (D35)",

	"pkg/connector/conformance:InsecureClient": "the suite's servers are TLS with self-signed certificates and a driver " +
		"under test builds its own client, so it needs one that trusts them. Named for what " +
		"it is: a driver using this outside a test would be disabling certificate " +
		"verification on a credential path",
	"pkg/connector/conformance:NewPoolSpy": "the spy `RunSource`'s borrow arm needs (D255). It is " +
		"CONSTRUCTED BY THE AUTHOR rather than by the suite, because `RunSource` receives a " +
		"driver that is already built — so the pool has to be wired in at construction, which " +
		"means the constructor has to be published. Test-only in this tree and production " +
		"surface for D35's out-of-tree author, the same standing every other symbol in this " +
		"package has",

	"pkg/connector/conformance:Arms": "the suite's own declaration of what it asserts, and the SOURCE the " +
		"connector blueprint's contract table is generated from (D218). Registered with what " +
		"it IS rather than with a phase: its in-tree caller is P2 step 46, which this walk " +
		"does not count, and its out-of-tree reader is anyone rendering the contract " +
		"elsewhere. It is emphatically NOT unused — step 46 requires the arms DECLARED, " +
		"CALLED and LISTED to be one set, so this cannot become a list nobody maintains",
	"pkg/bus/conformance:Run": "the published Bus contract (D260) — since the transport applies " +
		"Filter.Scope, a driver that ignores it delivers every tenant's events; called from " +
		"internal/bus's tests and by out-of-tree bus drivers (D35)",
	"pkg/provider/conformance:Run":        "the published Provider contract; called from every provider's tests and by out-of-tree implementers (D35, D156)",
	"pkg/provider/conformance:RunChained": "the chained-provider contract (D131); same, and Run would pass vacuously for that shape",

	// SUBSTITUTION SEAMS, and registered with what they actually are rather than
	// with a phase, because claiming a future phase for something already in use
	// would be the exact rot this table exists to prevent. Both have in-tree
	// users TODAY — acceptance steps 15 and 16 — and this walk does not count
	// test callers, which is correct for `pkg/`: a symbol only tests use is a
	// symbol whose production justification has to be written down.
	//
	// Written down here: a self-hoster whose metadata endpoint is not at the
	// documented link-local address, and one whose cluster starts the metadata
	// DaemonSet slowly enough that three attempts at one second is not enough.
	// D35 makes both of those out-of-tree users this walk will never see.
	//
	// THREE MORE OPTIONS WERE WRITTEN BESIDE THESE AND DELETED. WithEnv, WithStat
	// and WithSleep: two had no caller at all and one was replaceable by
	// `t.Setenv`. This guard caught them within the hour, which is the argument
	// for it in miniature — a seam added because it might be wanted is the same
	// defect as a config field nothing reads (D142).
	"pkg/provider/ambient:WithMetadataBase": "test seam + D35 out-of-tree user: a metadata endpoint not at the documented address",
	"pkg/provider/ambient:WithProbeBounds":  "test seam + D35 out-of-tree user: a cluster whose metadata DaemonSet is slower than the default bounds allow",

	"pkg/bus:StageOrder": "P3 exit criterion 5 — the stage-monotonicity checker (D21, D43)",

	// **`internal/cursor:Store` WAS HERE AND IS GONE.** Its entry read "the
	// poller is the first consumer", and `kyuushin.New` took one within the
	// hour — so the guard demanded the deletion the same session the
	// prediction was written. That is the expiry working at the shortest
	// timescale it has yet run at (D139).

	// **`pkg/connector:Source` WAS HERE AND IS GONE, WHICH IS THE ENTRY DOING
	// ITS JOB.** It read "P3 — kyuushin, the inbound plane; the Jira poller is
	// the first implementer", and this guard demanded its deletion within
	// minutes of `kata` gaining a `Poll`. Worth one line on what the entry got
	// wrong: the implementer is `kata`, not Jira, because D243 makes the SHAPE
	// the deliverable and the real source its second user.

	// **D174's `RecoveryPolicy`, `RecoveryMode` and the two modes are NOT here,
	// and trying to register them is how that was learned.** They are referenced
	// from `Source.Recovery`'s signature and from each other inside
	// `pkg/connector`, so the walk counts them as used and the entries were
	// FALSE the moment they were written — the guard said so by name within a
	// minute. Worth leaving as a note: "exported and unused" here means unused
	// by anything, including its own package, and a type named in a published
	// interface's method set is used by construction.

	// --- deliberate test seams, matching orphan_test.go's `permitted` ---------
	//
	// EXPORTED SO A TEST CAN ENUMERATE THE SET rather than naming one member.
	// A hand-written key in the catalog's guard would rot silently the moment a
	// second facet is added — the test would keep passing, having checked
	// nothing about the new one. Production code uses IsReservedWhereKey.
	"pkg/config:ReservedWhereKeys": "test seam: lets a guard assert over EVERY reserved facet (D136)",

	// An option, in the shape D35 intends: a self-hoster needing a proxy or a
	// custom trust store sets it, and the acceptance run points it at httptest.
	// No in-tree production caller by design — the default client is correct.
	"pkg/provider/oauth:WithHTTPClient": "test seam and self-hoster option (D35, D131)",
}

// TestNoUnregisteredOrphansInPublicAPI extends the orphan guard to exported
// TYPES and to `pkg/` (CONTRACTS §4 item 33).
//
// The original walk covered exported FUNCS under `internal/` only, and its own
// comment gave the reason types were excluded: all four historical instances
// were callable code, and including types "produced enough false positives to
// make the guard noise". That reasoning holds for a caller requirement and
// dissolves under a registration requirement — a false positive here costs one
// line naming a phase, which is information worth having anyway.
func TestNoUnregisteredOrphansInPublicAPI(t *testing.T) {
	root := repoRoot(t)

	// KEYED `package:Symbol` IN BOTH MAPS, and the bug that forced it is worth
	// naming: keyed by BARE NAME, `internal/gateway:Resolver` overwrote
	// `pkg/connector:Resolver` and the orphan item 33 was written about vanished
	// from its own guard. That is the third appearance of this exact trap here —
	// orphan_test.go's `permitted` table records the first two — so the rule is
	// now: nothing in this package is ever keyed by a bare identifier.
	declared := exportedTypesAndFuncs(t, root, "pkg")
	for key, where := range exportedTypesAndFuncs(t, root, "internal") {
		// Funcs under internal/ are the sibling guard's business; only TYPES are
		// new here, and exportedTypesAndFuncs marks them.
		if strings.HasSuffix(where, "\x00type") {
			declared[key] = where
		}
	}
	referenced := referencedNames(t, root)

	var orphans []string
	for key := range declared {
		if referenced[key] {
			continue
		}
		if _, registered := aheadOfItsPhase[key]; registered {
			continue
		}
		orphans = append(orphans, key)
	}

	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("%d exported symbol(s) have no user in this tree and are not "+
			"registered.\n\nEach is either FORGOTTEN or AHEAD OF ITS PHASE, and nothing "+
			"currently tells those apart — which is the whole of CONTRACTS §4 item 33. "+
			"A published API legitimately has out-of-tree users (D35), so the "+
			"requirement is a DECLARATION rather than a caller: add it to "+
			"`aheadOfItsPhase` with the phase that brings its user, or delete it.\n\n  %s",
			len(orphans), strings.Join(orphans, "\n  "))
	}
}

// TestRegisteredSymbolsAreStillUnused is the inversion, and it is the half that
// keeps the registry honest.
//
// A registered symbol that has ACQUIRED a caller must be removed from the table.
// Without this the entry survives its own justification: the phase arrives, the
// user lands, and the line stays — now asserting something false about a symbol
// nobody rechecks. That is how every allowlist rots, and this codebase has
// already paid for it once, by manufacturing an exception to silence a guard
// that was right.
func TestRegisteredSymbolsAreStillUnused(t *testing.T) {
	root := repoRoot(t)
	referenced := referencedNames(t, root)

	var stale []string
	for key := range aheadOfItsPhase {
		if referenced[key] {
			stale = append(stale, key)
		}
	}

	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d registered symbol(s) now HAVE a user, so their entries are "+
			"false.\n\nDelete each line from `aheadOfItsPhase`: it says the symbol is "+
			"waiting for a phase that has evidently arrived, and an allowlist entry "+
			"whose reason stopped being true is worse than no entry at all.\n\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}

// TestSchemaPackageIsImportedUnderOneAlias.
//
// The generated protobuf package is literally named `v1`, because buf writes it
// to `pkg/schema/sekizui/v1` with `paths=source_relative`. An unaliased import
// therefore reads `v1.CommandResult` at every call site — meaningless on its own
// and guaranteed to collide, since a generated API is nearly always `.../v1`.
// The tree aliases it `sekizuiv1` at all of its import sites, and nothing
// enforced that.
//
// THE RISK IS DRIFT, NOT THE ALIAS. One file importing it as `pb` and another as
// `schema` is how a reader stops recognising the same package across files, and
// it is exactly the confusion a versioned schema will make expensive: when v2
// lands, `sekizuiv1` beside `sekizuiv2` is legible, while `pb` beside `schema`
// is a puzzle. Go's type system already stops the dangerous half — the two
// versions' messages are distinct types, so passing one where the other is
// wanted does not compile — and this covers the readability half it cannot.
func TestSchemaPackageIsImportedUnderOneAlias(t *testing.T) {
	const (
		path = `"github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"`
		want = "sekizuiv1"
	)

	root := repoRoot(t)
	fset := token.NewFileSet()

	var wrong []string
	var seen int

	for _, dir := range []string{"cmd", "internal", "pkg"} {
		walkGo(t, filepath.Join(root, dir), func(p string) {
			file, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parsing %s: %v", p, err)
			}
			for _, imp := range file.Imports {
				if imp.Path.Value != path {
					continue
				}
				seen++
				got := "«unaliased»"
				if imp.Name != nil {
					got = imp.Name.Name
				}
				if got != want {
					rel, _ := filepath.Rel(root, p)
					wrong = append(wrong, rel+" imports it as "+got)
				}
			}
		})
	}

	sort.Strings(wrong)
	if len(wrong) > 0 {
		t.Errorf("%d file(s) import the schema package under a different name. The "+
			"package is named `v1`, so every site must alias it %q or the tree ends up "+
			"with several names for one package — which is precisely what makes a v2 "+
			"hard to read alongside it.\n\n  %s",
			len(wrong), want, strings.Join(wrong, "\n  "))
	}

	// NON-VACUITY. A walk that matched no imports would pass while checking
	// nothing — a moved package or a changed module path would silently disarm
	// it, and this guard exists because nothing was watching in the first place.
	if seen == 0 {
		t.Error("no imports of the schema package found; the guard is not looking " +
			"at anything")
	}
}

// exportedTypesAndFuncs collects exported declarations under dir.
//
// The value carries the position and, for a type, a "\x00type" suffix so the
// caller can tell the two apart without a second walk. A sentinel rather than a
// struct because the sibling guard's map shape is `map[string]string` and
// keeping them alike is worth more than tidiness here.
func exportedTypesAndFuncs(t *testing.T, root, dir string) map[string]string {
	t.Helper()

	out := map[string]string{}
	fset := token.NewFileSet()

	walkGo(t, filepath.Join(root, dir), func(path string) {
		if strings.HasSuffix(path, "_test.go") {
			return
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		pkg, _ := filepath.Rel(root, filepath.Dir(path))

		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				// METHODS ARE OUT OF SCOPE, and it is a limit rather than an
				// oversight. A method is called as `value.Method()`, a selector
				// whose left side is a VARIABLE — attributing it to a package
				// needs go/types, and the syntactic walk cannot. Including them
				// reported 30 false positives (every method on fault.Kind among
				// them), which would have made the registry noise and the guard
				// worthless. A method on an exported type is part of the
				// published API by construction anyway; the gap this leaves is
				// recorded in CONTRACTS §4 item 33 rather than papered over.
				name := d.Name.Name
				if d.Recv != nil || !ast.IsExported(name) || strings.HasPrefix(name, "Test") {
					continue
				}
				out[pkg+":"+name] = posOf(fset, d.Pos())
			case *ast.GenDecl:
				if d.Tok != token.TYPE {
					continue
				}
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || !ast.IsExported(ts.Name.Name) {
						continue
					}
					out[pkg+":"+ts.Name.Name] = posOf(fset, ts.Pos()) + "\x00type"
				}
			}
		}
	})
	return out
}

// modulePath is the import prefix, so an import path can be turned back into the
// directory `declared` is keyed by.
const modulePath = "github.com/fullstorydev/sekizui/"

// referencedNames collects every reference to an exported symbol, keyed
// `package/dir:Symbol`, from non-test files.
//
// QUALIFIED, NEVER BARE, AND THIS GUARD GOT IT WRONG FIRST. The initial version
// returned bare names, which made `connector.Resolver` look used because
// `gateway.Resolver` and `resolver.Resolver` exist — three unrelated types
// sharing one name, and the orphan silently passed. That is the SAME defect
// orphan_test.go's `permitted` table already records: keyed on the name alone,
// allowlisting `credential.Stats` covered every package's `Stats`. Written down
// twice in this package and reproduced anyway, which is a decent argument for
// the note being where the code is.
//
// Resolution is syntactic rather than type-checked: a `pkg.Symbol` selector is
// attributed to whatever `pkg` is bound to in that FILE's imports, and a bare
// identifier to the file's own package. That is exact for package-qualified
// references, which is what matters here — a value's method call
// (`someTarget.Residency()`) attributes to nothing and is simply not counted,
// so the guard errs toward reporting an orphan rather than hiding one.
//
// BROADER THAN calledNames, DELIBERATELY. That one collects call and selector
// positions, which is right for functions and blind to types: a type appears in
// a field, a parameter, a composite literal or a type assertion, none of which
// is a call. Excluding the declaration's own name node is what makes "used" mean
// something — a `TypeSpec.Name` is an identifier too, so a naive walk reports
// every type as referenced by itself.
//
// NON-TEST FILES ONLY, for the reason the sibling guard gives: every historical
// instance of this bug class had passing tests, and being exercised by a test is
// exactly what made them look implemented.
func referencedNames(t *testing.T, root string) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	fset := token.NewFileSet()

	for _, dir := range []string{"cmd", "internal", "pkg"} {
		walkGo(t, filepath.Join(root, dir), func(path string) {
			if strings.HasSuffix(path, "_test.go") {
				return
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			own, _ := filepath.Rel(root, filepath.Dir(path))

			// alias -> package directory, for this file only. Import names are
			// per-file, so a tree-wide map would be wrong the moment two files
			// disagree — which TestSchemaPackageIsImportedUnderOneAlias exists to
			// stop for one package and cannot promise for the rest.
			aliases := map[string]string{}
			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if !strings.HasPrefix(p, modulePath) {
					continue
				}
				rel := strings.TrimPrefix(p, modulePath)
				name := rel[strings.LastIndex(rel, "/")+1:]
				if imp.Name != nil {
					name = imp.Name.Name
				}
				aliases[name] = rel
			}

			// The identifier nodes that ARE declarations, by pointer, so the walk
			// below skips exactly those and nothing that merely shares a name.
			declSites := map[*ast.Ident]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				switch d := n.(type) {
				case *ast.FuncDecl:
					declSites[d.Name] = true
				case *ast.TypeSpec:
					declSites[d.Name] = true
				}
				return true
			})

			// Selector `Sel` nodes handled by the SelectorExpr case, so the bare
			// walk does not also count them against the WRONG package.
			asSelector := map[*ast.Ident]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				asSelector[sel.Sel] = true
				if x, isIdent := sel.X.(*ast.Ident); isIdent {
					if pkgDir, known := aliases[x.Name]; known {
						out[pkgDir+":"+sel.Sel.Name] = true
					}
				}
				return true
			})

			ast.Inspect(file, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && !declSites[id] && !asSelector[id] {
					out[own+":"+id.Name] = true
				}
				return true
			})
		})
	}
	return out
}
