package archcheck_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// identityMinters are the only sites that may construct a `sekizuiv1.Identity`.
//
// **THE ASYMMETRY THIS CLOSES (CONTRACTS 90, D215).** §6 mechanism 1 makes
// `connector.Target` unconstructable outside the resolver, precisely because "a
// pooled client keyed on a stale or incomplete PoolKey will eventually hand back
// a client belonging to another tenant, and no amount of care at construction
// prevents that — the bug is in the cache, not the constructor". Identity had no
// equivalent, and it is the more audit-relevant of the two: D39 embeds it WHOLE
// into every Decision.
//
// **WHAT IT DEFENDS AGAINST IS A FALSE ATTRIBUTION, NOT AN UNAUTHORISED ACTION,
// and being precise about that is what keeps the guard honestly scoped.**
// Anything in-process that could forge an Identity could equally bypass
// `Enforce` and call a driver directly, so this is not a new route to doing
// something forbidden. It is a route to a RECORD NAMING A PRINCIPAL THAT NEVER
// ASKED — and the audit log is the artefact this system exists to produce.
//
// **AN ALLOWLIST RATHER THAN A `Verified` WRAPPER TYPE, which was the other
// candidate and is the maintainer's call.** A newtype would make the guarantee structural,
// and it would change `Enforce`'s signature and every caller including the
// out-of-tree ones D35 invites — a large public-API change to close a gap that
// needs an in-process bug rather than an attacker. D139 and D205 established
// that a registry with a stated reason per entry is the proportionate instrument.
//
// Each entry names WHY that site legitimately mints one. An entry whose reason
// stops being true is caught by reading, which is the same residual
// `archcheck.permitted` carries.
//
//nolint:gochecknoglobals // immutable registry, read once
var identityMinters = map[string]string{
	"internal/identity/identity.go": "THE ONE THAT MATTERS: `Verify` builds an identity from a " +
		"verified mTLS peer and authorised metadata, and it is the only site that derives " +
		"rather than declares. Every other entry here mints one for a principal that has no " +
		"connection to derive from",

	"internal/reflex/engine.go": "D18: reflexes are principals like any other, with no bypass. A " +
		"rule firing has no wire identity, so the engine mints one naming the rule's own " +
		"principal — which is exactly what makes a reflex's actions attributable rather than " +
		"anonymous",

	"internal/gateway/anzenfire.go": "the anzen minter (D134), moved from cmd/sekizui/main.go by " +
		"D332 so the binary and the acceptance harness fire rules through one function. A rule " +
		"pulling a lever acts as " +
		"`anzen:<rule>`, narrowed by `anzenAuthorise` to that one rule on that one target, so " +
		"an audit log reading `anzen` cannot be made to mean anything wider",

	"internal/gateway/driftgate.go": "D311: the drift principal. A comparison is an outbound call " +
		"with a target's credential and has no wire identity, so it is recorded as the built-in " +
		"`sekizui:drift-watcher` — closed to one action, granted nothing, still under every ceiling",

	"internal/kyuushin/kyuushin.go": "D250's SCHEDULE half. A job a CALLER asked for " +
		"carries that caller's own identity end to end and mints nothing; a job a SCHEDULE " +
		"fired has no connection to derive one from, so the runner declares `source:<ref>` — " +
		"the same case, and the same reasoning, as the reflex engine two entries up. The " +
		"gateway's job binding deliberately does NOT appear here: it was rebuilding an " +
		"identity from a principal string and this guard is what found it, which is the " +
		"registry doing the job an allowlist is for",

	"internal/gateway/handles.go": "D291's handle expiry. Sekizui closes an idle handle, and " +
		"every handle at the drain, AS ITS OPENER — whose grant must cover the closer, checked " +
		"at load — with an INTERNAL caller naming `sekizui:handle-expiry` and a causation " +
		"joining the close to the open's decision, so the record credits the opener and says " +
		"the close was system-initiated. Minted from the recorded opener, never from a string " +
		"a caller supplied, and dispatched through Enforce like every other command (D18).",
	"internal/catalog/catalog.go": "the Describe PROBE. `capabilitiesFor` asks the policy engine " +
		"what a principal may do, which needs an identity to ask WITH — and the probe never " +
		"reaches `Enforce`, so nothing it constructs is ever recorded as having acted",
}

// TestOnlyNamedSitesMintAnIdentity keeps identity construction to the four sites
// that legitimately derive or declare one (CONTRACTS 90).
//
// **AST RATHER THAN A GREP, because the string `sekizuiv1.Identity` appears in
// doc comments, in type assertions and in function signatures all over the
// tree.** What is being forbidden is a COMPOSITE LITERAL — the act of building
// one — and only a parse can tell that from a mention.
func TestOnlyNamedSitesMintAnIdentity(t *testing.T) {
	root := repoRootFor(t)

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "bin", "out", ".gocache", "dev", "schema":
				return filepath.SkipDir
			}
			return nil
		}
		// **TESTS ARE EXEMPT, DELIBERATELY.** `assertedIdentity` and its
		// relatives exist so a step can drive the enforcement path without a
		// TLS peer, and forbidding them would mean either a certificate per
		// acceptance arm or no acceptance suite. The guarantee this guard makes
		// is about the SHIPPED binary; step 18 is what proves the real path
		// derives attribution rather than declaring it.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// The generated package DEFINES the type; it is not a caller.
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		if strings.HasPrefix(slash, "pkg/schema/") {
			return nil
		}
		if _, allowed := identityMinters[slash]; allowed {
			return nil
		}

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if identityLiteral(lit.Type) {
				offenders = append(offenders,
					slash+":"+fset.Position(lit.Pos()).String()[strings.LastIndex(
						fset.Position(lit.Pos()).String(), ":")+1:])
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Errorf("%d site(s) outside the registry construct a sekizuiv1.Identity:\n  %s\n\n"+
			"An Identity is embedded WHOLE into every Decision (D39), so a hand-built one is a "+
			"record naming a principal that never asked — and the audit log is the artefact "+
			"this system exists to produce. Derive one through identity.Verify, or add the site "+
			"to identityMinters with the reason it legitimately declares rather than derives "+
			"(CONTRACTS 90, D215).",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// TestIdentityMinterRegistryIsNotStale fails when an entry names a file that has
// stopped minting one.
//
// **THE INVERSION, which D205 made the house rule after `permitted` grew entries
// whose stated reasons had quietly become false.** An allowlist that only ever
// grows is one nobody re-reads; this makes a retired minter a build failure
// rather than a line somebody might notice.
func TestIdentityMinterRegistryIsNotStale(t *testing.T) {
	root := repoRootFor(t)

	for _, rel := range sortedMinters() {
		path := filepath.Join(root, rel)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("identityMinters names %q, which does not exist: %v", rel, err)
			continue
		}
		if !strings.Contains(string(b), "sekizuiv1.Identity{") {
			t.Errorf("identityMinters names %q, which no longer constructs an Identity. "+
				"Delete the entry: an allowlist entry whose reason stopped being true is "+
				"worse than no entry at all (D205's finding, and CONTRACTS 48's lesson "+
				"arriving in an allowlist)", rel)
		}
	}
}

func sortedMinters() []string {
	out := make([]string, 0, len(identityMinters))
	for k := range identityMinters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// identityLiteral reports whether a composite-literal type is a
// `sekizuiv1.Identity` or a pointer to one.
func identityLiteral(e ast.Expr) bool {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Identity" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	// **THE ALIAS IS PART OF THE CHECK.** `TestSchemaPackageIsImportedUnderOneAlias`
	// requires every site to import the generated package as `sekizuiv1`, which
	// is what lets this match on the qualifier rather than resolving types.
	return ok && pkg.Name == "sekizuiv1"
}
