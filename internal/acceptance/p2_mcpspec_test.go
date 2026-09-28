package acceptance

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/mcpspec"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// P2 step 28: the authoring tool cannot mint `vendor` provenance.

// step28TheAuthoringToolCannotMintVendorProvenance is the whole security
// argument for `cmd/sekizui-mcpspec` (D168).
//
// **D51 EXISTS TO STOP A HAND-WRITTEN GUESS MASQUERADING AS A VENDOR
// GUARANTEE, AND A GENERATED GUESS IS THE SAME THING WITH MORE CONFIDENCE
// BEHIND IT.** So the claim is not "the tool sets local by default" — a default
// is a thing somebody overrides — but that there is NO PATH to `vendor` at all.
//
// Asserted three ways, because each catches what the others cannot:
//
//   - STRUCTURALLY, over the package's own source. A behavioural test can only
//     show the paths it thought to drive; the absence of a path is a claim about
//     the code, and only reading the code can make it.
//   - BEHAVIOURALLY, over what the command emits, because "the word does not
//     appear" would also be true of a tool that emitted no provenance at all.
//   - BY CONSEQUENCE, over `mcp.CompareToSpec`, because the reason provenance
//     matters is that `local` is never drift-checked — and if that stopped being
//     true, the two arms above would still pass while the guarantee was gone.
func step28TheAuthoringToolCannotMintVendorProvenance(t *testing.T) {
	root := mustRoot(t)

	// **BOTH DIRECTORIES, and the split is why.** The drafting logic lives in
	// `internal/mcpspec` so this step can call it; the command is wiring. A
	// guard aimed at only one of them would be satisfied by moving the defect
	// into the other, which is the shape D155 found when `Query` grew its own
	// abbreviated copy of the enforcement path.
	dirs := []string{
		filepath.Join(root, "internal", "mcpspec"),
		filepath.Join(root, "cmd", "sekizui-mcpspec"),
	}

	// --- structurally: no path emits vendor ---------------------------------
	// **AMENDED BY D287 (2026-09-24), AND THE CLAIM IT KEEPS IS THE ONE D51 IS
	// ABOUT.** This arm said no path emits `vendor` at all. D287 added one on
	// The maintainer's ruling: when a server ADVERTISES an outputSchema, the tool COPIES
	// it, and a copy is the vendor's word — checked against the live server's
	// tools/list, so a wrong one fails as drift (§4.9a.7). What must never
	// happen is unchanged: a schema this tool INFERRED marked `vendor`. So the
	// arm now asserts that `vendor` lives in exactly one function, which copies
	// and calls none of the inference.
	t.Run("vendor provenance is emitted only where a schema is copied, never where one is inferred", func(t *testing.T) {
		fset := token.NewFileSet()

		// FILES, NOT `*ast.Package`, which is deprecated as of Go 1.22 in favour
		// of the type checker. Nothing here needs types — the claim is about
		// what the SOURCE contains.
		files := map[string]*ast.File{}
		for _, dir := range dirs {
			pkgs, err := parser.ParseDir(fset, dir, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parsing %s: %v", dir, err)
			}
			if len(pkgs) == 0 {
				t.Fatalf("no package parsed at %s; the guard is looking at nothing", dir)
			}
			for _, pkg := range pkgs {
				for name, file := range pkg.Files {
					files[name] = file
				}
			}
		}

		const copier = "DraftAdvertised"
		inference := map[string]bool{"infer": true, "shapeOf": true, "Draft": true, "Select": true}
		var checked, bareVendor int
		var copierSeen bool
		for name, file := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			checked++
			for _, decl := range file.Decls {
				fn, _ := decl.(*ast.FuncDecl)
				inCopier := fn != nil && fn.Name.Name == copier
				if inCopier {
					copierSeen = true
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "SchemaFromVendor" {
						t.Errorf("%s:%d references SchemaFromVendor; provenance is never chosen by "+
							"name here (D51, D168)", filepath.Base(name), fset.Position(sel.Pos()).Line)
					}
					if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING &&
						strings.Contains(lit.Value, string(connector.SchemaFromVendor)) &&
						!strings.Contains(lit.Value, "vendor's") && !strings.Contains(lit.Value, "the vendor") {
						if lit.Value == `"`+string(connector.SchemaFromVendor)+`"` {
							bareVendor++
						}
						if !inCopier {
							t.Errorf("%s:%d names %s outside %s. Only a COPIED schema may say "+
								"vendor; an inferred one saying it is the guess posing as a "+
								"guarantee D51 exists to stop", filepath.Base(name),
								fset.Position(lit.Pos()).Line, lit.Value, copier)
						}
					}
					if call, ok := n.(*ast.CallExpr); ok && inCopier {
						if id, ok := call.Fun.(*ast.Ident); ok && inference[id.Name] {
							t.Errorf("%s calls %s: the one function allowed to say vendor must "+
								"COPY, and a copy that infers is a guess with the vendor's name on it",
								copier, id.Name)
						}
					}
					return true
				})
			}
		}
		switch {
		case checked == 0:
			t.Error("no non-test files inspected; the guard is not looking at anything")
		case !copierSeen:
			t.Errorf("no %s found; the arm is asserting about a function that does not exist", copier)
		case bareVendor != 1:
			t.Errorf("the literal %q appears %d times; exactly once, in %s", "vendor", bareVendor, copier)
		}
	})

	// --- structurally: no flag offers the choice ----------------------------
	//
	// A SEPARATE ARM BECAUSE IT IS A SEPARATE MISTAKE. The obvious way this
	// tool acquires a vendor path is not a hardcoded literal but a helpful
	// `-origin` flag, which would read as flexibility and be the whole defect.
	t.Run("no flag or parameter lets a caller choose the provenance", func(t *testing.T) {
		src, err := os.ReadFile(filepath.Join(root, "cmd", "sekizui-mcpspec", "main.go"))
		if err != nil {
			t.Fatalf("reading main.go: %v", err)
		}
		for _, forbidden := range []string{`flag.String("origin"`, `flag.String("provenance"`} {
			if strings.Contains(string(src), forbidden) {
				t.Errorf("main.go registers %s. Provenance is not an option: a tool that can "+
					"be TOLD to say vendor is a tool that says vendor", forbidden)
			}
		}
		// AND THE SAME QUESTION OF THE FUNCTION SIGNATURE, because a parameter
		// is a flag with fewer steps. `Draft` takes a tool name, an output type
		// and observations — provenance is not among them and must not become
		// so.
		if got := reflect.TypeOf(mcpspec.Draft).NumIn(); got != 4 {
			t.Errorf("mcpspec.Draft takes %d parameters, want 4 (tool, output type, a "+
				"JSON pointer, samples). A FIFTH is how provenance becomes "+
				"caller-controlled", got)
		}
	})

	// --- behaviourally: what it emits ---------------------------------------
	t.Run("everything it emits is local, and it decides nothing a human must", func(t *testing.T) {
		dir := t.TempDir()
		one := filepath.Join(dir, "a.json")
		two := filepath.Join(dir, "b.json")
		write := func(path, body string) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("writing %s: %v", path, err)
			}
		}
		// **THE FIXTURE CONTAINS REAL GUESSES ON PURPOSE**, because a draft over
		// clean observations warns about nothing and would prove only that the
		// warning list can be empty. `archivedAt` is null in both responses and
		// `score` disagrees about its type between them — the two places where a
		// schema drawn from observation says more than the observations support.
		write(one, `{"id":"n-1","tags":["a"],"pinned":false,"archivedAt":null,"score":3}`)
		write(two, `{"id":"n-2","tags":[],"pinned":true,"extra":"x","archivedAt":null,"score":"3"}`)

		samples, _, err := readSampleFiles([]string{one, two})
		if err != nil {
			t.Fatalf("reading observations: %v", err)
		}
		fragment, err := mcpspec.Draft("notes.create", "notes.note.v1", "", samples)
		if err != nil {
			t.Fatalf("drafting: %v", err)
		}
		got := fragment.YAML

		if !strings.Contains(got, "output_schema_origin: "+string(connector.SchemaFromLocal)) {
			t.Errorf("the draft does not pin local provenance:\n%s", got)
		}
		if strings.Contains(got, "output_schema_origin: "+string(connector.SchemaFromVendor)) {
			t.Error("the draft claims vendor provenance")
		}

		// **IT MUST NOT DECIDE WHAT A HUMAN IS HERE TO DECIDE (§4.9a.1).**
		// `mutating` drives the retry gate and audit-as-external-effect, and
		// MCP's own hints are the vendor's word — a draft that filled them in
		// would destroy the review it exists to feed. Absent, not defaulted:
		// `mutating: false` in a draft is an answer nobody gave.
		for _, key := range []string{"mutating:", "idempotency:"} {
			if strings.Contains(got, key) {
				t.Errorf("the draft emits %q. That is the judgement a person is here to make, "+
					"and a default is an answer nobody gave", key)
			}
		}
		if !strings.Contains(fragment.Obligations, "MUST STILL SET `mutating`") {
			t.Errorf("the draft does not state what it could not answer:\n%s",
				fragment.Obligations)
		}
		// **THE WARNINGS ARE PART OF THE OUTPUT, NOT A DEBUG AID.** Every one
		// names a place where the observations were too thin to support the
		// schema that was written, and a reviewer vetting this fragment is the
		// only person who can go and check.
		joined := strings.Join(fragment.Warnings, "\n")
		if !strings.Contains(joined, "archivedAt") {
			t.Errorf("a field that was null in EVERY response is left untyped and the draft "+
				"does not say so. Typing it `null` would assert the vendor never fills "+
				"it:\n%s", joined)
		}
		if !strings.Contains(joined, "score") {
			t.Errorf("a field whose type DISAGREED between responses is accepted as a union "+
				"and the draft does not say so — which is wider than any single response "+
				"and probably wider than the vendor's contract:\n%s", joined)
		}
		// AND THE UNTYPED FIELD IS GENUINELY UNTYPED, not typed as null.
		if strings.Contains(got, `"null"`) {
			t.Errorf("the drafted schema types a field as null:\n%s", got)
		}

		// The schema is real, not a placeholder.
		if !strings.Contains(got, `"pinned"`) || !strings.Contains(got, `"boolean"`) {
			t.Errorf("the drafted schema does not describe the observed responses:\n%s", got)
		}
	})

	// --- an object keyed by DATA is not a record ----------------------------
	//
	// **THE DEFECT REAL FIRST CONTACT FOUND, and it is the one that makes a
	// drafted schema actively wrong rather than merely thin.** The Fullstory
	// MCP's `discover_org_context` returns `results` keyed by THE CALLER'S OWN
	// SEARCH TERMS. Drafted as a record, the schema's properties were the
	// arguments that happened to be passed — a schema that can never match
	// another response, with the caller's inputs baked in as though the vendor
	// had promised them. That is precisely what D51 exists to prevent, arriving
	// as a generated guess with more confidence behind it than a hand-written
	// one.
	t.Run("an object keyed by data is a map, and a record with an optional field is not",
		func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, body string) string {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatalf("writing %s: %v", name, err)
				}
				return path
			}

			// KEYED BY DATA: no key in common between the two responses, and
			// every value is an instance of one thing.
			mapA := write("map-a.json", `{"results":{"alpha":{"hits":1},"beta":{"hits":2}}}`)
			mapB := write("map-b.json", `{"results":{"gamma":{"hits":3}}}`)

			samples, _, err := readSampleFiles([]string{mapA, mapB})
			if err != nil {
				t.Fatalf("reading observations: %v", err)
			}
			fragment, err := mcpspec.Draft("search", "search.v1", "", samples)
			if err != nil {
				t.Fatalf("drafting: %v", err)
			}
			if !strings.Contains(fragment.YAML, "additionalProperties") {
				t.Errorf("an object with no key in common between two responses was drafted "+
					"as a RECORD, so its properties are one response's data:\n%s",
					fragment.YAML)
			}
			for _, leaked := range []string{"alpha", "beta", "gamma"} {
				if strings.Contains(fragment.YAML, `"`+leaked+`"`) {
					t.Errorf("the draft names %q as a schema property. Those are DATA — a "+
						"query term — and a schema carrying them cannot match any other "+
						"response", leaked)
				}
			}
			if !strings.Contains(strings.Join(fragment.Warnings, "\n"), "MAP") {
				t.Errorf("the draft made the map/record judgement silently; a reviewer "+
					"vetting this fragment is the only person who can check it:\n%v",
					fragment.Warnings)
			}

			// **NON-VACUITY, AND IT CAUGHT THE FIRST DRAFT OF THIS RULE.** The
			// original discriminator was "the key sets differ", and an OPTIONAL
			// FIELD makes key sets differ — so an obvious record with one extra
			// field in the second response was drafted as a map, which discards
			// every field name the vendor does promise. Optional fields are
			// ubiquitous and map keys are not, so the rule is that NOTHING
			// recurs.
			recA := write("rec-a.json", `{"id":"1","name":"a"}`)
			recB := write("rec-b.json", `{"id":"2","name":"b","optional":true}`)
			samples, _, err = readSampleFiles([]string{recA, recB})
			if err != nil {
				t.Fatalf("reading observations: %v", err)
			}
			fragment, err = mcpspec.Draft("get", "get.v1", "", samples)
			if err != nil {
				t.Fatalf("drafting: %v", err)
			}
			if strings.Contains(fragment.YAML, "additionalProperties") {
				t.Errorf("a record whose second response carried one extra field was drafted "+
					"as a MAP, discarding every field name the vendor promises:\n%s",
					fragment.YAML)
			}
			if !strings.Contains(fragment.YAML, `"id"`) {
				t.Errorf("the drafted record lost its field names:\n%s", fragment.YAML)
			}
		})

	// --- a page of data is not a type ---------------------------------------
	//
	// **THE MAINTAINER'S POINT, AND IT IS THE OTHER HALF OF DRAFTING FROM REAL RESPONSES.**
	// A session-events result is an envelope: a session stub, a page token, and
	// four hundred events. The SCHEMA stays small because arrays collapse to
	// `items` — what does not stay small is the OBSERVATION, which at that size
	// is session ids, user emails, page URLs and click text. So the tool narrows
	// to the subtree that carries the type a reflex actually reads (D42 validates
	// field paths against a TYPE, and for a page of data the type is the
	// element), and it says so when a sample is big enough to be customer data.
	t.Run("a subtree can be selected, and a pointer that misses is refused",
		func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "page.json")
			if err := os.WriteFile(path, []byte(
				`{"session":{"id":"1:2"},"events":[{"kind":"click","ts":"t"}],"next":"tok"}`),
				0o600); err != nil {
				t.Fatalf("writing: %v", err)
			}
			samples, _, err := readSampleFiles([]string{path})
			if err != nil {
				t.Fatalf("reading: %v", err)
			}

			// THE ELEMENT, not the envelope.
			fragment, err := mcpspec.Draft("get_session_events", "fs.event.v1",
				"/events/0", samples)
			if err != nil {
				t.Fatalf("drafting a subtree: %v", err)
			}
			if !strings.Contains(fragment.YAML, `"kind"`) {
				t.Errorf("the subtree draft does not describe the event:\n%s", fragment.YAML)
			}
			for _, envelope := range []string{`"next"`, `"session"`} {
				if strings.Contains(fragment.YAML, envelope) {
					t.Errorf("the subtree draft still carries the envelope field %s, so a "+
						"reflex declaring ExpectsType against it declares against the "+
						"wrapper", envelope)
				}
			}

			// **A POINTER THAT MISSES IS REFUSED, NOT SKIPPED.** A draft over
			// the samples that happened to match would describe a shape nobody
			// asked about, and would look like a successful run.
			if _, err := mcpspec.Draft("x", "y", "/nope/0", samples); err == nil {
				t.Error("a JSON pointer that matched nothing produced a draft anyway")
			}
			if _, err := mcpspec.Draft("x", "y", "events", samples); err == nil {
				t.Error("a pointer with no leading slash was accepted; RFC 6901 requires one " +
					"and `events` is indistinguishable from a typo")
			}
		})

	// --- by consequence: a local schema is never drift-checked --------------
	//
	// **THE ARM THAT SAYS WHY THE OTHER TWO MATTER.** D168's failure-direction
	// argument is that a wrong local schema surfaces as "we guessed wrong"
	// rather than as a security incident, and that rests entirely on `local`
	// being exempt from the drift comparison. Driven against the real
	// comparator, with the SAME divergence under both origins so provenance is
	// the only variable.
	t.Run("a local schema is never drift-checked, and a vendor one is", func(t *testing.T) {
		const (
			pinned = `{"type":"object","properties":{"id":{"type":"string"}}}`
			live   = `{"type":"object","properties":{"id":{"type":"number"}}}`
		)
		liveTools := []mcp.LiveTool{{
			Name:         "notes.create",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			OutputSchema: json.RawMessage(live),
		}}
		spec := func(origin string) []mcp.SpecTool {
			return []mcp.SpecTool{{
				Name:               "notes.create",
				InputSchema:        json.RawMessage(`{"type":"object"}`),
				OutputSchema:       json.RawMessage(pinned),
				OutputSchemaOrigin: origin,
			}}
		}

		local := mcp.CompareToSpec("notes", spec(string(connector.SchemaFromLocal)), liveTools)
		if len(local) != 0 {
			t.Errorf("a `local` schema was drift-checked and produced %d finding(s): %v.\n\n"+
				"The vendor asserted none of it, so there is nothing to diverge FROM — and "+
				"the whole reason this tool may only mint local is that a mistake then "+
				"surfaces as \"we guessed wrong\" rather than as a security incident",
				len(local), local)
		}

		// NON-VACUITY, and it is the arm that stops the one above passing
		// against a comparator that checks nothing at all.
		vendor := mcp.CompareToSpec("notes", spec(string(connector.SchemaFromVendor)), liveTools)
		if len(vendor) == 0 {
			t.Error("the same divergence under `vendor` provenance produced NO finding, so " +
				"the arm above proved a comparator that ignores everything rather than one " +
				"that exempts local")
		}
	})
}

// readSampleFiles parses observed responses from files. It replaced
// mcpspec.ReadSamples when D287 made the command read the agent's MCP output
// from stdin only; these arms exercise the INFERENCE, which is unchanged, so
// their fixtures stay files.
func readSampleFiles(files []string) ([]any, [][]byte, error) {
	var out []any
	var raw [][]byte
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, err
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, nil, err
		}
		out, raw = append(out, v), append(raw, b)
	}
	return out, raw, nil
}
