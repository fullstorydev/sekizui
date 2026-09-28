// Package docref is the one place the design documents are located, sliced and
// extracted from.
//
// **BUILT BECAUSE THERE WERE SIX WAYS TO FIND THE MODULE ROOT** (D185). Not
// three, which is the threshold D173 used when `internal/atomicfile` replaced
// three hand-rolled durable writes that none of them synced — six:
// `acceptance.repoRoot`, `acceptance.moduleRoot`, `archcheck.repoRoot`,
// `archcheck.repoRootFor`, the walk inlined in `archcheck.readDesign`, and a
// fourth style that hardcoded `../../DESIGN.md` and worked only from one package
// depth. Two of those pairs were in the SAME package under different names.
//
// **AND THE REASON IT MATTERS IS NOT TIDINESS.** A document reader whose
// extractor silently matches nothing turns its guard into a no-op that PASSES —
// and that has already happened here. CONTRACTS 67 records it: the
// decision-derivation guard regexed `\bD(\d+)\b` over a phase's section, could
// not see the RANGE citation `(D45–D51)`, and reported full coverage over a set
// missing D46, D49 and D50 — the three MCP decisions items 9 and 10 exist for.
// The fix lives in exactly one function, and every future reader that parses a
// citation without knowing about it re-makes the same mistake. D184's guard was
// about to be the second such reader.
//
// So the defining property of this package is not deduplication:
//
//	**AN EXTRACTOR THAT MATCHES NOTHING RETURNS AN ERROR, NEVER AN EMPTY RESULT.**
//
// A caller ranging over an empty slice sees a guard that passes. A caller
// handling an error sees a guard that broke. The first is the defect class this
// repository keeps finding; the second is a Tuesday.
//
// **IT DOES NOT IMPORT `testing`, deliberately.** Every caller today is a test,
// and taking a `*testing.T` would be shorter at each site — it would also pull
// the testing package's flag registration into any non-test importer, and it
// would make the failure mode `t.Fatalf` inside a library, which composes with
// nothing. Errors are values; each test package wraps them in a four-line
// `mustDoc` helper, and that duplication is not the same species as six
// root-finders because there is no logic in it to get wrong.
//
// DESIGN.md references: D162, D173, D184, D185, CONTRACTS 67.
package docref

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// maxWalk bounds the search for the module root.
//
// A BOUND RATHER THAN A LOOP TO `/`, because an unbounded walk in a test that is
// run from the wrong directory reads every parent directory up to the filesystem
// root before failing, and the error it eventually gives names none of them.
const maxWalk = 10

// Root returns the module root, found by walking up for go.mod.
//
// The one implementation. Callers that need a path rather than a document — the
// Makefile guard, a source tree walk — use this instead of writing the walk
// again.
func Root() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("docref.Root: getwd: %w", err)
	}
	start := dir

	for range maxWalk {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("docref.Root: no go.mod within %d parents of %q", maxWalk, start)
}

// Doc is one document, or one slice of one, plus the first error that occurred
// while producing it.
//
// **A STICKY ERROR SO SLICING CHAINS**, which is the pattern `bufio.Scanner` and
// `sql.Rows` use and it is the right one here: the alternative is
// `(*Doc, error)` on every slice, so extracting a table out of a subsection of a
// document is three error checks to answer one question, and the middle one is
// the one people skip.
//
// The rule that makes it safe: **every TERMINAL operation returns the error**.
// Text, Rows and Decisions cannot be called without being handed the failure, so
// a dropped slice error surfaces at the end rather than becoming an empty
// result — which is the whole point of the package.
type Doc struct {
	// name is what the document is called, carried so an error can say WHICH
	// document and which slice of it failed. An error reading "section not
	// found" without naming the file is a message that sends somebody to grep.
	name string

	text string

	err error
}

// Load reads a document by its path relative to the module root.
//
// `docref.Load("DESIGN.md")`, `docref.Load("scripts/mutate.py")`. The relative
// path is deliberate: an absolute one would be a second way to say where the
// repository is, which is the thing this package exists to have one of.
func Load(rel string) *Doc {
	root, err := Root()
	if err != nil {
		return &Doc{name: rel, err: err}
	}
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return &Doc{name: rel, err: fmt.Errorf("docref.Load(%q): %w", rel, err)}
	}
	return &Doc{name: rel, text: string(b)}
}

// Name returns what the document is called, including the slice that produced
// it. Useful in a caller's own error message.
func (d *Doc) Name() string { return d.name }

// Err returns the first failure, if any.
func (d *Doc) Err() error { return d.err }

// Text returns the content, or the error that prevented it.
func (d *Doc) Text() (string, error) {
	if d.err != nil {
		return "", d.err
	}
	return d.text, nil
}

// Section returns the text from a Markdown heading until the next heading at the
// SAME OR HIGHER level.
//
// **THE END IS DERIVED, NOT PASSED IN**, and that is the difference from the
// hand-rolled version this replaces. `phaseDecisions(t, "### P2 — First
// connectors", "### P3 — Afferent path")` names its own terminator, so renaming
// P3's heading silently changes what P2's guard reads — it would extend to the
// next literal match, or fail outright, and neither is a failure about P3.
// Deriving the end from the heading LEVEL makes a section's extent a property of
// the document rather than of an agreement between two call sites.
func (d *Doc) Section(heading string) *Doc {
	if d.err != nil {
		return d
	}

	level := len(heading) - len(strings.TrimLeft(heading, "#"))
	if level == 0 {
		return d.fail("Section(%q): the heading does not start with '#', so its level "+
			"is unknown and the end of the section cannot be derived", heading)
	}

	i := strings.Index(d.text, heading)
	if i < 0 {
		return d.fail("Section(%q): not found. The guard reading this cannot derive "+
			"what it checks, so it fails rather than passing vacuously", heading)
	}

	rest := d.text[i+len(heading):]
	end := len(rest)
	// A heading of the same or higher level ends the section; a deeper one does
	// not, because a subsection belongs to its parent.
	for _, line := range lineOffsets(rest) {
		text := rest[line:]
		if nl := strings.IndexByte(text, '\n'); nl >= 0 {
			text = text[:nl]
		}
		if !strings.HasPrefix(text, "#") {
			continue
		}
		if n := len(text) - len(strings.TrimLeft(text, "#")); n <= level {
			end = line
			break
		}
	}

	return &Doc{name: fmt.Sprintf("%s §%s", d.name, strings.TrimLeft(heading, "# ")),
		text: heading + rest[:end]}
}

// Between returns the text between two literal bounds, exclusive of neither.
//
// FOR THE CASES A HEADING CANNOT ADDRESS — a Makefile target, a Python list. It
// keeps the terminator a caller's business, which Section deliberately does not,
// because there is no level structure to derive one from.
func (d *Doc) Between(from, to string) *Doc {
	if d.err != nil {
		return d
	}

	i := strings.Index(d.text, from)
	if i < 0 {
		return d.fail("Between(%q, ...): the opening bound is not present", from)
	}
	rest := d.text[i:]
	j := strings.Index(rest[len(from):], to)
	if j < 0 {
		return d.fail("Between(%q, %q): the closing bound is not present after the "+
			"opening one", from, to)
	}
	return &Doc{name: fmt.Sprintf("%s[%s..%s]", d.name, from, to),
		text: rest[:len(from)+j]}
}

// Marked returns the text between `<!-- BEGIN:name -->` and `<!-- END:name -->`.
//
// **THE MARKERS ARE A PROMISE RATHER THAN A CONVENIENCE** (D183). Text inside one
// is DERIVED and owned by a guard, which is the signal to a human editing the
// file — and addressing it by marker rather than by heading means the prose
// around it can be reworded freely without breaking the check, which is exactly
// the freedom a document wants and a guard should not take away.
func (d *Doc) Marked(name string) *Doc {
	if d.err != nil {
		return d
	}
	begin, end := "<!-- BEGIN:"+name+" -->", "<!-- END:"+name+" -->"

	i, j := strings.Index(d.text, begin), strings.Index(d.text, end)
	if i < 0 || j < i {
		return d.fail("Marked(%q): no %s ... %s block. The markers are what make a "+
			"derived section identifiable; without them a guard cannot tell derived "+
			"text from prose and would silently check nothing", name, begin, end)
	}
	return &Doc{name: fmt.Sprintf("%s<%s>", d.name, name), text: d.text[i+len(begin) : j]}
}

// Rows returns every line beginning with prefix, trimmed of trailing space.
//
// ERRORS ON NONE, which is the property this package exists for: a table whose
// row prefix stopped matching returns no rows, and a caller comparing two empty
// slices finds them equal and reports success.
func (d *Doc) Rows(prefix string) ([]string, error) {
	if d.err != nil {
		return nil, d.err
	}

	var out []string
	for _, line := range strings.Split(d.text, "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, strings.TrimRight(line, " \t"))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("docref: %s has no rows beginning %q — the extractor has "+
			"drifted from the table, and a guard comparing an empty result would pass "+
			"while checking nothing", d.name, prefix)
	}
	return out, nil
}

// Cells splits one table row into its cells, without the leading and trailing
// pipe.
//
// Exists so a caller reading the third column does not slice on " | " itself and
// then disagree with the next caller about whether the empty leading cell counts.
func Cells(row string) []string {
	trimmed := strings.Trim(strings.TrimSpace(row), "|")
	cells := strings.Split(trimmed, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

// decisionRange matches a cited RANGE of decisions. An en dash, an em dash and a
// hyphen are all in use in these documents, which is how CONTRACTS 67 happened.
var decisionRange = regexp.MustCompile(`\bD(\d+)\s*[–—-]\s*D(\d+)\b`)

// decisionSingle matches one cited decision.
var decisionSingle = regexp.MustCompile(`\bD(\d+)\b`)

// maxRangeSpan bounds what counts as a decision range, so `D1-D9999` from a typo
// does not silently claim every decision ever made.
const maxRangeSpan = 200

// Decisions returns every decision cited, RANGES EXPANDED, sorted.
//
// **THE FUNCTION CONTRACTS 67 IS ABOUT.** The guard deriving what a phase must
// prove regexed single citations only, so `(D45–D51)` yielded D45 and D51 and
// hid D46, D49 and D50 — and reported FULL COVERAGE over a set missing the three
// MCP decisions. It is one function now, in one package, for the reason the
// package exists: the second person to write this will not remember the en dash.
//
//nolint:gochecknoglobals // compiled once
var decisionEntry = regexp.MustCompile(`(?m)^### D\d+ — .*$`)

func (d *Doc) Decisions() ([]string, error) {
	if d.err != nil {
		return nil, d.err
	}

	seen := map[int]bool{}

	// Ranges first, so a range's endpoints are also picked up if the range is
	// rejected as absurd below.
	for _, m := range decisionRange.FindAllStringSubmatch(d.text, -1) {
		lo, _ := strconv.Atoi(m[1])
		hi, _ := strconv.Atoi(m[2])
		if hi < lo || hi-lo > maxRangeSpan {
			continue
		}
		for n := lo; n <= hi; n++ {
			seen[n] = true
		}
	}
	for _, m := range decisionSingle.FindAllStringSubmatch(d.text, -1) {
		n, _ := strconv.Atoi(m[1])
		seen[n] = true
	}

	if len(seen) == 0 {
		return nil, fmt.Errorf("docref: %s cites no decisions — a guard deriving what a "+
			"phase must prove from an empty set proves nothing", d.name)
	}

	nums := make([]int, 0, len(seen))
	for n := range seen {
		nums = append(nums, n)
	}
	sort.Ints(nums)

	out := make([]string, 0, len(nums))
	for _, n := range nums {
		out = append(out, "D"+strconv.Itoa(n))
	}
	return out, nil
}

// DecisionEntries returns the numbered `### D<n> — ` headings of a decision
// record, in order.
//
// **ONE READING OF WHAT AN ENTRY IS, AND THERE WERE TWO (D234).**
// `archcheck.TestDecisionsAreContiguousAndUniquelyNumbered` matched the strict
// `^### D(\d+) — ` and P2 step 33d counted rows with the PREFIX `### D`, so a
// sub-heading inside an entry's body — `### DISCOVERY METADATA SAYS…` — counted
// as a decision in one guard and not the other. The count guard's own comment
// said its subject was "one `### D<n>` heading per entry", which is what its
// implementation did not do.
//
// Two parsers over one file is the divergent-lists failure with the file as the
// shared thing, and this package exists so the guards read a document ONE way
// (D185). Sub-headings inside an entry are an established style here; what was
// missing is a reader that knows they are not entries.
//
// FAILS ON AN EMPTY RESULT, like every extractor here: a decision record that
// parses to nothing has changed shape, and a guard that reported zero would
// pass every count comparison against a README nobody updated.
func (d *Doc) DecisionEntries() ([]string, error) {
	if d.err != nil {
		return nil, d.err
	}
	found := decisionEntry.FindAllString(d.text, -1)
	if len(found) == 0 {
		return nil, fmt.Errorf("docref: %s holds no `### D<n> — ` entries; the decision "+
			"record has changed shape and every guard counting them is now silent", d.name)
	}
	return found, nil
}

func (d *Doc) fail(format string, args ...any) *Doc {
	return &Doc{name: d.name, err: fmt.Errorf("docref: %s: "+format,
		append([]any{d.name}, args...)...)}
}

// lineOffsets returns the byte offset of every line start.
//
// Offsets rather than the lines themselves, because Section needs to CUT the
// original string at a line boundary and a split loses the position.
func lineOffsets(s string) []int {
	out := []int{0}
	for i := range len(s) {
		if s[i] == '\n' && i+1 < len(s) {
			out = append(out, i+1)
		}
	}
	return out
}
