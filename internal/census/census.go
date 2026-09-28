// Package census answers "does any record in the audit log actually carry this
// field", by walking the corpus an acceptance run produced.
//
// **A RUNTIME POPULATION CENSUS, NOT A STATIC CHECK, AND D149 IS THE REASON
// (D164).** CONTRACTS 23 proposed parsing the generated setters and grepping for
// writers. `Document.Version` HAD writers — it was assigned, and logged at boot
// — and the failure was that it never reached a RECORD. A static check answers
// "does some code assign this field", which is not the property anybody wants;
// the property is "does a row in the audit log carry it", and that is a runtime
// fact about a corpus.
//
// **A ZERO-VALUED SCALAR COUNTS AS ABSENT, and that is correct here.**
// `protoreflect.Message.Range` visits only populated fields, so `false` and `0`
// are indistinguishable from unset. Every historical instance of this class was
// an absent column that READ AS COMPLETE rather than a wrong one, so the
// pessimistic reading is the useful one — and a field that is genuinely always
// zero in the corpus is a LEDGER entry with a reason, which is a sentence
// somebody had to write.
//
// **SCOPED TO `Decision`.** That is where all four known instances were —
// `Capability.where`, `Decision.residency`, `Decision.reflex_name` (D96) and
// D149's config identity. `CommandResult`, `QueryResponse` and `Envelope` are
// NOT covered, and the honest position is a stated limit rather than taps built
// on speculation (CONTRACTS 22 is `CommandResult.deduplicated`, still open).
//
// DESIGN.md references: §5.2, §12.3, D96, D107, D149, D157, D164.
package census

import (
	"fmt"
	"sort"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Depth is how many levels of nested message the census descends.
//
// **THREE NAMES DEEP, WHICH IS WHERE THE INTERESTING FIELDS LIVE.** D164
// estimated "roughly 33 fields" and the census as built covers 69 paths,
// because the fields most likely to go unpopulated are the leaves of a
// sub-message somebody added with its parent — `revocation.torn_down`,
// `identity.subject.proof`, `credential_posture.audited_reads`. A top-level-only
// census would have reported every one of those as covered the moment its
// PARENT was populated, which is the same "absent column reading as complete"
// one level down.
const Depth = 2

// Result is one census over a corpus.
type Result struct {
	// Paths is every field path the census asked about.
	Paths []string

	// Populated is the union of paths at least one record carried.
	Populated []string

	// Missing is what nothing populated, MINUS the ledger.
	Missing []string

	// Stale is the ledger's expiry: a path recorded as never-populated that the
	// corpus now carries. **The half that stops the ledger rotting**, and the
	// mechanism D139's `aheadOfItsPhase` and D53's init ledger both needed —
	// an allowlist usually survives by nobody ever re-reading it.
	Stale []string
}

// Err renders the result as an error, or nil when the corpus is complete.
func (r Result) Err() error {
	switch {
	case len(r.Stale) > 0 && len(r.Missing) > 0:
		return fmt.Errorf("%w; and %v", r.staleErr(), r.missingErr())
	case len(r.Stale) > 0:
		return r.staleErr()
	case len(r.Missing) > 0:
		return r.missingErr()
	}
	return nil
}

func (r Result) missingErr() error {
	return fmt.Errorf("%d of %d Decision field path(s) are populated by NO record in the "+
		"corpus: %v.\n\nA declared field nothing writes reads as complete rather than as "+
		"wrong, which is why this class keeps being found by hand (CONTRACTS 23). Either "+
		"populate it, drive a step that does, or add it to census.Ledgered() with the reason "+
		"it is legitimately absent — a sentence somebody has to write",
		len(r.Missing), len(r.Paths), r.Missing)
}

func (r Result) staleErr() error {
	return fmt.Errorf("%d ledgered field path(s) ARE populated now: %v.\n\nThe ledger says "+
		"nothing writes them and the corpus disagrees, so the entry is stale. Delete it — "+
		"an allowlist nobody re-reads is how a guard comes to permit what it was written to "+
		"catch (D53, D139)", len(r.Stale), r.Stale)
}

// Of runs the census over a corpus, excusing the paths the ledger names.
func Of(records []*sekizuiv1.Decision, ledger map[string]string) Result {
	seen := map[string]bool{}
	for _, rec := range records {
		populated(rec.ProtoReflect(), "", seen, Depth)
	}

	res := Result{Paths: paths((&sekizuiv1.Decision{}).ProtoReflect().Descriptor(), "", Depth)}
	for _, p := range res.Paths {
		switch {
		case seen[p]:
			res.Populated = append(res.Populated, p)
			if _, excused := ledger[p]; excused {
				res.Stale = append(res.Stale, p)
			}
		default:
			if _, excused := ledger[p]; !excused {
				res.Missing = append(res.Missing, p)
			}
		}
	}
	sort.Strings(res.Missing)
	sort.Strings(res.Stale)
	return res
}

// paths enumerates every field path of a message, to Depth.
func paths(md protoreflect.MessageDescriptor, prefix string, depth int) []string {
	var out []string
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		p := prefix + string(f.Name())
		out = append(out, p)
		// MAPS ARE NOT DESCENDED. A map's value type is not a field set, and
		// `payload_schemas`-shaped fields would contribute a path per key.
		if f.Kind() == protoreflect.MessageKind && !f.IsMap() && depth > 0 {
			out = append(out, paths(f.Message(), p+".", depth-1)...)
		}
	}
	return out
}

// populated records the paths one record carries.
//
// **A REPEATED MESSAGE IS NOT DESCENDED EITHER**, and the asymmetry with `paths`
// above is deliberate rather than an oversight: descending the first element of
// a list would report a path as covered on the strength of one entry while
// `paths` counts it once, so the two would agree by accident. Lists that need
// their leaves censused get their own corpus question.
func populated(m protoreflect.Message, prefix string, into map[string]bool, depth int) {
	m.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		p := prefix + string(f.Name())
		into[p] = true
		if f.Kind() == protoreflect.MessageKind && !f.IsMap() && !f.IsList() && depth > 0 {
			populated(v.Message(), p+".", into, depth-1)
		}
		return true
	})
}
