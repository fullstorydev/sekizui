package archcheck_test

import (
	"testing"

	"github.com/fullstorydev/sekizui/internal/docref"
)

// The same four-line wrapper the acceptance package carries (D185).
//
// In `archcheck_test` rather than `archcheck`, matching every other file here —
// the external test package (§15w), which is what lets these guards import the
// tree they inspect without an import cycle.
//
// TWO COPIES OF THIS AND NOT ONE, deliberately: `internal/docref` returns errors
// rather than taking a `*testing.T`, which keeps it importable by non-test code
// and lets its failures compose. The price is these wrappers, and they contain no
// logic to get wrong — which is exactly what distinguished them from the three
// walks up to go.mod this package used to hold under three different names.

func mustRoot(t *testing.T) string {
	t.Helper()
	root, err := docref.Root()
	if err != nil {
		t.Fatalf("%v", err)
	}
	return root
}
