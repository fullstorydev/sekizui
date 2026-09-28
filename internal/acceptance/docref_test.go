package acceptance

import (
	"context"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/docref"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// kataBuild is the pool Build for a kata-only pool.
//
// **D190 MADE `BuildClient` A METHOD**, so the five tests that construct a
// throwaway pool for one driver need an instance to take it from. A method value
// off a fresh driver is exactly that, and it keeps those tests reading as
// "a pool for the kata" rather than as registry ceremony — the registry earns
// its keep where two kinds share ONE pool, which is production and the main
// harness, not a single-driver fixture.
func kataBuild() func(context.Context, connector.Target) (any, error) {
	return kata.New().BuildClient
}

// The four-line wrapper `internal/docref` deliberately does not provide (D185).
//
// docref returns errors rather than taking a `*testing.T`, so it stays
// importable by non-test code and its failures compose. Each test package pays
// four lines for that, and those four lines contain no logic to get wrong —
// which is the distinction from the six root-finders and four ad-hoc readers
// this replaced.

// mustDoc loads a document relative to the module root, or fails the test.
func mustDoc(t *testing.T, rel string) *docref.Doc {
	t.Helper()
	d := docref.Load(rel)
	if err := d.Err(); err != nil {
		t.Fatalf("%v", err)
	}
	return d
}

// mustText slices and returns text, or fails the test naming what broke.
func mustText(t *testing.T, d *docref.Doc) string {
	t.Helper()
	text, err := d.Text()
	if err != nil {
		t.Fatalf("%v", err)
	}
	return text
}

func mustRoot(t *testing.T) string {
	t.Helper()
	root, err := docref.Root()
	if err != nil {
		t.Fatalf("%v", err)
	}
	return root
}
