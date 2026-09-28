package file_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fullstorydev/sekizui/pkg/provider/conformance"
	filecred "github.com/fullstorydev/sekizui/pkg/provider/file"
)

// TestConformance runs the published Provider contract against this provider
// (D35, D156).
//
// IN AN EXTERNAL TEST PACKAGE (`file_test`), which is how a third-party
// implementer will consume the suite — from outside, with only the exported
// surface. Testing it from inside would prove the suite works on a view no
// self-hoster has.
func TestConformance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("conformance-material"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	conformance.Run(t, filecred.New(filecred.Roots(os.TempDir())), []conformance.Case{
		{Name: "an ordinary file", Ref: "file://" + path},
	})
}
