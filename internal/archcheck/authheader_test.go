package archcheck_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoAdHocAuthorizationHeaders is D199's structural half.
//
// **THREE DRIVERS HAND-ROLLED THE SAME SIX LINES** — borrow through `Use`,
// append a scheme, `AppendTo`, stringify, `Header.Set` — each free to get the
// lending discipline (D127) subtly different from the next, and none of them
// checking that the material could BE a header value. That is D173's shape
// exactly, where three copies of an atomic write existed and none of them
// synced; the guard that found the third one is the reason this exists before a
// fourth driver copies the pattern.
//
// **NO EXEMPTION BEYOND THE IMPLEMENTATION AND THIS FILE, and that is worth
// stating because it nearly had one.** The reference driver `kata` also appends
// `"Bearer "` into a buffer — but it SETS NO HTTP HEADER, because it has no
// transport at all, so it is not a false positive and needs no carve-out. A
// guard weakened on its first real file is worse than a stated limit (the
// residual D118 records), so the rule is keyed on the thing that actually
// matters: writing the Authorization header, not building a string that looks
// like one.
func TestNoAdHocAuthorizationHeaders(t *testing.T) {
	root := repoRootFor(t)

	// The implementation, and this guard, whose message must name what it
	// forbids.
	exempt := []string{"pkg/connector/authheader.go", "internal/archcheck"}

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "bin", "out", ".gocache", "dev":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		for _, ex := range exempt {
			if strings.HasPrefix(slash, ex) {
				return nil
			}
		}

		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		// TESTS ARE IN SCOPE TOO. A test that stamps the header itself is a test
		// asserting against a placement the product does not perform, which is
		// how a guard comes to be true of the tests and false of the code.
		if strings.Contains(string(b), `Set("Authorization"`) {
			offenders = append(offenders, slash)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("%d file(s) set the Authorization header directly: %v\n\n"+
			"Credential placement is governance rather than transport (D175, D186, D199): "+
			"use `connector.SetAuthorization`, which owns the borrow, keeps Sekizui's "+
			"material inside the lease (D127), and REFUSES material that cannot be a "+
			"header value. Hand-rolled, a credential file written with `echo` gets its "+
			"newline sent to net/http, which refuses the request — and the failure then "+
			"reads as the TARGET being unreachable, so it is retried and the breaker "+
			"opens on a server that is fine.", len(offenders), offenders)
	}
}
