package file

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// alwaysDenied are refused whatever the roots say (D286): process and kernel
// state, where `/proc/self/environ` holds every secret the process was given.
var alwaysDenied = []string{"/proc", "/sys"} //nolint:gochecknoglobals // immutable

var _ config.Confined = (*Provider)(nil)

// Roots confines `file://` references to these directories (D286,
// `-file-credential-root`). Validate them with ValidateRoots first.
func Roots(dirs ...string) Option { return func(p *Provider) { p.roots = append(p.roots, dirs...) } }

// Deny refuses references inside these directories even when a root contains
// them — the deployment passes its audit directory, which holds the log, the
// chain tail, the withdrawal and credential-version marks and the cursors.
func Deny(dirs ...string) Option { return func(p *Provider) { p.deny = append(p.deny, dirs...) } }

// AllowUnrooted admits `file://` references when NO root is declared — for a
// bare developer machine only, which is the one place `main` passes it (D286).
//
// **AN OPT-OUT, BECAUSE THE DEFAULT IS THE SAFE ONE.** This provider is
// published (D35): a third party calling `file.New()` gets a provider that
// refuses every reference until it is told where secrets live, rather than one
// that reads any file the process can until somebody knows to confine it.
func AllowUnrooted(yes bool) Option { return func(p *Provider) { p.allowUnrooted = yes } }

// ValidateRoots refuses roots that confine nothing: relative paths (they move
// with the working directory) and the filesystem root.
func ValidateRoots(roots []string) error {
	const op = "file.ValidateRoots"
	for _, r := range roots {
		switch {
		case !filepath.IsAbs(r):
			return fault.New(fault.KindConfig, op, fmt.Sprintf(
				"-file-credential-root %q is relative; a root must not move with the working directory", r))
		case filepath.Clean(r) == string(filepath.Separator):
			return fault.New(fault.KindConfig, op,
				"-file-credential-root / confines nothing; name the directories secrets are mounted in")
		}
	}
	return nil
}

// Confine says whether ref may be read at all (config.Confined, D286).
//
// **A CREDENTIAL REFERENCE IS A READ, AND ITS CONTENT LEAVES THE HOST** as the
// Authorization header of every call to the target's base_url — on a poll's
// cadence with nobody asking. So a reference is admitted only if the file it
// resolves to, SYMLINKS EVALUATED, lies inside a declared root and outside the
// audit directory and process state. Evaluated, not lexical: a link inside a
// root pointing at the audit log is the attack, and Kubernetes' own `..data`
// links resolve inside the mount, so they pass.
func (p *Provider) Confine(ref string) error {
	_, _, err := p.confined(ref)
	return err
}

// confined is Confine returning the RESOLVED path and the ROOT it lies in, both
// of which Resolve then reads through (D344). The resolved path alone was not
// enough: it is a NAME, re-walked by the read, so a directory on it swapped for
// a symlink between this check and that read sent a file from outside every
// root off-host. Resolve now opens it through os.Root at `root`, which refuses
// any walk leaving the root at the moment of the open. `root` is "" only for an
// unrooted developer machine (AllowUnrooted), where there is nothing to escape.
func (p *Provider) confined(ref string) (resolved, root string, err error) {
	const op = "file.Confine"
	path, err := PathOf(ref)
	if err != nil {
		return "", "", err
	}
	resolved, err = evaluate(path)
	if err != nil {
		return "", "", fault.Wrap(fault.KindConfig, op, "resolving "+path, err)
	}
	for _, d := range append(append([]string(nil), alwaysDenied...), p.deny...) {
		if within(resolved, evaluatedOrClean(d)) {
			return "", "", fault.New(fault.KindConfig, op, fmt.Sprintf(
				"%s resolves to %s, inside %s, which no credential may be read from: its "+
					"content would be sent off-host as the Authorization header of every call "+
					"to the target (D286)", ref, resolved, d))
		}
	}
	if len(p.roots) == 0 {
		if !p.allowUnrooted {
			return "", "", fault.New(fault.KindConfig, op, fmt.Sprintf(
				"%s is a file:// credential and this deployment declares no "+
					"-file-credential-root; off a developer machine a file credential must lie "+
					"inside a declared root, or one configuration line reads any file the "+
					"process can and sends it to the target's host (D286)", ref))
		}
		return resolved, "", nil
	}
	for _, r := range p.roots {
		if dir := evaluatedOrClean(r); within(resolved, dir) {
			return resolved, dir, nil
		}
	}
	return "", "", fault.New(fault.KindConfig, op, fmt.Sprintf(
		"%s resolves to %s, outside every -file-credential-root %v (D286)", ref, resolved, p.roots))
}

// evaluate makes path absolute and follows every symlink in it. A file that
// does not exist yet is evaluated through its nearest existing parent, so a
// reference into a root that has not been mounted is judged by where it WOULD
// land rather than refused for being absent (Resolve reports the absence).
func evaluate(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var rest []string
	cur := abs
	for {
		real, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(append([]string{real}, rest...)...), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = append([]string{filepath.Base(cur)}, rest...)
		cur = parent
	}
}

func evaluatedOrClean(dir string) string {
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		return real
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

// within reports whether path is dir or inside it.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) &&
		!filepath.IsAbs(rel))
}
