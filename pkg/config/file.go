package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// FileSource loads a Document from one YAML file, or from a DIRECTORY of them
// composed into one (D278).
//
// Shipped in pkg/ rather than internal/ following the precedent §11 sets for
// bus ("Bus interface + inproc driver"): the interface and one reference
// implementation live together, so a self-hoster on GCS or git has a worked
// example to copy rather than a bare interface to guess at.
//
// **STRICT (D278).** An unknown key is refused, not ignored — a typo in a
// governance field (`free_txt:`) would otherwise silently disable it — and so
// is a key set twice in one mapping, which a lax parse resolves by keeping the
// LAST: `acceptance.local.yaml` carried two `targets:` and lost every target
// above the second, unnoticed.
//
// **COMPOSABLE (D278).** A directory is every `*.yaml`/`*.yml` beneath it,
// hidden files and directories excepted, read in path order and merged with
// NO OVERRIDE (see merge.go): a connector's declaration pack — its payload
// kinds and schemas — can sit beside the deployment's grants, and neither can
// quietly replace the other. No hot reload: config arrives by redeploy (D144).
//
// YAML VIA sigs.k8s.io/yaml, NOT gopkg.in/yaml.v3. That library converts YAML to
// JSON and delegates to encoding/json, which has two consequences worth stating:
//   - Struct tags are `json:`, so there is ONE set of tags rather than two that
//     can disagree.
//   - connector.Secret's MarshalJSON/UnmarshalJSON apply, so a credential cannot
//     be parsed out of a config file and cannot be written into a dump of one.
//     A yaml.v3-style library uses its own reflection and would walk straight
//     past both.
type FileSource struct {
	path string
}

// NewFileSource returns a Source reading path — a file, or a directory.
func NewFileSource(path string) *FileSource {
	return &FileSource{path: path}
}

// Path returns the configured file path, for logs and error messages.
func (s *FileSource) Path() string { return s.path }

// Load reads, strictly parses and (for a directory) composes the document.
//
// Parse errors are KindConfig, not KindInternal: a malformed config file is an
// operator's problem to fix and the error should say which file and what was
// wrong, rather than reading as a bug in Sekizui.
func (s *FileSource) Load(ctx context.Context) (*Document, error) {
	const op = "config.FileSource.Load"

	// Honour cancellation before touching the filesystem. A boot that is
	// already being torn down should not go on to read and parse a file.
	if err := ctx.Err(); err != nil {
		return nil, fault.Wrap(fault.KindTimeout, op, "before reading "+s.path, err)
	}
	files, err := configFiles(s.path)
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "finding configuration at "+s.path, err)
	}

	var parts []part
	var newest time.Time
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, fault.Wrap(fault.KindConfig, op, fmt.Sprintf("reading %s", f), err)
		}
		var doc Document
		if err := decodeDocument(raw, &doc); err != nil {
			return nil, fault.Wrap(fault.KindConfig, op, fmt.Sprintf("parsing %s", f), err)
		}
		parts = append(parts, part{file: f, doc: &doc})
		if fi, err := os.Stat(f); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	doc, err := merge(parts)
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "composing "+s.path, err)
	}
	// AFTER COMPOSITION, because a preset and the grant naming it may live in
	// different files — the connector's fragment and the deployment's grants.
	if err := doc.ExpandPresets(); err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "expanding presets in "+s.path, err)
	}

	// Version is PROVENANCE — where this document came from. Absent an etag from
	// the source, the newest modification time among its files is the honest
	// answer: stable, comparable, and requiring no state.
	//
	// IT IS NOT THE DOCUMENT'S IDENTITY, and this comment used to claim it was
	// ("recorded on decisions so an audit row names the config that authorised
	// it", §4.9a.2). Nothing recorded it, and mtime could not have carried the
	// claim anyway: the same configuration deployed to two replicas has two
	// mtimes, and `touch -r` gives two different configurations one. Identity()
	// answers that question from CONTENT and is what a decision record carries
	// (D149). Both are logged at boot, so a hash on a row joins back to a file.
	if doc.Version == "" {
		doc.Version = fmt.Sprintf("%s@%d", filepath.Base(s.path), newest.Unix())
	}
	return doc, nil
}

// configFiles is the file itself, or every YAML file beneath a directory in
// path order. An empty directory is an error: a deployment configured from
// nothing is a typo in a path, not a policy.
func configFiles(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// HIDDEN ENTRIES ARE NOT CONFIGURATION: an editor's swap file or a
		// `.git` directory beside the files must not be read as policy.
		if p != path && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s is a directory with no .yaml or .yml files", path)
	}
	sort.Strings(files)
	return files, nil
}

// decodeDocument is THE parse: duplicate keys refused (YAMLToJSONStrict), then
// unknown fields refused (strictJSON).
func decodeDocument(raw []byte, doc *Document) error {
	j, err := yaml.YAMLToJSONStrict(raw)
	if err != nil {
		return err
	}
	return strictJSON(j, doc)
}

// strictJSON decodes refusing unknown fields and trailing content.
//
// **EVERY CUSTOM UnmarshalJSON IN THIS PACKAGE CALLS IT**, and that is not
// style: `DisallowUnknownFields` is a property of the DECODER, and a type with
// its own UnmarshalJSON receives raw bytes and decodes them itself — so
// strictness stops at its boundary unless it carries it on. Found by looking:
// a `targetz:` typo in a subscribe entry decoded silently under the strict
// top-level decoder (GO-PRIMER §15ap).
func strictJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing content after the document")
	}
	return nil
}

// Watch reports that this source cannot watch, per the Source contract: "Nil
// channel if unsupported, in which case the caller polls."
//
// NOT A STUB (D53). The interface explicitly provides for a source that cannot
// watch, and returning nil is the documented way to say so — as opposed to
// returning a channel that never delivers, which would look like a working
// watcher that simply never sees changes.
func (s *FileSource) Watch(ctx context.Context) (<-chan *Document, error) {
	return nil, nil
}
