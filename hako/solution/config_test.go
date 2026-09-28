package notes_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/hako/solution"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// TestTheGovernanceHalfIsREALCONFIGURATION loads `notes.yaml` and validates it.
//
// **WITHOUT THIS, THE KATA'S MOST IMPORTANT HALF IS UNCHECKED PROSE.** The
// driver is guarded by the conformance suite; steps 5 to 9 produce YAML, and
// YAML in a document nobody loads is exactly the plausible-looking snippet this
// blueprint exists to stop people pasting. Every key here is one the loader
// recognises, and a typo — `withold`, `forbid`, `rate_per_hour` — fails this
// test rather than being discovered by whoever copies it.
func TestTheGovernanceHalfIsRealConfiguration(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("notes.yaml"))
	if err != nil {
		t.Fatalf("reading the kata's configuration: %v", err)
	}

	var doc config.Document
	if err := yaml.UnmarshalStrict(raw, &doc); err != nil {
		// **STRICT, so an unknown key is an ERROR rather than silence.** A lens
		// spelled `witholds` parses cleanly under a lenient unmarshal, binds to
		// nothing, and withholds nothing — a bar that reads as being in force
		// and enforces nothing, which is this repository's recurring defect in
		// its quietest form.
		t.Fatalf("the kata's configuration does not load: %v", err)
	}

	if len(doc.Targets) != 1 || len(doc.Grants) != 1 || len(doc.Shin) != 1 ||
		len(doc.Anzen) != 1 {
		t.Fatalf("the kata is missing a governance block: %d targets, %d grants, "+
			"%d lenses, %d guards — the whole point is that all four are present",
			len(doc.Targets), len(doc.Grants), len(doc.Shin), len(doc.Anzen))
	}

	// **THE REAL BOOT CHECK, NOT A STRING THIS FILE TYPED ITSELF.** What stood
	// here was `doc.Shin[0].Type != "sekizui://schema/notes/note.v1"` — an
	// assertion that passed for two phases while being WRONG, because the driver
	// carried the same wrong value and the two agreed with each other.
	//
	// `OutputType` is the payload registry key and never the schema URI (D41,
	// D88), and this file, `notes.go` and `notes.yaml` all had the URI. A learner
	// following the answer key and registering `notes.note.v1` — the documented
	// convention, and what `internal/connectors/kata` does — would have been refused
	// at boot naming their own action. **The answer key's own guard cemented the
	// error instead of catching it**, which is the worst shape a teaching
	// artefact can take.
	//
	// So the check is the one a deployment actually runs. It closes the whole
	// class rather than this instance: an unregistered output type, a URI where a
	// key belongs, a type with no version suffix, and a lens KEEPING a field its
	// schema does not have are all one failure here.
	//
	// **THIS FILE IS WHY THE `pkg/`-ONLY RULE IS PER-FILE.** `notes.go` and
	// `conformance_test.go` use `pkg/` alone on purpose — that is a third-party
	// driver author's whole surface (D35). Configuration is not validated by the
	// author; it is validated by the DEPLOYMENT at boot, and reaching for
	// `internal/schemareg` here is that distinction rather than an erosion of it.
	checker := schemareg.NewChecker(
		func() *config.Document { return &doc },
		func(*config.Document) map[string]connector.Driver {
			return map[string]connector.Driver{notes.Kind: notes.New()}
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err := checker.Validate(context.Background()); err != nil {
		t.Errorf("the kata's configuration does not survive the boot-time schema "+
			"check: %v\n\nEvery type a driver declares must be registered in "+
			"`payload_schemas`, keyed by PAYLOAD TYPE and never by schema URI", err)
	}
	if len(doc.Shin[0].Withholds) == 0 || doc.Shin[0].Because == "" {
		t.Error("the lens withholds nothing or records no reason; both are the step")
	}
	if len(doc.Anzen[0].Forbids) == 0 || doc.Anzen[0].Mode != "enforce" {
		t.Error("the guard forbids nothing or is not enforcing — shadow is the " +
			"default, so an omitted mode is a ceiling that only warns")
	}
}
