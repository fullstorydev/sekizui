package conformance

import (
	"context"
	"fmt"
	"testing"

	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// runSchemasDeclared requires the connector to ship the schema of every type
// its actions declare, and nothing else (D279).
//
// **THE SAME CHECK THE BOOT MAKES, NOT A COPY OF IT.** The registry is built
// here exactly as a deployment builds it — `schemareg.ForDeployment`, with this
// driver alone — so a connector that passes this arm cannot be refused at boot
// for its schemas, and one refused at boot cannot pass here.
//
// **PLUGGING IN A CONNECTOR AND HOPING FOR THE BEST IS WHAT THIS REFUSES.** A
// type with no schema is a shape nobody reviewed; it cannot be shaped at
// ingest, lensed by field, or validated, and Sekizui would be forwarding
// whatever the far side sent.
func runSchemasDeclared(t *testing.T, d connector.Driver) {
	t.Helper()
	t.Run("every declared type ships its schema", func(t *testing.T) {
		// **THE QUARANTINE, NOT ONLY THE ERROR (D284).** Since D282 a
		// connector's schema fault QUARANTINES it rather than failing the boot,
		// and ForDeployment returns no error for it — so this arm, which read
		// only the error, passed a connector that declared a type and shipped
		// no schema, while every deployment would quarantine it. The published
		// suite certified exactly the connector it exists to refuse.
		reg, err := schemareg.ForDeployment(&config.Document{}, map[string]connector.Driver{d.Kind(): d})
		if err == nil {
			if faults, _ := reg.QuarantineOf(d.Kind()); faults != "" {
				err = fmt.Errorf("a deployment would QUARANTINE this connector: %s", faults)
			}
		}
		if err != nil {
			t.Errorf("%v\n\nShip a schema for every OutputType and OutputTypes entry — embed a "+
				"schemas.yaml beside the driver and return connector.ParseSchemas(it) from Schemas(). "+
				"It is CLOSED BY DEFAULT: name every field you mean to bring in; "+
				"`additionalProperties: true` admits everything, deliberately", err)
		}
	})
}

// runSourceConformsToItsSchema requires what the poll returns to conform to
// the connector's own schema once shaped (D279).
//
// Shaping only removes, so what fails here is a field the schema DECLARES
// arriving with the wrong type, or a kind the connector's own family refuses —
// the connector contradicting itself, which no deployment could fix.
func runSourceConformsToItsSchema(t *testing.T, s connector.Source, c SourceCase) {
	t.Helper()
	t.Run("the polled events conform to the connector's own schema", func(t *testing.T) {
		d, ok := s.(connector.Driver)
		if !ok {
			t.Fatal("this Source is not also a Driver, so it has no schemas to conform to")
		}
		reg, err := schemareg.ForDeployment(&config.Document{}, map[string]connector.Driver{d.Kind(): d})
		if err != nil {
			t.Fatalf("the connector's schemas do not load: %v", err)
		}
		events, _, err := s.Poll(pollCtx(context.Background(), c), c.Target, "", c.Limit)
		if err != nil {
			t.Fatalf("polling a healthy target failed: %v", err)
		}
		for _, ev := range events {
			shaped, report := reg.Shape(ev.Type, ev.Data)
			if report.Refused() {
				t.Errorf("event %q is kind %q, which your own family neither declares nor admits", ev.ID, report.Kind)
				continue
			}
			if err := reg.Validate(ev.Type, shaped); err != nil {
				t.Errorf("event %q does not conform to your own schema even after shaping: %v", ev.ID, err)
			}
		}
	})
}
