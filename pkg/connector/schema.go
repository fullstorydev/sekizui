package connector

import (
	"bytes"
	"encoding/json"
	"fmt"

	"sigs.k8s.io/yaml"
)

// Schema is a connector's declaration of one payload type it emits (D279).
//
// **THE CONNECTOR OWNS WHAT MAY ENTER.** Every type an action declares — its
// OutputType and OutputTypes — comes with its schema FROM THE CONNECTOR, shipped
// in the driver package beside the code that emits the data, so the two cannot
// be deployed apart. A declared type with no schema fails the boot and the
// published suite loudly: plugging in a connector and hoping for the best is
// what Sekizui exists not to do.
//
// **THE SCHEMA IS THE ALLOWLIST, CLOSED BY DEFAULT.** Unlike JSON Schema, where
// an object admits any property unless it says otherwise, a Sekizui schema
// admits only the properties it names; everything else is stripped at ingest,
// recursively. An object that should admit anything says
// `additionalProperties: true` — a deliberate choice by the connector's owner,
// after which the deployment protects its consumers with shin and anzen.
//
// **NOT AN MCP `outputSchema`.** That is a vendor's optional advertisement,
// kept in a vetted spec for drift detection (D51). This is Sekizui's own data
// schema, and it is never optional.
type Schema struct {
	// Type is the registry key, versioned: "fullstory.session_event.v1".
	Type string `json:"type"`

	// Body is the JSON Schema subset the registry enforces (type, properties,
	// required, additionalProperties, items, and `format: date-time` on a string
	// (D317); title, description, $comment and
	// examples as annotations). Any other keyword is refused (D278).
	Body json.RawMessage `json:"schema"`

	// Family makes the type DISCRIMINATED: one field names the kind, and the
	// kind decides the shape of another field (D276). Optional.
	Family *Family `json:"family,omitempty"`
}

// Family is a discriminated payload type (D276, D277, D279).
type Family struct {
	// Discriminator names the top-level field whose value is the kind.
	Discriminator string `json:"discriminator"`

	// Properties names the top-level field whose shape the kind decides.
	Properties string `json:"properties"`

	// FreeText names top-level fields that can restate anything — kept only
	// for a kind that names them in KeepFreeText. Found by looking: a
	// Fullstory custom event's `description` is its properties re-serialised.
	FreeText []string `json:"free_text,omitempty"`

	// Kinds are the declared kinds.
	Kinds map[string]Kind `json:"kinds"`

	// Other governs a kind NOT in Kinds. Nil: it is refused.
	Other *OtherKinds `json:"other,omitempty"`
}

// Kind is one declared kind: its properties' schema — closed by default, like
// every schema here — and the free-text fields it keeps.
type Kind struct {
	Schema       json.RawMessage `json:"schema"`
	KeepFreeText []string        `json:"keep_free_text,omitempty"`
}

// OtherKinds says what a kind the family does not declare becomes. Exactly one
// of the two is set.
//
// **WHICH OTHER KINDS ARRIVE AT ALL IS THE DRIVER'S BUSINESS**, not this
// type's. A source that can filter at the far side (Fullstory's Generate
// Context takes `include_types`) should fetch only what its target allows;
// this declares what the spine does with what arrives.
type OtherKinds struct {
	// Skeleton reduces the event to a few content-free fields and a mark.
	Skeleton *Skeleton `json:"skeleton,omitempty"`

	// Open admits it under this kind's schema and free-text rule.
	Open *Kind `json:"open,omitempty"`
}

// Skeleton is what survives of an event reduced for having an undeclared kind:
// the fields kept — which must include the discriminator and may carry no
// content — and a boolean field set true, so a reduced event is not mistaken
// for an empty one.
type Skeleton struct {
	Keep []string `json:"keep"`
	Mark string   `json:"mark"`
}

// ParseSchemas reads a driver's embedded schema file: a YAML list of Schema.
//
// STRICT, like the configuration loader (D278): an unknown key or a duplicate
// one is an error. A driver calls this on its `go:embed`ded file and reports a
// parse failure through Schemas' caller — the boot — rather than panicking at
// init, so the refusal names the connector.
func ParseSchemas(raw []byte) ([]Schema, error) {
	j, err := yaml.YAMLToJSONStrict(raw)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.DisallowUnknownFields()
	var out []Schema
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	for i, s := range out {
		if s.Type == "" || len(s.Body) == 0 {
			return nil, fmt.Errorf("schema %d names no type or has no schema body", i)
		}
	}
	return out, nil
}
