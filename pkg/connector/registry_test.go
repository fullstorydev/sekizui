package connector

import (
	"context"
	"strings"
	"testing"
)

// THE REGISTRY IS NOW THE ONE PLACE A TARGET FINDS ITS DRIVER, so its failure
// modes are worth pinning — particularly the two it exists to make impossible.

type probeDriver struct {
	kind  string
	built int
}

func (p *probeDriver) Kind() string                         { return p.kind }
func (p *probeDriver) Actions() []ActionSpec                { return nil }
func (p *probeDriver) Health(context.Context, Target) error { return nil }

func (p *probeDriver) Execute(context.Context, Target, string, map[string]any,
	Idempotency) (Result, error) {
	return Result{}, nil
}

func (p *probeDriver) Query(context.Context, Target, string, map[string]any) (Rows, error) {
	return Rows{}, nil
}

// builderDriver additionally implements the OPTIONAL interface.
type builderDriver struct{ probeDriver }

func (b *builderDriver) BuildClient(context.Context, Target) (any, error) {
	b.built++
	return "a real client", nil
}

func probeTarget(t *testing.T, kind string) Target {
	t.Helper()
	tgt, err := NewTarget(TargetParams{
		Ref: kind + ":one", Kind: kind, Tenant: "t", Residency: "eu",
		BaseURL: "https://example.invalid", CredentialVersion: "v1",
		Credential: Secret("s"),
	})
	if err != nil {
		t.Fatalf("building the target: %v", err)
	}
	return tgt
}

// TestTheKeyCannotDisagreeWithTheDriver is the defect the registry closes.
//
// `map[string]Driver{kata.Kind: kata.New()}` let a typo or a copied line key one
// driver under another's name, and the symptom is a target resolving to the
// wrong driver entirely — invisible in every artefact a reviewer inspects.
func TestTheKeyCannotDisagreeWithTheDriver(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&probeDriver{kind: "alpha"}); err != nil {
		t.Fatalf("registering: %v", err)
	}
	if _, ok := r.Drivers()["alpha"]; !ok {
		t.Error("the driver is not reachable under its own Kind()")
	}
	// There is no API through which a caller could supply a different key, which
	// is the assertion — stated here because "you cannot write it" is otherwise
	// only visible by reading the signature.
	if got := len(r.Drivers()); got != 1 {
		t.Errorf("registry holds %d drivers, want 1", got)
	}
}

func TestADuplicateKindIsRefused(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&probeDriver{kind: "alpha"}); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err := r.Register(&builderDriver{probeDriver{kind: "alpha"}})
	if err == nil {
		t.Fatal("two drivers claimed one kind and both were accepted. Every target of " +
			"that kind would reach whichever was registered last, which depends on " +
			"wiring order")
	}
	if !strings.Contains(err.Error(), "alpha") {
		t.Errorf("the refusal does not name the contested kind: %v", err)
	}
}

func TestAnEmptyOrNilDriverIsRefused(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("a nil driver was registered")
	}
	if err := r.Register(&probeDriver{kind: ""}); err == nil {
		t.Error("a driver with an empty Kind was registered, so no target could ever " +
			"name it and the registration is silently useless")
	}
}

// TestBuildAsksTheDriverWhenItCan.
func TestBuildAsksTheDriverWhenItCan(t *testing.T) {
	d := &builderDriver{probeDriver{kind: "alpha"}}
	r := NewRegistry()
	if err := r.Register(d); err != nil {
		t.Fatalf("registering: %v", err)
	}

	client, err := r.Build(context.Background(), probeTarget(t, "alpha"))
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	if client != "a real client" {
		t.Errorf("Build returned %v, want the driver's own client", client)
	}
	if d.built != 1 {
		t.Errorf("the driver's BuildClient ran %d times, want 1", d.built)
	}
}

// TestADriverWithNothingToBuildStillGetsAPoolEntry is the OPTIONAL half, and the
// property that keeps break-glass working.
//
// A driver the pool skipped would be invisible to `revoke_credential`, which
// would evict an empty pool and truthfully report cancelling nothing
// (CONTRACTS 35). The entry is a marker; the cancellation is real.
func TestADriverWithNothingToBuildStillGetsAPoolEntry(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&probeDriver{kind: "alpha"}); err != nil {
		t.Fatalf("registering: %v", err)
	}

	client, err := r.Build(context.Background(), probeTarget(t, "alpha"))
	if err != nil {
		t.Fatalf("a driver that does not implement ClientBuilder was refused: %v", err)
	}
	if client == nil {
		t.Fatal("Build returned a nil client for a credential-free driver. The pool " +
			"entry is what makes the call reachable by revocation, so a nil here " +
			"silently unpools the driver while everything reports success")
	}
	// THE MARKER SAYS WHY IT IS EMPTY. A human reading a pool dump should not
	// have to wonder what was lost.
	if s, ok := client.(interface{ String() string }); !ok ||
		!strings.Contains(s.String(), "class 1") {
		t.Errorf("the marker does not explain itself: %#v", client)
	}
}

// TestAnUnknownKindFailsClosed also catches the wiring mistake the registry
// exists to prevent: a pool constructed before registration and never populated.
func TestAnUnknownKindFailsClosed(t *testing.T) {
	r := NewRegistry()
	_, err := r.Build(context.Background(), probeTarget(t, "nobody-registered-this"))
	if err == nil {
		t.Fatal("Build accepted an unregistered kind. Returning a nil client would let " +
			"the call proceed with the driver silently unpooled, so break-glass would " +
			"evict nothing while reporting success")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("the refusal does not say what is wrong: %v", err)
	}
}

// TestDriversReturnsACopy. An aliased map turns "the gateway's drivers" and
// "the registry's drivers" into one thing two owners can edit.
func TestDriversReturnsACopy(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&probeDriver{kind: "alpha"}); err != nil {
		t.Fatalf("registering: %v", err)
	}
	got := r.Drivers()
	delete(got, "alpha")

	if _, ok := r.Drivers()["alpha"]; !ok {
		t.Error("mutating the returned map changed the registry")
	}
}

// Schemas: this double declares no output type, so it ships no schema (D279).
func (p *probeDriver) Schemas() ([]Schema, error) { return nil, nil }
func (p *probeDriver) Meter() Meter               { return Meter{} }
