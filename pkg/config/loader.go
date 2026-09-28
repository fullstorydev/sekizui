package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// EnvProvider resolves env://NAME references.
//
// The simplest possible SecretProvider, and the right one for P0 and for local
// development. Real deployments use GCP Secret Manager or Vault; those are
// separate Provider implementations selected by scheme, which is the whole
// point of the interface.
//
// NO VERSION IN AN ENV REF, which is a real limitation rather than an oversight.
// §4.7 says the version is part of the reference and is what makes credential
// rotation invalidate pooled clients. An environment variable has no version, so
// rotating one requires a restart. Acceptable for P0 and for a laptop; it is why
// this is not the production path.
type EnvProvider struct{}

func (EnvProvider) Scheme() string { return "env" }

// Posture declares what an environment variable can and cannot offer (D111,
// D153).
//
// **THIS IS WHAT MAKES D97 A DERIVED RULE.** Refusing `env://` off a developer
// machine used to be a hardcoded case in the boot check; it is now what happens
// when a deployment requires `versioned` and this provider says it has no
// version. The behaviour is identical and the mechanism is general, so the next
// source with the same weakness is refused without anybody editing a list.
//
// UNVERSIONED IS THE LOAD-BEARING FIELD, and D97's own argument leads with it:
// "An environment variable has no version, so rotation needs a new revision."
// Rotation is NONE for the same reason — the value is fixed when the process
// starts, and Kubernetes documents that a Secret consumed as an environment
// variable is never updated in a running container.
//
// `at_rest` is "environment", which is the fact D97's blast-radius argument
// rests on: the value sits in /proc/<pid>/environ for the process lifetime,
// readable by anything sharing the UID, and Sekizui is a credential BROKER — one
// read yields every credential it holds.
func (EnvProvider) Posture(string) (Posture, error) {
	return Posture{
		Versioning:   Unversioned,
		Rotation:     RotationNone,
		AuditedReads: false,
		AtRest:       "environment",
		Why: "an environment variable has no version, is fixed at process start, and " +
			"sits in /proc/<pid>/environ for the process lifetime",
	}, nil
}

// COMPILE-TIME ASSERTION for D139's reason: Postured is optional, so nothing
// would fail if this stopped satisfying it — D97's refusal would simply stop
// happening, because a provider that cannot describe itself offers no properties
// and the check has nothing to compare.
var _ Postured = EnvProvider{}

func (EnvProvider) Resolve(ctx context.Context, ref string) (Resolution, error) {
	const op = "config.EnvProvider.Resolve"

	// Reading an environment variable cannot block, so this check buys nothing
	// HERE. It is present because the Provider contract says every
	// implementation honours cancellation, and an implementation that quietly
	// does not becomes the one people copy when writing the Vault provider.
	if err := ctx.Err(); err != nil {
		return Resolution{}, fault.Wrap(fault.KindTimeout, op, "context done", err)
	}

	name, ok := strings.CutPrefix(ref, "env://")
	if !ok {
		return Resolution{}, fault.New(fault.KindConfig, op,
			fmt.Sprintf("ref %q is not an env:// reference", ref))
	}
	val, present := os.LookupEnv(name)
	if !present {
		// Distinguishes unset from empty. An empty variable is almost always a
		// misconfigured deployment rather than a deliberate empty credential,
		// and silently returning nothing produces a 401 far from the cause.
		return Resolution{}, fault.New(fault.KindConfig, op,
			fmt.Sprintf("environment variable %s is not set", name))
	}

	// Zero expiry means "no expiry information", not "expires now": the cache
	// applies its own TTL with jitter (§4.3.2).
	//
	// EMPTY VERSION IS THE HONEST ANSWER HERE, not an omission. An environment
	// variable has no version — that is the limitation documented above — so
	// this reports that it cannot tell, and the cache falls back to digesting
	// the material to notice a change (D130). A provider that invented a version
	// it could not stand behind would defeat the pool invalidation that the
	// field exists to drive.
	return Resolution{Material: []byte(val)}, nil
}

// Loader owns the configuration lifecycle: load it, validate it, hold it, and
// hand it out.
//
// IT SATISFIES spine.Component AND spine.Validator WITHOUT IMPORTING SPINE.
// Go's interfaces are structural, so implementing Name/Start/Stop/Validate with
// the right signatures is sufficient — there is no "implements" clause to write.
// That is what keeps pkg/ free of a dependency on internal/, which would
// otherwise invert the layering D35 sets up.
//
// Also worth knowing: nothing enforces that this KEEPS satisfying the interface.
// Change a signature here and the failure appears at the wiring site in
// cmd/sekizui, not here. TestLoaderSatisfiesSpineInterfaces pins it locally so
// the break is reported where it was caused.
type Loader struct {
	src Source
	log *slog.Logger

	mu  sync.RWMutex
	doc *Document
}

// NewLoader returns a Loader reading from src.
func NewLoader(src Source, log *slog.Logger) *Loader {
	return &Loader{src: src, log: log}
}

// Name identifies this component in the init ledger and readiness output.
func (l *Loader) Name() string { return "config" }

// Validate loads and checks the document, BEFORE anything starts.
//
// Loading happens here rather than in Start on purpose. spine runs every
// Validate to completion before any Start, so a malformed config file fails
// while nothing is running — no listener bound, no lease taken, nothing to
// unwind. That is what "rejected at boot" means in practice.
func (l *Loader) Validate(ctx context.Context) error {
	doc, err := l.src.Load(ctx)
	if err != nil {
		return err
	}
	if err := doc.Validate(); err != nil {
		return err
	}

	l.mu.Lock()
	l.doc = doc
	l.mu.Unlock()

	// BOTH, and this is the one place they appear together (D149). `identity` is
	// what the document IS and is what an audit row carries; `version` is where
	// it came from. The join between a hash on a decision record and a file on
	// disk happens here, which is why neither field makes the other redundant.
	//
	// A hash that cannot be computed is logged rather than fatal HERE, because
	// this is the shared load path and a Source may legitimately be validating a
	// candidate document; the gateway's boot treats the same failure as fatal,
	// where serving with unidentified config is the actual risk.
	identity, err := doc.Identity()
	if err != nil {
		l.log.Warn("could not compute config identity", "err", err)
	}

	l.log.Info("configuration validated",
		"identity", identity,
		"version", doc.Version,
		"files", doc.Files(),
		"targets", len(doc.Targets),
		"grants", len(doc.Grants),
		"reflexes", len(doc.Reflexes),
	)
	return nil
}

// Start makes the validated document available.
//
// Deliberately almost empty: Validate did the work. Start exists to satisfy the
// lifecycle and to fail loudly if the ordering is ever broken — a Loader started
// without validation has no document, and every consumer would get nil.
func (l *Loader) Start(ctx context.Context) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.doc == nil {
		return fault.New(fault.KindInternal, "config.Loader.Start",
			"started without a validated document; Validate must run first")
	}
	return nil
}

// Stop releases the document. Idempotent, as the Component contract requires.
func (l *Loader) Stop(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.doc = nil
	return nil
}

// Health reports whether configuration is currently in force.
//
// P0 EXIT CRITERION 5: "readiness fails when config is unloaded". This is that
// criterion, and it is why Loader implements spine.HealthReporter rather than
// relying on having started successfully — the two are different questions, and
// after Stop the answer changes.
func (l *Loader) Health(ctx context.Context) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.doc == nil {
		return fault.New(fault.KindUnavailable, "config.Loader.Health",
			"no configuration loaded")
	}
	return nil
}

// Document returns the configuration currently in force, or nil.
//
// Returns the pointer rather than a copy: Documents are large and read-only by
// convention. When hot reload lands, this becomes the swap point — readers take
// the pointer once and keep using it, and a reload publishes a NEW document
// rather than mutating the old one, so nobody observes a half-applied change.
func (l *Loader) Document() *Document {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.doc
}
