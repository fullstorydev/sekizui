// Package acceptance is P0's graduation evidence.
//
// ONE SCRIPTED RUN THROUGH EVERY CAPABILITY THAT EXISTS, producing an audit log
// that tells the whole story end to end. The log is the artifact: a reviewer
// reads it and sees what Sekizui does, in the order it does it, with the
// reasoning attached to each refusal.
//
// A PHASE IS NOT DONE UNTIL THIS RUN COVERS IT. That is the point — it is a
// living checklist in the same spirit as spine's init ledger and
// TestFixtureIsComplete: a capability that lands without appearing here is a
// capability nobody proved, and TestEveryReachableVerdictAppears fails when a
// verdict the code can produce never shows up.
//
// Run `make acceptance` to write the log somewhere readable.
package acceptance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/fullstorydev/sekizui/internal/builtin"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fullstorydev/sekizui/internal/actionset"
	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/bus"
	"github.com/fullstorydev/sekizui/internal/catalog"
	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/internal/denial"
	"github.com/fullstorydev/sekizui/internal/devcert"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/identity"
	"github.com/fullstorydev/sekizui/internal/kyuushin"
	"github.com/fullstorydev/sekizui/internal/limiter"
	"github.com/fullstorydev/sekizui/internal/meter"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/internal/reflex"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/internal/tracing"
	"github.com/fullstorydev/sekizui/internal/translate"
	"github.com/fullstorydev/sekizui/pkg/audit"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// AuditPath is where the run writes its log. Overridable so `make acceptance`
// can put it somewhere a human will look.
func auditPath(t *testing.T) string {
	if p := os.Getenv("SEKIZUI_ACCEPTANCE_OUT"); p != "" {
		return p
	}
	return filepath.Join(t.TempDir(), "acceptance.jsonl")
}

type run struct {
	srv    *gateway.Server
	engine *reflex.Engine

	// denials and dispatch are the tally the gateway feeds and the dispatcher
	// its signals reach, as `main` wires them (D332, D336).
	denials  *denial.Tally
	dispatch *anzen.Dispatcher
	doc      *config.Document
	sink     *auditwal.JSONLSink
	path     string
	step     int

	// The real transport. Agents reach Sekizui the way agents actually do —
	// over mTLS gRPC, with an identity a CA signed — rather than through a
	// peer.Peer this file constructed. See TestP0Acceptance's preamble.
	lis    *gateway.Listener
	bundle *devcert.Bundle
	addr   string
	bus    *bus.InProcess

	// pool is the same pool the server holds, so a step can put a call in
	// flight and then watch a governed revocation cancel it (step 10).
	pool *pool.Pool

	// tracer is the same provider the server holds, so a step can read the
	// spans an outbound call produced (step 29). THE PROVIDER, not a copy of
	// its output: a step asserting on spans it collected itself would be
	// asserting about the test.
	tracer *tracing.Provider

	// recorder is the server's own, so a reflex engine a step starts records
	// into the same chain (D264).
	recorder audit.Recorder

	// runner is the job runner the server holds, so a step can read the
	// conditions it raises (P3 step 18, D277).
	runner *kyuushin.Runner

	// cur is the step currently narrating, in the shared evidence ledger. The
	// report and the test output cannot disagree about what ran because there is
	// one record of it, and the ledger is what lets the report CITE the audit
	// lines this step produced rather than describe them.
	cur *evidenceStep

	// jobs is the same runner the server dispatches `StartJob` to, so a step
	// can stop it and watch the far side stop rather than only the stream.
	jobs *kyuushin.Runner

	// remote is set when driving a LIVE Sekizui rather than an in-process one
	// (D115). Steps that reach inside the process must then skip WITH A REASON
	// rather than silently — the point of the demo is that a person watches it,
	// and a step that vanishes teaches them nothing.
	remote bool
}

// localOnly skips a step that cannot cross a network, saying why.
//
// The reasons are architecture, not limitation: a reflex calls the enforcement
// path in-process because that is what a reflex IS (D69), and an audit log
// belongs to the process that wrote it.
func (r *run) localOnly(t *testing.T, why string) bool {
	t.Helper()
	if !r.remote {
		return false
	}
	r.detail(t, "SKIPPED against a live instance — %s", why)
	return true
}

func newRun(t *testing.T) *run {
	t.Helper()
	return newRunWith(t, runOpts{})
}

// runOpts is the narrow set of ways one step's run may differ from every
// other's, each for a reason stated where it is used.
//
// **FEW FIELDS, AND KEEPING IT FEW IS THE POINT.** A harness wired
// differently from production proves the harness (D190), so the only
// differences allowed are the ones a hermetic run cannot avoid — where a
// target's base_url points, which TLS roots the Fullstory driver trusts to
// reach it, where issuer keys are read from — and the ones a deployment
// varies by flag rather than by document: the residency ceiling (D320).
type runOpts struct {
	// patch edits the loaded document BEFORE validation, so a patched
	// document passes exactly the checks a deployment's would.
	patch func(*config.Document)

	// fullstoryClient replaces the Fullstory driver's HTTP client, so a TLS
	// fixture can stand in for api.fullstory.com.
	fullstoryClient *http.Client

	// issuerKeys reads signed-subject issuers' key files (D318). The binary
	// uses the file:// provider under its roots; a step supplies the same
	// provider rooted at its own directory, because this harness resolves
	// env:// only (CONTRACTS 148).
	issuerKeys identity.KeySource

	// mcpClient is the MCP driver's HTTP client, so a TLS fixture MCP server
	// can be reached (D323) — the same category as fullstoryClient. The
	// driver is registered either way, as `builtin.Drivers` registers it.
	mcpClient *http.Client

	// postValidate edits the document AFTER validation — standing up exactly
	// the deployment boot would refuse, for a test proving the RUNTIME backstop
	// behind that refusal (D331). Named for what it bypasses, and used only
	// where the bypass is the subject.
	postValidate func(*config.Document)

	// bootErr, when set, receives the gateway's boot refusal instead of failing
	// the test, and newRunWith returns nil — for a step whose assertion IS the
	// refusal (P5 step 4).
	bootErr *error

	// residency is this run's deployment ceiling, the one thing a deployment
	// sets by flag rather than in the document (D320); nil is
	// acceptanceResidency. ONE value, read by the resolver and the grant engine
	// alike, for the reason acceptanceResidency gives.
	residency []string
}

func newRunWith(t *testing.T, opts runOpts) *run {
	t.Helper()

	// DRIVING A LIVE INSTANCE (D115). `make run` in one terminal, `make demo` in
	// another. Everything below that builds a server is skipped; the clients
	// point at a real process instead.
	if addr := os.Getenv("SEKIZUI_ACCEPTANCE_TARGET"); addr != "" {
		return remoteRun(t, addr, os.Getenv("SEKIZUI_ACCEPTANCE_CERTS"))
	}

	t.Setenv("SEKIZUI_ACCEPT_TOK", "acceptance-token")
	ceiling := acceptanceResidency
	if opts.residency != nil {
		ceiling = opts.residency
	}

	doc, err := config.NewFileSource("acceptance.yaml").Load(context.Background())
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if opts.patch != nil {
		opts.patch(doc)
	}
	// THE CONFIG MUST PASS THE SAME VALIDATION A DEPLOYMENT USES. An acceptance
	// run over configuration that would be refused at boot proves nothing.
	if err := doc.Validate(); err != nil {
		t.Fatalf("the acceptance config would be refused at boot: %v", err)
	}
	// BOTH HALVES OF BOOT VALIDATION, not just the one that lives in pkg/config.
	// D42's field-path check needs the schema registry and the drivers, so it is
	// a separate component (D88) — and running only the first half here would
	// mean the acceptance run validated less than a real deployment does, which
	// is exactly the gap that let D42 go unenforced in the first place.
	checker := schemareg.NewChecker(
		func() *config.Document { return doc },
		// EVERY SHIPPED CONNECTOR, as the binary registers (D279): the
		// connectors own their schemas, so a checker told about kata alone
		// would know no Fullstory type. **THIS COMMENT WAS FALSE UNTIL
		// CONTRACTS 135:** the binary registered kata alone, so this harness
		// validated MORE than a deployment did. The same function now, and the
		// same shape — a function of the document.
		func(d *config.Document) map[string]connector.Driver { return builtin.ByKind(d, nil) },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := checker.Validate(context.Background()); err != nil {
		t.Fatalf("the acceptance config would be refused by schema validation: %v", err)
	}
	if opts.postValidate != nil {
		opts.postValidate(doc)
	}
	// AND THE CEILING'S BOOT CHECK, which `main` runs against the flag: under a
	// multi-class ceiling an unclassified target is an unpoliced route (D136).
	if orphans := policy.NewGrantEngine(doc, ceiling).UnclassifiedTargets(); len(orphans) > 0 {
		t.Fatalf("the acceptance config would be refused at boot under -residency %v: "+
			"unclassified targets %v", ceiling, orphans)
	}

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(context.Background()); err != nil {
		t.Fatalf("audit sink: %v", err)
	}

	// A DETERMINISTIC CLOCK, AND IT NEEDS A MUTEX.
	//
	// The first version was `func() time.Time { clock = clock.Add(time.Second);
	// return clock }` — a closure over local state, exactly GO-PRIMER §15e. That
	// was correct while the run was single-threaded, and the moment step 14 put
	// 48 commands in flight the race detector caught it reading and writing
	// `clock` from many goroutines at once.
	//
	// Worth keeping as a lesson rather than quietly fixing: closure state is
	// private, not synchronised, and privacy is not what makes concurrent access
	// safe. Timestamps are still distinct and monotonic; which command receives
	// which second is no longer predictable, and nothing depends on that.
	var (
		clockMu sync.Mutex
		clock   = time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	)
	tick := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(time.Second)
		return clock
	}

	profile := runtime.Detect(func(k string) string {
		if k == "SEKIZUI_REGION" {
			return "europe-west1"
		}
		return ""
	}, runtime.Override{})

	eventBus := bus.New(slog.New(slog.NewTextHandler(io.Discard, nil)), 16)

	// THE POOL IS SHARED WITH THE SERVER, and the driver now BORROWS from it, so
	// a revocation driven over the wire cancels real in-flight commands rather
	// than only what a step planted by hand. That wiring is what closed
	// CONTRACTS §4 item 35.
	// THE REAL DRIVER BUILDER, not a stand-in. The harness used to pool an
	// anonymous struct, which meant the acceptance run exercised the pool but
	// never the thing production puts in it — so §4.7.4's binding classes were
	// untested through the enforcement path and `Revocation.torn_down` was
	// structurally zero.
	// THROUGH THE REGISTRY, like the binary (D190). A harness that wired drivers
	// differently from production would prove the harness rather than the system,
	// which is D107's argument for old runs executing against the CURRENT stack.
	registry := connector.NewRegistry()
	clientPool := pool.New(registry.Build,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	// **THE FULLSTORY DRIVER JOINS THE HARNESS FOR STEPS 1 AND 4 (D225).** The
	// document declares an `fs:live` target, and a target whose kind no
	// registered driver serves is refused at the command rather than at boot —
	// so without this line the two live steps fail with "no driver registered"
	// and every other step is unaffected, which is a confusing way to learn that
	// the harness and the document disagree.
	//
	// Registering it costs nothing when the key is absent: the steps skip, and no
	// other step names an `fs:` target.
	for _, dr := range []connector.Driver{
		kata.New(kata.WithPool(clientPool)),
		fullstory.New(fullstoryOpts(clientPool, opts, doc)...),
		// **THE MCP DRIVER, AS THE BINARY REGISTERS IT (D323).** `builtin.Drivers`
		// always includes it and this harness did not — a D190 divergence nobody
		// had cause to notice while no acceptance target was MCP.
		mcp.New(doc.MCPSpecs, mcpOpts(clientPool, opts)...),
	} {
		if err := registry.Register(dr); err != nil {
			t.Fatalf("registering the %s driver: %v", dr.Kind(), err)
		}
	}

	tracer := tracing.New(tracing.WithClock(tick))

	// **THE RATE LIMITER, DERIVED FROM THE DOCUMENT EXACTLY AS THE BINARY
	// DERIVES IT — AND IT WAS ABSENT (D253).** `gateway.Config.Rate` was never
	// set here, so §4.3.4's shared budget was not exercised through the
	// enforcement path by any acceptance step: step 23 drives `limiter.Local`
	// DIRECTLY, which proves the algorithm and says nothing about whether a
	// verb consults it. That is how `Query` went a phase without consuming the
	// budget with the suite green.
	//
	// **THE BINARY'S OWN PLAN (D284).** This built its table with a copy of
	// `main`'s loop, and D284 changed that loop: every target is metered now,
	// by its connector's default or the universal one. A copy would go on
	// proving the old table while the binary served the new.
	plan, perr := meter.Build(doc, registry.Drivers(), nil, meter.Bounds{})
	if perr != nil {
		t.Fatalf("meter plan: %v", perr)
	}
	rates := plan.Rates
	rateLimiter := limiter.NewLocal(rates)

	// ONE RECORDER for the server and the reflex engine, as `cmd/sekizui`
	// wires it: a firing refused by its budget (D264) lands in the same hash
	// chain as everything else, and steps read it from the same log.
	recorder := auditwal.NewRecorder(sink, mustIdentity(t, doc), auditwal.WithClock(tick))
	projector, err := reflex.NewProjector(doc.Reflexes)
	if err != nil {
		t.Fatalf("the acceptance projections would refuse the boot: %v", err)
	}
	// THE SAME REGISTRY BOOT CHECKED (D276, D279): the connectors' schemas and
	// the document's. The server shapes query results with it, and every
	// envelope a job publishes is shaped and validated against it.
	schemas, err := schemareg.ForDeployment(doc, builtin.ByKind(doc, nil))
	if err != nil {
		t.Fatalf("the acceptance deployment's schemas: %v", err)
	}
	// THE SAME COMPILATION `main` RUNS (D317), so a step's seiren is the one a
	// deployment would serve.
	refinements, refineProblems, _ := schemareg.Refinements(schemas, doc, builtin.ByKind(doc, nil))
	if len(refineProblems) > 0 {
		t.Fatalf("the acceptance refinements would refuse the boot: %v", refineProblems)
	}
	// THE SURFACES `main` GIVES THE GRANT ENGINE (D323), from the same drivers.
	surfaces := policy.WithSurfaces(actionset.Surfaces(registry.Drivers()))
	denials := denial.New()
	srv := gateway.New(gateway.Config{
		Denials:     denials,
		Payloads:    schemas,
		Refinements: refinements,
		Projector:   projector,
		Bus:         eventBus,
		Tracer:      tracer,
		Doc:         doc,
		Pool:        clientPool,
		Verifier:    identity.NewVerifier(doc, identity.WithKeySource(opts.issuerKeys)),
		Guards:      anzen.New(doc.Anzen),
		Policy:      policy.NewGrantEngine(doc, ceiling, surfaces),
		Revocations: policy.NewRevocations(),
		Resolver:    resolver.New(doc, profile, ceiling, config.EnvProvider{}),
		Drivers:     registry.Drivers(),
		Catalog: catalog.New(catalog.Config{Doc: doc, Refinements: refinements,
			Drivers: map[string]connector.Driver{
				kata.Kind: kata.New(), fullstory.Kind: fullstory.New(), mcp.Kind: mcp.New(doc.MCPSpecs)},
			Policy: policy.NewGrantEngine(doc, ceiling, surfaces),
			Guards: anzen.New(doc.Anzen), Lenses: shin.New(doc.Shin)}),
		Lenses:    shin.New(doc.Shin),
		Rate:      rateLimiter,
		Recorder:  recorder,
		Admission: gateway.NewAdmission(128),
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:       tick,
	})
	// **THE GATEWAY'S OWN BOOT CHECK, WHICH `main` RUNS AND THIS HARNESS DID NOT
	// until P5 step 4 (D330):** the grant table against the drivers (D195) and
	// no reflex the ceiling forbids. Without it every in-process run validated
	// LESS than a deployment boots with — CONTRACTS 135's shape, again.
	if err := srv.Validate(); err != nil {
		if opts.bootErr != nil {
			*opts.bootErr = err
			return nil
		}
		t.Fatalf("the acceptance config would be refused by the gateway's boot check: %v", err)
	}

	// **THE JOB RUNNER, WIRED THE WAY `cmd/sekizui` WIRES IT (D250).** The two
	// wiring sites are deliberately separate — this one substitutes a clock and
	// a sink — but the SHAPE has to match, or the acceptance run proves the
	// harness rather than the system (D107). In particular the gate is
	// `srv.JobGate()` and not a permissive stand-in: step 31's whole claim is
	// that a job is admitted by the same ceilings an Execute takes, and a
	// harness gate that said yes would make that claim untestable while
	// appearing to test it.
	//
	// NO CONFIGURED RECURRENCES, which is what a gateway looks like (D252).
	envSeq := 0
	jobTrans, err := translate.New(doc.Stages[0], safestruct.DefaultBudget)
	if err != nil {
		t.Fatalf("translate.New: %v", err)
	}
	runner, err := kyuushin.New(nil, cursor.NewFileStore(t.TempDir()), jobTrans,
		eventBus, srv.JobGate(), slog.New(slog.NewTextHandler(io.Discard, nil)),
		kyuushin.Options{NewID: func() string {
			envSeq++
			return fmt.Sprintf("01J0JOB%04d", envSeq)
		}, Payloads: schemas})
	if err != nil {
		t.Fatalf("kyuushin.New: %v", err)
	}
	if err := srv.AttachJobRunner(runner); err != nil {
		t.Fatalf("AttachJobRunner: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runner.Stop(stopCtx)
	})

	seq := 0
	// SIGNALS GO WHERE `main` SENDS THEM (D332): the anzen dispatcher, firing
	// through the gateway's own firer — so a reflex's `budget_exceeded` reaches
	// the rules watching it here exactly as in the binary. It was a no-op, so no
	// in-process run could see an anzen rule respond to a reflex.
	dispatcher := anzen.NewDispatcher(anzen.New(doc.Anzen), srv.AnzenFirer(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	engine := reflex.NewEngine(doc.Reflexes, srv, recorder,
		func(ctx context.Context, name string, subjects map[string]string) {
			_ = dispatcher.Observe(ctx, name, subjects)
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() string { seq++; return fmt.Sprintf("01J0ENV%04d", seq) }, schemas.Validate,
		reflex.WithSharedBudgets(doc.ReflexBudgets))
	if err := srv.AttachReflexes(engine); err != nil {
		t.Fatalf("AttachReflexes: %v", err)
	}

	// --- the real transport --------------------------------------------------
	//
	// Every principal the run acts as gets a certificate from a real CA, with a
	// SPIFFE URI SAN that identity.principalFromCert parses back into the same
	// principal. Nothing here is synthesised.
	bundle, err := devcert.Generate(t.TempDir(), acceptancePrincipals)
	if err != nil {
		t.Fatalf("issuing development identities: %v", err)
	}

	lis := gateway.NewListener("127.0.0.1:0", gateway.TLSConfig{
		CertFile:     bundle.ServerCert,
		KeyFile:      bundle.ServerKey,
		ClientCAFile: bundle.CACertFile,
	}, func(context.Context) (*gateway.Server, error) { return srv, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := lis.Validate(context.Background()); err != nil {
		t.Fatalf("the listener would be refused at boot: %v", err)
	}
	if err := lis.Start(context.Background()); err != nil {
		t.Fatalf("binding the gateway: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lis.Stop(stopCtx)
	})

	return &run{srv: srv, engine: engine, denials: denials, dispatch: dispatcher, recorder: recorder, runner: runner, doc: doc, sink: sink, path: path,
		lis: lis, bundle: bundle, addr: lis.Addr(), bus: eventBus, pool: clientPool,
		tracer: tracer, jobs: runner}
}

// acceptanceResidency is this run's deployment ceiling, and it is ONE constant
// because two components have to agree about it.
//
// The resolver enforces the ceiling and the grant engine's second layer keys off
// it (D136). Written twice, they would drift, and the failure would be silent in
// the dangerous direction: a resolver serving `eu,us` beside a grant engine
// believing the deployment is single-class turns the grant layer off while every
// refusal still looks correct.
//
// SINGLE-CLASS, so the grant layer is OFF for the main run — every step written
// before D136 keeps its existing meaning, and step 59 builds its own
// multi-residency deployment rather than changing this one underneath them.
//
// `us`, THE CLASS OF THE ONE REAL ORG THE SUITE REACHES (D326). It was `eu`
// until CONTRACTS 152: EXAMPLE is NA1, and the live targets were declared `eu`
// to match a ceiling nobody had chosen for a reason.
//
//nolint:gochecknoglobals // immutable, read once
var acceptanceResidency = []string{"us"}

// acceptancePrincipals are every identity the run acts as.
//
// ONE LIST, used both to issue certificates locally and to check them when
// driving a live instance. `make dev-certs` must stay in step with it — a
// mismatch surfaces as a handshake failure that looks like a Sekizui bug rather
// than a missing file, which is why the check below names what is absent.
//
//nolint:gochecknoglobals // immutable list, read once
var acceptancePrincipals = []string{
	"agent:triage", "mesh:primary", "agent:global", "agent:bulk", "agent:analytics",

	// The human who breaks the glass (D129). A principal like any other, with a
	// certificate like any other — which is the point of making revocation a
	// governed verb rather than a side door.
	"operator:oncall",

	// Drives the three §4.7.4 binding classes (steps 50-52).
	"agent:binding",

	// Drives the idempotency classes through the full stack (P2 step 3).
	"agent:idempotency",

	// Asks for a governed asynchronous job and receives its results (P3 step
	// 31, D247). A principal of its own because the GRANT SHAPE is the point —
	// `kata.poll` and a subscribe grant, and nothing else.
	"agent:jobs",

	// Proves a read and a write draw on one shared budget (D253). Alone on
	// `kata:metered`, because the arm's evidence is a bucket nobody else is
	// spending from.
	"agent:metered",
	// P3 step 37: a subscriber whose grant is two crossed (subject, target) pairs (D259).
	"agent:scoped",

	// P3 step 23: three subscribers to one real connector's events, under an
	// allowlist lens, no lens, and a denylist lens — the demonstration the maintainer
	// asked for, that shin removes a person's name and email.
	"agent:analyst", "agent:support", "agent:auditor",

	// P4 step 12 (D323): one principal denied the native read and granted the
	// MCP server, one granted both — so Describe's union is read by each.
	"agent:union", "agent:union-native",

	// THE DEMO'S PRINCIPAL (D315): granted `fullstory.*` by demo.d/demo.yaml only,
	// so the showcase steps have an identity no in-process step's patch touches.
	"agent:showcase",
}

// remoteRun points the run at an already-running Sekizui.
//
// It reads the certificates `make dev-certs` produced rather than generating its
// own, because the live instance was started with that CA — a freshly generated
// bundle would be refused at the handshake, correctly, and would look like a bug
// in Sekizui rather than in the harness.
func remoteRun(t *testing.T, addr, certDir string) *run {
	t.Helper()

	if certDir == "" {
		t.Fatal("SEKIZUI_ACCEPTANCE_TARGET is set but SEKIZUI_ACCEPTANCE_CERTS is not; " +
			"the harness cannot guess which CA the live instance trusts")
	}
	doc, err := config.NewFileSource("acceptance.yaml").Load(context.Background())
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	bundle := &devcert.Bundle{
		CACertFile:  filepath.Join(certDir, "ca.crt"),
		ClientCerts: map[string]string{},
		ClientKeys:  map[string]string{},
	}
	var missing []string
	for _, p := range acceptancePrincipals {
		safe := strings.ReplaceAll(p, ":", "_")
		bundle.ClientCerts[p] = filepath.Join(certDir, safe+".crt")
		bundle.ClientKeys[p] = filepath.Join(certDir, safe+".key")
		if _, err := os.Stat(bundle.ClientCerts[p]); err != nil {
			missing = append(missing, p)
		}
	}
	// ALL of them, not the first. One run should tell an operator the whole fix
	// rather than one principal per attempt.
	if len(missing) > 0 {
		t.Fatalf("%s has no certificate for %s.\n\nRegenerate with:\n  "+
			"make dev-certs\n\nand restart the live instance — a new bundle means a new "+
			"CA, which the running process does not trust.", certDir, strings.Join(missing, ", "))
	}

	t.Logf("driving a LIVE Sekizui at %s using certificates from %s", addr, certDir)
	return &run{doc: doc, addr: addr, bundle: bundle, remote: true}
}

// as returns a gRPC client authenticated as the named principal.
//
// ONE CONNECTION PER PRINCIPAL, because that is how identity works here: the
// principal comes from the client certificate presented during the handshake,
// so "acting as someone else" means a different connection, not a different
// header. That constraint is the point — a header could be forged by whoever
// sets headers.
func (r *run) as(t *testing.T, principal string) sekizuiv1.GatewayServiceClient {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(r.bundle.ClientCerts[principal], r.bundle.ClientKeys[principal])
	if err != nil {
		t.Fatalf("loading the identity for %s: %v", principal, err)
	}
	return r.dial(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      r.caPool(t),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})
}

// anonymous returns a client presenting no certificate at all.
func (r *run) anonymous(t *testing.T) sekizuiv1.GatewayServiceClient {
	t.Helper()
	return r.dial(t, &tls.Config{
		RootCAs: r.caPool(t), ServerName: "localhost", MinVersion: tls.VersionTLS13,
	})
}

func (r *run) dial(t *testing.T, cfg *tls.Config) sekizuiv1.GatewayServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(r.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatalf("dialling the gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return sekizuiv1.NewGatewayServiceClient(conn)
}

func (r *run) caPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pemBytes, err := os.ReadFile(r.bundle.CACertFile)
	if err != nil {
		t.Fatalf("reading the CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("the generated CA file contains no certificates")
	}
	return pool
}

// waitFor polls a condition with a bounded deadline.
//
// Polling rather than a channel because the thing being waited on is state
// inside another goroutine's call stack — the server's Subscribe handler — and
// exposing a "subscription ready" signal purely for tests would put test
// scaffolding in the serving path.
func waitFor(t *testing.T, cond func() bool, whatFailed string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(whatFailed)
}

// sortedKeys renders a payload's shape compactly, for the narration.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (r *run) narrate(t *testing.T, what string) {
	r.step++
	// A PHASE LOOP'S ENTRY, WHEN THERE IS ONE (P3's). That loop opened the
	// range before the step ran, so the citation already starts at the log's
	// true position; opening another here would file the step under P0.
	if st := evidence.boundTo(t.Name()); st != nil {
		r.cur = st
		t.Logf("%s step %2d — %s", st.phase, st.n, what)
		return
	}
	// OPENING THE RANGE IS THE FIRST THING, before the step does any work, so
	// the citation starts at the log's true position rather than after whatever
	// the step's setup wrote.
	r.cur = evidence.open("P0", r.step, what, "", nil, nil)
	t.Logf("step %2d — %s", r.step, what)
}

// detail attaches an observation to the current step, for both the test output
// and the shareable report.
func (r *run) detail(t *testing.T, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if r.cur != nil {
		r.cur.detail(msg)
	}
	t.Logf("   %s", msg)
}

// --- identity plumbing ------------------------------------------------------

// actingFor asserts a subject on an OUTGOING call.
//
// Outgoing, not incoming: the claim now crosses a real wire, so the client sets
// it and the server reads it — which is exactly the asymmetry §4.4.1 governs.
// The subject is CLAIMED and checked against may_speak_for; only the caller is
// proven, by the certificate.
func actingFor(ctx context.Context, subject string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(identity.SubjectHeader, subject))
}

func execute(action, target string, args map[string]any) *sekizuiv1.ExecuteRequest {
	a, _ := structpb.NewStruct(args)
	return &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
		Action: action, TargetRef: target, Args: a,
		IdempotencyKey: "acc-" + action,
	}}
}

func envelope(t *testing.T, stage, typ string, data map[string]any) *sekizuiv1.Envelope {
	t.Helper()
	d, _ := structpb.NewStruct(data)
	return &sekizuiv1.Envelope{
		Id: "01J0ROOT", Source: "fs:fixture", SpecVersion: "1.0",
		Type: typ, Subject: "session:abc123", Stage: stage, Residency: "us",
		TraceId: "4bf92f3577b34da6", Data: d,
		Time: timestamppb.Now(), ObservedTime: timestamppb.Now(),
	}
}

// TestP0Acceptance is the graduation run.
//
// AGENTS OVER THE WIRE, REFLEXES IN PROCESS — and that split is the truth of the
// design rather than a testing convenience. D69 separates identity
// ESTABLISHMENT from enforcement precisely because the two callers differ: a
// gRPC request proves itself with a certificate, an in-process reflex cannot and
// constructs an identity for its own principal instead. Everything after that
// point is one shared path.
//
// So steps 1-7 and 11-14 traverse a real TLS 1.3 handshake with a real
// CA-signed client certificate, and steps 8-10 call the engine directly. If a
// future change made reflexes reach the gateway over the network, this file
// would have to change — which is the right amount of friction for a decision
// that size.
func TestP0Acceptance(t *testing.T) {
	r := newRun(t)
	// Nil when driving a live instance, whose sink belongs to its own process.
	if r.sink != nil {
		defer r.sink.Close(context.Background())
	}
	ctx := context.Background()

	triage := r.as(t, "agent:triage")
	mesh := r.as(t, "mesh:primary")
	global := r.as(t, "agent:global")

	// 1 — THE HAPPY PATH. A mesh acting for an agent it may speak for.
	r.narrate(t, "delegated command: mesh:primary acting for agent:triage")
	resp, err := mesh.Execute(actingFor(ctx, "agent:triage"),
		execute("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ", "title": "checkout friction"}))
	if err != nil {
		t.Fatalf("step 1: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 1: status %v, reason %q", got, resp.GetResult().GetReason())
	}

	// 2 — DENIAL. §5.4's highest-value row.
	r.narrate(t, "denied: an action the grant does not cover")
	resp, err = triage.Execute(ctx, execute("kata.comment", "kata:alpha", nil))
	if err != nil {
		t.Fatalf("step 2: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("step 2: status %v", got)
	}

	// 3 — CONSTRAINT. The grant permits project PROJ only.
	r.narrate(t, "denied: a `where` constraint is not satisfied")
	resp, _ = triage.Execute(ctx,
		execute("kata.create_issue", "kata:alpha", map[string]any{"project": "SECRET"}))
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("step 3: status %v", got)
	}

	// 4 — ANZEN CEILING. delete_project is ESCALATE in the grant; the guard
	// outranks that, and the record names anzen rather than policy.
	r.narrate(t, "refused by anzen: a destructive action, forbidden regardless of grants")
	resp, _ = triage.Execute(ctx, execute("kata.delete_project", "kata:alpha", nil))
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("step 4: status %v — a guard must outrank an escalation", got)
	}

	// 5 — RESIDENCY. Policy allows; the deployment's region does not.
	r.narrate(t, "refused on residency: a permitted action on an eu-resident target")
	// A RESULT, NOT A TRANSPORT ERROR (D135). Residency is §7.1 item 2's
	// guarantee working, so it refuses the way every deliberate refusal does —
	// with a status and a decision id joining it to the record that explains it.
	resp, rerr := global.Execute(ctx, execute("kata.create_issue", "kata:beta", nil))
	if rerr != nil {
		t.Fatalf("step 5: residency arrived as a transport error (%v); a deliberate "+
			"refusal must reach the caller as a result", rerr)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("step 5: status %v — an eu-resident target resolved in a us deployment", got)
	}
	if resp.GetResult().GetDecisionId() == "" {
		t.Fatal("step 5: the residency refusal carries no decision id, so the line an " +
			"operator watches cannot be joined to the record (D124)")
	}

	// 6 — DRY RUN. A real record, no effect.
	r.narrate(t, "dry run: audited as WOULD_HAVE_FIRED, no side effect")
	dry := execute("kata.create_issue", "kata:alpha", map[string]any{"project": "PROJ"})
	dry.Command.DryRun = true
	resp, _ = triage.Execute(ctx, dry)
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED {
		t.Fatalf("step 6: status %v", got)
	}

	// 7 — READ PLANE, governed identically (§4.1.1).
	r.narrate(t, "query: the read plane, audited like a write")
	qresp, err := triage.Query(ctx,
		&sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
	if err != nil || qresp.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 7: %v / %v", err, qresp.GetStatus())
	}

	// 8 — BUS -> BUS ENRICHMENT. No command, so no decision record (D23).
	r.narrate(t, "reflex enrichment: raw -> enriched, explicit carry, no audit record")
	skipReflexes := r.localOnly(t, "a reflex calls the enforcement path in-process, which "+
		"is what a reflex IS (D69) — there is no network path to drive it through")
	// A REALISTIC RAW EVENT — seven fields, including personal data. A raw
	// envelope carries everything the source knew; deciding who receives which
	// parts of it is shin's job, and a three-field fixture could not show that.
	var enriched *sekizuiv1.Envelope
	raw := envelope(t, "raw", "fullstory.rage_click.v1", map[string]any{
		"session_id": "abc123",
		"url":        "/checkout",
		"clicks":     7,
		"severity":   "high",
		"device":     "mobile",
		"region":     "eu",
		"user":       map[string]any{"id": "u-4417", "email": "someone@example.invalid"},
	})
	if !skipReflexes {
		outcomes := r.engine.Dispatch(ctx, raw)

		for _, o := range outcomes {
			if o.Err != nil {
				t.Fatalf("step 8: rule %s: %v", o.Rule, o.Err)
			}
			if o.Publish != nil {
				enriched = o.Publish
			}
		}
		if enriched == nil {
			t.Fatal("step 8: no enriched envelope produced")
		}
		if _, carried := enriched.GetData().AsMap()["clicks"]; carried {
			t.Error("step 8: an uncarried field propagated")
		}
	}

	// 9 — REFLEX FIRES on the enriched envelope, through the identical path.
	r.narrate(t, "reflex action: enriched -> command, same enforcement path as an agent")
	fired := skipReflexes
	if !skipReflexes {
		for _, o := range r.engine.Dispatch(ctx, enriched) {
			if o.Err != nil {
				t.Fatalf("step 9: rule %s: %v", o.Rule, o.Err)
			}
			if o.Result != nil && o.Result.GetStatus() == sekizuiv1.Status_STATUS_OK {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatal("step 9: the bus->driver reflex did not fire")
	}

	// 10 — LLM-STAGE REFLEX in shadow (D64). Acknowledged in config, and shadow
	// so it records rather than acts.
	r.narrate(t, "reflex downstream of a model: acknowledged, shadow-mode, audited")
	judged := envelope(t, "judged", "agent.verdict.v1", map[string]any{"severity": "high"})
	sawShadow := skipReflexes
	if !skipReflexes {
		for _, o := range r.engine.Dispatch(ctx, judged) {
			if o.Result != nil && o.Result.GetStatus() == sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED {
				sawShadow = true
			}
		}
	}
	if !sawShadow {
		t.Fatal("step 10: the llm-stage reflex did not record a shadow firing")
	}

	// 11 — UNAUTHENTICATED. No record, deliberately: no principal to attribute.
	//
	// Over a real socket this is refused during the HANDSHAKE, before a single
	// byte of the request is parsed — RequireAndVerifyClientCert. Stronger than
	// the in-process version, which had to reach the verifier to fail.
	r.narrate(t, "unauthenticated: refused at the TLS handshake, with NO audit record")
	unauthCtx, cancelUnauth := context.WithTimeout(ctx, 10*time.Second)
	defer cancelUnauth()
	if _, err := r.anonymous(t).Execute(unauthCtx,
		execute("kata.create_issue", "kata:alpha", nil)); err == nil {
		t.Fatal("step 11: a caller presenting no certificate was served")
	}

	// 12 — CONFUSED DEPUTY (§4.4.1).
	r.narrate(t, "confused deputy: an agent may not speak for the mesh")
	if _, err := triage.Execute(actingFor(ctx, "mesh:primary"),
		execute("kata.create_issue", "kata:alpha", nil)); err == nil {
		t.Fatal("step 12: impersonation succeeded")
	}

	// 13 — THE CATALOG (§4.9, D79). The efferent plane's other half: an agent
	// asking what it may do, before spending a turn finding out.
	//
	// PROVEN AGAINST THE RUN ITSELF rather than against a fixture. Steps 1-12
	// established what agent:triage can and cannot do by executing; this asserts
	// the catalog says the same thing. A catalog that agrees with a fixture but
	// not with the enforcement path is the exact drift D79 exists to prevent.
	r.narrate(t, "catalog: what agent:triage may do, and what it is not told about")
	beforeDescribe := 0
	if !r.remote {
		beforeDescribe = len(readLog(t, r.path))
	}
	described, err := triage.Describe(ctx, &sekizuiv1.DescribeRequest{})
	if err != nil {
		t.Fatalf("step 13: Describe: %v", err)
	}

	// **DESCRIBE WRITES EXACTLY ONE RECORD, AND THIS ASSERTION USED TO REQUIRE
	// ZERO (D79 → D166).** The enumeration trace was the one trace outside the
	// hash chain: a log line, at DEBUG for self-describe (D126), in a file
	// CONTRACTS 28 says loses records on rotation. D79's dilution objection is
	// answered by a row a query can exclude (`action == "sekizui.describe"`) and
	// its volume premise contradicted its own text — "a call agents make
	// rarely".
	//
	// **INVERTED RATHER THAN DELETED, AND IT WAS THE THIRD COPY.** The claim
	// reversed, so every guard enforcing it had to reverse too: this one,
	// `gateway.TestDescribeWritesNoAuditRecord`, and P2 step 22 which now proves
	// the row is in the chain. A deleted assertion would have left the reversal
	// unproven exactly where the old one proved it.
	//
	// Checked HERE rather than at the end of the run: a later comparison against
	// the final log length blames this step for every record any subsequent step
	// wrote, which is what the first version did.
	if after := logLen(t, r); !r.remote && after != beforeDescribe+1 {
		t.Errorf("step 13: Describe wrote %d audit record(s), want exactly 1 — the "+
			"disclosure row is what puts an enumeration inside the hash chain (D166)",
			after-beforeDescribe)
	}

	advertised := map[string]bool{}
	for _, c := range described.GetCapabilities() {
		advertised[c.GetAction()] = true
		r.detail(t, "`%s` — %s", c.GetAction(), c.GetDescription())
	}

	// Step 1 executed this successfully, so it must be advertised.
	if !advertised["kata.create_issue"] {
		t.Error("step 13: the catalog omits kata.create_issue, which step 1 executed")
	}
	// Step 5 was refused by anzen REGARDLESS of grants (D71). A guard that
	// blocks an action while the catalog still advertises it sends every agent
	// to a guaranteed refusal — the ceiling must be visible from below.
	if advertised["kata.delete_project"] {
		t.Error("step 13: the catalog advertises kata.delete_project, which anzen refuses " +
			"unconditionally (step 5); agents would be sent at a wall")
	}
	// 14 — MIXED-TENANT CONCURRENCY (§12.1 spikes 5 and 6, and §6 item 5).
	//
	// DESIGN calls this "the highest-value test in the project, and the reason Go
	// helps here at all". One principal, four tenants, every command in flight at
	// once over a single multiplexed HTTP/2 connection — the realistic shape of a
	// shared mesh serving several customers, and the only shape in which tenant
	// bleed is possible at all.
	//
	// The assertion is not "it did not crash". Each response carries the tenant
	// the DRIVER saw, so a Target substituted under concurrency shows up as a
	// response whose tenant is not the one its request asked for. That is the
	// failure §6 exists to prevent, and it is invisible to any single-threaded
	// test. Run under -race by `make verify`, which is what makes an unguarded
	// map or a shared Target a failure rather than a coin flip.
	r.narrate(t, "mixed-tenant concurrency: 4 tenants in flight at once, no bleed")
	bulk := r.as(t, "agent:bulk")
	tenants := map[string]string{
		"kata:alpha": "alpha", "kata:gamma": "gamma",
		"kata:delta": "delta", "kata:epsilon": "epsilon",
	}

	const perTenant = 12
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		seen    = map[string]int{} // decision id -> times issued
		bleeds  []string
		refused []error
	)

	for ref, want := range tenants {
		for range perTenant {
			wg.Add(1)
			go func(ref, want string) {
				defer wg.Done()
				resp, err := bulk.Execute(ctx, execute("kata.create_issue", ref,
					map[string]any{"project": "PROJ", "title": "concurrent " + want}))

				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					refused = append(refused, err)
					return
				}
				res := resp.GetResult()
				if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
					refused = append(refused, fmt.Errorf("%s: %s", ref, res.GetReason()))
					return
				}
				seen[res.GetDecisionId()]++

				// THE TENANT THE DRIVER ACTUALLY SAW, echoed back through
				// Result.Data. Not what the test believes it requested.
				if got, _ := res.GetResult().AsMap()["tenant"].(string); got != want {
					bleeds = append(bleeds, fmt.Sprintf(
						"a command for %s was executed against tenant %q", ref, got))
				}
			}(ref, want)
		}
	}
	wg.Wait()

	if len(bleeds) > 0 {
		t.Fatalf("step 14: TENANT BLEED under concurrent load — %d of %d commands "+
			"reached the wrong tenant:\n  %s", len(bleeds), len(tenants)*perTenant,
			strings.Join(bleeds, "\n  "))
	}
	if len(refused) > 0 {
		// Admission shedding is legitimate under load (§7.1), but the acceptance
		// run sizes its limit above this burst, so a refusal here is a defect
		// rather than a design behaving as intended.
		t.Fatalf("step 14: %d of %d concurrent commands were refused; first: %v",
			len(refused), len(tenants)*perTenant, refused[0])
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("step 14: decision id %q issued %d times; two concurrent actions "+
				"sharing an id are indistinguishable in the audit log forever after", id, n)
		}
	}
	r.detail(t, "%d commands across %d tenants, every one attributed to the tenant it named",
		len(seen), len(tenants))

	// 15 — SHIN (§4.12, D83–D86). What a consumer RECEIVES, as distinct from what
	// it may do.
	//
	// TWO CALLERS WITH DIFFERENT SHAPES, deliberately. Query hands the lens flat
	// rows over a real network egress; a reflex hands it a typed, versioned
	// envelope. A seam with one caller gets shaped to fit that caller (D70), and
	// the bus at P3 will be the third.
	r.narrate(t, "shin: the same data, shaped for who is receiving it")

	// 15a — IMPOSED. A jurisdiction ceiling the consumer cannot decline, over a
	// real socket. agent:analytics is fully entitled to this read and is still
	// the wrong recipient for the personal part of it.
	analytics := r.as(t, "agent:analytics")
	aresp, err := analytics.Query(ctx,
		&sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
	if err != nil {
		t.Fatalf("step 15a: %v", err)
	}
	if len(aresp.GetRows()) == 0 {
		t.Fatal("step 15a: no rows to lens")
	}
	lensed := aresp.GetRows()[0].AsMap()
	user, _ := lensed["user"].(map[string]any)
	if _, leaked := user["email"]; leaked {
		t.Errorf("step 15a: user.email reached agent:analytics; the imposed lens did not apply")
	}
	if _, kept := user["id"]; !kept {
		t.Error("step 15a: user.id was removed too — a lens withholds what it names, " +
			"not the subtree around it")
	}
	if got := aresp.GetAppliedLenses(); len(got) != 2 ||
		got[0] != "no-pii-to-analytics" || got[1] != "us-detail-withheld" {
		// SORTED BY NAME (shin.Apply), not declaration order — D326 renamed the
		// jurisdiction lens and moved it to the other side of `no-pii`.
		t.Errorf("step 15a: applied_lenses = %v, want [no-pii-to-analytics "+
			"us-detail-withheld]; a consumer must be able to tell a lens removed a "+
			"field from the data not being there", got)
	}

	// --- JURISDICTION-SCOPED LENSING, BOTH ARMS (CONTRACTS item 40) ----------
	//
	// `Lens.Residency` has existed since D84 and no fixture set it, so the arm
	// was proven by a unit test and never taken on the real delivery path — the
	// recurring defect's silhouette. Two lenses now scope on the DATA's class:
	// `us-detail-withheld` must apply here and `eu-detail-withheld` must not,
	// because kata:alpha is us-resident (the suite's home class, D326).
	//
	// ONE LENS COULD ONLY PROVE ONE ARM. A single us-scoped lens that applied
	// would be satisfied by a `covers` that ignored residency entirely; the eu
	// lens is what makes the field discriminate rather than merely exist.
	if _, present := lensed["target"]; present {
		t.Error("step 15a: `target` survived, so the us-scoped lens did not apply to " +
			"us-resident data — the residency arm of Lens.covers is not being taken")
	}
	if _, present := user["id"]; !present {
		t.Error("step 15a: `user.id` was withheld, so the EU-scoped lens applied to " +
			"US-resident data — a jurisdiction scope that matches everything is worse " +
			"than none, because the config claims a boundary it does not enforce")
	}
	r.detail(t, "imposed: `agent:analytics` receives %v, `user` narrowed to %v",
		sortedKeys(lensed), sortedKeys(user))

	// 15b — THE SAME QUERY, UNLENSED, for a consumer no lens covers. Proves 15a
	// removed something rather than the field never existing.
	tresp, err := triage.Query(ctx,
		&sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
	if err != nil {
		t.Fatalf("step 15b: %v", err)
	}
	whole, _ := tresp.GetRows()[0].AsMap()["user"].(map[string]any)
	if _, present := whole["email"]; !present {
		t.Fatal("step 15b: user.email is absent even unlensed, so 15a proved nothing")
	}
	if len(tresp.GetAppliedLenses()) != 0 {
		t.Errorf("step 15b: %v applied to a consumer no lens covers; absence of a lens "+
			"is not a lens that removes everything", tresp.GetAppliedLenses())
	}
	r.detail(t, "unlensed: the same query for a consumer no lens covers keeps `user` %v",
		sortedKeys(whole))

	// 15c — REQUESTABLE, on the reflex's published envelope. The two-key case:
	// seven fields become two, because a triage agent needs where the friction
	// happened rather than the whole session.
	// Applied to the RAW envelope, whose type is registered and versioned (D41).
	// The enriched envelope's type is derived from its bus subject and is
	// neither — recorded in CONTRACTS, because a lens cannot validate field paths
	// against a schema that does not exist.
	if r.localOnly(t, "shin.Deliver is an in-process call on the envelope a reflex "+
		"produced; the network path for it is Subscribe, which step 16 covers") {
		return
	}
	lenses := shin.New(r.doc.Shin)
	before := raw.GetData().AsMap()
	after, names, err := lenses.Deliver("agent:triage", raw, "triage-lite")
	if err != nil {
		t.Fatalf("step 15c: %v", err)
	}
	got := after.GetData().AsMap()
	if len(got) >= len(before) {
		t.Errorf("step 15c: %d fields in, %d out — a lens must reduce", len(before), len(got))
	}
	for _, want := range []string{"session_id", "url"} {
		if _, ok := got[want]; !ok {
			t.Errorf("step 15c: %q was removed; the lens names it as kept", want)
		}
	}
	if _, leaked := got["severity"]; leaked {
		t.Error("step 15c: an unnamed field survived the allow-list")
	}
	// PROVENANCE IS NEVER LENSED. Without id and type a consumer cannot correlate
	// what it received with what the audit log says happened, which is exactly
	// the evasion shin must not enable.
	if after.GetId() != raw.GetId() || after.GetType() != raw.GetType() {
		t.Error("step 15c: a lens altered envelope provenance; it may shape the payload only")
	}
	r.detail(t, "requested: `agent:triage` selects `%s` — %d fields %v become %d %v",
		strings.Join(names, ","), len(before), sortedKeys(before), len(got), sortedKeys(got))

	// 15e — A TYPED LENS ON A QUERY RESULT, possible only because the driver
	// declares its output type (D88). Before that, query results could be
	// narrowed by withholding but never by an allow-list.
	idsOnly, err := analytics.Query(ctx, &sekizuiv1.QueryRequest{
		Action: "kata.read", TargetRef: "kata:alpha", Lens: "ids-only",
	})
	if err != nil {
		t.Fatalf("step 15e: %v", err)
	}
	row := idsOnly.GetRows()[0].AsMap()
	if _, present := row["user"]; present {
		t.Error("step 15e: the allow-list kept a field it does not name")
	}
	for _, want := range []string{"id", "tenant"} {
		if _, ok := row[want]; !ok {
			t.Errorf("step 15e: %q was removed; the lens names it as kept", want)
		}
	}
	r.detail(t, "typed query lens: `agent:analytics` selects `ids-only` — %v via %v",
		sortedKeys(row), idsOnly.GetAppliedLenses())

	// 15d — A LENS NOBODY OFFERED IS REFUSED, not silently ignored. D46's model
	// for MCP tools: what is not declared is not selectable.
	if _, _, err := lenses.Deliver("agent:triage", raw, "give-me-everything"); err == nil {
		t.Error("step 15d: an undeclared lens was accepted")
	}
	// And an IMPOSED lens cannot be selected — it is a ceiling, not an offer.
	if _, _, err := lenses.Deliver("agent:analytics", raw, "no-pii-to-analytics"); err == nil {
		t.Error("step 15d: an imposed lens was selectable, which would let a consumer " +
			"treat a ceiling as a choice")
	}

	// 16 — SUBSCRIBE (§4.6, D91–D93). The afferent plane's egress, over the same
	// real socket, with the same three questions answered as an Execute:
	// authorised, audited, lensed.
	r.narrate(t, "subscribe: an authorised, audited, lensed event stream")
	if r.localOnly(t, "publishing onto the bus needs in-process access until P3 brings a "+
		"real ingress; the SUBSCRIPTION half is authorised and lensed over the wire either way") {
		return
	}

	subCtx, cancelSub := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSub()

	stream, err := analytics.Subscribe(subCtx, &sekizuiv1.SubscribeRequest{
		Subjects: []string{"sekizui.enriched.>"},
	})
	if err != nil {
		t.Fatalf("step 16: opening the subscription: %v", err)
	}

	// WAIT FOR THE SERVER TO REGISTER THE SUBSCRIPTION.
	//
	// A streaming RPC returns its client handle as soon as the call is made; the
	// server handler runs asynchronously and has not necessarily reached
	// bus.Subscribe yet. Publishing immediately fans the envelope out to zero
	// subscribers and it is gone — at-most-once means exactly that, and the
	// symptom is a Recv that blocks until the deadline with no error to explain
	// it. Real consumers hit the same race; they solve it by subscribing before
	// the source starts, which is what P3's poller ordering will do.
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 },
		"the server never registered the subscription")

	// The reflex-enriched envelope from step 8, published onto the bus. P3 adds
	// the poller that fills it from a real source; the governed path is what P0
	// proves.
	//
	// PUBLISHED AS ENRICH MADE IT. This step used to overwrite
	// `enriched.Subject` with "sekizui.enriched.friction_detected" first — the
	// entity field set to a routing string, because the bus routed on the entity
	// and nothing else would have matched (D258). The envelope is routed on its
	// stage and declared type now, and its entity is the session it is about.
	if err := r.srv.PublishForTest(enriched); err != nil {
		t.Fatalf("step 16: publishing: %v", err)
	}

	received, rerr := stream.Recv()
	if rerr != nil {
		t.Fatalf("step 16: receiving: %v", rerr)
	}

	// SHIN APPLIED ON THE WAY OUT. agent:analytics is under the imposed
	// no-pii ceiling, so the delivered payload is narrower than what was
	// published — the same lens layer Query uses, now with a second caller.
	streamed := received.GetEnvelope().GetData().AsMap()
	if _, leaked := streamed["user"]; leaked {
		if u, _ := streamed["user"].(map[string]any); u["email"] != nil {
			t.Error("step 16: user.email reached a subscriber the imposed lens covers")
		}
	}
	// PROVENANCE SURVIVES. Without id and type a consumer cannot correlate a
	// delivery with the audit log, which is the evasion shin must not enable.
	if received.GetEnvelope().GetId() != enriched.GetId() {
		t.Error("step 16: the delivered envelope lost its id")
	}
	r.detail(t, "delivered `%s` to `agent:analytics` as %v",
		received.GetEnvelope().GetType(), sortedKeys(streamed))

	// 16b — DENY BY DEFAULT. agent:triage has no subscribe grant at all.
	denyCtx, cancelDeny := context.WithTimeout(ctx, 10*time.Second)
	defer cancelDeny()
	badStream, derr := triage.Subscribe(denyCtx, &sekizuiv1.SubscribeRequest{})
	if derr == nil {
		_, derr = badStream.Recv()
	}
	if derr == nil {
		t.Error("step 16b: a principal with no subscribe grant opened a stream")
	}

	// 16c — A SUBJECT BROADER THAN THE GRANT IS REFUSED, not silently narrowed.
	wideCtx, cancelWide := context.WithTimeout(ctx, 10*time.Second)
	defer cancelWide()
	wideStream, werr := analytics.Subscribe(wideCtx,
		&sekizuiv1.SubscribeRequest{Subjects: []string{"sekizui.>"}})
	if werr == nil {
		_, werr = wideStream.Recv()
	}
	if werr == nil {
		t.Error("step 16c: a consumer subscribed to more than its grant covers")
	}
	r.detail(t, "refused: no grant at all, and a subject broader than the grant")

	// --- verification over the whole log ------------------------------------
	//
	// LOCAL ONLY. The audit log belongs to the process that wrote it, and a live
	// instance's log is on its own disk under its own WAL. Verifying a chain we
	// did not observe being written would prove nothing about this run.
	if r.localOnly(t, "the audit log, metrics, and hash chain belong to the live "+
		"instance's own process — `make acceptance` verifies them") {
		return
	}

	records := readLog(t, r.path)
	t.Logf("audit log: %s (%d records)", r.path, len(records))

	// The scrape is part of the evidence: an operator's dashboard and the audit
	// log must partition the same run the same way.
	var scrape strings.Builder
	if _, err := r.srv.Metrics().WriteTo(&scrape); err != nil {
		t.Fatalf("metrics: %v", err)
	}
	t.Logf("metrics scrape:\n%s", scrape.String())
	if out := os.Getenv("SEKIZUI_ACCEPTANCE_OUT"); out != "" {
		_ = os.WriteFile(strings.TrimSuffix(out, ".jsonl")+".prom", []byte(scrape.String()), 0o600)
	}
	// P0's scrape, and the report labels it as P0's. Each P1/P2 step builds its
	// own gateway, so there is no whole-file scrape to offer.
	evidence.metrics(scrape.String())

	chainErr := auditwal.VerifyChain(records)
	if chainErr != nil {
		t.Errorf("the hash chain over the acceptance run does not verify: %v", chainErr)
	}

	// THE SHAREABLE RENDERING (D87) IS NO LONGER WRITTEN HERE. It covers every
	// phase now, so it cannot be written by the first phase's test — the log it
	// renders is still being appended to by P1 and P2 when this line runs, which
	// is exactly how the old report came to describe 117 of 519 records while
	// claiming to be derived from the file. TestMain writes it after every phase
	// has run. The chain verification above stays local, because P0 is the run
	// whose records this process watched being written.
	// Every reflex-driven record must name the RULE, not only the principal
	// (D96). Three rules share `reflex:friction` in this configuration, so
	// without it the log cannot answer "why did this ticket get created".
	for _, rec := range records {
		if !strings.HasPrefix(rec.GetIdentity().GetSubject().GetPrincipal(), "reflex:") {
			continue
		}
		if rec.GetReflexName() == "" {
			t.Errorf("a reflex-driven record names no rule: %s on %s by %s — three rules "+
				"share this principal, so the log cannot say which fired",
				rec.GetAction(), rec.GetTargetRef(),
				rec.GetIdentity().GetSubject().GetPrincipal())
		}
	}

	assertEveryReachableVerdictAppears(t, records)
	assertEveryRecordIsSelfContained(t, records)
}

// assertEveryReachableVerdictAppears is what makes this a living checklist.
//
// A verdict the code can produce but the run never exercises is a capability
// nobody proved. BUDGET_EXCEEDED is deliberately absent — it needs reflex firing
// budgets, which arrive at P5 — and naming it here means the gap is recorded
// rather than forgotten.
func assertEveryReachableVerdictAppears(t *testing.T, records []*sekizuiv1.Decision) {
	t.Helper()

	seen := map[sekizuiv1.Verdict]bool{}
	for _, rec := range records {
		seen[rec.GetVerdict()] = true
	}

	for _, want := range []sekizuiv1.Verdict{
		sekizuiv1.Verdict_VERDICT_ALLOW,
		sekizuiv1.Verdict_VERDICT_DENY,
		sekizuiv1.Verdict_VERDICT_WOULD_HAVE_FIRED,
	} {
		if !seen[want] {
			t.Errorf("verdict %v never appears in the acceptance run; a capability the code "+
				"can produce was not exercised", want)
		}
	}

	// Recorded, not asserted: reaching it needs P5's firing budgets.
	if seen[sekizuiv1.Verdict_VERDICT_BUDGET_EXCEEDED] {
		t.Log("BUDGET_EXCEEDED now reachable — add it to the required set")
	}
}

// assertEveryRecordIsSelfContained is D39: each row must be independently
// readable years later with no joins.
func assertEveryRecordIsSelfContained(t *testing.T, records []*sekizuiv1.Decision) {
	t.Helper()

	for i, rec := range records {
		switch {
		case rec.GetId() == "":
			t.Errorf("record %d has no id", i)
		case rec.GetIdentity().GetSubject().GetPrincipal() == "":
			t.Errorf("record %d (%s) does not say WHO", i, rec.GetId())
		case rec.GetAction() == "":
			t.Errorf("record %d (%s) does not say WHAT", i, rec.GetId())
		case rec.GetVerdict() == sekizuiv1.Verdict_VERDICT_UNSPECIFIED:
			t.Errorf("record %d (%s) has no verdict", i, rec.GetId())
		case rec.GetMatchedRule() == "":
			t.Errorf("record %d (%s) does not say WHAT DECIDED; an unexplainable outcome "+
				"is a log line, not an audit record (§5.4)", i, rec.GetId())
		}
		// A refusal must carry a reason an operator can act on.
		if rec.GetVerdict() == sekizuiv1.Verdict_VERDICT_DENY && rec.GetReason() == "" {
			t.Errorf("record %d (%s) is a denial with no reason", i, rec.GetId())
		}
	}
}

// splitLines drops blanks, so a trailing newline does not become an empty record.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func readLog(t *testing.T, path string) []*sekizuiv1.Decision {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var out []*sekizuiv1.Decision
	for _, line := range splitLines(string(data)) {
		var d sekizuiv1.Decision
		if err := protojson.Unmarshal([]byte(line), &d); err != nil {
			t.Fatalf("parsing audit line: %v", err)
		}
		out = append(out, &d)
	}
	return out
}

// logLen reads the audit log length, or zero when driving a live instance whose
// log belongs to another process.
func logLen(t *testing.T, r *run) int {
	t.Helper()
	if r.remote {
		return 0
	}
	return len(readLog(t, r.path))
}

// noSignal discards anzen signals, for engines whose step is not about them.
func noSignal(context.Context, string, map[string]string) {}

// fullstoryOpts builds the Fullstory driver exactly as production does, plus
// the one substitution runOpts allows.
//
// **A FIXTURE CLIENT ADMITS THE FIXTURE HOSTS ITS DOCUMENT NAMES, AND NOTHING
// ELSE (P3 step 24).** The driver dials only Fullstory's own hosts; a step that
// patched a target onto a TLS fixture passes the client that trusts it, and
// only then are the patched hosts admitted.
func fullstoryOpts(p *pool.Pool, opts runOpts, doc *config.Document) []fullstory.Option {
	out := []fullstory.Option{fullstory.WithPool(p)}
	if opts.fullstoryClient != nil {
		out = append(out, fullstory.WithHTTPClient(opts.fullstoryClient))
		for _, t := range doc.Targets {
			if u, err := url.Parse(t.BaseURL); err == nil && t.Kind == fullstory.Kind {
				out = append(out, fullstory.WithHosts(u.Host))
			}
		}
	}
	return out
}

// mcpOpts is the MCP driver's options: the pool always, and a fixture's client
// when a step supplies one.
func mcpOpts(p *pool.Pool, opts runOpts) []mcp.Option {
	out := []mcp.Option{mcp.WithPool(p)}
	if opts.mcpClient != nil {
		out = append(out, mcp.WithHTTPClient(opts.mcpClient))
	}
	return out
}

// fixtureHost admits a TLS fixture's host to the Fullstory driver, which dials
// only Fullstory's own hosts otherwise (P3 step 24). For a step that builds its
// driver around a fixture it also trusts.
func fixtureHost(rawURL string) fullstory.Option {
	u, _ := url.Parse(rawURL)
	return fullstory.WithHosts(u.Host)
}
