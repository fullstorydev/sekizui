// Command sekizui is the single binary. The -mode flag selects which
// deployment it is (§5.3): same code, different lifecycle.
//
// WHAT THIS DOES: detects the runtime environment, refuses incoherent
// configuration, serves the governed gRPC surface over mTLS, serves liveness and
// readiness probes on a separate plaintext port, and drains on SIGTERM.
//
// TWO LISTENERS, NOT ONE. Probes are plaintext HTTP for a load balancer; the
// gateway is mTLS gRPC for agents. One port would force a choice between
// exposing probes only to verified clients and serving the enforcement path
// without client verification, and neither is acceptable.
//
// Deliberately NOT a module-level side effect. Lexicon's entry point ended with
//
//	export const lexicon = await initializeForFunctions()
//
// (lexicon/index.js:601) — a top-level await that is untestable,
// cannot fail gracefully, and is the main reason initialisation order there is
// hard to follow (§4.10.4). Everything here is explicit wiring inside main.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fullstorydev/sekizui/internal/actionset"
	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/builtin"
	"github.com/fullstorydev/sekizui/internal/bus"
	"github.com/fullstorydev/sekizui/internal/catalog"
	"github.com/fullstorydev/sekizui/internal/churn"
	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/internal/denial"
	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/grantcheck"
	"github.com/fullstorydev/sekizui/internal/identity"
	"github.com/fullstorydev/sekizui/internal/konbini"
	"github.com/fullstorydev/sekizui/internal/kyuushin"
	"github.com/fullstorydev/sekizui/internal/ledger"
	"github.com/fullstorydev/sekizui/internal/limiter"
	"github.com/fullstorydev/sekizui/internal/meter"
	"github.com/fullstorydev/sekizui/internal/metrics"
	"github.com/fullstorydev/sekizui/internal/mistenant"
	"github.com/fullstorydev/sekizui/internal/obs"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/internal/reflex"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/retry"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/internal/shin"
	"github.com/fullstorydev/sekizui/internal/spine"
	"github.com/fullstorydev/sekizui/internal/tracing"
	"github.com/fullstorydev/sekizui/internal/verb"
	"github.com/fullstorydev/sekizui/pkg/audit"
	pkgbus "github.com/fullstorydev/sekizui/pkg/bus"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/provider/ambient"
	filecred "github.com/fullstorydev/sekizui/pkg/provider/file"
	"github.com/fullstorydev/sekizui/pkg/provider/oauth"
)

func main() {
	// Install a redacting default logger BEFORE anything can log, so slog's
	// package-level default is never the stock non-redacting handler. "The
	// redacting handler is not optional" is only true if it is also unavoidable.
	//
	// TEXT, not JSON: run() replaces this within a few lines, so the only way
	// this handler emits anything is a failure before flags are even parsed —
	// which means a human at a terminal. Production never reaches this path;
	// its arguments come from a manifest and do not vary between deploys.
	slog.SetDefault(obs.NewLogger(os.Stdout, obs.Options{Level: slog.LevelInfo, JSON: false}))

	// main does nothing but translate a failure into an exit code. Everything
	// real is in run(), so that it can return errors normally rather than
	// calling os.Exit from deep inside the call stack — os.Exit skips deferred
	// functions, which would mean skipping the drain.
	if err := run(); err != nil {
		slog.Error("startup failed", "err", err, "kind", fault.KindOf(err))
		os.Exit(1)
	}
}

func run() error {
	const op = "main.run"

	var (
		modeFlag  = flag.String("mode", "gateway", "deployment mode: gateway|ingest (§5.3)")
		addrFlag  = flag.String("addr", "", "HTTP listen address for probes; defaults to :$PORT or :8080")
		auditFlag = flag.String("audit", "wal", "audit delivery: wal|sync")
		walFlag   = flag.String("wal", "", "WAL directory; required when -audit=wal")
		drainFlag = flag.Duration("drain", 15*time.Second, "shutdown drain budget")

		// Escape hatches for capabilities detection cannot determine. Cloud Run
		// exposes nothing distinguishing CPU-always-allocated, so an operator
		// who has configured it says so here.
		bgFlag   = flag.String("background-work", "", "override capability detection: true|false")
		leadFlag = flag.String("leader-election", "", "override capability detection: true|false")

		levelFlag = flag.String("log-level", "info", "debug|info|warn|error")
		textFlag  = flag.Bool("log-text", false, "human-readable logs instead of JSON")

		configFlag = flag.String("config", "sekizui.yaml", "path to the configuration file (§4.7)")

		// The governed surface. SEPARATE PORT FROM PROBES, deliberately: probes
		// are plaintext HTTP for a load balancer, the gateway is mTLS gRPC for
		// agents. Sharing a port would mean either exposing probes to mTLS
		// clients only, or serving the enforcement path without client
		// verification. Neither is acceptable, so they are two listeners.
		grpcFlag     = flag.String("grpc-addr", ":8443", "gRPC listen address for the governed surface")
		tlsCertFlag  = flag.String("tls-cert", "", "server certificate (PEM)")
		tlsKeyFlag   = flag.String("tls-key", "", "server private key (PEM)")
		tlsCAFlag    = flag.String("tls-client-ca", "", "CA that client certificates are verified against")
		residencyFl  = flag.String("residency", "", "comma-separated residency classes this instance may serve; empty means unconstrained (§7.1)")
		inflightFlag = flag.Int("max-inflight", 64, "admission control: maximum concurrent commands (§7.1)")
		stormFlag    = flag.Int("denial-storm-threshold", 10, "refusals of other principals, in one minute, attributed to one principal over its share, that raise denial_storm (D336)")

		// THE FOUR OPERATIONAL BOUNDS ARE CEILINGS, NOT SETTINGS (D142). A target
		// narrows them in config; these say how far any target may go. Note that
		// -breaker-cooldown is a FLOOR: a shorter cooldown probes a dead target
		// more often, so gentler means longer.
		poolLifetimeFl    = flag.Duration("pool-max-lifetime", time.Hour, "ceiling on how long a pooled client may live, whatever else happens; a target may only lower it (D108)")
		retryAttemptsFl   = flag.Int("retry-attempts", 3, "ceiling on attempts per command, including the first; a target may only lower it (D142)")
		retryCapFl        = flag.Duration("retry-cap", 5*time.Second, "ceiling on a single backoff wait; a target may only lower it (D142)")
		breakerTripFl     = flag.Int("breaker-trip", 5, "ceiling on consecutive failures before a target's breaker opens; a target may only lower it (§4.3.4)")
		budgetFloorFl     = flag.Int64("budget-floor-pct", 10, "percentage of a configured rate budget this instance keeps once its capacity allocator has been unreachable for three refreshes; a SECURITY dial, because fleet growth during an outage is the exposure (D210)")
		breakerCooldownFl = flag.Duration("breaker-cooldown", 30*time.Second, "FLOOR on how long a breaker stays open before one probe; a target may only RAISE it (D142)")
		// D284. THE METER'S DEPLOYMENT LAYER: a ceiling per unit, and the
		// universal calls default for a target nobody sized.
		handleIdleFl   = flag.Duration("handle-idle", 15*time.Minute, "ceiling on how long a stateful handle (a review session, a sandbox) may go unused before Sekizui closes it as its opener; a target may only lower it (D291)")
		meterDefaultFl = flag.Uint("meter-default-calls", meter.DefaultCallsPerHour, "universal budget, in calls per hour, for a target whose connector declares no default and which declares no rate_per_hr (D284)")
		// D120. A SECOND DESTINATION IS THE WHOLE POINT — `Sink.Residencies` can
		// only refuse with one sink (D89), and routes with two.
		extraSinkFl  = flag.String("audit-sink", "", "additional audit destination as path[:class|class]; comma-separated for several. The local JSONL sink is always present (D120)")
		auditLogFlag = flag.String("audit-log", "", "path to the local audit JSONL; defaults to <wal>/audit.jsonl")

		glossaryFlag = flag.Bool("glossary", false, "explain Sekizui's vocabulary and exit")

		// D150. The deployer is the authority on which configuration was shipped;
		// a quorum of peers is not, because peers are the thing an attacker can
		// forge.
		expectConfigFl = flag.String("expect-config", "", "refuse to boot unless the configuration's identity hash matches this value (D150); empty disables the check")
		// D97. A FLAG RATHER THAN A CONFIG KEY, deliberately: the posture then
		// lives in the deploy manifest where it is reviewable, instead of in a
		// file where it reads as an ordinary setting.
		allowEnvFl    = flag.Bool("allow-env-credentials", false, "permit env:// credentials off a developer machine (D97) — unversioned, unaudited, and readable from /proc")
		demoFl        = flag.Bool("demo", false, "permit a DEMONSTRATION deployment (`demo: true`) to boot (D315); `make run` passes it, and no production manifest should")
		printConfigFl = flag.Bool("config-hash", false, "print the configuration's identity hash and exit — this is what -expect-config takes")
	)
	// D284. Repeatable, so it is a flag.Var rather than one of the above.
	fileRootsFl := pathList{}
	flag.Var(&fileRootsFl, "file-credential-root", "directory a file:// credential may be read from, repeatable; off a bare developer machine a file credential outside every root refuses the boot, and the audit directory is refused regardless (D286)")
	meterCeilingFl := meterCeilings{}
	flag.Var(meterCeilingFl, "meter-ceiling", "ceiling per meter unit as unit=N per hour, repeatable (e.g. -meter-ceiling calls=3600); a target asking for more is refused at boot, a connector default above it is lowered (D284)")
	flag.Parse()
	if err := filecred.ValidateRoots(fileRootsFl); err != nil {
		return err
	}
	if *meterDefaultFl == 0 || *meterDefaultFl > math.MaxUint32 {
		return fmt.Errorf("-meter-default-calls must be a positive number of calls per hour that fits in 32 bits, got %d", *meterDefaultFl)
	}

	// Sekizui uses deliberately unusual vocabulary, and an operator meeting
	// "anzen guard refused this action" in a log has nowhere to look. The
	// naming carries its own remedy (D67).
	if *glossaryFlag {
		fmt.Print(konbini.Render())
		return nil
	}

	// A GUARD NOBODY CAN COMPUTE THE INPUT FOR IS A GUARD NOBODY USES.
	// -expect-config takes a hash, and without this an operator would have to
	// boot the server and read a log line to learn what to pass — so the deploy
	// pipeline meant to supply it could not.
	//
	// Deliberately does NOT validate the document beyond parsing it. "What is
	// this file's identity" has an answer even when the file would be refused at
	// boot, and refusing to answer would make the tool useless for the case
	// where it matters most: working out why a deployment disagrees with what
	// was shipped.
	if *printConfigFl {
		doc, err := config.NewFileSource(*configFlag).Load(context.Background())
		if err != nil {
			return err
		}
		id, err := doc.Identity()
		if err != nil {
			return err
		}
		fmt.Println(id)
		return nil
	}

	// Install the configured logger IMMEDIATELY after flag.Parse, before any
	// other validation can fail.
	//
	// Note the ordering: the FORMAT is known the moment flags are parsed, so
	// -log-text is honoured even when the level itself is what is wrong. An
	// invalid level falls back to info for the length of one error message
	// rather than discarding the operator's format choice along with it.
	//
	// obs.NewLogger, never slog.New directly: the redacting handler is not
	// optional and there is no constructor that omits it (§4.3.3). A logger
	// built here from a stock handler would silently lose layer-2 redaction.
	level, levelErr := parseLevel(*levelFlag)
	if levelErr != nil {
		level = slog.LevelInfo
	}
	log := obs.NewLogger(os.Stdout, obs.Options{Level: level, JSON: !*textFlag})
	slog.SetDefault(log)

	if levelErr != nil {
		return levelErr
	}

	mode, err := parseMode(*modeFlag)
	if err != nil {
		return err
	}

	// Named auditMode, not audit: pkg/audit is imported below, and a local
	// shadowing a package name compiles fine while making every later reference
	// ambiguous to a reader.
	auditMode, err := parseAudit(*auditFlag)
	if err != nil {
		return err
	}
	ov, err := parseOverrides(*bgFlag, *leadFlag)
	if err != nil {
		return err
	}

	// Axis 1 and axis 2 (§4.10), resolved once. Everything downstream reads a
	// capability flag instead of re-sniffing environment variables — which is
	// how three separate checks ended up scattered through Lexicon's index.js.
	profile := runtime.Detect(os.Getenv, ov)

	// §4.10.2's secondary benefit: "which environment does this instance think
	// it is in, and what has it therefore disabled" as one line, not an
	// inference across the logs.
	log.Info("runtime profile detected", "profile", profile)

	// P0 exit criterion 4. An incoherent combination refuses here rather than
	// misbehaving quietly under load.
	plan, err := profile.Check(runtime.Requirements{
		Mode:        mode,
		Audit:       auditMode,
		WALPath:     *walFlag,
		DrainBudget: *drainFlag,
	})
	if err != nil {
		return err
	}
	for _, w := range plan.Warnings {
		log.Warn("configuration adjusted", "detail", w)
	}

	// **THE `-mode=ingest` STUB WARNING IS GONE, AND THE REFUSAL REPLACED IT
	// (D252, retired 2026-09-22).**
	//
	// It warned "the afferent path does not exist yet ... this process will
	// serve probes and poll nothing", which D53 asked for: a skeleton must
	// run or refuse, never silently succeed at nothing. **It now REFUSES** —
	// `refuseIngestWithNothingToPoll` fails the boot with a message naming
	// what to change — so the warning described an outcome that no longer
	// happens, and an operator read it moments before a refusal that
	// contradicted it. Two statements about one behaviour, disagreeing, with
	// the wrong one first.
	//
	// **DELETED RATHER THAN CORRECTED, because the refusal is strictly the
	// better half of D53's own rule.** It is actionable, it sits at the layer
	// that knows the mode, and it cannot drift from itself. Found by the
	// Feierabend end-to-end read rather than by a guard: nothing checks a log
	// line against the behaviour it describes.

	// One registry, written by the enforcement path and read by the scrape
	// endpoint. Constructed here rather than inside the gateway so cmd can serve
	// it without reaching into the server.
	met := metrics.New()

	// Readiness is owned by spine, not a local flag: §4.10.3 wants one source of
	// truth feeding both the probe and (later) the gate in front of the gRPC
	// interceptor chain.
	sp := spine.New(profile, log)

	// THE INIT LEDGER (D53), now in internal/ledger so it can be TESTED.
	//
	// It used to be this table, inline, with a comment claiming a subsystem "lands
	// by deleting its Plan entry and calling Register instead, which is a change a
	// compiler and a reviewer both see". The compiler saw nothing, and `pool` and
	// `limiter` landed in P1 steps 1-8 and 20-24 with their entries still here —
	// so every boot said `implemented=5/12` and /readyz reported DEGRADED for two
	// reasons this same binary contradicted. A readiness signal that under-reports
	// is one an operator learns to ignore.
	for _, p := range ledger.Planned() {
		sp.Plan(p)
	}

	// The first REGISTERED component. Registration order is start order and the
	// reverse of stop order, so config goes first: everything downstream reads
	// from it.
	//
	// Loader satisfies spine.Component, Validator, and HealthReporter without
	// importing spine — Go's interfaces are structural, so the right method set
	// is the whole requirement (see TestLoaderSatisfiesSpineInterfaces).
	var enforcement atomic.Pointer[gateway.Server]

	// D157: anzen's reactive skeleton needs the pool and the dispatcher, both
	// built during the listener's validation — after this is registered.
	wiring := &enforcementWiring{}

	// D206: ONE drift store for the process, created HERE because it has two
	// readers on different call paths — the catalog, built inside
	// buildEnforcement, and the readiness handlers below, which close over it.
	// The writer is `driftWatcher`. Created before either so neither has to
	// reach for the other.

	cfgLoader := config.NewLoader(config.NewFileSource(*configFlag), log)
	sp.Register(cfgLoader)

	// The audit sink, registered BEFORE the gateway so it starts first and stops
	// last. Stop order is reverse registration order, which is what guarantees
	// the sink is still open while the gateway drains its final in-flight
	// commands — the opposite order would discard exactly the records written
	// during shutdown, and §5.2.2 calls losing audit records "the one
	// unacceptable failure".
	// THE BUS, registered before the gateway so it starts first and stops last:
	// closing it while a subscription is still streaming would drop envelopes a
	// consumer had already been told it would receive.
	eventBus := bus.New(log, bus.DefaultBuffer)
	sp.Register(eventBus)

	auditPath := auditLogPath(*auditLogFlag, *walFlag)

	// D311: the drift state PERSISTS beside the audit log, and loads at boot —
	// a target diverged when the process stopped is still diverged when it
	// starts, until a fresh comparison says otherwise. A file that cannot be
	// read FAILS THE BOOT (D150's direction): an empty store would forget every
	// finding.
	driftStore, err := drift.OpenStore(auditPath + ".drift")
	if err != nil {
		return err
	}
	// D120. THE GOVERNANCE PATH FANS OUT rather than becoming a second bus.
	//
	// The local JSONL sink is always present — it is the WAL's spill format and
	// the durability boundary — and additional destinations join it. Fan-out and
	// not a bus, because governance destinations are static and configured, and
	// because `internal/bus` DISCARDS on overflow while §5.2.2 calls losing an
	// audit record "the one unacceptable failure" (D118).
	localSink := auditwal.NewJSONLSink(auditPath)
	sp.Register(localSink)

	// **D319: DESTINATIONS ARE SHIPPED, NOT FANNED OUT.** The recorder writes the
	// local WAL alone, synchronously — the durability boundary — and every
	// `-audit-sink` destination is delivered to ASYNCHRONOUSLY by a shipper
	// tailing it, at least once, routed by residency. Under D120 a failing
	// destination refused every command; now it raises `audit_unavailable` and
	// catches up (D147: audit fails closed, but LOCALLY).
	var destinations []audit.Sink
	for _, spec := range splitSinks(*extraSinkFl) {
		extra, serr := parseSink(spec, sp)
		if serr != nil {
			return serr
		}
		destinations = append(destinations, extra)
	}
	var auditSink audit.Sink = localSink
	if len(destinations) > 0 {
		// AN UNROUTABLE CLASS REFUSES THE BOOT (D319): known now, so a record no
		// destination may receive cannot arise at run time.
		served := splitResidency(*residencyFl)
		if len(served) == 0 {
			unconstrained := false
			for _, dst := range destinations {
				unconstrained = unconstrained || dst.Residencies() == nil
			}
			if !unconstrained {
				return fault.New(fault.KindConfig, "main.auditShip", "this deployment serves every residency "+
					"class (-residency is empty) and every -audit-sink is class-restricted, so a record of an "+
					"unlisted class would reach no destination (D319). Add an unrestricted destination, or "+
					"declare -residency")
			}
		} else if unrouted := auditwal.Unrouted(served, destinations...); len(unrouted) > 0 {
			return fault.New(fault.KindConfig, "main.auditShip", fmt.Sprintf("this deployment serves %v and no "+
				"-audit-sink accepts %v, so those records would reach no destination (D319)", served, unrouted))
		}
		shipper, serr := auditwal.NewShipper(auditPath, destinations...)
		if serr != nil {
			return serr
		}
		// THE RECORDER BELOW PERSISTS ITS CHAIN TAIL (D78), so a segment start
		// after a shipped record is a break, not a restart; and a destination
		// stopping or recovering is logged the moment it happens (D324).
		shipper.RequireContinuousChain().WithLogger(log)
		sp.Register(&shipComponent{shipper: shipper, every: 5 * time.Second})
		wiring.auditUnavailable = shipper.Unavailable
		// EACH DESTINATION AND WHAT IT ACCEPTS, so an operator — and the demo —
		// can see where each residency class's records go (D319, D324).
		routes := make([]string, 0, len(destinations))
		for _, dest := range destinations {
			accepts := "every class"
			if r := dest.Residencies(); len(r) > 0 {
				accepts = strings.Join(r, ",")
			}
			routes = append(routes, dest.Name()+" <- "+accepts)
		}
		log.Info("audit records ship asynchronously to destinations, at least once (D319)",
			"destinations", len(destinations), "routes", strings.Join(routes, "; "))
	}

	// D42's BOOT CHECK, as a component. It needs both the validated document and
	// the drivers, and the drivers live in internal/ — which is why this check
	// could not sit inside config.Document.Validate, and why it went unenforced
	// until D88. Registered after config so the document exists when it runs.
	//
	// **THE DEPLOYMENT'S DRIVERS, THE SAME LIST THE GATEWAY BUILDS (D279).** This
	// was `kata` alone, so the boot knew no other connector's types (CONTRACTS
	// 135). No pool: the check reads declarations and never dials.
	sp.Register(schemareg.NewChecker(cfgLoader.Document,
		func(doc *config.Document) map[string]connector.Driver { return builtin.ByKind(doc, nil) }, log))

	// **THE TRACER, REGISTERED BEFORE THE LISTENER SO IT STOPS AFTER IT.**
	// spine stops in reverse registration order, and a provider flushed before
	// the gateway drains would discard the spans for the calls that were still
	// in flight — which are the ones somebody watching a shutdown wants (D207
	// withdraws readiness before the drain for the same reason).
	//
	// The sink LOGS, because a skeleton with no destination records spans nobody
	// can see. At INFO with a count rather than the spans themselves: a span per
	// outbound call is a volume decision, and dumping them all at shutdown is
	// how a useful line gets scrolled past (D77's crying wolf, in the shape D97
	// found for a repeated boot refusal).
	tracer := tracing.New(tracing.WithSink(func(spans []tracing.Span) {
		log.Info("flushed pending spans at shutdown", "spans", len(spans))
	}))
	sp.Register(tracer)

	// THE GOVERNED SURFACE. Its builder runs during validation, once
	// cfgLoader has produced a document — see NewListener on why construction is
	// deferred rather than done here.
	listener := gateway.NewListener(*grpcFlag, gateway.TLSConfig{
		CertFile:     *tlsCertFlag,
		KeyFile:      *tlsKeyFlag,
		ClientCAFile: *tlsCAFlag,
	}, func(ctx context.Context) (*gateway.Server, error) {
		// Captured so the drain below can report in-flight commands and dropped
		// envelopes. atomic.Pointer because the builder runs during spine's
		// validation phase, on a different call path from the drain.
		return buildAndRemember(ctx, &enforcement, enforcementDeps{
			Doc:          cfgLoader.Document(),
			Profile:      profile,
			Residency:    splitResidency(*residencyFl),
			AllowEnv:     *allowEnvFl,
			Demo:         *demoFl,
			Wiring:       wiring,
			Drift:        driftStore,
			ExpectConfig: *expectConfigFl,
			Bounds: config.OperationalBounds{
				MaxLifetime:     *poolLifetimeFl,
				RetryAttempts:   *retryAttemptsFl,
				RetryCap:        *retryCapFl,
				BreakerTrip:     *breakerTripFl,
				BudgetFloorPct:  *budgetFloorFl,
				BreakerCooldown: *breakerCooldownFl,
				MeterCeilings:   meterCeilingFl,
				HandleIdle:      *handleIdleFl,
				// flag.Uint is a uint; the check below refuses what does not fit.
				MeterDefaultCalls: uint32(*meterDefaultFl), //nolint:gosec // bounded at flag parse
			},
			Sink:        auditSink,
			Bus:         eventBus,
			AuditPath:   auditPath,
			FileRoots:   fileRootsFl,
			Mode:        mode,
			MaxInFlight: *inflightFlag,
			Metrics:     met,
			Tracer:      tracer,
			Log:         log,
		})
	}, log)
	// REGISTERED BEFORE THE LISTENER, SO IT STOPS AFTER IT. Reverse
	// registration order is what gives the drain its shape: the listener stops
	// first so no new job is accepted, this drains what is already running, and
	// the audit sink — registered earlier still — is the last thing closed, so
	// a job finishing during the drain can record what it did.
	sp.Register(&jobDrainer{wiring: wiring, log: log})

	sp.Register(listener)

	// THE REFLEX ENGINE, after the listener: starts last, stops FIRST (D261).
	sp.Register(&reflexRunner{wiring: wiring, log: log})

	// THE SCHEDULE, AFTER THE REFLEXES, and the order is the point (D266): it
	// starts only once every rule is listening, and stops before any rule
	// does. The other way round, a tick during start or shutdown publishes to
	// a bus with no rule on it and commits its cursor past rows nobody heard.
	sp.Register(&scheduleRunner{wiring: wiring})

	// REGISTERED AFTER THE LISTENER, so it starts last and stops FIRST. Stop
	// order is reverse registration order, and a watcher that outlived the
	// gateway would keep firing anzen rules into a server that is draining.
	// THE SECOND SIGNAL SOURCE, registered beside the first for the same reason:
	// after the listener, so it starts last and stops FIRST. A watcher that
	// outlived the gateway would keep firing anzen rules into a server that is
	// draining.
	// THE BUDGET REFRESHER, registered beside the signal watchers and for the
	// same ordering reason (D209). It fires no anzen rule; what it shares with
	// them is that it must stop before the gateway does.
	//
	// FIVE MINUTES. A lease is revised on the order of minutes at P7 and never
	// consulted per command, so polling faster buys nothing and would put a
	// coordinator round trip on a timer for no reason. It is also comfortably
	// under three misses' worth of the shortest lease anybody would issue, which
	// is what keeps the decay a response to an OUTAGE rather than to jitter.
	sp.Register(&budgetRefresher{
		wiring: wiring,
		every:  5 * time.Minute,
		log:    log,
	})

	// **THE FOURTH SIGNAL SOURCE (D226), registered beside the other three and
	// after the listener for the same reason: it stops FIRST, so a watcher never
	// fires anzen rules into a draining server.**
	// THE LAST ANZEN SIGNAL WITH NO PRODUCER, GIVEN ONE (D336), beside its
	// siblings and for their reasons.
	sp.Register(&denialStormWatcher{
		wiring: wiring, every: time.Minute, threshold: *stormFlag, log: log,
	})
	sp.Register(&mistenantWatcher{
		wiring: wiring,
		// A minute, matching its siblings. Not load-bearing: the level does not
		// decay, so polling faster finds a mismatch sooner without changing what
		// it means.
		every: time.Minute,
		log:   log,
	})

	// **THE JOB RUNNER'S THREE REPORTS (D280)**, beside the other watchers
	// and after the listener for their reason. A minute, matching its
	// siblings: none of the three levels decays, so polling faster finds a
	// condition sooner without changing what it means.
	sp.Register(&sourceWatcher{
		wiring: wiring,
		every:  time.Minute,
		log:    log,
	})

	// D291. THE HANDLE SWEEPER, after the listener so it stops FIRST: its Stop
	// closes every open handle while the pool can still reach the vendor, so a
	// clean shutdown holds no vendor slot for a caller that will never return.
	sp.Register(&handleSweeper{wiring: wiring, every: 30 * time.Second, log: log})

	sp.Register(&churnWatcher{
		wiring: wiring,
		// A MINUTE, matching its sibling, and the number is not load-bearing for
		// the same reason: the condition is a count over a fifteen-minute window,
		// so polling faster finds it sooner without changing what it means.
		every: time.Minute,
		log:   log,
	})

	// THE THIRD SIGNAL SOURCE (D206), registered beside the other two and after
	// the listener for the same reason: it starts last and stops FIRST, so a
	// watcher never fires anzen rules into a draining server.
	// FIVE MINUTES, and unlike its siblings this number IS a trade-off worth
	// naming: every tick is a `tools/list` round trip per spec-described target,
	// so polling hard turns governance into load on somebody else's server. A
	// vendor's tool list changes on a deploy cadence, not a per-second one, and
	// the cost of being up to five minutes late is that the catalog advertises a
	// tool whose call fails — the honest fail-closed outcome anyway, since the
	// tool is gone and nothing unreviewed can run.
	//
	// THE DEPS ARE A CLOSURE evaluated at Start, because the resolver is built
	// during the listener's validation — after this registration. Same deferred
	// handoff as `gateway.NewListener`'s builder.
	sp.Register(drift.NewWatcher(driftStore, 5*time.Minute, log, func() drift.Deps {
		return drift.Deps{
			Resolver: wiring.resolver,
			Drivers:  wiring.drivers,
			Targets:  wiring.targets,
			Observer: wiring.dispatch,
			// THE GATE (D311): every comparison admitted through the enforcement
			// path's ceilings and recorded. Nil only when no gateway was built,
			// and then the watcher idles before it would need one.
			Gate: driftGateOf(wiring),
		}
	}))

	sp.Register(&staleWatcher{
		wiring: wiring,
		// A MINUTE, and the number is not load-bearing. The condition it watches
		// for is a drain already past its lifetime bound, so it has been wrong
		// for a while by the time this looks — polling faster would find it
		// sooner without changing what it means.
		every: time.Minute,
		log:   log,
	})

	// Validate runs every component's checks to completion before ANY of them
	// start. A malformed config file therefore fails with no listener bound and
	// nothing to unwind — which is what "rejected at boot" means in practice.
	if err := sp.Validate(ctx0()); err != nil {
		return err
	}

	srv := &http.Server{
		Addr: listenAddr(*addrFlag),
		Handler: probeMux(sp, profile, mode, met, driftStore,
			func() map[string]string { return wiring.quarantined }),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Bind before announcing anything, so a port clash fails startup rather
	// than surfacing as an unexplained absence of traffic.
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fault.Wrap(fault.KindConfig, op, "binding probe listener", err)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fault.Wrap(fault.KindInternal, op, "probe server", err)
		}
	}()

	// Starts every registered component in order and logs the ledger. Today
	// that is one component and six planned ones — which is exactly what the
	// WARN output is for.
	if err := sp.Start(ctx0()); err != nil {
		return err
	}

	log.Info("ready",
		"mode", mode.String(),
		"audit", auditMode.String(),
		"addr", srv.Addr,
		"drain_budget", plan.DrainBudget,
	)

	// SIGINT for a laptop, SIGTERM for every platform that stops a container.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	// **READINESS IS WITHDRAWN BEFORE THE DRAIN, NOT AFTER IT.** `spine.Stop`
	// records STOPPING before stopping components, which is correct and happens
	// too late to matter here: the drain below runs first, so without this line
	// the process spends its whole drain window — the longest part of a
	// shutdown — still answering /readyz with "ready", and the load balancer
	// keeps sending work while we wait for work to finish. Stop's own comment
	// promised the opposite ordering; this is what makes it true.
	sp.BeginStopping()

	log.Info("draining", "budget", plan.DrainBudget, "phase", sp.Phase().String())

	// D62: report what is still running. GracefulStop waits for in-flight RPCs
	// and says nothing about them, so this is the only place the number that
	// explains a truncated audit log gets recorded.
	if srvRef := enforcement.Load(); srvRef != nil {
		drainStart := time.Now()
		remaining, byRPC := srvRef.DrainAdmission(ctx0(), func() { time.Sleep(10 * time.Millisecond) })
		if remaining > 0 {
			log.Warn("drain budget reached with commands still in flight; their audit "+
				"outcomes may be missing", "in_flight", remaining, "by_rpc", byRPC,
				"waited", time.Since(drainStart))
		} else {
			log.Info("all in-flight commands completed", "waited", time.Since(drainStart))
		}
		if dropped := srvRef.BusDropped(); dropped > 0 {
			log.Warn("envelopes were dropped for lagging subscribers over this process "+
				"lifetime", "dropped", dropped)
		}
	}

	// plan.DrainBudget, not the flag: Check may have shortened it to fit the
	// platform's grace period, or zeroed it where none is guaranteed.
	drainCtx, cancel := context.WithTimeout(context.Background(), plan.DrainBudget)
	defer cancel()

	// spine.Stop drops readiness FIRST, then stops components in reverse
	// registration order — the load balancer must stop sending work before the
	// process stops accepting it.
	if err := sp.Stop(drainCtx); err != nil {
		log.Warn("components did not stop cleanly", "err", err)
	}
	if err := srv.Shutdown(drainCtx); err != nil {
		log.Warn("drain did not complete within budget", "err", err)
	}
	log.Info("stopped")
	return nil
}

// buildEnforcement assembles the enforcement path from a validated document.
//
// ONE PLACE WHERE THE STACK IS ASSEMBLED, and the order of the fields mirrors
// the order of the checks in Enforce: identity, anzen ceiling, policy, resolver,
// driver, audit. Reading this function should tell you what a command traverses.
//
// The acceptance run builds the same stack by hand. That duplication is
// deliberate rather than accidental — the test must be able to substitute a
// clock and a sink — but it is also why gateway.Config is a struct: adding a
// dependency is a compile error at BOTH sites rather than a silent omission at
// one.
// A struct rather than seven parameters, for the reason gateway.Config gives:
// adding a dependency becomes a compile error at the call site rather than a
// silently-reordered argument.
type enforcementDeps struct {
	Doc       *config.Document
	Bus       pkgbus.Bus
	Profile   runtime.Profile
	Residency []string

	// Mode is the deployment split (§5.3). Carried because the job runner's
	// §12.0 guardrail is keyed on it and on nothing else: "no sources
	// configured" is a refusal for an ingest deployment and the steady state
	// for a gateway (D252).
	Mode runtime.Mode

	// Bounds is how hard anything in this deployment may push an upstream
	// (D142). A target narrows them in config; boot refuses one that does not.
	Bounds config.OperationalBounds

	// Wiring is filled DURING the build, for components registered before it.
	Wiring *enforcementWiring

	// Drift is the per-target spec-drift state the catalog withholds from
	// (D197, D206). Created in run() because readiness reads it too.
	Drift *drift.Store

	// ExpectConfig is the document identity the DEPLOYER says it shipped
	// (D150). Empty means no check.
	ExpectConfig string

	// AllowEnv overrides D97's refusal of env:// off a developer machine.
	AllowEnv  bool
	Demo      bool
	Sink      audit.Sink
	AuditPath string
	// FileRoots are the directories a file:// credential may be read from
	// (D286, -file-credential-root).
	FileRoots   []string
	MaxInFlight int
	Metrics     *metrics.Registry

	// Tracer mints one span per outbound call (§10.4, D235). A skeleton, in
	// process, no vendor SDK — the ledger entry asks for spans carrying the
	// delegation chain, not for an exporter, and the bus landed at P0 the same
	// way (D91).
	Tracer *tracing.Provider

	Log *slog.Logger
}

// buildAndRemember builds the stack and records it for the drain path.
func buildAndRemember(ctx context.Context, slot *atomic.Pointer[gateway.Server], d enforcementDeps) (*gateway.Server, error) {
	srv, err := buildEnforcement(ctx, d)
	if err != nil {
		return nil, err
	}
	slot.Store(srv)
	return srv, nil
}

// auditedReads renders the audited-reads fact for the boot report.
//
// A STRING RATHER THAN THE BOOL, because "reads=false" invites a reader to
// wonder what was false about them. The property is whether the SOURCE records
// who read this credential and when — which a secret manager does and a mounted
// file cannot.
func auditedReads(p config.Posture) string {
	if p.AuditedReads {
		return "audited"
	}
	return "unaudited"
}

func buildEnforcement(ctx context.Context, d enforcementDeps) (*gateway.Server, error) {
	const op = "main.buildEnforcement"

	if d.Doc == nil {
		return nil, fault.New(fault.KindInternal, op,
			"no validated configuration document; config must validate first")
	}
	doc, log := d.Doc, d.Log

	// P0 ships one driver, and it is kata. That is honest rather than
	// embarrassing: P2 adds Fullstory MCP and API, and the shape of this map is
	// what they land into. A real deployment pointing at `kata` targets gets
	// synthetic results, which is why kata.Kind is never a plausible name for
	// something real.
	// THE CLIENT POOL, and the drivers that borrow from it.
	//
	// Wiring order matters for a reason worth stating: a driver constructed
	// WITHOUT a pool still works and is still governed, but its clients are
	// invisible to `revoke_credential` — break-glass would evict an empty pool
	// and truthfully report cancelling nothing (CONTRACTS §4 item 35). The pool
	// is what makes revocation reach anything at all.
	// WITHDRAWALS ARE DURABLE, so a restart does not silently restore every
	// revoked credential (D145). They lived in memory until now, which made
	// D133's stated guarantee — "withdrawn stays withdrawn until explicitly told
	// otherwise, and explicitly means an authorised, audited act by a named
	// principal" — true only within one process lifetime. A restart is none of
	// those four things, and it is the most routine operation there is.
	withdrawnPath := pool.WithdrawnPathFor(d.AuditPath)
	// PER-TARGET LIFETIMES, bounded by the deployment ceiling (D108, D142's
	// shape). Boot has already refused a target that tries to WIDEN it, so this
	// only applies what survived that check.
	lifetimes := map[string]time.Duration{}
	for _, tg := range doc.Targets {
		if tg.Limits != nil && tg.Limits.MaxLifetimeS > 0 {
			lifetimes[tg.Ref] = time.Duration(tg.Limits.MaxLifetimeS) * time.Second
		}
	}

	// **THE REGISTRY IS CONSTRUCTED FIRST AND POPULATED AFTER, which breaks a
	// real wiring cycle (D190).** The pool needs a driver's build; a driver needs
	// the pool so `Execute` can route through `Do`. `registry.Build` is a method
	// value that reads the registry at CALL time — and the pool only builds a
	// client when a command arrives, long after wiring — so the pool can be
	// constructed before any driver exists.
	registry := connector.NewRegistry()
	clientPool := pool.New(registry.Build, d.Log,
		pool.WithStore(pool.NewFileStore(withdrawnPath)),
		pool.WithMaxLifetime(d.Bounds.MaxLifetime, lifetimes))

	// REHYDRATED BEFORE ANYTHING CAN SERVE, and a failure here fails the boot.
	// An empty withdrawal set is not the safe default: it is the attack D133
	// refused, arriving through a file that could not be read rather than
	// through a config edit.
	restored, rerr := clientPool.Rehydrate(ctx)
	if rerr != nil {
		return nil, rerr
	}
	if restored > 0 {
		log.Warn("withdrawals restored from the durable store; these targets were "+
			"withdrawn before this process started",
			"count", restored, "store", withdrawnPath,
			"lift_with", verb.RestoreTarget)
	}
	// **REGISTERED RATHER THAN KEYED BY HAND (D190).** The old form,
	// `map[string]connector.Driver{kata.Kind: kata.New(...)}`, let the key and the
	// driver's own `Kind()` disagree — a typo or a copied line — and the symptom
	// is a target resolving to the wrong driver entirely. `Register` reads the
	// kind off the driver, so the two cannot differ, and it refuses a duplicate.
	//
	// P2 ADDS THE SECOND DRIVER, which is what forced all of this. The Fullstory
	// driver is credential-free (§4.7.4 class 1) and therefore does NOT implement
	// `connector.ClientBuilder`; the registry gives it a marker pool entry so
	// break-glass still reaches its in-flight calls.
	//
	// **AND THE THIRD ARRIVES WITH D213, WHICH IS THE LINE THAT MAKES THE MCP
	// DRIVER REACHABLE AT ALL.** Until now no non-test file imported
	// `internal/driver/mcp`: its `Execute`, `Query`, `Kind` and `Actions` all
	// LOOKED reached because they satisfy `connector.Driver` and the gateway
	// calls that interface, and `mcp.New` having no caller was the only symbol
	// whose silence said the driver was inert (D205). Registering it here is
	// what retires that registration.
	//
	// **IT TAKES THE VETTED SPECS FROM THE DOCUMENT**, because the spec IS the
	// action set (D46) — a driver constructed without them loads cleanly and can
	// do nothing — and the pool, because a stateful revision keeps its session
	// there (§4.7.4 class 3, D213).
	//
	// **AND THE FOURTH IS THE THIN JIRA DRIVER (P2 step 27).** It is here for the
	// same reason the MCP line is: a driver no non-test file imports LOOKS
	// reached, because its methods satisfy `connector.Driver` and the gateway
	// calls that interface. Registering it is what makes it exist. It is class 1
	// like the others, so it takes the pool and no builder.
	//
	// **ONE LIST SINCE D279**, in `internal/builtin`: the tap builds the
	// same set, because the connectors own their schemas and a registry
	// without them knows none of their types.
	for _, dr := range builtin.Drivers(doc, clientPool) {
		if err := registry.Register(dr); err != nil {
			return nil, err
		}
	}
	drivers := registry.Drivers()
	log.Info("driver kinds registered", "kinds", registry.Kinds())
	logReferences(log, drivers)
	// A PRESET THAT FELL BEHIND ITS CONNECTOR'S SUGGESTION IS A FINDING, NOT A
	// GRANT CHANGE (D327): grants expand from the deployment's copy, so a
	// connector release that added an action widened nothing. Said at boot, so
	// taking the change is a decision somebody makes in a reviewed commit.
	// THE ANZEN VOCABULARY'S UNKEPT PROMISES, SAID ONCE (D331): actions boot
	// validates and no firing path implements. An enforcing rule doing one is
	// refused above; an operator writing one in shadow learns it here.
	log.Info("anzen actions this build validates but does not implement yet — enforcing rules may not use them",
		"actions", strings.Join(config.UnbuiltAnzenActions(), ","))
	for _, f := range grantcheck.PresetFindings(doc.Presets, drivers) {
		log.Info("preset differs from its connector's suggestion", "finding", f)
	}

	// **ONE PAYLOAD REGISTRY, BUILT ONCE (D279)**: the connectors' own schemas
	// and the document's, ownership checked. The server shapes Query results
	// with it, the runner polled events, the engine enrichments — three
	// callers, one answer to "what may enter". A connector that declares a type
	// and ships no schema fails the boot here, naming the connector.
	schemas, err := schemareg.ForDeployment(doc, drivers)
	if err != nil {
		return nil, err
	}
	// **A CONNECTOR WITH UNSOUND SCHEMAS IS QUARANTINED, NOT THE BOOT (D282).**
	// Its targets are refused; everything else serves. Logged here at ERROR,
	// on /readyz, and as a signal — loud everywhere an operator looks.
	quarantined := schemas.Quarantined()

	// **THE IMPOSED REFINES RULES, COMPILED ONCE (D317)** — by the function the
	// schema check reports on, so the rules the gateway runs are the rules boot
	// checked. A problem here is the schema check's refusal arriving early.
	refinements, refineProblems, _ := schemareg.Refinements(schemas, doc, drivers)
	if len(refineProblems) > 0 {
		return nil, fault.New(fault.KindConfig, "main.refinements", fmt.Sprintf(
			"%d refinement problem(s):\n  - %s", len(refineProblems), strings.Join(refineProblems, "\n  - ")))
	}
	// Since D284 this verdict includes the METER: a connector whose calls
	// cannot be priced is quarantined by ForDeployment, types and all.

	// P3 STEP 24. A TARGET WHOSE HOST ITS CONNECTOR DOES NOT SERVE REFUSES THE
	// BOOT: its credential would be sent there on every call (CONTRACTS 117).
	// Asked of every driver that knows its vendor's hosts; the driver asks
	// again on each call.
	var badHosts []string
	for _, t := range doc.Targets {
		if hb, ok := drivers[t.Kind].(connector.HostBound); ok {
			if err := hb.AdmitBaseURL(t.Ref, t.BaseURL); err != nil {
				badHosts = append(badHosts, err.Error())
			}
		}
	}
	if len(badHosts) > 0 {
		sort.Strings(badHosts)
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%d target(s) name a host their connector does not serve:\n  - %s",
			len(badHosts), strings.Join(badHosts, "\n  - ")))
	}
	for kind, why := range quarantined {
		log.Error("connector QUARANTINED at boot: its targets are refused until a fixed connector ships",
			"connector", kind, "why", why)
	}
	if d.Wiring != nil {
		d.Wiring.quarantined = quarantined
		// D289: the MCP driver's run-time conformance tally, found by the
		// method it offers rather than by its type.
		if nc, ok := drivers["mcp"].(interface{ Nonconforming() map[string]string }); ok {
			d.Wiring.toolNonconforming = nc.Nonconforming
		}
	}

	// THE GRANT ENGINE IS TOLD THE DEPLOYMENT'S RESIDENCY CEILING (D136), because
	// the second layer of the residency control lives in grants and the rule it
	// applies depends on the ceiling: a single-class instance has no crossing to
	// authorise, a multi-class one has nothing but crossings.
	//
	// AND THE DRIVERS' SURFACES, so an MCP tool declared `[opaque]` is held to
	// the whole surface of the native targets it is linked to (D323).
	eng := policy.NewGrantEngine(doc, d.Residency, policy.WithSurfaces(actionset.Surfaces(drivers)))

	// AN UNCLASSIFIED TARGET ESCAPES BOTH LAYERS, so a multi-residency
	// deployment refuses to boot with one. Empty on a single-class or
	// unconstrained instance, which cannot have the hole.
	if orphans := eng.UnclassifiedTargets(); len(orphans) > 0 {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"this deployment serves %v, and %d target(s) declare no residency: %v. "+
				"An undeclared target is permitted by the ceiling and unconstrained by "+
				"every grant, so it is an unpoliced route into any of the served classes "+
				"— declare a residency on each, or narrow -residency to a single class",
			d.Residency, len(orphans), orphans))
	}

	// WHAT THE GRANT LAYER JUST SWITCHED OFF, said out loud. Declaring a second
	// residency class changes the effective permission of grants across the file;
	// an operator who is not told will read the denials as a bug.
	//
	// GROUPED BY CLASS, ONE LINE EACH, and the grouping is the point rather than
	// tidiness. The first version logged one WARN per capability: on the
	// acceptance config that is twenty-two lines, twenty-one of them about
	// eu targets in a deployment that already served eu, and exactly one about
	// the us target that is the actual new crossing. A list where the signal is
	// one line in twenty-two is a list an operator learns to skip — which is the
	// same "a control that is too strict gets disabled" failure this whole
	// decision exists to avoid, reproduced inside its own mitigation.
	//
	// Class is the right axis because it is what CHANGED. An operator widening
	// `eu` to `eu,us` reads the `us` line and knows immediately that it is the
	// new one; the `eu` line is the migration backlog, and it can be worked
	// through without an incident.
	for _, g := range groupByResidency(eng.UncoveredCrossings()) {
		log.Warn("capabilities do not name the residency they reach, and will be denied",
			"target_residency", g.residency, "capabilities", g.count,
			"principals", strings.Join(g.principals, ","),
			"fix", "add `where: {target_residency: ["+g.residency+"]}` to each")
	}

	// THE BREAKER AND THE LIMITER ARE BUILT HERE AND SHARED, so their state is
	// per-INSTANCE rather than per-request (§4.3.4). A breaker constructed per
	// call would count to one and never trip, and a limiter constructed per call
	// would hand out a full bucket every time — the shape of a control that
	// exists and does nothing, with nothing about the call site looking wrong.
	//
	// THE PER-TARGET LIMITS COME FROM CONFIG, NOT FROM FLAGS (D142). These are
	// the knobs an operator reaches for during an incident; a flag means a
	// redeploy to lengthen a backoff, which is the same objection §4.7.10 raises
	// about break-glass. The flags remain as DEPLOYMENT CEILINGS a target may
	// only narrow, which is D108's shape and D71's asymmetry: how hard anything
	// here may retry is written once by whoever owns the blast radius.
	// REFUSED AT BOOT, NOT SILENTLY CLAMPED (D108, D142). A target quietly given
	// less than it asked for is a target whose operator believes something false,
	// and the belief survives until an incident tests it. Every offending target
	// is named in one error rather than the first one found, because an operator
	// fixing them one redeploy at a time is the failure this style of message
	// exists to prevent.
	if bad := config.ExceedingTargets(doc, d.Bounds); len(bad) > 0 {
		refs := make([]string, 0, len(bad))
		for ref := range bad {
			refs = append(refs, ref)
		}
		sort.Strings(refs)

		var b strings.Builder
		fmt.Fprintf(&b, "%d target(s) declare operational limits this deployment does not permit:", len(refs))
		for _, ref := range refs {
			for _, why := range bad[ref] {
				fmt.Fprintf(&b, "\n  %s: %s", ref, why)
			}
		}
		b.WriteString("\n\nA target may only be LESS aggressive than the deployment allows. " +
			"Lower the target's value, or raise the deployment's flag if the blast radius is acceptable.")
		return nil, fault.New(fault.KindConfig, op, b.String())
	}

	retryPolicies := map[string]retry.Policy{}
	breakerBounds := map[string]limiter.Bounds{}
	for _, tg := range doc.Targets {
		l := tg.Limits
		if l == nil {
			continue
		}
		if l.RetryAttempts > 0 || l.RetryCapMs > 0 {
			// Each field falls back INDEPENDENTLY to the deployment value. A
			// target narrowing only its cap must not silently inherit Go's zero
			// for attempts and stop retrying altogether.
			p := retry.Policy{
				MaxAttempts: d.Bounds.RetryAttempts,
				Base:        retry.DefaultPolicy().Base,
				Cap:         d.Bounds.RetryCap,
				Budget:      retry.DefaultPolicy().Budget,
			}
			if l.RetryAttempts > 0 {
				p.MaxAttempts = int(l.RetryAttempts)
			}
			if l.RetryCapMs > 0 {
				p.Cap = time.Duration(l.RetryCapMs) * time.Millisecond
			}
			retryPolicies[tg.Ref] = p
		}
		if l.BreakerTrip > 0 || l.BreakerCooldownS > 0 {
			breakerBounds[tg.Ref] = limiter.Bounds{
				Trip:     int(l.BreakerTrip),
				Cooldown: time.Duration(l.BreakerCooldownS) * time.Second,
			}
		}
	}

	breaker := limiter.NewBreaker(d.Bounds.BreakerTrip, d.Bounds.BreakerCooldown,
		limiter.WithTargetBounds(breakerBounds))

	// THE RE-ESTABLISHMENT TALLY (D204). Written by the enforcement path, read by
	// `churnWatcher`, which publishes `credential_churn` as a level.
	churnCounter := churn.New()
	mistenantTally := mistenant.New()
	denialTally := denial.New()

	// THE DEPLOYMENT'S OWN POLICY, WHICH NOTHING SUPPLIED BEFORE THIS. gateway
	// defaults Retry to retry.DefaultPolicy() when the field is nil, and main
	// never set it — so the retry policy was a constant in the binary and the
	// two flags bounding it did not exist. That is the gap D142 names: a control
	// an operator can only use by shipping is not one they can use in an
	// incident.
	deploymentRetry := retry.DefaultPolicy()
	deploymentRetry.MaxAttempts = d.Bounds.RetryAttempts
	deploymentRetry.Cap = d.Bounds.RetryCap

	// D171'S THREE LAYERS, COMPOSED ONCE (D284): the connector's meter and
	// default, the target's budget, the deployment's ceiling. Every target is
	// metered now — an absent rate_per_hr means the connector's default or the
	// universal one, never unlimited. One function, shared with the acceptance
	// harness, so the suite cannot prove a different table from the one served.
	plan, err := meter.Build(doc, drivers, quarantined, meter.Bounds{
		Ceilings: d.Bounds.MeterCeilings, DefaultCalls: d.Bounds.MeterDefaultCalls,
	})
	if err != nil {
		return nil, err
	}
	for _, note := range plan.Notes {
		log.Info("metered by default", "detail", note)
	}
	rates := plan.Rates

	// **THE ALLOCATION PATH RUNS AT ONE INSTANCE, WHICH IS THE POINT (D209).**
	// A local allocator hands each budget its whole configured capacity, so
	// behaviour is unchanged — and the code that applies a lease, clamps it to
	// the configured ceiling and decays it on lost contact is the code P7 will use,
	// executed from the first deployment rather than first executed in
	// production.
	allocator := limiter.NewLocalAllocator(rates)
	rateLimiter := limiter.NewLocal(rates,
		limiter.WithAllocator(allocator, instanceIdentity()),
		limiter.WithFloorPercent(d.Bounds.BudgetFloorPct))

	// **AND BOOT SAYS WHAT THE LOCAL ALLOCATOR CANNOT DO (CONTRACTS 41's
	// treatment).** Two replicas with this allocator each believe they hold the
	// entire budget, so the fleet spends twice what was configured. That is what
	// a local allocator MEANS rather than a defect, and the honest handling is
	// the one break-glass already uses: say it at boot, so an operator chooses
	// the limitation instead of discovering it as 429s.
	if allocator.Peers() == 0 && len(rates) > 0 {
		log.Warn("rate budgets are allocated LOCALLY; this instance cannot see peers",
			"budgets", len(rates),
			"note", "each replica believes it holds the whole budget, so N replicas "+
				"spend N times the configured rate. Correct at ONE replica (CONTRACTS 41)")
	}

	// THE RUNTIME REVOCATION SET, shared with the enforcement path so the lever
	// and the check read the same state (D146). Built here rather than inside
	// the Server for the same reason the pool is: one instance, not one per
	// request, or the lever would suspend somebody for the length of one command.
	revocations := policy.NewRevocations()

	guards := anzen.New(doc.Anzen)

	// A GUARD SCOPED TO A CLASS THIS INSTANCE DOES NOT SERVE governs nothing here
	// (D137). Document.Validate catches a class no target declares; this catches
	// the real-but-unserved one, which only the deployment knows. Refused rather
	// than warned: the file says a safety control exists, so nobody investigates
	// why it never fired.
	if unserved := guards.UnservedScopes(d.Residency); len(unserved) > 0 {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"this deployment serves %v, and %d anzen guard(s) are scoped to classes it "+
				"does not: %v. A defensive rule that matches nothing is worse than an "+
				"absent one — widen -residency, or move these rules to the deployment "+
				"that serves those classes",
			d.Residency, len(unserved), unserved))
	}

	lenses := shin.New(doc.Shin)

	// Computed ONCE here rather than per decision (D149). Identity marshals and
	// hashes the whole document, and every audit row carries the same answer for
	// the lifetime of the process — there is nothing to recompute, and doing it
	// on the command path would be a hash per command for a constant.
	//
	// A failure here fails the BOOT. The alternative is serving with an empty
	// identity on every row, which is §4.9a.2's promise quietly unkept, and
	// unkept in the direction where the log looks complete.
	configIdentity, err := doc.Identity()
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "computing config identity", err)
	}
	// ONE PROVIDER SET, used to build the cache AND to decide which schemes boot
	// will accept. Listed twice they drift, and the drift is silent: a config
	// naming a scheme the binary lost would pass a stale check and fail on its
	// first command.
	ambientProvider := ambient.New()
	credentialProviders := []config.Provider{
		config.EnvProvider{},
		oauth.New(),
		ambientProvider,
		// D151: built before gcp-sm:// because everything Helm and SOPS produce
		// terminates here (D103), and it needs a directory rather than a cloud
		// account. The build order is not §4.7.8's recommendation order.
		//
		// **CONFINED (D286).** A file credential is read and sent off-host as
		// the Authorization header of every call, so it may come only from a
		// declared root, never from the audit directory — which holds the log,
		// the chain tail, the withdrawal and credential-version marks and the
		// cursors — and never from /proc or /sys. With no root declared, only a
		// bare developer machine may read one at all.
		filecred.New(filecred.InKubernetes(d.Profile.Service == "kubernetes"),
			filecred.Roots(d.FileRoots...),
			filecred.Deny(filepath.Dir(d.AuditPath)),
			filecred.AllowUnrooted(d.Profile.Execution == runtime.ExecutionBare)),
	}

	// D315. A DEMONSTRATION DEPLOYMENT BOOTS ONLY WHEN ASKED FOR BY FLAG — one
	// reviewable act in the manifest, like -allow-env-credentials. The demo
	// carries `agent:showcase` with a wildcard grant; bare metal allows env://,
	// so without this the demo would be one misplaced directory from serving.
	if doc.Demo && !d.Demo {
		return nil, fault.New(fault.KindConfig, op,
			"this configuration is a DEMONSTRATION deployment (`demo: true`) — it grants a showcase "+
				"principal a wildcard and must never serve production. Refusing to boot it without "+
				"-demo, which `make run` passes and no production manifest should (D315)")
	}

	// D97, D98, D102. THE REFUSALS THAT NEED MORE THAN THE DOCUMENT — the runtime
	// profile, the override flag, and which providers this binary actually has.
	// Document.Validate can see none of the three (D136's split), and a check that
	// silently skipped when it could not see them would be worse than one that
	// lives out here and is called on purpose.
	if refused := credential.RefuseAtBoot(doc, d.Profile, d.AllowEnv,
		credentialProviders); len(refused) > 0 {

		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%d target(s) declare a credential this deployment refuses:%s",
			len(refused), credential.Render(refused)))
	}

	// D286. EVERY REFERENCE, CHAINS INCLUDED, THAT ITS PROVIDER WILL NOT READ AT
	// ALL — refused here so a bad one fails the deploy rather than the first
	// poll; the provider confines again on every read.
	if refused := credential.RefuseUnconfined(doc, credentialProviders); len(refused) > 0 {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%d credential reference(s) name a file this deployment may not read:\n  - %s",
			len(refused), strings.Join(refused, "\n  - ")))
	}

	// §4.7.7 TIERS 1.5, 2 AND 3, AFTER the free checks above and only for what
	// they left. Tier 1 — the cross-cloud claim and the typo — is settled without
	// a packet, and a configuration error must not need a network call to be
	// caught.
	confirmed, refusedAmbient := credential.ConfirmAmbient(ctx, doc, d.Profile, ambientProvider)
	if len(refusedAmbient) > 0 {
		return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%d target(s) declare ambient identity this deployment cannot confirm:%s\n"+
				"Refusing rather than warning: a target whose ambient identity does not "+
				"work fails EVERY call, so starting and failing every request is strictly "+
				"worse than refusing to start with the target named (§4.7.7).",
			len(refusedAmbient), credential.Render(refusedAmbient)))
	}
	for _, c := range confirmed {
		// TIER 3 IS AN ACCEPTED OUTCOME AND STILL HAS TO BE SAID OUT LOUD. The
		// operator is being told the deployment will fail at first use if the
		// declaration is wrong, which is the whole content of "unverified".
		if c.Confidence == ambient.Unverified {
			log.Warn("ambient identity accepted UNVERIFIED",
				"target", c.TargetRef, "cloud", c.Cloud,
				"why", "this platform forbids work at construction time, so the claim "+
					"could not be probed; it will fail at first use if it is wrong")
			continue
		}
		log.Info("ambient identity confirmed",
			"target", c.TargetRef, "cloud", c.Cloud, "how", c.Confidence)
	}

	// D152. THE MONOTONIC GUARD, built before the provider it defends.
	//
	// `gcp-sm://` is deprioritised (D151) and this does not wait for it: the
	// guard is provider-agnostic because D130 already has every provider report
	// the version it ACTUALLY resolved to, and the property is worth having in
	// place before the first tracking reference exists rather than after.
	//
	// FAILING TO LOAD FAILS THE BOOT. Starting with no marks silently permits
	// every downgrade they exist to refuse, which is withdrawal.Store's rule for
	// the same reason.
	credCache := credential.New(credentialProviders,
		credential.WithMetrics(d.Metrics),
		credential.WithLogger(log),
		credential.WithVersionMarks(credential.NewMarkFileStore(
			credential.MarkPathFor(d.AuditPath))))

	marks, err := credCache.RehydrateMarks(ctx)
	if err != nil {
		return nil, err
	}
	if marks > 0 {
		log.Info("credential version marks loaded; a tracking reference cannot resolve backwards",
			"refs", marks)
	}

	// **D186. A VOCABULARY MEMBER THIS BUILD CANNOT HONOUR IS DISCLOSED AT BOOT.**
	//
	// D163 builds the idempotency vocabulary WHOLE even where a member is not
	// fleshed out, so the connector blueprint can show an author the full shape.
	// The hazard that creates is a class sitting declared and inert — this
	// codebase's recurring defect wearing a taxonomy — and the load refusal
	// (ValidateActions) closes it for the connector AUTHOR, at the moment they
	// pick a class.
	//
	// It does nothing for the OPERATOR, who otherwise has no way to know the
	// vocabulary their configuration is validated against is not fully honoured.
	// One line, at boot, in the same place credential posture is reported and for
	// the same reason: a property that fails silently is not accounted for by a
	// paragraph in a design document.
	//
	// **NOT AN INIT-LEDGER ENTRY, and that is a deliberate amendment to what P2
	// step 30 declared** — see the step's own record. A ledger entry must name the
	// PHASE that retires it, `conditional` has no phase because no connector needs
	// it, and an entry claiming one would use the exact hole
	// TestLedgerEntriesInLivePhasesNameTheirSteps documents. It would also make
	// /readyz report DEGRADED for a taxonomy member, which is D77's crying-wolf
	// failure aimed at the readiness signal.
	//
	// WARNS RATHER THAN REFUSES: the build is fully able to serve, and every class
	// it cannot honour refuses at load rather than at runtime.
	if unimplemented := connector.UnimplementedClasses(); len(unimplemented) > 0 {
		for _, class := range unimplemented {
			log.Warn("idempotency class DECLARED and NOT implemented in this build",
				"class", class, "is", class.Explain(),
				"effect", "an action or vetted spec selecting it is REFUSED at load, "+
					"never silently downgraded (D53, D163)")
		}
	}

	// D104. POSTURE IS REPORTED, NOT DOCUMENTED — one line per credential.
	//
	// Two properties of §4.7.8 fail silently and a paragraph in a design document
	// accounts for neither: a `subPath` mount never updates, so rotation appears
	// configured and never happens; and SOPS is widely believed to protect the
	// runtime when it protects version control. The `material` column answers the
	// second without anybody needing to know it in advance.
	//
	// WARNS RATHER THAN REFUSES, unlike D97's env:// rule. A static credential is a
	// legitimate configuration; what is illegitimate is believing it rotates.
	for _, tp := range credential.PostureOf(doc, credentialProviders) {
		attrs := []any{
			"target", tp.TargetRef,
			"credential", tp.Ref,
			"rotation", string(tp.Posture.Rotation),
			// `at_rest`, not `material` — D119's ruling, and §4.7.9's example
			// output predates it. A field name is the only documentation most
			// readers get, and `material=` reads as though the material might
			// be in the log line.
			"at_rest", tp.Posture.AtRest,
			"reads", auditedReads(tp.Posture),
		}
		switch {
		case tp.Err != nil:
			log.Warn("credential posture could not be determined",
				append(attrs, "err", tp.Err)...)
		case tp.Warns():
			log.Warn("credential posture: THIS CREDENTIAL DOES NOT ROTATE",
				append(attrs, "why", tp.Posture.Why)...)
		default:
			log.Info("credential posture", append(attrs, "why", tp.Posture.Why)...)
		}
	}

	// D150. THE AUTHORITY IS THE DEPLOYER, NOT A QUORUM OF PEERS.
	//
	// D148's first form had a replica compare its identity against what its PEERS
	// reported and withdraw itself on divergence. That leaves the evidence
	// attacker-controlled while moving only the authority inside: forge a peer
	// majority and every honest replica removes itself, which is the fleet-wide
	// outage refusing peer enforcement was supposed to prevent. The pipeline that
	// deployed this configuration knows what it shipped, and an attacker who can
	// set this flag already owns the deployment.
	//
	// BOOT, NOT RUNTIME, and that is the blast radius. A refusal here is a deploy
	// that fails — visible, contained, and leaving the replicas already running
	// untouched, which is §4.9a.2's rule that a rejected configuration leaves the
	// previous one in force. The same signal acted on at runtime is the outage.
	//
	// EMPTY DISABLES IT. The default direction must be the one that cannot cause
	// an outage.
	if err := config.CheckExpectedIdentity(d.ExpectConfig, configIdentity); err != nil {
		return nil, err
	}
	if d.ExpectConfig != "" {
		log.Info("configuration identity matches the deployment's expectation",
			"identity", configIdentity)
	}

	// The chain tail sits beside the audit log, so a restart continues the hash
	// chain rather than starting a new segment (D78).
	recorder := auditwal.NewRecorder(d.Sink, configIdentity,
		auditwal.WithTailStore(auditwal.NewFileTailStore(auditwal.TailPathFor(d.AuditPath))))

	// D157. THE REACTIVE SKELETON, WIRED THROUGH THE GOVERNED PATH.
	//
	// The dispatcher NAMES A RULE and hands it to Enforce, exactly as a human
	// does with `sekizui.fire_anzen` — it does not revoke anything itself. D18 is
	// the reason ("no second code path, no hole in the audit log") and D155 is
	// the reminder that a second path is not hypothetical here.
	//
	// So automatic firing must be GRANTED to `anzen:dispatcher`, per rule. An
	// operator who has not written "may fire credential-compromise" gets no
	// automatic action, which is the right default for a mechanism that revokes
	// credentials with nobody in the loop.
	// ONE Resolver, shared by the enforcement path and the drift watcher (D206).
	// Hoisted for the same reason as the Verifier below: a second Resolver would
	// be a second credential cache and a second residency view, and the watcher
	// asking a different question of a different instance is how the catalog and
	// the enforcer come to disagree about a target.
	targetResolution := resolver.NewWithCache(doc, d.Profile, d.Residency, credCache)

	// ONE Verifier for the process, shared by the enforcement path and the
	// catalog. Both answer "may this caller act for that principal" and they
	// must answer it identically: the catalog used to carry its own copy of the
	// predicate, and the copy differed (see internal/catalog's `identity`
	// field). Hoisted out of the struct literal so the sharing is visible here
	// rather than implied by two constructors reading the same Document.
	//
	// ISSUER KEYS THROUGH THE SAME file:// PROVIDER EVERY CREDENTIAL USES (D286,
	// D318): its roots and its denial of the audit directory confine a JWKS as
	// they confine a secret, and it is read on each verification, so a rotated
	// key file is seen at once and nothing is fetched over a network.
	verifier := identity.NewVerifier(doc, identity.WithKeySource(func(ctx context.Context, ref string) ([]byte, error) {
		for _, p := range credentialProviders {
			if p.Scheme() == "file" {
				res, err := p.Resolve(ctx, ref)
				return res.Material, err
			}
		}
		return nil, fault.New(fault.KindConfig, "main.issuerKeys", "no file:// provider is built, so no issuer's keys can be read")
	}))

	// THE PROJECTOR (D269): the half of the reflex engine allowed on the
	// synchronous path. An ineligible rule refuses the boot here — the defence
	// behind validation's refusal of a projection that declares an action.
	projector, err := reflex.NewProjector(doc.Reflexes)
	if err != nil {
		return nil, err
	}

	srv := gateway.New(gateway.Config{
		HandleIdle:  d.Bounds.HandleIdle,
		Projector:   projector,
		Payloads:    schemas,
		Refinements: refinements,
		Quarantined: quarantined,
		Verifier:    verifier,
		Guards:      guards,
		Policy:      eng,
		// THE CACHE IS BUILT HERE, not inside the resolver, so its counters reach
		// the same registry the enforcement path writes to (§4.7.6). Resolution
		// frequency is the number that says whether the per-command provider call
		// is actually gone in a running deployment.
		//
		// EVERY PROVIDER THE DEPLOYMENT CAN USE IS REGISTERED HERE. A scheme
		// that exists in pkg/ and is not in this slice is a scheme no
		// deployment can reach — declared and inert, which is this codebase's
		// most persistent defect. `oauth-cc://` chains onto whichever of the
		// others holds its client secret (D47, D131).
		Resolver: targetResolution,
		Drivers:  drivers,
		Catalog: catalog.New(catalog.Config{Doc: doc, Drivers: drivers, Policy: eng, Refinements: refinements,
			Guards: guards, Lenses: lenses, Identity: verifier, Drift: d.Drift}),
		Lenses:      lenses,
		Bus:         d.Bus,
		Doc:         doc,
		Pool:        clientPool,
		Breaker:     breaker,
		Retry:       retry.New(deploymentRetry, retry.WithTargetPolicies(retryPolicies)),
		Rate:        rateLimiter,
		Churn:       churnCounter,
		Mistenant:   mistenantTally,
		Denials:     denialTally,
		Revocations: revocations,
		Recorder:    recorder,
		Admission:   gateway.NewAdmission(d.MaxInFlight),
		Metrics:     d.Metrics,
		Tracer:      d.Tracer,
		Log:         log,
	})

	// **THE JOB RUNNER, AND THE TWO-STEP IS A REAL CYCLE RATHER THAN CEREMONY.**
	// The runner admits every poll through this server's shared ceiling
	// sequence (D18, D155) and this server dispatches `StartJob` to the runner,
	// so neither can be constructed first. `srv.JobGate()` is safe to take now
	// because the adapter only holds the pointer; `AttachJobRunner` closes the
	// other edge and refuses a second call.
	//
	// This comment used to say "no configured recurrences yet": true until
	// D266, and exactly the kind of sentence that keeps applying after it
	// stops being true. `-mode=ingest` is still refused when it has nothing to
	// poll (D252), so an empty slice cannot pass for a working poller.
	//
	// **UNDER `-mode=ingest` THE DOCUMENT'S `sources:` ARE THE RECURRENCES
	// (D266).** A gateway serving the SAME document schedules none of them:
	// gateways scale 0..N, and N replicas each polling would read every row N
	// times, while cursors are ingest's state (§5.2). Logged rather than
	// refused, because one document serving both deployments is the normal
	// shape — refusing would force two documents, and two documents drift.
	var configuredJobs []kyuushin.Job
	switch {
	case d.Mode == runtime.ModeIngest:
		jobs, err := srv.ScheduledJobs(ctx, doc.Sources)
		if err != nil {
			return nil, err
		}
		configuredJobs = jobs
	case len(doc.Sources) > 0:
		log.Info("sources are declared and this gateway schedules none of them; "+
			"-mode=ingest runs them (D266)", "sources", len(doc.Sources))
	}
	if err := refuseIngestWithNothingToPoll(d.Mode, configuredJobs); err != nil {
		return nil, err
	}
	runner, err := buildJobRunner(doc, schemas, configuredJobs, d.Bus, srv.JobGate(), d.AuditPath, log)
	if err != nil {
		return nil, err
	}
	if err := srv.AttachJobRunner(runner); err != nil {
		return nil, err
	}

	if d.Wiring != nil {
		d.Wiring.jobs = runner
		d.Wiring.pool = clientPool
		d.Wiring.gateway = srv
		d.Wiring.lifetime = d.Bounds.MaxLifetime
		// THE SAME COUNTER THE GATEWAY WRITES. Shared rather than two instances:
		// a watcher reading a tally nothing writes is the declared-and-inert
		// shape this codebase keeps finding, and it would report a healthy fleet
		// while an amplification ran.
		d.Wiring.churn = churnCounter
		d.Wiring.mistenant = mistenantTally
		d.Wiring.denials = denialTally

		// D206: what `driftWatcher` needs. The resolver is the ONLY way to build
		// a `connector.Target` (§6 mechanism 1), so the watcher borrows the
		// enforcement path's rather than being given a second route.
		d.Wiring.resolver = targetResolution
		d.Wiring.drivers = drivers
		d.Wiring.targets = doc.Targets

		// D209: the limiter `budgetRefresher` re-reads allocations into. The SAME
		// one the gateway enforces through, for `churn`'s reason two fields up —
		// refreshing budgets nothing enforces would report a fleet dividing its
		// quota while every replica spent the whole thing.
		d.Wiring.rate = rateLimiter
		// THE FIRER IS THE GATEWAY'S (D332), so this and the acceptance harness
		// fire rules through one function rather than two copies of it.
		d.Wiring.dispatch = anzen.NewDispatcher(guards, srv.AnzenFirer(), log)

		// D261: the engine consumes as each rule's principal, through the
		// server's one scoped path, and dispatches through its Enforce. D264:
		// it records a firing refused by its budget through the SAME recorder,
		// and raises `budget_exceeded` into the SAME anzen dispatcher the
		// watchers feed — so it is wired AFTER the dispatcher exists.
		d.Wiring.reflexes = buildReflexRun(doc, schemas, srv, recorder, d.Wiring.dispatch, d.Bus, log)
	}

	// **THE ENFORCEMENT PATH VALIDATES ITSELF BEFORE IT CAN SERVE (D190).** A
	// target naming a driver kind nobody implements was already refused, at CALL
	// time, by the driver lookup in `Enforce` — correct and late. D50 puts an
	// offline check in the blocking half, because a configuration that cannot
	// mean anything is one somebody believes is in force.
	//
	// CALLED HERE RATHER THAN INSIDE `gateway.New`, which returns no error: a
	// constructor that cannot refuse would have to panic or log, and neither is a
	// boot refusal an operator can read.
	if err := srv.Validate(); err != nil {
		return nil, err
	}
	return srv, nil
}

// splitResidency parses the -residency flag.
//
// EMPTY MEANS UNCONSTRAINED, matching §7.1 residency item 2 — not "permit
// nothing", which would refuse every target and look like a bug. An operator
// who wants a hard boundary states it; an operator who has not thought about it
// yet is not silently locked out.
// residencyGroup is the boot report for one class: how many capabilities do not
// name it, and which principals hold them.
type residencyGroup struct {
	residency  string
	count      int
	principals []string
}

// groupByResidency collapses the per-capability list into one row per class.
//
// PRINCIPALS ARE DEDUPLICATED AND SORTED, because the useful question is "whose
// grants do I have to edit", not "how many lines can this print". A principal
// with nine uncovered capabilities is one entry in an operator's task list, not
// nine.
func groupByResidency(crossings []policy.Crossing) []residencyGroup {
	byClass := map[string]*residencyGroup{}
	seen := map[string]bool{}

	for _, c := range crossings {
		g, ok := byClass[c.Residency]
		if !ok {
			g = &residencyGroup{residency: c.Residency}
			byClass[c.Residency] = g
		}
		g.count++
		if key := c.Residency + "\x00" + c.Principal; !seen[key] {
			seen[key] = true
			g.principals = append(g.principals, c.Principal)
		}
	}

	out := make([]residencyGroup, 0, len(byClass))
	for _, g := range byClass {
		sort.Strings(g.principals)
		out = append(out, *g)
	}
	// Sorted so a boot log an operator diffs between restarts does not reshuffle
	// with Go's map iteration order.
	sort.Slice(out, func(i, j int) bool { return out[i].residency < out[j].residency })
	return out
}

func splitResidency(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// auditLogPath decides where decision records land.
//
// Defaults under the WAL directory rather than the working directory: an audit
// log written to wherever the process happened to start is one that lands on an
// ephemeral container filesystem, and §5.2.2's durability guarantee is only as
// good as the disk beneath it.
// splitSinks parses the comma-separated -audit-sink flag.
func splitSinks(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// parseSink builds one additional destination from `path` or `path:class|class`.
//
// A PATH AND OPTIONAL CLASSES, which is the smallest form that exercises D120's
// actual claim: with two destinations `Sink.Residencies` ROUTES, where with one
// it can only refuse (D89). A richer destination — BigQuery, a SIEM — is P2's
// connector work and lands behind the same public interface (D32, D35).
func parseSink(spec string, sp *spine.Spine) (audit.Sink, error) {
	const op = "main.parseSink"

	path, classes, _ := strings.Cut(strings.TrimSpace(spec), ":")
	if path == "" {
		return nil, fault.New(fault.KindConfig, op,
			"an -audit-sink entry has no path; write path or path:class|class")
	}

	s := auditwal.NewJSONLSink(path)
	sp.Register(s)
	if classes == "" {
		return s, nil
	}
	// RESIDENCY-SCOPED, which is what makes routing observable. A sink that may
	// receive anything cannot demonstrate that it received only what it may.
	return auditwal.Restrict(s, strings.Split(classes, "|")), nil
}

func auditLogPath(explicit, walDir string) string {
	if explicit != "" {
		return explicit
	}
	if walDir != "" {
		return filepath.Join(walDir, "audit.jsonl")
	}
	return "audit.jsonl"
}

// ctx0 is the background context for lifecycle calls that must not inherit the
// signal-cancelled context — validation and startup have to complete even if a
// SIGTERM arrives mid-boot, or a fast restart loop could leave resources
// half-initialised.
func ctx0() context.Context { return context.Background() }

// probeMux serves the plain-HTTP endpoints. These cannot be gRPC: platform
// probes and metric scrapers speak HTTP and will not learn otherwise
// (CONTRACTS §2).
func probeMux(sp *spine.Spine, p runtime.Profile, mode runtime.Mode,
	met *metrics.Registry, driftStore *drift.Store, quarantined func() map[string]string) http.Handler {

	mux := http.NewServeMux()

	// CONTRACTS §2: plain HTTP, "because platform probes and metric scrapers
	// expect HTTP" and will not learn otherwise.
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if _, err := met.WriteTo(w); err != nil {
			slog.Warn("writing metrics", "err", err)
		}
	})

	// Liveness: is the process alive? Answering 200 here while unready is the
	// point — a liveness probe that fails during initialisation gets the
	// container killed and restarted forever.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Readiness: may it receive traffic?
	//
	// Degraded is reported in the BODY, not the status code. 503 while
	// subsystems remain unbuilt would make the skeleton untestable for the
	// whole of P0 — but returning a bare "ready" would be the stub-that-lies
	// D53 forbids. So: serve what exists, and say plainly what does not.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		// THE CHEAP ANSWER GATES THE EXPENSIVE ONE. `Started` is a field read
		// under one RLock; `Status` polls every started HealthReporter. Asking
		// Status first meant a probe arriving DURING startup polled the health
		// of every registered component in order to discover the process had
		// not started yet — work whose answer could not change the response.
		//
		// Found by the type-resolved orphan guard, from the other end: making
		// `Spine.Ready` delegate to `Status` removed `Started`'s last non-test
		// caller, and rather than register an accessor as orphaned it was worth
		// asking who SHOULD be calling it. This is who.
		// THE PREDICATE GATES, THE PHASE EXPLAINS. `Started()` is the question
		// this branch asks — may it serve — and `Phase()` is the only thing that
		// can say WHICH WAY it is going, which is the whole of CONTRACTS 83. Two
		// field reads under two RLocks rather than one: a phase changing between
		// them (serving to stopping) yields a consistent answer either way, and
		// the alternative was comparing against a constant here, which reads as
		// a state machine detail at a place that only wants a yes or no.
		if !sp.Started() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, readinessRefusal(sp.Phase()))
			return
		}

		// The REQUEST's context, so a probe that gives up does not leave health
		// checks running behind it — and a slow component cannot outlive the
		// probe that asked.
		st := sp.Status(r.Context())

		if !st.Started() {
			// A RE-READ, AND IT IS REACHABLE: `Stop` records STOPPING and drops
			// readiness FIRST — deliberately, so load balancers stop sending
			// work before the process stops accepting it — while this mux keeps
			// serving. So a shutdown that begins DURING the health poll above is
			// observed here and not by the gate.
			//
			// **AND IT NOW SAYS WHICH WAY THE PROCESS IS GOING (CONTRACTS 83,
			// resolved).** Both exits used to print "initializing", which is
			// false during a rollout — the moment an operator is most likely to
			// be reading it. A bool could not tell the two apart: `ready` was
			// false before Start and false after Stop began, and nothing
			// recorded the direction. `spine.Phase` does.
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, readinessRefusal(st.Phase))
			return
		}
		// Started but unhealthy is a REAL 503: the process is alive (so
		// /healthz still passes and it is not killed and restarted) but must
		// not receive traffic.
		if !st.Ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "unhealthy")
			for _, u := range st.Unhealthy {
				fmt.Fprintf(w, "  %s: %v\n", u.Name, u.Err)
			}
			// §7.1: "readiness response should include the resolved
			// RuntimeProfile and any capabilities it disabled."
			//
			// ON THE FAILURE PATH ONLY. /readyz is the most exposed endpoint in
			// the process and the least able to use detail — a Kubernetes probe
			// reads the status code and discards the body. Emitting environment
			// and capability detail on every successful probe would put it on
			// the hot path and in front of anything that can reach the port, to
			// serve a reader that is not there. When readiness FAILS, a human is
			// about to look, and this is exactly what they need.
			fmt.Fprintln(w, "\nenvironment:")
			writeProfile(w, p, mode)
			return
		}
		w.WriteHeader(http.StatusOK)
		if st.Degraded() {
			fmt.Fprintf(w, "ready (DEGRADED: %d/%d subsystems implemented)\n",
				len(st.Implemented), len(st.Implemented)+len(st.Planned))
			for _, pl := range st.Planned {
				fmt.Fprintf(w, "  not implemented: %-12s lands in %-3s — %s\n", pl.Name, pl.LandsIn, pl.Why)
			}
		} else {
			fmt.Fprintln(w, "ready")
		}

		// **PER-TARGET READINESS, ONE LINE, AND THE STATUS CODE IS UNTOUCHED
		// (D197, D206).** A vendor withdrawing one tool of twenty must not take
		// this instance out of rotation — that is the over-refusal failure D197
		// refuses in as many words, and it is what would happen if the drift
		// state reached `Status.Ready` or if the watcher reported itself
		// unhealthy. `drift.Store` deliberately does not implement
		// `spine.HealthReporter`, which is asserted structurally rather than
		// left to a reader (P1 step 33's shape).
		//
		// A SUMMARY HERE AND THE DETAIL ON /debugz/targets, because of what this
		// endpoint is: the comment above on the failure path applies with equal
		// force to a per-probe body write. A Kubernetes probe reads the status
		// code and discards the body, so the detail goes where a human asks for
		// it and the summary goes where a human first looks. Empty when there is
		// nothing to say, so a deployment with no spec-described target reads
		// exactly as it did before this existed (D77: a control that speaks on
		// every healthy probe is one nobody reads).
		//
		// **AND `DEGRADED` IS NOT THE SPINE'S WORD HERE.** `st.Degraded()` above
		// means subsystems remain unbuilt — a fact about this BUILD, answered by
		// shipping the next phase. A degraded target means a vendor is offering
		// less than a human vetted — a fact about a TARGET at runtime, answered
		// by re-vetting a spec. Same adjective, different remedies, so they are
		// reported on separate lines rather than summed into one number.
		if summary := driftSummary(driftStore); summary != "" {
			fmt.Fprintf(w, "targets: %s — see /debugz/targets\n", summary)
		}
		// **A QUARANTINED CONNECTOR, ONE LINE, STATUS UNTOUCHED (D282)** — the
		// drift line's reasoning (D197): one connector's packaging defect must
		// not take this instance out of rotation, and must not be silent.
		if q := quarantineSummary(quarantined); q != "" {
			fmt.Fprintf(w, "connectors quarantined: %s — their targets are refused; see the boot log\n", q)
		}
	})

	// The profile as an operator-facing fact. Answers "what does this instance
	// think it is running on, and what has it disabled" without shell access to
	// read the startup log.
	// The konbini shelf, served. An operator reading a decision record does not
	// have the binary to hand, but does have the port.
	// Per-target spec drift, in full (D197, D206). The operator surface where
	// D197's "the finding is NAMED rather than the capability silently absent"
	// is discharged: an agent sees a capability disappear from its catalog, and
	// this is where a human reads why.
	mux.HandleFunc("GET /debugz/targets", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writeTargetDrift(w, driftStore)
	})

	mux.HandleFunc("GET /debugz/glossary", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, konbini.Render())
	})

	mux.HandleFunc("GET /debugz/profile", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writeProfile(w, p, mode)
	})

	return plainText(mux)
}

// plainText makes every probe response text/plain and unsniffable (D344).
//
// /healthz and /readyz set no Content-Type, so Go SNIFFED one from the first
// bytes of the body — and that body carries subsystem errors and connector
// names. Today it always begins with fixed text and sniffs as text/plain; a
// guarantee that holds only because of how a sentence happens to start is not
// one. Set here, once, before the handler: a handler that sets its own type
// (/metrics' exposition format) still replaces it. Found by a SAST scan.
func plainText(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// writeProfile renders the environment. One renderer, two callers: /debugz and
// the readiness FAILURE body — so the two can never drift into describing the
// same process differently.
func writeProfile(w io.Writer, p runtime.Profile, mode runtime.Mode) {
	fmt.Fprintf(w, "mode:               %s\n", mode)
	fmt.Fprintf(w, "provider:           %s\n", p.Provider)
	fmt.Fprintf(w, "execution:          %s\n", p.Execution)
	fmt.Fprintf(w, "service:            %s\n", p.Service)
	fmt.Fprintf(w, "region:             %s\n", orUnknown(p.Region))
	fmt.Fprintf(w, "background_work:    %t\n", p.BackgroundWork)
	fmt.Fprintf(w, "local_durable_disk: %t\n", p.LocalDurableDisk)
	fmt.Fprintf(w, "leader_election:    %t\n", p.LeaderElection)
	fmt.Fprintf(w, "grace_period:       %s\n", p.GracePeriod)
	fmt.Fprintf(w, "eager_validation:   %t\n", p.EagerValidation())
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

// listenAddr honours $PORT, which Cloud Run and App Service inject and expect
// to be obeyed. A flag beats the environment when both are set.
func listenAddr(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8080"
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fault.New(fault.KindConfig, "main.parseLevel",
			fmt.Sprintf("unknown log level %q; want debug, info, warn, or error", s))
	}
}

func parseMode(s string) (runtime.Mode, error) {
	switch s {
	case "gateway":
		return runtime.ModeGateway, nil
	case "ingest":
		return runtime.ModeIngest, nil
	default:
		return 0, fault.New(fault.KindConfig, "main.parseMode",
			fmt.Sprintf("unknown mode %q; want gateway or ingest", s))
	}
}

func parseAudit(s string) (runtime.AuditMode, error) {
	switch s {
	case "wal":
		return runtime.AuditWAL, nil
	case "sync":
		return runtime.AuditSync, nil
	default:
		return 0, fault.New(fault.KindConfig, "main.parseAudit",
			fmt.Sprintf("unknown audit mode %q; want wal or sync", s))
	}
}

// parseOverrides turns the tri-state flags into the pointer form Override
// wants. An empty string means "not set", which is why these are strings rather
// than flag.Bool — a bool flag cannot express the difference between "false"
// and "not mentioned", and that difference is the whole reason Override uses
// pointers.
func parseOverrides(bg, lead string) (runtime.Override, error) {
	const op = "main.parseOverrides"
	var ov runtime.Override

	parse := func(name, val string) (*bool, error) {
		switch val {
		case "":
			return nil, nil
		case "true":
			b := true
			return &b, nil
		case "false":
			b := false
			return &b, nil
		default:
			return nil, fault.New(fault.KindConfig, op,
				fmt.Sprintf("-%s=%q; want true, false, or unset", name, val))
		}
	}

	var err error
	if ov.BackgroundWork, err = parse("background-work", bg); err != nil {
		return ov, err
	}
	if ov.LeaderElection, err = parse("leader-election", lead); err != nil {
		return ov, err
	}
	return ov, nil
}

// instanceIdentity names this replica to a capacity allocator (D209).
//
// **THE HOSTNAME, AND IT IS DELIBERATELY WEAK.** A lease belongs to a replica,
// so the allocator seam takes an identity from its first version — but at one
// instance nothing reads it, and inventing something stronger now would be
// designing the P7 mechanism from the P2 seat with no coordinator to design
// against.
//
// **WHAT IT IS NOT IS WORTH WRITING DOWN, because the gap is a security one.**
// A hostname is self-asserted and unauthenticated: a coordinator that divided a
// budget by counting distinct hostnames could be diluted by anyone able to claim
// new ones, which is D210's phantom-instance attack. The floor bounds that, and
// the real answer at P7 is the same mTLS identity everything else on this path
// already uses (§4.4) — the workload certificate, not a string the process
// chose for itself. Recorded here so nobody mistakes this for the finished
// article.
func instanceIdentity() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		// UNKNOWN RATHER THAN A RANDOM VALUE. A fresh id per boot would make one
		// restarting replica look like an unbounded stream of new claimants to a
		// coordinator counting them, which is the dilution above arriving by
		// accident.
		return "unknown"
	}
	return h
}

// quarantineSummary names the quarantined connectors for /readyz, sorted, or
// is empty when there are none — so a healthy probe body reads exactly as it
// did before D282 (D77: a line on every healthy probe is one nobody reads).
func quarantineSummary(quarantined func() map[string]string) string {
	if quarantined == nil {
		return ""
	}
	q := quarantined()
	names := make([]string, 0, len(q))
	for kind := range q {
		names = append(names, kind)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// driftGateOf is the drift watcher's gate, or nil when no gateway was built
// (D311). A function rather than an inline expression so the nil case is one
// named branch, not a method call on a nil server.
func driftGateOf(w *enforcementWiring) drift.Gate {
	if w == nil || w.gateway == nil {
		return nil
	}
	return w.gateway.DriftGate()
}

// referenced is a connector pinned to a dated reference of its vendor's API
// (D299, D312): the revision it was checked against, and every operation it
// calls, in the reference's own spelling. Declared HERE, not in pkg/connector:
// only the boot log asks, and a published interface would be a contract for a
// question nothing else has.
type referenced interface {
	ReferenceRevision() string
	Surface() []string
}

// logReferences names, at boot, the vendor reference each connector is pinned to
// and how many documented operations it calls — the first thing an operator
// needs when a vendor changes something (D312).
func logReferences(log *slog.Logger, drivers map[string]connector.Driver) {
	kinds := make([]string, 0, len(drivers))
	for k := range drivers {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		if r, ok := drivers[k].(referenced); ok {
			log.Info("connector pinned to its vendor's reference", "kind", k,
				"revision", r.ReferenceRevision(), "documented_operations_called", len(r.Surface()))
		}
	}
}
