// Package runtime detects the execution environment and constrains
// configuration against it.
//
// PRIVATE (D35) — free to churn. Nothing a third party extends: drivers are
// told what to do, they do not decide it from the environment.
//
// NAME COLLISION, deliberately accepted: this shadows the standard library's
// "runtime". DESIGN §11 specifies internal/runtime/ and the clash is harmless
// while nothing here needs stdlib runtime; a file needing both aliases one.
// Worth revisiting if internal/spine ends up wanting runtime.NumCPU.
//
// THE POINT OF THIS PACKAGE (§4.10.2): Lexicon detected its environment and
// then picked a deployment shim. Sekizui detects and then refuses incoherent
// configuration at boot, turning environment detection from a deployment
// convenience into a correctness guard. Three of Lexicon's checks were buried
// in adapter constructors (index.js:178, :270, :408) — scattered, so nothing
// could reason about them together.
//
// DESIGN.md references: §4.10, §4.10.1, §4.10.2, §5.3, §12 P0, D11, D12, D16, D50.
package runtime

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Provider is axis 1: which cloud. A direct port of Lexicon's
// _isRunningInCloud (lexicon/config.js:413).
type Provider uint8

const (
	ProviderUnknown Provider = iota
	ProviderGCP
	ProviderAWS
	ProviderAzure
)

func (p Provider) String() string {
	switch p {
	case ProviderGCP:
		return "gcp"
	case ProviderAWS:
		return "aws"
	case ProviderAzure:
		return "azure"
	default:
		return "unknown"
	}
}

// Execution is axis 2: which execution model within that cloud.
//
// THIS IS THE AXIS WITH TEETH (§4.10). Provider decides which SDK to use;
// Execution decides lifecycle semantics, and lifecycle semantics are what D11
// and D12 actually depend on.
type Execution uint8

const (
	ExecutionUnknown Execution = iota

	// ExecutionFaaS is frozen between invocations: Lambda, Cloud Functions,
	// Azure Functions. No background work, no durable local disk, no leader
	// election, negligible grace period.
	ExecutionFaaS

	// ExecutionManaged is a platform-managed container with an opaque
	// lifecycle: Cloud Run, App Service, App Runner. Runs continuously while
	// serving, but scales to zero and offers no persistent volume.
	ExecutionManaged

	// ExecutionContainer is an orchestrated container with real primitives:
	// Kubernetes. Persistent volumes and leases are available.
	ExecutionContainer

	// ExecutionBare is a VM or a laptop. Everything is available; nothing is
	// managed.
	ExecutionBare
)

func (e Execution) String() string {
	switch e {
	case ExecutionFaaS:
		return "faas"
	case ExecutionManaged:
		return "managed"
	case ExecutionContainer:
		return "container"
	case ExecutionBare:
		return "bare"
	default:
		return "unknown"
	}
}

// Profile is the detected environment plus the capabilities the rest of the
// system may rely on.
//
// DESIGN §4.10.2 calls this RuntimeProfile; inside package runtime that would
// stutter at every use site (runtime.RuntimeProfile), so it is Profile here.
//
// Capability fields are answers to "may I", not "is it physically possible".
// Where detection cannot tell, they hold the CONSERVATIVE answer — see
// BackgroundWork.
type Profile struct {
	Provider  Provider
	Execution Execution

	// Region is the deployment's own region: "europe-west1", "us-east-1".
	//
	// §7.1 RESIDENCY ITEM 1: "Target carries a residency field; RuntimeProfile
	// carries the instance's region." Item 2 then refuses to resolve a target
	// whose residency conflicts with it — which is unimplementable without this
	// field, so its absence silently disabled the check rather than failing it.
	//
	// D29 calls the residency items "cheap now and expensive to retrofit". This
	// is the cheapest of them: one field, read from the platform's own metadata
	// variable, and everything downstream compares against it.
	//
	// Empty means UNKNOWN, not "anywhere". Resolve treats unknown as a refusal
	// for residency-bearing targets rather than a pass, because assuming is how
	// EU data reaches a US region.
	Region string

	// Service is the specific platform: "cloudrun", "cloudfunctions", "lambda",
	// "apprunner", "appservice", "kubernetes", "". For logs and metrics; no
	// behaviour keys off it, because behaviour keys off capabilities.
	Service string

	// BackgroundWork reports whether goroutines may be relied upon to make
	// progress after a response returns.
	//
	// CONSERVATIVE ON CLOUD RUN. With default CPU allocation, CPU is throttled
	// after the response — background work is not forbidden, it merely may not
	// progress, which is worse because it fails silently. Cloud Run exposes no
	// environment variable distinguishing CPU-always-allocated, so detection
	// cannot know; this defaults to false and an operator who has configured
	// CPU-always sets Override.BackgroundWork.
	//
	// Wrong-way-round costs an audit record. Right-way-round costs a config line.
	BackgroundWork bool

	// LocalDurableDisk reports whether fsync means anything beyond this
	// instance. False on Cloud Run and FaaS: an instance-lifetime filesystem is
	// not durable, and the WAL exists precisely to survive the instance dying.
	LocalDurableDisk bool

	// LeaderElection reports whether this instance may participate in
	// coordination. False anywhere that scales to zero — a leader that
	// evaporates is worse than no leader.
	LeaderElection bool

	// GracePeriod is the SIGTERM-to-SIGKILL budget. Zero means none is
	// guaranteed, which is the honest answer on FaaS rather than a small lie.
	GracePeriod time.Duration
}

// Override forces capabilities that detection cannot determine.
//
// Pointers rather than bools so that "not set" is distinguishable from "set to
// false" — the zero value of a bool would silently disable capabilities the
// operator never mentioned. This is the standard Go workaround for the absence
// of optional value types.
type Override struct {
	BackgroundWork   *bool
	LocalDurableDisk *bool
	LeaderElection   *bool
	GracePeriod      *time.Duration
}

// Getenv matches os.Getenv. Injected rather than called directly so detection
// is testable without mutating real process environment — the same reason
// context.Context is threaded rather than stashed in a global.
type Getenv func(string) string

// Detect identifies the environment. Ordering matters: more specific signals
// are tested first, because platforms layer their variables (Cloud Functions
// gen2 runs on Cloud Run and sets K_SERVICE too).
func Detect(getenv Getenv, ov Override) Profile {
	p := detectPlatform(getenv)
	p.Region = regionOf(getenv)
	p.applyCapabilities()
	p.applyOverride(ov)
	return p
}

// regionOf reads the platform's own region variable.
//
// Every platform spells this differently, and none of them agree on format —
// GCP gives "europe-west1", AWS "eu-west-1", Azure "westeurope". They are NOT
// normalised here: a residency comparison is against an operator-configured
// value, and inventing a canonical form would mean an operator guessing which
// spelling Sekizui expects. The raw platform value is the least surprising
// thing to configure against.
func regionOf(getenv Getenv) string {
	for _, key := range []string{
		"SEKIZUI_REGION", // explicit override always wins
		"GOOGLE_CLOUD_REGION",
		"FUNCTION_REGION", // Cloud Functions gen1
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
		"REGION_NAME", // Azure App Service / Functions
	} {
		if v := getenv(key); v != "" {
			return v
		}
	}
	return ""
}

func detectPlatform(getenv Getenv) Profile {
	has := func(k string) bool { return getenv(k) != "" }

	switch {
	// GCP Cloud Functions. FUNCTION_TARGET before K_SERVICE: gen2 functions set
	// BOTH, and testing K_SERVICE first would misreport every gen2 function as
	// Cloud Run — with the wrong lifecycle semantics attached.
	case has("FUNCTION_TARGET"), has("FUNCTION_NAME"):
		return Profile{Provider: ProviderGCP, Execution: ExecutionFaaS, Service: "cloudfunctions"}

	case has("K_SERVICE"):
		return Profile{Provider: ProviderGCP, Execution: ExecutionManaged, Service: "cloudrun"}

	// Azure Functions before App Service: a Function App sets WEBSITE_SITE_NAME
	// as well (index.js:270 made exactly this distinction).
	case has("FUNCTIONS_WORKER_RUNTIME"):
		return Profile{Provider: ProviderAzure, Execution: ExecutionFaaS, Service: "azurefunctions"}

	case has("WEBSITE_SITE_NAME"):
		return Profile{Provider: ProviderAzure, Execution: ExecutionManaged, Service: "appservice"}

	case has("AWS_LAMBDA_FUNCTION_NAME"):
		return Profile{Provider: ProviderAWS, Execution: ExecutionFaaS, Service: "lambda"}

	case strings.Contains(getenv("AWS_EXECUTION_ENV"), "AWS_AppRunner"):
		return Profile{Provider: ProviderAWS, Execution: ExecutionManaged, Service: "apprunner"}

	// Kubernetes last: it can host any of the above and runs on any cloud, so
	// it is the signal to fall back on rather than lead with. Provider stays
	// unknown — which cloud a cluster sits in does not change its lifecycle.
	//
	// THAT REASONING IS CORRECT FOR CAPABILITIES AND WRONG FOR CREDENTIALS, and
	// the distinction is worth stating here because the next reader will reach
	// the same conclusion for the same good reason (D102).
	//
	// Background work, durable disk, and leader election are properties of the
	// EXECUTION MODEL, so leaving Provider unknown costs nothing. Ambient
	// workload identity is a property of the CLOUD: `ambient://gcp` works on GKE
	// with Workload Identity and cannot work on kind or k3s, and
	// KUBERNETES_SERVICE_HOST is present in both. No environment variable
	// distinguishes them — only the metadata endpoint knows.
	//
	// So ambient validation probes rather than reading this field, gated on
	// EagerValidation (§4.7.7). Do not "fix" the detection by guessing a
	// provider here: a wrong guess would turn a refusable misconfiguration into
	// an accepted one.
	case has("KUBERNETES_SERVICE_HOST"):
		return Profile{Provider: ProviderUnknown, Execution: ExecutionContainer, Service: "kubernetes"}

	default:
		return Profile{Provider: ProviderUnknown, Execution: ExecutionBare, Service: ""}
	}
}

// applyCapabilities fills the capability fields from the execution model —
// the table in §4.10.1, in code.
func (p *Profile) applyCapabilities() {
	switch p.Execution {
	case ExecutionFaaS:
		p.BackgroundWork = false
		p.LocalDurableDisk = false
		p.LeaderElection = false
		p.GracePeriod = 0

	case ExecutionManaged:
		// See BackgroundWork's doc comment: false is the conservative default
		// because Cloud Run's throttled-CPU mode fails silently.
		p.BackgroundWork = false
		p.LocalDurableDisk = false
		p.LeaderElection = false
		p.GracePeriod = 10 * time.Second

	case ExecutionContainer:
		p.BackgroundWork = true
		p.LocalDurableDisk = true
		p.LeaderElection = true
		p.GracePeriod = 30 * time.Second // K8s default terminationGracePeriodSeconds

	case ExecutionBare:
		p.BackgroundWork = true
		p.LocalDurableDisk = true
		p.LeaderElection = true
		p.GracePeriod = 30 * time.Second

	default:
		// Unknown environment: assume nothing. Refusing to guess is what turns
		// a mystery platform into a loud boot failure instead of silent data loss.
		p.BackgroundWork = false
		p.LocalDurableDisk = false
		p.LeaderElection = false
		p.GracePeriod = 0
	}
}

func (p *Profile) applyOverride(ov Override) {
	if ov.BackgroundWork != nil {
		p.BackgroundWork = *ov.BackgroundWork
	}
	if ov.LocalDurableDisk != nil {
		p.LocalDurableDisk = *ov.LocalDurableDisk
	}
	if ov.LeaderElection != nil {
		p.LeaderElection = *ov.LeaderElection
	}
	if ov.GracePeriod != nil {
		p.GracePeriod = *ov.GracePeriod
	}
}

// EagerValidation reports whether live validation may run at startup, or must
// be deferred to first use (D50).
//
// Under FaaS there is no meaningful "shortly after start" — the instance is
// frozen between invocations, so a background validation goroutine may never
// run, and doing it inline at boot would pay the cost on every cold start.
func (p Profile) EagerValidation() bool { return p.Execution != ExecutionFaaS }

// ResidencyPermitted reports whether a target of the given residency may be
// resolved in this deployment — §7.1 residency item 2, "refuse to resolve a
// target whose residency conflicts with the instance region, rather than
// discovering it in an audit".
//
// THE COMPARISON IS AGAINST AN OPERATOR-DECLARED SET, not against Region
// directly. Platform region strings ("europe-west1") and residency
// classifications ("eu") are different vocabularies at different granularities,
// and hard-coding a mapping between them would be Sekizui guessing at a
// compliance boundary. The operator states which classifications this
// deployment may serve; Region is recorded alongside so an audit row shows
// where the decision was made.
//
// An empty permitted set means UNCONSTRAINED, which is correct for a
// single-region deployment that has not thought about residency yet. An empty
// target residency means UNCLASSIFIED and is always permitted — the refusal is
// for a target that declares a residency this deployment cannot serve.
func (p Profile) ResidencyPermitted(permitted []string, targetResidency string) bool {
	if len(permitted) == 0 || targetResidency == "" {
		return true
	}
	for _, r := range permitted {
		if r == targetResidency {
			return true
		}
	}
	return false
}

// LogValue renders the profile as one structured log line.
//
// §4.10.2's secondary benefit: "which environment does this instance think it's
// in, and what has it therefore disabled" should be one line at startup rather
// than an inference across scattered checks. Implementing slog.LogValuer means
// every logger renders it identically without a helper anyone has to remember.
func (p Profile) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("provider", p.Provider.String()),
		slog.String("execution", p.Execution.String()),
		slog.String("service", p.Service),
		slog.String("region", p.Region),
		slog.Bool("background_work", p.BackgroundWork),
		slog.Bool("local_durable_disk", p.LocalDurableDisk),
		slog.Bool("leader_election", p.LeaderElection),
		slog.Duration("grace_period", p.GracePeriod),
		slog.Bool("eager_validation", p.EagerValidation()),
	)
}

// Mode is the deployment split of §5.3. Same binary, different mode.
type Mode uint8

const (
	ModeGateway Mode = iota // stateless; scales 0..N on RPS
	ModeIngest              // holds cursors and leases; leader-elected
)

func (m Mode) String() string {
	if m == ModeIngest {
		return "ingest"
	}
	return "gateway"
}

// AuditMode is how decision records reach their sink.
type AuditMode uint8

const (
	// AuditWAL fsyncs locally, then ships in batches from a background
	// goroutine (§5.2.2). Needs both durable disk and background work.
	AuditWAL AuditMode = iota

	// AuditSync writes through to the sink on the request path. Bounded p99
	// suffers, but it needs neither capability — the correct choice on FaaS.
	AuditSync
)

func (a AuditMode) String() string {
	if a == AuditSync {
		return "sync"
	}
	return "wal"
}

// Requirements is what the configuration is asking to do. Checked against what
// the environment can actually provide.
type Requirements struct {
	Mode        Mode
	Audit       AuditMode
	DrainBudget time.Duration

	// WALPath is the local WAL location, empty when Audit is AuditSync.
	WALPath string
}

// Plan is the outcome of a successful check: what to actually do, after any
// safe adjustments, plus what the operator should be told.
type Plan struct {
	// DrainBudget, possibly shortened to fit inside GracePeriod.
	DrainBudget time.Duration

	// Warnings are non-fatal but must be logged at WARN. Adjustments the
	// operator did not ask for are exactly the thing that must not be silent.
	Warnings []string
}

// Check validates configuration against the environment, refusing incoherent
// combinations (§4.10.2). This is P0 exit criterion 4.
//
// Returns a fault of KindConfig on refusal, so the boot path reports it through
// the same taxonomy as everything else rather than inventing a private error
// type nobody maps.
//
// The bias is REFUSE over silently degrade. §4.10.2 permits downgrading an
// impossible async audit to synchronous, but doing that automatically means a
// deployment behaves differently from its configuration without anyone
// deciding — so the downgrade is an operator action (set Audit: AuditSync), and
// the error names it.
func (p Profile) Check(r Requirements) (Plan, error) {
	const op = "runtime.Check"

	// Ingest holds cursors and leases (§5.3). Without leader election, two
	// replicas poll the same cursor and duplicate every event.
	if r.Mode == ModeIngest && !p.LeaderElection {
		return Plan{}, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"mode=ingest requires leader election, unavailable on %s/%s; "+
				"run ingest on Kubernetes or a VM, or set an explicit override if coordination is provided externally",
			p.Provider, p.Execution))
	}

	if r.Audit == AuditWAL && !p.BackgroundWork {
		return Plan{}, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"audit=wal ships batches from a background goroutine, which %s/%s cannot be relied on to run; "+
				"set audit=sync, or override background_work if CPU is always allocated",
			p.Provider, p.Execution))
	}

	if r.Audit == AuditWAL && !p.LocalDurableDisk && r.WALPath != "" {
		return Plan{}, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"audit=wal at %q needs durable local disk; %s/%s provides instance-lifetime storage only, "+
				"so an fsynced record dies with the instance it was protecting against",
			r.WALPath, p.Provider, p.Execution))
	}

	plan := Plan{DrainBudget: r.DrainBudget}

	// Not fatal: a drain that overruns the grace period is merely truncated by
	// SIGKILL. Shortening it means the drain finishes deliberately instead of
	// being cut mid-batch.
	if p.GracePeriod > 0 && r.DrainBudget > p.GracePeriod {
		plan.DrainBudget = p.GracePeriod
		plan.Warnings = append(plan.Warnings, fmt.Sprintf(
			"drain budget %s exceeds the %s grace period on %s; shortened to %s",
			r.DrainBudget, p.GracePeriod, p.Service, p.GracePeriod))
	}

	if p.GracePeriod == 0 && r.DrainBudget > 0 {
		plan.DrainBudget = 0
		plan.Warnings = append(plan.Warnings, fmt.Sprintf(
			"no grace period is guaranteed on %s/%s; drain disabled, in-flight work is lost on termination",
			p.Provider, p.Execution))
	}

	if p.Execution == ExecutionUnknown {
		plan.Warnings = append(plan.Warnings,
			"execution environment not recognised; every capability assumed absent")
	}

	return plan, nil
}
