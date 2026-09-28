package runtime

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/fault"
)

// env builds a Getenv over a fixed map. Injecting rather than calling
// t.Setenv keeps these tests parallel-safe: process environment is global
// state, and -race would be the least of the problems.
func env(kv map[string]string) Getenv {
	return func(k string) string { return kv[k] }
}

func TestDetectPlatform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		wantSvc string
		wantPrv Provider
		wantExe Execution
	}{
		{
			name:    "bare when nothing is set",
			env:     nil,
			wantSvc: "",
			wantPrv: ProviderUnknown,
			wantExe: ExecutionBare,
		},
		{
			name:    "cloud run",
			env:     map[string]string{"K_SERVICE": "sekizui"},
			wantSvc: "cloudrun",
			wantPrv: ProviderGCP,
			wantExe: ExecutionManaged,
		},
		{
			name:    "cloud functions gen1",
			env:     map[string]string{"FUNCTION_NAME": "handler"},
			wantSvc: "cloudfunctions",
			wantPrv: ProviderGCP,
			wantExe: ExecutionFaaS,
		},
		{
			// THE ORDERING TRAP. Gen2 functions run on Cloud Run and set
			// K_SERVICE too. Testing K_SERVICE first would classify every gen2
			// function as Managed, granting it a 10s grace period and a
			// background-work assumption it does not have.
			name: "cloud functions gen2 sets K_SERVICE too, and must still be faas",
			env: map[string]string{
				"FUNCTION_TARGET": "handler",
				"K_SERVICE":       "handler",
			},
			wantSvc: "cloudfunctions",
			wantPrv: ProviderGCP,
			wantExe: ExecutionFaaS,
		},
		{
			name:    "azure functions",
			env:     map[string]string{"FUNCTIONS_WORKER_RUNTIME": "node"},
			wantSvc: "azurefunctions",
			wantPrv: ProviderAzure,
			wantExe: ExecutionFaaS,
		},
		{
			// Same trap on Azure: a Function App also sets WEBSITE_SITE_NAME.
			name: "azure function app also sets WEBSITE_SITE_NAME, and must still be faas",
			env: map[string]string{
				"FUNCTIONS_WORKER_RUNTIME": "node",
				"WEBSITE_SITE_NAME":        "sekizui",
			},
			wantSvc: "azurefunctions",
			wantPrv: ProviderAzure,
			wantExe: ExecutionFaaS,
		},
		{
			name:    "azure app service",
			env:     map[string]string{"WEBSITE_SITE_NAME": "sekizui"},
			wantSvc: "appservice",
			wantPrv: ProviderAzure,
			wantExe: ExecutionManaged,
		},
		{
			name:    "lambda",
			env:     map[string]string{"AWS_LAMBDA_FUNCTION_NAME": "sekizui"},
			wantSvc: "lambda",
			wantPrv: ProviderAWS,
			wantExe: ExecutionFaaS,
		},
		{
			name:    "app runner",
			env:     map[string]string{"AWS_EXECUTION_ENV": "AWS_AppRunner_dotnet"},
			wantSvc: "apprunner",
			wantPrv: ProviderAWS,
			wantExe: ExecutionManaged,
		},
		{
			name:    "kubernetes",
			env:     map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
			wantSvc: "kubernetes",
			wantPrv: ProviderUnknown,
			wantExe: ExecutionContainer,
		},
		{
			// K8s is checked last precisely so a Cloud Run service does not get
			// misread as a container because something injected the variable.
			name: "cloud run wins over a stray kubernetes variable",
			env: map[string]string{
				"K_SERVICE":               "sekizui",
				"KUBERNETES_SERVICE_HOST": "10.0.0.1",
			},
			wantSvc: "cloudrun",
			wantExe: ExecutionManaged,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Detect(env(tc.env), Override{})

			if got.Service != tc.wantSvc {
				t.Errorf("Service = %q, want %q", got.Service, tc.wantSvc)
			}
			if tc.wantPrv != ProviderUnknown && got.Provider != tc.wantPrv {
				t.Errorf("Provider = %v, want %v", got.Provider, tc.wantPrv)
			}
			if got.Execution != tc.wantExe {
				t.Errorf("Execution = %v, want %v", got.Execution, tc.wantExe)
			}
		})
	}
}

// TestFaaSGrantsNothing pins the whole point of axis 2: a frozen environment
// must not be credited with capabilities it lacks.
func TestFaaSGrantsNothing(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"AWS_LAMBDA_FUNCTION_NAME": "x"}), Override{})

	if p.BackgroundWork || p.LocalDurableDisk || p.LeaderElection {
		t.Errorf("FaaS granted a capability: %+v", p)
	}
	if p.GracePeriod != 0 {
		t.Errorf("GracePeriod = %v, want 0 — FaaS guarantees none", p.GracePeriod)
	}
	if p.EagerValidation() {
		t.Error("EagerValidation = true on FaaS; D50 requires lazy validation where there is no 'after start'")
	}
}

// TestCloudRunIsConservativeAboutBackgroundWork guards the deliberate default.
// Cloud Run exposes nothing distinguishing CPU-always-allocated, and guessing
// optimistically loses audit records silently.
func TestCloudRunIsConservativeAboutBackgroundWork(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"K_SERVICE": "sekizui"}), Override{})

	if p.BackgroundWork {
		t.Error("Cloud Run defaulted BackgroundWork=true; throttled CPU fails silently, so the default must be false")
	}
	if p.LocalDurableDisk {
		t.Error("Cloud Run claimed durable disk; storage is instance-lifetime only")
	}
	if p.EagerValidation() != true {
		t.Error("Cloud Run should allow eager validation — it is not frozen between requests")
	}
}

func TestContainerGrantsEverything(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"}), Override{})

	if !p.BackgroundWork || !p.LocalDurableDisk || !p.LeaderElection {
		t.Errorf("Kubernetes withheld a capability: %+v", p)
	}
}

// TestOverrideDistinguishesUnsetFromFalse is why Override uses pointers.
func TestOverrideDistinguishesUnsetFromFalse(t *testing.T) {
	t.Parallel()
	yes, no := true, false

	// Unset leaves the detected value alone.
	base := Detect(env(map[string]string{"KUBERNETES_SERVICE_HOST": "1"}), Override{})
	if !base.BackgroundWork {
		t.Fatal("precondition: kubernetes should have BackgroundWork")
	}

	// Explicit false must actually disable it, not read as "unset".
	off := Detect(env(map[string]string{"KUBERNETES_SERVICE_HOST": "1"}), Override{BackgroundWork: &no})
	if off.BackgroundWork {
		t.Error("Override.BackgroundWork=&false did not disable it")
	}

	// Explicit true is how a CPU-always Cloud Run operator opts in.
	on := Detect(env(map[string]string{"K_SERVICE": "x"}), Override{BackgroundWork: &yes})
	if !on.BackgroundWork {
		t.Error("Override.BackgroundWork=&true did not enable it on Cloud Run")
	}
}

// --- Check: P0 exit criterion 4 -------------------------------------------

// TestIngestWithoutLeaderElectionRefuses is P0 exit criterion 4 verbatim:
// "Boot refuses on an incoherent RuntimeProfile (e.g. ingest mode without
// leader election)".
func TestIngestWithoutLeaderElectionRefuses(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"K_SERVICE": "sekizui"}), Override{}) // Cloud Run: scales to zero

	_, err := p.Check(Requirements{Mode: ModeIngest, Audit: AuditSync})
	if err == nil {
		t.Fatal("ingest on Cloud Run was accepted; two replicas would poll one cursor and duplicate every event")
	}
	if !errors.Is(err, fault.KindConfig) {
		t.Errorf("error kind = %v, want KindConfig", fault.KindOf(err))
	}
	if !strings.Contains(err.Error(), "leader election") {
		t.Errorf("error does not name the incompatibility: %v", err)
	}
}

func TestIngestOnKubernetesIsAccepted(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"KUBERNETES_SERVICE_HOST": "1"}), Override{})

	if _, err := p.Check(Requirements{Mode: ModeIngest, Audit: AuditWAL, WALPath: "/var/lib/sekizui/wal"}); err != nil {
		t.Errorf("ingest on Kubernetes refused: %v", err)
	}
}

func TestWALWithoutBackgroundWorkRefuses(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"AWS_LAMBDA_FUNCTION_NAME": "x"}), Override{})

	_, err := p.Check(Requirements{Mode: ModeGateway, Audit: AuditWAL})
	if err == nil {
		t.Fatal("audit=wal accepted on Lambda; batches would never ship")
	}
	if !errors.Is(err, fault.KindConfig) {
		t.Errorf("error kind = %v, want KindConfig", fault.KindOf(err))
	}
	// The error must tell the operator what to do, not merely that it refused.
	if !strings.Contains(err.Error(), "audit=sync") {
		t.Errorf("error does not name the remedy: %v", err)
	}
}

func TestWALWithoutDurableDiskRefuses(t *testing.T) {
	t.Parallel()
	yes := true
	// CPU-always Cloud Run: background work is fine, disk still is not.
	p := Detect(env(map[string]string{"K_SERVICE": "x"}), Override{BackgroundWork: &yes})

	_, err := p.Check(Requirements{Mode: ModeGateway, Audit: AuditWAL, WALPath: "/tmp/sekizui.wal"})
	if err == nil {
		t.Fatal("WAL on instance-lifetime storage accepted; an fsynced record would die with the instance it protects against")
	}
	if !errors.Is(err, fault.KindConfig) {
		t.Errorf("error kind = %v, want KindConfig", fault.KindOf(err))
	}
}

// TestSyncAuditIsAcceptedOnFaaS confirms the refusals above are about the
// combination, not a blanket ban — FaaS is a legitimate deployment.
func TestSyncAuditIsAcceptedOnFaaS(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"AWS_LAMBDA_FUNCTION_NAME": "x"}), Override{})

	if _, err := p.Check(Requirements{Mode: ModeGateway, Audit: AuditSync}); err != nil {
		t.Errorf("gateway + sync audit on Lambda refused: %v", err)
	}
}

func TestDrainBudgetShortenedToGracePeriod(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"K_SERVICE": "x"}), Override{}) // 10s grace

	plan, err := p.Check(Requirements{Mode: ModeGateway, Audit: AuditSync, DrainBudget: 60 * time.Second})
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if plan.DrainBudget != 10*time.Second {
		t.Errorf("DrainBudget = %v, want 10s", plan.DrainBudget)
	}
	if len(plan.Warnings) == 0 {
		t.Error("budget was shortened silently; an adjustment nobody asked for must be logged")
	}
}

func TestNoGracePeriodDisablesDrainLoudly(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"AWS_LAMBDA_FUNCTION_NAME": "x"}), Override{})

	plan, err := p.Check(Requirements{Mode: ModeGateway, Audit: AuditSync, DrainBudget: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if plan.DrainBudget != 0 {
		t.Errorf("DrainBudget = %v, want 0 where no grace period is guaranteed", plan.DrainBudget)
	}
	if len(plan.Warnings) == 0 {
		t.Error("drain disabled with no warning")
	}
}

func TestDrainBudgetWithinGracePeriodIsUntouched(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"KUBERNETES_SERVICE_HOST": "1"}), Override{}) // 30s

	plan, err := p.Check(Requirements{Mode: ModeGateway, Audit: AuditSync, DrainBudget: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if plan.DrainBudget != 5*time.Second {
		t.Errorf("DrainBudget = %v, want 5s unchanged", plan.DrainBudget)
	}
	if len(plan.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", plan.Warnings)
	}
}

// TestLogValueNamesEveryCapability backs §4.10.2's claim that the profile is
// one legible startup line rather than an inference.
func TestLogValueNamesEveryCapability(t *testing.T) {
	t.Parallel()
	p := Detect(env(map[string]string{"K_SERVICE": "sekizui"}), Override{})

	got := p.LogValue().String()
	for _, want := range []string{
		"provider", "execution", "service",
		"background_work", "local_durable_disk", "leader_election",
		"grace_period", "eager_validation",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("LogValue missing %q: %s", want, got)
		}
	}
}
