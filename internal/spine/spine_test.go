package spine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// These tests assert the LIFECYCLE CONTRACT, not the current emptiness (D53,
// §12.0 principle 4). Every rule below — validate-before-start, reverse-order
// shutdown, unwind on partial failure, repeatable Start/Stop — is as true when
// P8 adds leader election as it is today, so none of them should need deleting
// when real components arrive.

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// capableProfile grants everything, so capability checks don't interfere with
// tests about ordering.
func capableProfile() runtime.Profile {
	return runtime.Detect(func(string) string { return "" }, runtime.Override{})
}

// fake records lifecycle calls against a shared, mutex-guarded journal so the
// ORDER across components is observable — which is the property most of these
// tests are about.
type fake struct {
	name     string
	journal  *journal
	needs    *Needs
	startErr error
	valErr   error
}

type journal struct {
	mu    sync.Mutex
	calls []string
}

func (j *journal) add(s string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.calls = append(j.calls, s)
}

func (j *journal) list() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.calls...)
}

func (f *fake) Name() string { return f.name }

func (f *fake) Start(context.Context) error {
	f.journal.add("start:" + f.name)
	return f.startErr
}

func (f *fake) Stop(context.Context) error {
	f.journal.add("stop:" + f.name)
	return nil
}

// validatingFake also satisfies Validator. Separate type so a plain fake can be
// used where the optional interface must NOT be present.
type validatingFake struct{ *fake }

func (f validatingFake) Validate(context.Context) error {
	f.journal.add("validate:" + f.name)
	return f.valErr
}

// capableFake also satisfies CapabilityAware.
type capableFake struct{ *fake }

func (f capableFake) Needs() Needs { return *f.needs }

func TestStartsInRegistrationOrderStopsInReverse(t *testing.T) {
	j := &journal{}
	s := New(capableProfile(), quietLogger())

	// Registered store-first, user-second: the dependency order.
	s.Register(&fake{name: "cursorstore", journal: j})
	s.Register(&fake{name: "poller", journal: j})

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	want := []string{"start:cursorstore", "start:poller", "stop:poller", "stop:cursorstore"}
	got := j.list()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("lifecycle order:\n got %v\nwant %v", got, want)
	}
}

// TestValidateRunsBeforeAnyStart is the "rejected at boot" guarantee that P3
// exit 5 and P5 exits 3 and 4 all depend on.
func TestValidateRunsBeforeAnyStart(t *testing.T) {
	j := &journal{}
	s := New(capableProfile(), quietLogger())

	s.Register(validatingFake{&fake{name: "a", journal: j}})
	s.Register(validatingFake{&fake{name: "b", journal: j}})

	if err := s.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	got := strings.Join(j.list(), ",")
	want := "validate:a,validate:b,start:a,start:b"
	if got != want {
		t.Errorf("every validation must precede every start:\n got %s\nwant %s", got, want)
	}
}

// TestValidateReportsEveryFailure: an operator fixing config wants the whole
// list, not one error per restart.
func TestValidateReportsEveryFailure(t *testing.T) {
	j := &journal{}
	s := New(capableProfile(), quietLogger())

	boom := errors.New("cyclic rule")
	s.Register(validatingFake{&fake{name: "a", journal: j, valErr: boom}})
	s.Register(validatingFake{&fake{name: "b", journal: j}})
	s.Register(validatingFake{&fake{name: "c", journal: j, valErr: boom}})

	err := s.Validate(context.Background())
	if err == nil {
		t.Fatal("Validate accepted two broken components")
	}
	if !errors.Is(err, fault.KindConfig) {
		t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
	}
	// Both failures named, and the good one still validated: no short-circuit.
	msg := err.Error()
	for _, name := range []string{`"a"`, `"c"`} {
		if !strings.Contains(msg, name) {
			t.Errorf("error omits component %s: %s", name, msg)
		}
	}
	if !strings.Contains(strings.Join(j.list(), ","), "validate:b") {
		t.Error("validation short-circuited; every component must be checked")
	}
}

// TestPartialStartFailureUnwinds. Leaving components running after a failed
// boot means a process neither up nor down, holding leases nothing will release.
func TestPartialStartFailureUnwinds(t *testing.T) {
	j := &journal{}
	s := New(capableProfile(), quietLogger())

	s.Register(&fake{name: "a", journal: j})
	s.Register(&fake{name: "b", journal: j})
	s.Register(&fake{name: "c", journal: j, startErr: errors.New("port in use")})
	s.Register(&fake{name: "d", journal: j})

	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("Start succeeded despite a failing component")
	}

	got := strings.Join(j.list(), ",")
	// c fails, d never starts, and b then a are unwound in reverse.
	want := "start:a,start:b,start:c,stop:b,stop:a"
	if got != want {
		t.Errorf("unwind sequence:\n got %s\nwant %s", got, want)
	}
	if s.Ready(context.Background()) {
		t.Error("Ready() is true after a failed Start")
	}
}

// TestRefusesComponentTheEnvironmentCannotSupport is §5.2.2's WAL-on-Cloud-Run
// case: refuse at boot, naming the component, rather than letting it start and
// silently fail to do its job.
func TestRefusesComponentTheEnvironmentCannotSupport(t *testing.T) {
	j := &journal{}
	// Lambda: no background work, no durable disk, no leader election.
	lambda := runtime.Detect(func(k string) string {
		if k == "AWS_LAMBDA_FUNCTION_NAME" {
			return "sekizui"
		}
		return ""
	}, runtime.Override{})

	s := New(lambda, quietLogger())
	s.Register(capableFake{&fake{
		name:    "auditwal",
		journal: j,
		needs:   &Needs{BackgroundWork: true, LocalDurableDisk: true},
	}})

	err := s.Validate(context.Background())
	if err == nil {
		t.Fatal("WAL shipper accepted on Lambda")
	}
	if !errors.Is(err, fault.KindConfig) {
		t.Errorf("kind = %v, want KindConfig", fault.KindOf(err))
	}
	for _, want := range []string{"auditwal", "background_work", "local_durable_disk"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits %q: %s", want, err)
		}
	}
}

func TestComponentWithoutNeedsIsUnconstrained(t *testing.T) {
	lambda := runtime.Detect(func(k string) string {
		if k == "AWS_LAMBDA_FUNCTION_NAME" {
			return "x"
		}
		return ""
	}, runtime.Override{})

	s := New(lambda, quietLogger())
	s.Register(&fake{name: "stateless", journal: &journal{}}) // no CapabilityAware

	if err := s.Validate(context.Background()); err != nil {
		t.Errorf("a component declaring no needs was refused: %v", err)
	}
}

// TestStartStopAreRepeatable is the P8 contract. Leader election stops
// components on lease loss and starts them again on re-acquisition, so a
// single-start assumption anywhere would be a v2 rewrite.
func TestStartStopAreRepeatable(t *testing.T) {
	j := &journal{}
	s := New(capableProfile(), quietLogger())
	s.Register(&fake{name: "poller", journal: j})

	ctx := context.Background()
	for range 2 {
		if err := s.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if !s.Ready(context.Background()) {
			t.Fatal("not ready after Start")
		}
		if err := s.Stop(ctx); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if s.Ready(context.Background()) {
			t.Fatal("still ready after Stop")
		}
	}

	got := strings.Join(j.list(), ",")
	want := "start:poller,stop:poller,start:poller,stop:poller"
	if got != want {
		t.Errorf("repeat cycle:\n got %s\nwant %s", got, want)
	}
}

// TestStopIsIdempotent — shutdown races and leader churn both call it twice.
func TestStopIsIdempotent(t *testing.T) {
	j := &journal{}
	s := New(capableProfile(), quietLogger())
	s.Register(&fake{name: "a", journal: j})

	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}

	if got := strings.Join(j.list(), ","); got != "start:a,stop:a" {
		t.Errorf("component stopped more than once: %s", got)
	}
}

func TestNotReadyBeforeStart(t *testing.T) {
	s := New(capableProfile(), quietLogger())
	s.Register(&fake{name: "a", journal: &journal{}})

	if s.Ready(context.Background()) {
		t.Error("Ready() true before Start")
	}
	if s.Started() {
		t.Error("Started() true before Start")
	}
}

// healthyFake reports health that can be flipped at runtime — the whole point
// of HealthReporter.
type healthyFake struct {
	*fake
	mu  sync.Mutex
	err error
}

func (f *healthyFake) Health(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *healthyFake) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// TestReadinessFollowsHealthAfterStart is the correction to the original
// design, where readiness was a boolean set once by Start and never revisited.
//
// D50's per-target MCP drift and P3/P5's long-running components both make
// health a RUNTIME property. A process whose poller has died must stop
// advertising itself as ready, without needing a restart to notice.
func TestReadinessFollowsHealthAfterStart(t *testing.T) {
	ctx := context.Background()
	h := &healthyFake{fake: &fake{name: "poller", journal: &journal{}}}

	s := New(capableProfile(), quietLogger())
	s.Register(h)

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !s.Ready(ctx) {
		t.Fatal("not ready immediately after a clean start")
	}

	// The component dies at runtime. Nothing restarts, nothing re-validates.
	h.setErr(errors.New("cursor store unreachable"))

	if s.Ready(ctx) {
		t.Error("still ready after the component reported itself unhealthy")
	}
	// Liveness must NOT follow: the process is alive and should not be killed
	// and restarted, it should merely stop receiving traffic.
	if !s.Started() {
		t.Error("Started() went false on a health failure; that would get the container restarted")
	}

	// Recovery is equally important — a target that comes back must not need a
	// restart to be usable again.
	h.setErr(nil)
	if !s.Ready(ctx) {
		t.Error("did not recover when the component became healthy again")
	}
}

func TestStatusNamesUnhealthyComponents(t *testing.T) {
	ctx := context.Background()
	bad := &healthyFake{fake: &fake{name: "mcp:fullstory", journal: &journal{}}}
	good := &healthyFake{fake: &fake{name: "audit", journal: &journal{}}}

	s := New(capableProfile(), quietLogger())
	s.Register(good)
	s.Register(bad)
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	bad.setErr(errors.New("inputSchema diverged from vetted spec"))
	st := s.Status(ctx)

	if st.Ready {
		t.Error("Status.Ready true with an unhealthy component")
	}
	if len(st.Unhealthy) != 1 {
		t.Fatalf("Unhealthy = %d entries, want 1", len(st.Unhealthy))
	}
	if st.Unhealthy[0].Name != "mcp:fullstory" {
		t.Errorf("Unhealthy names %q, want mcp:fullstory", st.Unhealthy[0].Name)
	}
	// An operator needs the reason, not just the name.
	if !strings.Contains(st.Unhealthy[0].Err.Error(), "diverged") {
		t.Errorf("Unhealthy entry lost the cause: %v", st.Unhealthy[0].Err)
	}
}

// TestComponentsWithoutHealthAreHealthy: most components have no runtime
// failure mode and must not be forced to implement a no-op method to say so.
func TestComponentsWithoutHealthAreHealthy(t *testing.T) {
	ctx := context.Background()
	s := New(capableProfile(), quietLogger())
	s.Register(&fake{name: "plain", journal: &journal{}}) // no HealthReporter

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !s.Ready(ctx) {
		t.Error("a component with no HealthReporter was treated as unhealthy")
	}
	if got := s.CheckHealth(ctx); len(got) != 0 {
		t.Errorf("CheckHealth reported %d entries for a non-reporter", len(got))
	}
}

// TestUnstartedComponentsAreNotPolled. A component that never started, or was
// unwound by a failed Start, has nothing meaningful to report — polling it
// would show unhealthy for the wrong reason.
func TestUnstartedComponentsAreNotPolled(t *testing.T) {
	ctx := context.Background()
	h := &healthyFake{fake: &fake{name: "never-started", journal: &journal{}}}
	h.setErr(errors.New("should not be consulted"))

	s := New(capableProfile(), quietLogger())
	s.Register(h)

	if got := s.CheckHealth(ctx); len(got) != 0 {
		t.Errorf("polled a component before Start: %v", got)
	}

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := s.CheckHealth(ctx); len(got) != 0 {
		t.Errorf("polled a component after Stop: %v", got)
	}
}

// TestPlannedSubsystemsMakeStatusDegraded is the D53 mechanism: an incomplete
// skeleton must report itself as incomplete rather than claiming readiness it
// has not earned.
func TestPlannedSubsystemsMakeStatusDegraded(t *testing.T) {
	s := New(capableProfile(), quietLogger())
	s.Register(&fake{name: "runtime", journal: &journal{}})
	s.Plan(Planned{Name: "policy", LandsIn: "P0", Why: "embedded Rego"})
	s.Plan(Planned{Name: "leader", LandsIn: "P8", Why: "lease-based leader election"})

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	st := s.Status(context.Background())
	if !st.Ready {
		t.Error("Ready false despite every registered component starting")
	}
	if !st.Degraded() {
		t.Error("Degraded false with two planned subsystems outstanding")
	}
	if len(st.Implemented) != 1 || len(st.Planned) != 2 {
		t.Errorf("Status = %d implemented / %d planned, want 1/2",
			len(st.Implemented), len(st.Planned))
	}
}

func TestNoPlannedSubsystemsMeansNotDegraded(t *testing.T) {
	s := New(capableProfile(), quietLogger())
	s.Register(&fake{name: "a", journal: &journal{}})

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.Status(context.Background()).Degraded() {
		t.Error("Degraded true with nothing planned")
	}
}

// phaseWatchingFake records the phase it observed while ITS OWN Stop ran.
//
// The only way to assert "readiness is dropped FIRST" from inside the process:
// a component that looks at the phase during its own shutdown either sees
// `stopping` or it does not, and the ordering claim is exactly that.
type phaseWatchingFake struct {
	*fake
	sp *Spine

	mu       sync.Mutex
	sawPhase Phase
}

func (f *phaseWatchingFake) Stop(ctx context.Context) error {
	f.mu.Lock()
	f.sawPhase = f.sp.Phase()
	f.mu.Unlock()
	return f.fake.Stop(ctx)
}

func (f *phaseWatchingFake) observed() Phase {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sawPhase
}

// TestPhaseDistinguishesStartingFromStopping is CONTRACTS 83.
//
// **A BOOL COULD NOT ANSWER THE QUESTION A PROBE ASKS.** `ready` was false
// before Start and false once Stop began, so `/readyz` reported 503
// "initializing" during a rollout — false at the moment an operator is most
// likely to be reading it, and the direction is not inferable from the value.
//
// Asserted as a PROGRESSION rather than as three separate states, because the
// defect was never one wrong answer: it was that two different situations
// produced the same one.
func TestPhaseDistinguishesStartingFromStopping(t *testing.T) {
	ctx := context.Background()

	s := New(capableProfile(), quietLogger())
	watcher := &phaseWatchingFake{fake: &fake{name: "a", journal: &journal{}}}
	watcher.sp = s
	s.Register(watcher)

	if got := s.Phase(); got != PhaseInitializing {
		t.Errorf("before Start, Phase() = %v, want %v", got, PhaseInitializing)
	}

	if err := s.Start(ctx); err != nil {
		t.Fatalf("starting: %v", err)
	}
	if got := s.Phase(); got != PhaseServing {
		t.Errorf("after Start, Phase() = %v, want %v", got, PhaseServing)
	}
	if !s.Started() {
		t.Error("Started() is false while serving, so it no longer derives from Phase")
	}

	if err := s.Stop(ctx); err != nil {
		t.Fatalf("stopping: %v", err)
	}
	if got := s.Phase(); got != PhaseStopped {
		t.Errorf("after Stop returned, Phase() = %v, want %v", got, PhaseStopped)
	}

	// **THE ORDERING GUARANTEE, WHICH HAD ONLY EVER BEEN A COMMENT.** Stop's own
	// doc says "readiness is dropped FIRST, so load balancers stop sending work
	// before the process stops accepting it" — and nothing checked it. A
	// component that observed `serving` during its own shutdown would mean the
	// window between "still advertised as ready" and "no longer able to serve"
	// was real, which is the window that drops requests during a rollout.
	if got := watcher.observed(); got != PhaseStopping {
		t.Errorf("a component's own Stop observed phase %v, want %v. Stop must record "+
			"STOPPING before asking any component to stop, or readiness is withdrawn "+
			"after capacity is — which is the ordering that drops in-flight requests "+
			"during a rollout", got, PhaseStopping)
	}
}

// TestStoppingIsNotReportedAsInitializing is the message half.
//
// The phase is what /readyz renders, so a step asserting the phase asserts what
// an operator reads — while `readinessRefusal` in cmd/sekizui owns the wording.
// **KEPT SEPARATE FROM THE PROGRESSION ABOVE** because this is the claim the
// item was filed for: the two 503s must not say the same thing.
func TestStoppingIsNotReportedAsInitializing(t *testing.T) {
	if PhaseStopping.String() == PhaseInitializing.String() {
		t.Fatalf("stopping and initializing render identically (%q), which is the whole "+
			"of CONTRACTS 83: a 503 during a rollout and a 503 during a cold start call "+
			"for opposite reactions", PhaseStopping)
	}
	for _, c := range []struct {
		p    Phase
		want string
	}{
		{PhaseInitializing, "initializing"},
		{PhaseServing, "serving"},
		{PhaseStopping, "stopping"},
		{PhaseStopped, "stopped"},
	} {
		if got := c.p.String(); got != c.want {
			t.Errorf("Phase(%d).String() = %q, want %q", c.p, got, c.want)
		}
	}
}
