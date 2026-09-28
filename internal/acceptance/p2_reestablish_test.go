package acceptance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/churn"
	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/limiter"
	"github.com/fullstorydev/sekizui/internal/metrics"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/retry"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	pkglimiter "github.com/fullstorydev/sekizui/pkg/limiter"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// --- the far side, and the credential behind it ----------------------------

// rotatingProvider mints a new version every time it is asked.
//
// **THE VERSION IS WHAT THE STEP MEASURES, so it must MOVE FORWARD.** D152's
// guard refuses a version that goes backwards, and a provider handing back the
// same version twice would make the two audit rows identical and the assertion
// about them vacuous. Monotonic, so the forced re-resolve is a legitimate one
// and the guard has no reason to fire — the arm where it SHOULD fire drives it
// deliberately, below.
type rotatingProvider struct {
	mu sync.Mutex
	n  int
}

func (p *rotatingProvider) Scheme() string { return "rot" }

func (p *rotatingProvider) Resolve(context.Context, string) (config.Resolution, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	return config.Resolution{
		Material: []byte(fmt.Sprintf("token-%d", p.n)),
		Version:  fmt.Sprintf("v%d", p.n),
	}, nil
}

func (p *rotatingProvider) resolves() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// rollbackProvider hands out v2 first and v1 afterwards.
//
// **WHAT AN ATTACKER WANTS THE FORCED RE-RESOLVE TO TURN UP.** A version that
// moves BACKWARDS is what a disabled compromised version looks like when a
// platform falls back to an older one — and D152's monotonic guard exists to
// refuse it. Re-establishment is the one path an outsider can trigger on demand,
// by returning 401, so it is the path where that guard matters most.
type rollbackProvider struct {
	mu sync.Mutex
	n  int
}

func (p *rollbackProvider) Scheme() string { return "rot" }

func (p *rollbackProvider) Resolve(context.Context, string) (config.Resolution, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	if p.n == 1 {
		return config.Resolution{Material: []byte("token-2"), Version: "2"}, nil
	}
	return config.Resolution{Material: []byte("token-1"), Version: "1"}, nil
}

// rejectingDriver is a far side that rejects the first credential it is shown
// and accepts the next one.
//
// **IT KEYS ON THE MATERIAL, NOT ON A CALL COUNT**, and that is the difference
// between this step measuring re-establishment and measuring "the second call
// works". A driver that succeeded on its second invocation would pass under
// D203's nested placement, under D204's re-entry, and under a bare retry that
// re-minted nothing — three designs the step is supposed to tell apart. Keyed on
// the bytes, it succeeds only if fresh material actually reached it.
type rejectingDriver struct {
	mu       sync.Mutex
	rejected []string
	accepted []string

	// between runs after the far side has rejected, and is how an arm makes
	// something change BETWEEN the two attempts — a suspension, an exhausted
	// budget, an opened breaker. That window is the whole subject of D204: a
	// nested retry at step 5 would never look again.
	between func()

	// stale is the material the far side refuses. Everything else is accepted.
	stale string

	// rejectAll makes the far side refuse whatever it is shown, which is the
	// case where a SECOND mint cannot help either.
	rejectAll bool

	// unmarked refuses with a bare `unauthenticated` — the shape a BORROW
	// failure has (D199's placement refusal, or a credential wiped by
	// break-glass). Same kind as a far-side 401 and must NOT be re-established.
	unmarked bool
}

func (d *rejectingDriver) Kind() string { return "reest" }

func (d *rejectingDriver) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{{
		Name:     "reest.write",
		Mutating: true,
		// NATURAL, so D163's gate does not refuse the repeat — the arm that
		// proves a `none`-class action is NOT repeated uses its own action
		// below. An upsert keyed on the caller's own identifier needs no key.
		Idempotency: connector.IdempotencyNatural,
		InputSchema: "sekizui://schema/reest/write.v1",
		Description: "Write, rejecting a stale credential the way a far side would.",
	}, {
		Name:        "reest.append",
		Mutating:    true,
		Idempotency: connector.IdempotencyNone,
		InputSchema: "sekizui://schema/reest/append.v1",
		Description: "Append, with no idempotency of any kind. Never safely repeated.",
	}}
}

func (d *rejectingDriver) Execute(_ context.Context, t connector.Target, action string,
	_ map[string]any, _ connector.Idempotency) (connector.Result, error) {

	var seen string
	if err := t.UseRaw(func(material []byte) error {
		seen = string(material)
		return nil
	}); err != nil {
		return connector.Result{}, fault.Wrap(fault.KindUnauthenticated, "reest.Execute",
			"the target's credential could not be borrowed", err)
	}

	d.mu.Lock()
	fresh := !d.rejectAll && seen != d.stale
	if fresh {
		d.accepted = append(d.accepted, seen)
	} else {
		d.rejected = append(d.rejected, seen)
	}
	between := d.between
	d.mu.Unlock()

	if fresh {
		return connector.Result{StatusCode: 200, ExternalRef: action + ":ok"}, nil
	}
	if between != nil {
		between()
	}
	if d.unmarked {
		// **THE BORROW FAILURE, VERBATIM FROM THE REAL DRIVERS.** Same kind as
		// the 401 below, no marker — because re-minting returns the same bad
		// bytes (D199) or fetches material break-glass just wiped.
		return connector.Result{}, fault.Wrap(fault.KindUnauthenticated, "reest.Execute",
			"the target's credential could not be borrowed", errUnusableMaterial)
	}
	// THE MARKED 401, THROUGH THE SAME CONSTRUCTOR THE REAL DRIVERS USE. A fake
	// far side that hand-built the error would be testing a marking the product
	// does not perform, which is how a guard comes to be true of the tests and
	// false of the code.
	return connector.Result{}, fault.CredentialRejected("reest.Execute",
		"the far side returned 401: credential rejected")
}

func (d *rejectingDriver) Query(context.Context, connector.Target, string,
	map[string]any) (connector.Rows, error) {
	return connector.Rows{}, nil
}

func (d *rejectingDriver) Health(context.Context, connector.Target) error { return nil }

func (d *rejectingDriver) counts() (rejected, accepted int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.rejected), len(d.accepted)
}

// errUnusableMaterial stands in for what `connector.SetAuthorization` returns
// when the credential cannot BE a header value (D199).
var errUnusableMaterial = errors.New("the credential ends with a newline")

// --- the fixture ------------------------------------------------------------

type reestFixture struct {
	gw          *gateway.Server
	prov        *rotatingProvider
	drv         *rejectingDriver
	revocations *policy.Revocations
	metrics     *metrics.Registry
	churn       *churn.Counter
	path        string
}

// reestOpts are the ceilings an arm wants to control. The zero value is a
// healthy deployment, which is what most arms want.
type reestOpts struct {
	limits  *config.TargetLimits
	rate    pkglimiter.Limiter
	breaker pkglimiter.Breaker

	// between runs on the far side's rejection, so an arm can change something
	// in the window a nested retry would never look at again.
	between func()

	// churn is the tally the enforcement path writes. Supplied when an arm needs
	// to control its clock or read its level.
	churn *churn.Counter
}

func newReestFixture(t *testing.T, o reestOpts) *reestFixture {
	limits := o.limits

	t.Helper()
	ctx := context.Background()

	doc := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "reest:one", Kind: "reest", Tenant: "acme",
			CredentialRef: "rot://key", Limits: limits,
		}},
		Grants: []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "reest.write", TargetRef: "reest:one"},
				{Action: "reest.append", TargetRef: "reest:one"},
			},
		}},
	}

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Stop(context.Background()) })

	prov := &rotatingProvider{}
	drv := &rejectingDriver{stale: "token-1", between: o.between}
	revs := policy.NewRevocations()

	breaker := o.breaker
	if breaker == nil {
		breaker = limiter.NewBreaker(5, time.Minute)
	}

	retryPolicies := map[string]retry.Policy{}
	if limits != nil && limits.ReestablishAttempts > 0 {
		retryPolicies["reest:one"] = retry.Policy{
			MaxAttempts:         1,
			ReestablishAttempts: int(limits.ReestablishAttempts),
		}
	}

	tally := o.churn
	if tally == nil {
		tally = churn.New()
	}
	reg := metrics.New()

	f := &reestFixture{prov: prov, drv: drv, revocations: revs,
		metrics: reg, churn: tally, path: path}
	f.gw = gateway.New(gateway.Config{
		Doc:      doc,
		Policy:   policy.NewGrantEngine(doc, nil),
		Resolver: resolver.New(doc, runtime.Profile{}, nil, prov),
		Drivers:  map[string]connector.Driver{"reest": drv},
		Guards:   anzen.New(nil),
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc)),
		// ONE ATTEMPT AT THE CALL, so nothing in this step is explained by step
		// 8c's retry loop. What it measures is the traversal above it.
		Retry:       retry.New(retry.Policy{MaxAttempts: 1}, retry.WithTargetPolicies(retryPolicies)),
		Revocations: revs,
		Churn:       tally,
		Metrics:     reg,
		Breaker:     breaker,
		Rate:        o.rate,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return f
}

// exhaustAfter is a limiter with budget for N calls and none after.
//
// **A STUB RATHER THAN A REAL LIMITER DRAINED BY REAL TRAFFIC, and the reason is
// what the arm is about.** What must be modelled is a budget that runs out
// BETWEEN the two attempts — most realistically because another principal spent
// it, which is precisely §4.3.4's shared-quota shape. Draining a real bucket
// from inside attempt 1 would need concurrent traffic and a clock, and would
// prove the bucket works rather than that the second traversal consults it.
type exhaustAfter struct {
	mu    sync.Mutex
	left  int
	asked int
}

func (l *exhaustAfter) Allow(context.Context, pkglimiter.Request) (bool, time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asked++
	if l.left <= 0 {
		return false, 30 * time.Second, nil
	}
	l.left--
	return true, 0, nil
}

func (l *exhaustAfter) Observe(context.Context, pkglimiter.Request, int, time.Duration) {}

func (l *exhaustAfter) times() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.asked
}

// openAfter is a breaker that is closed for N checks and open after.
//
// **IT CANNOT BE THE REAL BREAKER, AND FINDING THAT OUT IS WORTH RECORDING.**
// The first draft tripped a real breaker from inside the driver, five recorded
// failures deep, and the second attempt went out anyway — because D141 is
// working: a 401 is DELIBERATE, so `ImplicatesTarget` is false, so the gateway
// records attempt 1 as a SUCCESS and the consecutive-failure count resets. That
// is the same property that makes `credential_churn` necessary at all, arriving
// as a test failure. The condition to model is therefore a breaker opened by
// OTHER traffic on the same target, which is what this is.
type openAfter struct {
	mu     sync.Mutex
	closed int
	asked  int
}

func (b *openAfter) Allow(string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asked++
	if b.closed <= 0 {
		return false
	}
	b.closed--
	return true
}

func (b *openAfter) Record(string, bool) {}

func (b *openAfter) State(string) string { return "open" }

func (f *reestFixture) write(t *testing.T, action string) (*sekizuiv1.CommandResult, error) {
	t.Helper()
	return f.gw.Enforce(context.Background(), assertedIdentity("agent:dev"),
		&sekizuiv1.Command{
			Action: action, TargetRef: "reest:one",
			Args: mustArgs(t, map[string]any{"body": "x"}),
		})
}

// step42ACredentialIsReestablishedByRetraversingThePath is D203's marker and
// D204's vehicle, proven together because neither is meaningful alone.
//
// **THE HARD PART IS TELLING THE TWO DESIGNS APART.** On a healthy deployment,
// D203's nested retry at step 5 and D204's full re-entry behave identically:
// both invalidate, both re-mint, both succeed, both write an audit row. The
// difference is only observable when something changes BETWEEN the attempts —
// which is exactly the window a nested retry cannot see, and exactly what an
// operator pulling a lever mid-incident is doing. So four of the six arms below
// change something in that window and require the second attempt to be refused.
func step42ACredentialIsReestablishedByRetraversingThePath(t *testing.T) {
	// --- 42a: THE MECHANISM WORKS AT ALL -----------------------------------
	t.Run("a rejected credential is re-minted and the call succeeds", func(t *testing.T) {
		f := newReestFixture(t, reestOpts{})

		res, err := f.write(t, "reest.write")
		if err != nil {
			t.Fatalf("42a: %v", err)
		}
		if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("42a: the command was refused (%s: %s). The far side rejected a stale "+
				"credential and Sekizui is the only party that can re-mint it (D182)",
				res.GetKind(), res.GetReason())
		}

		rejected, accepted := f.drv.counts()
		if rejected != 1 || accepted != 1 {
			t.Errorf("42a: far side saw %d rejected and %d accepted credential(s), want 1 "+
				"and 1. Keyed on the MATERIAL, so this only passes if fresh bytes "+
				"actually arrived — not merely if a second call was made", rejected, accepted)
		}
		if got := f.prov.resolves(); got != 2 {
			t.Errorf("42a: the provider was asked %d time(s), want 2. One cold resolve "+
				"plus one forced by the invalidation; anything else means the cache was "+
				"not invalidated or was invalidated more than once", got)
		}
	})

	// --- 42b: THE AUDIT TRACE, WITH NO FIELD INVENTED FOR IT ---------------
	//
	// The residual raised before any of this was built: *the second attempt has
	// to be visible in the audit as an attempt, or it is a silent extra call on
	// someone else's system.* Re-entry closes it by construction — two
	// traversals write two intent rows and two outcome rows through the code
	// that already writes them.
	t.Run("both attempts are in the log, linked, with different credential versions",
		func(t *testing.T) {
			f := newReestFixture(t, reestOpts{})
			res, err := f.write(t, "reest.write")
			if err != nil {
				t.Fatalf("42b: %v", err)
			}

			// **WALKED BACKWARDS FROM THE ID THE CALLER GOT, NOT COUNTED OUT OF
			// THE FILE.** The first draft counted intent rows and passed alone
			// and failed under `make acceptance`, where every step shares one
			// log — 167 rows instead of 2. Scoping it by id is not a workaround:
			// it is the property D202 actually promises, which is that the
			// caller can NAME its row and reach the rest of the chain from
			// there. A count proved neither.
			second := rowsWithID(t, f.path, res.GetDecisionId())
			if len(second) != 2 {
				t.Fatalf("42b: the returned decision id names %d row(s), want 2 "+
					"(intent, outcome)", len(second))
			}

			parent := second[0].GetCausation().GetParentId()
			if parent == "" {
				t.Fatal("42b: the second attempt's row names no causation parent. The " +
					"caller receives attempt 2's id and walks BACKWARDS; nothing on " +
					"attempt 1 can name a successor that did not exist yet")
			}
			first := rowsWithID(t, f.path, parent)
			if len(first) != 2 {
				t.Fatalf("42b: attempt 2 names parent %q and the log has %d row(s) for "+
					"it, want 2. A second call went out on somebody's system and the "+
					"log has to say so — which is what a nested retry at step 5 would "+
					"NOT have done, because it never reaches step 7 a second time",
					parent, len(first))
			}

			if got := second[0].GetCausation().GetProducedBy(); !strings.HasPrefix(got, "reestablish:") {
				t.Errorf("42b: attempt 2's produced_by is %q, want a `reestablish:` "+
					"prefix. \"Why was this target called twice at 14:03\" is the "+
					"question, and the answer should be one field away", got)
			}

			// **THE PART THAT NEEDED NO NEW FIELD.** credential_posture.version is
			// already on every row (D130), so the pair says which version drew the
			// 401 and which replaced it.
			v1, v2 := first[0].GetCredentialPosture().GetVersion(), second[0].GetCredentialPosture().GetVersion()
			if v1 == "" || v2 == "" {
				t.Fatalf("42b: credential versions are %q and %q; the trace depends on "+
					"the posture already being recorded", v1, v2)
			}
			if v1 == v2 {
				t.Errorf("42b: both rows record credential version %q, so the log cannot "+
					"show that a re-mint happened. Either the cache was not invalidated "+
					"or the posture is stamped from something that did not change", v1)
			}
		})

	// --- 42c: EVERY CEILING RE-RUNS — THE ARM THAT IS THE DECISION ---------
	//
	// Each of these changes something between the two attempts and requires the
	// second one to be refused. Under D203's nested placement every one of them
	// would have gone out: a retry from step 5 skips the runtime revocation
	// check (D146), policy, break-glass placement (D129), the limiter (D143) and
	// the breaker (D141).
	t.Run("a principal suspended between the attempts does not get the second call",
		func(t *testing.T) {
			var f *reestFixture
			f = newReestFixture(t, reestOpts{between: func() {
				f.revocations.Revoke(policy.Revocation{
					Principal: "agent:dev", Reason: "42c: proving the ceiling re-runs",
					Trigger: "operator:oncall", At: time.Now(),
				})
			}})

			res, _ := f.write(t, "reest.write")
			if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
				t.Fatal("42c: the command SUCCEEDED after its principal was suspended " +
					"mid-command. D146's lever is the bluntest ceiling there is — " +
					"\"may this principal do ANYTHING right now\" — and a second attempt " +
					"that does not re-ask it is a call going out under a grant an " +
					"operator has already pulled")
			}
			if _, accepted := f.drv.counts(); accepted != 0 {
				t.Errorf("42c: the far side accepted %d call(s) after the suspension. The "+
					"refusal must happen BEFORE the driver, not be reported after it",
					accepted)
			}
			if !strings.Contains(res.GetReason(), "suspended") {
				t.Errorf("42c: the refusal reads %q, which does not name the suspension. "+
					"An operator seeing a refusal for a call they did not make needs "+
					"the reason to be the real one", firstSentence(res.GetReason()))
			}
		})

	t.Run("a breaker opened between the attempts does not get the second call",
		func(t *testing.T) {
			// CLOSED FOR ATTEMPT 1, OPEN FOR ATTEMPT 2 — a target that went down
			// under somebody else's traffic in the window between them.
			b := &openAfter{closed: 1}
			f := newReestFixture(t, reestOpts{breaker: b})

			_, err := f.write(t, "reest.write")
			if err == nil {
				t.Fatal("42c: the second attempt went out at a target whose breaker had " +
					"opened. The breaker is checked immediately before the call and not " +
					"earlier (D141), and a re-attempt that skips it is a call at a target " +
					"Sekizui is trying to leave alone")
			}
			if fault.KindOf(err) != fault.KindTargetUnavailable {
				t.Errorf("42c: the refusal is %v, want target_unavailable", fault.KindOf(err))
			}
			if b.asked < 2 {
				t.Errorf("42c: the breaker was consulted %d time(s). The second traversal "+
					"must ask it again, which is the whole difference from a nested "+
					"retry at step 5", b.asked)
			}
		})

	// **AND THIS IS THE ARM THAT REPAIRS D203'S OWN CAP ARGUMENT.** D203 says no
	// per-hour knob is needed because `rate_per_hr` already bounds
	// re-establishment. Under its own nested placement that was FALSE — the
	// second call never reaches `rate.Allow`, so the real bound was twice the
	// configured rate. Under re-entry it is true, and this is what says so.
	t.Run("the second attempt spends rate-limit budget like any other call",
		func(t *testing.T) {
			l := &exhaustAfter{left: 1}
			f := newReestFixture(t, reestOpts{rate: l})

			res, _ := f.write(t, "reest.write")
			if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
				t.Fatal("42c: the second attempt went out on an exhausted budget. " +
					"`rate_per_hr` is one of the two mechanisms D203 says bounds " +
					"re-establishment per hour, and it only does if the re-attempt " +
					"is charged for")
			}
			if got, _ := fault.ParseKind(res.GetKind()); got != fault.KindRateLimited {
				t.Errorf("42c: the refusal is %q, want rate_limited", res.GetKind())
			}
			if l.times() != 2 {
				t.Errorf("42c: the limiter was asked %d time(s), want 2 — one per "+
					"traversal. A second call on somebody's system that costs no budget "+
					"is an amplification the configuration cannot see", l.times())
			}
		})

	// --- 42d: D163'S CLASS STILL GATES IT ----------------------------------
	//
	// A 401 normally means the far side rejected before executing — and
	// "normally" is not a guarantee for every vendor, so a `none`-class action
	// is never silently repeated for a reason that looks benign.
	t.Run("a none-class action is not repeated even to re-establish", func(t *testing.T) {
		f := newReestFixture(t, reestOpts{})

		res, err := f.write(t, "reest.append")
		if err == nil && res.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Fatal("42d: a `none`-class action was repeated to re-establish a " +
				"credential. D163 exists because a repeat of that action can double-write, " +
				"and \"the far side probably did not act\" is not a guarantee")
		}
		if rejected, accepted := f.drv.counts(); rejected != 1 || accepted != 0 {
			t.Errorf("42d: far side saw %d rejected and %d accepted, want 1 and 0", rejected, accepted)
		}
		if got := f.prov.resolves(); got != 1 {
			t.Errorf("42d: the provider was asked %d time(s), want 1. A refused "+
				"re-establishment must not still spend a mint against the secret "+
				"manager — that is the amplification with none of the benefit", got)
		}
	})

	// --- 42e: THE SWITCH -----------------------------------------------------
	t.Run("reestablish_attempts 1 switches it off", func(t *testing.T) {
		f := newReestFixture(t, reestOpts{limits: &config.TargetLimits{ReestablishAttempts: 1}})

		res, _ := f.write(t, "reest.write")
		if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Fatal("42e: `reestablish_attempts: 1` did not switch re-establishment off. " +
				"One means never, and it is expressible only because the field copies " +
				"`retry_attempts`' escape from the zero-means-unlimited trap")
		}
		if got := f.prov.resolves(); got != 1 {
			t.Errorf("42e: the provider was asked %d time(s) with the mechanism off, want 1", got)
		}
	})

	// --- 42h: THE MARKER IS PER-ERROR, AND THIS IS THE ARM THAT SAYS SO ------
	//
	// **THE OTHER FOUR PRODUCERS OF `unauthenticated` MUST NOT RE-ESTABLISH**,
	// and a kind-based marker would be wrong for every one of them. This drives
	// the borrow failure — D199's placement refusal and a break-glass wipe share
	// its shape — which is the same KIND as a far-side 401 and the opposite
	// remedy: re-minting returns the same bad bytes, or fetches material an
	// operator has just wiped.
	//
	// WITHOUT THIS ARM THE WHOLE MARKER IS UNTESTED, which `make mutate` said
	// before it existed: replacing `fault.ReestablishOf(outcomeErr)` with
	// `KindOf(outcomeErr) == KindUnauthenticated` SURVIVED, because every other
	// arm drives an error that is marked. A step that only drives the case it
	// wants proves the mechanism fires, never that it discriminates.
	t.Run("an unmarked unauthenticated is not re-established", func(t *testing.T) {
		f := newReestFixture(t, reestOpts{})
		f.drv.mu.Lock()
		f.drv.unmarked = true
		f.drv.mu.Unlock()

		// **CHECKED ON THE RESULT, NOT THE ERROR** — `unauthenticated` is
		// deliberate, so D135 carries it to the caller as a CommandResult and
		// `err` is nil. The first draft of this arm checked the error and failed
		// itself for the right reason: it was measuring nothing.
		res, err := f.write(t, "reest.write")
		if err == nil && res.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Fatal("42h: a borrow failure succeeded, so this arm measures nothing")
		}
		if got := f.prov.resolves(); got != 1 {
			t.Errorf("42h: the provider was asked %d time(s), want 1. A credential that "+
				"cannot be PLACED is not a credential that is stale: re-minting returns "+
				"the same bytes, so this spends a mint against the secret manager and "+
				"refuses again. On D152's downgrade guard the same mistake would retry "+
				"the rollback an attacker is trying to make us accept", got)
		}
		if rejected, _ := f.drv.counts(); rejected != 1 {
			t.Errorf("42h: the far side was called %d time(s), want 1", rejected)
		}
	})

	// --- 42g: THE DOWNGRADE GUARD SURVIVES THE INVALIDATION ------------------
	t.Run("a forced re-resolve that rolls backwards is still refused",
		step42TheDowngradeGuardSurvivesInvalidation)

	// --- 42f: IT HAPPENS EXACTLY ONCE ---------------------------------------
	t.Run("a far side that rejects everything is not re-established twice", func(t *testing.T) {
		f := newReestFixture(t, reestOpts{})
		// REJECTS WHATEVER IT IS SHOWN. If the freshly minted credential is also
		// rejected, minting a third returns the same thing — so a third attempt
		// buys nothing and spends a call plus a mint.
		f.drv.mu.Lock()
		f.drv.rejectAll = true
		f.drv.mu.Unlock()

		res, _ := f.write(t, "reest.write")
		if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
			t.Fatal("42f: a far side rejecting every credential reported success")
		}
		if got := f.prov.resolves(); got != 2 {
			t.Errorf("42f: the provider was asked %d time(s), want 2 — one cold resolve "+
				"and exactly one forced. A third means the loop is unbounded, which is "+
				"the amplification primitive a hostile target reaches by returning 401", got)
		}
		rejected, _ := f.drv.counts()
		if rejected != 2 {
			t.Errorf("42f: the far side saw %d call(s), want 2", rejected)
		}
	})
}

// step43ChurnIsALevelThatQuarantinesTheTarget is D204's response half, and it is
// load-bearing rather than advisory.
//
// **THE ACCEPTED TRADE IS THAT AN ATTACKER MAY FORCE AN OUTAGE OF THE TARGET
// THEY ARE ATTACKING.** Without a quarantine the shape does not deliver that
// trade — it delivers a fleet-wide one, through two resources every target
// shares: the audit WAL, which fsyncs per record with no rotation and fails
// CLOSED for everybody when it fills, and the secret manager's own quota. So
// this step is not "the signal is nice to have"; it is what keeps the per-target
// outage per-target (CONTRACTS 78).
func step43ChurnIsALevelThatQuarantinesTheTarget(t *testing.T) {
	ctx := context.Background()

	// --- 43a: ONE LEGITIMATE EXPIRY DOES NOT RAISE IT ----------------------
	//
	// The half that makes the signal usable. A credential that expired once and
	// was re-minted is a working deployment doing exactly what it was built to
	// do, and firing on it would quarantine a healthy target — D77's crying wolf,
	// which D203 forbids in the same sentence that introduced the signal.
	t.Run("one re-establishment is an expiry and does not raise the level", func(t *testing.T) {
		f := newReestFixture(t, reestOpts{})
		if _, err := f.write(t, "reest.write"); err != nil {
			t.Fatalf("43a: %v", err)
		}

		if got := f.churn.Churning(); len(got) != 0 {
			t.Errorf("43a: one re-establishment raised credential_churn for %v. A rule "+
				"watching this quarantines a target, and a signal that fires on a "+
				"single expiry would take a healthy target out of service for "+
				"rotating its own credential", got)
		}
		// AND IT WAS COUNTED, or the arm above passes because nothing happened —
		// a quiet signal and an absent one look identical from the level alone.
		var b strings.Builder
		if _, err := f.metrics.WriteTo(&b); err != nil {
			t.Fatalf("43a: scraping: %v", err)
		}
		// **THE WHOLE LINE, LABEL INCLUDED, NOT A SUBSTRING.** A containment check
		// over a namespaced metric name cannot tell "present" from "present with
		// a prefix glued on" — the first version of this arm passed against
		// `sekizui_sekizui_credential_churn_total`, because the right name is a
		// substring of the doubled one. `archcheck.TestCounterNamesAreUnprefixed`
		// stops the cause; pinning the line stops the arm being fooled again.
		want := `sekizui_credential_churn_total{target="reest:one"} 1`
		if !strings.Contains(b.String(), want+"\n") {
			t.Errorf("43a: the scrape does not show one re-establishment for this "+
				"target. Want %q. Without it the arm above proves the signal is "+
				"quiet rather than that it is correct:\n%s", want, b.String())
		}
	})

	// --- 43b: A CHURNING TARGET DOES, AND THE LEVEL FALLS ------------------
	//
	// **THE EVENT-VERSUS-LEVEL FAILURE, DRIVEN IN BOTH DIRECTIONS.** Published as
	// a raw event this is one of two wrong things: latched forever, masking every
	// later churn, or an edge per re-establishment that fires on the first
	// expiry. A level rises, holds, and FALLS — and the fall is what re-arms the
	// rule, so a second incident after a lifted quarantine fires again.
	t.Run("a churning target raises the level, and it falls when the window empties",
		func(t *testing.T) {
			clock := time.Unix(0, 0).UTC()
			tally := churn.New(churn.WithClock(func() time.Time { return clock }))

			tally.Record("reest:one")
			if got := tally.Churning(); len(got) != 0 {
				t.Fatalf("43b: one event raised the level: %v", got)
			}

			clock = clock.Add(time.Minute)
			tally.Record("reest:one")
			raised := tally.Churning()
			if _, on := raised["reest:one"]; !on {
				t.Fatal("43b: two re-establishments inside the window did not raise " +
					"credential_churn. Two is not an expiry — a freshly minted " +
					"credential was rejected too, or the target is rejecting on purpose")
			}
			if !strings.Contains(raised["reest:one"], "reest:one") {
				t.Errorf("43b: the detail does not name the target: %q", raised["reest:one"])
			}

			// **STILL RAISED WHILE THE CONDITION HOLDS.** A level that fell on
			// being read would re-arm the rule immediately and produce the flood
			// the dispatcher's latch exists to prevent.
			if got := tally.Churning(); len(got) != 1 {
				t.Errorf("43b: the level fell on being read (%v). It must hold while the "+
					"condition does, or the latch re-arms every tick", got)
			}

			clock = clock.Add(churn.DefaultWindow + time.Minute)
			if got := tally.Churning(); len(got) != 0 {
				t.Errorf("43b: the level is still raised %v after the window emptied. "+
					"A level that never falls fires once and then MASKS every "+
					"subsequent churn, which is worse than not having it", got)
			}
		})

	// --- 43c: A WATCHING RULE QUARANTINES THE TARGET -----------------------
	//
	// End to end through the real dispatcher and real guards, so this also proves
	// the signal name is in the CLOSED vocabulary — a rule watching a signal boot
	// does not know is refused at load, which is how `credential_stale` was found
	// to have no producer.
	t.Run("a rule watching it quarantines the churning target, once per edge",
		func(t *testing.T) {
			guards := anzen.New([]config.AnzenSpec{{
				Name: "quarantine-churn", Enabled: true, Mode: "enforce",
				Watches: "credential_churn",
				// STOP RESOLVING, which is where the mint happens — the action is
				// aimed at the amplification primitive itself. NOT
				// `revoke_credential`: churn is evidence the TARGET is rejecting,
				// not that the material leaked, and wiping a good credential is
				// D106's severity for a different fact.
				Do: "quarantine_target", Subject: "reest:one",
			}})

			var fired []string
			d := anzen.NewDispatcher(guards, func(_ context.Context, rule string) error {
				fired = append(fired, rule)
				return nil
			}, slog.New(slog.NewTextHandler(io.Discard, nil)))

			raised := map[string]string{"reest:one": "forced 2 re-establishments"}
			d.Observe(ctx, "credential_churn", raised)
			d.Observe(ctx, "credential_churn", raised)

			if len(fired) != 1 {
				t.Fatalf("43c: the rule fired %d time(s) for one raised condition, want 1. "+
					"One condition, one response — a rule firing per tick is the flood "+
					"D158's latch exists to prevent, and every one of them would be a "+
					"quarantine attempt", len(fired))
			}
			if fired[0] != "quarantine-churn" {
				t.Errorf("43c: %q fired, want quarantine-churn", fired[0])
			}

			// AND THE FALL RE-ARMS IT. Nothing auto-lifts the withdrawal — that is
			// durable and needs `restore_target` (D133, D145) — but the RULE must
			// be able to fire again for a second incident.
			d.Observe(ctx, "credential_churn", nil)
			d.Observe(ctx, "credential_churn", raised)
			if len(fired) != 2 {
				t.Errorf("43c: the rule did not re-arm after the level fell (%d firings). "+
					"A one-shot rule protects a target once and then never again",
					len(fired))
			}
		})

	// --- 43d: THE COUNTER LEAVES THE BOX -----------------------------------
	//
	// **THE PERIMETER READS THE COUNTER, NOT THE WAL.** The audit log is local and
	// the warehouse is descoped from this phase (D169), so the WAL explains an
	// incident afterwards — it is not what holds the line during one. Driven
	// through the SCRAPE SURFACE rather than off the struct, because a counter
	// nothing can scrape proves nothing about what a perimeter would see.
	t.Run("the churn counter is on the scrape surface", func(t *testing.T) {
		f := newReestFixture(t, reestOpts{})
		if _, err := f.write(t, "reest.write"); err != nil {
			t.Fatalf("43d: %v", err)
		}

		var b strings.Builder
		if _, err := f.metrics.WriteTo(&b); err != nil {
			t.Fatalf("43d: scraping: %v", err)
		}
		// **LABELLED BY TARGET, WHICH IS THE HALF THAT MAKES IT ACTIONABLE.** A
		// perimeter told that churn is happening somewhere cannot scope a
		// response, and scoping a response is most of what a perimeter does. The
		// audit row and the anzen signal both name the target; the counter is the
		// only one of the three that leaves the process in time to matter, so it
		// has to name it too.
		want := `sekizui_credential_churn_total{target="reest:one"}`
		if !strings.Contains(b.String(), want) {
			t.Errorf("43d: the churn counter is not in /metrics keyed by target. Want a "+
				"line starting %q. Sekizui's job during an amplification is to hold out "+
				"long enough for the perimeter to act, and the perimeter cannot read a "+
				"value that never leaves the process — nor act on one that does not say "+
				"WHERE:\n%s", want, b.String())
		}
	})

	// --- 43e: THE COST OF THE CHATTER, MEASURED ----------------------------
	//
	// **THE EXTRA ROWS ARE SIGNAL AND THEY ARE NOT FREE.** The ruling is the maintainer's —
	// *"like your body signalling pain constantly; don't numb it, fix the
	// issue"* — and this arm is what keeps that ruling honest: the price is a
	// number in the acceptance output rather than a judgement in a document.
	//
	// **THE ROW COUNT IS ASSERTED AND THE LATENCY IS REPORTED**, deliberately. The
	// WAL fsyncs per record, so four records instead of two is the cost driver and
	// is deterministic; the wall-clock consequence depends on the disk under the
	// test and asserting a threshold on it would be a flake, not a guarantee.
	t.Run("a re-established command costs four audit records, and the latency is measured",
		func(t *testing.T) {
			plain := newReestFixture(t, reestOpts{})
			plain.drv.mu.Lock()
			plain.drv.stale = "" // accepted first time: no re-establishment
			plain.drv.mu.Unlock()

			startPlain := time.Now()
			plainRes, err := plain.write(t, "reest.write")
			if err != nil {
				t.Fatalf("43e: %v", err)
			}
			tookPlain := time.Since(startPlain)

			reest := newReestFixture(t, reestOpts{})
			startReest := time.Now()
			reestRes, err := reest.write(t, "reest.write")
			if err != nil {
				t.Fatalf("43e: %v", err)
			}
			tookReest := time.Since(startReest)

			// SCOPED BY DECISION ID, for the reason 42b records: `make acceptance`
			// points every step at one log, so a count over the file measures the
			// suite rather than the command.
			plainRows := rowsWithID(t, plain.path, plainRes.GetDecisionId())
			if len(plainRows) != 2 {
				t.Fatalf("43e: a plain command wrote %d record(s), want 2 (intent, outcome)",
					len(plainRows))
			}

			secondRows := rowsWithID(t, reest.path, reestRes.GetDecisionId())
			firstRows := rowsWithID(t, reest.path, secondRows[0].GetCausation().GetParentId())
			if got := len(firstRows) + len(secondRows); got != 4 {
				t.Errorf("43e: a re-established command wrote %d record(s), want 4 — two "+
					"traversals, each writing its own intent and outcome. Fewer means an "+
					"attempt is missing from the log, which is the silent extra call on "+
					"somebody's system this design exists to refuse", got)
			}

			t.Logf("D204 cost: a plain command took %v (2 fsynced records); a "+
				"re-established one took %v (4). The extra rows are the trace, and "+
				"this is what they cost on the enforcement path",
				tookPlain.Round(time.Microsecond), tookReest.Round(time.Microsecond))
		})
}

// step42TheDowngradeGuardSurvivesInvalidation is the arm the artefact table
// names, and it is instance ~eighteen of the recurring class caught before it
// landed rather than after.
//
// **`Invalidate` DROPS THE CACHED ENTRY AND MUST NOT TOUCH THE VERSION MARK.**
// The two live in the same struct behind different mutexes, and a new code path
// that had no reason to know D152's guard existed is exactly how a guard's state
// gets discarded — a value produced, recorded, and dropped by the next author.
// The cost of getting it wrong is specific: the guard would lose its memory on
// the one path an attacker can trigger on demand, which is the path it most
// needs it on.
func step42TheDowngradeGuardSurvivesInvalidation(t *testing.T) {
	ctx := context.Background()

	doc := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "reest:one", Kind: "reest", Tenant: "acme", CredentialRef: "rot://key",
		}},
		Grants: []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "reest.write", TargetRef: "reest:one"},
			},
		}},
	}

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer func() { _ = sink.Stop(context.Background()) }()

	// THE REAL CACHE WITH THE REAL MARK STORE, not a stub — the property under
	// test is that two pieces of one struct's state are treated differently by
	// one new method, and a stub would be asserting against my own model of it.
	cache := credential.New([]config.Provider{&rollbackProvider{}},
		credential.WithVersionMarks(credential.NewMarkFileStore(credential.MarkPathFor(path))))

	gw := gateway.New(gateway.Config{
		Doc:      doc,
		Policy:   policy.NewGrantEngine(doc, nil),
		Resolver: resolver.NewWithCache(doc, runtime.Profile{}, nil, cache),
		// REJECTS `token-2`, which is what the FIRST resolve hands back — so the
		// far-side 401 forces a re-resolve, and the re-resolve rolls back.
		Drivers:  map[string]connector.Driver{"reest": &rejectingDriver{stale: "token-2"}},
		Guards:   anzen.New(nil),
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc)),
		Retry:    retry.New(retry.Policy{MaxAttempts: 1}),
		Churn:    churn.New(),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	res, err := gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "reest.write", TargetRef: "reest:one",
		Args: mustArgs(t, map[string]any{"body": "x"}),
	})
	if err == nil && res.GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Fatal("42g: a forced re-resolve picked up an OLDER credential version and the " +
			"call succeeded. That is the attack's most valuable outcome — a rolled-back " +
			"credential accepted — reached through the one path an outsider can trigger " +
			"on demand by returning 401. D152's guard must still refuse it, which means " +
			"`Invalidate` must drop the cached entry and leave the high-water mark alone")
	}

	// **AND IT IS REFUSED AS A CREDENTIAL PROBLEM, NOT AS RESIDENCY** (D201). The
	// row is what somebody reviews six months later, and a downgrade recorded as
	// a data-residency decision is a control that fired correctly and explained
	// itself wrongly.
	var refusal *sekizuiv1.Decision
	for _, r := range readLog(t, path) {
		if r.GetRefusedBy() == sekizuiv1.RefusedBy_REFUSED_BY_CREDENTIAL {
			refusal = r
		}
	}
	if refusal == nil {
		t.Fatalf("42g: no row records a credential refusal. Result was %s/%s, err %v",
			res.GetStatus(), res.GetKind(), err)
	}
	if !strings.Contains(refusal.GetReason(), "1") {
		t.Errorf("42g: the refusal does not name the version it refused: %.160s",
			refusal.GetReason())
	}
}

// rowsWithID returns every audit row carrying one decision id.
//
// **BY ID RATHER THAN BY COUNTING THE FILE**, because `make acceptance` points
// every step at one shared log (`SEKIZUI_ACCEPTANCE_OUT`) so a human has one
// artefact to read. Two arms here were written counting rows, passed under `go
// test` where each gets a temp file, and failed under `make acceptance` with 167
// and 438 rows — which is the run doing its job, and the reason the assertions
// are now scoped the way a reader would scope them.
func rowsWithID(t *testing.T, path, id string) []*sekizuiv1.Decision {
	t.Helper()

	var out []*sekizuiv1.Decision
	for _, r := range readLog(t, path) {
		if r.GetId() == id {
			out = append(out, r)
		}
	}
	return out
}

// Schemas: this double declares no output type, so it ships no schema (D279).
func (d *rejectingDriver) Schemas() ([]connector.Schema, error) { return nil, nil }
func (d *rejectingDriver) Meter() connector.Meter               { return connector.Meter{} }
