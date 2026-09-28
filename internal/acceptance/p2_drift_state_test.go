package acceptance

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/catalog"
	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/spine"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// capturingObserver records what the watcher published, so a step can assert
// the SIGNAL rather than a log line.
//
// A FAKE OBSERVER RATHER THAN A REAL DISPATCHER, deliberately: the question
// here is what level the watcher reports and under which severities, and a real
// dispatcher would answer it through a rule set — making the assertion depend
// on rule matching, which D157's own steps already cover.
//
// **MUTEX-GUARDED, AND `-race` IS WHAT SAID SO.** Step 12 starts the REAL
// watcher, so `Observe` is called from its poll goroutine while the step reads
// what was captured — a textbook data race, and the first version of this had
// none of the locking. It passed every run under `go test` and failed under
// `make ci`, which is the argument for -race being in `verify` rather than
// something to run when a test looks flaky. The production observer
// (`anzen.Dispatcher`) has always locked; only the fake was unsound.
type capturingObserver struct {
	mu       sync.Mutex
	signals  []string
	subjects []map[string]string
}

func (o *capturingObserver) Observe(_ context.Context, signal string,
	subjects map[string]string) []string {

	o.mu.Lock()
	defer o.mu.Unlock()

	o.signals = append(o.signals, signal)
	copied := map[string]string{}
	for k, v := range subjects {
		copied[k] = v
	}
	o.subjects = append(o.subjects, copied)
	return nil
}

// captured returns a snapshot, so an assertion reads a stable value rather than
// a slice the watcher may append to mid-comparison.
func (o *capturingObserver) captured() ([]string, []map[string]string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]string(nil), o.signals...), append([]map[string]string(nil), o.subjects...)
}

// capturingGate admits every comparison and keeps what it would have recorded
// (D311) — the gate's half without a gateway behind it.
type capturingGate struct {
	mu      sync.Mutex
	records []drift.Comparison
}

func (g *capturingGate) Admit(context.Context, string) error { return nil }

func (g *capturingGate) Record(_ context.Context, _ string, c drift.Comparison) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.records = append(g.records, c)
	return nil
}

// driftFixture is one MCP target whose live surface a step can bend.
type driftFixture struct {
	*mcpRig
	store *drift.Store
	obs   *capturingObserver
	deps  drift.Deps
}

// newDriftFixture wires the REAL watcher dependencies around one target.
func newDriftFixture(ctx context.Context, t *testing.T,
	edit func(*config.Document)) *driftFixture {

	t.Helper()

	rig := newMCPRig(ctx, t, edit)
	store := memoryStore(t)
	obs := &capturingObserver{}

	return &driftFixture{
		mcpRig: rig,
		store:  store,
		obs:    obs,
		deps: drift.Deps{
			Resolver: resolveOnly{rig},
			Drivers:  map[string]connector.Driver{mcp.Kind: rig.driver},
			Targets:  rig.doc.Targets,
			Observer: obs,
			// A CAPTURING GATE (D311): these steps test the comparison and its
			// consequences on a rig with no gateway, and the watcher refuses to
			// START without somewhere to record. P4 step 32 drives the REAL gate.
			Gate: &capturingGate{},
		},
	}
}

// resolveOnly hands the watcher the rig's already-resolved target.
//
// The rig resolves through the REAL resolver in newMCPRig (§6 mechanism 1), so
// this is not a second construction path — it is the same Target, handed over
// without resolving it again per tick.
type resolveOnly struct{ rig *mcpRig }

func (r resolveOnly) Resolve(_ context.Context, ref string) (connector.Target, error) {
	if ref != r.rig.target.Ref() {
		return connector.Target{}, errUnknownTarget
	}
	return r.rig.target, nil
}

var errUnknownTarget = errString("no such target in this fixture")

type errString string

func (e errString) Error() string { return string(e) }

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// step9DriftSeveritiesAreDistinguished is criterion 7 (D48, D197).
//
// **THE WHOLE POINT OF THE VOCABULARY, and the definition-of-done says a single
// `schema mismatch` log conflates them.** Four severities that differ in KIND
// rather than in degree: one is a supply-chain WIN, one is a definition-of-done
// violation surfacing at runtime, one is dangerous, and one is news. Asserting
// them together because the failure being guarded against is treating them
// alike.
//
// **IT RANGES OVER `Severities()` RATHER THAN NAMING MEMBERS (§15q).** A step
// naming four severities passes forever and says nothing about the fifth
// somebody adds next year; this one fails until every member of the vocabulary
// has been PRODUCED by a real comparison and had its response asserted. That is
// the difference between covering a set and covering the members you remembered.
//
// **AND THE ASYMMETRY IS THE DECISION (D197).** `withheld` drops one action and
// leaves the target serving; `refused` takes the whole target down. The maintainer's
// framing of why that is sound rather than soft: a vendor RETRACTING a tool is
// fail-closed by construction — the tool is gone, so nothing can call it, and
// withholding only keeps our advertisement honest — while an `inputSchema`
// divergence leaves the tool CALLABLE with arguments nobody reviewed, which is
// fail-open and is why it is not confined to the tool that changed.
func step9DriftSeveritiesAreDistinguished(t *testing.T) {
	ctx := context.Background()

	// --- 9a: EVERY SEVERITY IN THE VOCABULARY IS PRODUCED AND GRADED ---------
	//
	// One comparison that makes all four happen at once: `search` matches,
	// `report` is missing from live (withheld), `render`'s inputSchema diverges
	// (refused), `export`'s vendor-pinned outputSchema changed (informational),
	// and the server offers `exfiltrate`, which no human vetted (unvetted).
	fix := newDriftFixture(ctx, t, func(d *config.Document) {
		spec := d.MCPSpecs["fixture-mcp"]
		spec.Tools = append(spec.Tools,
			config.MCPToolSpec{
				Name: "report", Description: "Report a finding.",
				InputSchema: objectSchema("body"),
			},
			config.MCPToolSpec{
				Name: "render", Description: "Render a chart.",
				InputSchema: objectSchema("series"),
			},
			config.MCPToolSpec{
				Name: "export", Description: "Export a dataset.",
				InputSchema:        objectSchema("dataset"),
				OutputSchema:       objectSchema("rows"),
				OutputSchemaOrigin: "vendor",
			},
		)
		d.MCPSpecs["fixture-mcp"] = spec
	})

	fix.up.offer(
		mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")},
		// `report` is absent — withheld.
		mcp.LiveTool{Name: "render", InputSchema: objectSchema("series", "palette")},
		mcp.LiveTool{Name: "export", InputSchema: objectSchema("dataset"),
			OutputSchema: objectSchema("rows", "total")},
		mcp.LiveTool{Name: "exfiltrate", InputSchema: objectSchema("path")},
	)

	findings, err := fix.driver.Drift(connector.WithTenant(ctx, fix.target.Tenant()), fix.target)
	if err != nil {
		t.Fatalf("9a: comparing: %v", err)
	}

	// RANGED, NOT NAMED. Every severity the vocabulary declares must appear.
	for _, sev := range drift.Severities() {
		if len(findings.Of(sev)) == 0 {
			t.Errorf("9a: severity %q was produced by no finding, so this step covers the "+
				"members somebody remembered rather than the vocabulary. Either the fixture "+
				"no longer provokes it or a new severity has landed with no driven case — "+
				"and an ungraded severity answers false to both RefusesTarget and "+
				"WithholdsAction, which reads as a finding and acts as nothing",
				sev)
		}
	}

	// And each severity's RESPONSE is what the vocabulary says it is.
	for _, sev := range drift.Severities() {
		switch sev {
		case drift.SeverityRefused:
			if !sev.RefusesTarget() {
				t.Errorf("9a: %q must refuse the target", sev)
			}
		case drift.SeverityWithheld:
			if !sev.WithholdsAction() || sev.RefusesTarget() {
				t.Errorf("9a: %q must withhold the ACTION and not refuse the target (D197)", sev)
			}
		case drift.SeverityUnvetted, drift.SeverityInformational:
			if sev.RefusesTarget() || sev.WithholdsAction() {
				t.Errorf("9a: %q must neither refuse nor withhold: it is %s",
					sev, sev.Explain())
			}
		}
	}

	// THE UNVETTED TOOL IS HARMLESS BY CONSTRUCTION, which is the claim rather
	// than a hope: it is not in the action set, so nothing can name it.
	for _, a := range actionNames(fix.driver) {
		if strings.Contains(a, "exfiltrate") {
			t.Errorf("9a: the action set contains %q, so the live tool list widened it", a)
		}
	}

	// --- 9b: WITHHELD DEGRADES AND KEEPS SERVING (D197) ---------------------
	//
	// A SEPARATE FIXTURE, because 9a's comparison also contains a `refused`
	// finding and a refused target would mask the whole point: the question here
	// is what happens when the ONLY divergence is a withdrawn tool.
	withheldOnly := newDriftFixture(ctx, t, func(d *config.Document) {
		spec := d.MCPSpecs["fixture-mcp"]
		spec.Tools = append(spec.Tools, config.MCPToolSpec{
			Name: "report", Description: "Report a finding.",
			InputSchema: objectSchema("body"),
		})
		d.MCPSpecs["fixture-mcp"] = spec

		// A WILDCARD GRANT, so 9e reads the catalog the way D195 says it must be
		// read: the pattern is resolved into the concrete vetted actions it
		// covers, which is what makes "one of them is withheld and the other
		// survives" an assertion about expansion rather than about a literal.
		d.Grants = append(d.Grants, config.GrantSpec{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "mcp.fixture.*", TargetRef: "fixture-mcp"},
			},
		})
	})
	withheldOnly.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})

	w := drift.NewWatcher(withheldOnly.store, time.Hour, discardLog(),
		func() drift.Deps { return withheldOnly.deps })
	w.Check(ctx, withheldOnly.deps)

	st, ok := withheldOnly.store.Of("fixture-mcp")
	if !ok {
		t.Fatal("9b: the watcher recorded nothing for the target")
	}
	if !st.Degraded() {
		t.Errorf("9b: a withdrawn vetted tool did not make the target DEGRADED: %+v", st.Findings)
	}
	if st.Refused() {
		t.Error("9b: a withdrawn tool REFUSED the whole target. That is the over-refusal " +
			"D197 rules out in as many words: a vendor deprecating one tool of twenty " +
			"would take down nineteen that work")
	}
	if got := st.Withheld(); len(got) != 1 || !strings.Contains(got[0], "report") {
		t.Errorf("9b: withheld actions = %v, want just the withdrawn tool's", got)
	}
	// **HEALTH IS NOT FAILED, which is the half D197 amended and the half whose
	// absence was the original defect.** `Findings.Withheld` had no caller and
	// `Health` failed only on RefusesTarget, so BOTH clauses of §4.9a.3's cell
	// were unimplemented.
	if herr := withheldOnly.driver.Health(connector.WithTenant(ctx, withheldOnly.target.Tenant()), withheldOnly.target); herr != nil {
		t.Errorf("9b: a withdrawn tool failed the target's HEALTH: %v. D197: the target "+
			"keeps serving its other tools and readiness reports degraded", herr)
	}

	// --- 9c: THE SIGNAL IS RAISED, KEYED BY SUBJECT (D134, D158) ------------
	sigs, subjectSets := withheldOnly.obs.captured()
	if len(sigs) != 1 || sigs[0] != "spec_drift" {
		t.Fatalf("9c: signals published = %v, want exactly [spec_drift]", sigs)
	}
	subjects := subjectSets[0]
	if _, named := subjects["fixture-mcp"]; !named {
		t.Errorf("9c: spec_drift was raised with subjects %v, which does not name the "+
			"diverged target. A rule acts on the target IT names (D134), so a signal with "+
			"no subject dimension fires every rule watching it — one target's divergence "+
			"quarantining a different, healthy one", subjects)
	}

	// --- 9d: AND THE HARMLESS SEVERITIES RAISE NOTHING ----------------------
	//
	// **THE ARM THAT STOPS THE SIGNAL BECOMING NOISE.** `unvetted` is the
	// supply-chain win — a vendor shipped a tool and it is not callable — and an
	// anzen rule that quarantined a target because the vendor ADDED something
	// would be D77's crying wolf with a credential revocation attached. Without
	// this arm, "only the actionable severities raise the signal" is a sentence
	// in a comment.
	unvettedOnly := newDriftFixture(ctx, t, nil)
	unvettedOnly.up.offer(
		mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")},
		mcp.LiveTool{Name: "exfiltrate", InputSchema: objectSchema("path")},
	)
	drift.NewWatcher(unvettedOnly.store, time.Hour, discardLog(),
		func() drift.Deps { return unvettedOnly.deps }).Check(ctx, unvettedOnly.deps)

	_, unvettedSubjects := unvettedOnly.obs.captured()
	if len(unvettedSubjects) != 1 {
		t.Fatalf("9d: expected one Observe call, got %d", len(unvettedSubjects))
	}
	if got := unvettedSubjects[0]; len(got) != 0 {
		t.Errorf("9d: an UNVETTED tool raised spec_drift with subjects %v. The signal must "+
			"carry only what withholds or refuses: a vendor adding a tool nobody vetted is "+
			"the supply-chain win being visible, not an incident", got)
	}
	if unvettedState, _ := unvettedOnly.store.Of("fixture-mcp"); unvettedState.Degraded() {
		t.Error("9d: an unvetted tool marked the target degraded")
	}

	// --- 9e: AND THE CAPABILITY DISAPPEARS FROM THE CATALOG (D197) ----------
	//
	// **THE HEADLINE CLAIM, AND THE ARM I NEARLY LEFT OUT.** 9b proves the STATE
	// is degraded and health still passes; neither says the catalog stopped
	// advertising the tool, which is the sentence D197 actually leads with. A
	// step that asserted the store alone would pass against a catalog that
	// ignored it entirely — the recurring defect in this codebase, arriving in
	// the step written to prevent it.
	//
	// **AND THE OTHER CAPABILITY MUST SURVIVE**, or this proves over-refusal
	// rather than withholding: "the target keeps serving its other tools" is
	// half of D197 and the half that makes it a control an operator keeps on.
	cat := catalog.New(catalog.Config{
		Doc:     withheldOnly.doc,
		Drivers: map[string]connector.Driver{mcp.Kind: withheldOnly.driver},
		Policy:  policy.NewGrantEngine(withheldOnly.doc, nil),
		Guards:  anzen.New(nil),
		Drift:   withheldOnly.store,
	})

	resp, err := cat.Describe(ctx, assertedIdentity("agent:dev"), "")
	if err != nil {
		t.Fatalf("9e: Describe: %v", err)
	}

	var advertised []string
	for _, c := range resp.GetCapabilities() {
		advertised = append(advertised, c.GetAction())
	}
	for _, a := range advertised {
		if strings.Contains(a, "report") {
			t.Errorf("9e: the catalog still advertises %q after the server withdrew it. An "+
				"agent reading this list would spend a turn discovering the call fails, "+
				"which is the §4.9 property 1 failure D197 exists to stop", a)
		}
	}
	var keptSearch bool
	for _, a := range advertised {
		if strings.Contains(a, "search") {
			keptSearch = true
		}
	}
	if !keptSearch {
		t.Errorf("9e: withholding one withdrawn tool also removed the tools that WORK: "+
			"advertised = %v. D197 turns on the target continuing to serve its other "+
			"tools; a withholding that takes the rest with it is the over-refusal it "+
			"rules out", advertised)
	}

	r := &run{}
	r.detail(t, "D48/D197: all %d severities in the vocabulary are produced by real "+
		"comparisons and graded; a withdrawn tool is dropped from what the CATALOG "+
		"advertises while its siblings survive, leaves health passing and raises "+
		"spec_drift keyed by target; an unvetted tool raises nothing",
		len(drift.Severities()))
}

// step12OfflineBlocksLoadLiveGatesReadinessPerTarget is criterion 7 (D50).
//
// **THE SPLIT D50 DRAWS, AND GETTING IT BACKWARDS FAILS IN BOTH DIRECTIONS.**
// An offline error that only warned would let a contradictory configuration
// serve; a live comparison that blocked start would make ONE unreachable MCP
// server prevent the whole instance from booting — including every target that
// has nothing to do with it. So the offline arm refuses the load, and the live
// arm leaves the process up with THAT TARGET not ready.
func step12OfflineBlocksLoadLiveGatesReadinessPerTarget(t *testing.T) {
	ctx := context.Background()

	// --- 12a: THE OFFLINE HALF REFUSES THE LOAD -----------------------------
	//
	// An MCP target with no vetted spec cannot be compared to anything, and
	// D192 makes the spec configuration rather than something fetched — so this
	// is decidable from the document alone, which is exactly why it must be a
	// LOAD failure rather than a runtime one.
	noSpec := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "fixture-mcp", Kind: mcp.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://mcp.invalid", CredentialRef: "env://TOK",
		}},
	}
	if err := noSpec.Validate(); err == nil {
		t.Error("12a: an MCP target with NO vetted spec loaded cleanly. Nothing could " +
			"compare it, so every drift guarantee would be vacuous for that target — and " +
			"D50 puts this half offline precisely because the document alone decides it")
	} else if !strings.Contains(err.Error(), "fixture-mcp") {
		t.Errorf("12a: the refusal does not name the target: %v", err)
	}

	// --- 12b: THE LIVE HALF LEAVES THE PROCESS UP ---------------------------
	//
	// **THE REAL WATCHER, STARTED, and that is the reason the loop lives in
	// `internal/` (D206).** Its two siblings sit in `package main` where a step
	// can only re-implement what they do — and a second copy of a sequence is
	// what D155 found `Query` had grown. Start() returning nil against an
	// unreachable server IS the claim: the boot is not gated.
	fix := newDriftFixture(ctx, t, nil)
	fix.unreachable()

	w := drift.NewWatcher(fix.store, time.Hour, discardLog(),
		func() drift.Deps { return fix.deps })
	if err := w.Start(ctx); err != nil {
		t.Fatalf("12b: an unreachable MCP server FAILED THE START: %v. One vendor's outage "+
			"must not stop this process serving every other target", err)
	}
	t.Cleanup(func() { _ = w.Stop(context.WithoutCancel(ctx)) })

	// The loop checks immediately, so the state arrives without waiting a tick.
	deadline := time.Now().Add(2 * time.Second)
	var st drift.State
	for time.Now().Before(deadline) {
		if got, ok := fix.store.Of("fixture-mcp"); ok && got.Err != nil {
			st = got
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if st.Err == nil {
		t.Fatal("12b: the watcher recorded no failure for an unreachable server, so " +
			"readiness would report the target as fine")
	}

	// **AND THE OUTAGE IS NOT DRIFT (step 13's distinction, carried here).** A
	// network failure must not become a governance finding, or a vendor's bad
	// afternoon reads as a supply-chain event and every rule watching
	// `spec_drift` fires on it.
	if len(st.Findings) != 0 {
		t.Errorf("12b: an unreachable server produced %d drift finding(s): %v. An outage is "+
			"`target_unavailable` and retryable; a divergence is `spec_drift` and is not",
			len(st.Findings), st.Findings)
	}
	if st.Checked() {
		t.Error("12b: a target whose comparison never completed reports as CHECKED, so an " +
			"operator reading readiness cannot tell `verified clean` from `never verified` " +
			"— D75's cannot-confirm versus refuted")
	}
	if _, raised := fix.obs.captured(); len(raised) == 0 || len(raised[0]) != 0 {
		t.Errorf("12b: an unreachable server raised spec_drift with subjects %v", raised)
	}

	// --- 12c: PER TARGET, NOT PER PROCESS -----------------------------------
	//
	// The arm that makes 12b mean what it says. One unreachable target leaves a
	// SECOND, healthy target verified and serving — asserted on two targets in
	// one store, because "the process stayed up" is also true of a process that
	// stopped comparing everything.
	healthy := newDriftFixture(ctx, t, nil)
	healthy.up.offer(mcp.LiveTool{Name: "search", InputSchema: objectSchema("query")})
	healthy.store = fix.store // the SAME store the unreachable target is in
	healthy.deps.Observer = healthy.obs

	drift.NewWatcher(healthy.store, time.Hour, discardLog(),
		func() drift.Deps { return healthy.deps }).Check(ctx, healthy.deps)

	good, ok := healthy.store.Of("fixture-mcp")
	if !ok || !good.Checked() {
		t.Fatalf("12c: the reachable target was not verified: %+v", good)
	}
	if good.Degraded() || good.Refused() || good.Err != nil {
		t.Errorf("12c: a matching target reported as degraded/refused/failing: %+v", good)
	}

	// --- 12d: THE DRIFT STATE CANNOT TAKE THE INSTANCE OUT OF ROTATION ------
	//
	// **THE STRUCTURAL FORM OF THE GUARANTEE, and P1 step 33 established the
	// shape for the pool.** A readiness reporter is a `spine.HealthReporter`;
	// asserting the store is NOT one forecloses the change rather than observing
	// that it currently behaves. The failure it prevents is the one D197 spends
	// its whole entry on: a component reporting unhealthy makes `Status.Ready`
	// false, so ONE vendor withdrawing ONE tool would stop this process serving
	// nineteen tools that work and every other target besides.
	//
	// **AND THE WATCHER IS NOT ONE EITHER**, which is the likelier mistake: it
	// is a spine COMPONENT, so adding a `Health(ctx) error` method to it is a
	// two-line change that reads as an improvement and would wire a vendor's
	// availability directly into this instance's readiness.
	var asStore any = fix.store
	if _, isReporter := asStore.(spine.HealthReporter); isReporter {
		t.Error("12d: drift.Store reports health, so a withdrawn tool can make the whole " +
			"instance unready. D197: the action is withheld and the TARGET degrades; the " +
			"process keeps serving")
	}
	var asWatcher any = w
	if _, isReporter := asWatcher.(spine.HealthReporter); isReporter {
		t.Error("12d: drift.Watcher reports health, so an unreachable vendor can make the " +
			"whole instance unready — including every target that has nothing to do with it")
	}

	r := &run{}
	r.detail(t, "D50: an MCP target with no vetted spec fails the LOAD; an unreachable "+
		"server does NOT fail the start, records no findings, stays UNVERIFIED rather than "+
		"clean, and leaves a second target verified and serving; and neither the store nor "+
		"the watcher can report health, so no vendor can make this instance unready")
}

// memoryStore is a drift store held in memory only (D311: OpenStore("")).
func memoryStore(t testing.TB) *drift.Store {
	t.Helper()
	s, err := drift.OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
