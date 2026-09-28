package drift_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/drift"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// D311 — the state PERSISTS, and a diverged target stays diverged across a
// restart until a fresh comparison says otherwise.

var withdrawn = drift.Findings{{Severity: drift.SeverityWithheld, Tool: "search",
	Action: "mcp.acme.search", Detail: "the server no longer offers it"}}

func TestADivergedTargetStaysDivergedAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl.drift")

	first, err := drift.OpenStore(path)
	if err != nil {
		t.Fatalf("a missing file is a first boot, not an error: %v", err)
	}
	if err := first.Record("mcp:acme", withdrawn, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := first.PersistErr(); err != nil {
		t.Fatal(err)
	}

	// THE RESTART: a second store over the same file.
	second, err := drift.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Withholds("mcp:acme", "mcp.acme.search") {
		t.Fatal("a restart forgot the divergence — the withdrawn tool would be served again; " +
			"a restart must never be how a finding goes away")
	}

	// A FAILED attempt keeps the last findings, and that survives a restart too.
	second.RecordFailure("mcp:acme", errors.New("vendor unreachable"), time.Now())
	third, err := drift.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := third.Of("mcp:acme")
	if !third.Withholds("mcp:acme", "mcp.acme.search") || st.Err == nil ||
		!strings.Contains(st.Err.Error(), "unreachable") {
		t.Fatalf("a failed attempt after a restart must keep the finding and record the failure: %+v", st)
	}

	// ONLY A FRESH, CLEAN COMPARISON clears it.
	if err := third.Record("mcp:acme", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	fourth, err := drift.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if fourth.Withholds("mcp:acme", "mcp.acme.search") {
		t.Fatal("a clean comparison did not clear the persisted finding")
	}
}

func TestAStateFileThatCannotBeReadFailsTheLoad(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":            "{not json",
		"another version":     `{"version": 99, "states": []}`,
		"an unknown severity": `{"version": 1, "states": [{"ref": "mcp:acme", "findings": [{"Severity": "catastrophic", "Tool": "x"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.drift")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := drift.OpenStore(path); err == nil {
				t.Fatal("an unreadable state file loaded — an empty store in its place would forget " +
					"every finding, so it must fail the boot (D150)")
			}
		})
	}
}

// --- the watcher records every comparison through its gate ---------------------

type recorded struct {
	ref string
	c   drift.Comparison
}

type fakeGate struct {
	mu       sync.Mutex
	refuse   error
	admitted []string
	records  []recorded
}

func (g *fakeGate) Admit(_ context.Context, ref string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.admitted = append(g.admitted, ref)
	return g.refuse
}

func (g *fakeGate) Record(_ context.Context, ref string, c drift.Comparison) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.records = append(g.records, recorded{ref, c})
	return nil
}

// fakeReporter embeds the Driver interface and adds Drift: the watcher asks a
// driver only whether it reports drift, and then for the comparison.
type fakeReporter struct {
	connector.Driver
	findings drift.Findings
	err      error
	calls    int
}

func (f *fakeReporter) Drift(context.Context, connector.Target) (drift.Findings, error) {
	f.calls++
	return f.findings, f.err
}

type anyTarget struct{ err error }

func (r anyTarget) Resolve(context.Context, string) (connector.Target, error) {
	return connector.Target{}, r.err
}

func deps(rep *fakeReporter, gate drift.Gate, resolveErr error) drift.Deps {
	d := drift.Deps{
		Resolver: anyTarget{resolveErr},
		Drivers:  map[string]connector.Driver{"mcp": rep},
		Targets:  []config.TargetSpec{{Ref: "mcp:acme", Kind: "mcp"}},
	}
	if gate != nil {
		d.Gate = gate
	}
	return d
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestEveryComparisonLeavesARecord(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name       string
		findings   drift.Findings
		reportErr  error
		resolveErr error
		want       drift.Outcome
	}{
		{"clean", nil, nil, nil, drift.OutcomeClean},
		{"diverged", withdrawn, nil, nil, drift.OutcomeDiverged},
		{"the comparison failed", nil, errors.New("vendor down"), nil, drift.OutcomeFailed},
		{"the target would not resolve", nil, nil, errors.New("credential refused"), drift.OutcomeFailed},
	} {
		t.Run(c.name, func(t *testing.T) {
			gate := &fakeGate{}
			rep := &fakeReporter{findings: c.findings, err: c.reportErr}
			d := deps(rep, gate, c.resolveErr)
			drift.NewWatcher(memoryStore(t), time.Hour, quiet(), func() drift.Deps { return d }).Check(ctx, d)
			if len(gate.records) != 1 || gate.records[0].c.Outcome != c.want {
				t.Fatalf("want one %q record, got %+v", c.want, gate.records)
			}
			if c.want == drift.OutcomeDiverged && len(gate.records[0].c.Findings) != len(withdrawn) {
				t.Errorf("the diverged record does not carry the findings: %+v", gate.records[0].c)
			}
		})
	}
}

func TestARefusedComparisonNeverReachesTheVendor(t *testing.T) {
	gate := &fakeGate{refuse: errors.New("residency: this deployment does not serve us")}
	rep := &fakeReporter{}
	d := deps(rep, gate, nil)
	drift.NewWatcher(memoryStore(t), time.Hour, quiet(), func() drift.Deps { return d }).Check(context.Background(), d)
	if rep.calls != 0 {
		t.Fatal("a comparison the ceilings refused still called the vendor")
	}
	if len(gate.records) != 0 {
		t.Errorf("the gate records its own refusal in Admit; Check must not add a second record: %+v", gate.records)
	}
}

func TestAWatcherWithNoGateRefusesToStart(t *testing.T) {
	d := deps(&fakeReporter{}, nil, nil)
	w := drift.NewWatcher(memoryStore(t), time.Hour, quiet(), func() drift.Deps { return d })
	err := w.Start(context.Background())
	if err == nil {
		_ = w.Stop(context.Background())
		t.Fatal("a drift watcher with targets to compare and no gate started — it would compare " +
			"in silence, which is the gap D311 closed")
	}
	if !strings.Contains(err.Error(), "D311") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}
