// Package metrics exposes RED metrics in Prometheus text format.
//
// PRIVATE (D35). CONTRACTS §2 lists /metrics beside /healthz and /readyz as
// plain HTTP, "because platform probes and metric scrapers expect HTTP".
//
// NO PROMETHEUS CLIENT LIBRARY. The exposition format is `name{labels} value`
// per line — small enough to emit correctly by hand, and the client library
// brings a registry, collectors, and a push gateway that P0 uses none of. The
// same reasoning as skipping Rego (D58) and a JSON Schema library: take the
// dependency when something needs what it does. Swapping later is confined to
// this file, because nothing outside it knows the format.
//
// RED, KEYED (target, action, outcome), which is what the connector
// definition-of-done requires of every driver. Outcome is a fault.Kind name or
// "ok", so the metric partitions the same way the audit log does — an operator
// comparing a dashboard against decision records is looking at one vocabulary.
//
// DESIGN.md references: §7.1, CONTRACTS §2 and §5.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// key identifies one RED series.
type key struct {
	target  string
	action  string
	outcome string
}

type series struct {
	count       uint64
	totalMillis uint64
}

// Registry accumulates counters. Safe for concurrent use.
//
// Counters only, no histograms. A histogram needs bucket boundaries chosen in
// advance, and choosing them before any real latency data exists produces
// buckets that describe nothing. Sum and count give a mean, which is enough to
// see a regression; percentiles arrive with OTel at P2 where the data justifies
// the choice.
type Registry struct {
	mu     sync.Mutex
	red    map[key]*series
	events map[eventKey]uint64 // free-form counters: decisions, refusals, reloads
}

// eventKey is a named counter, optionally scoped to one target.
//
// **ONE MAP FOR BOTH, NOT TWO**, so `Incr` and `IncrFor` cannot accumulate into
// separate places and disagree — the divergent-lists failure `pkg/fault`'s own
// doc cites Lexicon for. An empty target means the counter is deployment-wide.
type eventKey struct {
	name   string
	target string
}

func New() *Registry {
	return &Registry{red: map[key]*series{}, events: map[eventKey]uint64{}}
}

// Observe records one completed action.
//
// outcome is "ok" or a fault.Kind name — deliberately the SAME vocabulary the
// audit log uses, so a spike in `outcome="rate_limited"` on a dashboard and the
// matching decision records are the same word.
func (r *Registry) Observe(target, action, outcome string, took time.Duration) {
	k := key{target: target, action: action, outcome: outcome}

	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.red[k]
	if !ok {
		s = &series{}
		r.red[k] = s
	}
	s.count++
	s.totalMillis += uint64(took.Milliseconds())
}

// Incr bumps a deployment-wide named counter.
//
// **THE NAME IS UNPREFIXED. `WriteTo` OWNS THE `sekizui_` NAMESPACE**, the same
// way it does for the RED series, and passing a name that already carries it
// produces `sekizui_sekizui_...` in the scrape. That is not hypothetical: three
// call sites did it, and every test asserting with `strings.Contains` passed on
// the doubled name because the undoubled one is a substring of it.
// `archcheck.TestCounterNamesAreUnprefixed` is what catches it now.
func (r *Registry) Incr(name string) { r.IncrFor(name, "") }

// IncrFor bumps a named counter for ONE TARGET.
//
// **A LABEL, BECAUSE AN UNLABELLED SECURITY COUNTER ONLY HALF-ANSWERS.** D204
// builds `credential_churn` so a perimeter can react while an amplification is
// happening — the audit log is local and the warehouse is descoped (D169), so
// the scrape is the only thing that leaves the process in time to matter. A
// counter that says churn is happening and not WHERE cannot scope a response,
// which is most of what a perimeter does. The target is the dimension the RED
// series already keys on, so this adds a label rather than a vocabulary.
//
// An empty target is the deployment-wide form and emits no label at all.
func (r *Registry) IncrFor(name, target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[eventKey{name: name, target: target}]++
}

// Add bumps a deployment-wide named counter by n — for a count that arrives in
// batches, like envelopes a bus dropped between two deliveries (P3 step 6).
func (r *Registry) Add(name string, n uint64) {
	if n == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[eventKey{name: name}] += n
}

// WriteTo emits the Prometheus text exposition format.
//
// SORTED OUTPUT. Map iteration is randomised (GO-PRIMER §15), and a scrape whose
// line order changes every time is unreadable in a diff and defeats any tooling
// that compares two scrapes.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	snapshot := make(map[key]series, len(r.red))
	for k, s := range r.red {
		snapshot[k] = *s
	}
	events := make(map[eventKey]uint64, len(r.events))
	for k, v := range r.events {
		events[k] = v
	}
	r.mu.Unlock()

	// **A NAME MUST NOT APPEAR BOTH LABELLED AND UNLABELLED.** Prometheus rejects
	// a metric whose series carry inconsistent label sets, and it rejects the
	// whole scrape — so one careless call site would take out every metric this
	// process exposes, silently, leaving a dashboard that is empty rather than
	// wrong. Refused here rather than emitted, because the failure mode of
	// emitting it is a scrape nobody sees fail.
	shape := map[string]bool{}
	for k := range events {
		labelled := k.target != ""
		if prev, seen := shape[k.name]; seen && prev != labelled {
			return 0, fmt.Errorf("metric %q is recorded both with and without a target "+
				"label; Prometheus rejects the entire scrape for inconsistent label "+
				"sets, so one call site would blank every metric here. Use Incr or "+
				"IncrFor for a given name, never both", k.name)
		}
		shape[k.name] = labelled
	}

	var b strings.Builder

	b.WriteString("# HELP sekizui_actions_total Actions attempted, by target, action, and outcome.\n")
	b.WriteString("# TYPE sekizui_actions_total counter\n")
	for _, k := range sortedKeys(snapshot) {
		fmt.Fprintf(&b, "sekizui_actions_total{target=%q,action=%q,outcome=%q} %d\n",
			k.target, k.action, k.outcome, snapshot[k].count)
	}

	b.WriteString("# HELP sekizui_action_duration_milliseconds_total Summed action latency.\n")
	b.WriteString("# TYPE sekizui_action_duration_milliseconds_total counter\n")
	for _, k := range sortedKeys(snapshot) {
		fmt.Fprintf(&b, "sekizui_action_duration_milliseconds_total{target=%q,action=%q,outcome=%q} %d\n",
			k.target, k.action, k.outcome, snapshot[k].totalMillis)
	}

	keys := make([]eventKey, 0, len(events))
	for k := range events {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].target < keys[j].target
	})
	// ONE `# TYPE` PER NAME, not per series — a repeated TYPE line for the same
	// metric is malformed, and a labelled counter has one line per target.
	typed := map[string]bool{}
	for _, k := range keys {
		if !typed[k.name] {
			fmt.Fprintf(&b, "# TYPE sekizui_%s counter\n", k.name)
			typed[k.name] = true
		}
		if k.target == "" {
			fmt.Fprintf(&b, "sekizui_%s %d\n", k.name, events[k])
			continue
		}
		fmt.Fprintf(&b, "sekizui_%s{target=%q} %d\n", k.name, k.target, events[k])
	}

	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

func sortedKeys(m map[key]series) []key {
	out := make([]key, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].target != out[j].target {
			return out[i].target < out[j].target
		}
		if out[i].action != out[j].action {
			return out[i].action < out[j].action
		}
		return out[i].outcome < out[j].outcome
	})
	return out
}
