package main

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/pkg/config"
)

type levels struct{ nonconforming, stopped, undeclared map[string]string }

func (l levels) Nonconforming() map[string]string { return l.nonconforming }
func (l levels) Stopped() map[string]string       { return l.stopped }
func (l levels) Undeclared() map[string]string    { return l.undeclared }

// TestTheSourceWatcherPublishesEachReportAsItsOwnLevel is D280: each of the
// runner's three reports reaches the dispatcher as its own signal, the rule
// naming THAT source fires, and it fires once — the dispatcher's edge latch —
// not on every tick.
func TestTheSourceWatcherPublishesEachReportAsItsOwnLevel(t *testing.T) {
	var fired []string
	guards := anzen.New([]config.AnzenSpec{
		{Name: "tell-the-owner", Enabled: true, Mode: "enforce", Watches: "source_undeclared",
			Do: "alert", Subject: "fs:events"},
		{Name: "quarantine-broken", Enabled: true, Mode: "enforce", Watches: "source_nonconforming",
			Do: "quarantine_target", Subject: "kata:bad"},
		{Name: "someone-else", Enabled: true, Mode: "enforce", Watches: "source_undeclared",
			Do: "alert", Subject: "fs:other"},
		{Name: "page-the-owner", Enabled: true, Mode: "enforce", Watches: "connector_quarantined",
			Do: "alert", Subject: "jira"},
	})
	d := anzen.NewDispatcher(guards, func(_ context.Context, rule string) error {
		fired = append(fired, rule)
		return nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := &sourceWatcher{log: slog.New(slog.NewTextHandler(io.Discard, nil)), dispatch: d,
		quarantined: map[string]string{"jira": "ships no schema for jira.issue.v1"},
		jobs: levels{
			nonconforming: map[string]string{"kata:bad": "duplicate_id x1"},
			undeclared:    map[string]string{"fs:events": `kind "User Login" withheld x1`},
		}}
	w.check(context.Background())
	w.check(context.Background()) // a second tick: still raised, must not refire

	slices.Sort(fired)
	if !slices.Equal(fired, []string{"page-the-owner", "quarantine-broken", "tell-the-owner"}) {
		t.Errorf("fired %v; want each source's own rule, once — and not the rule for fs:other", fired)
	}
}
