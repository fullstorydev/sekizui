package main

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/denial"
	"github.com/fullstorydev/sekizui/pkg/config"
)

// TestTheDenialStormWatcherPublishesTheMonopoliser — D336: the watcher turns
// the gateway's tally into `denial_storm`, keyed by the principal causing the
// refusals; its rule fires once per storm, a victim's rule never.
func TestTheDenialStormWatcherPublishesTheMonopoliser(t *testing.T) {
	var fired []string
	guards := anzen.New([]config.AnzenSpec{
		{Name: "alert-on-hog", Enabled: true, Mode: "enforce", Watches: "denial_storm", Do: "alert", Subject: "agent:hog"},
		{Name: "alert-on-victim", Enabled: true, Mode: "enforce", Watches: "denial_storm", Do: "alert", Subject: "agent:quiet"},
	})
	d := anzen.NewDispatcher(guards, func(_ context.Context, rule string) error {
		fired = append(fired, rule)
		return nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	tally := denial.New()
	for range 3 {
		tally.Record("kata:alpha", "agent:quiet", []string{"agent:hog"})
	}
	w := &denialStormWatcher{log: slog.New(slog.NewTextHandler(io.Discard, nil)), dispatch: d, tally: tally,
		every: time.Minute, threshold: 3}
	w.check(context.Background())
	w.check(context.Background()) // still raised: must not refire
	if !slices.Equal(fired, []string{"alert-on-hog"}) {
		t.Errorf("fired %v; want the monopoliser's rule, once, and never the victim's", fired)
	}
}
