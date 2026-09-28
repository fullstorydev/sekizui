package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/fullstorydev/sekizui/internal/builtin"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/tap"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step15 — the raw-envelope dev tap captures for a human and rehearses
// offline, and cannot be mistaken for a producer (P3 criterion 1, D273).
//
// **"REHEARSE", NOT "REPLAY"** — replay is what Fullstory calls watching a
// session back (the maintainer asked). A rehearsal runs captured envelopes through the
// configured rules and projections to show what WOULD happen; nothing is sent.
func p3Step15(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the raw-envelope dev tap captures for a human, rehearses offline, and is no producer")

	// 15d FIRST, because it needs no instance: THE STRUCTURAL ARM.
	step15CannotProduce(t)

	if r.localOnly(t, "publishing onto the bus needs in-process access") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 15a — CAPTURE, as an ordinary governed subscription.
	var captured bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, err := tap.Capture(ctx, r.as(t, "agent:scoped"),
			&sekizuiv1.SubscribeRequest{Subjects: []string{"sekizui.raw.kata.>"}}, &captured, 2)
		done <- err
	}()
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 }, "the capture never subscribed")
	for i, ordinal := range []int{1, 7} {
		e := envelope(t, "raw", "kata.row.v1", map[string]any{"ordinal": ordinal, "ref": "kata:alpha"})
		e.Id, e.Source = "15-row-"+strconv.Itoa(i), "kata:alpha"
		if err := r.srv.PublishForTest(e); err != nil {
			t.Fatalf("step 15a: %v", err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("step 15a: capture: %v", err)
	}
	if lines := strings.Count(captured.String(), "\n"); lines != 2 {
		t.Fatalf("step 15a: captured %d line(s), want 2", lines)
	}

	// 15b — REHEARSE against this deployment's document: what WOULD happen.
	before := logLen(t, r)
	var out bytes.Buffer
	doc := loadAcceptanceDoc(t)
	n, err := tap.Rehearse(ctx, doc, builtin.ByKind(doc, nil), &captured, &out)
	if err != nil || n != 2 {
		t.Fatalf("step 15b: rehearsed %d, err %v", n, err)
	}
	var lines []tap.Line
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var l tap.Line
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatalf("step 15b: %v", err)
		}
		lines = append(lines, l)
	}
	first := lines[0]
	var unarmed *tap.Firing
	for i := range first.Would {
		if first.Would[i].Rule == "unarmed-ticket" {
			unarmed = &first.Would[i]
		}
	}
	switch {
	case unarmed == nil:
		t.Errorf("step 15b: the rehearsal did not show unarmed-ticket firing on a raw kata row: %+v", first)
	case unarmed.Action != "kata.create_issue" || unarmed.Armed:
		t.Errorf("step 15b: unarmed-ticket would send %q armed=%v; want kata.create_issue as a DRY run",
			unarmed.Action, unarmed.Armed)
	}
	if len(first.Projected) != 1 || first.Projected[0] != "row-summary" {
		t.Errorf("step 15b: ordinal 1 should project by row-summary, got %v", first.Projected)
	}

	// 15c — NOTHING WAS RECORDED. A rehearsal is not something that happened.
	if after := logLen(t, r); after != before {
		t.Errorf("step 15c: the rehearsal wrote %d audit record(s); it must write none", after-before)
	}
	r.detail(t, "captured 2 envelopes through a governed subscription; rehearsed offline: unarmed-ticket "+
		"would send kata.create_issue as a dry run and row-summary would project — no record written")
}

// step15CannotProduce is 15d: the tap imports nothing that can publish or
// execute, and the wire carries no tap or replay RPC.
func step15CannotProduce(t *testing.T) {
	t.Helper()
	root := mustRoot(t)
	forbidden := []string{"internal/gateway", "internal/bus", "internal/kyuushin", "internal/pool"}
	for _, dir := range []string{"internal/tap", "cmd/sekizui-tap"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("step 15d: %v", err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, dir, e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("step 15d: %v", err)
			}
			for _, imp := range f.Imports {
				for _, bad := range forbidden {
					if strings.Contains(imp.Path.Value, "/"+bad+`"`) {
						t.Errorf("step 15d: %s/%s imports %s — the tap would then be able to publish "+
							"or execute, which is the ingestion path it must not become (D273)",
							dir, e.Name(), bad)
					}
				}
			}
		}
	}
	svc, err := os.ReadFile(filepath.Join(root, "proto", "sekizui", "v1", "service.proto"))
	if err != nil {
		t.Fatalf("step 15d: %v", err)
	}
	for _, rpc := range []string{"rpc Tap", "rpc Replay", "rpc Rehearse", "rpc Publish"} {
		if strings.Contains(string(svc), rpc) {
			t.Errorf("step 15d: service.proto declares %q — the tap is reachable over the wire", rpc)
		}
	}
}
