package acceptance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/pkg/audit"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// AUDIT SHIPPING (D319), P4 steps 9-10: the recorder writes the local WAL alone,
// and a shipper delivers each record to the destinations its residency permits,
// asynchronously and at least once.

// destIDs lists the decision ids a JSONL destination holds.
func destIDs(t *testing.T, path string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var d sekizuiv1.Decision
		if protojson.Unmarshal([]byte(line), &d) == nil {
			out[d.GetId()] = true
		}
	}
	return out
}

// residencyOf is the class the WAL recorded for a decision.
func residencyOf(t *testing.T, r *run, id string) string {
	t.Helper()
	for _, d := range readLog(t, r.path) {
		if d.GetId() == id {
			return d.GetResidency()
		}
	}
	t.Fatalf("no record %s", id)
	return ""
}

// euAndUsRecords makes one eu-resident decision and one us-resident one — the
// residency refusal of the eu target, which is itself a record of that class, and
// a read on the suite's home class (D326).
func euAndUsRecords(t *testing.T, r *run) (eu, us string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	read, err := r.as(t, "agent:triage").Query(ctx, &sekizuiv1.QueryRequest{Action: "kata.read", TargetRef: "kata:alpha"})
	if err != nil || read.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("a us read failed: %v", err)
	}
	refused, err := r.as(t, "agent:global").Execute(ctx, &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
		Action: "kata.create_issue", TargetRef: "kata:beta", Args: mustArgs(t, map[string]any{"project": "PROJ"}),
		IdempotencyKey: "p4-ship-" + time.Now().Format("150405.000000000")}})
	if err != nil || refused.GetResult().GetKind() != "residency" {
		t.Fatalf("the eu target was not refused on residency: %v %v", err, refused.GetResult())
	}
	return refused.GetResult().GetDecisionId(), read.GetDecisionId()
}

// p4Step9 — EU-resident decision records land in an EU-resident audit
// destination, and nowhere else (D29 item 4, D319).
func p4Step9(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "EU-resident decision records land in an EU-resident audit destination")
	if r.localOnly(t, "the audit log belongs to the process that wrote it") {
		return
	}
	euID, usID := euAndUsRecords(t, r)
	if residencyOf(t, r, euID) != "eu" || residencyOf(t, r, usID) != "us" {
		t.Fatalf("step 9: the WAL recorded %q and %q; the records must carry the class of what they record",
			residencyOf(t, r, euID), residencyOf(t, r, usID))
	}

	// 9a — ROUTED BY RESIDENCY, from the WAL the recorder wrote.
	dir := t.TempDir()
	euDest, usDest := filepath.Join(dir, "eu.jsonl"), filepath.Join(dir, "us.jsonl")
	shipper, err := auditwal.NewShipper(r.path, auditwal.Restrict(auditwal.NewJSONLSink(euDest), []string{"eu"}),
		auditwal.Restrict(auditwal.NewJSONLSink(usDest), []string{"us"}))
	if err != nil {
		t.Fatal(err)
	}
	shipper.ShipOnce(context.Background())
	eu, us := destIDs(t, euDest), destIDs(t, usDest)
	if !eu[euID] || us[euID] {
		t.Errorf("step 9a: the eu decision is in eu=%v us=%v; it belongs in the EU destination only", eu[euID], us[euID])
	}
	if !us[usID] || eu[usID] {
		t.Errorf("step 9a: the us decision is in us=%v eu=%v; it belongs in the US destination only", us[usID], eu[usID])
	}

	// 9b — AN UNROUTABLE CLASS REFUSES THE BOOT: destinations that leave a
	// served class with nowhere to go.
	if got := auditwal.Unrouted([]string{"eu", "us"}, auditwal.Restrict(auditwal.NewJSONLSink(euDest), []string{"eu"})); strings.Join(got, ",") != "us" {
		t.Errorf("step 9b: with only an eu destination, the unrouted classes are %v; want us", got)
	}
	r.detail(t, "decision %s (eu) shipped to the EU destination only, %s (us) to the US destination only, from "+
		"the local WAL; a deployment serving us with only an eu destination is refused at boot", euID, usID)
}

// downSink is a destination that refuses while down.
type downSink struct {
	down bool
	path string
}

func (d *downSink) Name() string                { return "siem" }
func (d *downSink) Residencies() []string       { return nil }
func (d *downSink) Close(context.Context) error { return nil }
func (d *downSink) Write(ctx context.Context, b []*sekizuiv1.Decision) error {
	if d.down {
		return errors.New("destination refused the batch: 503 from the SIEM")
	}
	return auditwal.NewJSONLSink(d.path).Write(ctx, b)
}

var _ audit.Sink = (*downSink)(nil)

// p4Step10 — a destination that cannot accept records raises audit_unavailable,
// the command path does not wait on it, and nothing is lost (D147, D319).
func p4Step10(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "a sink that cannot accept records raises audit_unavailable, and nothing is lost")
	if r.localOnly(t, "the audit log belongs to the process that wrote it") {
		return
	}
	dest := &downSink{down: true, path: filepath.Join(t.TempDir(), "siem.jsonl")}
	shipper, err := auditwal.NewShipper(r.path, dest)
	if err != nil {
		t.Fatal(err)
	}

	// 10a — DOWN: the level names the destination; commands still serve.
	first, _ := euAndUsRecords(t, r)
	shipper.ShipOnce(context.Background())
	level := shipper.Unavailable()
	if len(level) != 1 {
		t.Fatalf("step 10a: audit_unavailable level %v; want the refusing destination named", level)
	}
	for name, why := range level {
		if !strings.Contains(name, "siem") || !strings.Contains(why, "503") || !strings.Contains(why, "catch up") {
			t.Errorf("step 10a: level %s = %q; want the destination and the reason, and that it will catch up", name, why)
		}
	}
	second, _ := euAndUsRecords(t, r) // the command path does not wait on the destination

	// 10b — RECOVERED: it catches up, every record delivered, the level clear.
	dest.down = false
	shipper.ShipOnce(context.Background())
	got := destIDs(t, dest.path)
	if !got[first] || !got[second] || len(shipper.Unavailable()) != 0 {
		t.Errorf("step 10b: after recovery the destination holds first=%v second=%v and the level is %v; want both "+
			"and a clear level", got[first], got[second], shipper.Unavailable())
	}
	for _, d := range readLog(t, r.path) {
		if !got[d.GetId()] {
			t.Errorf("step 10b: WAL record %s never reached the destination — a loss §5.2.2 forbids", d.GetId())
			break
		}
	}

	// 10d — A WAL THAT SHRANK UNDER ITS CURSOR IS NAMED, NOT SKIPPED (D321): a
	// copy of this run's WAL, shipped, then replaced by a shorter file.
	walCopy := filepath.Join(t.TempDir(), "wal.jsonl")
	raw, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(walCopy, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	copyDest := filepath.Join(t.TempDir(), "copy.jsonl")
	replaced, err := auditwal.NewShipper(walCopy, auditwal.NewJSONLSink(copyDest))
	if err != nil {
		t.Fatal(err)
	}
	replaced.ShipOnce(context.Background())
	firstLine := raw[:strings.IndexByte(string(raw), '\n')+1]
	if err := os.WriteFile(walCopy, firstLine, 0o600); err != nil {
		t.Fatal(err)
	}
	replaced.ShipOnce(context.Background())
	shrank := replaced.Unavailable()
	if len(shrank) != 1 {
		t.Errorf("step 10d: after the WAL shrank under its cursor the level is %v; a destination gone quiet "+
			"with the level clear is the silent loss §5.2.2 forbids", shrank)
	}
	for _, why := range shrank {
		if !strings.Contains(why, "truncated or replaced") {
			t.Errorf("step 10d: level %q; want it to say the WAL was truncated or replaced", why)
		}
	}

	// 10e — A RECORD THAT DOES NOT CONTINUE THE CHAIN IS NOT SHIPPED (D322): the
	// case a size check cannot see. The copy is restored and shipped afresh,
	// then a record whose prev_hash names no record here is appended.
	chained := filepath.Join(t.TempDir(), "chained.jsonl")
	if err := os.WriteFile(chained, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	chainDest := filepath.Join(t.TempDir(), "chain.jsonl")
	verifying, err := auditwal.NewShipper(chained, auditwal.NewJSONLSink(chainDest))
	if err != nil {
		t.Fatal(err)
	}
	verifying.ShipOnce(context.Background())
	forged, err := protojson.Marshal(&sekizuiv1.Decision{Id: "forged", Residency: "eu",
		PrevHash: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(chained, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fh.Write(append(forged, '\n'))
	_ = fh.Close()
	verifying.ShipOnce(context.Background())
	if destIDs(t, chainDest)["forged"] {
		t.Errorf("step 10e: a record that continues no chain in the WAL reached the destination")
	}
	if broke := verifying.Unavailable(); len(broke) != 1 {
		t.Errorf("step 10e: after a forged record the level is %v; want the destination named", broke)
	}

	// 10f — WHERE THE TAIL IS PERSISTED, A SEGMENT START IS A BREAK (D324): the
	// binary's recorder always persists its chain tail (D78), so a record with
	// no prev_hash after one already shipped means the tail was lost or the WAL
	// replaced — the case 10e's check alone reads as a restart.
	segmented := filepath.Join(t.TempDir(), "segmented.jsonl")
	if err := os.WriteFile(segmented, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	strict, err := auditwal.NewShipper(segmented, auditwal.NewJSONLSink(filepath.Join(t.TempDir(), "strict.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	strict.RequireContinuousChain()
	strict.ShipOnce(context.Background())
	restart, err := protojson.Marshal(&sekizuiv1.Decision{Id: "unchained", Residency: "eu"})
	if err != nil {
		t.Fatal(err)
	}
	sh, err := os.OpenFile(segmented, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sh.Write(append(restart, '\n'))
	_ = sh.Close()
	strict.ShipOnce(context.Background())
	if len(strict.Unavailable()) != 1 {
		t.Errorf("step 10f: a segment start after a shipped record, where the tail is persisted, left the level %v; "+
			"want the destination named", strict.Unavailable())
	}

	// 10g — THE OPERATOR'S RESET WORKS (D324): removing the cursor vouches for
	// the WAL as it stands, so shipping resumes past 10f's break — the first
	// version re-shipped to the same break and stopped again, and the refusal
	// named a remedy that did not work.
	cursors, err := filepath.Glob(segmented + ".ship.*")
	if err != nil || len(cursors) == 0 {
		t.Fatalf("step 10g: no cursor beside the WAL to remove: %v", err)
	}
	for _, c := range cursors {
		if err := os.Remove(c); err != nil {
			t.Fatal(err)
		}
	}
	strict.ShipOnce(context.Background())
	if len(strict.Unavailable()) != 0 {
		t.Errorf("step 10g: after the operator removed the cursor the level is %v; the reset must resume shipping",
			strict.Unavailable())
	}

	// 10c — AN ANZEN RULE CAN WATCH IT: the signal is in the closed set.
	doc := &config.Document{Anzen: []config.AnzenSpec{{Name: "audit-down", Enabled: true, Mode: "shadow",
		Watches: "audit_unavailable", Do: "alert"}}}
	if err := doc.Validate(); err != nil && strings.Contains(err.Error(), "audit_unavailable") {
		t.Errorf("step 10c: an anzen rule watching audit_unavailable was refused: %v", err)
	}
	r.detail(t, "with the destination refusing, audit_unavailable named it and commands kept serving; recovered, "+
		"it caught up — every WAL record delivered, the level clear; a WAL that shrank under its cursor, and a record continuing no chain, were named, "+
		"not shipped")
}
