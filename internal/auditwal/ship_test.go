package auditwal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// flaky is a destination that refuses until told otherwise.
type flaky struct {
	down bool
	got  []string
}

func (f *flaky) Name() string                { return "flaky" }
func (f *flaky) Residencies() []string       { return []string{"eu"} }
func (f *flaky) Close(context.Context) error { return nil }
func (f *flaky) Write(_ context.Context, b []*sekizuiv1.Decision) error {
	if f.down {
		return errors.New("destination unreachable")
	}
	for _, d := range b {
		f.got = append(f.got, d.GetId())
	}
	return nil
}

func writeWAL(t *testing.T, path string, recs ...*sekizuiv1.Decision) {
	t.Helper()
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	for _, r := range recs {
		line, _ := protojson.Marshal(r)
		_, _ = fh.Write(append(line, '\n'))
	}
}

func rec(id, residency string) *sekizuiv1.Decision {
	return &sekizuiv1.Decision{Id: id, Residency: residency}
}

func ids(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var d sekizuiv1.Decision
		if protojson.Unmarshal([]byte(line), &d) == nil {
			out = append(out, d.GetId())
		}
	}
	return strings.Join(out, ",")
}

func TestShipperRoutesByResidency(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "audit.jsonl")
	writeWAL(t, wal, rec("a", "eu"), rec("b", "us"), rec("c", ""), rec("d", "eu"))
	eu, us := filepath.Join(dir, "eu.jsonl"), filepath.Join(dir, "us.jsonl")
	s, err := NewShipper(wal, Restrict(NewJSONLSink(eu), []string{"eu"}), Restrict(NewJSONLSink(us), []string{"us"}))
	if err != nil {
		t.Fatal(err)
	}
	s.ShipOnce(context.Background())
	if got := ids(t, eu); got != "a,c,d" {
		t.Errorf("eu destination holds %q; want the eu records and the unclassified one", got)
	}
	if got := ids(t, us); got != "b,c" {
		t.Errorf("us destination holds %q", got)
	}
	// A second ship sends nothing again: the cursors moved.
	s.ShipOnce(context.Background())
	if got := ids(t, eu); got != "a,c,d" {
		t.Errorf("a re-ship duplicated records: %q", got)
	}
}

func TestAFailingDestinationCatchesUpAndLosesNothing(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "audit.jsonl")
	dest := &flaky{down: true}
	s, _ := NewShipper(wal, dest)
	writeWAL(t, wal, rec("a", "eu"), rec("b", "eu"))
	s.ShipOnce(context.Background())
	if len(s.Unavailable()) != 1 || len(dest.got) != 0 {
		t.Fatalf("while down: unavailable %v, delivered %v", s.Unavailable(), dest.got)
	}
	writeWAL(t, wal, rec("c", "eu"))
	dest.down = false
	s.ShipOnce(context.Background())
	if strings.Join(dest.got, ",") != "a,b,c" || len(s.Unavailable()) != 0 {
		t.Errorf("after recovery: delivered %v, unavailable %v; want all three and the level cleared", dest.got, s.Unavailable())
	}
}

func TestAHalfWrittenRecordIsNotShipped(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "audit.jsonl")
	writeWAL(t, wal, rec("a", "eu"))
	fh, _ := os.OpenFile(wal, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = fh.WriteString(`{"id":"b","resid`)
	fh.Close()
	dest := &flaky{}
	s, _ := NewShipper(wal, dest)
	s.ShipOnce(context.Background())
	if strings.Join(dest.got, ",") != "a" || len(s.Unavailable()) != 0 {
		t.Errorf("delivered %v, unavailable %v; the half-written line waits for its end", dest.got, s.Unavailable())
	}
}

// TestAWALShorterThanItsCursorStopsShippingLoudly — truncated or replaced under
// a destination, the WAL is not shipped from zero and not skipped in silence
// (D321): the level names it until an operator removes the cursor.
func TestAWALShorterThanItsCursorStopsShippingLoudly(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "audit.jsonl")
	writeWAL(t, wal, rec("a", "eu"), rec("b", "eu"), rec("c", "eu"))
	dest := &flaky{}
	s, _ := NewShipper(wal, dest)
	s.ShipOnce(context.Background())

	if err := os.Remove(wal); err != nil {
		t.Fatal(err)
	}
	writeWAL(t, wal, rec("x", "eu")) // a new, shorter file where the old one was
	s.ShipOnce(context.Background())
	level := s.Unavailable()
	if len(level) != 1 || strings.Join(dest.got, ",") != "a,b,c" {
		t.Fatalf("after the WAL shrank: delivered %v, level %v; want nothing more shipped and the destination named", dest.got, level)
	}
	for _, why := range level {
		if !strings.Contains(why, "truncated or replaced") || !strings.Contains(why, ".ship.") {
			t.Errorf("level %q; want the cause and the cursor an operator removes", why)
		}
	}

	// THE OPERATOR'S RESET: the cursor removed, the current file ships.
	for _, d := range s.dests {
		if err := os.Remove(d.cursor); err != nil {
			t.Fatal(err)
		}
	}
	s.ShipOnce(context.Background())
	if strings.Join(dest.got, ",") != "a,b,c,x" || len(s.Unavailable()) != 0 {
		t.Errorf("after the reset: delivered %v, level %v", dest.got, s.Unavailable())
	}
}

// TestAWALReplacedAndGrownPastItsCursorIsRefused — the case the size check
// cannot see (D322): a different WAL, already longer than the cursor. Its first
// new record does not continue the chain the destination last shipped.
func TestAWALReplacedAndGrownPastItsCursorIsRefused(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "audit.jsonl")
	rec := NewRecorder(NewJSONLSink(wal), "config-a")
	for _, id := range []string{"a", "b"} {
		if _, err := rec.Terminal(context.Background(), &sekizuiv1.Decision{Id: id, Residency: "eu"}); err != nil {
			t.Fatal(err)
		}
	}
	dest := &flaky{}
	s, _ := NewShipper(wal, dest)
	s.ShipOnce(context.Background())

	// ANOTHER CHAIN, LONGER: same shape, different history.
	if err := os.Remove(wal); err != nil {
		t.Fatal(err)
	}
	other := NewRecorder(NewJSONLSink(wal), "config-b")
	for _, id := range []string{"x", "y", "z", "w"} {
		if _, err := other.Terminal(context.Background(), &sekizuiv1.Decision{Id: id, Residency: "eu"}); err != nil {
			t.Fatal(err)
		}
	}
	s.ShipOnce(context.Background())
	level := s.Unavailable()
	if len(level) != 1 || strings.Join(dest.got, ",") != "a,b" {
		t.Fatalf("after the WAL was replaced by a longer one: delivered %v, level %v; want nothing more "+
			"shipped and the destination named", dest.got, level)
	}
	for _, why := range level {
		if !strings.Contains(why, "does not continue the chain") {
			t.Errorf("level %q; want the chain break named", why)
		}
	}
}

// TestARecordAlteredBeforeItShipsIsNotDelivered — and the records verified
// before it still are: a break stops the stream, it does not withhold what
// preceded it (D322).
func TestARecordAlteredBeforeItShipsIsNotDelivered(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "audit.jsonl")
	rec := NewRecorder(NewJSONLSink(wal), "config-a")
	record := func(ids ...string) {
		for _, id := range ids {
			if _, err := rec.Terminal(context.Background(), &sekizuiv1.Decision{Id: id, Residency: "eu"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	record("a", "b")
	dest := &flaky{}
	s, _ := NewShipper(wal, dest)
	s.ShipOnce(context.Background())
	record("c", "d")

	// "d"'s history rewritten after it was recorded, before it shipped.
	raw, _ := os.ReadFile(wal)
	lines := strings.SplitAfter(string(raw), "\n")
	var d sekizuiv1.Decision
	if err := protojson.Unmarshal([]byte(lines[3]), &d); err != nil {
		t.Fatal(err)
	}
	d.PrevHash = []byte("0123456789abcdef0123456789abcdef")
	forged, _ := protojson.Marshal(&d)
	lines[3] = string(forged) + "\n"
	if err := os.WriteFile(wal, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	s.ShipOnce(context.Background())
	if strings.Join(dest.got, ",") != "a,b,c" || len(s.Unavailable()) != 1 {
		t.Errorf("delivered %v, level %v; want c (verified) delivered, d (forged) withheld and named",
			dest.got, s.Unavailable())
	}
}

// TestASegmentStartIsABreakWhenTheTailIsPersisted — D322's blind spot (D324):
// where the recorder persists its tail, a record with no prev_hash after one
// already shipped means the tail was lost or the WAL replaced.
func TestASegmentStartIsABreakWhenTheTailIsPersisted(t *testing.T) {
	for _, continuous := range []bool{false, true} {
		dir := t.TempDir()
		wal := filepath.Join(dir, "audit.jsonl")
		first := NewRecorder(NewJSONLSink(wal), "config-a")
		if _, err := first.Terminal(context.Background(), &sekizuiv1.Decision{Id: "a", Residency: "eu"}); err != nil {
			t.Fatal(err)
		}
		dest := &flaky{}
		s, _ := NewShipper(wal, dest)
		if continuous {
			s.RequireContinuousChain()
		}
		s.ShipOnce(context.Background())
		// A SECOND RECORDER WITH NO TAIL: a new segment, prev_hash empty.
		second := NewRecorder(NewJSONLSink(wal), "config-a")
		if _, err := second.Terminal(context.Background(), &sekizuiv1.Decision{Id: "b", Residency: "eu"}); err != nil {
			t.Fatal(err)
		}
		s.ShipOnce(context.Background())
		got := strings.Join(dest.got, ",")
		switch {
		case !continuous && (got != "a,b" || len(s.Unavailable()) != 0):
			t.Errorf("without a persisted tail a segment start is a restart: delivered %q, level %v", got, s.Unavailable())
		case continuous && (got != "a" || len(s.Unavailable()) != 1):
			t.Errorf("with a persisted tail a segment start must stop the stream: delivered %q, level %v", got, s.Unavailable())
		}
	}
}

// TestAResetVouchesForTheWALAsItStands — the operator's remedy works (D324):
// after a mid-file break, removing the cursor re-ships past it, and what is
// appended afterwards is held to the chain again.
func TestAResetVouchesForTheWALAsItStands(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "audit.jsonl")
	first := NewRecorder(NewJSONLSink(wal), "config-a")
	if _, err := first.Terminal(context.Background(), &sekizuiv1.Decision{Id: "a", Residency: "eu"}); err != nil {
		t.Fatal(err)
	}
	dest := &flaky{}
	s, _ := NewShipper(wal, dest)
	s.RequireContinuousChain()
	s.ShipOnce(context.Background())
	second := NewRecorder(NewJSONLSink(wal), "config-a") // a lost tail: a mid-file segment start
	if _, err := second.Terminal(context.Background(), &sekizuiv1.Decision{Id: "b", Residency: "eu"}); err != nil {
		t.Fatal(err)
	}
	s.ShipOnce(context.Background())
	if len(s.Unavailable()) != 1 {
		t.Fatalf("the break was not refused: level %v", s.Unavailable())
	}

	// THE RESET: the cursor removed, the WAL re-shipped past the break.
	for _, d := range s.dests {
		if err := os.Remove(d.cursor); err != nil {
			t.Fatal(err)
		}
	}
	s.ShipOnce(context.Background())
	if got := strings.Join(dest.got, ","); got != "a,a,b" || len(s.Unavailable()) != 0 {
		t.Fatalf("after the reset: delivered %q, level %v; want the file re-shipped past its break (at least once)", got, s.Unavailable())
	}

	// AND WHAT FOLLOWS IS HELD TO THE CHAIN AGAIN.
	third := NewRecorder(NewJSONLSink(wal), "config-a")
	if _, err := third.Terminal(context.Background(), &sekizuiv1.Decision{Id: "c", Residency: "eu"}); err != nil {
		t.Fatal(err)
	}
	s.ShipOnce(context.Background())
	if len(s.Unavailable()) != 1 || strings.HasSuffix(strings.Join(dest.got, ","), ",c") {
		t.Errorf("a break appended after the reset was vouched for too: delivered %v, level %v", dest.got, s.Unavailable())
	}
}
