package acceptance

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/pkg/audit"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// recordingSink captures what it was given, and can be made slow or broken.
type recordingSink struct {
	name        string
	residencies []string

	// block, when non-nil, holds Write until it is closed — a sink having a bad
	// day, which is the case D120 says must not cost a record.
	block chan struct{}

	// fail makes Write refuse, so the never-drop property can be tested in the
	// direction that matters.
	fail bool

	mu   sync.Mutex
	got  []*sekizuiv1.Decision
	when time.Time
}

func (s *recordingSink) Name() string          { return s.name }
func (s *recordingSink) Residencies() []string { return s.residencies }
func (s *recordingSink) Close(context.Context) error {
	return nil
}

func (s *recordingSink) Write(_ context.Context, batch []*sekizuiv1.Decision) error {
	if s.block != nil {
		<-s.block
	}
	if s.fail {
		return errors.New("sink " + s.name + " is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, batch...)
	s.when = time.Now()
	return nil
}

func (s *recordingSink) received() []*sekizuiv1.Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*sekizuiv1.Decision(nil), s.got...)
}

func rec(id, residency string) *sekizuiv1.Decision {
	return &sekizuiv1.Decision{Id: id, Residency: residency}
}

// shipThrough writes records to a WAL and ships it once to sinks — the path
// D319 put every audit destination on.
func shipThrough(t *testing.T, recs []*sekizuiv1.Decision, sinks ...audit.Sink) *auditwal.Shipper {
	t.Helper()
	wal := filepath.Join(t.TempDir(), "audit.jsonl")
	appendWAL(t, wal, recs...)
	s, err := auditwal.NewShipper(wal, sinks...)
	if err != nil {
		t.Fatal(err)
	}
	s.ShipOnce(context.Background())
	return s
}

func appendWAL(t *testing.T, wal string, recs ...*sekizuiv1.Decision) {
	t.Helper()
	if err := auditwal.NewJSONLSink(wal).Write(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
}

// step45DecisionRecordsReachEverySinkAndNoneIsDropped proves D120 — ON THE
// SHIPPER SINCE D319, which moved every destination off the recorder's
// synchronous path. The claims are the same, and one is stronger: a slow or
// broken destination now costs no record AND does not hold up a command.
//
// **THE NEVER-DROP PROPERTY IS WHAT SEPARATES THIS PATH FROM THE DATA BUS.**
// D118 ruled that decisions never travel on the bus because `internal/bus`
// discards on overflow, deliberately, and §5.2.2 calls losing an audit record
// "the one unacceptable failure".
func step45DecisionRecordsReachEverySinkAndNoneIsDropped(t *testing.T) {
	// --- 45a: EVERY DESTINATION GETS EVERY RECORD IT MAY HAVE ----------
	t.Run("every configured destination receives the records", func(t *testing.T) {
		a := &recordingSink{name: "warehouse"}
		b := &recordingSink{name: "siem"}
		shipThrough(t, []*sekizuiv1.Decision{rec("d1", ""), rec("d2", "")}, a, b)
		for _, s := range []*recordingSink{a, b} {
			if len(s.received()) != 2 {
				t.Errorf("%s received %d records, want 2. A destination configured and "+
					"not written to is a governance hole nobody would notice until an "+
					"audit asked for something it never got", s.name, len(s.received()))
			}
		}
	})

	// --- 45b: A SLOW DESTINATION DOES NOT COST A RECORD, OR THE OTHERS --
	//
	// **THE ARM D120 EXISTS FOR.** A bus would drop here and count it. This must
	// not: the slow destination's records are still delivered, and it does not
	// serialise the fast one (D319 ships each destination concurrently).
	t.Run("a slow destination delays only itself, and still receives", func(t *testing.T) {
		slow := &recordingSink{name: "slow-siem", block: make(chan struct{})}
		fast := &recordingSink{name: "warehouse"}
		wal := filepath.Join(t.TempDir(), "audit.jsonl")
		appendWAL(t, wal, rec("d1", ""))
		s, err := auditwal.NewShipper(wal, slow, fast)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { s.ShipOnce(context.Background()); close(done) }()

		deadline := time.Now().Add(2 * time.Second)
		for len(fast.received()) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if len(fast.received()) == 0 {
			t.Error("the fast destination had received nothing while a slow one was blocked; " +
				"shipping is serialised, so one bad destination sets the pace for every other")
		}
		close(slow.block)
		<-done
		if len(slow.received()) != 1 {
			t.Error("the slow destination lost its record. A bus drops on overflow by design; " +
				"this path must never, which is the whole reason decisions do not travel on " +
				"the bus (D118)")
		}
	})

	// --- 45c: A REFUSING DESTINATION LOSES NOTHING ----------------------
	//
	// **INVERTED BY D319, ON PURPOSE.** Under D120 a refusing sink failed the
	// write, and the command with it — a destination outage became a total one,
	// the coupling §9.15 rejected. Now the record is durable in the WAL, the
	// destination's cursor holds, it is NAMED as unavailable, and it catches up.
	t.Run("a destination that refuses is named, and catches up", func(t *testing.T) {
		broken := &recordingSink{name: "broken", fail: true}
		ok := &recordingSink{name: "warehouse"}
		wal := filepath.Join(t.TempDir(), "audit.jsonl")
		appendWAL(t, wal, rec("d1", ""))
		s, _ := auditwal.NewShipper(wal, broken, ok)
		s.ShipOnce(context.Background())
		level := s.Unavailable()
		if len(level) != 1 || len(ok.received()) != 1 {
			t.Fatalf("with one destination refusing: unavailable %v, the healthy one received %d; want the "+
				"refusing one named and the healthy one served", level, len(ok.received()))
		}
		for name := range level {
			if !strings.Contains(name, "broken") {
				t.Errorf("the level names %q, not the destination that refused", name)
			}
		}
		broken.fail = false
		s.ShipOnce(context.Background())
		if len(broken.received()) != 1 || len(s.Unavailable()) != 0 {
			t.Errorf("after recovery the destination holds %d record(s) and the level is %v; want the "+
				"record delivered and the level clear", len(broken.received()), s.Unavailable())
		}
	})
}

// step46SinkResidenciesRoutesRatherThanRefuses proves the half of D89 that one
// sink could never exercise — ON THE SHIPPER SINCE D319.
//
// **`Sink.Residencies` WAS WRITTEN FOR THIS.** With a single destination the
// method can only refuse; with two, it routes: an `eu` destination and a `us`
// one each receive only what they may, which is what D29 item 4 asks for.
func step46SinkResidenciesRoutesRatherThanRefuses(t *testing.T) {
	ctx := context.Background()
	eu := &recordingSink{name: "eu-warehouse", residencies: []string{"eu"}}
	us := &recordingSink{name: "us-warehouse", residencies: []string{"us"}}
	shipThrough(t, []*sekizuiv1.Decision{rec("eu-1", "eu"), rec("us-1", "us"), rec("eu-2", "eu"),
		rec("unclassified", "")}, eu, us)

	// --- 46a: EACH RECEIVES ONLY WHAT IT MAY ---------------------------
	for _, c := range []struct {
		sink *recordingSink
		want []string
	}{
		{eu, []string{"eu-1", "eu-2", "unclassified"}},
		{us, []string{"us-1", "unclassified"}},
	} {
		var got []string
		for _, d := range c.sink.received() {
			got = append(got, d.GetId())
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s received %v, want %v. Shipping an EU-resident record to a US "+
				"warehouse makes the audit log itself the violation (D29 item 4)",
				c.sink.name, got, c.want)
		}
	}

	// --- 46b: AN UNCLASSIFIED RECORD REACHES EVERY DESTINATION --------
	//
	// A record with no class — a Describe, or a ref no target declares (since
	// D319 a refusal about a CONFIGURED target carries that target's class, P4
	// step 9) — is not withheld: withholding it would lose rows an incident
	// reads first. Asserted in 46a: "unclassified" is in both.

	// --- 46c: A CLASS NO DESTINATION MAY RECEIVE REFUSES THE BOOT -----
	//
	// **NOT SILENTLY KEPT NOWHERE** — and since D319 refused where it is known,
	// at boot, rather than at the record: the operator's problem is a missing
	// destination.
	t.Run("a class no destination accepts is unrouted, for the boot to refuse", func(t *testing.T) {
		got := auditwal.Unrouted([]string{"eu", "us", "jp"}, eu, us)
		if strings.Join(got, ",") != "jp" {
			t.Errorf("Unrouted = %v; want jp, the served class no destination accepts", got)
		}
	})

	// --- 46c2: THE RECORDER REFUSES, AND THE CHAIN DOES NOT ADVANCE ---
	//
	// **ADDED BY THE MUTATION AUDIT (D161).** Deleting the recorder's own
	// residency check survived the whole suite: nothing proved D89's claim that
	// "the recorder refuses before hashing, so a rejected record never advances
	// the chain and never leaves a gap that reads as tampering". The routing arms
	// above test the SINK's view; this tests the recorder's, and they are
	// different guarantees — a sink can only decline what it is handed, and the
	// recorder is what decides not to hand it over.
	//
	// **THE CHAIN IS THE HALF THAT MATTERS.** Refusing the write is the obvious
	// part. Not advancing `prevHash` is the subtle one: a rejected record that
	// consumed a chain position would leave every later record pointing at a hash
	// nothing produced, and `VerifyChain` would report tampering for a system
	// behaving exactly as designed — which is D77's crying-wolf failure aimed at
	// the one artefact that must stay trustworthy.
	t.Run("the recorder refuses a record its sink may not receive", func(t *testing.T) {
		euOnly := &recordingSink{name: "eu-only", residencies: []string{"eu"}}
		rec := auditwal.NewRecorder(euOnly, "test-config")

		if _, err := rec.Terminal(ctx, &sekizuiv1.Decision{
			Action: "kata.create_issue", TargetRef: "kata:beta", Residency: "us",
		}); err == nil {
			t.Fatal("the recorder wrote a us-resident record to an eu-only sink. " +
				"Shipping EU-resident decision records to a US warehouse makes the " +
				"audit log itself the violation (D29 item 4), and the sink can only " +
				"decline what it is handed")
		}
		if len(euOnly.received()) != 0 {
			t.Error("the refused record reached the sink anyway")
		}

		// AND THE CHAIN IS INTACT. Two permitted records after the refusal must
		// verify as a continuous chain — if the refused one had advanced
		// prevHash, the first of these would point at a hash nothing wrote.
		for _, id := range []string{"eu-a", "eu-b"} {
			if _, err := rec.Terminal(ctx, &sekizuiv1.Decision{
				Id: id, Action: "kata.create_issue", TargetRef: "kata:alpha", Residency: "eu",
			}); err != nil {
				t.Fatalf("writing %s: %v", id, err)
			}
		}
		if err := auditwal.VerifyChain(euOnly.received()); err != nil {
			t.Errorf("the chain does not verify after a refused write: %v. A rejected "+
				"record that consumed a chain position makes every later record point "+
				"at a hash nothing produced, and the log reports tampering for a system "+
				"working as designed", err)
		}
	})

}
