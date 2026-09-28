package auditwal

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/fullstorydev/sekizui/internal/atomicfile"
	"github.com/fullstorydev/sekizui/pkg/audit"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Shipper delivers the local WAL's records to audit destinations,
// ASYNCHRONOUSLY, routed by residency (D319).
//
// **THE WAL IS THE DURABILITY BOUNDARY; DESTINATIONS ARE NOT ON THE COMMAND
// PATH.** The recorder writes the local JSONL synchronously — nothing executes
// that is not recorded there (§5.2.2) — and this tails it. D120 fanned out to
// destinations synchronously, so a broken SIEM refused every command; D147's
// rule is that audit fails closed but LOCALLY, and §9.15 rejected centralised
// audit for exactly that coupling.
//
// **AT LEAST ONCE (D319).** Each destination has a cursor — the byte offset of
// the first record it has not accepted — persisted beside the WAL. It advances
// only after the destination accepts a batch, so a crash mid-ship re-delivers;
// every record carries its decision id and phase to deduplicate on. Only whole
// lines are shipped, so a record the recorder is mid-writing is never sent half.
//
// **A FAILING DESTINATION IS A LEVEL, NOT A LOSS.** Its cursor stays where it
// is, `Unavailable` names it and why — the `audit_unavailable` signal an anzen
// rule acts on — and the next successful ship catches up and clears it.
type Shipper struct {
	wal   string
	dests []destination
	batch int

	// continuous is set when the recorder persists its chain tail (D78): a
	// restart's first record then carries the old tail's hash, so a record
	// with NO prev_hash after one already shipped is a break, not a restart
	// (D324).
	continuous bool

	// log reports each destination's edge — stopped, recovered — the moment
	// it happens, and each break a reset vouched for (D324). Nil is silent.
	log *slog.Logger

	mu          sync.Mutex
	unavailable map[string]string // destination -> why, while failing
}

// RequireContinuousChain declares that the WAL's recorder persists its chain
// tail, so every record after the first a destination receives must name its
// predecessor (D324). `main` sets it: its recorder always persists the tail.
// Without it, an empty prev_hash is read as a restart, as VerifyChain reads
// it — the blind spot D322 recorded.
func (s *Shipper) RequireContinuousChain() *Shipper {
	s.continuous = true
	return s
}

// WithLogger reports each destination stopping or recovering AS IT HAPPENS
// (D324): the source watcher publishes `audit_unavailable` once a minute for
// anzen, which left an operator up to a minute behind a stopped stream.
func (s *Shipper) WithLogger(l *slog.Logger) *Shipper {
	s.log = l
	return s
}

type destination struct {
	name   string
	sink   audit.Sink
	cursor string // file holding the byte offset
}

// NewShipper ships wal to each sink, keeping each one's cursor at
// `<wal>.ship.<name>`. Names come from the sinks and must be unique.
func NewShipper(wal string, sinks ...audit.Sink) (*Shipper, error) {
	s := &Shipper{wal: wal, batch: 256, unavailable: map[string]string{}}
	seen := map[string]bool{}
	for i, sink := range sinks {
		name := fmt.Sprintf("%d-%s", i, safeName(sink.Name()))
		if seen[name] {
			return nil, fault.New(fault.KindConfig, "auditwal.NewShipper", "two destinations share the name "+name)
		}
		seen[name] = true
		s.dests = append(s.dests, destination{name: name, sink: sink, cursor: wal + ".ship." + name})
	}
	return s, nil
}

// Unrouted reports the residency classes of served that no destination accepts
// — for the boot to refuse (D319). An unconstrained destination accepts all.
func Unrouted(served []string, sinks ...audit.Sink) []string {
	if len(sinks) == 0 {
		return nil
	}
	var out []string
	for _, class := range served {
		ok := false
		for _, s := range sinks {
			if accepts(s.Residencies(), class) {
				ok = true
				break
			}
		}
		if !ok {
			out = append(out, class)
		}
	}
	sort.Strings(out)
	return out
}

// Unavailable is the `audit_unavailable` level: each destination currently
// failing, and why. Empty when every destination is caught up or catching up.
func (s *Shipper) Unavailable() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.unavailable))
	for k, v := range s.unavailable {
		out[k] = v
	}
	return out
}

// ShipOnce delivers everything each destination has not yet accepted. It
// returns nothing: a failing destination is recorded in Unavailable and retried
// next time, and never stops the others.
//
// **CONCURRENTLY, ONE GOROUTINE PER DESTINATION** — D120's "a slow sink delays
// only itself", kept: each destination has its own cursor, so a SIEM having a
// bad day must not decide how fast a warehouse is shipped to.
func (s *Shipper) ShipOnce(ctx context.Context) {
	var wg sync.WaitGroup
	for _, d := range s.dests {
		wg.Add(1)
		go func(d destination) {
			defer wg.Done()
			err := s.shipTo(ctx, d)
			s.mu.Lock()
			defer s.mu.Unlock()
			was, failing := s.unavailable[d.name]
			switch {
			case err != nil:
				s.unavailable[d.name] = err.Error()
				if s.log != nil && (!failing || was != err.Error()) {
					s.log.Warn("an audit destination stopped receiving records", "destination", d.name, "why", err.Error())
				}
			case failing:
				delete(s.unavailable, d.name)
				if s.log != nil {
					s.log.Info("an audit destination recovered and is caught up", "destination", d.name)
				}
			}
		}(d)
	}
	wg.Wait()
}

// Run ships every interval until ctx ends.
func (s *Shipper) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.ShipOnce(ctx)
		select {
		case <-ctx.Done():
			s.ShipOnce(context.WithoutCancel(ctx)) // one last catch-up on shutdown
			return
		case <-t.C:
		}
	}
}

func (s *Shipper) shipTo(ctx context.Context, d destination) error {
	const op = "auditwal.Shipper.ship"
	offset, prev, vouched, fresh, err := readCursor(d.cursor)
	if err != nil {
		return err
	}
	f, err := os.Open(s.wal)
	if errors.Is(err, os.ErrNotExist) {
		return nil // nothing recorded yet
	}
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "opening the WAL", err)
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing

	// **A WAL SHORTER THAN THE CURSOR WAS TRUNCATED OR REPLACED, AND SHIPPING
	// STOPS UNTIL AN OPERATOR SAYS WHY (D321).** Seeking past the end reads
	// nothing, so this destination went quiet for good while the level said all
	// was well — the silent loss §5.2.2 forbids, and found that way: a rebuilt
	// acceptance WAL under the previous run's cursors shipped nothing and raised
	// nothing. Resetting to zero would ship whatever file now sits here, and a
	// shrinking audit log is what tampering looks like, so trust is not restored
	// automatically. Deleting the cursor is the operator's reset. KindConfig,
	// as the chain tail's: on-disk state beside the WAL an operator must fix.
	info, err := f.Stat()
	if err != nil {
		return fault.Wrap(fault.KindInternal, op, "reading the WAL's size", err)
	}
	// **A FRESH CURSOR VOUCHES FOR THE WAL AS IT STANDS (D324).** No cursor is
	// a first ship, or an operator's reset — removing it is the one act that
	// restores trust. Breaks before this size are then accepted and logged,
	// not refused: a reset that stopped at the same mid-file break again, as
	// the first version did, left an operator no way forward. What is
	// appended after is held to the chain again.
	if fresh {
		vouched = info.Size()
	}
	if offset > info.Size() {
		return fault.New(fault.KindConfig, op, fmt.Sprintf("the WAL is %d bytes, shorter than destination "+
			"%s's cursor at byte %d: it was truncated or replaced. Nothing is shipped to %s until an operator "+
			"has established why and removes %s", info.Size(), d.name, offset, d.name, d.cursor))
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return fault.Wrap(fault.KindInternal, op, "seeking the WAL", err)
	}
	r := bufio.NewReader(f)
	for {
		var batch []*sekizuiv1.Decision
		consumed := int64(0)
		var broken error
		for len(batch) < s.batch {
			line, rerr := r.ReadBytes('\n')
			if rerr == io.EOF || (rerr == nil && len(line) == 0) {
				break // a partial last line is left for the next ship
			}
			if rerr != nil {
				return fault.Wrap(fault.KindInternal, op, "reading the WAL", rerr)
			}
			at := offset + consumed
			var rec sekizuiv1.Decision
			if err := protojson.Unmarshal(line, &rec); err != nil {
				if at < vouched {
					s.vouch(d, at, "a line that does not parse is skipped")
					consumed += int64(len(line))
					continue
				}
				broken = fault.Wrap(fault.KindConfig, op, fmt.Sprintf("WAL record at byte %d does not parse; "+
					"nothing from it on is shipped to %s", at, d.name), err)
				break
			}
			// The two chain checks below yield to a reset's vouching (D324).
			vouchedFor := at < vouched
			// **EVERY RECORD CONTINUES THE CHAIN THE CURSOR LAST SAW (D322).**
			// The cursor holds the hash of the last record it consumed, so the
			// next must name it as prev_hash — or start a new segment (a
			// restart), as VerifyChain allows. A WAL replaced and grown past the
			// cursor fails here at its first record, and a record altered before
			// it shipped is refused rather than delivered: a destination only
			// ever receives records that continue the chain. With no hash yet —
			// a first ship, or an operator's reset — the file's first record is
			// taken as it stands: a persisted chain tail (D78) legitimately
			// carries a prev_hash into a rotated WAL, and nothing here can say
			// what it should be.
			segmentStart := prev != nil && len(rec.GetPrevHash()) == 0 && s.continuous
			mismatch := prev != nil && len(rec.GetPrevHash()) != 0 && !bytesEqual(rec.GetPrevHash(), prev)
			if vouchedFor && (segmentStart || mismatch) {
				s.vouch(d, at, fmt.Sprintf("record %q does not continue the chain; shipped on the reset's word", rec.GetId()))
				segmentStart, mismatch = false, false
			}
			if segmentStart {
				broken = fault.New(fault.KindConfig, op, fmt.Sprintf("WAL record %q at byte %d starts a new chain "+
					"segment, and this WAL's recorder persists its tail, so a restart would have continued the "+
					"chain (D78): the tail was lost, or the WAL was replaced. Nothing from it on is shipped to %s "+
					"until an operator has established why and removes %s (D324)", rec.GetId(), at, d.name, d.cursor))
				break
			}
			if mismatch {
				broken = fault.New(fault.KindConfig, op, fmt.Sprintf("WAL record %q at byte %d does not continue the "+
					"chain destination %s last shipped (prev_hash %s, expected %s): the WAL was altered, replaced "+
					"or reordered. Nothing from it on is shipped to %s until an operator has established why and "+
					"removes %s", rec.GetId(), at, d.name, short(rec.GetPrevHash()), short(prev), d.name, d.cursor))
				break
			}
			h, err := hashDecision(&rec)
			if err != nil {
				return fault.Wrap(fault.KindInternal, op, "hashing a WAL record", err)
			}
			prev = h
			consumed += int64(len(line))
			if accepts(d.sink.Residencies(), rec.GetResidency()) {
				batch = append(batch, &rec)
			}
		}
		// What verified before a break still ships: the break stops the stream,
		// it does not withhold the records that preceded it.
		if len(batch) > 0 {
			if err := d.sink.Write(ctx, batch); err != nil {
				return fault.Wrap(fault.KindTargetUnavailable, op, fmt.Sprintf("destination %s refused %d record(s); "+
					"its cursor stays at byte %d and it will catch up", d.name, len(batch), offset), err)
			}
		}
		if consumed > 0 {
			offset += consumed
			if err := writeCursor(d.cursor, offset, prev, vouched); err != nil {
				return fault.Wrap(fault.KindInternal, op, "persisting "+d.name+"'s cursor", err)
			}
		}
		if broken != nil || consumed == 0 {
			return broken
		}
	}
}

// A cursor is `<byte offset> <hex hash of the last record consumed> <vouched
// through>` — the hash empty at offset zero, and the last field the WAL's size
// when the cursor was created fresh: breaks before it were vouched for by a
// first ship or an operator's reset (D324). The hash is not a secret: it is
// the next record's own prev_hash, already in the WAL and in every
// destination (D322).
func writeCursor(path string, offset int64, last []byte, vouched int64) error {
	return atomicfile.Write(path, []byte(fmt.Sprintf("%d %s %d", offset, hex.EncodeToString(last), vouched)), 0o600)
}

// readCursor returns the offset, the last hash, the vouched boundary, and
// whether there was no cursor at all — a first ship, or an operator's reset.
func readCursor(path string) (offset int64, last []byte, vouched int64, fresh bool, err error) {
	const op = "auditwal.readCursor"
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil, 0, true, nil
	}
	if err != nil {
		return 0, nil, 0, false, fault.Wrap(fault.KindInternal, op, path, err)
	}
	bad := fault.New(fault.KindConfig, op, fmt.Sprintf("%s holds %q, not `<byte offset> <record hash> <vouched through>`", path, raw))
	fields := strings.Fields(string(raw))
	if len(fields) < 1 || len(fields) > 3 {
		return 0, nil, 0, false, bad
	}
	n, perr := strconv.ParseInt(fields[0], 10, 64)
	if perr != nil || n < 0 {
		return 0, nil, 0, false, bad
	}
	if len(fields) > 1 {
		if last, err = hex.DecodeString(fields[1]); err != nil {
			return 0, nil, 0, false, bad
		}
	}
	if n > 0 && len(last) != sha256.Size {
		return 0, nil, 0, false, bad
	}
	if len(fields) == 3 {
		if vouched, perr = strconv.ParseInt(fields[2], 10, 64); perr != nil || vouched < 0 {
			return 0, nil, 0, false, bad
		}
	}
	return n, last, vouched, false, nil
}

// vouch logs a break a fresh cursor accepted (D324): the operator's reset is
// what let it through, and the log is where that stays visible.
func (s *Shipper) vouch(d destination, at int64, what string) {
	if s.log != nil {
		s.log.Warn("an audit break was shipped past on a fresh cursor's vouching", "destination", d.name,
			"byte", at, "what", what)
	}
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}
