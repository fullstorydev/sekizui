package auditwal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// JSONLSink appends decision records to a local file, one JSON object per line.
//
// THE P0 SINK, and a legitimate one beyond P0 for a single-node deployment.
// D32 puts the real destination in the operator's own warehouse, and BigQuery
// arrives with P2 — but a local file is what makes P0's exit criteria checkable
// without standing up infrastructure, and JSONL is what every log shipper and
// SIEM already ingests.
//
// STRUCTURED STDOUT IS NOT AN AUDIT LOG (§5.4): retention-limited, interleaved
// with everything else, effectively mutable. Hence a separate file with its own
// lifecycle, rather than a logger call.
type JSONLSink struct {
	path string

	mu sync.Mutex
	f  *os.File
}

// NewJSONLSink returns a sink appending to path. The file is opened on first
// write rather than here, so constructing a sink cannot fail and a misconfigured
// path surfaces during spine's Start rather than during wiring.
func NewJSONLSink(path string) *JSONLSink {
	return &JSONLSink{path: path}
}

// Name identifies this sink in logs and metrics.
func (s *JSONLSink) Name() string { return "jsonl" }

// Residencies returns nil: a local file accepts any residency.
//
// Correct for a single-region deployment and DANGEROUS if that assumption
// changes. D29 item 4 is that shipping EU-resident records to a US warehouse
// makes the audit log itself the violation — a nil here means "no constraint",
// which is only true while the file is on a node inside the right region. P4
// brings residency-partitioned sinks; this returns nil until then because
// claiming a specific residency it cannot enforce would be worse.
func (s *JSONLSink) Residencies() []string { return nil }

// Write appends a batch, one record per line, and fsyncs before returning.
//
// FSYNC IS THE POINT. This is the synchronous audit path (runtime.AuditSync), so
// "written" must mean "survives power loss" — otherwise the two-phase intent
// record buys nothing, because the intent could be lost in exactly the crash it
// exists to describe.
func (s *JSONLSink) Write(ctx context.Context, batch []*sekizuiv1.Decision) error {
	const op = "auditwal.JSONLSink.Write"

	if len(batch) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.openLocked(op); err != nil {
		return err
	}

	// protojson, not encoding/json: protobuf enums must render as their string
	// names ("VERDICT_DENY", not 2) or the audit trail becomes unreadable the
	// moment an enum gains a value. It also handles Timestamp and Struct
	// correctly, which encoding/json does not.
	marshal := protojson.MarshalOptions{
		EmitUnpopulated: false,
		UseProtoNames:   true, // snake_case, matching the .proto and the wire
	}

	buf := make([]byte, 0, 1024*len(batch))
	for _, d := range batch {
		line, err := marshal.Marshal(d)
		if err != nil {
			return fault.Wrap(fault.KindInternal, op,
				fmt.Sprintf("marshalling decision %q", d.GetId()), err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}

	if _, err := s.f.Write(buf); err != nil {
		return fault.Wrap(fault.KindInternal, op, "appending to "+s.path, err)
	}
	// Without this, a crash loses records the caller was told were durable.
	if err := s.f.Sync(); err != nil {
		return fault.Wrap(fault.KindInternal, op, "fsync "+s.path, err)
	}
	return nil
}

func (s *JSONLSink) openLocked(op string) error {
	if s.f != nil {
		return nil
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fault.Wrap(fault.KindConfig, op, "creating audit directory "+dir, err)
		}
	}
	// 0600: decision records carry principals, actions, and targets. Not
	// secrets, but not world-readable either.
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fault.Wrap(fault.KindConfig, op, "opening audit sink "+s.path, err)
	}
	s.f = f
	return nil
}

// Close flushes and releases the file. Called during drain, within
// RuntimeProfile.GracePeriod.
func (s *JSONLSink) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.f == nil {
		return nil // idempotent, per the Component contract
	}
	err := s.f.Close()
	s.f = nil
	if err != nil {
		return fault.Wrap(fault.KindInternal, "auditwal.JSONLSink.Close", "closing "+s.path, err)
	}
	return nil
}

// --- spine lifecycle --------------------------------------------------------
//
// Satisfies spine.Component and spine.HealthReporter structurally, without
// importing spine — same pattern as config.Loader, and the same reason: pkg and
// internal packages should not depend on the lifecycle layer just to be managed
// by it.

// Start opens the sink eagerly, so a bad path fails at boot rather than on the
// first decision — by which point something has already been executed and there
// is nowhere to record it.
func (s *JSONLSink) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openLocked("auditwal.JSONLSink.Start")
}

// Stop closes the file.
func (s *JSONLSink) Stop(ctx context.Context) error { return s.Close(ctx) }

// Health reports whether the sink can currently accept records.
//
// AN UNWRITEABLE AUDIT SINK MUST FAIL READINESS. §5.2.2 calls losing audit
// records "the one unacceptable failure in a governance system" — so a process
// that cannot record must stop accepting work rather than executing commands it
// cannot account for.
func (s *JSONLSink) Health(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.f == nil {
		return fault.New(fault.KindUnavailable, "auditwal.JSONLSink.Health",
			"audit sink is not open")
	}
	return nil
}
