package kyuushin

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Results is a caller's job's output, addressed to that caller alone (D267).
//
// **NOT THE SHARED BUS, AND THAT IS THE DECISION.** D247 put a job's results
// on the bus, where every principal whose subscribe grant matched the subject
// received them: the data another principal ASKED FOR, what it asked, and
// volume it chose to push into their stream — and, once P5 arms reflexes, a
// read-only caller able to trigger writes by starting jobs. A schedule still
// publishes to the bus; its caller is configuration, and its readers are
// scoped by target (D259).
//
// BOUNDED BY THE JOB, NOT BY A NEW NUMBER. A caller's job polls once and asks
// for at most `Limit` events, so a buffer of `Limit` can never fill — and
// `Limit` is already bounded before the job runs by the capability's
// max_bytes (D257). Filling it anyway is a bug, and fails the job rather
// than blocking it or dropping silently.
//
// ONE CONSUMER, AND THE STREAM ENDS WHEN THE JOB DOES. The channel closes when
// the job's work returns, so a caller draining it reaches a real end — the
// thing a bus subscription could never give it.
type Results struct {
	ch chan *sekizuiv1.Envelope

	mu       sync.Mutex
	attached bool
	closed   bool
}

func newResults(limit int) *Results {
	return &Results{ch: make(chan *sekizuiv1.Envelope, limit)}
}

// Publish buffers one result. It never blocks: the buffer is sized to the
// job's limit, so a full buffer is a defect, reported as one.
func (r *Results) Publish(_ context.Context, env *sekizuiv1.Envelope) error {
	select {
	case r.ch <- env:
		return nil
	default:
		return fault.New(fault.KindInternal, "kyuushin.Results.Publish", fmt.Sprintf(
			"the job produced more than its limit of %d results; the buffer is sized to "+
				"the limit and cannot fill unless the poll ignored it", cap(r.ch)))
	}
}

func (r *Results) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		close(r.ch)
	}
}

// Attach claims the stream. A second claim is refused: two readers would each
// receive part of one job's results and neither could tell.
func (r *Results) Attach() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attached {
		return fault.New(fault.KindInvalidArgument, "kyuushin.Results.Attach",
			"this job's results are already being read; a job's results go to one reader "+
				"once, and a second would silently receive only what the first left")
	}
	r.attached = true
	return nil
}

func (r *Results) isAttached() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attached
}

// Next returns the next result, or false when the job has ended and every
// result has been read, or ctx ends.
func (r *Results) Next(ctx context.Context) (*sekizuiv1.Envelope, bool) {
	select {
	case <-ctx.Done():
		return nil, false
	case env, ok := <-r.ch:
		return env, ok
	}
}

// Results returns a caller's job's results, if this runner still holds them.
// The caller authorises the question; this only answers it (D254's split).
func (p *Runner) Results(id string) (*Results, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.results[id]
	return r, ok
}

// finishResults closes a job's results and, if nobody has attached by the time
// the configured TTL passes (Options.ResultsTTL, D268), drops them — logged with the count, because results a
// caller never collected are data nobody read, and saying so is the only trace.
func (p *Runner) finishResults(id string, r *Results) {
	r.close()
	ttl := p.opts.ResultsTTL
	time.AfterFunc(ttl, func() {
		p.mu.Lock()
		delete(p.results, id)
		p.mu.Unlock()
		if !r.isAttached() {
			p.log.Warn("a job's results were never collected and have been dropped",
				"job", id, "undelivered", len(r.ch), "after", ttl)
		}
	})
}
