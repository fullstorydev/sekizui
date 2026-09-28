package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// handleExpiry is the producer named on every close Sekizui makes itself
// (D291) — the caller's credential id and the causation's produced_by, so the
// log says the close was SYSTEM-initiated while crediting it to the opener.
const handleExpiry = "sekizui:handle-expiry"

// openHandle is one stateful handle an opener returned and nothing has closed.
type openHandle struct {
	target, value         string // value is the handle itself: never logged raw
	opener                string // the subject principal who opened it
	closeAction, closeArg string
	openDecision          string
	lastUsed              time.Time
}

// handleTable holds the open handles, per replica (like D254's job table).
type handleTable struct {
	mu   sync.Mutex
	open map[string]*openHandle // key: target + "\\x00" + value
}

func handleKey(target, value string) string { return target + "\x00" + value }

// fingerprint is what a log may say about a handle: Fullstory's `client_id`
// ENCODES the session and org it opens, so the value itself is never logged.
func fingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

// trackHandle updates the table after a SUCCESSFUL command (D291): an opener
// records its handle, a user touches it, a closer forgets it. Called with the
// driver's raw result, before shaping — the handle is the connector's field,
// whatever the data_schema admits.
func (s *Server) trackHandle(spec connector.ActionSpec, driver connector.Driver, id *sekizuiv1.Identity,
	cmd *sekizuiv1.Command, args, data map[string]any, decisionID string) {

	h := spec.Handle
	if h == nil || s.handles == nil {
		return
	}
	target := cmd.GetTargetRef()
	s.handles.mu.Lock()
	defer s.handles.mu.Unlock()
	switch {
	case h.Opens != "":
		v, _ := data[h.Opens].(string)
		if v == "" {
			s.log.Warn("an opener returned no handle; nothing to close later",
				"action", spec.Name, "target", target, "field", h.Opens)
			return
		}
		closeAction, closeArg := closerFor(driver, spec.Name)
		if closeAction == "" {
			return // validated at load: an opener has a closer
		}
		s.handles.open[handleKey(target, v)] = &openHandle{
			target: target, value: v, opener: id.GetSubject().GetPrincipal(),
			closeAction: closeAction, closeArg: closeArg, openDecision: decisionID,
			lastUsed: s.now(),
		}
	case h.Uses != "":
		if v, _ := args[h.Uses].(string); v != "" {
			if e, ok := s.handles.open[handleKey(target, v)]; ok {
				e.lastUsed = s.now()
			}
		}
	case h.Closes != "":
		if v, _ := args[h.Closes].(string); v != "" {
			delete(s.handles.open, handleKey(target, v))
		}
	}
}

// closerFor finds the action that closes the handle `opener` opens: the one in
// the same connector namespace (`mcp.<server>.`) declaring Closes.
func closerFor(driver connector.Driver, opener string) (action, arg string) {
	prefix := opener[:strings.LastIndex(opener, ".")+1]
	for _, a := range driver.Actions() {
		if a.Handle != nil && a.Handle.Closes != "" && strings.HasPrefix(a.Name, prefix) {
			return a.Name, a.Handle.Closes
		}
	}
	return "", ""
}

// idleFor is a target's idle limit: its own handle_idle_s, else the deployment's.
func (s *Server) idleFor(target string) time.Duration {
	if s.doc != nil {
		for _, t := range s.doc.Targets {
			if t.Ref == target && t.Limits != nil && t.Limits.HandleIdleS > 0 {
				return time.Duration(t.Limits.HandleIdleS) * time.Second
			}
		}
	}
	return s.handleIdle
}

// SweepHandles closes every handle idle past its target's limit (D291) and
// returns how many closes it attempted. Called on a timer by the handle
// sweeper component.
func (s *Server) SweepHandles(ctx context.Context) int {
	return s.closeHandles(ctx, func(e *openHandle) bool {
		idle := s.idleFor(e.target)
		return idle > 0 && s.now().Sub(e.lastUsed) >= idle
	}, "idle past its limit")
}

// CloseAllHandles closes every open handle — the drain (D291), so a clean
// shutdown leaves no vendor slot held for a caller that will never return.
func (s *Server) CloseAllHandles(ctx context.Context) int {
	return s.closeHandles(ctx, func(*openHandle) bool { return true }, "the process is draining")
}

// closeHandles closes the handles `due` selects, THROUGH THE ENFORCEMENT PATH
// (D18): as the opener — whose grant must cover the closer, checked at load —
// with an INTERNAL caller naming Sekizui and a causation joining the close to
// the open's decision. The record credits the opener and says the close was
// system-initiated; it never claims the opener's own credential made it.
//
// **BREAK-GLASS CLOSES NOTHING (the maintainer, D291).** A withdrawn target's handles are
// skipped, not attempted: closing needs the very credential break-glass
// revoked, and using a credential declared compromised to tidy up is the wrong
// direction. The vendor expires the slot.
func (s *Server) closeHandles(ctx context.Context, due func(*openHandle) bool, why string) int {
	if s.handles == nil {
		return 0
	}
	s.handles.mu.Lock()
	var batch []*openHandle
	for k, e := range s.handles.open {
		if !due(e) {
			continue
		}
		if s.pool != nil {
			if _, withdrawn := s.pool.Withdrawn(e.target); withdrawn {
				s.log.Warn("a handle on a withdrawn target is NOT closed: closing would use the revoked credential",
					"target", e.target, "handle", fingerprint(e.value))
				delete(s.handles.open, k)
				continue
			}
		}
		batch = append(batch, e)
		delete(s.handles.open, k)
	}
	s.handles.mu.Unlock()
	sort.Slice(batch, func(i, j int) bool { return batch[i].openDecision < batch[j].openDecision })

	for _, e := range batch {
		args, _ := structpb.NewStruct(map[string]any{e.closeArg: e.value})
		id := &sekizuiv1.Identity{
			Caller: &sekizuiv1.Caller{Principal: e.opener, Method: sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL,
				CredentialId: handleExpiry},
			Subject: &sekizuiv1.Subject{Principal: e.opener, Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED},
			Chain:   []string{e.opener},
		}
		res, err := s.Enforce(ctx, id, &sekizuiv1.Command{
			Action: e.closeAction, TargetRef: e.target, Args: args,
			Causation: &sekizuiv1.Causation{RootId: e.openDecision, ParentId: e.openDecision,
				Depth: 1, ProducedBy: handleExpiry, DecisionId: e.openDecision},
		})
		if err != nil || res.GetStatus() != sekizuiv1.Status_STATUS_OK {
			s.log.Warn("Sekizui could not close a handle; the vendor's own expiry will release it",
				"target", e.target, "handle", fingerprint(e.value), "why", why,
				"status", res.GetStatus().String(), "error", err)
			continue
		}
		s.log.Info("Sekizui closed a handle as its opener", "target", e.target,
			"handle", fingerprint(e.value), "opener", e.opener, "why", why)
	}
	return len(batch)
}
