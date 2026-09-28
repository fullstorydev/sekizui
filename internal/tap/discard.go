package tap

import (
	"context"

	"github.com/fullstorydev/sekizui/pkg/audit"

	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// discard is a recorder that keeps nothing: a rehearsal's refusals (a spent
// budget, the depth cap) are REPORTED in its output, never written to anybody's
// audit log — a rehearsal is not something that happened.
type discard struct{}

func (discard) Intent(context.Context, *sekizuiv1.Decision) (string, error) { return "rehearsal", nil }
func (discard) Outcome(context.Context, string, *sekizuiv1.Effect, ...audit.OutcomeOption) error {
	return nil
}
func (discard) Terminal(context.Context, *sekizuiv1.Decision) (string, error) {
	return "rehearsal", nil
}
