package gateway

import (
	"fmt"

	"github.com/fullstorydev/sekizui/internal/refine"
	"github.com/fullstorydev/sekizui/internal/safestruct"
	"github.com/fullstorydev/sekizui/internal/shin"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// seirenFor is the SEIREN (精錬) for one result: the imposed `refines:` rules
// this caller's audience matches, run over the result's rows AFTER each was
// shaped and lensed for the caller, then lensed again under the seiren's own
// type (D297, D300, D317). Nil when no rule is imposed on this caller.
//
// **IMPOSED, NEVER REQUESTED (D297 ruling 2).** Nothing on the request selects
// it: configuration decides who receives which refinement, and a caller
// outside a rule's `for:` receives the same rows and no seiren (D298).
//
// **A ROW DROPPED AT SHAPING MAKES EVERY RULE UNAVAILABLE (D300).** A lens
// withholds fields; removing a ROW from under a sequence would silently
// falsify it — a wrong dwell, a login that never happened — so the seiren says
// it could not be built rather than being built over a gap.
func (s *Server) seirenFor(target string, lensReq shin.Request, rows []map[string]any, truncated bool,
	dropped int) (*sekizuiv1.Seiren, error) {
	rs := refine.For(s.refinements, target, lensReq.Principal, lensReq.Type)
	if len(rs) == 0 {
		return nil, nil
	}
	if dropped > 0 {
		out := &sekizuiv1.Seiren{Type: rs[0].Rule.Into}
		for _, r := range rs {
			out.Gaps = append(out.Gaps, &sekizuiv1.SeirenGap{Key: r.Rule.Key,
				Kind: sekizuiv1.SeirenGapKind_SEIREN_GAP_KIND_UNAVAILABLE, Reason: fmt.Sprintf(
					"%d row(s) of this result were not admitted at shaping; a sequence over the rest would be false",
					dropped)})
		}
		return out, nil
	}

	// A selected lens that cannot be selected was already refused by Apply,
	// so an error here cannot happen past that point; treat it as withheld
	// rather than as readable, the direction that cannot disclose.
	withheld := func(path string) (string, bool) {
		lens, w, err := s.lenses.Withholds(lensReq, path)
		if err != nil {
			return "(unresolvable)", true
		}
		return lens, w
	}
	computed, err := refine.Refine(rs, rows, truncated, withheld)
	if err != nil {
		return nil, err
	}

	// THE SEIREN IS A PAYLOAD LIKE ANY OTHER, AND PASSES SHIN AGAIN (D297):
	// the imposed lenses on its own type, for this caller. A selected lens is
	// scoped to the ROW type, and has already reached the rules through
	// `withheld` above.
	value, _, lerr := s.lenses.Apply(shin.Request{Principal: lensReq.Principal, Type: computed.Type,
		Residency: lensReq.Residency, Added: lensReq.Added}, computed.Value)
	if lerr != nil {
		return nil, lerr
	}
	v, rep := safestruct.Convert(value, safestruct.DefaultBudget)
	if len(rep.Substituted) > 0 {
		s.log.Warn("a seiren carried values protobuf cannot represent; they were substituted",
			"target", target, "fields", rep.Substituted)
	}
	out := &sekizuiv1.Seiren{
		Type:  computed.Type,
		Value: v,
		Window: &sekizuiv1.SeirenWindow{FirstEventTime: computed.Window.FirstEventTime,
			LastEventTime: computed.Window.LastEventTime, Truncated: computed.Window.Truncated},
		Rules: computed.Rules,
	}
	for _, g := range computed.Gaps {
		kind := sekizuiv1.SeirenGapKind_SEIREN_GAP_KIND_UNAVAILABLE
		if g.Kind == refine.GapTruncated {
			kind = sekizuiv1.SeirenGapKind_SEIREN_GAP_KIND_TRUNCATED
		}
		out.Gaps = append(out.Gaps, &sekizuiv1.SeirenGap{Key: g.Key, Kind: kind, Reason: g.Reason})
	}
	return out, nil
}
