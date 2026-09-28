package auditwal

import (
	"strings"

	"github.com/fullstorydev/sekizui/pkg/audit"
)

// **THE SYNCHRONOUS FAN-OUT WAS HERE, AND D319 RETIRED IT.** D120 delivered
// every record to every permitted sink on the recorder's path, so a refusing
// destination refused the record — and the command with it. Destinations are
// now shipped ASYNCHRONOUSLY from the local WAL (ship.go): the same residency
// routing, the same never-drop property, and a failing destination raises
// `audit_unavailable` instead of stopping the gateway. What survives here is
// the routing both share: which sink may receive which record.

// accepts reports whether a sink permitted these classes may take this record.
//
// NIL MEANS ANY, matching Sink.Residencies' contract. An EMPTY residency on the
// record is accepted by every sink: a decision refused before resolution has no
// target and therefore no class, and those are §5.4's highest-value rows (D89).
func accepts(allowed []string, residency string) bool {
	if allowed == nil || residency == "" {
		return true
	}
	for _, a := range allowed {
		if a == residency {
			return true
		}
	}
	return false
}

// Restrict narrows which residency classes a sink may receive (D29 item 4,
// D120).
//
// A WRAPPER RATHER THAN A FIELD ON JSONLSink, because the restriction is a
// property of how a destination is CONFIGURED rather than of what it is. The
// same warehouse can be the eu destination in one deployment and unconstrained
// in another, and a sink type that carried its own classes would have to be
// constructed differently for each — which is where the two drift.
func Restrict(s audit.Sink, classes []string) audit.Sink {
	return &restricted{Sink: s, classes: classes}
}

type restricted struct {
	audit.Sink
	classes []string
}

func (r *restricted) Residencies() []string { return r.classes }

func (r *restricted) Name() string {
	return r.Sink.Name() + "[" + strings.Join(r.classes, "|") + "]"
}
