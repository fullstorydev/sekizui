package fullstory

import (
	"net/http"
	"strings"
)

// referenceRevision is the Fullstory Server API reference this driver was built
// and checked against — the DATE is the label, the committed snapshot at
// `reference/<revision>/manifest.yaml` is the evidence (D299). Every endpoint in
// `surface` must be in that manifest (P4 criterion 7), and refreshing the
// reference is a new directory and a new value here, re-passing the guard.
const referenceRevision = "2026-09"

// endpoint is one Fullstory API operation this driver calls: its method and its
// documented path template, exactly as the reference writes it.
type endpoint struct {
	method   string
	template string
}

// THE DRIVER'S WHOLE SURFACE, DECLARED ONCE (D299, P4 step 2). Every request
// this package builds takes its method and path from one of these — `send` and
// `post` accept an endpoint, never a path string — so the list below cannot
// under-report what the driver calls, and a guard compares it with the
// reference instead of reading string concatenations.
//
//nolint:gochecknoglobals // immutable surface, fixed at compile time
var (
	epSessionContext = endpoint{http.MethodPost, "/v2/sessions/{session_id}/context"}
	epListSessions   = endpoint{http.MethodGet, "/sessions/v2"}
	epCreateEvent    = endpoint{http.MethodPost, "/v2/events"}
	epUpsertUser     = endpoint{http.MethodPost, "/v2/users"}

	surface = []endpoint{epSessionContext, epListSessions, epCreateEvent, epUpsertUser}
)

// path fills the template's `{placeholders}` in order with values the caller
// has already escaped (a session id's colon is `%3A`, which url.PathEscape does
// not do). A placeholder left unfilled stays in the path and the request 404s —
// a programming error the package's tests make impossible.
func (e endpoint) path(params ...string) string {
	out := e.template
	for _, p := range params {
		i := strings.IndexByte(out, '{')
		j := strings.IndexByte(out, '}')
		if i < 0 || j < i {
			break
		}
		out = out[:i] + p + out[j+1:]
	}
	return out
}

// Surface returns every operation this driver calls, as "METHOD /template", in
// the reference's own spelling — what P4 step 2 checks against the snapshot.
func (d *Driver) Surface() []string {
	out := make([]string, 0, len(surface))
	for _, e := range surface {
		out = append(out, e.method+" "+e.template)
	}
	// AND EVERY DERIVED ACTION'S OPERATION (D314): the same one endpoint type,
	// built from the contract, taking the same one send.
	if derived, err := apiActions(); err == nil {
		for _, a := range derived {
			out = append(out, a.ep.method+" "+a.ep.template)
		}
	}
	return out
}

// ReferenceRevision is the reference revision this driver declares (D299).
func (d *Driver) ReferenceRevision() string { return referenceRevision }
