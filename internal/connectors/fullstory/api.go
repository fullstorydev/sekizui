package fullstory

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/fullstorydev/sekizui/internal/apiref"
	"github.com/fullstorydev/sekizui/internal/schemasubset"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// THE DOCUMENTED API, DERIVED FROM ITS CONTRACTS (D313, D314). Every operation
// the reference revision documents and no decision excluded becomes an action:
// its input schema is the operation's parameters and request body, its data
// schema is the closed subset of its success response, and its request is built
// from its documented path. What is NOT derived is what only a human can say —
// the action's NAME where the vendor's operation id is ambiguous, and whether a
// write is repeat-safe (§4.9a.1, D163) — and both are tables below, reviewed.
//
// The four actions P2 built by hand (create_event, upsert_user, session_events,
// poll) keep their own code and shapes: grants, lenses and signed steps name
// them, and their handling is not generic.

//go:embed reference/2026-09/contracts/*.json
var contractFS embed.FS

// excludedByDecision are the operations this connector does not carry, with the
// decision (D301: legacy data export and segment export). The manifest records
// the same; P4 step 3 holds the two to each other.
//
//nolint:gochecknoglobals // immutable, reviewed
var excludedByDecision = map[string]string{
	"GET /api/v1/export/get": "D301", "GET /api/v1/export/list": "D301",
	"GET /api/v1/export/userEvents": "D301", "GET /api/v1/export/userPages": "D301",
	"POST /segments/v1/exports": "D301", "GET /search/v1/exports/{id}/results": "D301",
}

// handBuilt are the operations the P2 actions already reach.
//
//nolint:gochecknoglobals // immutable
var handBuilt = map[string]bool{
	"POST /v2/events": true, "POST /v2/users": true,
	"POST /v2/sessions/{session_id}/context": true, "GET /sessions/v2": true,
}

// writeClass is the maintainer's ruling on every operation that is not a GET (D314): a
// POST may READ (context, summary), and a write's idempotency is how a repeat is
// made safe — `natural` for an update or delete that lands the same state twice,
// `none` for a create or an append that a repeat would duplicate.
type writeClass struct {
	mutating    bool
	idempotency connector.IdempotencyClass
}

//nolint:gochecknoglobals // immutable, ruled by the maintainer (D314)
var writeClasses = map[string]writeClass{
	"POST /v2/sessions/{session_id}/summary":                  {mutating: false},
	"POST /v2/users/{id}":                                     {true, connector.IdempotencyNatural},
	"DELETE /v2/users/{id}":                                   {true, connector.IdempotencyNatural},
	"DELETE /users/v1/individual/{uid}":                       {true, connector.IdempotencyNatural},
	"POST /users/v1/individual/{uid}/customvars":              {true, connector.IdempotencyNatural},
	"POST /users/v1/individual/{uid}/customevent":             {true, connector.IdempotencyNone},
	"POST /v2/events/batch":                                   {true, connector.IdempotencyNone},
	"POST /v2/users/batch":                                    {true, connector.IdempotencyNone},
	"POST /v2/users/stream":                                   {true, connector.IdempotencyNone},
	"POST /v2/annotations":                                    {true, connector.IdempotencyNone},
	"POST /v2/visit_profile":                                  {true, connector.IdempotencyNone},
	"POST /v2/visit_profile/{id}":                             {true, connector.IdempotencyNatural},
	"DELETE /v2/visit_profile/{id}":                           {true, connector.IdempotencyNatural},
	"POST /operations/v1/{id}/cancel":                         {true, connector.IdempotencyNatural},
	"POST /settings/recording/v1/privacy:element-block-rules": {true, connector.IdempotencyNone},
	"POST /v2beta/privacy/elements":                           {true, connector.IdempotencyNone},
	"POST /v2beta/privacy/elements/{id}":                      {true, connector.IdempotencyNatural},
	"DELETE /v2beta/privacy/elements/{id}":                    {true, connector.IdempotencyNatural},
	"POST /v2beta/extraction/rules":                           {true, connector.IdempotencyNone},
	"PUT /v2beta/extraction/rules/{id}":                       {true, connector.IdempotencyNatural},
	"PATCH /v2beta/extraction/rules/{id}":                     {true, connector.IdempotencyNatural},
	"POST /v2beta/extraction/rules/{id}/archive":              {true, connector.IdempotencyNatural},
	"POST /v2beta/extraction/rules/{id}/unarchive":            {true, connector.IdempotencyNatural},
}

// nameOverrides give an action a name where the vendor's operation id would
// collide or say nothing (D49's reasoning for MCP tools): `list-sessions` names
// two operations, `Get`/`Update`/`Delete` name session profiles without saying
// so, and the v1 user operations share ids with the v2 ones.
//
//nolint:gochecknoglobals // immutable, reviewed
var nameOverrides = map[string]string{
	"GET /v2/visit_profile/{id}":                  "get_session_profile",
	"GET /v2/visit_profile":                       "list_session_profiles",
	"POST /v2/visit_profile":                      "create_session_profile",
	"POST /v2/visit_profile/{id}":                 "update_session_profile",
	"DELETE /v2/visit_profile/{id}":               "delete_session_profile",
	"GET /users/v1/individual/{uid}":              "get_user_v1",
	"DELETE /users/v1/individual/{uid}":           "delete_user_v1",
	"POST /users/v1/individual/{uid}/customevent": "set_user_events_v1",
	"POST /users/v1/individual/{uid}/customvars":  "set_user_properties_v1",
	"PUT /v2beta/extraction/rules/{id}":           "replace_extraction_rule",
	"GET /me":                                     "get_api_key_owner",
}

// apiAction is one derived action and what it needs at call time.
type apiAction struct {
	spec   connector.ActionSpec
	ep     endpoint
	op     apiref.Operation
	params []apiParam
	body   map[string]any // the request body schema, nil when there is none
	schema string         // the data schema's JSON, "" for NoResult
}

type apiParam struct {
	name, in, typ string
	required      bool
}

// apiActions are derived once, from the embedded contracts.
var apiActions = sync.OnceValues(func() ([]apiAction, error) { //nolint:gochecknoglobals // derived once
	entries, err := contractFS.ReadDir("reference/2026-09/contracts")
	if err != nil {
		return nil, err
	}
	var out []apiAction
	names := map[string]string{}
	for _, e := range entries {
		raw, err := contractFS.ReadFile("reference/2026-09/contracts/" + e.Name())
		if err != nil {
			return nil, err
		}
		var op apiref.Operation
		if err := json.Unmarshal(raw, &op); err != nil {
			return nil, fmt.Errorf("contract %s: %w", e.Name(), err)
		}
		key := op.Key()
		if op.Tier == "anywhere" || excludedByDecision[key] != "" || handBuilt[key] {
			continue
		}
		a, err := deriveAction(op)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if other, dup := names[a.spec.Name]; dup {
			return nil, fmt.Errorf("%s and %s both derive the action %s — add a name override", key, other, a.spec.Name)
		}
		names[a.spec.Name] = key
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].spec.Name < out[j].spec.Name })
	return out, nil
})

var camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`) //nolint:gochecknoglobals // immutable

func actionName(op apiref.Operation) string {
	if n := nameOverrides[op.Key()]; n != "" {
		return Kind + "." + n
	}
	id := camelBoundary.ReplaceAllString(op.OperationID, "${1}_${2}")
	return Kind + "." + strings.ToLower(strings.ReplaceAll(id, "-", "_"))
}

func deriveAction(op apiref.Operation) (apiAction, error) {
	key := op.Key()
	class, ruled := writeClasses[key]
	switch {
	case op.Method == http.MethodGet:
		class = writeClass{mutating: false}
	case !ruled:
		return apiAction{}, fmt.Errorf("no ruling on whether this %s writes, or how a repeat is made safe — "+
			"a human decides (§4.9a.1, D163)", op.Method)
	}
	name := actionName(op)
	a := apiAction{op: op, ep: endpoint{op.Method, op.Path}}

	var params []struct {
		Name     string         `json:"name"`
		In       string         `json:"in"`
		Required bool           `json:"required"`
		Schema   map[string]any `json:"schema"`
	}
	if len(op.Parameters) > 0 && string(op.Parameters) != "null" {
		if err := json.Unmarshal(op.Parameters, &params); err != nil {
			return apiAction{}, fmt.Errorf("parameters: %w", err)
		}
	}
	for _, p := range params {
		if p.In != "path" && p.In != "query" {
			continue // headers and cookies are the driver's, never a caller's
		}
		typ, _ := p.Schema["type"].(string)
		a.params = append(a.params, apiParam{name: p.Name, in: p.In, typ: typ, required: p.Required || p.In == "path"})
	}
	if len(op.RequestBody) > 0 && string(op.RequestBody) != "null" {
		if err := json.Unmarshal(op.RequestBody, &a.body); err != nil {
			return apiAction{}, fmt.Errorf("request body: %w", err)
		}
		props, _ := a.body["properties"].(map[string]any)
		for _, p := range a.params {
			if _, clash := props[p.name]; clash {
				return apiAction{}, fmt.Errorf("parameter %q and a body field share a name", p.name)
			}
		}
	}

	a.spec = connector.ActionSpec{
		Name: name, Mutating: class.mutating, Idempotency: class.idempotency,
		InputSchema: "sekizui://schema/fullstory/" + strings.TrimPrefix(name, Kind+".") + ".v1",
		Description: describe(op),
	}
	if len(op.Response) > 0 && string(op.Response) != "null" {
		var resp map[string]any
		if err := json.Unmarshal(op.Response, &resp); err != nil {
			return apiAction{}, fmt.Errorf("response: %w", err)
		}
		var warnings []string
		closed := schemasubset.Closed(resp, "", &warnings)
		if closed["type"] == nil {
			closed["type"] = "object"
		}
		body, _ := json.Marshal(closed)
		a.schema = string(body)
		a.spec.OutputType = Kind + ".api." + strings.TrimPrefix(name, Kind+".") + ".v1"
	} else {
		a.spec.NoResult = true
	}
	return a, nil
}

// describe is the action's catalog description: the reference's own first
// sentence, which is documentation prose rather than instructions to a model,
// and the operation it performs — so a grant reviewer sees what it touches.
func describe(op apiref.Operation) string {
	d := strings.TrimSpace(op.Description)
	if i := strings.Index(d, ". "); i > 0 {
		d = d[:i+1]
	}
	if d == "" {
		d = op.Title + "."
	}
	return fmt.Sprintf("%s (%s %s)", d, op.Method, op.Path)
}

// apiActionFor finds a derived action by name.
func apiActionFor(name string) (apiAction, bool) {
	actions, err := apiActions()
	if err != nil {
		return apiAction{}, false
	}
	for _, a := range actions {
		if a.spec.Name == name {
			return a, true
		}
	}
	return apiAction{}, false
}

// callAPI performs one derived action: the arguments checked against the
// operation's contract CLOSED BY DEFAULT (an argument the reference does not
// document is refused, as D289 refuses one for an MCP tool), the path filled,
// the query and body built, the request sent through the one egress path.
func (d *Driver) callAPI(ctx context.Context, op string, t connector.Target, a apiAction,
	args map[string]any) (map[string]any, error) {

	var pathVals []string
	query := url.Values{}
	known := map[string]bool{}
	for _, p := range a.params {
		known[p.name] = true
		v, present := args[p.name]
		if !present {
			if p.required {
				return nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
					"%s requires %q (%s)", a.spec.Name, p.name, p.in))
			}
			continue
		}
		s := fmt.Sprint(v)
		if p.in == "path" {
			pathVals = append(pathVals, strings.ReplaceAll(url.PathEscape(s), ":", "%3A"))
		} else {
			query.Set(p.name, s)
		}
	}
	var body []byte
	props, _ := a.body["properties"].(map[string]any)
	payload := map[string]any{}
	for k, v := range args {
		if known[k] {
			continue
		}
		if _, documented := props[k]; !documented {
			return nil, fault.New(fault.KindInvalidArgument, op, fmt.Sprintf(
				"%s takes no argument %q: it is not in the reference's parameters or request body "+
					"(revision %s), and an undocumented argument is refused, not forwarded", a.spec.Name, k,
				referenceRevision))
		}
		payload[k] = v
	}
	if a.body != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fault.Wrap(fault.KindInvalidArgument, op, "the arguments cannot be encoded as JSON", err)
		}
		body = b
	}
	q := ""
	if len(query) > 0 {
		q = "?" + query.Encode()
	}
	var raw []byte
	work := func(ctx context.Context, _ any) error {
		var err error
		raw, err = d.send(ctx, op, t, a.ep, pathVals, q, body)
		return err
	}
	if err := connector.AssertTenant(ctx, t); err != nil {
		return nil, err
	}
	if d.pool == nil {
		if err := work(ctx, nil); err != nil {
			return nil, err
		}
	} else if err := d.pool.Do(ctx, t, work); err != nil {
		return nil, err
	}
	if a.spec.NoResult || len(raw) == 0 {
		return nil, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fault.Wrap(fault.KindTargetError, op, "the response is not the documented JSON object", err)
	}
	return out, nil
}

// apiSchemas are the derived actions' data schemas, for Schemas().
func apiSchemas() ([]connector.Schema, error) {
	actions, err := apiActions()
	if err != nil {
		return nil, err
	}
	var out []connector.Schema
	for _, a := range actions {
		if a.schema != "" {
			out = append(out, connector.Schema{Type: a.spec.OutputType, Body: json.RawMessage(a.schema)})
		}
	}
	return out, nil
}
