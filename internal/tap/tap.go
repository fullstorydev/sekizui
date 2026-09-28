// Package tap is the raw-envelope dev tap: CAPTURE what a consumer receives,
// and REHEARSE the configured rules against a capture, offline (P3 step 15,
// D273).
//
// **"REHEARSE", NOT "REPLAY".** Replay is what Fullstory calls watching a
// session back, and this is not that. A rehearsal runs captured envelopes
// back through this deployment's reflex rules and projections to show what
// WOULD fire, publish, be refused or project — and nothing is sent anywhere.
//
// **IT CANNOT BECOME AN INGESTION PATH, AND THAT IS STRUCTURAL.** The risk the
// step names is `PublishForTest`'s: a debugging affordance that becomes an
// unsupported way in because nothing stopped it. So:
//
//   - CAPTURE is an ordinary governed Subscribe — authorised by the caller's
//     subscribe grant, recorded once, lensed, scoped by target (D259, D260).
//     It reads; it adds no surface.
//   - REHEARSE runs the real engine code (Dispatch, the Projector) — a second
//     copy of the rules would drift from the first (D155) — with an enforcer
//     that executes nothing and a recorder that keeps nothing. This package
//     does not import the gateway (the only real Enforcer), the bus, or the
//     runner; P3 step 15 fails the build's acceptance if it ever does.
//   - There is no RPC for either. A human runs `sekizui-tap`.
package tap

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/fullstorydev/sekizui/internal/reflex"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// Capture streams envelopes from a governed Subscribe into w, one protojson
// line each, until ctx ends or max envelopes are written (0 = no limit). It
// returns how many were written.
func Capture(ctx context.Context, client sekizuiv1.GatewayServiceClient,
	req *sekizuiv1.SubscribeRequest, w io.Writer, max int) (int, error) {

	stream, err := client.Subscribe(ctx, req)
	if err != nil {
		return 0, err
	}
	n := 0
	for max == 0 || n < max {
		msg, err := stream.Recv()
		if err != nil {
			return n, unlessCleanEnd(ctx, err)
		}
		line, err := protojson.Marshal(msg.GetEnvelope())
		if err != nil {
			return n, fmt.Errorf("envelope %q cannot be written as protojson: %w",
				msg.GetEnvelope().GetId(), err)
		}
		if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// unlessCleanEnd returns err, or nil when it is a CLEAN end of a capture: the
// stream closed, or the human interrupted. Anything else that ends the stream
// is an error the caller must see.
func unlessCleanEnd(ctx context.Context, err error) error {
	if errors.Is(err, io.EOF) || ctx.Err() != nil {
		return nil //nolint:nilerr // deciding which errors are not failures is this function's whole job
	}
	return err
}

// Line is what a rehearsal says about one captured envelope.
type Line struct {
	Envelope   string         `json:"envelope"`
	Would      []Firing       `json:"would,omitempty"`
	Projection map[string]any `json:"projection,omitempty"`
	Projected  []string       `json:"projected_by,omitempty"`
}

// Firing is one rule's outcome for the envelope.
type Firing struct {
	Rule   string `json:"rule"`
	Action string `json:"action,omitempty"`
	Target string `json:"target,omitempty"`
	// Armed is true when the command would have run for real (mode: enforce);
	// false means it would have been a dry run.
	Armed     bool   `json:"armed,omitempty"`
	Publishes string `json:"publishes,omitempty"`
	Debounced bool   `json:"debounced,omitempty"`
	Refused   string `json:"refused,omitempty"`
}

// Rehearse runs each captured envelope in r through doc's rules and
// projections and writes one JSON Line per envelope to w. `drivers` are the
// connectors whose schemas the rehearsal validates against (D279) — handed in
// by the caller, so this package imports no driver and can call none.
func Rehearse(ctx context.Context, doc *config.Document, drivers map[string]connector.Driver,
	r io.Reader, w io.Writer) (int, error) {
	rehearsal := &rehearsalEnforcer{}
	// THE DOCUMENT'S OWN VALIDATOR, so a rehearsal shows an enrichment that
	// would be refused as refused (CONTRACTS 128) rather than as published.
	reg, err := schemareg.ForDeployment(doc, drivers)
	if err != nil {
		return 0, err
	}
	engine := reflex.NewEngine(doc.Reflexes, rehearsal, discard{}, func(context.Context, string, map[string]string) {},
		slog.New(slog.NewTextHandler(io.Discard, nil)), func() string { return "rehearsal" }, reg.Validate)
	projector, err := reflex.NewProjector(doc.Reflexes)
	if err != nil {
		return 0, err
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	enc := json.NewEncoder(w)
	n := 0
	for sc.Scan() {
		env := &sekizuiv1.Envelope{}
		if err := protojson.Unmarshal(sc.Bytes(), env); err != nil {
			return n, fmt.Errorf("capture line %d is not an envelope: %w", n+1, err)
		}
		line := Line{Envelope: env.GetId()}
		rehearsal.last = map[string]*sekizuiv1.Command{}
		for _, o := range engine.Dispatch(ctx, env) {
			f := Firing{Rule: o.Rule, Debounced: o.Debounced}
			if cmd := rehearsal.last[o.Rule]; cmd != nil {
				f.Action, f.Target, f.Armed = cmd.GetAction(), cmd.GetTargetRef(), !cmd.GetDryRun()
			}
			if o.Publish != nil {
				f.Publishes = o.Publish.GetType()
			}
			if o.Err != nil {
				f.Refused = o.Err.Error()
			}
			line.Would = append(line.Would, f)
		}
		if p, by, perr := projector.Project(env); perr == nil && p != nil {
			line.Projection, line.Projected = p.AsMap(), by
		}
		if err := enc.Encode(line); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}

// rehearsalEnforcer executes NOTHING. It remembers the command a rule built so
// the rehearsal can say what would have been sent, and answers as a dry run.
type rehearsalEnforcer struct {
	last map[string]*sekizuiv1.Command
}

func (e *rehearsalEnforcer) Enforce(_ context.Context, id *sekizuiv1.Identity,
	cmd *sekizuiv1.Command) (*sekizuiv1.CommandResult, error) {

	if e.last != nil {
		e.last[ruleOf(cmd)] = cmd
	}
	return &sekizuiv1.CommandResult{Status: sekizuiv1.Status_STATUS_WOULD_HAVE_FIRED,
		Reason: "rehearsal: nothing was executed"}, nil
}

// ruleOf recovers the rule name from the causation BuildCommand stamps.
func ruleOf(cmd *sekizuiv1.Command) string {
	const prefix = "reflex:"
	p := cmd.GetCausation().GetProducedBy()
	if len(p) > len(prefix) {
		return p[len(prefix):]
	}
	return p
}
