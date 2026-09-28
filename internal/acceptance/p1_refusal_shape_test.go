package acceptance

import (
	"context"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/verb"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// P1 step 58: every deliberate refusal reaches the caller the SAME way, and the
// record names which stage refused (D135).

func step58RefusalsShareOneShape(t *testing.T) {
	ctx := context.Background()
	r := newRun(t)
	if r.sink != nil {
		defer r.sink.Close(ctx)
	}

	// Four stages, four principals, one shape.
	cases := []struct {
		stage     string
		principal string
		action    string
		target    string
		want      sekizuiv1.RefusedBy
	}{
		{"anzen", "agent:triage", "kata.delete_project", "kata:alpha",
			sekizuiv1.RefusedBy_REFUSED_BY_ANZEN},
		{"policy", "agent:triage", "kata.comment", "kata:alpha",
			sekizuiv1.RefusedBy_REFUSED_BY_POLICY},
		{"residency", "agent:global", "kata.create_issue", "kata:beta",
			sekizuiv1.RefusedBy_REFUSED_BY_RESIDENCY},
	}

	// The withdrawal stage needs setting up, and tearing down again so this step
	// cannot poison a live instance for the next run.
	if _, err := r.as(t, "operator:oncall").Execute(ctx,
		execute(verb.RevokeCredential, "kata:restore", nil)); err != nil {
		t.Fatalf("revoking kata:restore: %v", err)
	}
	defer func() {
		if _, err := r.as(t, "operator:oncall").Execute(ctx,
			execute(verb.RestoreTarget, "kata:restore", nil)); err != nil {
			t.Errorf("restoring kata:restore: %v", err)
		}
	}()
	cases = append(cases, struct {
		stage     string
		principal string
		action    string
		target    string
		want      sekizuiv1.RefusedBy
	}{"withdrawal", "agent:binding", "kata.create_issue", "kata:restore",
		sekizuiv1.RefusedBy_REFUSED_BY_WITHDRAWAL})

	seen := map[sekizuiv1.RefusedBy]bool{}
	kinds := map[string]bool{}
	statuses := map[sekizuiv1.Status]bool{}

	for _, c := range cases {
		t.Run(c.stage, func(t *testing.T) {
			resp, err := r.as(t, c.principal).Execute(ctx,
				execute(c.action, c.target, map[string]any{"project": "PROJ"}))

			// --- ONE SHAPE ---------------------------------------------------
			if err != nil {
				t.Fatalf("refused as a transport ERROR (%v). Before D135 some stages did "+
					"and some did not, so a client had to handle two shapes to catch one "+
					"category — and this suite got that wrong twice while knowing it", err)
			}
			res := resp.GetResult()
			if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
				t.Fatalf("not refused at all (status OK); this case proves nothing")
			}

			// --- AND A JOIN KEY ----------------------------------------------
			//
			// D124 requires the stdout line to carry the decision id. A refusal
			// returning no result carried none, so the line an operator watches
			// read `decision=""` on precisely the rows §5.4 calls highest-value.
			if res.GetDecisionId() == "" {
				t.Error("the refusal carries no decision id, so the line an operator " +
					"watches cannot be joined to the record explaining it (D124)")
			}

			// --- AND THE FINE TAXONOMY (D138) --------------------------------
			//
			// `status` is deliberately coarse — denied, unauthenticated and
			// residency all collapse into STATUS_DENIED — so once D135 made every
			// deliberate refusal a RESULT, the finer answer stopped reaching
			// anyone. It survived in the metric and on the record, and the reflex
			// engine calls Enforce directly (D18, D69): it gets a CommandResult,
			// not an error, so it cannot ask fault.KindOf.
			if res.GetKind() == "" {
				t.Error("the refusal carries no `kind`, so a caller sees only the " +
					"coarse status and an in-process caller cannot tell a residency " +
					"refusal from a rate limit (D138)")
			}
			kinds[res.GetKind()] = true

			if r.localOnly(t, "the stage is recorded in this process's audit log") {
				return
			}
			var rec *sekizuiv1.Decision
			for _, d := range readLog(t, r.path) {
				if d.GetId() == res.GetDecisionId() {
					rec = d
				}
			}
			if rec == nil {
				t.Fatalf("no record for decision %q", res.GetDecisionId())
			}
			if got := rec.GetRefusedBy(); got != c.want {
				t.Errorf("refused_by = %v, want %v", got, c.want)
			}
			seen[rec.GetRefusedBy()] = true
			statuses[res.GetStatus()] = true
		})
	}

	if r.remote {
		return
	}

	// --- NON-VACUITY 1: the stages actually differ ---------------------------
	//
	// Without this, a constant would satisfy every assertion above.
	if len(seen) != len(cases) {
		t.Errorf("%d distinct refused_by values across %d stages; the field is not "+
			"discriminating and a reviewer learns nothing from it", len(seen), len(cases))
	}

	// --- NON-VACUITY 1b: `kind` SAYS MORE THAN `status` (D138) ---------------
	//
	// The point of the field is that it survives a collapse the status does not.
	// If both had the same number of distinct values across these four stages,
	// `kind` would be a second spelling of `status` and worth deleting. Asserted
	// as a RELATIONSHIP rather than against expected values, so it keeps meaning
	// something when a stage is added.
	if len(kinds) <= len(statuses) {
		t.Errorf("%d distinct kinds vs %d distinct statuses across %d stages; `kind` "+
			"exists because Status collapses denied/unauthenticated/residency into "+
			"one, and here it is adding nothing", len(kinds), len(statuses), len(cases))
	}

	// --- NON-VACUITY 2: a FAILURE is still an error --------------------------
	//
	// The shape must not swallow everything. A target that cannot be reached is
	// not Sekizui refusing on purpose, and turning it into a tidy DENIED result
	// would tell a caller to stop retrying a condition that clears itself.
	if _, err := r.as(t, "agent:triage").Execute(ctx,
		execute("kata.create_issue", "kata:alpha", map[string]any{
			"project": "PROJ", kata.FailKey: "target_unavailable",
		})); err == nil {
		t.Error("an unreachable target returned a result rather than an error. " +
			"`Deliberate()` is the line: a refusal is a result, a failure is an error, " +
			"and collapsing the two loses the distinction D125 exists to draw")
	}
}
