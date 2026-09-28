package acceptance

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/internal/gateway"
	"github.com/fullstorydev/sekizui/internal/policy"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step40TheAuditRowNamesTheStageThatActuallyRefused proves D201.
//
// **THE DEFECT WAS PROVEN WITH A THROWAWAY PROBE BEFORE IT WAS FIXED**, and the
// output is the argument for the step:
//
//	refused_by=REFUSED_BY_RESIDENCY
//	reason=credential.Cache.Resolve: denied: credential resolved to a version OLDER...
//
// **D152's MONOTONIC GUARD — the control that stops a revoked credential coming
// back — was recorded in the audit log as a DATA RESIDENCY refusal.** The
// enforcement path gated on `Deliberate()` and labelled every deliberate
// refusal from the resolve stage `REFUSED_BY_RESIDENCY`, using "did Sekizui
// decide" as a stand-in for "is this residency". The control fired correctly and
// the row explained it wrongly, which is worse than either alone: the row is
// what somebody reviews six months later, and it sends them to a deployment
// topology problem that does not exist.
//
// **AND THE LABEL IT CHOSE IS THE ONE STAGE THAT CANNOT FIRE THERE.** The
// residency ceiling is checked in `ceilings` before policy (D136); `Resolve`
// re-checks it only as defence in depth, off the same predicate. So the branch
// asserted the single outcome it could not be.
//
// DRIVEN THROUGH THE REAL CREDENTIAL CACHE, not a stubbed resolver: the kind
// under test has to be the one the SYSTEM produces, or the step compares a value
// with the one it chose itself (D159).
func step40TheAuditRowNamesTheStageThatActuallyRefused(t *testing.T) {
	ctx := context.Background()
	const ref = "sm://projects/p/secrets/s/versions/latest"

	doc := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "kata:alpha", Kind: kata.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://alpha.invalid", CredentialRef: ref,
		}},
		Grants: []config.GrantSpec{{
			Principal: "agent:dev",
			Allow: []config.CapabilitySpec{
				{Action: "kata.create_issue", TargetRef: "kata:alpha"},
			},
		}},
	}

	// THE REAL CHAIN, wired as `cmd/sekizui` wires it (D107): a provider whose
	// version can step backwards, a cache with the version marks D152's guard
	// reads, and `resolver.NewWithCache` — which is the constructor production
	// uses precisely because the guard needs a cache it did not build itself.
	//
	// TTL ZERO, for step 67's reason: while the newer version is cached there is
	// nothing to refuse, and the guard is only reached on a MISS.
	provider := stepping("sm", "projects/p/secrets/s/versions/7")
	marks := credential.NewMarkFileStore(filepath.Join(t.TempDir(), "audit.jsonl.credver"))
	cache := credential.New([]config.Provider{provider},
		credential.WithTTL(0),
		credential.WithVersionMarks(marks),
		credential.WithLogger(quietLogger()))
	if _, err := cache.RehydrateMarks(ctx); err != nil {
		t.Fatalf("rehydrating marks: %v", err)
	}

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer func() { _ = sink.Stop(ctx) }()

	gw := gateway.New(gateway.Config{
		Doc:      doc,
		Policy:   policy.NewGrantEngine(doc, nil),
		Resolver: resolver.NewWithCache(doc, runtime.Profile{}, nil, cache),
		Drivers:  map[string]connector.Driver{kata.Kind: kata.New()},
		Guards:   anzen.New(nil),
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc)),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	issue := func() (*sekizuiv1.CommandResult, error) {
		return gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
			Action: "kata.create_issue", TargetRef: "kata:alpha",
			Args: mustArgs(t, map[string]any{"project": "PROJ"}),
		})
	}

	// --- 40a: FORWARD IS FINE, so the mark exists to move backwards from ---
	if _, err := issue(); err != nil {
		t.Fatalf("40a: a command at version 7 failed: %v. Nothing below can be a "+
			"DOWNGRADE if the first resolution never happened", err)
	}

	// --- 40b: THE DOWNGRADE IS REFUSED, AND THE ROW NAMES THE CREDENTIAL ---
	//
	// v7 is declared compromised and disabled; the platform answers `latest`
	// with v6, which is enabled and older — a credential somebody revoked back
	// in service.
	provider.version.Store("projects/p/secrets/s/versions/6")

	res, err := issue()
	if err != nil {
		t.Fatalf("40b: the refusal arrived as a transport error rather than a result "+
			"(D135): %v", err)
	}
	if res.GetStatus() == sekizuiv1.Status_STATUS_OK {
		t.Fatal("40b: a credential that resolved BACKWARDS was used")
	}

	rows := readLog(t, path)
	last := rows[len(rows)-1]
	if got := last.GetRefusedBy(); got != sekizuiv1.RefusedBy_REFUSED_BY_CREDENTIAL {
		t.Errorf("40b: the audit row says refused_by=%v, want %v. This is D152's "+
			"guard — the control that stops a revoked credential coming back — and %v "+
			"sends an operator to a deployment topology problem that does not exist",
			got, sekizuiv1.RefusedBy_REFUSED_BY_CREDENTIAL, got)
	}
	// **THE DECISION ID IS ON THE RESULT, asserted rather than claimed.** This is
	// the half of the maintainer's argument that decided the shape: on the error path
	// `recordFailure` mints an id and discards it, so a caller cannot name the
	// row explaining its own failure. Checked against the RECORDED row's id, not
	// merely for non-emptiness — an id that does not match the row it claims to
	// name is worse than none.
	if res.GetDecisionId() == "" {
		t.Error("40b: the refusal carries no decision id, so a caller cannot name the " +
			"audit row it just caused — which across replicas under load is the only " +
			"join key it has")
	} else if res.GetDecisionId() != last.GetId() {
		t.Errorf("40b: the result names decision %q and the row is %q",
			res.GetDecisionId(), last.GetId())
	}

	// AND THE REASON STILL CARRIES WHAT TO DO. The stage is the index; the
	// reason is the explanation, and D152 owes both versions and the remedy.
	for _, want := range []string{"versions/6", "versions/7", "PIN"} {
		if !strings.Contains(last.GetReason(), want) {
			t.Errorf("40b: the row does not mention %q: %.120s", want, last.GetReason())
		}
	}

	// --- 40c: A RESIDENCY REFUSAL STILL SAYS RESIDENCY ---------------------
	//
	// NON-VACUITY, and the arm that stops the fix being "relabel everything".
	// Asserted on the taxonomy rather than by standing up a second deployment:
	// residency keeps its own stage because it is its own kind.
	if fault.KindResidency.Attribution() == fault.AttributionCredential {
		t.Error("40c: a residency conflict is attributed to the credential, so it would " +
			"now be recorded as a credential refusal — the same defect with the labels " +
			"swapped")
	}

	// --- 40d: AND A CONFIG FAULT REACHES THE CALLER AS A RESULT (the maintainer) -----
	//
	// **THE HALF THE MAINTAINER ASKED FOR, and the argument that carried it was the one I
	// had dismissed.** As a transport error a config fault gave the caller a
	// coarse gRPC code, no `kind` to branch on, and no decision id to name the
	// row it had just caused — `recordFailure` mints one and discards it. For
	// later phases that is the difference between a reflex or an agent being
	// able to say WHICH row explains its failure and having to search by
	// timestamp across replicas.
	if !fault.KindConfig.Deliberate() {
		t.Error("40d: a configuration fault is not deliberate, so it reaches the caller " +
			"as a transport error with no kind and no decision id")
	}
	if got := fault.KindConfig.Status(); got != sekizuiv1.Status_STATUS_MISCONFIGURED {
		t.Errorf("40d: a configuration fault maps to status %v. A deliberate kind with "+
			"no case in Kind.Status() reaches callers as STATUS_UNSPECIFIED, which is "+
			"D138's bug arriving through a kind that had just changed shape", got)
	}
	// AND IT MUST NOT BE MISTAKEN FOR EITHER PARTY'S FAULT.
	if fault.KindConfig.ImplicatesTarget() {
		t.Error("40d: a configuration fault implicates the target (D200)")
	}
	if got := fault.KindConfig.Attribution(); got != fault.AttributionSekizui {
		t.Errorf("40d: a configuration fault is attributed to %v, want sekizui", got)
	}

	r := &run{path: path}
	r.detail(t, "D201: a credential downgrade is recorded as refused_by=%v rather than "+
		"as a residency decision, residency keeps its own stage, and a configuration "+
		"fault reaches the caller as a %v result with a decision id instead of an "+
		"opaque error",
		sekizuiv1.RefusedBy_REFUSED_BY_CREDENTIAL, sekizuiv1.Status_STATUS_MISCONFIGURED)
}
