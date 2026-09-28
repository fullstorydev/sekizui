package acceptance

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

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
	filecred "github.com/fullstorydev/sekizui/pkg/provider/file"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// step19PostureReachesTheDecisionRecord proves D100, D104 and D119.
//
// D104's boot report states the posture ONCE, to whoever happens to be watching
// a terminal at startup. That is the wrong artefact for the question an auditor
// actually asks — "which targets were reachable with an unrotatable credential
// last quarter" — because it needs the posture per ACTION, from a record that
// stands alone (§5.4).
//
// D100 originally specified the SCHEME alone on the record. D119 widened it to
// the full posture, and the reason the widening is safe is D118: decisions
// provably reach no bus consumer, so the reconnaissance concern that argued for
// restraint does not apply.
//
// **THE MATERIAL IS NEVER IN THE RECORD, and this step asserts that too.**
// `at_rest` names where the bytes live and is deliberately not called
// `material`, on D119's ruling — a field name is the only documentation most
// readers get.
func step19PostureReachesTheDecisionRecord(t *testing.T) {
	ctx := context.Background()

	// A REAL PROJECTED VOLUME, so `rotation` on the record is a fact this test
	// established rather than a string it asked for.
	_, secretPath := projectedVolume(t, "token-from-a-mounted-secret")

	doc := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "kata:filecred", Kind: kata.Kind, Tenant: "postural",
			BaseURL: "https://filecred.invalid", CredentialRef: "file://" + secretPath,
		}},
		Grants: []config.GrantSpec{{
			Principal: "agent:triage",
			Allow: []config.CapabilitySpec{{
				Action: "kata.create_issue", TargetRef: "kata:filecred",
			}},
		}},
	}

	path := auditPath(t)
	sink := auditwal.NewJSONLSink(path)
	if err := sink.Start(ctx); err != nil {
		t.Fatalf("audit sink: %v", err)
	}

	clock := time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC)
	tick := func() time.Time { clock = clock.Add(time.Second); return clock }

	// InKubernetes(true) so the ..data link is what decides the answer rather
	// than the absence of a pod — the laptop reading would report `on-change`
	// for a genuine projected volume and the step would prove less.
	cache := credential.New([]config.Provider{filecred.New(filecred.InKubernetes(true), filecred.Roots(os.TempDir()))},
		credential.WithLogger(quietLogger()))

	srv := gateway.New(gateway.Config{
		Doc:      doc,
		Policy:   policy.NewGrantEngine(doc, nil),
		Resolver: resolver.NewWithCache(doc, runtime.Profile{}, nil, cache),
		Drivers:  map[string]connector.Driver{kata.Kind: kata.New()},
		Guards:   anzen.New(nil),
		Recorder: auditwal.NewRecorder(sink, mustIdentity(t, doc), auditwal.WithClock(tick)),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      tick,
	})

	res, err := srv.Enforce(ctx, assertedIdentity("agent:triage"), &sekizuiv1.Command{
		Action: "kata.create_issue", TargetRef: "kata:filecred",
		Args:           mustArgs(t, map[string]any{"project": "PROJ"}),
		IdempotencyKey: "acc-19",
	})
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if res.GetStatus() != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("status = %v (%s); the step needs an ALLOWED command, because a "+
			"refusal before resolve legitimately carries no posture",
			res.GetStatus(), res.GetReason())
	}

	if err := sink.Stop(ctx); err != nil {
		t.Fatalf("stopping sink: %v", err)
	}

	var found int
	for _, rec := range readLog(t, path) {
		if rec.GetIdempotencyKey() != "acc-19" {
			continue
		}
		p := rec.GetCredentialPosture()
		if p == nil {
			t.Errorf("a record for a resolved target carries no credential_posture. "+
				"The field existed and nothing populated it, which is the state D100 "+
				"described as already working — CONTRACTS item 23's class, invisible "+
				"because the column is ABSENT rather than wrong (phase %v)", rec.GetPhase())
			continue
		}
		found++

		if p.GetScheme() != filecred.Scheme {
			t.Errorf("scheme = %q, want %q — D100's original contract", p.GetScheme(), filecred.Scheme)
		}
		if p.GetRotation() != string(config.RotationLive) {
			t.Errorf("rotation = %q, want %q. The credential is behind a real ..data "+
				"link, so a record saying otherwise would send an auditor after a "+
				"rotation problem that does not exist", p.GetRotation(), config.RotationLive)
		}
		if p.GetAtRest() != "k8s-secret" {
			t.Errorf("at_rest = %q, want k8s-secret. This is the column that answers the "+
				"SOPS misconception — helm-secrets encrypts version control and leaves "+
				"the material in a Kubernetes Secret", p.GetAtRest())
		}
		if p.GetAuditedReads() {
			t.Error("audited_reads is true for a mounted file. Nothing records who read " +
				"a file: the property belongs to a secret manager and claiming it here " +
				"would overstate the posture in the direction that matters")
		}

		// **THE MATERIAL IS NOT IN THE RECORD.** D119: "Material itself is never
		// a field, and never becomes one." Asserted against the actual bytes,
		// because a field added later with a plausible name is exactly how this
		// would be lost.
		// BLUNT ON PURPOSE: the assertion is "these bytes are nowhere in this
		// record". Anything cleverer — walking named fields, say — would pass a
		// record that leaked the material through a field nobody thought to
		// check, which is the only way this could actually happen.
		if strings.Contains(rec.String(), "token-from-a-mounted-secret") {
			t.Error("the credential MATERIAL appears in the decision record. The record " +
				"carries metadata ABOUT a credential and never the credential")
		}
	}

	if found == 0 {
		t.Fatal("no record for this command was found in the log, so nothing above ran")
	}
}
