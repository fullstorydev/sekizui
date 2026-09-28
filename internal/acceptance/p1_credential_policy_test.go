package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/provider/ambient"
	filecred "github.com/fullstorydev/sekizui/pkg/provider/file"
)

// mute is a provider that resolves and declares NOTHING about itself — a
// third-party implementation written before D111 existed (D35).
type mute struct{}

func (mute) Scheme() string { return "mute" }
func (mute) Resolve(context.Context, string) (config.Resolution, error) {
	return config.Resolution{Material: []byte("x")}, nil
}

// policyDoc is one target on one scheme, plus an optional explicit policy.
func policyDoc(ref string, require []string) *config.Document {
	d := &config.Document{Targets: []config.TargetSpec{
		{Ref: "kata:alpha", Kind: "kata", CredentialRef: ref},
	}}
	if require != nil {
		d.CredentialPolicy = &config.CredentialPolicySpec{Require: require}
	}
	return d
}

func managed() runtime.Profile {
	return runtime.Profile{Provider: runtime.ProviderGCP, Execution: runtime.ExecutionManaged}
}

// step36CredentialPolicyRefusesAMissingProperty proves D111's mechanism.
func step36CredentialPolicyRefusesAMissingProperty(t *testing.T) {
	// A real file, so the file provider answers about something that exists.
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("t"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	fileRef := "file://" + tokenPath

	providers := []config.Provider{
		config.EnvProvider{}, filecred.New(filecred.Roots(os.TempDir())), ambient.New(), mute{},
	}

	// --- 36a: THE REFUSAL NAMES THE PROPERTY, NOT THE SCHEME --------------
	//
	// The whole reason the mechanism is worth generalising. "file:// is not
	// allowed here" tells an operator nothing about what to reach for;
	// "cannot satisfy audited_reads" tells them what to look for in an
	// alternative.
	t.Run("a source lacking a required property is refused by property name", func(t *testing.T) {
		refusals := credential.RefuseAtBoot(
			policyDoc(fileRef, []string{"audited_reads"}), managed(), false, providers)

		assertRefused(t, refusals, "audited_reads")
		joined := refusalText(refusals)
		if strings.Contains(joined, "file:// is not allowed") {
			t.Error("the refusal names the SCHEME rather than the property")
		}
	})

	// --- 36b: NON-VACUITY — a source that HAS the property passes ---------
	//
	// Without this the step would pass against a check that refused everything,
	// and `audited_reads` is the right foil: a mounted file cannot offer it and
	// workload identity can, because the cloud's own IAM log records every mint.
	t.Run("a source offering the property is accepted", func(t *testing.T) {
		if got := credential.RefuseAtBoot(
			policyDoc("ambient://gcp", []string{"audited_reads"}), managed(), false, providers); len(got) > 0 {
			t.Errorf("ambient://gcp was refused under require:[audited_reads]: %v. The "+
				"platform logs every token it mints, which is exactly the property a "+
				"mounted file cannot offer", got)
		}
	})

	// --- 36c: A PROVIDER THAT DESCRIBES NOTHING OFFERS NOTHING ------------
	//
	// D111: "An unstated field is false, so an existing provider that has not
	// been updated is treated as not offering it. The default direction is
	// refusal, which is the one that fails safe." Matters because Provider is
	// published (D35) and a third-party implementation predates this mechanism.
	t.Run("a provider that declares no posture fails every requirement", func(t *testing.T) {
		assertRefused(t, credential.RefuseAtBoot(
			policyDoc("mute://whatever", []string{"versioned"}), managed(), false, providers),
			"versioned")
	})

	// --- 36d: AN UNKNOWN PROPERTY IS REFUSED, NOT IGNORED -----------------
	//
	// The defect this codebase has found fourteen times, in the one place where
	// the consequence is somebody's audit: `require: [audited_read]` that parsed
	// and did nothing would read as a compliance bar in force and enforce
	// nothing at all.
	t.Run("a misspelled requirement refuses the boot", func(t *testing.T) {
		refusals := credential.RefuseAtBoot(
			policyDoc(fileRef, []string{"audited_read"}), managed(), false, providers)

		assertRefused(t, refusals, "not a property Sekizui knows")
		// The available set is named, or an operator has to read the source to
		// find the spelling.
		assertRefused(t, refusals, "audited_reads")
	})
}

// step37TheEnvRefusalIsDerivedNotHardcoded proves D111's general mechanism drives
// D97's specific behaviour — and D153's correction to how.
func step37TheEnvRefusalIsDerivedNotHardcoded(t *testing.T) {
	dir := t.TempDir()
	staticPath := filepath.Join(dir, "token")
	if err := os.WriteFile(staticPath, []byte("t"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	staticRef := "file://" + staticPath

	providers := []config.Provider{config.EnvProvider{}, filecred.New(filecred.Roots(os.TempDir())), ambient.New()}

	// --- 37a: THE DEFAULT STILL REFUSES env:// ----------------------------
	t.Run("the default off-bare policy refuses env", func(t *testing.T) {
		assertRefused(t, credential.RefuseAtBoot(
			policyDoc("env://TOKEN", nil), managed(), false, providers), "versioned")
	})

	// --- 37b: REMOVING THE REQUIREMENT PERMITS IT ------------------------
	//
	// THE ARM THAT PROVES THE MECHANISM IS REAL. If `env://` stayed refused with
	// nothing required, the rule would be decoration beside a hardcoded case
	// still doing the work.
	t.Run("stating an empty policy permits env off-bare", func(t *testing.T) {
		if got := credential.RefuseAtBoot(
			policyDoc("env://TOKEN", []string{}), managed(), false, providers); len(got) > 0 {
			t.Errorf("env:// stayed refused with an explicit empty policy: %v. Then the "+
				"refusal is not derived from the requirement set and D111's mechanism is "+
				"sitting beside a special case rather than replacing it", got)
		}
	})

	// --- 37c: D153 — THE DEFAULT MUST NOT REFUSE A STATIC FILE -----------
	//
	// **THE MOST VALUABLE ARM, and the one that caught D111's derivation being
	// wrong.** D111 said the default off-bare should require `rotatable_live`.
	// A static file cannot offer that — nor can a subPath mount, nor anything
	// Vault Agent writes to an emptyDir — so that default would refuse the exact
	// configuration D104 rules must only WARN, on the explicit grounds that a
	// static credential is legitimate and what is illegitimate is believing it
	// rotates. `versioned` separates them: a file is versioned by content even
	// when it never changes.
	t.Run("the default does not refuse a credential that merely cannot rotate", func(t *testing.T) {
		if got := credential.RefuseAtBoot(
			policyDoc(staticRef, nil), managed(), false, providers); len(got) > 0 {
			t.Errorf("a static file was refused by the DEFAULT off-bare policy: %v.\n"+
				"That contradicts D104, which rules this must warn and not refuse — and "+
				"it is what requiring `rotatable_live` by default would have done", got)
		}
	})

	// --- 37d: rotatable_live IS AVAILABLE, JUST NOT DEFAULT --------------
	//
	// D153 demotes it rather than deleting it: a regulated deployment may
	// reasonably require live rotation, and the property has to work when asked
	// for or the demotion would have removed a capability rather than a default.
	t.Run("rotatable_live can still be required deliberately", func(t *testing.T) {
		assertRefused(t, credential.RefuseAtBoot(
			policyDoc(staticRef, []string{"rotatable_live"}), managed(), false, providers),
			"rotatable_live")
	})

	// --- 37e: THE OVERRIDE FLAG GOES THROUGH THE SAME MECHANISM ----------
	t.Run("the override drops the requirement rather than special-casing a scheme", func(t *testing.T) {
		if got := credential.RefuseAtBoot(
			policyDoc("env://TOKEN", nil), managed(), true, providers); len(got) > 0 {
			t.Errorf("-allow-env-credentials did not lift the refusal: %v", got)
		}
		// AND IT IS NARROW. Dropping `versioned` must not drop a requirement the
		// operator stated explicitly — otherwise one flag quietly disables a
		// compliance bar somebody wrote down.
		assertRefused(t, credential.RefuseAtBoot(
			policyDoc(staticRef, []string{"audited_reads"}), managed(), true, providers),
			"audited_reads")
	})
}

// refusalText joins refusals for a substring assertion.
func refusalText(refusals []credential.Refusal) string {
	parts := make([]string, 0, len(refusals))
	for _, r := range refusals {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, "\n")
}
