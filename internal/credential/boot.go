package credential

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/provider/ambient"
)

// Refusal is one target's credential reference that this deployment must not
// accept, with the remedy named.
type Refusal struct {
	TargetRef string
	Ref       string
	Why       string
}

// Schemes lists the schemes a provider set can actually resolve.
//
// DERIVED FROM THE PROVIDERS RATHER THAN LISTED BESIDE THEM, so the boot check
// and the cache cannot disagree about what this binary supports. A hand-written
// list is the shape of defect this codebase has found thirteen times: it is
// correct when written and silently wrong the first time a provider is added or
// removed, and nothing about the call site looks off.
func Schemes(providers []config.Provider) []string {
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.Scheme())
	}
	sort.Strings(out)
	return out
}

// RefuseAtBoot returns every credential reference this deployment must refuse,
// with the remedy in each message (D97, D98, D102, §4.7.2).
//
// SEPARATE FROM Document.Validate FOR D136'S REASON, and it is the same split
// twice over: Validate cannot see the runtime profile, cannot see
// -allow-env-credentials, and cannot see which providers this binary was built
// with. A check that silently skipped when it could not see them would be worse
// than one that lives here and is called explicitly at boot.
//
// EVERY REFUSAL IS COLLECTED, not just the first. An operator fixing credential
// references one redeploy at a time is the failure this shape exists to prevent.
func RefuseAtBoot(doc *config.Document, profile runtime.Profile, allowUnversioned bool,
	providers []config.Provider) []Refusal {

	// THE PROVIDERS THEMSELVES, not a list of scheme names. The check needs to
	// ask each one what it offers (D111), and taking names alone would mean the
	// caller passing two things that must agree — which is the drift `Schemes`
	// was derived to prevent, reintroduced at the call site.
	known := map[string]config.Provider{}
	for _, p := range providers {
		known[p.Scheme()] = p
	}
	schemes := Schemes(providers)

	required, policyErr := EffectivePolicy(doc, profile, allowUnversioned)
	if policyErr != nil {
		// A MALFORMED POLICY IS ITS OWN REFUSAL, reported once rather than per
		// target: an operator who mistyped a property name has one thing to fix,
		// and repeating it under nine targets would bury it.
		return []Refusal{{TargetRef: "credential_policy", Why: policyErr.Error()}}
	}

	var out []Refusal
	for _, t := range doc.Targets {
		// D98. AN ABSENCE IS NO LONGER AN ANSWER. Empty conflated "this target
		// authenticates through workload identity" with "somebody forgot the
		// reference", which is this codebase's recurring failure in the config
		// file rather than in the code.
		if t.CredentialRef == "" {
			out = append(out, Refusal{TargetRef: t.Ref, Why: "declares no credential. " +
				"An absence used to mean 'no credential needed' and could not be told " +
				"apart from a forgotten reference (D98). State it: `ambient://<cloud>` " +
				"for workload identity, or a scheme that names where the material comes " +
				"from (§4.7.2)"})
			continue
		}

		scheme, rest, ok := strings.Cut(t.CredentialRef, "://")
		if !ok {
			// Document.Validate already refuses this, and it is repeated rather
			// than assumed: everything below reads a scheme, and a check that
			// depends on an earlier one having run is a check that breaks when
			// somebody reorders boot.
			continue
		}

		// NO PROVIDER MEANS NO RESOLUTION, AND BOOT IS WHERE THAT SHOULD SURFACE.
		// Without this an unregistered scheme fails at FIRST USE — a target that
		// boots clean and refuses the first real command, which is exactly the
		// class of failure D42 exists to move to boot. §4.7.2's table lists
		// schemes by intended phase, and nothing checked that a listed scheme is
		// one this binary actually has.
		provider, isKnown := known[scheme]
		if !isKnown {
			out = append(out, Refusal{TargetRef: t.Ref, Ref: t.CredentialRef, Why: fmt.Sprintf(
				"uses scheme %q, which this binary has no provider for. Available: %s. "+
					"Without this check the target would boot and fail on its first "+
					"command instead", scheme, strings.Join(schemes, ", "))})
			continue
		}

		// D111 AND D153. THE REQUIREMENT CHECK, WHICH REPLACED A HARDCODED CASE.
		//
		// This block used to be `switch scheme { case "env": ... }` — a refusal
		// list with one entry, which meant the next source with the same weakness
		// would have been permitted until somebody remembered to add it. Now the
		// provider declares what it offers, the deployment declares its bar, and
		// boot compares them. D97's behaviour is unchanged and is no longer
		// written down anywhere as a special case.
		out = append(out, unmetRequirements(t, provider, required)...)

		if scheme == ambient.Scheme {
			out = append(out, ambientRefusals(t.Ref, t.CredentialRef, rest, profile)...)
		}
	}
	return out
}

// ambientRefusals implements D102's TIER 1 only: what the environment refutes on
// its own, with no I/O.
//
// TIER 2 (probing a metadata endpoint) AND TIER 3 (cannot confirm at all) ARE
// NOT HERE, and the difference is the whole decision. D75 already establishes
// that *cannot confirm* and *refuted* are different answers, so a claim this
// function cannot disprove is ACCEPTED rather than refused — Kubernetes reports
// ProviderUnknown by design, and refusing there would reject every valid GKE,
// EKS and AKS deployment for lack of a signal that was never going to arrive
// from an environment variable.
func ambientRefusals(targetRef, ref, cloud string, profile runtime.Profile) []Refusal {
	// Refutable with no environment knowledge at all: a cloud that does not
	// exist. `ambient://gpc` is a typo and would otherwise be a runtime failure
	// on a deployment nobody could talk to.
	switch cloud {
	case "gcp", "aws", "azure":
	default:
		return []Refusal{{TargetRef: targetRef, Ref: ref, Why: fmt.Sprintf(
			"claims ambient identity on %q, which is not a cloud Sekizui knows. "+
				"Expected one of gcp, aws, azure (§4.7.2)", cloud)}}
	}

	// TIER 2/3: the profile cannot say where this is running, so the claim is
	// UNCONFIRMED rather than refuted. Accepted here, and D102 puts the
	// confirmation behind a metadata probe gated on EagerValidation.
	if profile.Provider == runtime.ProviderUnknown {
		return nil
	}

	if cloud != profile.Provider.String() {
		return []Refusal{{TargetRef: targetRef, Ref: ref, Why: fmt.Sprintf(
			"declares ambient://%s, but this instance is running on %s. Workload "+
				"identity does not cross clouds. Use a secret manager on %s to hold a "+
				"%s credential, or configure workload identity federation and reference "+
				"the federated credential",
			cloud, profile.Provider, profile.Provider, cloud)}}
	}
	return nil
}

// String renders ONE refusal, target and reason together.
//
// The boot error goes through Render, which groups by REASON (D97) and so must
// not repeat the reason per target — that repetition is the defect Render was
// written to remove. What the two share is how a target is NAMED, and that is
// now `target()` below rather than a copy in each: the guard that found this
// function had no caller also found Render re-deriving `ref (credential-ref)`
// inline, five lines from the method that already knew how.
//
// The comment this replaces read "Error renders refusals as one boot error
// naming every target", which described Render — a doc comment left behind by
// the change that superseded the function it sits on.
func (r Refusal) String() string { return r.target() + " " + r.Why }

// target names the refused target, with its credential reference when there is
// one. ONE implementation, read by String and by Render.
func (r Refusal) target() string {
	if r.Ref == "" {
		return r.TargetRef
	}
	return r.TargetRef + " (" + r.Ref + ")"
}

// Confirmation is what tier 1.5/2/3 concluded about one ambient target.
type Confirmation struct {
	TargetRef  string
	Cloud      string
	Confidence ambient.Confidence
}

// ConfirmAmbient runs §4.7.7's tiers 1.5, 2 and 3 for every ambient target,
// returning what was confirmed and what must refuse the boot.
//
// SEPARATE FROM RefuseAtBoot BECAUSE ONE OF THESE DOES I/O AND THE OTHER MUST
// NOT. RefuseAtBoot answers everything the environment settles for free —
// including tier 1, the cross-cloud claim — and a typo must not depend on a
// network call to be caught. This runs after it, only for what is left, and only
// when the profile permits work at construction time.
//
// THE CONFIRMATIONS ARE RETURNED RATHER THAN LOGGED HERE. Tier 3 is an ACCEPTED
// outcome that the operator has to be told about — "accepted, unverified, will
// fail at first use with the target named" — and a package that logged it itself
// would decide the level and the destination for its caller.
func ConfirmAmbient(ctx context.Context, doc *config.Document, profile runtime.Profile,
	v *ambient.Provider) ([]Confirmation, []Refusal) {

	var (
		out      []Confirmation
		refusals []Refusal
	)
	for _, t := range doc.Targets {
		if !strings.HasPrefix(t.CredentialRef, ambient.Scheme+"://") {
			continue
		}
		cloud, err := ambient.CloudOf(t.CredentialRef)
		if err != nil {
			// Already refused by RefuseAtBoot's tier-1 check; repeated rather
			// than assumed, for the same reason the scheme split is.
			refusals = append(refusals, Refusal{TargetRef: t.Ref, Ref: t.CredentialRef,
				Why: err.Error()})
			continue
		}

		conf, err := v.Validate(ctx, cloud, profile.EagerValidation())
		if err != nil {
			refusals = append(refusals, Refusal{TargetRef: t.Ref, Ref: t.CredentialRef,
				Why: err.Error()})
			continue
		}
		out = append(out, Confirmation{TargetRef: t.Ref, Cloud: cloud, Confidence: conf})
	}
	return out, refusals
}

// Render groups refusals by REASON and lists the targets under each, for one
// boot error an operator can actually read.
//
// GROUPED BECAUSE THE UNGROUPED FORM IS UNREADABLE, and the boot-refusal demo is
// what showed it: nine targets sharing one env:// posture produced D97's
// five-hundred-character explanation nine times, and the one line that differed
// — which target — was buried in the repetition. A message that has to be
// diffed against itself to find the variable part is a message an operator skims.
//
// The reason is the unit of ACTION, too. Nine targets refused for one reason is
// one fix, and presenting it as nine problems invites nine.
func Render(refusals []Refusal) string {
	order := make([]string, 0, len(refusals))
	byReason := map[string][]string{}
	for _, r := range refusals {
		if _, seen := byReason[r.Why]; !seen {
			order = append(order, r.Why)
		}
		byReason[r.Why] = append(byReason[r.Why], r.target())
	}

	var b strings.Builder
	for _, why := range order {
		targets := byReason[why]
		fmt.Fprintf(&b, "\n  %s\n", why)
		// The plural is worth getting right: "1 target" reads as a typo and
		// makes a reader wonder what else the message got wrong.
		noun := "targets"
		if len(targets) == 1 {
			noun = "target"
		}
		fmt.Fprintf(&b, "    %d %s: %s\n", len(targets), noun, strings.Join(targets, ", "))
	}
	return b.String()
}

// PostureOf reports each target's credential posture, for the boot report D104
// requires.
//
// TYPE-ASSERTED, because Postured is optional (D35: adding a required method to
// a published interface breaks every out-of-tree provider). A provider that
// cannot answer is reported UNKNOWN rather than assumed to rotate — the
// assumption D104 exists to stop anybody making.
func PostureOf(doc *config.Document, providers []config.Provider) []TargetPosture {
	byScheme := map[string]config.Provider{}
	for _, p := range providers {
		byScheme[p.Scheme()] = p
	}

	out := make([]TargetPosture, 0, len(doc.Targets))
	for _, t := range doc.Targets {
		tp := TargetPosture{TargetRef: t.Ref, Ref: t.CredentialRef}

		scheme, _, ok := strings.Cut(t.CredentialRef, "://")
		if !ok {
			out = append(out, tp)
			continue
		}
		p, known := byScheme[scheme]
		if !known {
			out = append(out, tp)
			continue
		}

		// GO-PRIMER §2.2's pattern, and the same one ChainedProvider uses.
		asked, ok := p.(config.Postured)
		if !ok {
			tp.Posture = config.Posture{
				Rotation: "unknown",
				Why: "the " + scheme + " provider does not describe its posture yet, so " +
					"nothing here should be assumed about rotation",
			}
			out = append(out, tp)
			continue
		}

		got, err := asked.Posture(t.CredentialRef)
		if err != nil {
			tp.Err = err
			out = append(out, tp)
			continue
		}
		tp.Posture = got
		out = append(out, tp)
	}
	return out
}

// TargetPosture is one line of the boot report.
type TargetPosture struct {
	TargetRef string
	Ref       string
	Posture   config.Posture

	// Err is set when a provider could not answer — a mounted path that does not
	// exist, most often. NOT fatal here: the resolution itself will fail with the
	// same cause and a better place to fail, and refusing the boot on a posture
	// LOOKUP would make a reporting feature into an availability risk.
	Err error
}

// Warns reports whether this line deserves an operator's attention.
//
// ROTATION=NONE WARNS RATHER THAN REFUSES, unlike D97. A static credential is a
// legitimate configuration; what is illegitimate is BELIEVING it rotates. So the
// warning names the consequence and the fix, and the boot continues.
func (t TargetPosture) Warns() bool {
	return t.Err != nil || t.Posture.Rotation == config.RotationNone
}

// EffectivePolicy is the requirement set actually in force (D111, D153).
//
// PRECEDENCE, and each step is a decision rather than a convenience:
//
//  1. An EXPLICIT `credential_policy` in configuration REPLACES the default
//     rather than adding to it. That is what makes the mechanism demonstrably
//     general — stating `require: []` permits what the default refused, which is
//     how acceptance step 37 proves the specific behaviour is driven by the rule
//     and not sitting beside it.
//  2. Otherwise the default for the execution model.
//  3. `-allow-env-credentials` drops `versioned`, which is D97's override
//     expressed through the general mechanism instead of beside it.
//
// AN UNKNOWN PROPERTY NAME IS AN ERROR, not a silent skip. A deployment whose
// `require: [audited_read]` parsed and did nothing would believe a compliance
// bar was in force — this codebase's most persistent defect, in the one place
// where the consequence is somebody's audit.
func EffectivePolicy(doc *config.Document, profile runtime.Profile,
	allowUnversioned bool) ([]config.CredentialProperty, error) {

	const op = "credential.EffectivePolicy"

	var required []config.CredentialProperty
	if doc.CredentialPolicy != nil {
		for _, name := range doc.CredentialPolicy.Require {
			prop := config.CredentialProperty(name)
			if !slices.Contains(config.CredentialProperties, prop) {
				names := make([]string, 0, len(config.CredentialProperties))
				for _, p := range config.CredentialProperties {
					names = append(names, string(p))
				}
				return nil, fault.New(fault.KindConfig, op, fmt.Sprintf(
					"credential_policy requires %q, which is not a property Sekizui "+
						"knows. Available: %s. A requirement nobody implements would "+
						"read as a bar in force and enforce nothing",
					name, strings.Join(names, ", ")))
			}
			required = append(required, prop)
		}
	} else {
		required = DefaultPolicy(profile)
	}

	if allowUnversioned {
		required = slices.DeleteFunc(required, func(p config.CredentialProperty) bool {
			return p == config.PropertyVersioned
		})
	}
	return required, nil
}

// DefaultPolicy is the bar a deployment gets without stating one (D153).
//
// **`versioned` AND NOT `rotatable_live`**, which is D153's correction to D111's
// stated derivation. Requiring live rotation off a developer machine would refuse
// every static file — a `subPath` mount, a plain file, anything Vault Agent
// writes to an `emptyDir` — and D104 rules those must WARN, on the explicit
// grounds that a static credential is a legitimate configuration and what is
// illegitimate is believing it rotates.
//
// KEYED ON THE EXECUTION MODEL, NOT THE CLOUD PROVIDER, which is D97's own
// reasoning and survives the generalisation intact: Kubernetes reports
// ProviderUnknown by design (§4.7.7), so keyed on provider an on-prem cluster
// would escape a rule it needs as much as any managed one. `ExecutionBare` is a
// laptop or a plain `docker run`, which is where `env://` belongs.
func DefaultPolicy(profile runtime.Profile) []config.CredentialProperty {
	if profile.Execution == runtime.ExecutionBare {
		return nil
	}
	return []config.CredentialProperty{config.PropertyVersioned}
}

// unmetRequirements names every property a target's credential source does not
// offer.
//
// **THE REFUSAL NAMES THE PROPERTY, NOT THE SCHEME** (D111). "env:// is not
// allowed here" tells an operator nothing about what to reach for instead;
// "env:// cannot satisfy `versioned`, which this deployment requires" tells them
// what to look for in an alternative. That is the whole reason the mechanism is
// worth generalising, rather than a side effect of doing so.
//
// A PROVIDER THAT CANNOT DESCRIBE ITSELF OFFERS NOTHING, and so fails every
// requirement. D111 asks for exactly that: "An unstated field is false, so an
// existing provider that has not been updated is treated as not offering it. The
// default direction is refusal, which is the one that fails safe."
func unmetRequirements(t config.TargetSpec, p config.Provider,
	required []config.CredentialProperty) []Refusal {

	if len(required) == 0 {
		return nil
	}

	var posture config.Posture
	if asked, can := p.(config.Postured); can {
		if got, err := asked.Posture(t.CredentialRef); err == nil {
			posture = got
		}
	}

	var out []Refusal
	for _, prop := range required {
		if posture.Offers(prop) {
			continue
		}
		why := fmt.Sprintf("cannot satisfy %q, which this deployment requires", prop)
		if posture.Why != "" {
			why += " — " + posture.Why
		}
		if prop == config.PropertyVersioned {
			// D97'S REMEDY, still named, because the general rule must not make
			// the specific advice worse. An operator who genuinely has no
			// versioned source needs to know the override exists and that using
			// it is visible in the manifest.
			why += ". Use file:// or a secret manager, or pass -allow-env-credentials " +
				"to accept unversioned credentials — a flag rather than a config key, so " +
				"the posture is visible in the deploy manifest where somebody reviews it"
		}
		out = append(out, Refusal{TargetRef: t.Ref, Ref: t.CredentialRef, Why: why})
	}
	return out
}

// RefuseUnconfined names every credential reference its provider refuses to
// read at all (config.Confined, D286) — each target's, and every reference
// chained inside it, found with the same innerRefs the cache resolves with.
//
// **A BOOT REFUSAL, AND ALSO A CHECK ON EVERY READ.** The provider confines
// again on each Resolve, because a symlink inside a root can be re-pointed
// after this ran; this is the half that makes a bad reference fail the deploy
// instead of the first poll.
func RefuseUnconfined(doc *config.Document, providers []config.Provider) []string {
	const op = "credential.RefuseUnconfined"
	byScheme := make(map[string]config.Provider, len(providers))
	for _, p := range providers {
		byScheme[p.Scheme()] = p
	}
	var out []string
	var walk func(target, ref string, depth int)
	walk = func(target, ref string, depth int) {
		scheme, _, ok := strings.Cut(ref, "://")
		p, known := byScheme[scheme]
		if !ok || !known || depth > 8 {
			return // unknown schemes are RefuseAtBoot's to report
		}
		if c, confines := p.(config.Confined); confines {
			if err := c.Confine(ref); err != nil {
				out = append(out, fmt.Sprintf("target %q: %v", target, err))
			}
		}
		if chained, isChained := p.(config.ChainedProvider); isChained {
			nested, err := innerRefs(op, chained, ref)
			if err != nil {
				out = append(out, fmt.Sprintf("target %q: %v", target, err))
				return
			}
			for _, inner := range nested {
				walk(target, inner, depth+1)
			}
		}
	}
	for _, t := range doc.Targets {
		if t.CredentialRef != "" {
			walk(t.Ref, t.CredentialRef, 0)
		}
	}
	sort.Strings(out)
	return out
}
