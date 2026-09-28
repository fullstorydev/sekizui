package acceptance

import (
	"strings"
	"testing"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/provider/ambient"
)

// credentialBootDoc is one target with one credential reference.
func credentialBootDoc(ref string) *config.Document {
	return &config.Document{Targets: []config.TargetSpec{
		{Ref: "kata:alpha", Kind: "kata", CredentialRef: ref},
	}}
}

// builtProviders is what this binary can actually resolve — the providers
// themselves, because the boot check now asks each one what it OFFERS (D111)
// rather than comparing scheme names.
func builtProviders() []config.Provider {
	return []config.Provider{config.EnvProvider{}}
}

// withAmbient adds the ambient provider, for the cases about cross-cloud claims.
func withAmbient() []config.Provider {
	return append(builtProviders(), ambient.New())
}

// assertRefused fails unless exactly one refusal names want.
func assertRefused(t *testing.T, refusals []credential.Refusal, want string) {
	t.Helper()

	if len(refusals) == 0 {
		t.Fatalf("accepted; expected a refusal naming %q. A credential problem that "+
			"boots clean is one discovered by a failing command in production", want)
	}
	var joined []string
	for _, r := range refusals {
		joined = append(joined, r.String())
	}
	if !strings.Contains(strings.Join(joined, "\n"), want) {
		t.Errorf("the refusal does not name %q, so an operator cannot act on it:\n  %s",
			want, strings.Join(joined, "\n  "))
	}
}

// step12BootRefusesEnvOffADeveloperMachine proves D97.
//
// The trigger is the EXECUTION MODEL, not the cloud provider, and that is the
// substance of the decision rather than a detail of it: Kubernetes reports
// ProviderUnknown by design (§4.7.7), so keyed on provider an on-prem cluster
// would escape a rule it needs every bit as much as a managed one — while
// file:// is available there, so nothing is lost by refusing.
func step12BootRefusesEnvOffADeveloperMachine(t *testing.T) {
	doc := credentialBootDoc("env://JIRA_TOKEN")

	t.Run("a developer machine is where env:// belongs", func(t *testing.T) {
		p := runtime.Profile{Provider: runtime.ProviderUnknown, Execution: runtime.ExecutionBare}
		if got := credential.RefuseAtBoot(doc, p, false, builtProviders()); len(got) > 0 {
			t.Errorf("env:// refused on a bare execution: %v. D97 refuses a CLASS of "+
				"deployment, and refusing the laptop too would make local development "+
				"impossible without the override", got)
		}
	})

	// THE ON-PREM CASE, WHICH IS WHY THE RULE IS KEYED THIS WAY. A container
	// reporting ProviderUnknown is a Kubernetes cluster as far as the profile is
	// concerned. Keyed on the cloud provider this would be permitted, and it has
	// every one of the problems D97 lists.
	t.Run("a container escapes nothing by being on no known cloud", func(t *testing.T) {
		p := runtime.Profile{Provider: runtime.ProviderUnknown, Execution: runtime.ExecutionContainer}
		assertRefused(t, credential.RefuseAtBoot(doc, p, false, builtProviders()),
			"-allow-env-credentials")
	})

	t.Run("a managed platform is refused", func(t *testing.T) {
		p := runtime.Profile{Provider: runtime.ProviderGCP, Execution: runtime.ExecutionManaged}
		assertRefused(t, credential.RefuseAtBoot(doc, p, false, builtProviders()), "env://")
	})

	// THE OVERRIDE EXISTS AND WORKS, or the refusal is not a policy but a wall.
	// A self-hoster may have no secret manager, and D97's whole argument for a
	// FLAG rather than a config key is that the posture then sits in the deploy
	// manifest where somebody reviews it.
	t.Run("the override is honoured and is a flag, not a config key", func(t *testing.T) {
		p := runtime.Profile{Provider: runtime.ProviderGCP, Execution: runtime.ExecutionManaged}
		if got := credential.RefuseAtBoot(doc, p, true, builtProviders()); len(got) > 0 {
			t.Errorf("-allow-env-credentials did not lift the refusal: %v. An operator "+
				"with no secret manager and no way to say so cannot deploy at all", got)
		}
	})
}

// step13BootRefusesACrossCloudAmbientClaim proves D98 and D102's tier 1.
//
// Tier 1 is what the environment refutes on its own, with NO I/O. The arm that
// matters most is the one that does NOT refuse: D75 already establishes that
// *cannot confirm* and *refuted* are different answers, and Kubernetes reports
// ProviderUnknown by design — so refusing an unconfirmable claim would reject
// every valid GKE, EKS and AKS deployment for want of a signal that was never
// going to come from an environment variable.
func step13BootRefusesACrossCloudAmbientClaim(t *testing.T) {
	providers := withAmbient()

	t.Run("gcp claimed while running on aws", func(t *testing.T) {
		p := runtime.Profile{Provider: runtime.ProviderAWS, Execution: runtime.ExecutionManaged}
		refusals := credential.RefuseAtBoot(credentialBootDoc("ambient://gcp"), p, false, providers)
		assertRefused(t, refusals, "does not cross clouds")
		// THE REMEDY, NAMED. §7.1's argument is that an operator must not have
		// to infer what to do, and this refusal has two real answers rather than
		// one — a secret manager, or workload identity federation.
		assertRefused(t, refusals, "federation")
	})

	t.Run("the matching cloud is accepted", func(t *testing.T) {
		p := runtime.Profile{Provider: runtime.ProviderGCP, Execution: runtime.ExecutionManaged}
		if got := credential.RefuseAtBoot(credentialBootDoc("ambient://gcp"), p, false, providers); len(got) > 0 {
			t.Errorf("ambient://gcp refused while running on GCP: %v — the configuration "+
				"§4.7.2 recommends", got)
		}
	})

	// TIER 2/3. THE ARM THAT MUST NOT REFUSE.
	t.Run("an unconfirmable claim is accepted, not refused", func(t *testing.T) {
		p := runtime.Profile{Provider: runtime.ProviderUnknown, Execution: runtime.ExecutionContainer}
		if got := credential.RefuseAtBoot(credentialBootDoc("ambient://gcp"), p, false, providers); len(got) > 0 {
			t.Errorf("ambient://gcp refused where the profile cannot say which cloud "+
				"this is: %v. That is every Kubernetes deployment, because runtime.Detect "+
				"reports ProviderUnknown for k8s ON PURPOSE. Refuted and unconfirmed are "+
				"different answers (D75); confirming this one needs a metadata probe "+
				"gated on EagerValidation, which is D102's tier 2", got)
		}
	})

	// REFUTABLE WITH NO ENVIRONMENT KNOWLEDGE AT ALL. A typo is refusable
	// everywhere, including the tier where nothing else is.
	t.Run("a cloud that does not exist is refused anywhere", func(t *testing.T) {
		for _, p := range []runtime.Profile{
			{Provider: runtime.ProviderUnknown, Execution: runtime.ExecutionContainer},
			{Provider: runtime.ProviderGCP, Execution: runtime.ExecutionManaged},
		} {
			assertRefused(t, credential.RefuseAtBoot(credentialBootDoc("ambient://gpc"), p, false, providers),
				"not a cloud Sekizui knows")
		}
	})
}

// step14BootRefusesAnEmptyCredential proves D98's other half — and a second
// silence found while building it.
//
// An empty `credential:` conflated "this target authenticates through workload
// identity" with "somebody forgot the reference". Both read as a target that
// works until it does not.
func step14BootRefusesAnEmptyCredential(t *testing.T) {
	p := runtime.Profile{Provider: runtime.ProviderUnknown, Execution: runtime.ExecutionBare}

	t.Run("an absence is no longer an answer", func(t *testing.T) {
		refusals := credential.RefuseAtBoot(credentialBootDoc(""), p, false, builtProviders())
		assertRefused(t, refusals, "declares no credential")
		// The remedy names the thing an absence used to mean. Without it this
		// refusal tells an operator that silence is wrong and not what to say
		// instead, which for a target genuinely using workload identity is the
		// only question they have.
		assertRefused(t, refusals, "ambient://")
	})

	// THE SECOND SILENCE, FOUND WHILE BUILDING THE FIRST. A scheme with no
	// registered provider failed at FIRST USE — the cache looks the scheme up
	// per resolve and returns "no provider registered". So a target naming a
	// scheme §4.7.2's table lists as P1 but nothing implements would boot clean
	// and refuse its first command. That is the failure D42 exists to move to
	// boot, and §4.7.2's table had nothing checking it.
	t.Run("a scheme with no provider is refused at boot, not at first use", func(t *testing.T) {
		refusals := credential.RefuseAtBoot(credentialBootDoc("gcp-sm://projects/p/secrets/s"),
			p, false, builtProviders())
		assertRefused(t, refusals, "no provider for")
		// The available set is named, because "unsupported" without a list is a
		// message that sends an operator to the source.
		assertRefused(t, refusals, "Available:")
	})

	// NON-VACUITY. Everything above is satisfied by a function that refuses
	// every target it is shown.
	t.Run("a well-formed reference this binary supports is accepted", func(t *testing.T) {
		if got := credential.RefuseAtBoot(credentialBootDoc("env://TOKEN"), p, false, builtProviders()); len(got) > 0 {
			t.Errorf("env://TOKEN on a developer machine was refused: %v", got)
		}
	})

	// AND THE SCHEME LIST IS DERIVED, NOT WRITTEN DOWN. A hand-maintained list
	// is correct when written and silently wrong the first time a provider is
	// added or removed — this codebase's recurring defect, in the guard rather
	// than in the thing guarded.
	t.Run("the accepted schemes come from the providers themselves", func(t *testing.T) {
		env := config.EnvProvider{}
		got := credential.Schemes([]config.Provider{env})
		if len(got) != 1 || got[0] != env.Scheme() {
			t.Errorf("Schemes = %v, want the provider's own answer %q", got, env.Scheme())
		}
	})
}
