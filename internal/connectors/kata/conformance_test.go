package kata_test

import (
	"context"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/resolver"
	"github.com/fullstorydev/sekizui/internal/runtime"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	"github.com/fullstorydev/sekizui/pkg/connector/conformance"
)

// The published Driver contract, run against the REFERENCE driver (D176).
//
// **`RunHTTP` IS DELIBERATELY NOT SELECTED, and that is the suite's design
// working rather than a gap.** `kata` is in-memory: it has no transport, so
// there are no HTTP statuses for it to classify. A universal suite would have to
// either fail it for not speaking HTTP or skip the half that matters silently —
// which is why the transport contract is chosen by the driver that has one
// (D167, and D160's vacuous-`Run` lesson).
//
// It matters more here than anywhere that `kata` conforms: D176 renamed it from
// `fake` because its doc comment had been DISCLAIMING the role it already held,
// and a connector author reads it as the worked example.
func TestDriverConformance(t *testing.T) {
	t.Setenv("SEKIZUI_KATA_CONF_TOK", "conformance-token")

	doc := &config.Document{
		Targets: []config.TargetSpec{{
			Ref: "kata:conf", Kind: kata.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://kata.invalid", CredentialRef: "env://SEKIZUI_KATA_CONF_TOK",
		}},
	}
	drv := kata.New()

	conformance.Run(t, drv, conformance.Case{
		UnknownAction: "kata.drop_database",

		// **NO FAR SIDE, AND THIS DRIVER IS WHY THE FIELD EXISTS (D218).**
		// `kata` is in-memory. Its outbound `Authorization` is built into a
		// buffer the driver owns and `clear()`ed before `simulate` runs, and the
		// Data map it returns is assembled from the TARGET IT WAS HANDED — so
		// reading `Data["tenant"]` back would compare the fixture's own input
		// with itself, which is D159's failure dressed as coverage. Echoing the
		// credential instead is forbidden by the arm added beside this one.
		//
		// Its statelessness IS proven, one layer out where an observation
		// exists: P0 step 14 drives 48 concurrent commands across four tenants
		// at kata targets from `acceptance.yaml`, and P1 step 24 counts the
		// pooled entries they leave.
		WhyNoFarSide: "kata is in-memory: the outbound header is cleared inside the " +
			"driver and Data echoes the target it was given, so every available " +
			"observation shares an origin with the input. Covered instead by P0 step " +
			"14 (48 concurrent commands, four tenants) and P1 step 24 (pooled entries)",
		Refuse: func(ctx context.Context) error {
			target, err := resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{}).
				Resolve(ctx, "kata:conf")
			if err != nil {
				return err
			}
			ctx = connector.WithTenant(ctx, target.Tenant())
			_, err = drv.Execute(ctx, target, "kata.drop_database", nil,
				connector.Idempotency{Class: connector.IdempotencyNone})
			return err
		},
	})
}

// The published SOURCE contract, run against the reference driver.
//
// **THIS IS THE SUITE'S FIRST REAL USER, AND D233's LESSON IS THAT THE FIRST
// REAL USER IS THE ONLY HONEST TEST OF A REUSABLE ARTEFACT** — the blueprint
// cost three defects that way (D222) and the schema drafter two. Running it
// here, against the driver a connector author is told to copy, is what stops
// `RunSource` being a suite that agrees with itself.
//
// The target carries rows and nothing else: the `_misbehave_*` settings are
// deliberately ABSENT, because this asserts that kata CONFORMS. The arms that
// need a source doing the wrong thing belong to the poller, which is what has
// to survive one (D243).
func TestSourceConformance(t *testing.T) {
	tgt, err := connector.NewTarget(connector.TargetParams{
		Ref: "kata:source", Kind: kata.Kind, Tenant: "alpha", Residency: "eu",
		BaseURL:           "https://alpha.invalid",
		CredentialVersion: "v1", Credential: connector.Secret("conformance-token"),
		Settings: map[string]string{kata.SettingRows: "10"},
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	// THE SPY IS WIRED AT CONSTRUCTION and handed to the suite, which is the
	// only way the borrow arm can see anything (D255). A driver built without
	// one fails that arm — correctly, because a source that dials privately
	// cannot be stopped by `revoke_credential`.
	spy := conformance.NewPoolSpy()
	conformance.RunSource(t, kata.New(kata.WithPool(spy)),
		conformance.SourceCase{Target: tgt, Limit: 4, Tenant: "alpha", Pool: spy})
}

// TestDriftConformance — kata is the worked form of connector.Drifter (D311),
// so it runs the suite every Drifter must: a clean surface reports nothing, a
// diverged one is graded in the vocabulary, a comparison only reads, and it
// asserts the tenant before anything that would be egress.
func TestDriftConformance(t *testing.T) {
	t.Setenv("SEKIZUI_KATA_CONF_TOK", "conformance-token")
	doc := &config.Document{Targets: []config.TargetSpec{
		{Ref: "kata:conf", Kind: kata.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://kata.invalid", CredentialRef: "env://SEKIZUI_KATA_CONF_TOK"},
		// THE VENDOR DROPPED `comment` AND SHIPPED `archive`: one withheld, one unvetted.
		{Ref: "kata:drifted", Kind: kata.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://kata.invalid", CredentialRef: "env://SEKIZUI_KATA_CONF_TOK",
			Settings: map[string]string{kata.SurfaceKey: "create_issue,upsert_record,append_event,delete_project,read,poll,archive"}},
	}}
	res := resolver.New(doc, runtime.Profile{}, nil, config.EnvProvider{})
	resolve := func(ref string) connector.Target {
		tgt, err := res.Resolve(context.Background(), ref)
		if err != nil {
			t.Fatalf("resolving %s: %v", ref, err)
		}
		return tgt
	}
	conformance.RunDrift(t, kata.New(), conformance.DriftCase{
		Clean: resolve("kata:conf"), Diverged: resolve("kata:drifted"), OtherTenant: "globex",
	})
}

// TestRefinerConformance: the reference driver's rules parse in the closed
// vocabulary and refine and write only kata's own types (D317).
func TestRefinerConformance(t *testing.T) {
	conformance.RunRefiner(t, kata.New())
}

// TestPresetterConformance: the reference driver's suggested presets are a
// fragment a deployment can drop in, name only kata's actions, and hold their
// `mirrors:` claims against kata's own grading (D327).
func TestPresetterConformance(t *testing.T) {
	conformance.RunPresetter(t, kata.New())
}
