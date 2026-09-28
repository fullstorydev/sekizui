package acceptance

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/fullstorydev/sekizui/internal/builtin"
	"github.com/fullstorydev/sekizui/internal/cursor"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step23 — an envelope produced by a REAL connector is lensed on the bus
// (criterion 9): a person's name and email, in a Fullstory session event the
// real driver polled, removed for one consumer and delivered to another.
//
// **THE FIRST TIME SHIN GOVERNS DATA SEKIZUI DID NOT INVENT.** P0 step 16
// lensed an envelope the suite shaped itself. Here the Fullstory driver polls
// step 18's fixture — shapes captured from the synthetic EXAMPLE session — and
// the target lists `User Login`, a custom event that carries `email` and
// `displayName` and restates both in its `description`.
//
// **THREE CONSUMERS, BECAUSE THE LESSON IS IN THE THIRD** (the maintainer: "can we also
// implement a shin that demonstrates removing the name and email from
// session_events?"):
//
//   - agent:analyst — an ALLOWLIST lens (`fields`): what is not named does not
//     arrive. No email, no name, no description.
//   - agent:support — no lens: everything arrives. Non-vacuity.
//   - agent:auditor — a DENYLIST lens (`withholds`) naming email and
//     displayName — and the email STILL ARRIVES, in `description`, which
//     restates the properties as text. Asserted on purpose: a denylist has to
//     know every field that carries the data, including its carriers, and an
//     allowlist does not. It is the screenshot-URL-in-`text` lesson (D289) in a
//     second connector's data.
func p3Step23(t *testing.T) {
	// THE TARGET LISTS `User Login`, so the real driver fetches it (D279); the
	// three consumers' grants and lenses are part of the served document.
	r := eventsRunWith(t, config.TargetLimits{},
		map[string]string{"custom_events": "sekizui_acceptance_step1,sekizui_acceptance_step29,User Login"},
		func(d *config.Document) {
			for _, p := range []string{"agent:analyst", "agent:support", "agent:auditor"} {
				d.Grants = append(d.Grants, config.GrantSpec{Principal: p, Subscribe: []config.SubscriptionSpec{
					{Subject: "sekizui.raw.fullstory.>", TargetRef: "fs:events"}}})
			}
			d.Shin = append(d.Shin,
				config.ShinSpec{Name: "analysts-see-no-person", Enabled: true, Mode: "imposed",
					AppliesTo: []string{"agent:analyst"}, Type: "fullstory.session_event.v1",
					// AN ALLOWLIST: what is not named does not arrive. Paths
					// resolve THROUGH THE FAMILY (D292): `fs-element` is declared
					// by the click kinds; `is_host` is carried by no declared kind
					// but is PLAUSIBLE under the open custom kind, and admitted
					// when the org's data carries it. What happened, not who.
					Fields: []string{"device_id", "session_id", "event_time", "event_type",
						"event_properties.fs-element", "event_properties.is_host"},
					Because: "an analyst needs what happened, not who it happened to"},
				config.ShinSpec{Name: "auditors-see-no-email-field", Enabled: true, Mode: "imposed",
					AppliesTo: []string{"agent:auditor"}, Type: "fullstory.session_event.v1",
					// A DENYLIST: it names the fields, and misses their carrier.
					Withholds: []string{"event_properties.email", "event_properties.displayName"},
					Because:   "step 23c's lesson: a denylist must know every carrier"})
		})
	if r.localOnly(t, "the runner, the lenses and the bus are this instance's") {
		return
	}
	r.narrate(t, "an envelope produced by a real connector result is lensed on the bus")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	subscribe := func(principal string) sekizuiv1.GatewayService_SubscribeClient {
		t.Helper()
		sub, err := r.as(t, principal).Subscribe(ctx, &sekizuiv1.SubscribeRequest{
			Subjects: []string{"sekizui.raw.fullstory.>"}})
		if err != nil {
			t.Fatalf("step 23: %s subscribing: %v", principal, err)
		}
		return sub
	}
	analyst, support, auditor := subscribe("agent:analyst"), subscribe("agent:support"), subscribe("agent:auditor")
	waitFor(t, func() bool { return r.bus.Subscribers() >= 3 }, "the three subscriptions never registered")

	runner := newRunnerFor(t, r, ctx,
		[]config.SourceSpec{{TargetRef: "fs:events", EverySec: 1, Limit: 10}},
		cursor.NewFileStore(t.TempDir()))
	if err := runner.Start(ctx); err != nil {
		t.Fatalf("step 23: %v", err)
	}
	defer func() { _ = runner.Stop(context.Background()) }()

	// The User Login envelope, as each consumer received it — its BYTES.
	loginFor := func(sub sekizuiv1.GatewayService_SubscribeClient) string {
		t.Helper()
		for {
			m, err := sub.Recv()
			if err != nil {
				t.Fatalf("step 23: receiving: %v", err)
			}
			if m.GetEnvelope().GetData().AsMap()["event_type"] == "User Login" {
				b, _ := protojson.Marshal(m.GetEnvelope())
				return string(b)
			}
		}
	}
	pii := []string{"benjamin.clark@example.com", "Benjamin Clark"}

	// 23a — THE ALLOWLIST: neither the name nor the email arrives, anywhere.
	got := loginFor(analyst)
	for _, v := range pii {
		if strings.Contains(got, v) {
			t.Errorf("step 23a: agent:analyst's lens allowlists event fields and %q still arrived: %s", v, got)
		}
	}
	if !strings.Contains(got, `"event_time"`) || !strings.Contains(got, "User Login") ||
		!strings.Contains(got, `"is_host"`) {
		t.Errorf("step 23a: the allowlisted fields did not arrive either — a lens removing "+
			"everything proves nothing: %s", got)
	}

	// 23b — NO LENS: everything arrives (the arm above is not vacuous).
	got = loginFor(support)
	for _, v := range pii {
		if !strings.Contains(got, v) {
			t.Fatalf("step 23b: agent:support has no lens and %q did not arrive — the fixture is not "+
				"serving what the step claims: %s", v, got)
		}
	}

	// 23c — THE DENYLIST: the named fields are gone, and the email arrives
	// anyway through the field that restates them.
	got = loginFor(auditor)
	var env struct {
		Data map[string]any `json:"data"`
	}
	_ = json.Unmarshal([]byte(got), &env)
	props, _ := env.Data["event_properties"].(map[string]any)
	switch {
	case props["email"] != nil || props["displayName"] != nil:
		t.Errorf("step 23c: the denylist did not remove the fields it names: %v", props)
	case !strings.Contains(got, "benjamin.clark@example.com"):
		t.Error("step 23c: the email did not arrive through `description`. If the connector stopped " +
			"restating properties there, this lesson needs a new witness — do not read it as the " +
			"denylist becoming safe")
	}

	// 23d — A TYPO IN A TYPED LENS'S `withholds` REFUSES THE BOOT (D292). It
	// used to withhold nothing, silently. 23e pins the limit: under the open
	// custom kind a misspelled PROPERTY is plausible, because an org's custom
	// event may carry any name — only the carrier and declared kinds are known.
	for _, tc := range []struct {
		arm, path string
		refused   bool
	}{
		{"23d", "event_propertes.email", true},
		{"23e", "event_properties.emial", false},
	} {
		err := checkWithLens(t, config.ShinSpec{Name: "typo", Enabled: true, Mode: "imposed",
			AppliesTo: []string{"agent:auditor"}, Type: "fullstory.session_event.v1",
			Withholds: []string{tc.path}, Because: "a typo"})
		switch {
		case tc.refused && (err == nil || !strings.Contains(err.Error(), "withholds nothing")):
			t.Errorf("step %s: a typed lens withholding %q, which no kind could carry, booted (%v)",
				tc.arm, tc.path, err)
		case !tc.refused && err != nil:
			t.Errorf("step %s: withholding %q under the open custom kind is plausible and was "+
				"refused: %v", tc.arm, tc.path, err)
		}
	}
	r.detail(t, "the allowlist removed the name and email everywhere; with no lens both arrived; the "+
		"denylist removed the fields it named and the email arrived anyway, in description; a "+
		"misspelled carrier in withholds refused the boot")
}

// checkWithLens runs BOTH halves of boot validation over the acceptance
// config plus one lens (and a grant for whom it applies to, so the refusal is
// the lens's and not "a lens for a principal with no grant"), and returns it.
func checkWithLens(t *testing.T, lens config.ShinSpec) error {
	t.Helper()
	doc, err := config.NewFileSource("acceptance.yaml").Load(context.Background())
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	for _, p := range lens.AppliesTo {
		doc.Grants = append(doc.Grants, config.GrantSpec{Principal: p, Subscribe: []config.SubscriptionSpec{
			{Subject: "sekizui.raw.fullstory.>", TargetRef: "fs:events"}}})
	}
	doc.Shin = append(doc.Shin, lens)
	return validateAsBoot(doc)
}

// validateAsBoot runs BOTH halves of boot validation — the document's own, and
// the schema checker over every shipped connector — as a deployment does.
func validateAsBoot(doc *config.Document) error {
	if err := doc.Validate(); err != nil {
		return err
	}
	return schemareg.NewChecker(func() *config.Document { return doc },
		func(d *config.Document) map[string]connector.Driver { return builtin.ByKind(d, nil) },
		slog.New(slog.NewTextHandler(io.Discard, nil))).Validate(context.Background())
}
