package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step37 — a subscription is scoped to the targets it names, as a command is
// (P3 criterion 20, D258, D259).
//
// **THE COMMAND PLANE COULD ALWAYS SAY "ONLY CUSTOMER X" AND THE BUS COULD
// NOT.** `allow` is action × target; `subscribe` was a subject pattern alone,
// and D60 keeps the target out of the subject, so anybody granted a type
// received every org's events of it. The maintainer found it by asking whether a job
// scheduled for one customer would be visible to everyone — it would have
// been, and not because of jobs.
//
// **ORDER IS THE INSTRUMENT.** The bus delivers to one subscription in publish
// order, so every envelope that must be WITHHELD is published BEFORE the one
// that must arrive. A withheld envelope that leaked would be the first thing
// received — an absence made observable without waiting for a deadline, which
// is the only honest way to assert one (P1 step 15's lesson in another form).
func p3Step37(t *testing.T) {
	r := newRun(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r.narrate(t, "a subscription is scoped to the targets it names, as a command is")

	// 37c FIRST, because it needs no live instance: THE BOOT REFUSES WHAT THE
	// GRANT CANNOT EXPRESS, and says what to write instead.
	step37BootRefusals(t)

	if r.localOnly(t, "publishing onto the bus needs in-process access; the boot "+
		"refusals above are this step's half a live instance cannot show") {
		return
	}

	scoped := r.as(t, "agent:scoped")

	// An EMPTY subject list means everything granted (D92's convenience), which
	// here is both pairs — the case where pairing matters, because a check of
	// "subject granted somewhere, target granted somewhere" passes both halves.
	subCtx, cancelSub := context.WithTimeout(ctx, 20*time.Second)
	defer cancelSub()
	stream, err := scoped.Subscribe(subCtx, &sekizuiv1.SubscribeRequest{})
	if err != nil {
		t.Fatalf("step 37: opening the subscription: %v", err)
	}
	waitFor(t, func() bool { return r.bus.Subscribers() > 0 },
		"the server never registered the subscription")

	publish := func(id, stage, source string) {
		t.Helper()
		e := envelope(t, stage, "kata.row.v1", map[string]any{"ordinal": 1})
		e.Id, e.Source = id, source
		if err := r.srv.PublishForTest(e); err != nil {
			t.Fatalf("step 37: publishing %s: %v", id, err)
		}
	}

	// 37a — A TARGET THE GRANT NAMES NOWHERE is withheld.
	publish("37a-gamma-raw", "raw", "kata:gamma")
	// 37b — THE PAIRING. Raw rows are granted from kata:alpha and enriched ones
	// from kata:beta, so a raw row from BETA and an enriched one from ALPHA
	// each satisfy one half of the grant and neither satisfies an entry.
	publish("37b-beta-raw", "raw", "kata:beta")
	publish("37b-alpha-enriched", "enriched", "kata:alpha")
	// NON-VACUITY: the granted pair is DELIVERED. A check that withheld
	// everything would pass every arm above and make subscriptions useless.
	publish("37-alpha-raw", "raw", "kata:alpha")

	got, err := stream.Recv()
	if err != nil {
		t.Fatalf("step 37: receiving: %v", err)
	}
	switch id := got.GetEnvelope().GetId(); id {
	case "37-alpha-raw":
	case "37a-gamma-raw":
		t.Fatalf("step 37a: an envelope from kata:gamma, which no subscribe entry names, " +
			"reached agent:scoped. A subscription is subject × target (D259)")
	case "37b-beta-raw", "37b-alpha-enriched":
		t.Fatalf("step 37b: %q reached agent:scoped. Its subject is granted for one target "+
			"and its target for another subject — the two halves were checked independently "+
			"rather than as one entry (D259)", id)
	default:
		t.Fatalf("step 37: received %q, which this step did not publish", id)
	}

	// And the SECOND pair delivers too, or the arm above proved one entry.
	publish("37-beta-enriched", "enriched", "kata:beta")
	got, err = stream.Recv()
	if err != nil {
		t.Fatalf("step 37: receiving the second pair: %v", err)
	}
	if id := got.GetEnvelope().GetId(); id != "37-beta-enriched" {
		t.Fatalf("step 37: received %q, want the enriched row from kata:beta — the second "+
			"entry confers nothing, so the grant is being read as one pair", id)
	}
	r.detail(t, "agent:scoped received only (raw, kata:alpha) and (enriched, kata:beta); "+
		"three envelopes satisfying neither entry, or only half of one, were withheld")

	// 37d — THE ESTABLISHMENT RECORD NAMES THE TARGETS. D93 records a
	// subscription once, so that row is the only place a reviewer can learn
	// which customers' events this consumer can see.
	var opened *sekizuiv1.Decision
	for _, d := range readLog(t, r.path) {
		if d.GetAction() == "sekizui.subscribe" &&
			d.GetIdentity().GetSubject().GetPrincipal() == "agent:scoped" &&
			d.GetVerdict() == sekizuiv1.Verdict_VERDICT_ALLOW {
			opened = d
		}
	}
	if opened == nil {
		t.Fatal("step 37d: no record of agent:scoped's subscription being opened")
	}
	for _, target := range []string{"kata:alpha", "kata:beta"} {
		if !strings.Contains(opened.GetReason(), target) {
			t.Errorf("step 37d: the subscription record does not name %s: %q — a reviewer "+
				"cannot tell whose events this consumer receives", target, opened.GetReason())
		}
	}
}

// step37BootRefusals is 37c: each form a subscribe entry cannot take is refused
// at boot, naming the fix.
//
// THE PRE-D259 FORM IS THE ONE THAT MATTERS. Every existing deployment wrote
// bare strings; left to the decoder that fails as "cannot unmarshal string into
// Go struct field", which names a Go type to an operator who wanted to know
// what to type.
func step37BootRefusals(t *testing.T) {
	t.Helper()

	base, err := os.ReadFile("acceptance.yaml")
	if err != nil {
		t.Fatalf("step 37c: reading acceptance.yaml: %v", err)
	}
	const entry = `      - {subject: "sekizui.raw.kata.>", target: kata:alpha}`
	if !strings.Contains(string(base), entry) {
		t.Fatalf("step 37c: acceptance.yaml no longer carries %q, which this step edits", entry)
	}

	for _, tc := range []struct {
		name, replacement string
		want              []string
	}{
		{"a bare subject (the pre-D259 form)", `      - "sekizui.raw.kata.>"`,
			[]string{"bare subject", "D259", "target"}},
		{"no target", `      - {subject: "sekizui.raw.kata.>"}`,
			[]string{"names no target", "D259"}},
		{"a wildcard target", `      - {subject: "sekizui.raw.kata.>", target: "*"}`,
			[]string{"unknown target", "matched exactly"}},
		{"an undeclared target", `      - {subject: "sekizui.raw.kata.>", target: kata:nobody}`,
			[]string{"unknown target", "kata:nobody"}},
	} {
		src := strings.Replace(string(base), entry, tc.replacement, 1)
		path := filepath.Join(t.TempDir(), "acceptance.yaml")
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatalf("step 37c: %v", err)
		}
		// Parse and validate are both boot: either refusing is the property.
		doc, err := config.NewFileSource(path).Load(context.Background())
		if err == nil {
			err = doc.Validate()
		}
		if err == nil {
			t.Errorf("step 37c: %s was accepted at boot", tc.name)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("step 37c: %s was refused without saying %q, so the operator is "+
					"not told what to write instead: %v", tc.name, w, err)
			}
		}
	}
}
