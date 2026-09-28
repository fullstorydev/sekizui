package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/connectors/fullstory"
	"github.com/fullstorydev/sekizui/pkg/connector"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// liveWriteRequested is the environment variable that says a human asked for the
// writes, and `make acceptance-live` is the only thing that sets it.
const liveWriteRequested = "SEKIZUI_FULLSTORY_WRITE"

// liveFullstory gates the two steps that touch a system nobody here controls.
//
// **TWO SEPARATE QUESTIONS, AND CONFLATING THEM SPAMMED A REAL ORG (D229).**
// *Is there a key* is a capability; *may this run write* is an intent. The first
// version asked only the first, so every `make acceptance` on the one laptop
// holding the key appended an event and upserted a user — and `make mutate`
// re-runs the whole acceptance suite ONCE PER MUTATION, so a single `make ci`
// put roughly a hundred and forty synthetic records into the maintainers' test org and pushed
// the run past ten minutes on network calls nobody wanted. Neither write is
// undoable: `POST /v2/events` is append-only and there is no delete.
//
// The intent lives in the MAKE TARGET a human types rather than in a file that
// persists, for D97's reason one layer over: a posture that sits where it is
// reviewed at the moment of use cannot be inherited by accident. A key on disk
// is inherited by every process that runs afterwards, including 68 mutation
// runs; `make acceptance-live` is a sentence somebody wrote on purpose.
//
// **NOT ASKING IS THE NORMAL CASE and must not be a failure; ASKING WITHOUT
// COORDINATES IS ONE, because a live run that reached nothing must not pass.** A run
// that does not ask skips these two and runs everything else, which is the blueprint's own rule: unit
// tests against a fake transport, one integration test against a real sandbox,
// skipped without credentials. Both skips are LOUD and name what is missing,
// because a step that quietly does nothing is indistinguishable from one that
// passed.
func liveFullstory(t *testing.T) liveCoordinates {
	t.Helper()

	// INTENT FIRST, because on the machine that HAS the key it is the only
	// missing half, and naming the other one would send a reader looking for a
	// file that is already there.
	if os.Getenv(liveWriteRequested) == "" {
		t.Skipf("live Fullstory writes were not requested, so this step is skipped and "+
			"everything else runs. It appends a real server-side event and upserts a real "+
			"user in the org dev/fullstory-live.yaml names, and neither is undoable — `POST /v2/events` is "+
			"append-only. Run `make acceptance-live` to ask for it, which sets %s. "+
			"`make acceptance`, `make ci` and `make mutate` are hermetic by construction, "+
			"which is what keeps 68 mutation runs from writing 136 records nobody reads",
			liveWriteRequested)
	}

	lc := loadLiveConfig(t) // fails, naming what is missing: the run was asked for
	key, err := os.ReadFile(lc.Key)
	if err != nil || len(strings.TrimSpace(string(key))) == 0 {
		t.Fatalf("no Fullstory key at %s (%v): a live run was asked for and cannot "+
			"authenticate. dev/fullstory-live.yaml's `key` names the file", lc.Key, err)
	}

	// **TRIMMED, AND D199 IS WHY.** The file is written with no trailing newline
	// on purpose, and a newline that survived into a header value is refused as a
	// configuration fault naming the byte — correct, and a confusing first
	// contact. Trimming here means the step proves Fullstory's answer rather than
	// our own header validation, which step 38 already owns.
	t.Setenv("SEKIZUI_FS_LIVE", strings.TrimSpace(string(key)))
	return lc
}

// step1AnAgentWritesARealEventToFullstory proves criterion 1.
//
// **THE PHASE'S HEADLINE CLAIM, and the first time any of this touches a system
// nobody here controls.** Everything else is provable against a fixture that
// agrees with us by construction. This is the step where the far side is somebody
// else's, and where "the governed path works" stops being a statement about our
// own test doubles.
//
// A command from a real gRPC client holding a CA-signed certificate traverses
// mTLS, identity, the ceilings, policy, the resolver, the pool and the driver,
// and the event appears in Fullstory. **The audit row carries `ExternalRef`**,
// which is what makes the trail checkable against the far side rather than only
// against itself.
//
// **IT WRITES, AND THE WRITE IS NOT UNDOABLE.** `POST /v2/events` is append-only:
// there is no delete. It runs only when a live run is asked for, against the org
// the contributor configured, and the event is named so anyone finding it later can tell
// what produced it.
func step1AnAgentWritesARealEventToFullstory(t *testing.T) {
	lc := liveFullstory(t)

	r := newRun(t)
	ctx := context.Background()

	// **NAMED FOR ITS PROVENANCE, because it cannot be deleted.** An event called
	// `test` in a real org is somebody's puzzle six months from now; this one says
	// what wrote it and when, and the run stamp makes two executions
	// distinguishable in the UI.
	stamp := time.Now().UTC().Format("20060102T150405Z")
	eventName := "sekizui_acceptance_step1"

	res, err := r.as(t, "agent:triage").Execute(ctx, &sekizuiv1.ExecuteRequest{
		Command: &sekizuiv1.Command{
			Action:    fullstory.ActionCreateEvent,
			TargetRef: "fs:live",
			Args: mustArgs(t, map[string]any{
				"name": eventName,
				// **SESSION ONLY — `user` AND `session.id` ARE MUTUALLY EXCLUSIVE,
				// which the API told us and no document did.** Sending both is a
				// 400: *"user field is not allowed when session.id is provided"*.
				// The session is the more specific of the two — it implies the
				// user — and it is what puts the event where a human will look.
				// Recorded here because the driver's own comment lists `user.uid`
				// and `session.id` side by side as though a caller may pass both.
				"session": map[string]any{"id": lc.Session},
				"properties": map[string]any{
					"run":    stamp,
					"source": "sekizui-acceptance",
				},
			}),
		},
	})
	if err != nil {
		t.Fatalf("step 1: the governed write failed: %v", err)
	}
	if got := res.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("step 1: Fullstory refused the event: %v — %s",
			got, res.GetResult().GetReason())
	}

	// --- 1a: THE AUDIT ROW IS REACHABLE AND RECORDS THE EFFECT -------------
	//
	// **THE DECLARED ASSERTION FOR THIS STEP PROMISED `ExternalRef`, AND THE
	// VENDOR CANNOT SUPPLY ONE (D224).** `POST /v2/events` answers `200 {}` — an
	// empty object, verified by hand against the live org. There is no event id,
	// no location header, nothing to join on. So the driver is not dropping a
	// field; the field does not exist for this action, and an arm requiring it
	// would fail forever for a reason no code change here could fix.
	//
	// **WHAT IS ASSERTED INSTEAD IS EVERYTHING THAT IS TRUE**: the caller can NAME
	// its row (D202), the row records the effect against the real far side, and
	// the join gap is stated rather than left as a silent absence. Blueprint step
	// 12's obligation stands for connectors whose vendor returns an identifier —
	// `upsert_user` in step 4 is the contrast — and this one is a documented
	// exception rather than an oversight.
	t.Run("the audit row is reachable and records the real effect", func(t *testing.T) {
		rows := rowsWithID(t, r.path, res.GetResult().GetDecisionId())
		if len(rows) == 0 {
			t.Fatalf("the returned decision id names no row. The caller cannot reach "+
				"its own audit trail, which is D202 falsified. Session: %s", lc.describe())
		}

		var effect *sekizuiv1.Effect
		for _, row := range rows {
			if e := row.GetEffect(); e != nil && e.GetSuccess() {
				effect = e
			}
		}
		if effect == nil {
			t.Fatal("no row for this command records a successful Effect, though " +
				"Fullstory accepted the write. The trail then disagrees with the far side")
		}
		if got := effect.GetStatusCode(); got != http.StatusOK {
			t.Errorf("the recorded status is %d, want 200 — the row disagrees with what "+
				"the vendor actually answered", got)
		}

		// **THE GAP, ASSERTED AS A GAP.** If Fullstory ever starts returning an
		// id, this fails and somebody deletes the exception — which is the point
		// of pinning it rather than merely commenting on it.
		if ref := effect.GetExternalRef(); ref != "" {
			t.Errorf("the row carries ExternalRef %q. `POST /v2/events` returned no "+
				"identifier when this exception was recorded (D224); if the vendor now "+
				"supplies one, delete this arm and require it instead", ref)
		}
	})

	// --- 1b: THE EVENT IS NOT READ BACK, AND THAT IS A STATED LIMIT --------
	//
	// **THERE IS NO READ-BACK PATH FOR SERVER EVENTS, and both candidates were
	// tried rather than assumed.** `GET /v2/events` answers 405: the endpoint is
	// write-only. The Fullstory MCP server this repository has configured points
	// at a non-production host, while the maintainers' test org is production NA1, so
	// session review through it would query a different deployment entirely.
	//
	// **INGESTION WAS CONFIRMED BY A HUMAN, ONCE, AND THAT IS THE HONEST STATUS.**
	// The maintainer read the session back in the Fullstory UI on the first run and found
	// both events attached to it with their properties intact. So the write
	// demonstrably lands; what does not exist is an API this step could ask, so
	// the confirmation is a fact about one run rather than an arm that will catch
	// a regression.
	//
	// **THE STEP THEREFORE PROVES THE GOVERNED WRITE AND NOT THE INGESTION.** What
	// criterion 1 actually claims is that a command from a real client traverses
	// the whole enforcement path and reaches a system nobody here controls —
	// settled by Fullstory's own 200 on a request carrying a credential the agent
	// was never given. Whether the event is subsequently searchable is
	// Fullstory's pipeline rather than Sekizui's enforcement path.
	//
	// **THE PROPERTY NAMES CARRY NO TYPE SUFFIX, because Fullstory adds its own.**
	// The first run sent `run_str` and the UI showed `run_str_str`. The API infers
	// the suffix from the value, so supplying one doubles it.
	r.detail(t, "criterion 1: agent:triage wrote %q into a REAL Fullstory session "+
		"over mTLS, through identity, ceilings, policy, the resolver, the pool and "+
		"the driver — the maintainers' test org accepted it with 200. The vendor returns no event "+
		"id, so there is no ExternalRef to join on (D224); INGESTION IS READ BACK BY "+
		"P3 STEP 29 (D270), which writes its own stamped event and finds it in "+
		"session %s through a governed query — the check that was a human opening "+
		"the UI for two phases", eventName, lc.device+":"+lc.uiSession)
}

// step4ANaturalClassActionRetriesAndProducesOneEffect proves criterion 6.
//
// **THE HALF THAT SHOWS THE CLASSIFICATION IS DOING WORK RATHER THAN REFUSING
// EVERYTHING.** Step 3 proves a `none`-class action refuses its retry; a driver
// that refused every retry would pass it and be useless. `POST /v2/users` is a
// create-or-update keyed on `uid`, so replaying it is harmless and it needs no
// idempotency key at all — and the proof has to be at the FAR SIDE, because
// counting local calls proves we sent two requests and nothing about what they
// did.
//
// **ONE USER, WITH THE LAST WRITE'S VALUES.** That is the whole of `natural`:
// not "the second call was suppressed" — it was not, both were sent — but "the
// second call converged on the same record".
func step4ANaturalClassActionRetriesAndProducesOneEffect(t *testing.T) {
	lc := liveFullstory(t)

	r := newRun(t)
	ctx := context.Background()

	first := time.Now().UTC().Format("20060102T150405Z")
	second := first + "-again"

	upsert := func(marker string) {
		t.Helper()
		res, err := r.as(t, "agent:triage").Execute(ctx, &sekizuiv1.ExecuteRequest{
			Command: &sekizuiv1.Command{
				Action:    fullstory.ActionUpsertUser,
				TargetRef: "fs:live",
				Args: mustArgs(t, map[string]any{
					"uid": lc.UID,
					"properties": map[string]any{
						"sekizui_run": marker,
					},
				}),
			},
		})
		if err != nil {
			t.Fatalf("step 4: the governed upsert failed: %v", err)
		}
		if got := res.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
			t.Fatalf("step 4: Fullstory refused the upsert: %v — %s",
				got, res.GetResult().GetReason())
		}
	}

	// **REPLAYED DELIBERATELY, WITH DIFFERENT VALUES.** Sending the identical body
	// twice would leave "one user" true for a reason that has nothing to do with
	// idempotency — a far side that ignored the second call entirely looks the
	// same. Changing the marker makes the second write OBSERVABLE, so the
	// assertion below can tell convergence from suppression.
	upsert(first)
	upsert(second)

	t.Run("one user carries the last write's values", func(t *testing.T) {
		// Eventually consistent, for step 1's reason.
		deadline := time.Now().Add(90 * time.Second)
		for {
			users, err := liveUsersByUID(t, lc)
			if err != nil {
				t.Fatalf("querying Fullstory for the user: %v", err)
			}

			switch {
			case len(users) > 1:
				// **THE FALSIFYING OUTCOME, and the reason the count is asserted
				// rather than assumed.** Two records for one uid would mean
				// `natural` is the wrong classification — the action creates
				// rather than converges — and D163's per-action ruling would have
				// been wrong about this vendor.
				t.Fatalf("uid %s has %d user records, want exactly 1. A `natural` "+
					"action that CREATES on replay is misclassified, and every retry "+
					"the enforcement path permits duplicates a record", lc.UID, len(users))
			case len(users) == 1:
				if got := users[0].marker; got == second {
					r.detail(t, "criterion 6: two upserts of uid %s converged on ONE "+
						"record carrying the second write's value — `natural` proven at "+
						"the far side rather than by counting local calls", lc.UID)
					return
				}
			}
			if time.Now().After(deadline) {
				t.Errorf("uid %s did not settle on the second write's marker %q within "+
					"90s. Either ingestion is slower than the budget or the upsert is "+
					"not converging; %s", lc.UID, second, lc.describe())
				return
			}
			time.Sleep(5 * time.Second)
		}
	})
}

// --- reading the far side back ------------------------------------------------
//
// **READ-ONLY, AND DELIBERATELY NOT THROUGH SEKIZUI.** The driver has no read
// action — it is a two-action write connector by design — and giving it one so a
// test could check itself would be adding product surface to satisfy a test. The
// verification is an independent observer, which is also what makes it evidence:
// a step that checked its own write through its own driver would prove the driver
// agrees with itself.

type liveUser struct{ marker string }

func liveUsersByUID(t *testing.T, lc liveCoordinates) ([]liveUser, error) {
	t.Helper()

	var body struct {
		Results []struct {
			ID         string            `json:"id"`
			UID        string            `json:"uid"`
			Properties map[string]any    `json:"properties"`
			Extra      map[string]string `json:"-"`
		} `json:"results"`
	}
	if err := liveGet(t, "/v2/users?uid="+url.QueryEscape(lc.UID), &body); err != nil {
		return nil, err
	}

	out := make([]liveUser, 0, len(body.Results))
	for _, u := range body.Results {
		// **`sekizui_run`, WITH NO TYPE SUFFIX, and the asymmetry is the vendor's.**
		// EVENT properties get one appended — `run` is stored as `run_str` — while
		// USER properties keep the name they were sent with. Both were verified
		// against the live org rather than reasoned about, after the first run
		// wrote `run_str` and the UI showed `run_str_str`.
		marker, _ := u.Properties["sekizui_run"].(string)
		out = append(out, liveUser{marker: marker})
	}
	return out, nil
}

func liveGet(t *testing.T, path string, into any) error {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "https://api.fullstory.com"+path, nil)
	if err != nil {
		return err
	}
	// **THROUGH `connector.SetAuthorization`, NOT BY HAND, and the guard that
	// insisted was right.** `TestNoAdHocAuthorizationHeaders` caught the first
	// draft stamping the header itself. The exemption would have been easy to
	// argue — this is an INDEPENDENT observer, deliberately not the driver — and
	// it would have been wrong: the helper is the shared credential LEASE (D127),
	// not the driver, so using it here is not the verifier checking itself. It
	// also gets the newline refusal (D199) for free, which is exactly the failure
	// a hand-rolled key read would produce.
	tg, err := connector.NewTarget(connector.TargetParams{
		Ref: "fs:live-observer", Kind: "fullstory", Tenant: "live", Residency: "eu",
		BaseURL: "https://api.fullstory.com", CredentialVersion: "live",
		Credential: connector.Secret(os.Getenv("SEKIZUI_FS_LIVE")),
	})
	if err != nil {
		return err
	}
	if err := connector.SetAuthorization(req.Header, tg, "Basic"); err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}
