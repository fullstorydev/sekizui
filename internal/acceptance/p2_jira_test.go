package acceptance

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/connectors/jira"
	"github.com/fullstorydev/sekizui/internal/schemareg"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// step27TheThinJiraDriverIsBuiltFromTheBlueprint proves criterion 11 (D167, D222).
//
// **THE ONLY HONEST TEST OF A REUSABLE ARTEFACT IS ITS SECOND USER.** Fullstory
// shaped `hako/BLUEPRINT.md`; a document validated only by the connector
// that produced it is validated by nobody. So the thin Jira driver was written
// with the blueprint open and `internal/connectors/fullstory` deliberately unread,
// and everything Jira needed that the blueprint did not say was recorded as a
// defect THERE rather than fixed silently in the driver.
//
// **THE MEASUREMENT IS SPENT AND CANNOT BE REPEATED**, which is why this step
// asserts the artefacts rather than the process. Whether a document was FOLLOWED
// is not machine-checkable — nothing can tell a driver written from the
// blueprint from one written from another driver and retro-fitted — so that half
// is named as a limit below and is not pretended away.
//
// **WHAT IS ASSERTED IS WHAT WOULD BE MISSING IF THE BLUEPRINT HAD BEEN
// SKIPPED**: the mechanical contract, an idempotency class per mutating action,
// a lens, a ceiling, a registered payload schema — and registration, which is
// D222's finding and the one an author is most likely to omit because nothing
// about the driver looks wrong without it.
//
// **THE DRIVER'S OWN PACKAGE ALREADY TESTS ITS BEHAVIOUR, AND THIS IS NOT A
// SECOND COPY OF THAT.** `internal/connectors/jira` runs the conformance suite, the
// 404 decision, the attribution stamp and the auth scheme. What lives HERE is
// what only the phase can see: that the connector is reachable at all, and that
// its governance travels with it rather than existing beside it.
func step27TheThinJiraDriverIsBuiltFromTheBlueprint(t *testing.T) {
	r := &run{path: auditPath(t)}

	drv := jira.New()
	doc := jiraConnectorDoc(t)

	// --- 27a: THE DRIVER IS REGISTERED, SO IT EXISTS AT ALL (D190, D222) ----
	//
	// **AN UNREGISTERED DRIVER COMPILES, TESTS GREEN, PASSES THE WHOLE
	// CONFORMANCE SUITE, AND IS ROUTED TO BY NOTHING.** It fails in the most
	// convincing way available: `Execute`, `Query`, `Kind` and `Actions` all LOOK
	// reached, because they satisfy `connector.Driver` and the gateway calls that
	// interface. The blueprint had eleven steps about making a driver correct and
	// none about making it reachable until D222 — so this arm is the phase-level
	// version of the question that finding turned on: what constructs it?
	//
	// **THROUGH THE REAL REGISTRY, not by grepping main.go.** `Register` reads the
	// kind off the driver rather than taking a key (D190), so this also proves the
	// routing key and `Kind()` cannot disagree.
	t.Run("the driver registers under its own kind", func(t *testing.T) {
		reg := connector.NewRegistry()
		if err := reg.Register(drv); err != nil {
			t.Fatalf("registering the jira driver: %v", err)
		}
		if _, ok := reg.Drivers()[jira.Kind]; !ok {
			t.Fatalf("the registry has no %q after registering it; kinds are %v",
				jira.Kind, reg.Kinds())
		}
		// The target the connector ships names this kind. A connector whose
		// target routes to a driver nobody registered is the same inert state
		// with one more file in it.
		if got := doc.Targets[0].Kind; got != jira.Kind {
			t.Errorf("the connector's target is kind %q and the driver registers %q",
				got, jira.Kind)
		}
	})

	// --- 27b: THE MECHANICAL CONTRACT, THROUGH THE SAME FUNCTION BOOT USES --
	//
	// **`connector.ValidateActions` RATHER THAN A HAND-WRITTEN LOOP (D163,
	// D167).** It is what `schemareg`'s boot check calls and what the published
	// conformance suite calls, so a driver that passes here passes boot and vice
	// versa. Two implementations of "what makes an ActionSpec valid" would drift,
	// and the drift would be silent in the worst direction: a deployment
	// accepting what the suite rejected.
	t.Run("every action is valid and every mutating one is classified", func(t *testing.T) {
		if problems := connector.ValidateActions(jira.Kind, drv.Actions()); len(problems) > 0 {
			t.Errorf("the jira driver's action set is invalid:\n  - %s",
				strings.Join(problems, "\n  - "))
		}

		var mutating, classified int
		for _, spec := range drv.Actions() {
			if !spec.Mutating {
				continue
			}
			mutating++
			if spec.Idempotency != "" {
				classified++
			}
		}
		// **NON-VACUITY, AND THE PHASE SCOPE IS WHY IT MATTERS.** §12 P2 scoped
		// Jira to "ticket lookup only", and a read-only driver satisfies "declares
		// an idempotency class per action" by having no action that needs one.
		// D222 widened the scope by exactly one action so that blueprint step 3 —
		// D163's whole subject — gets a second user rather than being skipped.
		if mutating == 0 {
			t.Fatal("the jira driver has no mutating action, so this arm asserts " +
				"nothing. D163's classification is the step the blueprint's second " +
				"user exists to exercise, and a read-only driver cannot exercise it")
		}
		if classified != mutating {
			t.Errorf("%d of %d mutating actions declare an idempotency class. An "+
				"absent classification fails the load, and there is no safe default: "+
				"one would either forbid retries the upstream supports or permit a "+
				"double-write nobody chose", classified, mutating)
		}
	})

	// --- 27c: THE GOVERNANCE HALF SHIPS WITH THE CONNECTOR ------------------
	//
	// **THIS IS THE HALF NOTHING WOULD HAVE FAILED THE BUILD OVER**, which is the
	// whole reason the blueprint exists (D175): a driver can be stateless,
	// tenant-asserting, idempotency-classified and attribution-stamped, tick every
	// one of CONTRACTS §5's thirty checkboxes, and ship with no lens, no ceiling
	// and grants nobody narrowed. It would work perfectly and govern nothing.
	t.Run("the connector ships a lens, a ceiling and a narrow grant", func(t *testing.T) {
		if len(doc.Shin) == 0 {
			t.Error("no shin lens. A Jira issue carries a reporter's email address and " +
				"a description support agents paste customer detail into; nothing in " +
				"the system will ever report this missing")
		}
		if len(doc.Anzen) == 0 {
			t.Fatal("no anzen ceiling. A grant is written per principal by whoever " +
				"needs the capability; a ceiling is written once by whoever is " +
				"accountable for the blast radius, and it is checked FIRST")
		}
		// **SHADOW IS THE DEFAULT, so an omitted mode is a ceiling that only
		// warns while reading in review as enforcement.**
		if mode := doc.Anzen[0].Mode; mode != "enforce" {
			t.Errorf("the ceiling is mode %q, so it records what it would have "+
				"refused and refuses nothing", mode)
		}
		for _, g := range doc.Grants {
			for _, c := range g.Allow {
				if c.TargetRef == "" {
					t.Errorf("grant capability %q names no target, so it authorises "+
						"that action against every jira target — including ones added "+
						"later by somebody who never read this grant", c.Action)
				}
			}
		}
	})

	// --- 27d: AND THE LENS IS ENFORCEABLE RATHER THAN DECORATIVE (D221) -----
	//
	// **A LENS TYPED ON SOMETHING NO ACTION PRODUCES LOADS CLEANLY AND WITHHOLDS
	// NOTHING**, and it reads in review as a control in force. That is not
	// hypothetical: it is exactly what the kata's answer key did for two phases,
	// because `OutputType` takes the payload REGISTRY KEY and the schema URI
	// looks interchangeable with it (D41, D88).
	//
	// **THE REAL BOOT CHECK, NOT A STRING THIS FILE TYPED.** D221's lesson is
	// that three hand-written copies which agree are not one checked copy, so the
	// question goes to the component that would refuse the boot.
	t.Run("the query action's payload schema is registered", func(t *testing.T) {
		checker := schemareg.NewChecker(
			func() *config.Document { return &doc },
			func(*config.Document) map[string]connector.Driver { return map[string]connector.Driver{jira.Kind: drv} },
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)
		if err := checker.Validate(context.Background()); err != nil {
			t.Errorf("the jira connector would not survive boot: %v", err)
		}

		declared := map[string]bool{}
		for _, spec := range drv.Actions() {
			if !spec.Mutating && spec.OutputType != "" {
				declared[spec.OutputType] = true
			}
		}
		if len(declared) == 0 {
			t.Fatal("no query action declares an OutputType, so its results are " +
				"lensable only by the type-less jurisdiction rules and the lens " +
				"below has no type to name")
		}
		for _, lens := range doc.Shin {
			if lens.Type != "" && !declared[lens.Type] {
				t.Errorf("lens %q is typed %q and no query action declares that "+
					"OutputType. A lens on a type nothing produces is INERT", lens.Name,
					lens.Type)
			}
		}
	})

	// --- 27e: THE DRIVER SAYS WHAT IT HAS NOT VERIFIED ----------------------
	//
	// **THIS CONNECTOR HAS NEVER SPOKEN TO A REAL JIRA (the maintainer's ruling), so its
	// fixtures agree with it BY CONSTRUCTION and prove nothing about the
	// vendor.** Only the auth scheme was checked against Atlassian's published
	// documentation; the endpoints, the comment body and the attribution
	// placement are read from the documented shape.
	//
	// A driver built from documentation HAS assumptions, and the only question is
	// whether they are written down or rediscovered from a 400. Emptying the list
	// would make the package look verified, so the list is required to exist and
	// to distinguish what was checked from what was guessed.
	t.Run("what was assumed is separated from what was verified", func(t *testing.T) {
		got := jira.Assumptions()
		if len(got) == 0 {
			t.Fatal("the jira driver records no assumptions. It has never met a real " +
				"Jira, so an empty list is not a clean bill of health — it is the " +
				"evidence having been deleted")
		}
		var verified int
		for _, a := range got {
			if strings.HasPrefix(a, "VERIFIED") {
				verified++
			}
		}
		if verified == 0 {
			t.Error("nothing in the assumption list is marked VERIFIED, so it cannot " +
				"tell a reader which claims were checked against the vendor's own " +
				"documentation and which were inferred")
		}
	})

	// --- THE LIMIT, STATED RATHER THAN PRETENDED AWAY -----------------------
	//
	// **WHETHER THE BLUEPRINT WAS FOLLOWED IS NOT MACHINE-CHECKABLE.** Nothing
	// here can distinguish a driver written FROM the document from one written
	// against another driver and retro-fitted to look like it. What the arms above
	// prove is that the artefacts the blueprint asks for exist and are coherent;
	// the reading discipline is a claim by its author, recorded in D222 and in the
	// package comment, and believable only to the extent that the three defects it
	// reported are real.
	//
	// That is the same shape the blueprint gives itself in its closing section,
	// and repeating it here is deliberate: a step that quietly asserted less than
	// its name suggests would be the defect this phase keeps finding.
	r.detail(t, "criterion 11: the thin Jira driver is registered, contract-valid, "+
		"idempotency-classified, lensed, ceilinged and schema-registered. Being the "+
		"blueprint's second user cost it three defects (CONTRACTS 97-99, D222). "+
		"LIMIT: that the document was FOLLOWED is not machine-checkable and is not "+
		"claimed here")
}

// jiraConnectorDoc loads the governance half the connector ships.
//
// **BESIDE THE DRIVER RATHER THAN IN `acceptance.yaml`, and blueprint step 11
// says why**: the shared fixture is loaded once before any step runs, so a target
// whose `base_url` is not known until a test server starts cannot live in it.
// Jira's is a fixture URL in every test that has one.
//
// STRICT, so an unknown key is an error rather than silence: a lens spelled
// `witholds` parses cleanly under a lenient unmarshal, binds to nothing, and
// withholds nothing.
func jiraConnectorDoc(t *testing.T) config.Document {
	t.Helper()

	path := filepath.Join(mustRoot(t), "internal", "connectors", "jira", "jira.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the jira connector's configuration: %v", err)
	}

	var doc config.Document
	if err := yaml.UnmarshalStrict(raw, &doc); err != nil {
		t.Fatalf("the jira connector's configuration does not load: %v", err)
	}
	if len(doc.Targets) == 0 {
		t.Fatal("the jira connector declares no target, so every arm reading it " +
			"would pass vacuously")
	}
	return doc
}
