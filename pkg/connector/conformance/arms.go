package conformance

// Arm is one assertion this suite makes, named so a document can state the
// contract without restating it.
type Arm struct {
	// Name is the internal function, `runX`, and is the join key the guard uses.
	Name string

	// Suite is "Run", "RunHTTP", "RunSource", "RunDrift", "RunRefiner" or "RunPresetter" — which part a
	// driver has to select to get it.
	Suite string

	// What is one line an author can read, in the imperative of the obligation
	// rather than of the check.
	What string
}

// Arms is what this suite asserts, and it is the SOURCE the connector
// blueprint's enforced table is generated from (D218).
//
// **WHY A TABLE AND NOT PROSE SOMEWHERE.** CONTRACTS 93: the connector contract
// was stated in three places — §5's checkboxes, D167's sentence, and this
// package's code — and no two agreed. D167 named seven assertions and the suite
// made four, which nothing could tell, because a sentence in a decision has
// nothing to be checked against. A fourth statement would not have helped; what
// helps is that the document is GENERATED from here.
//
// **AND THIS TABLE IS ITSELF GUARDED, or it would be the fourth statement.** P2
// step 46 walks this package's AST and requires three sets to be equal: the
// `run*` functions DECLARED, the ones CALLED from `Run` and `RunHTTP`, and the
// entries here. An arm added without a line rots the document; a line without an
// arm claims coverage that does not exist; and an arm declared but never called
// is the shape D139's registry exists to catch.
func Arms() []Arm {
	return []Arm{
		{Name: "runKind", Suite: "Run",
			What: "your Kind is non-empty, so a target's `kind:` can route to you at all"},
		{Name: "runActions", Suite: "Run",
			What: "every action has a unique name, a real description (not its own identifier " +
				"restated), and — if it mutates — a declared idempotency class"},
		{Name: "runSchemasDeclared", Suite: "Run",
			What: "you ship the schema of every type your actions declare, and of nothing else — " +
				"closed by default, the same check the boot makes (D279)"},
		{Name: "runMeterSound", Suite: "Run",
			What: "your meter can price every call and every poll before it is sent — a Source " +
				"declares its poll's worst case, and a unit other than calls declares its own " +
				"default and action cost; the same check the boot makes (D284)"},
		{Name: "runUnknownAction", Suite: "Run",
			What: "an action you do not implement is refused DELIBERATELY, is not retryable, " +
				"and does not touch the target's breaker"},
		{Name: "runStateless", Suite: "Run",
			What: "one instance serves every tenant at once and the far side sees each call's " +
				"OWN credential — under `-race`, which the arm requires"},
		{Name: "runTenantAsserted", Suite: "Run",
			What: "a request whose tenant does not match the target's never REACHES the far " +
				"side, and the refusal is not attributed to the target"},
		{Name: "runUnauthorized", Suite: "RunHTTP",
			What: "a 401 is `unauthenticated`, does not implicate the target, and asks for the " +
				"CREDENTIAL to be re-established"},
		{Name: "runForbidden", Suite: "RunHTTP",
			What: "a 403 is deliberate and is NOT re-establishable — the credential was " +
				"accepted and the action refused"},
		{Name: "runRateLimited", Suite: "RunHTTP",
			What: "a 429 is `rate_limited`, does not implicate the target, and its " +
				"`Retry-After` survives classification"},
		{Name: "runServerError", Suite: "RunHTTP",
			What: "a 5xx implicates the target, is retryable, and is not re-establishable"},
		{Name: "runUnreachable", Suite: "RunHTTP",
			What: "an unreachable server implicates the target and is never reported as drift"},
		{Name: "runCancelled", Suite: "RunHTTP",
			What: "an already-cancelled context stops you doing work the caller abandoned"},
		{Name: "runSourceIsAdvertised", Suite: "RunSource",
			What: "your poll appears in Actions() as `<kind>.poll` and is not mutating, " +
				"because a grant cannot name an action no driver implements"},
		{Name: "runSourceTypesDeclared", Suite: "RunSource",
			What: "your poll declares the types it yields, and every event it returns " +
				"carries one of them — an undeclared type is refused, never published"},
		{Name: "runSourceConformsToItsSchema", Suite: "RunSource",
			What: "what your poll returns conforms to your own schema once shaped — no declared " +
				"field of the wrong type, no kind your own family refuses"},
		{Name: "runSourceResponse", Suite: "RunSource",
			What: "one poll's response conforms — within the limit, no repeated or missing " +
				"ids, every event typed and dated, and the cursor not handed straight back"},
		{Name: "runSourceTenantAsserted", Suite: "RunSource",
			What: "a poll carrying a tenant the target is not bound to is REFUSED — a read " +
				"is not exempt from the egress assertion"},
		{Name: "runSourceProgress", Suite: "RunSource",
			What: "a second poll from the cursor you returned yields DIFFERENT rows, so a " +
				"cursor that changes while the window does not is caught"},
		{Name: "runSourceRecoveryIsTrue", Suite: "RunSource",
			What: "your declared recovery policy is true: `requery` really returns the same " +
				"window twice, and `unable` says what an operator should change"},
		{Name: "runSourceCancelled", Suite: "RunSource",
			What: "a cancelled context stops the poll and returns no events, because the " +
				"spine's per-poll deadline arrives as exactly that"},
		{Name: "runSourceBorrows", Suite: "RunSource",
			What: "your poll borrows its client from the pool, because a source that " +
				"dials privately cannot be stopped by `revoke_credential` — and a poll " +
				"repeats on a timer"},
		{Name: "runNoCredentialInTheError", Suite: "RunHTTP",
			What: "the credential you send appears nowhere in the error you return"},
		{Name: "runDriftPriced", Suite: "RunDrift",
			What: "if you report drift, you declare a system budget and price a comparison before it " +
				"is sent — comparisons are Sekizui's safety traffic and never billed to consumers (D311)"},
		{Name: "runDriftClean", Suite: "RunDrift",
			What: "a live surface that matches what was vetted reports nothing"},
		{Name: "runDriftGraded", Suite: "RunDrift",
			What: "every difference is graded in the published vocabulary, names what diverged, and " +
				"withholds only actions you actually advertise"},
		{Name: "runDriftReadOnly", Suite: "RunDrift",
			What: "a comparison only reads — two in a row of an unchanged target agree"},
		{Name: "runDriftTenantAsserted", Suite: "RunDrift",
			What: "a comparison asserts the tenant before any egress, and refuses with none bound"},
		{Name: "runRefinerParses", Suite: "RunRefiner",
			What: "if you ship `refines:` rules, your reflexes.yaml loads in the closed vocabulary and " +
				"every rule is named under your kind (D300, D317)"},
		{Name: "runRefinerOwnsItsTypes", Suite: "RunRefiner",
			What: "every rule refines a type your actions return and writes a seiren type your schemas " +
				"declare — one type, one owner (D279, D299)"},
		{Name: "runPresetterParses", Suite: "RunPresetter",
			What: "if you suggest presets, your presets.yaml is a fragment a deployment can drop in as it " +
				"stands, every preset named under your kind (D327)"},
		{Name: "runPresetterHoldsItsClaims", Suite: "RunPresetter",
			What: "every preset names only your actions, and every `mirrors:` claim holds against your own " +
				"connector.Leveled grading — the rule boot applies (D327)"},
	}
}
