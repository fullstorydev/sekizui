package census

// Ledgered names the `Decision` field paths no record in the acceptance corpus
// populates, each with the reason it is legitimately absent.
//
// **AN ENTRY REPORTS A GAP AND DOES NOT CLOSE ONE**, which is the rule D53's
// init ledger arrived at the hard way: its entries said a subsystem was
// unimplemented and stayed after two of them landed, so every boot reported
// `implemented=5/12` while the code was in the same binary. `Result.Stale`
// closes that here — a ledgered path the corpus starts carrying FAILS the
// census, so an entry cannot outlive its reason in silence.
//
// **THE BAR FOR AN ENTRY IS A SENTENCE, NOT A SHRUG.** Three of the five the
// census found on its first run were fixed by extending the corpus instead,
// because "no step drives this" is a gap in the evidence rather than a property
// of the field.
//
//nolint:gochecknoglobals // immutable table, read once
var ledgered = map[string]string{
	// A BOOL, SO `false` IS INDISTINGUISHABLE FROM UNSET, and false is the
	// honest value for every provider the corpus uses. Only `ambient://`
	// declares audited reads — the cloud logs every mint (§4.7.2) — and an
	// ambient credential cannot be exercised here without a cloud account
	// (D156). Populating it would need a target whose credential the platform
	// mints, which is P4's ground.
	"credential_posture.audited_reads": "only ambient:// declares audited reads and no " +
		"ambient-credentialled target can run without a cloud account (D156)",

	// CALLS STILL RUNNING WHEN THE DRAIN BUDGET EXPIRED. Zero in a healthy run
	// BY DESIGN, and engineering a corpus case would mean a deliberately
	// unkillable call outliving `revocationDrainBudget` — a 30-second step
	// whose only assertion is that a counter is non-zero. The counter is
	// covered by `internal/pool`'s own tests, where the budget is injectable.
	"revocation.stragglers": "zero in a healthy run; forcing one means a 30s step to " +
		"assert a counter internal/pool already tests with an injectable budget",
}

// Ledgered returns the table.
//
// A FUNCTION RATHER THAN THE MAP, so no caller can add an entry at runtime —
// the same reason `ledger.Planned()` and `verb.Names()` are functions.
func Ledgered() map[string]string {
	out := make(map[string]string, len(ledgered))
	for k, v := range ledgered {
		out[k] = v
	}
	return out
}
