package acceptance

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/internal/auditwal"
	"github.com/fullstorydev/sekizui/internal/census"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestMain writes the evidence report after every phase has run.
//
// IT CANNOT BE WRITTEN BY A PHASE. The report covers P0, P1 and P2, and those
// are three top-level tests appending to one audit log — so a report written at
// the end of the first one describes the log as it was a third of the way
// through. That is not a hypothetical: it is what the previous report did, for
// months, while its own footer said it was derived from the file.
//
// THE FAILURE DIRECTION IS DELIBERATE. A broken report fails the run even when
// every assertion passed, because `make acceptance` exists to produce this
// artefact and a green run that emitted a document nobody can trust has not
// done its job. It refuses to write a partial or mis-cited document rather than
// writing one and hoping somebody notices — D145's rule about failure
// directions, applied to evidence instead of to withdrawals.
func TestMain(m *testing.M) {
	// BEFORE ANY TEST RUNS, so a pre-existing log is recognised as one.
	evidence.begin()

	code := m.Run()

	if err := writeEvidenceReport(); err != nil {
		fmt.Fprintf(os.Stderr, "\nREFUSING TO WRITE THE ACCEPTANCE REPORT: %v\n\n"+
			"THE AUDIT LOG ITSELF IS INTACT AND IS THE AUTHORITY. What failed is one of the "+
			"three claims this document makes about it: that every step's citations point "+
			"at the lines it wrote (D227), that no row contradicts itself (D228, D231), or "+
			"that every declared field is populated by some row (D164). None of them is "+
			"worth publishing unchecked — a citation nobody can follow and a column nobody "+
			"writes both look complete.\n\n", err)
		if code == 0 {
			code = 1
		}
	}

	os.Exit(code)
}

// writeEvidenceReport renders the run as the document a human reads.
//
// A SECOND RENDERING OF THE SAME EVIDENCE, not a second source of truth. The
// JSONL log is the artefact a reviewer or a SIEM consumes; this is the one a
// person reads to see that a claim and its records are the same thing.
// Everything here is DERIVED from the records the run actually wrote — including
// which step wrote which line — because a report that could disagree with the
// log would be worse than no report.
func writeEvidenceReport() error {
	path := evidenceLogPath()
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// NOTHING RAN. `go test -run TestP1StepsAreWellFormed` with the
			// environment set is a legitimate thing to do and owes no report.
			return nil
		}
		// ANY OTHER stat FAILURE IS REPORTED. A permission error on the log is
		// not "no run happened", and swallowing it would produce the silence
		// this whole path exists to avoid. `nilerr` asked the question and was
		// right to.
		return err
	}

	if !evidence.observedWholeLog() {
		// A TARGETED RUN APPENDING TO AN EARLIER RUN'S LOG. It cannot say which
		// step wrote which line, and the previous report is still true of the
		// file it describes, so the honest act is to leave both alone and say so.
		fmt.Fprintf(os.Stderr, "\nno acceptance report written: %s already held records "+
			"before this run started, so this process cannot say which step wrote which "+
			"line. `make acceptance` removes the log first.\n\n", logName(path))
		return nil
	}

	records, err := parseLog(path)
	if err != nil {
		return err
	}
	if err := evidence.audit(len(records)); err != nil {
		return err
	}
	if evidence.stepsRan() == 0 {
		fmt.Fprintf(os.Stderr, "\nno acceptance report written: no acceptance step ran, so "+
			"there is nothing to cite. %s holds %d record(s) written by other tests.\n\n",
			logName(path), len(records))
		return nil
	}
	if err := assertRefusalsAreRecordedAsRefusals(records); err != nil {
		return err
	}
	// SKIPPED ON A PARTIAL RUN, and the report is still written. The citations
	// are valid for whatever ran; the census is a claim about the WHOLE corpus
	// and a subset of it says nothing (D235).
	// **THE POPULATION CENSUS (D164), OVER THE FINISHED CORPUS.** It asks the one
	// question a static check cannot: does any ROW carry this field. D149 is the
	// counter-example that settled the instrument — `Document.Version` had
	// writers, was assigned, was logged at boot, and never reached a record.
	//
	// Here rather than in a step for D227's reason: while P2 step 24 runs, two
	// thirds of the corpus is unwritten. That step proves the census MECHANISM
	// by sabotage; this is the census.
	if evidence.wholeSuiteRan() {
		if err := census.Of(records, census.Ledgered()).Err(); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(os.Stderr, "\nthe population census was SKIPPED: not every step ran, so "+
			"an unpopulated field means no step touched it rather than that nothing writes "+
			"it. `make acceptance` runs the whole suite.\n\n")
	}

	doc, err := renderReport(records, evidence.ranges(len(records)),
		auditwal.VerifyChain(records), evidence.scrape, logName(path))
	if err != nil {
		return err
	}
	return os.WriteFile(strings.TrimSuffix(path, ".jsonl")+".md", []byte(doc), 0o644)
}

func logName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func parseLog(path string) ([]*sekizuiv1.Decision, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*sekizuiv1.Decision
	for i, line := range splitLines(string(data)) {
		var d sekizuiv1.Decision
		if err := protojson.Unmarshal([]byte(line), &d); err != nil {
			return nil, fmt.Errorf("%s line %d does not parse as a Decision: %w", path, i+1, err)
		}
		out = append(out, &d)
	}
	return out, nil
}

//nolint:gocyclo // one linear document; splitting it would scatter the layout
func renderReport(records []*sekizuiv1.Decision, ranges []evidenceRange,
	chainErr error, scrape, log string) (string, error) {

	var b strings.Builder

	b.WriteString("# Sekizui — acceptance run\n\n")
	b.WriteString("One scripted pass through every capability every phase so far delivers, and the audit\n")
	b.WriteString("log it produced. A phase is not done until this run covers it.\n\n")
	fmt.Fprintf(&b, "**Every step below cites the lines of `%s` it wrote.** The citation is\n", log)
	b.WriteString("derived from the log's own length at each step boundary, so a step's claim and\n")
	b.WriteString("the records that back it are joined by the artefact rather than by the\n")
	b.WriteString("narration — which is what lets you see when each control fired and what it did.\n\n")

	// --- the headline ---------------------------------------------------------
	verdicts := map[string]int{}
	phases := map[string]int{}
	ids := map[string]bool{}
	targets := map[string]int{}
	for _, r := range records {
		verdicts[trimEnum(r.GetVerdict().String(), "VERDICT_")]++
		phases[trimEnum(r.GetPhase().String(), "PHASE_")]++
		ids[r.GetId()] = true
		if t := r.GetTargetRef(); t != "" {
			targets[t]++
		}
	}

	chain := "verified over every record"
	if chainErr != nil {
		chain = "**FAILED** — " + chainErr.Error()
	}

	var built, skipped, failed, silent, cited int
	for _, r := range ranges {
		switch {
		case r.step.failed:
			failed++
		case r.step.skipped:
			skipped++
		default:
			built++
		}
		if r.count == 0 {
			silent++
		}
		cited += r.count
	}
	lead := 0
	if len(ranges) > 0 {
		lead = ranges[0].step.at
	}

	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Steps run | %d — %d executed, %d skipped", len(ranges), built, skipped)
	if failed > 0 {
		fmt.Fprintf(&b, ", **%d FAILED**", failed)
	}
	b.WriteString(" |\n")
	fmt.Fprintf(&b, "| Audit records | %d |\n", len(records))
	fmt.Fprintf(&b, "| Records cited by a step | %d of %d |\n", cited, len(records))
	fmt.Fprintf(&b, "| Steps that wrote no record | %d |\n", silent)
	fmt.Fprintf(&b, "| Distinct decisions | %d |\n", len(ids))
	fmt.Fprintf(&b, "| Targets touched | %d |\n", len(targets))
	fmt.Fprintf(&b, "| Hash chain | %s |\n", chain)
	fmt.Fprintf(&b, "| Transport | mTLS gRPC, TLS 1.3, CA-signed client certificates |\n\n")

	if lead > 0 {
		fmt.Fprintf(&b, "> %d record(s) were written before the first step opened, at lines 1-%d. "+
			"They belong to no step and are named here rather than dropped.\n\n", lead, lead)
	}

	b.WriteString("**`at` IS WHEN THE DECISION WAS MADE, NOT WHEN THE CALL FINISHED.** A two-phase\n")
	b.WriteString("pair shares one timestamp: `Recorder.Outcome` clones the intent row so the two\n")
	b.WriteString("cannot disagree about what was attempted, and only the duration differs — which\n")
	b.WriteString("`Effect.latency_ms` carries. So an outcome line can show an earlier `at` than an\n")
	b.WriteString("intent line above it, and the log is not out of order: FILE ORDER is causal, and\n")
	b.WriteString("the hash chain is what fixes it (D78).\n\n")
	b.WriteString("**A step that wrote no record is not a gap.** Most of them assert about boot, the\n")
	b.WriteString("import graph or the AST, where the whole point is that nothing runs — a refused\n")
	b.WriteString("boot has no audit log to leave. The count is here so the absence is visible and\n")
	b.WriteString("countable rather than inferred from a missing citation.\n\n")

	// --- the evidence, phase by phase ----------------------------------------
	//
	// IN THE ORDER THEY RAN, which is not the order they are numbered. The step
	// tables are grouped by subject rather than sorted, so P1 runs 68 before 65,
	// and the citations are contiguous down the page BECAUSE this follows
	// execution rather than numbering. Sorting by step number would leave a
	// reader wondering why line 118 comes before line 126.
	for _, phase := range phaseOrder(ranges) {
		fmt.Fprintf(&b, "## %s — in the order the steps ran\n\n", phase)
		for _, r := range ranges {
			if r.step.phase != phase {
				continue
			}
			renderStep(&b, r, records, log)
		}
	}

	// --- verdicts -------------------------------------------------------------
	b.WriteString("## Verdicts recorded\n\n")
	b.WriteString("| Verdict | Records |\n|---|---|\n")
	for _, v := range sortedByKey(verdicts) {
		fmt.Fprintf(&b, "| `%s` | %d |\n", v, verdicts[v])
	}
	b.WriteString("\nEvery verdict the code can produce appears here, because a verdict that never\n")
	b.WriteString("shows up is one nobody proved (`assertEveryReachableVerdictAppears`). There is\n")
	b.WriteString("no `UNSPECIFIED` row and there cannot be one: a Decision with no verdict is\n")
	b.WriteString("invisible to every query that filters on one, and a row with `refused_by` set may\n")
	b.WriteString("not read `ALLOW` — that would say a command which never ran was permitted. Both\n")
	b.WriteString("are checked over this whole file by `assertRefusalsAreRecordedAsRefusals`, which\n")
	b.WriteString("refuses to write this document rather than describing a log that contradicts\n")
	b.WriteString("itself (D228).\n\n")

	fmt.Fprintf(&b, "Two-phase recording (§5.2.2): ")
	parts := []string{}
	for _, p := range sortedByKey(phases) {
		parts = append(parts, fmt.Sprintf("%d %s", phases[p], strings.ToLower(p)))
	}
	fmt.Fprintf(&b, "%s. Intent is written before the side effect and outcome after, so a\n", strings.Join(parts, ", "))
	b.WriteString("crash mid-call leaves a record of an action that may well have happened.\n\n")

	// --- a real record --------------------------------------------------------
	if len(records) > 0 {
		b.WriteString("## One record, in full\n\n")
		fmt.Fprintf(&b, "Each row is independently readable years later with no joins (D39). This is\n")
		fmt.Fprintf(&b, "`%s:1`, the shape every citation above points into.\n\n", log)
		b.WriteString("```json\n")
		b.WriteString(renderRecord(records[0]))
		b.WriteString("\n```\n\n")
	}

	// --- every refusal, in one place -----------------------------------------
	b.WriteString("## Every refusal in the run\n\n")
	b.WriteString("The highest-value rows in the log (§5.4) — a denial that records *why* is what\n")
	b.WriteString("makes the system reviewable rather than merely restrictive. Each is shown at its\n")
	b.WriteString("own step above; this is the index.\n\n")
	b.WriteString("| line | action | target | principal | refused by | reason |\n|---|---|---|---|---|---|\n")
	for i, r := range records {
		if r.GetVerdict() == sekizuiv1.Verdict_VERDICT_ALLOW || r.GetReason() == "" {
			continue
		}
		fmt.Fprintf(&b, "| %d | `%s` | `%s` | `%s` | %s | %s |\n",
			i+1, r.GetAction(), orDash(r.GetTargetRef()),
			r.GetIdentity().GetSubject().GetPrincipal(),
			orDash(trimEnum(r.GetRefusedBy().String(), "REFUSED_BY_")),
			cell(firstSentence(r.GetReason())))
	}
	b.WriteString("\n")

	if scrape != "" {
		b.WriteString("## Metrics from the P0 pass\n\n")
		b.WriteString("An operator's dashboard and the audit log must partition the run identically.\n")
		b.WriteString("P0's, and labelled as P0's: every P1 and P2 step builds its own gateway with its\n")
		b.WriteString("own registry, so there is no single scrape for the whole file and a section\n")
		b.WriteString("claiming one would be quietly untrue about every other step.\n\n")
		b.WriteString("```\n")
		b.WriteString(strings.TrimSpace(scrape))
		b.WriteString("\n```\n\n")
	}

	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "Generated by `make acceptance`. The machine-readable log is `%s`;\n", log)
	fmt.Fprintf(&b, "this document is derived from it, never narrated independently.\n")

	return b.String(), nil
}

// assertRefusalsAreRecordedAsRefusals is D228's guard at the ARTEFACT level.
//
// The taxonomy guard (`fault.TestEveryDeliberateKindHasAVerdict`) and the funnel
// guard (`gateway.TestEveryDeliberateKindHasAllThreeViews`) both check the code.
// This checks the LOG THIS RUN ACTUALLY WROTE, which is the only one of the
// three that would have caught the original defect: it was found by counting
// verdicts across `acceptance.jsonl`, months after both other guards existed and
// passed. A property of every row is cheap to state here and expensive to notice
// anywhere else.
//
// IT LIVES ON THE REPORT'S PATH, NOT IN A STEP, because no step can see the
// whole file — P0's whole-log assertions run before P1 and P2 have written
// anything, and the three ALLOW-stamped refusals were P1's.
func assertRefusalsAreRecordedAsRefusals(records []*sekizuiv1.Decision) error {
	var bad []string
	for i, r := range records {
		switch {
		case r.GetMatchedRule() == "":
			// **§5.4's SELF-CONTAINMENT, CHECKED OVER THE WHOLE FILE.**
			// `assertEveryRecordIsSelfContained` has required this since P0 and
			// runs inside TestP0Acceptance, so it sees 117 of 527 records — and
			// the row it could not see, D215's request-bound refusal, carried an
			// empty `matched_rule` for two phases. **The same scope gap that hid
			// D228's four rows, in a second field.** A record that cannot say
			// what decided is a log line, not an audit record.
			bad = append(bad, fmt.Sprintf("line %d: %s on %s does not say WHAT DECIDED "+
				"(matched_rule is empty), so the row cannot explain its own outcome",
				i+1, r.GetAction(), orDash(r.GetTargetRef())))
		case r.GetVerdict() == sekizuiv1.Verdict_VERDICT_UNSPECIFIED:
			bad = append(bad, fmt.Sprintf("line %d: %s on %s carries NO VERDICT, so it is "+
				"invisible to every query that filters on one", i+1, r.GetAction(), orDash(r.GetTargetRef())))
		case r.GetRefusedBy() != sekizuiv1.RefusedBy_REFUSED_BY_UNSPECIFIED &&
			r.GetVerdict() == sekizuiv1.Verdict_VERDICT_ALLOW:
			bad = append(bad, fmt.Sprintf("line %d: %s on %s was refused by %s and is recorded "+
				"as VERDICT_ALLOW with matched_rule %q — the log says a command that never ran "+
				"was permitted, and names the grant that permitted it",
				i+1, r.GetAction(), orDash(r.GetTargetRef()),
				trimEnum(r.GetRefusedBy().String(), "REFUSED_BY_"), r.GetMatchedRule()))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%d record(s) cannot be read on their own (D228, D231):\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
	return nil
}

// renderStep is one step and the records it produced.
func renderStep(b *strings.Builder, r evidenceRange, records []*sekizuiv1.Decision, log string) {
	fmt.Fprintf(b, "### %s step %d — %s\n\n", r.step.phase, r.step.n, r.step.what)

	// The provenance line: what the step discharges, and where its evidence is.
	var prov []string
	if len(r.step.decides) > 0 {
		prov = append(prov, "proves "+strings.Join(r.step.decides, ", "))
	}
	if len(r.step.covers) > 0 {
		prov = append(prov, "criterion "+joinInts(r.step.covers))
	}
	switch {
	case r.count == 1:
		prov = append(prov, fmt.Sprintf("`%s:%d` — 1 record", log, r.from))
	case r.count > 1:
		prov = append(prov, fmt.Sprintf("`%s:%d-%d` — %d records", log, r.from, r.to, r.count))
	default:
		prov = append(prov, "no audit records")
	}
	switch {
	case r.step.failed:
		prov = append(prov, "**FAILED**")
	case r.step.skipped:
		prov = append(prov, "*skipped*")
	}
	fmt.Fprintf(b, "%s\n\n", strings.Join(prov, " · "))

	if r.step.claim != "" {
		fmt.Fprintf(b, "> %s\n\n", r.step.claim)
	}
	for _, d := range r.step.details {
		fmt.Fprintf(b, "- %s\n", d)
	}
	if len(r.step.details) > 0 {
		b.WriteString("\n")
	}

	if r.count == 0 {
		return
	}

	// THE EXAMPLE. Capped, because a step that puts 48 commands in flight would
	// otherwise bury every other step in the document — and its own `detail`
	// lines already state the aggregate the records are evidence for.
	const maxRows = 8
	rows := records[r.from-1 : r.to]
	shown := rows
	if len(shown) > maxRows {
		shown = shown[:maxRows]
	}

	b.WriteString("| line | at | caller → subject | action | target | verdict | refused by |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for i, rec := range shown {
		fmt.Fprintf(b, "| %d | %s | %s | `%s` | `%s` | %s | %s |\n",
			r.from+i,
			rec.GetAt().AsTime().Format(time.RFC3339),
			actor(rec),
			rec.GetAction(),
			orDash(rec.GetTargetRef()),
			orDash(trimEnum(rec.GetVerdict().String(), "VERDICT_")),
			orDash(trimEnum(rec.GetRefusedBy().String(), "REFUSED_BY_")))
	}
	if len(rows) > len(shown) {
		fmt.Fprintf(b, "\n… and %d more, at lines %d-%d.\n", len(rows)-len(shown),
			r.from+len(shown), r.to)
	}
	b.WriteString("\n")

	// The reasons, which are the part a table cell cannot hold.
	const maxReasons = 3
	quoted := 0
	for i, rec := range rows {
		if rec.GetVerdict() == sekizuiv1.Verdict_VERDICT_ALLOW || rec.GetReason() == "" {
			continue
		}
		if quoted == maxReasons {
			fmt.Fprintf(b, "…and further refusals in the same range.\n\n")
			break
		}
		fmt.Fprintf(b, "> **line %d** — %s\n\n", r.from+i, firstSentence(rec.GetReason()))
		quoted++
	}
}

// actor renders who acted, and NAMES THE RULE when a reflex did.
//
// D96's reason: three rules share `reflex:friction` in this configuration, so
// the principal alone cannot answer "why did this ticket get created".
func actor(r *sekizuiv1.Decision) string {
	caller := r.GetIdentity().GetCaller().GetPrincipal()
	subject := r.GetIdentity().GetSubject().GetPrincipal()
	if name := r.GetReflexName(); name != "" {
		subject += "#" + name
	}
	if caller == subject || caller == "" {
		return "`" + orDash(subject) + "`"
	}
	return "`" + caller + "` → `" + subject + "`"
}

func phaseOrder(ranges []evidenceRange) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range ranges {
		if !seen[r.step.phase] {
			seen[r.step.phase] = true
			out = append(out, r.step.phase)
		}
	}
	return out
}

// cell makes a string safe to put in a Markdown table cell.
func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

func trimEnum(s, prefix string) string {
	s = strings.TrimPrefix(s, prefix)
	if s == "UNSPECIFIED" {
		return ""
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// firstSentence keeps a refusal readable in a bulleted list. The reasons in this
// system are deliberately long — they explain the rule and the rationale — and
// the full text is in the JSONL for anyone who wants it.
func firstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if head, _, found := strings.Cut(s, ". "); found {
		return head + "."
	}
	const limit = 240
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

func sortedByKey(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func renderRecord(r *sekizuiv1.Decision) string {
	return strings.Join([]string{
		"{",
		fmt.Sprintf("  %-18s %q,", `"id":`, r.GetId()),
		fmt.Sprintf("  %-18s %q,", `"phase":`, r.GetPhase().String()),
		fmt.Sprintf("  %-18s %q,", `"at":`, r.GetAt().AsTime().Format(time.RFC3339)),
		fmt.Sprintf("  %-18s %q,", `"caller":`, r.GetIdentity().GetCaller().GetPrincipal()),
		fmt.Sprintf("  %-18s %q,", `"subject":`, r.GetIdentity().GetSubject().GetPrincipal()),
		fmt.Sprintf("  %-18s %v,", `"chain":`, quoteAll(r.GetIdentity().GetChain())),
		fmt.Sprintf("  %-18s %q,", `"action":`, r.GetAction()),
		fmt.Sprintf("  %-18s %q,", `"target_ref":`, r.GetTargetRef()),
		fmt.Sprintf("  %-18s %q,", `"verdict":`, r.GetVerdict().String()),
		fmt.Sprintf("  %-18s %q", `"matched_rule":`, r.GetMatchedRule()),
		"}",
	}, "\n")
}

func quoteAll(in []string) string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(out, ", ") + "]"
}
