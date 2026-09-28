// Package konbini (コンビニ, "convenience store") is a library of conveniences
// that reflexes, agents, and operators call upon (D67).
//
// A CLASS, NOT A CONNECTOR. Originally scoped to warehouse dialects, the
// generalisation is that a Fullstory taxonomy explainer and a BigQuery dialect
// are the same KIND of thing: vendor knowledge that is expensive to rediscover
// and belongs in one place, so every consumer inherits it rather than
// reimplementing it. §4.6.2's projections are its first real member.
//
// P0 STOCKS ONE SHELF: the glossary. Sekizui uses deliberately unusual
// vocabulary — sekizui, anzen, konbini, enshin, kyuushin — and an operator
// meeting "anzen guard refused this action" in a log has nowhere to look. That
// is a real cost of the naming, so the naming carries its own remedy.
//
// Thin, and honestly so: a konbini that only sells one thing is still a konbini.
//
// DESIGN.md references: §4.6.2, §12.0 principle 4, D66, D67.
package konbini

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// Term is one entry.
type Term struct {
	Word     string
	Japanese string // kanji, where the word is Japanese
	Reading  string // romaji, where it differs from Word
	Means    string
	Because  string // why Sekizui uses this word rather than an English one
}

// Glossary returns every term Sekizui uses that an operator would not otherwise
// know.
//
// A FUNCTION, NOT A PACKAGE VARIABLE (§6 item 4). It allocates on each call and
// is called by humans at human frequency, so the cost is irrelevant and the
// alternative is package-level mutable state.
//
// **THIS SLICE IS THE SOURCE THE README RENDERS FROM (D220).** It had been one of
// THREE glossaries — this one, DESIGN §13, and the README's own table — and no
// two agreed on what the planes were called: D66 named them enshin and kyuushin
// in P0, and the two documents went on teaching "efferent" and "afferent" while
// the one list written to be the remedy held the Japanese. Acceptance step 33
// now renders the README's block from here and fails with the replacement text.
//
// SO THE ORDER IS PEDAGOGICAL RATHER THAN ALPHABETICAL, and it is free to be:
// Render sorts for the terminal, so declaration order costs `-glossary` nothing
// and is exactly what a reader meeting the vocabulary for the first time reads
// top to bottom. Sekizui, then its two planes, then the subsystems, then the
// governance nouns, then the event vocabulary.
//
// **Means IS WHAT IT IS; Because IS WHY THE WORD.** The split is what the field
// comments always said and what the entries had drifted away from — `kata` and
// `connector` carried four lines of reasoning in Means, which reads fine in a
// terminal and blows out a table cell. Nothing was lost: Render prints both.
func Glossary() []Term {
	return []Term{
		{
			Word: "sekizui", Japanese: "脊髄", Reading: "sekizui",
			Means:   "The spinal cord. The governed pathway every agent action travels.",
			Because: "A spinal cord carries signals both ways and reflexes act without the brain — which is the whole architecture in one word.",
		},
		{
			Word: "enshin", Japanese: "遠心", Reading: "enshin",
			Means:   "Centrifugal — outward. The command plane: caller → policy → driver → external system, and Sekizui's primary path.",
			Because: "\"Efferent\" is anatomical jargon most readers look up anyway, so the Japanese costs nothing and matches 脊髄.",
		},
		{
			Word: "kyuushin", Japanese: "求心", Reading: "kyuushin",
			Means:   "Centripetal — inward. The event plane: sources → translate → bus → consumers. Built in P3: pollers, durable cursors, translation.",
			Because: "The antonym pair to enshin. Written without a macron so it types and greps cleanly.",
		},
		{
			Word: "anzen", Japanese: "安全", Reading: "anzen",
			Means:   "Safety. The ceilings no grant can exceed, plus the rules that watch Sekizui's own health. Policy answers \"may you\"; anzen answers \"should anyone, ever\".",
			Because: "\"The defensive rule class whose actions may only touch Sekizui itself\" is a phrase, not a word. It earned a name.",
		},
		{
			Word: "shin", Japanese: "真", Reading: "shin",
			Means:   "Truth. The lens deciding what a given consumer actually receives — not whether it may, but in what shape.",
			Because: "Policy answers \"may you\" and anzen answers \"should anyone ever\". Neither answers \"in what shape\", and the information a body sends a hand is not what it sends an organ.",
		},
		{
			Word: "konbini", Japanese: "コンビニ", Reading: "konbini",
			Means:   "Convenience store. Vendor knowledge and helpers stocked once, so every consumer inherits them rather than reimplementing them.",
			Because: "Not a connector and not a service — a shelf of small useful things, stocked once so nobody reimplements them.",
		},
		{
			Word: "kata", Japanese: "型", Reading: "kata",
			Means: "The reference DRIVER a connector author fills in: no upstream, and every seam a real one must exercise. " +
				"The Go half of the connector blueprint, and what you find inside `hako` (D244).",
			Because: "A kata is the prescribed form practised until it is structural, which is what this " +
				"package is for: the shape a connector author fills in, run against the real " +
				"enforcement path rather than described in a document. It exercises statelessness, " +
				"pooled clients, the egress tenant assertion, all three credential-binding classes " +
				"and every implemented idempotency class. It was called `fake`, which was exact in " +
				"the test-double taxonomy and exact about the wrong thing — the package had become " +
				"the reference pattern while its own doc comment denied being one (D176).",
		},
		{
			Word: "hako", Japanese: "箱", Reading: "hako",
			Means: "The reference CONNECTOR: the blueprint, a complete governed skeleton, and the exercise that makes you build one. " +
				"What most people should look at first.",
			Because: "A box, because that is what D175 says a connector IS — the driver plus the targets, " +
				"limits, grants, lens, guard and schemas that make it safe to run, which is a packing " +
				"list. `kata` is the FORM of the Go half and is what the box contains; `hako` is the " +
				"box. The two words divide exactly where D175 divides driver from connector, a " +
				"distinction that was real in the decisions and nameless in the tree (D244). Both are " +
				"walking skeletons that grow with each phase, so a diff on either is the visible " +
				"signal that a contributor's obligations changed.",
		},
		{
			Word: "seiren", Japanese: "精錬", Reading: "seiren",
			Means: "Refining ore into metal. The third tier: silver refined by a `refines:` rule, carried beside a " +
				"result's rows as one typed message with the window it covers and what it could not build (D317).",
			Because: "The tiers are metallurgy — bronze is the vendor's raw response, silver is shaped by the " +
				"connector's schema, and 精錬 is the refining that turns it into something an agent can use " +
				"directly. It was \"gold\"; the maintainer renamed the tier and its message together (D317), and a " +
				"translation of \"refinement\" would have collided with the rule kind `refines:` and the key " +
				"`refinements:`.",
		},
		{
			Word:    "reflex",
			Means:   "A deterministic event-to-action rule that fires without a model in the loop. It is a principal, enforced identically to an agent.",
			Because: "English, deliberately. \"Reflex\" is precise and universal; renaming it 反射 would cost every reader a lookup and buy only symmetry.",
		},
		{
			Word:    "principal",
			Means:   "Anything that can act: an agent, a mesh, a reflex, a person. All are bounded by grants; none is a bypass.",
			Because: "A reflex is a principal like any other (D18) — the word is what makes that true rather than aspirational.",
		},
		{
			Word:    "grant",
			Means:   "What one principal may do: action x target x constraints. Deny by default, and a decision record names the grant that matched.",
			Because: "The unit an operator writes and reviews. A decision record names the grant that matched.",
		},
		{
			Word:    "target",
			Means:   "One specific external instance, with a tenant bound and a credential resolved. Named by callers, constructed only by the resolver.",
			Because: "Agents name a target; they never build one. That is what stops an agent influencing credential selection.",
		},
		{
			Word: "driver",
			Means: "The Go type implementing connector.Driver: stateless, credential-free, one instance " +
				"per process, shared across every tenant. The CODE half of a connector.",
			Because: "Named Driver rather than Connector because Go makes the package part of the " +
				"identifier, so connector.Connector stutters (GO-PRIMER §10). The naming is idiomatic " +
				"and it cost something: the two words were then used interchangeably in prose, which " +
				"is what let the definition-of-done cover half its subject without anybody noticing.",
		},
		{
			Word: "connector",
			Means: "The driver plus the governance that makes it safe to run: target specs and limits, " +
				"grants, the shin lens, the anzen ceiling and the payload schemas. The deliverable an operator installs.",
			Because: "A driver that works and a connector that is safe to run are different milestones, " +
				"and conflating them is how a system ships ungoverned. CONTRACTS §5 was called the " +
				"\"connector definition-of-done\" and every one of its thirty checkboxes was about " +
				"the driver — so a connector could tick all of them with no lens, no ceiling and " +
				"grants nobody reviewed (D167, D175).",
		},
		{
			Word:    "stage",
			Means:   "Where an event sits in the pipeline: raw, enriched, triaged, judged. A rule may only publish to a later stage than it consumes.",
			Because: "Monotonic stages make event loops impossible by construction rather than merely detectable.",
		},
		{
			Word:    "causation",
			Means:   "What triggered this — root, parent, depth, and producer. Distinct from the identity chain, which records who authorised it.",
			Because: "\"Who allowed this\" and \"what caused this\" are different questions, and an incident review needs both.",
		},
		{
			Word:    "shadow",
			Means:   "A rule that evaluates and records what it WOULD have done, without doing it. It is the default, so the dangerous option is never the easy one.",
			Because: "The staging mechanism most automation lacks. It is the default, so the dangerous option is never the easy one.",
		},
	}
}

// Explain returns one term, matched case-insensitively.
//
// Also matches the Japanese and the reading, since a log line says "anzen" and a
// document might say 安全.
func Explain(word string) (Term, bool) {
	needle := strings.ToLower(strings.TrimSpace(word))
	for _, t := range Glossary() {
		if strings.ToLower(t.Word) == needle ||
			t.Japanese == word ||
			strings.ToLower(t.Reading) == needle {
			return t, true
		}
	}
	return Term{}, false
}

// Render writes the glossary as plain text, for `sekizui -glossary` and the
// debug endpoint.
func Render() string {
	terms := Glossary()
	sort.Slice(terms, func(i, j int) bool { return terms[i].Word < terms[j].Word })

	var b strings.Builder
	b.WriteString("Sekizui vocabulary\n")
	b.WriteString("==================\n\n")
	b.WriteString("Words this system uses that you would not otherwise know,\n")
	b.WriteString("and why it uses them rather than the obvious English.\n\n")

	for _, t := range terms {
		head := t.Word
		if t.Japanese != "" {
			head = fmt.Sprintf("%s (%s)", t.Word, t.Japanese)
		}
		// utf8.RuneCountInString, NOT len(). len() counts BYTES, and 安全 is six
		// bytes for two characters — so a byte-length underline runs three
		// times too long under any non-ASCII term. Go strings are byte slices
		// and range yields runes; the two disagree exactly where this project's
		// vocabulary lives.
		fmt.Fprintf(&b, "%s\n%s\n", head, strings.Repeat("-", utf8.RuneCountInString(head)))
		fmt.Fprintf(&b, "  %s\n", t.Means)
		if t.Because != "" {
			fmt.Fprintf(&b, "  why: %s\n", t.Because)
		}
		b.WriteString("\n")
	}
	return b.String()
}
