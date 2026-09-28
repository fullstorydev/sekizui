package konbini

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestEveryTermIsExplained. A glossary entry with no meaning is worse than no
// entry: it looks like documentation and answers nothing.
func TestEveryTermIsExplained(t *testing.T) {
	terms := Glossary()
	if len(terms) < 10 {
		t.Fatalf("%d terms; the vocabulary is larger than that", len(terms))
	}

	seen := map[string]bool{}
	for _, term := range terms {
		if term.Word == "" || term.Means == "" {
			t.Errorf("term %+v has no word or no meaning", term)
		}
		if seen[term.Word] {
			t.Errorf("%q appears twice", term.Word)
		}
		seen[term.Word] = true

		// The "why" is the part that stops the naming looking arbitrary.
		if term.Because == "" {
			t.Errorf("%q has no rationale; an unusual word without a reason reads as affectation", term.Word)
		}
	}
}

// TestTheWordsWeActuallyUseAreExplained pins the ones that appear in logs and
// config, where an operator meets them with nowhere to look.
func TestTheWordsWeActuallyUseAreExplained(t *testing.T) {
	for _, word := range []string{
		"sekizui", "anzen", "shin", "konbini", "enshin", "kyuushin", "seiren",
		"reflex", "grant", "principal", "target", "stage", "causation", "shadow",
	} {
		if _, ok := Explain(word); !ok {
			t.Errorf("%q appears in output but is not in the glossary", word)
		}
	}
}

func TestExplainMatchesJapaneseAndCase(t *testing.T) {
	for _, q := range []string{"anzen", "ANZEN", " Anzen ", "安全"} {
		term, ok := Explain(q)
		if !ok {
			t.Errorf("Explain(%q) found nothing", q)
			continue
		}
		if term.Word != "anzen" {
			t.Errorf("Explain(%q) = %q", q, term.Word)
		}
	}
	if _, ok := Explain("nonsense"); ok {
		t.Error("Explain invented a term")
	}
}

// TestUnderlinesMatchVisibleWidth is the byte-vs-rune trap.
//
// len("安全") is 6; the term is 2 characters wide. A byte-length underline runs
// three times too long under exactly the vocabulary this project invented.
func TestUnderlinesMatchVisibleWidth(t *testing.T) {
	lines := strings.Split(Render(), "\n")

	for i, line := range lines {
		if !strings.HasPrefix(line, "---") || i == 0 {
			continue
		}
		head := lines[i-1]
		if strings.HasPrefix(head, "===") || head == "" {
			continue
		}
		if want, got := utf8.RuneCountInString(head), utf8.RuneCountInString(line); want != got {
			t.Errorf("underline for %q is %d wide, heading is %d — len() counts bytes, "+
				"and this vocabulary is not ASCII", head, got, want)
		}
	}
}
