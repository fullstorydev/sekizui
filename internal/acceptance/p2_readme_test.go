package acceptance

import (
	"strconv"
	"strings"
	"testing"
)

// PUBLIC EXPORT: this step checks the maintainers' internal design record, which is not published with the source; it runs in the maintainers' tree.

func step33TheReadmeCannotDriftFromItsSources(t *testing.T) {
	t.Skip("this step checks the maintainers' internal design record, which is not published with the source; it runs in the maintainers' tree")
}

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}
