package limiter

import "sort"

// sortByUsage orders principals worst-first, then by name.
//
// THE TIE-BREAK IS NOT DECORATION. Go randomises map iteration, so equal usage
// would reorder between calls — and this list reaches an audit record and an
// anzen signal, where a set that reshuffles is a set nobody can diff.
func sortByUsage(principals []string, used map[string]float64) {
	sort.Slice(principals, func(i, j int) bool {
		if used[principals[i]] != used[principals[j]] {
			return used[principals[i]] > used[principals[j]]
		}
		return principals[i] < principals[j]
	})
}
