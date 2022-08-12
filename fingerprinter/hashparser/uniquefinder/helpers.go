package uniquefinder

import "sort"

func getMostUniqueAcross(uniques map[string]uniqueness) string {
	// iterate over uniques alphabetically to always run same order
	mk := make([]string, len(uniques))
	i := 0
	for k := range uniques {
		mk[i] = k
		i++
	}

	// when requesting randomly, first try those files with many hashes
	// to get the biggest bang for the buck when requesting random files
	sort.Slice(mk, func(i, j int) bool {
		return mk[i] < mk[j]
	})

	uq := uniqueness{}
	for _, k := range mk {
		unique := uniques[k]

		// first value
		if uq.u == 0 {
			uq = unique
			continue
		}

		// lowest value is best
		if uq.u > unique.u {
			uq = unique
		}
	}

	return uq.file
}

func sortByUniqueness(uniques []uniqueness) []uniqueness {
	sort.Slice(uniques, func(i, j int) bool {

		// if uniqueness is same, sort alphabetically to have same order on every run
		if uniques[i].u == uniques[j].u {
			return uniques[i].file < uniques[j].file
		}

		// MUST be sorted from lowest to highest
		return uniques[i].u < uniques[j].u
	})

	return uniques
}
