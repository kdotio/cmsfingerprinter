package uniquefinder

import (
	"log"

	"cms-fingerprinter/helpers"
	"cms-fingerprinter/structs"
)

type uniqueness struct {
	u    int    // sharedness level, low equals more unique
	file string // filepath
}

type UniqueFinder struct {
	// map[rev][]uniqueFiles
	// i.e. 2.8.1 [{1 readme.html} {7 wp-includes/js/autosave.js}
	tagsUniqueFiles map[string][]uniqueness
}

// most unique file is defined as
// a file most likely to prove or disprove one or multiple tags from a list
func (u UniqueFinder) GetMostUniqueFile(tags []string, priorFiles []string) string {

	// TODO: later on, this should return a file that can split remaining tags 50/50
	// depending on result. currently tags are decreased by at least +1
	// and the rest is luck

	// if initial hash returns 0 returns, there are no tags to decrement yet
	// in that case just get any random file for next request
	// which has not been requested yet
	if len(tags) == 0 {
		for _, unqe := range u.tagsUniqueFiles {
			for _, u := range unqe {
				if !helpers.Contains(priorFiles, u.file) {
					return u.file
				}
			}
		}
	}

	return u.getMostUniqueFile(tags, priorFiles)
}

func (u UniqueFinder) getMostUniqueFile(tags []string, priorFiles []string) string {
	// keep one uniqueness entry per tag
	uniques := map[string]uniqueness{}

tagloop:
	for _, tag := range tags {

		unqe, ok := u.tagsUniqueFiles[tag]
		if !ok {
			log.Println("No entry for tag", tag)
			continue
		}

		// unqe MUST be pre-sorted with lowest uniqueness first
		for _, u := range unqe {
			// unique entry has to be one not already requested

			if !helpers.Contains(priorFiles, u.file) {

				if _, ok := uniques[tag]; ok {
					log.Println("ERROR: Tag exists already", tag)
					continue tagloop
				}

				uniques[tag] = u
				continue tagloop
			}
		}
	}

	return getMostUniqueAcross(uniques)
}

func GetTagCounts(hashes map[string]structs.Filehash) UniqueFinder {
	return UniqueFinder{tagsUniqueFiles: parse(hashes)}
}

func parse(hashes map[string]structs.Filehash) map[string][]uniqueness {
	filecounts := map[string]map[string]int{}

	for file, hashmap := range hashes {

		count := map[string]int{}
		// key = "0027d921c041fc9d082d52b025c94e5f"
		// tags = ["2.0.7", "2.0.6"]
		for _, tags := range hashmap {

			// for each tags array, calculate uniqueness, lowest (1) value being best
			// len == 1 means, the filehash is unique to a single revision, which is the best possible outcome
			length := len(tags)

			// for each of the tag inside, append the uniqueness factor
			for _, tag := range tags {
				if _, ok := count[tag]; ok {
					log.Println("ERROR: Tag not unique:", tag, file)
				}

				count[tag] = length
			}
		}

		if _, ok := filecounts[file]; ok {
			log.Println("ERROR: File not unique:", file)
		}

		filecounts[file] = count
	}

	// create map of tags with sorted slice of most unique file
	// this allows quick lookup of most unique file per tag
	// map[tag][]uniqueness
	tcounts := map[string][]uniqueness{}

	for file, fcounts := range filecounts { // file - dashicons.css
		for tag, uniq := range fcounts { // key - tag

			if _, ok := tcounts[tag]; !ok {
				// create initial slice
				tcounts[tag] = []uniqueness{{u: uniq, file: file}}
				continue
			}

			tcounts[tag] = append(tcounts[tag], uniqueness{u: uniq, file: file})
		}
	}

	for tag := range tcounts {
		tcounts[tag] = sortByUniqueness(tcounts[tag])
	}

	return tcounts
}
