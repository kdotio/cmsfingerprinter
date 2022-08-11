package fingerprinter

import (
	"log"
	"sort"

	"cms-fingerprinter/helpers"
	"cms-fingerprinter/structs"
)

type filecount map[string]int

type uniqueness struct {
	u    int    // sharedness level
	file string // filepath
}

type tagscount map[string][]uniqueness

// most unique file is defined as
// a file most likely to prove or disprove one or multiple tags from a list
func (t tagscount) getMostUniqueFile(tags []string, priorFiles []string) string {

	// TODO: later on, this should return a file that can split remaining tags 50/50
	// depending on result. currently tags are decreased by at least +1
	// and the rest is luck

	// if initial hash returns 0 returns, there are no tags to decrement yet
	// in that case just get any random file for next request
	// which has not been requested yet
	if len(tags) == 0 {
		for _, unqe := range t {
			for _, u := range unqe {
				if !helpers.Contains(priorFiles, u.file) {
					return u.file
				}
			}
		}
	}

	// keep one uniqueness entry per tag
	uniques := map[string]uniqueness{}

tagloop:
	for _, tag := range tags {

		unqe, ok := t[tag]
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

func GetTagCounts(hashes map[string]structs.Filehash) tagscount {
	filecounts := hashesToCounts(hashes)
	return filesToTagsCount(filecounts)
}

func filesToTagsCount(filecounts map[string]filecount) tagscount {
	tcounts := tagscount{}

	// file - dashicons.css
	for file, fcounts := range filecounts {

		// key - tag
		for tag, uniq := range fcounts {

			if _, ok := tcounts[tag]; !ok {
				tcounts[tag] = []uniqueness{uniqueness{u: uniq, file: file}}
				continue
			}

			tcounts[tag] = append(tcounts[tag], uniqueness{u: uniq, file: file})
		}
	}

	for tag := range tcounts {
		sort.Slice(tcounts[tag], func(i, j int) bool {

			// if uniqueness is same, sort alphabetically to have same order on every run
			if tcounts[tag][i].u == tcounts[tag][j].u {
				return tcounts[tag][i].file < tcounts[tag][j].file
			}

			return tcounts[tag][i].u < tcounts[tag][j].u // TODO: make sure sort is from lowest to highest
		})
	}

	return tcounts
}

func hashesToCounts(hashes map[string]structs.Filehash) map[string]filecount {
	filecounts := map[string]filecount{}

	for file, hashmap := range hashes {

		// add same file entry to filecounts
		// hashmap - type Filehash map[string][]string // map[hash][versions]

		count := filecount{}

		// key = "0027d921c041fc9d082d52b025c94e5f"
		// tags = ["2.0.7", "2.0.6"]
		for _, tags := range hashmap {

			// for each tags array, calculate uniqueness, lowest (1) value being best
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

	return filecounts
}
