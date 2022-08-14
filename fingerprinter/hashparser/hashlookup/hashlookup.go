package hashlookup

import (
	"fmt"
	"log"

	"cmsfingerprinter/structs"
)

type filetags map[string]string

type HashLookup struct {
	filesTagsHashes map[string]filetags
}

// New turns
// map[file]map[hashes][revs]
// into
// map[file]map[rev]hash
// allowing quick lookup of hash for specific file in specific revision.
func New(hashes map[string]structs.Filehash) HashLookup {
	filemap := map[string]filetags{}

	for file, hashmap := range hashes {

		// for one single file
		ftag := filetags{}

		// key = "0027d921c041fc9d082d52b025c94e5f"
		// tags = ["2.0.7", "2.0.6"]
		for hash, tags := range hashmap {

			for _, tag := range tags {
				// per tag, add hash as entry to map
				if _, ok := ftag[tag]; ok {
					log.Println("ERROR: entry already exists for tag:", tag, hash, file)
				}

				ftag[tag] = hash
			}
		}

		filemap[file] = ftag
	}

	return HashLookup{filesTagsHashes: filemap}
}

func (h *HashLookup) DoTagsShareHash(file string, tags []string) (bool, error) {
	if len(tags) == 1 {
		log.Println("only one tag left:", tags[0])
		return false, nil
	}

	filehashes, ok := h.filesTagsHashes[file]
	if !ok {
		return false, fmt.Errorf("ERROR: no entry for file: %s", file)
	}

	//		"readme.html": {
	//			"4.1.32": "0027d921c041fc9d082d52b025c94e5f",
	//			"4.1.31": "0027d921c041fc9d082d52b025c94e5f",
	//			"3.4": "01189c4abc9f8845de357ab736598039",

	foundhashes := map[string]struct{}{}

	for _, tag := range tags {
		hash, ok := filehashes[tag]
		if !ok {

			// this means the file does not exist in the specified revision
			// log.Println("ERROR: no hash for tag", tag, file)
			continue
		}

		foundhashes[hash] = struct{}{}
	}

	if len(foundhashes) == 0 {
		return false, fmt.Errorf("found zero hashes: %s", tags)
	}

	if len(foundhashes) == 1 {
		return true, nil
	}

	return false, nil
}
