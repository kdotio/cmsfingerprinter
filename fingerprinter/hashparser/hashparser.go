package hashparser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"cmsfingerprinter/fingerprinter/hashparser/hashlookup"
	"cmsfingerprinter/fingerprinter/hashparser/uniquefinder"
	"cmsfingerprinter/helpers"
	"cmsfingerprinter/structs"
)

type HashParser struct {
	hashes  map[string]structs.Filehash // all files hashes
	files   []string                    // file paths in alphabetical order
	uniques uniquefinder.UniqueFinder   // used for quick lookup of next-to-be http get
	hlookup hashlookup.HashLookup

	// options
	PreferFilesInRoot   bool
	ExcludedFileMatcher []string
	IncludeOnlyMatcher  []string
}

// New returns a HashParser
// MUST call Parse() before any usage
// NOT thread-safe to modify options during parse
func New() *HashParser {
	return &HashParser{}
}

func (h *HashParser) Parse(rawHashes []byte) error {
	hashes := map[string]structs.Filehash{}
	err := json.Unmarshal(rawHashes, &hashes)
	if err != nil {
		return err
	}

	if len(h.ExcludedFileMatcher) > 0 {
		hashes = excludeForbiddenFiles(hashes, h.ExcludedFileMatcher)
	}

	if len(h.IncludeOnlyMatcher) > 0 {
		hashes = includeOnly(hashes, h.IncludeOnlyMatcher)
	}

	if len(hashes) == 0 {
		return errors.New("zero hashes available")
	}

	h.hashes = hashes
	h.uniques = uniquefinder.GetTagCounts(hashes)
	h.hlookup = hashlookup.New(hashes)
	h.files = sortFilesByAccessLikelyhood(hashes, h.PreferFilesInRoot) // TODO: initial sort should prefer files that are part of the latest release

	// TODO: generate list of unique files for EACH tag
	// so narrowing down is sped up greatly when fixed number of tags is known

	return nil
}

func (h *HashParser) GetFile(index int) (string, error) {
	if len(h.files) > index {
		return h.files[index], nil
	}

	return "", fmt.Errorf("unknown index: %d", index)
}

func (h *HashParser) GetMostUniqueFile(tags []string, priorFiles []string) string {
	return h.uniques.GetMostUniqueFile(tags, priorFiles)
}

func (h *HashParser) GetTags(file, hash string) ([]string, error) {
	filehashes, ok := h.hashes[file]
	if !ok {
		return []string{}, fmt.Errorf("could not find file hashes for: %s", hash)
	}

	tags, ok := filehashes[hash]
	if !ok {
		return []string{}, fmt.Errorf("could not find hash equivalent for: %s", hash)
	}

	if len(tags) == 0 {
		return []string{}, fmt.Errorf("zero tags for hash: %s", hash)
	}

	return tags, nil
}

func (h *HashParser) GuessNextRequest(ctx context.Context, possibleVersions []string, requestedFiles []string) (nextRequest string, requested []string) {
	for {
		if helpers.IsDone((ctx.Done())) {
			return "", []string{}
		}

		nextRequest = h.uniques.GetMostUniqueFile(possibleVersions, requestedFiles)
		if nextRequest == "" {
			break
		}

		// skip running file get, if no versions can be truncated by running the hash
		allFilesShareHash, err := h.hlookup.DoTagsShareHash(nextRequest, possibleVersions)
		if err != nil {
			log.Println("ERROR:", err)
		}

		// if running the file, one or more tags can be eliminated, run it
		if !allFilesShareHash {
			break
		}

		// log.Println("cannot eliminate any tags using file. skipping:", nextRequest)

		// else consider the file skipped
		requestedFiles = helpers.AppendIfMissing(requestedFiles, nextRequest)
	}

	return nextRequest, requestedFiles
}
