package hashparser

import (
	"sort"
	"strings"

	"cmsfingerprinter/structs"
)

func includeOnly(fhashes map[string]structs.Filehash, includeMatcher []string) map[string]structs.Filehash {
	if fhashes == nil {
		return map[string]structs.Filehash{}
	}

	// include all
	if len(includeMatcher) == 0 {
		return fhashes
	}

	// each file tested must contain at least ONE of the matchers
hashesLoop:
	for k := range fhashes {

		for _, matcher := range includeMatcher {
			if strings.Contains(k, matcher) {
				continue hashesLoop
			}
		}

		delete(fhashes, k)
	}

	return fhashes
}

func excludeForbiddenFiles(fhashes map[string]structs.Filehash, forbiddenFileMatcher []string) map[string]structs.Filehash {
	if fhashes == nil {
		return map[string]structs.Filehash{}
	}

	for _, matcher := range forbiddenFileMatcher {
		for k := range fhashes {
			if strings.Contains(k, matcher) {
				delete(fhashes, k)
			}
		}
	}

	return fhashes
}

func sortFilesByHashAmounts(hashesPerFile map[string]structs.Filehash) []string {
	// get file keys in alphabetical order to always run in same order
	mk := make([]string, len(hashesPerFile))
	i := 0
	for k := range hashesPerFile {
		mk[i] = k
		i++
	}

	// when requesting randomly, first try those files with many hashes
	// to get the biggest bang for the buck when requesting random files
	sort.Slice(mk,
		func(i, j int) bool {
			return len(hashesPerFile[mk[i]]) > len(hashesPerFile[mk[j]])
		},
	)

	return mk
}

func sortFilesByAccessLikelyhood(hashesPerFile map[string]structs.Filehash, preferFilesInRoot bool) []string {
	// get file keys in alphabetical order to always run in same order
	mk := make([]string, len(hashesPerFile))
	i := 0
	for k := range hashesPerFile {
		mk[i] = k
		i++
	}

	// when requesting randomly, first try those files with many hashes
	// to get the biggest bang for the buck when requesting random files
	sort.Slice(mk,
		func(i, j int) bool {

			// should prefer files that contain the most recent version
			// otherwise, as in TYPO3, older files that are 404 in new versions will be requested
			// sysext/rtehtmlarea/htmlarea/htmlarea.js
			// typo3/sysext/css_styled_content/static/setup.txt
			// without allow further limiting
			// this order will be obsolete anyhow after the first initial succesful hit

			// e.g. Drupal
			// robots.txt is always the most likely available, so sort to top
			if preferFilesInRoot {

				if strings.Count(mk[i], "/") == 0 && strings.Count(mk[j], "/") == 0 {
					return len(hashesPerFile[mk[i]]) > len(hashesPerFile[mk[j]])
				}

				if strings.Count(mk[i], "/") == 0 {
					return true
				}

				if strings.Count(mk[j], "/") == 0 {
					return false
				}
			}

			// if the amount of hashes is equal, sort by preference indicators
			// e.g. prefer /wp-includes over /wp-admin
			if len(hashesPerFile[mk[i]]) == len(hashesPerFile[mk[j]]) {

				// if both files are likely accessible, sort alphabetically
				if isLikelyAccessible(mk[i]) == isLikelyAccessible(mk[j]) {

					// just sort alphabetically for consistent tries across requests
					return mk[i] > mk[j]
				}

				// if one is more accessible than the other, prefer
				if isLikelyAccessible(mk[i]) {
					return true
				}
				if isLikelyAccessible(mk[j]) {
					return false
				}
			}

			return len(hashesPerFile[mk[i]]) > len(hashesPerFile[mk[j]])
		},
	)

	return mk
}

// TODO: allow custom sorting by caller
func isLikelyAccessible(file string) bool {
	if strings.Contains(file, "wp-includes") ||
		strings.Contains(file, "wp-content") {
		return true
	}

	if strings.Contains(file, "assets/contao") { // contao: tinymce4 may not be available
		return true
	}

	if strings.Contains(file, "language/") { // joomla
		return true
	}

	return false
}
