package fingerprinter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cms-fingerprinter/fingerprinter/hashlookup"
	"cms-fingerprinter/helpers"
	"cms-fingerprinter/structs"
)

// should return with err after this many 404 calls
const (
	maxNon200HTTP = 20

	defaultRequestDelay = 1 * time.Second

	excludeFilesWithUnlikelyAccess = true
)

type fingerprinter struct {
	h                map[string]structs.Filehash // all files hashes
	k                []string                    // file paths in alphabetical order
	tcounts          tagscount                   // used for quick lookup of next-to-be http get
	hashLookup       hashlookup.HashLookup
	requestHash      httpHashRequester
	httpRequestDelay time.Duration

	preferFilesInRoot bool
}

func NewFingerprinter(hashFilepath string) (*fingerprinter, error) {
	// load hashes from file
	bytes, err := os.ReadFile(hashFilepath)
	if err != nil {
		return nil, err
	}

	hashes := map[string]structs.Filehash{}
	err = json.Unmarshal(bytes, &hashes)
	if err != nil {
		return nil, err
	}

	if excludeFilesWithUnlikelyAccess {
		hashes = excludeForbiddenFiles(hashes, []string{"wp-admin", "/config/"})
	}

	// Umbraco
	// hashes = includeOnly(hashes, []string{"/assets/", "/lib/"}) // TODO: add option for including only certain files
	// Wordpress
	// hashes = includeOnly(hashes, []string{".xlf})

	// Contao accessibility
	// hashes = includeOnly(hashes, []string{"assets/contao"})

	if len(hashes) == 0 {
		return nil, errors.New("zero hashes available")
	}

	// TODO: allow exclusion of certain versions for limiting down quickly
	// e.g. if I know it's 5.1.3 or 5.1.2, use just those

	fp := &fingerprinter{
		h:                hashes,
		tcounts:          GetTagCounts(hashes),
		hashLookup:       hashlookup.New(hashes),
		requestHash:      defaultHttpHasher(),
		httpRequestDelay: defaultRequestDelay,

		preferFilesInRoot: true,
	}

	fp.k = sortFilesByAccessLikelyhood(fp.h, fp.preferFilesInRoot) // TODO: initial sort should prefer files that are part of the latest release

	return fp, nil
}

type summary struct {
	// const
	requiredMatches int

	// vars
	iterations   int
	foundMatches int
	matchedTag   string

	possibleVersions []string
	requestedFiles   []string
	httpNon200       int
}

func (f *fingerprinter) Analyze(ctx context.Context, target string, depth int) (httpRequests int, revs []string, err error) {
	defer helpers.TimeTrack(time.Now(), "Analyzing")

	target = strings.TrimSuffix(target, "/")

	log.Println("Analyzing", target)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// TODO: do not just iterate over ALL hashes
	// ideally start iterating with non-blocked folders, wp-includes/wp-content, not wp-admin
	// but: if a small list of versions is found
	// use pre-calculated best route for quick determination
	// e.g. get files for which a tag is unique
	// alternatively
	// Currently (4) possible versions: [5.4.4 5.4.3 5.4.2 5.4.1]
	// testcase should be 5.4.4, ultimately

	sum := summary{
		requiredMatches: 1, // might require more than one hash match for finalization
	}

	queue := make(chan string, 5)
	queue <- f.k[0] // TODO: what to use as first file call?? ideally something that splits versions 50/50 - or contains latest version, as is most likely..
	// TODO: if latest version is 5.1.0, then the first file to call should be one that still exists in 5.1.0
	// otherwise might start an endless stream of fetching legacy files

	for file := range queue {
		if helpers.IsDone((ctx.Done())) {
			return sum.iterations, []string{}, errors.New("context canceled")
		}

		if depth != 0 && sum.iterations+1 > depth {
			return sum.iterations, []string{}, fmt.Errorf("depth reached (%d)", depth)
		}
		sum.iterations++

		var nextRequest string
		var err error
		nextRequest, sum, err = f.analyze(ctx, target, file, client, sum)
		if err != nil {
			return sum.iterations, []string{}, err
		}

		if nextRequest == "" {
			if sum.foundMatches == 0 {
				log.Println("ERROR: no more files to request")
			}

			break
		}

		queue <- nextRequest
		time.Sleep(f.httpRequestDelay)
	}

	if sum.foundMatches > 0 {

		if sum.foundMatches < sum.requiredMatches {
			log.Printf("TRACE: Got match, but not enough verifications. Expected (%d), got only (%d)\n", sum.requiredMatches, sum.foundMatches)
		}

		return sum.iterations, []string{sum.matchedTag}, nil
	}

	sorted := helpers.SortRevsAlphabeticallyDesc(sum.possibleVersions)

	return sum.iterations, sorted, fmt.Errorf("too many possible versions (%d): %s", len(sum.possibleVersions), sorted)
}

func (f *fingerprinter) analyze(ctx context.Context, target, file string, client *http.Client, sum summary) (nextRequest string, s summary, err error) {
	if sum.httpNon200 > maxNon200HTTP {
		return "", sum, fmt.Errorf("max non-200 http exceeded (%d)", maxNon200HTTP)
	}

	// make sure all requests are registered, irregardless of status code or error
	sum.requestedFiles = append(sum.requestedFiles, file)

	tags, sCode, err := f.getVersions(ctx, target, file, client)
	if err != nil {
		log.Println(err)

		if helpers.IsHostUnavailable(err) {
			return "", sum, fmt.Errorf("target unreachable: %s", err)
		}

		// if no versions were identified positively yet
		// use next file in pre-sorted list
		if len(sum.possibleVersions) == 0 {

			if len(f.k) > sum.iterations {
				return f.k[sum.iterations], sum, nil
			}

			return "", sum, errors.New("no tags identified. no more files to request")
		}

		next := f.tcounts.getMostUniqueFile(sum.possibleVersions, sum.requestedFiles)
		return next, sum, nil
	}

	if sCode != 200 {
		sum.httpNon200++

		// if no versions were identified positively yet
		// use next file in pre-sorted list
		if len(sum.possibleVersions) == 0 {

			if len(f.k) > sum.iterations {
				return f.k[sum.iterations], sum, nil
			}

			return "", sum, errors.New("no tags identified. no more files to request")
		}

		var next string
		next, sum.requestedFiles = f.guessNextRequest(ctx, sum.possibleVersions, sum.requestedFiles)

		return next, sum, nil
	}

	// TODO: compare possible version, grab best uniqueness level from each and then
	// channel most lucrative filepath

	previousPossibleVersions := sum.possibleVersions

	if len(sum.possibleVersions) == 0 {
		sum.possibleVersions = tags

	} else {
		sum.possibleVersions = helpers.Intersect(sum.possibleVersions, tags)
	}

	log.Printf("Currently (%d) possible versions: %s\n", len(sum.possibleVersions), sum.possibleVersions)

	// this may happen if e.g. a file returns tags:[5.4.2]
	// and previous possible versions is [5.7 5.6.2 5.6.1 5.6 5.5.3 5.5.2 5.5.1 5.5]
	// from then on, there is no more way to continue
	if len(sum.possibleVersions) == 0 {
		return "", sum, fmt.Errorf("ERROR: no intersection between tags %s and previous possible versions %s", tags, previousPossibleVersions)
	}

	if len(sum.possibleVersions) == 1 {

		// first finding
		if sum.matchedTag == "" {
			sum.matchedTag = sum.possibleVersions[0]
			sum.foundMatches++
		}

		if sum.matchedTag == sum.possibleVersions[0] {
			sum.foundMatches++

		} else {
			return "", sum, fmt.Errorf("ERROR: Got two separate uniqe matches: %s (%d matches) vs. %s", sum.matchedTag, sum.foundMatches, sum.possibleVersions[0])
		}

		if sum.foundMatches >= sum.requiredMatches {
			return "", sum, nil
		}

		// else continue search w/ previous tags
		sum.possibleVersions = previousPossibleVersions
	}

	var next string
	next, sum.requestedFiles = f.guessNextRequest(ctx, sum.possibleVersions, sum.requestedFiles)

	return next, sum, nil
}

func (f *fingerprinter) getVersions(ctx context.Context, target, file string, client *http.Client) (tags []string, sCode int, err error) {
	// TODO: must consider deployment path is different than github
	// https://example.local/wp-content/plugins/woocommerce/assets/css/woocommerce-layout.css?ver=4.8.0
	// vs.
	// /assets/js/frontend/checkout.js

	t := fmt.Sprintf("%s/%s", strings.TrimSuffix(target, "/"), file)
	log.Println("---------")

	h, sCode, err := f.requestHash(ctx, client, t, file)
	if err != nil {
		return []string{}, 0, err
	}

	if sCode != 200 {
		return []string{}, sCode, nil
	}

	// get corresponding entry in list
	tags, ok := f.h[file][h]
	if !ok {
		return []string{}, 200, fmt.Errorf("could not find hash equivalent for: %s", h)
	}

	if len(tags) == 0 {
		return []string{}, 200, fmt.Errorf("zero tags for hash: %s", h)
	}

	log.Println("Found tags:", tags)

	return tags, 200, nil
}

func (f *fingerprinter) guessNextRequest(ctx context.Context, possibleVersions []string, requestedFiles []string) (nextRequest string, requested []string) {

	for {
		if helpers.IsDone((ctx.Done())) {
			return "", []string{}
		}

		nextRequest = f.tcounts.getMostUniqueFile(possibleVersions, requestedFiles)

		if nextRequest == "" {
			break
		}

		// skip running file get, if no versions can be truncated by running the hash
		allFilesShareHash, err := f.hashLookup.DoTagsShareHash(nextRequest, possibleVersions)
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
