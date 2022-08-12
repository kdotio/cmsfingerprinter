package fingerprinter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"cms-fingerprinter/fingerprinter/evaluator"
	"cms-fingerprinter/fingerprinter/hashparser"
	"cms-fingerprinter/helpers"
)

const (
	defaultRequestDelay = 1 * time.Second
)

type fingerprinter struct {
	hashes           *hashparser.HashParser
	requestHash      httpHashRequester
	httpRequestDelay time.Duration
}

// NewFingerprinter returns a re-usable fingerprinter for a specific CMS.
// Is currently NOT THREAD-SAFE
func NewFingerprinter(hashFilepath string) (*fingerprinter, error) {
	// TODO: allow exclusion of certain versions for limiting down quickly
	// e.g. if I know it's 5.1.3 or 5.1.2, use just those

	parser := hashparser.New()
	parser.PreferFilesInRoot = true
	parser.ExcludedFileMatcher = []string{"wp-admin", "/config/"}

	// parser.IncludeOnlyMatcher =  []string{"/assets/", "/lib/"} // Umbraco
	// parser.IncludeOnlyMatcher =  []string{".xlf"} // Wordpress
	// parser.IncludeOnlyMatcher =  []string{"assets/contao"} // Contao accessibility

	err := parser.Parse(hashFilepath)
	if err != nil {
		return nil, fmt.Errorf("parse: %s", err)
	}

	fp := &fingerprinter{
		hashes: parser,
		requestHash: defaultHttpHasher(&http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // allow invalid certs for pentesting purposes
		}),
		httpRequestDelay: defaultRequestDelay,
	}

	return fp, nil
}

func (f *fingerprinter) Analyze(ctx context.Context, target string, depth int) (httpRequests int, revs []string, err error) {
	defer helpers.TimeTrack(time.Now(), "Analyzing")

	target = strings.TrimSuffix(target, "/")
	log.Println("Analyzing", target)

	// TODO: do not just iterate over ALL hashes
	// ideally start iterating with non-blocked folders, wp-includes/wp-content, not wp-admin
	// but: if a small list of versions is found
	// use pre-calculated best route for quick determination
	// e.g. get files for which a tag is unique
	// alternatively
	// Currently (4) possible versions: [5.4.4 5.4.3 5.4.2 5.4.1]
	// testcase should be 5.4.4, ultimately

	queue := make(chan string, 1)
	next, err := f.hashes.GetFile(0)
	if err != nil {
		return 0, []string{}, errors.New("missing zero index")
	}

	queue <- next // TODO: what to use as first file call?? ideally something that splits versions 50/50 - or contains latest version, as is most likely..
	// TODO: if latest version is 5.1.0, then the first file to call should be one that still exists in 5.1.0
	// otherwise might start an endless stream of fetching legacy files

	eval, err := evaluator.New(depth, f.hashes, f.getVersions)
	if err != nil {
		return 0, []string{}, err
	}

	for file := range queue {
		if helpers.IsDone((ctx.Done())) {
			return eval.Iterations(), []string{}, errors.New("context canceled")
		}

		nextRequest, err := eval.Analyze(ctx, target, file)
		if err != nil {
			return eval.Iterations(), []string{}, err
		}

		if match, err := eval.SingleMatch(); err == nil {
			return eval.Iterations(), []string{match}, nil
		}

		if nextRequest == "" {
			log.Println("ERROR: no more files to request")
			break
		}

		queue <- nextRequest
		time.Sleep(f.httpRequestDelay)
	}

	possibleVersions := eval.PossibleVersions()
	return eval.Iterations(), possibleVersions, fmt.Errorf("too many possible versions (%d): %s", len(possibleVersions), possibleVersions)
}

func (f *fingerprinter) getVersions(ctx context.Context, target, file string) (tags []string, sCode int, err error) {
	// TODO: must consider deployment path is different than github
	// https://example.local/wp-content/plugins/woocommerce/assets/css/woocommerce-layout.css?ver=4.8.0
	// vs.
	// /assets/js/frontend/checkout.js

	t := fmt.Sprintf("%s/%s", strings.TrimSuffix(target, "/"), file)
	log.Println("---------")

	h, sCode, err := f.requestHash(ctx, t, file)
	if err != nil {
		return []string{}, 0, err
	}

	if sCode != 200 {
		return []string{}, sCode, nil
	}

	tags, err = f.hashes.GetTags(file, h)
	if err != nil {
		return []string{}, 200, err
	}

	log.Println("Found tags:", tags)

	return tags, 200, nil
}
