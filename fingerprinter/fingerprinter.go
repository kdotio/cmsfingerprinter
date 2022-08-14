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
	defaultRequestDelay = 500 * time.Millisecond
)

type fingerprinter struct {
	hashes           *hashparser.HashParser
	requestHash      httpHashRequester
	httpRequestDelay time.Duration
}

// NewFingerprinter returns a re-usable fingerprinter for a specific CMS.
// Is currently NOT THREAD-SAFE
func NewFingerprinter(hashFilepath string) (*fingerprinter, error) {
	parser := hashparser.New()
	parser.PreferFilesInRoot = true
	parser.ExcludedFileMatcher = []string{"wp-admin", "/config/", "wp-content/themes"} // WordPress

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
	target = strings.TrimSuffix(target, "/")
	log.Println("Analyzing", target)

	queue := make(chan string, 1)
	next, err := f.hashes.GetFile(0)
	if err != nil {
		return 0, []string{}, errors.New("missing zero index")
	}

	// TODO: what to use as first file call?? ideally something that splits versions 50/50 - or contains latest version, as is most likely..
	// if latest version is 5.1.0, then the first file to call should be one that still exists in 5.1.0
	// otherwise might start an endless stream of fetching legacy files
	queue <- next

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

func (f *fingerprinter) getVersions(ctx context.Context, baseTarget, file string) (tags []string, sCode int, err error) {
	t := fmt.Sprintf("%s/%s", strings.TrimSuffix(baseTarget, "/"), file)
	log.Println("---------")

	h, sCode, err := f.requestHash(ctx, t)
	if err != nil || sCode != 200 {
		return []string{}, sCode, err
	}

	tags, err = f.hashes.GetTags(file, h)
	if err != nil {
		return []string{}, 200, err
	}

	return tags, 200, nil
}
