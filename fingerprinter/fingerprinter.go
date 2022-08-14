package fingerprinter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"cms-fingerprinter/fingerprinter/evaluator"
	"cms-fingerprinter/fingerprinter/hashparser"
	"cms-fingerprinter/helpers"
)

const (
	defaultRequestDelay = 500 * time.Millisecond
	defaultMaxDepth     = 15
)

type fingerprinter struct {
	mutex            sync.RWMutex
	hashes           *hashparser.HashParser
	requestHash      httpHashRequester
	httpRequestDelay time.Duration
	maxDepth         int
}

// New returns a re-usable fingerprinter for a specific CMS.
func New(rawHashes []byte) (*fingerprinter, error) {
	parser := hashparser.New()
	parser.PreferFilesInRoot = true
	parser.ExcludedFileMatcher = []string{"wp-admin", "/config/", "wp-content/themes"} // WordPress

	// parser.IncludeOnlyMatcher =  []string{"/assets/", "/lib/"} // Umbraco
	// parser.IncludeOnlyMatcher =  []string{".xlf"} // Wordpress
	// parser.IncludeOnlyMatcher =  []string{"assets/contao"} // Contao accessibility

	err := parser.Parse(rawHashes)
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
		maxDepth:         defaultMaxDepth,
	}

	return fp, nil
}

func (f *fingerprinter) Analyze(ctx context.Context, target string) (httpRequests int, revs []string, err error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	target = strings.TrimSuffix(target, "/")
	log.Println("Analyzing", target)

	// TODO: run optional faulty redirect check
	// if target returns faulty 200 status code for any URI, evaluation may run til timeout needlessly

	next, err := f.hashes.GetFile(0)
	if err != nil {
		return 0, []string{}, errors.New("missing zero index")
	}

	// TODO: what to use as first file call?? ideally something that splits versions 50/50 - or contains latest version, as is most likely..
	// if latest version is 5.1.0, then the first file to call should be one that still exists in 5.1.0
	// otherwise might start an endless stream of fetching legacy files
	queue := make(chan string, 1)
	queue <- next

	eval, err := evaluator.New(f.maxDepth, f.hashes, f.getVersions)
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

	return eval.Iterations(), eval.PossibleVersions(), nil
}

func (f *fingerprinter) SetRequestDelay(duration time.Duration) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.httpRequestDelay = duration
}

func (f *fingerprinter) SetDepth(depth int) {
	if depth < 0 {
		return
	}

	// 0 is a valid value, meaning algorithm will run until done
	// irregardless of necessary requests

	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.maxDepth = depth
}

func (f *fingerprinter) SetRequester(requester httpHashRequester) error {
	if requester == nil {
		return errors.New("nil http requester")
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.requestHash = requester
	return nil
}

func (f *fingerprinter) getVersions(ctx context.Context, target, file string) (tags []string, sCode int, err error) {
	t := fmt.Sprintf("%s/%s", strings.TrimSuffix(target, "/"), file)
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
