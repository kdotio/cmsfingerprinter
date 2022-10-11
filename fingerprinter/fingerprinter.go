package fingerprinter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"cmsfingerprinter/fingerprinter/evaluator"
	"cmsfingerprinter/fingerprinter/hashparser"
	"cmsfingerprinter/helpers"
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
	traceLogger      *log.Logger
	errLogger        *log.Logger
}

type Options struct {
	// PreferFilesInRoot will prefer files in root dir
	// for initial requesting when no tags have been identified yet
	// as these are most likely not to be blocked
	PreferFilesInRoot bool

	// ExcludedFileMatcher will exclude all files containing any of the strings
	// must NOT have a leading slash for root dir
	ExcludedFileMatcher []string
	IncludeOnlyMatcher  []string
}

func defaultOpts() Options {
	return Options{
		ExcludedFileMatcher: []string{
			"wp-admin", "config/", "wp-content/themes", // WordPress
			// "admin/", // OpenCart
		},

		// parser.IncludeOnlyMatcher =  []string{"assets/", "lib/"} // Umbraco
		// parser.IncludeOnlyMatcher =  []string{".xlf"} // Wordpress
		// parser.IncludeOnlyMatcher =  []string{"assets/contao"} // Contao accessibility
	}
}

func NewOptions(rawHashes []byte, opts Options) (*fingerprinter, error) {
	parser := hashparser.New()
	parser.PreferFilesInRoot = opts.PreferFilesInRoot
	parser.ExcludedFileMatcher = opts.ExcludedFileMatcher
	parser.IncludeOnlyMatcher = opts.IncludeOnlyMatcher

	err := parser.Parse(rawHashes)
	if err != nil {
		return nil, fmt.Errorf("parse: %s", err)
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	fp := &fingerprinter{
		hashes: parser,
		requestHash: defaultHttpHasher(&http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           dialer.DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   http.DefaultMaxIdleConnsPerHost,
				IdleConnTimeout:       90 * time.Second, // ensure idle conns are eventually terminated
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,

				// allow invalid certs for pentesting purposes
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}),
		httpRequestDelay: defaultRequestDelay,
		maxDepth:         defaultMaxDepth,

		// by default, use a discard logger
		// avoids nil check on every log
		traceLogger: log.New(io.Discard, "", 0),
		errLogger:   log.New(io.Discard, "", 0),
	}

	return fp, nil
}

// New returns a re-usable fingerprinter for a specific CMS.
func New(rawHashes []byte) (*fingerprinter, error) {
	return NewOptions(rawHashes, defaultOpts())
}

func (f *fingerprinter) Analyze(ctx context.Context, target string) (revs []string, err error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	target = strings.TrimSuffix(target, "/")

	// TODO: run optional faulty redirect check
	// if target returns faulty 200 status code for any URI, evaluation may run til timeout needlessly

	next, err := f.hashes.GetFile(0)
	if err != nil {
		return []string{}, errors.New("missing zero index")
	}

	// TODO: what to use as first file call?? ideally something that splits versions 50/50 - or contains latest version, as is most likely..
	// if latest version is 5.1.0, then the first file to call should be one that still exists in 5.1.0
	// otherwise might start an endless stream of fetching legacy files
	queue := make(chan string, 1)
	queue <- next

	eval, err := evaluator.New(f.maxDepth, f.hashes, f.getVersions)
	if err != nil {
		return []string{}, err
	}
	eval.SetLogger(f.traceLogger, f.errLogger)

	for file := range queue {
		if helpers.IsDone((ctx.Done())) {
			return []string{}, errors.New("context canceled")
		}

		nextRequest, err := eval.Analyze(ctx, target, file)
		if err != nil {

			// return partial results if requests run into depth limit
			// vulnerabilities may still be identified, even if 2-3 versions left
			if errors.Is(err, evaluator.ErrDepthReached) {
				return eval.PossibleVersions(), err
			}

			return []string{}, err
		}

		if match, err := eval.SingleMatch(); err == nil {
			return []string{match}, nil
		}

		if nextRequest == "" {
			f.errLogger.Println("no more files to request")
			break
		}

		queue <- nextRequest
		time.Sleep(f.httpRequestDelay)
	}

	return eval.PossibleVersions(), nil
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

func (f *fingerprinter) SetLogger(traceLogger, errLogger *log.Logger) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.traceLogger = traceLogger
	f.errLogger = errLogger

	// always discard logs if silent to avoid nil checks on call
	if f.traceLogger == nil {
		f.traceLogger = log.New(io.Discard, "", 0)
	}

	if f.errLogger == nil {
		f.errLogger = log.New(io.Discard, "", 0)
	}
}

func (f *fingerprinter) getVersions(ctx context.Context, target, file string) (tags []string, sCode int, err error) {
	target = fmt.Sprintf("%s/%s", strings.TrimSuffix(target, "/"), file)

	hash, sCode, err := f.requestHash(ctx, target)
	if err != nil || sCode != 200 {
		if err == nil {
			f.traceLogger.Printf("(%d) %s\n", sCode, target)
		}

		return []string{}, sCode, err
	}

	f.traceLogger.Printf("(%d) %s [%s]\n", sCode, target, hash)

	tags, err = f.hashes.GetTags(file, hash)
	if err != nil {
		return []string{}, 200, err
	}

	return tags, 200, nil
}
