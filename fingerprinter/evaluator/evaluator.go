package evaluator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	"cmsfingerprinter/helpers"
)

// should return with err after this many 404 calls
const maxNon200HTTP = 20

type hashAccesser interface {
	GetFile(index int) (string, error)
	GetMostUniqueFile(tags []string, priorFiles []string) (string, error)
	GuessNextRequest(ctx context.Context, possibleVersions []string, requestedFiles []string) (nextRequest string, requested []string, err error)
}

type versionGetter func(ctx context.Context, target, file string) (tags []string, sCode int, err error)

type Evaluation struct {
	mutex sync.RWMutex

	maxDepth   int
	iterations int

	hashes     hashAccesser
	getVersion versionGetter

	possibleVersions []string
	requestedFiles   []string
	httpNon200       int

	traceLogger *log.Logger
	errLogger   *log.Logger
}

func New(depth int, hashes hashAccesser, versionGet versionGetter) (*Evaluation, error) {
	if hashes == nil || versionGet == nil {
		return nil, errors.New("nil params")
	}

	return &Evaluation{
		maxDepth:   depth,
		hashes:     hashes,
		getVersion: versionGet,

		traceLogger: log.New(io.Discard, "", 0),
		errLogger:   log.New(io.Discard, "", 0),
	}, nil
}

var ErrDepthReached = errors.New("max depth reached")

func (e *Evaluation) Analyze(ctx context.Context, target, file string) (nextRequest string, err error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.httpNon200 > maxNon200HTTP {
		return "", fmt.Errorf("max non-200 http exceeded (%d)", maxNon200HTTP)
	}

	if e.maxDepth > 0 && e.iterations+1 > e.maxDepth {
		return "", ErrDepthReached
	}

	e.iterations++

	// make sure all requests are registered, irregardless of status code or error
	e.requestedFiles = append(e.requestedFiles, file)

	tags, sCode, err := e.getVersion(ctx, target, file)
	if err == nil {
		return e.nextRequestOnSuccess(ctx, sCode, tags)
	}

	e.errLogger.Println(err)

	if helpers.IsHostUnavailable(err) {
		return "", fmt.Errorf("target unreachable: %s", err)
	}

	if len(e.possibleVersions) == 0 {
		return e.nextRequestOnZeroKnownVersions()
	}

	next, err := e.hashes.GetMostUniqueFile(e.possibleVersions, e.requestedFiles)
	if err != nil {
		return "", fmt.Errorf("get most unique file: %w", err)
	}

	return next, nil
}

func (e *Evaluation) nextRequestOnZeroKnownVersions() (nextRequest string, err error) {
	// if no versions were identified positively yet
	// use next file in pre-sorted list

	if next, err := e.hashes.GetFile(e.iterations); err == nil {
		return next, nil
	}

	return "", errors.New("no tags identified. no more files to request")
}

func (e *Evaluation) nextRequestOnSuccess(ctx context.Context, sCode int, tags []string) (nextRequest string, err error) {
	if sCode != 200 {
		e.httpNon200++

		if len(e.possibleVersions) == 0 {
			return e.nextRequestOnZeroKnownVersions()
		}

		next, requested, err := e.hashes.GuessNextRequest(ctx, e.possibleVersions, e.requestedFiles)
		if err != nil {
			return "", fmt.Errorf("guess next request: %w", err)
		}

		e.requestedFiles = requested
		return next, nil
	}

	e.traceLogger.Println("Found tags:", tags)

	previousPossibleVersions := e.possibleVersions
	if len(e.possibleVersions) == 0 {
		e.possibleVersions = tags

	} else {
		e.possibleVersions = helpers.Intersect(e.possibleVersions, tags)
	}

	e.traceLogger.Printf("Currently (%d) possible versions: %s\n", len(e.possibleVersions), e.possibleVersions)

	// this may happen if e.g. a file returns tags:[5.4.2]
	// and previous possible versions is [5.7 5.6.2 5.6.1 5.6 5.5.3 5.5.2 5.5.1 5.5]
	// from then on, there is no more way to continue
	if len(e.possibleVersions) == 0 {
		return "", fmt.Errorf("ERROR: no intersection between tags %s and previous possible versions %s", tags, previousPossibleVersions)
	}

	// search is finalized here
	if len(e.possibleVersions) == 1 {
		return "", nil
	}

	next, requested, err := e.hashes.GuessNextRequest(ctx, e.possibleVersions, e.requestedFiles)
	if err != nil {
		return "", fmt.Errorf("guess next request: %w", err)
	}

	e.requestedFiles = requested
	return next, nil
}

func (e *Evaluation) Iterations() int {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return e.iterations
}

func (e *Evaluation) SingleMatch() (string, error) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	if len(e.possibleVersions) == 1 {
		return e.possibleVersions[0], nil
	}

	return "", fmt.Errorf("possible versions (%d) > 0", len(e.possibleVersions))
}

func (e *Evaluation) PossibleVersions() []string {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	// always return sorted for easy readability in output
	return helpers.SortRevsAlphabeticallyDesc(e.possibleVersions)
}

func (e *Evaluation) SetLogger(traceLogger, errLogger *log.Logger) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.traceLogger = traceLogger
	e.errLogger = errLogger

	// always discard logs if silent to avoid nil checks on call
	if e.traceLogger == nil {
		e.traceLogger = log.New(io.Discard, "", 0)
	}

	if e.errLogger == nil {
		e.errLogger = log.New(io.Discard, "", 0)
	}
}
