package helpers

import (
	"log"
	"sort"
	"strings"
	"time"
)

func IsDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}

func Intersect(x, y []string) []string {
	intersect := []string{}

xloop:
	for _, ex := range x {
		for _, ey := range y {
			if ex == ey {

				if !Contains(intersect, ex) {
					intersect = append(intersect, ex)
				}

				continue xloop
			}
		}
	}

yloop:
	for _, ey := range y {
		for _, ex := range x {
			if ey == ex {

				if !Contains(intersect, ey) {
					intersect = append(intersect, ey)
				}

				continue yloop
			}
		}
	}

	return intersect
}

func Contains(strs []string, str string) bool {
	for _, s := range strs {
		if s == str {
			return true
		}
	}
	return false
}

func AppendIfMissing(strs []string, s string) []string {
	if Contains(strs, s) {
		return strs
	}

	return append(strs, s)
}

func AreEqual(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}

xloop:
	for _, ex := range x {
		for _, ey := range y {
			if ex == ey {
				continue xloop
			}
		}

		return false
	}

yloop:
	for _, ey := range y {
		for _, ex := range x {
			if ey == ex {
				continue yloop
			}
		}

		return false
	}

	return true
}

func SortRevsAlphabeticallyDesc(elems []string) []string {
	sort.Slice(elems, func(i, j int) bool {
		x := strings.Split(elems[i], ".")
		y := strings.Split(elems[j], ".")

		if len(x) != len(y) {
			return elems[i] > elems[j]
		}

		for mmp := range x {

			// if major differs, return major
			// if minor differs, return minor
			// else return patch
			if x[mmp] != y[mmp] {

				// e.g. 12 vs 2
				if len(x[mmp]) > len(y[mmp]) {
					return true
				}
				// e.g. 2 vs 12
				if len(x[mmp]) < len(y[mmp]) {
					return false
				}

				// e.g. 12 vs. 24
				return x[mmp] > y[mmp]
			}
		}

		// should never call, unless patch is equal
		return elems[i] > elems[j]
	})

	return elems
}
