package hashes_test

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cmsfingerprinter/fingerprinter"
)

// TestHashParse ensures that all available hashes
// can be properly parsed by fingerprinter,
// i.e. no duplicate tags exist, no multiple hashes per tag
func TestHashParse(t *testing.T) {
	fs, err := os.ReadDir("./")
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range fs {
		if f.IsDir() || !strings.HasSuffix(f.Name(), "json") {
			continue
		}

		t.Run(f.Name(), func(t *testing.T) {
			fpath := filepath.Join("./", f.Name())

			bytes, err := os.ReadFile(fpath)
			if err != nil {
				t.Fatal(err)
			}

			_, err = fingerprinter.New(bytes)
			if err != nil {
				log.Fatal(err)
			}
		})
	}
}
