package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"cmsfingerprinter/fingerprinter"
)

func main() {
	target := flag.String("target", "", "target url, i.e. https://example.com")
	input := flag.String("cms", "", "cms to be fingerprinted, i.e. 'wordpress'")

	flag.Parse()

	if len(*input) == 0 {
		log.Fatal("cms must be specified")
	}

	if len(*target) == 0 {
		log.Fatal("no target defined")
	}

	fpath, err := filepath.Abs(filepath.Join("./hashes/", fmt.Sprintf("%s.json", *input)))
	if err != nil {
		log.Fatal(err)
	}

	bytes, err := os.ReadFile(fpath)
	if err != nil {
		log.Fatal(err)
	}

	fp, err := fingerprinter.New(bytes)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Succesfully parsed hashes.")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, tags, err := fp.Analyze(ctx, *target)
	if err != nil {
		log.Fatal(err)
	}

	if len(tags) != 1 {
		log.Fatalf("too many possible versions (%d): %s", len(tags), tags)
	}

	log.Println("SUCCESS. Found", tags[0])
}
