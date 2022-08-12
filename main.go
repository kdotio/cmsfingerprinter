package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"cms-fingerprinter/fingerprinter"
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

	f, err := fingerprinter.NewFingerprinter(fpath)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Succesfully parsed hashes.")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, tags, err := f.Analyze(ctx, *target, 15)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("SUCCESS. Found", tags)
}
