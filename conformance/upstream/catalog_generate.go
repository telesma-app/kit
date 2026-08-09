//go:build ignore

// Command catalog_generate prints the deterministic CTAP 2.3 source catalog.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/telesma-app/kit/conformance/upstream"
)

func main() {
	corpusPath := flag.String("corpus", "", "path to the extracted fido-conformance-tools corpus")
	flag.Parse()
	if *corpusPath == "" {
		fmt.Fprintln(os.Stderr, "catalog_generate: -corpus is required")
		os.Exit(2)
	}

	catalog, err := upstream.GenerateCatalog(os.DirFS(*corpusPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog_generate: %v\n", err)
		os.Exit(1)
	}
	data, err := upstream.MarshalCatalog(catalog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog_generate: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "catalog_generate: write: %v\n", err)
		os.Exit(1)
	}
}
