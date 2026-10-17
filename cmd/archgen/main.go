// Command archgen generates .golangci.arch.yml: the checked-in golangci-lint
// config (.golangci.yml) merged with the import bans, banned calls, module
// manifest and baseline suppressions that architecture.yaml drives. The
// command stays deliberately thin — everything it does lives in
// internal/archtest so the gate can also verify the file is fresh.
//
// Run from the repo root: go run ./cmd/archgen
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "archgen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	arch := flag.String("arch", "architecture.yaml", "architecture rules")
	config := flag.String("config", ".golangci.yml", "base golangci-lint config to merge into")
	baseline := flag.String("baseline", "architecture.baseline.yaml", "known violations (missing file: none)")
	out := flag.String("out", ".golangci.arch.yml", "file to write")
	flag.Parse()
	return generate(*arch, *config, *baseline, *out)
}
