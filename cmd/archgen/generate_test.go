package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerate writes the three inputs into a scratch tree and checks the
// generated config: valid output for real inputs, and a clear error when the
// architecture file is broken.
func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	arch := write("architecture.yaml", `
version: 1
classes:
  - id: domain
    layer: domain
    paths: ["a"]
zones:
  shared: ["a"]
rules:
  - id: L3
    checker: golangci+archtest
    fix: inject the I/O
    banned-imports: [net/http]
    applies-to-classes: [domain]
modules:
  direct:
    - module: example.com/dep
      layers: [repository]
`)
	base := write(".golangci.yml", "version: \"2\"\nlinters:\n  enable: [staticcheck]\n")
	baseline := write("baseline.yaml", "baseline:\n  - rule: L3\n    package: a\n    why: today\n")
	out := filepath.Join(dir, ".golangci.arch.yml")

	if err := generate(arch, base, baseline, out); err != nil {
		t.Fatalf("generate: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "depguard") || !strings.Contains(string(got), "staticcheck") {
		t.Errorf("generated config misses the merge:\n%s", got)
	}

	// A broken architecture file fails with the parse error, not a partial file.
	broken := write("broken.yaml", "version: 2\n")
	if err := generate(broken, base, baseline, out); err == nil {
		t.Error("generate accepted an invalid architecture")
	}

	// A missing baseline file means no suppressions, not an error.
	if err := generate(arch, base, filepath.Join(dir, "absent.yaml"), out); err != nil {
		t.Errorf("generate with no baseline: %v", err)
	}
}

// TestGenerateMatchesCommitted regenerates from the real repo inputs and byte-
// compares the result with the committed .golangci.arch.yml: the committed file
// is the generator's output, so a stale one (or a generator drift) fails here
// instead of silently diverging from architecture.yaml.
func TestGenerateMatchesCommitted(t *testing.T) {
	out := filepath.Join(t.TempDir(), ".golangci.arch.yml")
	if err := generate("../../architecture.yaml", "../../.golangci.yml", "../../architecture.baseline.yaml", out); err != nil {
		t.Fatalf("generate: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../.golangci.arch.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("committed .golangci.arch.yml is stale — run `go run ./cmd/archgen`\ngot:\n%s\nwant:\n%s", got, want)
	}
}
