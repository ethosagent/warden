package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ethosagent/warden/tools/report"
)

// memTree is a Tree held in memory: a fixture repository.
type memTree map[string]string

func (m memTree) Files() ([]string, error) {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (m memTree) Read(name string) ([]byte, error) {
	s, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("no such file %s", name)
	}
	return []byte(s), nil
}

func (m memTree) clone() memTree {
	c := memTree{}
	for k, v := range m {
		c[k] = v
	}
	return c
}

// replace swaps old for new in a file and fails the fixture if old is absent, so
// a fixture can never silently stop exercising what it names.
func (m memTree) replace(t *testing.T, file, old, new string) {
	t.Helper()
	if !strings.Contains(m[file], old) {
		t.Fatalf("fixture bug: %s does not contain %q", file, old)
	}
	m[file] = strings.Replace(m[file], old, new, 1)
}

const checkSh = `#!/usr/bin/env bash
set -euo pipefail
# --list-stages prints the stage names, one per line.
COVERAGE_MIN="${COVERAGE_MIN:-70}"
GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-v1.5.0}"
GOLANGCI_VERSION="${GOLANGCI_VERSION:-v2.12.2}"
PKGS=(./...)
PKG_STAGES=1
banner() { printf '=== %s ===\n' "$1"; }
banner "format (gofmt)"
gofmt -l .
unformatted="$(gofmt -l . | grep -v '^vendor/' || true)"
if [ "$PKG_STAGES" -eq 1 ]; then
banner "vet (go vet ./...)"
go vet "${PKGS[@]}"
fi
banner "test (go test -race -coverprofile)"
go test -race -coverprofile=coverage.out ./...
banner "vulncheck (govulncheck ${GOVULNCHECK_VERSION})"
go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...
banner "fuzz (go test -fuzz)"
go test -run '^$' -fuzz "^FuzzParse\$" -fuzztime=5s ./internal/a
banner "lint (golangci-lint ${GOLANGCI_VERSION})"
go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION}" run --config .golangci.arch.yml ./...
banner "coverage gate (min ${COVERAGE_MIN}%)"
total="$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$3); print $3}')"
if awk "BEGIN { exit !(${total} < ${COVERAGE_MIN}) }"; then
	echo "coverage ${total}% is below minimum" >&2
	exit 1
fi
`

const ciYml = `name: ci
on:
  push:
    branches: [main]
  pull_request:
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Run check.sh
        run: scripts/check.sh --integration --json-out check-report.json
`

const golangciYml = `version: "2"
linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - nolintlint
  exclusions:
    generated: lax
    presets:
      - std-error-handling
    rules:
      - path: _test\.go
        linters:
          - errcheck
issues:
  max-same-issues: 0
`

const archYml = `version: 1
classes:
  - id: devtool
    paths:
      - tools/**
  - id: engine
    paths:
      - internal/proxy/**
rules:
  - id: L1
    title: Imports point down only
    checker: archtest # L1
    fix: import the port
  - id: L3
    title: Domain does no I/O
    checker: golangci+archtest # L3
    fix: inject a port
    banned-imports: [net, os, os/exec]
    banned-calls: ["time.Now"]
    references-too: true
  - id: S1
    title: Only assembly constructs adapters
    checker: archtest+proxy # S1
    test: internal/config/secretstore_test.go
    fix: construct in cmd
  - id: X3
    title: exec only in adapters
    checker: golangci+archtest
    fix: pass an env
    exec-allowed-in:
      - repository
  - id: L4b
    title: Hot path budget
    checker: proxy
    stage: benchmark
    fix: keep side calls off the hot path
    coverage:
      - part: the benchmarks compile and run
        enforced: proxy
      - part: sync port calls are allowlisted
        planned: needs call-graph analysis
  - id: X6
    title: Deny reasons are constants
    checker: planned
    reason: no reasons file yet
`

const baselineYml = `baseline:
  - rule: L1
    package: internal/detect
    why: pre-migration
    allow: ["internal/analytics", "internal/integration"]
  - rule: L3
    package: internal/config
    why: pre-migration
    allow: ["net", "os"]
  - rule: C3
    package: examples/demo
    why: demo binary
`

// goodRepo is a small repository that satisfies every rule. Each case below
// edits a copy of it into the head of a PR.
func goodRepo() memTree {
	return memTree{
		"scripts/check.sh":            checkSh,
		"scripts/fuzz-targets.txt":    "# targets\nFuzzParse ./internal/a\nFuzzDecode ./internal/a\n",
		".github/workflows/ci.yml":    ciYml,
		".golangci.yml":               golangciYml,
		".golangci.arch.yml":          golangciYml,
		"architecture.yaml":           archYml,
		"architecture.baseline.yaml":  baselineYml,
		"internal/a/a.go":             "package a\n\nfunc A() {}\n\nfunc B() { _ = 1 } //nolint:gosec // operator-provided path\n",
		"internal/a/a_test.go":        "package a\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) { A() }\n\nfunc TestB(t *testing.T) { A() }\n\nfunc FuzzParse(f *testing.F) {}\n",
		"internal/a/long_test.go":     "//go:build integration\n\npackage a\n\nimport \"testing\"\n\nfunc TestLong(t *testing.T) {\n\tif testing.Short() {\n\t\tt.Skip(\"slow\")\n\t}\n}\n",
		"docs/readme.md":              "docs\n",
		".github/workflows/other.yml": "name: other\non: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
	}
}

func lineOf(t *testing.T, content, marker string) int {
	t.Helper()
	for i, l := range strings.Split(content, "\n") {
		if strings.HasPrefix(marker, "^") && strings.HasPrefix(l, marker[1:]) || !strings.HasPrefix(marker, "^") && strings.Contains(l, marker) {
			return i + 1
		}
	}
	t.Fatalf("fixture bug: marker %q not found", marker)
	return 0
}

func compare(t *testing.T, base, head memTree) []report.Finding {
	t.Helper()
	fs, err := Compare(base, head)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// weakening is one row of the ticket's table: an edit to the good repository
// that must fail with a named kind, file and line. at names the file and a
// marker whose line is expected, taken from the head (or the base when the
// weakening is a removal, which has no head line).
type weakening struct {
	name     string
	kind     string
	edit     func(t *testing.T, m memTree)
	file     string
	marker   string
	inBase   bool
	contains string
}

func weakenings() []weakening {
	return []weakening{
		// --- coverage minimum
		{name: "coverage default lowered", kind: "coverage-lowered", file: "scripts/check.sh", marker: `COVERAGE_MIN="${COVERAGE_MIN:-65}"`,
			edit:     func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", ":-70}", ":-65}") },
			contains: "from 70 to 65"},
		{name: "coverage min overridden low in CI", kind: "coverage-lowered", file: ".github/workflows/ci.yml", marker: "COVERAGE_MIN: 40",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "        run: scripts", "        env:\n          COVERAGE_MIN: 40\n        run: scripts")
			}},
		{name: "coverage min overridden low inline", kind: "coverage-lowered", file: ".github/workflows/ci.yml", marker: "COVERAGE_MIN=10 scripts",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "run: scripts/check.sh", "run: COVERAGE_MIN=10 scripts/check.sh")
			}},
		{name: "coverage default no longer readable", kind: "coverage-lowered", file: "scripts/check.sh", marker: "COVERAGE_MIN=",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", `COVERAGE_MIN="${COVERAGE_MIN:-70}"`, `COVERAGE_MIN="${COVERAGE_MIN:-$(cat .covmin)}"`)
			}},

		// --- check.sh stage removed or skipped
		{name: "stage removed", kind: "stage-removed", file: "scripts/check.sh", marker: `banner "vet`, inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "banner \"vet (go vet ./...)\"\ngo vet \"${PKGS[@]}\"\n", "")
			}},
		{name: "stage skipped with || true", kind: "stage-skipped", file: "scripts/check.sh", marker: "go test -race -coverprofile=coverage.out ./... || true",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go test -race -coverprofile=coverage.out ./...", "go test -race -coverprofile=coverage.out ./... || true")
			}},
		{name: "stage command deleted, banner kept", kind: "stage-skipped", file: "scripts/check.sh", marker: "^go vet", inBase: true,
			edit: func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "") }},
		{name: "stage command commented out", kind: "stage-skipped", file: "scripts/check.sh", marker: "^go vet", inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "\ngo vet \"${PKGS[@]}\"\n", "\n# go vet \"${PKGS[@]}\"\n")
			}},
		{name: "stage exits early", kind: "stage-skipped", file: "scripts/check.sh", marker: "exit 0",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "go vet \"${PKGS[@]}\"\nexit 0\n")
			}},
		{name: "stage behind a skip variable", kind: "stage-skipped", file: "scripts/check.sh", marker: "SKIP_LINT",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go test -race -coverprofile=coverage.out ./...\n", "[ -n \"${SKIP_LINT:-}\" ] || go test -race -coverprofile=coverage.out ./...\n")
			}},
		{name: "errexit dropped", kind: "stage-skipped", file: "scripts/check.sh", marker: "set -euo pipefail", inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "set -euo pipefail\n", "set -uo pipefail\n")
			}},

		// --- CI no longer runs the gate
		{name: "CI runs something else", kind: "ci-gate-missing", file: ".github/workflows/ci.yml", marker: "run: scripts/check.sh", inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "scripts/check.sh --integration --json-out check-report.json", "go test ./...")
			}},
		{name: "CI workflow deleted", kind: "ci-gate-missing", file: ".github/workflows/ci.yml", marker: "run: scripts/check.sh", inBase: true,
			edit: func(t *testing.T, m memTree) { delete(m, ".github/workflows/ci.yml") }},
		{name: "CI drops --integration", kind: "ci-integration-dropped", file: ".github/workflows/ci.yml", marker: "run: scripts/check.sh --json-out",
			edit: func(t *testing.T, m memTree) { m.replace(t, ".github/workflows/ci.yml", "--integration ", "") }},
		{name: "CI gate step continues on error", kind: "ci-gate-weakened", file: ".github/workflows/ci.yml", marker: "continue-on-error: true",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "        run: scripts", "        continue-on-error: true\n        run: scripts")
			}},
		{name: "CI gate job continues on error", kind: "ci-gate-weakened", file: ".github/workflows/ci.yml", marker: "continue-on-error: true",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    continue-on-error: true\n")
			}},
		{name: "CI gate step made conditional", kind: "ci-gate-weakened", file: ".github/workflows/ci.yml", marker: "if: github.actor",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "        run: scripts", "        if: github.actor != 'dependabot[bot]'\n        run: scripts")
			}},
		{name: "CI gate job made conditional", kind: "ci-gate-weakened", file: ".github/workflows/ci.yml", marker: "if: github.event",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    if: github.event_name == 'push'\n")
			}},
		{name: "CI runs only --fast", kind: "ci-gate-weakened", file: ".github/workflows/ci.yml", marker: "--fast",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "--integration", "--integration --fast")
			}},
		{name: "CI no longer runs on pull requests", kind: "ci-gate-weakened", file: ".github/workflows/ci.yml", marker: "pull_request:", inBase: true,
			edit: func(t *testing.T, m memTree) { m.replace(t, ".github/workflows/ci.yml", "  pull_request:\n", "") }},
		{name: "CI check job renamed", kind: "ci-gate-weakened", file: ".github/workflows/ci.yml", marker: "  check:", inBase: true,
			edit: func(t *testing.T, m memTree) { m.replace(t, ".github/workflows/ci.yml", "  check:\n", "  verify:\n") }},

		// --- tests deleted
		{name: "test deleted", kind: "test-deleted", file: "internal/a/a_test.go", marker: "func TestB", inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/a_test.go", "func TestB(t *testing.T) { A() }\n\n", "")
			}},
		{name: "test renamed", kind: "test-deleted", file: "internal/a/a_test.go", marker: "func TestB", inBase: true,
			edit: func(t *testing.T, m memTree) { m.replace(t, "internal/a/a_test.go", "func TestB(", "func TestBee(") }},
		{name: "test disabled by lowercasing", kind: "test-deleted", file: "internal/a/a_test.go", marker: "func TestB", inBase: true,
			edit: func(t *testing.T, m memTree) { m.replace(t, "internal/a/a_test.go", "func TestB(", "func testB(") }},
		{name: "test file deleted", kind: "test-deleted", file: "internal/a/long_test.go", marker: "func TestLong", inBase: true,
			edit: func(t *testing.T, m memTree) { delete(m, "internal/a/long_test.go") }},
		{name: "fuzz target dropped from the list", kind: "test-deleted", file: "scripts/fuzz-targets.txt", marker: "FuzzDecode", inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/fuzz-targets.txt", "FuzzDecode ./internal/a\n", "")
			}},

		// --- tests skipped
		{name: "t.Skip added", kind: "test-skipped", file: "internal/a/a_test.go", marker: `t.Skip("flaky")`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/a_test.go", "func TestB(t *testing.T) { A() }", "func TestB(t *testing.T) {\n\tt.Skip(\"flaky\")\n\tA()\n}")
			}},
		{name: "t.Skipf added in a new test", kind: "test-skipped", file: "internal/a/new_test.go", marker: "t.Skipf",
			edit: func(t *testing.T, m memTree) {
				m["internal/a/new_test.go"] = "package a\n\nimport \"testing\"\n\nfunc TestNew(t *testing.T) {\n\tt.Skipf(\"later %d\", 1)\n}\n"
			}},
		{name: "testing.Short guard added", kind: "test-skipped", file: "internal/a/a_test.go", marker: "testing.Short()",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }", "func TestA(t *testing.T) {\n\tif testing.Short() {\n\t\treturn\n\t}\n\tA()\n}")
			}},
		{name: "build tag excludes an existing test file", kind: "test-skipped", file: "internal/a/a_test.go", marker: "//go:build ignore",
			edit: func(t *testing.T, m memTree) {
				m["internal/a/a_test.go"] = "//go:build ignore\n\n" + m["internal/a/a_test.go"]
			}},
		{name: "build tag changed on an existing test file", kind: "test-skipped", file: "internal/a/long_test.go", marker: "//go:build never",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/long_test.go", "//go:build integration", "//go:build never")
			}},
		{name: "go test -short added", kind: "test-skipped", file: "scripts/check.sh", marker: "go test -short",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go test -race -coverprofile=coverage.out ./...", "go test -short -race -coverprofile=coverage.out ./...")
			}},
		{name: "go test -skip added", kind: "test-skipped", file: "scripts/check.sh", marker: "-skip",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go test -race -coverprofile=coverage.out ./...", "go test -race -skip TestB -coverprofile=coverage.out ./...")
			}},

		// --- lint loosened
		{name: "linter removed", kind: "lint-loosened", file: ".golangci.yml", marker: "enable:", inBase: false,
			edit: func(t *testing.T, m memTree) { m.replace(t, ".golangci.yml", "    - staticcheck\n", "") }},
		{name: "linter disabled", kind: "lint-loosened", file: ".golangci.yml", marker: "- govet",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".golangci.yml", "linters:\n", "linters:\n  disable:\n    - govet\n")
			}},
		{name: "exclusion rule added", kind: "lint-loosened", file: ".golangci.yml", marker: "internal/a/",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".golangci.yml", "    rules:\n", "    rules:\n      - path: internal/a/\n        linters:\n          - staticcheck\n")
			}},
		{name: "exclusion path added", kind: "lint-loosened", file: ".golangci.yml", marker: "- internal/a",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".golangci.yml", "    presets:\n", "    paths:\n      - internal/a\n    presets:\n")
			}},
		{name: "exclusion preset added", kind: "lint-loosened", file: ".golangci.yml", marker: "- comments",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".golangci.yml", "      - std-error-handling\n", "      - std-error-handling\n      - comments\n")
			}},
		{name: "legacy exclude-rules added", kind: "lint-loosened", file: ".golangci.yml", marker: "- path: x",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".golangci.yml", "issues:\n", "issues:\n  exclude-rules:\n    - path: x\n      linters: [govet]\n")
			}},
		{name: "issue cap introduced", kind: "lint-loosened", file: ".golangci.yml", marker: "max-same-issues: 3",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".golangci.yml", "max-same-issues: 0", "max-same-issues: 3")
			}},
		{name: "staticcheck check disabled in settings", kind: "lint-loosened", file: ".golangci.yml", marker: `"-SA1019"`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".golangci.yml", "  exclusions:\n", "  settings:\n    staticcheck:\n      checks: [\"all\", \"-SA1019\"]\n  exclusions:\n")
			}},
		{name: "tests no longer linted", kind: "lint-loosened", file: ".golangci.yml", marker: "tests: false",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".golangci.yml", "issues:\n", "run:\n  tests: false\nissues:\n")
			}},
		{name: "nolint added", kind: "nolint-added", file: "internal/a/a.go", marker: "nolint:errcheck",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/a.go", "func A() {}", "func A() { _ = 2 } //nolint:errcheck // flaky")
			}},
		{name: "second identical nolint added", kind: "nolint-added", file: "internal/a/a.go", marker: "func C",
			edit: func(t *testing.T, m memTree) {
				m["internal/a/a.go"] += "\nfunc C() { _ = 1 } //nolint:gosec // operator-provided path\n"
			}},
		{name: "bare nolint added in a new file", kind: "nolint-added", file: "internal/a/b.go", marker: "//nolint",
			edit: func(t *testing.T, m memTree) { m["internal/a/b.go"] = "package a\n\n//nolint\nfunc D() {}\n" }},

		// --- architecture rules loosened (#349)
		{name: "arch rule removed", kind: "arch-rule-removed", file: "architecture.yaml", marker: "id: L1", inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "  - id: L1\n    title: Imports point down only\n    checker: archtest # L1\n    fix: import the port\n", "")
			}},
		{name: "arch rule downgraded to planned", kind: "arch-rule-downgraded", file: "architecture.yaml", marker: "checker: planned # L1",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "checker: archtest # L1", "checker: planned # L1")
			}},
		{name: "arch rule downgraded to proxy", kind: "arch-rule-downgraded", file: "architecture.yaml", marker: "checker: proxy # L1",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "checker: archtest # L1", "checker: proxy # L1")
			}},
		{name: "arch rule loses one of its checkers", kind: "arch-rule-downgraded", file: "architecture.yaml", marker: "checker: archtest # L3",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "checker: golangci+archtest # L3", "checker: archtest # L3")
			}},
		{name: "arch rule loses its proxy test", kind: "arch-rule-downgraded", file: "architecture.yaml", marker: "checker: archtest # S1",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "checker: archtest+proxy # S1", "checker: archtest # S1")
			}},
		{name: "arch coverage part moved to planned", kind: "arch-rule-downgraded", file: "architecture.yaml", marker: "planned: later",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "        enforced: proxy\n", "        planned: later\n")
			}},
		{name: "arch coverage part removed", kind: "arch-rule-downgraded", file: "architecture.yaml", marker: "coverage:",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "      - part: the benchmarks compile and run\n        enforced: proxy\n", "")
			}},
		{name: "arch banned import removed", kind: "arch-rule-loosened", file: "architecture.yaml", marker: "banned-imports: [net, os]",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "[net, os, os/exec]", "[net, os]")
			}},
		{name: "arch banned call removed", kind: "arch-rule-loosened", file: "architecture.yaml", marker: "banned-calls: []",
			edit: func(t *testing.T, m memTree) { m.replace(t, "architecture.yaml", `["time.Now"]`, "[]") }},
		{name: "arch allowed place added", kind: "arch-rule-loosened", file: "architecture.yaml", marker: "- engine",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "      - repository\n", "      - repository\n      - engine\n")
			}},
		{name: "arch shared repository added", kind: "arch-rule-loosened", file: "architecture.yaml", marker: "- internal/cpstate",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "    fix: pass an env\n", "    fix: pass an env\n    shared-repositories:\n      - internal/cpstate\n")
			}},
		{name: "arch references-too dropped", kind: "arch-rule-loosened", file: "architecture.yaml", marker: "references-too: false",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "references-too: true", "references-too: false")
			}},
		{name: "arch except-tests introduced", kind: "arch-rule-loosened", file: "architecture.yaml", marker: "except-tests: true",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "    banned-calls: [\"time.Now\"]\n", "    banned-calls: [\"time.Now\"]\n    except-tests: true\n")
			}},
		{name: "arch package moved into an exempt class", kind: "arch-rule-loosened", file: "architecture.yaml", marker: "- internal/dlp",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.yaml", "      - tools/**\n", "      - tools/**\n      - internal/dlp\n")
			}},
		{name: "arch.yaml deleted", kind: "arch-rule-removed", file: "architecture.yaml", marker: "version: 1", inBase: true,
			edit: func(t *testing.T, m memTree) { delete(m, "architecture.yaml") }},

		// --- baseline growth: it may only shrink
		{name: "baseline gains an entry", kind: "baseline-grew", file: "architecture.baseline.yaml", marker: "package: internal/dlp",
			edit: func(t *testing.T, m memTree) {
				m["architecture.baseline.yaml"] += "  - rule: L1\n    package: internal/dlp\n    why: new\n    allow: [\"internal/analytics\"]\n"
			}},
		{name: "baseline gains an entry without an allow list", kind: "baseline-grew", file: "architecture.baseline.yaml", marker: "package: internal/dlp",
			edit: func(t *testing.T, m memTree) {
				m["architecture.baseline.yaml"] += "  - rule: C3\n    package: internal/dlp\n    why: new\n"
			}},
		{name: "baseline gains an allow item", kind: "baseline-grew", file: "architecture.baseline.yaml", marker: `"internal/audit"`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.baseline.yaml", `["net", "os"]`, `["net", "os", "internal/audit"]`)
			}},
		{name: "baseline allow item swapped", kind: "baseline-grew", file: "architecture.baseline.yaml", marker: `"os/exec"`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.baseline.yaml", `["net", "os"]`, `["net", "os/exec"]`)
			}},
		{name: "baseline entry re-keyed to another package", kind: "baseline-grew", file: "architecture.baseline.yaml", marker: "package: internal/other",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "architecture.baseline.yaml", "package: internal/detect", "package: internal/other")
			}},

		// --- tool versions downgraded
		{name: "golangci-lint downgraded", kind: "tool-downgraded", file: "scripts/check.sh", marker: `GOLANGCI_VERSION:-v2.11.0`,
			edit:     func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", "v2.12.2", "v2.11.0") },
			contains: "v2.12.2 to v2.11.0"},
		{name: "govulncheck downgraded", kind: "tool-downgraded", file: "scripts/check.sh", marker: `GOVULNCHECK_VERSION:-v1.4.9`,
			edit: func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", "v1.5.0", "v1.4.9") }},
		{name: "minor version compared numerically", kind: "tool-downgraded", file: "scripts/check.sh", marker: `GOLANGCI_VERSION:-v2.9.0`,
			edit: func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", "v2.12.2", "v2.9.0") }},
		{name: "tool version pinned low in CI", kind: "tool-downgraded", file: ".github/workflows/ci.yml", marker: "GOLANGCI_VERSION: v1.0.0",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "        run: scripts", "        env:\n          GOLANGCI_VERSION: v1.0.0\n        run: scripts")
			}},
		{name: "tool pin removed", kind: "tool-downgraded", file: "scripts/check.sh", marker: "GOVULNCHECK_VERSION=",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", `GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-v1.5.0}"`, `GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-latest}"`)
			}},

		// --- vulnerability scan suppressed
		{name: "known vuln filtered out", kind: "vuln-suppressed", file: "scripts/check.sh", marker: "GO-2026-1234",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go run \"golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}\" ./...", "go run \"golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}\" ./... | grep -v GO-2026-1234")
			}},
		{name: "govulncheck failure ignored", kind: "vuln-suppressed", file: "scripts/check.sh", marker: "govulncheck@${GOVULNCHECK_VERSION}\" ./... || true",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "govulncheck@${GOVULNCHECK_VERSION}\" ./...", "govulncheck@${GOVULNCHECK_VERSION}\" ./... || true")
			}},
		{name: "govulncheck exclusion flag", kind: "vuln-suppressed", file: "scripts/check.sh", marker: "-exclude",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "${GOVULNCHECK_VERSION}\" ./...", "${GOVULNCHECK_VERSION}\" -exclude GO-2026-1 ./...")
			}},
		{name: "govulncheck ignore file added", kind: "vuln-suppressed", file: ".govulncheck-ignore", marker: "GO-2026",
			edit: func(t *testing.T, m memTree) { m[".govulncheck-ignore"] = "GO-2026-0001\n" }},
		{name: "vuln id ignored in CI", kind: "vuln-suppressed", file: ".github/workflows/ci.yml", marker: "GO-2026-77",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, ".github/workflows/ci.yml", "        run: scripts", "        env:\n          GOVULNCHECK_IGNORE: GO-2026-77\n        run: scripts")
			}},

		// --- a stage keeps its banner but runs less (script.go analysis of check.sh)
		{name: "go test loses -race", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "^go test -coverprofile",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go test -race -coverprofile=", "go test -coverprofile=")
			}},
		{name: "go test loses -coverprofile", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "^go test -race ./...",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go test -race -coverprofile=coverage.out ./...", "go test -race ./...")
			}},
		{name: "fuzz loses -fuzz", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "-fuzztime=5s",
			edit: func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", "-fuzz \"^FuzzParse\\$\" ", "") }},
		{name: "go test narrowed from ./...", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "-coverprofile=coverage.out ./internal/a",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "-coverprofile=coverage.out ./...", "-coverprofile=coverage.out ./internal/a")
			}},
		{name: "go vet narrowed", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "go vet ./internal/a",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"", "go vet ./internal/a")
			}},
		{name: "package list narrowed", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "PKGS=(./internal/a)",
			edit: func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", "PKGS=(./...)", "PKGS=(./internal/a)") }},
		{name: "govulncheck narrowed", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "govulncheck@${GOVULNCHECK_VERSION}\" ./internal/a",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "govulncheck@${GOVULNCHECK_VERSION}\" ./...", "govulncheck@${GOVULNCHECK_VERSION}\" ./internal/a")
			}},
		{name: "golangci-lint narrowed", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "arch.yml ./internal/a",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "--config .golangci.arch.yml ./...", "--config .golangci.arch.yml ./internal/a")
			}},
		{name: "lint command replaced", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "go run other-tool",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go run \"github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION}\" run --config .golangci.arch.yml ./...", "go run other-tool")
			}},

		// --- the coverage comparison
		{name: "coverage comparison inverted", kind: "coverage-check-changed", file: "scripts/check.sh", marker: "BEGIN",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "${total} < ${COVERAGE_MIN}", "${total} > ${COVERAGE_MIN}")
			}},
		{name: "coverage compared with zero", kind: "coverage-check-changed", file: "scripts/check.sh", marker: "< 0)",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "${total} < ${COVERAGE_MIN}", "${total} < 0")
			}},
		{name: "coverage gate no longer exits", kind: "coverage-check-changed", file: "scripts/check.sh", marker: "exit 1", inBase: true,
			edit: func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", "\texit 1\n", "\ttrue\n") }},
		{name: "coverage read from another profile", kind: "coverage-check-changed", file: "scripts/check.sh", marker: "coverage.other.out",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go tool cover -func=coverage.out", "go tool cover -func=coverage.other.out")
			}},

		// --- the lint config
		{name: "lint --config target changed", kind: "lint-config-changed", file: "scripts/check.sh", marker: "--config .golangci.yml",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "--config .golangci.arch.yml", "--config .golangci.yml")
			}},
		{name: "lint --config dropped", kind: "lint-config-changed", file: "scripts/check.sh", marker: "go run \"github.com/golangci",
			edit: func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", " --config .golangci.arch.yml", "") }},
		{name: "new golangci config introduced", kind: "lint-config-changed", file: ".golangci.loose.yml", marker: "version",
			edit: func(t *testing.T, m memTree) {
				m[".golangci.loose.yml"] = "version: \"2\"\nlinters:\n  enable: [govet]\n"
			}},
		{name: "workflow lints with another config", kind: "lint-config-changed", file: ".github/workflows/ci.yml", marker: ".golangci.loose.yml",
			edit: func(t *testing.T, m memTree) {
				m[".github/workflows/ci.yml"] += "      - run: golangci-lint run --config .golangci.loose.yml\n"
			}},

		// --- a banner renamed
		{name: "banner renamed", kind: "stage-renamed", file: "scripts/check.sh", marker: `banner "check (go vet`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "banner \"vet (go vet ./...)\"", "banner \"check (go vet ./...)\"")
			}},

		// --- more ways of not running a test
		{name: "early return on os.Getenv", kind: "test-skipped", file: "internal/a/a_test.go", marker: `os.Getenv("CI")`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }", "func TestA(t *testing.T) {\n\tif os.Getenv(\"CI\") != \"\" {\n\t\treturn\n\t}\n\tA()\n}")
			}},
		{name: "early return on os.LookupEnv", kind: "test-skipped", file: "internal/a/a_test.go", marker: `os.LookupEnv`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }", "func TestA(t *testing.T) {\n\tif _, ok := os.LookupEnv(\"CI\"); ok {\n\t\treturn\n\t}\n\tA()\n}")
			}},
		{name: "early return on a variable read from the environment", kind: "test-skipped", file: "internal/a/a_test.go", marker: `if ci ==`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }", "func TestA(t *testing.T) {\n\tci := os.Getenv(\"CI\")\n\tif ci == \"yes\" {\n\t\treturn\n\t}\n\tA()\n}")
			}},
		{name: "early return on testing.Short in a subtest", kind: "test-skipped", file: "internal/a/a_test.go", marker: `if testing.Short()`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }", "func TestA(t *testing.T) {\n\tt.Run(\"x\", func(t *testing.T) {\n\t\tif testing.Short() {\n\t\t\treturn\n\t\t}\n\t})\n}")
			}},
		{name: "helper in a non-test file skips", kind: "test-skipped", file: "internal/a/helper.go", marker: `t.Skip`,
			edit: func(t *testing.T, m memTree) {
				m["internal/a/helper.go"] = "package a\n\nimport \"testing\"\n\nfunc Setup(t *testing.T) {\n\tt.Skip(\"later\")\n}\n"
			}},
		{name: "helper in a non-test file skips on -short", kind: "test-skipped", file: "internal/a/helper.go", marker: `testing.Short()`,
			edit: func(t *testing.T, m memTree) {
				m["internal/a/helper.go"] = "package a\n\nimport \"testing\"\n\nfunc Setup(tb testing.TB) {\n\tif testing.Short() {\n\t\ttb.SkipNow()\n\t}\n}\n"
			}},
		{name: "helper in an existing non-test file skips", kind: "test-skipped", file: "internal/a/a.go", marker: `t.Skipf`,
			edit: func(t *testing.T, m memTree) {
				m["internal/a/a.go"] += "\nfunc Need(t *testing.T) {\n\tt.Skipf(\"no %s\", \"db\")\n}\n"
			}},
		{name: "helper in a non-test file returns early on the environment", kind: "test-skipped", file: "internal/a/helper.go", marker: `os.Getenv`,
			edit: func(t *testing.T, m memTree) {
				m["internal/a/helper.go"] = "package a\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc Setup(t *testing.T) {\n\tif os.Getenv(\"CI\") != \"\" {\n\t\treturn\n\t}\n}\n"
			}},

		// --- composite actions are CI too
		{name: "coverage min overridden low in a composite action", kind: "coverage-lowered", file: ".github/actions/gate/action.yml", marker: "COVERAGE_MIN: 10",
			edit: func(t *testing.T, m memTree) {
				m[".github/actions/gate/action.yml"] = "name: gate\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      env:\n        COVERAGE_MIN: 10\n      run: scripts/check.sh\n"
			}},
		{name: "tool pin overridden low in a composite action", kind: "tool-downgraded", file: ".github/actions/gate/action.yml", marker: "GOLANGCI_VERSION: v1.0.0",
			edit: func(t *testing.T, m memTree) {
				m[".github/actions/gate/action.yml"] = "name: gate\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      env:\n        GOLANGCI_VERSION: v1.0.0\n      run: scripts/check.sh\n"
			}},
		{name: "go test -short in a composite action", kind: "test-skipped", file: ".github/actions/gate/action.yml", marker: "go test -short",
			edit: func(t *testing.T, m memTree) {
				m[".github/actions/gate/action.yml"] = "name: gate\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: go test -short ./...\n"
			}},

		// --- a gate variable reassigned after its defaults (F-1)
		{name: "coverage min reassigned after the defaults", kind: "coverage-lowered", file: "scripts/check.sh", marker: "^COVERAGE_MIN=1",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "PKGS=(./...)\n", "PKGS=(./...)\nCOVERAGE_MIN=1\n")
			}},
		{name: "coverage min exported low", kind: "coverage-lowered", file: "scripts/check.sh", marker: "export COVERAGE_MIN=1",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "PKGS=(./...)\n", "PKGS=(./...)\nexport COVERAGE_MIN=1\n")
			}},
		{name: "tool version reassigned", kind: "tool-downgraded", file: "scripts/check.sh", marker: "^GOLANGCI_VERSION=v1.0.0",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "PKGS=(./...)\n", "PKGS=(./...)\nGOLANGCI_VERSION=v1.0.0\n")
			}},
		{name: "stages switched off by PKG_STAGES", kind: "stage-skipped", file: "scripts/check.sh", marker: "^PKG_STAGES=0",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "PKG_STAGES=1\n", "PKG_STAGES=1\nPKG_STAGES=0\n")
			}},
		{name: "package list reassigned after the defaults", kind: "stage-skipped", file: "scripts/check.sh", marker: "^PKGS=(./internal/a)",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "PKG_STAGES=1\n", "PKG_STAGES=1\nPKGS=(./internal/a)\n")
			}},
		{name: "variable used by a stage command reassigned", kind: "stage-skipped", file: "scripts/check.sh", marker: "^FUZZTIME=0s",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "PKG_STAGES=1\n", "PKG_STAGES=1\nFUZZTIME=0s\n")
			}},
		{name: "coverage total overwritten", kind: "coverage-lowered", file: "scripts/check.sh", marker: "^total=0",
			edit: func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", "if awk", "total=0\nif awk") }},

		// --- stages guarded by a condition (F-2)
		{name: "test stage behind an if", kind: "stage-guard-changed", file: "scripts/check.sh", marker: `if [ "${RUN_TESTS:-0}" -eq 1 ]`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "banner \"test (go test -race -coverprofile)\"\ngo test -race -coverprofile=coverage.out ./...\n",
					"if [ \"${RUN_TESTS:-0}\" -eq 1 ]; then\nbanner \"test (go test -race -coverprofile)\"\ngo test -race -coverprofile=coverage.out ./...\nfi\n")
			}},
		{name: "vet stage behind a case", kind: "stage-guard-changed", file: "scripts/check.sh", marker: `case "${MODE:-}" in`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "case \"${MODE:-}\" in\nfull) go vet \"${PKGS[@]}\" ;;\nesac\n")
			}},
		{name: "command guarded by &&", kind: "stage-guard-changed", file: "scripts/check.sh", marker: "&& go vet",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "[ \"${DO_VET:-0}\" = 1 ] && go vet \"${PKGS[@]}\"\n")
			}},
		{name: "guard moved from one stage to another", kind: "stage-guard-changed", file: "scripts/check.sh", marker: `if [ "$PKG_STAGES" -eq 1 ]; then`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "if [ \"$PKG_STAGES\" -eq 1 ]; then\nbanner \"vet (go vet ./...)\"\ngo vet \"${PKGS[@]}\"\nfi\n",
					"banner \"vet (go vet ./...)\"\ngo vet \"${PKGS[@]}\"\nif [ \"$PKG_STAGES\" -eq 1 ]; then\nbanner \"test (go test -race -coverprofile)\"\nfi\n")
			}},

		// --- decoys that satisfy the token match (F-3)
		{name: "duplicate banner as a decoy", kind: "stage-banner-duplicated", file: "scripts/check.sh", marker: "test decoy",
			edit: func(t *testing.T, m memTree) {
				m["scripts/check.sh"] += "banner \"test decoy\"\n"
			}},
		{name: "go vet only inside an assignment", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "^go vet", inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "VET_CMD=\"go vet ${PKGS[@]}\"\n")
			}},
		{name: "go vet only inside a quoted no-op", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "^go vet", inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", ": \"go vet ${PKGS[@]}\"\n")
			}},
		{name: "go test only after a quoted semicolon", kind: "stage-command-weakened", file: "scripts/check.sh", marker: "^go vet", inBase: true,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "log \"x; go vet ${PKGS[@]}\"\n")
			}},

		// --- failure swallowed in other ways (F-4)
		{name: "|| echo", kind: "stage-skipped", file: "scripts/check.sh", marker: "|| echo",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "go vet \"${PKGS[@]}\" || echo vet failed\n")
			}},
		{name: "|| printf", kind: "stage-skipped", file: "scripts/check.sh", marker: "|| printf",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "go vet \"${PKGS[@]}\" || printf 'x'\n")
			}},
		{name: "|| :", kind: "stage-skipped", file: "scripts/check.sh", marker: "|| :",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "go vet \"${PKGS[@]}\" || :\n")
			}},
		{name: "; true", kind: "stage-skipped", file: "scripts/check.sh", marker: "; true",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "go vet \"${PKGS[@]}\"; true\n")
			}},
		{name: "set +e added", kind: "stage-skipped", file: "scripts/check.sh", marker: "^set +e",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "PKG_STAGES=1\n", "PKG_STAGES=1\nset +e\n")
			}},
		{name: "if ! gate; then :", kind: "stage-skipped", file: "scripts/check.sh", marker: "if ! go test",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go test -race -coverprofile=coverage.out ./...\n", "if ! go test -race -coverprofile=coverage.out ./...; then :; fi\n")
			}},
		{name: "if ! gate with an empty then-branch", kind: "stage-skipped", file: "scripts/check.sh", marker: "if ! go test",
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "scripts/check.sh", "go test -race -coverprofile=coverage.out ./...\n", "if ! go test -race -coverprofile=coverage.out ./...; then\n\techo failed\nfi\n")
			}},

		// --- environment guards (F-5)
		{name: "env guard after the fifth statement", kind: "test-skipped", file: "internal/a/a_test.go", marker: `os.Getenv("CI")`,
			edit: func(t *testing.T, m memTree) {
				m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }",
					"func TestA(t *testing.T) {\n\tA()\n\tA()\n\tA()\n\tA()\n\tA()\n\tA()\n\tif os.Getenv(\"CI\") != \"\" {\n\t\treturn\n\t}\n\tA()\n}")
			}},
		{name: "guard calls a helper that reads the environment", kind: "test-skipped", file: "internal/a/a_test.go", marker: "if ciOnly()",
			edit: func(t *testing.T, m memTree) {
				m["internal/a/env.go"] = "package a\n\nimport \"os\"\n\nfunc ciOnly() bool { return os.Getenv(\"CI\") != \"\" }\n"
				m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }", "func TestA(t *testing.T) {\n\tif ciOnly() {\n\t\treturn\n\t}\n\tA()\n}")
			}},
		{name: "guard calls a helper that reads testing.Short", kind: "test-skipped", file: "internal/a/a_test.go", marker: "if quick()",
			edit: func(t *testing.T, m memTree) {
				m["internal/a/env_test.go"] = "package a\n\nimport \"testing\"\n\nfunc quick() bool {\n\tshort := testing.Short()\n\treturn short\n}\n"
				m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }", "func TestA(t *testing.T) {\n\tif quick() {\n\t\treturn\n\t}\n\tA()\n}")
			}},
	}
}

func TestEveryWeakeningFailsWithFileLineAndKind(t *testing.T) {
	for _, w := range weakenings() {
		t.Run(w.name, func(t *testing.T) {
			base := goodRepo()
			head := base.clone()
			w.edit(t, head)
			fs := compare(t, base, head)
			src := head
			if w.inBase {
				src = base
			}
			wantLine := lineOf(t, src[w.file], w.marker)
			for _, f := range fs {
				if f.Rule == "gates/"+w.kind && f.File == w.file && f.Line == wantLine {
					if f.Severity != report.SevError {
						t.Errorf("severity = %q, want error", f.Severity)
					}
					if !strings.Contains(f.Fix, "gates-change-approved") || f.Message == "" {
						t.Errorf("finding must say what weakened and how to approve it: %+v", f)
					}
					if w.contains != "" && !strings.Contains(f.Message, w.contains) {
						t.Errorf("message %q lacks %q", f.Message, w.contains)
					}
					return
				}
			}
			t.Errorf("want gates/%s at %s:%d, got:\n%s", w.kind, w.file, wantLine, dump(fs))
		})
	}
}

func dump(fs []report.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "  %s %s:%d %s\n", f.Rule, f.File, f.Line, f.Message)
	}
	if b.Len() == 0 {
		return "  (no findings)"
	}
	return b.String()
}

// Tightening must pass: raising a bar, adding a test, adding a rule and
// shrinking the baseline are exactly what the gate wants more of.
func TestTighteningPasses(t *testing.T) {
	cases := []struct {
		name string
		edit func(t *testing.T, m memTree)
	}{
		{"nothing changed", func(*testing.T, memTree) {}},
		{"docs only", func(t *testing.T, m memTree) { m["docs/readme.md"] = "more docs\n" }},
		{"coverage raised", func(t *testing.T, m memTree) { m.replace(t, "scripts/check.sh", ":-70}", ":-80}") }},
		{"coverage raised with a CI override", func(t *testing.T, m memTree) {
			m.replace(t, ".github/workflows/ci.yml", "        run: scripts", "        env:\n          COVERAGE_MIN: 90\n        run: scripts")
		}},
		{"tool versions raised", func(t *testing.T, m memTree) {
			m.replace(t, "scripts/check.sh", "v2.12.2", "v2.13.0")
			m.replace(t, "scripts/check.sh", "v1.5.0", "v1.10.0")
		}},
		{"test added", func(t *testing.T, m memTree) {
			m["internal/a/a_test.go"] += "\nfunc TestC(t *testing.T) { A() }\n"
		}},
		{"test file added", func(t *testing.T, m memTree) {
			m["internal/a/c_test.go"] = "package a\n\nimport \"testing\"\n\nfunc TestC(t *testing.T) {}\n"
		}},
		{"integration test added behind its tag", func(t *testing.T, m memTree) {
			m["internal/a/i_test.go"] = "//go:build integration\n\npackage a\n"
		}},
		{"stage added", func(t *testing.T, m memTree) {
			m["scripts/check.sh"] += "banner \"extra (go build)\"\ngo build ./...\n"
		}},
		{"linter enabled", func(t *testing.T, m memTree) {
			m.replace(t, ".golangci.yml", "    - govet\n", "    - govet\n    - gosec\n")
		}},
		{"fuzz target added", func(t *testing.T, m memTree) { m["scripts/fuzz-targets.txt"] += "FuzzMore ./internal/a\n" }},
		{"rule added", func(t *testing.T, m memTree) {
			m["architecture.yaml"] += "  - id: L9\n    title: new\n    checker: archtest\n    fix: x\n"
		}},
		{"rule upgraded from planned", func(t *testing.T, m memTree) {
			m.replace(t, "architecture.yaml", "checker: planned\n    reason: no reasons file yet", "checker: archtest\n    fix: use constants")
		}},
		{"rule upgraded from proxy", func(t *testing.T, m memTree) {
			m.replace(t, "architecture.yaml", "checker: proxy\n    stage: benchmark", "checker: archtest+proxy\n    stage: benchmark")
		}},
		{"banned import added", func(t *testing.T, m memTree) {
			m.replace(t, "architecture.yaml", "[net, os, os/exec]", "[net, os, os/exec, io/fs]")
		}},
		{"coverage part upgraded", func(t *testing.T, m memTree) {
			m.replace(t, "architecture.yaml", "        planned: needs call-graph analysis\n", "        enforced: archtest\n")
		}},
		{"allowed place removed", func(t *testing.T, m memTree) {
			m.replace(t, "architecture.yaml", "    exec-allowed-in:\n      - repository\n", "    exec-allowed-in: []\n")
		}},
		{"baseline entry removed", func(t *testing.T, m memTree) {
			m.replace(t, "architecture.baseline.yaml", "  - rule: C3\n    package: examples/demo\n    why: demo binary\n", "")
		}},
		{"baseline allow item removed", func(t *testing.T, m memTree) {
			m.replace(t, "architecture.baseline.yaml", `["internal/analytics", "internal/integration"]`, `["internal/analytics"]`)
		}},
		{"baseline allow items reordered", func(t *testing.T, m memTree) {
			m.replace(t, "architecture.baseline.yaml", `["internal/analytics", "internal/integration"]`, `["internal/integration", "internal/analytics"]`)
		}},
		{"baseline reason reworded", func(t *testing.T, m memTree) {
			m.replace(t, "architecture.baseline.yaml", "why: demo binary", "why: still a demo")
		}},
		{"skip kept where it was", func(t *testing.T, m memTree) {
			m.replace(t, "internal/a/long_test.go", "func TestLong(t *testing.T) {\n", "// slow\nfunc TestLong(t *testing.T) {\n")
		}},
		{"existing nolint kept", func(t *testing.T, m memTree) {
			m.replace(t, "internal/a/a.go", "func A() {}", "func A() {} // doc")
		}},
		{"nolint removed", func(t *testing.T, m memTree) {
			m.replace(t, "internal/a/a.go", " //nolint:gosec // operator-provided path", "")
		}},
		{"prose mentioning nolint is not a directive", func(t *testing.T, m memTree) {
			m["internal/a/a.go"] += "\n// A is documented: use nolint sparingly, and #nosec never.\nfunc E() {}\n"
		}},
		{"unrelated workflow edited", func(t *testing.T, m memTree) { m.replace(t, ".github/workflows/other.yml", "echo hi", "echo bye") }},
		{"gate step gains a flag", func(t *testing.T, m memTree) {
			m.replace(t, ".github/workflows/ci.yml", "--json-out", "--keep-going --json-out")
		}},
		{"go test gains a flag", func(t *testing.T, m memTree) {
			m.replace(t, "scripts/check.sh", "go test -race -coverprofile=", "go test -race -count=1 -coverprofile=")
		}},
		{"package list widened", func(t *testing.T, m memTree) {
			m.replace(t, "scripts/check.sh", "PKGS=(./...)", "PKGS=(./... ./examples/...)")
		}},
		{"lint config swapped for a base file kept as is", func(t *testing.T, m memTree) {
			m.replace(t, "scripts/check.sh", "arch.yml ./...", "arch.yml --timeout 5m ./...")
		}},
		{"stage added with its own banner", func(t *testing.T, m memTree) {
			m["scripts/check.sh"] += "banner \"extra2 (go build)\"\ngo build ./...\n"
		}},
		{"non-test code reads the environment", func(t *testing.T, m memTree) {
			m["internal/a/a.go"] += "\nfunc E() {\n\tif os.Getenv(\"X\") != \"\" {\n\t\treturn\n\t}\n}\n"
		}},
		{"helper without a testing handle", func(t *testing.T, m memTree) {
			m["internal/a/helper.go"] = "package a\n\nfunc Setup(n int) {\n\tif n == 0 {\n\t\treturn\n\t}\n}\n"
		}},
		{"composite action raises the coverage minimum", func(t *testing.T, m memTree) {
			m[".github/actions/gate/action.yml"] = "name: gate\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      env:\n        COVERAGE_MIN: 90\n      run: scripts/check.sh\n"
		}},
		{"test with an early return that is not env driven", func(t *testing.T, m memTree) {
			m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }", "func TestA(t *testing.T) {\n\tn := 0\n\tif n > 1 {\n\t\treturn\n\t}\n\tA()\n}")
		}},
		{"guards of the base left as they are", func(t *testing.T, m memTree) {
			m["scripts/check.sh"] += "# a trailing comment\n"
		}},
		{"stage added after the guarded ones", func(t *testing.T, m memTree) {
			m["scripts/check.sh"] += "banner \"extra3 (go build)\"\ngo build ./...\n"
		}},
		{"canonical default line unchanged next to a raise", func(t *testing.T, m memTree) {
			m.replace(t, "scripts/check.sh", `GOLANGCI_VERSION="${GOLANGCI_VERSION:-v2.12.2}"`, `GOLANGCI_VERSION="${GOLANGCI_VERSION:-v2.13.0}"`)
		}},
		{"go vet gains a quoted argument", func(t *testing.T, m memTree) {
			m.replace(t, "scripts/check.sh", "go vet \"${PKGS[@]}\"\n", "go vet -tags \"a b\" \"${PKGS[@]}\"\n")
		}},
		{"test guard on a helper that does not read the environment", func(t *testing.T, m memTree) {
			m["internal/a/env.go"] = "package a\n\nfunc never() bool { return false }\n"
			m.replace(t, "internal/a/a_test.go", "func TestA(t *testing.T) { A() }", "func TestA(t *testing.T) {\n\tif never() {\n\t\treturn\n\t}\n\tA()\n}")
		}},
		{"new workflow added", func(t *testing.T, m memTree) {
			m[".github/workflows/risk.yml"] = "name: risk\non: pull_request\njobs:\n  x:\n    if: github.event_name == 'pull_request'\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo risk\n"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := goodRepo()
			head := base.clone()
			c.edit(t, head)
			if fs := compare(t, base, head); len(fs) != 0 {
				t.Errorf("a tightening change must pass, got:\n%s", dump(fs))
			}
		})
	}
}
