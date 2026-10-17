#!/usr/bin/env bash
#
# check.sh — the single source of truth for "is this green?".
#
# CI (.github/workflows/ci.yml) and the pre-push git hook both call THIS script,
# so "passes locally, fails in CI" is structurally impossible.
#
# Usage:
#   scripts/check.sh [--integration] [--json] [--json-out <path>] [--keep-going]
#
#   (no flags)        human output, stop at the first failing stage
#   --json            ONE warden.check.v1 JSON report on stdout (schema:
#                     docs/check-report.schema.json); human progress goes to
#                     stderr. Implies --keep-going.
#   --json-out PATH   human output as usual, plus the report written to PATH
#   --keep-going      run every stage after a failure, so all problems show in
#                     one pass
#
# The flags only change what is reported. The pass/fail verdict, and so the exit
# code, is the same as without them (0 pass, non-zero fail). Agents: run
# `scripts/check.sh --json` and fix the findings in order.
#
# Env:
#   COVERAGE_MIN          minimum total coverage percent (default: 70)
#   GOVULNCHECK_VERSION   pinned govulncheck version to run (default: v1.5.0)
#   GOLANGCI_VERSION      pinned golangci-lint version to run (default: v2.12.2)
set -euo pipefail

cd "$(dirname "$0")/.."

COVERAGE_MIN="${COVERAGE_MIN:-70}"
GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-v1.5.0}"
GOLANGCI_VERSION="${GOLANGCI_VERSION:-v2.12.2}"
RUN_INTEGRATION=0
JSON=0
JSON_OUT=""
KEEP_GOING=0
while [ "$#" -gt 0 ]; do
	case "$1" in
	--integration) RUN_INTEGRATION=1 ;;
	--json) JSON=1 ;;
	--keep-going) KEEP_GOING=1 ;;
	--json-out)
		if [ "$#" -lt 2 ]; then
			echo "--json-out requires a path" >&2
			exit 2
		fi
		JSON_OUT="$2"
		shift
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
	shift
done

# Report mode: tools/checkreport runs the same stages (tools/checkreport/
# checksh_test.go keeps the two lists in step) and emits the JSON report. The
# plain path below is untouched, so its output cannot change.
if [ "$JSON" -eq 1 ] || [ -n "$JSON_OUT" ] || [ "$KEEP_GOING" -eq 1 ]; then
	tmpbin="$(mktemp -d)"
	trap 'rm -rf "$tmpbin"' EXIT
	if ! go build -o "$tmpbin/checkreport" ./tools/checkreport; then
		# The report must still be one valid document when the reporter itself is broken.
		echo "check.sh: tools/checkreport does not compile" >&2
		crash='{"schema":"warden.check.v1","ok":false,"durationMs":0,"stages":[{"name":"setup","tool":"go build","ok":false,"durationMs":0,"findings":[{"rule":"stage/crashed","severity":"error","message":"tools/checkreport did not compile","fix":"run `go build ./tools/checkreport` and fix the compile error"}]}]}'
		if [ "$JSON" -eq 1 ]; then printf '%s\n' "$crash"; fi
		if [ -n "$JSON_OUT" ]; then printf '%s\n' "$crash" >"$JSON_OUT"; fi
		exit 1
	fi
	report_args=(-coverage-min "$COVERAGE_MIN" -golangci-version "$GOLANGCI_VERSION" -govulncheck-version "$GOVULNCHECK_VERSION")
	if [ "$RUN_INTEGRATION" -eq 1 ]; then report_args+=(-integration); fi
	if [ "$KEEP_GOING" -eq 1 ]; then report_args+=(-keep-going); fi
	if [ "$JSON" -eq 1 ]; then report_args+=(-json); fi
	if [ -n "$JSON_OUT" ]; then report_args+=(-json-out "$JSON_OUT"); fi
	"$tmpbin/checkreport" "${report_args[@]}" || exit $?
	exit 0
fi

banner() { printf '\n=== %s ===\n' "$1"; }

# 1. format check
banner "format (gofmt)"
unformatted="$(gofmt -l . | grep -v '^vendor/' || true)"
if [ -n "$unformatted" ]; then
	echo "gofmt found unformatted files:" >&2
	echo "$unformatted" >&2
	echo "hint: run 'gofmt -w .'" >&2
	exit 1
fi
echo "ok"

# 2. vet
banner "vet (go vet ./...)"
go vet ./...
echo "ok"

# 3. lint (golangci-lint, pinned + always-run)
#
# Run via `go run` at a pinned version so local dev, the pre-push hook, and CI
# all run the SAME linter version (no `@latest` drift) and lint never silently
# skips when the tool isn't on PATH — that skip is what let CI catch issues a
# local run didn't.
banner "lint (golangci-lint ${GOLANGCI_VERSION})"
go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION}" run
echo "ok"

# 3b. roadmap docs are generated from docs/roadmap/tickets.json; fail if
# the data is invalid or a generated file was hand-edited or not regenerated.
banner "roadmap (go run docs/roadmap/gen.go check)"
go run docs/roadmap/gen.go check

# 4. build
banner "build (go build ./...)"
go build ./...
echo "ok"

# 5. vulnerability scan (govulncheck, pinned + always-run)
#
# A security gate must not silently skip when the tool is absent (unlike the
# lint stage above), so run it via `go run` at a pinned version: always present,
# reproducible, and no separate install step. CI inherits this by calling
# check.sh — no workflow change needed.
banner "vulncheck (govulncheck ${GOVULNCHECK_VERSION})"
go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...
echo "ok"

# 6. test + race + coverage profile
banner "test (go test -race -coverprofile)"
go test -race -coverprofile=coverage.out ./...
echo "ok"

# 7. benchmark smoke (compile + run once; NOT gated on ns/op)
#
# The hot-path benchmarks are the regression tripwire for the scalability work.
# Run them at -benchtime=1x (one iteration each) so they are guaranteed to
# compile and not panic on every gate, without measurably slowing it. This step
# fails ONLY on a build error or a panic — never on performance numbers.
banner "benchmark smoke (go test -bench . -benchtime=1x)"
go test -run '^$' -bench . -benchtime=1x ./... >/dev/null
echo "ok"

# 8. coverage gate
banner "coverage gate (min ${COVERAGE_MIN}%)"
# Product code only: tools/ (developer tooling such as tools/checkreport) is
# tested above but must not lift the number that gates a product regression.
module="$(awk '/^module / {print $2}' go.mod)"
{ awk -v p="${module}/tools/" 'index($0, p) != 1' coverage.out || true; } >coverage.product.out
total="$(go tool cover -func=coverage.product.out | awk '/^total:/ {gsub("%","",$3); print $3}')"
echo "total coverage: ${total}%"
if awk "BEGIN { exit !(${total} < ${COVERAGE_MIN}) }"; then
	echo "coverage ${total}% is below minimum ${COVERAGE_MIN}%" >&2
	exit 1
fi
echo "ok"

# 9. integration (opt-in)
if [ "$RUN_INTEGRATION" -eq 1 ]; then
	banner "integration (go test -tags=integration)"
	go test -tags=integration ./test/integration/...
	echo "ok"
fi

banner "all checks passed"
