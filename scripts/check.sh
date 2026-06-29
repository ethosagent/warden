#!/usr/bin/env bash
#
# check.sh — the single source of truth for "is this green?".
#
# CI (.github/workflows/ci.yml) and the pre-push git hook both call THIS script,
# so "passes locally, fails in CI" is structurally impossible.
#
# Usage:
#   scripts/check.sh [--integration]
#
# Env:
#   COVERAGE_MIN          minimum total coverage percent (default: 70)
#   GOVULNCHECK_VERSION   pinned govulncheck version to run (default: v1.5.0)
set -euo pipefail

cd "$(dirname "$0")/.."

COVERAGE_MIN="${COVERAGE_MIN:-70}"
GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-v1.5.0}"
RUN_INTEGRATION=0
for arg in "$@"; do
	case "$arg" in
	--integration) RUN_INTEGRATION=1 ;;
	*)
		echo "unknown argument: $arg" >&2
		exit 2
		;;
	esac
done

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

# 3. lint
banner "lint (golangci-lint)"
if command -v golangci-lint >/dev/null 2>&1; then
	golangci-lint run
	echo "ok"
else
	echo "golangci-lint not installed — skipping (CI installs it)."
fi

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

# 7. coverage gate
banner "coverage gate (min ${COVERAGE_MIN}%)"
total="$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$3); print $3}')"
echo "total coverage: ${total}%"
if awk "BEGIN { exit !(${total} < ${COVERAGE_MIN}) }"; then
	echo "coverage ${total}% is below minimum ${COVERAGE_MIN}%" >&2
	exit 1
fi
echo "ok"

# 8. integration (opt-in)
if [ "$RUN_INTEGRATION" -eq 1 ]; then
	banner "integration (go test -tags=integration)"
	go test -tags=integration ./test/integration/...
	echo "ok"
fi

banner "all checks passed"
