#!/usr/bin/env bash
#
# check.sh — the single source of truth for "is this green?".
#
# CI (.github/workflows/ci.yml) and the pre-push git hook both call THIS script,
# so "passes locally, fails in CI" is structurally impossible.
#
# Usage:
#   scripts/check.sh [--fast] [--integration] [--json] [--json-out <path>] [--keep-going]
#
#   --fast            INNER LOOP ONLY. Checks just the packages changed since
#                     origin/main (committed, staged, unstaged and untracked) plus
#                     every package that imports them, in its code or its tests:
#                     format, vet, lint and `go test -race` on those packages. It
#                     skips roadmap, build, govulncheck, fuzz, the benchmark smoke
#                     run and the coverage gate, so a green --fast is NOT a green
#                     gate. CI and the pre-push hook run the full gate. With
#                     --json the report's "fast" object lists the packages and why.
#                     If origin/main is missing (shallow clone) it runs the full
#                     gate and says so. Cannot be combined with --integration.
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
#   FUZZTIME              -fuzztime for each fuzz target (default: 5s); the targets
#                         are listed in scripts/fuzz-targets.txt
#   GOVULNCHECK_VERSION   pinned govulncheck version to run (default: v1.5.0)
#   GOLANGCI_VERSION      pinned golangci-lint version to run (default: v2.12.2)
set -euo pipefail

cd "$(dirname "$0")/.."

COVERAGE_MIN="${COVERAGE_MIN:-70}"
GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-v1.5.0}"
GOLANGCI_VERSION="${GOLANGCI_VERSION:-v2.12.2}"
FUZZTIME="${FUZZTIME:-5s}"
FAST=0
RUN_INTEGRATION=0
JSON=0
JSON_OUT=""
KEEP_GOING=0
while [ "$#" -gt 0 ]; do
	case "$1" in
	--integration) RUN_INTEGRATION=1 ;;
	--fast) FAST=1 ;;
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

if [ "$FAST" -eq 1 ] && [ "$RUN_INTEGRATION" -eq 1 ]; then
	echo "--fast cannot be combined with --integration: --fast is the inner loop, the full gate is what CI runs" >&2
	exit 2
fi

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
	report_args=(-coverage-min "$COVERAGE_MIN" -golangci-version "$GOLANGCI_VERSION" -govulncheck-version "$GOVULNCHECK_VERSION" -fuzz-time "$FUZZTIME")
	if [ "$FAST" -eq 1 ]; then report_args+=(-fast); fi
	if [ "$RUN_INTEGRATION" -eq 1 ]; then report_args+=(-integration); fi
	if [ "$KEEP_GOING" -eq 1 ]; then report_args+=(-keep-going); fi
	if [ "$JSON" -eq 1 ]; then report_args+=(-json); fi
	if [ -n "$JSON_OUT" ]; then report_args+=(-json-out "$JSON_OUT"); fi
	"$tmpbin/checkreport" "${report_args[@]}" || exit $?
	exit 0
fi

banner() { printf '\n=== %s ===\n' "$1"; }

# --fast (plain mode): ask tools/checkreport for the package plan, so this path and
# the report path (which computes the same plan itself) cannot disagree about
# what "changed" means. PKGS stays (./...) for the full gate.
PKGS=(./...)
LINT_PKGS=()
PKG_STAGES=1
if [ "$FAST" -eq 1 ]; then
	tmpbin="$(mktemp -d)"
	trap 'rm -rf "$tmpbin"' EXIT
	go build -o "$tmpbin/checkreport" ./tools/checkreport
	plan="$("$tmpbin/checkreport" -fast-plan)"
	kind="$(printf '%s\n' "$plan" | head -n1 | cut -f1)"
	if [ "$kind" = "full" ]; then
		echo "fast: running the FULL gate: $(printf '%s\n' "$plan" | head -n1 | cut -f2)"
		FAST=0
	else
		PKGS=()
		plan_lines=()
		while IFS=$'\t' read -r _ dir reason; do
			[ -n "$dir" ] || continue
			pkg="./$dir"
			if [ "$dir" = "." ]; then pkg="."; fi
			PKGS+=("$pkg")
			plan_lines+=("  $pkg  ($reason)")
		done < <(printf '%s\n' "$plan" | tail -n +2)
		echo "fast: ${#PKGS[@]} package(s) against $(printf '%s\n' "$plan" | head -n1 | cut -f2)"
		if [ "${#plan_lines[@]}" -gt 0 ]; then printf '%s\n' "${plan_lines[@]}"; fi
		LINT_PKGS=("${PKGS[@]}")
		if [ "${#PKGS[@]}" -eq 0 ]; then
			echo "  no Go package changed: only the format check runs"
			PKG_STAGES=0
		fi
	fi
fi

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
if [ "$PKG_STAGES" -eq 1 ]; then
	banner "vet (go vet ./...)"
	go vet "${PKGS[@]}"
	echo "ok"
fi

# 3. lint (golangci-lint, pinned + always-run)
#
# Run via `go run` at a pinned version so local dev, the pre-push hook, and CI
# all run the SAME linter version (no `@latest` drift) and lint never silently
# skips when the tool isn't on PATH — that skip is what let CI catch issues a
# local run didn't.
if [ "$PKG_STAGES" -eq 1 ]; then
	banner "lint (golangci-lint ${GOLANGCI_VERSION})"
	go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION}" run ${LINT_PKGS[@]+"${LINT_PKGS[@]}"}
	echo "ok"
fi

if [ "$FAST" -eq 0 ]; then
	# 3b. roadmap docs are generated from docs/roadmap/tickets.json; fail if
	# the data is invalid or a generated file was hand-edited or not regenerated.
	banner "roadmap (go run docs/roadmap/gen.go check)"
	go run docs/roadmap/gen.go check

	# 4. build
	banner "build (go build ./...)"
	go build ./...
	echo "ok"
fi

if [ "$FAST" -eq 0 ]; then
	# 5. vulnerability scan (govulncheck, pinned + always-run)
	#
	# A security gate must not silently skip when the tool is absent (unlike the
	# lint stage above), so run it via `go run` at a pinned version: always present,
	# reproducible, and no separate install step. CI inherits this by calling
	# check.sh — no workflow change needed.
	banner "vulncheck (govulncheck ${GOVULNCHECK_VERSION})"
	go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...
	echo "ok"
fi

# 6. test + race + coverage profile (--fast: just the planned packages, no profile)
if [ "$PKG_STAGES" -eq 1 ]; then
	banner "test (go test -race -coverprofile)"
	if [ "$FAST" -eq 1 ]; then
		go test -race "${PKGS[@]}"
	else
		go test -race -coverprofile=coverage.out ./...
	fi
	echo "ok"
fi

if [ "$FAST" -eq 0 ]; then
	# 6b. fuzz: each target in scripts/fuzz-targets.txt for a short fixed time
	#
	# The seed corpora (testdata/fuzz/) already replay in the test stage above; this
	# adds ${FUZZTIME} of mutation per target. The nightly workflow runs the same
	# targets for minutes and uploads any crasher. A failing target writes its
	# crasher under the package's testdata/fuzz/; do not delete it — see the
	# finding's fix text, and treat a crash in policy/CONNECT/MCP as a security bug.
	banner "fuzz (go test -fuzz, ${FUZZTIME} per target)"
	fuzz_count=0
	while read -r fuzz_name fuzz_pkg; do
		case "$fuzz_name" in "" | \#*) continue ;; esac
		go test -run '^$' -fuzz "^${fuzz_name}\$" -fuzztime="$FUZZTIME" "$fuzz_pkg"
		fuzz_count=$((fuzz_count + 1))
	done <scripts/fuzz-targets.txt
	echo "fuzz budget: ${fuzz_count} target(s) x ${FUZZTIME}"
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
fi

# 9. integration (opt-in)
if [ "$RUN_INTEGRATION" -eq 1 ]; then
	banner "integration (go test -tags=integration)"
	go test -tags=integration ./test/integration/...
	echo "ok"
fi

banner "all checks passed"
