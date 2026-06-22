#!/usr/bin/env bash
#
# install-hooks.sh — point git at the repo's .githooks directory and make the
# hooks executable. Run once after cloning.
set -euo pipefail

cd "$(dirname "$0")/.."

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true

echo "git hooks installed (core.hooksPath = .githooks)"
echo "active hooks:"
echo "  pre-commit : fast subset (gofmt + go vet + golangci-lint if installed)"
echo "  pre-push   : full gate (scripts/check.sh — same as CI)"
