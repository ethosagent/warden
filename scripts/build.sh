#!/bin/sh
# build.sh — the single source of truth for building the warden binary.
#
# Used by the Makefile, the Dockerfile, scripts/repro-verify.sh, and release
# builds so every binary is produced identically. Reproducible by construction:
#
#   -trimpath      strip absolute filesystem paths from the binary
#   -buildid=      clear the (non-deterministic) build id
#   -s -w          drop the symbol table and DWARF debug info
#   CGO_ENABLED=0  pure-Go static binary, no C toolchain in the trust boundary
#
# Same commit + same Go toolchain => byte-identical binary
# (verify with scripts/repro-verify.sh).
#
# Usage: scripts/build.sh [output-path]   (default: ./warden)
# Env:   VERSION   stamped into main.version (default: `git describe`, else 0.0.0-dev)
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

out="${1:-warden}"
if [ -z "${VERSION:-}" ]; then
	VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)"
fi

CGO_ENABLED=0 go build \
	-trimpath \
	-ldflags "-s -w -buildid= -X main.version=${VERSION}" \
	-o "$out" \
	./cmd/proxy
