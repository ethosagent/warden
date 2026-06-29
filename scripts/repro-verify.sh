#!/bin/sh
# repro-verify.sh — prove the warden binary builds reproducibly.
#
# Builds the binary twice (via scripts/build.sh) from the current tree and
# asserts the two outputs are byte-identical by SHA-256. A pinned VERSION keeps
# the comparison independent of `git describe` output.
#
# Exit 0 + "reproducible" on match; exit 1 on mismatch.
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

VERSION="${VERSION:-repro}"
export VERSION

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

echo "build 1/2..."
scripts/build.sh "$tmp/warden-1"
echo "build 2/2..."
scripts/build.sh "$tmp/warden-2"

h1="$(sha256 "$tmp/warden-1")"
h2="$(sha256 "$tmp/warden-2")"
echo "sha256 #1: $h1"
echo "sha256 #2: $h2"

if [ "$h1" != "$h2" ]; then
	echo "FAIL: builds are NOT reproducible (SHA-256 differs)" >&2
	exit 1
fi
echo "OK: reproducible — identical SHA-256"
