# Warden — thin wrappers over scripts/. The real logic lives in scripts/check.sh
# so CI, git hooks, and `make` all run the identical gate.

.PHONY: build test check integration hooks fmt lint repro release release-dry version

build:
	scripts/build.sh warden

test:
	go test -race ./...

check:
	scripts/check.sh

integration:
	scripts/check.sh --integration

hooks:
	scripts/install-hooks.sh

fmt:
	gofmt -w .

lint:
	golangci-lint run

repro:
	scripts/repro-verify.sh

# ---------- release (tag-driven) ----------
# The git tag IS the version — scripts/build.sh stamps it via `git describe`,
# there is no VERSION file. Pushing a vX.Y.Z tag triggers
# .github/workflows/release.yml (signed binaries + SBOM + provenance + GitHub
# Release + multi-arch signed GHCR image). See RELEASE.md.
#
#   make release VERSION=1.2.3        cut + push the tag (CI does the rest)
#   make release-dry VERSION=1.2.3    preview, no side effects
#   make version                      what the current commit builds as

version:
	@git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev

release-dry:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release-dry VERSION=1.2.3"; exit 1; fi
	@echo "=== Release dry run for v$(VERSION) ==="
	@echo ""
	@echo "Pre-flight checks that would run:"
	@echo "  1. clean working tree            (git status --porcelain empty)"
	@echo "  2. HEAD == origin/main           (release only from pushed main)"
	@echo "  3. tag v$(VERSION) unused        (local + remote)"
	@echo "  4. scripts/check.sh              (fmt, vet, lint, govulncheck, build, race tests, coverage)"
	@echo ""
	@echo "Then:"
	@echo "  5. git tag -a v$(VERSION)"
	@echo "  6. git push origin v$(VERSION)   <- triggers .github/workflows/release.yml"
	@echo ""
	@echo "CI then publishes: signed binaries (cosign) + CycloneDX SBOM + SLSA"
	@echo "provenance + GitHub Release, and a multi-arch signed image to GHCR."

release:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release VERSION=1.2.3"; exit 1; fi
	@echo "==> Releasing v$(VERSION)"
	@test -z "$$(git status --porcelain)" || { echo "ERROR: working tree not clean — commit or stash first"; exit 1; }
	@git fetch --quiet origin
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/main)" || { echo "ERROR: HEAD is not origin/main — release from a clean, pushed main"; exit 1; }
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1 || git ls-remote --exit-code --tags origin "v$(VERSION)" >/dev/null 2>&1; then \
		echo "ERROR: tag v$(VERSION) already exists (local or remote)"; exit 1; fi
	@echo "==> Running full gate (scripts/check.sh)"
	@scripts/check.sh
	@echo "==> Tagging v$(VERSION) and pushing (triggers the release workflow)"
	@git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	@git push origin "v$(VERSION)"
	@echo ""
	@echo "✓ Pushed tag v$(VERSION). Watch it: gh run watch  (or the Actions tab)."
	@echo "  When done, verify per RELEASE.md (cosign verify / gh attestation verify)."
