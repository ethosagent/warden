# Warden — thin wrappers over scripts/. The real logic lives in scripts/check.sh
# so CI, git hooks, and `make` all run the identical gate.

.PHONY: build test check integration hooks fmt lint repro release release-dry version e2e-up e2e-down e2e-certs e2e e2e-scenario

# ---------- e2e harness (issue #366, L2 part 1) ----------
# The hermetic compose stack: control plane + 2 workers + 2 agents + the fake
# upstream (api/llm/mcp/evil.example.test, request recorder, fake DNS), all
# built from source, all scenario networks internal. deploy/compose/
# docker-compose.e2e.yml is the override; configs/config.e2e-*.yaml the policy.
# The scenario driver itself lands in part 2 (#367); today you drive the stack
# by hand (docs/docker-end-to-end.md, "Hermetic e2e harness").

E2E_COMPOSE := -f deploy/compose/docker-compose.control-plane.yml -f deploy/compose/docker-compose.e2e.yml

# Every file gen.sh produces; e2e-up regenerates when ANY one is missing, not
# only the CA cert (a half-populated certs dir would boot a broken stack).
E2E_CERTS := proxy-ca.crt proxy-ca.key upstream-ca.crt upstream-ca.key \
             upstream-server.crt upstream-server.key upstream-ca-bundle.crt

# up --build unless WARDEN_IMAGE is set: the build cache makes a no-op rebuild
# fast, and a source edit ALWAYS reaches the containers (a pre-existing image
# tag must never shadow the checkout — that is how a harness tests stale code).
# With WARDEN_IMAGE set nothing is built (--no-build) and both images must
# already exist, or e2e-up fails before starting anything.
e2e-up: e2e-certs
	if [ -n "$$WARDEN_IMAGE" ]; then \
		docker image inspect "$$WARDEN_IMAGE" >/dev/null 2>&1 || { echo "e2e: WARDEN_IMAGE=$$WARDEN_IMAGE is not present locally; build or pull it first, or unset WARDEN_IMAGE to build from source" >&2; exit 1; }; \
		docker image inspect warden-e2e-fakeupstream:local >/dev/null 2>&1 || { echo "e2e: WARDEN_IMAGE is set (--no-build) but warden-e2e-fakeupstream:local is missing; run one 'make e2e-up' without WARDEN_IMAGE to build it" >&2; exit 1; }; \
		docker compose $(E2E_COMPOSE) up -d --wait --no-build; \
	else \
		docker compose $(E2E_COMPOSE) up -d --build --wait; \
	fi
	test/e2e/hermeticity.sh

e2e-down:
	docker compose $(E2E_COMPOSE) down -v

# Idempotent cert generation: gen.sh refuses to overwrite existing keys.
.PHONY: e2e-certs
e2e-certs:
	@missing=""; \
	for f in $(E2E_CERTS); do \
		[ -f test/e2e/certs/$$f ] || missing="$$missing $$f"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "e2e: (re)generating certs; missing:$$missing"; \
		test/e2e/certs/gen.sh; \
	fi

e2e e2e-scenario:
	@echo "e2e scenarios land in part 2 (issue #367) — the stack is up; drive it by hand for now."

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
	golangci-lint run --config .golangci.arch.yml

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
