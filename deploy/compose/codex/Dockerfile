# Codex CLI agent image for deploy/compose/docker-compose.codex.yml.
#
# The agent holds NOTHING secret: the compose file hands it only a placeholder
# API key, the proxy CA certificate (public) and the forwarder URL. No Warden
# token, Dex token, agent key or real vendor key is ever in this image or its
# environment.
#
# Base image pinned by tag AND digest (reproducible, tamper-evident); bump both
# deliberately. Node is only the launcher (bin/codex.js); the CLI is a static
# native binary.
FROM node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57

# Exact version, at least two weeks old at the time of pinning (published
# 2026-11-11). The launcher package and the platform package that carries the
# native binary are fetched with `npm pack` and checked against the registry's
# published dist.integrity (sha512) before anything is installed (one platform
# value per CPU architecture). The platform package is not installed through npm:
# its vendor/ tree is unpacked into the launcher package, where codex.js looks
# for it when the optional platform dependency is absent.
ARG TARGETARCH
ARG CODEX_VERSION=0.167.2
ARG CODEX_INTEGRITY=sha512-6OFkr2ndzTdFb32OEiUlM9BgpeY8+wnMe8vRhuvt+22TnxVR39KnJ22Ghay98IY9OmEltoNgFN4GALUkxFQCOw==
ARG CODEX_INTEGRITY_AMD64=sha512-2Rw3VkWonMxwCSgOw+NkiKLOuOzyoQNWmxU7x8GniesdMfhKc4asNqOzTgQwJLKCrSlPc4/6fYTaH7fYcuGWGQ==
ARG CODEX_INTEGRITY_ARM64=sha512-x/PhPRq0X+hBZDqXKE0YIm4NZoSyCF99KcJJWRn0B2WNdmYk3eBDtjNO5+wl7zWMCBwjTOev5Tz2ZZ6+Y14YQA==
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) plat=linux-x64;   want_plat="$CODEX_INTEGRITY_AMD64" ;; \
      arm64) plat=linux-arm64; want_plat="$CODEX_INTEGRITY_ARM64" ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir /tmp/cx && cd /tmp/cx; \
    npm pack "@openai/codex@${CODEX_VERSION}" "@openai/codex@${CODEX_VERSION}-${plat}" >/dev/null; \
    check() { got="sha512-$(node -e 'process.stdout.write(require("crypto").createHash("sha512").update(require("fs").readFileSync(process.argv[1])).digest("base64"))' "$1")"; \
              [ "$got" = "$2" ] || { echo "integrity mismatch for $1" >&2; exit 1; }; }; \
    check "openai-codex-${CODEX_VERSION}.tgz" "$CODEX_INTEGRITY"; \
    check "openai-codex-${CODEX_VERSION}-${plat}.tgz" "$want_plat"; \
    npm install -g --no-audit --no-fund --omit=optional "./openai-codex-${CODEX_VERSION}.tgz"; \
    tar -xzf "openai-codex-${CODEX_VERSION}-${plat}.tgz" -C "$(npm root -g)/@openai/codex" --strip-components=1 package/vendor; \
    cd /; rm -rf /tmp/cx; npm cache clean --force; \
    codex --version

# curl for the isolation checks in docs/recipes/codex.md. bubblewrap stays out:
# the pinned release ships its own bwrap, and the container is the sandbox.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Non-root user with its own home and a workspace directory. Named volumes
# mounted here inherit this ownership.
RUN useradd --uid 10001 --create-home --shell /bin/bash agent \
 && mkdir -p /workspace && chown agent:agent /workspace
USER agent
WORKDIR /workspace

# Verified against @openai/codex 0.167.2 (see docs/recipes/codex.md): the CLI
# honours HTTPS_PROXY / NO_PROXY, trusts the CA named by CODEX_CA_CERTIFICATE
# (then SSL_CERT_FILE), and `codex exec` authenticates with OPENAI_API_KEY. The
# compose file sets HTTPS_PROXY (it carries the forwarder credential) and mounts
# the CA at the path below.
ENV NO_PROXY=localhost,127.0.0.1,::1 \
    CODEX_CA_CERTIFICATE=/etc/warden/certs/proxy-ca.crt \
    SSL_CERT_FILE=/etc/warden/certs/proxy-ca.crt \
    OPENAI_API_KEY=openai_secret_001

CMD ["sleep", "infinity"]
