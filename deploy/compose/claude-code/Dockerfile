# Claude Code agent image for deploy/compose/docker-compose.claude-code.yml.
#
# The agent holds NOTHING secret: the compose file hands it only a placeholder
# API key, the proxy CA certificate (public) and the forwarder URL. No Warden
# token, Dex token, agent key or real vendor key is ever in this image or its
# environment.
#
# Base image pinned by tag AND digest (reproducible, tamper-evident); bump both
# deliberately. Node 24 is needed for NODE_USE_ENV_PROXY on node-based tools the
# agent runs; the Claude Code binary itself is native.
FROM node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57

# Exact version, at least two weeks old at the time of pinning (published
# 2026-11-10). npm resolves the matching native binary package for this
# platform from the optionalDependencies of this exact version.
ARG CLAUDE_CODE_VERSION=2.1.322
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force

# curl for the isolation checks in docs/recipes/claude-code.md (and the proof script).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Non-root user with its own home and a workspace directory. Named volumes
# mounted here inherit this ownership.
RUN useradd --uid 10001 --create-home --shell /bin/bash agent \
 && mkdir -p /workspace && chown agent:agent /workspace
USER agent
WORKDIR /workspace

# Variable names confirmed against @anthropic-ai/claude-code 2.1.322 (strings in
# the native binary): HTTPS_PROXY, NO_PROXY, NODE_EXTRA_CA_CERTS,
# NODE_USE_ENV_PROXY, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC,
# DISABLE_AUTOUPDATER, ANTHROPIC_API_KEY. The compose file sets HTTPS_PROXY
# (it carries the forwarder credential) and mounts the CA at the path below.
ENV NO_PROXY=localhost,127.0.0.1,::1 \
    NODE_EXTRA_CA_CERTS=/etc/warden/certs/proxy-ca.crt \
    NODE_USE_ENV_PROXY=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_AUTOUPDATER=1 \
    ANTHROPIC_API_KEY=anthropic_secret_001

CMD ["sleep", "infinity"]
