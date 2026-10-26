# Build the e2e fake upstream into a tiny static image. Context is the repo
# root (see deploy/compose/docker-compose.e2e.yml) so the build can see go.mod
# and internal/mcp/poisoned. Base images are pinned by digest — same pins as the
# root Dockerfile; bump deliberately when upgrading.
FROM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/mcp/poisoned/ internal/mcp/poisoned/
COPY test/e2e/fakeupstream/ test/e2e/fakeupstream/
RUN CGO_ENABLED=0 go build -o /fakeupstream ./test/e2e/fakeupstream/

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=builder /fakeupstream /usr/local/bin/fakeupstream
# Same non-root pattern as the warden image. The fake upstream binds 443 and 53
# (both < 1024); docker-compose.e2e.yml grants that with the per-container
# sysctl net.ipv4.ip_unprivileged_port_start=0 — no capabilities involved.
RUN addgroup -S fakeupstream && adduser -S fakeupstream -G fakeupstream
USER fakeupstream
EXPOSE 443 8081 53
ENTRYPOINT ["fakeupstream"]
