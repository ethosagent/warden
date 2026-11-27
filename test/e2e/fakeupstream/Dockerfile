# Build the e2e fake upstream into a tiny static image. Context is the repo
# root (see deploy/compose/docker-compose.e2e.yml) so the build can see go.mod
# and internal/mcp/poisoned. Base images are pinned by digest — same pins as the
# root Dockerfile; bump deliberately when upgrading.
FROM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/mcp/poisoned/ internal/mcp/poisoned/
COPY test/e2e/fakeupstream/ test/e2e/fakeupstream/
COPY test/e2e/fakeaws/ test/e2e/fakeaws/
RUN CGO_ENABLED=0 go build -o /fakeupstream ./test/e2e/fakeupstream/
# The identity stack's fake AWS Secrets Manager (consent.store) rides the same
# image: docker-compose.e2e-identity.yml runs it with entrypoint fakeaws.
RUN CGO_ENABLED=0 go build -o /fakeaws ./test/e2e/fakeaws/

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=builder /fakeupstream /usr/local/bin/fakeupstream
COPY --from=builder /fakeaws /usr/local/bin/fakeaws
# Same non-root pattern as the warden image. The fake upstream binds 443 and 53
# (both < 1024); docker-compose.e2e.yml grants that with the per-container
# sysctl net.ipv4.ip_unprivileged_port_start=0 — no capabilities involved.
RUN addgroup -S fakeupstream && adduser -S fakeupstream -G fakeupstream
USER fakeupstream
EXPOSE 443 8081 53
ENTRYPOINT ["fakeupstream"]
