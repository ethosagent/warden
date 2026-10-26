# Multi-stage build: compile in a Go builder, ship a single static binary.
# Base images are pinned by digest for reproducible, tamper-evident builds —
# bump the digest deliberately when upgrading. Match GO_VERSION to go.mod.
ARG GO_VERSION=1.26.10
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION is stamped into the binary (pass --build-arg VERSION=... to override;
# default suits local builds). The build flags live in scripts/build.sh so the
# image and host builds stay identical.
ARG VERSION=0.0.0-dev
# Cross-compile to the target platform from a native builder (fast, no QEMU for
# the compile): scripts/build.sh honors GOOS/GOARCH, which buildx populates via
# TARGETOS/TARGETARCH. A plain single-platform build sets them to the host.
ARG TARGETOS
ARG TARGETARCH
RUN VERSION="${VERSION}" GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" sh scripts/build.sh /warden

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates
RUN addgroup -S warden && adduser -S warden -G warden
# Writable data dir for the analytics db when a volume is mounted at /data.
# A fresh named volume mounted here inherits this ownership, so the non-root
# warden user can create/open the SQLite file.
RUN mkdir -p /data && chown warden:warden /data
COPY --from=builder /warden /usr/local/bin/warden
USER warden
ENTRYPOINT ["warden"]
