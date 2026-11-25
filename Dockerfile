# Multi-stage build: compile in a Go builder, ship a single static binary.
# Base images are pinned by digest for reproducible, tamper-evident builds —
# bump the digest deliberately when upgrading. Match GO_VERSION to go.mod.
ARG GO_VERSION=1.26.11
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS builder
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

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates
RUN addgroup -S warden && adduser -S warden -G warden
# Writable data dir for the analytics db when a volume is mounted at /data.
# A fresh named volume mounted here inherits this ownership, so the non-root
# warden user can create/open the SQLite file.
RUN mkdir -p /data && chown warden:warden /data
# Worker CA directory (the compose recipe's cp-ca volume): same inheritance, so
# `warden control-plane ca init --out-dir /ca` can write it as the warden user.
RUN mkdir -p /ca && chown warden:warden /ca
COPY --from=builder /warden /usr/local/bin/warden
USER warden
ENTRYPOINT ["warden"]
