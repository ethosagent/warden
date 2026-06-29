# Multi-stage build: compile in a Go builder, ship a single static binary.
# Base images are pinned by digest for reproducible, tamper-evident builds —
# bump the digest deliberately when upgrading. Match GO_VERSION to go.mod.
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION is stamped into the binary (pass --build-arg VERSION=... to override;
# default suits local builds). The build flags live in scripts/build.sh so the
# image and host builds stay identical.
ARG VERSION=0.0.0-dev
RUN VERSION="${VERSION}" sh scripts/build.sh /warden

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache ca-certificates
RUN addgroup -S warden && adduser -S warden -G warden
# Writable data dir for the analytics db when a volume is mounted at /data.
# A fresh named volume mounted here inherits this ownership, so the non-root
# warden user can create/open the SQLite file.
RUN mkdir -p /data && chown warden:warden /data
COPY --from=builder /warden /usr/local/bin/warden
USER warden
ENTRYPOINT ["warden"]
