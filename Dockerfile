# Multi-stage build: compile in a Go builder, ship a single static binary.
# Match GO_VERSION to go.mod; pass --build-arg GO_VERSION=X.Y to override
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /warden ./cmd/proxy

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
RUN addgroup -S warden && adduser -S warden -G warden
COPY --from=builder /warden /usr/local/bin/warden
USER warden
ENTRYPOINT ["warden"]
