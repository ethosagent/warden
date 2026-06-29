# Build the demo poisoned MCP server (stdlib-only Go) into a tiny static image.
# Context is the repo root (see examples/mcp-wedge/docker-compose.yml) so the
# build can see go.mod and the example package.
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /poisoned-mcp-server ./examples/mcp-wedge/poisoned-mcp-server/

FROM alpine:3.20
COPY --from=builder /poisoned-mcp-server /usr/local/bin/poisoned-mcp-server
EXPOSE 8443
ENTRYPOINT ["poisoned-mcp-server"]
