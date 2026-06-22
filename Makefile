# Warden — thin wrappers over scripts/. The real logic lives in scripts/check.sh
# so CI, git hooks, and `make` all run the identical gate.

.PHONY: build test check integration hooks fmt lint

build:
	go build -o warden ./cmd/proxy

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
	golangci-lint run
