# Warden — thin wrappers over scripts/. The real logic lives in scripts/check.sh
# so CI, git hooks, and `make` all run the identical gate.

.PHONY: build test check integration hooks fmt lint repro

build:
	scripts/build.sh warden

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

repro:
	scripts/repro-verify.sh
