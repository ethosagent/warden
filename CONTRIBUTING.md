# Contributing to Warden

Thanks for contributing. Warden is a security tool, so the bar is correctness +
tests, not feature velocity. The checklist below mirrors `scripts/check.sh` —
the same gate CI runs.

## One-time setup

```sh
scripts/install-hooks.sh   # pre-commit (fast) + pre-push (full gate)
```

## PR checklist

Run the full gate before opening a PR:

```sh
scripts/check.sh           # add --integration to include tagged e2e tests
```

That script runs, in order — and your PR must pass every stage:

- [ ] **Format** — `gofmt -l .` is clean (run `gofmt -w .` to fix).
- [ ] **Vet** — `go vet ./...` passes.
- [ ] **Lint** — `golangci-lint run` passes (CI installs it; locally it is
      skipped if absent).
- [ ] **Build** — `go build ./...` succeeds.
- [ ] **Test + race** — `go test -race ./...` passes.
- [ ] **Coverage gate** — total coverage ≥ `COVERAGE_MIN` (default 70).
- [ ] **Integration** (if relevant) — `scripts/check.sh --integration`.

## Conventions (enforced in review)

- **Test-first.** New `internal/<domain>` packages ship with `_test.go` covering
  the interface contract. Encode the behavioral invariants as tests:
  default-deny, secret-by-reference never leaks the raw value, no-body logging,
  cache stale-on-failure vs manual hard-fail.
- **Interfaces for all external deps.** Don't reach around `ConfigProvider`,
  `SecretProvider`, or `AnalyticsStore`.
- **`cmd/` thin, `internal/` by domain.** No speculative `pkg/`.
- **Logging hygiene.** Reference secrets by hash/last-4/version; headers only,
  never full bodies.
- **Pure-Go SQLite only** (`modernc.org/sqlite`) — never a CGo driver.
- **Default-deny is sacred** — never weaken it for convenience.

See [`AGENTS.md`](AGENTS.md) for the full conventions, package map, and design
rationale.
