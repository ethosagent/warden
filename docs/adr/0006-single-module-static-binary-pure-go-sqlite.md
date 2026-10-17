# 0006. One Go module and one static binary; pure-Go SQLite; no CGo

- **Status:** Accepted. `go.mod` is the only module, SQLite is `modernc.org/sqlite`, and `AGENTS.md`
  forbids CGo drivers.
- **Source:** Not found as a separate issue or PR; recorded from `AGENTS.md` ("Do NOT" list),
  `docs/architecture.md` ("Single static binary") and the initial scaffold commit `b718837`.

## Context

Warden is a security boundary that runs in a container beside an untrusted agent. It must build and ship
without a C toolchain, and the same binary serves both roles.

## Decision

One Go module (`github.com/ethosagent/warden`), one static binary with a worker and a control-plane role,
and pure-Go SQLite (`modernc.org/sqlite`). `mattn/go-sqlite3` and any other CGo dependency are not allowed.
No speculative `pkg/` directory: use `cmd/` and `internal/`.

## Consequences

- Cross-compiling and minimal images stay simple, and `scripts/check.sh` needs no C toolchain.
- New dependencies must be pure Go (`ARCH-11`). A CGo ban check is planned in #349 (rule C2).
- Splitting the repo into several modules or binaries needs a new ADR.
