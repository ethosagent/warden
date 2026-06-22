# AGENTS.md

Canonical, tool-agnostic instructions for any coding agent (or human) working
in this repo. The nearest `AGENTS.md` wins; this root file governs the whole
project.

## What this is

Warden is an **agent egress guardrail proxy**: a security boundary that wraps an
untrusted LLM agent runtime so it cannot exfiltrate data, make rogue calls, or
hold real secrets. The agent has **no direct network route out**; the only path
to the internet is through Warden, which enforces default-deny egress policy and
swaps placeholder tokens for real secrets at the network edge.

**Core invariant (never weaken this):** the wrapped agent is *structurally
incapable* of bypassing the guardrail. Only egress is through the proxy, and
that isolation is enforced by the container/orchestration runtime — not by
asking the agent to behave. Default-deny is sacred; secrets never reach the
agent; logs never contain real secret values or full bodies.

## Build

```sh
make build          # go build ./...
go build ./cmd/proxy
```

## Test (required before commit)

```sh
make test                 # go test -race ./...
scripts/check.sh          # the FULL gate — exactly what CI runs
scripts/install-hooks.sh  # run once: wires pre-commit (fast) + pre-push (full)
```

`scripts/check.sh` is the single source of truth: format → vet → lint → build →
test+race+coverage → coverage gate (`COVERAGE_MIN`, default 70) → integration
(`--integration`). CI runs the same script, so "green locally" means "green in
CI".

## Conventions

- **Test-first / TDD.** No core code lands without tests; coverage gate blocks
  regressions.
- **Interfaces for all external deps.** Config, secrets, and storage sit behind
  `ConfigProvider`, `SecretProvider`, `AnalyticsStore`. Never reach around them.
- **`cmd/` stays thin** (wire + start, no business logic); **`internal/` is
  organized by domain**.
- **Logging hygiene.** Reference secrets by hash/last-4/version — never the raw
  value. Headers only; no full request/response bodies.
- **Default-deny is sacred.** A destination not on the allowlist is blocked.

## Do NOT

- Add `pkg/` speculatively (use `cmd/` + `internal/`).
- Bypass the three core interfaces.
- Use a CGo SQLite driver — use pure-Go `modernc.org/sqlite` (keeps the single
  static binary, no C toolchain).
- Log real secrets or full bodies anywhere.
- Add bare local-process deployment — isolation requires a container runtime.

## Required tools / skills

- **Go toolchain** (version pinned in `go.mod` + CI) — build, test, `go vet`,
  race detector.
- **golangci-lint** — aggregated linting (`.golangci.yml`).
- **gofumpt / gofmt** — formatting (enforced in pre-commit).
- **Docker / Docker Compose** — dev harness + integration tests (no bare-local
  mode).
- **kubectl + kind/minikube** — validate sidecar + default-deny NetworkPolicy.
- **OpenSSL / Go crypto** — `scripts/gen-certs.sh` (bake-once proxy cert).
- **`modernc.org/sqlite`** (pure-Go) — no CGo / system SQLite.
- **mockgen or hand-written fakes** — test doubles for the three core
  interfaces (see `test/fakes/`).

## Where things live

```
cmd/proxy/main.go     wire deps, load config, start — no business logic
internal/config/      ConfigProvider + Policy types + local YAML impl
internal/secrets/     SecretProvider + in-memory cache + ENV impl + Reference
internal/analytics/   AnalyticsStore + Event/EventFilter + modernc SQLite impl
internal/policy/      default-deny allowlist evaluator (domain + port inference)
internal/proxy/       listener / TCP-accept / TLS-termination skeleton
internal/protocol/    protocol detection + HTTP handler skeleton
internal/agentid/     agent identification (port-binding in M1)
internal/admin/       /healthz + /admin/refresh-secrets handlers
deploy/{compose,k8s,vm}/  deployment templates that encode the isolation
configs/config.example.yaml  documented sample config
test/fakes/           hand-written fakes for the three interfaces
test/integration/     end-to-end tests behind the `integration` build tag
scripts/              check.sh (the gate), install-hooks.sh, gen-certs.sh
```

Each `internal/<domain>` package keeps its interface, implementation(s), and
`_test.go` together.
