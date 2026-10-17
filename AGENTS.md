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

Agents: run `scripts/check.sh --json` and fix the findings in order. It prints
one report on stdout (human progress goes to stderr) and keeps going after a
failure, so every problem shows in one pass. Each finding has a `rule`, a
`file:line` and a `fix` that says what to do. Report format:
[`docs/check-report.schema.json`](docs/check-report.schema.json)
(`warden.check.v1`). Other flags: `--json-out <path>` (human output as usual,
plus the report in a file), `--keep-going` (all stages, human output). The
exit code is the same with or without them. In report mode the console shows a
per-stage summary instead of live tool output, and a tool that cannot run at all
maps to exit 1. The coverage gate counts product code only (`tools/` is tested
but excluded from the total). The reporter is
`tools/checkreport` — developer tooling that no Warden package may import.

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

## Reviews

Review rubrics live in [`.agents/reviews/`](.agents/reviews/README.md), one
per lens: security invariants, architecture, hot path, acceptance and test
quality. Each check has a stable ID (`SEC-4`, `HOT-1`, …). Use them when
reviewing, or run `openai-review --lens <name>`. A check that keeps finding
the same problem should become a rule in `scripts/check.sh`.

For exploratory attack runs — actively trying to break Warden against a stack
built from a PR — follow [`.agents/playbooks/red-team.md`](.agents/playbooks/red-team.md)
(rules of engagement, bypass list, canary hunt, reporting as `RT-*` findings).
Every confirmed break becomes a scripted regression scenario in the L1/L2
harnesses.

## Pipeline contract

The autonomous pipeline has two parts: a generic harness (a separate repo) and
this repo's contract. The harness knows nothing about Go or Warden. It reads
[`.agents/pipeline.yaml`](.agents/pipeline.yaml) (schema:
`docs/pipeline.schema.json`) for commands, paths, review lenses and the PR
template. An entry marked `planned: true` names the issue that delivers it, so
the harness skips it. `test/contract` fails if the file is invalid, if an
entry that is not `planned` points at something missing, or if a `planned`
entry names no issue. When planned work merges, drop `planned` in that PR.

### Intake: the `agent-ready` label

An issue gets the `agent-ready` label when all of these hold:

- every issue it depends on is closed;
- it has testable acceptance criteria;
- its risk tier is known, or the files it touches predict it (roadmap tickets
  carry `touches`);
- it is sized S or M.

Open issues from `.github/ISSUE_TEMPLATE/` (feature or bug). Both templates
require acceptance criteria and "files likely touched". Roadmap issues keep
their generated format.

### Commits and PRs

- One PR per issue. Put `Closes #N` in the PR description.
- Fill `.github/pull_request_template.md`: why first, then what changes, the
  acceptance criterion → evidence table, risk tier, review lenses and
  outcome, and what was not done with follow-up issues.
- Add a `Co-Authored-By:` trailer to every commit an agent writes.

## Task skills and decisions

Step-by-step patterns for the common changes live in
[`.agents/skills/`](.agents/skills/README.md): `add-request-stage`, `add-adapter`,
`add-config-key`, `add-control-plane-route`. Use the matching skill before you start.

Architecture decision records live in [`docs/adr/`](docs/adr/README.md). **Read the relevant
ADR before changing that area** (data-plane/control-plane layering, per-user credentials,
architecture checks, admin route prefixes, audit and machine events, build and dependencies).
**Write a new ADR when a change moves a boundary**, and mark an old one superseded rather than
silently reversing it.

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
