# 0001. Data plane split into engine, decision stages and side calls; repository layer for the control plane

- **Status:** Proposed. The split describes today's `internal/proxy` shape, but the layer checks and the
  `adapters/` layout are not built yet.
- **Source:** [#349](https://github.com/ethosagent/warden/issues/349) (model section; carried over from
  [#344](https://github.com/ethosagent/warden/issues/344)).

## Context

Warden's boundaries lived only as prose in `AGENTS.md`, and the code had drifted
(`analytics` → `mcp/gateway`, `controlplane` → `worker`, `worker` importing 18 packages). A single
"everything goes through a repository" rule doesn't fit the data plane: proxying bytes *is* its I/O.

## Decision

- **Control plane:** domain (rules, ports) → repository (`internal/<domain>/adapters/<x>/`, the only
  code that touches databases, networks and SDKs) → transport (HTTP handlers) → assembly (`cmd/`).
  Imports point down.
- **Data plane:** three parts. The **engine** (listener, TLS, dialer, forward, relay, h2/WebSocket
  streaming) moves proxied bytes with `net` and `crypto/tls` directly. **Decision stages** are pure
  functions over request metadata that allow, deny or annotate. **Side calls** (control plane, secrets,
  analytics, judge, hooks) go through ports and adapters, and on the hot path must be cached, async
  or bounded by a timeout that fails closed.

## Consequences

- A new request check is a decision stage, not engine code (`runRequestStages`; see skill
  `add-request-stage`). A new outside system is an adapter (skill `add-adapter`).
- Review checks: `ARCH-1`..`ARCH-4` in `.agents/reviews/architecture.md`.
- Existing code that breaks the layering is baselined in #349 and migrated package by package; do not
  add new violations.
