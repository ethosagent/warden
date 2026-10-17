# 0002. Per-user credentials live only in a control-plane store; workers never hold them

- **Status:** Proposed. `Policy` fields marked `json:"-"` already keep local config off the worker
  wire, but the control-plane user store described in #277 is not built.
- **Source:** [#277](https://github.com/ethosagent/warden/issues/277) (CP-only user credential store);
  epics [#138](https://github.com/ethosagent/warden/issues/138) and
  [#127](https://github.com/ethosagent/warden/issues/127).

## Context

Features such as consent sign-in and per-user secret refresh store IdP refresh tokens, provider grants
and OAuth client secrets per user. Today the control plane's `secretStore` credential reaches workers
through the settings wire, and `/central/secrets` can write any key, so anything stored there would be
readable by every worker.

## Decision

Per-user credentials go in a separate control-plane-only store (`consent.store`) that no worker gets a
credential for. User keys come from one helper (hash of issuer and subject), under reserved key prefixes
that static mappings and console edits cannot touch. Workers receive short-lived, narrowly scoped tokens
minted by the control plane, never the refresh credentials.

## Consequences

- A compromised worker cannot read another user's credentials; the agent never holds a real secret
  (core invariant).
- New control-plane config that holds credentials carries `json:"-"` (skill `add-config-key`, check
  `SEC-9`). A Go-native check for this is planned in #349 (rule X2).
- Workers need a control-plane call to obtain per-user tokens, which must be cached and fail closed
  (`SEC-5`).
