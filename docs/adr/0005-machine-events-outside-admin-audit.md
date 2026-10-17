# 0005. Machine events go to their own tables and log streams, not the admin audit chain

- **Status:** Proposed. The admin audit chain and the event tables are roadmap items and are not in the
  code yet.
- **Source:** [#85](https://github.com/ethosagent/warden/issues/85) (token issuance records),
  [#38](https://github.com/ethosagent/warden/issues/38) (admin audit chain); applied in
  [#167](https://github.com/ethosagent/warden/issues/167) (grant events),
  [#218](https://github.com/ethosagent/warden/issues/218) (notify outbox) and
  [#185](https://github.com/ethosagent/warden/issues/185) (git imports). Wording is in
  `docs/roadmap/features/token-exchange.md` and `docs/roadmap/features/delegation-grants.md`.

## Context

The admin audit log is a hash-chained, signed record of actions by people in the console. Machine traffic
(token issuance, grant transitions, notifications, git imports) is high-volume and has no session. Chaining it
would flood the log and make it hard to verify and read.

## Decision

The admin audit chain records admin actions and logins only. Machine events go to their own prunable
control-plane tables plus a versioned JSON log line each (for example `token_events` with
`warden.token.v1`, `grant_events` with `warden.grant.v1`). System actors that change served state, such as
an automatic rollback, still appear in the admin chain as `system:` actors.

## Consequences

- A new automated flow gets its own event table and schema-versioned log line (`ARCH-8`), not an
  admin-audit row.
- Neither store holds secrets, tokens or bodies (`SEC-3`).
- Where a machine event gates a security action (for example releasing a token), failing to record it
  fails closed (`SEC-5`).
