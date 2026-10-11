# Warden identity & control-plane roadmap — handoff

> Kept for history. This is the note carried over from the planning session that
> produced `docs/roadmap/tickets.json`. The living roadmap is
> [`docs/roadmap/README.md`](../README.md); where this note and the roadmap
> disagree, the roadmap wins. The original `create-warden-issues.sh` it mentions
> was replaced by `go run docs/roadmap/gen.go issues`.

## Goal
Let agents act for real users, safely, through Warden. Every agent request already goes through Warden; what's missing is user identity, delegated per-user auth, and an enterprise control plane.

## Decisions made
- Single-tenant: one Warden deployment per company.
- Identity: Warden is a **generic OIDC client**. Dex sits in front today (pinned stable release, never master/nightly) and is replaceable; direct Okta/Entra/Google come in Phase 5.
- Warden does not build its own IdP and never stores users' passwords.
- Admins sign in to the console with SSO. Employees sign in to their agent platform, not to Warden (except the consent portal from Phase 3).
- Identity reaches the worker as `Proxy-Authorization: Basic base64("session:"+token)` on CONNECT (from a proxy URL), fallback header `X-Warden-Identity`. Worker verifies locally against cached JWKS; the IdP is never on the hot path. Headers are stripped before forwarding.
- Roadmap is platform-neutral: **no Ethos-specific tickets**. Agents integrate via a documented identity contract and a `warden identity` CLI. Ethos is tested later.
- JIT auth: missing grant -> structured 403 (`authorization_required`, `authorize_url`, `status_url`), MCP tool error equivalent; completion via retry, status long-poll, or (Phase 4) park + notify.
- Docs live in `docs/roadmap/` in this repo; tracking in GitHub Issues. Both generated from `warden-tickets.json` — never hand-edit one side.

## Phases
| Phase | Name | What works at the end |
|---|---|---|
| P1 | Who did it | Console SSO via Dex + 3 roles, admin audit log, policy history + rollback, per-worker tokens (no mTLS yet), user token verified on worker in attribute mode, group-aware policy, fleet-wide user block, JSON audit logs, identity contract + CLI |
| P2 | Proven identity | Agent registry, RFC 8693 token service (15-min agent-bound tokens), key manager, worker CA + mTLS, signed bundles, two-person approval with replay, scoped API keys, require-identity mode, Claude Code/Codex recipes |
| P3 | Act as the user | Consent portal, OAuth broker (Google, GitHub), per-user secrets + refresh model, JIT 403 + long-poll, offboarding revocation, per-user limits |
| P4 | Agents everywhere | Delegation grants, park + notify, MCP gateway + registry, external hooks, admin MCP server, policy as code + canary |
| P5 | Enterprise scale | Postgres + HA, Helm, OTel logs/traces, SIEM export, KMS, retention, direct IdP adapters |

Phase 1 must be production-usable on its own.

## Ticket data
- `warden-tickets.json` (now `docs/roadmap/tickets.json`): 43 items (features) plus 8 already-shipped Phase 0 items, 216 tickets. Each item: id, phase, name, lane, label, summary, design[], touches[], depends_on_items[], done_when, tickets[]. Each ticket: key (`W-P<phase>-<CODE>-NN`), title, type, estimate (S/M/L), body, acceptance[], depends_on[].
- `create-warden-issues.sh`: creates labels, one epic per item, one issue per ticket; idempotent; `REPO=... PHASE=1 DRY_RUN=1`.

## Agreed next steps (as of the handoff)
1. Rewrite P1 and P2 tickets in the richer format:
   - Title: `[<Feature> n/N] <action>`; label `feature:<slug>`.
   - Body first line breadcrumb: `Feature · Ticket n of N · Phase · Key · Parent epic`.
   - Sections: Why, Context, In scope, Out of scope, Acceptance (given/when/then), How to verify (exact command), Definition of done, Depends on / Unblocks.
   - Each ticket = one PR, mergeable on its own behind a flag, main stays green. Split L tickets and M tickets spanning two components.
   - Each feature gets a plain-language story: before/after, numbered flow, out of scope, risks.
2. Generate `docs/roadmap/`: `README.md` (phases + Mermaid diagram + gates), `conventions.md` (ticket key format, titles, labels, sizes), `features/<feature>.md` per feature (P1–P2 full, P3–P5 summary). Add a pointer from the repo README.
3. Open a PR (do not push to main).
4. After merge: dry-run then run the script — labels, one milestone per phase, epics, P1 issues as sub-issues of their epics, pinned "Roadmap" issue. Open decision: P2 full tickets or epics only (recommendation: epics only until P1 is ~70% done).

## Known risk
Estimates summed from tickets are large (P1 ≈ 20–35 eng-weeks). If P1 needs trimming: defer JSON audit export and break-glass/backups, keep roles to admin + viewer.

## Reference
- Dex advisory GHSA-7qjx-gp9h-65qj (token exchange ignores AllowedConnectors; unreleased master only) — reason Warden runs its own token service instead of trusting Dex's exchange.

## Decisions log (2026-10-11)
Phase 1
- W-P1-JAUD-05/06 ship first in p1-json-audit, and the JAUD-05 secret-in-URL leak fix ships with no flag, because it is a bug fix.
- Policy history ships behind `--policy-store=versioned` in release N, becomes the default in N+1 and removes YAML as a policy source in N+2, so the migration is gradual and reversible.
- Admin-audit key rotation is deferred to p2-key-manager (W-P2-KEYS-06). P1 ships one key plus a documented manual rotation that starts a new chain segment stamped with the new key_id (`--admin-audit-new-segment`), which keeps P1 small and still verifiable.
- Console sessions are idle 1h and absolute 12h, and `query/generate` needs the editor role, because it spends LLM tokens.
- Worker tokens bind only to an exact proxy_id in P1, with no prefix binding. Autoscaled per-pod identity waits for P2 mTLS enrollment.
- `warden identity exec` moves to P1 as W-P1-IDC-04 (S). It runs a child behind a loopback forwarder that refreshes the short-lived token before expiry and never puts it in env or argv. This removes the stale token in HTTPS_PROXY.
- Size caps are 16 KiB per token and 32 KiB, 100 lines and a 10s deadline for CONNECT headers everywhere, so the worker, contract and forwarders agree.
- Hand edits of the served YAML are audited in file mode too, as `config.external_change` with the new hash, so the default mode has no silent policy changes.
- W-P1-DEX-03 may depend on tickets in later P1 features. This is accepted because it is a docs ticket that only has to merge after the keys it cites.

Phase 2
- The per-agent identity mode stays in settings `agents[].identity`, not in a registry column, so it is versioned, can be rolled back and goes through approvals.
- The API-key admin routes move to `/dashboard/api/api-keys`. `/api/` is reserved for a future public key-authenticated API, so all admin routes use one chain.
- Token issuance is recorded in a separate `token_events` table plus a `warden.token.v1` line, not in the admin audit chain, so machine traffic does not flood the chain.
- Workers use one `controlPlane.stateDir` with subdirectories (`cert/`, `bundle/`; no `bundleCacheDir`), so there is one directory to secure. Bundle verification flips to require by default at the Phase 2 gate.
- With approvals on, removing a block-list entry needs a second admin, while adding a block stays single-admin. Break-glass can bypass only through the audited emergency apply, which keeps the kill switch fast and makes unblocking deliberate.
- An offline `warden control-plane block add|remove|list` CLI is added as W-P1-BLOCK-08 (S). It follows the WTOK-05 audit and key rules, so P1 operators and recipe checks can block users without a console session.
- W-P2-WBND-05 and W-P2-WBND-06 stay as small tickets, because each still proves a distinct behaviour.

Phase 3
- `consent.store` is CP-only, and workers never get stored per-user credentials, so a compromised worker cannot read refresh tokens.
- `allowClientSecrets` is dropped. Client secrets come only from consent.store or clientSecretEnv.
- Consent requires `console.auth=oidc`, with no dev bypass for the IdP link, so dev and prod share one code path.
- Two new worker→CP calls are accepted: `/control/user-token` and `/control/connect/pending`. Both need the worker cert (mTLS), are rate-limited and have the CP re-verify the user token, and the docs no longer say "exactly three calls".
- If saving a refresh token fails, the CP retries briefly in memory, then raises a metric and a Finding. There is no encrypted queue in P3. Buffered responses reuse the existing response scanner to redact swapped per-user tokens; the implementer checks coverage first and extends the scanner if needed.
- Saving a `dailyCostUSD` rule returns 409 while workers without `usercost/v1` are connected, unless an admin sends an audited `force=true`, because old workers fail open on cost caps. The W-P3-PUL-06 cost fix ships with no flag.
- Offboarding mode defaults to off, and token_lost users are only alerted. Blocks created by offboarding expire after a configurable 90 days with an audit record, so the 5000-entry block list does not fill up.
