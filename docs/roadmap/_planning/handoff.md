# Warden identity & control-plane roadmap — handoff

> Kept for history. This is the note carried over from the planning session that
> produced `docs/roadmap/tickets.json`. The living roadmap is
> [`docs/roadmap/README.md`](../README.md); where this note and the roadmap
> disagree, the roadmap wins. The original `create-warden-issues.sh` it mentions
> was replaced by `go run docs/roadmap/gen.go issues`.

## Goal
Make Warden cover what Arcade.dev (agent "actions runtime") does. Every agent request already goes through Warden; what's missing is user identity, delegated per-user auth, and an enterprise control plane.

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
