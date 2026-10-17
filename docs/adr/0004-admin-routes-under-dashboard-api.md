# 0004. Admin routes live under `/dashboard/api/*`; `/api/` is reserved for a future public API

- **Status:** Accepted. Every admin route in `internal/dashboard/dashboard.go` is mounted under
  `/dashboard/api/`, and nothing is served under `/api/`. The route-coverage test that would enforce it
  is part of the planned role and scope work.
- **Source:** [#108](https://github.com/ethosagent/warden/issues/108) (scoped API keys, authz table);
  see `docs/roadmap/features/api-keys.md`.

## Context

API keys, roles and later admin features add many routes. Mixing admin and public routes under one prefix
would blur which routes need session, CSRF or scope checks, and would lock a public API shape too early.

## Decision

All admin routes, including API-key routes, live under `/dashboard/api/*`. `/api/` stays unmounted and
reserved for a public, key-authenticated API. Worker-facing routes keep their own prefixes (`/policy`,
`/control/*`, `/central/*`); agent-facing OAuth routes are planned under `/oauth2/*` (not yet implemented; see
`docs/roadmap/features/token-exchange.md`).

## Consequences

- New admin routes use the `/dashboard/api/` prefix (skill `add-control-plane-route`).
- A route under `/api/` is a review finding.
- The planned authz table is the single place that says which role or scope each route needs.
