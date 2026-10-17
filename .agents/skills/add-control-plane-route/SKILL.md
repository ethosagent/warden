---
name: add-control-plane-route
description: Add an HTTP route to the Warden control plane or dashboard. Use when adding an admin API endpoint, a worker-facing control endpoint or a browser route.
---

# Add a control-plane route

Rules live in [`AGENTS.md`](../../../AGENTS.md); checks in
[`security-invariants`](../../reviews/security-invariants.md) (`SEC-3`, `SEC-7`, `SEC-8`, `SEC-9`,
`SEC-10`), [`architecture`](../../reviews/architecture.md) (`ARCH-1`) and
[`test-quality`](../../reviews/test-quality.md) (`TEST-2`). Read
[ADR 0004](../../../docs/adr/0004-admin-routes-under-dashboard-api.md) first.

## Steps

1. **Pick the prefix.** Admin routes go under `/dashboard/api/*`. Never mount under `/api/`
   (reserved for a future public API). Worker-facing routes (`/policy`, `/control/*`, `/central/*`)
   use the worker bearer token; keep them separate from admin routes.
2. **Test first**, including the callers who must fail: no credentials (401) and wrong role/scope (403),
   plus oversized body and malformed input.
3. **Keep the handler thin** (`ARCH-1`): parse, authorise, call the domain/writer, map the response.
4. **Register it** next to the others: `mux.HandleFunc` in `internal/dashboard/dashboard.go`
   (admin) or `Server.Handler` in `internal/controlplane/controlplane.go` (worker-facing). Mount
   write routes only where a writer is configured; elsewhere return 405 or leave it unmounted
   (see `putPolicy`, `putSettings`). Workers never get write routes.
5. **Authenticate.** Worker-facing handlers call `s.bearerOK(r)` (constant-time bearer check,
   `internal/controlplane/secrets.go`).
6. **Bound input** (`SEC-7`): `http.MaxBytesReader` on every body, as `putSecret` does with
   `maxSecretBodyBytes`.
7. **Return safe errors** (`SEC-3`): fixed messages, no `err.Error()` from stores or drivers, no
   secret values. Log the detail server-side by reference (`secrets.Ref`). Validation errors that
   only describe the caller's own input may be returned.
8. **Never expose control-plane-only data** to workers or the browser unmasked (`SEC-9`).
9. Run `scripts/check.sh`.

## Planned, not built yet

Roles, scopes, CSRF, object-level checks, rate limits and the admin audit chain are roadmap items,
not code on this branch: the SSO/role table (`W-P1-SSO-05`), scopes (#108), audit middleware (#39)
and the audit store (#38). Until they land, state in the PR which of these a new route would need
and add a TODO linking the issue. When they land, every route needs: a role or scope in the authz
table, CSRF for browser routes, an object-level ownership check, a rate limit, an audit record for
changes, and tests for unauthenticated and wrong-role callers (`SEC-10`).

## Worked example: `POST /central/secrets`

`putSecret` in `internal/controlplane/secrets.go`: mounted only when `s.secretStore != nil`
(`Handler`), bearer-checked, body capped with `MaxBytesReader`, empty key/value rejected with 400,
store failures return a fixed `"secret store error"` 500 and log the value only as `secrets.Ref`.
Tests: `internal/controlplane/secrets_test.go`.
