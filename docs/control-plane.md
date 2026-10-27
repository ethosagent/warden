# Control plane

Warden ships one binary with two roles:

- **Worker** (`warden run`) — the data plane. Sits in front of an agent,
  enforces allow/deny policy on every call, swaps secrets at the edge.
- **Control plane** (`warden control-plane`) — serves allow/deny policy to many
  workers and aggregates their analytics into a fleet dashboard.

They are **separate processes that only ever talk over HTTPS**, so you can run
them together on one host today and split the control plane onto its own host
later by *moving a service* — no code change.

```
                 ┌──────────────────────────────┐
   GET /policy   │      warden control-plane     │   POST /central/ingest
  ◀──────────────┤  • serves allow/deny policy   ├──────────────▶
   (hot-reloaded)│  • ingests fleet analytics    │   (events)
                 │  • fleet dashboard :7070      │
                 └──────────────────────────────┘
                        ▲                ▲
              ┌─────────┘                └─────────┐
        warden run (worker-1)            warden run (worker-2)
        agent-1 ──▶ egress               agent-2 ──▶ egress
```

## The boundary: policy only, never secrets

The control plane serves an explicit allow/deny wire type — it **cannot** send
secrets, judge config, or anything else, even if `config.Policy` grows new
fields later (the guarantee is structural, in code, not a struct tag). Secrets
stay on each worker and are injected at that worker's edge. A compromised
control plane still cannot leak a single real credential, because it never holds
one.

## Trust (HTTPS)

Workers require HTTPS for the policy pull. The control plane mints its server
cert from a CA you give it (`--ca-cert`/`--ca-key`); in the example that's the
same proxy CA the workers already use. Each worker trusts it via
`controlPlane.caCert` / `central.caCert`, which adds that CA to a
**per-connection** pool only — the worker's upstream TLS trust is unchanged.

## Worker ↔ control plane: the only interactions

Every connection is **worker-initiated** (the worker always dials out, so no
inbound port is opened on the worker), and the control plane **never** calls into
a worker. There are exactly three calls:

1. **Long-poll config** — `GET /policy?wait=30s` with an `If-None-Match` ETag. The
   CP holds the request open and returns **200 + new policy the instant it
   changes**, or **304** at the timeout; the worker re-polls immediately. Policy
   edits reach workers in ~one round-trip, not after a fixed interval.
2. **Heartbeat** — `POST /control/heartbeat` (~every 10s) so the CP lists the
   worker as online even when idle, and knows its current policy version.
3. **Analytics** — `POST /central/ingest` (worker → CP).

The dashboard shows only what the CP already has (pushed analytics + the
registry); it never reaches into a worker.

## Managed vs local-only

By default a worker with `controlPlane.endpoint` set is **CP-managed**: its
allow/deny policy comes **only** from the control plane. It boots **fail-closed
(denies all egress)** until its first successful pull, then enforces CP policy and
keeps the last-known-good across CP outages — it never falls back to a local
allowlist the operator didn't intend. (Secrets always stay local; "managed" is
about allow/deny policy only.)

Set `controlPlane.localOnly: true` (or run `warden run --local-only`) to ignore
the control plane and enforce the worker's **local** policy standalone — the
escape hatch for offline/debug. A managed worker needs no local `allowlist`; a
local-only/standalone worker still requires one.

## Run it

```sh
# 1. Generate the bake-once proxy CA (the control plane mints its cert from it).
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh

# 2. Bring up the control plane + two workers + two synthetic agents.
WARDEN_CP_TOKEN=dev-token \
  docker compose -f deploy/compose/docker-compose.control-plane.yml up
```

- Fleet dashboard: **https://localhost:7070/dashboard/** (cert signed by the
  proxy CA — trust it in your browser, or `curl --cacert deploy/compose/certs/proxy-ca.crt`).
  A **worker selector** appears top-left: view the whole fleet or slice to one
  worker. The **policy panel is live** — it reflects the current served policy.
- Per-worker dashboards: http://localhost:9091/dashboard/ and http://localhost:9092/dashboard/.

Edit [`configs/config.control-plane.yaml`](../configs/config.control-plane.yaml)
(add/remove an allowed domain) and within one poll interval both workers enforce
the change — no restart.

## Standalone (no Docker)

```sh
# Control plane (HTTPS, minted from the proxy CA):
warden control-plane --config configs/config.control-plane.yaml \
  --listen 0.0.0.0:7070 --token-env WARDEN_CP_TOKEN \
  --admin-token-env WARDEN_CP_ADMIN_TOKEN \
  --ca-cert certs/proxy-ca.crt --ca-key certs/proxy-ca.key --tls-host control-plane

# Worker pointed at it (configs/config.worker.yaml sets controlPlane + central):
WARDEN_PROXY_ID=worker-1 warden run --config configs/config.worker.yaml ...
```

Omit `--ca-cert`/`--ca-key` to serve plain HTTP for local poking, but a real
worker requires HTTPS for the policy pull.

## What the control-plane dashboard does

- **Edit policy** — add/remove allow and deny rules from the dashboard and Save.
  The edit is validated (an empty allowlist is rejected — default-deny is
  preserved) and written back to the served policy file, so every worker pulls it
  on its next poll. The editor only appears on the control plane; worker
  dashboards show policy read-only and expose no write path.

  > **Writable served config required.** Saving an edit writes a temp file next
  > to the served config and atomic-renames it into place, so the served config
  > must live on a writable, container-user-owned location. Pass
  > `--state-dir=<writable dir>` (the compose uses `/data`): the control plane
  > seeds it once from `--config` and then serves+edits that writable copy, so
  > edits persist across restarts. Without `--state-dir` the control plane edits
  > `--config` in place — fine for a writable file, but with a read-only
  > single-file `--config` mount (see [Standalone](#standalone-no-docker), the
  > `:ro` mount) the dashboard surfaces a `permission denied` error and editing
  > is effectively disabled. The control plane logs a clear warning at startup
  > when its served-config directory is not writable.
- **Connected workers** — a live list of every worker the control plane has heard
  from (via policy pulls and analytics ingest): online/offline status, last-seen,
  last policy pull, and events forwarded. Hidden on a single-node dashboard.
- **Per-worker slicing** — events are tagged with their originating worker, so the
  dashboard shows a per-worker breakdown and lets you filter the whole view to one
  worker.
- **MCP per worker** — each worker forwards its MCP inventory + observed
  request/response schema (value-free: paths · types · the specific detector that
  fired — e.g. `github_token · HIGH`, `email · MEDIUM`) over the ingest channel,
  so the control-plane MCP panel shows it per worker (follows the worker
  selector). Requires `mcp.enabled` on the worker.
- **Debug a finding** — expand a flagged field to see the exact detector +
  severity (not just the coarse `credential_leak`/`pii` class). Set
  `mcp.scan.evidence: true` on a worker to also keep a **masked** sample
  (`•••• + last-4 (len N)`, never the raw value) so you can tell a real leak from
  a false positive. From a flagged tool you can **Deny it fleet-wide** in one
  click — that writes `settings.mcp.tools.deny` via the same validated settings
  writer, so every worker blocks the tool on its next poll.
- **Live policy** — the policy panel reflects the policy currently being served
  (control plane) or enforced (worker, including hot-reloads), not a startup snapshot.
- **Alert integrations** — configure outbound alert sinks (webhook today) from the
  dashboard. Secrets are entered as `${ENV}` references only (raw values are
  rejected) and resolved from the control plane's environment at start.

### Verifying webhook signatures

If a webhook integration has a **Signing secret** configured, every delivery is
signed Slack/Stripe-style so your receiver can authenticate the payload and
reject replays:

- `X-Warden-Timestamp: <unix seconds>` — when the request was sent.
- `X-Warden-Signature: v1=<hex>` — where `<hex>` is
  `HMAC-SHA256(secret, "<timestamp>.<raw request body>")`.

To verify: read the raw body bytes **before** JSON-parsing, recompute
`hex(hmac_sha256(secret, timestamp + "." + body))`, compare against the value
after `v1=` with a constant-time comparison, and reject requests whose
timestamp is older than your replay window (e.g. 5 minutes). Without a
configured secret the headers are absent and deliveries are unsigned.

### Dashboard writes need the control-plane token

This is the `console.auth: none` mode (the default). Dashboard reads are open;
every state-changing call under `/dashboard/api/` (`PUT`, `POST`, `PATCH`,
`DELETE`: policy, settings, integrations, detection, LLM providers, the secret
store, and the query and audit-verify `POST`s) is gated by the control-plane
admin bearer, `Authorization: Bearer <control-plane admin token>`, checked in
constant time and fail closed. `/central/secrets` (GET, POST and
`DELETE /central/secrets/{key}`) takes the same bearer in this mode. In
`console.auth: oidc` none of this applies: sessions and CSRF replace the bearer
on every human route (see [Migrating from none to oidc](#migrating-from-none-to-oidc)).

- **The admin token.** Start the control plane with `--admin-token-env <ENV>`
  (for example `--admin-token-env WARDEN_CP_ADMIN_TOKEN`) naming the env var that
  holds its own admin bearer. It is separate from the `--token-env` token workers
  present: once it is set, the worker token gets `401` on dashboard writes and on
  `/central/secrets`, and the admin token gets `401` on the worker routes
  (`/policy`, `/control/heartbeat`, `/central/ingest`). Use different values; the
  control plane warns at startup when the two are equal. Scripts that write with
  `curl -H "Authorization: Bearer ..."` must send the admin token once it is set.
  Giving the control plane its own admin token means retiring the shared worker
  token (per-worker tokens) never disables dashboard writes.
- **Fallback.** Without `--admin-token-env`, the admin bearer is the shared
  `--token-env` token, exactly as before, and startup logs one warning:
  `dashboard writes use the shared worker token; set --admin-token-env`. With no
  token of either kind, `/central/secrets` keeps the development pass-through of
  the worker routes, and dashboard writes are refused (below).
- **Visible.** At startup the control plane logs one warning,
  `console.auth=none: dashboard reads are unauthenticated; writes need the admin bearer`,
  `GET /dashboard/api/setup` returns `"authMode":"none"`, and the dashboard shows a
  persistent "Open console" banner. Start the control plane with
  `--require-console-auth` to make none mode a startup error instead.

- **Fail closed.** A control plane started with no admin bearer (neither
  `--admin-token-env` nor `--token-env`, or their variables empty) refuses every
  dashboard write with `403` and a message (`dashboard writes are disabled`) that
  names `--admin-token-env`. There is no open mode for dashboard writes. A
  whitespace-only token counts as not configured. When `--admin-token-env` names
  an empty variable the control plane logs
  `control-plane: admin-token-env set but empty; dashboard writes will be refused`
  and does not fall back to the worker token: dashboard writes get `403` and
  `/central/secrets` gets `401`. No token value is ever logged. The worker-facing endpoints
  (`/central/ingest`, `/control/heartbeat`) keep the existing development
  pass-through when no token is set; the loopback publish of `:7070` in the demo
  compose files is what bounds that.
- **Reads stay open.** `GET` routes (traffic, analytics, policy view, workers, …)
  need no token. Restrict `:7070` to operators regardless: the demo compose files
  publish it, and each worker's `:9090` admin/dashboard port, on `127.0.0.1` only.
- **The UI asks once.** A change goes out without a token first; a `401` prompts for the token and retries once. It is kept in `sessionStorage` (this tab only; never `localStorage` or a
  cookie) and sent as the bearer header. A `401` clears it.
  Because the credential is a header the page adds itself, a cross-site form or
  request cannot make the browser send it: writes are CSRF-safe.
- **Audit.** A refused write logs `control plane dashboard write refused` with the
  method, path, remote address and reason, never the token. A successful write
  logs as before.

```sh
curl --cacert proxy-ca.crt -X PUT https://localhost:7070/dashboard/api/policy \
  -H "Authorization: Bearer $WARDEN_CP_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"allowlist":[{"domain":"api.openai.com"}],"denylist":[]}'

# Secret writes take the same admin bearer:
curl --cacert proxy-ca.crt -X POST https://localhost:7070/central/secrets \
  -H "Authorization: Bearer $WARDEN_CP_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"openai","value":"..."}'
```

Without `--admin-token-env` (the fallback), use `$WARDEN_CP_TOKEN` in these
examples instead.

A worker's own admin dashboard (its local `:9090`) is a separate listener with its
own token, not this one: see [Worker admin token](#worker-admin-token).

## Console sign-in config

The control plane reads an optional `console:` block from the operator-owned
`--config` file (never the `--state-dir` copy, which is seeded once and rewritten by
the dashboard, so a different block there is ignored with a warning). It is
control-plane-local: it never reaches a worker or the settings wire, and changing it
needs a restart. It holds the *name* of the client-secret env var, never the secret.

| Key | Default | Notes |
|---|---|---|
| `auth` | `none` | `none` keeps today's behaviour; `oidc` enables SSO. Any other value is a startup error. |
| `oidc.issuer`, `oidc.clientSecretEnv`, `oidc.redirectURL` | required for `oidc` | The issuer must be https unless `oidc.internalIssuerURL` is set (the dev profile); `redirectURL` is absolute, ends in `/auth/callback` and is https unless its host is loopback. |
| `oidc.clientID` | `warden-console` | The reference Dex client. |
| `oidc.scopes` | `openid email profile groups` | Must include `openid`. |
| `oidc.internalIssuerURL` | none | Origin the control-plane container uses to reach the IdP, for example `http://dex:5556`. Origin only; there is no insecure-issuer key. |
| `roles.admin`, `roles.editor`, `roles.viewer` | none | IdP group names, matched exactly and case-sensitively; the highest matching role wins. `roles.admin` needs at least one group. |
| `session.idle`, `session.absolute` | `1h`, `12h` | `0 < idle <= absolute <= 168h`. |
| `adminAudit.enabled` | `false` | Turns on the signed admin audit log; needs `--state-dir`. See [Admin audit log](#admin-audit-log). |
| `trustedProxies` | none | CIDRs of reverse proxies in front of the control plane. Only a peer inside one may set the client address the admin audit log records, through `X-Forwarded-For`. A bare address or anything that is not a CIDR is a startup error. |

In `oidc` mode the control plane also needs a non-empty value in the client-secret env
var and `--state-dir`; without either it refuses to start. See
`configs/config.control-plane.yaml` for commented examples.

In `oidc` mode every human route needs a session: each `/dashboard/*` route needs at
least the viewer role, writes need the CSRF header, and `/central/secrets` (GET, POST
and `DELETE /central/secrets/{key}`) needs an admin session plus CSRF. An
`Authorization` header is ignored on those routes, so neither the shared
`--token-env` token, the `--admin-token-env` token nor any other bearer opens them (401 without a session, 403 for a
role below admin). The worker routes (`/policy`, `/control/heartbeat`,
`/central/ingest`) keep the shared bearer in both modes.

### Admin audit log

`console.adminAudit.enabled: true` turns on the admin audit log: a hash-chained,
Ed25519-signed table in `<state-dir>/warden-cp.db`. It is off by default. Off, the
control plane creates no key file, no HMAC key file and no audit rows, and behaves
exactly as before. On without `--state-dir` it refuses to start
(`control-plane: console.adminAudit.enabled needs --state-dir`).

The first enabled start creates the signing key at `--admin-audit-key-file` (default
`<state-dir>/cp-audit.key`, PKCS#8, mode 0600) and the actor HMAC key
`cp-audit-hmac.key` beside it, writes the chain's genesis entry and logs one
`admin audit enabled` line with `key_id` and the base64 public key (never the private
key or the HMAC key). Put the key on a separate secret mount with
`--admin-audit-key-file=/secrets/cp-audit.key`; the HMAC key then lives in
`/secrets` too.

Every later start checks the keys before serving and fails closed when the chain has
rows and:

- the key file (or the HMAC key file beside it) is missing. A missing key is never
  replaced silently; restore it from backup.
- the key's `key_id` is not the chain head's `key_id`. The error names the expected
  `key_id` and `--admin-audit-key-file`.
- the HMAC key does not match the one the chain was started with.

Turning the feature off again keeps the rows and the tables; the control plane always
registers the admin audit migration, so the state database never trips the
downgrade guard.

**Manual key change (new segment).** To move to a new signing key, stop the control
plane, archive the old segment (the offline verify and export commands and the full
runbook come with W-P1-AAUD-04), put the new key at `--admin-audit-key-file` with the
same `cp-audit-hmac.key` beside it, and start once with
`--admin-audit-new-segment=<new key_id>`. The control plane appends one
`audit.segment_start` entry signed by the new key, linked to the old head and naming
the previous `key_id`; every later row carries the new `key_id`, and verification
reads each segment's public key from the chain. The flag must equal the loaded key's
`key_id` (anything else stops startup) and is a no-op once the head is on that key,
so leaving it set can never rotate twice. The flag without
`console.adminAudit.enabled` is a startup error. Automatic rotation is W-P2-KEYS-06.

**What is recorded.** With the log on, every admin change made through the control
plane writes one row: dashboard policy, settings, detection, integrations and
llmproviders writes, `/dashboard/api/secretstore` POST and DELETE, `/central/secrets`
POST, `DELETE /central/secrets/{key}` and the admin session revoke
(`DELETE /dashboard/api/sessions`). Which routes count comes from the authz route
table (`Audited`), not from the HTTP method, so worker heartbeats, ingest, `/policy`
and the read-only POSTs (`/dashboard/api/query`, `query/generate`, `audit/verify`)
never write a row. Each row carries:

- the actor: the session's subject, role and `auth_method` (`oidc` or `breakglass`),
  or, in `console.auth: none`, actor `cp-admin-token` with role `admin` and
  `auth_method` `bearer` for a write that presented the `--admin-token-env` bearer.
  A request with neither a session nor that bearer writes no row (it is counted and
  logged as `admin_audit_unauthenticated`, at most once a minute per client address).
  The one exception is a development control plane with no token configured at all,
  where `/central/secrets` accepts anonymous writes: a successful anonymous change is
  recorded with `auth_method` `none`; a failed or refused one still writes no row.
- the outcome: `ok` (2xx/3xx), `denied` (401/403, including a CSRF refusal, for an
  authenticated actor), `rejected` (other 4xx) or `error` (5xx), and the HTTP status.
- `before_hash` and `after_hash`: HMAC-SHA256 of the target's state with the
  CP-local HMAC key, so low-entropy config cannot be guessed from a hash. A denied
  write has equal hashes. Secret stores keep their state outside Warden, so secrets
  rows have empty hashes and name the key (`target_ref` `secret:<key>`, `op` put or
  delete); a policy write names the version written (`policy@<etag>`). No secret
  value, bearer or body is ever in a row.
- `request_id` (a valid incoming `X-Request-Id` of up to 64 `[A-Za-z0-9-]`
  characters, or a new one; echoed in the response) and `client_ip` (the peer
  address, or the left-most valid `X-Forwarded-For` address when the peer is in
  `console.trustedProxies`).

Audited changes run one at a time behind a control-plane-wide lock, so the hashes
describe exactly that change; a change that waits more than 30 s answers 503
`admin_audit_busy`. If a row cannot be appended after a change succeeded, the entry
is logged at ERROR with `persist_failed=true`, an `admin_audit_degraded` alert is
raised, and further audited changes answer 503 `{"error":"admin_audit_unavailable"}`
before they run, until the database accepts writes again. Reads, `/policy`, ingest
and heartbeats never depend on the audit log.

Offline CLIs that change admin state record through the same chain with
`adminaudit.OpenForCLI`: actor `cli:<os user>`, auth_method `cli`, the same key
check, and never a new key while rows exist. On a state dir where audit was never
enabled they skip the record with a notice.

### Migrating from none to oidc

1. Add the `console:` block to the operator-owned `--config` file: `auth: oidc`, the
   `oidc` block (`issuer`, `clientSecretEnv`, `redirectURL`, and `internalIssuerURL`
   when the control plane reaches the IdP on a different origin than the browser) and
   `roles` mapping your IdP groups to `admin`, `editor` and `viewer`.
2. Put the client secret in the environment variable `oidc.clientSecretEnv` names.
3. Start the control plane with `--state-dir` on a writable volume (sessions and
   pending logins live in `<state-dir>/warden-cp.db`). Add `--require-console-auth`
   so a lost `console:` block fails startup instead of reopening the console.
4. Verify: the startup log no longer carries the `console.auth=none` warning; opening
   `/dashboard/` redirects to the IdP; after sign-in a viewer can read every tab but
   gets 403 on a policy change, and an admin can edit integrations, LLM providers and
   secrets. A request with only a bearer (`$WARDEN_CP_TOKEN` or `$WARDEN_CP_ADMIN_TOKEN`) gets 401 on
   `/dashboard/api/*` and `/central/secrets`, while workers keep pulling `/policy`.

Scripts that call `/central/secrets` with the admin (or shared) bearer stop working in oidc
mode: secret writes then need an admin session plus CSRF, so they go through the
admin's secret store tab in the dashboard until scoped API keys exist. Scripts that
write `/dashboard/api/*` with the bearer stop working for the same reason.

### Login routes

In `oidc` mode (with `--state-dir`) the control plane serves `GET /auth/login` and
`GET /auth/callback`; in `none` mode both are 404. Login is the authorization-code flow
with S256 PKCE, a random `state` and `nonce`, and a pending row in the state DB (10 minute
TTL, single use, at most 10,000 rows). The row is bound to the browser by a short-lived
`__Host-warden_login` cookie (`warden_login` on an http loopback redirect URL). The ID
token must pass the shared verifier with `aud` = `oidc.clientID`, an `azp` equal to it
when present (required when `aud` has several entries), RS256 or ES256 only, and the
nonce. The user then needs a role from `console.roles`; the session id is minted by the
control plane after both checks and never taken from the request. No access, refresh or
ID token is stored, and `offline_access` is not requested. `next` is honoured only as a
path under `/dashboard/`. A failed login redirects to `/dashboard/?login_error=<code>` with
a code from `state_invalid`, `nonce_mismatch`, `token_invalid`, `exchange_failed`,
`idp_error`, `no_role` or `idp_unavailable`; IdP error text is never echoed. `/auth/login`
itself answers 503 `login_busy` when 10,000 logins are pending and 500 `login_error`
if the attempt cannot be stored. At most 256 groups are read from the token. Discovery
runs in the background with backoff, so an unreachable IdP never blocks startup or
`/policy`; until it succeeds both routes answer 503 `idp_unavailable`. Each attempt logs
one `console_login` line (`result`, `reason`, `sub`, `duration_ms`), never a code, state,
verifier, nonce or token.

## Console roles and the role matrix

The console has two modes, chosen by `console.auth`:

| | `none` (default) | `oidc` |
|---|---|---|
| Who you are | nobody: there is no sign-in | an IdP user with a server-side session (cookie) |
| Reads | open reads: any client that reaches `:7070` | need a session with at least `viewer` |
| Writes | gated by the CP admin bearer (`Authorization: Bearer`, [above](#dashboard-writes-need-the-control-plane-token)) | need a session, the role in the matrix below and the session's CSRF token (`X-Warden-CSRF`, from `GET /auth/me`) |
| Shared tokens | the bearer is the write credential | the shared tokens never open a human route, the bearer included |
| `/auth/me`, `/auth/logout` | absent (`404`) | any live session; logout is CSRF-checked and ends only the console session, not the IdP's |

Moving a deployment from `none` to `oidc` is covered in
[Migrating from none to oidc](#migrating-from-none-to-oidc).

**Roles.** The role is the highest of `admin` > `editor` > `viewer` whose
`console.roles` groups match the user's IdP groups. Roles are computed from the groups
in the login token and stored with the session, and the role is re-derived from the
current `console.roles` on every request, so a `console.roles` change applies after a
restart. A user demoted or removed in the IdP keeps their console role until the
session's idle (1h) or absolute (12h) expiry unless an admin revokes it with the
sessions API below. This is documented behaviour, not a bug: revocation is the
manual control for offboarding.

**Listing and revoking sessions** (admin, `oidc` mode only; `404` in `none` mode).
The *Console sessions* card on the Settings page uses the same API:

- `GET /dashboard/api/sessions` returns the live sessions, newest first:
  `[{handle, iss, sub, email, authMethod, createdAt, lastSeenAt, expiresAt, current}]`.
  `handle` is the hex sha256 of the session id, which cannot be used as a cookie; the
  raw id and the CSRF token are never returned. `current` marks the caller's session.
- `DELETE /dashboard/api/sessions?handle=<hex>` revokes one session (`404` if unknown);
  `DELETE /dashboard/api/sessions?sub=<sub>` revokes every session of that subject
  (`{"revoked": n}`, `0` is not an error). Send exactly one of the two (`400` otherwise).
  The next request with a revoked cookie gets `401`.
- Both need an admin session; `DELETE` also needs `X-Warden-CSRF`. The routes are
  served by the control plane ahead of the dashboard, so the shared and admin bearer
  tokens never reach them (`401` without a session). Each revoke logs
  `console_session_revoked` with `by_sub`, `target_sub` and `count` (and the first 8
  hex characters of a revoked handle), never a cookie value.

**The UI follows the role.** After `GET /auth/me` succeeds the dashboard shows the
signed-in email, the role and a *Log out* button, and hides every control whose
minimum role is above the user's (the `data-min-role` attribute in
`internal/dashboard/index.html`). Hiding is cosmetic: the server checks every request
against the table below. In `none` mode nothing is hidden and no user is shown.

**Role matrix** (`oidc` mode). Generated from the authz table; `TestAuthzMatrixDoc`
fails when the two differ.

<!-- authz-matrix:start -->
<!-- Generated from authzTable() and internal/config/settings_roles.go; do not edit by hand.
     Regenerate: go test ./internal/controlplane -run TestAuthzMatrixDoc -update -->

| Route | Method | Minimum role | Action |
|---|---|---|---|
| `/dashboard/` | GET | viewer | `ui.read` |
| `/dashboard/api/alerts` | GET | viewer | `alerts.read` |
| `/dashboard/api/analytics` | GET | viewer | `analytics.read` |
| `/dashboard/api/audit` | GET | viewer | `audit.read` |
| `/dashboard/api/audit/verify` | POST | viewer | `audit.verify` |
| `/dashboard/api/detection` | GET | viewer | `detection.read` |
| `/dashboard/api/detection` | POST | editor | `detection.write` |
| `/dashboard/api/detection` | PUT | editor | `detection.write` |
| `/dashboard/api/endpoints` | GET | viewer | `endpoints.read` |
| `/dashboard/api/integrations` | GET | viewer | `integrations.read` |
| `/dashboard/api/integrations` | POST | admin | `integrations.write` |
| `/dashboard/api/integrations` | DELETE | admin | `integrations.delete` |
| `/dashboard/api/llmproviders` | GET | viewer | `llmproviders.read` |
| `/dashboard/api/llmproviders` | POST | admin | `llmproviders.write` |
| `/dashboard/api/llmproviders` | PUT | admin | `llmproviders.write` |
| `/dashboard/api/mcp` | GET | viewer | `mcp.read` |
| `/dashboard/api/policy` | GET | viewer | `policy.read` |
| `/dashboard/api/policy` | POST | editor | `policy.write` |
| `/dashboard/api/policy` | PUT | editor | `policy.write` |
| `/dashboard/api/query` | POST | viewer | `query.run` |
| `/dashboard/api/query/generate` | POST | editor | `query.generate` |
| `/dashboard/api/query/schema` | GET | viewer | `query.schema` |
| `/dashboard/api/secrets` | GET | viewer | `secrets.read` |
| `/dashboard/api/secretstore` | GET | viewer | `secretstore.read` |
| `/dashboard/api/secretstore` | POST | admin | `secretstore.write` |
| `/dashboard/api/secretstore` | DELETE | admin | `secretstore.delete` |
| `/dashboard/api/sessions` | GET | admin | `sessions.read` |
| `/dashboard/api/sessions` | DELETE | admin | `sessions.revoke` |
| `/dashboard/api/settings` | GET | viewer | `settings.read` |
| `/dashboard/api/settings` | POST | editor | `settings.write` |
| `/dashboard/api/settings` | PUT | editor | `settings.write` |
| `/dashboard/api/setup` | GET | viewer | `setup.read` |
| `/dashboard/api/traffic` | GET | viewer | `traffic.read` |
| `/dashboard/api/workers` | GET | viewer | `workers.read` |

A method and path with no row is refused (`403`) for every role, `GET` included.

Settings writes (`POST`/`PUT /dashboard/api/settings`) are then checked per changed field:

- An editor may change only `advisory`, `agents`, `cacheTTLSeconds`, `compliance`, `dlp`, `logging`.
- Inside those, these subfields still need admin (list elements are matched by `id`): `agents[].identity`.
- Every other field needs admin, including any field added later.

`POST /dashboard/api/query/generate` is limited to 10 calls a minute per console session (`429` past it).
<!-- authz-matrix:end -->

## Worker admin token

The worker's admin listener (`:9090`, default `127.0.0.1:9090`) serves the same
dashboard as the control plane, with live writers for detection, integrations and the
managed secret store. Those writes use the same guard as above, with a **worker admin
token** that is separate from the control-plane token (`Authorization: Bearer <worker
admin token>`, constant-time compare).

- **Configure it.** Name the env var that holds the token with `--admin-token-env
  <ENV>` or `admin.tokenEnv: <ENV>` in the worker config (the flag wins). The token
  is read from the worker's own environment; the compose files use
  `WARDEN_ADMIN_TOKEN`, defaulting to the demo value `dev-admin-token`. Surrounding
  whitespace is trimmed.
- **What needs the token.** Every state-changing call on the admin listener — any
  method but `GET`/`HEAD`:
  - every `/dashboard/api/*` writer (`PUT /dashboard/api/policy`,
    `PUT /dashboard/api/detection`, …),
  - every `/admin/*` writer — today `POST /admin/refresh-secrets` (drop the secret
    cache and refetch). A writer added under `/admin/` later is guarded by default.
- **Reads stay open.** `GET`/`HEAD` need no token: `/healthz`, `/metrics`, the
  dashboard pages and every `/dashboard/api/*` and `/admin/*` read.
- **Fail closed.** With no token configured (flag and key unset, the variable unset or
  empty or whitespace-only) every write is refused with `403` and a message
  that names `--admin-token-env` and `admin.tokenEnv`. A missing or wrong token is
  `401`.
- **UI.** The dashboard prompts for the admin token after a `401`, exactly as above.
- **Audit.** A refused write logs `worker dashboard write refused` (WARN) with the
  method, path, remote address and reason, never the token.
- Keep the admin port on loopback (the default) or a private network regardless.

```sh
WARDEN_ADMIN_TOKEN=$(openssl rand -hex 32) \
  ./warden run --config configs/config.yaml --admin-token-env WARDEN_ADMIN_TOKEN
curl -X PUT http://127.0.0.1:9090/dashboard/api/detection \
  -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"enabled":true}'
curl -X POST http://127.0.0.1:9090/admin/refresh-secrets \
  -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN"
```

## Identity verification

A worker can attribute traffic to the person behind an agent by verifying a user
token from an OIDC issuer (for example the reference Dex). It is **off unless
configured** and, in P1, only **attributes**: it records who made a request and
never blocks one.

### The `identity` block

The same block is served to managed workers (in the settings document) and read
from local YAML by standalone workers. It holds no secrets.

```yaml
identity:
  defaultMode: attribute        # off (default) | attribute
  issuer: https://dex.example.com/dex
  audience: warden
  allowedAZP: [agent-harness, warden-cli]
  # optional:
  # internalIssuerURL: http://dex:5556   # how containers reach the issuer
  # jwksURL: https://dex.example.com/dex/keys
  # groupsClaim: groups
  # clockSkewSeconds: 60                 # 0..300
  # maxTokenTTLSeconds: 3600

agents:
  - id: research-bot
    identity: attribute          # per-agent override of defaultMode
```

- A worker resolves its mode from the `agents` entry whose `id` matches the
  agent id the worker uses (the single configured agent's id, otherwise
  `agent:<port>`), then `identity.defaultMode`, then off. `require` is a Phase 2
  mode: config validation rejects it, and a worker that is served it (a newer
  control plane) keeps its previous identity config and logs one warning.
- `issuer` and `audience` are required once any mode is `attribute`. An `http`
  issuer is rejected unless `internalIssuerURL` is set; use `internalIssuerURL`
  when workers reach the issuer on a container network (`http://dex:5556`) while
  tokens carry the public issuer.
- `allowedAZP: [agent-harness, warden-cli]` is the recommended value for the
  reference Dex clients. There is no built-in default: empty means no `azp` check.
- The worker builds the verifier at startup **without contacting the issuer**; keys
  are fetched on the first token. A worker with the issuer down still starts and
  serves, and tokens it cannot verify are recorded as unverified and allowed.
- A settings change hot-reloads with no restart. The verifier is rebuilt only when
  `issuer`, `internalIssuerURL`, `audience`, `jwksURL`, `allowedAZP`, `groupsClaim`,
  `clockSkewSeconds` or `maxTokenTTLSeconds` change; a mode-only change swaps the
  mode and keeps the verifier. A failed rebuild keeps the previous config and logs
  one warning (no token data).

### Where the token travels

- `Proxy-Authorization` on `CONNECT` works everywhere, with or without TLS
  termination: Basic with username `session` and the token as password, or
  `Bearer <token>`. It identifies the whole tunnel.
- `X-Warden-Identity: Bearer <token>` needs TLS termination (a CA configured), because
  Warden must read the request headers. On a tunnel it cannot
  decrypt it is never seen. Both headers are stripped before forwarding.
- In transparent mode there is no `CONNECT`, so only `X-Warden-Identity` on
  terminated traffic attributes. A worker in that mode logs a startup warning, as
  does attribute mode without a CA.

### Trust rules

- `sub` is authoritative. Email matching is only ever meaningful with a verified
  email (`email_verified: true`); an unverified email never identifies anyone.
- Only a token with status `valid` yields a policy subject, so group and user rules
  can never match an unverified caller.

### Limits and gaps

- A token is at most 16 KiB.
- The `CONNECT` request line is capped at 8 KiB and the header block at 64 KiB,
  with a 10 s deadline. Over a limit the worker answers 431 and records deny reason
  `malformed_connect` with detail `headers_too_large`.
- In transparent mode (no `CONNECT`) only `X-Warden-Identity` on terminated traffic
  attributes.
- A P1 identity is a **bearer assertion** signed by the IdP and **not yet bound to
  the agent**: whoever holds a valid token can present it. P2 adds binding and
  bundle-distributed JWKS.

### Deployment and rollout

Workers need egress to the issuer. `deploy/k8s/networkpolicy.yaml` carries an
issuer egress rule whose address is an **operator-set value** (replace the
documentation address); the compose templates note which network reaches it
(`egress` for a public issuer, `cp-net` for one on the compose network).

Roll out **control plane first**: upgrade the control plane so it accepts and serves
the `identity` block, then upgrade workers, then set `identity.defaultMode` or a
per-agent `identity` value. Workers on an older build ignore the block, and a worker
on this build with no block stays off, so every step is safe to pause at.

## What's deliberately not here (yet)

The control plane's policy source is a YAML file it re-reads per request, and the
fleet analytics store is in-memory (lost on restart). A database (persistent fleet
analytics), per-user SSO/RBAC policy editing (today one shared token), and per-agent (not just per-worker)
slicing are future work — and because the worker↔control-plane contract is just
HTTP, adding them doesn't change the workers.
