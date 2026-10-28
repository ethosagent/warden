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
   worker as online even when idle, and knows its current policy version and the
   capabilities it advertises (`caps`, e.g. `blocklist/v1`), so the console can flag
   workers that would silently ignore newer policy fields.
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
plane, check and archive the old segment with `admin-audit verify` and `admin-audit
export` (below), put the new key at `--admin-audit-key-file` with the
same `cp-audit-hmac.key` beside it, and start once with
`--admin-audit-new-segment=<new key_id>`. The control plane appends one
`audit.segment_start` entry signed by the new key, linked to the old head and naming
the previous `key_id`; every later row carries the new `key_id`, and verification
reads each segment's public key from the chain. The flag must equal the loaded key's
`key_id` (anything else stops startup) and is a no-op once the head is on that key,
so leaving it set can never rotate twice. The flag without
`console.adminAudit.enabled` is a startup error. The step-by-step procedure is
[docs/runbooks/admin-audit-key.md](runbooks/admin-audit-key.md). Automatic rotation is W-P2-KEYS-06.

**Startup verification.** After the key check, every enabled start verifies the
newest 1000 rows and the head signature. A failure logs
`admin audit chain verification failed` at ERROR (with `first_bad_seq` and `reason`)
and publishes an `admin_audit_verify_failed` Finding (severity critical) to the alert
pipeline; a chain that cannot be read at all raises the same Finding with reason
`verify_error`. The control plane still starts and serves `/policy`.

**Offline verify and export.** Two subcommands check the chain without a running
control plane, for example after a restore or when the control plane is down. Both
open `<state-dir>/warden-cp.db` read-only (the file's bytes and mtime stay unchanged),
read public keys from the chain, never load the signing key and write no audit row.

```sh
warden control-plane admin-audit verify --state-dir /data [--from-seq N] [--anchor seq:hash]
warden control-plane admin-audit export --state-dir /data --out audit.jsonl [--include-identity]
```

- `admin-audit verify` prints `{ok, checked, firstBadSeq, reason, headSeq, headHash,
  lastVerifiedSeq}` (hashes in hex) and exits 0 when the chain verifies, 1 when it does
  not (`firstBadSeq` is the first bad entry) and 2 on a usage or I/O error. `--anchor`
  takes an earlier `headSeq:headHash` and fails when the newest rows were removed.
- `admin-audit export` writes JSONL to a new file (mode 0600, never overwriting): one
  `keys` record with every `key_id`, its public key and first seq, then every entry in
  seq order. The side-table sub and email are left out unless `--include-identity` is
  set. `adminaudit.VerifyExport` verifies the file with no database.
- A state dir migrated by a newer Warden still opens: the read-only open tolerates
  migrations of other features it does not know, and refuses only an unknown
  `adminaudit/` migration (a chain layout this binary cannot read).

**What is recorded.** With the log on, every admin change made through the control
plane writes one row: dashboard policy, settings, detection, integrations and
llmproviders writes, `/dashboard/api/secretstore` POST and DELETE, `/central/secrets`
POST, `DELETE /central/secrets/{key}` and the admin session revoke
(`DELETE /dashboard/api/sessions`). Which routes count comes from the authz route
table (`Audited`), not from the HTTP method, so worker heartbeats, ingest, `/policy`
and the read-only POSTs (`/dashboard/api/query`, `query/generate`, `audit/verify`,
`admin-audit/verify`) never write a row. Each row carries:

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

**Sign-ins and sign-outs.** In `oidc` mode the login and logout handlers record
their own rows (the middleware never wraps `/auth/*`), all with target `session`,
`auth_method` `oidc` (`breakglass` for the logout of a break-glass session), a `request_id` (echoed as `X-Request-Id`) and `client_ip`:

| Action | When | Actor | Outcome | Details |
|---|---|---|---|---|
| `auth.login` | `GET /auth/callback` created a session | the verified ID token's `sub` and `email`, role from `console.roles` | `ok` (status 302) | `{role}` |
| `auth.login_failed` | `GET /auth/callback` failed after its pending `state` was consumed | the verified token's subject when there is one (`no_role`), otherwise `anonymous` | `denied` or `error` (status 302) | `{reason}` |
| `auth.logout` | `POST /auth/logout` ended a live session | the session's user, captured before the row is deleted | `ok` (status 204) | none |
| `auth.breakglass` | `POST /auth/breakglass` (only with `console.breakGlass.enabled`) | `breakglass:<configured username>` on a username match, `breakglass:unknown` otherwise; `auth_method` `breakglass` | `ok` (200), `denied` (401), `error` (503); a rate-limited request adds at most one `denied` row (`{reason: rate_limited}`) per address per 15 minutes | none |

`target_ref` of `auth.login` and `auth.logout` is the first 8 hex characters of the
session's id hash (the `console_login`/`console logout` log lines use the same value),
so a sign-in and its sign-out can be matched. `details.reason` is a closed set:

| `reason` | Outcome | Cause (`login_error` code) |
|---|---|---|
| `no_role` | `denied` | the verified user matches no `console.roles` group (`no_role`) |
| `bad_token` | `denied` | the ID token failed verification or its nonce did not match (`token_invalid`, `nonce_mismatch`) |
| `state_invalid` | `denied` | the state was valid but the browser-binding login cookie was missing or wrong (`state_invalid`) |
| `idp_error` | `error` | the IdP answered with an error, or its keys could not be fetched (`idp_error`, `idp_unavailable`) |
| `exchange_failed` | `error` | no code, the token exchange failed, or the session could not be stored (`exchange_failed`) |

A callback with a missing, unknown or expired `state` consumed nothing and writes no
row, and neither does a logout without a live session or one refused for CSRF. At most
20 `auth.login_failed` rows per client address are written per minute. At most 4,096
addresses are tracked at once; while all of them are inside their minute, a new
address writes no row either. Further attempts only increment an in-memory counter and
log `admin_audit_login_failed_rate_limited`, at most once a minute per address.
Successful logins are never rate-limited. The authorization code, `state`, PKCE
verifier, nonce, tokens and cookie values never appear in a row or a log line. If a
row cannot be appended, the entry is logged at ERROR with `persist_failed=true` and
the `admin_audit_degraded` alert is raised as above, but the sign-in or sign-out
itself still succeeds: it changes no admin state.

**Reading and verifying in the dashboard.** With the log on, the control plane
serves three read-only routes and an **Admin log** tab (separate from the receipts
**Audit** tab and its `/dashboard/api/audit*` routes). Off, or on a worker, all three
answer 404 and the tab stays hidden; the tab is also hidden from viewers and editors.
Nothing in the dashboard writes to the chain, and none of these routes is recorded.

| Route | Role (oidc) | What it returns |
|---|---|---|
| `GET /dashboard/api/admin-audit` | admin | `{entries, nextCursor}`, newest first |
| `POST /dashboard/api/admin-audit/verify` | admin | `{ok, checked, firstBadSeq, reason, headSeq, headHash, lastVerifiedSeq, partial}` |
| `GET /dashboard/api/admin-audit/pubkey` | any role | `{alg: "ed25519", keys: [{keyId, publicKey, firstSeq}]}` |

The list takes `actor` (a sub or an `actor_id`), `action`, `outcome` (`ok`,
`denied`, `rejected`, `error`), `since` (RFC3339), `limit` (1 to 200, default 50)
and `cursor`; a malformed value answers 400. Pass the returned `nextCursor` as
`cursor` for the next page; it is 0 on the last one. Each entry has the signed fields
(hashes in hex) plus the actor's plaintext sub and email from the side table, never
a signature or a request body.

Verify streams the chain and checks seq continuity, every `prev_hash` link, each
recomputed entry hash, each Ed25519 signature under the key its `key_id` names (keys
come from the chain's genesis and `segment_start` entries), that the key changes only
at a `segment_start`, and the signed `actor_id` against the side table with the
control plane's HMAC key. The optional body `{fromSeq, anchor: {seq, hash}}` starts
at `fromSeq` and compares the entry at `anchor.seq` with a hex entry hash you saw
earlier (for example the head of an emitted log line), which also detects a deleted
tail. One call checks at most 10,000 rows: when `partial` is true, call again with
`fromSeq` = `lastVerifiedSeq + 1` (the tab does this for you). On failure `ok` is
false, `firstBadSeq` is the first row that does not verify and `reason` names the
check (`entry_hash`, `prev_hash`, `signature`, `seq_gap`, `actor_id`,
`anchor_mismatch`, ...); the control plane also logs it at WARN. One verification
runs at a time; a concurrent call answers 429. In `console.auth: none` the verify
POST, like every dashboard POST, needs the `--admin-token-env` bearer.

The pubkey route lists every key the chain declares, so entries signed before a
manual key change stay verifiable; the tab shows each key with a copy button.

Offline CLIs that change admin state record through the same chain with
`adminaudit.OpenForCLI`: actor `cli:<os user>`, auth_method `cli`, the same key
check, and never a new key while rows exist. On a state dir where audit was never
enabled they skip the record with a notice.

**Hand edits of the served YAML.** In the default file policy-store mode, when the
3-second re-read finds served-config bytes that no control-plane writer produced,
the control plane still serves them and appends one `config.external_change` row
(auth_method `system`, target `policy`, before `file:<old sha256>`, after
`file:<new sha256>`), once per distinct file hash; the row and its log line carry
only the two hashes, never the file's content or path.

#### Anchoring the audit chain

The hash chain proves the rows agree with each other, but someone who can write the
state dir can still delete the newest rows or restore an older backup, and the shorter
chain still verifies. To catch that, the control plane also writes the chain to its log
(stdout, at INFO whatever `logLevel` says), as `schema=warden.admin.v1` lines:

- `msg=admin_audit`, one per committed entry, after its transaction commits: `seq`,
  `ts`, `entry_hash`, `prev_hash`, `key_id`, `actor_id`, `actor_sub`, `actor_email`,
  `actor_role`, `auth_method`, `action`, `target`, `target_ref`, `outcome`,
  `http_status`, `before_hash`, `after_hash`, `client_ip`, `request_id` and `details`.
  The plaintext `actor_sub` and `actor_email` appear only here and in the side table,
  never in the signed bytes. Only the fields of a validated entry are written: no
  request body, bearer token or secret value.
- `msg=admin_audit.checkpoint`, the chain head (`head_seq`, `head_entry_hash`,
  `key_id`) at startup, every 5 minutes and at shutdown.

Ship these lines off-host (your log collector or SIEM) where the control plane's state
dir cannot reach them. The newest `admin_audit.checkpoint` or `admin_audit` line you
hold is an anchor: verify the chain with `admin-audit verify --anchor <seq>:<entry_hash>`
(see "Offline verify and export" above). Verification fails with `anchor_missing` when the
chain no longer reaches that seq (rows deleted from the tail, or an older backup
restored) and `anchor_mismatch` when the entry at that seq has a different hash. A
log line that fails to write never fails or rolls back the admin change itself.

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

**Break-glass login.** With `console.breakGlass.enabled` (and `console.auth: oidc`),
`POST /auth/breakglass` with `{"username","password"}` (JSON, at most 4 KiB, same-origin)
opens an admin session for when the IdP is down. It is not CSRF-checked (there is no
session yet) and answers `404` when break-glass is off. Failures are limited to 5 per
client address (`RemoteAddr`, never `X-Forwarded-For`) and 20 in total per 15 minutes;
a limited request answers `429 {"error":"rate_limited"}` with `Retry-After` and never
runs argon2id, and at most two verifications run at once (`429 {"error":"busy"}`). A
wrong username and a wrong password are indistinguishable (`401
{"error":"invalid_credentials"}`, one argon2id run each). The session has role `admin`,
`auth_method` `breakglass`, an absolute expiry of `sessionTTL` that activity never
extends, and a `Secure` cookie even behind a TLS terminator; a new login revokes the
earlier break-glass session. The hash is re-read on every attempt (`503
breakglass_unavailable` when it cannot be read). Every attempt logs one ERROR line
`breakglass_login` (outcome, client address and, on success, the 8-character session
hash), and publishes a `breakglass_login` Finding: critical per login, high for
failures. With admin audit on, a row that cannot be written fails the login closed (`503
audit_unavailable`). The limiter is in memory: its windows reset when the control plane
restarts. The password and the submitted username are never stored or logged.

Enabling break-glass is guarded at startup. The control plane refuses to start when
`--state-dir` is empty, when the hash does not load or is outside the argon2id bounds (the
error names `console.breakGlass.passwordHashEnv` or `passwordHashFile`, never the value),
and when it would serve plain HTTP (no `--ca-cert`/`--ca-key`) on a non-loopback `--listen`
address (`0.0.0.0`, `::`, an empty host such as `:7070`, any non-loopback IP or hostname)
unless `console.breakGlass.allowBehindTLSTerminator` is true. It logs a WARN at startup when
no alert pipeline exists or no integration's `alerts.match` routes a critical
`breakglass_login` Finding, and when `console.adminAudit.enabled` is false. While a
break-glass session is live it logs the WARN `breakglass_session_active` (count and earliest
expiry, no session id) every 5 minutes, and the dashboard shows a red banner with the
expiry. The control plane starts, serves workers and accepts break-glass logins with the
IdP unreachable; `/auth/login` answers `503 idp_unavailable` until discovery succeeds.

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
| `/dashboard/api/admin-audit` | GET | admin | `adminaudit.read` |
| `/dashboard/api/admin-audit/pubkey` | GET | viewer | `adminaudit.pubkey` |
| `/dashboard/api/admin-audit/verify` | POST | admin | `adminaudit.verify` |
| `/dashboard/api/alerts` | GET | viewer | `alerts.read` |
| `/dashboard/api/analytics` | GET | viewer | `analytics.read` |
| `/dashboard/api/audit` | GET | viewer | `audit.read` |
| `/dashboard/api/audit/verify` | POST | viewer | `audit.verify` |
| `/dashboard/api/blocked-users` | GET | admin | `blocked_users.read` |
| `/dashboard/api/blocked-users` | POST | admin | `blocked_users.add` |
| `/dashboard/api/blocked-users/{id}` | DELETE | admin | `blocked_users.remove` |
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
| `/dashboard/api/policy/versions` | GET | viewer | `policy.versions.read` |
| `/dashboard/api/policy/versions/{v}` | GET | viewer | `policy.version.read` |
| `/dashboard/api/policy/versions/{v}/diff` | GET | viewer | `policy.diff` |
| `/dashboard/api/policy/versions/{v}/rollback` | POST | editor | `policy.rollback` |
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

## Policy history (`--policy-store`)

The allow/deny policy and the distributed settings can live in an append-only
versioned store in control-plane state instead of being edited in place in the
served YAML. Every save creates a new version with its author and message,
editors can diff any two versions and roll back, and workers are always served
the head version. The feature is off by default; see the release plan at the
end of this section.

### Turning it on

`warden control-plane --policy-store=file|versioned` picks where the policy
served on `/policy` comes from.

- `file` (the default) serves the served config YAML, exactly as before. With
  `--state-dir` the served YAML is a writable copy seeded once from `--config`
  (`<state-dir>/config.yaml`); without `--state-dir` the dashboard keeps
  editing `--config` in place.
- `versioned` serves the head of the version history in
  `<state-dir>/warden-cp.db` and requires `--state-dir`; without it, or with any
  other flag value, the control plane refuses to start.

### Version 1: the migration

The first versioned start on an empty store imports the served config's
allow/deny lists and settings as version 1 (author `system:import`, source
`import`, message `initial import from <served path>`). `/policy` serves the
same bytes and ETag before and after, so no worker sees a change. If the import
would change the ETag, the control plane refuses to start and leaves the store
empty; start with `--policy-store=file` and report it. A store that already has
versions is never re-imported, and two control planes racing the first start
import once. With `console.adminAudit.enabled` the import appends one
`policy.initial_import` admin audit row (target `policy`, auth_method `system`,
before `file:<sha256 of the served YAML>`, after `v1:<doc_sha256>`); a failed
append is logged at ERROR and does not stop startup.

### What a version holds, and what it never holds

- Each version holds the allow/deny lists and the distributed settings
  (including `llmProviders`), its parent version, the author (sub, email,
  kind), a message, the source (`import`, `policy`, `settings`,
  `llmproviders`, `rollback`) and the `doc_sha256` of the stored doc. Versions
  and the publish log are append-only: SQLite triggers refuse an UPDATE or
  DELETE.
- **Credential values are never stored.** An AWS `secretAccessKey` is kept in a
  version only as its fingerprint, `sha256:<16 hex>`; the live value stays in
  the served YAML `secretStore` block and is merged in when `/policy` is built,
  so workers get the same bytes as before. In history responses and diffs a
  credential appears only as its fingerprint, never the value.
- Serve-time overlay data is not stored either. The credential
  (versioned mode) and the user block list (whenever a state dir is set) are the
  overlays today. A rollback therefore never restores an old credential or
  block list.
- CP-local blocks (integrations, detection, `central`, `controlPlane`, ...)
  are not versioned; their editors keep rewriting the served YAML.

### Saves, authors and field ownership

- Dashboard saves of the policy, the settings form and the LLM providers each
  create a new version from the head (source `policy`, `settings` or
  `llmproviders`). Each writer changes only the fields it owns and carries
  every other field from the head: the policy save owns the allow/deny lists,
  the LLM providers save owns `llmProviders`, and the settings save owns the
  rest of the settings except `dlp` and `advisory`, which the settings form
  does not edit and which are always carried from the head (change them with
  `warden policy import`).
- An edit the config loader rejects (for example an empty allowlist) returns
  the loader error and creates no version; a save that changes nothing creates
  none either.
- The author is the signed-in user (sub and email, kind `oidc`),
  `breakglass:<username>` for a break-glass session, or `anonymous` (kind
  `none`) in `console.auth: none`, where the bearer proves possession of the
  shared token, not an identity.
- A settings save with an empty `secretAccessKey` keeps the live credential. A
  new value is written to the served YAML `secretStore` block (the only place
  the credential lives) and the version stores only its fingerprint; if the
  version cannot be created the YAML is put back.

### The version header, If-Match, 409 and 428

- Policy, settings and LLM providers share one head version. Their GETs
  (`/dashboard/api/policy`, `/dashboard/api/settings`,
  `/dashboard/api/llmproviders`) and `GET /dashboard/api/policy/versions`
  return it as `version` (`head` for the history list) in the body and in an
  `X-Warden-Policy-Version: N` header; in file mode neither is present.
  `/policy`'s content-hash ETag is unchanged.
- In versioned mode every save must send `If-Match: "v<N>"` with the version
  it was based on. If the head has moved since, the save returns `409
  {"error":"policy_conflict","head":M,"author":{"sub":...,"email":...}}` (the
  head's author, never doc content) and creates nothing, so a settings save
  makes a concurrent policy save from the same version conflict. A missing
  `If-Match` on a save or a rollback returns `428
  {"error":"precondition_required"}` and a malformed one 400; neither creates a
  version.
- A save may also send an optional message in `X-Warden-Policy-Message`,
  percent-encoded UTF-8 (as `encodeURIComponent` writes it), at most 512
  characters after decoding, with control characters stripped; it is stored on
  the new version, and a longer or badly encoded value returns 400.
- In file mode `If-Match` and `X-Warden-Policy-Message` are ignored and saves
  work as before.

### History, diff and rollback

In versioned mode the control plane serves these routes (in file mode they
answer 404). Reads need the viewer role and a rollback the editor role (see the
role matrix above).

| Route | What it returns |
|---|---|
| `GET /dashboard/api/policy/versions?cursor=&limit=` | `{"head":N,"versions":[...],"next_cursor":C}`: version metadata (version, parent, created_at, author_sub, author_email, author_kind, message, source, doc_sha256), newest first, 50 per page by default and at most 200; pass `next_cursor` as `cursor` for the next page (0 = no more). |
| `GET /dashboard/api/policy/versions/{v}` | One version's metadata and its `doc`, credential as a fingerprint. |
| `GET /dashboard/api/policy/versions/{v}/diff?against={u}` | `{"from":u,"to":v,"diff":{"allow":[...],"deny":[...],"settings":[...]}}`: the structural diff from `u` (default: the head) to `v`, by entry and settings path, each change `added`, `removed` or `changed`. With the default it is what a rollback to `v` would change. |
| `POST /dashboard/api/policy/versions/{v}/rollback` | Body `{"note":"..."}` (optional, at most 512 characters). Publishes version `v`'s doc as a **new** head version (source `rollback`, message `rollback to v<N>[: note]`); history is never rewritten. Returns `{"head":M,"changed":true}` and `X-Warden-Policy-Version: M`; a target equal to the head creates nothing (`changed: false`). |

A rollback keeps the head's credential fingerprint (the served credential does
not change), is revalidated with today's config loader (a target that no longer
validates answers `422 {"error":"invalid_policy"}` and creates nothing), and
uses the same conflict check as a save. An unknown version answers 404.

The console's Guardrails → Egress tab shows a History card on these routes in
versioned mode (hidden in file mode): versions newest first with author,
relative time, source and message, 20 at a time with "Load more"; selecting one
shows the server's structural diff from head to that version (added, removed
and changed entries and settings paths with old and new values); editors and
admins get a Roll back button that asks for confirmation naming the target
version and an optional note. The policy, settings and LLM provider saves ask
for an optional message and send `If-Match`; on a 409 the console says
`policy changed by <author> (v<N>)`, takes the new head and keeps the unsaved
edit on screen.

### The served YAML: write-through mirror and drift

- The served YAML is a write-through mirror of the head: after every head move
  (a dashboard save, a rollback, or a version from another process seen by the
  3-second check) the control plane renders the head's policy and settings
  blocks into it, with the live credential, through the same validated atomic
  write. So `--policy-store=file` or an older binary serves the same policy. A
  mirror failure (for example a read-only file) is logged at ERROR with the
  version and never fails the save.
- A hand edit of the YAML's policy or settings blocks is drift: it is never
  served. The 3-second check logs `served config policy block differs from
  head; ignored` (with `file_sha256`, the hash of those blocks, and `head`) once
  per distinct file hash, `GET /dashboard/api/policy` reports `drift: true` and
  the Guardrails page shows a banner. With `console.adminAudit.enabled` each
  distinct file hash appends one `config.external_change` row (before
  `v<head>:<doc_sha256>`, after `file:<file_sha256>`); the file-mode check in
  the admin audit section is not used. Edits to the credential or to CP-local
  blocks are not drift. Bring an edit in with `warden policy import`; putting
  the file back, or the next save, clears the drift.
- The first check after a restart does not write the file: it compares the file
  with what the head would render to, so an edit made while the control plane
  was down shows as drift instead of being overwritten.
- The control plane checks for a new head every 3 seconds and only re-reads a
  version when the head moved, so a version written by another process reaches
  workers within 3 seconds plus one long-poll cycle. The `/policy` hot path
  never reads the database.
- Startup fails closed: if the store cannot be read, the head points at a
  missing version, or a version fails its `doc_sha256` check, the control plane
  refuses to start and never falls back to the YAML. A read error at runtime
  keeps serving the last good policy and logs a warning.

### `warden policy import` and `warden policy export`

- `warden policy import --state-dir <dir> --file <yaml> [--message m]
  [--admin-audit-key-file F] [--expected-head N]` stores a config YAML's
  policy, settings and llmProviders blocks as a new version, with the control
  plane running or stopped. The file is loaded strictly (an unknown key is an
  error) and checked like a dashboard write, against the file itself and
  against `<dir>/config.yaml` when it exists. A raw `secretAccessKey` is stored
  as its fingerprint; it must match the served config's credential, because the
  store cannot carry a new value (change the credential in the served config
  instead). A file without the credential is refused while the served config
  has one, so an unedited export cannot drop it. The version is authored
  `cli:<os user>` with source `import`, and is created by compare-and-swap from
  the current head (or `--expected-head`): a moved head exits non-zero naming
  the new head, and a file equal to the head prints `no change` and exits 0.
  The state dir must already hold the store (any control plane of this version
  started with `--state-dir` creates it). When admin audit has rows in the
  state dir, the import appends a `policy.import` row (actor `cli:<os user>`,
  auth_method `cli`, target `policy`, before `v<head>:<doc_sha256>`, after
  `v<new>:<doc_sha256>`); a missing or mismatching key file aborts before the
  version is written. Without admin audit it prints a one-line notice.
- `warden policy export --state-dir <dir> [--version N]` opens the database
  read-only and writes one version (default: the head) to stdout as a config
  YAML (policy, the settings blocks and llmProviders) that the loader accepts,
  for a downgrade, disaster recovery or a GitOps hand-off. Credential values and
  fingerprints are never written: a version with an AWS credential is exported
  without `secretStore.aws.accessKeyId`/`secretAccessKey`, with a note on
  stderr; add them back before you serve or re-import the file.

### Fleet policy version

Every head move appends a publish-log row with the `/policy` ETag it serves. A
served-ETag change without a new version (an overlay change, such as the
credential edited in the served YAML, or a version recorded without the ETag
the control plane actually serves) is appended by the control plane on its next
refresh, with the overlay's name or `external` as the reason, and logged as
`policy publish logged`. The fleet view maps each worker's heartbeat ETag to the newest
version with that ETag and shows `v<N> · <etag>`
(`policyVersion` in `GET /dashboard/api/workers`); an ETag with no row, and
every worker in file mode, shows the bare ETag. The `behind` flag still
compares the worker's ETag with the one served now.

### What is audited

With `console.adminAudit.enabled`, these policy changes append admin audit
rows (target `policy`, before and after as `v<N>:<doc_sha256>` in versioned
mode):

- `policy.initial_import`: the version 1 migration (auth_method `system`).
- `policy.write`: a dashboard policy save, including a rejected 409 (outcome
  `rejected`); settings and LLM providers saves are `settings.write` and
  `llmproviders.write`.
- `policy.rollback`: a rollback.
- `policy.import`: `warden policy import` (auth_method `cli`).
- `config.external_change`: a hand edit of the served YAML (drift in versioned
  mode, a served change in file mode; auth_method `system`).

History reads and diffs are not audited. Credentials appear in history only as
fingerprints; audit rows carry only state hashes, and exports leave the
credential out.

### Downgrade

Because the served YAML mirrors the head, restarting with
`--policy-store=file` (or an older binary) serves the same policy. Edits made
in file mode go to the YAML only, not to the store; before switching back to
`versioned`, bring them in with `warden policy import`, or they show as drift
and are not served. `warden policy export` writes any version as a loadable
YAML if the mirror is lost.

### Release plan

- **Release N** (the first release with policy history) ships the versioned
  store only behind `--policy-store=versioned`; the default stays `file`.
- **Release N+1** flips the default to `versioned`. `--policy-store=file` stays
  as an explicit opt-out, and a control plane started without `--state-dir`
  keeps file mode with a startup WARN.
- **Release N+2** removes YAML as a policy source: `--policy-store=file` is
  removed, the served YAML is only the write-through mirror of head, and hand
  edits are never served (they come in through `warden policy import`).

## Block list: offline CLI

The user block list lives in `<state-dir>/warden-cp.db`, outside policy
versions. When the console or the IdP is unavailable, or a script needs to
block someone without a browser session, use the command line. It works with
the control plane running or stopped.

```sh
warden control-plane block add --state-dir D [--sub S] [--email E] --reason R
warden control-plane block remove --state-dir D --id ID
warden control-plane block list --state-dir D [--json]
```

- `add` needs `--sub`, `--email` or both, and prints the new id. It uses the
  same store and validator as the admin API: the email is lowercased, a
  duplicate sub or email is refused, the reason is at most 512 bytes with no
  control characters, and the count and size limits apply. A validation error
  exits 1 with the API's message.
- `remove` exits 2 for an id that is not on the list.
- `list` opens the database read-only.
- `--admin-audit-key-file` (add and remove) defaults to `<state-dir>/cp-audit.key`.

**Audit.** With admin audit enabled in the state dir, each add and remove
appends one `blocked_users.add` or `blocked_users.remove` row (actor
`cli:<os user>`, auth_method `cli`, target `blocked_users`, target_ref
`block:<id>`). The reason text is not recorded in the row or logged. The
audit key is checked first: with audit rows present and the key missing or not
matching, the command exits non-zero and writes nothing. If the audit append
still fails, an add is rolled back and a remove deletes nothing. The block and
its audit row are two commits, not one transaction, so a crash between them
(or two concurrent removes of one id) can leave one without the other. A state dir where audit was never enabled
gets a one-line notice and no row.

**Pickup.** A running control plane polls `PRAGMA data_version` every 2 s and,
when another process wrote, refreshes the served policy and runs the block
store's change callbacks. A connected worker then receives the new list within
2 s plus one long-poll round trip.

The CLI has no console identity, so the self-unblock check of the admin API does
not apply. Write access to the state dir already allows policy changes, so
this adds no new authority.

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

### Block list enforcement

A worker denies every request from a user on the block list (`policy.blockedUsers`,
by IdP `sub` and/or email). The list lives in the worker's policy evaluator and is
swapped with allow/deny, at boot, on every long-poll update and for standalone
YAML. It is checked at `CONNECT` (a `403` with `{"error":"user_blocked"}` before any
dial, TLS or raw tunnel) and again on every request (HTTP/1.1 keep-alive, h2, gRPC
streams and WebSocket upgrades, before any policy gate, judge or secret swap). Each
deny records reason `user_blocked` and ends the session. `sub` is an exact match;
email is matched case-insensitively.

Matching uses the claims of any token the worker parsed, verified or not (valid,
expired, bad signature): a match can only deny. Gaps:

- A request that carries **no token** is anonymous in attribute mode and is not
  matched (P2 require mode closes this).
- With `identity` mode off the worker parses no token, so there are no claims to
  match: the block list needs attribute mode.
- In transparent mode there is no `CONNECT` and no `Proxy-Authorization`, so the
  `CONNECT` check cannot run; only requests carrying `X-Warden-Identity` on
  terminated traffic are matched.
- Every policy update also resets rate-limit windows, so each block or unblock
  resets them on every worker.
- Sessions that are already open are cut at their next request; a user who is
  blocked is cut at once (see [Block list](#block-list)).

### Deployment and rollout

Workers need egress to the issuer. `deploy/k8s/networkpolicy.yaml` carries an
issuer egress rule whose address is an **operator-set value** (replace the
documentation address); the compose templates note which network reaches it
(`egress` for a public issuer, `cp-net` for one on the compose network).

Roll out **control plane first**: upgrade the control plane so it accepts and serves
the `identity` block, then upgrade workers, then set `identity.defaultMode` or a
per-agent `identity` value. Workers on an older build ignore the block, and a worker
on this build with no block stays off, so every step is safe to pause at.

## Block list

An admin blocks a person by Dex `sub` or email. The list ships to workers on the
policy wire as `blockedUsers`; a worker denies any request whose identity claims
match with `403 {"error":"user_blocked"}` and a deny event with reason
`user_blocked`. Matching uses the claims of any token the worker parsed, verified
or not (an expired or bad-signature token still names its user), because a match
can only deny.

### Open sessions are cut

A request that **arrived** under the old policy completes under it. A **session**
that the new list matches is **cut when the change is applied**, not drained:

- a raw CONNECT tunnel, an HTTP/2 connection and a WebSocket are closed at once,
  and the close interrupts active streams, not only new ones;
- an idle HTTP/1 keep-alive connection is closed without another request;
- an HTTP/1 connection that is mid-request finishes that request, delivers its
  full response, and is then closed. An HTTP/1 streaming response (for example
  SSE) that began before the block runs to its end; the same stream over h2, a
  tunnel or a WebSocket is cut at once.

After each applied policy change the worker closes the matching sessions and
writes **one** `user_blocked` deny event per closed session (its protocol, domain
and the user's sub). Sessions with no identity are not tracked, so anonymous
traffic pays nothing. Two metrics report it, neither labelled with identity:
`warden_blocklist_entries` (users on the list after the last applied change) and
`warden_blocklist_sessions_closed_total`.

### How fast a block applies

`BlockStore.Add` refreshes the served policy, which wakes held long-polls at
once, so a connected worker applies a block within about 1 s. The offline CLI
(`warden control-plane block add --state-dir`) adds at most one 2 s `data_version`
poll. A worker backing off after control-plane errors applies it after at most the
15 s backoff plus one long-poll round trip; `controlPlane.longPollWait` (default
30 s) does not delay a changed policy.

### Known gaps

- **No token, no match.** In identity `attribute` mode a request or session that
  carries no token at all has no claims to match and is not blocked. P2 `require`
  mode closes this gap.
- **Identity off.** With identity mode off the worker parses no token, so nothing
  is matched; turn identity on (`attribute`) for the block list to bite.
- **Transparent mode.** There is no CONNECT, so only an `X-Warden-Identity` header
  on terminated traffic identifies a user; a transparent connection is tracked
  only once such a header resolves.
- **Rate limits restart.** Every policy replace resets the rate-limit windows, so a
  block change resets them fleet-wide.

### Degraded modes

- **Control plane unreachable:** a worker keeps its last list and never unblocks
  on its own; new blocks apply when it reconnects.
- **Dex down:** admins cannot sign in to the console; use break-glass to block or
  unblock.
- **No `--state-dir`:** the control plane has no block-list store, so the
  block-list API answers 503 `state_dir_required` and `/policy` is unchanged.

## What's deliberately not here (yet)

The control plane's policy source is a YAML file it re-reads per request (or,
with `--policy-store=versioned`, the versioned store above), and the
fleet analytics store is in-memory (lost on restart). A database (persistent fleet
analytics), per-user SSO/RBAC policy editing (today one shared token), and per-agent (not just per-worker)
slicing are future work — and because the worker↔control-plane contract is just
HTTP, adding them doesn't change the workers.
