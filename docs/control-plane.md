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

Every state-changing call under `/dashboard/api/` (`PUT`, `POST`, `PATCH`,
`DELETE`: policy, settings, integrations, detection, LLM providers, the secret
store, and the query and audit-verify `POST`s) must carry
`Authorization: Bearer <control-plane token>`, the same token workers use for
`/policy` and `/central/*`, checked in constant time.

- **Fail closed.** A control plane started without a token (`--token-env` unset
  or the variable empty) refuses every dashboard write with `403` and a message
  saying how to configure the token. There is no open mode for dashboard writes.
  A whitespace-only token counts as not configured. The worker-facing endpoints
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
  -H "Authorization: Bearer $WARDEN_CP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"allowlist":[{"domain":"api.openai.com"}],"denylist":[]}'
```

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

In `oidc` mode the control plane also needs a non-empty value in the client-secret env
var and `--state-dir`. Until W-P1-SSO-06 lands it then refuses to start with
"console oidc enforcement is not available in this build", so no build serves login
routes while a human route still accepts the shared bearer. See
`configs/config.control-plane.yaml` for commented examples.

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
`idp_error`, `no_role` or `idp_unavailable`; IdP error text is never echoed. Discovery
runs in the background with backoff, so an unreachable IdP never blocks startup or
`/policy`; until it succeeds both routes answer 503 `idp_unavailable`. Each attempt logs
one `console_login` line (`result`, `reason`, `sub`, `duration_ms`), never a code, state,
verifier, nonce or token.

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
