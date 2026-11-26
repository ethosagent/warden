# Token service

The token service is the control plane's RFC 8693 token-exchange endpoint,
`POST /oauth2/token`. A harness sends it a user's IdP ID token and a signed
assertion from the agent's own key. It answers with a short-lived **Warden
token**: a JWT signed by the control plane, bound to that agent, that workers
verify offline in `require` mode.

This page is for two readers. **Operators** turn the service on and run it
([enable it](#enabling-it-safely), [degraded modes](#degraded-modes),
[revocation](#revoking-access), [records and metrics](#issuance-records-and-metrics)).
**Harness authors** call it ([the request](#the-request), [errors and retries](#errors-and-which-to-retry),
[the assertion](#the-client-assertion), [the token](#the-issued-token)). The exact
claim and header checks a worker applies to the token are in the
[identity contract](identity-contract.md#warden-tokens-phase-2); the route-level
reference (startup checks, the publish-window guard, session revoke routes) is the
[control plane's token endpoint section](control-plane.md#token-endpoint-rfc-8693).
If you only want a working harness, the [recipes](recipes/README.md) wire all of
this with `warden identity forward`.

## The flow

```
  user ──login──> IdP (Dex, ...) ──ID token──> harness
                                                 │  signs an assertion with the agent's private key
                                                 ▼
                         POST /oauth2/token  (subject_token + client_assertion)
                                                 │
   control plane: verify assertion ─ verify ID token ─ block list ─ agent groups ─ scope ─ sign
                                                 │
                                                 ▼
                        Warden token (typ wt+jwt, act.sub = agent, cnf.jkt = agent key)
                                                 │  Proxy-Authorization on CONNECT
                                                 ▼
                    worker (require mode): checks agent match + key liveness
```

The agent never holds a real upstream credential, and the worker never sees the
IdP token. Because the token names the agent (`act.sub`) and its key (`cnf.jkt`),
one worker serves exactly one agent and refuses a token minted for another.

**What the token proves, and what it does not.** Binding is **agent match plus key
liveness**: the worker checks `act.sub` against its own agent and `cnf.jkt` against
the agent's registered keys. It is **not proof of possession**. The Warden token is
a bearer token, so anyone who holds an unexpired one can present it to that agent's
worker until it expires. Replay of a stolen token is a documented Phase 2 non-goal;
proof of possession (agent mTLS, `cnf` `x5t#S256`) comes later. Limit the exposure
with the short lifetime, by keeping the token out of the agent (the sidecar holds
it), and by [revoking access](#revoking-access). See
[binding in the identity contract](identity-contract.md#agent-binding-of-warden-tokens).

## Enabling it safely

The service is **off by default** and has no command-line flag. It is the
control-plane-local `tokenService:` block of the operator's `--config` file, read
only by the control plane and never sent to a worker. While it is absent or
`enabled: false`, `POST /oauth2/token` and `GET /.well-known/oauth-authorization-server`
answer `404`, no token-service table is created and `/policy` is unchanged.

Before you set `enabled: true`, have these in place. Items 1-4 are checked at startup, which
fails without them; items 5-6 are not checked but the service is not useful without them:

1. **`--state-dir`.** Replay protection, token sessions and issuance records live in
   `<state-dir>/warden-cp.db`.
2. **An `identity:` block with an issuer and audience.** The service verifies the
   user's ID token against the same IdP the workers trust (see the
   [identity contract](identity-contract.md) and [Dex](identity-dex.md)).
3. **`keys.enabled: true`** and `keys.token.overlap` of at least `tokenService.ttl`
   plus 2 minutes, so a retired token key stays published long enough. See the
   [key rotation runbook](runbooks/key-rotation.md).
4. **An `https` issuer different from `identity.issuer`.** `tokenService.issuer` is Warden's own issuer, not the
   IdP's (startup refuses the same value, because workers tell Warden tokens and IdP tokens apart by issuer): an absolute `https` URL with no trailing slash, query or fragment. Plain
   `http` is accepted only for a loopback host and logs a warning. Use an issuer
   with no path, or clients that rely on discovery will not find the metadata.
5. **At least one registered agent** with a public key and `allowed_groups`:
   `warden control-plane agent register --state-dir D --id ID --jwk-file F --groups G`
   (`warden identity enroll --agent-id ID` creates the key and prints the public
   JWK). An agent with no matching group gets `unauthorized_client`.
6. **Bundles and require mode, if workers enforce.** Set `--bundles=offer|require`
   and pin the bundle keys, so workers get the token keys and `tokenIssuer` from
   the signed bundle. See [signed bundles](control-plane.md#signed-bundles---bundles)
   and [require mode](identity-contract.md#require-mode).

### The `tokenService` block

Every key, with its default and range. Values are validated when the file is read,
whether or not the block is enabled, so a typo shows up when it is written.

```yaml
tokenService:
  enabled: false           # default false
  issuer: https://warden.example.com   # required when enabled; iss of every issued token
  ttl: 15m                 # default 15m, range 1m-15m; never longer than the ID token
  assertionMaxAge: 5m      # default 5m, longest exp-iat of a client assertion (max 15m)
  clockSkew: 60s           # default 60s, greater than 0 and at most 5m, leeway on assertion times
  allowedAZP: [agent-harness]   # default [agent-harness]; 1-16 unique OIDC client ids
  session:
    idle: 12h              # default 12h, a token session idle this long ends
    absolute: 168h         # default 168h (7d), max 720h, idle <= absolute
  rateLimit:
    perIP: 120/minute      # default 120/minute, before the request is parsed
    perAgent: 300/minute   # default 300/minute, charged after the assertion verifies
    perUser: 30/minute     # default 30/minute, charged after the ID token verifies
    maxInFlight: 64        # default 64, range 1-10000, concurrent exchanges
  eventRetention: 720h     # default 720h, minimum 24h, how long token_events rows are kept
```

| Key | Meaning |
|---|---|
| `enabled` | Master switch. |
| `issuer` | The `iss` of issued tokens, and the base of the audience a client assertion must carry (`<issuer>` or `<issuer>/oauth2/token`). Taken from config, never from the `Host` header. Workers learn it from the signed bundle (`tokenIssuer`); it must differ from `identity.issuer`. |
| `ttl` | Longest lifetime of an issued token. The real `exp` is the earlier of `iat + ttl` and the ID token's own expiry. |
| `assertionMaxAge` | Longest `exp - iat` a client assertion may claim. |
| `clockSkew` | Leeway on the assertion's `exp`, `iat` and `nbf`. |
| `allowedAZP` | Only ID tokens whose `azp` is in this list can be exchanged. It narrows `identity.allowedAZP` for this endpoint, so a token minted for another client is refused. |
| `session.idle`, `session.absolute` | A token session (one user, one IdP, one agent) is reused until it has been idle for `idle`, is `absolute` old, or is revoked. A new `sid` then starts. |
| `rateLimit.perIP`, `perAgent`, `perUser` | `N/second`, `N/minute` or `N/hour`. See [rate limits](#rate-limits). |
| `rateLimit.maxInFlight` | Concurrent exchanges the control plane handles; the next is answered `429`. |
| `eventRetention` | Age at which issuance records are pruned. |

The block is commented in `configs/config.example.yaml`.

## The request

`POST /oauth2/token`, `Content-Type: application/x-www-form-urlencoded`, no query
string and no `Authorization` header of any scheme (a session cookie, a `wwt_`
worker token or a `wak_` API key is never client authentication). The body is at
most 32 KiB. Send each parameter once.

| Parameter | |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | the user's IdP ID token |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:id_token` (the only type today) |
| `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | the signed [assertion](#the-client-assertion), at most 8 KiB |
| `client_id` | optional; if present it must equal the assertion's `iss` |
| `audience` | optional; only `warden-worker` |
| `requested_token_type` | optional; `urn:ietf:params:oauth:token-type:jwt` or `urn:ietf:params:oauth:token-type:access_token` |
| `scope` | optional, space-delimited; see [scope](#scope) |

`resource`, `actor_token` and `actor_token_type` are refused. Every response,
success or error, carries `Cache-Control: no-store` and `Pragma: no-cache`.

### Success (200)

```sh
curl -sS https://warden.example.com/oauth2/token \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token="$ID_TOKEN" \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode client_assertion="$ASSERTION" \
  --data-urlencode scope="repo:read"
```

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsImtpZCI6Ii4uLiIsInR5cCI6Ind0K2p3dCJ9...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "repo:read"
}
```

`expires_in` is `exp - iat` of the token, at most `ttl`, and shorter when the
user's ID token expires sooner. `scope` is omitted when the token carries none.
Treat the token as a secret and never log it.

To skip writing this yourself, `warden identity token --agent-id ID
--token-endpoint URL` (see the [identity contract](identity-contract.md#getting-a-token-dex))
does the exchange and prints the token, and `warden identity forward` keeps it
fresh for a harness. A harness author can discover the endpoint from
`GET /.well-known/oauth-authorization-server` (RFC 8414), which lists `issuer`,
`token_endpoint`, `jwks_uri`, `grant_types_supported`,
`token_endpoint_auth_methods_supported` (`private_key_jwt`) and
`token_endpoint_auth_signing_alg_values_supported` (`EdDSA`, `ES256`); it can be
cached for 5 minutes.

### Scope

`scope` is optional. Each token matches `^[a-z0-9:._-]{1,64}$` and there are at most
16. The issued scope is the requested one when it is a subset of the agent's
`allowed_scopes`, or all of `allowed_scopes` when none is requested. A token with
no scope has no `scope` claim. Anything else is `400 invalid_scope`.

### Errors and which to retry

Errors are RFC 6749 section 5.2 JSON, `{"error": "...", "error_description": "..."}`.
`error_description` is one fixed word, never an echo of a token, an assertion or a claim:
either one of the 31 **reasons** below, or one of these handler words for a request that
is refused before the exchange: `missing_parameter`, `duplicate_parameter`,
`unsupported_parameter`, `unsupported_content_type`, `malformed_body`, `body_too_large`,
`query_parameters_not_allowed`, `authorization_header_not_allowed`, `method_not_allowed`,
`unsupported_grant_type` and `service_unavailable`. The `error` code and HTTP status decide
what to do:

| Status | `error` | Retry? | Typical reason |
|---|---|---|---|
| 400 | `invalid_request` | no, fix the request | `missing_parameter`, `duplicate_parameter`, `unsupported_parameter`, `unsupported_content_type`, `malformed_body`, `body_too_large`, `query_parameters_not_allowed`, `authorization_header_not_allowed`, `unsupported_token_type`, `token_too_large` |
| 400 | `unsupported_grant_type` | no | `unsupported_grant_type` |
| 400 | `invalid_target` | no | `invalid_target` (`audience` is not `warden-worker`) |
| 400 | `invalid_grant` | no, sign the user in again | `subject_invalid`, `subject_expired`, `user_blocked`, `session_revoked` |
| 400 | `unauthorized_client` | no | `group_not_allowed` |
| 400 | `invalid_scope` | no | `scope_not_allowed` |
| 401 | `invalid_client` | no, with a **new** assertion only if you fixed the cause | `client_authentication_failed` (always) |
| 404 | none | no | the service is disabled; the body is not JSON |
| 405 | `invalid_request` | no | `method_not_allowed`; use `POST` |
| 429 | `rate_limited` | **yes**, after `Retry-After` | `rate_limited` |
| 503 | `temporarily_unavailable` | **yes**, after `Retry-After` | `idp_unavailable`, `signer_unavailable`, `block_store_unavailable`, `agent_store_unavailable`, `replay_store_unavailable`, `session_store_unavailable`, `event_store_unavailable`, `verifier_misconfigured`, `service_unavailable` |

Retry only `429` and `503`. Both carry an integer `Retry-After` in seconds (a `503`
says `5`). A `503` is the control plane saying "not now", not "no": a harness must
retry it, including its first exchange, instead of sending the user to log in
again. Never retry a `4xx` with the same inputs. A retry after a `401` needs a
freshly signed assertion, because every `jti` is accepted once.

Examples of each. Bodies are exactly what the control plane sends.

**400** (the user is not in a group the agent allows):

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{"error":"unauthorized_client","error_description":"group_not_allowed"}
```

**401** (an unknown agent, an unknown key, a bad signature, a replayed `jti`, a
wrong audience and a disabled agent all look the same, so the endpoint does not
reveal which agent ids exist; the real reason is in the control plane's logs and
metrics):

```http
HTTP/1.1 401 Unauthorized

{"error":"invalid_client","error_description":"client_authentication_failed"}
```

**404** (the service is disabled; also the discovery document):

```http
HTTP/1.1 404 Not Found
```

**429** (a per-IP, per-agent or per-user limit, or the in-flight cap):

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 12

{"error":"rate_limited","error_description":"rate_limited"}
```

**503** (the IdP's keys cannot be fetched and the ID token's `kid` is not cached):

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 5

{"error":"temporarily_unavailable","error_description":"idp_unavailable"}
```

#### The reason enum

The reason is the `error_description` of every exchange error except `invalid_client`, and
the `reason` of every record and metric. It is a closed set of 31 values. The handler
words above appear raw only in the denied and unauthenticated log lines; the metric folds
them into `malformed` (`body_too_large` into `too_large`). An unexpected internal error is
counted as `verifier_misconfigured` while the wire says `service_unavailable`. The first 16
reasons come from client authentication; the rest can follow once the assertion verifies,
except `unsupported_token_type` and `invalid_target`, which are decided before it.

| Group | Reasons |
|---|---|
| Client authentication (all answer 401 `invalid_client`, except the three stores) | `malformed`, `too_large`, `alg_not_allowed`, `unknown_kid`, `bad_signature`, `wrong_iss`, `wrong_aud`, `expired`, `not_yet_valid`, `lifetime_too_long`, `replay`, `agent_unknown`, `agent_disabled`; `agent_store_unavailable`, `replay_store_unavailable`, `verifier_misconfigured` (503) |
| Request and subject | `unsupported_token_type`, `invalid_target`, `subject_invalid`, `subject_expired`, `idp_unavailable` (503), `user_blocked`, `block_store_unavailable` (503) |
| Authorization and minting | `group_not_allowed`, `scope_not_allowed`, `session_revoked`, `session_store_unavailable` (503), `token_too_large`, `signer_unavailable` (503), `event_store_unavailable` (503), `rate_limited` (429) |

On the wire a client authentication failure only ever says
`client_authentication_failed`; the specific reason is for operators.

## The client assertion

The agent authenticates with an RFC 7523 `private_key_jwt`: a compact JWS signed
with the agent's private key. Warden checks it in this order and rejects it with `401 invalid_client` on the first failure:

| Rule | Reason when it fails |
|---|---|
| At most 8 KiB; three base64url segments; parseable header and payload; `alg` is `EdDSA` or `ES256`; none of the `jwk`, `jku`, `x5u`, `x5c` or `crit` headers | `too_large`, `malformed`, `alg_not_allowed` (`none`, `HS*`, `RS*`), `malformed` (the forbidden headers) |
| `iss` is a valid agent id and names a registered agent | `agent_unknown` |
| `kid` header is present and equals a registered JWK's `kid` or its RFC 7638 thumbprint | `unknown_kid` |
| `alg` fits that key's type (`EdDSA` for Ed25519, `ES256` for P-256) | `alg_not_allowed` |
| The signature verifies against that registered key | `bad_signature` |
| `iss` and `sub` are both the agent id; an optional form `client_id` equals it | `wrong_iss` |
| `jti` is 1 to 128 printable characters | `malformed` |
| `aud` is a single value equal to `tokenService.issuer` or `<issuer>/oauth2/token` | `wrong_aud` |
| `exp` and `iat` are present and `exp - iat` is at most `assertionMaxAge` (5m) | `malformed`, `lifetime_too_long` |
| not expired, and `iat` and `nbf` at most `clockSkew` (60s) in the future | `expired`, `not_yet_valid` |
| The agent is active | `agent_disabled` |
| The `jti` has not been used by this agent | `replay` |

Mint a new assertion for every request, with a random `jti`. Replay protection is
per agent and stored in the control plane database, so a restart does not reopen
it. A `jti` is recorded only after every other check passes, so a rejected assertion never
burns one. Rows are kept until `clockSkew` after the assertion expires and removed by the
hourly retention purge.

## The issued token

A JWS with header `alg` (`EdDSA` or `ES256`, from the signing key), `kid` and
`typ: wt+jwt`. Claims:

| Claim | Value |
|---|---|
| `ver` | `1` |
| `iss` | `tokenService.issuer` |
| `aud` | `warden-worker` |
| `sub` | the user's IdP subject |
| `idp_iss` | the IdP issuer of the ID token |
| `email`, `email_verified` | only when the IdP marked the email verified |
| `groups`, `groups_truncated` | the verified group list, sorted; `groups_truncated` when it was cut |
| `act` | `{"sub": "<agent id>"}`, the agent the token is bound to |
| `sid` | the token session id, `wts_` plus 128 random bits |
| `idp_sid` | the IdP session id, when the ID token has one |
| `jti` | 128 random bits, base64url |
| `iat`, `nbf` | issue time (equal) |
| `exp` | `min(iat + tokenService.ttl, the ID token's exp)` |
| `scope` | the [issued scope](#scope); omitted when empty |
| `cnf` | `{"jkt": "<RFC 7638 thumbprint of the agent key that signed the assertion>"}` |

A user who re-authenticates at the IdP gets the new ID token's lifetime, so the
Warden token is never longer-lived than the user's proof. A token that would
encode to more than 12 KiB (a huge group list) is refused with `token_too_large`.
Verify the token against the keys at `GET /.well-known/jwks.json`, and refetch
(rate-limited) on an unknown `kid`; Warden workers never use that endpoint and take
the keys from the signed bundle instead.

## Authorization order

Before the assertion is checked, the audience (`invalid_target`) and the token types
(`unsupported_token_type`) are refused; these write no `token_events` row. After the
assertion verifies, the exchange checks in this order and stops at the first refusal:
the per-agent limit, the ID token, the per-user limit, that the agent is still active and
still has the signing key, the [block list](control-plane.md#block-list) (by `sub`
exactly, or by lowercased email when verified), the agent's `allowed_groups`, the scope,
the expiry (`subject_expired`), the signer (`signer_unavailable`), the session, and
finally the signature. An error in the block store is `503`, never an allow.

## Rate limits

Three limits and one cap protect the endpoint. They run in this order, and each
answers `429` with an integer `Retry-After`:

| Limit | Default | Charged |
|---|---|---|
| `rateLimit.perIP` | 120/minute | before the body is parsed |
| `rateLimit.maxInFlight` | 64 | before the body is read; the over-cap request gets `Retry-After: 1` |
| `rateLimit.perAgent` | 300/minute | only after the assertion verifies |
| `rateLimit.perUser` | 30/minute, keyed on IdP issuer and `sub` | only after the ID token verifies |

Because the per-agent and per-user buckets are charged only after verification, an
attacker who forges an `iss` cannot spend a real agent's or user's budget. The
default per-agent rate is sized for one shared harness agent. Notes for operators:

- **Limits are per control plane replica**, in memory, and reset on restart. Each
  table keeps at most 10,000 keys and drops the least recently used.
- The client IP is the TCP peer, unless the peer is in `console.trustedProxies`, in
  which case the nearest untrusted `X-Forwarded-For` hop is used. IPv6 clients are
  keyed by `/64`. **Behind a NAT or proxy that is not trusted, every harness shares
  one IP and one 120/minute budget**; list your proxy in `console.trustedProxies`.
- The in-flight slot is taken before the body is read, with a 10 second read
  deadline. A handful of clients that trickle bodies can hold the slots, so set
  server and proxy timeouts at your edge.
- The limits use token-bucket semantics: a quiet key may burst up to its limit.

## Issuance records and metrics

Machine issuance stays out of the hash-chained [admin audit log](control-plane.md#admin-audit-log),
which is for admin actions. Instead:

- **`token_events` table.** Every outcome after the assertion verified, issued or
  denied, writes one row in `<state-dir>/warden-cp.db`: `id`, `ts`, `outcome`
  (`issued` or `denied`), `reason`, `agent_id`, `sub_hmac`, `sid`, `jti`, `kid`,
  `exp`, `scope`. The user is a pseudonym: `sub_hmac` is HMAC-SHA256 of the IdP
  issuer and `sub` under a per-control-plane salt kept in the same database. It
  correlates one user's rows and keeps the subject out of the log, but a reader of
  the database also holds the salt, and the salt never rotates. Rows older than
  `eventRetention` are pruned. If the row for an issued token cannot be written, the exchange answers
  `503 event_store_unavailable` and **no token is released**. If the row for a denial
  cannot be written, the denial still stands and `token_event_record_failed` is logged.
- **A log line per outcome.** `msg=token_exchange schema=warden.token.v1` with
  `outcome`, `reason`, `agent`, `sub` (the pseudonym), `sid`, `jti`, `kid` and
  `exp`, written only for a row that exists.
- **Unauthenticated failures** (a bad assertion, a malformed request) write no row.
  They log `token_exchange_unauthenticated` with the reason and client IP, at most
  once per reason and IP per minute, and count in the metric below.
- **Never recorded:** the `subject_token`, the `client_assertion` and the issued
  token appear in no row, log or label.

Metrics are kept in memory by the token service: `warden_cp_tokens_issued_total{agent}`,
`warden_cp_tokens_denied_total{reason}` and the histogram
`warden_cp_token_exchange_seconds`. `reason` is one of the 31 values above and
`agent` is a registered id, `unknown` or `other`; a subject, email or IP is never
a label. **The control plane has no `/metrics` endpoint yet**, so these are not
scrapable until the exporter lands (W-P5-RETN-06). Until then, query `token_events`
(for example, denied rows by reason in the last hour) and alert on the log lines.

```sh
sqlite3 -readonly "$STATE_DIR/warden-cp.db" \
  "SELECT reason, count(*) FROM token_events WHERE outcome='denied' AND ts > strftime('%s','now','-1 hour') GROUP BY reason"
```

## Revoking access

Revocation has two parts, because a minted token stays valid until its `exp`.

- **Stop new exchanges for a session.** Admins can revoke one token session
  (`POST /dashboard/api/token-sessions/{sid}/revoke`) or all sessions of a user or
  an agent (`POST /dashboard/api/token-sessions/revoke`); `GET /dashboard/api/token-sessions`
  lists them. After a revoke, an exchange whose ID token was issued at or before
  the revoke gets `400 invalid_grant` / `session_revoked`, so the user has to sign
  in again. The routes, roles and audit rows are in the
  [control plane reference](control-plane.md#token-endpoint-rfc-8693).
- **Stop live tokens.** A worker has no revocation list. Tokens already minted work
  until `exp`, at most `tokenService.ttl` (15 minutes). To cut them sooner, block the
  user, disable the agent or rotate the token key (an emergency rotation); workers
  act within one policy long-poll cycle.

To stop a user for good, block them: a revoke clears sessions only, and the user can
sign in again and exchange.

## Degraded modes

| Failure | What happens | Operator action |
|---|---|---|
| No active token key (secret backend or KMS down, key not loaded) | `503 signer_unavailable`; `/readyz` reports it | restore the key store; no restart needed |
| First token key just created, or an emergency promotion of a barely published key | `503 signer_unavailable` until the key has been published for about 2 minutes and, with signed bundles on, a signed bundle carries it. The control plane does not wait for workers; the window itself covers their pickup | wait; harnesses retry. The first exchange of a new deployment hits this |
| Bundle publisher degraded after a scheduled rotation (`/healthz` answers `200 degraded: bundle signing failed`) | the mint guard refuses the new key and minting stops with `signer_unavailable` until the next successful bundle sign. Tokens already minted work until `exp` | fix the signer key or bundle store; do not disable bundles to get around it. See the [runbook](control-plane.md#require-mode-session-closing-and-degraded-modes) and [key rotation](runbooks/key-rotation.md) |
| IdP unreachable | cached keys still verify known `kid`s. An unknown `kid`, or a cold cache, gives `503 idp_unavailable`; a harness retries and does not force a new login | restore the IdP; no action on Warden |
| Block store, agent store, replay store, session store or event store error | `503 temporarily_unavailable` with that reason; never an allow | repair `<state-dir>/warden-cp.db` |
| Control plane restarts | replay protection and sessions survive (both are in the database) | none |

**Require mode and a control plane outage.** In `require` mode a worker keeps
serving an agent only while its Warden token is valid, then closes its sessions and
answers CONNECT with `407`. A harness refreshes the token before it expires (the
`warden identity forward` sidecar renews at two thirds of its life), so an outage
that starts just before a refresh leaves about a third of the token's life (5 minutes at
the default `ttl`);
one that outlasts that stops the agent's traffic until the control plane returns.
This is accepted until the control plane is highly available (the Postgres HA
feature). See [require mode](control-plane.md#require-mode-session-closing-and-degraded-modes)
and [the identity contract](identity-contract.md#require-mode).

An IdP outage does not stop an agent that holds a valid Warden token; only new
exchanges fail, and existing tokens work until `exp`.

## Testing a harness

Two tests show the real flow end to end, and are the pattern to copy:

- `TestTokenExchangeE2E` in `internal/controlplane/tokenexchange_e2e_test.go`
  drives the real handler in-process: it registers an agent, mints an ID token from
  an in-process fake IdP, signs an assertion and checks the token, the refusals,
  the restart and the IdP outage.
- `TestTokenExchangeDex` in `test/e2e/identity/token_exchange_test.go` does the same
  against the compose stack with a real Dex ID token (`make e2e`).

For your own tests, use the in-process fake IdP `fakes.OIDCIssuer`
(`test/fakes`) to mint ID tokens with chosen claims, `fakes.NewAgentKey` for an
agent key and assertion, and `test/harness`'s `WithTokenService` and
`RegisterTokenAgent` to stand up a control plane with the service on. The
[testing guide](testing-guide.md) covers the harness. Remember to retry a `503
signer_unavailable` right after a first key is created.
