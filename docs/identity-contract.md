# Agent identity contract

**Contract v1.** This page is for people who build agent harnesses and
platforms. It says exactly which token to send to a Warden worker, how to send
it, what the worker does with it, and what a harness must never do.

**Versioning rule.** Later phases may add to Contract v1 (new optional headers,
claims, statuses or reasons), but they never change the meaning or spelling of a
v1 header or claim. A harness that follows this page keeps working when the
worker is upgraded.

Phase 1 is **attribution only**. A missing, expired or bad token never blocks a
request, and default-deny egress policy is unchanged: identity records *who*
made a request, it does not decide *whether* the request goes out.

Two tests keep this page honest: `go test ./internal/proxy -run
TestContractDocMatchesConstants` fails when a header, mode, status, reason,
event field or limit here drifts from the code, and `go test ./cmd/proxy -run
TestContractDocCommands` fails when a `warden identity` command shown here does
not parse against the real CLI.

Related: the reference identity provider is Dex
([`deploy/compose/dex/README.md`](../deploy/compose/dex/README.md), and the
operator guide `docs/identity-dex.md` once it lands), and the recipes index
[`docs/recipes/README.md`](recipes/README.md#per-user-identity).

## Token

The token is an **OIDC ID token** for the end user, issued by the issuer the
worker trusts. It is a JWT; examples on this page show it only as
`eyJ...redacted`.

| Rule | Who enforces it |
|---|---|
| `iss` is byte-identical to the worker's `identity.issuer` (no trailing-slash or case folding) | Worker (reason `wrong_iss`) |
| `aud` contains the worker's `identity.audience` (a string or a list) | Worker (reason `wrong_aud`) |
| Signed with RS256 or ES256; every other `alg`, including `none` and HMAC, is refused | Worker (reason `alg_not_allowed`) |
| The key id (`kid`) is in the issuer's JWKS; the signature verifies | Worker (reasons `unknown_kid`, `bad_signature`) |
| `exp` and `iat` present; `exp` not passed, `nbf` (when present) reached, both with 60 s clock skew (`identity.clockSkewSeconds`, at most 300) | Worker (status `expired`; a future `nbf` is `invalid`/`malformed`) |
| `exp - iat` at most 1 h (`identity.maxTokenTTLSeconds` overrides) | Worker (reason `ttl_too_long`) |
| `azp`, when `identity.allowedAZP` is set, is one of the listed clients (a token without `azp` must then have exactly one `aud`) | Worker (reason `wrong_azp`) |
| `sub` is a non-empty string | Worker (reason `malformed`) |
| The raw token is at most 16 KiB | Worker (reason `too_large`) |
| ID-token lifetime of 1 h | Issuer configuration (Dex `expiry.idTokens: 1h`) |
| `email` present; it is kept lower-cased, and dropped when `email_verified` is false | Issuer configuration (scope `email`) |
| `groups` claim present (claim name from `identity.groupsClaim`, default `groups`) | Issuer configuration (scope `groups`); the worker keeps at most 64 groups of at most 256 bytes each and marks the list truncated otherwise |
| `sid` (session id) present | Issuer configuration |

**Identity is keyed on (iss, sub).** `sub` is the stable user id; `email` is a
display attribute only and must never be used as the key. With Dex, `sub`
encodes the connector id, so renaming a connector makes every user a new person.

**Audiences and clients.** The worker audience (`warden` in the reference
config) is a **data-plane-only** client: it never logs anyone in, has no
redirect URI, and only appears in `aud`. It is a different client from the
console client `warden-console`, which the control plane uses for admin SSO. A
console login token never carries `aud` `warden` (`warden-console` is not a
trusted peer of `warden`), and the console login accepts only `aud`
`warden-console`, so a harness token is never a console token and the reverse.
Workers should set `identity.allowedAZP: [agent-harness, warden-cli]` so only
the harness client and the CLI client can mint tokens the worker accepts.

### Getting a token (Dex)

Dex issues the token through cross-client trust: the `warden` client lists
`agent-harness` and `warden-cli` as `trustedPeers`, so those clients may ask for
`warden` in `aud`. Request these scopes:

```text
openid email profile groups offline_access audience:server:client_id:warden
```

`groups` and `offline_access` are required: without `groups` the token has no
groups claim, and without `offline_access` there is no refresh token and the
login ends when the 1 h ID token expires.

- **Harness platforms** use the confidential `agent-harness` client and their
  normal OIDC login (authorization code), then refresh server-side.
- **User machines** use the public device-code client `warden-cli` through the
  `warden identity` CLI:

```sh
warden identity login --issuer https://dex.example.com/dex --scopes audience:server:client_id:warden
warden identity status
warden identity token
warden identity logout
```

`login` runs the RFC 8628 device-code grant and prints the verification URL and
code on stderr. `status` prints iss, sub, email, groups and exp, never the token.
`token` prints a valid ID token on stdout, refreshing it once it is past two
thirds of its lifetime; it never prompts. Settings come from flags, the
`WARDEN_IDENTITY_*` variables, or `identity.yaml` in the user config directory.
The default client id is `warden-cli` and the default audience `warden`.

| Exit code | Meaning |
|---|---|
| `0` | Success |
| `1` | Any other error |
| `2` | Login is required |
| `3` | The issuer is unreachable and no valid cached token remains |

## Transport

The worker reads the token from one of two headers. Both are proxy-only: the
worker strips `Proxy-Authorization` and `X-Warden-Identity` before forwarding, in
every mode including `off`, so the destination never sees the token.

**Primary: CONNECT `Proxy-Authorization`.** Send

```text
Proxy-Authorization: Basic base64("session:"+token)
```

on the CONNECT request. The user name is `session` (case-sensitive) and the
password is the token. `Proxy-Authorization: Bearer <token>` is accepted too.
Every common client sends the Basic form by itself from a proxy URL that carries
credentials:

```text
HTTPS_PROXY=http://session:<token>@<worker>:8080
```

In `attribute` mode, more than one `Proxy-Authorization` line, a different user
name, or any other scheme gives status `invalid` with reason `malformed`.

**Fallback: `X-Warden-Identity`.** Send

```text
X-Warden-Identity: Bearer <token>
```

on an HTTP request. The worker can read it **only where it terminates TLS** (a
worker with a CA, or a transparent listener that terminates). Inside a raw
tunnel the header is encrypted end to end and invisible, so harnesses must
prefer `Proxy-Authorization`. The header is used only when CONNECT carried no
token; more than one value, or a value that is not exactly one Bearer token, is
`invalid`/`malformed`.

**Attribution is bound per tunnel at CONNECT time.** The CONNECT token is
verified once, and every request inside that tunnel carries its result. Its
`exp` (plus skew) is re-checked on every request, so a long-lived tunnel turns
`expired` once the token lapses. A tunnel opened before a refresh keeps its
original token, so long-lived clients must recycle connections after a refresh.

**Conflict.** If a tunnel has a valid CONNECT identity and a request inside it
also carries a valid `X-Warden-Identity` for a different `sub`, the request gets
identity_status `conflict` and no user. In Phase 1 the request still proceeds; a
403 is reserved for the Phase 2 `require` mode.

**Only https through CONNECT.** The explicit-proxy listener speaks CONNECT
only. A plain `HTTP_PROXY` request (`GET http://...`) is not CONNECT and is
denied with reason `unsupported_protocol`, which is why `warden identity env`
leaves `HTTP_PROXY` unset unless you pass `--include-http`.

**Transparent mode.** A worker with `proxy.mode: transparent` has no CONNECT
listener, so there is no `Proxy-Authorization` to read: only `X-Warden-Identity`
on traffic the worker terminates carries identity, and a raw transparent tunnel
stays anonymous (status `none`). `warden identity env` and `warden identity exec`
set proxy variables, so they do not apply to a transparently intercepted agent.
With `proxy.mode: both`, CONNECT traffic is attributed as above and transparent
traffic as described here.

### Lifetimes and limits

All limits are constants in the worker, not config keys.

| Limit | Value | What happens past it |
|---|---|---|
| Raw token size | 16 KiB | Status `invalid`, reason `too_large`; the token is never parsed |
| CONNECT request line | 8 KiB | `414 URI Too Long`, deny reason `malformed_connect` (detail `request_line_too_long`) |
| Whole CONNECT preamble (request line, headers, blank line) | 64 KiB | `431 Request Header Fields Too Large`, deny reason `malformed_connect` (detail `headers_too_large`) |
| Time to deliver the CONNECT preamble | 10 s | Connection dropped |
| One token verification | 2 s | Status `unverified`; the request is never held longer |
| Clock skew on `exp`/`nbf` | 60 s (default) | Status `expired` |
| Token lifetime `exp - iat` | 1 h (default) | Status `invalid`, reason `ttl_too_long` |

A 16 KiB token base64-encoded in Basic credentials is about 22 KiB, so it fits
in the 64 KiB preamble.

## Modes and statuses

### Modes

The mode is set per worker in `identity.defaultMode` and per agent in
`agents[].identity` (the agent's value wins). An empty value means `off`.

| Mode | Behaviour |
|---|---|
| `off` | Default. No token is read or verified. Events, logs and metrics are byte-identical to a worker without identity. |
| `attribute` | A presented token is verified and the result recorded on every event. Nothing is ever blocked. Needs `identity.issuer` and `identity.audience`. |

`require` is rejected at config load until Phase 2.

### Statuses

In `attribute` mode every event carries one of these `identity_status` values.
`off` is the status of a request in mode `off`; it is never stored.

| Status | Meaning | Dashboard |
|---|---|---|
| `off` | Mode `off`; a token was presented but not read. Events are written without identity fields, so the stored identity_status is empty. | User column shows `—` |
| `none` | No token on the CONNECT or in the header. | `—` |
| `valid` | The token passed every worker check. The event carries the user fields. | User column shows the email (sub on hover); the request counts in Top users |
| `invalid` | The token failed a check; `identity_reason` says which. | `—` |
| `expired` | The token (or the tunnel's CONNECT token) is past `exp` plus skew. | `—` |
| `unverified` | The worker could not check the token in time (key set unavailable or the 2 s bound hit). It fails open to this status, never to a hang or a block. | `—` |
| `conflict` | Two valid identities with different `sub` on one request. | `—` |

### Reasons

`identity_reason` is one of a fixed set; raw token text and library error
strings never become a reason.

| Reason | Cause |
|---|---|
| `bad_signature` | The signature does not verify, or the key type does not fit `alg` |
| `wrong_iss` | `iss` differs from `identity.issuer` |
| `wrong_aud` | `aud` does not contain `identity.audience` |
| `wrong_azp` | `azp` is not in `identity.allowedAZP` |
| `unknown_kid` | The key id is not in the issuer's key set |
| `alg_not_allowed` | `alg` is not RS256 or ES256 |
| `malformed` | Not a parseable JWT, a missing `sub`/`exp`/`iat`, a future `nbf`, or a header in the wrong form |
| `too_large` | The token is over 16 KiB |
| `ttl_too_long` | `exp - iat` is over the maximum token lifetime |
| `jwks_unavailable` | The issuer's key set could not be fetched (status `unverified`) |
| `wrong_nonce` | Console login only: the nonce does not match. Never seen on proxied traffic |

## Observability

Event fields (on `/dashboard/api/traffic` and in the fleet view):

| Field | Set when |
|---|---|
| `identity_status` | Every event, in `attribute` mode |
| `identity_reason` | With a non-valid status that has a reason |
| `user_sub` | Status `valid` |
| `user_email` | Status `valid` and a verified email |
| `user_groups` | Status `valid` |
| `user_groups_truncated` | Status `valid` and groups were dropped for count or size |
| `user_sid` | Status `valid` and the token has `sid` |

The unverified `sub` or `email` of an expired or invalid token is never stored.

Filter by user with `/dashboard/api/traffic?user=<sub or email>` (an exact
`sub` match or a case-insensitive email match).

The worker counts every verification in the metric
`warden.identity.verify.total{result,reason}`, exported to Prometheus as
`warden_identity_verify_total`. `result` is the status and `reason` the reason
(`none` when there is none). Alert on the share of non-valid results per worker
(one worker serves one agent), for example:

```text
sum by (instance) (rate(warden_identity_verify_total{result!="valid"}[15m]))
  / sum by (instance) (rate(warden_identity_verify_total[15m])) > 0.2
```

A rising share of `none` means a harness stopped sending tokens; `expired` means
it stopped refreshing; `unverified` means the worker cannot reach the issuer.

## Harness duties

A harness that sends identity must:

1. Keep the IdP login and the refresh token **out of the agent's reach**: in
   another uid, a sidecar, or the platform's backend, never in the agent's
   container, files or environment.
2. Give each user's agent processes **only that user's token**. One token per
   user; never share a token across users.
3. **Refresh before expiry** (the CLI refreshes at two thirds of the lifetime)
   and recycle proxy connections after a refresh.
4. Prefer `Proxy-Authorization` on CONNECT; use `X-Warden-Identity` only where
   the worker terminates TLS.

A harness must never put the token:

- in prompts or model context;
- in logs, traces or error reports;
- in argv (it shows in `ps`), including as a `--token` style flag value;
- in tool output returned to the model;
- in `curl -v` or other verbose output that echoes proxy credentials.

### Phase 1 limitation: a token in HTTPS_PROXY

`warden identity env` prints proxy variables that contain the token:

```sh
eval "$(warden identity env --worker 127.0.0.1:8080 --ca certs/proxy-ca.crt)"
```

That is convenient but limited, and tolerated only because Phase 1 is
attribute-only:

- any tool the agent runs can read `HTTPS_PROXY`, and so the token;
- the value is a snapshot that goes stale after about 1 h;
- the agent-to-worker hop carries it in plaintext inside the CONNECT, so that
  hop must stay on a private network.

A harness that already holds a token (for example from its own backend) can
render the same variables without the login cache, reading the token from stdin
(never from argv):

```sh
warden identity env --worker 127.0.0.1:8080 --token-stdin --format dotenv
```

`warden identity exec` removes the first two limits.

### warden identity exec

```sh
warden identity exec --worker 127.0.0.1:8080 --ca certs/proxy-ca.crt -- curl -sS https://api.example.com/
warden identity exec --worker 127.0.0.1:8080 --env OPENAI_API_KEY -- my-agent
```

`exec` starts a forwarder on loopback and runs the command with `HTTPS_PROXY`
pointing at it. The forwarder holds the user's ID token in memory, takes a fresh
token from the refreshing client for **every new CONNECT**, and sends it to the
worker as `Proxy-Authorization: Basic base64("session:"+token)`. The token is
never in the command's environment or argv; the command sees only a random
per-run credential (user `wx`) that is valid for the forwarder alone. A tunnel
opened before a refresh keeps its original token, so long-lived clients still
recycle connections.

**The child gets a least-privilege environment, not a copy of yours.** Warden's
architecture rule X3 forbids enumerating the process environment, and `exec`
turns that into a deliberate design: it looks up a fixed allowlist by name and
passes only those that are set:

`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TERM`, `TMPDIR`, `TZ`, `LANG`,
`LC_ALL`, `LC_CTYPE`, `LC_NUMERIC`, `LC_TIME`, `LC_COLLATE`, `LC_MONETARY`,
`LC_MESSAGES`, `LC_PAPER`, `LC_NAME`, `LC_ADDRESS`, `LC_TELEPHONE`,
`LC_MEASUREMENT`, `LC_IDENTIFICATION`.

Then `exec` adds what it sets itself:

- `HTTPS_PROXY` and `https_proxy`: the loopback forwarder URL with the per-run
  credential;
- `NO_PROXY` and `no_proxy`: `localhost,127.0.0.1,::1`;
- `HTTP_PROXY` and `http_proxy`: only with `--include-http`;
- `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` and
  `NODE_EXTRA_CA_CERTS`: only with `--ca`.

Anything else, such as an API key the agent needs, reaches the child only when
named with the repeatable `--env NAME`. It takes a name only: `--env NAME=VALUE`
is refused so a value never sits in argv, and the proxy variables and
`WARDEN_IDENTITY_*` are refused because `exec` owns them. An inherited
`HTTPS_PROXY` is replaced, with a warning.

Without a login, `exec` runs the device-code login when stdin is a terminal;
otherwise it exits 2 without starting the command. Its exit code is the
command's, or 128+N when signal N killed it.

**Same-uid limit.** A command that runs as the same user can still read the
identity cache file (it is 0600 to that user). Run the command as a separate
uid; Phase 2 adds `--run-as`.

## Client compatibility

The worker never sends a `407` challenge, so a client must send
`Proxy-Authorization` **preemptively** on the CONNECT.

| Client | Preemptive Basic from proxy-URL credentials | Identity |
|---|---|---|
| curl | Yes | Works |
| Go `net/http` | Yes | Works |
| Python `requests` | Yes | Works |
| Node with `NODE_USE_ENV_PROXY=1` | Yes | Works |
| Node without `NODE_USE_ENV_PROXY=1` | Ignores `HTTPS_PROXY` | No traffic reaches the worker at all |
| Clients that send credentials only after a `407` | No | No identity in Phase 1 (status `none`); the request still proceeds |

Under `warden identity exec` the loopback forwarder does answer a missing
credential with `407`, so challenge-only clients work there.

Examples, after `eval "$(warden identity env ...)"` or under `warden identity
exec` (both set the CA variables when given `--ca`):

```sh
curl -sS https://api.example.com/v1/models
```

```python
import requests

# requests reads HTTPS_PROXY and REQUESTS_CA_BUNDLE from the environment.
print(requests.get("https://api.example.com/v1/models").status_code)
```

```sh
NODE_USE_ENV_PROXY=1 node -e 'fetch("https://api.example.com/v1/models").then(r => console.log(r.status))'
```

A token never appears in these commands; if you must show one in a ticket or a
log, write it as `eyJ...redacted`.

## Upgrading to Phase 2

Phase 2 adds agent-bound tokens, mTLS workers and the `require` mode. It adds to
Contract v1 and changes none of it: the `Proxy-Authorization` and
`X-Warden-Identity` headers, the `session` user name, the claims above and the
status and reason values keep their v1 meaning. v1 Dex tokens must stay accepted
for workers that already set `identity.issuer`, so a harness that follows this
page keeps attributing after the upgrade. The planned `require` mode turns
`conflict` and the non-valid statuses into a 403, and only for agents an
operator moves to that mode.
