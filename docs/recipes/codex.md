# Codex CLI behind Warden, as a proven user

This recipe runs [Codex CLI](https://github.com/openai/codex) so that
every request it makes is attributed to the person who started it, and the agent can
reach nothing but OpenAI's API through Warden.

What the agent container holds: a **placeholder** API key (`openai_secret_001`),
the public proxy CA certificate and the address of the forwarder. It holds no real
OpenAI key, no Warden token, no Dex token, no agent key and no CA key.

> **ChatGPT sign-in is not supported.** Codex must use an OpenAI API key (the worker
> swaps in the real one). `codex login` with a ChatGPT account sends that account's
> OAuth token from the agent container, which this design deliberately keeps empty of
> credentials, and talks to `auth.openai.com` and `chatgpt.com`, which the recipe's
> policy denies. This recipe is the Claude Code recipe ([claude-code.md](claude-code.md))
> with the agent image, host, placeholder and names changed, so the degraded-mode and
> `407`/`503` tables there apply here unchanged (substitute `codex` for `claude-code`).

## How it fits together

```
codex ──(codex-internal, internal: true)──► warden-identity :3128
                                                            │ CONNECT + Warden token
                                       cp-net               ▼
control-plane ◄──── policy, bundles ──── warden (worker, require mode) ──(egress)──► api.openai.com
    ▲  /oauth2/token                      │ swaps openai_secret_001 for the real key
    └──────── warden-identity ────────────┘
```

| Service | Role | Networks |
|---|---|---|
| `codex` | the agent (`init: true`, non-root) | `codex-internal` only |
| `warden-identity` | sidecar: holds the agent key and the user's login, exchanges them for a short-lived Warden token and adds it to every CONNECT | `codex-internal`, `cp-net` |
| `warden` | the worker: `warden run --agent-id codex`, identity `require`, signed bundles pinned, holds the real key | `cp-net`, `egress` |
| `control-plane` | serves policy as signed bundles, runs the token endpoint | `cp-net` |
| `identity-bootstrap` | one-shot: registers the worker token, enrolls the agent key, registers the agent, exports the bundle keys | none |
| `dex` | the dev identity provider | `cp-net`, `idp-net` |
| `ldap` | the seeded users behind Dex | `idp-net` only |

`codex-internal` is `internal: true`: Docker gives it no route to the internet,
the control plane, Dex or LDAP. The worker is deliberately **not** on it, so the agent
cannot present anything to the worker itself; its only reachable peer is the sidecar.

The worker runs in `require` mode for agent `codex`: a request without a Warden
token that names a user, the agent `codex` and a registered key is refused with
`407`. A raw Dex token is refused too (`unbound_token`).

## Prerequisites

- Docker Engine 26 or later with Compose v2.24 or later. Older engines forward external
  DNS lookups for containers attached only to `internal: true` networks, which is a
  DNS-tunnel exfiltration path out of the agent; Engine 26 closed it. Free host ports: `127.0.0.1:5556`, `:7070`, `:9091`,
  `:9092` and `:9095`. Do not run it beside the Claude Code recipe: both use the service names `warden`, `warden-identity` and `control-plane`. The recipe also uses the subnet `172.29.120.0/24` for `codex-internal`
  (change it in the compose file, with the sidecar's address, if it collides).
- This repository checked out: the Warden services build from its `Dockerfile`,
  because the published `ethosagent/warden:0.3.0` image has no `identity forward`,
  `identity enroll` or `control-plane agent` commands.
- Network access to pull the pinned images and to npm during the agent image build (about 170 MB for the native binary).
- For a real prompt: an OpenAI API key (it goes on the worker only).

## 1. Generate the CA (once)

```sh
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
```

The worker and control plane use `proxy-ca.crt` and `proxy-ca.key`. The agent and the
sidecar mount **only** `proxy-ca.crt`. The script writes the key mode 0600 for the
host user, which the container's `warden` user (uid 100) cannot read, so for this dev
stack make it readable:

```sh
sudo chown 100:101 deploy/compose/certs/proxy-ca.key   # the container's warden user; keeps mode 0600
```

If you cannot use `sudo`, `chmod 644 deploy/compose/certs/proxy-ca.key` works as a
**dev-only** fallback (any local user can then read the CA key). Real deployments mount
the key as a secret.

## 2. Settings

Everything below has a public dev placeholder, so a laptop run needs no setup beyond
loading the Dex placeholders. Anywhere else, set real values in your shell or in a
git-ignored `deploy/compose/.env`; nothing real is ever written into a compose file.

```sh
set -a; . deploy/compose/dex/.env.example; set +a    # Dex client secrets, dev only
export OPENAI_API_KEY=                            # real key: worker only; empty = placeholder only
```

| Variable | Default | Where it goes |
|---|---|---|
| `OPENAI_API_KEY` | empty | the worker only. The agent always gets `openai_secret_001`. |
| `WARDEN_CODEX_WORKER_TOKEN` | dev placeholder | the worker's own `wwt_` token, registered by `identity-bootstrap` and bound to proxy id `codex`. Generate one with `echo wwt_$(head -c32 /dev/urandom \| base32 \| tr -d = \| tr A-Z a-z \| head -c52)`. |
| `WARDEN_FORWARDER_CREDENTIAL` | dev placeholder | a password the agent must send to the sidecar (URL-safe: no `@`, `:` or `/`). It gates the listener as defence in depth; it is not an identity or a vendor key. **Change it outside a laptop.** |
| `WARDEN_CP_ADMIN_TOKEN`, `WARDEN_ADMIN_TOKEN` | dev placeholders | dashboard writes on the control plane and the worker. |

## 3. Bring it up

```sh
docker compose \
  -f deploy/compose/docker-compose.control-plane.yml \
  -f deploy/compose/docker-compose.identity.yml \
  -f deploy/compose/docker-compose.codex.yml \
  up -d --build codex
```

Naming `codex` starts only what it needs: Dex and LDAP, the control plane, the
bootstrap, the worker and the sidecar. The first build compiles Warden and installs
Codex CLI, so allow a few minutes.

`identity-bootstrap` waits for the control plane to create its signing keys, then:

1. registers the worker's token (`warden control-plane token create --from-env`);
2. runs `warden identity enroll --agent-id codex` **only if** no key exists on
   the sidecar volume `identity-codex`;
3. registers agent `codex` with `warden control-plane agent register --groups eng`
   and the public JWK, **only if** it is not registered;
4. writes the bundle signing keys with `warden control-plane keys export --purpose
   bundle` into a volume the worker mounts read-only, which is how the worker pins
   them (`controlPlane.bundleKeysFile`).

Running `up -d` again re-runs the bootstrap and changes nothing. Two failure cases are
deliberate:

- If you later change `WARDEN_CODEX_WORKER_TOKEN`, step 1 fails (same name,
  different value) and the stack stays down rather than running with two tokens. Rotate
  it with `warden control-plane token revoke` and `create`, then restart the worker.
- If the agent is registered but its key file (or public JWK) is gone from the sidecar
  volume, the bootstrap stops with instructions instead of enrolling a new key: a new
  key the registry does not hold would make every token fail with `cnf_mismatch`. Recover
  by registering the new key (`warden control-plane agent update`), or by deleting the
  agent and the volume `identity-codex` and running `up` again.

**Right after the first start, Warden-token exchange fails for a few minutes** (the
publish window is two minutes plus the policy long-poll cycles that carry the key to the
worker; three to four minutes in a clean run). The control plane creates its first token key and holds
it back until every worker could have picked it up (`signer_unavailable`,
`Retry-After`). The sidecar keeps retrying; a request in that window gets `503` from
the sidecar (reason `cp_unreachable` in its log) and works on a retry. This happens
once per fresh state volume.

## 4. Sign in as a user

The sidecar needs a user's login: the agent acts **for** that user, and every logged
request names them.

### Interactive login (device flow)

```sh
docker compose -f deploy/compose/docker-compose.control-plane.yml \
  -f deploy/compose/docker-compose.identity.yml \
  -f deploy/compose/docker-compose.codex.yml \
  exec warden-identity warden identity login
```

(`exec` into the running sidecar: it has a fixed address on the agent network, so a second
`run` container could not start beside it.)

It prints a URL and a code; open it in a browser, sign in (the dev users are `alice`,
`bob`, `carol`, `dave`; see `deploy/compose/dex/README.md`) and the login is cached on
the sidecar's volume. The agent registered here lists group `eng`, so alice (`eng`)
and dave (`eng`) may delegate to it; bob and carol may not.

In this **dev stack** the issuer is `http://localhost:5556/dex`, which only the host
can reach: inside the sidecar `localhost` is the sidecar itself. Use the dev path
below unless your issuer has a public https URL the sidecar can reach (then set
`WARDEN_IDENTITY_ISSUER` and the CP's `identity.issuer` to it).

### Dev path: a token from `scripts/dex-token.sh`

For a laptop or CI, fetch alice's ID token with the password grant (dev Dex only) and
put it on the sidecar's volume without passing it through a command line:

```sh
COMPOSE="docker compose -f deploy/compose/docker-compose.control-plane.yml \
  -f deploy/compose/docker-compose.identity.yml \
  -f deploy/compose/docker-compose.codex.yml"
scripts/dex-token.sh alice --raw | $COMPOSE exec -T warden-identity \
  sh -c 'umask 077; cat > /data/subject-token'
COMPOSE="$COMPOSE -f deploy/compose/docker-compose.codex.subject-token.yml"
$COMPOSE up -d warden-identity
```

Keep the four-file `$COMPOSE` from here on. A later `up -d` without the fourth `-f`
recreates the sidecar without `--subject-token-file`, and it then answers
`login_required`.

`docker-compose.codex.subject-token.yml` only adds `--subject-token-file
/data/subject-token` to the sidecar's command. The Dex ID token lives one hour
(`expiry.idTokens` in the dev Dex): repeat the first command to refresh it; the
sidecar re-reads the file.

## 5. Run Codex

Headless:

```sh
$COMPOSE exec codex codex exec --skip-git-repo-check 'say ok'
```

`codex exec` reads `OPENAI_API_KEY` from the environment, so no `codex login` is
needed (and none should be run: `codex login --with-api-key` would write the key, here
the placeholder, to `~/.codex/auth.json` for no benefit).

**Codex's own sandbox does not work in this container.** Its Linux sandbox (bubblewrap)
needs unprivileged user namespaces, which Docker's default profile blocks: `codex
sandbox linux -- echo hi` fails with `bwrap: No permissions to create a new namespace`.
The recipe does not add `cap_add`, `privileged` or a relaxed seccomp profile to fix that
(those would weaken the isolation the recipe exists for). A prompt that makes no tool
call, like the one above, is unaffected. For a task that runs commands, tell Codex it
is already inside a sandbox: the container is the sandbox, and Warden is the egress gate.

```sh
$COMPOSE exec codex codex exec --skip-git-repo-check --sandbox danger-full-access 'run the tests'
```

This is a real trade-off. With `danger-full-access` the commands the model chooses run
with no Codex sandbox, so they can write anywhere the `agent` user can, including
`~/.codex` (config, history and any skills) on the persistent `codex-home` volume, which
the next run reads back, and `/workspace`. They can also make every call the policy
allows through the forwarder, as the logged-in user. What stays out of reach is the
same as for the rest of the recipe: no vendor key, no Warden token, no agent key, no
route to anything but `api.openai.com`. Run it only on workspaces and prompts you would
run as that user, and reset the `codex-home` volume (`docker compose down -v` or
`docker volume rm`) if you suspect it was altered.

With only the placeholder (`OPENAI_API_KEY` empty on the worker) the call reaches
OpenAI and the answer is **401**: the request was allowed and attributed, and the
upstream rejected the key. With a real key on the worker the prompt completes (manual
step, not run in this repository's checks, which never hold a real key):

```sh
OPENAI_API_KEY=<your real key> $COMPOSE up -d warden
$COMPOSE exec codex codex exec --skip-git-repo-check 'say ok'
```

Codex also calls hosts the policy denies: `chatgpt.com` and `ab.chatgpt.com`
(catalog, analytics), `github.com` and `api.github.com`. Those show up as `deny` lines
in the worker log and do not stop a prompt.

### Transport: WebSocket first, HTTPS fallback

Observed against 0.167.2 with the placeholder key (the upstream answered 401, which
may be what triggers the fallback; with a real key the WebSocket may succeed and no
fallback occur): `codex exec` first opens a WebSocket to
`wss://api.openai.com/v1/responses` (a `CONNECT` to `api.openai.com:443`, then an HTTP
upgrade) and, after its retries fail, falls back to `POST https://api.openai.com/v1/responses`
over HTTP/2. Both go to the one allowed host, so the policy needs no change, and both
appear in the worker log as `allow` decisions (the upgrade as `GET`). The WebSocket
retries add several seconds before the fallback, and a prompt can therefore look slow
before it answers.

## 6. Read the attribution

The worker's decision line for the call names the user:

```sh
$COMPOSE logs warden | grep '"domain":"api.openai.com"'
```

Look for `"decision":"allow"`, `"identity_status":"valid"` and `user_sub` (alice's Dex
`sub`). The agent (`act`, here `codex`) is recorded on the stored event as
`user_act`, so filter on it in the control plane's traffic API, which joins events
across workers:

```sh
curl -ks -H "Authorization: Bearer $WARDEN_CP_ADMIN_TOKEN" \
  'https://localhost:7070/dashboard/api/traffic?user=alice@example.org&act=codex'
```

(The seeded users' emails, `alice@example.org` and so on, are in
`deploy/compose/dex/seed.ldif`.) **Manual step, not verified end to end:** the worker
log lines and `identity_status` were checked on a live stack, but the control-plane
traffic query was not (it returned an empty list when run immediately after the
request). Workers push events to the control plane on an interval, so wait a minute
and retry; if it stays empty, read the same fields from the worker's own dashboard at
`http://localhost:9095/dashboard/`. With only the
placeholder the upstream `response_status` is 401. No token, user token, agent key or
request body is logged.

## Degraded modes

| Situation | What the agent sees | What happens |
|---|---|---|
| Nobody logged in / token file missing or expired | `503`, `X-Warden-Forwarder-Reason: login_required` | The sidecar keeps retrying; log in and the next request works. |
| Control plane down | `503`, reason `cp_unreachable` for a new token; requests with a still-valid cached Warden token keep working until it expires (at most 15 minutes) | The worker keeps its last-known-good policy and bundle. |
| Token exchange refused | `503`, reason `exchange_denied` | See [Troubleshooting](#troubleshooting). |
| Agent disabled (`warden control-plane agent disable`) | `403 agent_disabled` within about two seconds on the control plane and a policy-wire cycle on the worker | New CONNECTs are refused; so is every request on an open tunnel at its next request. |
| Worker restarts with the control plane down | `407` reason `jwks_unavailable` until the first bundle verifies | Fail-closed. A bundle cache (`controlPlane.stateDir`) lifts this; see `docs/control-plane.md`. |

## Troubleshooting

**TLS errors from Codex** (`failed to connect to Responses WebSocket stage=Tls`, or an
`invalid peer certificate` / `UnknownIssuer` message). The agent does not trust the proxy
CA. Check that `deploy/compose/certs/proxy-ca.crt` exists before `up` (otherwise Docker
creates a directory there), and that `docker compose exec codex env` shows
`CODEX_CA_CERTIFICATE=/etc/warden/certs/proxy-ca.crt`. A CA regenerated after `up` needs
`up -d --force-recreate`.

**`407` from the worker** (`{"error":"identity_required","reason":...}`), by reason:

| reason | Meaning | Fix |
|---|---|---|
| `unbound_token` | an IdP (Dex) token was sent, not a Warden token | the sidecar must run with `--agent-id`; do not point the agent at the worker directly |
| `none` | no token | the request did not go through the sidecar |
| `agent_unregistered` | the worker's agent is not in the bundle it holds | `identity-bootstrap` failed or the worker has not taken the next bundle (a few seconds); `$COMPOSE run --rm --no-deps --entrypoint warden identity-bootstrap control-plane agent list --state-dir /cp-data` |
| `agent_disabled` / `agent_mismatch` / `cnf_mismatch` | the agent is disabled, or the token is for another agent or key | enable the agent; re-enroll and register the key the sidecar holds |
| `jwks_unavailable` | the worker has no verified bundle yet | wait for the first pull; check `controlPlane.bundleKeysFile` and the worker log for `bundle` warnings |
| `expired` | the token expired and was not refreshed | check the clocks (`warden_controlplane_clock_skew_seconds`) |

**`503` from the sidecar or the control plane:**

| Source | reason | Meaning |
|---|---|---|
| sidecar | `login_required` | no usable user login; see step 4 |
| sidecar | `cp_unreachable` | the token endpoint did not answer; check `docker compose logs control-plane` |
| sidecar | `exchange_denied` | the control plane refused the exchange: the user is not in a group the agent allows (`--groups eng`), the agent is disabled or unregistered, the ID token's client is not in `tokenService.allowedAZP`, or the token is expired |
| control plane | `signer_unavailable` | the first token key is still in its publish window (a few minutes, once: two minutes of publish window plus the time to reach the worker), or the signed bundle that carries it is not served yet |
| control plane | `temporarily_unavailable` (`Retry-After`) | transient; retry |

**`HTTPS_PROXY` rejected, or the forwarder answers `407`.** The agent must send the
forwarder credential: `HTTPS_PROXY=http://wx:<WARDEN_FORWARDER_CREDENTIAL>@warden-identity:3128`.
A credential with `@`, `:` or `/` in it breaks the URL; use URL-safe characters (letters, digits, `-`, `_`).

**Codex waits at `Reconnecting...`.** It retries the WebSocket five times and then the
HTTPS call five times with backoff. If the sidecar answers `503` (no login yet, or the
first-start token window) or the TLS check fails, it keeps retrying, so check the
sidecar log first.

### Trust and key mechanism, as verified against the pinned release

The agent image pins `@openai/codex` **0.167.2** (published 2026-11-11; the package's
`dist.integrity` is checked in the Dockerfile before install). The release is a static
native binary started by a small Node launcher. Verified by running it in the recipe
stack with a placeholder key:

| Question | Result |
|---|---|
| CA trust | The binary reads `CODEX_CA_CERTIFICATE` and then `SSL_CERT_FILE` (its `custom_ca` module logs which it used). Each variable alone makes the handshake with the Warden-minted leaf succeed; with neither set the handshake fails (`stage=Tls`). The recipe sets both: `CODEX_CA_CERTIFICATE` is the documented mechanism, `SSL_CERT_FILE` also makes `curl` and other tools in the container trust the same CA. No system trust store change is needed. |
| Proxy | `HTTPS_PROXY` / `NO_PROXY` are honoured, including a `user:password@` URL (the forwarder credential). |
| API key | `codex exec` uses `OPENAI_API_KEY` from the environment (provider `openai`, no login). `CODEX_API_KEY` also exists; the recipe does not use it. |
| Hosts | `api.openai.com` for the model. Also tried: `chatgpt.com`, `ab.chatgpt.com`, `github.com`, `api.github.com` (denied, harmless). |
| Transport | WebSocket first, HTTPS fallback; see above. |

| Variable | Value | Purpose |
|---|---|---|
| `HTTPS_PROXY` | `http://wx:<credential>@warden-identity:3128` | send all HTTPS through the forwarder |
| `NO_PROXY` | `localhost,127.0.0.1,::1` | never proxy loopback |
| `CODEX_CA_CERTIFICATE` | `/etc/warden/certs/proxy-ca.crt` | trust the Warden CA |
| `SSL_CERT_FILE` | `/etc/warden/certs/proxy-ca.crt` | same, for other tools in the container |
| `OPENAI_API_KEY` | `openai_secret_001` | the placeholder the worker swaps |

## Prove the isolation

`scripts/recipe-isolation.sh codex` brings this stack up from a clean state and proves the
claims below on the real containers (no route out, no secret in the agent, attribution,
agent disable). It needs no real key. See
[Recipe isolation proof](../testing-guide.md#recipe-isolation-proof-claude-code-codex).

## Threat model

What the recipe stops:

- **A compromised agent cannot exfiltrate.** Its only route is the forwarder, then the
  worker, whose policy allows `api.openai.com:443` and nothing else.
- **A compromised agent cannot steal a credential.** The real key is on the worker; the
  Warden token, the user's login and the agent key are on the sidecar's volume, which
  the agent never mounts. The agent can still *use* the forwarder while it runs: it
  can make allowed calls as the logged-in user, which is the point, and is bounded by
  the policy, the token lifetime (15 minutes) and the user's group membership.
- **A neighbour on `cp-net` cannot borrow the user's identity.** The sidecar listens on
  its address on `codex-internal` only, not on `cp-net`, and it also demands the
  forwarder credential; Dex and other workers have neither a route nor the credential.
- **A stolen user token is not enough.** The worker refuses an IdP token, and a Warden
  token is bound to this agent and its registered key.

What it does not stop:

- Anyone with access to the Docker host, the sidecar volume or the worker container.
- Misuse within policy: Codex can send anything to `api.openai.com`, including
  content from the workspace you mount.
- A Warden token is a bearer credential for up to 15 minutes; revoke access by
  disabling the agent (about two seconds on the control plane, then one policy cycle on
  the worker), or by blocking the user.

## Other notes

- Real deployments replace Dex with the organisation's IdP, use real secrets from a
  secret manager, and register the agent through the console (**Agents** tab) instead
  of the bootstrap.
- The file `deploy/compose/recipe-bootstrap.sh` is the entire bootstrap (shared with the Claude Code recipe); read it
  before you adapt it.
