# Claude Code behind Warden, as a proven user

This recipe runs [Claude Code](https://docs.anthropic.com/en/docs/claude-code) so that
every request it makes is attributed to the person who started it, and the agent can
reach nothing but Anthropic's API through Warden. It is the reference for the other
identity recipes (Codex copies it).

What the agent container holds: a **placeholder** API key (`anthropic_secret_001`),
the public proxy CA certificate and the address of the forwarder. It holds no real
Anthropic key, no Warden token, no Dex token, no agent key and no CA key.

> **Claude.ai subscription sign-in is not supported.** Claude Code must use an
> Anthropic API key (the worker swaps in the real one). The `/login` flow for a
> Claude.ai Pro/Max account sends the account's OAuth token from the agent
> container, which this design deliberately keeps empty of credentials, and talks
> to hosts other than `api.anthropic.com`, which the recipe's policy denies.

## How it fits together

```
claude-code ──(claude-code-internal, internal: true)──► warden-identity :3128
                                                            │ CONNECT + Warden token
                                       cp-net               ▼
control-plane ◄──── policy, bundles ──── warden (worker, require mode) ──(egress)──► api.anthropic.com
    ▲  /oauth2/token                      │ swaps anthropic_secret_001 for the real key
    └──────── warden-identity ────────────┘
```

| Service | Role | Networks |
|---|---|---|
| `claude-code` | the agent (`init: true`, non-root) | `claude-code-internal` only |
| `warden-identity` | sidecar: holds the agent key and the user's login, exchanges them for a short-lived Warden token and adds it to every CONNECT | `claude-code-internal`, `cp-net` |
| `warden` | the worker: `warden run --agent-id claude-code`, identity `require`, signed bundles pinned, holds the real key | `cp-net`, `egress` |
| `control-plane` | serves policy as signed bundles, runs the token endpoint | `cp-net` |
| `identity-bootstrap` | one-shot: registers the worker token, enrolls the agent key, registers the agent, exports the bundle keys | none |
| `dex`, `ldap` | the dev identity provider and its seeded users | `cp-net`, `idp-net` |

`claude-code-internal` is `internal: true`: Docker gives it no route to the internet,
the control plane, Dex or LDAP. The worker is deliberately **not** on it, so the agent
cannot present anything to the worker itself; its only reachable peer is the sidecar.

The worker runs in `require` mode for agent `claude-code`: a request without a Warden
token that names a user, the agent `claude-code` and a registered key is refused with
`407`. A raw Dex token is refused too (`unbound_token`).

## Prerequisites

- Docker with Compose v2.24 or later and a free `127.0.0.1:5556`, `:7070`, `:9091`,
  `:9092` and `:9094`.
- This repository checked out: the Warden services build from its `Dockerfile`,
  because the published `ethosagent/warden:0.3.0` image has no `identity forward`,
  `identity enroll` or `control-plane agent` commands.
- Network access to pull the pinned images and to npm during the agent image build.
- For a real prompt: an Anthropic API key (it goes on the worker only).

## 1. Generate the CA (once)

```sh
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
```

The worker and control plane use `proxy-ca.crt` and `proxy-ca.key`. The agent and the
sidecar mount **only** `proxy-ca.crt`. The script writes the key mode 0600 for the
host user, which the container's `warden` user (uid 100) cannot read, so for this dev
stack make it readable:

```sh
chmod 644 deploy/compose/certs/proxy-ca.key   # dev only; real deployments mount the key as a secret
```

## 2. Settings

Everything below has a public dev placeholder, so a laptop run needs no setup beyond
loading the Dex placeholders. Anywhere else, set real values in your shell or in a
git-ignored `deploy/compose/.env`; nothing real is ever written into a compose file.

```sh
set -a; . deploy/compose/dex/.env.example; set +a    # Dex client secrets, dev only
export ANTHROPIC_API_KEY=                            # real key: worker only; empty = placeholder only
```

| Variable | Default | Where it goes |
|---|---|---|
| `ANTHROPIC_API_KEY` | empty | the worker only. The agent always gets `anthropic_secret_001`. |
| `WARDEN_CLAUDE_CODE_WORKER_TOKEN` | dev placeholder | the worker's own `wwt_` token, registered by `identity-bootstrap` and bound to proxy id `claude-code`. Generate one with `echo wwt_$(head -c32 /dev/urandom \| base32 \| tr -d = \| tr A-Z a-z \| head -c52)`. |
| `WARDEN_FORWARDER_CREDENTIAL` | dev placeholder | a password the agent must send to the sidecar (letters and digits only; it sits in a URL). It gates the listener, which is on two networks; it is not an identity or a vendor key. |
| `WARDEN_CP_ADMIN_TOKEN`, `WARDEN_ADMIN_TOKEN` | dev placeholders | dashboard writes on the control plane and the worker. |

## 3. Bring it up

```sh
docker compose \
  -f deploy/compose/docker-compose.control-plane.yml \
  -f deploy/compose/docker-compose.identity.yml \
  -f deploy/compose/docker-compose.claude-code.yml \
  up -d --build claude-code
```

Naming `claude-code` starts only what it needs: Dex and LDAP, the control plane, the
bootstrap, the worker and the sidecar. The first build compiles Warden and installs
Claude Code, so allow a few minutes.

`identity-bootstrap` waits for the control plane to create its signing keys, then:

1. registers the worker's token (`warden control-plane token create --from-env`);
2. runs `warden identity enroll --agent-id claude-code` **only if** no key exists on
   the sidecar volume `identity-claude-code`;
3. registers agent `claude-code` with `warden control-plane agent register --groups eng`
   and the public JWK, **only if** it is not registered;
4. writes the bundle signing keys with `warden control-plane keys export --purpose
   bundle` into a volume the worker mounts read-only, which is how the worker pins
   them (`controlPlane.bundleKeysFile`).

Running `up -d` again re-runs the bootstrap and changes nothing.

**Right after the first start, Warden-token exchange answers 503 for about two
minutes.** The control plane creates its first token key and holds it back until
every worker has had time to pick it up (`signer_unavailable`, `Retry-After`). The
sidecar keeps retrying; a request in that window gets `503` from the sidecar and works
on a retry. This happens once per fresh state volume.

## 4. Sign in as a user

The sidecar needs a user's login: the agent acts **for** that user, and every logged
request names them.

### Interactive login (device flow)

```sh
docker compose -f deploy/compose/docker-compose.control-plane.yml \
  -f deploy/compose/docker-compose.identity.yml \
  -f deploy/compose/docker-compose.claude-code.yml \
  run --rm warden-identity identity login
```

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
  -f deploy/compose/docker-compose.claude-code.yml"
scripts/dex-token.sh alice --raw | $COMPOSE run --rm -T --no-deps --entrypoint sh warden-identity \
  -c 'umask 077; cat > /data/subject-token'
$COMPOSE -f deploy/compose/docker-compose.claude-code.subject-token.yml up -d warden-identity
```

`docker-compose.claude-code.subject-token.yml` only adds `--subject-token-file
/data/subject-token` to the sidecar's command. The Dex ID token lives one hour
(`expiry.idTokens` in the dev Dex): repeat the first command to refresh it; the
sidecar re-reads the file.

## 5. Run Claude Code

Headless:

```sh
$COMPOSE exec claude-code claude -p 'say ok'
```

Interactive (Claude Code asks once whether to use the API key it finds in the
environment; answer yes, it is the placeholder):

```sh
$COMPOSE exec claude-code claude
```

With only the placeholder (`ANTHROPIC_API_KEY` empty on the worker) the call reaches
Anthropic and the answer is **401**: the request was allowed and attributed, and the
upstream rejected the key. With a real key on the worker the prompt completes:

```sh
ANTHROPIC_API_KEY=<your real key> $COMPOSE up -d warden
$COMPOSE exec claude-code claude -p 'say ok'
```

## 6. Read the attribution

A worker decision line for the call carries the user and the agent:

```sh
$COMPOSE logs warden | grep '"host":"api.anthropic.com"'
```

Look for `"decision":"allow"`, `user.sub` / `user_sub` (alice's Dex `sub`) and `user.act`
(`claude-code`). The control plane's traffic API joins the same events across workers:

```sh
curl -ks -H "Authorization: Bearer $WARDEN_CP_ADMIN_TOKEN" \
  'https://localhost:7070/dashboard/api/traffic?user=alice@example.test'
```

(The seeded users' emails are in `deploy/compose/dex/seed.ldif`.) Each event has
`identity_status: valid`. No token, user token, agent key or request body is logged.

## Degraded modes

| Situation | What the agent sees | What happens |
|---|---|---|
| Nobody logged in / token file missing or expired | `503`, `X-Warden-Forwarder-Reason: login_required` | The sidecar keeps retrying; log in and the next request works. |
| Control plane down | `503`, reason `cp_unreachable` for a new token; requests with a still-valid cached Warden token keep working until it expires (at most 15 minutes) | The worker keeps its last-known-good policy and bundle. |
| Token exchange refused | `503`, reason `exchange_denied` | See [Troubleshooting](#troubleshooting). |
| Agent disabled (`warden control-plane agent disable`) | `403 agent_disabled` within about two seconds on the control plane and a policy-wire cycle on the worker | New CONNECTs are refused; so is every request on an open tunnel at its next request. |
| Worker restarts with the control plane down | `407` reason `jwks_unavailable` until the first bundle verifies | Fail-closed. A bundle cache (`controlPlane.stateDir`) lifts this; see `docs/control-plane.md`. |

## Troubleshooting

**x509 errors from Claude Code** (`unable to verify the first certificate`, `self signed
certificate in certificate chain`). The agent does not trust the proxy CA. Check that
`deploy/compose/certs/proxy-ca.crt` exists before `up` (otherwise Docker creates a
directory there), and that `docker compose exec claude-code env` shows
`NODE_EXTRA_CA_CERTS=/etc/warden/certs/proxy-ca.crt`. A CA regenerated after `up`
needs `up -d --force-recreate`.

**`407` from the worker** (`{"error":"identity_required","reason":...}`), by reason:

| reason | Meaning | Fix |
|---|---|---|
| `unbound_token` | an IdP (Dex) token was sent, not a Warden token | the sidecar must run with `--agent-id`; do not point the agent at the worker directly |
| `none` | no token | the request did not go through the sidecar |
| `agent_unregistered` | the worker's agent is not in the bundle it holds | `identity-bootstrap` failed or the worker has not taken the next bundle (a few seconds); `docker compose run --rm --no-deps --entrypoint warden control-plane control-plane agent list --state-dir /data` |
| `agent_disabled` / `agent_mismatch` / `cnf_mismatch` | the agent is disabled, or the token is for another agent or key | enable the agent; re-enroll and register the key the sidecar holds |
| `jwks_unavailable` | the worker has no verified bundle yet | wait for the first pull; check `controlPlane.bundleKeysFile` and the worker log for `bundle` warnings |
| `expired` | the token expired and was not refreshed | check the clocks (`warden_controlplane_clock_skew_seconds`) |

**`503` from the sidecar or the control plane:**

| Source | reason | Meaning |
|---|---|---|
| sidecar | `login_required` | no usable user login; see step 4 |
| sidecar | `cp_unreachable` | the token endpoint did not answer; check `docker compose logs control-plane` |
| sidecar | `exchange_denied` | the control plane refused the exchange: the user is not in a group the agent allows (`--groups eng`), the agent is disabled or unregistered, the ID token's client is not in `tokenService.allowedAZP`, or the token is expired |
| control plane | `signer_unavailable` | the first token key is still in its publish window (about two minutes, once), or the signed bundle that carries it is not served yet |
| control plane | `temporarily_unavailable` (`Retry-After`) | transient; retry |

**`HTTPS_PROXY` rejected, or the forwarder answers `407`.** The agent must send the
forwarder credential: `HTTPS_PROXY=http://wx:<WARDEN_FORWARDER_CREDENTIAL>@warden-identity:3128`.
A credential with `@`, `:` or `/` in it breaks the URL; use letters and digits.

**Claude Code hangs on start.** `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` keeps it
from calling telemetry and update hosts that the policy denies; if you remove it,
expect denied requests in the worker log and slow starts.

### Environment variables, as confirmed against the pinned release

The agent image pins `@anthropic-ai/claude-code` **2.1.322** (published 2026-11-10).
Each name below was found in that release's binary; the release is a native executable,
so `NODE_USE_ENV_PROXY` matters for the Node tools Claude Code launches, not for Claude
Code itself.

| Variable | Value | Purpose |
|---|---|---|
| `HTTPS_PROXY` | `http://wx:<credential>@warden-identity:3128` | send all HTTPS through the forwarder |
| `NO_PROXY` | `localhost,127.0.0.1,::1` | never proxy loopback |
| `NODE_EXTRA_CA_CERTS` | `/etc/warden/certs/proxy-ca.crt` | trust the Warden CA |
| `NODE_USE_ENV_PROXY` | `1` | Node tools the agent runs honour the proxy variables |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` | `1` | no telemetry, updater or other non-model calls |
| `DISABLE_AUTOUPDATER` | `1` | the version is pinned by the image |
| `ANTHROPIC_API_KEY` | `anthropic_secret_001` | the placeholder the worker swaps |

## Threat model

What the recipe stops:

- **A compromised agent cannot exfiltrate.** Its only route is the forwarder, then the
  worker, whose policy allows `api.anthropic.com:443` and nothing else.
- **A compromised agent cannot steal a credential.** The real key is on the worker; the
  Warden token, the user's login and the agent key are on the sidecar's volume, which
  the agent never mounts. The agent can still *use* the forwarder while it runs: it
  can make allowed calls as the logged-in user, which is the point, and is bounded by
  the policy, the token lifetime (15 minutes) and the user's group membership.
- **A neighbour on `cp-net` cannot borrow the user's identity.** The sidecar's listener
  is on `cp-net` too, so it demands the forwarder credential; Dex, LDAP and other
  workers do not have it.
- **A stolen user token is not enough.** The worker refuses an IdP token, and a Warden
  token is bound to this agent and its registered key.

What it does not stop:

- Anyone with access to the Docker host, the sidecar volume or the worker container.
- Misuse within policy: Claude Code can send anything to `api.anthropic.com`, including
  content from the workspace you mount.
- A Warden token is a bearer credential for up to 15 minutes; revoke access by
  disabling the agent (about two seconds on the control plane, then one policy cycle on
  the worker), or by blocking the user.

## Other notes

- Real deployments replace Dex with the organisation's IdP, use real secrets from a
  secret manager, and register the agent through the console (**Agents** tab) instead
  of the bootstrap.
- The file `deploy/compose/claude-code/bootstrap.sh` is the entire bootstrap; read it
  before you adapt it.
