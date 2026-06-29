# OpenClaw behind Warden

[OpenClaw](https://docs.openclaw.ai/install/docker) is a Node-based self-hosted AI
assistant. Because it is Node-based, it **requires `NODE_USE_ENV_PROXY=1`** — the
compose sets it so Node's built-in `fetch` actually uses the proxy.

## 1. Generate the CA (once)

From the repo root:

```sh
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
```

## 2. Bring it up

```sh
docker compose -f deploy/compose/docker-compose.openclaw.yml up
```

> Warden is pulled from Docker Hub (`ethosagent/warden`) — no local build. Override
> the version with `WARDEN_VERSION` (default `0.1.0`):
> `WARDEN_VERSION=0.2.0 docker compose -f deploy/compose/docker-compose.openclaw.yml up`

- **OpenClaw Control UI:** http://localhost:18789/#token=warden-dev-token (the `#token=` fragment auto-authenticates — see [First run & gateway auth](#first-run--gateway-auth))
- **Warden dashboard:** http://localhost:9090/dashboard/ (+ `/metrics`)

OpenClaw is on an `internal: true` network; its only route out is Warden. The UI
is reachable via a `socat` forwarder, not a direct port on OpenClaw.

## First run & gateway auth

OpenClaw won't start unconfigured, and it refuses to expose its gateway on a
non-loopback bind without auth — two gates the compose clears for you:

- **`command: [... "gateway", "--allow-unconfigured"]`** lets the gateway boot
  before you've run `openclaw setup`. Without it the container exits with code 78
  (`Missing config`). Configure providers and channels later from the Control UI.
- **`OPENCLAW_GATEWAY_TOKEN`** supplies the gateway auth token. In a container
  OpenClaw auto-binds `0.0.0.0` (so the `socat` forwarder can reach it), but
  refuses a non-loopback bind without a token or password.

Open the Control UI with the token as a URL **fragment** (note the `#`, not `?` —
the UI reads it client-side and uses it for the gateway WebSocket handshake):

```
http://localhost:18789/#token=warden-dev-token
```

Change the token by editing `OPENCLAW_GATEWAY_TOKEN` in
`deploy/compose/docker-compose.openclaw.yml` (use `OPENCLAW_GATEWAY_PASSWORD` for
password auth instead). For anything beyond a local demo, use a strong random
token.

## 3. Prove the isolation

```sh
# Through Warden — succeeds, and shows in the dashboard:
docker compose -f deploy/compose/docker-compose.openclaw.yml \
  exec openclaw sh -c 'curl -sS --max-time 10 https://example.com -o /dev/null -w "via proxy: %{http_code}\n"'

# Bypassing the proxy — FAILS (no direct route out):
docker compose -f deploy/compose/docker-compose.openclaw.yml \
  exec openclaw sh -c 'curl -sS --noproxy "*" --max-time 5 https://example.com' ; echo "exit: $?"
```

## Secrets: placeholders only

Hand OpenClaw **placeholder** tokens (e.g. `openai_secret_001`), never real keys.
Warden swaps them at the edge; real keys live in **Warden's** environment only.

## Tighten the policy

`configs/config.recipe.yaml` ships allow-all for first-run visibility. Once you
see OpenClaw's real traffic in the dashboard, replace the `~.*` catch-all with the
hosts it actually needs and add `secrets:` placeholder→envVar mappings. See
`docs/docker-end-to-end.md`.
