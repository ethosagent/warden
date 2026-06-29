# Hermes Agent behind Warden

[Hermes Agent](https://hermes-agent.nousresearch.com/docs/user-guide/docker) is
Nous Research's agent runtime; it bundles an OpenAI-compatible API. Because it is
Node-based, it **requires `NODE_USE_ENV_PROXY=1`** — the compose sets it so Node's
built-in `fetch` actually uses the proxy.

## 1. Generate the CA (once)

From the repo root:

```sh
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
```

## 2. Bring it up

```sh
docker compose -f deploy/compose/docker-compose.hermes.yml up
```

> Warden is pulled from Docker Hub (`ethosagent/warden`) — no local build. Override
> the version with `WARDEN_VERSION` (default `0.1.0`):
> `WARDEN_VERSION=0.2.0 docker compose -f deploy/compose/docker-compose.hermes.yml up`

- **Hermes API (OpenAI-compatible):** http://localhost:8642
- **Hermes dashboard:** http://localhost:9119 (enabled via `HERMES_DASHBOARD=1`; **login: `admin` / `warden`** — see [Dashboard login](#dashboard-login))
- **Warden dashboard:** http://localhost:9090/dashboard/ (+ `/metrics`)

Hermes is on an `internal: true` network; its only route out is Warden. Both the
API and the dashboard are reachable via `socat` forwarders, not direct ports on
Hermes.

## Dashboard login

Hermes refuses to expose its web dashboard on a non-loopback bind unless an auth
provider is registered. The dashboard is reached through a `socat` forwarder over
the Docker bridge (a non-loopback address), so an auth provider is **required** —
without one, Hermes silently falls back to binding `127.0.0.1` inside the
container and host port `9119` is unreachable.

The compose file registers Hermes's built-in username/password provider via env
vars (env wins over `config.yaml`, so nothing inside the data volume needs
editing):

```yaml
- HERMES_DASHBOARD_BASIC_AUTH_USERNAME=admin
- HERMES_DASHBOARD_BASIC_AUTH_PASSWORD=warden   # plaintext, hashed in-memory at boot
```

Default login is **`admin` / `warden`**. To change it, edit those env vars in
`deploy/compose/docker-compose.hermes.yml` and recreate the stack. For anything
beyond a local demo, precompute a hash and use `HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH`
instead of the plaintext password:

```sh
docker compose -f deploy/compose/docker-compose.hermes.yml exec hermes \
  python -c "from plugins.dashboard_auth.basic import hash_password; print(hash_password('your-password'))"
```

Login sessions are signed with a per-process key by default, so they reset on
every Hermes restart. Set `HERMES_DASHBOARD_BASIC_AUTH_SECRET` (uncomment it in
the compose file; generate with `openssl rand -base64 32`) to keep sessions
stable across restarts.

## 3. Prove the isolation

```sh
# Through Warden — succeeds, and shows in the dashboard:
docker compose -f deploy/compose/docker-compose.hermes.yml \
  exec hermes sh -c 'curl -sS --max-time 10 https://example.com -o /dev/null -w "via proxy: %{http_code}\n"'

# Bypassing the proxy — FAILS (no direct route out):
docker compose -f deploy/compose/docker-compose.hermes.yml \
  exec hermes sh -c 'curl -sS --noproxy "*" --max-time 5 https://example.com' ; echo "exit: $?"
```

## Secrets: placeholders only

Hand Hermes **placeholder** tokens (e.g. `openai_secret_001`), never real keys.
Warden swaps them at the edge; real keys live in **Warden's** environment only.
(Hermes normally reads keys from `/opt/data/.env` — leave that holding
placeholders too.)

## Tighten the policy

`configs/config.recipe.yaml` ships allow-all for first-run visibility. Once you
see Hermes's real traffic in the dashboard, replace the `~.*` catch-all with the
hosts it actually needs and add `secrets:` placeholder→envVar mappings. See
`docs/docker-end-to-end.md`.
