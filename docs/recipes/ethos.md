# Ethos behind Warden

[Ethos](https://hub.docker.com/r/ethosagent/ethos) (`ethosagent/ethos`) is a
Node-based agent runtime with a web UI and a companion JSON API. Because it is
Node-based, it **requires `NODE_USE_ENV_PROXY=1`** — the compose sets it so Node's
built-in `fetch` actually uses the proxy.

## 1. Generate the CA (once)

From the repo root:

```sh
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
```

## 2. Bring it up

```sh
docker compose -f deploy/compose/docker-compose.ethos.yml up
```

> Warden is pulled from Docker Hub (`ethosagent/warden`) — no local build. Override
> the version with `WARDEN_VERSION` (default `0.2.1`):
> `WARDEN_VERSION=0.2.0 docker compose -f deploy/compose/docker-compose.ethos.yml up`

- **Ethos web UI:** http://localhost:3000
- **Ethos API:** http://localhost:3001 (the authenticated JSON API the UI calls)
- **Warden dashboard:** http://localhost:9090/dashboard/ (+ `/metrics`)

Ethos is on an `internal: true` network; its only route out is Warden. Both the UI
and the API are reachable via `socat` forwarders, not direct ports on Ethos.

**First run:** on a fresh volume Ethos starts in **onboarding mode**, serving only
the web UI on `:3000`; the API on `:3001` comes up once you finish onboarding. Open
http://localhost:3000 to begin (the container logs also print a one-time
`/auth/exchange?t=…` onboarding link). A one-shot `ethos-init` service in the
compose chowns the named volume to Ethos's uid first, so first boot doesn't fail
with "unable to open database file".

## 3. Prove the isolation

```sh
# Through Warden — succeeds, and shows in the dashboard:
docker compose -f deploy/compose/docker-compose.ethos.yml \
  exec ethos sh -c 'curl -sS --max-time 10 https://example.com -o /dev/null -w "via proxy: %{http_code}\n"'

# Bypassing the proxy — FAILS (no direct route out):
docker compose -f deploy/compose/docker-compose.ethos.yml \
  exec ethos sh -c 'curl -sS --noproxy "*" --max-time 5 https://example.com' ; echo "exit: $?"
```

## Secrets: placeholders only

Hand Ethos **placeholder** tokens (e.g. `openai_secret_001`), never real keys.
Warden swaps them at the edge; real keys live in **Warden's** environment only.

## Tighten the policy

This recipe uses `configs/config.ethos.yaml`, which ships allow-all (`~.*`) for
first-run visibility. Once you see Ethos's real traffic in the dashboard, replace
the catch-all with the hosts it actually needs and add `secrets:` placeholder→envVar
mappings. See `docs/docker-end-to-end.md`.
