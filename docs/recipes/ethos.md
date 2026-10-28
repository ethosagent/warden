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
> the version with `WARDEN_VERSION` (default `0.3.0`):
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

> Ethos 0.8.0's boxed "SECURITY: … NON-LOOPBACK address" banner ("will not log in over plain http"; the auth cookie is now `Secure`) is expected here:
> Ethos must bind `0.0.0.0` so the `ui` socat forwarder can reach it on the internal-only network, and browsers treat `http://localhost` as a secure origin, so login at http://localhost:3000 works.
> Only if you expose port 3000 beyond localhost do you need a TLS-terminating reverse proxy plus Ethos `webBaseUrl`.

## 3. Prove the isolation

```sh
# Through Warden — succeeds, and shows in the dashboard:
docker compose -f deploy/compose/docker-compose.ethos.yml \
  exec ethos sh -c 'curl -sS --max-time 10 https://example.com -o /dev/null -w "via proxy: %{http_code}\n"'

# Bypassing the proxy — FAILS (no direct route out):
docker compose -f deploy/compose/docker-compose.ethos.yml \
  exec ethos sh -c 'curl -sS --noproxy "*" --max-time 5 https://example.com' ; echo "exit: $?"
```

## User sign-in (optional)

Warden can ask each user to sign in before their agent reaches anything: a worker
in identity **challenge** mode refuses a request that has no valid identity with a
`407` and a sign-in URL (the user opens it, signs in with their own provider, and
the client retries with their token). The reference identity provider is in
[`deploy/compose/docker-compose.identity.yml`](../../deploy/compose/docker-compose.identity.yml)
(Dex in front of a seeded LDAP; [identity-dex.md](../identity-dex.md)):

1. Bring the stack up with the identity file merged in
   (`docker compose -f deploy/compose/docker-compose.ethos.yml -f deploy/compose/docker-compose.identity.yml up`,
   after `set -a; . deploy/compose/dex/.env.example; set +a`). Dex is on
   http://localhost:5556 for you and `http://dex:5556` for the containers.
2. Serve an identity block with `defaultMode: challenge` from the control plane,
   as in [control-plane.md](../control-plane.md#challenge-mode) (upgrade the
   control plane and the worker before you set it).
3. Run the sign-in client where it can reach both the worker and Dex, for example
   `warden identity exec --worker <worker>:8080 --challenge -- <command>`. Its first
   request prints `warden: sign in at http://localhost:5556/dex/device?user_code=...`;
   open it, sign in as `alice` (the seeded user), and the next request is attributed
   to her.

**Sign-in link in the chat.** A plain `407` does not reach the chat: Ethos's Node
`fetch` throws `fetch failed` and never reads the body. Run the client with
`--challenge-in-tunnel` and the worker answers inside the tunnel instead: the agent's
request gets a `403` whose error message holds the link, and Ethos shows a provider's
HTTP error body in the chat ("Sign in to continue: http://localhost:5556/dex/device?...").
The overlay [`docker-compose.ethos-sso.yml`](../../deploy/compose/docker-compose.ethos-sso.yml)
wires this up (Ethos under `warden identity exec --challenge-in-tunnel`, a
challenge-mode control plane config, and a relay that gives the client Dex's port
5556 and nothing else); the flow is in
[docker-end-to-end.md](../docker-end-to-end.md#ethos-with-sign-in-in-the-chat).

## Secrets: placeholders only

Hand Ethos **placeholder** tokens (e.g. `openai_secret_001`), never real keys.
Warden swaps them at the edge; real keys live in **Warden's** environment only.

## Tighten the policy

This recipe uses `configs/config.ethos.yaml`, which ships allow-all (`~.*`) for
first-run visibility. Once you see Ethos's real traffic in the dashboard, replace
the catch-all with the hosts it actually needs and add `secrets:` placeholder→envVar
mappings. See `docs/docker-end-to-end.md`.
