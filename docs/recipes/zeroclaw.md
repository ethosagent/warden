# ZeroClaw behind Warden

[ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) is a Rust single-binary
agent runtime (OpenAI / Anthropic / OpenRouter / Ollama compatible). Its HTTP
client honors `HTTP(S)_PROXY` and `SSL_CERT_FILE` natively — no Node workaround.

## 1. Generate the CA (once)

From the repo root:

```sh
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
```

## 2. Bring it up

```sh
docker compose -f deploy/compose/docker-compose.zeroclaw.yml up
```

> Warden is pulled from Docker Hub (`ethosagent/warden`) — no local build. Override
> the version with `WARDEN_VERSION` (default `0.2.1`):
> `WARDEN_VERSION=0.2.0 docker compose -f deploy/compose/docker-compose.zeroclaw.yml up`

- **ZeroClaw gateway:** http://localhost:42617
- **Warden dashboard:** http://localhost:9090/dashboard/ (+ `/metrics`)

ZeroClaw is on an `internal: true` network; its only route out is Warden. The
gateway is reachable via a `socat` forwarder, not a direct port on ZeroClaw.

> ARM64: if the distroless image exits immediately, switch the `zeroclaw` service
> to `image: ghcr.io/zeroclaw-labs/zeroclaw:debian`.

## 3. Prove the isolation

```sh
# Through Warden — succeeds, and shows in the dashboard:
docker compose -f deploy/compose/docker-compose.zeroclaw.yml \
  exec zeroclaw sh -c 'curl -sS --max-time 10 https://example.com -o /dev/null -w "via proxy: %{http_code}\n"'

# Bypassing the proxy — FAILS (no direct route out):
docker compose -f deploy/compose/docker-compose.zeroclaw.yml \
  exec zeroclaw sh -c 'curl -sS --noproxy "*" --max-time 5 https://example.com' ; echo "exit: $?"
```

(Distroless image has no shell — use the `:debian` variant for the exec test, or
just read the dashboard's Traffic view.)

## Secrets: placeholders only

The compose hands ZeroClaw a **placeholder** API key
(`openrouter_secret_001`), never a real one. Warden swaps it at the edge. Keep
real keys in **Warden's** environment only.

## Tighten the policy

`configs/config.recipe.yaml` ships allow-all for first-run visibility. Once you
see ZeroClaw's real traffic in the dashboard, replace the `~.*` catch-all with the
hosts it actually needs and add `secrets:` placeholder→envVar mappings. See
`docs/docker-end-to-end.md`.
