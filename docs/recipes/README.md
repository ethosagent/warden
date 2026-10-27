# Agent recipes — wrap any agent behind Warden

Drop-in Docker Compose recipes that put a popular agent runtime behind Warden so
**every byte of its egress is policy-checked, TLS-terminated, secret-swapped, and
logged** — and the agent has no way around it.

Each recipe is the same shape; only the agent image, ports, and CA-trust knobs
change. Start here, then jump to your runtime:

| Recipe | Runtime | Agent UI | Node fetch workaround? |
|---|---|---|---|
| [ZeroClaw](zeroclaw.md) | Rust single binary | `http://localhost:42617` | No (reqwest honors env natively) |
| [OpenClaw](openclaw.md) | Node self-hosted assistant | `http://localhost:18789/` | **Yes** (`NODE_USE_ENV_PROXY=1`) |
| [Hermes Agent](hermes.md) | Node + OpenAI-compatible API | `http://localhost:8642` (dash `:9119`) | **Yes** (`NODE_USE_ENV_PROXY=1`) |
| [Ethos](ethos.md) | Node agent (web UI + API) | `http://localhost:3000` (API `:3001`) | **Yes** (`NODE_USE_ENV_PROXY=1`) |

Warden's own dashboard is always at **http://localhost:9090/dashboard/** (+ `/metrics`).

## The isolation pattern (shared by every recipe)

The guarantee is structural, not configured-in-good-faith: the agent is placed on
a Docker network with **no route to the internet**, and the only service that
*does* have egress is Warden. Even a fully compromised agent has nowhere to send
data except through the gate.

Three networks make the boundary real:

```
        ┌──────────────── <agent>-internal (internal: true — NO internet) ┐
        │                                                                  │
  ┌─────┴──────┐      CONNECT + TLS       ┌────────────────┐               │
  │   agent    │ ───────────────────────► │  warden proxy  │ ──────────────┼──► internet
  │ placeholder│  HTTPS_PROXY=warden:8080 │ real secrets,  │               │   (egress net,
  │ keys; trust│                          │ TLS terminate, │               │    warden only)
  │  the CA    │                          │ policy + swap  │               │
  └─────┬──────┘                          └────────────────┘               │
        │                                                                   │
        │   ┌──────────┐  host:<uiport>                                     │
        └───┤ ui socat ├──────────────► frontend bridge ──► your browser    │
            └──────────┘   (forwarder only; no agent egress)                │
        └───────────────────────────────────────────────────────────────────┘
```

- **`<agent>-internal`** (`internal: true`) — the agent lives here, and only here.
  Docker gives it no default route, so direct egress is impossible.
- **`egress`** — real internet, attached to **Warden only**.
- **`frontend`** — carries only the `socat` UI forwarder and its host port. The
  agent is never on this network, so exposing its UI grants it no internet route.

The `ui` service is a tiny `alpine/socat` hop: `internal: true` networks can't
publish host ports, so it forwards `host:<uiport> -> <agent>:<uiport>` to make the
web UI reachable without ever giving the agent a way out.

## Two gotchas every recipe handles

**1. Trust the CA.** Warden terminates TLS by presenting a leaf cert signed by its
own CA. The agent must trust that CA or it rejects every HTTPS call with an x509
error. Every recipe mounts `proxy-ca.crt` read-only and points the runtime's trust
env at it:

| Runtime knob | Picked up by |
|---|---|
| `SSL_CERT_FILE` | OpenSSL, Rust (reqwest), most native clients |
| `REQUESTS_CA_BUNDLE` | Python `requests` |
| `CURL_CA_BUNDLE` | `curl` |
| `NODE_EXTRA_CA_CERTS` | Node.js / bundled JS tools |

**2. Node ignores the proxy by default.** Node's built-in `fetch` (undici) does
**not** honor `HTTP(S)_PROXY` unless `NODE_USE_ENV_PROXY=1` is set (Node ≥ ~v20).
Without it, a Node agent's `fetch()` calls go direct, hit the dead-end internal
network, and fail with `fetch failed` — they never reach Warden. So the
**OpenClaw**, **Hermes**, and **Ethos** recipes set it; **ZeroClaw** (Rust/reqwest, which
honors the env natively) does not.

## Secrets stay with Warden, never the agent

In every recipe the agent is handed **placeholder** tokens (e.g.
`openrouter_secret_001`, `openai_secret_001`), never real keys. Warden swaps the
placeholder for the real secret at the edge, so a leaked agent leaks nothing
usable. The starter `configs/config.recipe.yaml` ships allow-all with no swaps
configured; add `secrets:` placeholder→envVar mappings (and the real keys in
**Warden's** environment only) when you tighten the policy.

## Verify isolation (works for every recipe)

Bring a recipe up, then exec into the agent container and prove both directions:

```sh
# 1. Through Warden — succeeds (and shows up in the dashboard):
docker compose -f deploy/compose/docker-compose.<tool>.yml \
  exec <tool> sh -c 'curl -sS --max-time 10 https://example.com -o /dev/null -w "via proxy: %{http_code}\n"'

# 2. Bypassing the proxy — FAILS, because the agent has no direct route out:
docker compose -f deploy/compose/docker-compose.<tool>.yml \
  exec <tool> sh -c 'curl -sS --noproxy "*" --max-time 5 https://example.com' \
  ; echo "exit: $?"
```

The first call returns an HTTP code and appears at
**http://localhost:9090/dashboard/**. The second times out or fails to resolve —
the proof that Warden is the *only* way out. (Distroless agent images may lack a
shell; run the same two `curl` commands from any sidecar on `<tool>-internal`, or
read the dashboard's Traffic / Blocked views instead.)

## Per-user identity

A worker in identity `attribute` mode records which user each request was made
for, without blocking anything. To send the user's identity from a recipe's
agent, give the agent an OIDC ID token from the worker's issuer on the CONNECT:
the proxy URL becomes `http://session:<token>@warden:8080`. The full contract
(token rules, headers, statuses, limits, harness duties) is in
[`docs/identity-contract.md`](../identity-contract.md).

For a CLI agent, `warden identity exec --worker <worker>:8080 --ca proxy-ca.crt -- <agent>`
is the safer path: it runs the agent behind a loopback forwarder that holds the
token in memory and injects a fresh one on every new CONNECT, so the token is
never in the agent's environment or argv. The agent gets only an allowlisted
environment (PATH, HOME, locale and the like, plus the proxy and CA variables);
pass anything else, such as an API key, by name with `--env NAME`. A tunnel
opened before a refresh keeps its original token, and an agent running as the
same uid can still read the identity cache file, so run it as a separate uid.
Transparent-mode recipes carry no proxy URL, so only `X-Warden-Identity` on
terminated traffic applies there.

## Tighten the policy

Allow-all is for first-run visibility. Once you can see the agent's real traffic
in the dashboard, edit `configs/config.recipe.yaml`: replace the `~.*` catch-all
with the specific hosts the agent needs, and add `secrets:` mappings so the agent
only ever holds placeholders. See `docs/docker-end-to-end.md` for the full
allowlist + secret-swap walkthrough.
