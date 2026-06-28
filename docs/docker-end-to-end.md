# Running Warden with another service in Docker (end-to-end)

This walks through running Warden next to a second service (your "agent") in Docker Compose:
generating the proxy CA, wiring the cert so the agent trusts it, bringing the stack up, and
proving — end-to-end — that the agent can only reach allow-listed destinations and never holds a
real secret.

## How it works

Warden is an **HTTP `CONNECT` forward proxy**. The agent points `HTTPS_PROXY` at Warden; for each
outbound HTTPS request the agent issues `CONNECT host:443`, Warden checks the destination against
the policy, **terminates TLS** (presenting a leaf cert signed by its own CA), reads the request,
**swaps placeholder tokens for real secrets**, forwards the call over a fresh TLS connection to the
real destination, logs the decision, and streams the response back.

Two Docker networks make the boundary structural:

```
            ┌──────────────────────── agent-internal (internal: true — NO internet) ┐
            │                                                                        │
   ┌────────┴────────┐         CONNECT + TLS          ┌──────────────────┐           │
   │   your agent    │ ─────────────────────────────► │   warden proxy   │ ──────────┼──► internet
   │ (placeholders,  │   HTTPS_PROXY=http://proxy:8080│ (real secrets,   │           │   (egress net,
   │  trusts the CA) │                                │  TLS terminate,  │           │    proxy only)
   └─────────────────┘                                │  policy + swap)  │           │
            │                                          └──────────────────┘           │
            └───────────────────────────────────────────────────────────────────────┘
```

The agent is attached **only** to `agent-internal` (`internal: true`), so Docker gives it no route
to the internet. Warden sits on both networks and is the only service with egress. Even a fully
compromised agent cannot exfiltrate — it has nowhere to send data except through the gate.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose version`)
- `openssl` (to generate the CA)
- A real API key for the destination you'll call. This guide uses **OpenRouter**
  (`OPENROUTER_API_KEY`) because the repo ships a ready config + compose override for it.

All commands below run from the **repo root** unless noted.

## 1. Generate the proxy CA

Warden terminates TLS, so the agent must trust a CA that Warden holds. Generate it once, into the
directory the compose files mount (`deploy/compose/certs`):

```sh
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh
```

This writes:
- `deploy/compose/certs/proxy-ca.crt` — the CA the **agent trusts** (mounted into both containers).
- `deploy/compose/certs/proxy-ca.key` — proxy-only signing key. Gitignored; **never commit it**.

> Warden mints a short-lived leaf cert per destination, signed by this CA, when it terminates TLS.
> The agent accepts those leaves because it trusts the CA.

## 2. The compose topology

`deploy/compose/docker-compose.yml` already encodes everything:

- **`proxy`** — built from the repo `Dockerfile`; on both `agent-internal` and `egress`. It mounts
  the config and the CA, runs with `--ca-cert/--ca-key` (TLS termination) and `--admin-listen`
  (dashboard), and publishes `9090` to the host for the dashboard.
- **`agent`** — a stand-in `alpine` container on `agent-internal` **only**. It has
  `HTTPS_PROXY=http://proxy:8080`, holds **placeholder** secrets, and mounts `proxy-ca.crt` so its
  HTTPS clients trust Warden.
- **`agent-internal`** is `internal: true` (no internet); **`egress`** carries real internet and is
  attached to the proxy only.

The `docker-compose.openrouter.yml` override swaps in `configs/config.openrouter.yaml` (allowlist:
`openrouter.ai`; secret `openrouter_secret_001 → OPENROUTER_API_KEY`) and the matching run command.

## 3. How the agent trusts the cert

The agent's HTTPS client must trust `proxy-ca.crt` or it will reject Warden's leaf certs with an
x509 error. The compose mounts the CA at `/etc/warden/certs/proxy-ca.crt` in the agent; you then
point the client at it. Per runtime:

| Runtime | How to trust the CA |
|---|---|
| `curl` | `--cacert /etc/warden/certs/proxy-ca.crt` (or `export CURL_CA_BUNDLE=...`) |
| Python `requests` | `export REQUESTS_CA_BUNDLE=/etc/warden/certs/proxy-ca.crt` |
| Python / OpenSSL | `export SSL_CERT_FILE=/etc/warden/certs/proxy-ca.crt` |
| Node.js | `export NODE_EXTRA_CA_CERTS=/etc/warden/certs/proxy-ca.crt` |
| System-wide (Debian/Alpine) | copy to `/usr/local/share/ca-certificates/warden.crt` then `update-ca-certificates` |

## 4. Bring the stack up

```sh
export OPENROUTER_API_KEY="sk-or-v1-..."   # the REAL key — lives with the proxy, never the agent

docker compose \
  -f deploy/compose/docker-compose.yml \
  -f deploy/compose/docker-compose.openrouter.yml \
  up --build
```

The proxy logs:
```
warden admin+dashboard on http://0.0.0.0:9090/dashboard/
warden proxy listening on 0.0.0.0:8080
```

Open the dashboard at **http://localhost:9090/dashboard/** (published from the proxy; the agent
cannot reach it — it's on the host-facing side only).

## 5. Run it end-to-end

In another terminal, exec into the **agent** container and drive traffic from inside the isolated
network:

```sh
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.openrouter.yml \
  exec agent sh
```

**a) Allowed call + secret swap** — the agent sends only the *placeholder*; Warden injects the real
key at the edge, so the call succeeds:

```sh
curl --cacert /etc/warden/certs/proxy-ca.crt \
  https://openrouter.ai/api/v1/chat/completions \
  -H "Authorization: Bearer openrouter_secret_001" \
  -H "Content-Type: application/json" \
  -d '{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}'
```

A `200` with a completion proves the swap happened — the agent never had the real key, yet
OpenRouter authenticated the request.

**b) Blocked call (default-deny)** — any destination not on the allowlist dies at the gate:

```sh
curl --cacert /etc/warden/certs/proxy-ca.crt https://api.github.com
# -> "Received HTTP code 403 from proxy after CONNECT"
```

**c) Isolation proof — no direct route** — bypass the proxy and the agent has nowhere to go:

```sh
curl --noproxy '*' --max-time 5 https://openrouter.ai
# -> times out / "Could not resolve host" — the agent has no internet without Warden
```

**d) See the decisions** — every allow/deny is logged (headers only, secret-by-reference, no
bodies). The simplest view is the dashboard at **http://localhost:9090/dashboard/** (Traffic /
Blocked / Stats), or hit the JSON API from the host:

```sh
curl -s http://localhost:9090/dashboard/api/traffic | head
curl -s http://localhost:9090/dashboard/api/blocked     # denied attempts grouped by domain
```

(The analytics SQLite file lives at `/tmp/warden.db` inside the proxy container and is ephemeral —
mount a volume there if you want it to persist.)

Tear down with `Ctrl-C`, then:

```sh
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.openrouter.yml down
```

## 6. Use your own service instead of the demo agent

The `alpine` agent is just a placeholder. Any container becomes a guarded agent with four changes:

1. **Attach it to `agent-internal` only** — never to `egress` or the default bridge. This is what
   removes its internet route.
2. **Point its HTTP client at Warden:**
   ```yaml
   environment:
     - HTTPS_PROXY=http://proxy:8080
     - HTTP_PROXY=http://proxy:8080
     - NO_PROXY=localhost,127.0.0.1   # don't proxy in-process/sidecar calls
   ```
3. **Trust the CA** — mount it and select it per the runtime table in §3:
   ```yaml
   volumes:
     - ./certs/proxy-ca.crt:/etc/warden/certs/proxy-ca.crt:ro
   ```
4. **Hand it placeholders, not real secrets** — set the agent's credentials to the placeholder
   tokens from your config (e.g. `OPENAI_API_KEY=openai_secret_001`). Warden swaps them at the edge.

Then add the destinations your service needs to `policy.allowlist` in the config Warden mounts, and
keep the real keys in the **proxy's** environment only.

Example service block:

```yaml
  my-agent:
    image: my-org/my-agent:latest
    depends_on: [proxy]
    networks: [agent-internal]          # isolated — egress only via Warden
    environment:
      - HTTPS_PROXY=http://proxy:8080
      - HTTP_PROXY=http://proxy:8080
      - NODE_EXTRA_CA_CERTS=/etc/warden/certs/proxy-ca.crt
      - OPENAI_API_KEY=openai_secret_001   # placeholder
    volumes:
      - ./certs/proxy-ca.crt:/etc/warden/certs/proxy-ca.crt:ro
```

## Request flow (recap)

```
agent: CONNECT openrouter.ai:443  ──►  policy check (domain+port)
                                         │ deny → 403 at the proxy (logged)
                                         │ allow ↓
                                       TLS terminate (leaf signed by Warden CA)
                                         ↓
                                       read HTTP request
                                         ↓
                                       swap placeholder → real secret (header/query/body)
                                         ↓
                                       forward over fresh TLS to openrouter.ai
                                         ↓
                                       log decision (headers only, secret-by-reference)
                                         ↓
                                       stream response back to the agent
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `curl: (60) SSL certificate problem` / x509 error | Agent isn't trusting the CA. Mount `proxy-ca.crt` and use `--cacert` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS`. |
| `403 from proxy after CONNECT` | Destination isn't on the allowlist (default-deny). Add it to `policy.allowlist`. |
| Proxy exits: `both CACertPath and CAKeyPath must be set` | Pass **both** `--ca-cert` and `--ca-key` (already wired in the compose commands). |
| Proxy can't read the cert / `no such file` | CA not generated into `deploy/compose/certs`. Run `OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh`. |
| Allowed call returns 401/403 from the *upstream* | Real key missing/invalid. Set `OPENROUTER_API_KEY` in the **host** env before `up` (it flows to the proxy, not the agent). |
| Agent reaches the internet directly | It's attached to a network with egress. Put it on `agent-internal` **only**. |
| Dashboard not loading on `:9090` | Proxy must run with `--admin-listen=0.0.0.0:9090` and publish `9090` (both already in the compose). |

## See also

- `docs/setup-guide.md` — running the binary locally (no Docker).
- `deploy/k8s/` — the same isolation as a Kubernetes sidecar + default-deny NetworkPolicy.
