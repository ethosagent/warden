<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/warden-logo-dark.svg">
    <img src="assets/logo/warden-logo.svg" alt="Warden — egress guardrail for AI agents" width="440">
  </picture>
</p>

# Warden

**An agent egress guardrail proxy that makes it structurally impossible for an LLM agent to bypass security controls.**

Warden sits between your AI agent and the internet as a MITM proxy. The agent has no direct network route — every outbound request passes through Warden, which enforces default-deny policy, swaps placeholder tokens for real secrets at the network edge, scans responses for threats, and logs every decision. The agent never holds a real credential and cannot reach a destination you haven't explicitly allowed.

Built for teams running LLM agents (coding assistants, support bots, autonomous workflows) who need a security boundary that doesn't rely on the agent behaving correctly.

<p align="center">
  <img src="assets/architecture.svg" alt="Warden Architecture" width="800"/>
</p>

## Quickstart

```sh
# Build
go build -o warden ./cmd/proxy

# Generate the proxy CA cert (agent trusts this for TLS termination)
scripts/gen-certs.sh

# Set a real API key (the agent never sees this)
export OPENROUTER_API_KEY="sk-or-v1-..."

# Start the proxy + dashboard
./warden run \
  --config configs/config.openrouter.yaml \
  --listen 127.0.0.1:8080 \
  --ca-cert certs/proxy-ca.crt \
  --ca-key certs/proxy-ca.key \
  --admin-listen 127.0.0.1:9090
```

```sh
# In another terminal — request through the proxy (agent sends placeholder, real key injected)
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://openrouter.ai/api/v1/models \
  -H "Authorization: Bearer openrouter_secret_001"

# Blocked destination (default-deny)
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://evil.example.com/

# Open the dashboard
open http://127.0.0.1:9090/dashboard/
```

### Docker Compose (full isolation proof)

Full walkthrough — including how the agent trusts the proxy cert and how to drop in your own
service — is in **[docs/docker-end-to-end.md](docs/docker-end-to-end.md)**. The short version:

```sh
# 1. Generate the bake-once proxy CA into the dir the compose files mount
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh

# 2. Bring up the proxy + an isolated demo agent
export OPENROUTER_API_KEY="sk-or-v1-..."   # real key — lives with the proxy, never the agent
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.openrouter.yml up

# 3. Exec into the agent container
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.openrouter.yml exec agent sh

# Inside agent — works (via proxy; placeholder swapped for the real key at the edge):
curl --cacert /etc/warden/certs/proxy-ca.crt https://openrouter.ai/api/v1/models \
  -H "Authorization: Bearer openrouter_secret_001"

# Inside agent — fails (no internet route — proves isolation):
curl --noproxy '*' --connect-timeout 5 https://openrouter.ai/api/v1/models
```

Dashboard: **http://localhost:9090/dashboard/**.

### Run Warden behind a real agent — out-of-the-box recipes

Warden ships drop-in Docker Compose recipes that put a popular agent runtime behind it with **zero local build** — the Warden image is pulled straight from Docker Hub (`ethosagent/warden`). The agent runs on an internal-only network with **no route to the internet**; Warden is its sole way out. Each recipe boots **allow-all**, so you immediately *see* every call on the dashboard — then you tighten the policy.

| Agent | What it is | Bring it up | Agent UI | Warden dashboard |
|---|---|---|---|---|
| **[Ethos](docs/recipes/ethos.md)** | Node agent (web UI + API) | `docker compose -f deploy/compose/docker-compose.ethos.yml up` | http://localhost:3000 | http://localhost:9091/dashboard/ |
| **[Hermes](docs/recipes/hermes.md)** | Node + OpenAI-compatible API | `docker compose -f deploy/compose/docker-compose.hermes.yml up` | http://localhost:8642 | http://localhost:9090/dashboard/ |
| **[OpenClaw](docs/recipes/openclaw.md)** | Node self-hosted assistant | `docker compose -f deploy/compose/docker-compose.openclaw.yml up` | http://localhost:18789/ | http://localhost:9090/dashboard/ |
| **[ZeroClaw](docs/recipes/zeroclaw.md)** | Rust single binary | `docker compose -f deploy/compose/docker-compose.zeroclaw.yml up` | http://localhost:42617 | http://localhost:9090/dashboard/ |

```sh
# One-time: generate the proxy CA the compose files mount
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh

# Bring up any recipe — the Warden image is pulled from Docker Hub (no build):
docker compose -f deploy/compose/docker-compose.ethos.yml up

# Pin a specific Warden version (defaults to the tested release, 0.2.1):
WARDEN_VERSION=0.2.1 docker compose -f deploy/compose/docker-compose.ethos.yml up
```

Every recipe also runs a **control-plane** that serves policy and aggregates the agent's traffic into a fleet dashboard at **https://localhost:7070/dashboard/** (served with the proxy CA — trust it). Full per-recipe details (ports, the Node `fetch` proxy workaround, and how to prove isolation) are in **[docs/recipes/](docs/recipes/)**.

#### How a recipe works (Ethos, in detail)

[`deploy/compose/docker-compose.ethos.yml`](deploy/compose/docker-compose.ethos.yml) wraps the [Ethos](https://github.com/ethosagent/ethos) agent runtime so **all of its egress flows through Warden** with full visibility. Ethos runs on an internal-only network (no direct internet); the Warden worker is its sole route out, and the policy is **allow-all** for now, so nothing is blocked — you just *see* every call. The compose encodes everything needed to route and observe a real agent:

| Concern | How it's handled |
|---|---|
| **No bypass** | Ethos is on an `internal: true` network — its only egress is the Warden worker; a direct call simply fails. |
| **Proxy routing** | `HTTP(S)_PROXY=http://worker:8080`, plus **`NODE_USE_ENV_PROXY=1`** — Node's built-in `fetch` ignores `HTTPS_PROXY` without it, so agent calls would otherwise go direct and fail (`fetch failed`). |
| **TLS trust** | The proxy CA is mounted and trusted via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`, so Warden can terminate TLS and see URLs/methods/status. |
| **UI access** | An internal network blocks host port-publishing, so a tiny `socat` sidecar forwards the Ethos UI to the host **without** giving Ethos an internet route. |
| **Persistent audit** | Named data volumes hold the analytics DBs so they survive restarts/redeploys. |

To put **your own** service behind Warden, copy the `ethos` service block: attach it to `ethos-internal` only, set the proxy env (incl. `NODE_USE_ENV_PROXY=1` for Node runtimes), trust the CA, and add its destinations to the allowlist. Full walkthrough: [docs/docker-end-to-end.md](docs/docker-end-to-end.md).

## How It Works

1. **Agent sends request** — the agent connects to Warden via `HTTPS_PROXY` and sends a `CONNECT` request. It holds only placeholder tokens (`openrouter_secret_001`), never real API keys.

2. **TCP default-deny** — Warden checks the destination against the policy. If the domain/port isn't on the allowlist, the connection is dropped immediately. Denylist entries take absolute precedence.

3. **TLS termination** — Warden presents a dynamically-generated certificate (signed by a CA the agent trusts), decrypts the traffic to plaintext, and verifies the domain.

4. **Secret swap + forward** — Warden replaces placeholder tokens with real secrets in headers, query params, and body. It then forwards the request to the real destination with proper TLS. The real secret is injected at the edge and never returns to the agent.

5. **Response scan + log** — Warden scans the response for prompt-injection patterns and credential leakage, logs the decision (method, URL, status, secret-by-reference — never bodies or raw secrets), and returns the response to the agent.

## Features

### Security

- **Default-deny egress** — anything not on the allowlist is blocked at the TCP floor, including unknown protocols
- **Secret isolation** — agent holds placeholders; proxy holds and injects real secrets; the agent is structurally incapable of seeing the real value
- **TLS MITM** — dynamic per-domain leaf certs, CA validation at startup (IsCA + key match), PKCS#1/PKCS#8 support
- **Response scanning** — prompt-injection detection (4 pattern families) and credential-leakage detection (7 pattern families) with base64/URL encoding awareness
- **Denylist** — explicit deny rules with deny-wins-on-conflict precedence
- **Secret-by-reference logging** — secrets are referenced by SHA-256 hash / last-4 / length in logs and analytics; raw values are never persisted

### Policy

- **Domain matching** — exact, `*.wildcard`, `~regex` patterns
- **Rate limiting** — per-rule fixed-window (`100/hour`, `10/minute`, `5/second`)
- **Time windows** — per-rule hour ranges (`9-17`)
- **Port inference** — 443 for HTTPS, 80 for HTTP when omitted
- **Any-match-wins evaluation** — a request matching multiple allowlist entries is allowed if any entry passes its constraints

### Protocol Awareness

- **HTTP/1.1** — full handler with keep-alive, streaming, secret swap in headers/query/body, content-length correction
- **HTTP/2** — connection preface detection, routed to raw forwarding (gRPC handler planned)
- **MCP** — JSON-RPC detection, tool-call parsing, default-deny `ToolPolicy`
- **Unsupported protocols** — gated pass-through (still policy-checked at TCP/TLS, just not inspected)

### Secret Providers

- **ENV** — environment variable mapping (phase 1)
- **Vault** — HashiCorp Vault KV v1/v2 via HTTP API (no SDK dependency)
- **AWS Secrets Manager** — interface-only (wire in your AWS SDK client)
- **GCP Secret Manager** — interface-only (wire in your GCP SDK client)

### Observability

- **SQLite analytics** — every decision logged locally (domain, port, method, URL, decision, status, secret-ref — no bodies)
- **Dashboard** — built-in HTML UI at `/dashboard/` with auto-refresh, traffic table, policy view, secret references, blocked list, stats
- **JSON APIs** — `/dashboard/api/traffic`, `/dashboard/api/policy`, `/dashboard/api/secrets`, `/dashboard/api/blocked`, `/dashboard/api/stats`
- **Cost tracking** — estimated spend per LLM provider (OpenAI, Anthropic, Google, Cohere)
- **Admin** — `GET /healthz` (liveness), `POST /admin/refresh-secrets` (drop cache + refetch)

### Governance

- **Signed audit receipts** — Ed25519 signed, verified against trusted external key
- **Compliance mappings** — MITRE ATT&CK (T1048, T1071, T1552, T1059) + OWASP LLM Top 10 (LLM01, LLM02, LLM06, LLM07)
- **Central aggregation** — sync worker batches local events to a central store with buffer-cap resilience
- **Remote config** — HTTPS-only control-plane polling with last-known-good fallback

### Deployment

- **Docker Compose** — agent on internal-only network, proxy on internal + egress network; structural isolation via Docker network namespaces
- **Kubernetes** — sidecar container + default-deny egress `NetworkPolicy`; agent can only reach the proxy
- **VM / EC2** — systemd unit or container; agent container with egress routed to proxy
- **Single binary** — `CGO_ENABLED=0`, pure-Go SQLite, multi-stage Dockerfile, non-root container

## What Warden Does NOT Do

- **Not a content moderation layer** — we sit at the network boundary outside the agent, not inside it. For in-process guardrails, look at NeMo Guardrails.
- **No bare local-process mode** — agents can spawn containers and redirect traffic; host-process isolation is unwinnable. A container runtime is required.
- **No full body logging** — by design, analytics store headers and metadata only. Bodies are never persisted.
- **No automatic policy weakening** — the enforcing proxy is deterministic. LLM-assisted features (planned) are advisory only and cannot modify live policy.

## Configuration

```yaml
policy:
  allowlist:
    - domain: api.openai.com             # port omitted → inferred 443
    - domain: "*.internal.company.com"
      port: 8443
      rateLimit: "100/hour"
      timeWindow: "9-17"
  denylist:
    - domain: evil.example.com
    - domain: "*.malware.net"

secrets:
  - placeholder: openai_secret_001
    envVar: OPENAI_API_KEY

cache:
  ttl: 3600

logging:
  level: info
  format: json
```

See [`configs/config.example.yaml`](configs/config.example.yaml) for the full documented config.

## Project Structure

```
cmd/proxy/              Entry point — wire deps + start (no business logic)
internal/
  config/               ConfigProvider interface + YAML + remote HTTPS provider
  secrets/              SecretProvider interface + cache + ENV/Vault/AWS/GCP fetchers
  policy/               Default-deny evaluator + denylist + regex + rate limit + time window
  proxy/                TCP listener, TLS termination, HTTP handler, secret swap
  protocol/             Protocol detection (HTTP/1.1, HTTP/2, MCP)
  mcp/                  MCP tool-call parsing + ToolPolicy
  analytics/            AnalyticsStore + SQLite + central aggregation + sync worker
  scan/                 Injection + credential-leakage scanning
  dashboard/            HTML dashboard + JSON APIs
  audit/                Ed25519 signed receipts + compliance mappings
  cost/                 LLM provider cost estimation
  admin/                /healthz + /admin/refresh-secrets
  agentid/              Agent identification
deploy/
  compose/              Docker Compose (local dev + e2e harness)
  k8s/                  Kubernetes sidecar + NetworkPolicy
  vm/                   VM/systemd documentation
configs/                Example YAML configs
scripts/                check.sh (CI gate), gen-certs.sh, install-hooks.sh
test/
  integration/          E2E tests (behind integration build tag)
  fakes/                Hand-written test doubles for core interfaces
```

## Development

```sh
make build              # go build ./...
make test               # go test -race ./...
make check              # scripts/check.sh — the full CI gate
make integration        # scripts/check.sh --integration
make hooks              # install pre-commit + pre-push hooks
make fmt                # gofmt -w .
make lint               # golangci-lint run
```

## License

[Apache-2.0](LICENSE)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Run `scripts/check.sh` before pushing — it's the same gate CI runs.
