<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/warden-logo-dark.svg">
    <img src="assets/logo/warden-logo.svg" alt="Warden — egress guardrail for AI agents" width="440">
  </picture>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/ethosagent/warden/releases"><img src="https://img.shields.io/github/v/release/ethosagent/warden" alt="Release"></a>
  <img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go 1.26+">
</p>

# Warden

**A default-deny egress proxy for AI agents. The agent can't bypass it — it's the only route out of the network.**

Warden sits between your AI agent and the internet. Every outbound connection goes through it. There is no opt-out: the agent's container has no direct internet route, so Warden is the single chokepoint that enforces policy, swaps placeholder tokens for real secrets at the edge, scans responses, and logs every decision. The agent never holds a real credential and cannot reach a destination you haven't explicitly allowed.

Built for teams running LLM agents (coding assistants, support bots, autonomous workflows) who need a security boundary that doesn't rely on the agent behaving correctly.

<p align="center">
  <img src="assets/architecture.svg" alt="Warden Architecture" width="800"/>
</p>

**Roadmap:** where Warden is going next (user identity, acting as the user with consent, and an enterprise control plane) lives in [`docs/roadmap/`](docs/roadmap/README.md), including the [final design](docs/roadmap/architecture.svg).

## Why Warden

- **It works below the agent.** Controls sit in the network path, so they hold even when the agent is prompt-injected, buggy or compromised. SDK-level guardrails can be ignored; a network proxy can't.
- **Credentials never reach the agent.** Tokens are injected at the edge per request. The agent holds only meaningless placeholders.
- **Default-deny.** Nothing gets out unless your policy says so — no implicit allow, no fail-open.
- **Agent-neutral.** Any harness that can use an HTTP proxy works: Cursor, Claude Code, Codex, OpenHands, custom agents. No SDK integration required.
- **Self-hosted and open.** Single binary, your infrastructure, Apache-2.0.

## Quickstart

```sh
# Build
go build -o warden ./cmd/proxy

# Generate the proxy CA cert (agent trusts this for TLS termination)
scripts/gen-certs.sh

# Set a real API key (the agent never sees this)
export OPENROUTER_API_KEY="sk-or-v1-..."

# Start the proxy + dashboard
./warden run --config configs/config.openrouter.yaml
```

`listen`, `adminListen` and `tls.caCert`/`tls.caKey` can live in the config
file (see `configs/config.example.yaml`); the equivalent flags
(`--listen`, `--admin-listen`, `--ca-cert`, `--ca-key`) override them.
Precedence: CLI flag > config key > built-in default (`127.0.0.1:8080`,
`127.0.0.1:9090`, no TLS termination). Startup logs the effective values and
their source.

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

| Agent | Stack | Bring it up | Agent UI | Warden dashboard |
|---|---|---|---|---|
| **[Ethos](docs/recipes/ethos.md)** | Node.js web UI + API | `docker compose -f deploy/compose/docker-compose.ethos.yml up` | http://localhost:3000 | http://localhost:9091/dashboard/ |
| **[Hermes](docs/recipes/hermes.md)** | Node.js, OpenAI-compatible | `docker compose -f deploy/compose/docker-compose.hermes.yml up` | http://localhost:8642 | http://localhost:9090/dashboard/ |
| **[OpenClaw](docs/recipes/openclaw.md)** | Node.js self-hosted assistant | `docker compose -f deploy/compose/docker-compose.openclaw.yml up` | http://localhost:18789/ | http://localhost:9090/dashboard/ |
| **[ZeroClaw](docs/recipes/zeroclaw.md)** | Rust, single binary | `docker compose -f deploy/compose/docker-compose.zeroclaw.yml up` | http://localhost:42617 | http://localhost:9090/dashboard/ |

```sh
# One-time: generate the proxy CA the compose files mount
OUT_DIR=deploy/compose/certs ./scripts/gen-certs.sh

# Bring up any recipe — the Warden image is pulled from Docker Hub (no build):
docker compose -f deploy/compose/docker-compose.ethos.yml up

# Pin a specific Warden version (defaults to the tested release, 0.3.0):
WARDEN_VERSION=0.3.0 docker compose -f deploy/compose/docker-compose.ethos.yml up
```

Every recipe also runs a **control-plane** that serves policy and aggregates the agent's traffic into a fleet dashboard at **https://localhost:7070/dashboard/** (served with the proxy CA — trust it). Full per-recipe details (ports, the Node `fetch` proxy workaround, and how to prove isolation) are in **[docs/recipes/](docs/recipes/)**.

**Per-user identity.** To record which user each agent request was made for, a harness sends the user's OIDC ID token to the worker. The **[agent identity contract](docs/identity-contract.md)** says exactly what token to send, how to send it (`Proxy-Authorization` on CONNECT, or `warden identity exec`), what the worker records, and what a harness must never do. To run the identity provider (Dex: clients, connectors, issuer rules, failure modes, production checklist), see the **[Dex operator guide](docs/identity-dex.md)**.

**Group-scoped policy.** An allow entry or an MCP tool `allowWhen` can be limited to IdP `groups` or named `users`; a non-member, or a request with no verified identity, is denied and never sent to the judge. Rules, fail-closed cases, deny reasons, `policy eval` replay and metrics: **[docs/group-policy.md](docs/group-policy.md)**.

#### How a recipe works

Each recipe puts the agent on a Docker `internal: true` network — its only egress
is the Warden worker. `HTTP(S)_PROXY` is set, the proxy CA is trusted, and a
`socat` sidecar forwards the agent UI to the host without giving the agent an
internet route. To put **your own** service behind Warden, see
[docs/docker-end-to-end.md](docs/docker-end-to-end.md).

## How It Works

1. **Agent sends request** — the agent connects to Warden via `HTTPS_PROXY` and sends a `CONNECT` request. It holds only placeholder tokens (`openrouter_secret_001`), never real API keys.

2. **TCP default-deny** — Warden checks the destination against the policy. If the domain/port isn't on the allowlist, the connection is dropped immediately. Denylist entries take absolute precedence.

3. **TLS termination** — Warden presents a dynamically-generated certificate (signed by a CA the agent trusts), decrypts the traffic to plaintext, and verifies the domain.

4. **Secret swap + forward** — Warden first checks the request's method and path against the allowlist entry's `methods`/`paths` constraints (every request of a keep-alive connection, before any swap), then replaces placeholder tokens with real secrets in headers, query params, and body. It then forwards the request to the real destination with proper TLS. The real secret is injected at the edge and never returns to the agent.

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
- **Method + path constraints** — narrow an allowlist entry to specific HTTP methods (`methods`) and request paths (`paths`), enforced per request before any secret swap or upstream write (HTTP/1.1, HTTP/2/gRPC, and WebSocket upgrades alike)
- **Rate limiting** — per-rule fixed-window (`100/hour`, `10/minute`, `5/second`)
- **Time windows** — per-rule hour ranges (`9-17`)
- **Port inference** — 443 for HTTPS, 80 for HTTP when omitted
- **Path-confusion deny** — requests with path traversal patterns (`/../`, `%2e`, matrix params) are denied outright when `paths` constraints are active

Policy evaluation details and edge cases: [docs/protocol-details.md](docs/protocol-details.md#policy-evaluation-details).

### Protocol Awareness

- **HTTP/1.1** — full handler with keep-alive, streaming, secret swap in headers/query/body, content-length correction
- **HTTP/2** — connection preface detection, routed to raw forwarding (gRPC handler planned)
- **MCP** — JSON-RPC detection, tool-call parsing, default-deny `ToolPolicy`
- **Unsupported protocols** — gated pass-through (still policy-checked at TCP/TLS, just not inspected)

### Secret Providers

- **ENV** — environment variable mapping (phase 1)
- **Vault** — HashiCorp Vault KV v1/v2 via HTTP API (no SDK dependency)
- **AWS Secrets Manager** — read/write store via a dependency-free SigV4 HTTP client; credentials resolve from each node's env or IAM role
- **GCP Secret Manager** — interface-only (wire in your GCP SDK client)
- **Backend selection** — choose env / echo / AWS from the dashboard (**Settings → Secret backend**) as well as the `secretStore:` config block; only the backend name + region/prefix are stored, never a credential

### Observability

- **SQLite analytics** — every decision logged locally (domain, port, method, URL, decision, status, secret-ref — no bodies)
- **JSON audit stream for a SIEM** — optional `audit.jsonLog`: one JSON line per decision (and per control-plane admin change), to stdout or a rotating file, with Vector and Fluent Bit examples ([docs/siem.md](docs/siem.md))
- **Dashboard** — built-in HTML UI at `/dashboard/` with auto-refresh, traffic table, policy view, secret references, blocked list, stats
- **JSON APIs** — `/dashboard/api/traffic`, `/dashboard/api/policy`, `/dashboard/api/secrets`, `/dashboard/api/blocked`, `/dashboard/api/stats`
- **Cost tracking** — estimated spend per LLM provider (OpenAI, Anthropic, Google, Cohere)
- **Admin** — `GET /healthz` (liveness), `POST /admin/refresh-secrets` (drop cache + refetch; needs the worker admin token, like every dashboard write)

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

- **Not a content moderation layer** — Warden sits at the network boundary outside the agent, not inside it. Use in-process guardrails for prompt/response filtering.
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
    matchHosts: ["api.openai.com"]       # swap only for this destination

cache:
  ttl: 3600

logging:
  level: info
  format: json

# Optional: upstream DNS for Warden's OWN lookups (VPN / split-horizon networks).
# dns:
#   upstreamResolver: "10.20.30.2:53"   # <host>:<port>; omit → Go default resolver
```

See [`configs/config.example.yaml`](configs/config.example.yaml) for the full documented config.

### Scoping secrets to destination hosts

`matchHosts` restricts where Warden swaps a placeholder — the same syntax as the
policy (exact host, `*.suffix`, `~regex`). A placeholder sent to a non-matching
host is forwarded **untouched** and a `secret_out_of_scope` event is recorded.
Full details: [docs/protocol-details.md](docs/protocol-details.md#scoping-secrets-to-destination-hosts).

### gRPC: put credentials in metadata

Warden swaps placeholders in gRPC **metadata** (headers), never inside protobuf
message bodies. If a placeholder appears in a gRPC message body, Warden refuses
the call with `PERMISSION_DENIED` rather than silently passing it through.
Streaming, split-frame detection, and compressed-message handling are all
covered. Full details: [docs/protocol-details.md](docs/protocol-details.md#grpc-credential-scanning-in-message-bodies).

### Upstream DNS resolver

`dns.upstreamResolver` points Warden's upstream dials at a specific DNS server
(`<host>:<port>`) for corporate networks, VPNs and split-horizon environments.
Full details: [docs/protocol-details.md](docs/protocol-details.md#upstream-dns-resolver).

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

## Future

Today Warden controls **where** an agent's traffic goes and keeps real credentials out of the agent. The next step is to control **who** the agent is acting for, and **what** it may do for them.

**The goal:** every action an AI agent takes on the network is tied to a real person, allowed by policy, done with that person's consent, and recorded. The agent still never holds a credential.

```mermaid
flowchart LR
  T["<b>Today</b><br/>Default-deny egress<br/>Secrets swapped at the edge"]
  P1["<b>Who did it</b><br/>Every request tied to a user<br/>Console SSO, roles, signed audit"]
  P2["<b>Proven identity</b><br/>Short-lived agent-bound tokens<br/>mTLS workers, signed policy"]
  P3["<b>Act as the user</b><br/>One-time consent, per-user OAuth<br/>Just-in-time approval, offboarding"]
  P4["<b>Agents everywhere</b><br/>Central MCP gateway, delegation grants<br/>Policy as code with canary"]
  T --> P1 --> P2 --> P3 --> P4
```

When the [roadmap](docs/roadmap/README.md) through Phase 4 ships, Warden becomes the **identity, authorization and audit layer for agent actions**: the one trusted path between any agent and the APIs, SaaS tools and MCP servers it works with.

**What that gives you**

| For | Value |
|---|---|
| Security teams | Know which person every agent request was for. Block a user across the whole fleet in seconds. Ship tamper-evident audit to your SIEM. |
| Platform teams | One control plane for every agent, whatever harness it runs in. Policy history, rollback, two-person approval and canary rollouts. One MCP gateway with pinned, reviewed tools. |
| Developers and end users | Agents can act as you in Google, GitHub and other tools after a single consent, without pasting tokens. Missing access becomes a "click to approve" link, not a failed run. |
| Compliance | A signed answer to "which agent did what, for whom, approved by whom", and access that ends when the person leaves. |

**What using Warden will look like**

The end goal is that safe agent access feels like nothing extra to the people using it.

*End users* never copy an API key or paste a token:

1. **Sign in once** with company SSO. In an agent platform this is the normal login. With a CLI agent it is `warden identity login`, then `warden identity exec -- <agent>`.
2. **Approve each tool once**, such as Google or GitHub, in the consent portal.
3. **Click approve when the agent needs more.** A Slack or email message arrives, and the agent's request waits and then continues instead of failing.
4. **See and revoke** connected tools, grants and recent agent activity in the portal at any time.
5. **When they leave, they do nothing.** Their tokens are revoked at each provider and access ends across the fleet.

*Admins* set it up once:

1. Deploy the control plane and workers, and connect the company IdP.
2. Assign console roles: admin, editor, viewer.
3. Register the OAuth apps and MCP servers your agents may use.
4. Write policy for which agents, groups and users may reach which destinations and tools, with history, approval and rollback built in.
5. Optionally, connect Slack or email for notifications, the SIEM export, and policy as code from git.

*Agent builders* register the agent, route its traffic through a Warden worker (ready-made recipes exist for common harnesses), and optionally use the single Warden MCP gateway URL in place of many MCP servers.

Follow the work on the [Roadmap issue](https://github.com/ethosagent/warden/issues/15).
