# Setup Guide

Get Warden running locally in under 5 minutes.

## Prerequisites

- **Go 1.26+** — check with `go version`
- **OpenSSL** — for generating the proxy CA certificate
- **Docker + Docker Compose** — only needed for the isolation-proof test (optional for local dev)
- **SQLite** — only needed if you want to query analytics directly (optional; the dashboard covers most use cases)

## 1. Clone and build

```sh
git clone git@github.com:ethosagent/warden.git
cd warden
make build
```

This produces a single static binary `./warden` (CGO_ENABLED=0, no external dependencies).

Verify:
```sh
./warden version
```

## 2. Generate the proxy CA certificate

Warden terminates TLS to inspect traffic and swap secrets. The agent must trust a CA
certificate that Warden holds. Generate it once:

```sh
scripts/gen-certs.sh
```

This creates:
- `certs/proxy-ca.crt` — distribute to agents (added to their trust store)
- `certs/proxy-ca.key` — proxy-only, never leaves the proxy boundary

Both files are gitignored. Do not commit them.

## 3. Create a config file

Copy the example and customize:

```sh
cp configs/config.example.yaml configs/config.yaml
```

Edit `configs/config.yaml`:

```yaml
policy:
  allowlist:
    - domain: api.openai.com
    # Add the domains your agent needs to reach.
    # Everything else is blocked (default-deny).

secrets:
  - placeholder: openai_secret_001   # what the agent sees
    envVar: OPENAI_API_KEY            # where the real key lives

cache:
  ttl: 3600

logging:
  level: info
  format: json
```

### Config reference

| Section | Field | Description |
|---------|-------|-------------|
| `policy.allowlist[].domain` | string | Exact domain, `*.wildcard`, or `~regex` pattern |
| `policy.allowlist[].port` | int | Optional; defaults to 443 (HTTPS) or 80 (HTTP) |
| `policy.allowlist[].rateLimit` | string | Optional; e.g. `"100/hour"`, `"10/minute"`, `"5/second"` |
| `policy.allowlist[].timeWindow` | string | Optional; e.g. `"9-17"` (hours, local time) |
| `policy.denylist[].domain` | string | Explicit deny; takes precedence over allowlist |
| `secrets[].placeholder` | string | Token the agent holds (e.g. `openai_secret_001`) |
| `secrets[].envVar` | string | Env var containing the real secret |
| `cache.ttl` | int | Secret cache TTL in seconds |
| `logging.level` | string | `debug`, `info`, `warn`, or `error` |
| `logging.format` | string | `json` or `text` |

## 4. Set secrets as environment variables

```sh
export OPENAI_API_KEY="sk-..."
# Add one export per secret in your config
```

Warden reads these on startup and caches them in memory. They are never written to disk
and never logged.

## 5. Start the proxy

```sh
./warden run \
  --config configs/config.yaml \
  --listen 127.0.0.1:8080 \
  --ca-cert certs/proxy-ca.crt \
  --ca-key certs/proxy-ca.key \
  --admin-listen 127.0.0.1:9090
```

You should see:
```
warden admin+dashboard on http://127.0.0.1:9090/dashboard/
warden proxy listening on 127.0.0.1:8080
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `configs/config.example.yaml` | Path to YAML config |
| `--listen` | `127.0.0.1:8080` | Proxy listen address (agent connects here) |
| `--ca-cert` | (none) | CA cert for TLS termination; omit for blind tunneling |
| `--ca-key` | (none) | CA private key (both cert+key required together) |
| `--admin-listen` | `127.0.0.1:9090` | Admin + dashboard listen address |
| `--db` | `warden.db` | SQLite analytics database path |

## 6. Point your agent at the proxy

Configure your agent's HTTP proxy setting:

```sh
# For most tools (curl, Python requests, Node fetch, etc.)
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080

# For TLS trust (agent must trust the proxy CA)
export SSL_CERT_FILE=certs/proxy-ca.crt        # Python, curl
export NODE_EXTRA_CA_CERTS=certs/proxy-ca.crt   # Node.js
export REQUESTS_CA_BUNDLE=certs/proxy-ca.crt     # Python requests
```

Or pass it per-command:

```sh
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer openai_secret_001"
```

## 7. Open the dashboard

Navigate to: **http://127.0.0.1:9090/dashboard/**

The dashboard shows:
- **Traffic** — live request log (auto-refreshes every 5s)
- **Policy** — current allowlist and denylist
- **Secrets** — placeholder references (SHA-256 hash, last-4, length — never raw values)
- **Blocked** — denied requests grouped by domain
- **Stats** — total/allowed/denied counts, top destinations

### JSON APIs

| Endpoint | Description |
|----------|-------------|
| `GET /dashboard/api/traffic` | Recent events (supports `?domain=`, `?decision=`, `?limit=`) |
| `GET /dashboard/api/policy` | Current policy as JSON |
| `GET /dashboard/api/secrets` | Placeholder references |
| `GET /dashboard/api/blocked` | Denied events grouped by domain |
| `GET /dashboard/api/stats` | Summary statistics |
| `GET /healthz` | Liveness probe |
| `POST /admin/refresh-secrets` | Drop secret cache and refetch |

## 8. Verify it works

```sh
# Allowed (should return 200 with model list):
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer openai_secret_001"

# Blocked (should return 403):
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://evil.example.com/

# Check analytics:
sqlite3 warden.db "SELECT domain, decision, method, secret_ref FROM events ORDER BY id DESC LIMIT 5;"
```

## Stopping

Press `Ctrl-C`. The proxy shuts down gracefully on SIGINT/SIGTERM.
