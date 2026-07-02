# Testing Guide

How to test Warden at every level — unit tests, integration tests, manual local testing,
and the Docker Compose isolation proof.

## Unit tests

Run the full test suite with the race detector:

```sh
make test
# or equivalently:
go test -race ./...
```

This runs tests for all 19 packages. No external services needed — all tests use
in-memory stores, httptest servers, and test fakes.

### Running a single package

```sh
go test -race -v ./internal/proxy/
go test -race -v ./internal/policy/
go test -race -v ./internal/scan/
```

### Test fakes

Hand-written test doubles for the three core interfaces live in `test/fakes/`:

| Fake | Implements | Use for |
|------|-----------|---------|
| `FakeConfigProvider` | `config.ConfigProvider` | Fixed policy |
| `FakeSecretProvider` | `secrets.SecretProvider` | In-memory secret map |
| `FakeAnalyticsStore` | `analytics.AnalyticsStore` | In-memory event list |

## Integration tests

Integration tests wire real components together (real SQLite store, real secret cache,
real policy evaluator) and verify the M1 exit criteria. They run behind the `integration`
build tag:

```sh
make integration
# or equivalently:
scripts/check.sh --integration
# or directly:
go test -tags=integration -race -v ./test/integration/...
```

### What the integration tests verify

| Test | What it proves |
|------|---------------|
| `TestE2E_AllowlistedHTTPSSucceeds` | CONNECT to allowlisted domain → 200 |
| `TestE2E_NonAllowlistedBlocked` | CONNECT to non-allowlisted domain → 403, deny event in SQLite |
| `TestE2E_SecretSwapped` | Real `secrets.Cache` + `EnvFetcher` resolves placeholder → real key |
| `TestE2E_DecisionLogging` | Both allow and deny events appear in real SQLite store with correct fields |
| `TestSingleBinary` | `CGO_ENABLED=0 go build` succeeds → confirms pure-Go, no C deps |

## Full CI gate

Run exactly what CI runs:

```sh
make check
# or equivalently:
scripts/check.sh
```

This runs in order:
1. `gofmt` check (format)
2. `go vet` (static analysis)
3. `golangci-lint run` (linting — skipped if not installed)
4. `go build ./...` (build)
5. `go test -race -coverprofile` (tests + race detector + coverage)
6. Coverage gate (fails if below `COVERAGE_MIN`, default 70%)

Add `--integration` for the full gate including e2e tests.

## Manual local testing

### Setup

```sh
make build
scripts/gen-certs.sh
export OPENAI_API_KEY="sk-..."  # or any real API key
```

### Start the proxy

```sh
./warden run \
  --config configs/config.example.yaml \
  --listen 127.0.0.1:8080 \
  --ca-cert certs/proxy-ca.crt \
  --ca-key certs/proxy-ca.key \
  --admin-listen 127.0.0.1:9090
```

### Test scenarios

Open a second terminal and run each scenario:

#### Scenario 1: Allowed request with secret swap

```sh
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer openai_secret_001"
```

**Expected:** 200 OK with model list. The proxy replaced `openai_secret_001` with
the real `$OPENAI_API_KEY` before forwarding.

#### Scenario 2: Blocked destination (default-deny)

```sh
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://evil.example.com/steal-data
```

**Expected:** HTTP 403 Forbidden. The destination is not on the allowlist.

#### Scenario 3: POST with secret swap in header and body

```sh
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer openai_secret_001" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello"}]}'
```

**Expected:** 200 OK with a chat response. Secret swapped in the Authorization header.

#### Scenario 4: Check the dashboard

Open http://127.0.0.1:9090/dashboard/ in a browser. You should see the requests from
scenarios 1-3 in the traffic table.

#### Scenario 5: Check analytics directly

```sh
sqlite3 warden.db "SELECT domain, decision, method, url, secret_ref FROM events ORDER BY id DESC LIMIT 10;"
```

**Expected:** Rows for each request. `secret_ref` shows `sha256:...` (never the raw key).

#### Scenario 6: Verify no raw secret leaked

```sh
sqlite3 warden.db "SELECT COUNT(*) FROM events WHERE secret_ref LIKE '%sk-%';"
```

**Expected:** 0.

#### Scenario 7: Refresh secrets

```sh
curl -X POST http://127.0.0.1:9090/admin/refresh-secrets
```

**Expected:** `refreshed`. The secret cache is dropped and refetched from env vars.

#### Scenario 8: Health check

```sh
curl http://127.0.0.1:9090/healthz
```

**Expected:** `ok`.

## Docker Compose testing (full isolation proof)

This proves the core invariant: the agent container has **zero internet access** — the
only path out is through Warden.

### Setup

```sh
cd deploy/compose
export OPENAI_API_KEY="sk-..."
```

### Start the stack

```sh
docker compose up
```

This starts two containers:
- `proxy` — Warden, on both internal and egress networks
- `agent` — Alpine, on internal network only (no internet route)

### Test from inside the agent

```sh
# Open a shell in the agent container
docker compose exec agent sh
```

Inside the agent:

```sh
# Install curl
apk add --no-cache curl

# Scenario A: Allowed via proxy (works)
curl -x http://proxy:8080 https://api.openai.com/v1/models \
  -H "Authorization: Bearer openai_secret_001"
# Expected: 200 OK

# Scenario B: Blocked via proxy (default-deny)
curl -x http://proxy:8080 https://evil.example.com/
# Expected: 403 Forbidden

# Scenario C: Direct internet (FAILS — proves isolation)
curl --connect-timeout 5 https://api.openai.com/v1/models
# Expected: connection timeout / refused — no internet route

# Scenario D: Direct internet to any host (FAILS)
curl --connect-timeout 5 https://google.com
# Expected: connection timeout / refused
```

Scenarios C and D are the isolation proof: the agent container literally cannot reach
the internet without going through Warden.

### OpenRouter variant

If you have an OpenRouter key instead of OpenAI:

```sh
export OPENROUTER_API_KEY="sk-or-v1-..."
docker compose -f docker-compose.yml -f docker-compose.openrouter.yml up
```

Then inside the agent:

```sh
curl -x http://proxy:8080 https://openrouter.ai/api/v1/models \
  -H "Authorization: Bearer openrouter_secret_001"
```

### Cleanup

```sh
docker compose down
```

## Policy CLI tools

### Suggest policy from traffic

After running the proxy for a while with some traffic:

```sh
./warden policy suggest --since 7d --min-count 5 --db warden.db
```

Outputs a YAML allowlist generated from observed traffic patterns, with confidence
levels. Review and merge into your config.

### Evaluate a policy change

Before deploying a new policy, measure its impact:

```sh
./warden policy eval --candidate new-policy.yaml --since 30d --db warden.db
```

Outputs:
- **Agreement rate** — % of historical decisions that would be the same
- **New allows** — requests that would be unblocked (security review needed)
- **New denies** — requests that would be broken (availability review needed)

## Git hooks

Install once to get automatic checks on commit and push:

```sh
make hooks
```

- **pre-commit** (fast): gofmt + go vet + golangci-lint
- **pre-push** (full): runs `scripts/check.sh` (the complete CI gate)

## Troubleshooting

### `proxy: CA cert is not a certificate authority`

Your CA cert is missing the CA extensions. Regenerate:
```sh
rm certs/proxy-ca.crt certs/proxy-ca.key
scripts/gen-certs.sh
```

### `secrets: env var "X" not set for placeholder "Y"`

The env var referenced in your config isn't set. Export it before starting the proxy:
```sh
export OPENAI_API_KEY="sk-..."
```

### `proxy: both CACertPath and CAKeyPath must be set`

You provided `--ca-cert` without `--ca-key` or vice versa. Both are required together.
Omit both for blind TCP tunneling (no TLS termination, no secret swap).

### Curl returns `SSL certificate problem`

The agent/curl doesn't trust the proxy CA. Add `--cacert certs/proxy-ca.crt` to curl,
or set `SSL_CERT_FILE=certs/proxy-ca.crt` in the environment.

### Dashboard shows no traffic

Make sure you're pointing curl at the proxy with `-x http://127.0.0.1:8080` and
the proxy has TLS termination enabled (`--ca-cert` + `--ca-key`). Without TLS
termination, the proxy does blind tunneling and cannot inspect or log HTTP requests.
