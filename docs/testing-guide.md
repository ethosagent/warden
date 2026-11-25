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

Integration tests exercise the built artifact. They run behind the `integration`
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
| `TestSingleBinary` | `CGO_ENABLED=0 go build` succeeds → confirms pure-Go, no C deps |

The behavioural end-to-end checks that used to live here (allowlisted HTTPS,
default-deny, secret swap, decision logging) are harness scenarios now:
`go test ./test/scenarios/`.

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

## L2: container tests

The L1 harness (`test/harness`, `test/scenarios`) runs Warden in-process. L2 runs it as
real containers, to prove what only real containers can: the agent has no route out
except its worker, default-deny holds, no real credential reaches the agent, and a fleet
(one control plane, two workers) behaves when policy changes or the control plane dies.
The suite lives in `test/e2e` behind the `e2e` build tag, so `go test ./...` and
`scripts/check.sh` never start Docker. It needs Docker, `make` and the free host ports
7070, 8081, 9091 and 9092 (one stack at a time).

```sh
make e2e                                  # the whole suite, ~3 min: up, test, down
make e2e-up                               # just bring the hermetic stack up (and prove it hermetic)
make e2e-down                             # down -v
make e2e-scenario NAME=TestFleet_         # one test or a group (-run regexp)
KEEP_STACK=1 make e2e                     # leave the stack up after the run, to debug
E2E_STACK_RUNNING=1 go test -tags e2e ./test/e2e/ -run TestFleet -v   # reuse a stack you started
```

`go vet -tags e2e ./test/e2e/` compiles the package without Docker. Details of the stack,
the oracles and the fleet scenarios: `docs/docker-end-to-end.md`. In CI the suite is the
`e2e` job: required for `risk:critical` PRs, nightly on `main`, and a gate on every
release image.

### Recipe isolation proof (Claude Code, Codex)

`scripts/recipe-isolation.sh <claude-code|codex>` proves, on the real containers of an
identity recipe ([Claude Code](recipes/claude-code.md), [Codex](recipes/codex.md)), that
the agent has no route out except the forwarder and the worker, holds no identity
material or real vendor key, and is attributed to the logged-in user. It runs only on
request and needs no real vendor key (the worker holds a sentinel; the upstream answers
401):

```sh
flock /tmp/warden-e2e.lock scripts/recipe-isolation.sh claude-code   # one recipe
scripts/check.sh --smoke-recipes                                      # both recipes
```

`scripts/check.sh` without `--smoke-recipes` starts no Docker container. The script
needs Docker with Compose v2, network access, `jq` and `openssl`, and the free host ports
of the recipe stack (7070, 5556, 9091, 9092, 9094, 9095); it shares them with `make e2e`,
so hold the same lock. From a clean state it builds and starts the merged stack, puts
alice's token (`scripts/dex-token.sh --raw alice`) on the sidecar's volume from stdin,
and runs `docker compose down -v` in a trap. A first run waits a few minutes for the
control plane's first token key (see the recipe). Every check prints `PASS <name>` or
`FAIL <name>`; the first failure prints the worker's last 50 log lines with JWT-shaped
strings redacted and exits non-zero.

| Check | Where | Proves |
|---|---|---|
| `direct-egress-blocked` | agent | `curl --noproxy '*' https://example.com` fails |
| `idp-and-cp-unreachable` | agent | no TCP to `dex:5556` or `control-plane:7070`; the identity volume path is absent |
| `forwarder-405` | agent | a plain HTTP request (with the forwarder credential) to `warden-identity:3128` gets 405 |
| `no-secrets-in-agent` | agent | env, `/proc/*/environ` and `$HOME` hold no JWT-shaped string, PEM private key or vendor key other than the placeholder; the agent has `CapEff` 0 and `NoNewPrivs` 1 |
| `no-token-407` | probe on `cp-net` | the worker answers 407 `Proxy-Authenticate: Basic realm="warden"` to a request with no credentials |
| `attributed-allow` | agent + worker log | a request to the allowed API host gets an upstream answer (401 with the placeholder); the worker's decision is `allow` with alice's `user_sub` and `act` equal to the agent id |
| `header-replaced` | agent + worker log | the client's own `Proxy-Authorization` (the forwarder credential) is replaced, not forwarded: the worker attributes the request to alice and never sees the credential |
| `policy-deny` | agent + worker log | a CONNECT to a non-allowed host is refused and logged as deny |
| `cp-attribution` | control plane | `/dashboard/api/traffic?user=alice@example.org&act=<agent>` returns the event with `identity_status` valid (polled up to 120 s for the worker's push) |
| `agent-disabled` | control plane CLI | after `warden control-plane agent disable` a new CONNECT is refused within 10 s |
| `no-token-in-logs` | script output + logs | no JWT-shaped string in the script's output or in the logs of the worker, `warden-identity` and the control plane |

Self-tests of the proof (each must exit non-zero): merge
`deploy/compose/test/recipe-egress-leak.yml` (it also attaches the agent to the egress
network) through `RECIPE_ISOLATION_COMPOSE_EXTRA` and the script fails at
`direct-egress-blocked`; serve `identity: attribute` instead of `require` for the agent
and it fails at `no-token-407`. `RECIPE_ISOLATION_KEEP=1` leaves the stack up for
interactive debugging only: it keeps host ports 7070 and others bound after the lock is
released, so never use it while other stacks run and tear it down yourself
(`docker compose -p warden-recipe-<recipe> down -v`). The default always tears down.

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

These run as `go test ./test/scenarios/`. See `test/scenarios/README.md`.
The curl commands for trying them by hand are in the appendix
[Demo by hand](#appendix-demo-by-hand).

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

## Appendix: Demo by hand

With the proxy from "Start the proxy" running, open a second terminal. Each step
below is automated as a scenario in `test/scenarios/` (named in the heading); run
them here only to see the behaviour with your own eyes.

### Step 1: Allowed request with secret swap (`allow_with_swap`)

```sh
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer openai_secret_001"
```

**Expected:** 200 OK with model list. The proxy replaced `openai_secret_001` with
the real `$OPENAI_API_KEY` before forwarding.

### Step 2: Blocked destination (`default_deny`)

```sh
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://evil.example.com/steal-data
```

**Expected:** HTTP 403 Forbidden. The destination is not on the allowlist.

### Step 3: POST with secret swap in header and body (`swap_in_body`)

```sh
curl -x http://127.0.0.1:8080 --cacert certs/proxy-ca.crt \
  https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer openai_secret_001" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello"}]}'
```

**Expected:** 200 OK with a chat response. Secret swapped in the Authorization header.

### Step 4: Check the dashboard (`dashboard_traffic_api`)

Open http://127.0.0.1:9090/dashboard/ in a browser. You should see the requests from
scenarios 1-3 in the traffic table.

### Step 5: Check analytics directly (`events_recorded`)

```sh
sqlite3 warden.db "SELECT domain, decision, method, url, secret_ref FROM events ORDER BY id DESC LIMIT 10;"
```

**Expected:** Rows for each request. `secret_ref` shows `sha256:...` (never the raw key).

### Step 6: Verify no raw secret leaked (every scenario ends with `AssertCanaryNeverLeaked`)

```sh
sqlite3 warden.db "SELECT COUNT(*) FROM events WHERE secret_ref LIKE '%sk-%';"
```

**Expected:** 0.

### Step 7: Refresh secrets (`refresh_secrets`)

```sh
curl -X POST http://127.0.0.1:9090/admin/refresh-secrets \
  -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN"
```

**Expected:** `refreshed`. The secret cache is dropped and refetched from env vars.
The route is a writer: without the worker admin token it answers `401`, and with no
token configured at all `403` (see [control-plane.md](control-plane.md#worker-admin-token)).

### Step 8: Health check (`healthz`)

```sh
curl http://127.0.0.1:9090/healthz
```

**Expected:** `ok`.
