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
  up
```

The proxy logs:
```
warden admin+dashboard on http://0.0.0.0:9090/dashboard/
warden proxy listening on 0.0.0.0:8080
```

Open the dashboard at **http://localhost:9090/dashboard/** (published from the proxy; the agent
cannot reach it — it's on the host-facing side only).

## 5. Run `make e2e`

The proof that the isolation holds is a test suite, not a list of curl commands:

```sh
make e2e
```

It builds the hermetic stack from your checkout (control plane, two workers, two
agents, a fake upstream; no real internet, no real credentials), runs
`test/e2e` against it and tears it down (about 3 minutes). It checks, from inside the
agents, that every route out fails, that an allowed call arrives upstream with the
secret swapped while the agent only held the placeholder, that a denied host is
refused and logged, that no real secret leaks anywhere, and that policy changes and
control-plane outages behave as a fleet should (fail closed). See
[Run the L2 suite](#run-the-l2-suite-make-e2e) below for flags, and
`docs/testing-guide.md` ("L2: container tests"). CI runs the same suite as the `e2e`
job: required for `risk:critical` PRs, nightly on `main`, and on every release image
before the release is published.

To see the proof with your own eyes against the demo OpenRouter stack, follow
[Appendix: Demo by hand](#appendix-demo-by-hand).

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

## Hermetic e2e harness (`make e2e-up`)

The stack above reaches real internet services. The **hermetic** variant never
completes a round trip to the internet: `deploy/compose/docker-compose.e2e.yml` overrides the same
topology so every upstream is one fake container built from this repo
(`test/e2e/fakeupstream/`), which serves `api.example.test`, `llm.example.test`
(OpenAI-shaped stub), `mcp.example.test` (the poisoned MCP server), and
`evil.example.test` on one pinned cert — plus the DNS server for the internal
`10.200.0.0/24` egress network, where unknown names are NXDOMAIN.

**Hermeticity is enforced, not assumed.** All scenario networks (including the
control-plane bus) are `internal: true`, so the agents have no route out except
their worker. The only non-internal network, `published`, exists solely so
Docker (Engine ≥ 29) will actually forward the host-published ports (recorder
8081, CP 7070, worker admins 9091/9092). It runs with outbound masquerading
**disabled** — which buys exactly this: the CP, workers and fake upstream
cannot complete a round trip to the internet on a host whose network does not
NAT or route foreign source addresses. Their packets may still leave the host
un-NATed, and they can open connections to the Docker host itself. `make
e2e-up` proves the no-round-trip property every time: after `--wait` it runs
`test/e2e/hermeticity.sh`, which per container first proves the probe path
works (the container is up with a shell and a probe tool, and a positive
control — the fake upstream recorder, or the agent's own worker admin
`/healthz` — must succeed), then requires every negative probe to fail: no
HTTP exchange with `1.1.1.1` over TCP 80/443, and no answer to a UDP DNS query
against `1.1.1.1:53`. A missing service, a stopped container, a missing shell
or probe tool, or a failed positive control fails the up with the container
named — only an answered probe is a leak.

A request recorder on `127.0.0.1:8081` is the scenarios' oracle:
`GET /_recorded` returns `{"records": […], "dropped": N}` (the recorder keeps
the newest 1024 requests — the oldest are dropped and counted in `dropped`),
`POST /_reset` clears records + rebinding, and `POST /_rebind?host=…` re-arms a
DNS name to answer `127.0.0.1` (the SSRF red-team case: Warden must refuse the
redirected dial).

```sh
make e2e-up      # gen certs if missing → up --build --wait → hermeticity check
make e2e-down    # down -v
```

The stack is **always built from the checkout you run it from** (`up --build`;
the build cache keeps a no-op rebuild fast), so a source edit always reaches
the next `make e2e-up`. Set `WARDEN_IMAGE` to test a specific pre-built image
instead — then nothing is built (`--no-build`) and the image must already
exist, or the up fails with a clear message.

## Run the L2 suite (`make e2e`)

`test/e2e` is a Go package behind the `e2e` build tag, so `go test ./...` and
`scripts/check.sh` never touch Docker. It needs Docker, `make` and free
host ports 7070, 8081, 9091, 9092 (one stack at a time).

```sh
make e2e                                        # whole suite (~1-3 min)
make e2e-scenario NAME=TestIsolation_DefaultDeny # one test (-run regexp)
E2E_KEEP_STACK=1 make e2e                       # leave the stack up to debug
E2E_STACK_RUNNING=1 go test -tags e2e ./test/e2e/ -v   # reuse a stack you started
```

`TestMain` runs `make e2e-up` (build from source, wait healthy, hermeticity
check), polls the control plane, both workers and the recorder with a 120 s
deadline, runs the tests, then `down -v`. With the tag set and no working
Docker the package fails; it never skips. The isolation suite proves, from
`agent-1`, that every route out fails for the right reason (public IP, public
DNS, IPv6, control plane, Docker gateway/metadata, the other worker's network;
each beside a positive control), that an allowed call reaches the fake upstream
with the swapped canary while the agent never sees it, that a denied host
leaves exactly one deny event with reason `policy_denylist` (and the wrong-port
call one with `policy_no_match`), and that the canary (raw, base64, URL, hex) is absent
from agent output, every service's logs, both workers' traffic APIs and the
control plane's fleet API. The recorder is the one place it must appear.
Workers forward analytics to the control plane asynchronously, so event reads
poll with a deadline. The helpers (`agentExec`, `recorded`, `resetRecorded`,
`events`, `logs`, `AssertCanaryNeverLeaked`) are reused by the later L2 suites.

The fleet suite (`fleet_test.go`) changes policy through the route the dashboard
uses (`PUT /dashboard/api/policy` on the control plane) and checks that both workers
pick it up within one long-poll; that with the control plane stopped the workers keep
the last policy and stay fail-closed (an allowed host works, a denied host and a host
nobody allowed stay refused); that a restarted control plane resyncs the workers;
that a restarted worker decides by policy on its first request; and that each
agent's request is attributed to its own worker in the fleet view. Each test puts the
stack back as it found it, so the order does not matter.

### In CI

`.github/workflows/e2e.yml` (job `e2e`, 15 minute limit) runs on PRs that touch a
risky path, nightly on `main`, and as a reusable workflow that `release.yml` calls
with the pushed image digest (`WARDEN_IMAGE`; the GitHub Release waits for it). On
failure it uploads `docker compose logs`, both workers' traffic APIs, the fleet API
and `/_recorded` as the `e2e-diagnostics` artifact; `KEEP_STACK=1` is what keeps the
stack alive long enough to collect them. Its `paths` filter must include every
`critical` glob in `.agents/risk.yaml` (a Go test in `tools/riskmap` enforces it),
because `risk.yml` waits for a check run named `e2e` on every critical PR.

## Drive it by hand

Try it by hand:

```sh
docker compose -p warden-e2e exec agent-1 curl -s \
  -H 'Authorization: Bearer example_secret_001' https://api.example.test/
curl -s http://127.0.0.1:8081/_recorded   # placeholder→canary swap visible upstream
```

> **`/echo` reflects request headers back to the agent — including a swapped
> canary.** That is by design: it is the endpoint the echo-leak scenarios need.
> Never use `/echo` for a "the agent never sees the secret" check; that
> assertion belongs to the recorder (`/_recorded`), which sees the traffic on
> the wire while the agent only sees its own response.

Workers are **CP-managed** (`configs/config.e2e-worker.yaml`): the allow/deny
policy lives in `configs/config.e2e-cp.yaml` (allow `api/llm/mcp.example.test`,
deny `evil.example.test`) and is pulled by both workers from the control plane,
hot-reloaded on change. Each worker's local file keeps only local wiring: the
canary secret mapping, `dns.upstreamResolver` (the fake DNS), and
`upstream.allowPrivateCIDRs: ["10.200.0.0/24"]` — the one sanctioned SSRF
exception, local-only by design and never settable by the control plane. They
verify the fake upstream via `SSL_CERT_FILE` pointing at the fake-CA + system
bundle `test/e2e/certs/gen.sh` builds; no extra config key. `make e2e` /
`make e2e-scenario` run the suite described above.

No root anywhere: the warden services run as the image's non-root `warden`
user, the fake upstream runs as its own non-root user (it binds 443 and 53 via
the per-container `net.ipv4.ip_unprivileged_port_start=0` sysctl — no
capabilities), and the lab keys under `test/e2e/certs/` (gitignored,
regenerated by `make e2e-up` whenever any of them is missing) are
world-readable on purpose so the non-root containers can read the bind-mounts.

## See also

- `docs/setup-guide.md` — running the binary locally (no Docker).
- `deploy/k8s/` — the same isolation as a Kubernetes sidecar + default-deny NetworkPolicy.

## Appendix: Demo by hand

Manual version of the proof, against the OpenRouter demo stack from steps 1-4. `make e2e`
(step 5) automates and extends it; use this only to watch it happen.

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
