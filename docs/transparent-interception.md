# Transparent interception mode

Transparent mode is the deployment where the agent is **never configured with a
proxy**: it dials destinations the way it always does, and the network steers
those dials through Warden. Warden accepts the raw connections on its own
listeners, reads the destination from the TLS ClientHello (SNI) or the HTTP
`Host` header, and runs **the same enforcement pipeline as the CONNECT
proxy** — same policy, same secret swap, same DLP/MCP scans, same audit events,
same declared deny reasons.

This page is the operator recipe. The tickets are #376 (mode + listeners +
pipeline parity) and #391/#409 (the deny reasons it reuses).

## Contents

- [Choosing a mode](#choosing-a-mode)
- [Configuration](#configuration)
- [What the gate enforces](#what-the-gate-enforces)
- [QUIC and ECH: block UDP 443](#quic-and-ech-block-udp-443)
- [The interception network and the loop guard](#the-interception-network-and-the-loop-guard)
- [Recipe: Docker / Docker Compose](#recipe-docker--docker-compose)
- [Recipe: Kubernetes](#recipe-kubernetes)
- [CA distribution](#ca-distribution)
- [Low-port binding without root](#low-port-binding-without-root)
- [What the e2e suite proves](#what-the-e2e-suite-proves)

## Choosing a mode

```yaml
proxy:
  mode: forward | transparent | both   # default: forward
  transparent:
    httpsListen: "0.0.0.0:443"         # raw TLS, SNI-gated
    httpListen: "0.0.0.0:80"           # plain HTTP, Host-gated (OFF unless set)
```

| `mode` | CONNECT `:8080` | transparent `:443` | transparent `:80` |
|-----------|----|----|----|
| `forward` (default) | served | — | — |
| `transparent` | — | served if `httpsListen` set | served if `httpListen` set |
| `both` | served | served if `httpsListen` set | served if `httpListen` set |

Rules the worker enforces at boot (fail fast, clear error):

- `mode` must be one of the three values — anything else refuses to start.
- `transparent` or `both` requires `proxy.transparent.httpsListen`. Serving TLS
  interception without a listener is a misconfiguration, not a fallback.
- `httpListen` is strictly opt-in. Plain-HTTP interception only runs where you
  asked for it; the default is off even in transparent mode.
- Two listeners may not claim the same address (including the CLI
  `--listen`/`--admin-listen` flags). Port `0` never clashes — the kernel hands
  out distinct ephemeral ports.

`forward` (the default) is byte-identical to the pre-#376 behavior.

## Configuration

Full example (`configs/config.example.yaml` carries the same block):

```yaml
proxy:
  mode: both
  transparent:
    httpsListen: "0.0.0.0:443"
    httpListen: "0.0.0.0:80"
```

| Section | Field | Description |
|---------|-------|-------------|
| `proxy.mode` | string | `forward` (default), `transparent`, or `both` |
| `proxy.transparent.httpsListen` | string | Raw-TLS listener (required in `transparent`/`both`). Destination read from SNI |
| `proxy.transparent.httpListen` | string | Plain-HTTP listener (optional). Destination read from the `Host` header |

Policy entries keep working unchanged: an entry **without** a `port` matches the
TLS (443) and HTTP (80) evaluations of a transparent request; a `port`-pinned
entry matches only its port. If you want `api.example.com` reachable on both
listeners, leave the entry port-less.

## What the gate enforces

Everything below rides the ONE pipeline — there is no second policy engine for
transparent traffic. After the handshake (or Host read), the request enters the
identical CONNECT-tunnel path: policy → constraints → judge → swap → scans →
forward, one audit event per request.

- **Policy on SNI, before the handshake.** A TLS ClientHello with a missing,
  unparsable or not-allowlisted SNI is refused before any certificate is minted
  or any byte is forwarded. The client sees a failed handshake, never a Warden
  leaf. Deny reasons: `transparent_no_sni`, `transparent_bad_client_hello`,
  `policy_no_match`.
- **Fail closed on the hello.** A hello Warden cannot parse is a denial
  (`transparent_bad_client_hello`), never a bypass.
- **h2 prior knowledge is refused.** A cleartext HTTP/2 connection (ALPN-less
  `h2c` prior knowledge) aimed at the TLS port cannot be mediated; it is denied
  with `transparent_h2_prior_knowledge` and audited.
- **Every request re-carries the destination.** On a TLS or keep-alive
  connection each request's `Host` (and each h2 `:authority`) must equal the
  SNI the connection was admitted on; a mismatch is denied with the declared
  `host_mismatch` reason (409 Misdirected Request on h1, 421 per h2 stream) —
  defense in depth against re-describing an admitted connection mid-life.
  Plain HTTP admits on the `Host` header; a request with **no** `Host` is
  denied (`malformed_request`).
- **Same deny reasons.** A destination the allowlist does not name produces the
  same declared reason over CONNECT and over transparent listeners — the
  in-process parity scenario asserts the two events carry equal reasons.

## QUIC and ECH: block UDP 443

Transparent mode serves **TCP only**. HTTP/3 (QUIC over UDP 443) does not
transit it, and Encrypted Client Hello hides the SNI from the gate. Warden
logs a `WARN` at startup in `transparent`/`both` mode naming exactly this; the
operator MUST close the bypass on the network:

- block or redirect **UDP 443** on the egress path (the common choice: drop it —
  agents then fall back to TCP, which Warden intercepts), and
- if you terminate ECH upstream, remember that a ClientHello whose SNI Warden
  cannot read is treated as **missing SNI → denied**. That is the intended
  fail-closed behavior, not a bug.

An agent that cannot fall back to TCP cannot reach the internet; an agent that
can, lands on Warden.

## The interception network and the loop guard

Two layers keep upstream dials from re-entering Warden's own listeners (an
interception loop):

1. **Code-level (always on in transparent mode).** At startup Warden derives
   its own listener addresses and installs them into the SSRF-safe dialer: an
   upstream dial that **resolves** to one of those addresses is refused as a
   policy decision with the declared reason `transparent_loop_guard` (audited,
   answered with a 502). This fires even when `upstream.allowPrivateCIDRs`
   would otherwise admit the address.
2. **Network-level (operator requirement).** The interception network's DNS
   and routes must point **agent destinations** at Warden — never point
   Warden's own resolvable names at itself. Warden cannot police the network's
   DNS; keep the resolver the worker uses for upstream dials
   (`dns.upstreamResolver`) authoritative for the allowlisted names only.

## Recipe: Docker / Docker Compose

The pattern: a dedicated **interception network**; the worker attached to it;
the agent attached ONLY to it; the network's name resolution pointing the
agent's destinations at the worker.

```yaml
services:
  warden:
    image: ethosagent/warden:latest
    command: ["run", "--config=/etc/warden/config.yaml",
              "--listen=0.0.0.0:8080",
              "--ca-cert=/etc/warden/certs/proxy-ca.crt",
              "--ca-key=/etc/warden/certs/proxy-ca.key",
              "--admin-listen=0.0.0.0:9090", "--db=/data/warden.db"]
    sysctls:
      net.ipv4.ip_unprivileged_port_start: "0"   # bind 443/80 unprivileged
    networks: [egress, agents]

  agent:
    image: your-agent:latest
    networks: [agents]            # ONLY the interception network
    # NO HTTP_PROXY/HTTPS_PROXY — transparent mode is the point.
    # "DNS" that points destinations at the worker (production: your DNS):
    extra_hosts:
      - "api.openai.com:IP-OF-WARDEN-ON-AGENTS"

networks:
  agents:
    internal: true                # no route out except through warden
  egress: {}
```

The `hermetic` proof of this shape lives in `deploy/compose/docker-compose.e2e.yml`
(services `worker-3`/`agent-3` on `t-net`, subnet `10.201.0.0/24`): agent-3 has
no proxy environment and its host entries play the part the network DNS plays
in production. In real deployments the `extra_hosts` line is replaced by the
network's DNS server (a per-network resolver, CoreDNS forward zone, or
`--dns`), resolving the allowlisted names to the worker's interception
address. Names you do NOT point at Warden bypass the guardrail — point all of
the agent's egress names at it, or give the interception network no other
route (as above).

If a name resolves to the worker's own address by mistake — or an attacker
re-points one there — the loop guard refuses the dial and audits
`transparent_loop_guard`; the agent gets a 502, the upstream sees nothing.

## Recipe: Kubernetes

Options, simplest first:

1. **DaemonSet/pod per node + destination steering.** Run the worker with
   `proxy.mode: transparent`; steer pod egress to it with a NetworkPolicy that
   only allows egress to the worker pod plus a DNS override
   (CoreDNS rewrite rule: the allowlisted zones → the worker's Service).
2. **Service in front.** A `ClusterIP` Service (or LB) whose `:443`/`:80` are
   backed by the worker pod; the agent's DNS resolves destinations to that
   Service. TLS passthrough must be OFF — the worker needs the ClientHello.

Sketched CoreDNS rewrite (the "DNS points fake hosts at worker" half of the
contract):

```corefile
example.openai.com {
    rewrite name example.openai.com warden-egress.warden.svc.cluster.local
}
```

The worker still enforces default-deny on top: a name that resolves through it
but is not allowlisted is denied at the SNI gate.

## CA distribution

Transparent TLS interception means the worker terminates TLS with a leaf it
mints per SNI, signed by **the proxy CA**. Every agent on the interception
network must trust that CA, or every request fails certificate verification:

- bake the CA into agent images (`update-ca-certificates` on Debian/Alpine
  bases), or
- point the client at it (`CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`,
  Node `NODE_EXTRA_CA_CERTS`, Go `SSL_CERT_FILE`).

The CA private key never lives on agents — distribution is the **certificate**
only. See `scripts/gen-certs.sh` for baking one once.

## Low-port binding without root

Ports 443/80 are privileged. From least to most invasive:

1. **Higher ports + DNS that targets them** (`httpsListen: "0.0.0.0:8443"`)
   works only where the steering layer can add the port (DNS cannot).
2. **`CAP_NET_BIND_SERVICE`** on the container/pod grants exactly the low-port
   bind. Compose: `cap_add: [NET_BIND_SERVICE]`. Kubernetes:
   `containers[].securityContext.capabilities.add: [NET_BIND_SERVICE]`.
3. **Per-namespace sysctl** (Docker Compose, what the e2e stack uses):
   `sysctls: { net.ipv4.ip_unprivileged_port_start: "0" }` — unprivileged
   low ports inside the container's own network namespace, no capabilities.

## What the e2e suite proves

`make e2e` runs the two-network L2 proof on every change: agent-3 (no proxy
env, hermetic `t-net`) reaches an allowlisted host through worker-3's `:443`
with the secret swapped and audited; plain `:80` behaves the same with the
`Host` gate; a denylisted SNI is refused at the hello with the CONNECT workers'
reason; and a dial aimed back at the worker's own address is refused by the
loop guard (`transparent_loop_guard`), upstream untouched.
