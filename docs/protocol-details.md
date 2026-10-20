# Protocol Details

Advanced configuration and behaviour details for Warden's protocol-level
features. For an overview, see the [README](../README.md).

## gRPC: credential scanning in message bodies

Warden swaps a placeholder in gRPC **metadata** (headers such as
`authorization`), never inside a gRPC **message**. Rewriting a placeholder in a
protobuf message without its schema is unsafe: a length-delimited field can be a
string or a nested message, and changing a string's length means re-encoding
every enclosing length. So a gRPC credential must ride metadata, and a
placeholder found in a message body is refused visibly rather than silently
reaching the upstream unswapped (#418).

When a gRPC call is made to a host a placeholder is in scope for (`matchHosts`),
Warden checks each length-prefixed message before forwarding it:

- **Placeholder in a message** — the message is not forwarded. The call ends
  with gRPC status `PERMISSION_DENIED` (7) and `grpc-message: secret
  placeholders must be sent in gRPC metadata`, and a deny event with reason
  `grpc_body_placeholder` is recorded. Warden holds the request back
  up to 250 ms for the call's first message, so a call refused on a first message
  that arrives within that window reaches the upstream not at all. A first
  message that arrives later means the request headers (with the swapped
  metadata) have already gone upstream; the message itself is still refused. On
  a client- or bidi-streaming call, messages before the offending one were
  already forwarded and the stream then ends with the same status.
- **Frame bound** — a message is buffered up to 4 MiB (`maxGRPCFrameBytes`, the
  gRPC default message size) to be inspected. A larger one fails closed:
  `RESOURCE_EXHAUSTED` (8), reason `grpc_frame_too_large`.
- **Compressed messages** — a message with the compressed flag set cannot be
  inspected and is refused: `FAILED_PRECONDITION` (9), reason
  `grpc_frame_compressed`. Turn gRPC message compression off for calls through
  Warden to hosts that hold a placeholder.
- **Malformed framing** — a bad flag byte, or a stream that ends inside a
  message: `INVALID_ARGUMENT` (3), reason `grpc_frame_malformed`.
- **Streaming** — messages without a placeholder are forwarded as they arrive;
  at most one message is held at a time.
- **A placeholder split across messages** is caught at the boundary: Warden
  keeps the last bytes of the messages before (as many as the longest
  placeholder, less one) and checks them joined with the start of the next. The
  message that completes the placeholder is refused as above; the earlier part
  was already forwarded, and is inert because nothing in a body is ever swapped.
- **A placeholder for a different host** (out of scope here) is not inspected
  for and passes untouched. Unlike an out-of-scope placeholder in an HTTP/1.1
  body, it records no `secret_out_of_scope` event on gRPC today.
- **Known corner** — if the upstream ends its response without reading the
  request body and the offending message only arrives afterwards, the message
  goes nowhere (the transport has stopped reading it), but no deny is recorded
  and the client sees no refusal status; the call is logged as an ordinary allow.
  Pinned by `TestGRPCBody_RefusalAfterUpstreamFinishedRecordsNoDeny`.

With no placeholder in scope for the destination, the body is streamed verbatim
and none of the above applies.

## Scoping secrets to destination hosts

A placeholder should only ever be exchanged for its real value on the host it
belongs to. `matchHosts` (same syntax as the policy: exact host, `*.suffix`,
`~regex`) restricts where Warden swaps a placeholder, in HTTP/1.1, HTTP/2/gRPC
and WebSocket-upgrade requests alike:

- The destination is the CONNECT/SNI host — the one the allow/deny decision used
  and the upstream is dialed at — never a `Host` header or URL host the agent
  controls.
- On a non-matching host the placeholder is forwarded **untouched** (the
  destination rejects it as an invalid credential) and a distinct
  `secret_out_of_scope` event is recorded with the placeholder *name* only, so
  operators can see attempted cross-host carriage. Allow/deny counts are unchanged.
- A secret that cannot be fetched fails the request with 503 only on hosts where
  it is in scope; an unrelated missing secret no longer 503s every request.
- `~regex` is an **unanchored** (substring) match, exactly like the policy engine:
  `~github\.com` also matches `evil-github.com`. Anchor it —
  `~^api\.github\.com$` — or prefer an exact host / `*.suffix`.
- Invalid patterns (bad regex or wildcard) fail config load.
- `auth:` injectors (OAuth2, SigV4, HMAC, API key) are scoped by their required
  `match` field, with the same syntax.

**Migration:** entries without `matchHosts` keep the old behavior (swap on every
allowed host) and log a startup warning per placeholder. Add `matchHosts` to each
secret; it is expected to become required in a future release.

## Upstream DNS resolver

On networks where the resolver the container inherits cannot resolve public
names — corporate networks and VPNs that block or filter public DNS,
split-horizon environments, or container runtimes whose embedded DNS refuses
external names — Warden cannot look up allowlisted destinations at all.
`dns.upstreamResolver` points Warden's **own** upstream dials (CONNECT tunnels
and TLS-terminated upstreams; SNI keeps the client-supplied hostname) at a
specific `<host>:<port>` server. Plain UDP/TCP only — DoH/DoT transports are
out of scope for v1.

It is scoped to Warden's egress path: the dashboard/admin listeners are
unaffected, and the **agent's** own DNS path is a separate concern (under the
transparent-interception contract, [#376](https://github.com/ethosagent/warden/issues/376),
agent-side names are routed to Warden by the orchestration runtime). If the
configured server is unreachable, affected requests fail like any other
upstream-connect failure (visible in analytics and the dashboard's
blocked/fail lists) — there is no silent fallback to the system resolver.

Use an **IP literal** for `upstreamResolver` (e.g. `10.20.30.2:53`): the server
address itself is resolved by the system resolver, so a hostname there would be
looked up through the very resolver being overridden — `/etc/hosts` still
applies as before.

## Policy evaluation details

### Path-confusion deny

When an entry constrains `paths`, a request whose raw path contains a dot segment, a matrix parameter, or an encoded separator (`/../`, `/./`, `%2e`, `%2f`, `%5c`, `%3b`, raw or encoded `;`, backslash, `//`) is denied (`path_not_canonical`) even if it string-matches a pattern: patterns are matched against the raw percent-encoded path that goes upstream, never a decoded one. Java servers (Tomcat, Jetty, Spring) strip `;params` per segment — `/v1/..;/admin` would be `/admin` upstream, so it is denied outright.

**Residual risk:** decodings Warden cannot see still apply origin-side — double-encoding (`%252e`), overlong UTF-8 (`%c0%ae`), and `%00` reach the origin verbatim when the pattern allows them, and `methods` does not inspect method-override headers such as `X-HTTP-Method-Override`.

### Rate limiting behaviour change (#371)

Limits used to be consumed once per CONNECT tunnel; they are now consumed **per request**. For a rule without `methods`/`paths`, N keep-alive requests over one tunnel now count N, not 1 — tighten the limit (or add constraints, which keep denied requests free) when migrating.

### Any-match-wins evaluation

A request matching multiple allowlist entries is allowed if any entry passes its constraints. **Sharp edge:** an unconstrained entry for the same domain makes a constrained twin useless — scope them to distinct ports or drop the unconstrained entry.
