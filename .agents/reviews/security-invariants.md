# Security invariants (`SEC-*`)

Warden's core invariant, from [`AGENTS.md`](../../AGENTS.md): the wrapped agent
is structurally incapable of bypassing the guardrail. Default-deny is sacred,
secrets never reach the agent, and logs never contain real secret values or
full bodies. This lens checks that a change keeps all of that true, on every
code path.

## Already covered by CI

Don't spend review time on these. If one fails, CI says so.

- Integration tests for allowlisted HTTPS, default-deny, secret swap and
  decision logging (`test/integration`, run in CI since #352).
- `govulncheck` for known-vulnerable dependencies.
- Once they land: architecture and banned-call rules (#349), the canary
  leak check and harness scenarios (#350, #351), and the gates check (#354).

## Checks

**SEC-1 Default-deny holds for the new behaviour.**
Is any destination, port, tool or path allowed by the change that isn't in
the allowlist? Watch for new fallbacks such as "if no rule matches, allow",
wildcard matching that is wider than intended, and case or trailing-dot
handling in hosts. Where to look: `internal/policy`, the CONNECT decision in
`internal/proxy`, and `judgeGate` in `internal/proxy/http.go`.

**SEC-2 Secrets never reach the agent.**
The agent holds placeholders only. Check:
- responses and error bodies sent back to the agent;
- an upstream that echoes request headers back;
- redirects;
- anything the change copies from the swapped request into a response,
  event or log.

The swap happens in `swapSecrets` (`internal/proxy/http.go`), *after* the
scans, so scanners never see real values. A new stage placed after
`swapSecrets` handles real secrets and must not log, store or return them.

**SEC-3 Logs and events hold no secret values and no full bodies.**
Secrets appear only by reference (hash, last four characters, version).
Headers only, no full request or response bodies. Look at `slog` calls,
error wrapping (`fmt.Errorf("…%v", req)` can print headers), decision
events, analytics rows, dashboard API responses and metrics labels.

**SEC-4 Every protocol path gets the change.**
`runRequestStages` covers HTTP/1.1 after TLS termination. Other paths don't
go through it:
- HTTP/2 and gRPC (`handleGRPC` and `serveGRPCStream` in
  `internal/proxy/grpc.go`);
- WebSocket (`internal/proxy/ws.go`);
- SSE and MCP streams (`internal/mcp/...`).

A security behaviour added to one path but not the others is a bypass.
Check that the change applies everywhere it needs to, or explains why not.

**SEC-5 Failure denies, never allows.**
For every new dependency on the request path (judge, LLM policy, a control
plane call, a store, a parser), what happens on error, timeout, empty or
corrupt data, or "not configured"? The answer must be deny, or keep the last
known good policy, never allow. `judgeGate` is the model: it fails closed on
error, and when the judge was turned off between CONNECT and now.

**SEC-6 Outbound connections use the SSRF-safe dialer.**
Any new code that dials or makes HTTP calls to an address that comes from
config, a user, an upstream or the agent must go through `SafeDialer`
(`internal/proxy/safedial.go`) or an equivalent check for private, loopback,
link-local and metadata addresses. Check for DNS rebinding: the address must
be checked at dial time, not only when the name is resolved.

**SEC-7 Agent-supplied input is bounded and validated.**
Header and body sizes, line counts, JSON nesting depth and decompression
ratios all need limits, plus read deadlines. Identity or control headers
from the agent (for example `X-Warden-Identity`, `Proxy-Authorization`) must
be verified and **stripped** before forwarding.

**SEC-8 No new way in for the agent.**
New listeners, admin or dashboard routes, debug endpoints, or ports must not
be reachable from the agent's network. Check `deploy/compose` networks
(`internal: true` on the agent network), the Kubernetes NetworkPolicy, and
listen addresses defaulting to all interfaces.

**SEC-9 Control-plane data stays on the control plane.**
Settings and secrets meant for the control plane only must not be sent to
workers. In `internal/config`, local-only fields carry `json:"-"` (for
example `Secrets`, `SecretStore`). A new field without it is sent to workers
in the policy wire. Per-user credentials (Phase 3) must never be readable by
workers.

**SEC-10 New HTTP routes are authenticated, authorised and audited.**
Each new route needs:
- authentication;
- a role or scope check;
- CSRF protection on browser routes;
- object-level checks (one user or worker can't read another's data);
- size and rate limits;
- an audit record for changes.

An error response must not echo internals.

**SEC-11 Crypto and randomness are correct.**
Use `crypto/rand` for tokens, nonces and IDs. Compare secrets with
`subtle.ConstantTimeCompare`. Verify signatures and certificates fully (no
`InsecureSkipVerify` outside tests). Pin algorithms; don't accept `none` or
whatever the peer offers.

**SEC-12 Defaults are safe.**
New behaviour ships behind a flag or default-off config. A missing or unknown
config value must fail at startup or fall back to the safe choice, never to
"allow" or "skip the check".

## Out of scope for this lens

Code style, naming and performance. Those belong to other lenses.
