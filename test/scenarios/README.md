# Scenarios

Warden's behaviour checks, written once as data over the L1 harness
(`test/harness`). `scenarios.All` is the catalog; `TestScenarios` boots a fresh
in-process control plane + worker per entry. #351 runs the same `All` against a
compose stack, so a scenario body may only use the harness API (addresses,
oracles, faults) — never reach into the process.

## Run

```sh
go test ./test/scenarios/ -race                 # everything
go test ./test/scenarios/ -run 'TestScenarios/default_deny'
go test ./test/scenarios/ -run 'TestScenarios/canary_h2' -v   # a protocol's rows
```

Scenario names are the subtest names; the canary matrix is
`canary_<http1|h2|grpc|ws>_<allow|deny|allow_echo>`.

## Add one

1. Write `func yourScenario(t *testing.T, h *harness.H)` in a non-`_test` file
   (`All` must be importable). Declare traffic with `h.Agent()` / `h.AgentH2()`,
   fake upstreams with `h.Upstream(host)` / `h.FakeLLM()`, and assert on what
   Warden itself reports: `h.Events()`, `h.Logs()`, `h.Metrics()`, the upstream's
   `Requests()`.
2. Add one line to the literal in `scenarios_list.go` with its `Opts`
   (`harness.WithSecret`, `harness.Allow`, `harness.Fleet`, …). No `init()`.
3. If it touches a secret, end with `h.AssertCanaryNeverLeaked()`.
4. Set `L2: true` only if it needs nothing in-process-only (no `RotateSecret`,
   no `Upstream` faults).

Rules: no sleeps — wait with `h.Eventually`, `Upstream.WaitParked` and the fake
clock (`h.Clock().Advance`). Close every response body.

## Minting user tokens (OIDC issuer fake)

`harness.WithOIDCIssuer()` starts an in-process OIDC issuer (`fakes.OIDCIssuer`,
`test/fakes/oidcissuer.go`) and exposes it as `h.Issuer()`; it stops at cleanup
and shares the harness clock, so `h.Clock().Advance` moves token time too. Mint
with `h.Issuer().Mint(fakes.Valid("sub", "a@example.com", "group"...))`, or
`fakes.Expired()`, `WrongAudience()`, `WrongAZP()`, `TooLong()`, `RotateKey()`
and the `With*` overrides (`WithClaim`, `WithAlg`, `WithKID`, `WithoutClaim`, ...).
`Stop()` / `Start()` take the issuer down and up; `JWKSRequests()` counts key
fetches. Present the token with `h.AgentWithProxyToken(tok)` /
`h.AgentH2WithProxyToken(tok)` (sent as `Proxy-Authorization: Basic` on CONNECT),
`h.ConnectStatusWithAuth(hostPort, rawHeaderValue)` for Bearer, malformed or
duplicate forms, or set `X-Warden-Identity` on a request yourself. The issuer is
plain http on loopback, so a verifier config for it needs
`InternalIssuerURL: h.Issuer().Issuer()` (the http-issuer rule). Never print a
token in a failure message; name the claim instead.

## Identity scenarios

`harness.WithIdentity("attribute"|"off")` boots the worker with the `identity`
block pointing at the issuer fake (audience `warden`, allowedAZP
`agent-harness` and `warden-cli`, `internalIssuerURL` = the fake's origin) and
turns on signed receipts. Mint tokens the block accepts with
`h.MintUserToken(fakes.Valid(...), fakes.Expired(), ...)`; the fake's own
defaults do not match the block. `h.Receipts()` returns the events worker-1
signed, signature-checked. The block is served by the control plane, so a
scenario changes it live by read-modify-write on `/dashboard/api/settings`
(`h.CP().GetJSON` / `PostJSON`); the worker applies it without a restart.

The catalog is `identity_*` (`test/scenarios/identity.go`):
`go test ./test/scenarios -race -run 'TestScenarios/identity_'`. Notes:

- With identity on, an event for a request with no token stores
  `identity_status=none` (and so do its receipt and decision log line); with
  identity off (`identity_mode_off`) the status stays empty, byte-identical to a
  pre-identity event, so an auditor can tell the two apart.
- The worker's verifier uses real time and re-fetches a failed key set at most
  every 30s, so a scenario recovers an issuer by changing a verifier input
  (a rebuild), not by waiting.
- No scenario prints a token; `assertNoLeakOf` checks logs, events, receipts,
  metrics and upstream recordings for each token and its pieces.

## Group-policy scenarios

`groups_*` (`test/scenarios/groups.go`) prove the group-aware policy end to end:
`go test ./test/scenarios -race -run 'TestScenarios/groups_'`. Harness levers:
`harness.WithFakeJudge()` points the inline judge at a counting loopback fake
(`h.Judge().Calls()`), so a deny scenario can assert the judge was never
consulted; `harness.WithScopedAllow(domain, groups...)` serves a
`{domain, groups}` entry from the control plane's boot YAML (the dashboard
policy save, `savePolicy`, is the other way in); `harness.WithoutProxyCA()`
boots a worker that cannot terminate TLS. MCP settings are applied on change,
so `groups_mcp_tool_gated` adds the `mcp:` block with
`h.EditControlPlaneConfig` after boot. `groups_old_worker_denies` decodes the
real `/policy` body with a frozen pre-group decoder and feeds the result to the
real evaluator and MCP gateway.

## Known issues

A row that an open issue breaks is marked `knownIssue` (see `canary.go` and
`expectKnown`). It asserts the violation STILL happens and fails with
"appears fixed: remove knownIssue" once it does not. Never skip a row or weaken
its assertion — fix the product or mark it.

Open product issues the scenarios work around (none is a `knownIssue` row unless
it breaks an assertion that exists):

- **#408** — a plain WebSocket with the MCP gateway off completes the 101 but
  never relays frames. The `canary_ws_*` rows cover the handshake only until it
  is fixed.
- **#409** — policy deny events carry no reason. `default_deny` asserts the
  decision, the log and the `reason="policy"` blocked metric, with a
  `TODO(#409)` for `Event.Reason`; a missing feature is not a `knownIssue`.
