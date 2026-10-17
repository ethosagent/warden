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
