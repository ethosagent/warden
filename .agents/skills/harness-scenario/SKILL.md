---
name: harness-scenario
description: Add a fake and a scenario to Warden's L1 in-process test harness (test/harness, test/scenarios). Use whenever a feature changes observable behaviour or talks to something new outside Warden — no feature is done without a scenario.
---

# Add a harness fake and scenario (Warden)

The L1 harness boots the real worker and the real control plane in one test
process on loopback; everything outside Warden is a fake. A feature's
acceptance criteria are proven by a scenario in `test/scenarios`, asserted
through Warden's own outputs (events, logs, metrics, the upstream's recorded
requests). The rule is in [`AGENTS.md`](../../../AGENTS.md); the API is in
[`test/scenarios/README.md`](../../../test/scenarios/README.md).

## Steps

1. **Pick the topology.** `harness.Local()` is the default (one worker).
   `harness.Fleet(n)` boots n workers behind one control plane,
   `harness.ControlPlaneDownAtBoot()` starts workers with the control plane
   unreachable. Everything is default-deny: `harness.Allow(domain...)` for any
   host beyond the harness's own `*.example.com` fakes.
2. **Add a fake if the feature talks to something new.** The new dependency
   gets a port (an interface), and the fake lives in `test/harness`
   (upstream-style servers: see `upstream.go`, `fakellm.go`, `fakemcp.go`) or
   in `test/fakes/fakes.go` (in-memory implementations of a port). Then
   register it in `Fakes` in `test/harness/registry.go` with a conformance
   suite that checks real behaviour. `TestPortCoverage` in
   `test/harness/registry_test.go` fails, naming the port, when an interface
   whose name ends in `Provider`, `Store`, `Client`, `Dialer`, `Clock`,
   `Notifier`, `Signer`, `Fetcher`, `Resolver`, `Alerter` or `Streamer` (or is
   a named suffix-less port such as `proxy.Judge`), or a type alias of one,
   under `internal/` has neither a `Fakes` entry nor an `Excluded`
   entry with a reason.
3. **Write the scenario** as `func yourScenario(t *testing.T, h *harness.H)` in
   a non-`_test` file in `test/scenarios`. Drive traffic with `h.Agent()` /
   `h.AgentH2()`, fake upstreams with `h.Upstream(host)` / `h.FakeLLM()`, and
   assert with `h.Events()`, `h.Logs()`, `h.Metrics()`. No sleeps: use
   `h.Eventually` and `h.Clock().Advance`. Close every response body.
4. **Register it** with one line in the literal in
   `test/scenarios/scenarios_list.go` (`Name`, `Opts`, `Run`; `L2: true` only
   if it needs nothing in-process-only). No `init()`.
5. **Run it with `-race`:**
   `go test ./test/scenarios -race -run 'TestScenarios/your_scenario'`, then
   `scripts/check.sh`.
6. **End with `h.AssertCanaryNeverLeaked()`** in any scenario that touches a
   secret (`harness.WithSecret`). It fails the test if the real value reaches
   the agent, logs, events, metrics or an out-of-scope upstream.

## Worked example: `allow_with_swap`

- Registered in `test/scenarios/scenarios_list.go`:
  `{Name: "allow_with_swap", L2: true, Opts: swapOpts(), Run: allowWithSwap}`.
- `swapOpts()` in `test/scenarios/swap.go` plants a fresh `harness.Canary()` as
  the `openai` secret via `harness.WithSecret`, swappable only for
  `api.example.com` and `llm.example.com`.
- `allowWithSwap` (same file) gets the fake provider with `h.FakeLLM()`, takes
  the placeholder from `h.Placeholder("openai")`, and POSTs through
  `h.Agent()` with `Authorization: Bearer <placeholder>`.
- It asserts the provider saw the real value (`llm.AuthHeaders()` is
  `Bearer <canary>`), then ends with `h.AssertCanaryNeverLeaked()`.
- Run it: `go test ./test/scenarios -race -run 'TestScenarios/allow_with_swap'`.
