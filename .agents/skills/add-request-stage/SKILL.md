---
name: add-request-stage
description: Add a new decision stage (scan, gate, transform) to Warden's HTTP request path. Use when a change must inspect, deny, annotate or rewrite proxied requests.
---

# Add a request stage

Rules live in [`AGENTS.md`](../../../AGENTS.md); checks in
[`security-invariants`](../../reviews/security-invariants.md) (`SEC-3`, `SEC-4`,
`SEC-5`, `SEC-12`), [`hot-path`](../../reviews/hot-path.md) (`HOT-1`..`HOT-10`),
[`architecture`](../../reviews/architecture.md) (`ARCH-4`, `ARCH-5`) and
[`test-quality`](../../reviews/test-quality.md) (`TEST-2`, `TEST-8`).

## Steps

1. **Test first.** Write the failing proxy test (deny, failure and off-by-default cases).
2. **One job, one method.** Add `func (p *Proxy) myStage(s *requestScope) (endSession bool)` in
   `internal/proxy`. Return `true` only when the stage ended the request (it already wrote the
   response). Keep decision logic out of `swapSecrets` and `forward` (`ARCH-5`).
3. **Place it in `runRequestStages`** (`internal/proxy/http.go`). Order today:
   `readRequest → judgeGate → mcpRequestScan → dlpScan → swapSecrets → applyTransforms → forward → relayResponse`.
   - Anything that scans or decides goes **before** `swapSecrets`, so it sees placeholder names and
     never a real secret value.
   - Nothing may log, store or put request data on an event **after** `swapSecrets` without checking
     that swapped values stay out (`SEC-3`). Note: events still build their URL from the
     post-swap request; recording the pre-swap URL is tracked in #237.
4. **Gate it off by default.** Read the live component through an atomic pointer (`p.dlp()` style).
   `nil` means disabled: return `false` with no body read and no behaviour change (`SEC-12`).
5. **Fail closed.** A missing dependency, error or timeout denies (403 + event), as `judgeGate` does
   when the judge was turned off after CONNECT (`SEC-5`). If a stage must fail open (as `dlpScan` does
   on bodies it cannot read), flag the gap on the event (`dlpPartial`) and say why in the doc comment.
6. **Share the body.** Use `s.ensureBody()` (read once, capped by `maxBodySwapSize`); never
   buffer a second time (`HOT-4`).
7. **Record the decision.** Put results on `requestScope`, copy them onto the single allow event in
   `finishResponse`, and on deny write one `analytics.Event` with a bounded `Reason` (see `dlpDeny`:
   `"dlp_" + action`), the metrics call and `logDecision`. Never log bodies or secret values (`SEC-3`).
8. **Cover the other paths** (`SEC-4`, `TEST-8`). `runRequestStages` is HTTP/1.1 only:
   - HTTP/2 and gRPC: `serveGRPCStream` in `internal/proxy/grpc.go` does its own header swap and
     does **not** run the stages. Add the behaviour there, or record in the PR why it cannot apply.
   - WebSocket: the upgrade request goes through the stages; frames after the 101 go to
     `handleWSUpgrade` (`internal/proxy/ws.go`).
   - Add a test per path. The cross-path invariant suite (#359) and L1 harness (#350) are planned,
     not built: add the rows there once they exist.
9. **Benchmark** (`HOT-10`). Add or extend a benchmark next to `http_bench_test.go`, with the stage
   off and on (see `BenchmarkHandleHTTP_DLPOff` / `_DLPMonitor`). Observe added latency with
   `p.cfg.Metrics.ObserveAddedLatency("<stage>", …)`.
10. Run `scripts/check.sh`.

## Worked example: `dlpScan`

`internal/proxy/http.go`, `dlpScan` and `dlpDeny`. Runs just before `swapSecrets` so it scans the
pre-swap body. Off when `p.dlp() == nil`. Reads the body only when `ensureBody` cannot 413. Sets
`s.dlpAction`, `s.dlpClasses`, `s.dlpPartial`, which `finishResponse` copies onto the event. In
enforce mode it denies through `dlpDeny`. Benchmarks: `internal/proxy/dlp_bench_test.go`.
Config gate: see `add-config-key`.
