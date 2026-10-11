# Hot path (`HOT-*`)

Every agent request passes through a worker, so per-request cost on the data
plane is paid by every agent call. This lens looks for work added to that
path that doesn't need to be there.

The hot path is: accepting the connection, the CONNECT decision, TLS
termination, each stage in `runRequestStages` (`internal/proxy/http.go`), the
HTTP/2 and gRPC path (`internal/proxy/grpc.go`), WebSocket relaying
(`internal/proxy/ws.go`), stream scanning, `forward` and `relayResponse`.

## Already covered by CI

- The benchmark smoke run in `scripts/check.sh` (`go test -bench . -benchtime=1x`)
  only proves benchmarks compile and don't panic. **It doesn't catch
  slowdowns**, so judgement is still needed here.
- The race detector catches unsynchronised access, not lock contention.

## Checks

**HOT-1 No blocking network call per request, unless bounded.**
A new call to the control plane, a secret store, the analytics database or
an LLM from the request path must be cached, async, or have a timeout and a
fail-closed result (like `judgeGate`). Policy and secrets should come from
memory, refreshed in the background.

**HOT-2 No SQL or disk I/O per request.**
Events go to the async analytics writer, never a synchronous insert. No file
reads or writes per request.

**HOT-3 Work that can happen once happens once.**
Regex compilation, policy parsing, allowlist indexing, certificate loading,
template parsing and HTTP client construction belong at startup or policy
reload, not per request. Watch for `regexp.MustCompile`, `template.Parse`,
`x509.ParseCertificate`, `&http.Client{}` and `json.Unmarshal` of config
inside handlers.

**HOT-4 Bodies are streamed, not buffered, unless scanning needs them.**
Buffering a body costs memory per request. Where a scan needs the whole body,
it must have a size cap and a defined behaviour above the cap. SSE and
streaming responses must not be fully buffered.

**HOT-5 Allocations stay proportional.**
No copying the whole policy, allowlist or header map per request. Reuse
buffers (`sync.Pool`, `io.CopyBuffer`) for byte copying. Avoid string
concatenation in loops and `fmt.Sprintf` for map keys on every request.

**HOT-6 Locks are short and not shared across all requests.**
No global mutex held across I/O or across a whole request. Prefer immutable
snapshots swapped atomically (the policy reload model) for read-mostly data.

**HOT-7 Every connection and goroutine ends.**
A goroutine started per connection or stream must exit when the client or
upstream goes away. Check context cancellation, read and write deadlines,
`defer` closes, and channel sends that can block forever.

**HOT-8 Timeouts are set.**
Dials, TLS handshakes, header reads, idle connections and upstream responses
all need deadlines. A missing timeout on the hot path is a slow-loris risk
as well as a resource leak.

**HOT-9 Logging per request is bounded.**
At most one decision event per request, as today. No debug logging of
headers or bodies at info level, and no expensive argument building when the
log level is off.

**HOT-10 New hot code has a benchmark.**
A new stage or a change to an existing one comes with a benchmark (or an
updated one), and the PR states its cost, for example ns/op and allocs/op
before and after.

## Out of scope for this lens

Control-plane endpoints, the dashboard and background jobs, unless they're
called per request.
