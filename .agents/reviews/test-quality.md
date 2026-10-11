# Test quality (`TEST-*`)

Coverage says code ran. This lens asks whether the tests would **fail** if
the behaviour broke. For a security proxy, untested deny paths and untested
failure modes are where bypasses hide.

## Already covered by CI

- `go test -race` and the coverage minimum (`COVERAGE_MIN`, 70%) in
  `scripts/check.sh`.
- Integration tests in `test/integration` (since #352).
- Once they land: the L1 and L2 harness scenarios (#350, #351) and the gates
  check that stops tests from being deleted or skipped (#354).

## Checks

**TEST-1 The test fails without the change.**
Ask: if the new code were deleted or reverted, which test fails? If none,
the behaviour is untested. Mentally break one line (flip a condition, drop a
stage) and check that a test would catch it.

**TEST-2 Deny and failure paths are tested, not only success.**
For each new decision: a blocked case, an error case, a timeout case, and
an "empty or missing" case. For Warden, the deny path matters more than the
allow path.

**TEST-3 Assertions check outcomes, not just "no error".**
Assert on the response body, the deny reason, the event written, the header
forwarded upstream and what was *not* sent. A test that only checks
`err == nil` or a 200 status rarely proves the requirement.

**TEST-4 Secrets in tests are canaries, and the test checks they don't leak.**
Use obvious fake values. Where a test touches swapping, logging or
responses, assert the value doesn't appear where it mustn't: the agent
response, logs, events. Tests must never print real-looking secrets.

**TEST-5 Fakes, not the network.**
Use the fakes in `test/fakes` (or the harness from #350) and `httptest`
servers. No calls to real hosts, real DNS or real cloud services in unit
tests.

**TEST-6 No sleeps; deterministic time.**
No `time.Sleep` to wait for something. Wait on a signal or poll with a
deadline. Expiry, rotation and TTL logic should take an injected clock, not
wait in real time.

**TEST-7 Table tests cover the edges.**
Boundaries (empty, one, max, max+1), unusual input (case, trailing dots,
IP literals, IDN for hosts; nested or huge JSON; non-UTF-8), and each branch
of a security decision.

**TEST-8 Every protocol path is tested where the change applies.**
If a change affects request handling, test it over HTTP/1.1 and, where it
applies, HTTP/2 and gRPC, WebSocket and SSE (see `SEC-4`).

**TEST-9 Tests are independent and race-safe.**
No shared global state between tests, no order dependence, temp dirs via
`t.TempDir()`, listeners on `:0`, cleanup with `t.Cleanup`. Parallel tests
don't share fakes unless the fake is safe for that.

**TEST-10 Test names say the behaviour.**
`TestSwap_DeniedHostKeepsPlaceholder` beats `TestSwap2`. A failing test name
should tell the reader which promise broke.

**TEST-11 New wire formats and parsers have golden or fuzz tests.**
New serialised formats get golden files. New parsers of untrusted input get
a fuzz target, or at least table tests with malformed input.

## Out of scope for this lens

Whether the behaviour itself is right (`ACC-*`) or secure (`SEC-*`). This lens
checks only how well it is proven.
