// Package security is the in-process security suite: it attacks the identity,
// token exchange, worker mTLS, enrollment and signed-bundle paths of the real
// control plane and worker code with known-bad inputs, and asserts the exact
// rejection for each.
//
// # Running it
//
// It is ordinary Go tests with no build tag, so scripts/check.sh runs it in its
// normal "go test -race -coverprofile ./..." stage, and
//
//	go test -race -count=1 ./test/security
//
// runs it alone. It is hermetic: loopback only, 127.0.0.1:0 ports, t.TempDir
// state, no Docker, no outside network.
//
// The suite is serial. Every worker reads its enrollment token from an
// environment variable (controlPlane.enrollment.tokenEnv) the stack sets with
// t.Setenv, and t.Setenv cannot be used in a t.Parallel test, so no test here
// calls t.Parallel. Each test boots its own stack (a couple of seconds).
//
// # What is real
//
// StartStack boots controlplane.Run and two worker.Run instances from
// generated YAML, through the existing assembly seams only:
// controlplane.Params (Listener, OnReady, OnServer, KeysReady, Clock) and
// worker.Params (ProxyListener, AdminListener, OnReady, Overrides.Dialer,
// UpstreamRootCAs, Clock, OnAnalyticsWriter). No identity, mTLS, bundle or
// block check is re-implemented in test code. The workers enroll with wet_
// tokens minted through the admin API, pin the CP's bundle keys and bind to
// agent-a and agent-b through central.agentID.
//
// # Notes for reviewers
//
// The CA for the stack (fakes.TestCA in the first draft) lives in test/harness
// as harness.TestCA, with harness.NewLoopbackClient for the clients: the
// architecture baseline allows certificate minting and bare HTTP clients there
// and nowhere else in test/. In ValidFlow warden_identity_verify_total{valid}
// rises by 4, not 3, for the three transports: the terminated transport
// carries the token on CONNECT (Proxy-Authorization) and again in
// X-Warden-Identity, and the worker verifies each credential it reads.
//
// # Tampering with the control plane
//
// StackOptions.CPEndpoint points one worker at a TamperProxy (tamperproxy.go)
// instead of the CP. The proxy relays everything with the worker's own client
// certificate and can serve one armed response on GET /policy: a replayed,
// mutated or replaced signed bundle, a stub CP certificate. It is test code
// only; the worker's controlPlane.endpoint is an ordinary config value, so no
// production seam exists for it. StackOptions.PinBundleIssuer additionally pins
// controlPlane.bundleIssuer. Cert cases mint hostile worker certificates with
// harness.MintWorkerLeaf (signed by the stack's worker CA) and harness.TestCA
// (a foreign CA).
//
// # Writing a case
//
// A ticket adds cases and nothing else:
//
//  1. Declare them as a package-level []Case, naming what each one covers
//     (CoverIdentity, CoverBundle, CoverToken, CoverRoute), and append the
//     slice to allCases in cases_test.go.
//  2. In a test, start a stack, run the category's positive control with
//     Stack.PositiveControl, then Run the cases.
//  3. Delete the covered lines from pending.go. TestEnumCompleteness fails
//     until you do.
//
// Run asserts the status, body and headers; the assertion sources a case names
// (the worker's warden_identity_verify_total and warden_bundle_rejected_total
// from its admin /metrics, its deny events, the CP's admin audit rows,
// token_events rows and logs); the upstream hit count; and finally
// AssertNoLeak, which proves no token, client assertion, enrollment token,
// console session or key PEM appears in a response, an upstream request, a log,
// an audit row, an event or a metrics scrape, that the swapped secret appears
// only in allowed upstream requests, and that Proxy-Authorization and
// X-Warden-Identity never reach the upstream.
//
// A case that needs state built first (a tunnel held open across a cut, a
// rotated key) sets Case.Setup, which runs before the assertion sources are
// read and keeps what it built with Stack.Put; the Attack reads it back with
// Stack.Get. Admin cuts (RotateAgentKey, SetAgentEnabled, BlockUser,
// RotateTokenKey) go through the console API and are waited for with
// Stack.AwaitBundle. A worker with no central.agentID is StackOptions.
// UnboundWorker, and one without a CA (raw tunnels) is StackOptions.NoCA.
//
// Time is a fake clock shared by the CP, the workers and the issuer. Drive it
// only on a condition (Stack.EventuallyAdvance), never with a fixed Advance
// followed by a read.
//
// # Deviations from the ticket text (carry forward to #113)
//
// Config validation still refuses identity mode require, so the worker matrix
// runs in challenge mode. Consequently: raw Dex with acceptDexTokens true is
// not tested as a refusal (challenge mode accepts it; require must reject it);
// the require-mode 403 shapes for terminated and MCP requests are not pinned
// (every refused credential is a 407 at CONNECT); the clock-skew lower bound is
// tested at skew minus 2 minutes, on a skew-300 stack, because the proxy
// re-checks tunnel expiry on the real clock. Token-endpoint refusals before
// the client assertion verifies have no token_events row: they are pinned
// through the CP's debug-level token_exchange_denied line (Case.Unverified),
// and the TokenEdge.Metrics.Denied counter is not asserted.
//
// # The gate canary
//
// TestCanary fails when WARDEN_SECURITY_CANARY=1. Running
// "WARDEN_SECURITY_CANARY=1 scripts/check.sh" must exit non-zero with a FAIL
// for this package: the proof that the suite really gates the build.
package security
