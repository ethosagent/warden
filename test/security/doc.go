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
// # Writing a case
//
// A ticket adds cases and nothing else:
//
//  1. Declare them as a package-level []Case, naming what each one covers
//     (CoverIdentity, CoverBundle, CoverToken, CoverRoute), and append the
//     slice to allCases in cases.go.
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
// Time is a fake clock shared by the CP, the workers and the issuer. Drive it
// only on a condition (Stack.EventuallyAdvance), never with a fixed Advance
// followed by a read.
//
// # The gate canary
//
// TestCanary fails when WARDEN_SECURITY_CANARY=1. Running
// "WARDEN_SECURITY_CANARY=1 scripts/check.sh" must exit non-zero with a FAIL
// for this package: the proof that the suite really gates the build.
package security
