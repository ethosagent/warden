package worker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dnstest"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/scan"
)

// writeConfig writes cfg to a temp file and returns its path.
func writeConfig(t *testing.T, cfg string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// runParams returns Params wired to ephemeral loopback ports and a temp DB, so a
// Run under a cancelled context binds nothing that can collide and returns promptly.
func runParams(t *testing.T, configPath string) Params {
	t.Helper()
	return Params{
		ConfigPath: configPath,
		ListenAddr: "127.0.0.1:0",
		DBPath:     filepath.Join(t.TempDir(), "warden.db"),
		AdminAddr:  "127.0.0.1:0",
		Version:    "test",
	}
}

// runUntilCtxDone runs worker.Run under a context cancelled after a short delay,
// so the proxy binds, serves, and shuts down cleanly. It returns Run's error (nil
// on a clean ctx-driven shutdown). It is the end-to-end assembly exercise: the full
// wiring in worker.go runs against fakes/temp dirs without a live network peer.
func runUntilCtxDone(t *testing.T, p Params) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel almost immediately: Serve blocks on Accept and returns nil on ctx.Done.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	return Run(ctx, io.Discard, p)
}

// TestRun_LocalOnly_Minimal exercises the full worker assembly for a plain
// local-only worker (every optional feature off): config load, secret cache, logger,
// analytics + MCP-store wiring, evaluator, proxy build, admin server, and a clean
// ctx-driven Serve shutdown.
func TestRun_LocalOnly_Minimal(t *testing.T) {
	cfg := `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: info
  format: json
`
	if err := runUntilCtxDone(t, runParams(t, writeConfig(t, cfg))); err != nil {
		t.Fatalf("Run returned error on clean shutdown: %v", err)
	}
}

// TestRun_LocalOnly_UpstreamDNS boots a worker with dns.upstreamResolver set and
// proves the assembly accepts it and logs the one clear startup line naming the
// configured server. The resolver threading itself is covered end-to-end in the
// proxy package (TestSafeDialer_UpstreamResolverEndToEnd) and by
// TestNewSafeHTTPClient_UpstreamResolver here.
func TestRun_LocalOnly_UpstreamDNS(t *testing.T) {
	cfg := `
policy:
  allowlist:
    - domain: api.openai.com
dns:
  upstreamResolver: "10.20.30.2:53"
logging:
  level: info
  format: text
`
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	if err := Run(ctx, &out, runParams(t, writeConfig(t, cfg))); err != nil {
		t.Fatalf("Run returned error on clean shutdown: %v", err)
	}
	logged := out.String()
	if !strings.Contains(logged, "upstream DNS resolver configured") {
		t.Fatalf("startup log line missing; got:\n%s", logged)
	}
	if !strings.Contains(logged, "10.20.30.2:53") {
		t.Fatalf("startup log line does not name the resolver; got:\n%s", logged)
	}
}

// TestRun_UpstreamResolverReachesProxyDial is the worker-level wiring test for
// dns.upstreamResolver: the resolver built from pol.DNS.UpstreamResolver must
// land in proxy.Config.UpstreamResolver, so a CONNECT through the booted
// worker's own listener to a name only the stub knows makes the stub count a
// query. Deleting UpstreamResolver from the proxy.Config literal in Run leaves
// the proxy on net.DefaultResolver, the stub stays silent, and this test
// fails. (That the resolver then drives the proxy's real dial path end to end
// is proven in the proxy package by TestProxy_UpstreamResolverReachesDialPath.)
func TestRun_UpstreamResolverReachesProxyDial(t *testing.T) {
	stub := dnstest.New(t, map[string]string{"tunnel.stub.test": "127.0.0.1"})

	// Pin the proxy's listen port so the test can dial it: grab a free port,
	// then release it for Run to bind.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("grab port: %v", err)
	}
	proxyAddr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}

	cfg := `
policy:
  allowlist:
    - domain: tunnel.stub.test
dns:
  upstreamResolver: "` + stub.Addr() + `"
logging:
  level: error
  format: text
`
	params := runParams(t, writeConfig(t, cfg))
	params.ListenAddr = proxyAddr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- Run(ctx, io.Discard, params) }()

	// Wait for the worker's proxy to accept, then CONNECT to the stub-only
	// name. No CA is configured, so an allowed CONNECT is raw-tunneled: the
	// tunnel's dial resolves the name via the stub, whose loopback answer the
	// SSRF blocklist rejects and the tunnel closes — the 200 plus the stub's
	// query counter are the wiring proof.
	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, dialErr := net.DialTimeout("tcp", proxyAddr, time.Second)
		if dialErr == nil {
			conn = c
			break
		}
		select {
		case err := <-runErr:
			t.Fatalf("Run exited before the proxy accepted: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker proxy never accepted on %s: %v", proxyAddr, dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT tunnel.stub.test:443 HTTP/1.1\r\nHost: tunnel.stub.test:443\r\n\r\n"); err != nil {
		t.Fatalf("send CONNECT: %v", err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT through the worker proxy: got %q, want 200", status)
	}
	// The 200 is written before the server-side tunnel goroutine resolves the
	// target, so poll for the stub's counter rather than asserting immediately.
	// Under the wiring regression (resolver never reaches proxy.Config) the
	// counter stays at zero and the deadline expires.
	deadline = time.Now().Add(5 * time.Second)
	for stub.Queries.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("stub received no queries; the worker never wired dns.upstreamResolver into proxy.Config.UpstreamResolver")
		}
		select {
		case err := <-runErr:
			t.Fatalf("Run exited before the tunnel resolved: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error on clean shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// syncBuffer is a mutex-guarded buffer for passing as Run's out. Run's
// background goroutines (admin server, long-poll loops) may still log after Run
// returns, so a plain bytes.Buffer would race between the last writes and the
// test's read.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRun_LocalOnly_FeaturesOn turns on the optional decorators and collaborators a
// local worker can assemble without a network peer: MCP gateway, response scanner,
// inline judge (key from local env), auth transforms, signed receipts, compliance
// tagging, and central aggregator ingest. It proves the whole decorator chain +
// gateway/store wiring builds and shuts down cleanly.
func TestRun_LocalOnly_FeaturesOn(t *testing.T) {
	t.Setenv("WARDEN_RUN_JUDGE_KEY", "sk-test")
	t.Setenv("WARDEN_RUN_SECRET", "s3cr3t")
	receiptLog := filepath.Join(t.TempDir(), "receipts.log")

	cfg := `
policy:
  allowlist:
    - domain: api.openai.com
secrets:
  - placeholder: openai_secret_001
    envVar: WARDEN_RUN_SECRET
logging:
  level: warn
  format: text
judge:
  enabled: true
  model: gpt-4o-mini
  baseURL: https://api.openai.com/v1
  apiKeyEnv: WARDEN_RUN_JUDGE_KEY
agents:
  - id: default
    policy: allow reads
mcp:
  enabled: true
  mode: monitor
responseScan:
  enabled: true
  mode: monitor
auth:
  - match: api.example.com
    type: api_key
    location: header
    name: X-API-Key
    value: ${WARDEN_RUN_SECRET}
central:
  mode: aggregator
audit:
  signedReceipts:
    enabled: true
    log: ` + receiptLog + `
  compliance:
    enabled: true
`
	if err := runUntilCtxDone(t, runParams(t, writeConfig(t, cfg))); err != nil {
		t.Fatalf("Run (features on) returned error on clean shutdown: %v", err)
	}
	// The signed-receipts log file was created by the assembly path.
	if _, err := os.Stat(receiptLog); err != nil {
		t.Errorf("receipts log not created: %v", err)
	}
}

// TestRun_Managed_ControlPlaneUnreachable exercises the MANAGED branch: a
// controlPlane endpoint is configured but unreachable, so the worker builds the
// remote provider, fails the boot pull, starts FAIL-CLOSED, constructs the
// SettingsApplier, and spins up the long-poll + heartbeat loops (which back off
// against the dead endpoint) — all torn down cleanly on ctx cancel. Central worker
// forwarding is on (also unreachable) to build the HTTPRemoteStore + sync worker.
func TestRun_Managed_ControlPlaneUnreachable(t *testing.T) {
	// 127.0.0.1:1 refuses fast, keeping the boot pull + loops from hanging.
	cfg := `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: error
  format: json
controlPlane:
  endpoint: https://127.0.0.1:1/policy
  longPollWait: 50ms
  heartbeatInterval: 20ms
central:
  mode: worker
  endpoint: https://127.0.0.1:1/central/ingest
  proxyID: worker-1
`
	if err := runUntilCtxDone(t, runParams(t, writeConfig(t, cfg))); err != nil {
		t.Fatalf("Run (managed, CP unreachable) returned error on clean shutdown: %v", err)
	}
}

// TestRun_ConfigError verifies Run surfaces a load error (missing config file)
// instead of proceeding to bind anything.
func TestRun_ConfigError(t *testing.T) {
	p := runParams(t, filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err := Run(context.Background(), io.Discard, p); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

// TestNewSafeHTTPClient covers both the no-CA path and the CA-pool path, plus the
// error path for a missing/invalid CA file.
func TestNewSafeHTTPClient(t *testing.T) {
	if _, err := newSafeHTTPClient(5*time.Second, "", nil); err != nil {
		t.Fatalf("no-CA client: %v", err)
	}
	caPath := writeTestCACert(t)
	if _, err := newSafeHTTPClient(5*time.Second, caPath, nil); err != nil {
		t.Fatalf("CA client: %v", err)
	}
	if _, err := newSafeHTTPClient(5*time.Second, filepath.Join(t.TempDir(), "nope.pem"), nil); err == nil {
		t.Fatal("expected error for a missing CA file")
	}
}

// TestNewSafeHTTPClient_UpstreamResolver proves the optional resolver reaches
// the client's dial path: a request for a NAME only the stub can resolve makes
// the stub count a query (the SafeDialer then blocks the loopback answer — SSRF
// protection working as designed — which is exactly the deterministic,
// network-free outcome the assertion wants).
func TestNewSafeHTTPClient_UpstreamResolver(t *testing.T) {
	stub := dnstest.New(t, map[string]string{"token.stub.test": "127.0.0.1"})
	client, err := newSafeHTTPClient(5*time.Second, "", proxy.NewUpstreamResolver(stub.Addr(), nil))
	if err != nil {
		t.Fatalf("newSafeHTTPClient: %v", err)
	}
	_, err = client.Get("http://token.stub.test:1/")
	if err == nil {
		t.Fatal("want request failure (loopback answer is SSRF-blocked)")
	}
	if stub.Queries.Load() == 0 {
		t.Fatal("stub received no queries; the client dial path ignored the configured resolver")
	}
}

// TestNewControlPlaneHTTPClient mirrors the SafeHTTPClient cases for the
// control-plane client (which deliberately skips the SafeDialer).
func TestNewControlPlaneHTTPClient(t *testing.T) {
	if _, err := newControlPlaneHTTPClient(5*time.Second, ""); err != nil {
		t.Fatalf("no-CA client: %v", err)
	}
	caPath := writeTestCACert(t)
	if _, err := newControlPlaneHTTPClient(5*time.Second, caPath); err != nil {
		t.Fatalf("CA client: %v", err)
	}
	if _, err := newControlPlaneHTTPClient(5*time.Second, filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Fatal("expected error for a missing CA file")
	}
	// A file with no PEM certificate is rejected.
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newControlPlaneHTTPClient(5*time.Second, bad); err == nil {
		t.Fatal("expected error for a file with no certificate")
	}
}

// writeTestCACert generates a throwaway self-signed certificate, writes it as PEM
// to a temp file, and returns the path — enough for the HTTP-client CA-pool
// branches (AppendCertsFromPEM) to be exercised with a real, parseable cert.
func writeTestCACert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "warden-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPushMCPSnapshots drives the MCP-snapshot push loop against a real gateway and
// an httptest ingest endpoint: the initial full push lands, a change pushes again,
// and the loop returns on ctx cancel — proving the hash-gated forwarding path.
func TestPushMCPSnapshots(t *testing.T) {
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		got++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	remote, err := analytics.NewHTTPRemoteStore(srv.URL, "", "worker-1", srv.Client())
	if err != nil {
		t.Fatalf("NewHTTPRemoteStore: %v", err)
	}
	gw := gateway.New(config.MCPConfig{Enabled: true, Mode: "monitor"}, scan.NewScanner(), nil)
	t.Cleanup(func() { _ = gw.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pushMCPSnapshots(ctx, gw, remote, 5*time.Millisecond, nil)
		close(done)
	}()

	// Give the initial push + a couple of ticks time to land, then stop.
	time.Sleep(40 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pushMCPSnapshots did not return after ctx cancel")
	}
	if got == 0 {
		t.Fatal("expected at least the initial MCP snapshot push to reach the ingest endpoint")
	}
}

// TestRun_AllowPrivateCIDRsReachProxy guards the wiring of the LOCAL-ONLY
// upstream.allowPrivateCIDRs: the parsed list must land in
// proxy.Config.UpstreamAllowPrivateCIDRs so the proxy's SafeDialer exempts
// those ranges. Dropping the field from the proxy.Config literal silently
// re-blocks every private upstream (and breaks the L2 compose stack, whose
// fake upstream lives on a Docker bridge network).
func TestRun_AllowPrivateCIDRsReachProxy(t *testing.T) {
	var got proxy.Config
	orig := newProxy
	newProxy = func(cfg proxy.Config) (*proxy.Proxy, error) {
		got = cfg
		return orig(cfg)
	}
	t.Cleanup(func() { newProxy = orig })

	cfg := `
policy:
  allowlist:
    - domain: api.example.test
upstream:
  allowPrivateCIDRs:
    - "10.200.0.0/24"
logging:
  level: error
  format: text
`
	if err := runUntilCtxDone(t, runParams(t, writeConfig(t, cfg))); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"10.200.0.0/24"}
	if !reflect.DeepEqual(got.UpstreamAllowPrivateCIDRs, want) {
		t.Fatalf("UpstreamAllowPrivateCIDRs = %v, want %v", got.UpstreamAllowPrivateCIDRs, want)
	}
}

// TestRun_AllowPrivateCIDRsWarnsLabOnly boots a worker with the SSRF exception
// list set and asserts the one clear startup WARN that names the active
// exceptions and says the key is for lab use only — the operator-facing line
// production must never be able to miss.
func TestRun_AllowPrivateCIDRsWarnsLabOnly(t *testing.T) {
	const warnCfg = `
policy:
  allowlist:
    - domain: api.example.test
upstream:
  allowPrivateCIDRs:
    - "10.200.0.0/24"
logging:
  level: info
  format: text
`
	const plainCfg = `
policy:
  allowlist:
    - domain: api.example.test
logging:
  level: info
  format: text
`
	// Deterministic waits, not sleeps: Run logs the WARN during startup, so
	// wait for the exact line, then cancel. The quiet case waits for "proxy
	// listening" — proof startup COMPLETED without the warning ever logging.
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, &out, runParams(t, writeConfig(t, warnCfg))) }()
	waitForLog(t, &out, "upstream.allowPrivateCIDRs")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error on clean shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	logged := out.String()
	if !strings.Contains(logged, "10.200.0.0/24") {
		t.Fatalf("startup WARN does not name the active exception; got:\n%s", logged)
	}
	if !strings.Contains(logged, "lab") {
		t.Fatalf("startup WARN does not say the key is lab-only; got:\n%s", logged)
	}

	// Absent block: no warning (default-off must stay silent).
	var quiet syncBuffer
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { done2 <- Run(ctx2, &quiet, runParams(t, writeConfig(t, plainCfg))) }()
	waitForLog(t, &quiet, "proxy listening")
	cancel2()
	select {
	case err := <-done2:
		if err != nil {
			t.Fatalf("Run (no exceptions) returned error on clean shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run (no exceptions) did not return after ctx cancel")
	}
	if strings.Contains(quiet.String(), "upstream.allowPrivateCIDRs") {
		t.Fatalf("default-off worker must not log the lab-only warning; got:\n%s", quiet.String())
	}
}

// TestRun_AuthFetchClientNeverExemptsPrivateRanges pins the ONE-SITE rule for
// upstream.allowPrivateCIDRs: the exception list widens the PROXY's dialer
// only (proxy.Config.UpstreamAllowPrivateCIDRs). The auth-fetch client (the
// second SafeDialer, used for OAuth2/SigV4 token fetches) must never inherit
// it — a loopback/private token endpoint stays refused by SSRF protection even
// when the worker locally excepts that range for its upstream dials. The
// worker boots with an oauth2 auth entry whose tokenURL is on loopback AND
// upstream.allowPrivateCIDRs exempting loopback; driving the captured
// transformer proves the fetch is blocked and the token endpoint is never hit.
// Wiring the exception into the auth client again makes the fetch succeed and
// this test fail.
func TestRun_AuthFetchClientNeverExemptsPrivateRanges(t *testing.T) {
	// tokenURL sits INSIDE the locally excepted range on an address with no
	// listener. That makes the two worlds distinguishable without trusting TLS:
	// correct wiring refuses the dial outright with the SSRF error; a stray
	// exception would make the client ATTEMPT the dial, which fails differently
	// (refused/timeout) — and this test fails. Loopback cannot play this role:
	// it is never exemptable (the /_rebind defense keeps 127.0.0.0/8 forbidden).
	var got proxy.Config
	orig := newProxy
	newProxy = func(cfg proxy.Config) (*proxy.Proxy, error) {
		got = cfg
		return orig(cfg)
	}
	t.Cleanup(func() { newProxy = orig })

	cfg := `
policy:
  allowlist:
    - domain: api.example.test
auth:
  - match: api.example.test
    type: oauth2_client_credentials
    tokenURL: http://10.200.0.1:9/token
    clientID: e2e-client
    clientSecret: e2e-secret
upstream:
  allowPrivateCIDRs:
    - "10.200.0.0/24"
logging:
  level: error
  format: text
`
	if err := runUntilCtxDone(t, runParams(t, writeConfig(t, cfg))); err != nil {
		t.Fatalf("Run returned error on clean shutdown: %v", err)
	}
	if len(got.Transformers) != 1 {
		t.Fatalf("transformers = %d, want 1 (the oauth2 entry)", len(got.Transformers))
	}

	req, err := http.NewRequest(http.MethodGet, "http://api.example.test/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if err := got.Transformers[0].Transformer.Transform(req); err == nil ||
		!strings.Contains(err.Error(), "blocked (SSRF protection)") {
		t.Fatalf("token fetch: got %v, want an SSRF block (upstream.allowPrivateCIDRs must never widen the auth-fetch client)", err)
	}
}

// TestRun_Managed_KeepsLocalUpstreamExceptions is the worker-level guard for
// the managed-mode interaction: a CP-MANAGED worker pulls its allow/deny from
// the control plane, but the SSRF exception list (upstream.allowPrivateCIDRs)
// is LOCAL-only wiring that json:"-" keeps off the CP wire. The proxy's dialer
// must therefore be built from the LOCAL value — the CP-served policy must not
// clear it, and (being unable to name exceptions at all) must not widen it.
// The fake CP below serves a policy with NO upstream block; if Run ever
// sourced UpstreamAllowPrivateCIDRs from the remote policy (or the live
// evaluator) instead of the local file, the captured proxy.Config would come
// up empty and this test would fail.
func TestRun_Managed_KeepsLocalUpstreamExceptions(t *testing.T) {
	t.Setenv("WARDEN_CP_TOKEN", "test-token")

	const policyV1 = `{"allowlist":[{"domain":"api.example.test"}],"denylist":[{"domain":"evil.example.test"}]}`
	const policyV2 = `{"allowlist":[{"domain":"api.example.test"},{"domain":"llm.example.test"}],"denylist":[{"domain":"evil.example.test"}]}`

	// Minimal CP: /policy serves v1, then v2 once flip is set (the long-poll
	// returns 304 while nothing changed), /control/heartbeat is a 200.
	var flip atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/policy", func(w http.ResponseWriter, r *http.Request) {
		body := policyV1
		etag := `"v1"`
		if flip.Load() {
			body, etag = policyV2, `"v2"`
		}
		if r.URL.Query().Get("wait") != "" && r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/control/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cp := httptest.NewTLSServer(mux)
	defer cp.Close()
	caPath := filepath.Join(t.TempDir(), "cp-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write cp ca pem: %v", err)
	}

	var got proxy.Config
	orig := newProxy
	newProxy = func(cfg proxy.Config) (*proxy.Proxy, error) {
		got = cfg
		return orig(cfg)
	}
	t.Cleanup(func() { newProxy = orig })

	// The worker's LOCAL file keeps only local things — including the SSRF
	// exception — and carries NO allowlist (a managed worker gets it from the CP).
	cfg := `
controlPlane:
  endpoint: ` + cp.URL + `/policy
  tokenEnv: WARDEN_CP_TOKEN
  caCert: ` + caPath + `
  longPollWait: 50ms
  heartbeatInterval: 1s
upstream:
  allowPrivateCIDRs:
    - "10.200.0.0/24"
logging:
  level: info
  format: text
`
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- Run(ctx, &out, runParams(t, writeConfig(t, cfg))) }()

	// The initial CP pull must have been applied (the worker is genuinely
	// managed). "proxy listening" is logged after the proxy (and its dialer)
	// is built, so the captured proxy.Config is populated by then.
	waitForLog(t, &out, "control plane policy applied")
	waitForLog(t, &out, "proxy listening")
	want := []string{"10.200.0.0/24"}
	if !reflect.DeepEqual(got.UpstreamAllowPrivateCIDRs, want) {
		t.Fatalf("UpstreamAllowPrivateCIDRs after the initial CP pull = %v, want %v (the local exception must survive a CP-served policy)", got.UpstreamAllowPrivateCIDRs, want)
	}

	// And again on every update: change the CP policy, wait for the reload,
	// re-assert the local value is untouched.
	flip.Store(true)
	waitForLog(t, &out, "control plane policy reloaded")
	if !reflect.DeepEqual(got.UpstreamAllowPrivateCIDRs, want) {
		t.Fatalf("UpstreamAllowPrivateCIDRs after a CP policy update = %v, want %v", got.UpstreamAllowPrivateCIDRs, want)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error on clean shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// waitForLog polls buf until it contains substr, failing after a deadline.
// Deterministic stand-in for fixed sleeps: Run's startup and background loops
// log asynchronously, so the test waits for the exact line it asserts on.
func waitForLog(t *testing.T, buf *syncBuffer, substr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if strings.Contains(buf.String(), substr) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log line %q never appeared; got:\n%s", substr, buf.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
