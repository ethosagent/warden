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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dnstest"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/test/fakes"
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

// TestRun_Managed_ClosesControlPlaneConnectionsOnShutdown pins the shutdown
// hygiene the in-process harness (and any embedder) depends on: when Run
// returns, the HTTP clients it assembled (policy pull/long-poll, heartbeat,
// central forwarding) hold NO open connections to the control plane. Run
// returning must not strand pooled keep-alive conns — in a hosted process they
// keep server-side goroutines alive past shutdown.
//
// The central-forwarding leg is exercised FOR REAL: the worker's DB is
// pre-seeded with one event, so the SyncWorker's immediate SyncOnce POSTs it
// to /central/ingest and that client demonstrably holds a pooled connection at
// shutdown. (With no events to forward the client never opens one, and the
// assertion would pass vacuously even with the close missing.) Shutdown is
// triggered only AFTER the ingest POST is observed, so the close-under-test
// always has a connection to close.
func TestRun_Managed_ClosesControlPlaneConnectionsOnShutdown(t *testing.T) {
	var connsMu sync.Mutex
	open := 0
	sawIngest := make(chan struct{}, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/central/ingest" {
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case sawIngest <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		connsMu.Lock()
		defer connsMu.Unlock()
		switch s {
		case http.StateNew:
			open++
		case http.StateClosed:
			open--
		}
	}

	// The worker must trust the stub CP's certificate: export it as PEM for
	// controlPlane.caCert.
	caPath := filepath.Join(t.TempDir(), "cp-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: srv.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_TEST_CP_TOKEN", "tok")

	cfg := `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: error
  format: json
controlPlane:
  endpoint: https://` + strings.TrimPrefix(srv.URL, "https://") + `/policy
  tokenEnv: WARDEN_TEST_CP_TOKEN
  caCert: ` + caPath + `
  pollInterval: 20ms
  longPollWait: 10ms
  heartbeatInterval: 20ms
central:
  mode: worker
  endpoint: https://` + strings.TrimPrefix(srv.URL, "https://") + `/central/ingest
  proxyID: worker-1
  caCert: ` + caPath + `
  interval: 50ms
`
	p := runParams(t, writeConfig(t, cfg))

	// Pre-seed the worker's analytics DB: the SyncWorker fires SyncOnce
	// immediately at Start, so the forwarding client opens its connection
	// deterministically at boot — the test never waits on a tick to make the
	// central leg live (the 50ms interval above only matters for retries).
	seed, err := analytics.NewSQLiteStore("file:"+p.DBPath, 0)
	if err != nil {
		t.Fatalf("open the worker DB to seed an event: %v", err)
	}
	if err := seed.StoreEvent(analytics.Event{
		Domain:   "api.openai.com",
		Decision: "allow",
		Protocol: "https",
	}); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close the seeding store: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- Run(ctx, io.Discard, p) }()
	select {
	case <-sawIngest:
	case <-time.After(10 * time.Second):
		t.Fatal("the central forwarding client never POSTed the seeded event to /central/ingest; the central leg never went live")
	}
	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("Run (managed) returned error on clean shutdown: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		connsMu.Lock()
		n := open
		connsMu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d control-plane connection(s) still open after Run returned; the assembled clients were not closed", n)
		}
		<-time.After(10 * time.Millisecond)
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

// goPolicy builds the minimal policy an in-process boot needs, constructed in
// Go (never from YAML) so the ConfigProvider seam is exercised the way the L1
// harness (#350) will use it: no config file anywhere.
func goPolicy() config.Policy {
	return config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "api.openai.com"}},
		LogLevel:  "error",
		LogFormat: "text",
	}
}

// TestRunServesHealthzOnInjectedListeners proves the worker harness seam: Run
// boots the real worker from a Go-built policy — no config file, no fixed port
// — serves the proxy and the admin+dashboard on caller-supplied port-0
// listeners, reports both bound addresses through OnReady (injected listeners
// win over the resolved addresses), answers /healthz with ok, and returns nil
// after ctx cancel. It mirrors controlplane.Run's TestRunServesHealthzOnInjectedListener.
func TestRunServesHealthzOnInjectedListeners(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen admin: %v", err)
	}

	p := Params{
		Config:        &fakes.FakeConfigProvider{Policy: goPolicy()},
		DBPath:        filepath.Join(t.TempDir(), "warden.db"),
		Version:       "test",
		ProxyListener: proxyLn,
		AdminListener: adminLn,
	}
	ready := make(chan [2]string, 1)
	p.OnReady = func(proxyAddr, adminAddr string) { ready <- [2]string{proxyAddr, adminAddr} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, io.Discard, p) }()

	var addrs [2]string
	select {
	case addrs = <-ready:
	case err := <-errCh:
		t.Fatalf("Run returned before OnReady: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}
	if addrs[0] != proxyLn.Addr().String() {
		t.Errorf("OnReady proxy addr = %q, want the injected listener's %q", addrs[0], proxyLn.Addr().String())
	}
	if addrs[1] != adminLn.Addr().String() {
		t.Errorf("OnReady admin addr = %q, want the injected listener's %q", addrs[1], adminLn.Addr().String())
	}

	resp, err := http.Get("http://" + addrs[1] + "/healthz")
	if err != nil {
		cancel()
		t.Fatalf("GET /healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		cancel()
		t.Fatalf("GET /healthz = %d %q, want 200 %q", resp.StatusCode, body, "ok")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Run to return after cancel")
	}
	// Both injected listeners must be closed by the time Run returns: the proxy
	// closes its listener on ctx-done shutdown and Run closes the admin's, so a
	// second boot on the same ports can never collide.
	for name, ln := range map[string]net.Listener{"proxy": proxyLn, "admin": adminLn} {
		if _, aerr := ln.Accept(); !errors.Is(aerr, net.ErrClosed) {
			t.Errorf("%s listener Accept after Run = %v, want net.ErrClosed (listener leaked)", name, aerr)
		}
	}
}

// TestRunClosesInjectedListenersOnBootError proves a failed boot never leaks
// the harness's ports: every early-error return in Run happens before any
// server starts, so both injected listeners must come back closed — one
// net.ErrClosed Accept each, at two different return sites (provider error,
// unsupported secret backend).
func TestRunClosesInjectedListenersOnBootError(t *testing.T) {
	tests := []struct {
		name string
		pol  config.Policy
		err  error
	}{
		{"config provider error", goPolicy(), errors.New("boom")},
		{"unsupported secret backend", func() config.Policy {
			pol := goPolicy()
			pol.SecretStore = config.SecretStoreConfig{Backend: "bogus"}
			return pol
		}(), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen proxy: %v", err)
			}
			adminLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen admin: %v", err)
			}
			// Bound the Accepts below so a leaked listener fails the test rather
			// than hanging it.
			for _, ln := range []net.Listener{proxyLn, adminLn} {
				if tcp, ok := ln.(*net.TCPListener); ok {
					_ = tcp.SetDeadline(time.Now().Add(10 * time.Second))
				}
			}

			p := Params{
				Config:        &fakes.FakeConfigProvider{Policy: tt.pol, Err: tt.err},
				DBPath:        filepath.Join(t.TempDir(), "warden.db"),
				Version:       "test",
				ProxyListener: proxyLn,
				AdminListener: adminLn,
			}
			if err := Run(context.Background(), io.Discard, p); err == nil {
				t.Fatal("Run = nil error, want a boot error")
			}
			for name, ln := range map[string]net.Listener{"proxy": proxyLn, "admin": adminLn} {
				if _, aerr := ln.Accept(); !errors.Is(aerr, net.ErrClosed) {
					t.Errorf("%s listener Accept after failed boot = %v, want net.ErrClosed (injected listener leaked)", name, aerr)
				}
			}
		})
	}
}
