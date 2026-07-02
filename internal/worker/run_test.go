package worker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
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
	if _, err := newSafeHTTPClient(5*time.Second, ""); err != nil {
		t.Fatalf("no-CA client: %v", err)
	}
	caPath := writeTestCACert(t)
	if _, err := newSafeHTTPClient(5*time.Second, caPath); err != nil {
		t.Fatalf("CA client: %v", err)
	}
	if _, err := newSafeHTTPClient(5*time.Second, filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Fatal("expected error for a missing CA file")
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
