package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
)

// startAndProbe exercises the full Run lifecycle the L1 harness (parent #350)
// relies on: it boots a real control plane in-process, waits for OnReady, GETs
// /healthz on the bound address (want 200), cancels the context, and requires
// Run to return nil. It returns the bound address OnReady reported. probeClient
// issues the /healthz request (pass a CA-trusting client for the TLS path).
func startAndProbe(t *testing.T, p Params, probeClient *http.Client) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	ready := make(chan string, 1)
	p.OnReady = func(addr string) { ready <- addr }
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, &bytes.Buffer{}, p) }()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("Run returned before OnReady: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}

	scheme := "http"
	if p.CACert != "" && p.CAKey != "" {
		scheme = "https"
	}
	resp, err := probeClient.Get(scheme + "://" + addr + "/healthz")
	if err != nil {
		cancel()
		t.Fatalf("GET %s://%s/healthz: %v", scheme, addr, err)
	}
	status := resp.StatusCode
	_ = resp.Body.Close()
	if status != http.StatusOK {
		cancel()
		t.Fatalf("GET /healthz status = %d, want 200", status)
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
	return addr
}

// TestRunServesHealthzOnInjectedListener proves the harness seam: Run serves
// the real control plane on a caller-supplied loopback listener on port 0 —
// no fixed address, no --listen flag — and reports the bound address.
func TestRunServesHealthzOnInjectedListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	addr := startAndProbe(t, Params{
		ConfigPath:        writePolicyFile(t, "api.openai.com"),
		StateDir:          filepath.Join(t.TempDir(), "state"),
		AnalyticsProvider: "memory",
		Listener:          ln,
	}, http.DefaultClient)
	if addr != ln.Addr().String() {
		t.Errorf("OnReady addr = %q, want the injected listener's %q", addr, ln.Addr().String())
	}
}

// TestRunServesHealthzFromListenAddr covers the flag path: with no injected
// listener Run binds ListenAddr itself (port 0 included) and reports the
// resolved address, not the placeholder.
func TestRunServesHealthzFromListenAddr(t *testing.T) {
	addr := startAndProbe(t, Params{
		ConfigPath:        writePolicyFile(t, "api.openai.com"),
		StateDir:          filepath.Join(t.TempDir(), "state"),
		AnalyticsProvider: "memory",
		ListenAddr:        "127.0.0.1:0",
	}, http.DefaultClient)
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" || port == "0" {
		t.Errorf("OnReady addr = %q, want a resolved 127.0.0.1:<port>", addr)
	}
}

// TestRunAcceptsInjectedClock proves the CP's time port: Run boots normally
// with a fake Clock in Params. Its one consumer so far, the console
// query/generate rate limit, is tested with the fake in TestAuthzQueryGenerateEditor
// (the detection engine migrates in its own phase, rule L3 in #349), so the
// assertion here is the boot itself — nil keeps clock.Real(), the production
// default exercised by every other test here.
func TestRunAcceptsInjectedClock(t *testing.T) {
	startAndProbe(t, Params{
		ConfigPath:        writePolicyFile(t, "api.openai.com"),
		StateDir:          filepath.Join(t.TempDir(), "state"),
		AnalyticsProvider: "memory",
		ListenAddr:        "127.0.0.1:0",
		Clock:             clocktest.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
	}, http.DefaultClient)
}

// TestRunClosesInjectedListenerOnBootError proves a failed boot never leaks the
// harness's port: every early-error return in Run closes an injected listener,
// because httpSrv.Shutdown only closes listeners Serve has registered — one
// that never got there would stay bound forever. Each case fails before the
// serve goroutine starts, at a different return site.
func TestRunClosesInjectedListenerOnBootError(t *testing.T) {
	caCertPath, _, _ := genTestCA(t) // key deliberately withheld for the mismatch case
	tests := []struct {
		name string
		boot func(t *testing.T) Params
	}{
		{"missing config file", func(t *testing.T) Params {
			return Params{ConfigPath: filepath.Join(t.TempDir(), "missing.yaml")}
		}},
		{"state-dir seed unreadable", func(t *testing.T) Params {
			return Params{
				ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"),
				StateDir:   filepath.Join(t.TempDir(), "state"),
			}
		}},
		{"ca-cert without ca-key", func(t *testing.T) Params {
			return Params{ConfigPath: writePolicyFile(t, "api.openai.com"), CACert: caCertPath}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			// Bound the Accept below so a leaked listener fails the test rather
			// than hanging it; a Close always beats a pending Accept deadline.
			if tcp, ok := ln.(*net.TCPListener); ok {
				_ = tcp.SetDeadline(time.Now().Add(10 * time.Second))
			}

			p := tt.boot(t)
			p.AnalyticsProvider = "memory"
			p.Listener = ln
			if err := Run(context.Background(), &bytes.Buffer{}, p); err == nil {
				t.Fatal("Run = nil error, want a boot error")
			}
			if _, aerr := ln.Accept(); !errors.Is(aerr, net.ErrClosed) {
				t.Errorf("Accept after failed boot = %v, want net.ErrClosed (injected listener leaked)", aerr)
			}
		})
	}
}

// TestRunServesTLSHealthzOnInjectedListener covers the ServeTLS branch: with a
// CA configured, Run mints its server cert from it and serves HTTPS, so a
// client trusting that CA can pull /healthz on the injected listener.
func TestRunServesTLSHealthzOnInjectedListener(t *testing.T) {
	caCertPath, caKeyPath, caCert := genTestCA(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	startAndProbe(t, Params{
		ConfigPath:        writePolicyFile(t, "api.openai.com"),
		StateDir:          filepath.Join(t.TempDir(), "state"),
		AnalyticsProvider: "memory",
		CACert:            caCertPath,
		CAKey:             caKeyPath,
		TLSHost:           "127.0.0.1",
		Listener:          ln,
	}, client)
}

// TestToInstanceConfigs verifies the CP-local integration config maps onto the
// integration package's InstanceConfig, carrying match clauses through untouched.
func TestToInstanceConfigs(t *testing.T) {
	if got := toInstanceConfigs(nil); got != nil {
		t.Errorf("nil input should map to nil, got %v", got)
	}
	insts := []config.IntegrationInstance{{
		Type:   "webhook",
		Name:   "alerts",
		Config: map[string]any{"url": "https://hooks.example/x"},
		Match:  []config.IntegrationMatch{{Severity: "high", Category: "leak", Domain: "api.x.com", Rule: "r1"}},
	}}
	got := toInstanceConfigs(insts)
	if len(got) != 1 {
		t.Fatalf("got %d instance configs, want 1", len(got))
	}
	ic := got[0]
	if ic.Type != "webhook" || ic.Name != "alerts" {
		t.Errorf("type/name not carried: %+v", ic)
	}
	if len(ic.Match) != 1 || ic.Match[0].Severity != "high" || ic.Match[0].Domain != "api.x.com" {
		t.Errorf("match clause not carried: %+v", ic.Match)
	}
	if ic.Config["url"] != "https://hooks.example/x" {
		t.Errorf("opaque config not passed through: %+v", ic.Config)
	}
}

func TestSeedServedConfig(t *testing.T) {
	t.Run("seeds when absent", func(t *testing.T) {
		dir := t.TempDir()
		seed := filepath.Join(dir, "seed.yaml")
		if err := os.WriteFile(seed, []byte("policy: {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		served := filepath.Join(dir, "state", "config.yaml")

		seeded, err := seedServedConfig(served, seed)
		if err != nil {
			t.Fatalf("seedServedConfig: %v", err)
		}
		if !seeded {
			t.Fatal("expected seeded=true on first call")
		}
		got, err := os.ReadFile(served)
		if err != nil {
			t.Fatalf("read served: %v", err)
		}
		if string(got) != "policy: {}\n" {
			t.Fatalf("served content = %q, want seed copy", string(got))
		}
	})

	t.Run("reuses when present and preserves edits", func(t *testing.T) {
		dir := t.TempDir()
		seed := filepath.Join(dir, "seed.yaml")
		if err := os.WriteFile(seed, []byte("seed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		served := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(served, []byte("edited\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		seeded, err := seedServedConfig(served, seed)
		if err != nil {
			t.Fatalf("seedServedConfig: %v", err)
		}
		if seeded {
			t.Fatal("expected seeded=false when served already exists")
		}
		got, _ := os.ReadFile(served)
		if string(got) != "edited\n" {
			t.Fatalf("served content = %q, want the existing edit preserved", string(got))
		}
	})

	t.Run("errors when seed missing", func(t *testing.T) {
		dir := t.TempDir()
		served := filepath.Join(dir, "config.yaml")
		if _, err := seedServedConfig(served, filepath.Join(dir, "nope.yaml")); err == nil {
			t.Fatal("expected error when seed file is missing")
		}
	})
}

func TestDirWritable(t *testing.T) {
	if !dirWritable(t.TempDir()) {
		t.Fatal("expected a fresh temp dir to be writable")
	}
	// A path under a non-existent directory cannot be written to.
	if dirWritable(filepath.Join(t.TempDir(), "does-not-exist")) {
		t.Fatal("expected a non-existent directory to be non-writable")
	}
}

// TestRunCreatesStateDB: with --state-dir, Run opens <state-dir>/warden-cp.db
// (mode 0600) before serving, closes it on shutdown, and does not create it
// without a state dir.
func TestRunCreatesStateDB(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	startAndProbe(t, Params{
		ConfigPath:        writePolicyFile(t, "api.openai.com"),
		StateDir:          stateDir,
		AnalyticsProvider: "memory",
		ListenAddr:        "127.0.0.1:0",
	}, http.DefaultClient)

	fi, err := os.Stat(filepath.Join(stateDir, "warden-cp.db"))
	if err != nil {
		t.Fatalf("warden-cp.db not created: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("warden-cp.db mode = %o, want 600", perm)
	}
}

// TestRunLogsStateDB: the startup line carries the db path and applied
// migration IDs, and nothing else about the contents.
func TestRunLogsStateDB(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	var out syncBuffer
	go func() {
		errCh <- Run(ctx, &out, Params{
			ConfigPath:        writePolicyFile(t, "api.openai.com"),
			StateDir:          stateDir,
			AnalyticsProvider: "memory",
			ListenAddr:        "127.0.0.1:0",
			OnReady:           func(a string) { ready <- a },
		})
	}()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("Run returned early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run = %v", err)
	}
	log := out.String()
	for _, want := range []string{"control plane state db", filepath.Join(stateDir, "warden-cp.db"), `"applied"`} {
		if !strings.Contains(log, want) {
			t.Errorf("startup log missing %q:\n%s", want, log)
		}
	}
}

// TestRunCorruptStateDB: a warden-cp.db of random bytes stops startup with an
// error naming the path, and closes an injected listener.
func TestRunCorruptStateDB(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbFile := filepath.Join(stateDir, "warden-cp.db")
	garbage := make([]byte, 4096)
	if _, err := rand.Read(garbage); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbFile, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tcp, ok := ln.(*net.TCPListener); ok {
		_ = tcp.SetDeadline(time.Now().Add(10 * time.Second))
	}

	err = Run(context.Background(), &bytes.Buffer{}, Params{
		ConfigPath:        writePolicyFile(t, "api.openai.com"),
		StateDir:          stateDir,
		AnalyticsProvider: "memory",
		Listener:          ln,
	})
	if err == nil || !strings.Contains(err.Error(), dbFile) {
		t.Fatalf("Run err = %v, want one naming %s", err, dbFile)
	}
	if _, aerr := ln.Accept(); !errors.Is(aerr, net.ErrClosed) {
		t.Errorf("Accept after failed boot = %v, want net.ErrClosed", aerr)
	}
	after, _ := os.ReadFile(dbFile)
	if !bytes.Equal(after, garbage) {
		t.Error("corrupt state db was modified")
	}
}

// TestRunNoStateDirNoStateDB: without --state-dir no warden-cp.db appears.
func TestRunNoStateDirNoStateDB(t *testing.T) {
	startAndProbe(t, Params{
		ConfigPath:        writePolicyFile(t, "api.openai.com"),
		AnalyticsProvider: "memory",
		ListenAddr:        "127.0.0.1:0",
	}, http.DefaultClient)
	if _, err := os.Stat("warden-cp.db"); err == nil {
		t.Error("warden-cp.db created in the working directory without --state-dir")
	}
}

// syncBuffer is a bytes.Buffer safe for the log writer goroutine and the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
