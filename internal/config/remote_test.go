package config

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteProvider_SuccessfulPull(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowlist": [{"domain": "api.example.com"}]}`))
	}))
	defer srv.Close()

	rp, err := NewRemoteProvider(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewRemoteProvider: %v", err)
	}
	rp.client = srv.Client()
	if err := rp.Pull(); err != nil {
		t.Fatalf("Pull: %v", err)
	}

	pol, err := rp.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(pol.Allowlist) != 1 {
		t.Fatalf("allowlist len = %d, want 1", len(pol.Allowlist))
	}
	if pol.Allowlist[0].Domain != "api.example.com" {
		t.Errorf("domain = %q, want %q", pol.Allowlist[0].Domain, "api.example.com")
	}
	if pol.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", pol.LogLevel, "info")
	}
	if pol.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want %q", pol.LogFormat, "json")
	}
	if pol.CacheTTLSeconds != defaultCacheTTLSeconds {
		t.Errorf("CacheTTLSeconds = %d, want %d", pol.CacheTTLSeconds, defaultCacheTTLSeconds)
	}
}

func TestRemoteProvider_Unreachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowlist": [{"domain": "api.example.com"}]}`))
	}))

	rp, err := NewRemoteProvider(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewRemoteProvider: %v", err)
	}
	rp.client = srv.Client()
	if err := rp.Pull(); err != nil {
		t.Fatalf("first Pull: %v", err)
	}

	// Shut down the server.
	srv.Close()

	// Second pull should fail.
	if err := rp.Pull(); err == nil {
		t.Fatal("expected error from Pull after server shutdown")
	}

	// Last known good policy should still be available.
	pol, err := rp.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy after failed pull: %v", err)
	}
	if len(pol.Allowlist) != 1 || pol.Allowlist[0].Domain != "api.example.com" {
		t.Errorf("policy was not preserved: %+v", pol.Allowlist)
	}
}

func TestRemoteProvider_InvalidJSON(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer srv.Close()

	rp, err := NewRemoteProvider(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewRemoteProvider: %v", err)
	}
	rp.client = srv.Client()
	if err := rp.Pull(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	// No prior good policy, so GetPolicy should error.
	if _, err := rp.GetPolicy(); err == nil {
		t.Fatal("expected error from GetPolicy with no prior good policy")
	}
}

func TestRemoteProvider_AuthToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowlist": [{"domain": "api.example.com"}]}`))
	}))
	defer srv.Close()

	rp, err := NewRemoteProvider(srv.URL, "my-secret-token")
	if err != nil {
		t.Fatalf("NewRemoteProvider: %v", err)
	}
	rp.client = srv.Client()
	if err := rp.Pull(); err != nil {
		t.Fatalf("Pull: %v", err)
	}

	want := "Bearer my-secret-token"
	if gotAuth != want {
		t.Errorf("Authorization header = %q, want %q", gotAuth, want)
	}
}

func TestRemoteProvider_PollingUpdates(t *testing.T) {
	var reqCount atomic.Int64
	var mu sync.Mutex
	response := `{"allowlist": [{"domain": "first.example.com"}]}`

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		mu.Lock()
		resp := response
		mu.Unlock()
		// After 2 requests, switch to the new response.
		if n >= 3 {
			mu.Lock()
			response = `{"allowlist": [{"domain": "second.example.com"}]}`
			mu.Unlock()
			resp = `{"allowlist": [{"domain": "second.example.com"}]}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(resp))
	}))
	defer srv.Close()

	rp, err := NewRemoteProvider(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewRemoteProvider: %v", err)
	}
	rp.client = srv.Client()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rp.StartPolling(ctx, 50*time.Millisecond)

	// Wait for the updated policy to appear.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for policy update")
		default:
		}

		pol, err := rp.GetPolicy()
		if err == nil && len(pol.Allowlist) > 0 && pol.Allowlist[0].Domain == "second.example.com" {
			return // success
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestRemoteProviderSendsProxyIDWithCACert verifies SetProxyID adds the
// X-Warden-Proxy-ID header on a pull, and SetCACert lets the worker trust a
// privately-signed control plane (an httptest TLS server here).
func TestRemoteProviderSendsProxyIDWithCACert(t *testing.T) {
	var gotProxyID string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProxyID = r.Header.Get("X-Warden-Proxy-ID")
		_, _ = w.Write([]byte(`{"allowlist":[{"domain":"a.com"}]}`))
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	rp, err := NewRemoteProvider(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.SetCACert(caPath); err != nil {
		t.Fatalf("SetCACert: %v", err)
	}
	rp.SetProxyID("worker-9")
	if err := rp.Pull(); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if gotProxyID != "worker-9" {
		t.Fatalf("proxy id header = %q, want worker-9", gotProxyID)
	}
}

// TestPollLongAndHeartbeat exercises the long-poll (200-with-ETag then 304) and
// the heartbeat (derived /control/heartbeat URL carrying proxy id + ETag).
func TestPollLongAndHeartbeat(t *testing.T) {
	var hbProxy, hbETag, lastWait string
	mux := http.NewServeMux()
	mux.HandleFunc("/policy", func(w http.ResponseWriter, r *http.Request) {
		lastWait = r.URL.Query().Get("wait")
		if strings.Trim(r.Header.Get("If-None-Match"), `"`) == "v1" {
			w.Header().Set("ETag", `"v1"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowlist":[{"domain":"a.com"}]}`))
	})
	mux.HandleFunc("/control/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		hbProxy = r.Header.Get("X-Warden-Proxy-ID")
		var b struct {
			PolicyETag string `json:"policyETag"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		hbETag = b.PolicyETag
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	rp, err := NewRemoteProvider(srv.URL+"/policy", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.SetCACert(caPath); err != nil {
		t.Fatal(err)
	}
	rp.SetProxyID("worker-1")

	// First long-poll: changed, policy + ETag stored, wait param sent.
	changed, err := rp.PollLong(context.Background(), 2*time.Second)
	if err != nil || !changed {
		t.Fatalf("first poll: changed=%v err=%v", changed, err)
	}
	if lastWait != "2s" {
		t.Errorf("wait param = %q, want 2s", lastWait)
	}
	p, _ := rp.GetPolicy()
	if len(p.Allowlist) != 1 || p.Allowlist[0].Domain != "a.com" {
		t.Fatalf("policy not stored: %+v", p.Allowlist)
	}

	// Second long-poll: ETag matches -> 304 -> not changed.
	changed, err = rp.PollLong(context.Background(), 2*time.Second)
	if err != nil || changed {
		t.Fatalf("second poll: changed=%v err=%v", changed, err)
	}

	// Heartbeat carries proxy id + current ETag to the derived endpoint.
	if err := rp.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hbProxy != "worker-1" || hbETag != "v1" {
		t.Fatalf("heartbeat proxy=%q etag=%q, want worker-1/v1", hbProxy, hbETag)
	}
}

// TestRemoteProvider_DecodesSettings verifies the worker decodes the optional
// "settings" block from /policy, stores it, and Settings() returns it with the
// judge's env-NAME reference round-tripped. A response with no "settings" key
// leaves Settings() nil (back-compat).
func TestRemoteProvider_DecodesSettings(t *testing.T) {
	body := `{
		"allowlist": [{"domain": "api.example.com"}],
		"settings": {
			"mcp": {"enabled": true, "mode": "enforce"},
			"judge": {"enabled": true, "model": "gpt-4o", "apiKeyEnv": "OPENAI_API_KEY"},
			"logging": {"level": "debug", "format": "text"}
		}
	}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	rp, err := NewRemoteProvider(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewRemoteProvider: %v", err)
	}
	rp.client = srv.Client()
	if err := rp.Pull(); err != nil {
		t.Fatalf("Pull: %v", err)
	}

	s := rp.Settings()
	if s == nil {
		t.Fatal("Settings() returned nil after a pull carrying settings")
	}
	if s.MCP == nil || !s.MCP.Enabled || s.MCP.Mode != "enforce" {
		t.Errorf("mcp settings not decoded: %+v", s.MCP)
	}
	if s.Judge == nil || s.Judge.APIKeyEnv != "OPENAI_API_KEY" || s.Judge.Model != "gpt-4o" {
		t.Errorf("judge env-name ref not decoded: %+v", s.Judge)
	}
	if s.Logging == nil || s.Logging.Level != "debug" {
		t.Errorf("logging settings not decoded: %+v", s.Logging)
	}

	// Mutating the returned copy must not affect the stored settings.
	s.MCP.Mode = "mutated"
	if again := rp.Settings(); again.MCP.Mode != "enforce" {
		t.Fatal("Settings() did not return an independent deep copy")
	}
}

// TestRemoteProvider_NoSettings_BackCompat verifies a CP response with only
// allow/deny (no "settings" key) still parses and leaves Settings() nil.
func TestRemoteProvider_NoSettings_BackCompat(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"allowlist": [{"domain": "api.example.com"}]}`))
	}))
	defer srv.Close()

	rp, err := NewRemoteProvider(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewRemoteProvider: %v", err)
	}
	rp.client = srv.Client()
	if err := rp.Pull(); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if s := rp.Settings(); s != nil {
		t.Fatalf("Settings() = %+v, want nil for allow/deny-only response", s)
	}
	// Policy still works.
	pol, err := rp.GetPolicy()
	if err != nil || len(pol.Allowlist) != 1 {
		t.Fatalf("policy not parsed without settings: pol=%+v err=%v", pol, err)
	}
}

func TestRemoteProvider_RejectsHTTP(t *testing.T) {
	_, err := NewRemoteProvider("http://example.com/policy", "token")
	if err == nil {
		t.Fatal("expected error for HTTP endpoint")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS, got: %v", err)
	}
}
