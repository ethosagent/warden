package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteProvider_SuccessfulPull(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"allowlist": [{"domain": "api.example.com"}]}`))
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
		w.Write([]byte(`{"allowlist": [{"domain": "api.example.com"}]}`))
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
		w.Write([]byte(`not json at all`))
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
		w.Write([]byte(`{"allowlist": [{"domain": "api.example.com"}]}`))
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
		w.Write([]byte(resp))
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

func TestRemoteProvider_RejectsHTTP(t *testing.T) {
	_, err := NewRemoteProvider("http://example.com/policy", "token")
	if err == nil {
		t.Fatal("expected error for HTTP endpoint")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS, got: %v", err)
	}
}
