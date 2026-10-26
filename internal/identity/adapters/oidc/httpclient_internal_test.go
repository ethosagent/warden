package oidc

import (
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, internal string, timeout time.Duration) *http.Client {
	t.Helper()
	issuer := "http://localhost:5556/dex"
	if internal == "" {
		issuer = "https://idp.example.com"
	}
	c, err := newHTTPClient(HTTPClientConfig{Issuer: issuer, InternalIssuerURL: internal}, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHTTPClientLimits(t *testing.T) {
	t.Run("static", func(t *testing.T) {
		c := testClient(t, "http://dex:5556", clientTimeout)
		if c.Timeout != 5*time.Second {
			t.Fatalf("timeout %v", c.Timeout)
		}
		base := c.Transport.(capBody).next.(rewriteTransport).next.(*http.Transport)
		if base.Proxy != nil {
			t.Fatal("Proxy must be nil")
		}
		if base.TLSClientConfig.MinVersion < 0x0303 {
			t.Fatal("TLS 1.2 minimum")
		}
		if base.DialContext == nil {
			t.Fatal("plain net.Dialer required")
		}
	})
	t.Run("ca file", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()
		dir := t.TempDir()
		caPath := filepath.Join(dir, "ca.pem")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := HTTPClientConfig{Issuer: "https://idp.example.com", InternalIssuerURL: srv.URL}
		c, err := newHTTPClient(cfg, clientTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := c.Get("https://idp.example.com/x"); err == nil {
			resp.Body.Close()
			t.Fatal("untrusted CA must fail without CAFile")
		}
		cfg.CAFile = caPath
		c, err = newHTTPClient(cfg, clientTimeout)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Get("https://idp.example.com/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("ca file garbage", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(p, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := newHTTPClient(HTTPClientConfig{Issuer: "https://idp.example.com", CAFile: p}, clientTimeout)
		if err == nil || !strings.Contains(err.Error(), "no certificates found in ca file") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("ca file missing", func(t *testing.T) {
		_, err := newHTTPClient(HTTPClientConfig{Issuer: "https://idp.example.com", CAFile: filepath.Join(t.TempDir(), "nope.pem")}, clientTimeout)
		if err == nil || !strings.Contains(err.Error(), "read ca file") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("host header overridden", func(t *testing.T) {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Host }))
		defer srv.Close()
		req, _ := http.NewRequest(http.MethodGet, "http://localhost:5556/dex/x", nil)
		req.Host = "evil.example"
		resp, err := testClient(t, srv.URL, clientTimeout).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got != "localhost:5556" {
			t.Fatalf("host %q", got)
		}
	})
	t.Run("env proxy unused", func(t *testing.T) {
		var hits int
		px := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
		defer px.Close()
		t.Setenv("HTTP_PROXY", px.URL)
		t.Setenv("HTTPS_PROXY", px.URL)
		c := testClient(t, "", clientTimeout)
		c.Timeout = 2 * time.Second
		if resp, err := c.Get("http://warden-test.invalid/"); err == nil {
			resp.Body.Close()
			t.Fatal("want failure")
		}
		if hits != 0 {
			t.Fatal("environment proxy was used")
		}
	})
	t.Run("body cap", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("a", maxBodyBytes+1)))
		}))
		defer srv.Close()
		resp, err := testClient(t, "", clientTimeout).Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if _, err := io.ReadAll(resp.Body); !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("body at cap ok", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("a", maxBodyBytes)))
		}))
		defer srv.Close()
		resp, err := testClient(t, "", clientTimeout).Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if b, err := io.ReadAll(resp.Body); err != nil || len(b) != maxBodyBytes {
			t.Fatalf("len=%d err=%v", len(b), err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(time.Second) }))
		defer srv.Close()
		_, err := testClient(t, srv.URL, 200*time.Millisecond).Get("http://localhost:5556/dex/x")
		var te interface{ Timeout() bool }
		if err == nil || !errors.As(err, &te) || !te.Timeout() {
			t.Fatalf("want timeout, got %v", err)
		}
	})
	t.Run("no redirect", func(t *testing.T) {
		var hits int
		mux := http.NewServeMux()
		mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
		mux.HandleFunc("/b", func(http.ResponseWriter, *http.Request) { hits++ })
		srv := httptest.NewServer(mux)
		defer srv.Close()
		resp, err := testClient(t, "", clientTimeout).Get(srv.URL + "/a")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || hits != 0 {
			t.Fatalf("status=%d hits=%d", resp.StatusCode, hits)
		}
	})
}
