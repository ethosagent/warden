package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuth2_FetchesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok123",
			"expires_in":   3600,
			"token_type":   "bearer",
		})
	}))
	defer srv.Close()

	o := NewOAuth2ClientCredentials(srv.Client(), srv.URL, "cid", "csecret", []string{"read"})
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err := o.Transform(req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer tok123" {
		t.Fatalf("expected 'Bearer tok123', got %q", got)
	}
}

func TestOAuth2_CachesToken(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok123",
			"expires_in":   3600,
			"token_type":   "bearer",
		})
	}))
	defer srv.Close()

	o := NewOAuth2ClientCredentials(srv.Client(), srv.URL, "cid", "csecret", nil)

	req1, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err := o.Transform(req1); err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err := o.Transform(req2); err != nil {
		t.Fatal(err)
	}

	if c := atomic.LoadInt64(&calls); c != 1 {
		t.Fatalf("expected 1 token request, got %d", c)
	}
}

func TestOAuth2_RefreshesExpiredToken(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&calls, 1)
		tok := "tok-first"
		if n > 1 {
			tok = "tok-refreshed"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": tok,
			"expires_in":   3600,
			"token_type":   "bearer",
		})
	}))
	defer srv.Close()

	o := NewOAuth2ClientCredentials(srv.Client(), srv.URL, "cid", "csecret", nil)

	// First call -- fetches token
	req1, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err := o.Transform(req1); err != nil {
		t.Fatal(err)
	}

	// Manually expire the token
	o.mu.Lock()
	o.expiry = time.Now().Add(-time.Minute)
	o.mu.Unlock()

	// Second call -- should fetch a new token
	req2, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err := o.Transform(req2); err != nil {
		t.Fatal(err)
	}

	if got := req2.Header.Get("Authorization"); got != "Bearer tok-refreshed" {
		t.Fatalf("expected 'Bearer tok-refreshed', got %q", got)
	}
	if c := atomic.LoadInt64(&calls); c != 2 {
		t.Fatalf("expected 2 token requests, got %d", c)
	}
}

func TestOAuth2_EndpointFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	o := NewOAuth2ClientCredentials(srv.Client(), srv.URL, "cid", "csecret", nil)
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err := o.Transform(req); err == nil {
		t.Fatal("expected error for 500 response")
	}
}
