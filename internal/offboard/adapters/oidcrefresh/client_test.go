package oidcrefresh_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/offboard/adapters/oidcrefresh"
)

const secretToken = "rt-secret-refresh-token-value-0001"

func newClient(t *testing.T, h http.HandlerFunc, ready bool) *oidcrefresh.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := oidcrefresh.New(oidcrefresh.Config{
		HTTP: srv.Client(), ClientID: "warden portal", ClientSecret: "s3cr:t&x",
		TokenURL: func() (string, bool) { return srv.URL + "/token", ready },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientRequestShape(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if r.Method != http.MethodPost || r.URL.Path != "/token" || !ok ||
			id != url.QueryEscape("warden portal") || secret != url.QueryEscape("s3cr:t&x") ||
			r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "bad request shape", http.StatusTeapot)
			return
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != secretToken || r.PostForm.Has("scope") {
			http.Error(w, "bad form", http.StatusTeapot)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a","refresh_token":"rt-next","id_token":"idt"}`))
	}, true)
	r, err := c.Refresh(context.Background(), secretToken)
	if err != nil || r.Status != 200 || r.RefreshToken != "rt-next" || r.IDToken != "idt" || r.ErrorCode != "" {
		t.Fatalf("Refresh = %v, %v", r, err)
	}
}

func TestClientErrorAnswers(t *testing.T) {
	cases := []struct {
		name, body  string
		status      int
		code, desc  string
		wantNoToken bool
	}{
		{"dex expired", `{"error":"invalid_request","error_description":"Refresh token expired."}`, 400, "invalid_request", "Refresh token expired.", true},
		{"dex refused", `{"error":"invalid_request"}`, 500, "invalid_request", "", true},
		{"plain text", "upstream unavailable", 503, "", "", true},
		{"error body with tokens", `{"error":"invalid_client","refresh_token":"x","id_token":"y"}`, 401, "invalid_client", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}, true)
			r, err := c.Refresh(context.Background(), secretToken)
			if err != nil || r.Status != tc.status || r.ErrorCode != tc.code || r.Description != tc.desc || r.RefreshToken != "" || r.IDToken != "" {
				t.Fatalf("Refresh = %+v, %v", r, err)
			}
		})
	}
}

func TestClientNoAnswer(t *testing.T) {
	c := newClient(t, func(http.ResponseWriter, *http.Request) {}, false)
	if _, err := c.Refresh(context.Background(), secretToken); !errors.Is(err, oidcrefresh.ErrNotReady) {
		t.Fatalf("before discovery = %v, want ErrNotReady", err)
	}
	slow := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}, true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := slow.Refresh(ctx, secretToken)
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), secretToken) {
		t.Fatalf("timeout = %v, want DeadlineExceeded without the token", err)
	}
	down, err := oidcrefresh.New(oidcrefresh.Config{
		HTTP: http.DefaultClient, ClientID: "c",
		TokenURL: func() (string, bool) { return "http://127.0.0.1:1/token", true },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = down.Refresh(context.Background(), secretToken)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), secretToken) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("unreachable = %v, want a kind-only error", err)
	}
	for _, cfg := range []oidcrefresh.Config{{}, {HTTP: http.DefaultClient}, {HTTP: http.DefaultClient, TokenURL: func() (string, bool) { return "", false }}} {
		if _, err := oidcrefresh.New(cfg); err == nil {
			t.Errorf("New(%+v) accepted an incomplete config", cfg)
		}
	}
}
