package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/secrets"
)

// realClientAgainst points warden's own Secrets Manager client (the one the
// CP's consent.store uses) at srv: every dial goes to srv, and srv's
// certificate is trusted, the way the compose stack's network alias and
// SSL_CERT_FILE do it. The client is built exactly as production builds it.
func realClientAgainst(t *testing.T, srv *httptest.Server) secrets.AWSSecretsClient {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "warden-e2e-fake-access-key-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fake-secret-access-key")
	t.Setenv("AWS_SESSION_TOKEN", "")
	prev := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = prev })
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12},
	}
	c, err := secrets.NewAWSSecretsClientFromEnv("us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestFakeAWSWithWardenClient drives the fake with warden's real AWS client
// through the same SecretStore the CP's consent.store builds: create, update,
// read, list by prefix, delete, and not-found mapping.
func TestFakeAWSWithWardenClient(t *testing.T) {
	s := newStore(func() time.Time { return time.Unix(1_800_000_000, 0) })
	srv := httptest.NewTLSServer(s.apiHandler())
	defer srv.Close()
	st := secrets.NewAWSSecretStore(realClientAgainst(t, srv), "us-east-1", "warden-cp/")
	ctx := context.Background()

	if _, err := st.Get(ctx, "idp/abc"); !errors.Is(err, secrets.ErrSecretNotFound) {
		t.Fatalf("Get of a missing key = %v, want not found", err)
	}
	if err := st.Put(ctx, "idp/abc", "rt-one"); err != nil {
		t.Fatalf("Put (create): %v", err)
	}
	if err := st.Put(ctx, "idp/abc", "rt-two"); err != nil {
		t.Fatalf("Put (update): %v", err)
	}
	if v, err := st.Get(ctx, "idp/abc"); err != nil || v != "rt-two" {
		t.Fatalf("Get = %q, %v; want rt-two", v, err)
	}
	s.mu.Lock()
	s.secrets["other/xyz"] = secret{value: "outside the prefix"}
	s.mu.Unlock()
	metas, err := st.List(ctx)
	if err != nil || len(metas) != 1 || metas[0].Key != "idp/abc" {
		t.Fatalf("List = %+v, %v; want only idp/abc", metas, err)
	}
	if err := st.Delete(ctx, "idp/abc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get(ctx, "idp/abc"); err == nil {
		t.Fatal("Get after Delete succeeded")
	}
}

// TestFakeAWSRejectsUnsigned: a request without a SigV4 Authorization header
// or a secretsmanager target is refused, and the store is untouched.
func TestFakeAWSRejectsUnsigned(t *testing.T) {
	s := newStore(time.Now)
	h := s.apiHandler()
	for name, hdr := range map[string]map[string]string{
		"unsigned":  {"X-Amz-Target": "secretsmanager.CreateSecret"},
		"no target": {"Authorization": "AWS4-HMAC-SHA256 Credential=x"},
	} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"Name":"n","SecretString":"v","ClientRequestToken":"t"}`))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	if len(s.secrets) != 0 {
		t.Fatal("a refused request stored a secret")
	}
}

// TestFakeAWSControl: the control listener reports health, names and one
// value, and 404s a missing name.
func TestFakeAWSControl(t *testing.T) {
	s := newStore(time.Now)
	s.secrets["warden-cp/idp/k"] = secret{value: "rt-value"}
	srv := httptest.NewServer(s.controlHandler())
	defer srv.Close()
	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("/_health"); code != 200 || body != "ok" {
		t.Errorf("/_health = %d %q", code, body)
	}
	if code, body := get("/_names"); code != 200 || strings.TrimSpace(body) != `["warden-cp/idp/k"]` {
		t.Errorf("/_names = %d %q", code, body)
	}
	if code, body := get("/_secret?name=warden-cp/idp/k"); code != 200 || body != "rt-value" {
		t.Errorf("/_secret = %d %q", code, body)
	}
	if code, _ := get("/_secret?name=missing"); code != http.StatusNotFound {
		t.Errorf("/_secret missing = %d, want 404", code)
	}
}
