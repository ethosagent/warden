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

// testKeyID is the access key id the stores under test accept.
const testKeyID = "warden-e2e-fake-access-key-id"

// realClientAgainst points warden's own Secrets Manager client (the one the
// CP's consent.store uses) at srv: every dial goes to srv, and srv's
// certificate is trusted, the way the compose stack's network alias and
// SSL_CERT_FILE do it. The client is built exactly as production builds it.
func realClientAgainst(t *testing.T, srv *httptest.Server, keyID string) secrets.AWSSecretsClient {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", keyID)
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
	s := newStore(testKeyID, func() time.Time { return time.Unix(1_800_000_000, 0) })
	srv := httptest.NewTLSServer(s.apiHandler())
	defer srv.Close()
	st := secrets.NewAWSSecretStore(realClientAgainst(t, srv, testKeyID), "us-east-1", "warden-cp/")
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
	s := newStore(testKeyID, time.Now)
	h := s.apiHandler()
	for name, hdr := range map[string]map[string]string{
		"unsigned":  {"X-Amz-Target": "secretsmanager.CreateSecret"},
		"no target": {"Authorization": "AWS4-HMAC-SHA256 Credential=" + testKeyID + "/20261127/us-east-1/secretsmanager/aws4_request"},
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
	s := newStore(testKeyID, time.Now)
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

// TestFakeAWSAccessKeyID: a request signed with any access key id but the one
// the store accepts (a worker's, say) is 403 and stores nothing, through
// warden's real client too; an empty configured id accepts no key.
func TestFakeAWSAccessKeyID(t *testing.T) {
	s := newStore(testKeyID, time.Now)
	srv := httptest.NewTLSServer(s.apiHandler())
	defer srv.Close()
	st := secrets.NewAWSSecretStore(realClientAgainst(t, srv, "some-other-access-key-id"), "us-east-1", "warden-cp/")
	err := st.Put(context.Background(), "idp/abc", "rt-one")
	if err == nil || !strings.Contains(err.Error(), "UnrecognizedClientException") {
		t.Fatalf("Put with a foreign access key id = %v, want UnrecognizedClientException", err)
	}
	if len(s.secrets) != 0 {
		t.Fatal("a refused request stored a secret")
	}

	open := newStore("", time.Now)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"SecretId":"n"}`))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=/20261127/us-east-1/secretsmanager/aws4_request, SignedHeaders=host, Signature=x")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	rec := httptest.NewRecorder()
	open.apiHandler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("a store with no configured access key id accepted a request")
	}
	for authz, want := range map[string]string{
		"AWS4-HMAC-SHA256 Credential=AK1/20261127/us-east-1/secretsmanager/aws4_request, SignedHeaders=host, Signature=x": "AK1",
		"AWS4-HMAC-SHA256 SignedHeaders=host, Credential=AK2/x":                                                           "AK2",
		"Bearer AK3": "",
	} {
		if got := credentialKeyID(authz); got != want {
			t.Errorf("credentialKeyID(%q) = %q, want %q", authz, got, want)
		}
	}
}
