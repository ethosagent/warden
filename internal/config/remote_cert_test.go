package config

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type seenReq struct {
	auth, proxyID, path string
	body                map[string]any
}

func certProviderServer(t *testing.T) (*httptest.Server, func() []seenReq) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []seenReq
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := seenReq{auth: r.Header.Get("Authorization"), proxyID: r.Header.Get("X-Warden-Proxy-ID"), path: r.URL.Path}
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &s.body)
		}
		mu.Lock()
		seen = append(seen, s)
		mu.Unlock()
		if r.URL.Path == "/policy" {
			_, _ = io.WriteString(w, `{"allowlist":[{"domain":"a.example"}]}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []seenReq {
		mu.Lock()
		defer mu.Unlock()
		return append([]seenReq(nil), seen...)
	}
}

// TestRemoteProviderBearerUnlessCertClient: without a certificate client every
// request carries the bearer; with SetHTTPClient none does, the proxy id comes
// from the function and the heartbeat names the certificate.
func TestRemoteProviderBearerUnlessCertClient(t *testing.T) {
	srv, seen := certProviderServer(t)
	cl := srv.Client()

	rp, err := NewRemoteProvider(srv.URL+"/policy", "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	rp.client, rp.longClient = cl, cl
	rp.SetProxyID("fixed-id")
	if err := rp.Pull(); err != nil {
		t.Fatal(err)
	}
	if err := rp.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, s := range seen() {
		if s.auth != "Bearer shared-token" || s.proxyID != "fixed-id" {
			t.Errorf("bearer mode %s: auth %q proxy %q", s.path, s.auth, s.proxyID)
		}
		if s.body["certSerial"] != nil {
			t.Errorf("bearer mode heartbeat named a certificate: %v", s.body)
		}
	}

	rp2, _ := NewRemoteProvider(srv.URL+"/policy", "shared-token")
	rp2.SetHTTPClient(cl)
	rp2.SetProxyIDFunc(func() string { return "cert-id" })
	notAfter := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	rp2.SetCertInfo(func() (string, time.Time, bool) { return "ab12", notAfter, true })
	before := len(seen())
	if err := rp2.Pull(); err != nil {
		t.Fatal(err)
	}
	if _, err := rp2.PollLong(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := rp2.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := seen()[before:]
	if len(got) != 3 {
		t.Fatalf("saw %d requests, want 3", len(got))
	}
	for _, s := range got {
		if s.auth != "" || s.proxyID != "cert-id" {
			t.Errorf("cert mode %s: auth %q proxy %q, want no Authorization and the cert id", s.path, s.auth, s.proxyID)
		}
	}
	if hb := got[2]; hb.body["certSerial"] != "ab12" || hb.body["certNotAfter"] != "2026-06-02T12:00:00Z" {
		t.Errorf("heartbeat body = %v, want certSerial and certNotAfter", hb.body)
	}
}

// TestRemoteProviderNoBearerWithCert (W-P2-WBND-05): with a certificate client
// installed, Pull, PollLong and Heartbeat never send an Authorization header
// although a token was given, also after the control plane answers 401 (a
// revoked or expired certificate) and on every retry.
func TestRemoteProviderNoBearerWithCert(t *testing.T) {
	var (
		mu     sync.Mutex
		auths  []string
		status = http.StatusOK
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		code := status
		mu.Unlock()
		if code != http.StatusOK {
			http.Error(w, "no certificate", code)
			return
		}
		if r.URL.Path == "/policy" {
			_, _ = io.WriteString(w, `{"allowlist":[{"domain":"a.example"}]}`)
		}
	}))
	t.Cleanup(srv.Close)

	rp, err := NewRemoteProvider(srv.URL+"/policy", "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	rp.SetHTTPClient(srv.Client())
	calls := func() []error {
		_, pollErr := rp.PollLong(context.Background(), time.Millisecond)
		return []error{rp.Pull(), pollErr, rp.Heartbeat(context.Background())}
	}
	for i, e := range calls() {
		if e != nil {
			t.Fatalf("call %d with a certificate: %v", i, e)
		}
	}
	mu.Lock()
	status = http.StatusUnauthorized
	mu.Unlock()
	for i, e := range calls() {
		if e == nil {
			t.Errorf("call %d: a 401 was not reported", i)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(auths) != 6 {
		t.Fatalf("saw %d requests, want 6", len(auths))
	}
	for i, a := range auths {
		if a != "" {
			t.Errorf("request %d carried Authorization %q in certificate mode", i, a)
		}
	}
}
