package exchange

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/oauthbroker"
)

const loopback = "127.0.0.0/8"

func newExchanger(t *testing.T, allow ...string) *Exchanger {
	t.Helper()
	e, err := New(Options{AllowPrivate: allow})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func request(url string) oauthbroker.ExchangeRequest {
	return oauthbroker.ExchangeRequest{
		TokenURL: url, ClientID: "cid", ClientSecret: oauthbroker.NewSecret("csecret"),
		Code: "the-code", Verifier: "the-verifier-0123456789012345678901234567890123", RedirectURL: "https://cp.example/connect/callback",
	}
}

func kind(t *testing.T, err error) (oauthbroker.ExchangeKind, string) {
	t.Helper()
	var xe *oauthbroker.ExchangeError
	if !errors.As(err, &xe) {
		t.Fatalf("err = %v, want an *ExchangeError", err)
	}
	return xe.Kind, xe.Code
}

func serve(t *testing.T, contentType string, status int, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

// TestExchangeSuccess: a Google-style JSON response yields the tokens, the
// scope string as sent and absolute expiries; the request carried Accept, the
// code, the verifier and the client credentials in the body.
func TestExchangeSuccess(t *testing.T) {
	var seen http.Request
	var form string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		seen, form = *r, r.PostForm.Encode()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","refresh_token":"RT","token_type":"Bearer","expires_in":3599,"scope":"a b","refresh_token_expires_in":7200}`))
	}))
	defer s.Close()
	before := time.Now()
	got, err := newExchanger(t, loopback).Exchange(context.Background(), request(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "AT" || got.RefreshToken != "RT" || got.TokenType != "Bearer" || got.Scope != "a b" {
		t.Fatalf("response = %v", got)
	}
	if d := got.Expiry.Sub(before); d < 3500*time.Second || d > 3700*time.Second {
		t.Fatalf("expiry in %v", d)
	}
	if d := got.RefreshExpiry.Sub(before); d < 7100*time.Second || d > 7300*time.Second {
		t.Fatalf("refresh expiry in %v", d)
	}
	if seen.Header.Get("Accept") != "application/json" || seen.Method != http.MethodPost {
		t.Fatalf("request %s Accept=%q", seen.Method, seen.Header.Get("Accept"))
	}
	for _, want := range []string{"code=the-code", "code_verifier=the-verifier", "grant_type=authorization_code", "client_id=cid", "client_secret=csecret", "redirect_uri="} {
		if !strings.Contains(form, want) {
			t.Errorf("form %q lacks %s", form, want)
		}
	}
}

// TestExchangeErrorFields: an error field is a failure whatever the status,
// including GitHub's HTTP 200 and a body that also carries a token; the
// provider's description never surfaces.
func TestExchangeErrorFields(t *testing.T) {
	cases := map[string]struct {
		ctype  string
		status int
		body   string
		want   oauthbroker.ExchangeKind
		code   string
	}{
		"github 200":      {"application/json", 200, `{"error":"bad_verification_code","error_description":"SECRET-TEXT"}`, oauthbroker.ExchangeRejected, "bad_verification_code"},
		"error and token": {"application/json", 200, `{"error":"invalid_grant","access_token":"AT","token_type":"bearer"}`, oauthbroker.ExchangeRejected, "invalid_grant"},
		"google 400":      {"application/json", 400, `{"error":"invalid_grant","error_description":"Bad Request"}`, oauthbroker.ExchangeRejected, "invalid_grant"},
		"form encoded":    {"application/x-www-form-urlencoded", 200, `error=bad_verification_code&error_description=SECRET-TEXT`, oauthbroker.ExchangeRejected, "bad_verification_code"},
		"access_denied":   {"application/json", 400, `{"error":"access_denied"}`, oauthbroker.ExchangeDenied, "access_denied"},
		"hostile code":    {"application/json", 400, `{"error":"<script>alert(1)</script>"}`, oauthbroker.ExchangeRejected, "invalid_response"},
		"object error":    {"application/json", 400, `{"error":{"message":"SECRET-TEXT"}}`, oauthbroker.ExchangeRejected, "invalid_response"},
		"no access token": {"application/json", 200, `{"token_type":"bearer"}`, oauthbroker.ExchangeRejected, "invalid_response"},
		"not json":        {"text/html", 200, `<html>login</html>`, oauthbroker.ExchangeRejected, "invalid_response"},
		"500 with error":  {"application/json", 500, `{"error":"server_error"}`, oauthbroker.ExchangeUnavailable, ""},
		"502 html":        {"text/html", 502, `<html>bad gateway</html>`, oauthbroker.ExchangeUnavailable, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := serve(t, c.ctype, c.status, c.body)
			_, err := newExchanger(t, loopback).Exchange(context.Background(), request(s.URL))
			k, code := kind(t, err)
			if k != c.want || code != c.code {
				t.Fatalf("kind %d code %q, want %d %q (%v)", k, code, c.want, c.code, err)
			}
			if strings.Contains(err.Error(), "SECRET-TEXT") || strings.Contains(err.Error(), "csecret") || strings.Contains(err.Error(), "the-code") {
				t.Fatalf("error text leaks: %v", err)
			}
		})
	}
}

// TestExchangeFormEncodedSuccess: GitHub answers form-encoded when Accept is
// ignored; it still parses.
func TestExchangeFormEncodedSuccess(t *testing.T) {
	s := serve(t, "application/x-www-form-urlencoded", 200, "access_token=AT&scope=repo%2Cread%3Auser&token_type=bearer")
	got, err := newExchanger(t, loopback).Exchange(context.Background(), request(s.URL))
	if err != nil || got.AccessToken != "AT" || got.Scope != "repo,read:user" {
		t.Fatalf("= %v, %v", got, err)
	}
}

// TestExchangeNoRedirects: a 302 is not followed, so the code and the client
// secret are never sent to its target.
func TestExchangeNoRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"AT","token_type":"bearer"}`))
	}))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	_, err := newExchanger(t, loopback).Exchange(context.Background(), request(s.URL))
	if k, _ := kind(t, err); k != oauthbroker.ExchangeRejected {
		t.Fatalf("redirect = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the redirect was followed")
	}
}

// TestExchangeBodyCap: a response over 64 KiB is refused.
func TestExchangeBodyCap(t *testing.T) {
	big := `{"access_token":"` + strings.Repeat("A", oauthbroker.MaxProviderResponseBytes) + `","token_type":"bearer"}`
	s := serve(t, "application/json", 200, big)
	_, err := newExchanger(t, loopback).Exchange(context.Background(), request(s.URL))
	if k, _ := kind(t, err); k != oauthbroker.ExchangeUnavailable {
		t.Fatalf("oversized body = %v", err)
	}
	ok := `{"access_token":"` + strings.Repeat("A", 60<<10) + `","token_type":"bearer"}`
	s2 := serve(t, "application/json", 200, ok)
	if _, err := newExchanger(t, loopback).Exchange(context.Background(), request(s2.URL)); err != nil {
		t.Fatalf("a body under the cap failed: %v", err)
	}
}

// TestExchangeBlocksPrivateAddresses: without an allow-list the SSRF-safe
// dialer refuses loopback, and the server sees nothing.
func TestExchangeBlocksPrivateAddresses(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer s.Close()
	_, err := newExchanger(t).Exchange(context.Background(), request(s.URL))
	if k, _ := kind(t, err); k != oauthbroker.ExchangeUnavailable {
		t.Fatalf("loopback = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the request reached a loopback server")
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("the error names the address: %v", err)
	}
}

// TestExchangeIgnoresEnvProxy: HTTP_PROXY does not divert the exchange.
func TestExchangeIgnoresEnvProxy(t *testing.T) {
	var proxied atomic.Int32
	px := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxied.Add(1) }))
	defer px.Close()
	t.Setenv("HTTP_PROXY", px.URL)
	t.Setenv("http_proxy", px.URL)
	t.Setenv("NO_PROXY", "")
	s := serve(t, "application/json", 200, `{"access_token":"AT","token_type":"bearer"}`)
	if _, err := newExchanger(t, loopback).Exchange(context.Background(), request(s.URL)); err != nil {
		t.Fatal(err)
	}
	if proxied.Load() != 0 {
		t.Fatal("the exchange went through the environment proxy")
	}
}

// TestExchangeTimeout: the caller's deadline ends a hung provider.
func TestExchangeTimeout(t *testing.T) {
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer s.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := newExchanger(t, loopback).Exchange(ctx, request(s.URL))
	if k, _ := kind(t, err); k != oauthbroker.ExchangeUnavailable {
		t.Fatalf("hung provider = %v", err)
	}
}

// TestNewRejectsBadCIDR: a malformed allow-list entry is a construction error.
func TestNewRejectsBadCIDR(t *testing.T) {
	if _, err := New(Options{AllowPrivate: []string{"not-a-cidr"}}); err == nil {
		t.Fatal("want an error")
	}
}
