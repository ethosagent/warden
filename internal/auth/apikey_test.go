package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestAPIKeyInjector_Header(t *testing.T) {
	a, err := NewAPIKeyInjector("header", "X-Api-Key", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	if err := a.Transform(req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Api-Key"); got != "secret123" {
		t.Fatalf("expected header X-Api-Key=secret123, got %q", got)
	}
}

func TestAPIKeyInjector_BasicAuth(t *testing.T) {
	a, err := NewAPIKeyInjector("basic_auth", "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	if err := a.Transform(req); err != nil {
		t.Fatal(err)
	}
	u, p, ok := req.BasicAuth()
	if !ok {
		t.Fatal("expected basic auth to be set")
	}
	if u != "user" || p != "pass" {
		t.Fatalf("expected user/pass, got %q/%q", u, p)
	}
}

func TestAPIKeyInjector_QueryRejected(t *testing.T) {
	_, err := NewAPIKeyInjector("query", "api_key", "secret123")
	if err == nil {
		t.Fatal("expected error for query location")
	}
	if !strings.Contains(err.Error(), "unsupported api key location") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestAPIKeyInjector_UnknownLocation(t *testing.T) {
	_, err := NewAPIKeyInjector("cookie", "name", "val")
	if err == nil {
		t.Fatal("expected error for unknown location")
	}
	if !strings.Contains(err.Error(), "unsupported api key location") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestInjectedSecrets(t *testing.T) {
	inj, _ := NewAPIKeyInjector("header", "X-Key", "k-value")
	if got := inj.InjectedSecrets(); len(got) != 1 || got[0] != "k-value" {
		t.Fatalf("apikey InjectedSecrets = %v", got)
	}
	if got := NewAWSSigV4("AK", "SK", "", "us-east-1", "s3").InjectedSecrets(); len(got) != 0 {
		t.Fatalf("sigv4 without a session token injects no secret, got %v", got)
	}
	if got := NewAWSSigV4("AK", "SK", "tok", "us-east-1", "s3").InjectedSecrets(); len(got) != 1 || got[0] != "tok" {
		t.Fatalf("sigv4 session token = %v", got)
	}
	o := NewOAuth2ClientCredentials(nil, "http://x", "id", "sec", nil)
	if got := o.InjectedSecrets(); len(got) != 0 {
		t.Fatalf("oauth2 before a token is fetched injects nothing, got %v", got)
	}
	o.token = "bearer-tok"
	if got := o.InjectedSecrets(); len(got) != 1 || got[0] != "bearer-tok" {
		t.Fatalf("oauth2 InjectedSecrets = %v", got)
	}
}
