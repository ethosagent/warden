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
