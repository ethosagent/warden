package secrets

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultFetcher_KVv2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Errorf("missing or wrong token header: %q", r.Header.Get("X-Vault-Token"))
		}
		if r.URL.Path != "/v1/secret/data/openai" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"value": "sk-secret-v2",
				},
				"metadata": map[string]interface{}{
					"version": 1,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	f := NewVaultFetcher(srv.URL, "test-token", map[string]string{
		"openai_key": "secret/data/openai",
	})

	got, err := f.Fetch("openai_key")
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if got != "sk-secret-v2" {
		t.Errorf("Fetch = %q, want %q", got, "sk-secret-v2")
	}
}

func TestVaultFetcher_KVv1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"value": "sk-secret-v1",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	f := NewVaultFetcher(srv.URL, "test-token", map[string]string{
		"openai_key": "secret/data/openai",
	})

	got, err := f.Fetch("openai_key")
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if got != "sk-secret-v1" {
		t.Errorf("Fetch = %q, want %q", got, "sk-secret-v1")
	}
}

func TestVaultFetcher_UnknownPlaceholder(t *testing.T) {
	f := NewVaultFetcher("http://localhost:8200", "token", map[string]string{})
	_, err := f.Fetch("unknown")
	if !errors.Is(err, ErrUnknownPlaceholder) {
		t.Errorf("err = %v, want ErrUnknownPlaceholder", err)
	}
}

func TestVaultFetcher_Unreachable(t *testing.T) {
	f := NewVaultFetcher("http://127.0.0.1:1", "token", map[string]string{
		"key": "secret/data/test",
	})
	_, err := f.Fetch("key")
	if err == nil {
		t.Fatal("expected error for unreachable Vault")
	}
}

func TestVaultFetcher_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	f := NewVaultFetcher(srv.URL, "bad-token", map[string]string{
		"key": "secret/data/test",
	})
	_, err := f.Fetch("key")
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}
