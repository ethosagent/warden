package main

import (
	"bytes"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

func TestExpandEnv(t *testing.T) {
	t.Setenv("WARDEN_TEST_X", "val")
	if got := expandEnv("${WARDEN_TEST_X}"); got != "val" {
		t.Errorf("expandEnv ${} = %q, want val", got)
	}
	if got := expandEnv("Bearer ${WARDEN_TEST_X}"); got != "Bearer val" {
		t.Errorf("embedded expand = %q, want 'Bearer val'", got)
	}
	if got := expandEnv("${WARDEN_TEST_UNSET}"); got != "" {
		t.Errorf("unset expand = %q, want empty", got)
	}
}

func TestBuildTransformers(t *testing.T) {
	t.Setenv("WARDEN_TEST_KEY", "secretval")
	entries := []config.AuthEntry{
		{Match: "api.x.com", Type: config.AuthAPIKey, Location: "header", Name: "X-API-Key", Value: "${WARDEN_TEST_KEY}"},
		{Match: "api.stripe.com", Type: config.AuthHMAC, Algorithm: "sha256", Secret: "${WARDEN_TEST_KEY}", Header: "Stripe-Signature"},
	}
	ts, err := buildTransformers(entries, nil)
	if err != nil {
		t.Fatalf("buildTransformers: %v", err)
	}
	if len(ts) != 2 {
		t.Fatalf("got %d transformers, want 2", len(ts))
	}
	if !ts[0].Matches("api.x.com") || ts[0].Matches("api.stripe.com") {
		t.Error("api.x.com transformer matched the wrong host")
	}

	// The API-key transformer injects the env-expanded value, never the placeholder.
	req, _ := http.NewRequest(http.MethodGet, "https://api.x.com/", nil)
	if err := ts[0].Transformer.Transform(req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-API-Key"); got != "secretval" {
		t.Errorf("X-API-Key = %q, want secretval (env-expanded)", got)
	}
}

func TestLoadOrCreateSignerPersists(t *testing.T) {
	kf := filepath.Join(t.TempDir(), "receipt-key.pem")
	s1, err := loadOrCreateSigner(kf)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	s2, err := loadOrCreateSigner(kf)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !bytes.Equal(s1.PubKey(), s2.PubKey()) {
		t.Fatal("persisted key changed across loads; receipts would not verify after restart")
	}
}
