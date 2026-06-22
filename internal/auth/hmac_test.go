package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func TestHMACSigner_SHA256(t *testing.T) {
	secret := []byte("mysecret")
	body := "hello world"

	signer, err := NewHMACSigner(secret, "X-Signature-256", "sha256")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://example.com/webhook", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	if err := signer.Transform(req); err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	expected := hex.EncodeToString(mac.Sum(nil))

	if got := req.Header.Get("X-Signature-256"); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestHMACSigner_SHA512(t *testing.T) {
	secret := []byte("mysecret")
	body := "hello world"

	signer, err := NewHMACSigner(secret, "X-Signature-512", "sha512")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://example.com/webhook", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	if err := signer.Transform(req); err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha512.New, secret)
	mac.Write([]byte(body))
	expected := hex.EncodeToString(mac.Sum(nil))

	if got := req.Header.Get("X-Signature-512"); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestHMACSigner_EmptyBody(t *testing.T) {
	secret := []byte("mysecret")

	signer, err := NewHMACSigner(secret, "X-Signature-256", "sha256")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://example.com/webhook", nil)
	if err := signer.Transform(req); err != nil {
		t.Fatal(err)
	}

	mac := hmac.New(sha256.New, secret)
	// empty body -> HMAC of empty byte slice
	expected := hex.EncodeToString(mac.Sum(nil))

	if got := req.Header.Get("X-Signature-256"); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestHMACSigner_InvalidAlgorithm(t *testing.T) {
	_, err := NewHMACSigner([]byte("key"), "X-Sig", "md5")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}
