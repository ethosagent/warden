package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func TestSigV4_KnownVector(t *testing.T) {
	signer := NewAWSSigV4(
		"AKIDEXAMPLE",
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"", // no session token
		"us-east-1",
		"service",
	)

	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	req.Host = "example.amazonaws.com"
	// Pin timestamp for reproducibility
	req.Header.Set("X-Amz-Date", "20150830T123600Z")

	if err := signer.Transform(req); err != nil {
		t.Fatal(err)
	}

	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
		t.Fatalf("expected AWS4-HMAC-SHA256 prefix, got %q", authHeader)
	}
	if !strings.Contains(authHeader, "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request") {
		t.Fatalf("unexpected Credential in %q", authHeader)
	}
	if !strings.Contains(authHeader, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") {
		t.Fatalf("unexpected SignedHeaders in %q", authHeader)
	}
	if !strings.Contains(authHeader, "Signature=") {
		t.Fatalf("missing Signature in %q", authHeader)
	}
}

func TestSigV4_WithSessionToken(t *testing.T) {
	signer := NewAWSSigV4(
		"AKID",
		"secret",
		"session-tok",
		"us-west-2",
		"s3",
	)

	req, _ := http.NewRequest("GET", "https://s3.us-west-2.amazonaws.com/bucket/key", nil)
	req.Host = "s3.us-west-2.amazonaws.com"
	req.Header.Set("X-Amz-Date", "20230101T000000Z")

	if err := signer.Transform(req); err != nil {
		t.Fatal(err)
	}

	if got := req.Header.Get("X-Amz-Security-Token"); got != "session-tok" {
		t.Fatalf("expected X-Amz-Security-Token=session-tok, got %q", got)
	}

	authHeader := req.Header.Get("Authorization")
	if !strings.Contains(authHeader, "x-amz-security-token") {
		t.Fatalf("expected x-amz-security-token in SignedHeaders, got %q", authHeader)
	}
}

func TestSigV4_BodyHash(t *testing.T) {
	signer := NewAWSSigV4("AKID", "secret", "", "us-east-1", "execute-api")

	body := `{"action":"test"}`
	req, _ := http.NewRequest("POST", "https://api.example.com/invoke", strings.NewReader(body))
	req.Host = "api.example.com"
	req.Header.Set("X-Amz-Date", "20230601T120000Z")

	if err := signer.Transform(req); err != nil {
		t.Fatal(err)
	}

	expectedHash := sha256.Sum256([]byte(body))
	expected := hex.EncodeToString(expectedHash[:])
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != expected {
		t.Fatalf("expected X-Amz-Content-Sha256=%s, got %q", expected, got)
	}
}
