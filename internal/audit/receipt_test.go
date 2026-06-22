package audit

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
)

func sampleEvent() analytics.Event {
	return analytics.Event{
		Timestamp:      time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Domain:         "api.openai.com",
		Port:           443,
		Protocol:       "https",
		Method:         "POST",
		URL:            "https://api.openai.com/v1/chat/completions",
		Decision:       "allow",
		ResponseStatus: 200,
		SecretRef:      "sha256:abcd1234...last4:sk-Ab",
	}
}

func TestSignAndVerify(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	receipt, err := signer.Sign(sampleEvent())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !Verify(receipt, signer.PubKey()) {
		t.Fatal("Verify returned false for a valid receipt")
	}
}

func TestTamperedEvent(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	receipt, err := signer.Sign(sampleEvent())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper with the event JSON
	receipt.EventJSON = append(receipt.EventJSON[:0:0], receipt.EventJSON...)
	receipt.EventJSON[0] = '['

	if Verify(receipt, signer.PubKey()) {
		t.Fatal("Verify returned true for a tampered event")
	}
}

func TestTamperedSignature(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	receipt, err := signer.Sign(sampleEvent())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Flip a byte in the signature
	receipt.Signature[0] ^= 0xff

	if Verify(receipt, signer.PubKey()) {
		t.Fatal("Verify returned true for a tampered signature")
	}
}

func TestDifferentKey(t *testing.T) {
	signer1, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner (1): %v", err)
	}

	signer2, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner (2): %v", err)
	}

	receipt, err := signer1.Sign(sampleEvent())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if Verify(receipt, signer2.PubKey()) {
		t.Fatal("Verify returned true with a different signer's public key")
	}
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	receipt, err := signer.Sign(sampleEvent())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	data, err := MarshalReceipt(receipt)
	if err != nil {
		t.Fatalf("MarshalReceipt: %v", err)
	}

	restored, err := UnmarshalReceipt(data)
	if err != nil {
		t.Fatalf("UnmarshalReceipt: %v", err)
	}

	if !bytes.Equal(receipt.EventJSON, restored.EventJSON) {
		t.Error("EventJSON mismatch after round-trip")
	}
	if !bytes.Equal(receipt.Signature, restored.Signature) {
		t.Error("Signature mismatch after round-trip")
	}
	if !bytes.Equal(receipt.PublicKey, restored.PublicKey) {
		t.Error("PublicKey mismatch after round-trip")
	}
	if !Verify(restored, signer.PubKey()) {
		t.Error("Verify returned false for round-tripped receipt")
	}
}

func TestNewSignerGeneratesValidKeypair(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	pub := signer.PubKey()
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(signer.privateKey) != ed25519.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(signer.privateKey), ed25519.PrivateKeySize)
	}
}

func TestNewSignerFromKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer := NewSignerFromKey(priv)

	if !bytes.Equal(signer.PubKey(), pub) {
		t.Error("PubKey mismatch from NewSignerFromKey")
	}

	receipt, err := signer.Sign(sampleEvent())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !Verify(receipt, signer.PubKey()) {
		t.Fatal("Verify returned false for receipt signed with NewSignerFromKey")
	}
}
