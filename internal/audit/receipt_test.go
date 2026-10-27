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

// An identity-free event's receipt has no user_* keys; an attributed event's
// receipt carries them and still verifies.
func TestReceiptIdentityFields(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}

	plain, err := signer.Sign(sampleEvent())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"user_", "identity_"} {
		if bytes.Contains(plain.EventJSON, []byte(k)) {
			t.Fatalf("identity-free receipt contains %q: %s", k, plain.EventJSON)
		}
	}

	ev := sampleEvent()
	ev.UserSub = "sub-1"
	ev.IdentityStatus = "valid"
	ev.UserGroups = []string{"cn=eng,ou=groups,dc=corp"}
	r, err := signer.Sign(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(r.EventJSON, []byte(`"user_sub"`)) || !bytes.Contains(r.EventJSON, []byte(`"identity_status":"valid"`)) {
		t.Fatalf("attributed receipt missing identity keys: %s", r.EventJSON)
	}
	if !Verify(r, signer.PubKey()) {
		t.Fatal("attributed receipt does not verify")
	}
	// Tampering with the identity invalidates it.
	r.EventJSON = bytes.Replace(r.EventJSON, []byte("sub-1"), []byte("sub-2"), 1)
	if Verify(r, signer.PubKey()) {
		t.Fatal("tampered identity still verifies")
	}
}

func TestSignBytesRoundTrip(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	msg := []byte("entry hash bytes")
	sig := signer.SignBytes(msg)
	if !VerifyBytes(signer.PubKey(), msg, sig) {
		t.Fatal("VerifyBytes rejected a valid signature")
	}
	if VerifyBytes(signer.PubKey(), []byte("other"), sig) {
		t.Fatal("VerifyBytes accepted a signature over different bytes")
	}
	other, _ := NewSigner()
	if VerifyBytes(other.PubKey(), msg, sig) {
		t.Fatal("VerifyBytes accepted a signature under the wrong key")
	}
	if VerifyBytes(ed25519.PublicKey{1, 2, 3}, msg, sig) {
		t.Fatal("VerifyBytes accepted a short public key")
	}
	// Domain separation: SignBytes does not sign the bare message.
	if ed25519.Verify(signer.PubKey(), msg, sig) {
		t.Fatal("SignBytes signature verifies without the domain prefix")
	}
}

// TestVerifyBytesRejectsReceiptSignature pins the domain separation in the
// other direction: a receipt signature produced by Sign(event) over some bytes
// never verifies as a SignBytes signature over the same bytes.
func TestVerifyBytesRejectsReceiptSignature(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	receipt, err := signer.Sign(sampleEvent())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(receipt, signer.PubKey()) {
		t.Fatal("receipt does not verify")
	}
	if VerifyBytes(signer.PubKey(), receipt.EventJSON, receipt.Signature) {
		t.Fatal("receipt signature verified as a SignBytes signature")
	}
}
