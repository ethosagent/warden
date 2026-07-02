// Package audit provides tamper-evident audit trails over analytics events: an
// Ed25519 signing store that emits a verifiable Receipt per mediation, and a
// tagging store that stamps each event with the compliance-framework control IDs
// it maps to. Both are AnalyticsStore decorators, so they compose in the write
// chain without the base store knowing.
package audit

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
)

// Receipt is a signed, verifiable record of a proxy mediation event.
type Receipt struct {
	EventJSON []byte            // canonical JSON of the analytics Event
	Signature []byte            // Ed25519 signature over EventJSON
	PublicKey ed25519.PublicKey // signer's public key (for verification)
	Timestamp time.Time
}

// Signer creates signed receipts from events.
type Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewSigner generates a new Ed25519 keypair for signing receipts.
func NewSigner() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("audit: generate keypair: %w", err)
	}
	return &Signer{privateKey: priv, publicKey: pub}, nil
}

// NewSignerFromKey creates a signer from an existing private key.
func NewSignerFromKey(privateKey ed25519.PrivateKey) *Signer {
	return &Signer{
		privateKey: privateKey,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
	}
}

// Sign creates a signed receipt for the given event.
func (s *Signer) Sign(event analytics.Event) (*Receipt, error) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal event: %w", err)
	}
	sig := ed25519.Sign(s.privateKey, eventJSON)
	return &Receipt{
		EventJSON: eventJSON,
		Signature: sig,
		PublicKey: s.publicKey,
		Timestamp: time.Now(),
	}, nil
}

// PubKey returns the signer's public key for distribution.
func (s *Signer) PubKey() ed25519.PublicKey {
	return s.publicKey
}

// Verify checks that a receipt's signature is valid against the given trusted public key.
func Verify(receipt *Receipt, trustedKey ed25519.PublicKey) bool {
	return ed25519.Verify(trustedKey, receipt.EventJSON, receipt.Signature)
}

// receiptJSON is the JSON-serializable form of Receipt.
type receiptJSON struct {
	EventJSON []byte    `json:"event_json"`
	Signature []byte    `json:"signature"`
	PublicKey []byte    `json:"public_key"`
	Timestamp time.Time `json:"timestamp"`
}

// MarshalReceipt serializes a receipt to JSON for export.
func MarshalReceipt(r *Receipt) ([]byte, error) {
	rj := receiptJSON{
		EventJSON: r.EventJSON,
		Signature: r.Signature,
		PublicKey: r.PublicKey,
		Timestamp: r.Timestamp,
	}
	data, err := json.Marshal(rj)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal receipt: %w", err)
	}
	return data, nil
}

// UnmarshalReceipt deserializes a receipt from JSON.
func UnmarshalReceipt(data []byte) (*Receipt, error) {
	var rj receiptJSON
	if err := json.Unmarshal(data, &rj); err != nil {
		return nil, fmt.Errorf("audit: unmarshal receipt: %w", err)
	}
	return &Receipt{
		EventJSON: rj.EventJSON,
		Signature: rj.Signature,
		PublicKey: ed25519.PublicKey(rj.PublicKey),
		Timestamp: rj.Timestamp,
	}, nil
}
