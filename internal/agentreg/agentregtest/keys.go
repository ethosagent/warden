// Package agentregtest is the conformance suite for agentreg.Store and the
// key fixtures its tests share. It is test support: production code never
// imports it.
package agentregtest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/ethosagent/warden/internal/keys"
)

// Ed25519JWK returns the public JWK document of a key derived from name:
// the same name always gives the same key, different names different keys.
func Ed25519JWK(t testing.TB, name string) json.RawMessage {
	t.Helper()
	seed := sha256.Sum256([]byte(name))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public()
	return marshal(t, pub, keys.AlgEdDSA)
}

// ES256JWK returns the public JWK document of a fresh P-256 key.
func ES256JWK(t testing.TB) json.RawMessage {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p-256 key: %v", err)
	}
	return marshal(t, &k.PublicKey, keys.AlgES256)
}

func marshal(t testing.TB, pub any, alg string) json.RawMessage {
	t.Helper()
	j, err := keys.PublicJWK(pub, alg)
	if err != nil {
		t.Fatalf("build jwk: %v", err)
	}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	return b
}
