// Package keys_test exercises the JOSE pipeline the way its consumers do:
// a signer from the adapter produces a signature and a public JWK, the
// domain package verifies it, with a JWKS document in between. It is an
// external test package on purpose — archtest's L5 rule reads the imports
// of a package's non-test files, so a domain test may import its own
// adapter without the domain itself ever depending on it.
package keys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ethosagent/warden/internal/keys"
	signer "github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// TestBlackBoxRoundTrip is the acceptance path over the public surface only:
// generate a key in the adapter, sign with it, publish the JWK inside a JWKS,
// take the JWK back out of the JSON, and verify — for both algorithms.
func TestBlackBoxRoundTrip(t *testing.T) {
	input := []byte("eyJhbGciOiJFZERTQSJ9.cGF5bG9hZA")

	for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
		t.Run(alg, func(t *testing.T) {
			s, err := signer.GenerateLocal(alg)
			if err != nil {
				t.Fatalf("GenerateLocal(%s): %v", alg, err)
			}
			sig, err := s.Sign(context.Background(), input)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			jwk, err := keys.PublicJWK(s.Public(), alg)
			if err != nil {
				t.Fatalf("PublicJWK: %v", err)
			}

			// The JWK travels as JSON — inside a JWKS document on the wire, as
			// the control plane will serve it (#77's key store, #111's worker
			// verifiers) — and comes back through ParseJWK before verifying.
			doc, err := json.Marshal(keys.JWKS{Keys: []keys.JWK{jwk}})
			if err != nil {
				t.Fatal(err)
			}
			var set keys.JWKS
			if err := json.Unmarshal(doc, &set); err != nil {
				t.Fatal(err)
			}
			if len(set.Keys) != 1 || set.Keys[0].Kid != s.KID() {
				t.Fatalf("JWKS round trip lost the key: %+v", set)
			}
			member, err := json.Marshal(set.Keys[0])
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := keys.ParseJWK(member)
			if err != nil {
				t.Fatalf("ParseJWK: %v", err)
			}

			if err := keys.Verify(parsed, alg, input, sig); err != nil {
				t.Errorf("Verify(black box round trip): %v", err)
			}
			if err := keys.Verify(parsed, alg, append([]byte("x"), input...), sig); !errors.Is(err, keys.ErrBadSignature) {
				t.Errorf("Verify(other input) error = %v, want ErrBadSignature", err)
			}
		})
	}
}

// TestBlackBoxRejectsDERSignature signs the same input the way a non-JOSE
// caller would — ecdsa.SignASN1, an ASN.1 DER sequence — and proves the
// domain's Verify refuses it: only the fixed-width r||s encoding is a
// signature here, at any length.
func TestBlackBoxRejectsDERSignature(t *testing.T) {
	input := []byte("eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signer.NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	joseSig, err := s.Sign(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	jwk, err := keys.PublicJWK(s.Public(), keys.AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Verify(jwk, keys.AlgES256, input, joseSig); err != nil {
		t.Fatalf("Verify(r||s): %v", err)
	}
	if err := keys.Verify(jwk, keys.AlgES256, input, der); !errors.Is(err, keys.ErrBadSignature) {
		t.Errorf("Verify(DER) error = %v, want ErrBadSignature", err)
	}
}
