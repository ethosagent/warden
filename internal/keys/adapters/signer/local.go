// Package signer is the local private-key adapter behind the keys.Signer
// port: Ed25519 (AlgEdDSA) and P-256 (AlgES256) keys generated or loaded in
// process, and the PKCS#8 PEM form they persist as. Assembly constructs the
// signers (GenerateLocal, NewLocalSigner) and injects them; the domain
// package never imports this adapter (L5), and X1 confines private-key
// signing to exactly here.
package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/ethosagent/warden/internal/keys"
)

// scalarSize is half an ES256 signature: each of r and s is 32 bytes.
const scalarSize = keys.ES256SignatureSize / 2

// LocalSigner signs with a key held in process: Ed25519 (AlgEdDSA) or ECDSA
// over P-256 (AlgES256). It is safe for concurrent use, performs no I/O, and
// its printable and loggable forms carry only the kid and algorithm — never
// key bytes. Build one with GenerateLocal or NewLocalSigner; the zero value
// has no key and fails closed with keys.ErrNoActiveKey.
type LocalSigner struct {
	ed  ed25519.PrivateKey // set for AlgEdDSA
	ec  *ecdsa.PrivateKey  // set for AlgES256
	kid string
	alg string
}

var (
	_ keys.Signer    = (*LocalSigner)(nil)
	_ slog.LogValuer = (*LocalSigner)(nil)
	_ fmt.Stringer   = (*LocalSigner)(nil)
	_ fmt.GoStringer = (*LocalSigner)(nil)
)

// GenerateLocal generates a fresh key for alg (AlgEdDSA or AlgES256) and
// returns a LocalSigner over it. Any other algorithm is
// keys.ErrUnsupportedAlg.
func GenerateLocal(alg string) (*LocalSigner, error) {
	switch alg {
	case keys.AlgEdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("keys: generate ed25519 key: %w", err)
		}
		return newLocalSigner(priv)
	case keys.AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("keys: generate p-256 key: %w", err)
		}
		return newLocalSigner(priv)
	default:
		return nil, fmt.Errorf("%w: %q", keys.ErrUnsupportedAlg, alg)
	}
}

// NewLocalSigner wraps an existing private key, which must be an
// ed25519.PrivateKey or a P-256 *ecdsa.PrivateKey. A key of another type is
// keys.ErrAlgMismatch; a malformed key of a supported type is
// keys.ErrInvalidKey. The signer retains priv, so callers must not mutate it
// afterwards.
func NewLocalSigner(priv crypto.Signer) (*LocalSigner, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: nil signer", keys.ErrInvalidKey)
	}
	return newLocalSigner(priv)
}

func newLocalSigner(priv crypto.Signer) (*LocalSigner, error) {
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: ed25519 key is %d bytes, want %d", keys.ErrInvalidKey, len(k), ed25519.PrivateKeySize)
		}
		jwk, err := keys.PublicJWK(k.Public(), keys.AlgEdDSA)
		if err != nil {
			return nil, err
		}
		return &LocalSigner{ed: k, kid: jwk.Kid, alg: keys.AlgEdDSA}, nil
	case *ecdsa.PrivateKey:
		if k == nil || k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: es256 needs a p-256 key", keys.ErrAlgMismatch)
		}
		jwk, err := keys.PublicJWK(&k.PublicKey, keys.AlgES256)
		if err != nil {
			return nil, err
		}
		return &LocalSigner{ec: k, kid: jwk.Kid, alg: keys.AlgES256}, nil
	default:
		return nil, fmt.Errorf("%w: %T is not an ed25519 or p-256 key", keys.ErrAlgMismatch, priv)
	}
}

// KID returns the RFC 7638 thumbprint of the public key.
func (s *LocalSigner) KID() string { return s.kid }

// Alg returns AlgEdDSA for an Ed25519 key, AlgES256 for a P-256 key.
func (s *LocalSigner) Alg() string { return s.alg }

// Public returns the public half of the signing key.
func (s *LocalSigner) Public() crypto.PublicKey {
	switch {
	case s.ed != nil:
		return s.ed.Public()
	case s.ec != nil:
		return &s.ec.PublicKey
	}
	return nil
}

// Sign returns the JWS signature over signingInput. A cancelled context is
// honoured before signing starts; the signing itself is CPU-only. The zero
// value fails closed with keys.ErrNoActiveKey.
func (s *LocalSigner) Sign(ctx context.Context, signingInput []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keys: sign: %w", err)
	}
	switch {
	case s.ed != nil:
		return ed25519.Sign(s.ed, signingInput), nil
	case s.ec != nil:
		return signES256(s.ec, signingInput)
	}
	return nil, keys.ErrNoActiveKey
}

// signES256 signs per RFC 7518 section 3.4: hash the input with SHA-256,
// sign the digest with ECDSA, and return the two fixed-width 32-byte
// big-endian halves r||s. The ASN.1 DER form Go's ecdsa.Sign produces is an
// intermediate here, never an output.
func signES256(priv *ecdsa.PrivateKey, signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("keys: es256 sign: %w", err)
	}
	sig := make([]byte, keys.ES256SignatureSize)
	r.FillBytes(sig[:scalarSize])
	s.FillBytes(sig[scalarSize:])
	return sig, nil
}

// String describes the signer for logs and errors: the kid and algorithm
// only, never key bytes.
func (s *LocalSigner) String() string {
	return fmt.Sprintf("signer.LocalSigner{kid: %s, alg: %s}", s.kid, s.alg)
}

// GoString backs %#v with the same redacted form as String.
func (s *LocalSigner) GoString() string { return s.String() }

// LogValue lets the signer be logged with slog without exposing key
// material: the record carries kid and alg attributes only.
func (s *LocalSigner) LogValue() slog.Value {
	return slog.GroupValue(slog.String("kid", s.kid), slog.String("alg", s.alg))
}

// MarshalPKCS8PEM encodes priv as a PKCS#8 "PRIVATE KEY" PEM block — the
// form the key store persists on disk. Only Ed25519 and P-256 keys are
// accepted, so anything MarshalPKCS8PEM writes, ParsePKCS8PEM reads back:
// the round trip is total by construction.
func MarshalPKCS8PEM(priv crypto.Signer) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: nil signer", keys.ErrInvalidKey)
	}
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: ed25519 key is %d bytes, want %d", keys.ErrInvalidKey, len(k), ed25519.PrivateKeySize)
		}
	case *ecdsa.PrivateKey:
		if k == nil || k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: es256 needs a p-256 key", keys.ErrAlgMismatch)
		}
	default:
		return nil, fmt.Errorf("%w: %T is not an ed25519 or p-256 key", keys.ErrAlgMismatch, priv)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePKCS8PEM decodes a PKCS#8 "PRIVATE KEY" PEM block into a signer key.
// Only Ed25519 and P-256 ECDSA keys are accepted — a key of any other type or
// curve is keys.ErrAlgMismatch, and a document that is not a parseable PEM or
// PKCS#8 block is keys.ErrInvalidKey.
func ParsePKCS8PEM(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", keys.ErrInvalidKey)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%w: PEM type %q, want \"PRIVATE KEY\"", keys.ErrInvalidKey, block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// The blob may itself be sensitive, so its parse error text stays out
		// of this error: name the problem, not the cause.
		return nil, fmt.Errorf("%w: not a pkcs8 private key", keys.ErrInvalidKey)
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: ed25519 key is %d bytes, want %d", keys.ErrInvalidKey, len(k), ed25519.PrivateKeySize)
		}
		return k, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: curve %s, want P-256", keys.ErrAlgMismatch, k.Curve.Params().Name)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("%w: %T is not an ed25519 or p-256 key", keys.ErrAlgMismatch, key)
	}
}
