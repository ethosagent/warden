// Package keys provides the JOSE signing primitives behind Warden's key
// management: local signers for Ed25519 (EdDSA) and P-256 (ES256), the
// public JWK format with RFC 7638 thumbprint kids, and JWS signature
// verification. The package is pure computation — it holds no state, does no
// I/O and never logs — so persistence, rotation and the JWKS endpoint are
// built on top of it by the key manager (W-P2-KEYS-02) and its consumers.
//
// Nothing in this package lets private key material escape: errors name
// algorithms and member names, never bytes, and LocalSigner's string and log
// forms carry only the kid and algorithm.
package keys

import (
	"context"
	"crypto"
	"errors"
)

// JOSE algorithms supported for signing and verification. Everything else —
// including "none", HMAC and RSA — is rejected, so a peer cannot talk this
// package into an algorithm it does not implement.
const (
	// AlgEdDSA is Ed25519 signing (RFC 8037): the signing input is signed
	// directly and the signature is 64 raw bytes.
	AlgEdDSA = "EdDSA"
	// AlgES256 is ECDSA over P-256 with a SHA-256 digest (RFC 7518 section
	// 3.4): the signature is the fixed 64-byte r||s encoding, never ASN.1
	// DER.
	AlgES256 = "ES256"
)

// Errors returned by this package. Every failure is one of these (possibly
// wrapped with fmt.Errorf("%w: ...") naming only public facts — algorithms,
// member names, lengths — so a caller can branch on errors.Is without
// parsing, and an error in a log or audit trail cannot leak key material.
var (
	// ErrNoActiveKey is returned when a rotation window holds no active key
	// for the requested purpose. The key manager (W-P2-KEYS-02) returns it;
	// it lives here so manager and callers share one sentinel.
	ErrNoActiveKey = errors.New("keys: no active key")
	// ErrUnsupportedAlg reports an algorithm this package does not implement
	// at all, or a JWK whose key type or curve is not Ed25519 or P-256.
	ErrUnsupportedAlg = errors.New("keys: unsupported algorithm")
	// ErrAlgMismatch reports an algorithm that exists but does not fit the
	// key it was paired with — ES256 with an Ed25519 key, EdDSA with an
	// EC key, or a JWK whose alg member disagrees with the requested one.
	ErrAlgMismatch = errors.New("keys: algorithm does not match key type")
	// ErrBadSignature reports a signature that is not a valid signature for
	// the given key and signing input: wrong encoding (including an ASN.1
	// DER ES256 signature), wrong length, or cryptographically wrong.
	ErrBadSignature = errors.New("keys: invalid signature")
	// ErrInvalidKey reports a malformed key document: a private "d" member
	// where a public JWK is expected, a non-string member, a coordinate that
	// is not unpadded base64url, has the wrong length, or is not on the
	// curve. It is never returned for a well-formed key of the wrong kind —
	// that is ErrAlgMismatch or ErrUnsupportedAlg.
	ErrInvalidKey = errors.New("keys: invalid key")
)

// Signer signs JWS signing inputs. The signing input is the ASCII
// "header.payload" of a JWS compact serialization; building and parsing
// serializations is the caller's job (W-P2-TOKX-01 adds those helpers).
//
// Implementations must be safe for concurrent use and must perform no I/O:
// the interface is the seam behind which the key manager can later put a KMS
// adapter, and the failure modes of Sign are the key's, not the network's.
type Signer interface {
	// KID returns the RFC 7638 thumbprint of the public key, base64url
	// without padding. It is the "kid" JWS header member and the JWKS entry
	// identifier.
	KID() string
	// Alg returns the JWS algorithm this signer produces, AlgEdDSA or
	// AlgES256.
	Alg() string
	// Public returns the public half of the signing key: an
	// ed25519.PublicKey or a *ecdsa.PublicKey on P-256.
	Public() crypto.PublicKey
	// Sign returns the JWS signature over signingInput, encoded per Alg:
	// EdDSA signs the input itself and returns 64 raw bytes; ES256 signs
	// the SHA-256 digest of the input and returns the fixed 64-byte r||s
	// encoding. Sign returns an error without signing if ctx is already
	// cancelled; local signing itself is fast and uninterruptible.
	Sign(ctx context.Context, signingInput []byte) ([]byte, error)
}
