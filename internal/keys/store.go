package keys

import (
	"context"
	"crypto"
	"errors"
	"fmt"
)

// Key purposes. Each key belongs to exactly one, so a token key can never
// verify a bundle. The name "audit" is reserved: the admin audit key stays in
// internal/adminaudit and is never a purpose here.
const (
	// PurposeToken signs Warden tokens. Scheduled rotation, published in the
	// JWKS.
	PurposeToken = "token"
	// PurposeBundle signs policy bundles. EdDSA only: workers pin the public
	// keys out of band.
	PurposeBundle = "bundle"
	// PurposeCA holds the worker CA intermediate key. Store only: it is
	// imported (Manager.ImportKey), never generated, scheduled or loaded into
	// a KeySet.
	PurposeCA = "ca"
)

// Purposes returns every valid purpose.
func Purposes() []string { return []string{PurposeToken, PurposeBundle, PurposeCA} }

// loadPurposes are the purposes LoadKeySet generates and loads.
var loadPurposes = []string{PurposeToken, PurposeBundle}

// ValidPurpose reports whether p names a key purpose.
func ValidPurpose(p string) bool {
	for _, v := range Purposes() {
		if p == v {
			return true
		}
	}
	return false
}

// Errors of the key store and the manager. None carries key material.
var (
	// ErrKeyNotFound is returned by PrivateKeyStore.Get for a key the store
	// does not hold.
	ErrKeyNotFound = errors.New("keys: key material not found")
	// ErrKeyExists is returned by PrivateKeyStore.Put when material is already
	// stored under that purpose and kid. A Put never overwrites.
	ErrKeyExists = errors.New("keys: key material already exists")
	// ErrInvalidPurpose reports a purpose that is not one of Purposes, or one
	// the operation does not accept.
	ErrInvalidPurpose = errors.New("keys: invalid purpose")
	// ErrConflict is returned by MetaStore.Insert when a row would break the
	// kid primary key or the one-active / one-next-per-purpose invariant.
	ErrConflict = errors.New("keys: signing key row conflicts with an existing row")
)

// PrivateKeyStore is the seam behind which private signing keys live: a
// CP-only store workers can never read. The default backend keeps PKCS#8 PEM
// files; W-P2-KEYS-07 adds AWS Secrets Manager. The store moves opaque
// encoded private keys and never interprets them — encoding, parsing and the
// public-key comparison are the manager's job — and it never logs them.
//
// Implementations must be safe for concurrent use. Purpose is one of Purposes
// and kid an RFC 7638 thumbprint; an implementation must reject anything else
// so a name can never address a path outside its namespace.
type PrivateKeyStore interface {
	// Put stores pem under purpose/kid and makes it durable before returning.
	// It never overwrites: existing material is ErrKeyExists.
	Put(ctx context.Context, purpose, kid string, pem []byte) error
	// Get returns the material for purpose/kid, or ErrKeyNotFound.
	Get(ctx context.Context, purpose, kid string) ([]byte, error)
	// Delete removes the material. Deleting what is not there is not an error.
	Delete(ctx context.Context, purpose, kid string) error
	// List returns the kids that have material under purpose, in no
	// particular order.
	List(ctx context.Context, purpose string) ([]string, error)
}

// KeyCodec is the private-key side of the Signer: generating a key, encoding
// it for a PrivateKeyStore and decoding it again. It is a port so that this
// package stays free of private-key operations (rule X1); the local adapter in
// internal/keys/adapters/signer implements it, and assembly injects it.
type KeyCodec interface {
	// Generate creates a fresh private key for alg (AlgEdDSA or AlgES256).
	Generate(alg string) (crypto.Signer, error)
	// Marshal encodes priv for a PrivateKeyStore (PKCS#8 PEM).
	Marshal(priv crypto.Signer) ([]byte, error)
	// Parse decodes what Marshal produced into a Signer. A malformed document
	// is ErrInvalidKey.
	Parse(pem []byte) (Signer, error)
	// NewSigner wraps priv in a Signer.
	NewSigner(priv crypto.Signer) (Signer, error)
}

// storeErr wraps a store error with the operation and the public coordinates
// of the key, never its bytes.
func storeErr(op, purpose, kid string, err error) error {
	return fmt.Errorf("keys: %s %s key %s: %w", op, purpose, kid, err)
}
