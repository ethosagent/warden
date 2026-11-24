package signer

import (
	"crypto"

	"github.com/ethosagent/warden/internal/keys"
)

// Codec is the local implementation of keys.KeyCodec: keys are generated in
// process and persisted as PKCS#8 PEM. Assembly injects it into the key
// manager.
type Codec struct{}

var _ keys.KeyCodec = Codec{}

// Generate creates a fresh private key for alg.
func (Codec) Generate(alg string) (crypto.Signer, error) { return GenerateKey(alg) }

// Marshal encodes priv as a PKCS#8 "PRIVATE KEY" PEM block.
func (Codec) Marshal(priv crypto.Signer) ([]byte, error) { return MarshalPKCS8PEM(priv) }

// Parse decodes a PKCS#8 PEM block into a LocalSigner.
func (Codec) Parse(pem []byte) (keys.Signer, error) {
	priv, err := ParsePKCS8PEM(pem)
	if err != nil {
		return nil, err
	}
	return wrap(priv)
}

// NewSigner wraps priv in a LocalSigner.
func (Codec) NewSigner(priv crypto.Signer) (keys.Signer, error) { return wrap(priv) }

// wrap returns a true nil interface on error, not a typed nil *LocalSigner.
func wrap(priv crypto.Signer) (keys.Signer, error) {
	s, err := NewLocalSigner(priv)
	if err != nil {
		return nil, err
	}
	return s, nil
}
