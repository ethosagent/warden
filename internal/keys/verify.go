package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Verify checks sig as the JWS signature of signingInput by jwk under alg.
// The verdict is an error value so callers can branch: ErrUnsupportedAlg for
// an algorithm outside {AlgEdDSA, AlgES256} — "none", HS*, RS* and anything
// else never reach a key; ErrAlgMismatch when alg does not fit the key's
// type, or when jwk.Alg is set and disagrees; ErrInvalidKey when the JWK
// itself is malformed; ErrBadSignature for a signature of the wrong encoding
// — an ES256 signature in ASN.1 DER is rejected by its length alone, never
// parsed — of the wrong length, or cryptographically wrong.
func Verify(jwk JWK, alg string, signingInput, sig []byte) error {
	switch alg {
	case AlgEdDSA, AlgES256:
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return err
	}
	var p ed25519.PublicKey
	var ec *ecdsa.PublicKey
	switch k := pub.(type) {
	case ed25519.PublicKey:
		p = k
	case *ecdsa.PublicKey:
		ec = k
	}
	if alg != algFor(jwk.Kty) {
		return fmt.Errorf("%w: %q with kty %q", ErrAlgMismatch, alg, jwk.Kty)
	}
	if jwk.Alg != "" && jwk.Alg != alg {
		return fmt.Errorf("%w: jwk alg is %q, asked for %q", ErrAlgMismatch, jwk.Alg, alg)
	}
	switch {
	case p != nil:
		if len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("%w: signature is %d bytes, want %d", ErrBadSignature, len(sig), ed25519.SignatureSize)
		}
		if !ed25519.Verify(p, signingInput, sig) {
			return ErrBadSignature
		}
		return nil
	case ec != nil:
		if len(sig) != ES256SignatureSize {
			return fmt.Errorf("%w: signature is %d bytes, want %d (is it DER?)", ErrBadSignature, len(sig), ES256SignatureSize)
		}
		// RFC 7518 section 3.4: verify over the SHA-256 digest, with the two
		// halves read as fixed-width big-endian integers.
		digest := sha256.Sum256(signingInput)
		half := ES256SignatureSize / 2
		r := new(big.Int).SetBytes(sig[:half])
		s := new(big.Int).SetBytes(sig[half:])
		if !ecdsa.Verify(ec, digest[:], r, s) {
			return ErrBadSignature
		}
		return nil
	}
	return fmt.Errorf("%w: kty %q", ErrUnsupportedAlg, jwk.Kty)
}
