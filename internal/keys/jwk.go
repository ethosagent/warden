package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// JWK member values this package understands.
const (
	ktyOKP     = "OKP"
	ktyEC      = "EC"
	crvEd25519 = "Ed25519"
	crvP256    = "P-256"
	useSig     = "sig"
)

// coordSize is the fixed byte length of every coordinate this package
// encodes or accepts: an Ed25519 x and a P-256 x or y are all 32 bytes.
const coordSize = 32

// JWK is a public JSON Web Key (RFC 7517) in one of the two shapes this
// package signs with: OKP Ed25519 (kty, crv, x) or EC P-256 (kty, crv, x, y).
// There is deliberately no field for the private member "d": a JWK is built
// to be published, pinned, logged and shipped to verifiers, and ParseJWK
// rejects a document that carries one, so no code path can smuggle private
// key material through this type.
type JWK struct {
	Kty string `json:"kty,omitempty"` // key type: "OKP" or "EC"
	Crv string `json:"crv,omitempty"` // curve: "Ed25519" or "P-256"
	X   string `json:"x,omitempty"`   // x coordinate, unpadded base64url
	Y   string `json:"y,omitempty"`   // y coordinate (EC only), unpadded base64url
	Kid string `json:"kid,omitempty"` // RFC 7638 thumbprint by convention
	Alg string `json:"alg,omitempty"` // AlgEdDSA or AlgES256
	Use string `json:"use,omitempty"` // "sig" for keys this package publishes
}

// JWKS is a JWK Set (RFC 7517 section 5): the document the control plane
// serves so workers and peers can fetch verification keys.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK builds the public JWK for pub under alg, with kid set to the RFC
// 7638 thumbprint and use to "sig". alg must match the key type (AlgEdDSA for
// an ed25519.PublicKey, AlgES256 for a P-256 *ecdsa.PublicKey) so a
// mismatched pair can never be published.
func PublicJWK(pub crypto.PublicKey, alg string) (JWK, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if alg != AlgEdDSA {
			return JWK{}, fmt.Errorf("%w: %q with an ed25519 key", ErrAlgMismatch, alg)
		}
		if len(k) != ed25519.PublicKeySize {
			return JWK{}, fmt.Errorf("%w: ed25519 public key is %d bytes, want %d", ErrInvalidKey, len(k), ed25519.PublicKeySize)
		}
		return newJWK(ktyOKP, crvEd25519, encodeCoord(k), "", alg)
	case *ecdsa.PublicKey:
		if alg != AlgES256 {
			return JWK{}, fmt.Errorf("%w: %q with an ec key", ErrAlgMismatch, alg)
		}
		if k == nil || k.Curve != elliptic.P256() {
			return JWK{}, fmt.Errorf("%w: es256 needs a p-256 key", ErrAlgMismatch)
		}
		// Bytes() is the non-deprecated coordinate encoding: the SEC 1
		// uncompressed point 0x04||x||y, validated on the curve.
		point, err := k.Bytes()
		if err != nil || len(point) != 1+2*coordSize {
			return JWK{}, fmt.Errorf("%w: invalid p-256 public key", ErrInvalidKey)
		}
		return newJWK(ktyEC, crvP256, encodeCoord(point[1:1+coordSize]), encodeCoord(point[1+coordSize:]), alg)
	case nil:
		return JWK{}, fmt.Errorf("%w: nil public key", ErrInvalidKey)
	default:
		return JWK{}, fmt.Errorf("%w: %T is not an ed25519 or p-256 key", ErrAlgMismatch, pub)
	}
}

// newJWK assembles a JWK and fills in its thumbprint kid.
func newJWK(kty, crv, x, y, alg string) (JWK, error) {
	j := JWK{Kty: kty, Crv: crv, X: x, Y: y, Alg: alg, Use: useSig}
	kid, err := Thumbprint(j)
	if err != nil {
		return JWK{}, err
	}
	j.Kid = kid
	return j, nil
}

// encodeCoord returns the JOSE encoding of a coordinate: base64url without
// padding, over the fixed-width big-endian bytes.
func encodeCoord(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// PublicKey decodes the JWK's coordinate members into a crypto.PublicKey: an
// ed25519.PublicKey for OKP Ed25519, a *ecdsa.PublicKey for EC P-256. The
// point must be on the curve, so an off-curve x/y pair cannot be loaded as a
// key.
func (j JWK) PublicKey() (crypto.PublicKey, error) {
	if err := j.checkType(); err != nil {
		return nil, err
	}
	switch j.Kty {
	case ktyOKP:
		x, err := j.coord("x", j.X, coordSize)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(x), nil
	case ktyEC:
		x, err := j.coord("x", j.X, coordSize)
		if err != nil {
			return nil, err
		}
		y, err := j.coord("y", j.Y, coordSize)
		if err != nil {
			return nil, err
		}
		point := make([]byte, 1+2*coordSize)
		point[0] = 4 // uncompressed
		copy(point[1:], x)
		copy(point[1+coordSize:], y)
		// ParseUncompressedPublicKey rejects anything not exactly on the curve.
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return nil, fmt.Errorf("%w: point is not on P-256", ErrInvalidKey)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("%w: kty %q", ErrUnsupportedAlg, j.Kty)
}

// checkType validates the kty/crv pair, the one check PublicKey and
// Thumbprint share.
func (j JWK) checkType() error {
	switch {
	case j.Kty == ktyOKP && j.Crv == crvEd25519, j.Kty == ktyEC && j.Crv == crvP256:
		return nil
	case j.Kty != ktyOKP && j.Kty != ktyEC:
		return fmt.Errorf("%w: kty %q", ErrUnsupportedAlg, j.Kty)
	case j.Crv != crvEd25519 && j.Crv != crvP256:
		return fmt.Errorf("%w: crv %q", ErrUnsupportedAlg, j.Crv)
	}
	return fmt.Errorf("%w: kty %q with crv %q", ErrUnsupportedAlg, j.Kty, j.Crv)
}

// coord decodes member name from base64url and checks its byte length.
func (j JWK) coord(name, v string, want int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%w: member %q is not unpadded base64url", ErrInvalidKey, name)
	}
	if len(b) != want {
		return nil, fmt.Errorf("%w: member %q is %d bytes, want %d", ErrInvalidKey, name, len(b), want)
	}
	return b, nil
}

// Thumbprint returns the RFC 7638 thumbprint of jwk: base64url without
// padding over the SHA-256 of the canonical JSON of the required members
// only, in lexicographic member order — crv, kty, x for OKP and crv, kty, x,
// y for EC. kid, alg and use never take part, and the thumbprint is the hash
// itself, never a hash of a hash.
func Thumbprint(jwk JWK) (string, error) {
	if err := jwk.checkType(); err != nil {
		return "", err
	}
	var canonical []byte
	var err error
	if jwk.Kty == ktyOKP {
		if jwk.X == "" {
			return "", fmt.Errorf("%w: missing member \"x\"", ErrInvalidKey)
		}
		// Struct field order is the marshal order; it is already lexicographic.
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{jwk.Crv, jwk.Kty, jwk.X})
	} else {
		if jwk.X == "" || jwk.Y == "" {
			return "", fmt.Errorf("%w: ec key needs members \"x\" and \"y\"", ErrInvalidKey)
		}
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{jwk.Crv, jwk.Kty, jwk.X, jwk.Y})
	}
	if err != nil {
		return "", fmt.Errorf("keys: marshal canonical thumbprint json: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ParseJWK decodes one public JWK document. It rejects: a private "d" member
// (ErrInvalidKey); a kty other than OKP/EC or a crv other than Ed25519/P-256
// (ErrUnsupportedAlg); a coordinate that is not unpadded base64url, has the
// wrong length, or is not on the curve (ErrInvalidKey); and an alg member
// that does not match the key type (ErrAlgMismatch). An absent alg is
// accepted — the caller states the algorithm when verifying. kid is kept as
// given: per RFC 7517 it is an opaque hint, not something to recompute.
func ParseJWK(data []byte) (JWK, error) {
	// Pointer members so a non-string value surfaces as a decode error
	// rather than silently zeroing a field.
	raw := struct {
		Kty *string `json:"kty"`
		Crv *string `json:"crv"`
		X   *string `json:"x"`
		Y   *string `json:"y"`
		D   *string `json:"d"`
		Kid *string `json:"kid"`
		Alg *string `json:"alg"`
		Use *string `json:"use"`
	}{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return JWK{}, fmt.Errorf("%w: not a jwk object: %v", ErrInvalidKey, redactJSONErr(err))
	}
	if raw.D != nil {
		return JWK{}, fmt.Errorf("%w: private member \"d\" in a public jwk", ErrInvalidKey)
	}
	if raw.Kty == nil {
		return JWK{}, fmt.Errorf("%w: missing member \"kty\"", ErrInvalidKey)
	}
	if *raw.Kty != ktyOKP && *raw.Kty != ktyEC {
		// A key type we do not implement at all outranks other complaints
		// about the document.
		return JWK{}, fmt.Errorf("%w: kty %q", ErrUnsupportedAlg, *raw.Kty)
	}
	if raw.Crv == nil {
		return JWK{}, fmt.Errorf("%w: missing member \"crv\"", ErrInvalidKey)
	}
	j := JWK{Kty: *raw.Kty, Crv: *raw.Crv}
	if raw.X == nil {
		return JWK{}, fmt.Errorf("%w: missing member \"x\"", ErrInvalidKey)
	}
	j.X = *raw.X
	if raw.Kid != nil {
		j.Kid = *raw.Kid
	}
	if raw.Alg != nil {
		j.Alg = *raw.Alg
	}
	if raw.Use != nil {
		j.Use = *raw.Use
	}
	if j.Kty == ktyEC {
		if raw.Y == nil {
			return JWK{}, fmt.Errorf("%w: ec key needs member \"y\"", ErrInvalidKey)
		}
		j.Y = *raw.Y
	} else if raw.Y != nil {
		return JWK{}, fmt.Errorf("%w: okp key must not have member \"y\"", ErrInvalidKey)
	}
	if err := j.checkType(); err != nil {
		return JWK{}, err
	}
	// PublicKey() is the coordinate gate: base64url, length, on-curve.
	if _, err := j.PublicKey(); err != nil {
		return JWK{}, err
	}
	if j.Alg != "" && j.Alg != algFor(j.Kty) {
		return JWK{}, fmt.Errorf("%w: alg %q does not match kty %q", ErrAlgMismatch, j.Alg, j.Kty)
	}
	return j, nil
}

// redactJSONErr keeps json decode errors — which can quote a fragment of the
// input — from carrying that fragment into error strings.
func redactJSONErr(err error) error {
	var se *json.SyntaxError
	var ue *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se), errors.As(err, &ue):
		return errors.New("malformed json")
	default:
		return err
	}
}

// algFor is the algorithm that fits a key type.
func algFor(kty string) string {
	if kty == ktyOKP {
		return AlgEdDSA
	}
	return AlgES256
}
