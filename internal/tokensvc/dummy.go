package tokensvc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"math/big"

	"github.com/ethosagent/warden/internal/keys"
)

// dummyKey returns a verification key of the type alg selects, used to spend
// the same work on an assertion whose agent or kid is unknown as on one whose
// key is real, so response time does not reveal which agent ids exist. The
// keys are fixed public constants and both private keys are public knowledge
// (the P-256 key is the curve base point, whose private scalar is 1; the
// Ed25519 seed comes from a public label). A signature made with them would
// verify, so the result of a dummy verification must always be discarded and
// never used to authenticate anything.
func dummyKey(alg string) (keys.JWK, bool) {
	switch alg {
	case keys.AlgEdDSA:
		return dummyEd25519, true
	case keys.AlgES256:
		return dummyP256, true
	}
	return keys.JWK{}, false
}

var dummyEd25519, dummyP256 = func() (keys.JWK, keys.JWK) {
	seed := sha256.Sum256([]byte("warden tokensvc dummy verification key"))
	ed, err := keys.PublicJWK(ed25519.NewKeyFromSeed(seed[:]).Public(), keys.AlgEdDSA)
	if err != nil {
		panic("tokensvc: dummy ed25519 jwk: " + err.Error())
	}
	// NIST P-256 base point G (FIPS 186-4 D.1.2.3).
	gx, _ := new(big.Int).SetString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
	gy, _ := new(big.Int).SetString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
	enc := base64.RawURLEncoding.EncodeToString
	ec := keys.JWK{Kty: "EC", Crv: "P-256", X: enc(gx.Bytes()), Y: enc(gy.Bytes())}
	if _, err := ec.PublicKey(); err != nil {
		panic("tokensvc: dummy p-256 jwk: " + err.Error())
	}
	return ed, ec
}()
