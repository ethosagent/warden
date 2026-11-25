package fakes

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// AgentKey is an agent's client credential for the token endpoint: a key pair
// whose public half an operator registers and whose private half signs
// private_key_jwt client assertions (RFC 7523). Keys are generated at run time.
// It deliberately has no dependency on the control plane or the agent registry,
// so a case can register it through the real admin API and attack with it.
type AgentKey struct {
	tb   testing.TB
	kid  string
	alg  string // EdDSA or ES256
	ed   ed25519.PrivateKey
	ec   *ecdsa.PrivateKey
}

// NewAgentKey generates an Ed25519 key with key id kid.
func NewAgentKey(tb testing.TB, kid string) *AgentKey {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("agent key: generate: %v", err)
	}
	return &AgentKey{tb: tb, kid: kid, alg: "EdDSA", ed: priv}
}

// NewAgentKeyES256 generates a P-256 key (ES256) with key id kid.
func NewAgentKeyES256(tb testing.TB, kid string) *AgentKey {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("agent key: generate: %v", err)
	}
	return &AgentKey{tb: tb, kid: kid, alg: "ES256", ec: k}
}

// KID is the key id the registry lists and an assertion header names.
func (k *AgentKey) KID() string { return k.kid }

// Alg is the signing algorithm, EdDSA or ES256.
func (k *AgentKey) Alg() string { return k.alg }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// JWKMap is the public JWK as a map.
func (k *AgentKey) JWKMap() map[string]string {
	if k.ec != nil {
		return map[string]string{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": k.kid,
			"x": b64(k.ec.X.FillBytes(make([]byte, 32))), "y": b64(k.ec.Y.FillBytes(make([]byte, 32))),
		}
	}
	pub, _ := k.ed.Public().(ed25519.PublicKey)
	return map[string]string{
		"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": k.kid, "x": b64(pub),
	}
}

// JWK is the public JWK document to register for the agent.
func (k *AgentKey) JWK() []byte {
	b, err := json.Marshal(k.JWKMap())
	if err != nil {
		k.tb.Fatalf("agent key: encode jwk: %v", err)
	}
	return b
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of the public key, base64url:
// the value a Warden token's cnf.jkt carries.
func (k *AgentKey) Thumbprint() string {
	m := k.JWKMap()
	var canon string
	if k.ec != nil {
		canon = `{"crv":"P-256","kty":"EC","x":"` + m["x"] + `","y":"` + m["y"] + `"}`
	} else {
		canon = `{"crv":"Ed25519","kty":"OKP","x":"` + m["x"] + `"}`
	}
	sum := sha256.Sum256([]byte(canon))
	return b64(sum[:])
}

// AssertionSpec is a client assertion under construction.
type AssertionSpec struct {
	Header map[string]any
	Claims map[string]any
	// Key, when set, signs instead of the receiver (a foreign key under this
	// agent's kid).
	Key *AgentKey
}

// AssertionOption adjusts an assertion before it is signed.
type AssertionOption func(*AssertionSpec)

// AssertionClaim sets a claim; a nil value removes it.
func AssertionClaim(name string, v any) AssertionOption {
	return func(s *AssertionSpec) {
		if v == nil {
			delete(s.Claims, name)
			return
		}
		s.Claims[name] = v
	}
}

// AssertionHeader sets a header member; a nil value removes it.
func AssertionHeader(name string, v any) AssertionOption {
	return func(s *AssertionSpec) {
		if v == nil {
			delete(s.Header, name)
			return
		}
		s.Header[name] = v
	}
}

// AssertionSignedBy signs with another key while the header keeps naming this
// key's kid.
func AssertionSignedBy(other *AgentKey) AssertionOption {
	return func(s *AssertionSpec) { s.Key = other }
}

// ClientAssertion builds and signs a private_key_jwt for agentID: iss and sub
// are agentID, aud is audience, iat is now, exp a minute later and jti fresh.
// Options then adjust it. Failures never print the assertion.
func (k *AgentKey) ClientAssertion(agentID, audience string, now time.Time, opts ...AssertionOption) string {
	k.tb.Helper()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		k.tb.Fatalf("agent key: jti: %v", err)
	}
	s := &AssertionSpec{
		Header: map[string]any{"alg": k.alg, "kid": k.kid, "typ": "JWT"},
		Claims: map[string]any{
			"iss": agentID, "sub": agentID, "aud": audience,
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": hex.EncodeToString(jti),
		},
	}
	for _, o := range opts {
		o(s)
	}
	hb, err := json.Marshal(s.Header)
	if err != nil {
		k.tb.Fatalf("agent key: encode header: %v", err)
	}
	cb, err := json.Marshal(s.Claims)
	if err != nil {
		k.tb.Fatalf("agent key: encode claims: %v", err)
	}
	in := b64(hb) + "." + b64(cb)
	signer := k
	if s.Key != nil {
		signer = s.Key
	}
	alg, _ := s.Header["alg"].(string)
	return in + "." + b64(signer.sign(in, alg))
}

// sign signs in with the key's own algorithm (an alg of "none" gives an empty
// signature, a lying header alg of anything else still gets the key's own
// signature, which is what a confusion case wants).
func (k *AgentKey) sign(in, headerAlg string) []byte {
	if headerAlg == "none" {
		return nil
	}
	if k.ec != nil {
		sum := sha256.Sum256([]byte(in))
		der, err := k.ec.Sign(rand.Reader, sum[:], crypto.SHA256)
		if err != nil {
			k.tb.Fatalf("agent key: sign: %v", err)
		}
		// crypto.Signer returns ES256 as ASN.1 DER; JWS wants fixed-width r||s.
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &rs); err != nil {
			k.tb.Fatalf("agent key: decode signature: %v", err)
		}
		out := make([]byte, 64)
		rs.R.FillBytes(out[:32])
		rs.S.FillBytes(out[32:])
		return out
	}
	sig, err := k.ed.Sign(rand.Reader, []byte(in), crypto.Hash(0))
	if err != nil {
		k.tb.Fatalf("agent key: sign: %v", err)
	}
	return sig
}
