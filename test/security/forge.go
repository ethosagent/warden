package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	keysigner "github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// Raw JWS forging for the Warden token. A forged token is built from a valid
// template (the claims the token service mints) and edited one member at a
// time, so each case differs from a token the worker accepts in exactly the
// thing it attacks. The signing key is the control plane's own token key
// (Keys().Signer), because a claim-level forgery (wrong iss, a missing exp, a
// long lifetime) is only a test of the claim check when the signature is
// valid; a signature-level forgery overrides the signer instead.

// ForgedSkew is the margin the boundary cases use around the verifier's
// clock-skew tolerance: a token this far inside the tolerance is accepted, one
// this far outside is refused. The shared clock is a fake, so the margin is
// not eroded by a slow run; it only has to be larger than the clock's own
// granularity (one second).
const ForgedSkew = 5 * time.Second

// tokenSpec is a Warden token under construction.
type tokenSpec struct {
	header, claims map[string]any
	signer         keys.Signer
	hmacKey        []byte
	unsigned       bool
	junkSignature  bool
	flipSignature  bool
	signed         bool
}

// TokenOption edits a forged token.
type TokenOption func(*tokenSpec)

// Claim sets a claim.
func Claim(name string, v any) TokenOption {
	return func(t *tokenSpec) { t.claims[name] = v }
}

// WithoutClaim removes claims.
func WithoutClaim(names ...string) TokenOption {
	return func(t *tokenSpec) {
		for _, n := range names {
			delete(t.claims, n)
		}
	}
}

// Header sets a protected header member.
func Header(name string, v any) TokenOption {
	return func(t *tokenSpec) { t.header[name] = v }
}

// WithoutHeader removes header members.
func WithoutHeader(names ...string) TokenOption {
	return func(t *tokenSpec) {
		for _, n := range names {
			delete(t.header, n)
		}
	}
}

// SignedBy signs with signer instead of the control plane's token key; the
// header kid and alg stay what the template said unless an option changes them.
func SignedBy(signer keys.Signer) TokenOption {
	return func(t *tokenSpec) { t.signer = signer }
}

// HMAC signs with HMAC-SHA256 keyed with secret and sets alg to HS256.
func HMAC(secret []byte) TokenOption {
	return func(t *tokenSpec) {
		t.hmacKey = append([]byte(nil), secret...)
		t.header["alg"] = "HS256"
	}
}

// Unsigned sets alg none and leaves the signature segment empty.
func Unsigned() TokenOption {
	return func(t *tokenSpec) {
		t.unsigned = true
		t.header["alg"] = "none"
	}
}

// JunkSignature keeps whatever alg the header says but signs with garbage.
func JunkSignature() TokenOption { return func(t *tokenSpec) { t.junkSignature = true } }

// FlippedSignature signs correctly and then corrupts the signature's bytes.
func FlippedSignature() TokenOption { return func(t *tokenSpec) { t.flipSignature = true } }

// TokenKey is the control plane's active token signer.
func (s *Stack) TokenKey(tb testing.TB) keys.Signer {
	tb.Helper()
	return s.signerFor(tb, keys.PurposeToken)
}

// BundleKey is the control plane's active bundle signer: the key the signed
// bundles are signed with, which must never verify a Warden token.
func (s *Stack) BundleKey(tb testing.TB) keys.Signer {
	tb.Helper()
	return s.signerFor(tb, keys.PurposeBundle)
}

func (s *Stack) signerFor(tb testing.TB, purpose string) keys.Signer {
	tb.Helper()
	km := s.Keys()
	if km == nil {
		tb.Fatal("security: the control plane never reported its key manager")
	}
	sg, err := km.Signer(context.Background(), purpose)
	if err != nil {
		tb.Fatalf("security: the %s signer: %v", purpose, err)
	}
	return sg
}

// ForeignSigner is a fresh key of the same algorithm as the token key that the
// control plane has never published.
func (s *Stack) ForeignSigner(tb testing.TB) keys.Signer {
	tb.Helper()
	sg, err := keysigner.GenerateLocal(s.TokenKey(tb).Alg())
	if err != nil {
		tb.Fatalf("security: generate a foreign key: %v", err)
	}
	return sg
}

// TokenJWK is the public JWK (JSON) of the control plane's active token key:
// the bytes an HS256 key-confusion forgery uses as its HMAC secret.
func (s *Stack) TokenJWK(tb testing.TB) []byte {
	tb.Helper()
	kid := s.TokenKey(tb).KID()
	for _, k := range s.Keys().KeySet().JWKS(keys.PurposeToken).Keys {
		if k.Kid == kid {
			b, err := json.Marshal(k)
			if err != nil {
				tb.Fatalf("security: encode the token JWK: %v", err)
			}
			return b
		}
	}
	tb.Fatalf("security: the active token key %s is not in the served JWKS", kid)
	return nil
}

// ForgeWarden builds a Warden-shaped token for sub as agent a. With no option
// it is a valid token a worker bound to a accepts (iat now, ten minutes of
// life, the agent's key thumbprint in cnf); options then attack one part of it.
// The token is registered with the leak invariant.
func (s *Stack) ForgeWarden(tb testing.TB, a *Agent, sub string, opts ...TokenOption) string {
	tb.Helper()
	tok := buildWarden(tb, s.TokenKey(tb), s.Clock.Now(), a.ID, a.Key.Thumbprint(), sub, s.Issuer.Issuer(), opts...)
	s.tracker.add("forged warden token", tok)
	return tok
}

// buildWarden is ForgeWarden without a stack: the signer, the clock reading and
// the agent are given (the fuzz target forges against its own key).
func buildWarden(tb testing.TB, signer keys.Signer, at time.Time, agentID, jkt, sub, idpIss string, opts ...TokenOption) string {
	tb.Helper()
	now := at.Truncate(time.Second)
	t := &tokenSpec{
		header: map[string]any{"alg": signer.Alg(), "kid": signer.KID(), "typ": identity.WardenTokenTyp},
		claims: map[string]any{
			"ver": identity.WardenTokenVer, "iss": TokenIssuer, "aud": identity.WardenAudience,
			"sub": sub, "idp_iss": idpIss, "groups": []string{"eng"},
			"act": map[string]any{"sub": agentID}, "sid": "wts_forged", "jti": "forged-" + randHex(tb),
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
			"cnf": map[string]any{"jkt": jkt},
		},
		signer: signer,
	}
	for _, o := range opts {
		o(t)
	}
	return t.compact(tb)
}

// compact serializes and signs the token as the spec says.
func (t *tokenSpec) compact(tb testing.TB) string {
	tb.Helper()
	enc := base64.RawURLEncoding
	hb, err := json.Marshal(t.header)
	if err != nil {
		tb.Fatalf("security: encode a forged header: %v", err)
	}
	cb, err := json.Marshal(t.claims)
	if err != nil {
		tb.Fatalf("security: encode forged claims: %v", err)
	}
	in := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	var sig []byte
	switch {
	case t.unsigned:
		return in + "."
	case t.junkSignature:
		sig = []byte("not a signature, only bytes that decode")
	case t.hmacKey != nil:
		mac := hmac.New(sha256.New, t.hmacKey)
		mac.Write([]byte(in))
		sig = mac.Sum(nil)
	default:
		sig, err = t.signer.Sign(context.Background(), []byte(in))
		if err != nil {
			tb.Fatalf("security: sign a forged token: %v", err)
		}
		if t.flipSignature {
			sig = append([]byte(nil), sig...)
			for i := range sig {
				sig[i] ^= 0xff
			}
		}
	}
	return in + "." + enc.EncodeToString(sig)
}

// Segments splits a compact token for a case that rebuilds one (a JWE shape,
// a swapped payload). It never prints the parts.
func Segments(tok string) []string { return strings.Split(tok, ".") }
