package fakes

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
)

// The security fakes: the issuer's forgery options reach the real verifier's
// verdicts, the CA issues exactly the hostile shapes a case asks for, the
// upstream counts what reaches it, and an agent key signs assertions that a
// verifier reading its public JWK accepts.

func TestOIDCIssuerForgeriesReachTheVerifier(t *testing.T) {
	iss := NewOIDCIssuer(t)
	v, err := oidc.NewOIDCVerifier(oidc.Config{
		Issuer: iss.Issuer(), InternalIssuerURL: iss.Issuer(), Audience: OIDCAudience,
		AllowedAZP: []string{OIDCAZP}, Now: time.Now,
	})
	if err != nil {
		t.Fatalf("build the real verifier: %v", err)
	}
	verify := func(tok string) (identity.Status, identity.Reason) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, st, r := v.Verify(ctx, tok)
		return st, r
	}
	rsKID := iss.KIDs()[0]

	if st, r := verify(iss.Mint()); st != identity.StatusValid || r != "" {
		t.Fatalf("a valid token = %s/%s, want valid", st, r)
	}
	for _, c := range []struct {
		name   string
		tok    string
		reason identity.Reason
	}{
		{"alg none", iss.Mint(WithAlg("none")), identity.ReasonAlgNotAllowed},
		{"HS256 keyed with the public PEM", iss.Mint(WithHS256(iss.PublicKeyPEM(rsKID))), identity.ReasonAlgNotAllowed},
		{"HS256 keyed with the public JWK bytes", iss.Mint(WithHS256(iss.PublicJWKJSON(rsKID))), identity.ReasonAlgNotAllowed},
		{"unknown kid", iss.Mint(WithKID("no-such-kid")), identity.ReasonUnknownKID},
		{"foreign key under a real kid", iss.Mint(WithForeignKey(rsKID)), identity.ReasonBadSignature},
	} {
		st, r := verify(c.tok)
		if st == identity.StatusValid || r != c.reason {
			t.Errorf("%s = %s/%s, want a refusal with reason %s", c.name, st, r, c.reason)
		}
	}
}

func TestOIDCIssuerHS256IsReallyHMAC(t *testing.T) {
	iss := NewOIDCIssuer(t)
	secret := iss.PublicKeyPEM(iss.KIDs()[0])
	tok := iss.Mint(WithHS256(secret), WithClaims(map[string]any{"sub": "mallory"}))
	hdr, claims, in, sig := decoded(t, tok)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(in))
	if hdr["alg"] != "HS256" || claims["sub"] != "mallory" || !bytes.Equal(sig, mac.Sum(nil)) {
		t.Errorf("WithHS256: header %v sub %v, signature is not HMAC-SHA256 of the input", hdr["alg"], claims["sub"])
	}
	if strings.Contains(string(secret), "PRIVATE") {
		t.Error("PublicKeyPEM leaked a private key")
	}
}

func TestAgentKeyAssertions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, k := range []*AgentKey{NewAgentKey(t, "a-1"), NewAgentKeyES256(t, "a-1")} {
		tok := k.ClientAssertion("agent-a", "https://cp/oauth2/token", now,
			AssertionClaim("exp", now.Add(time.Hour).Unix()), AssertionClaim("nbf", nil), AssertionHeader("x", 1))
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Fatalf("%s: assertion has %d segments", k.Alg(), len(parts))
		}
		var hdr, claims map[string]any
		for i, dst := range []*map[string]any{&hdr, &claims} {
			raw, err := base64.RawURLEncoding.DecodeString(parts[i])
			if err != nil || json.Unmarshal(raw, dst) != nil {
				t.Fatalf("%s: segment %d: %v", k.Alg(), i, err)
			}
		}
		if hdr["kid"] != "a-1" || hdr["alg"] != k.Alg() || hdr["x"] != float64(1) ||
			claims["iss"] != "agent-a" || claims["sub"] != "agent-a" || claims["aud"] != "https://cp/oauth2/token" ||
			claims["exp"] != float64(now.Add(time.Hour).Unix()) || claims["jti"] == "" {
			t.Errorf("%s: header %v claims %v", k.Alg(), hdr, claims)
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		in := []byte(parts[0] + "." + parts[1])
		ok := false
		switch k.Alg() {
		case "EdDSA":
			ok = ed25519.Verify(k.ed.Public().(ed25519.PublicKey), in, sig)
		case "ES256":
			sum := sha256.Sum256(in)
			r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
			ok = ecdsa.Verify(&k.ec.PublicKey, sum[:], r, s)
		}
		if !ok {
			t.Errorf("%s: the signature does not verify under the public key", k.Alg())
		}
		var jwk map[string]string
		if err := json.Unmarshal(k.JWK(), &jwk); err != nil || jwk["kid"] != "a-1" || jwk["x"] == "" || k.Thumbprint() == "" {
			t.Errorf("%s: JWK %s thumbprint %q", k.Alg(), k.JWK(), k.Thumbprint())
		}
	}
	a, b := NewAgentKey(t, "k"), NewAgentKey(t, "k")
	if a.Thumbprint() == b.Thumbprint() {
		t.Error("two generated keys share a thumbprint")
	}
	forged := a.ClientAssertion("agent-a", "aud", now, AssertionSignedBy(b))
	parts := strings.Split(forged, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if ed25519.Verify(a.ed.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), sig) {
		t.Error("AssertionSignedBy still verifies under the named key")
	}
	if none := a.ClientAssertion("agent-a", "aud", now, AssertionHeader("alg", "none")); !strings.HasSuffix(none, ".") {
		t.Error("alg none must be unsigned")
	}
}
