package security

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	keysigner "github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// FuzzWardenToken feeds mutated tokens to the worker's Warden verifier. The seed
// corpus is the forgeries of the worker matrix (the shapes of wardenForgeries)
// and the tokens it accepts; in a normal "go test" run only the seeds execute.
// The property: no input verifies unless it is one of the valid seeds,
// unmodified. A fuzzer that finds a mutation of a valid token that still
// verifies has found a verifier that ignores part of what it signs.
func FuzzWardenToken(f *testing.F) {
	const agentID, jkt = "agent-a", "agent-a-key-thumbprint"
	signer, err := keysigner.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		f.Fatalf("generate the token key: %v", err)
	}
	foreign, err := keysigner.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		f.Fatalf("generate a foreign key: %v", err)
	}
	pub, err := keys.PublicJWK(signer.Public(), signer.Alg())
	if err != nil {
		f.Fatalf("token JWK: %v", err)
	}
	pub.Kid = signer.KID()
	clk := clocktest.NewFake(time.Now())
	v, err := identity.NewWardenVerifier(identity.WardenConfig{Now: clk.Now})
	if err != nil {
		f.Fatalf("verifier: %v", err)
	}
	snap, err := identity.NewWardenSnapshot(identity.WardenBundle{Generation: 1, TokenIssuer: TokenIssuer, JWKS: []keys.JWK{pub}})
	if err != nil || v.SetSnapshot(snap) != nil {
		f.Fatalf("install the snapshot: %v", err)
	}
	now := clk.Now()
	rel := func(d time.Duration) int64 { return now.Truncate(time.Second).Add(d).Unix() }
	forge := func(opts ...TokenOption) string {
		return buildWarden(f, signer, now, agentID, jkt, "user-1", "https://idp.example", opts...)
	}

	valid := map[string]bool{}
	for _, tok := range []string{
		forge(),
		forge(Claim("iat", rel(-10*time.Minute)), Claim("exp", rel(-(defaultSkew-ForgedSkew)))),
		forge(Claim("nbf", rel(defaultSkew-ForgedSkew))),
	} {
		valid[tok] = true
		f.Add(tok)
	}
	seg := Segments(forge())
	for _, tok := range []string{
		"", ".", "..", "a.b.c", "not-a-jwt",
		forge(Unsigned()),
		forge(Header("alg", "none"), JunkSignature()),
		forge(Header("alg", "RS256"), JunkSignature()),
		forge(HMAC([]byte(pub.X))),
		forge(FlippedSignature()),
		forge(SignedBy(foreign)),
		forge(Header("kid", "no-such-key-id")),
		forge(Header("jwk", map[string]string{"kty": "OKP"})),
		forge(Header("jku", "https://attacker.example/keys")),
		forge(Header("x5u", "https://attacker.example/cert")),
		forge(Header("crit", []string{"exp-ext"}), Header("exp-ext", true)),
		forge(WithoutHeader("typ")),
		forge(Claim("iss", "https://attacker.example")),
		forge(Claim("aud", "warden")),
		forge(WithoutClaim("exp")),
		forge(Claim("exp", rel(20*time.Minute))),
		forge(Claim("iat", rel(-10*time.Minute)), Claim("exp", rel(-(defaultSkew+ForgedSkew)))),
		forge(Claim("nbf", rel(defaultSkew+ForgedSkew))),
		forge(WithoutClaim("sub")),
		forge(WithoutClaim("cnf")),
		forge(Claim("pad", strings.Repeat("a", 17<<10))),
		strings.Join([]string{seg[0], seg[1], seg[1], seg[1], seg[2]}, "."),
		seg[0] + "." + seg[1] + "." + seg[2] + "x",
		seg[0] + "." + seg[1],
	} {
		f.Add(tok)
	}

	f.Fuzz(func(t *testing.T, tok string) {
		c, status, _ := v.Verify(context.Background(), tok)
		if status == identity.StatusValid && !valid[tok] {
			t.Fatalf("a token that is not a valid seed verified (sub %q, %d bytes)", c.Sub, len(tok))
		}
		if status == identity.StatusValid && valid[tok] && c.Sub != "user-1" {
			t.Fatalf("a valid seed verified as another subject (%q)", c.Sub)
		}
	})
}
