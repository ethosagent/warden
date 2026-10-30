package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
)

// RFC 8037 Appendix A: the Ed25519 example key (sections A.1-A.3) and its
// JWS example (section A.4). These pin the wire format: the kid is the RFC
// 7638 thumbprint and the signature is EdDSA over the bare signing input.
const (
	rfc8037SeedB64 = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037X       = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037Kid     = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	rfc8037Input   = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	rfc8037SigB64  = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

// P-256 golden key: scalar d = sha256("warden keys p-256 golden test key"),
// with the coordinates and thumbprint it deterministically produces.
const (
	p256GoldenX   = "GvPmlGmk0aSPkIX4bWgDHifhkA5sbMjCgKgtKWV7oBE"
	p256GoldenY   = "-agAFznRqQeutJtbnQJ0hCANiCu0NccTB5FZhwh-MoM"
	p256GoldenKid = "EuZBwZ6lIytZBEKllb5fx9N5GTzscXvvXYCdCZFiYVM"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	input := []byte("eyJhbGciOiJFZERTQSJ9.cGF5bG9hZA")

	for _, alg := range []string{AlgEdDSA, AlgES256} {
		t.Run(alg, func(t *testing.T) {
			s, err := GenerateLocal(alg)
			if err != nil {
				t.Fatalf("GenerateLocal(%s): %v", alg, err)
			}
			if s.Alg() != alg {
				t.Errorf("Alg() = %q, want %q", s.Alg(), alg)
			}
			if s.KID() == "" {
				t.Fatal("KID() is empty")
			}

			sig, err := s.Sign(context.Background(), input)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			jwk, err := PublicJWK(s.Public(), alg)
			if err != nil {
				t.Fatalf("PublicJWK: %v", err)
			}
			if jwk.Kid != s.KID() {
				t.Errorf("PublicJWK kid %q != signer KID() %q", jwk.Kid, s.KID())
			}
			if err := Verify(jwk, alg, input, sig); err != nil {
				t.Fatalf("Verify(round trip): %v", err)
			}

			// Tampering with any part must fail closed.
			tampered := append([]byte(nil), input...)
			tampered[len(tampered)-1] ^= 1
			if err := Verify(jwk, alg, tampered, sig); !errors.Is(err, ErrBadSignature) {
				t.Errorf("Verify(tampered input) error = %v, want ErrBadSignature", err)
			}
			badSig := append([]byte(nil), sig...)
			badSig[0] ^= 1
			if err := Verify(jwk, alg, input, badSig); !errors.Is(err, ErrBadSignature) {
				t.Errorf("Verify(tampered sig) error = %v, want ErrBadSignature", err)
			}

			// A signature from another key of the same algorithm must not verify.
			other, err := GenerateLocal(alg)
			if err != nil {
				t.Fatalf("GenerateLocal(other): %v", err)
			}
			otherSig, err := other.Sign(context.Background(), input)
			if err != nil {
				t.Fatalf("other.Sign: %v", err)
			}
			if err := Verify(jwk, alg, input, otherSig); !errors.Is(err, ErrBadSignature) {
				t.Errorf("Verify(other key's sig) error = %v, want ErrBadSignature", err)
			}
		})
	}
}

// TestSignVerifyConcurrency hammers Sign and Verify from parallel goroutines:
// the port promises concurrent-safe, I/O-free signing, and -race guards it.
func TestSignVerifyConcurrency(t *testing.T) {
	for _, alg := range []string{AlgEdDSA, AlgES256} {
		s, err := GenerateLocal(alg)
		if err != nil {
			t.Fatalf("GenerateLocal(%s): %v", alg, err)
		}
		jwk, err := PublicJWK(s.Public(), alg)
		if err != nil {
			t.Fatalf("PublicJWK: %v", err)
		}
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				input := []byte(fmt.Sprintf("eyJhbGciOiJFZERTQSJ9.payload-%d", g))
				for i := 0; i < 25; i++ {
					sig, err := s.Sign(context.Background(), input)
					if err != nil {
						t.Errorf("goroutine %d: Sign: %v", g, err)
						return
					}
					if err := Verify(jwk, alg, input, sig); err != nil {
						t.Errorf("goroutine %d: Verify: %v", g, err)
						return
					}
				}
			}(g)
		}
		wg.Wait()
	}
}

func TestSignHonoursCancelledContext(t *testing.T) {
	s, err := GenerateLocal(AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Sign(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Errorf("Sign(cancelled) error = %v, want context.Canceled", err)
	}
}

func TestZeroValueSignerFailsClosed(t *testing.T) {
	var s LocalSigner
	if _, err := s.Sign(context.Background(), []byte("x")); !errors.Is(err, ErrNoActiveKey) {
		t.Errorf("zero-value Sign error = %v, want ErrNoActiveKey", err)
	}
	if s.KID() != "" || s.Alg() != "" || s.Public() != nil {
		t.Errorf("zero-value signer must expose no key: %v", s)
	}
}

// TestEd25519RFC8037Vector signs the RFC 8037 Appendix A.4 example with the
// RFC's own key and pins both the kid and the exact signature bytes.
func TestEd25519RFC8037Vector(t *testing.T) {
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037SeedB64)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	s, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	if got := s.KID(); got != rfc8037Kid {
		t.Errorf("KID() = %q, want the RFC 7638 thumbprint %q", got, rfc8037Kid)
	}

	sig, err := s.Sign(context.Background(), []byte(rfc8037Input))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	want, err := base64.RawURLEncoding.DecodeString(rfc8037SigB64)
	if err != nil {
		t.Fatalf("decode golden sig: %v", err)
	}
	if !bytes.Equal(sig, want) {
		t.Errorf("signature = %s, want the RFC 8037 value %s",
			base64.RawURLEncoding.EncodeToString(sig), rfc8037SigB64)
	}

	jwk, err := PublicJWK(s.Public(), AlgEdDSA)
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	if jwk.X != rfc8037X {
		t.Errorf("PublicJWK x = %q, want %q", jwk.X, rfc8037X)
	}
	if err := Verify(jwk, AlgEdDSA, []byte(rfc8037Input), want); err != nil {
		t.Errorf("Verify(RFC vector): %v", err)
	}
}

// TestPublicJWKRejects pins the publish gate: alg must fit the key, and only
// Ed25519 and P-256 keys are publishable at all.
func TestPublicJWKRejects(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		pub  crypto.PublicKey
		alg  string
		want error
	}{
		"nil key":            {nil, AlgEdDSA, ErrInvalidKey},
		"ed25519 with es256": {edPub, AlgES256, ErrAlgMismatch},
		"ed25519 short":      {ed25519.PublicKey(edPub[:16]), AlgEdDSA, ErrInvalidKey},
		"ec with eddsa":      {&p256.PublicKey, AlgEdDSA, ErrAlgMismatch},
		"p-384 key":          {&p384.PublicKey, AlgES256, ErrAlgMismatch},
		"not a key":          {"a string is not a key", AlgEdDSA, ErrAlgMismatch},
	} {
		if _, err := PublicJWK(tc.pub, tc.alg); !errors.Is(err, tc.want) {
			t.Errorf("PublicJWK(%s) error = %v, want %v", name, err, tc.want)
		}
	}

	// What it does publish: the RFC 8037 key under EdDSA.
	jwk, err := PublicJWK(edPub, AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != AlgEdDSA || jwk.Use != "sig" || jwk.Y != "" {
		t.Errorf("PublicJWK(ed25519) = %+v; wrong members", jwk)
	}
	ec, err := PublicJWK(&p256.PublicKey, AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if ec.Kty != "EC" || ec.Crv != "P-256" || ec.Y == "" {
		t.Errorf("PublicJWK(p-256) = %+v; wrong members", ec)
	}
	if kid, err := Thumbprint(ec); err != nil || kid != ec.Kid {
		t.Errorf("PublicJWK kid %q is not the thumbprint %q (%v)", ec.Kid, kid, err)
	}
}

// TestThumbprint pins RFC 7638: the RFC 8037 Appendix A.3 OKP vector, a
// derived-and-pinned P-256 vector, and the rule that only the required
// members take part in the hash.
func TestThumbprint(t *testing.T) {
	okp := JWK{Kty: "OKP", Crv: "Ed25519", X: rfc8037X}
	if got, err := Thumbprint(okp); err != nil || got != rfc8037Kid {
		t.Errorf("Thumbprint(OKP) = %q, %v; want %q", got, err, rfc8037Kid)
	}
	ec := JWK{Kty: "EC", Crv: "P-256", X: p256GoldenX, Y: p256GoldenY}
	if got, err := Thumbprint(ec); err != nil || got != p256GoldenKid {
		t.Errorf("Thumbprint(EC) = %q, %v; want %q", got, err, p256GoldenKid)
	}

	// kid, alg and use are not required members: setting them cannot move the
	// thumbprint.
	dressed := okp
	dressed.Kid, dressed.Alg, dressed.Use = "some-other-kid", AlgEdDSA, "sig"
	if got, err := Thumbprint(dressed); err != nil || got != rfc8037Kid {
		t.Errorf("Thumbprint(dressed) = %q, %v; want the same %q", got, err, rfc8037Kid)
	}

	for name, jwk := range map[string]JWK{
		"okp missing x":      {Kty: "OKP", Crv: "Ed25519"},
		"ec missing y":       {Kty: "EC", Crv: "P-256", X: p256GoldenX},
		"ec missing x":       {Kty: "EC", Crv: "P-256", Y: p256GoldenY},
		"kty rsa":            {Kty: "RSA"},
		"kty oct":            {Kty: "oct"},
		"crv p-384":          {Kty: "EC", Crv: "P-384", X: p256GoldenX, Y: p256GoldenY},
		"okp with crv ec":    {Kty: "OKP", Crv: "P-256", X: p256GoldenX},
		"missing everything": {},
	} {
		if _, err := Thumbprint(jwk); err == nil {
			t.Errorf("Thumbprint(%s): expected an error", name)
		}
	}
}

// TestES256JOSEEncoding pins the RFC 7518 section 3.4 encoding: 64 bytes,
// two fixed-width big-endian halves, verifiable by the stdlib, and DER never
// accepted.
func TestES256JOSEEncoding(t *testing.T) {
	input := []byte("eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != es256SigSize {
		t.Fatalf("ES256 signature is %d bytes, want %d", len(sig), es256SigSize)
	}

	// The stdlib must accept our halves over the SHA-256 digest: the same
	// arithmetic, independently encoded.
	digest := sha256.Sum256(input)
	r := new(big.Int).SetBytes(sig[:es256ScalarSize])
	sc := new(big.Int).SetBytes(sig[es256ScalarSize:])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, sc) {
		t.Error("stdlib ecdsa.Verify rejects the package's r||s encoding")
	}

	// A genuine ASN.1 DER signature over the same digest must be rejected:
	// Verify never parses DER.
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := PublicJWK(&priv.PublicKey, AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(jwk, AlgES256, input, der); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify(DER) error = %v, want ErrBadSignature", err)
	}
	for _, n := range []int{0, 1, 63, 65, 70, 71, 72, 128} {
		if err := Verify(jwk, AlgES256, input, make([]byte, n)); !errors.Is(err, ErrBadSignature) {
			t.Errorf("Verify(%d-byte sig) error = %v, want ErrBadSignature", n, err)
		}
	}

	// Flipping a bit of s is still well-formed r||s, just not the signature.
	tampered := append([]byte(nil), sig...)
	tampered[len(tampered)-1] ^= 1
	if err := Verify(jwk, AlgES256, input, tampered); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify(tampered) error = %v, want ErrBadSignature", err)
	}
}

// TestVerifyAlgRules pins the algorithm gate: anything but EdDSA and ES256 is
// ErrUnsupportedAlg, and the algorithm must fit both the key type and, when
// present, the JWK's own alg member.
func TestVerifyAlgRules(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(context.Background(), []byte("a.b"))
	if err != nil {
		t.Fatal(err)
	}
	ecJWK, err := PublicJWK(&priv.PublicKey, AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edJWK, err := PublicJWK(edPub, AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}

	for _, alg := range []string{"", "none", "HS256", "RS256", "ES384", "Ed448", "PS256"} {
		if err := Verify(ecJWK, alg, []byte("a.b"), sig); !errors.Is(err, ErrUnsupportedAlg) {
			t.Errorf("Verify(alg %q) error = %v, want ErrUnsupportedAlg", alg, err)
		}
	}
	// ES256 with an OKP key and EdDSA with an EC key are mismatches, not
	// unsupported algorithms.
	if err := Verify(edJWK, AlgES256, []byte("a.b"), sig); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("Verify(ES256, okp key) error = %v, want ErrAlgMismatch", err)
	}
	if err := Verify(ecJWK, AlgEdDSA, []byte("a.b"), sig); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("Verify(EdDSA, ec key) error = %v, want ErrAlgMismatch", err)
	}
	// A JWK that states its algorithm must be asked for exactly that.
	misdeclared := ecJWK
	misdeclared.Alg = AlgEdDSA
	if err := Verify(misdeclared, AlgES256, []byte("a.b"), sig); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("Verify(jwk.alg disagrees) error = %v, want ErrAlgMismatch", err)
	}
	// A JWK that cannot become a key at all fails before any crypto runs.
	broken := JWK{Kty: "EC", Crv: "P-256", X: "not-base64!", Y: p256GoldenY}
	if err := Verify(broken, AlgES256, []byte("a.b"), sig); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Verify(malformed jwk) error = %v, want ErrInvalidKey", err)
	}

	// The EdDSA length gate: 63 raw bytes is not an Ed25519 signature, however
	// they were produced.
	edSigner, err := NewLocalSigner(mustEd25519(t))
	if err != nil {
		t.Fatal(err)
	}
	edSig, err := edSigner.Sign(context.Background(), []byte("a.b"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(edJWK, AlgEdDSA, []byte("a.b"), edSig[:63]); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify(63-byte sig) error = %v, want ErrBadSignature", err)
	}
}

func mustEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestParseJWKRejects(t *testing.T) {
	okpOK := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, rfc8037X)
	ecOK := fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, p256GoldenX, p256GoldenY)
	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"okp with private d", fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"d":%q}`, rfc8037X, rfc8037SeedB64), ErrInvalidKey},
		{"ec with private d", fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q,"d":%q}`, p256GoldenX, p256GoldenY, p256GoldenX), ErrInvalidKey},
		{"kty rsa", `{"kty":"RSA","n":"aaa","e":"AQAB"}`, ErrUnsupportedAlg},
		{"kty oct", `{"kty":"oct","k":"AAAA"}`, ErrUnsupportedAlg},
		{"kty missing", fmt.Sprintf(`{"crv":"Ed25519","x":%q}`, rfc8037X), ErrInvalidKey},
		{"crv missing", fmt.Sprintf(`{"kty":"OKP","x":%q}`, rfc8037X), ErrInvalidKey},
		{"crv x25519", fmt.Sprintf(`{"kty":"OKP","crv":"X25519","x":%q}`, rfc8037X), ErrUnsupportedAlg},
		{"crv p-384", fmt.Sprintf(`{"kty":"EC","crv":"P-384","x":%q,"y":%q}`, p256GoldenX, p256GoldenY), ErrUnsupportedAlg},
		{"okp crv p-256", fmt.Sprintf(`{"kty":"OKP","crv":"P-256","x":%q}`, rfc8037X), ErrUnsupportedAlg},
		{"ec crv ed25519", fmt.Sprintf(`{"kty":"EC","crv":"Ed25519","x":%q,"y":%q}`, p256GoldenX, p256GoldenY), ErrUnsupportedAlg},
		{"okp with y", fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"y":%q}`, rfc8037X, p256GoldenY), ErrInvalidKey},
		{"x missing", `{"kty":"OKP","crv":"Ed25519"}`, ErrInvalidKey},
		{"ec y missing", fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q}`, p256GoldenX), ErrInvalidKey},
		{"x 31 bytes", fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, strings.Repeat("A", 42)), ErrInvalidKey},
		{"x 33 bytes", fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 33))), ErrInvalidKey},
		{"x not base64url", `{"kty":"OKP","crv":"Ed25519","x":"not+base64/chars*"}`, ErrInvalidKey},
		{"x padded base64", fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, rfc8037X[:42]+"="), ErrInvalidKey},
		{"x non-string", `{"kty":"OKP","crv":"Ed25519","x":5}`, ErrInvalidKey},
		{"kty non-string", fmt.Sprintf(`{"kty":true,"crv":"Ed25519","x":%q}`, rfc8037X), ErrInvalidKey},
		{"y wrong length", fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":"AAAA"}`, p256GoldenX), ErrInvalidKey},
		{"point off curve", fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`,
			base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
			base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))), ErrInvalidKey},
		{"alg mismatches okp", fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"alg":"ES256"}`, rfc8037X), ErrAlgMismatch},
		{"alg mismatches ec", fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q,"alg":"EdDSA"}`, p256GoldenX, p256GoldenY), ErrAlgMismatch},
		{"alg rs256 on okp", fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"alg":"RS256"}`, rfc8037X), ErrAlgMismatch},
		{"truncated json", `{"kty":"OKP","crv"`, ErrInvalidKey},
		{"trailing garbage", okpOK + "}", ErrInvalidKey},
		{"top-level array", `[{"kty":"OKP"}]`, ErrInvalidKey},
		{"empty", ``, ErrInvalidKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			jwk, err := ParseJWK([]byte(c.doc))
			if err == nil {
				t.Fatalf("ParseJWK accepted %s: %+v", c.name, jwk)
			}
			if !errors.Is(err, c.want) {
				t.Errorf("ParseJWK(%s) error = %v, want %v", c.name, err, c.want)
			}
		})
	}

	// The two shapes that must survive, with no optional members present.
	for name, doc := range map[string]string{"okp": okpOK, "ec": ecOK} {
		jwk, err := ParseJWK([]byte(doc))
		if err != nil {
			t.Fatalf("ParseJWK(%s): %v", name, err)
		}
		if jwk.Alg != "" || jwk.Kid != "" || jwk.Use != "" {
			t.Errorf("ParseJWK(%s) filled optional members from nothing: %+v", name, jwk)
		}
		if _, err := jwk.PublicKey(); err != nil {
			t.Errorf("PublicKey after ParseJWK(%s): %v", name, err)
		}
	}
	// kid is kept as given, not recomputed: it is a hint, and the JWKS
	// serves exactly what the manager pinned.
	full := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"kid":"custom","alg":"EdDSA","use":"sig"}`, rfc8037X)
	jwk, err := ParseJWK([]byte(full))
	if err != nil {
		t.Fatalf("ParseJWK(full): %v", err)
	}
	if jwk.Kid != "custom" || jwk.Alg != AlgEdDSA || jwk.Use != "sig" {
		t.Errorf("ParseJWK(full) = %+v; optional members must round trip", jwk)
	}
}

// TestJWKMarshal pins the JSON shape: member names and order, omitempty, the
// JWKS wrapper, and the absence of any private member.
func TestJWKMarshal(t *testing.T) {
	jwk := JWK{Kty: "OKP", Crv: "Ed25519", X: rfc8037X, Kid: rfc8037Kid, Alg: AlgEdDSA, Use: "sig"}
	b, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"kid":%q,"alg":"EdDSA","use":"sig"}`, rfc8037X, rfc8037Kid)
	if string(b) != want {
		t.Errorf("JWK JSON = %s, want %s", b, want)
	}
	if bytes.Contains(b, []byte(`"d"`)) {
		t.Error("JWK JSON mentions a private member \"d\"")
	}

	// Empty members disappear; a bare key stays a bare key.
	bare, err := json.Marshal(JWK{Kty: "OKP", Crv: "Ed25519", X: rfc8037X})
	if err != nil {
		t.Fatal(err)
	}
	if string(bare) != fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, rfc8037X) {
		t.Errorf("bare JWK JSON = %s", bare)
	}

	// The published form parses back to itself.
	for _, alg := range []string{AlgEdDSA, AlgES256} {
		s, err := GenerateLocal(alg)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := PublicJWK(s.Public(), alg)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(pub)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseJWK(b)
		if err != nil {
			t.Fatalf("ParseJWK(marshal(PublicJWK(%s))): %v", alg, err)
		}
		if back != pub {
			t.Errorf("%s: marshal/parse round trip = %+v, want %+v", alg, back, pub)
		}
	}

	// A JWKS is just the keys wrapper, and it round trips.
	set := JWKS{Keys: []JWK{jwk}}
	b, err = json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte(`{"keys":[{`)) || !bytes.HasSuffix(b, []byte(`}]}`)) {
		t.Errorf("JWKS JSON = %s, want the keys wrapper", b)
	}
	var back JWKS
	if err := json.Unmarshal(b, &back); err != nil || len(back.Keys) != 1 || back.Keys[0] != jwk {
		t.Errorf("JWKS round trip = %+v, %v; want %+v", back, err, set)
	}
}

// TestSignerRedaction proves the signer's printable and loggable forms carry
// only the kid and algorithm — never key bytes.
func TestSignerRedaction(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("keys.LocalSigner{kid: %s, alg: EdDSA}", s.KID())
	if got := s.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if got := fmt.Sprintf("%#v", s); got != want {
		t.Errorf("%%#v of the signer = %q, want %q", got, want)
	}

	var buf bytes.Buffer
	h := slog.New(slog.NewJSONHandler(&buf, nil))
	h.Info("signer", "s", s)
	var logged struct {
		S map[string]string `json:"s"`
	}
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("log line %s is not JSON: %v", buf.Bytes(), err)
	}
	if len(logged.S) != 2 || logged.S["kid"] != s.KID() || logged.S["alg"] != "EdDSA" {
		t.Errorf("logged value = %v, want only {kid, alg}", logged.S)
	}

	// Neither form may contain key material: the seed, the full private key,
	// or the PEM that persists it.
	pemBytes, err := MarshalPKCS8PEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	for name, leak := range map[string]string{
		"seed":     base64.RawURLEncoding.EncodeToString(priv.Seed()),
		"full key": base64.RawURLEncoding.EncodeToString(priv),
	} {
		if strings.Contains(want, leak) || strings.Contains(buf.String(), leak) {
			t.Errorf("%s leaked into the signer's display forms", name)
		}
	}
	for _, line := range strings.Split(string(pemBytes), "\n") {
		if len(line) < 16 { // PEM header/footer lines are fine to name
			continue
		}
		if strings.Contains(want, line) || strings.Contains(buf.String(), line) {
			t.Error("PEM body leaked into the signer's display forms")
		}
	}
}

// TestLocalSignerRejects pins the key gate: only Ed25519 and P-256 keys get
// in, at both constructors and MarshalPKCS8PEM.
func TestLocalSignerRejects(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := GenerateLocal("RS256"); !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("GenerateLocal(RS256) error = %v, want ErrUnsupportedAlg", err)
	}
	if _, err := GenerateLocal(""); !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("GenerateLocal(empty) error = %v, want ErrUnsupportedAlg", err)
	}
	for name, tc := range map[string]struct {
		priv crypto.Signer
		want error
	}{
		"rsa key":            {priv: rsaPriv, want: ErrAlgMismatch},
		"p-384 key":          {priv: p384Priv, want: ErrAlgMismatch},
		"nil key":            {priv: nil, want: ErrInvalidKey},
		"ed25519 wrong size": {priv: edPriv[:16], want: ErrInvalidKey},
	} {
		if _, err := NewLocalSigner(tc.priv); !errors.Is(err, tc.want) {
			t.Errorf("NewLocalSigner(%s) error = %v, want %v", name, err, tc.want)
		}
		if _, err := MarshalPKCS8PEM(tc.priv); !errors.Is(err, tc.want) {
			t.Errorf("MarshalPKCS8PEM(%s) error = %v, want %v", name, err, tc.want)
		}
	}
}

func TestPEMHelpersRoundTrip(t *testing.T) {
	for _, alg := range []string{AlgEdDSA, AlgES256} {
		var priv crypto.Signer
		switch alg {
		case AlgEdDSA:
			_, k, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			priv = k
		case AlgES256:
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			priv = k
		}
		orig, err := NewLocalSigner(priv)
		if err != nil {
			t.Fatalf("%s: NewLocalSigner: %v", alg, err)
		}

		pemBytes, err := MarshalPKCS8PEM(priv)
		if err != nil {
			t.Fatalf("%s: MarshalPKCS8PEM: %v", alg, err)
		}
		if !bytes.HasPrefix(pemBytes, []byte("-----BEGIN PRIVATE KEY-----")) {
			t.Errorf("%s: PEM block type = %s", alg, pemBytes)
		}
		parsed, err := ParsePKCS8PEM(pemBytes)
		if err != nil {
			t.Fatalf("%s: ParsePKCS8PEM: %v", alg, err)
		}
		back, err := NewLocalSigner(parsed)
		if err != nil {
			t.Fatalf("%s: NewLocalSigner(parsed): %v", alg, err)
		}
		if back.KID() != orig.KID() || back.Alg() != orig.Alg() {
			t.Errorf("%s: PEM round trip kid/alg = %q/%q, want %q/%q",
				alg, back.KID(), back.Alg(), orig.KID(), orig.Alg())
		}
		input := []byte("eyJhbGciOiJFZERTQSJ9.cGVtLXJvdW5kLXRyaXA")
		sig, err := back.Sign(context.Background(), input)
		if err != nil {
			t.Fatalf("%s: Sign after round trip: %v", alg, err)
		}
		jwk, err := PublicJWK(back.Public(), alg)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(jwk, alg, input, sig); err != nil {
			t.Errorf("%s: Verify after round trip: %v", alg, err)
		}
	}

	// Documents that are not one of our keys fail closed.
	p384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string][]byte{
		"garbage":        []byte("not a pem"),
		"empty":          nil,
		"wrong pem type": []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"),
		"ecdsa p-384":    foreignPKCS8PEM(t, p384Priv),
		"rsa":            foreignPKCS8PEM(t, rsaPriv),
	} {
		if _, err := ParsePKCS8PEM(doc); err == nil {
			t.Errorf("ParsePKCS8PEM(%s) accepted the document", name)
		} else if !errors.Is(err, ErrInvalidKey) && !errors.Is(err, ErrAlgMismatch) {
			t.Errorf("ParsePKCS8PEM(%s) error = %v, want a typed error", name, err)
		}
	}
}

// foreignPKCS8PEM hand-marshals a key MarshalPKCS8PEM rightly refuses to
// write, so ParsePKCS8PEM can be tested against it.
func foreignPKCS8PEM(t *testing.T, priv crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func FuzzParseJWK(f *testing.F) {
	f.Add([]byte(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, rfc8037X)))
	f.Add([]byte(fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, p256GoldenX, p256GoldenY)))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"","y":"","d":""}`))
	f.Add([]byte(`{"kty":0}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"AAAA","y":"AAAA"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		jwk, err := ParseJWK(data)
		if err != nil {
			return
		}
		// Whatever ParseJWK accepts must be usable: it yields a public key and
		// a thumbprint without panicking, and it survives its own JSON form.
		if _, err := jwk.PublicKey(); err != nil {
			t.Fatalf("accepted JWK has no public key: %v (%+v)", err, jwk)
		}
		if _, err := Thumbprint(jwk); err != nil {
			t.Fatalf("accepted JWK has no thumbprint: %v (%+v)", err, jwk)
		}
		b, err := json.Marshal(jwk)
		if err != nil {
			t.Fatalf("accepted JWK does not marshal: %v", err)
		}
		back, err := ParseJWK(b)
		if err != nil || back != jwk {
			t.Fatalf("accepted JWK does not round trip: %+v vs %+v (%v)", back, jwk, err)
		}
		// And Verify on it fails cleanly, never panics, whatever the inputs.
		_ = Verify(jwk, AlgEdDSA, data, data)
		_ = Verify(jwk, AlgES256, data, data)
	})
}

// Benchmarks document the budget the token minting path relies on: an
// Ed25519 sign or verify well under 100 microseconds per operation.
func BenchmarkSignEd25519(b *testing.B) {
	s, err := GenerateLocal(AlgEdDSA)
	if err != nil {
		b.Fatal(err)
	}
	input := []byte(rfc8037Input)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := s.Sign(context.Background(), input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignES256(b *testing.B) {
	s, err := GenerateLocal(AlgES256)
	if err != nil {
		b.Fatal(err)
	}
	input := []byte(rfc8037Input)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := s.Sign(context.Background(), input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	s, err := GenerateLocal(AlgEdDSA)
	if err != nil {
		b.Fatal(err)
	}
	input := []byte(rfc8037Input)
	sig, err := s.Sign(context.Background(), input)
	if err != nil {
		b.Fatal(err)
	}
	jwk, err := PublicJWK(s.Public(), AlgEdDSA)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := Verify(jwk, AlgEdDSA, input, sig); err != nil {
			b.Fatal(err)
		}
	}
}
