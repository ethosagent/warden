package signer

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

	"github.com/ethosagent/warden/internal/keys"
)

// RFC 8037 Appendix A: the Ed25519 example key (sections A.1-A.3) and its JWS
// example (section A.4). These pin the adapter's wire format: the kid is the
// RFC 7638 thumbprint and the signature is EdDSA over the bare signing input.
const (
	rfc8037SeedB64 = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037X       = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037Kid     = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	rfc8037Input   = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	rfc8037SigB64  = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	input := []byte("eyJhbGciOiJFZERTQSJ9.cGF5bG9hZA")

	for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
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
			jwk, err := keys.PublicJWK(s.Public(), alg)
			if err != nil {
				t.Fatalf("PublicJWK: %v", err)
			}
			if jwk.Kid != s.KID() {
				t.Errorf("PublicJWK kid %q != signer KID() %q", jwk.Kid, s.KID())
			}
			if err := keys.Verify(jwk, alg, input, sig); err != nil {
				t.Fatalf("Verify(round trip): %v", err)
			}

			// Tampering with any part must fail closed.
			tampered := append([]byte(nil), input...)
			tampered[len(tampered)-1] ^= 1
			if err := keys.Verify(jwk, alg, tampered, sig); !errors.Is(err, keys.ErrBadSignature) {
				t.Errorf("Verify(tampered input) error = %v, want ErrBadSignature", err)
			}
			badSig := append([]byte(nil), sig...)
			badSig[0] ^= 1
			if err := keys.Verify(jwk, alg, input, badSig); !errors.Is(err, keys.ErrBadSignature) {
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
			if err := keys.Verify(jwk, alg, input, otherSig); !errors.Is(err, keys.ErrBadSignature) {
				t.Errorf("Verify(other key's sig) error = %v, want ErrBadSignature", err)
			}
		})
	}
}

// TestSignVerifyConcurrency hammers Sign and Verify from parallel goroutines:
// the port promises concurrent-safe, I/O-free signing, and -race guards it.
func TestSignVerifyConcurrency(t *testing.T) {
	for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
		s, err := GenerateLocal(alg)
		if err != nil {
			t.Fatalf("GenerateLocal(%s): %v", alg, err)
		}
		jwk, err := keys.PublicJWK(s.Public(), alg)
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
					if err := keys.Verify(jwk, alg, input, sig); err != nil {
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
	s, err := GenerateLocal(keys.AlgEdDSA)
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
	if _, err := s.Sign(context.Background(), []byte("x")); !errors.Is(err, keys.ErrNoActiveKey) {
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

	jwk, err := keys.PublicJWK(s.Public(), keys.AlgEdDSA)
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	if jwk.X != rfc8037X {
		t.Errorf("PublicJWK x = %q, want %q", jwk.X, rfc8037X)
	}
	if err := keys.Verify(jwk, keys.AlgEdDSA, []byte(rfc8037Input), want); err != nil {
		t.Errorf("Verify(RFC vector): %v", err)
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
	if len(sig) != keys.ES256SignatureSize {
		t.Fatalf("ES256 signature is %d bytes, want %d", len(sig), keys.ES256SignatureSize)
	}

	// The stdlib must accept our halves over the SHA-256 digest: the same
	// arithmetic, independently encoded.
	digest := sha256.Sum256(input)
	r := new(big.Int).SetBytes(sig[:keys.ES256SignatureSize/2])
	sc := new(big.Int).SetBytes(sig[keys.ES256SignatureSize/2:])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, sc) {
		t.Error("stdlib ecdsa.Verify rejects the adapter's r||s encoding")
	}

	// A genuine ASN.1 DER signature over the same digest must be rejected:
	// Verify never parses DER.
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := keys.PublicJWK(&priv.PublicKey, keys.AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Verify(jwk, keys.AlgES256, input, der); !errors.Is(err, keys.ErrBadSignature) {
		t.Errorf("Verify(DER) error = %v, want ErrBadSignature", err)
	}
	for _, n := range []int{0, 1, 63, 65, 70, 71, 72, 128} {
		if err := keys.Verify(jwk, keys.AlgES256, input, make([]byte, n)); !errors.Is(err, keys.ErrBadSignature) {
			t.Errorf("Verify(%d-byte sig) error = %v, want ErrBadSignature", n, err)
		}
	}

	// Flipping a bit of s is still well-formed r||s, just not the signature.
	tampered := append([]byte(nil), sig...)
	tampered[len(tampered)-1] ^= 1
	if err := keys.Verify(jwk, keys.AlgES256, input, tampered); !errors.Is(err, keys.ErrBadSignature) {
		t.Errorf("Verify(tampered) error = %v, want ErrBadSignature", err)
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
	want := fmt.Sprintf("signer.LocalSigner{kid: %s, alg: EdDSA}", s.KID())
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

	if _, err := GenerateLocal("RS256"); !errors.Is(err, keys.ErrUnsupportedAlg) {
		t.Errorf("GenerateLocal(RS256) error = %v, want ErrUnsupportedAlg", err)
	}
	if _, err := GenerateLocal(""); !errors.Is(err, keys.ErrUnsupportedAlg) {
		t.Errorf("GenerateLocal(empty) error = %v, want ErrUnsupportedAlg", err)
	}
	for name, tc := range map[string]struct {
		priv crypto.Signer
		want error
	}{
		"rsa key":            {priv: rsaPriv, want: keys.ErrAlgMismatch},
		"p-384 key":          {priv: p384Priv, want: keys.ErrAlgMismatch},
		"nil key":            {priv: nil, want: keys.ErrInvalidKey},
		"ed25519 wrong size": {priv: edPriv[:16], want: keys.ErrInvalidKey},
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
	for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
		var priv crypto.Signer
		switch alg {
		case keys.AlgEdDSA:
			_, k, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			priv = k
		case keys.AlgES256:
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
		jwk, err := keys.PublicJWK(back.Public(), alg)
		if err != nil {
			t.Fatal(err)
		}
		if err := keys.Verify(jwk, alg, input, sig); err != nil {
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
		} else if !errors.Is(err, keys.ErrInvalidKey) && !errors.Is(err, keys.ErrAlgMismatch) {
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

// Benchmarks document the budget the token minting path relies on: an
// Ed25519 sign well under 100 microseconds per operation.
func BenchmarkSignEd25519(b *testing.B) {
	s, err := GenerateLocal(keys.AlgEdDSA)
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
	s, err := GenerateLocal(keys.AlgES256)
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
