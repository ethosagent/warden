package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// RFC 8037 Appendix A: the Ed25519 example key (sections A.1-A.3) and its JWS
// example (section A.4). These pin the wire format: the kid is the RFC 7638
// thumbprint and the signature is EdDSA over the bare signing input.
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

	// A P-256 public key publishes both coordinates; the shape round trips.
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicJWK(&p256.PublicKey, AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseJWK(b)
	if err != nil {
		t.Fatalf("ParseJWK(marshal(PublicJWK)): %v", err)
	}
	if back != pub {
		t.Errorf("marshal/parse round trip = %+v, want %+v", back, pub)
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
	var backSet JWKS
	if err := json.Unmarshal(b, &backSet); err != nil || len(backSet.Keys) != 1 || backSet.Keys[0] != jwk {
		t.Errorf("JWKS round trip = %+v, %v; want %+v", backSet, err, set)
	}
}

// TestVerifyAlgRules pins the algorithm gate: anything but EdDSA and ES256 is
// ErrUnsupportedAlg, and the algorithm must fit both the key type and, when
// present, the JWK's own alg member. The signatures are built with the
// stdlib directly (tests are exempt from X1) so the domain stays free of its
// adapter: Verify is checked against the wire encodings, not against Sign.
func TestVerifyAlgRules(t *testing.T) {
	input := []byte("a.b")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecJWK, err := PublicJWK(&priv.PublicKey, AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	sig := es256Sig(t, priv, input)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edJWK, err := PublicJWK(edPub, AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	edSig := ed25519.Sign(edPriv, input)

	// The happy paths first: a stdlib-built signature verifies.
	if err := Verify(ecJWK, AlgES256, input, sig); err != nil {
		t.Errorf("Verify(es256) error = %v, want nil", err)
	}
	if err := Verify(edJWK, AlgEdDSA, input, edSig); err != nil {
		t.Errorf("Verify(eddsa) error = %v, want nil", err)
	}

	for _, alg := range []string{"", "none", "HS256", "RS256", "ES384", "Ed448", "PS256"} {
		if err := Verify(ecJWK, alg, input, sig); !errors.Is(err, ErrUnsupportedAlg) {
			t.Errorf("Verify(alg %q) error = %v, want ErrUnsupportedAlg", alg, err)
		}
	}
	// ES256 with an OKP key and EdDSA with an EC key are mismatches, not
	// unsupported algorithms.
	if err := Verify(edJWK, AlgES256, input, sig); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("Verify(ES256, okp key) error = %v, want ErrAlgMismatch", err)
	}
	if err := Verify(ecJWK, AlgEdDSA, input, edSig); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("Verify(EdDSA, ec key) error = %v, want ErrAlgMismatch", err)
	}
	// A JWK that states its algorithm must be asked for exactly that.
	misdeclared := ecJWK
	misdeclared.Alg = AlgEdDSA
	if err := Verify(misdeclared, AlgES256, input, sig); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("Verify(jwk.alg disagrees) error = %v, want ErrAlgMismatch", err)
	}
	// A JWK that cannot become a key at all fails before any crypto runs.
	broken := JWK{Kty: "EC", Crv: "P-256", X: "not-base64!", Y: p256GoldenY}
	if err := Verify(broken, AlgES256, input, sig); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Verify(malformed jwk) error = %v, want ErrInvalidKey", err)
	}
	// The length gates: 63 raw bytes is not an Ed25519 signature, and a
	// genuine ASN.1 DER ECDSA signature is not r||s.
	if err := Verify(edJWK, AlgEdDSA, input, edSig[:63]); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify(63-byte sig) error = %v, want ErrBadSignature", err)
	}
	digest := sha256.Sum256(input)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(ecJWK, AlgES256, input, der); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify(DER) error = %v, want ErrBadSignature", err)
	}
	// Tampering fails closed.
	tampered := append([]byte(nil), sig...)
	tampered[len(tampered)-1] ^= 1
	if err := Verify(ecJWK, AlgES256, input, tampered); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify(tampered) error = %v, want ErrBadSignature", err)
	}
	wrongInput := append([]byte(nil), input...)
	wrongInput[len(wrongInput)-1] ^= 1
	if err := Verify(ecJWK, AlgES256, wrongInput, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify(tampered input) error = %v, want ErrBadSignature", err)
	}
}

// es256Sig builds the RFC 7518 section 3.4 r||s encoding with the stdlib.
func es256Sig(t *testing.T, priv *ecdsa.PrivateKey, input []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, ES256SignatureSize)
	half := ES256SignatureSize / 2
	r.FillBytes(sig[:half])
	s.FillBytes(sig[half:])
	return sig
}

// TestVerifyRFC8037Vector pins the EdDSA path against the RFC 8037
// Appendix A.4 signature.
func TestVerifyRFC8037Vector(t *testing.T) {
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037SeedB64)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	jwk, err := PublicJWK(priv.Public(), AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.Kid != rfc8037Kid || jwk.X != rfc8037X {
		t.Errorf("PublicJWK(RFC key) = %+v; want kid %s x %s", jwk, rfc8037Kid, rfc8037X)
	}
	sig, err := base64.RawURLEncoding.DecodeString(rfc8037SigB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(jwk, AlgEdDSA, []byte(rfc8037Input), sig); err != nil {
		t.Errorf("Verify(RFC vector): %v", err)
	}
}

// TestVerifyConcurrency hammers Verify from parallel goroutines: the port
// promises concurrent-safe, I/O-free verification, and -race guards it.
func TestVerifyConcurrency(t *testing.T) {
	input := []byte("a.b")
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := PublicJWK(edPub, AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(edPriv, input)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := Verify(jwk, AlgEdDSA, input, sig); err != nil {
					t.Errorf("Verify: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
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

// BenchmarkVerify documents the verification budget the token path relies
// on: well under 100 microseconds per operation.
func BenchmarkVerify(b *testing.B) {
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037SeedB64)
	if err != nil {
		b.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	jwk, err := PublicJWK(priv.Public(), AlgEdDSA)
	if err != nil {
		b.Fatal(err)
	}
	input := []byte(rfc8037Input)
	sig := ed25519.Sign(priv, input)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := Verify(jwk, AlgEdDSA, input, sig); err != nil {
			b.Fatal(err)
		}
	}
}
