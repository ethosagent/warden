package keys_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// RFC 8037 appendix A.4: an Ed25519 JWS.
const (
	rfc8037JWS = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	rfc8037X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

// RFC 7515 appendix A.3: an ES256 JWS.
const (
	rfc7515JWS = "eyJhbGciOiJFUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	rfc7515X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	rfc7515Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
)

func TestParseCompact_RFCVectors(t *testing.T) {
	cases := []struct {
		name, jws, alg string
		jwk            keys.JWK
	}{
		{"rfc8037 ed25519", rfc8037JWS, keys.AlgEdDSA, keys.JWK{Kty: "OKP", Crv: "Ed25519", X: rfc8037X}},
		{"rfc7515 es256", rfc7515JWS, keys.AlgES256, keys.JWK{Kty: "EC", Crv: "P-256", X: rfc7515X, Y: rfc7515Y}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, payload, input, sig, err := keys.ParseCompact(c.jws)
			if err != nil {
				t.Fatalf("ParseCompact: %v", err)
			}
			if h.Alg != c.alg || len(payload) == 0 {
				t.Fatalf("header %+v, payload %d bytes", h, len(payload))
			}
			if err := keys.Verify(c.jwk, h.Alg, input, sig); err != nil {
				t.Fatalf("the RFC vector must verify: %v", err)
			}
			input[0] ^= 1
			if err := keys.Verify(c.jwk, h.Alg, input, sig); !errors.Is(err, keys.ErrBadSignature) {
				t.Fatalf("tampered input: %v", err)
			}
		})
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestParseCompact_Rejects(t *testing.T) {
	p, s := b64(`{"a":1}`), b64("sig")
	tok := func(h string) string { return b64(h) + "." + p + "." + s }
	cases := []struct {
		name, raw string
		want      error
	}{
		{"empty", "", keys.ErrMalformedJWS},
		{"two segments", b64(`{"alg":"EdDSA"}`) + "." + p, keys.ErrMalformedJWS},
		{"four segments", tok(`{"alg":"EdDSA"}`) + ".x", keys.ErrMalformedJWS},
		{"empty payload", b64(`{"alg":"EdDSA"}`) + ".." + s, keys.ErrMalformedJWS},
		{"empty signature", b64(`{"alg":"EdDSA"}`) + "." + p + ".", keys.ErrMalformedJWS},
		{"padded segment", tok(`{"alg":"EdDSA"}`) + "=", keys.ErrMalformedJWS},
		{"standard alphabet", b64(`{"alg":"EdDSA","kid":"???>>>"}`) + "." + strings.NewReplacer("-", "+", "_", "/").Replace(base64.RawURLEncoding.EncodeToString([]byte{0xfb, 0xff})) + "." + s, keys.ErrMalformedJWS},
		{"header not an object", tok(`["alg"]`), keys.ErrMalformedJWS},
		{"header trailing data", tok(`{"alg":"EdDSA"}{}`), keys.ErrMalformedJWS},
		{"duplicate alg", tok(`{"alg":"ES256","alg":"EdDSA"}`), keys.ErrMalformedJWS},
		{"mis-cased alg", tok(`{"ALG":"EdDSA"}`), keys.ErrMalformedJWS},
		{"alg not a string", tok(`{"alg":5}`), keys.ErrMalformedJWS},
		{"no alg", tok(`{"kid":"k"}`), keys.ErrMalformedJWS},
		{"alg none", tok(`{"alg":"none"}`), keys.ErrUnsupportedAlg},
		{"alg HS256", tok(`{"alg":"HS256","kid":"k"}`), keys.ErrUnsupportedAlg},
		{"alg RS256", tok(`{"alg":"RS256","kid":"k"}`), keys.ErrUnsupportedAlg},
		{"jwk header", tok(`{"alg":"EdDSA","jwk":{"kty":"OKP"}}`), keys.ErrForbiddenHeader},
		{"jku header", tok(`{"alg":"EdDSA","jku":"https://x"}`), keys.ErrForbiddenHeader},
		{"x5u header", tok(`{"alg":"EdDSA","x5u":"https://x"}`), keys.ErrForbiddenHeader},
		{"x5c header", tok(`{"alg":"EdDSA","x5c":[]}`), keys.ErrForbiddenHeader},
		{"crit header", tok(`{"alg":"EdDSA","crit":["b64"]}`), keys.ErrForbiddenHeader},
		{"mis-cased jwk", tok(`{"alg":"EdDSA","JWK":{}}`), keys.ErrForbiddenHeader},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, _, _, err := keys.ParseCompact(c.raw)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if c.raw != "" && strings.Contains(err.Error(), c.raw) {
				t.Fatalf("error quotes the input: %v", err)
			}
		})
	}
}

func TestSignCompact_RoundTrip(t *testing.T) {
	for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
		t.Run(alg, func(t *testing.T) {
			s, err := signer.GenerateLocal(alg)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := keys.SignCompact(context.Background(), s, keys.Header{Typ: "JWT"}, map[string]any{"iss": "a"})
			if err != nil {
				t.Fatal(err)
			}
			h, payload, input, sig, err := keys.ParseCompact(raw)
			if err != nil {
				t.Fatal(err)
			}
			if h.Alg != alg || h.Kid != s.KID() || h.Typ != "JWT" || string(payload) != `{"iss":"a"}` {
				t.Fatalf("header %+v payload %s", h, payload)
			}
			jwk, err := keys.PublicJWK(s.Public(), alg)
			if err != nil {
				t.Fatal(err)
			}
			if err := keys.Verify(jwk, h.Alg, input, sig); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

func TestSignCompact_Rejects(t *testing.T) {
	s, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.SignCompact(context.Background(), s, keys.Header{Alg: keys.AlgES256}, 1); !errors.Is(err, keys.ErrAlgMismatch) {
		t.Fatalf("alg mismatch: %v", err)
	}
	if _, err := keys.SignCompact(context.Background(), nil, keys.Header{}, 1); !errors.Is(err, keys.ErrInvalidKey) {
		t.Fatalf("nil signer: %v", err)
	}
	if _, err := keys.SignCompact(context.Background(), s, keys.Header{}, func() {}); err == nil {
		t.Fatal("unmarshalable claims must fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := keys.SignCompact(ctx, s, keys.Header{}, 1); err == nil {
		t.Fatal("cancelled context must fail")
	}
}
