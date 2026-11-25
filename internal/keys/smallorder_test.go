package keys

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
)

// SEC-11: an Ed25519 public key that is a small-order point, or a
// non-canonical encoding, makes verification independent of the message.
func TestParseJWKRejectsSmallOrderAndNonCanonicalEd25519(t *testing.T) {
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	le := func(first, mid, last byte) []byte {
		b := make([]byte, 32)
		b[0], b[31] = first, last
		for i := 1; i < 31; i++ {
			b[i] = mid
		}
		return b
	}
	orderEightA := mustDecode(t, "JuiVj8KyJ7BFw_SJ8u-Y8NXfrAXTxjM5sTgCiG1T_AU")
	signedA := append([]byte(nil), orderEightA...)
	signedA[31] |= 0x80
	cases := map[string]string{
		// the two documents the ticket names
		"identity point (y=1)": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"all-zero x (y=0)":     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// canonical small-order points, sign bit set and clear
		"identity, sign bit set":  enc(le(0x01, 0, 0x80)),
		"y=0, sign bit set":       enc(le(0x00, 0, 0x80)),
		"y=p-1 (order 2)":         enc(le(0xec, 0xff, 0x7f)),
		"y=p-1, sign bit set":     enc(le(0xec, 0xff, 0xff)),
		"order 8 point A":         enc(orderEightA),
		"order 8 point B":         "xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA3o",
		"order 8 point A, signed": enc(signedA),
		// non-canonical encodings: y >= p
		"y=p (non-canonical 0)":   enc(le(0xed, 0xff, 0x7f)),
		"y=p+1 (non-canonical 1)": enc(le(0xee, 0xff, 0x7f)),
		"y=2^255-1":               enc(le(0xff, 0xff, 0x7f)),
		"y=2^255-1, sign bit set": enc(le(0xff, 0xff, 0xff)),
	}
	for name, x := range cases {
		t.Run(name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, x)
			if _, err := ParseJWK([]byte(doc)); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("ParseJWK = %v, want ErrInvalidKey", err)
			}
			if _, err := (JWK{Kty: "OKP", Crv: "Ed25519", X: x}).PublicKey(); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("PublicKey = %v, want ErrInvalidKey", err)
			}
		})
	}
	// A real key still parses (RFC 8037 appendix A.2).
	if _, err := ParseJWK([]byte(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, rfc8037X))); err != nil {
		t.Fatalf("a valid key was rejected: %v", err)
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
