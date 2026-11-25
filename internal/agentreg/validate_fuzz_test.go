package agentreg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/keys"
)

// FuzzValidate feeds arbitrary key documents and kids through Validate. Every
// accepted key must come back canonical: no rejected member survives, the jkt
// is exactly keys.Thumbprint of the stored document, and the document is
// within the size bound.
func FuzzValidate(f *testing.F) {
	for _, seed := range []string{
		string(edJWK("")), string(ecJWK("")),
		string(edJWK(`,"d":"AAAA"`)), string(edJWK(`,"x5u":"https://x"`)), string(edJWK(`,"D":null`)),
		string(edJWK(`,"key_ops":["verify"],"use":"sig","alg":"EdDSA"`)),
		`{"kty":"OKP","crv":"Ed25519","x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		`{"kty":"oct","k":"AAAA"}`, `[]`, `null`, ``,
	} {
		f.Add([]byte(seed), "kid-1")
	}
	f.Fuzz(func(t *testing.T, doc []byte, kid string) {
		a := Agent{ID: "fz", AllowedGroups: []string{"g"}, Keys: []Key{{KID: kid, JWK: doc}}}
		out, err := Validate(a)
		if err != nil {
			return
		}
		for _, k := range out.Keys {
			if len(k.JWK) > MaxJWKBytes {
				t.Fatalf("stored jwk is %d bytes", len(k.JWK))
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(k.JWK, &members); err != nil {
				t.Fatalf("stored jwk is not an object: %v", err)
			}
			for name := range members {
				for _, bad := range rejectedMembers {
					if strings.EqualFold(name, bad) {
						t.Fatalf("stored jwk carries rejected member %q", bad)
					}
				}
			}
			j, err := keys.ParseJWK(k.JWK)
			if err != nil {
				t.Fatalf("stored jwk does not re-parse: %v", err)
			}
			tp, err := keys.Thumbprint(j)
			if err != nil || tp != k.JKT {
				t.Fatalf("jkt %q != keys.Thumbprint %q (%v)", k.JKT, tp, err)
			}
			if k.KID == "" || checkKID(k.KID) != nil {
				t.Fatalf("stored kid is invalid: %q", k.KID)
			}
		}
	})
}
